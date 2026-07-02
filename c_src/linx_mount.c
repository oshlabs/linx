/*
 * linx_mount -- the NIF backing `Linx.Mount`.
 *
 * Wraps the three filesystem-mount syscalls:
 *
 *   - mount(2)        -- mount/6
 *   - umount2(2)      -- umount/3
 *   - pivot_root(2)   -- pivot_root/4 (M4, not in this build)
 *
 * NAMESPACE TARGETING
 * -------------------
 * Each fallible function takes an `ns_path` binary argument:
 *
 *   - empty binary -- perform the syscall in the caller's namespace
 *     (the BEAM's mount namespace). No thread is spawned.
 *   - non-empty -- a path to a namespace file (typically
 *     `/proc/<pid>/ns/mnt`). The NIF spawns a throwaway pthread,
 *     opens the path with O_RDONLY|O_CLOEXEC, `setns(fd, CLONE_NEWNS)`s
 *     into it, performs the syscall there, and exits the thread.
 *     setns(2) operates per-thread, so the BEAM's own scheduler
 *     threads never enter the target namespace -- the throwaway
 *     thread's namespace membership is destroyed when it exits.
 *
 * Same throwaway-thread pattern as `c_src/netlink_socket.c`'s
 * `open_in_netns` -- both use the same trick to perform a
 * per-thread namespace switch without contaminating the BEAM.
 *
 * ERROR SHAPE
 * -----------
 * Every fallible function returns either `:ok` or
 * `{:error, {Stage::atom, ErrnoAtom | ErrnoInt}}`. Stages:
 *
 *   - :mount / :umount / :pivot_root -- the target syscall failed.
 *   - :open_ns -- couldn't open the namespace file.
 *   - :setns   -- couldn't enter the target namespace.
 *   - :thread  -- couldn't create the worker thread.
 *
 * Common Linux errnos are mapped to POSIX-style atoms; any errno
 * not in the table falls back to the raw integer.
 */

#include <erl_nif.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>      /* setns, CLONE_NEWNS */
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>    /* lstat / S_ISLNK -- ensure_target_file hardening */
#include <sys/syscall.h> /* SYS_pivot_root (no glibc wrapper) */
#include <sys/wait.h>    /* waitpid -- reap the pidns mount fork */
#include <unistd.h>

#define LINX_MOUNT_VERSION "linx_mount"

/* --- errno -> atom ------------------------------------------------------- */

static const char *errno_atom(int err)
{
	switch (err) {
	case EACCES:       return "eacces";
	case EAGAIN:       return "eagain";
	case EBADF:        return "ebadf";
	case EBUSY:        return "ebusy";
	case EFAULT:       return "efault";
	case EINVAL:       return "einval";
	case ELOOP:        return "eloop";
	case EMFILE:       return "emfile";
	case ENAMETOOLONG: return "enametoolong";
	case ENODEV:       return "enodev";
	case ENOENT:       return "enoent";
	case ENOMEM:       return "enomem";
	case ENOTBLK:      return "enotblk";
	case ENOTDIR:      return "enotdir";
	case ENXIO:        return "enxio";
	case EOPNOTSUPP:   return "eopnotsupp";
	case EPERM:        return "eperm";
	case EROFS:        return "erofs";
	case ESRCH:        return "esrch";
	default:           return NULL;
	}
}

/* Build {error, {Stage::atom, ErrnoAtom | ErrnoInt}}. */
static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *stage, int err)
{
	const char *name = errno_atom(err);
	ERL_NIF_TERM val = name
		? enif_make_atom(env, name)
		: enif_make_int(env, err);
	return enif_make_tuple2(
		env, enif_make_atom(env, "error"),
		enif_make_tuple2(env, enif_make_atom(env, stage), val));
}

static ERL_NIF_TERM ok_atom(ErlNifEnv *env)
{
	return enif_make_atom(env, "ok");
}

/* --- string args -------------------------------------------------------- */

/* Copy an Elixir binary into a freshly-allocated null-terminated C
 * string. Caller frees with `enif_free`. Returns NULL on allocation
 * failure or if the term isn't a binary. */
static char *binary_to_cstr(ErlNifEnv *env, ERL_NIF_TERM term)
{
	ErlNifBinary bin;
	if (!enif_inspect_binary(env, term, &bin))
		return NULL;

	/* Reject embedded NUL bytes: the result is used as a C path, so
	 * "<validated>\0<smuggled>" would silently truncate at the NUL and
	 * defeat any string-based validation done on the Elixir side. */
	if (memchr(bin.data, '\0', bin.size) != NULL)
		return NULL;

	char *s = enif_alloc(bin.size + 1);
	if (!s)
		return NULL;

	memcpy(s, bin.data, bin.size);
	s[bin.size] = '\0';
	return s;
}

/* --- version/0 ---------------------------------------------------------- */

static ERL_NIF_TERM version(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;
	(void)argv;
	return enif_make_string(env, LINX_MOUNT_VERSION, ERL_NIF_LATIN1);
}

/* --- worker job structs ------------------------------------------------- */

/* Both mount and umount workers share this header. Specific args follow
 * via the dedicated structs. */
struct ns_job_result {
	int err;            /* errno from the failing step, or 0 */
	const char *stage;  /* "open_ns" | "setns" | "mount" | "umount" */
};

struct mount_job {
	struct ns_job_result r;
	const char *ns_path;
	const char *source;     /* NULL if not specified */
	const char *target;
	const char *fstype;     /* NULL if not specified */
	unsigned long flags;
	const char *data;       /* NULL if not specified */
	const char *pidns_path; /* non-empty => fork into this pid ns to mount (procfs) */
	int create_target;      /* create an empty file at target (in-ns) before mounting */
};

struct umount_job {
	struct ns_job_result r;
	const char *ns_path;
	const char *target;
	int flags;
};

struct pivot_root_job {
	struct ns_job_result r;
	const char *ns_path;   /* empty == BEAM ns */
	const char *new_root;
	const char *put_old;
};

/* Common setns enter/exit pattern used by mount/umount workers.
 * Returns the opened ns fd (caller closes after the syscall), or
 * -1 on failure (with j->r.{err,stage} set).
 *
 * CRITICAL: the kernel's mntns_install() refuses setns(CLONE_NEWNS)
 * if the calling thread's fs_struct is shared with any other thread
 * -- specifically, it returns EINVAL when `fs->users != 1`. Every
 * scheduler thread in the BEAM shares one fs_struct, so a naked
 * setns from a throwaway thread fails. The fix is to call
 * unshare(CLONE_FS) first to give this thread its own fs_struct,
 * separating it from the rest of the BEAM. The unshare only affects
 * the calling thread; when the thread exits, its fs_struct is
 * discarded. Same trick `nsenter(1)` and similar userspace tools use
 * when they need to enter another mount namespace.
 *
 * The order matters: unshare BEFORE setns, otherwise the open() of
 * the namespace file might succeed via the BEAM's fs_struct but the
 * setns then refuses. */
static int enter_target_ns(struct ns_job_result *r, const char *ns_path)
{
	if (unshare(CLONE_FS) < 0) {
		r->err = errno;
		r->stage = "unshare";
		return -1;
	}

	int ns = open(ns_path, O_RDONLY | O_CLOEXEC);
	if (ns < 0) {
		r->err = errno;
		r->stage = "open_ns";
		return -1;
	}

	if (setns(ns, CLONE_NEWNS) < 0) {
		r->err = errno;
		r->stage = "setns";
		close(ns);
		return -1;
	}

	return ns;
}

/* Create an empty regular file at `target` if it doesn't already
 * exist -- a placeholder for a device-node bind mount onto a fresh
 * tmpfs (e.g. /dev/null). Runs on the worker thread, which has
 * already entered the target mount namespace, so the file lands on
 * the in-container tmpfs (a host-side creat would land on the dir
 * underneath the tmpfs, invisible in the container). Returns 0 on
 * success or if it already exists, otherwise an errno.
 *
 * Hardening: we run as root inside a mount namespace whose directories
 * may be container-writable, so a symlink at `target` must not redirect
 * the create (or the subsequent bind mount) to an attacker-chosen path.
 * O_EXCL|O_NOFOLLOW refuses a symlink at the final component; a
 * pre-existing symlink is reported as ELOOP rather than accepted.
 * (Symlinked *parent* directories would need openat2 with
 * RESOLVE_BENEATH/RESOLVE_NO_SYMLINKS — worth adding if this is ever
 * used against live, adversarial containers; the typical call here
 * precedes the workload.) */
static int ensure_target_file(const char *target)
{
	struct stat st;
	if (lstat(target, &st) == 0)
		return S_ISLNK(st.st_mode) ? ELOOP : 0;

	int fd = open(target,
		      O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC,
		      0644);
	if (fd < 0)
		return errno == EEXIST ? 0 : errno;

	close(fd);
	return 0;
}

/* Mount from inside the target PID namespace. setns(CLONE_NEWPID)
 * only arms the namespace for *future children*, and procfs binds to
 * the mounting task's active pid namespace -- so to get a /proc that
 * reflects the container's pids we must fork() and let the child do
 * the mount. The worker thread has already entered the target mount
 * namespace, so the fork child inherits it.
 *
 * ASYNC-SIGNAL-SAFE CONTRACT: fork() in the multithreaded BEAM
 * duplicates only this thread; a lock held by any other thread stays
 * locked forever in the child. The child therefore touches NOTHING
 * but direct syscalls (mount, write, close, _exit) -- no malloc, no
 * erl_nif, no pthread primitives -- and reports its errno over a pipe.
 * Every buffer it reads (j->target etc.) was allocated before fork. */
static void do_mount_in_pidns(struct mount_job *j)
{
	int pidns = open(j->pidns_path, O_RDONLY | O_CLOEXEC);
	if (pidns < 0) {
		j->r.err = errno;
		j->r.stage = "open_pidns";
		return;
	}

	if (setns(pidns, CLONE_NEWPID) < 0) {
		j->r.err = errno;
		j->r.stage = "setns_pid";
		close(pidns);
		return;
	}

	int pfd[2];
	if (pipe(pfd) < 0) {
		j->r.err = errno;
		j->r.stage = "pipe";
		close(pidns);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		j->r.err = errno;
		j->r.stage = "fork";
		close(pfd[0]);
		close(pfd[1]);
		close(pidns);
		return;
	}

	if (pid == 0) {
		/* CHILD -- async-signal-safe only (see contract above). */
		close(pfd[0]);
		int e = 0;
		if (mount(j->source, j->target, j->fstype, j->flags, j->data) < 0)
			e = errno;
		ssize_t w = write(pfd[1], &e, sizeof e);
		(void)w;
		_exit(0);
	}

	/* PARENT (the worker thread). */
	close(pfd[1]);
	int child_err = 0;
	ssize_t n = read(pfd[0], &child_err, sizeof child_err);
	close(pfd[0]);

	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (n != (ssize_t)sizeof child_err) {
		/* couldn't read the child's errno -- report a generic failure */
		j->r.err = EINVAL;
		j->r.stage = "mount";
	} else if (child_err != 0) {
		j->r.err = child_err;
		j->r.stage = "mount";
	}

	close(pidns);
}

static void *mount_worker(void *arg)
{
	struct mount_job *j = arg;

	int ns = enter_target_ns(&j->r, j->ns_path);
	if (ns < 0)
		return NULL;

	if (j->create_target) {
		int e = ensure_target_file(j->target);
		if (e) {
			j->r.err = e;
			j->r.stage = "create";
			close(ns);
			return NULL;
		}
	}

	if (j->pidns_path && j->pidns_path[0] != '\0') {
		do_mount_in_pidns(j);
	} else if (mount(j->source, j->target, j->fstype, j->flags, j->data) < 0) {
		j->r.err = errno;
		j->r.stage = "mount";
	}

	close(ns);
	return NULL;
}

static void *umount_worker(void *arg)
{
	struct umount_job *j = arg;

	int ns = enter_target_ns(&j->r, j->ns_path);
	if (ns < 0)
		return NULL;

	if (umount2(j->target, j->flags) < 0) {
		j->r.err = errno;
		j->r.stage = "umount";
	}

	close(ns);
	return NULL;
}

/* pivot_root requires the calling thread's CWD to be inside
 * new_root before the syscall (kernel-enforced). We chdir on the
 * worker thread so the BEAM's CWD is untouched.
 *
 * Empty ns_path = BEAM's own mount namespace. We still need to
 * unshare(CLONE_FS) so the chdir is private to this thread; we
 * just skip the open+setns. */
static void *pivot_root_worker(void *arg)
{
	struct pivot_root_job *j = arg;
	int ns = -1;

	if (j->ns_path[0] == '\0') {
		/* BEAM ns: unshare so the chdir is thread-local. */
		if (unshare(CLONE_FS) < 0) {
			j->r.err = errno;
			j->r.stage = "unshare";
			return NULL;
		}
	} else {
		ns = enter_target_ns(&j->r, j->ns_path);
		if (ns < 0)
			return NULL;
	}

	if (chdir(j->new_root) < 0) {
		j->r.err = errno;
		j->r.stage = "chdir";
		if (ns >= 0) close(ns);
		return NULL;
	}

	/* glibc doesn't ship a pivot_root() wrapper; go direct. */
	if (syscall(SYS_pivot_root, j->new_root, j->put_old) < 0) {
		j->r.err = errno;
		j->r.stage = "pivot_root";
	}

	if (ns >= 0) close(ns);
	return NULL;
}

/* --- mount/6 ------------------------------------------------------------ */

/* Args: source, target, fstype, flags (uint64), data (binary),
 *       ns_path (binary), pidns_path (binary), create_target (int).
 *
 * Empty `ns_path`: mount in the caller's namespace (no thread).
 * Non-empty `ns_path`: spawn a worker that enters that namespace.
 *
 * Non-empty `pidns_path` (a /proc/<pid>/ns/pid file): the worker also
 * enters that PID namespace and fork()s a child to perform the mount,
 * so procfs binds to the container's pid namespace (see
 * do_mount_in_pidns). Only meaningful alongside a non-empty ns_path.
 *
 * `create_target` != 0: create an empty file at `target` (inside the
 * target mount ns) before mounting -- a placeholder for a device-node
 * bind onto a fresh tmpfs (see ensure_target_file).
 *
 * `source` and `data` and `fstype` may be empty binaries; the NIF passes
 * NULL to mount(2) for any that are empty (kernel-idiomatic for
 * propagation changes, MS_MOVE, MS_REMOUNT, etc.). */
static ERL_NIF_TERM nif_mount(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	ErlNifUInt64 flags;
	if (!enif_get_uint64(env, argv[3], &flags))
		return enif_make_badarg(env);

	int create_target;
	if (!enif_get_int(env, argv[7], &create_target))
		return enif_make_badarg(env);

	char *source     = binary_to_cstr(env, argv[0]);
	char *target     = binary_to_cstr(env, argv[1]);
	char *fstype     = binary_to_cstr(env, argv[2]);
	char *data       = binary_to_cstr(env, argv[4]);
	char *ns_path    = binary_to_cstr(env, argv[5]);
	char *pidns_path = binary_to_cstr(env, argv[6]);

	if (!target || !fstype || !source || !data || !ns_path || !pidns_path) {
		enif_free(source);  enif_free(target);
		enif_free(fstype);  enif_free(data);
		enif_free(ns_path); enif_free(pidns_path);
		return enif_make_badarg(env);
	}

	const char *src_arg    = source[0] ? source : NULL;
	const char *fstype_arg = fstype[0] ? fstype : NULL;
	const char *data_arg   = data[0]   ? data   : NULL;

	ERL_NIF_TERM result;

	if (ns_path[0] == '\0') {
		/* BEAM namespace -- direct syscall, no thread. (pidns_path is
		 * only meaningful with a target mount ns, so it's ignored here.) */
		int cerr = create_target ? ensure_target_file(target) : 0;
		if (cerr)
			result = make_error(env, "create", cerr);
		else if (mount(src_arg, target, fstype_arg, (unsigned long)flags, data_arg) < 0)
			result = make_error(env, "mount", errno);
		else
			result = ok_atom(env);
	} else {
		/* Cross-namespace -- worker thread. */
		struct mount_job job = {
			.r = { .err = 0, .stage = NULL },
			.ns_path = ns_path,
			.source  = src_arg,
			.target  = target,
			.fstype  = fstype_arg,
			.flags   = (unsigned long)flags,
			.data    = data_arg,
			.pidns_path    = pidns_path,
			.create_target = create_target,
		};

		ErlNifTid tid;
		int rc = enif_thread_create("linx_mount", &tid, mount_worker, &job, NULL);
		if (rc != 0) {
			result = make_error(env, "thread", rc);
		} else {
			enif_thread_join(tid, NULL);
			result = job.r.err
				? make_error(env, job.r.stage, job.r.err)
				: ok_atom(env);
		}
	}

	enif_free(source);  enif_free(target);
	enif_free(fstype);  enif_free(data);
	enif_free(ns_path); enif_free(pidns_path);

	return result;
}

/* --- umount/3 ----------------------------------------------------------- */

/* Args: target (binary), flags (int), ns_path (binary). */
static ERL_NIF_TERM nif_umount(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	int flags;
	if (!enif_get_int(env, argv[1], &flags))
		return enif_make_badarg(env);

	char *target  = binary_to_cstr(env, argv[0]);
	char *ns_path = binary_to_cstr(env, argv[2]);

	if (!target || !ns_path) {
		enif_free(target);
		enif_free(ns_path);
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM result;

	if (ns_path[0] == '\0') {
		if (umount2(target, flags) < 0)
			result = make_error(env, "umount", errno);
		else
			result = ok_atom(env);
	} else {
		struct umount_job job = {
			.r = { .err = 0, .stage = NULL },
			.ns_path = ns_path,
			.target  = target,
			.flags   = flags,
		};

		ErlNifTid tid;
		int rc = enif_thread_create("linx_umount", &tid, umount_worker, &job, NULL);
		if (rc != 0) {
			result = make_error(env, "thread", rc);
		} else {
			enif_thread_join(tid, NULL);
			result = job.r.err
				? make_error(env, job.r.stage, job.r.err)
				: ok_atom(env);
		}
	}

	enif_free(target);
	enif_free(ns_path);

	return result;
}

/* --- pivot_root/3 ------------------------------------------------------- */

/* Args: new_root (binary), put_old (binary), ns_path (binary).
 *
 * Always runs on a worker thread -- even in the BEAM-namespace
 * case, because pivot_root requires the calling thread's CWD to be
 * inside new_root, and we don't want to change the BEAM's CWD. The
 * worker unshare(CLONE_FS)'s first so its chdir is isolated. */
static ERL_NIF_TERM nif_pivot_root(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	char *new_root = binary_to_cstr(env, argv[0]);
	char *put_old  = binary_to_cstr(env, argv[1]);
	char *ns_path  = binary_to_cstr(env, argv[2]);

	if (!new_root || !put_old || !ns_path) {
		enif_free(new_root);
		enif_free(put_old);
		enif_free(ns_path);
		return enif_make_badarg(env);
	}

	struct pivot_root_job job = {
		.r = { .err = 0, .stage = NULL },
		.ns_path  = ns_path,
		.new_root = new_root,
		.put_old  = put_old,
	};

	ERL_NIF_TERM result;
	ErlNifTid tid;
	int rc = enif_thread_create("linx_pivot_root", &tid, pivot_root_worker, &job, NULL);
	if (rc != 0) {
		result = make_error(env, "thread", rc);
	} else {
		enif_thread_join(tid, NULL);
		result = job.r.err
			? make_error(env, job.r.stage, job.r.err)
			: ok_atom(env);
	}

	enif_free(new_root);
	enif_free(put_old);
	enif_free(ns_path);

	return result;
}

/* --- NIF init ----------------------------------------------------------- */

/* mount/umount/pivot_root get the dirty-I/O-bound flag because
 * (a) the cross-namespace path spawns a thread + opens a file,
 * and (b) the underlying syscalls on real filesystems (NFS,
 * network mounts, large superblock reads) can take milliseconds.
 * version/0 stays on a normal scheduler -- it just returns a
 * string. */
static ErlNifFunc nif_funcs[] = {
	{ "version",    0, version,        0                          },
	{ "mount",      8, nif_mount,      ERL_NIF_DIRTY_JOB_IO_BOUND },
	{ "umount",     3, nif_umount,     ERL_NIF_DIRTY_JOB_IO_BOUND },
	{ "pivot_root", 3, nif_pivot_root, ERL_NIF_DIRTY_JOB_IO_BOUND },
};

ERL_NIF_INIT(Elixir.Linx.Mount.Native, nif_funcs, NULL, NULL, NULL, NULL)
