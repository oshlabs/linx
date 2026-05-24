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
#include <unistd.h>

/* Bumped per shipping milestone. */
#define LINX_MOUNT_VERSION "linx_mount 0.1.0 (M3)"

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
};

struct umount_job {
	struct ns_job_result r;
	const char *ns_path;
	const char *target;
	int flags;
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

static void *mount_worker(void *arg)
{
	struct mount_job *j = arg;

	int ns = enter_target_ns(&j->r, j->ns_path);
	if (ns < 0)
		return NULL;

	if (mount(j->source, j->target, j->fstype, j->flags, j->data) < 0) {
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

/* --- mount/6 ------------------------------------------------------------ */

/* Args: source, target, fstype, flags (uint64), data (binary), ns_path (binary).
 *
 * Empty `ns_path`: mount in the caller's namespace (no thread).
 * Non-empty `ns_path`: spawn a worker that enters that namespace.
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

	char *source  = binary_to_cstr(env, argv[0]);
	char *target  = binary_to_cstr(env, argv[1]);
	char *fstype  = binary_to_cstr(env, argv[2]);
	char *data    = binary_to_cstr(env, argv[4]);
	char *ns_path = binary_to_cstr(env, argv[5]);

	if (!target || !fstype || !source || !data || !ns_path) {
		enif_free(source);  enif_free(target);
		enif_free(fstype);  enif_free(data);
		enif_free(ns_path);
		return enif_make_badarg(env);
	}

	const char *src_arg    = source[0] ? source : NULL;
	const char *fstype_arg = fstype[0] ? fstype : NULL;
	const char *data_arg   = data[0]   ? data   : NULL;

	ERL_NIF_TERM result;

	if (ns_path[0] == '\0') {
		/* BEAM namespace -- direct syscall, no thread. */
		if (mount(src_arg, target, fstype_arg, (unsigned long)flags, data_arg) < 0)
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
	enif_free(ns_path);

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

/* --- NIF init ----------------------------------------------------------- */

/* mount/umount get the dirty-I/O-bound flag because (a) the
 * cross-namespace path spawns a thread + opens a file, and (b)
 * mount(2) on real filesystems (NFS, network mounts, large
 * superblock reads) can take milliseconds. version/0 stays on a
 * normal scheduler -- it just returns a string. */
static ErlNifFunc nif_funcs[] = {
	{ "version", 0, version,    0                          },
	{ "mount",   6, nif_mount,  ERL_NIF_DIRTY_JOB_IO_BOUND },
	{ "umount",  3, nif_umount, ERL_NIF_DIRTY_JOB_IO_BOUND },
};

ERL_NIF_INIT(Elixir.Linx.Mount.Native, nif_funcs, NULL, NULL, NULL, NULL)
