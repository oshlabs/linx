/*
 * linx_sysctl -- the NIF backing `Linx.Sysctl`'s cross-namespace
 * verbs.
 *
 * The host-side (caller's namespace) read/write/list path stays in
 * pure Elixir using File.read/1 + File.write/2 + File.ls/1 over
 * /proc/sys/. This NIF is only invoked when the caller passed an
 * `:in` option naming a different process's namespaces.
 *
 * Three operations, all sharing one shape:
 *
 *   - read_in_ns/2  -- read the file at PATH, return its bytes
 *                      (untrimmed; the Elixir layer trims).
 *   - write_in_ns/3 -- write DATA to the file at PATH.
 *   - list_in_ns/2  -- recursively walk the directory tree at ROOT,
 *                      returning a list of {path_binary,
 *                      value_binary} tuples for every readable
 *                      regular file. Unreadable files are silently
 *                      skipped (matches the pure-Elixir list/0
 *                      behaviour).
 *
 * NAMESPACE TARGETING
 * -------------------
 * Every operation takes an `ns_paths` argument: a list of binaries,
 * each naming a `/proc/<pid>/ns/<kind>` file (typically the full
 * stack: user, mount, UTS, IPC, net). The NIF opens every fd FIRST
 * (in the BEAM's own namespace, so the paths resolve correctly),
 * then spawns a throwaway pthread that:
 *
 *   1. unshare(CLONE_FS)        -- detach this thread's fs_struct
 *                                  from the BEAM's. Required before
 *                                  setns(CLONE_NEWNS); see the long
 *                                  comment in c_src/linx_mount.c.
 *   2. setns(fd, 0) for each    -- 0 lets the kernel autodetect the
 *      ns fd in order.            namespace type from the file.
 *   3. performs the I/O.
 *   4. exits the thread.
 *
 * setns(2) operates per-thread, so the BEAM's own scheduler threads
 * never enter the target namespace -- the throwaway thread's
 * namespace membership is destroyed when it exits.
 *
 * The Elixir layer always passes the namespaces in the canonical
 * order user -> mount -> UTS -> IPC -> net so a future unprivileged
 * caller works the same way as today's privileged BEAM (user ns
 * first means CAP_SYS_ADMIN is granted in that ns before we try to
 * enter mount).
 *
 * ERROR SHAPE
 * -----------
 * Every operation returns `:ok` (write), `{:ok, binary}` (read), or
 * `{:ok, [tuple]}` (list) on success, or
 * `{:error, {stage::atom, errno_atom | errno_int}}` on failure.
 * Stages:
 *
 *   - :open_ns   -- couldn't open one of the ns paths.
 *   - :unshare   -- unshare(CLONE_FS) failed (vanishingly rare).
 *   - :setns     -- couldn't enter one of the namespaces (typically
 *                   EPERM in the rootless case).
 *   - :thread    -- couldn't create the worker thread.
 *   - :read      -- the open() or read() inside the target ns failed.
 *   - :write     -- the open() or write() inside the target ns failed.
 *   - :list      -- the opendir() of the root failed inside the
 *                   target ns. Per-file failures during the walk are
 *                   skipped silently, not returned as :list errors.
 *
 * Common Linux errnos are mapped to POSIX-style atoms; any errno
 * not in the table falls back to the raw integer.
 */

#include <erl_nif.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>      /* setns, CLONE_FS */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LINX_SYSCTL_VERSION "linx_sysctl"

/* Per-file read cap. Sysctl files are bounded by the kernel; the
 * largest knobs we know of (lists of registered congestion-control
 * algorithms, available kernel symbols, etc.) stay well under 16K. */
#define LINX_SYSCTL_READ_MAX 65536

/* --- errno -> atom ------------------------------------------------------- */

static const char *errno_atom(int err)
{
	switch (err) {
	case EACCES:       return "eacces";
	case EAGAIN:       return "eagain";
	case EBADF:        return "ebadf";
	case EBUSY:        return "ebusy";
	case EEXIST:       return "eexist";
	case EFAULT:       return "efault";
	case EFBIG:        return "efbig";
	case EINVAL:       return "einval";
	case EIO:          return "eio";
	case EISDIR:       return "eisdir";
	case ELOOP:        return "eloop";
	case EMFILE:       return "emfile";
	case ENAMETOOLONG: return "enametoolong";
	case ENODEV:       return "enodev";
	case ENOENT:       return "enoent";
	case ENOMEM:       return "enomem";
	case ENOSPC:       return "enospc";
	case ENOSYS:       return "enosys";
	case ENOTDIR:      return "enotdir";
	case EOPNOTSUPP:   return "eopnotsupp";
	case EPERM:        return "eperm";
	case ERANGE:       return "erange";
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

/* --- input parsing ------------------------------------------------------- */

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

/* Convert an Elixir list of binaries into a heap-allocated C array
 * of null-terminated strings. Sets *out_n on success. Returns NULL
 * on any failure; on failure no allocations are leaked. */
static char **list_to_cstr_array(ErlNifEnv *env, ERL_NIF_TERM list, int *out_n)
{
	unsigned length;
	if (!enif_get_list_length(env, list, &length))
		return NULL;

	/* Bound the length (the multiply below could overflow) and treat an
	 * empty list as a valid zero-element array: enif_alloc(0) may return
	 * NULL, which the caller would misread as failure. */
	if (length > 4096)
		return NULL;

	char **arr = enif_alloc((length ? length : 1) * sizeof(char *));
	if (!arr)
		return NULL;

	ERL_NIF_TERM head;
	ERL_NIF_TERM tail = list;
	unsigned i = 0;
	while (enif_get_list_cell(env, tail, &head, &tail)) {
		arr[i] = binary_to_cstr(env, head);
		if (!arr[i]) {
			for (unsigned j = 0; j < i; j++)
				enif_free(arr[j]);
			enif_free(arr);
			return NULL;
		}
		i++;
	}

	*out_n = (int)length;
	return arr;
}

static void free_cstr_array(char **arr, int n)
{
	for (int i = 0; i < n; i++)
		enif_free(arr[i]);
	enif_free(arr);
}

/* --- the setns dance ----------------------------------------------------- */

/* Result-channel struct shared by every worker. */
struct ns_job_result {
	int err;            /* errno from the failing step, or 0 */
	const char *stage;  /* "open_ns" | "unshare" | "setns" | op-specific */
};

/* Open every ns_path in the BEAM's namespace and stash the fds in
 * out_fds (which must be sized for `n` entries). On failure, closes
 * any already-opened fds, sets r->{err,stage}, returns -1. */
static int open_ns_fds(struct ns_job_result *r, char **ns_paths, int n, int *out_fds)
{
	for (int i = 0; i < n; i++) {
		int fd = open(ns_paths[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			r->err = errno;
			r->stage = "open_ns";
			for (int j = 0; j < i; j++)
				close(out_fds[j]);
			return -1;
		}
		out_fds[i] = fd;
	}
	return 0;
}

/* Per the long comment in linx_mount.c: setns(CLONE_NEWNS) refuses
 * if the caller's fs_struct is shared. unshare(CLONE_FS) gives this
 * thread its own fs_struct; the thread is about to exit so the
 * unshare is discarded with it.
 *
 * Then setns each fd in order. The 0 in `setns(fd, 0)` means "let
 * the kernel infer the namespace type from the file" -- works for
 * every /proc/<pid>/ns/<kind> file. */
static int enter_ns_stack(struct ns_job_result *r, int *fds, int n)
{
	if (unshare(CLONE_FS) < 0) {
		r->err = errno;
		r->stage = "unshare";
		return -1;
	}

	for (int i = 0; i < n; i++) {
		if (setns(fds[i], 0) < 0) {
			r->err = errno;
			r->stage = "setns";
			return -1;
		}
	}

	return 0;
}

/* --- file I/O (inside the target ns) ------------------------------------- */

/* Read /proc/sys/... into a freshly-allocated buffer. Caller frees
 * with enif_free. Returns 0 on success, errno on failure (with
 * *out_buf left NULL). Caps reads at LINX_SYSCTL_READ_MAX. */
static int read_proc_file(const char *path, char **out_buf, size_t *out_len)
{
	*out_buf = NULL;
	*out_len = 0;

	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;

	size_t cap = 4096;
	char *buf = enif_alloc(cap);
	if (!buf) {
		close(fd);
		return ENOMEM;
	}

	size_t len = 0;
	for (;;) {
		if (len == cap) {
			if (cap >= LINX_SYSCTL_READ_MAX)
				break;
			size_t new_cap = cap * 2;
			if (new_cap > LINX_SYSCTL_READ_MAX)
				new_cap = LINX_SYSCTL_READ_MAX;
			char *grown = enif_realloc(buf, new_cap);
			if (!grown) {
				enif_free(buf);
				close(fd);
				return ENOMEM;
			}
			buf = grown;
			cap = new_cap;
		}

		ssize_t n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			enif_free(buf);
			close(fd);
			return e;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}

	close(fd);
	*out_buf = buf;
	*out_len = len;
	return 0;
}

/* Write data to /proc/sys/... in one go. Returns 0 on success,
 * errno on failure. */
static int write_proc_file(const char *path, const char *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;

	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, data + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			return e;
		}
		off += (size_t)n;
	}

	close(fd);
	return 0;
}

/* --- read_in_ns/2 worker ------------------------------------------------- */

struct read_job {
	struct ns_job_result r;

	/* in */
	const char *path;
	char **ns_paths;
	int n_ns;

	/* out */
	char *buf;
	size_t buf_len;
};

static void *read_worker(void *arg)
{
	struct read_job *j = arg;

	int *fds = enif_alloc((j->n_ns ? j->n_ns : 1) * sizeof(int));
	if (!fds) {
		j->r.err = ENOMEM;
		j->r.stage = "open_ns";
		return NULL;
	}

	if (open_ns_fds(&j->r, j->ns_paths, j->n_ns, fds) < 0) {
		enif_free(fds);
		return NULL;
	}

	if (enter_ns_stack(&j->r, fds, j->n_ns) < 0)
		goto cleanup;

	int e = read_proc_file(j->path, &j->buf, &j->buf_len);
	if (e != 0) {
		j->r.err = e;
		j->r.stage = "read";
	}

cleanup:
	for (int i = 0; i < j->n_ns; i++)
		close(fds[i]);
	enif_free(fds);
	return NULL;
}

/* Args: path (binary), ns_paths (list of binaries). */
static ERL_NIF_TERM nif_read(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	char *path = binary_to_cstr(env, argv[0]);
	if (!path)
		return enif_make_badarg(env);

	int n_ns = 0;
	char **ns_paths = list_to_cstr_array(env, argv[1], &n_ns);
	if (!ns_paths) {
		enif_free(path);
		return enif_make_badarg(env);
	}

	struct read_job job = {
		.r       = { .err = 0, .stage = NULL },
		.path    = path,
		.ns_paths = ns_paths,
		.n_ns    = n_ns,
		.buf     = NULL,
		.buf_len = 0,
	};

	ERL_NIF_TERM result;

	ErlNifTid tid;
	int rc = enif_thread_create("linx_sysctl_read", &tid, read_worker, &job, NULL);
	if (rc != 0) {
		result = make_error(env, "thread", rc);
	} else {
		enif_thread_join(tid, NULL);

		if (job.r.err) {
			result = make_error(env, job.r.stage, job.r.err);
		} else {
			ErlNifBinary bin;
			if (!enif_alloc_binary(job.buf_len, &bin)) {
				result = make_error(env, "read", ENOMEM);
			} else {
				memcpy(bin.data, job.buf, job.buf_len);
				result = enif_make_tuple2(env, ok_atom(env), enif_make_binary(env, &bin));
			}
		}
	}

	if (job.buf)
		enif_free(job.buf);
	enif_free(path);
	free_cstr_array(ns_paths, n_ns);

	return result;
}

/* --- write_in_ns/3 worker ------------------------------------------------ */

struct write_job {
	struct ns_job_result r;

	/* in */
	const char *path;
	const char *data;
	size_t data_len;
	char **ns_paths;
	int n_ns;
};

static void *write_worker(void *arg)
{
	struct write_job *j = arg;

	int *fds = enif_alloc((j->n_ns ? j->n_ns : 1) * sizeof(int));
	if (!fds) {
		j->r.err = ENOMEM;
		j->r.stage = "open_ns";
		return NULL;
	}

	if (open_ns_fds(&j->r, j->ns_paths, j->n_ns, fds) < 0) {
		enif_free(fds);
		return NULL;
	}

	if (enter_ns_stack(&j->r, fds, j->n_ns) < 0)
		goto cleanup;

	int e = write_proc_file(j->path, j->data, j->data_len);
	if (e != 0) {
		j->r.err = e;
		j->r.stage = "write";
	}

cleanup:
	for (int i = 0; i < j->n_ns; i++)
		close(fds[i]);
	enif_free(fds);
	return NULL;
}

/* Args: path (binary), data (binary), ns_paths (list of binaries). */
static ERL_NIF_TERM nif_write(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	ErlNifBinary data_bin;
	if (!enif_inspect_binary(env, argv[1], &data_bin))
		return enif_make_badarg(env);

	char *path = binary_to_cstr(env, argv[0]);
	if (!path)
		return enif_make_badarg(env);

	int n_ns = 0;
	char **ns_paths = list_to_cstr_array(env, argv[2], &n_ns);
	if (!ns_paths) {
		enif_free(path);
		return enif_make_badarg(env);
	}

	struct write_job job = {
		.r        = { .err = 0, .stage = NULL },
		.path     = path,
		.data     = (const char *)data_bin.data,
		.data_len = data_bin.size,
		.ns_paths = ns_paths,
		.n_ns     = n_ns,
	};

	ERL_NIF_TERM result;

	ErlNifTid tid;
	int rc = enif_thread_create("linx_sysctl_write", &tid, write_worker, &job, NULL);
	if (rc != 0)
		result = make_error(env, "thread", rc);
	else {
		enif_thread_join(tid, NULL);
		result = job.r.err
			? make_error(env, job.r.stage, job.r.err)
			: ok_atom(env);
	}

	enif_free(path);
	free_cstr_array(ns_paths, n_ns);

	return result;
}

/* --- list_in_ns/2 worker ------------------------------------------------- */

/* Linked-list node for a discovered entry. The walker accumulates
 * these; the NIF caller converts them into an Elixir list and frees
 * the chain. */
struct list_node {
	char *path;          /* enif_alloc'd, full /proc/sys/... */
	char *value;         /* enif_alloc'd, raw bytes (untrimmed) */
	size_t value_len;
	struct list_node *next;
};

static void free_list_nodes(struct list_node *head)
{
	while (head) {
		struct list_node *next = head->next;
		enif_free(head->path);
		enif_free(head->value);
		enif_free(head);
		head = next;
	}
}

/* Recursive walker. `buf` is a writable scratch buffer of at least
 * PATH_MAX bytes containing the current path at offset 0..len-1
 * (NUL-terminated at [len]). Appends entries to *head. Silently
 * skips unreadable directories and unreadable files (matches the
 * Elixir-side walker behaviour). */
static void walk_dir(char *buf, size_t len, size_t cap, struct list_node **head,
                     unsigned depth)
{
	/* /proc/sys is shallow; cap recursion so a pathological tree cannot
	 * blow the worker thread stack. */
	if (depth > 32)
		return;

	DIR *d = opendir(buf);
	if (!d)
		return;

	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		const char *name = e->d_name;
		if (name[0] == '.' &&
		    (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
			continue;

		size_t name_len = strlen(name);

		/* len + '/' + name + NUL */
		if (len + 1 + name_len + 1 > cap)
			continue;

		buf[len] = '/';
		memcpy(buf + len + 1, name, name_len);
		size_t new_len = len + 1 + name_len;
		buf[new_len] = '\0';

		struct stat st;
		if (stat(buf, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				walk_dir(buf, new_len, cap, head, depth + 1);
			} else if (S_ISREG(st.st_mode)) {
				char *value = NULL;
				size_t value_len = 0;
				if (read_proc_file(buf, &value, &value_len) == 0) {
					struct list_node *node = enif_alloc(sizeof(*node));
					char *path_copy = enif_alloc(new_len + 1);
					if (node && path_copy) {
						memcpy(path_copy, buf, new_len + 1);
						node->path = path_copy;
						node->value = value;
						node->value_len = value_len;
						node->next = *head;
						*head = node;
					} else {
						/* Allocation failure: drop this entry,
						 * keep walking. The list result is "best
						 * effort" already. */
						if (node)
							enif_free(node);
						if (path_copy)
							enif_free(path_copy);
						enif_free(value);
					}
				}
				/* read_proc_file failure: silent skip. */
			}
		}

		buf[len] = '\0';
	}

	closedir(d);
}

struct list_job {
	struct ns_job_result r;

	/* in */
	const char *root;
	char **ns_paths;
	int n_ns;

	/* out */
	struct list_node *entries;
};

static void *list_worker(void *arg)
{
	struct list_job *j = arg;

	int *fds = enif_alloc((j->n_ns ? j->n_ns : 1) * sizeof(int));
	if (!fds) {
		j->r.err = ENOMEM;
		j->r.stage = "open_ns";
		return NULL;
	}

	if (open_ns_fds(&j->r, j->ns_paths, j->n_ns, fds) < 0) {
		enif_free(fds);
		return NULL;
	}

	if (enter_ns_stack(&j->r, fds, j->n_ns) < 0)
		goto cleanup;

	/* Confirm the root opendir's before walking, so the caller
	 * gets an :enoent error for a non-existent prefix instead of
	 * silently returning []. */
	DIR *d = opendir(j->root);
	if (!d) {
		j->r.err = errno;
		j->r.stage = "list";
		goto cleanup;
	}
	closedir(d);

	char buf[PATH_MAX];
	size_t root_len = strlen(j->root);
	if (root_len >= sizeof(buf)) {
		j->r.err = ENAMETOOLONG;
		j->r.stage = "list";
		goto cleanup;
	}
	memcpy(buf, j->root, root_len + 1);

	walk_dir(buf, root_len, sizeof(buf), &j->entries, 0);

cleanup:
	for (int i = 0; i < j->n_ns; i++)
		close(fds[i]);
	enif_free(fds);
	return NULL;
}

/* Args: root_path (binary), ns_paths (list of binaries). */
static ERL_NIF_TERM nif_list(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	char *root = binary_to_cstr(env, argv[0]);
	if (!root)
		return enif_make_badarg(env);

	int n_ns = 0;
	char **ns_paths = list_to_cstr_array(env, argv[1], &n_ns);
	if (!ns_paths) {
		enif_free(root);
		return enif_make_badarg(env);
	}

	struct list_job job = {
		.r        = { .err = 0, .stage = NULL },
		.root     = root,
		.ns_paths = ns_paths,
		.n_ns     = n_ns,
		.entries  = NULL,
	};

	ERL_NIF_TERM result;

	ErlNifTid tid;
	int rc = enif_thread_create("linx_sysctl_list", &tid, list_worker, &job, NULL);
	if (rc != 0) {
		result = make_error(env, "thread", rc);
	} else {
		enif_thread_join(tid, NULL);

		if (job.r.err) {
			result = make_error(env, job.r.stage, job.r.err);
		} else {
			result = enif_make_list(env, 0);
			for (struct list_node *n = job.entries; n; n = n->next) {
				ErlNifBinary path_bin;
				size_t plen = strlen(n->path);
				if (!enif_alloc_binary(plen, &path_bin)) {
					result = make_error(env, "list", ENOMEM);
					break;
				}
				memcpy(path_bin.data, n->path, plen);

				ErlNifBinary value_bin;
				if (!enif_alloc_binary(n->value_len, &value_bin)) {
					enif_release_binary(&path_bin);
					result = make_error(env, "list", ENOMEM);
					break;
				}
				memcpy(value_bin.data, n->value, n->value_len);

				ERL_NIF_TERM tuple = enif_make_tuple2(
					env,
					enif_make_binary(env, &path_bin),
					enif_make_binary(env, &value_bin));
				result = enif_make_list_cell(env, tuple, result);
			}

			if (!job.r.err) {
				/* Wrap successful list in {:ok, list}. */
				result = enif_make_tuple2(env, ok_atom(env), result);
			}
		}
	}

	free_list_nodes(job.entries);
	enif_free(root);
	free_cstr_array(ns_paths, n_ns);

	return result;
}

/* --- version/0 ----------------------------------------------------------- */

static ERL_NIF_TERM version(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;
	(void)argv;
	return enif_make_string(env, LINX_SYSCTL_VERSION, ERL_NIF_LATIN1);
}

/* --- NIF init ------------------------------------------------------------ */

/* All three operations spawn a thread + do file I/O against procfs,
 * so they're dirty-I/O. version/0 stays on a normal scheduler. */
static ErlNifFunc nif_funcs[] = {
	{ "version",     0, version,   0                          },
	{ "read_in_ns",  2, nif_read,  ERL_NIF_DIRTY_JOB_IO_BOUND },
	{ "write_in_ns", 3, nif_write, ERL_NIF_DIRTY_JOB_IO_BOUND },
	{ "list_in_ns",  2, nif_list,  ERL_NIF_DIRTY_JOB_IO_BOUND },
};

ERL_NIF_INIT(Elixir.Linx.Sysctl.Native, nif_funcs, NULL, NULL, NULL, NULL)
