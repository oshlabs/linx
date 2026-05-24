/*
 * linx_process -- the Port binary backing `Linx.Process`.
 *
 * Linx.Process performs operations that cannot live inside the multithreaded
 * BEAM: clone(), setns(), fork() and execve(). Doing those in the BEAM
 * corrupts the VM (see silo's DESIGN.md for the reasoning), so they run in
 * this separate OS process, spawned via Port.open from Elixir.
 *
 * CONTROL CHANNEL
 * ---------------
 * The Erlang Port is opened with `:nouse_stdio` and `{:packet, 4}`. That
 * leaves fd 0/1/2 free for the workload (P4) and gives us fd 3 (BEAM -> us)
 * and fd 4 (us -> BEAM) for control traffic. Every message is a 4-byte
 * big-endian length prefix followed by an Erlang External Term Format
 * payload; ETF means the BEAM side needs no codec.
 *
 * TWO MODES
 * ---------
 * The BEAM sends one of two requests on fd 3:
 *
 *   {:spawn, %{argv, namespaces?, env?}}
 *     -- clone() a child with the requested CLONE_NEW* flags. The child
 *        is born in those fresh namespaces.
 *
 *   {:enter, %{target, argv, namespaces?, env?}}
 *     -- setns() the agent itself into the namespaces of host pid
 *        `target`, then fork(). The fork's child inherits those
 *        namespaces. `namespaces` chooses which of the target's
 *        namespaces to join; if absent, join all of them.
 *
 * Both modes share the rest of the protocol: the parent reports the host
 * pid as {:status, :spawned, _}, the child reaches the checkpoint and
 * the parent reports {:status, :ready, child_pid_inside_ns}, the BEAM
 * does any host-side setup and replies :proceed, the parent forwards
 * that to the child over an internal pipe, the child execve()s and the
 * parent reports {:status, :running, _}. On waitpid,
 * {:status, :exited, code} or {:status, :signaled, signum} terminates
 * the session. Pre-exec failures arrive as {:error, errno, stage}.
 *
 * THE RELAY
 * ---------
 * The agent process talks to the BEAM on fd 3/4. The cloned child does not
 * touch the BEAM channel; instead, two internal pipes carry the checkpoint
 * handshake:
 *
 *   `c2p` (child writes, parent reads, O_CLOEXEC on the child end)
 *     - One byte 'R' + 4-byte pidns-internal child pid -> :ready
 *     - One byte 'E' + 4-byte errno + 1-byte stage -> pre-exec error
 *     - EOF (the child execve'd successfully and CLOEXEC closed the pipe)
 *       -> :running
 *
 *   `p2c` (parent writes, child reads)
 *     - One byte 'P' -> proceed (release the checkpoint)
 *
 * The CLOEXEC trick on the c2p pipe is how the parent learns the
 * execve succeeded: nothing to write -- the kernel auto-closes the fd at
 * exec time, the parent sees EOF, and emits :running. If execve fails,
 * the child writes 'E' + errno + stage BEFORE the close-on-exec would
 * trigger, so the parent sees the failure with detail.
 *
 * EXIT CODES (of this agent, not the workload)
 * --------------------------------------------
 *   0   success (workload was reported on, agent terminating normally)
 *   1   I/O failure on the BEAM channel
 *   2   malformed request from the BEAM
 *   3   clone() failed
 *   4   internal pipe failure
 *
 * The workload's own exit code is reported as {:status, :exited, code}.
 */

#define _GNU_SOURCE
#include <ei.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CTL_IN	3
#define CTL_OUT	4

/* The clone child gets a private 1 MiB stack; it does not recurse, so this is
 * ample. clone() needs the *top* of the stack since it grows down. */
#define CHILD_STACK_SIZE (1024 * 1024)

/* Stage tags carried in 'E' errors from the child over the c2p pipe, mapped
 * by the parent into Erlang atoms for {:error, errno, stage}. Numbers are
 * an internal protocol; the strings are what the BEAM sees. */
enum stage {
	STAGE_EXECVE = 1,
	STAGE_STDIO = 2, /* per-fd plumbing in child: /dev/null, AF_UNIX connect, PTY ioctl */
	STAGE_CAP_DROP_BOUNDING = 3, /* prctl(PR_CAPBSET_DROP) failed in the child */
	STAGE_CAP_SET_THREAD = 4,    /* capset(2) failed in the child */
	STAGE_CAP_SET_AMBIENT = 5,   /* prctl(PR_CAP_AMBIENT_*) failed in the child */
};

static const char *stage_name(enum stage s)
{
	switch (s) {
	case STAGE_EXECVE:           return "execve";
	case STAGE_STDIO:            return "stdio";
	case STAGE_CAP_DROP_BOUNDING: return "cap_drop_bounding";
	case STAGE_CAP_SET_THREAD:   return "cap_set_thread";
	case STAGE_CAP_SET_AMBIENT:  return "cap_set_ambient";
	}
	return "unknown";
}

/* Namespace types the agent knows about. `atom` is the name on the Elixir
 * side and on the wire; `proc` is the filename under /proc/<pid>/ns/
 * (note that the mount namespace is `mnt` in procfs, not `mount`); `flag`
 * is the CLONE_NEW* bit for `clone(2)` in create mode.
 *
 * The list is in setns-safe order for enter mode: user first (so any
 * later setns calls have capabilities in the new user namespace), pid
 * last (it only takes effect on future fork()s, so must happen before
 * the fork). The order is irrelevant for create mode, where the flags
 * are OR'd into a single clone() call. */
struct ns_info {
	const char *atom;
	const char *proc;
	int flag;
};

static const struct ns_info NS_INFO[] = {
	{ "user",   "user",   CLONE_NEWUSER },
	{ "mount",  "mnt",    CLONE_NEWNS },
	{ "uts",    "uts",    CLONE_NEWUTS },
	{ "ipc",    "ipc",    CLONE_NEWIPC },
	{ "cgroup", "cgroup", CLONE_NEWCGROUP },
	{ "net",    "net",    CLONE_NEWNET },
	{ "time",   "time",   CLONE_NEWTIME },
	{ "pid",    "pid",    CLONE_NEWPID },
	{ NULL, NULL, 0 },
};

/* --- low-level I/O on fd 3/4 -------------------------------------------- */

static int read_exact(int fd, void *buf, size_t count)
{
	uint8_t *p = buf;
	while (count > 0) {
		ssize_t n = read(fd, p, count);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			errno = 0;
			return -1;
		}
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

static int write_exact(int fd, const void *buf, size_t count)
{
	const uint8_t *p = buf;
	while (count > 0) {
		ssize_t n = write(fd, p, count);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		count -= (size_t)n;
	}
	return 0;
}

/* Write one {:packet, 4} frame (4-byte big-endian length + body) to `fd`.
 * Used both for talking to BEAM on CTL_OUT and for the parent-to-child
 * checkpoint command stream on p2c (K2 capability commands). */
static int write_frame_fd(int fd, const void *buf, uint32_t len)
{
	uint8_t hdr[4] = {
		(uint8_t)(len >> 24), (uint8_t)(len >> 16),
		(uint8_t)(len >> 8),  (uint8_t)len,
	};
	if (write_exact(fd, hdr, sizeof hdr) < 0)
		return -1;
	return write_exact(fd, buf, len);
}

static int write_frame(const void *buf, uint32_t len)
{
	return write_frame_fd(CTL_OUT, buf, len);
}

/* Read one {:packet, 4} frame from `fd` into `buf`. Returns the message
 * length, or -1 on error/EOF. Used both for reading BEAM commands on
 * CTL_IN and for the child-side read of checkpoint commands on p2c. */
static ssize_t read_frame_fd(int fd, uint8_t *buf, size_t cap)
{
	uint8_t hdr[4];
	if (read_exact(fd, hdr, sizeof hdr) < 0)
		return -1;
	uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
		       ((uint32_t)hdr[2] << 8)  | (uint32_t)hdr[3];
	if (len > cap) {
		errno = EMSGSIZE;
		return -1;
	}
	if (read_exact(fd, buf, len) < 0)
		return -1;
	return (ssize_t)len;
}

static ssize_t read_frame(uint8_t *buf, size_t cap)
{
	return read_frame_fd(CTL_IN, buf, cap);
}

/* --- emitting outbound events on fd 4 ----------------------------------- */

static void emit_buff(ei_x_buff *x)
{
	/* EPIPE here is the normal "BEAM port closed underneath us" case --
	 * the surrounding loops handle the dropped channel, no stderr noise
	 * needed. Other errors stay loud so real bugs are visible. */
	if (write_frame(x->buff, (uint32_t)x->index) < 0 && errno != EPIPE)
		fprintf(stderr, "linx_process: write to BEAM: %s\n",
			strerror(errno));
	ei_x_free(x);
}

/* {:status, atom, integer}. */
static void emit_status_int(const char *kind, long value)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 3);
	ei_x_encode_atom(&x, "status");
	ei_x_encode_atom(&x, kind);
	ei_x_encode_long(&x, value);
	emit_buff(&x);
}

/* {:status, :running} -- no payload. */
static void emit_status_running(void)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 2);
	ei_x_encode_atom(&x, "status");
	ei_x_encode_atom(&x, "running");
	emit_buff(&x);
}

/* {:error, errno, stage_atom}. */
static void emit_error(int err, const char *stage)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 3);
	ei_x_encode_atom(&x, "error");
	ei_x_encode_long(&x, err);
	ei_x_encode_atom(&x, stage);
	emit_buff(&x);
}

/* --- the request: parse {:spawn, _} or {:enter, _} -------------------- */

enum req_mode { MODE_SPAWN, MODE_ENTER };

/* Per-fd stdio directive. INHERIT leaves the child's fd untouched; DEVNULL
 * dup2's /dev/null on; CONNECT_UNIX connects an AF_UNIX stream to `path`
 * and dup2's it on. (The whole-stdio PTY mode is handled separately --
 * see `pty` below -- since it shares one slave fd across 0/1/2 plus
 * setsid + TIOCSCTTY.) */
struct stdio_dir {
	enum stdio_kind {
		STDIO_INHERIT = 0,
		STDIO_DEVNULL,
		STDIO_CONNECT_UNIX,
	} kind;
	char *path; /* CONNECT_UNIX only; malloc'd */
};

/* The parsed shape of an inbound request.
 *   mode      -- which kind of request.
 *   target    -- enter mode: the host pid of the process whose namespaces
 *                we should join. Unused in spawn mode.
 *   argv/env  -- NULL-terminated arrays of malloc'd C strings (suitable
 *                for execve directly).
 *   ns_flags  -- OR of CLONE_NEW* flags. In spawn mode: which namespaces
 *                to create fresh; defaults to 0 (none) if :namespaces is
 *                omitted. In enter mode: which of the target's namespaces
 *                to join, when explicitly listed.
 *   all_ns    -- enter mode only: 1 if :namespaces was *not* listed in
 *                the request, meaning "join every namespace the target
 *                has". 0 if :namespaces was listed (use ns_flags).
 *   stdio[]   -- per-fd directive for fd 0/1/2. Defaults: INHERIT.
 *   pty       -- 1 if :stdio was the atom :pty; all three fds then point
 *                at a single PTY slave with the child as session leader.
 *                Mutually exclusive with `stdio[]`.  */
struct request {
	enum req_mode mode;
	pid_t target;
	char **argv;
	char **env;
	int ns_flags;
	int all_ns;
	struct stdio_dir stdio[3];
	int pty;
};

static void free_str_array(char **arr)
{
	if (!arr)
		return;
	for (char **p = arr; *p; p++)
		free(*p);
	free(arr);
}

static void free_request(struct request *r)
{
	free_str_array(r->argv);
	free_str_array(r->env);
	for (int i = 0; i < 3; i++)
		free(r->stdio[i].path);
}

/* Decode a binary or string ETF term into a freshly malloc'd NUL-terminated
 * C string. */
static int decode_string(const char *buf, int *idx, char **out)
{
	int type, sz;
	if (ei_get_type(buf, idx, &type, &sz) < 0)
		return -1;

	*out = malloc((size_t)sz + 1);
	if (!*out)
		return -1;

	if (type == ERL_BINARY_EXT) {
		long got;
		if (ei_decode_binary(buf, idx, *out, &got) < 0) {
			free(*out);
			*out = NULL;
			return -1;
		}
		(*out)[got] = '\0';
		return 0;
	}

	/* A string of all-ASCII bytes can arrive as STRING_EXT (a list of
	 * small ints in disguise). Decode either way. */
	if (ei_decode_string(buf, idx, *out) < 0) {
		free(*out);
		*out = NULL;
		return -1;
	}
	return 0;
}

/* Decode a list of binaries into a NULL-terminated argv-style array. */
static int decode_string_list(const char *buf, int *idx, char ***out)
{
	int arity;
	if (ei_decode_list_header(buf, idx, &arity) < 0)
		return -1;

	char **arr = calloc((size_t)arity + 1, sizeof(char *));
	if (!arr)
		return -1;

	for (int i = 0; i < arity; i++) {
		if (decode_string(buf, idx, &arr[i]) < 0) {
			free_str_array(arr);
			return -1;
		}
	}

	/* List tail: an empty list (NIL_EXT) unless arity was 0. */
	if (arity > 0) {
		int t, s;
		ei_get_type(buf, idx, &t, &s);
		if (t == ERL_NIL_EXT) {
			int dummy;
			ei_decode_list_header(buf, idx, &dummy);
		}
	}

	*out = arr;
	return 0;
}

/* Decode a list of namespace atoms into a CLONE_NEW* bitmask. */
static int decode_ns_list(const char *buf, int *idx, int *flags_out)
{
	int arity;
	if (ei_decode_list_header(buf, idx, &arity) < 0)
		return -1;

	int flags = 0;
	for (int i = 0; i < arity; i++) {
		char atom[MAXATOMLEN];
		if (ei_decode_atom(buf, idx, atom) < 0)
			return -1;

		int matched = 0;
		for (const struct ns_info *info = NS_INFO; info->atom; info++) {
			if (strcmp(atom, info->atom) == 0) {
				flags |= info->flag;
				matched = 1;
				break;
			}
		}
		if (!matched)
			return -1;
	}

	if (arity > 0) {
		int t, s;
		ei_get_type(buf, idx, &t, &s);
		if (t == ERL_NIL_EXT) {
			int dummy;
			ei_decode_list_header(buf, idx, &dummy);
		}
	}

	*flags_out = flags;
	return 0;
}

/* Decode a per-fd stdio directive, one of:
 *   :inherit       -- ERL_SMALL_ATOM_UTF8_EXT or similar
 *   :devnull
 *   {:connect_unix, "path"} -- a 2-tuple
 * Stores the result in `out`. Returns 0 on success, -1 on bad shape. */
static int decode_stdio_directive(const char *buf, int *idx, struct stdio_dir *out)
{
	int type, sz;
	if (ei_get_type(buf, idx, &type, &sz) < 0)
		return -1;

	if (type == ERL_SMALL_ATOM_UTF8_EXT || type == ERL_ATOM_UTF8_EXT ||
	    type == ERL_ATOM_EXT || type == ERL_SMALL_ATOM_EXT) {
		char atom[MAXATOMLEN];
		if (ei_decode_atom(buf, idx, atom) < 0)
			return -1;
		if (strcmp(atom, "inherit") == 0) {
			out->kind = STDIO_INHERIT;
			return 0;
		}
		if (strcmp(atom, "devnull") == 0) {
			out->kind = STDIO_DEVNULL;
			return 0;
		}
		return -1;
	}

	if (type == ERL_SMALL_TUPLE_EXT || type == ERL_LARGE_TUPLE_EXT) {
		int arity;
		if (ei_decode_tuple_header(buf, idx, &arity) < 0 || arity != 2)
			return -1;
		char tag[MAXATOMLEN];
		if (ei_decode_atom(buf, idx, &tag[0]) < 0)
			return -1;
		if (strcmp(tag, "connect_unix") != 0)
			return -1;
		if (decode_string(buf, idx, &out->path) < 0)
			return -1;
		out->kind = STDIO_CONNECT_UNIX;
		return 0;
	}

	return -1;
}

/* Decode the :stdio value, which is either an atom shorthand
 * (:inherit | :devnull | :pty) or a keyword list of `[stdin: dir,
 * stdout: dir, stderr: dir]`. Stores results into req->stdio[] and
 * req->pty. */
static int decode_stdio(const char *buf, int *idx, struct request *req)
{
	int type, sz;
	if (ei_get_type(buf, idx, &type, &sz) < 0)
		return -1;

	if (type == ERL_SMALL_ATOM_UTF8_EXT || type == ERL_ATOM_UTF8_EXT ||
	    type == ERL_ATOM_EXT || type == ERL_SMALL_ATOM_EXT) {
		char atom[MAXATOMLEN];
		if (ei_decode_atom(buf, idx, atom) < 0)
			return -1;
		if (strcmp(atom, "inherit") == 0) {
			/* default already; no change */
			return 0;
		}
		if (strcmp(atom, "devnull") == 0) {
			for (int i = 0; i < 3; i++)
				req->stdio[i].kind = STDIO_DEVNULL;
			return 0;
		}
		if (strcmp(atom, "pty") == 0) {
			req->pty = 1;
			return 0;
		}
		return -1;
	}

	/* A keyword list arrives as LIST_EXT of 2-tuples, ending in NIL_EXT. */
	int arity;
	if (ei_decode_list_header(buf, idx, &arity) < 0)
		return -1;

	for (int i = 0; i < arity; i++) {
		int tarity;
		if (ei_decode_tuple_header(buf, idx, &tarity) < 0 || tarity != 2)
			return -1;

		char key[MAXATOMLEN];
		if (ei_decode_atom(buf, idx, key) < 0)
			return -1;

		int fd = -1;
		if (strcmp(key, "stdin") == 0)  fd = 0;
		else if (strcmp(key, "stdout") == 0) fd = 1;
		else if (strcmp(key, "stderr") == 0) fd = 2;
		else return -1;

		if (decode_stdio_directive(buf, idx, &req->stdio[fd]) < 0)
			return -1;
	}

	if (arity > 0) {
		ei_get_type(buf, idx, &type, &sz);
		if (type == ERL_NIL_EXT) {
			int dummy;
			ei_decode_list_header(buf, idx, &dummy);
		}
	}

	return 0;
}

/* Decode the inbound request, either:
 *   {:spawn, %{argv, namespaces?, env?, stdio?}}
 *   {:enter, %{target, argv, namespaces?, env?, stdio?}}
 * Returns 0 on success, -1 on malformed input. */
static int decode_request(const uint8_t *buf, int len, struct request *req)
{
	(void)len;

	/* Sane defaults. all_ns is meaningful only in enter mode and is
	 * lowered the moment the caller mentioned :namespaces explicitly. */
	req->all_ns = 1;

	int idx = 0, version;
	if (ei_decode_version((const char *)buf, &idx, &version) < 0)
		return -1;

	int arity;
	if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 ||
	    arity != 2)
		return -1;

	char tag[MAXATOMLEN];
	if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
		return -1;

	if (strcmp(tag, "spawn") == 0) {
		req->mode = MODE_SPAWN;
	} else if (strcmp(tag, "enter") == 0) {
		req->mode = MODE_ENTER;
	} else {
		return -1;
	}

	if (ei_decode_map_header((const char *)buf, &idx, &arity) < 0)
		return -1;

	for (int i = 0; i < arity; i++) {
		char key[MAXATOMLEN];
		if (ei_decode_atom((const char *)buf, &idx, key) < 0)
			return -1;

		if (strcmp(key, "argv") == 0) {
			if (decode_string_list((const char *)buf, &idx, &req->argv) < 0)
				return -1;
		} else if (strcmp(key, "env") == 0) {
			if (decode_string_list((const char *)buf, &idx, &req->env) < 0)
				return -1;
		} else if (strcmp(key, "namespaces") == 0) {
			req->all_ns = 0;
			if (decode_ns_list((const char *)buf, &idx, &req->ns_flags) < 0)
				return -1;
		} else if (strcmp(key, "target") == 0) {
			long t;
			if (ei_decode_long((const char *)buf, &idx, &t) < 0 ||
			    t <= 0)
				return -1;
			req->target = (pid_t)t;
		} else if (strcmp(key, "stdio") == 0) {
			if (decode_stdio((const char *)buf, &idx, req) < 0)
				return -1;
		} else {
			/* Skip unknown keys -- the BEAM may carry extras we
			 * don't yet understand; future-compatibility. */
			ei_skip_term((const char *)buf, &idx);
		}
	}

	if (!req->argv || !req->argv[0])
		return -1;
	if (req->mode == MODE_ENTER && req->target <= 0)
		return -1;

	return 0;
}

/* --- entering an existing target's namespaces (P3) --------------------- */

/* Walk the canonical NS_INFO list and join the target's namespaces. The
 * order in NS_INFO is setns-safe: user first (so later calls have the
 * capabilities a fresh user namespace grants), pid last (it only takes
 * effect on future fork()s, so must precede the fork below).
 *
 * Two modes:
 *   req->all_ns == 1 -- :namespaces was *not* in the request. Join every
 *     namespace the target has; silently skip a type whose
 *     /proc/<pid>/ns file is missing (e.g. CLONE_NEWTIME on an old
 *     kernel).
 *   req->all_ns == 0 -- :namespaces was listed. Join exactly the ones
 *     whose flag is set in req->ns_flags; any failure surfaces as
 *     {:error, errno, :open_ns | :setns} on fd 4.
 *
 * On a real failure (in either mode), emits :error and returns -1. */
/* The agent and target share a given namespace iff their /proc/<pid>/ns/<type>
 * files point at the same inode. Used to skip no-op setns calls -- entering
 * the namespace you're already in returns EINVAL on some kernels (notably
 * the user namespace), and is wasteful even where it doesn't. */
static int same_namespace(pid_t target, const char *proc_name)
{
	char self_path[64], target_path[64];
	snprintf(self_path, sizeof self_path, "/proc/self/ns/%s", proc_name);
	snprintf(target_path, sizeof target_path, "/proc/%d/ns/%s",
		 (int)target, proc_name);

	struct stat ss, ts;
	if (stat(self_path, &ss) < 0 || stat(target_path, &ts) < 0)
		return 0;
	return ss.st_ino == ts.st_ino && ss.st_dev == ts.st_dev;
}

static int enter_target_namespaces(const struct request *req)
{
	for (const struct ns_info *info = NS_INFO; info->atom; info++) {
		if (!req->all_ns && !(req->ns_flags & info->flag))
			continue;

		/* Already in the target's namespace of this type -- no setns
		 * needed; some kernels return EINVAL for setns-to-self. */
		if (same_namespace(req->target, info->proc))
			continue;

		char path[64];
		snprintf(path, sizeof path, "/proc/%d/ns/%s",
			 (int)req->target, info->proc);

		int fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			if (req->all_ns && errno == ENOENT)
				continue;
			/* Error stage names the namespace so the BEAM-side
			 * error can pinpoint which type failed -- e.g.
			 * :open_ns_time, :setns_user. */
			char stage[32];
			snprintf(stage, sizeof stage, "open_ns_%s", info->atom);
			emit_error(errno, stage);
			return -1;
		}

		if (setns(fd, 0) < 0) {
			int err = errno;
			close(fd);
			char stage[32];
			snprintf(stage, sizeof stage, "setns_%s", info->atom);
			emit_error(err, stage);
			return -1;
		}
		close(fd);
	}
	return 0;
}

/* --- the cloned child --------------------------------------------------- */

/* Arguments handed to child_fn via clone's `arg` pointer.
 *
 * stdio    -- per-fd directives. The child applies them after :proceed
 *             but before execve.
 * pty_slave -- if >= 0, the child closes pty_master, sets up a new
 *              session (setsid), makes pty_slave its controlling TTY
 *              (TIOCSCTTY), and dups it onto fd 0/1/2. The per-fd
 *              stdio[] is ignored in PTY mode.
 * pty_master -- the parent's end of the PTY pair. The child closes it
 *              before execve. */
struct child_args {
	int c2p_w; /* child writes events here (CLOEXEC) */
	int p2c_r; /* child reads commands here */
	int c2p_r; /* parent's read end -- child closes on entry */
	int p2c_w; /* parent's write end -- child closes on entry */
	char **argv;
	char **env;
	struct stdio_dir stdio[3];
	int pty_master;
	int pty_slave;
};

/* Report an in-child pre-exec failure on the c2p pipe ('E' tag + 4-byte
 * errno + 1-byte stage code) and exit. Called when something between the
 * checkpoint and execve fails -- e.g. opening /dev/null, connecting to
 * the AF_UNIX path, ioctl on the PTY slave. */
__attribute__((noreturn))
static void child_fail(int c2p_w, int err, enum stage stage)
{
	uint8_t fail[6];
	fail[0] = 'E';
	fail[1] = (uint8_t)(err >> 24);
	fail[2] = (uint8_t)(err >> 16);
	fail[3] = (uint8_t)(err >> 8);
	fail[4] = (uint8_t)err;
	fail[5] = (uint8_t)stage;
	(void)write_exact(c2p_w, fail, sizeof fail);
	_exit(127);
}

/* Apply stdio plumbing in the child before execve. Returns 0 on success,
 * -1 on failure (caller should report and exit). */
static int apply_stdio(struct child_args *ca)
{
	if (ca->pty_slave >= 0) {
		/* Whole-stdio PTY mode. Drop the master copy the child
		 * inherited from the fork, become session leader, take the
		 * PTY slave as the controlling terminal, then dup it onto
		 * fd 0/1/2. */
		if (ca->pty_master >= 0)
			close(ca->pty_master);
		if (setsid() < 0)
			return -1;
		if (ioctl(ca->pty_slave, TIOCSCTTY, 0) < 0)
			return -1;
		for (int fd = 0; fd < 3; fd++) {
			if (dup2(ca->pty_slave, fd) < 0)
				return -1;
		}
		if (ca->pty_slave > 2)
			close(ca->pty_slave);
		return 0;
	}

	/* Per-fd directives. */
	for (int fd = 0; fd < 3; fd++) {
		switch (ca->stdio[fd].kind) {
		case STDIO_INHERIT:
			break;

		case STDIO_DEVNULL: {
			int n = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (n < 0)
				return -1;
			if (dup2(n, fd) < 0) {
				close(n);
				return -1;
			}
			close(n);
			break;
		}

		case STDIO_CONNECT_UNIX: {
			int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
			if (s < 0)
				return -1;
			struct sockaddr_un addr = { .sun_family = AF_UNIX };
			size_t len = strlen(ca->stdio[fd].path);
			if (len >= sizeof addr.sun_path) {
				close(s);
				errno = ENAMETOOLONG;
				return -1;
			}
			memcpy(addr.sun_path, ca->stdio[fd].path, len + 1);
			if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
				int e = errno;
				close(s);
				errno = e;
				return -1;
			}
			if (dup2(s, fd) < 0) {
				int e = errno;
				close(s);
				errno = e;
				return -1;
			}
			close(s);
			break;
		}
		}
	}
	return 0;
}

/* --- K2 capability syscalls (per-thread, called from the child) -------- */

/* Drop every bit set in `mask` from the calling thread's bounding set via
 * prctl(PR_CAPBSET_DROP). One-way; returns -1 with errno on first failure
 * (we don't try to continue past a denied drop -- the caller treats this
 * as a pre-exec failure and exits). */
static int apply_cap_drop_bounding(uint64_t mask)
{
	for (int bit = 0; bit < 64; bit++) {
		if (mask & ((uint64_t)1 << bit)) {
			if (prctl(PR_CAPBSET_DROP, (unsigned long)bit, 0UL, 0UL, 0UL) < 0)
				return -1;
		}
	}
	return 0;
}

/* Set the calling thread's effective/permitted/inheritable sets via
 * capset(2). We use the kernel's v3 64-bit layout (two cap_data_struct
 * entries, low 32 bits in [0], high 32 bits in [1]). syscall(SYS_capset)
 * is used directly rather than linking libcap. */
static int apply_cap_set_thread(uint64_t e, uint64_t p, uint64_t i)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0, /* current thread */
	};
	struct __user_cap_data_struct data[2];
	data[0].effective   = (uint32_t)(e & 0xFFFFFFFFu);
	data[0].permitted   = (uint32_t)(p & 0xFFFFFFFFu);
	data[0].inheritable = (uint32_t)(i & 0xFFFFFFFFu);
	data[1].effective   = (uint32_t)(e >> 32);
	data[1].permitted   = (uint32_t)(p >> 32);
	data[1].inheritable = (uint32_t)(i >> 32);
	return (int)syscall(SYS_capset, &hdr, data);
}

/* Replace the calling thread's ambient set with exactly the caps in
 * `mask`. The kernel only exposes per-cap RAISE/LOWER plus a global
 * CLEAR_ALL, so the natural shape is "clear, then raise the desired
 * caps." Requires Linux 4.3+. */
static int apply_cap_set_ambient(uint64_t mask)
{
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL) < 0)
		return -1;
	for (int bit = 0; bit < 64; bit++) {
		if (mask & ((uint64_t)1 << bit)) {
			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
				  (unsigned long)bit, 0UL, 0UL) < 0)
				return -1;
		}
	}
	return 0;
}

/* Read + dispatch one checkpoint-window command frame from `p2c_r`.
 * Returns:
 *    0 -- a cap_* command was applied successfully; caller should loop
 *         and read the next frame.
 *    1 -- :proceed received; caller should fall through to apply_stdio
 *         + execve.
 *   -1 -- read error or EOF (abort path); caller should _exit(102).
 *   -2 -- protocol error (unknown command or malformed frame); caller
 *         should _exit(103).
 *
 * On a cap-apply syscall failure, this function child_fail's directly
 * with the appropriate stage; it does not return. */
static int child_read_command(int p2c_r, int c2p_w)
{
	uint8_t buf[256];
	ssize_t len = read_frame_fd(p2c_r, buf, sizeof buf);
	if (len < 0) {
		/* EOF (errno == 0) means the parent closed p2c without
		 * sending :proceed -- the abort path. Real read errors
		 * land here too; both should _exit(102). */
		return -1;
	}

	int idx = 0, version;
	if (ei_decode_version((const char *)buf, &idx, &version) < 0)
		return -2;

	int type, size;
	if (ei_get_type((const char *)buf, &idx, &type, &size) < 0)
		return -2;

	/* Bare :proceed atom -- the sentinel that ends the loop. */
	if (type == ERL_SMALL_ATOM_UTF8_EXT || type == ERL_ATOM_UTF8_EXT ||
	    type == ERL_ATOM_EXT || type == ERL_SMALL_ATOM_EXT) {
		char atom[MAXATOMLEN];
		if (ei_decode_atom((const char *)buf, &idx, atom) < 0)
			return -2;
		if (strcmp(atom, "proceed") == 0)
			return 1;
		return -2;
	}

	/* Tuple commands: {:cap_drop_bounding, mask},
	 * {:cap_set_thread, e, p, i}, {:cap_set_ambient, mask}. */
	if (type != ERL_SMALL_TUPLE_EXT && type != ERL_LARGE_TUPLE_EXT)
		return -2;

	int arity;
	if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0)
		return -2;

	char tag[MAXATOMLEN];
	if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
		return -2;

	if (strcmp(tag, "cap_drop_bounding") == 0 && arity == 2) {
		unsigned long long mask;
		if (ei_decode_ulonglong((const char *)buf, &idx, &mask) < 0)
			return -2;
		if (apply_cap_drop_bounding((uint64_t)mask) < 0)
			child_fail(c2p_w, errno, STAGE_CAP_DROP_BOUNDING);
		return 0;
	}

	if (strcmp(tag, "cap_set_thread") == 0 && arity == 4) {
		unsigned long long e, p, i;
		if (ei_decode_ulonglong((const char *)buf, &idx, &e) < 0 ||
		    ei_decode_ulonglong((const char *)buf, &idx, &p) < 0 ||
		    ei_decode_ulonglong((const char *)buf, &idx, &i) < 0)
			return -2;
		if (apply_cap_set_thread((uint64_t)e, (uint64_t)p, (uint64_t)i) < 0)
			child_fail(c2p_w, errno, STAGE_CAP_SET_THREAD);
		return 0;
	}

	if (strcmp(tag, "cap_set_ambient") == 0 && arity == 2) {
		unsigned long long mask;
		if (ei_decode_ulonglong((const char *)buf, &idx, &mask) < 0)
			return -2;
		if (apply_cap_set_ambient((uint64_t)mask) < 0)
			child_fail(c2p_w, errno, STAGE_CAP_SET_AMBIENT);
		return 0;
	}

	return -2;
}

/* Inside the cloned child: announce :ready (with our pidns-internal pid),
 * loop on checkpoint commands until :proceed, plumb stdio, exec. Any
 * pre-exec failure is reported as 'E' on the c2p pipe and the child exits
 * non-zero. */
static int child_fn(void *arg)
{
	struct child_args *ca = arg;

	/* Close the parent's ends of our internal pipes. clone(2) gives
	 * the child the full inherited fd table -- including the parent's
	 * c2p[0] (read end) and p2c[1] (write end) -- and unless we close
	 * them here, closing them in the parent leaves the kernel still
	 * counting one writer (us) on p2c, so the child's read on p2c_r
	 * would never see EOF if the parent abandons the session. That
	 * matters for the :abort path. (The fork() branch in main does
	 * these closes explicitly before calling child_fn; here we
	 * centralise them so both paths converge on the same shape.) */
	if (ca->c2p_r >= 0) close(ca->c2p_r);
	if (ca->p2c_w >= 0) close(ca->p2c_w);

	/* :ready -- send 'R' + pidns-internal pid (uint32 big-endian). */
	uint8_t ready[5];
	ready[0] = 'R';
	uint32_t pid = (uint32_t)getpid();
	ready[1] = (uint8_t)(pid >> 24);
	ready[2] = (uint8_t)(pid >> 16);
	ready[3] = (uint8_t)(pid >> 8);
	ready[4] = (uint8_t)pid;
	if (write_exact(ca->c2p_w, ready, sizeof ready) < 0)
		_exit(101);

	/* Loop on checkpoint-window commands. {:cap_*, _} tuples apply
	 * per-thread cap syscalls (K2); :proceed breaks the loop. A
	 * closed p2c (EOF) is the :abort path -- exit 102. */
	for (;;) {
		int r = child_read_command(ca->p2c_r, ca->c2p_w);
		if (r == 1) break;        /* :proceed */
		if (r == 0) continue;     /* cap_* applied, next command */
		if (r == -1) _exit(102);  /* EOF / abort */
		_exit(103);               /* protocol error */
	}

	/* Stdio plumbing (P4): dup2 /dev/null or an AF_UNIX socket onto
	 * 0/1/2, or set up the PTY slave as a controlling tty. */
	if (apply_stdio(ca) < 0)
		child_fail(ca->c2p_w, errno, STAGE_STDIO);

	/* Unblock SIGCHLD before execve so the workload sees default
	 * signal-mask semantics -- the agent had it blocked so signalfd
	 * could capture it, but the child inherits the mask across
	 * execve and would surprise the workload otherwise. */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	execve(ca->argv[0], ca->argv, ca->env);

	/* execve returned -> failure. */
	child_fail(ca->c2p_w, errno, STAGE_EXECVE);
}

/* --- the relay (parent of clone) ---------------------------------------- */

/* Drain c2p until either: the child reported success (EOF on the pipe
 * because of CLOEXEC after execve), or a pre-exec error ('E' tag).
 *
 * Returns 0 on success (the workload is running). Returns 1 on
 * pre-exec error (already emitted on fd 4). Returns -1 on relay failure. */
static int await_exec_outcome(int c2p_r)
{
	uint8_t tag;
	ssize_t n = read(c2p_r, &tag, 1);
	if (n == 0)
		return 0;                /* EOF -> execve succeeded */
	if (n < 0)
		return -1;

	if (tag != 'E')
		return -1;

	uint8_t payload[5];
	if (read_exact(c2p_r, payload, sizeof payload) < 0)
		return -1;

	int err = ((int)payload[0] << 24) | ((int)payload[1] << 16) |
		  ((int)payload[2] << 8)  | (int)payload[3];
	enum stage s = (enum stage)payload[4];
	emit_error(err, stage_name(s));
	return 1;
}

/* Block on the BEAM control channel until :proceed (or :abort) arrives,
 * handling pre-proceed commands valid during the checkpoint window:
 *
 *   * {:pty_winsize, _} -- applied in-agent on `pty_master` via TIOCSWINSZ.
 *     The child doesn't need to know.
 *
 *   * {:cap_drop_bounding, _}, {:cap_set_thread, _, _, _},
 *     {:cap_set_ambient, _} -- K2 capability commands. The agent can't
 *     apply these on the child's behalf (capset/prctl are per-thread),
 *     so we forward the frame verbatim to `p2c_w` and the child applies
 *     it before execve.
 *
 *   * :proceed -- forwarded as a frame to `p2c_w` (the sentinel that
 *     ends the child's checkpoint-command loop). Returns 0.
 *
 *   * :abort -- caller closes `p2c_w` so the child sees EOF and _exits.
 *     Returns 1.
 *
 * `pty_master` is the agent's master fd in PTY mode (or -1 otherwise).
 * `p2c_w` is the write end of the agent->child unblock pipe.
 * `c2p_r` is the read end of the child->agent status pipe; we poll it
 * here so a cap-command failure in the child surfaces as a
 * {:linx_process, :error, errno, stage} on the BEAM even though the
 * checkpoint hasn't proceeded yet. (Pre-K2, c2p was only consumed by
 * await_exec_outcome after :proceed.)
 *
 * {:signal, _} and {:pty_in, _} are post-running-only and treated as
 * protocol errors if they show up here.
 *
 * Returns:
 *   0   -- :proceed forwarded to child; caller closes p2c_w and waits
 *          for execve outcome on c2p.
 *   1   -- :abort received; caller closes p2c_w to deliver EOF to the
 *          child, reaps, and emits {:status, :aborted, child_pid}.
 *  -1   -- read/parse error, unknown command, or child failure during
 *          a cap command (emit_error already called for that case). */
static int await_proceed(int pty_master, int p2c_w, int c2p_r)
{
	for (;;) {
		/* Multiplex BEAM commands on CTL_IN with child failure
		 * notifications on c2p_r. The latter is only relevant
		 * during the K2 cap-command window -- a cap_* command
		 * that the child can't apply (EPERM on capset, etc.)
		 * lands here as 'E' + payload, ahead of any :proceed. */
		struct pollfd pfds[2] = {
			{ .fd = CTL_IN, .events = POLLIN },
			{ .fd = c2p_r,  .events = POLLIN },
		};

		int rc = poll(pfds, 2, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (pfds[1].revents & (POLLIN | POLLHUP)) {
			/* Child wrote 'E' + payload (or unexpectedly
			 * closed). Drain the error and surface it; main
			 * cleans up. */
			uint8_t tag;
			ssize_t n = read(c2p_r, &tag, 1);
			if (n <= 0)
				return -1;
			if (tag != 'E')
				return -1;
			uint8_t payload[5];
			if (read_exact(c2p_r, payload, sizeof payload) < 0)
				return -1;
			int err = ((int)payload[0] << 24) |
				  ((int)payload[1] << 16) |
				  ((int)payload[2] << 8)  |
				  (int)payload[3];
			enum stage s = (enum stage)payload[4];
			emit_error(err, stage_name(s));
			return -1;
		}

		if (!(pfds[0].revents & POLLIN)) {
			/* CTL_IN closed or errored -- the BEAM port is
			 * gone; treat as -1 (main cleans up). */
			if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
				return -1;
			continue;
		}

		uint8_t buf[256];
		ssize_t len = read_frame(buf, sizeof buf);
		if (len < 0)
			return -1;

		int idx = 0, version;
		if (ei_decode_version((const char *)buf, &idx, &version) < 0)
			return -1;

		int type, size;
		if (ei_get_type((const char *)buf, &idx, &type, &size) < 0)
			return -1;

		if (type == ERL_SMALL_ATOM_UTF8_EXT || type == ERL_ATOM_UTF8_EXT ||
		    type == ERL_ATOM_EXT || type == ERL_SMALL_ATOM_EXT) {
			char atom[MAXATOMLEN];
			if (ei_decode_atom((const char *)buf, &idx, atom) < 0)
				return -1;
			if (strcmp(atom, "proceed") == 0) {
				/* Forward the :proceed frame to the child as
				 * the sentinel that ends its command loop. */
				if (write_frame_fd(p2c_w, buf, (uint32_t)len) < 0)
					return -1;
				return 0;
			}
			if (strcmp(atom, "abort") == 0)
				return 1;
			return -1;
		}

		/* Tuple commands valid at the checkpoint:
		 *   {:pty_winsize, _}             -- applied in-agent
		 *   {:cap_drop_bounding, _}       -- forwarded to child
		 *   {:cap_set_thread, _, _, _}    -- forwarded to child
		 *   {:cap_set_ambient, _}         -- forwarded to child */
		if (type != ERL_SMALL_TUPLE_EXT && type != ERL_LARGE_TUPLE_EXT)
			return -1;

		int arity;
		if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0)
			return -1;

		char tag[MAXATOMLEN];
		if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
			return -1;

		/* Cap commands -- forward the frame verbatim. The child
		 * decodes and applies; failures come back on c2p as 'E'
		 * + payload (handled by await_exec_outcome later). */
		if ((strcmp(tag, "cap_drop_bounding") == 0 && arity == 2) ||
		    (strcmp(tag, "cap_set_thread")    == 0 && arity == 4) ||
		    (strcmp(tag, "cap_set_ambient")   == 0 && arity == 2)) {
			if (write_frame_fd(p2c_w, buf, (uint32_t)len) < 0)
				return -1;
			continue;
		}

		if (strcmp(tag, "pty_winsize") != 0 || arity != 2)
			return -1;

		int tarity;
		if (ei_decode_tuple_header((const char *)buf, &idx, &tarity) < 0 ||
		    tarity != 4)
			return -1;

		long rows, cols, xpix, ypix;
		if (ei_decode_long((const char *)buf, &idx, &rows) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &cols) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &xpix) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &ypix) < 0)
			return -1;

		if (pty_master >= 0 &&
		    rows >= 0 && cols >= 0 && xpix >= 0 && ypix >= 0 &&
		    rows <= 0xFFFF && cols <= 0xFFFF &&
		    xpix <= 0xFFFF && ypix <= 0xFFFF) {
			struct winsize ws = {
				.ws_row    = (unsigned short)rows,
				.ws_col    = (unsigned short)cols,
				.ws_xpixel = (unsigned short)xpix,
				.ws_ypixel = (unsigned short)ypix,
			};
			(void)ioctl(pty_master, TIOCSWINSZ, &ws);
		}
		/* Loop for the next command. */
	}
}

enum post_running_cmd_kind {
	CMD_NONE = 0,
	CMD_SIGNAL,
	CMD_PTY_IN,
	CMD_PTY_WINSIZE,
};

struct post_running_cmd {
	enum post_running_cmd_kind kind;
	int signum;        /* CMD_SIGNAL */
	uint8_t *bytes;    /* CMD_PTY_IN -- malloc'd; caller frees */
	size_t bytes_len;
	/* CMD_PTY_WINSIZE -- struct winsize is unsigned short per field;
	 * we store as unsigned so decode bounds-checks are clear. */
	unsigned ws_rows, ws_cols, ws_xpix, ws_ypix;
};

/* Decode one {:packet, 4} ETF frame from the BEAM (post-:running):
 *   {:signal, n}      -- forward to the workload
 *   {:pty_in, binary} -- write to the PTY master (PTY mode only)
 *
 * Returns 0 on success (cmd filled), -1 on parse failure (cmd untouched),
 * -2 on EOF/IO error so the caller can distinguish "BEAM went away". */
static int read_post_running_command(struct post_running_cmd *cmd)
{
	uint8_t buf[8192];
	ssize_t len = read_frame(buf, sizeof buf);
	if (len < 0)
		return -2;

	int idx = 0, version;
	if (ei_decode_version((const char *)buf, &idx, &version) < 0)
		return -1;

	int arity;
	if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 ||
	    arity != 2)
		return -1;

	char tag[MAXATOMLEN];
	if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
		return -1;

	if (strcmp(tag, "signal") == 0) {
		long signum;
		if (ei_decode_long((const char *)buf, &idx, &signum) < 0)
			return -1;
		if (signum <= 0 || signum > 64)
			return -1;
		cmd->kind = CMD_SIGNAL;
		cmd->signum = (int)signum;
		return 0;
	}

	if (strcmp(tag, "pty_in") == 0) {
		int type, sz;
		if (ei_get_type((const char *)buf, &idx, &type, &sz) < 0)
			return -1;
		if (type != ERL_BINARY_EXT)
			return -1;
		cmd->bytes = malloc((size_t)sz);
		if (!cmd->bytes)
			return -1;
		long got;
		if (ei_decode_binary((const char *)buf, &idx,
				     cmd->bytes, &got) < 0) {
			free(cmd->bytes);
			cmd->bytes = NULL;
			return -1;
		}
		cmd->bytes_len = (size_t)got;
		cmd->kind = CMD_PTY_IN;
		return 0;
	}

	if (strcmp(tag, "pty_winsize") == 0) {
		int tarity;
		if (ei_decode_tuple_header((const char *)buf, &idx, &tarity) < 0 ||
		    tarity != 4)
			return -1;

		long rows, cols, xpix, ypix;
		if (ei_decode_long((const char *)buf, &idx, &rows) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &cols) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &xpix) < 0 ||
		    ei_decode_long((const char *)buf, &idx, &ypix) < 0)
			return -1;
		if (rows < 0 || cols < 0 || xpix < 0 || ypix < 0 ||
		    rows > 0xFFFF || cols > 0xFFFF ||
		    xpix > 0xFFFF || ypix > 0xFFFF)
			return -1;

		cmd->kind = CMD_PTY_WINSIZE;
		cmd->ws_rows = (unsigned)rows;
		cmd->ws_cols = (unsigned)cols;
		cmd->ws_xpix = (unsigned)xpix;
		cmd->ws_ypix = (unsigned)ypix;
		return 0;
	}

	return -1;
}

/* Emit {:pty_out, binary} on fd 4. */
static void emit_pty_out(const uint8_t *bytes, size_t n)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 2);
	ei_x_encode_atom(&x, "pty_out");
	ei_x_encode_binary(&x, bytes, (long)n);
	emit_buff(&x);
}

/* The post-exec supervise loop: forward {:signal, n} from the BEAM to
 * the workload, reap the workload via SIGCHLD-on-signalfd, and (in PTY
 * mode) shuttle bytes between the BEAM and the PTY master fd. Emits the
 * terminal event ({:status, :exited, _} or {:status, :signaled, _}) and
 * returns when the child is gone.
 *
 * SIGCHLD is captured via signalfd (set up in main, blocked from normal
 * delivery in the agent's signal mask); the child unblocks SIGCHLD again
 * before execve, so the workload sees default semantics.
 *
 * `pty_master` is -1 when stdio is not :pty; otherwise it's the parent's
 * end of the PTY pair created before clone/fork. */
static void supervise(pid_t child_pid, int sigfd, int pty_master)
{
	struct pollfd pfds[3] = {
		{ .fd = CTL_IN,    .events = POLLIN },
		{ .fd = sigfd,     .events = POLLIN },
		{ .fd = pty_master, .events = POLLIN }, /* fd = -1 when no PTY */
	};

	for (;;) {
		int rc = poll(pfds, 3, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "linx_process: poll: %s\n",
				strerror(errno));
			return;
		}

		/* BEAM command on fd 3: {:signal, n} or {:pty_in, bytes}.
		 * A POLLHUP on fd 3 means the BEAM disappeared -- keep
		 * going so the child finishes naturally, but stop polling
		 * that side. */
		if (pfds[0].revents & POLLIN) {
			struct post_running_cmd cmd = { 0 };
			int r = read_post_running_command(&cmd);
			if (r == 0) {
				switch (cmd.kind) {
				case CMD_SIGNAL:
					kill(child_pid, cmd.signum);
					break;
				case CMD_PTY_IN:
					if (pty_master >= 0)
						(void)write_exact(pty_master,
								  cmd.bytes,
								  cmd.bytes_len);
					free(cmd.bytes);
					break;
				case CMD_PTY_WINSIZE:
					if (pty_master >= 0) {
						struct winsize ws = {
							.ws_row    = (unsigned short)cmd.ws_rows,
							.ws_col    = (unsigned short)cmd.ws_cols,
							.ws_xpixel = (unsigned short)cmd.ws_xpix,
							.ws_ypixel = (unsigned short)cmd.ws_ypix,
						};
						/* Best-effort: a stale fd or
						 * a kernel that rejects the
						 * value just gets ignored. */
						(void)ioctl(pty_master,
							    TIOCSWINSZ, &ws);
					}
					break;
				case CMD_NONE:
					break;
				}
			}
		}
		if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
			pfds[0].fd = -1; /* poll(2) ignores fd < 0 */

		/* SIGCHLD fired. Drain the signalfd (SFD_NONBLOCK; the loop
		 * returns EAGAIN when empty) and waitpid the workload. */
		if (pfds[1].revents & POLLIN) {
			struct signalfd_siginfo si;
			while (read(sigfd, &si, sizeof si) == sizeof si)
				;

			int status;
			pid_t r = waitpid(child_pid, &status, WNOHANG);
			if (r == child_pid) {
				/* Workload exited. In PTY mode the master may
				 * still have buffered output the workload
				 * wrote just before exit; drain it before the
				 * terminal event so callers don't lose the
				 * final bytes. The master is O_NONBLOCK so
				 * the drain terminates on EAGAIN. */
				if (pty_master >= 0) {
					uint8_t buf[8192];
					while (1) {
						ssize_t n = read(pty_master,
								 buf, sizeof buf);
						if (n > 0) {
							emit_pty_out(buf, (size_t)n);
							continue;
						}
						break;
					}
				}

				if (WIFEXITED(status))
					emit_status_int("exited",
							WEXITSTATUS(status));
				else if (WIFSIGNALED(status))
					emit_status_int("signaled",
							WTERMSIG(status));
				return;
			}
			/* Spurious SIGCHLD (not our child, or already
			 * reaped). Ignore and keep polling. */
		}

		/* PTY master has bytes to read -- the workload wrote
		 * something. Forward as {:pty_out, binary}. EIO on a
		 * PTY master means the slave was closed (workload
		 * exited); waitpid picks the exit up via SIGCHLD, so
		 * we just stop polling the master. POLLHUP can arrive
		 * with buffered data still pending, so drain it too
		 * (the master is O_NONBLOCK, EAGAIN ends the drain). */
		if (pty_master >= 0 &&
		    (pfds[2].revents & (POLLIN | POLLHUP))) {
			uint8_t buf[8192];
			while (1) {
				ssize_t n = read(pty_master, buf, sizeof buf);
				if (n > 0) {
					emit_pty_out(buf, (size_t)n);
					continue;
				}
				if (n < 0 && errno == EAGAIN)
					break;
				/* n == 0, or n < 0 with EIO / EBADF /
				 * EINTR-already-handled: peer closed. */
				pfds[2].fd = -1;
				break;
			}
		}
		if (pty_master >= 0 &&
		    pfds[2].revents & (POLLERR | POLLNVAL))
			pfds[2].fd = -1;
	}
}

/* --- main -------------------------------------------------------------- */

int main(void)
{
	/* Don't let a vanished BEAM kill us with SIGPIPE on a stale fd 4 --
	 * we'd rather see EPIPE from write() and drop out cleanly. */
	signal(SIGPIPE, SIG_IGN);

	/* Block SIGCHLD so signalfd can capture it (signals delivered the
	 * normal way bypass signalfd). The child unblocks SIGCHLD again
	 * before execve so the workload sees default semantics. */
	sigset_t chld_mask;
	sigemptyset(&chld_mask);
	sigaddset(&chld_mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &chld_mask, NULL) < 0) {
		fprintf(stderr, "linx_process: sigprocmask: %s\n",
			strerror(errno));
		return 4;
	}

	/* Read the spawn request. */
	uint8_t req_buf[8192];
	ssize_t req_len = read_frame(req_buf, sizeof req_buf);
	if (req_len < 0) {
		fprintf(stderr, "linx_process: read spawn request: %s\n",
			errno ? strerror(errno) : "eof");
		return 1;
	}

	struct request req = { 0 };
	if (decode_request(req_buf, (int)req_len, &req) < 0) {
		fprintf(stderr, "linx_process: malformed request\n");
		free_request(&req);
		return 2;
	}

	/* If :env wasn't given, inherit the agent's. execve with a NULL envp
	 * is undefined; pass an empty list instead. We approximate "inherit"
	 * here by handing through our own environ -- the simplest semantics
	 * the BEAM-side caller will expect. */
	extern char **environ;
	char **child_env = req.env ? req.env : environ;

	/* Two internal pipes for the checkpoint handshake. c2p uses CLOEXEC
	 * on the child end so a successful execve auto-closes it (the
	 * parent sees EOF and emits :running). */
	int c2p[2], p2c[2];
	if (pipe2(c2p, O_CLOEXEC) < 0 || pipe2(p2c, 0) < 0) {
		fprintf(stderr, "linx_process: pipe2: %s\n", strerror(errno));
		free_request(&req);
		return 4;
	}

	struct child_args ca = {
		.c2p_w = c2p[1],
		.p2c_r = p2c[0],
		.c2p_r = c2p[0],
		.p2c_w = p2c[1],
		.argv = req.argv,
		.env = child_env,
		.pty_master = -1,
		.pty_slave = -1,
	};
	for (int i = 0; i < 3; i++)
		ca.stdio[i] = req.stdio[i];

	int pty_master = -1, pty_slave = -1;
	if (req.pty) {
		/* Create the PTY pair in the agent (parent) so it's inherited
		 * across clone/fork. The child closes the master and dups the
		 * slave onto 0/1/2; the parent closes the slave and shuttles
		 * bytes between the master and fd 4 in the supervise loop. */
		pty_master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
		if (pty_master < 0) {
			emit_error(errno, "posix_openpt");
			free_request(&req);
			return 4;
		}
		if (grantpt(pty_master) < 0 || unlockpt(pty_master) < 0) {
			emit_error(errno, "ptsetup");
			close(pty_master);
			free_request(&req);
			return 4;
		}

		/* ptsname(3) returns a pointer into a static buffer; copy out
		 * before any other call could clobber it. */
		char slave_path[64];
		const char *p = ptsname(pty_master);
		if (!p) {
			emit_error(errno, "ptsname");
			close(pty_master);
			free_request(&req);
			return 4;
		}
		size_t plen = strlen(p);
		if (plen >= sizeof slave_path) {
			emit_error(ENAMETOOLONG, "ptsname");
			close(pty_master);
			free_request(&req);
			return 4;
		}
		memcpy(slave_path, p, plen + 1);

		pty_slave = open(slave_path, O_RDWR | O_NOCTTY);
		if (pty_slave < 0) {
			emit_error(errno, "pts_open");
			close(pty_master);
			free_request(&req);
			return 4;
		}

		ca.pty_master = pty_master;
		ca.pty_slave = pty_slave;
	}

	pid_t pid;

	switch (req.mode) {
	case MODE_SPAWN: {
		/* CLONE_NEW* flags chosen by the request, OR'd with SIGCHLD so
		 * waitpid sees the child the way it does for fork(2). The
		 * child runs on its own private stack -- 1 MiB is ample for
		 * the work it does (no recursion, no large frames). */
		static char child_stack[CHILD_STACK_SIZE];
		int flags = req.ns_flags | SIGCHLD;

		pid = clone(child_fn, child_stack + CHILD_STACK_SIZE, flags, &ca);
		if (pid < 0) {
			emit_error(errno, "clone");
			free_request(&req);
			return 3;
		}
		break;
	}

	case MODE_ENTER: {
		/* Join the target's namespaces *in the agent* before forking
		 * -- so the fork's child is born inside them. setns is per
		 * thread, the agent is single-threaded, and PID-namespace
		 * setns only takes effect on subsequent forks. */
		if (enter_target_namespaces(&req) < 0) {
			free_request(&req);
			return 3;
		}

		pid = fork();
		if (pid < 0) {
			emit_error(errno, "fork");
			free_request(&req);
			return 3;
		}
		if (pid == 0) {
			/* Child: close the parent ends of our internal pipes
			 * and reuse the same checkpoint+execve logic the
			 * cloned-child path runs. */
			close(c2p[0]);
			close(p2c[1]);
			child_fn(&ca);
			_exit(127); /* unreachable */
		}
		break;
	}
	}

	/* Close the child's ends of the internal pipes in the parent. The
	 * child end of c2p is already CLOEXEC-closed at exec time too -- the
	 * close here is the parent's copy. */
	close(c2p[1]);
	close(p2c[0]);
	/* In PTY mode, the slave is for the child only; the parent keeps the
	 * master. Closing the slave here removes the agent's extra reference;
	 * once the child also closes it (via dup2 onto 0/1/2 + close), the
	 * slave end goes away when the workload exits, triggering EIO on
	 * the master so the supervise loop notices. */
	if (pty_slave >= 0)
		close(pty_slave);

	emit_status_int("spawned", (long)pid);

	/* Read the child's first message -- expected: 'R' + 4-byte pidns
	 * pid -> :ready. */
	uint8_t ready_tag;
	if (read_exact(c2p[0], &ready_tag, 1) < 0 || ready_tag != 'R') {
		fprintf(stderr, "linx_process: child did not send ready\n");
		free_request(&req);
		return 4;
	}
	uint8_t ready_pid[4];
	if (read_exact(c2p[0], ready_pid, sizeof ready_pid) < 0) {
		fprintf(stderr, "linx_process: short ready frame\n");
		free_request(&req);
		return 4;
	}
	long child_pid = ((long)ready_pid[0] << 24) | ((long)ready_pid[1] << 16) |
			 ((long)ready_pid[2] << 8) | (long)ready_pid[3];
	emit_status_int("ready", child_pid);

	/* Wait for :proceed (or :abort) from the BEAM. await_proceed
	 * forwards both :proceed and any K2 cap_* commands to the child
	 * via p2c[1] as ei frames. On :abort we close p2c[1] so the
	 * child sees EOF and _exits without execve'ing, then we reap and
	 * emit {:status, :aborted, ...}.
	 *
	 * A negative return here is most commonly EOF on fd 3 -- the BEAM
	 * port closing because its owning GenServer died, which is a routine
	 * cleanup path (not an error worth a stderr line). */
	int decision = await_proceed(pty_master, p2c[1], c2p[0]);
	if (decision < 0) {
		free_request(&req);
		return 1;
	}

	if (decision == 1) {
		/* :abort -- the child is parked reading p2c[0]. Closing our
		 * write end without sending a :proceed frame gives it EOF;
		 * child _exits 102 (see child_fn / child_read_command). */
		close(p2c[1]);
		close(c2p[0]);

		int status;
		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr,
				"linx_process: waitpid after abort: %s\n",
				strerror(errno));
		}

		/* Emit the same shape as :ready -- {:status, :aborted, pid}.
		 * `child_pid` is the pidns-internal pid the child sent us
		 * earlier (matches what we delivered with :ready). */
		emit_status_int("aborted", child_pid);

		if (pty_master >= 0)
			close(pty_master);
		free_request(&req);
		return 0;
	}

	/* :proceed was forwarded inside await_proceed. Close our write end
	 * so the child won't block on a subsequent read if anything else
	 * shows up on fd 3 -- it will execve from where it is. */
	close(p2c[1]);

	/* The child either execve's successfully (the c2p pipe closes on
	 * exec via CLOEXEC, we see EOF) or fails before exec ('E' frame). */
	int outcome = await_exec_outcome(c2p[0]);
	close(c2p[0]);

	if (outcome == 1) {
		/* :error already emitted. Reap the child to avoid a
		 * zombie, then exit. */
		int status;
		waitpid(pid, &status, 0);
		free_request(&req);
		return 0;
	}

	if (outcome < 0) {
		fprintf(stderr, "linx_process: relay error before exec\n");
		free_request(&req);
		return 4;
	}

	emit_status_running();

	/* Capture SIGCHLD via signalfd so the supervise loop can multiplex
	 * it against fd 3 in a single poll(). The mask was blocked early
	 * in main. Non-blocking so the drain loop in supervise() terminates
	 * rather than hanging on a quiet signalfd. */
	int sigfd = signalfd(-1, &chld_mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (sigfd < 0) {
		fprintf(stderr, "linx_process: signalfd: %s\n",
			strerror(errno));
		free_request(&req);
		return 4;
	}

	supervise(pid, sigfd, pty_master);
	close(sigfd);
	if (pty_master >= 0)
		close(pty_master);

	free_request(&req);
	return 0;
}
