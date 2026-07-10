/*
 * linx_process -- the Port binary backing `Linx.Process`.
 *
 * Linx.Process performs operations that cannot live inside the multithreaded
 * BEAM: clone(), setns(), fork() and execve(). Doing those in the BEAM
 * corrupts the VM, so they run in
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
 * does any host-side setup (optionally including K2 cap_* commands that
 * the parent forwards to the child) and replies :proceed, the parent
 * forwards that to the child over an internal pipe, the child execve()s
 * and the parent reports {:status, :running, _}. On waitpid,
 * {:status, :exited, code} or {:status, :signaled, signum} terminates
 * the session. Pre-exec failures arrive as {:error, errno, stage}.
 *
 * THE RELAY
 * ---------
 * The agent process talks to the BEAM on fd 3/4. The cloned child does not
 * touch the BEAM channel; instead, two internal pipes carry the checkpoint
 * handshake:
 *
 *   `c2p` (child writes, parent reads, O_CLOEXEC on the child end): a
 *   stream of {:packet, 4} ei frames, same encoding as p2c and the BEAM
 *   channel. Recognised frames:
 *     - {:ready, pidns_internal_child_pid}
 *     - {:error, errno, stage_atom}     -- pre-exec failure; stage is
 *       :execve / :stdio / :cap_drop_bounding / :cap_set_thread /
 *       :cap_set_ambient / :seccomp_install / :seccomp_no_new_privs
 *       (see enum stage / stage_name in this file)
 *     - EOF (the child execve'd successfully and CLOEXEC closed the
 *       pipe) -> :running
 *
 *   `p2c` (parent writes, child reads): a stream of {:packet, 4} ei frames,
 *   same encoding as the BEAM channel. Recognised frames:
 *     - :proceed -- sentinel that ends the child's checkpoint loop;
 *       child falls through to apply_stdio + execve
 *     - {:cap_drop_bounding, mask},
 *       {:cap_set_thread, eff, prm, inh},
 *       {:cap_set_ambient, mask}    -- K2 capability commands; child
 *       applies the corresponding prctl/capset syscall per-thread
 *     - {:seccomp_install, <<bpf>>} -- S2 seccomp install; child sets
 *       PR_SET_NO_NEW_PRIVS if not already on, then calls
 *       seccomp(SECCOMP_SET_MODE_FILTER) with the cBPF blob
 *     - EOF (parent closed without writing :proceed) -> :abort path;
 *       child _exits 102
 *
 * The CLOEXEC trick on the c2p pipe is how the parent learns the
 * execve succeeded: nothing to write -- the kernel auto-closes the fd at
 * exec time, the parent sees EOF, and emits :running. If execve fails,
 * the child writes the {:error, errno, stage} frame BEFORE the close-
 * on-exec would trigger, so the parent sees the failure with detail.
 *
 * The parent also polls c2p alongside the BEAM channel during the
 * checkpoint window (see await_proceed) so that a K2 cap-command
 * failure in the child surfaces as {:error, errno, stage} immediately,
 * rather than getting stranded until :proceed is sent.
 *
 * EXIT CODES (of this agent, not the workload)
 * --------------------------------------------
 *   0   success (workload was reported on, agent terminating normally)
 *   1   I/O failure on the BEAM channel (no emit possible)
 *   2   malformed request -- emits {:error, EINVAL, :malformed_request}
 *   3   clone()/fork() failed -- emits {:error, errno, :clone | :fork}
 *   4   internal infrastructure failure -- emits {:error, errno, stage}
 *       where stage is :sigprocmask | :pipe2 | :signalfd | :posix_openpt
 *       | :ptsetup | :ptsname | :pts_open | :ready_frame |
 *       :malformed_ready | :exec_outcome
 *
 * Every non-zero exit except code 1 emits a structured error on fd 4
 * before bailing -- so the BEAM-side GenServer always sees a clean
 * terminal even when the agent dies before sending a :status frame.
 * Code 1 paths are silent because the BEAM channel is the failure
 * cause; a write would just EPIPE.
 *
 * The BEAM falls back to a synthesised {:linx_process, :error, exit_code,
 * :agent_died} owner message if the agent exits without having emitted
 * anything (truly catastrophic -- segfault, OOM-kill, …).
 *
 * The workload's own exit code is reported as {:status, :exited, code}.
 *
 * KERNEL FLOOR
 * ------------
 * This file uses syscalls and constants that need Linux >= 5.8:
 *
 *   - clone(2) namespace flags: CLONE_NEWUSER (3.8+), CLONE_NEWCGROUP
 *     (4.6+), CLONE_NEWTIME (5.6+), and the older NEW* flags.
 *   - prctl(PR_CAPBSET_DROP)              -- 2.6.25+
 *   - prctl(PR_CAP_AMBIENT_*)             -- 4.3+
 *   - prctl(PR_SET_NO_NEW_PRIVS)          -- 3.5+
 *   - capset(2) v3 layout                 -- 2.6.26+
 *   - CAP_LAST_CAP = 40 (cap_checkpoint_restore) -- 5.8+
 *   - seccomp(2) SECCOMP_SET_MODE_FILTER  -- 3.17+
 *   - signalfd(2)                         -- 2.6.22+
 *   - pipe2(2)                            -- 2.6.27+
 *
 * 5.8 is the effective floor (driven by the cap table in
 * Linx.Capabilities.Constants). Older kernels may compile, but the
 * cap-table forward-compat path will treat any post-2.6.25 missing
 * caps as :unknown rather than refusing to run.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ei.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
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

/* Stage tags identifying which step of the pre-exec setup failed.
 * Encoded as the third element of a {:error, errno, stage_atom} ei
 * frame the child sends to the parent over c2p; the parent forwards
 * the atom to the BEAM via emit_error. The integer values are an
 * internal enum (used by stage_name); the strings are what the BEAM
 * sees. */
enum stage {
	STAGE_EXECVE = 1,
	STAGE_STDIO = 2, /* per-fd plumbing in child: /dev/null open, dup2 of pre-connected AF_UNIX fds, PTY ioctl */
	STAGE_CAP_DROP_BOUNDING = 3, /* prctl(PR_CAPBSET_DROP) failed in the child */
	STAGE_CAP_SET_THREAD = 4,    /* capset(2) failed in the child */
	STAGE_CAP_SET_AMBIENT = 5,   /* prctl(PR_CAP_AMBIENT_*) failed in the child */
	STAGE_SECCOMP_NO_NEW_PRIVS = 6, /* prctl(PR_SET_NO_NEW_PRIVS) failed in the child */
	STAGE_SECCOMP_INSTALL = 7,   /* seccomp(SECCOMP_SET_MODE_FILTER) failed in the child */
	STAGE_CHDIR = 8,             /* chdir(:cwd) failed in the child before execve */
};

static const char *stage_name(enum stage s)
{
	switch (s) {
	case STAGE_EXECVE:           return "execve";
	case STAGE_STDIO:            return "stdio";
	case STAGE_CAP_DROP_BOUNDING: return "cap_drop_bounding";
	case STAGE_CAP_SET_THREAD:   return "cap_set_thread";
	case STAGE_CAP_SET_AMBIENT:  return "cap_set_ambient";
	case STAGE_SECCOMP_NO_NEW_PRIVS: return "seccomp_no_new_privs";
	case STAGE_SECCOMP_INSTALL:  return "seccomp_install";
	case STAGE_CHDIR:            return "chdir";
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
 * Used on all three internal channels that carry ei frames:
 *   - CTL_OUT (agent -> BEAM): status/error events via emit_*
 *   - p2c (parent -> child): :proceed sentinel + K2 cap commands
 *   - c2p (child -> parent): {:ready, _} and {:error, _, _} */
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
 * length, or -1 on error/EOF (errno == 0 on EOF, per read_exact). Used
 * on all three internal channels that carry ei frames:
 *   - CTL_IN (BEAM -> agent): request and post-:running commands
 *   - p2c (parent -> child, read in the child): :proceed + cap commands
 *   - c2p (child -> parent, read in the agent): :ready / :error frames */
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
 * dup2's /dev/null on; CONNECT_UNIX dup2's a pre-connected AF_UNIX stream
 * socket on. The *agent* performs the connect, host-side, before any
 * namespace transition (spawn-mode clone or enter-mode setns) -- see
 * connect_stdio_sockets -- so `path` is always resolved in the host's
 * mount namespace, immune to whatever the checkpoint window does to the
 * child's (rootfs pivots included), and a bad path fails the request up
 * front instead of post-:proceed. The child merely inherits the fd.
 * (The whole-stdio PTY mode is handled separately -- see `pty` below --
 * since it shares one slave fd across 0/1/2 plus setsid + TIOCSCTTY.) */
struct stdio_dir {
	enum stdio_kind {
		STDIO_INHERIT = 0,
		STDIO_DEVNULL,
		STDIO_CONNECT_UNIX,
	} kind;
	char *path; /* CONNECT_UNIX only; malloc'd */
	int fd;     /* CONNECT_UNIX only; connected by the agent, -1 until then */
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
	int no_new_privs; /* set PR_SET_NO_NEW_PRIVS in child before checkpoint */
	char *cwd;        /* chdir() target in the child before execve; NULL = inherit */
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
	free(r->cwd);
	for (int i = 0; i < 3; i++)
		free(r->stdio[i].path);
}

/* Decode a binary or string ETF term into a freshly malloc'd NUL-terminated
 * C string. Rejects embedded NUL bytes: every consumer treats the result as
 * a C path/arg, so "<validated>\0<smuggled>" would silently truncate at the
 * NUL and defeat any string-based validation done on the Elixir side. */
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
		if (ei_decode_binary(buf, idx, *out, &got) < 0 ||
		    memchr(*out, '\0', (size_t)got) != NULL) {
			free(*out);
			*out = NULL;
			return -1;
		}
		(*out)[got] = '\0';
		return 0;
	}

	/* A string of all-ASCII bytes can arrive as STRING_EXT (a list of
	 * small ints in disguise). Decode either way. ei_decode_string
	 * writes sz chars + NUL; an embedded NUL shows as a short strlen. */
	if (ei_decode_string(buf, idx, *out) < 0 ||
	    strlen(*out) != (size_t)sz) {
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
		out->fd = -1; /* connect_stdio_sockets fills this in */
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
		} else if (strcmp(key, "cwd") == 0) {
			if (decode_string((const char *)buf, &idx, &req->cwd) < 0)
				return -1;
		} else if (strcmp(key, "no_new_privs") == 0) {
			/* Boolean. ei_decode_boolean wants `int *`. */
			int b;
			if (ei_decode_boolean((const char *)buf, &idx, &b) < 0)
				return -1;
			req->no_new_privs = b ? 1 : 0;
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
 * the user namespace), and is wasteful even where it doesn't. The target's
 * side resolves through `target_dirfd` (an open fd on /proc/<pid>), so it
 * cannot race against pid reuse. */
static int same_namespace(int target_dirfd, const char *proc_name)
{
	char self_path[64], ns_rel[32];
	snprintf(self_path, sizeof self_path, "/proc/self/ns/%s", proc_name);
	snprintf(ns_rel, sizeof ns_rel, "ns/%s", proc_name);

	struct stat ss, ts;
	if (stat(self_path, &ss) < 0 ||
	    fstatat(target_dirfd, ns_rel, &ts, 0) < 0)
		return 0;
	return ss.st_ino == ts.st_ino && ss.st_dev == ts.st_dev;
}

/* Upper bound on NS_INFO entries (excluding the NULL sentinel). */
#define NS_MAX 8
_Static_assert(sizeof(NS_INFO) / sizeof(NS_INFO[0]) - 1 <= NS_MAX,
	       "NS_MAX must cover every NS_INFO entry");

static int enter_target_namespaces(const struct request *req)
{
	/* Pin the target's identity ONCE: an fd on /proc/<pid> is bound to
	 * that specific process incarnation. If the target dies and the
	 * kernel recycles the pid, openat() through this fd fails (ESRCH/
	 * ENOENT) instead of resolving into the imposter's namespaces.
	 * Rebuilding "/proc/<pid>/ns/<type>" per iteration had a TOCTOU:
	 * a mid-loop pid reuse spliced together the namespaces of two
	 * different processes (silently, in all_ns mode, via the ENOENT
	 * skip). */
	char proc_path[64];
	snprintf(proc_path, sizeof proc_path, "/proc/%d", (int)req->target);

	int dirfd = open(proc_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0) {
		emit_error(errno, "open_ns_proc");
		return -1;
	}

	/* Phase 1: open every wanted namespace fd before the first setns, so
	 * a target death mid-sequence can never yield a partial join -- the
	 * held fds keep the namespaces alive even if the target exits before
	 * phase 2. */
	int fds[NS_MAX];
	for (int i = 0; i < NS_MAX; i++)
		fds[i] = -1;

	for (int i = 0; i < NS_MAX && NS_INFO[i].atom; i++) {
		const struct ns_info *info = &NS_INFO[i];

		if (!req->all_ns && !(req->ns_flags & info->flag))
			continue;

		/* Already in the target's namespace of this type -- no setns
		 * needed; some kernels return EINVAL for setns-to-self. */
		if (same_namespace(dirfd, info->proc))
			continue;

		char ns_rel[32];
		snprintf(ns_rel, sizeof ns_rel, "ns/%s", info->proc);

		int fd = openat(dirfd, ns_rel, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			if (req->all_ns && errno == ENOENT)
				continue;
			/* Error stage names the namespace so the BEAM-side
			 * error can pinpoint which type failed -- e.g.
			 * :open_ns_time, :setns_user. */
			char stage[32];
			snprintf(stage, sizeof stage, "open_ns_%s", info->atom);
			emit_error(errno, stage);
			goto fail;
		}
		fds[i] = fd;
	}

	close(dirfd);
	dirfd = -1;

	/* Phase 2: join, in NS_INFO order -- user first (capabilities for the
	 * later joins), pid last (applies to the upcoming fork). */
	for (int i = 0; i < NS_MAX && NS_INFO[i].atom; i++) {
		if (fds[i] < 0)
			continue;

		if (setns(fds[i], 0) < 0) {
			char stage[32];
			snprintf(stage, sizeof stage, "setns_%s",
				 NS_INFO[i].atom);
			emit_error(errno, stage);
			goto fail;
		}
		close(fds[i]);
		fds[i] = -1;
	}
	return 0;

fail:
	if (dirfd >= 0)
		close(dirfd);
	for (int i = 0; i < NS_MAX; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	return -1;
}

/* --- the cloned child --------------------------------------------------- */

/* Arguments handed to child_fn via clone's `arg` pointer.
 *
 * stdio    -- per-fd directives. The child applies them after :proceed
 *             but before execve. CONNECT_UNIX entries carry an
 *             already-connected fd (agent-side connect, pre-clone/setns);
 *             the child only dup2's it.
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
	const char *cwd; /* chdir() here before execve; NULL = inherit the agent's cwd */
	struct stdio_dir stdio[3];
	int pty_master;
	int pty_slave;
	int no_new_privs; /* call apply_no_new_privs() early in child_fn */
};

/* Report an in-child pre-exec failure as a `{:error, errno, stage_atom}`
 * ei frame on the c2p pipe and exit. Called when something between the
 * checkpoint and execve fails -- e.g. opening /dev/null, dup2 of a
 * pre-connected AF_UNIX fd, ioctl on the PTY slave, capset/prctl in the
 * K2 cap commands. The parent reads the frame in await_exec_outcome
 * (post-proceed) or in await_proceed's c2p poll branch (checkpoint
 * window), and forwards the {:error, _, _} to the BEAM. */
__attribute__((noreturn))
static void child_fail(int c2p_w, int err, enum stage stage)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 3);
	ei_x_encode_atom(&x, "error");
	ei_x_encode_long(&x, err);
	ei_x_encode_atom(&x, stage_name(stage));
	(void)write_frame_fd(c2p_w, x.buff, (uint32_t)x.index);
	ei_x_free(&x);
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
			/* Connected by the agent (host-side, pre-clone/setns
			 * -- see connect_stdio_sockets); just dup2 it on.
			 * dup2 clears CLOEXEC on the new fd; the original is
			 * CLOEXEC so it would clean itself up at execve, but
			 * close it eagerly for symmetry with the other cases. */
			int s = ca->stdio[fd].fd;
			if (s < 0) {
				errno = EBADF;
				return -1;
			}
			if (dup2(s, fd) < 0)
				return -1;
			if (s > 2)
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

/* --- S2 seccomp syscalls (per-thread, called from the child) ----------- */

/* prctl(PR_SET_NO_NEW_PRIVS, 1) -- forbid this thread and its descendants
 * from ever gaining new privileges via setuid/file-caps on execve. This
 * is the precondition the kernel demands before an unprivileged caller
 * can install a seccomp filter (without CAP_SYS_ADMIN); we also expose
 * it as an option on `Linx.Process.spawn/1` for callers who want the
 * security posture without seccomp itself.
 *
 * One-way: once set, NNP stays on across execve and clone. Linux 3.5+.
 * Returns -1 on failure (errno preserved). */
static int apply_no_new_privs(void)
{
	return prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL);
}

/* PR_GET_NO_NEW_PRIVS returns 0 if NNP is off, 1 if on. Negative on
 * the (unlikely) failure case -- we treat that as "off" and let the
 * subsequent set attempt surface the real error. */
static int get_no_new_privs(void)
{
	int r = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
	return r < 0 ? 0 : r;
}

/* Install the cBPF program `bpf` (len bytes, must be a multiple of 8 --
 * struct sock_filter is 8 bytes) as a seccomp filter on the calling
 * thread.
 *
 * Direct `syscall(SYS_seccomp, ...)` so we don't depend on the libc
 * wrapper (added in glibc 2.27); the linx-process binary should run
 * on older systems too. Linux 3.17+ for the seccomp(2) entry point.
 *
 * Returns 0 on success, -1 with errno on failure. EINVAL is the usual
 * "malformed BPF" code. */
static int apply_seccomp(const void *bpf, size_t len)
{
	if (len == 0 || (len % sizeof(struct sock_filter)) != 0) {
		errno = EINVAL;
		return -1;
	}

	size_t n = len / sizeof(struct sock_filter);
	if (n > 0xFFFF) {
		/* struct sock_fprog.len is a u16; > 65535 instructions
		 * can't be represented. (Real filters are 5..a few
		 * hundred; this is defensive.) */
		errno = E2BIG;
		return -1;
	}

	struct sock_fprog prog = {
		.len = (unsigned short)n,
		.filter = (struct sock_filter *)bpf,
	};

	return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0UL, &prog);
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
	/* Buffer needs to accommodate the largest checkpoint command. K2 cap
	 * commands are tiny (a few u64s); seccomp_install carries a binary
	 * cBPF blob -- 8 bytes per instruction. 32 KiB fits ~4000
	 * instructions including ei encoding overhead, well over any
	 * practical filter (the hand-curated syscall tables have < 250
	 * entries), and matches the documented per-command ceiling and the
	 * forward-side buffer in await_proceed. */
	uint8_t buf[32768];
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

	/* {:seccomp_install, <<bpf>>} -- the S2 seccomp install command.
	 * seccomp(SECCOMP_SET_MODE_FILTER) requires either CAP_SYS_ADMIN
	 * or PR_SET_NO_NEW_PRIVS to be on. If NNP isn't on we set it now
	 * ("be helpful" per PLAN.md D2 -- callers who forgot the spawn
	 * opt shouldn't get a confusing EPERM from the install). NNP is
	 * a one-way bit and harmless when set redundantly. */
	if (strcmp(tag, "seccomp_install") == 0 && arity == 2) {
		int btype, bsize;
		if (ei_get_type((const char *)buf, &idx, &btype, &bsize) < 0)
			return -2;
		if (btype != ERL_BINARY_EXT)
			return -2;
		/* The BPF binary lives inline in `buf` after our 4-byte
		 * binary header. ei_decode_binary copies it out; we then
		 * hand the copy to apply_seccomp and free after. */
		if (bsize <= 0)
			child_fail(c2p_w, EINVAL, STAGE_SECCOMP_INSTALL);
		void *bpf = malloc((size_t)bsize);
		if (!bpf)
			child_fail(c2p_w, ENOMEM, STAGE_SECCOMP_INSTALL);
		long got;
		if (ei_decode_binary((const char *)buf, &idx, bpf, &got) < 0) {
			free(bpf);
			return -2;
		}
		if (!get_no_new_privs()) {
			if (apply_no_new_privs() < 0) {
				int err = errno;
				free(bpf);
				child_fail(c2p_w, err, STAGE_SECCOMP_NO_NEW_PRIVS);
			}
		}
		if (apply_seccomp(bpf, (size_t)got) < 0) {
			int err = errno;
			free(bpf);
			child_fail(c2p_w, err, STAGE_SECCOMP_INSTALL);
		}
		free(bpf);
		return 0;
	}

	return -2;
}

/* Inside the cloned child: announce :ready (with our pidns-internal pid),
 * loop on checkpoint commands until :proceed, plumb stdio, exec. Any
 * pre-exec failure is reported as a {:error, errno, stage} ei frame
 * on the c2p pipe and the child exits non-zero. */
static int child_fn(void *arg)
{
	struct child_args *ca = arg;

	/* Close the parent's ends of our internal pipes. clone(2) and
	 * fork(2) both give the child the full inherited fd table --
	 * including the parent's c2p[0] (read end) and p2c[1] (write
	 * end) -- and unless we close them here, closing them in the
	 * parent leaves the kernel still counting one writer (us) on
	 * p2c, so the child's read on p2c_r would never see EOF if
	 * the parent abandons the session. That matters for the
	 * :abort path. */
	if (ca->c2p_r >= 0) close(ca->c2p_r);
	if (ca->p2c_w >= 0) close(ca->p2c_w);

	/* If the caller asked for PR_SET_NO_NEW_PRIVS at spawn time (the D2
	 * spawn-time NNP path -- both the principled home for NNP as a
	 * security posture *and* the precondition for unprivileged seccomp
	 * installs at the checkpoint), set it now. The cap-command and
	 * seccomp_install branches below also auto-set NNP if needed (the
	 * "be helpful" path), but doing it here keeps the workload's
	 * pre-checkpoint state predictable for callers who explicitly asked. */
	if (ca->no_new_privs) {
		if (apply_no_new_privs() < 0)
			child_fail(ca->c2p_w, errno, STAGE_SECCOMP_NO_NEW_PRIVS);
	}

	/* :ready -- send {:ready, pidns_internal_pid} as an ei frame. */
	{
		ei_x_buff x;
		ei_x_new_with_version(&x);
		ei_x_encode_tuple_header(&x, 2);
		ei_x_encode_atom(&x, "ready");
		ei_x_encode_long(&x, (long)getpid());
		int rc = write_frame_fd(ca->c2p_w, x.buff, (uint32_t)x.index);
		ei_x_free(&x);
		if (rc < 0)
			_exit(101);
	}

	/* Loop on checkpoint-window commands. {:cap_*, _} tuples apply
	 * per-thread cap syscalls (K2); {:seccomp_install, _} installs
	 * a cBPF filter (S2); :proceed breaks the loop. A closed p2c
	 * (EOF) is the :abort path -- exit 102. */
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

	/* Set the workload's working directory. Done last, just before
	 * execve: after any rootfs pivot the agent's inherited cwd may no
	 * longer exist, so :cwd (typically the image's WorkingDir, or "/")
	 * gives the workload a valid cwd inside its own root. */
	if (ca->cwd && chdir(ca->cwd) < 0)
		child_fail(ca->c2p_w, errno, STAGE_CHDIR);

	execve(ca->argv[0], ca->argv, ca->env);

	/* execve returned -> failure. */
	child_fail(ca->c2p_w, errno, STAGE_EXECVE);
}

/* --- the relay (parent of clone) ---------------------------------------- */

/* Drain c2p until either: the child reported success (EOF on the pipe
 * because of CLOEXEC after execve), or a pre-exec error arrived as a
 * `{:error, errno, stage_atom}` ei frame.
 *
 * Returns 0 on success (the workload is running). Returns 1 on
 * pre-exec error (already emitted on fd 4). Returns -1 on relay failure. */
static int await_exec_outcome(int c2p_r)
{
	uint8_t buf[256];
	ssize_t len = read_frame_fd(c2p_r, buf, sizeof buf);
	if (len < 0) {
		/* read_exact sets errno=0 on EOF; that's the success
		 * path (CLOEXEC closed the child's write end at exec). */
		return errno == 0 ? 0 : -1;
	}

	int idx = 0, version, arity;
	if (ei_decode_version((const char *)buf, &idx, &version) < 0 ||
	    ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 ||
	    arity != 3)
		return -1;

	char tag[MAXATOMLEN];
	long err;
	char stage[MAXATOMLEN];
	if (ei_decode_atom((const char *)buf, &idx, tag) < 0 ||
	    strcmp(tag, "error") != 0 ||
	    ei_decode_long((const char *)buf, &idx, &err) < 0 ||
	    ei_decode_atom((const char *)buf, &idx, stage) < 0)
		return -1;

	emit_error((int)err, stage);
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
 *   * {:seccomp_install, <<bpf>>} -- S2 seccomp install. Same per-thread
 *     constraint as the cap commands -- the agent forwards verbatim and
 *     the child does the seccomp(2) syscall before execve.
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
		 * arrives as a {:error, errno, stage} ei frame, ahead
		 * of any :proceed. */
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
			/* Child wrote a {:error, errno, stage_atom} ei
			 * frame (or unexpectedly closed). Drain it and
			 * surface to BEAM; main cleans up. */
			uint8_t buf[256];
			ssize_t len = read_frame_fd(c2p_r, buf, sizeof buf);
			if (len < 0)
				return -1;

			int idx = 0, version, arity;
			if (ei_decode_version((const char *)buf, &idx, &version) < 0 ||
			    ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 ||
			    arity != 3)
				return -1;

			char tag[MAXATOMLEN];
			long err;
			char stage[MAXATOMLEN];
			if (ei_decode_atom((const char *)buf, &idx, tag) < 0 ||
			    strcmp(tag, "error") != 0 ||
			    ei_decode_long((const char *)buf, &idx, &err) < 0 ||
			    ei_decode_atom((const char *)buf, &idx, stage) < 0)
				return -1;

			emit_error((int)err, stage);
			return -1;
		}

		if (!(pfds[0].revents & POLLIN)) {
			/* CTL_IN closed or errored -- the BEAM port is
			 * gone; treat as -1 (main cleans up). */
			if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
				return -1;
			continue;
		}

		/* Same 32 KiB ceiling as child_read_command -- this buffer
		 * has to accommodate {:seccomp_install, <<bpf>>} before
		 * we forward it verbatim to p2c. On EMSGSIZE the wire is
		 * desynced (the length header was consumed, the body was
		 * not), so surface an actionable error before giving up --
		 * the owner sees :command_too_big instead of :agent_died. */
		uint8_t buf[32768];
		ssize_t len = read_frame(buf, sizeof buf);
		if (len < 0) {
			if (errno == EMSGSIZE)
				emit_error(EMSGSIZE, "command_too_big");
			return -1;
		}

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
		 *   {:cap_set_ambient, _}         -- forwarded to child
		 *   {:seccomp_install, <<bpf>>}   -- forwarded to child */
		if (type != ERL_SMALL_TUPLE_EXT && type != ERL_LARGE_TUPLE_EXT)
			return -1;

		int arity;
		if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0)
			return -1;

		char tag[MAXATOMLEN];
		if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
			return -1;

		/* Cap commands -- forward the frame verbatim. The child
		 * decodes and applies; failures come back on c2p as
		 * an {:error, errno, stage} ei frame, surfaced by the
		 * c2p poll branch above. */
		if ((strcmp(tag, "cap_drop_bounding") == 0 && arity == 2) ||
		    (strcmp(tag, "cap_set_thread")    == 0 && arity == 4) ||
		    (strcmp(tag, "cap_set_ambient")   == 0 && arity == 2)) {
			if (write_frame_fd(p2c_w, buf, (uint32_t)len) < 0)
				return -1;
			continue;
		}

		/* {:seccomp_install, <<bpf>>} -- S2 seccomp install. Same
		 * shape as the cap commands: forward verbatim and let the
		 * child do the per-thread `seccomp(SECCOMP_SET_MODE_FILTER)`
		 * call. Failures surface via the c2p poll branch with
		 * stage :seccomp_install or :seccomp_no_new_privs. */
		if (strcmp(tag, "seccomp_install") == 0 && arity == 2) {
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
 *   {:signal, n}                   -- forward to the workload
 *   {:pty_in, binary}              -- write to the PTY master (PTY mode)
 *   {:pty_winsize, {r, c, xp, yp}} -- TIOCSWINSZ on the PTY master
 *
 * Returns:
 *    0 on success (cmd filled)
 *   -1 on parse failure (cmd untouched; recoverable)
 *   -2 on EOF/IO error -- "BEAM went away"
 *   -3 on oversized frame (EMSGSIZE) -- the wire is now desynced
 *      because we consumed the 4-byte header but skipped the body;
 *      the caller must surface an error and tear down. */
static int read_post_running_command(struct post_running_cmd *cmd)
{
	uint8_t buf[32768];
	ssize_t len = read_frame(buf, sizeof buf);
	if (len < 0)
		return errno == EMSGSIZE ? -3 : -2;

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
		if (sz == 0) {
			/* Empty write -- a valid no-op. malloc(0) may return
			 * NULL, which would misclassify this as a bad frame. */
			cmd->kind = CMD_NONE;
			return 0;
		}
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

/* Emit {:pty_in_dropped, n} on fd 4 -- the write-buffer cap was hit and
 * `n` bytes of PTY input were discarded. Non-terminal: the session keeps
 * running; the BEAM side surfaces it to the owner. */
static void emit_pty_in_dropped(size_t n)
{
	ei_x_buff x;
	ei_x_new_with_version(&x);
	ei_x_encode_tuple_header(&x, 2);
	ei_x_encode_atom(&x, "pty_in_dropped");
	ei_x_encode_ulong(&x, (unsigned long)n);
	emit_buff(&x);
}

/* Pending PTY input: bytes accepted from the BEAM but not yet written to
 * the master. The tty input queue is only ~4 KiB and the master is
 * O_NONBLOCK (the read paths need EAGAIN), so a paste larger than the
 * queue hits EAGAIN mid-write; write_exact used to discard the tail
 * silently. Buffer instead, and flush on POLLOUT. Capped so a workload
 * that never reads its terminal can't grow the agent without bound --
 * overflow drops the *new* bytes and reports {:pty_in_dropped, n}. */
struct pty_wbuf {
	uint8_t *data;
	size_t off; /* first unwritten byte */
	size_t len; /* bytes past data[off] */
	size_t cap;
};

#define PTY_WBUF_MAX (1024 * 1024)

static void pty_wbuf_append(struct pty_wbuf *w, const uint8_t *bytes, size_t n)
{
	if (n == 0)
		return;

	/* Compact first so cap math is on live bytes only. */
	if (w->off > 0) {
		memmove(w->data, w->data + w->off, w->len);
		w->off = 0;
	}

	if (w->len + n > PTY_WBUF_MAX || w->len + n < w->len) {
		emit_pty_in_dropped(n);
		return;
	}

	if (w->len + n > w->cap) {
		size_t cap = w->cap ? w->cap : 4096;
		while (cap < w->len + n)
			cap *= 2;
		uint8_t *p = realloc(w->data, cap);
		if (!p) {
			emit_pty_in_dropped(n);
			return;
		}
		w->data = p;
		w->cap = cap;
	}

	memcpy(w->data + w->len, bytes, n);
	w->len += n;
}

/* Write as much buffered input as the master accepts. Returns 0, or -1
 * when the master is gone (EIO/EPIPE/EBADF) -- the caller stops PTY I/O;
 * EAGAIN just leaves the rest for the next POLLOUT. */
static int pty_wbuf_flush(struct pty_wbuf *w, int fd)
{
	while (w->len > 0) {
		ssize_t n = write(fd, w->data + w->off, w->len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			w->len = 0;
			w->off = 0;
			return -1;
		}
		w->off += (size_t)n;
		w->len -= (size_t)n;
	}
	w->off = 0;
	return 0;
}

/* The post-exec supervise loop. Dispatches three kinds of BEAM commands
 * on CTL_IN -- {:signal, n} (forward to the workload), {:pty_in, binary}
 * (write to the PTY master, PTY mode only), and {:pty_winsize, {r, c,
 * xp, yp}} (TIOCSWINSZ on the master) -- reaps the workload via
 * SIGCHLD-on-signalfd, and (in PTY mode) forwards bytes the workload
 * writes to its terminal as {:pty_out, binary} on fd 4. Emits the
 * terminal event ({:status, :exited, _} or {:status, :signaled, _})
 * and returns when the child is gone.
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

	/* Freed on every return path below (the workload-exited return and
	 * the poll-failure return). */
	struct pty_wbuf wbuf = { 0 };

	for (;;) {
		/* Ask for writability only while input is pending -- POLLOUT
		 * on an idle PTY master is a busy loop. */
		if (pfds[2].fd >= 0)
			pfds[2].events =
				POLLIN | (wbuf.len > 0 ? POLLOUT : 0);

		int rc = poll(pfds, 3, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "linx_process: poll: %s\n",
				strerror(errno));
			free(wbuf.data);
			return;
		}

		/* BEAM command on fd 3: {:signal, n}, {:pty_in, bytes},
		 * or {:pty_winsize, {r, c, xp, yp}}. A POLLHUP on fd 3
		 * means the BEAM disappeared -- keep going so the child
		 * finishes naturally, but stop polling that side. */
		if (pfds[0].revents & POLLIN) {
			struct post_running_cmd cmd = { 0 };
			int r = read_post_running_command(&cmd);
			if (r == 0) {
				switch (cmd.kind) {
				case CMD_SIGNAL:
					kill(child_pid, cmd.signum);
					break;
				case CMD_PTY_IN:
					if (pty_master >= 0 &&
					    pfds[2].fd >= 0) {
						pty_wbuf_append(&wbuf,
								cmd.bytes,
								cmd.bytes_len);
						if (pty_wbuf_flush(&wbuf,
								   pty_master) < 0)
							pfds[2].fd = -1;
					}
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
			} else if (r == -3) {
				/* Oversized frame on fd 3 -- the wire is
				 * desynced (we ate the 4-byte header but
				 * skipped the body). Can't recover; surface
				 * a clean error, SIGKILL the workload so
				 * the session ends, and stop polling fd 3
				 * to avoid spinning on the desynced bytes.
				 * SIGCHLD will fire shortly, the supervise
				 * loop reaps, and main returns. */
				emit_error(EMSGSIZE, "command_too_big");
				kill(child_pid, SIGKILL);
				pfds[0].fd = -1;
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
				free(wbuf.data);
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

		/* Room opened in the tty input queue -- flush buffered
		 * PTY input (see pty_wbuf above). */
		if (pty_master >= 0 && pfds[2].fd >= 0 &&
		    (pfds[2].revents & POLLOUT)) {
			if (pty_wbuf_flush(&wbuf, pty_master) < 0)
				pfds[2].fd = -1;
		}

		if (pty_master >= 0 &&
		    pfds[2].revents & (POLLERR | POLLNVAL))
			pfds[2].fd = -1;
	}
}

/* --- CONNECT_UNIX stdio: agent-side connect ----------------------------- */

/* Connect one AF_UNIX stream socket to `path`. Returns the connected fd
 * (SOCK_CLOEXEC -- the child's dup2 onto 0/1/2 clears the flag on the
 * duplicate; the original closes itself at execve), or -1 with errno set. */
static int connect_one_unix(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	size_t len = strlen(path);
	if (len >= sizeof addr.sun_path) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(addr.sun_path, path, len + 1);

	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
		int e = errno;
		close(s);
		errno = e;
		return -1;
	}
	return s;
}

/* Connect every CONNECT_UNIX stdio directive -- in the agent, before the
 * mode switch (spawn-mode clone or enter-mode setns). The paths are
 * caller-supplied *host* paths (the listener lives BEAM-side, bound
 * before the request was sent), so they must be resolved in the host's
 * mount namespace -- never the child's, whose view the checkpoint window
 * is free to rearrange (Tank pivots the rootfs there). Connecting here
 * also fails fast: a bad path surfaces as {:error, errno, :connect_unix}
 * before any child exists, and the child needs no socket syscalls in its
 * seccomp filter -- apply_stdio just dup2's the inherited fd.
 *
 * On failure: closes any fds connected so far and returns -1 with errno
 * set. */
static int connect_stdio_sockets(struct request *req)
{
	for (int fd = 0; fd < 3; fd++) {
		if (req->stdio[fd].kind != STDIO_CONNECT_UNIX)
			continue;
		int s = connect_one_unix(req->stdio[fd].path);
		if (s < 0) {
			int e = errno;
			for (int j = 0; j < fd; j++) {
				if (req->stdio[j].kind == STDIO_CONNECT_UNIX &&
				    req->stdio[j].fd >= 0)
					close(req->stdio[j].fd);
			}
			errno = e;
			return -1;
		}
		req->stdio[fd].fd = s;
	}
	return 0;
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
		emit_error(errno, "sigprocmask");
		return 4;
	}

	/* Read the spawn request. */
	uint8_t req_buf[32768];
	ssize_t req_len = read_frame(req_buf, sizeof req_buf);
	if (req_len < 0) {
		if (errno == EMSGSIZE) {
			/* Frame exceeded our buffer cap (envs and argvs
			 * are the usual culprits at scale). Surface a
			 * clean structured error to the BEAM-side
			 * GenServer before bailing -- without this, the
			 * caller just sees the port close with no
			 * detail. */
			emit_error(EMSGSIZE, "request_too_big");
		} else {
			fprintf(stderr, "linx_process: read spawn request: %s\n",
				errno ? strerror(errno) : "eof");
		}
		return 1;
	}

	struct request req = { 0 };
	if (decode_request(req_buf, (int)req_len, &req) < 0) {
		/* The BEAM sent a {:spawn, _} / {:enter, _} we couldn't
		 * parse -- shape mismatch, missing required keys, invalid
		 * field types. Emit a structured error so the GenServer
		 * doesn't hang on the bare port close. */
		emit_error(EINVAL, "malformed_request");
		free_request(&req);
		return 2;
	}

	/* If :env wasn't given, inherit the agent's. execve with a NULL envp
	 * is undefined; pass an empty list instead. We approximate "inherit"
	 * here by handing through our own environ -- the simplest semantics
	 * the BEAM-side caller will expect. */
	extern char **environ;
	char **child_env = req.env ? req.env : environ;

	/* CONNECT_UNIX stdio directives connect here -- host-side, before
	 * the clone/setns below -- so the child only inherits ready-made
	 * fds. See connect_stdio_sockets for the full reasoning. */
	if (connect_stdio_sockets(&req) < 0) {
		emit_error(errno, "connect_unix");
		free_request(&req);
		return 4;
	}

	/* Two internal pipes for the checkpoint handshake. c2p uses CLOEXEC
	 * on the child end so a successful execve auto-closes it (the
	 * parent sees EOF and emits :running). */
	int c2p[2], p2c[2];
	if (pipe2(c2p, O_CLOEXEC) < 0 || pipe2(p2c, 0) < 0) {
		emit_error(errno, "pipe2");
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
		.cwd = req.cwd,
		.pty_master = -1,
		.pty_slave = -1,
		.no_new_privs = req.no_new_privs,
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
		 * the work it does (no recursion, no large frames). Static and load-bearing: the
		 * agent clones once per process lifetime, so this buffer is never
		 * reused; a second spawn would clobber it. Keep the agent single-shot. */
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
			/* Child: reuse the same checkpoint+execve logic
			 * the cloned-child path runs. child_fn does its
			 * own fd hygiene (closing the parent ends of our
			 * internal pipes) on entry, so we don't need to
			 * touch them here. */
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
	/* And the parent's copies of any pre-connected CONNECT_UNIX fds: the
	 * child holds its own across clone/fork. Dropping ours here means
	 * the BEAM-side listener sees EOF when the *workload* exits (or the
	 * child aborts before dup2'ing them), not when the agent does. */
	for (int i = 0; i < 3; i++) {
		if (req.stdio[i].kind == STDIO_CONNECT_UNIX &&
		    req.stdio[i].fd >= 0)
			close(req.stdio[i].fd);
	}
	/* In PTY mode, the slave is for the child only; the parent keeps the
	 * master. Closing the slave here removes the agent's extra reference;
	 * once the child also closes it (via dup2 onto 0/1/2 + close), the
	 * slave end goes away when the workload exits, triggering EIO on
	 * the master so the supervise loop notices. */
	if (pty_slave >= 0)
		close(pty_slave);

	emit_status_int("spawned", (long)pid);

	/* Read the child's first message -- expected: a {:ready, pid}
	 * ei frame on c2p. */
	long child_pid;
	{
		uint8_t buf[256];
		ssize_t len = read_frame_fd(c2p[0], buf, sizeof buf);
		if (len < 0) {
			/* Child died before sending :ready, or the c2p
			 * pipe broke. Surface errno (or EIO on EOF). */
			emit_error(errno ? errno : EIO, "ready_frame");
			free_request(&req);
			return 4;
		}

		int idx = 0, version, arity;
		char tag[MAXATOMLEN];
		if (ei_decode_version((const char *)buf, &idx, &version) < 0 ||
		    ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 ||
		    arity != 2 ||
		    ei_decode_atom((const char *)buf, &idx, tag) < 0 ||
		    strcmp(tag, "ready") != 0 ||
		    ei_decode_long((const char *)buf, &idx, &child_pid) < 0) {
			emit_error(EPROTO, "malformed_ready");
			free_request(&req);
			return 4;
		}
	}
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
	 * exec via CLOEXEC, we see EOF) or fails before exec (an
	 * {:error, errno, stage} frame). */
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
		/* await_exec_outcome failed to read either an :error
		 * frame or a clean EOF from c2p. Rare -- usually means
		 * the child died in a way that left the pipe broken. */
		emit_error(EIO, "exec_outcome");
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
		emit_error(errno, "signalfd");
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
