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
 * P1: CLONE + CHECKPOINT
 * ----------------------
 * The BEAM sends one {:spawn, %{argv: [...], namespaces: [...], env: [...]}}
 * request on fd 3. We clone() a child with the requested CLONE_NEW* flags
 * and report its host pid as {:status, :spawned, _}; the child reaches the
 * checkpoint, the parent reports {:status, :ready, child_pid_inside_ns};
 * the BEAM does host-side setup (e.g. moves a netlink interface into the
 * new netns) and replies :proceed; the parent forwards that to the child
 * over an internal pipe; the child execve()s the workload and the parent
 * reports {:status, :running, _}. On waitpid, {:status, :exited, code}
 * or {:status, :signaled, signum} terminates the session. Pre-exec
 * failures arrive as {:error, errno, stage}.
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
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
};

static const char *stage_name(enum stage s)
{
	switch (s) {
	case STAGE_EXECVE: return "execve";
	}
	return "unknown";
}

/* Namespace flags the spawn request can ask for, by Elixir atom name. The
 * order does not matter -- the flags are OR'd together before clone(). */
struct ns_flag {
	const char *name;
	int flag;
};

static const struct ns_flag NS_FLAGS[] = {
	{ "net",    CLONE_NEWNET },
	{ "mount",  CLONE_NEWNS },
	{ "pid",    CLONE_NEWPID },
	{ "uts",    CLONE_NEWUTS },
	{ "ipc",    CLONE_NEWIPC },
	{ "user",   CLONE_NEWUSER },
	{ "cgroup", CLONE_NEWCGROUP },
	{ "time",   CLONE_NEWTIME },
	{ NULL, 0 },
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

static int write_frame(const void *buf, uint32_t len)
{
	uint8_t hdr[4] = {
		(uint8_t)(len >> 24), (uint8_t)(len >> 16),
		(uint8_t)(len >> 8),  (uint8_t)len,
	};
	if (write_exact(CTL_OUT, hdr, sizeof hdr) < 0)
		return -1;
	return write_exact(CTL_OUT, buf, len);
}

/* Read one {:packet, 4} frame into `buf`. Returns the message length, or
 * -1 on error/EOF. */
static ssize_t read_frame(uint8_t *buf, size_t cap)
{
	uint8_t hdr[4];
	if (read_exact(CTL_IN, hdr, sizeof hdr) < 0)
		return -1;
	uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
		       ((uint32_t)hdr[2] << 8)  | (uint32_t)hdr[3];
	if (len > cap) {
		errno = EMSGSIZE;
		return -1;
	}
	if (read_exact(CTL_IN, buf, len) < 0)
		return -1;
	return (ssize_t)len;
}

/* --- emitting outbound events on fd 4 ----------------------------------- */

static void emit_buff(ei_x_buff *x)
{
	if (write_frame(x->buff, (uint32_t)x->index) < 0)
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

/* --- the spawn request: parse {:spawn, %{argv, namespaces, env}} ------- */

/* The parsed shape of a {:spawn, _} request. argv/env are NULL-terminated
 * arrays of malloc'd C strings (suitable for execve); ns_flags is the OR
 * of CLONE_NEW* flags from the requested :namespaces. */
struct spawn_req {
	char **argv;
	char **env;
	int ns_flags;
};

static void free_str_array(char **arr)
{
	if (!arr)
		return;
	for (char **p = arr; *p; p++)
		free(*p);
	free(arr);
}

static void free_spawn_req(struct spawn_req *r)
{
	free_str_array(r->argv);
	free_str_array(r->env);
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

/* Decode a list of namespace atoms into ns_flags. */
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
		for (const struct ns_flag *f = NS_FLAGS; f->name; f++) {
			if (strcmp(atom, f->name) == 0) {
				flags |= f->flag;
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

/* Decode the inbound {:spawn, %{argv: [...], namespaces: [...], env: [...]}}
 * frame in `buf` into `req`. Returns 0 on success, -1 on malformed input. */
static int decode_spawn_request(const uint8_t *buf, int len, struct spawn_req *req)
{
	int idx = 0, version;
	if (ei_decode_version((const char *)buf, &idx, &version) < 0)
		return -1;

	int arity;
	if (ei_decode_tuple_header((const char *)buf, &idx, &arity) < 0 || arity != 2)
		return -1;

	char tag[MAXATOMLEN];
	if (ei_decode_atom((const char *)buf, &idx, tag) < 0)
		return -1;
	if (strcmp(tag, "spawn") != 0)
		return -1;

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
			if (decode_ns_list((const char *)buf, &idx, &req->ns_flags) < 0)
				return -1;
		} else {
			/* Skip unknown keys -- the BEAM may carry extras we
			 * don't yet understand; future-compatibility. */
			ei_skip_term((const char *)buf, &idx);
		}
	}

	(void)len;
	return req->argv && req->argv[0] ? 0 : -1;
}

/* --- the cloned child --------------------------------------------------- */

/* Arguments handed to child_fn via clone's `arg` pointer. */
struct child_args {
	int c2p_w; /* child writes events here (CLOEXEC) */
	int p2c_r; /* child reads commands here */
	char **argv;
	char **env;
};

/* Inside the cloned child: announce :ready (with our pidns-internal pid),
 * wait for :proceed, exec. Any pre-exec failure is reported as 'E' on the
 * c2p pipe and the child exits non-zero. */
static int child_fn(void *arg)
{
	struct child_args *ca = arg;

	/* :ready -- send 'R' + pidns-internal pid (uint32 little-endian; the
	 * parent and child run on the same machine so endianness doesn't
	 * matter, but pick one). */
	uint8_t ready[5];
	ready[0] = 'R';
	uint32_t pid = (uint32_t)getpid();
	ready[1] = (uint8_t)(pid >> 24);
	ready[2] = (uint8_t)(pid >> 16);
	ready[3] = (uint8_t)(pid >> 8);
	ready[4] = (uint8_t)pid;
	if (write_exact(ca->c2p_w, ready, sizeof ready) < 0)
		_exit(101);

	/* Wait for :proceed -- a single 'P' byte from the parent. */
	uint8_t cmd;
	if (read_exact(ca->p2c_r, &cmd, 1) < 0)
		_exit(102);
	if (cmd != 'P')
		_exit(103);

	/* execve. argv[0] is the binary; we don't shell-resolve, so a
	 * relative-name argv[0] without a slash will be looked up against
	 * the inherited PATH only if the caller's argv[0] is e.g. "/bin/sh
	 * -c". The straightforward interpretation: argv[0] is the binary
	 * to exec. */
	execve(ca->argv[0], ca->argv, ca->env);

	/* execve returned -> failure. Report errno + stage and exit. */
	int err = errno;
	uint8_t fail[6];
	fail[0] = 'E';
	fail[1] = (uint8_t)(err >> 24);
	fail[2] = (uint8_t)(err >> 16);
	fail[3] = (uint8_t)(err >> 8);
	fail[4] = (uint8_t)err;
	fail[5] = (uint8_t)STAGE_EXECVE;
	(void)write_exact(ca->c2p_w, fail, sizeof fail);
	_exit(127);
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

/* Block reading one {:packet, 4} frame from the BEAM and decode it. For
 * now :proceed is the only command we recognise. */
static int await_proceed(void)
{
	uint8_t buf[64];
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
		if (strcmp(atom, "proceed") == 0)
			return 0;
	}

	/* Unknown command -- ignore quietly for now; later phases add a
	 * vocabulary (`{:signal, n}`, etc.) and warn or error. */
	return -1;
}

/* --- main -------------------------------------------------------------- */

int main(void)
{
	/* Read the spawn request. */
	uint8_t req_buf[8192];
	ssize_t req_len = read_frame(req_buf, sizeof req_buf);
	if (req_len < 0) {
		fprintf(stderr, "linx_process: read spawn request: %s\n",
			errno ? strerror(errno) : "eof");
		return 1;
	}

	struct spawn_req req = { 0 };
	if (decode_spawn_request(req_buf, (int)req_len, &req) < 0) {
		fprintf(stderr, "linx_process: malformed spawn request\n");
		free_spawn_req(&req);
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
		free_spawn_req(&req);
		return 4;
	}

	/* The child stack must be aligned and we pass its *top* to clone. */
	static char child_stack[CHILD_STACK_SIZE];

	struct child_args ca = {
		.c2p_w = c2p[1],
		.p2c_r = p2c[0],
		.argv = req.argv,
		.env = child_env,
	};

	/* CLONE_NEW* flags chosen by the request, OR'd with SIGCHLD so
	 * waitpid sees the child the way it does for fork(2). */
	int flags = req.ns_flags | SIGCHLD;

	pid_t pid = clone(child_fn, child_stack + CHILD_STACK_SIZE, flags, &ca);
	if (pid < 0) {
		emit_error(errno, "clone");
		free_spawn_req(&req);
		return 3;
	}

	/* Close the child's ends of the internal pipes in the parent. The
	 * child end of c2p is already CLOEXEC-closed at exec time too -- the
	 * close here is the parent's copy. */
	close(c2p[1]);
	close(p2c[0]);

	emit_status_int("spawned", (long)pid);

	/* Read the child's first message -- expected: 'R' + 4-byte pidns
	 * pid -> :ready. */
	uint8_t ready_tag;
	if (read_exact(c2p[0], &ready_tag, 1) < 0 || ready_tag != 'R') {
		fprintf(stderr, "linx_process: child did not send ready\n");
		free_spawn_req(&req);
		return 4;
	}
	uint8_t ready_pid[4];
	if (read_exact(c2p[0], ready_pid, sizeof ready_pid) < 0) {
		fprintf(stderr, "linx_process: short ready frame\n");
		free_spawn_req(&req);
		return 4;
	}
	long child_pid = ((long)ready_pid[0] << 24) | ((long)ready_pid[1] << 16) |
			 ((long)ready_pid[2] << 8) | (long)ready_pid[3];
	emit_status_int("ready", child_pid);

	/* Wait for :proceed from the BEAM, forward as 'P' to the child. */
	if (await_proceed() < 0) {
		fprintf(stderr, "linx_process: expected :proceed from BEAM\n");
		free_spawn_req(&req);
		return 1;
	}
	uint8_t go = 'P';
	if (write_exact(p2c[1], &go, 1) < 0) {
		fprintf(stderr, "linx_process: write proceed to child: %s\n",
			strerror(errno));
		free_spawn_req(&req);
		return 4;
	}
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
		free_spawn_req(&req);
		return 0;
	}

	if (outcome < 0) {
		fprintf(stderr, "linx_process: relay error before exec\n");
		free_spawn_req(&req);
		return 4;
	}

	emit_status_running();

	/* Reap the workload and report. */
	int status;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			fprintf(stderr, "linx_process: waitpid: %s\n",
				strerror(errno));
			free_spawn_req(&req);
			return 4;
		}
	}

	if (WIFEXITED(status))
		emit_status_int("exited", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		emit_status_int("signaled", WTERMSIG(status));

	free_spawn_req(&req);
	return 0;
}
