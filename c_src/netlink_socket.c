/*
 * netlink_socket -- open an AF_NETLINK socket inside a given network
 * namespace, and hand the file descriptor back to the BEAM.
 *
 * This NIF exists because Linx.Netlink is otherwise pure Elixir: the BEAM can
 * open and drive a netlink socket on its own, but only in its own network
 * namespace. Reaching another netns needs setns(2), which acts per-thread --
 * unsafe to do on a BEAM scheduler, where it would strand unrelated work in
 * the wrong namespace.
 *
 * WHY A THREAD
 * ------------
 * setns(2) with CLONE_NEWNET changes the network namespace of the *calling
 * thread* only. A socket, once created, is permanently bound to whatever
 * network namespace was current on its creating thread at socket() time --
 * it carries that namespace for its whole life, no matter which thread later
 * uses the fd.
 *
 * So a throwaway thread does setns() into the target netns, opens the socket
 * there, and exits. The kernel destroys that thread's namespace membership
 * when it exits -- unconditionally, on every code path, with nothing to
 * restore -- while the socket fd survives, already pinned to the target netns
 * and usable from any BEAM thread.
 *
 * The alternative (setns in, socket(), setns back, all on a dirty scheduler
 * thread) is correct only if every error path restores the namespace; a
 * single missed branch leaves a *shared* scheduler thread in the wrong netns,
 * silently corrupting unrelated later NIF calls. The throwaway thread makes
 * that failure mode structurally impossible.
 *
 * CONTRACT
 * --------
 *   open_in_netns(NetnsPath::binary, Protocol::integer)
 *     -> {ok, Fd::integer}              the netns-pinned AF_NETLINK fd
 *     -> {error, {Stage::atom, Errno::integer}}
 *   close_fd(Fd::integer) -> ok         close an open_in_netns fd that
 *                                       :socket.open/1 did not adopt
 *
 * NetnsPath names a network-namespace file -- typically /proc/<pid>/ns/net,
 * or /proc/self/ns/net for the BEAM's own netns. Protocol is the netlink
 * protocol number passed to socket(2) (NETLINK_ROUTE, NETLINK_GENERIC, ...).
 * Stage is one of: open, setns, socket, thread.
 *
 * The returned fd belongs to the caller: it is a process-wide descriptor in
 * the BEAM's OS process and is not closed here. The Elixir side adopts it
 * with :socket.open/1 -- the socket object then owns and closes the fd. If
 * that adopt fails, the fd is still the caller's; close_fd/1 disposes of it.
 */

#include <erl_nif.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h> /* struct sockaddr_nl */
#include <sched.h>      /* setns, CLONE_NEWNET */
#include <string.h>
#include <sys/socket.h> /* socket, AF_NETLINK, SOCK_RAW, SOCK_CLOEXEC */
#include <unistd.h>

/* Work handed to the worker thread, and its results read back afterward. */
struct netns_job {
	const char *path;  /* the network-namespace file to setns() into */
	int protocol;      /* netlink protocol number for socket(2) */
	int sock;          /* result: the AF_NETLINK fd, or -1 on failure */
	int err;           /* result: errno of the failing step, or 0 */
	const char *stage; /* result: which step failed ("open"/"setns"/...) */
};

/* Runs on a private thread, created and joined within one NIF call. It does
 * setns() into the target netns and opens the socket there; when the thread
 * returns, the kernel discards its netns membership -- so there is
 * deliberately nothing to undo, on success or on any error path. */
static void *netns_worker(void *arg)
{
	struct netns_job *j = arg;

	int ns = open(j->path, O_RDONLY | O_CLOEXEC);
	if (ns < 0) {
		j->err = errno;
		j->stage = "open";
		return NULL;
	}

	/* setns() moves only this thread into the target network namespace.
	 * The thread is discarded right after, so no BEAM scheduler ever runs
	 * in this namespace. */
	if (setns(ns, CLONE_NEWNET) < 0) {
		j->err = errno;
		j->stage = "setns";
		close(ns);
		return NULL;
	}

	/* The socket is pinned to the target netns from here on, for any
	 * thread that later uses the fd. SOCK_CLOEXEC so it is never inherited
	 * by a process the BEAM later fork+execs -- a leaked netns-bound fd
	 * would be a namespace-confinement hole. */
	j->sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, j->protocol);
	if (j->sock < 0) {
		j->err = errno;
		j->stage = "socket";
	}

	close(ns);
	return NULL; /* thread exits -> its netns membership is destroyed */
}

/* Build {error, {Stage::atom, Errno::integer}}. */
static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *stage, int err)
{
	return enif_make_tuple2(
		env, enif_make_atom(env, "error"),
		enif_make_tuple2(env, enif_make_atom(env, stage),
				 enif_make_int(env, err)));
}

/* open_in_netns(NetnsPath::binary, Protocol::integer)
 *   -> {ok, Fd} | {error, {Stage, Errno}}.
 *
 * Flagged ERL_NIF_DIRTY_JOB_IO_BOUND: it creates and joins a thread and does
 * filesystem opens, so it runs on a dirty I/O scheduler rather than blocking
 * a normal scheduler. The work itself is sub-millisecond. */
static ERL_NIF_TERM open_in_netns(ErlNifEnv *env, int argc,
				  const ERL_NIF_TERM argv[])
{
	(void)argc;

	ErlNifBinary path;
	if (!enif_inspect_iolist_as_binary(env, argv[0], &path))
		return enif_make_badarg(env);

	int protocol;
	if (!enif_get_int(env, argv[1], &protocol))
		return enif_make_badarg(env);

	/* open() needs a NUL-terminated C string. Reject embedded NUL:
	 * "validated\0smuggled" would silently truncate at the NUL and open
	 * a different path than the Elixir side validated -- same hardening
	 * as binary_to_cstr in the other three C units. */
	char cpath[PATH_MAX];
	if (path.size >= sizeof cpath)
		return make_error(env, "open", ENAMETOOLONG);
	if (memchr(path.data, '\0', path.size))
		return make_error(env, "open", EINVAL);
	memcpy(cpath, path.data, path.size);
	cpath[path.size] = '\0';

	struct netns_job job = {
		.path = cpath,
		.protocol = protocol,
		.sock = -1,
		.err = 0,
		.stage = NULL,
	};

	/* enif_thread_create returns an errno-like code (not via errno). */
	ErlNifTid tid;
	int rc = enif_thread_create("linx_netns", &tid, netns_worker, &job, NULL);
	if (rc != 0)
		return make_error(env, "thread", rc);
	enif_thread_join(tid, NULL);

	if (job.sock < 0)
		return make_error(env, job.stage, job.err);

	return enif_make_tuple2(env, enif_make_atom(env, "ok"),
				enif_make_int(env, job.sock));
}

/* close_fd(Fd::integer) -> ok
 *
 * Disposes of a descriptor from open_in_netns on the one path where Elixir
 * itself still owns it: a successful open_in_netns whose fd :socket.open/1
 * then declined to adopt. close(2) on a netlink socket does not block, so
 * this is a plain (non-dirty) NIF. */
static ERL_NIF_TERM close_fd(ErlNifEnv *env, int argc,
			     const ERL_NIF_TERM argv[])
{
	(void)argc;

	int fd;
	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);

	close(fd);
	return enif_make_atom(env, "ok");
}

/* bind_netlink(Fd::integer, GroupsBitmask::integer) -> ok | {error, Errno}
 *
 * Binds the netlink fd with nl_pid = 0 (kernel auto-assigns) and the given
 * group-membership bitmask. Erlang's :socket.bind/2 doesn't accept netlink
 * sockaddrs, so we do this in C.
 *
 * For modern multi-group subscriptions, NETLINK_ADD_MEMBERSHIP via
 * setsockopt is preferred — but the socket must still be bound first to
 * receive multicast (else the kernel never delivers events to it). Calling
 * this with groups=0 just binds for auto-port assignment. */
static ERL_NIF_TERM bind_netlink(ErlNifEnv *env, int argc,
				 const ERL_NIF_TERM argv[])
{
	(void)argc;

	int fd;
	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);

	unsigned int groups;
	if (!enif_get_uint(env, argv[1], &groups))
		return enif_make_badarg(env);

	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0, /* let the kernel auto-assign */
		.nl_groups = groups,
	};

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		return enif_make_tuple2(
			env, enif_make_atom(env, "error"),
			enif_make_int(env, errno));
	}

	return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
	{"open_in_netns", 2, open_in_netns, ERL_NIF_DIRTY_JOB_IO_BOUND},
	{"close_fd", 1, close_fd, 0},
	{"bind_netlink", 2, bind_netlink, 0},
};

ERL_NIF_INIT(Elixir.Linx.Netlink.Socket.Native, nif_funcs, NULL, NULL, NULL, NULL)
