/*
 * linx_tty -- the NIF backing `Linx.Tty`.
 *
 * Wraps the small set of termios(3) and tty ioctl(2) syscalls
 * `Linx.Tty` exposes:
 *
 *   - open(/dev/tty) + cfmakeraw + tcsetattr  (raw-mode entry)
 *   - tcsetattr + close                       (restore exit)
 *   - ioctl(TIOCGWINSZ) / ioctl(TIOCSWINSZ)   (window size)
 *
 * The work is short and syscall-shaped, so a plain (non-dirty) NIF is
 * the right tool -- no scheduler-blocking concern. fd lifetimes are
 * caller-controlled: the NIF returns the integer fd, the Elixir side
 * wraps it (`:erlang.open_port({:fd, _, _}, _)`) and hands it back to
 * the close/restore call.
 *
 * ERROR SHAPE
 * -----------
 * Every fallible function returns either the success shape (`:ok`,
 * `{:ok, ...}`) or `{:error, {Stage::atom, ErrnoAtom | ErrnoInt}}`.
 * Common Linux errnos are mapped to POSIX-style atoms (`:enxio`,
 * `:enotty`, `:eperm`, ...) so callers can pattern-match cleanly; any
 * errno we don't recognise falls back to the raw integer.
 *
 * The TERMIOS BLOB
 * ----------------
 * `open_controlling_raw/0` returns the saved `struct termios` as a
 * binary -- its bytes are an opaque token, not part of the public API.
 * `restore_and_close/2` accepts the same shape unchanged. The Elixir
 * side wraps it in `%Linx.Tty.Saved{}` so the type is visible at call
 * sites; the binary itself is not meant for inspection or mutation.
 */

#include <erl_nif.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

/* Bumped per shipping milestone. */
#define LINX_TTY_VERSION "linx_tty 0.1.0 (T1)"

/* --- errno -> atom ------------------------------------------------------- */

static const char *errno_atom(int err)
{
	switch (err) {
	case EACCES:  return "eacces";
	case EBADF:   return "ebadf";
	case EBUSY:   return "ebusy";
	case EINTR:   return "eintr";
	case EINVAL:  return "einval";
	case EIO:     return "eio";
	case ENOENT:  return "enoent";
	case ENOMEM:  return "enomem";
	case ENOTTY:  return "enotty";
	case ENXIO:   return "enxio";
	case EPERM:   return "eperm";
	default:      return NULL;
	}
}

static ERL_NIF_TERM make_errno(ErlNifEnv *env, int err)
{
	const char *a = errno_atom(err);
	if (a)
		return enif_make_atom(env, a);
	return enif_make_int(env, err);
}

/* {error, {Stage::atom, ErrnoAtom | ErrnoInt}} */
static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *stage, int err)
{
	return enif_make_tuple2(
		env,
		enif_make_atom(env, "error"),
		enif_make_tuple2(env,
				 enif_make_atom(env, stage),
				 make_errno(env, err)));
}

/* --- version ------------------------------------------------------------ */

static ERL_NIF_TERM version(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;
	(void)argv;

	ErlNifBinary bin;
	size_t len = strlen(LINX_TTY_VERSION);
	if (!enif_alloc_binary(len, &bin))
		return enif_make_badarg(env);
	memcpy(bin.data, LINX_TTY_VERSION, len);
	return enif_make_binary(env, &bin);
}

/* --- open_controlling_raw/0 ---------------------------------------------- */

/* Open /dev/tty, save the current termios, switch to raw mode.
 *
 * Returns {:ok, Fd::int, Saved::binary} or {:error, {Stage, Errno}}
 * where Stage is one of :open, :tcgetattr, :tcsetattr. The common
 * "no controlling terminal" case (process detached from a tty)
 * surfaces as {:error, {:open, :enxio}}.
 *
 * The fd is opened O_RDWR | O_NOCTTY | O_CLOEXEC -- the agent does
 * not want /dev/tty to become its *new* controlling tty (it already
 * has one if we got here at all), and CLOEXEC keeps the fd from
 * leaking into any child the BEAM later forks. */
static ERL_NIF_TERM open_controlling_raw(ErlNifEnv *env, int argc,
					 const ERL_NIF_TERM argv[])
{
	(void)argc;
	(void)argv;

	int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0)
		return make_error(env, "open", errno);

	struct termios saved;
	if (tcgetattr(fd, &saved) < 0) {
		int e = errno;
		close(fd);
		return make_error(env, "tcgetattr", e);
	}

	struct termios raw = saved;
	cfmakeraw(&raw);
	if (tcsetattr(fd, TCSANOW, &raw) < 0) {
		int e = errno;
		close(fd);
		return make_error(env, "tcsetattr", e);
	}

	/* The saved termios travels back to Elixir as an opaque binary. */
	ErlNifBinary bin;
	if (!enif_alloc_binary(sizeof saved, &bin)) {
		close(fd);
		return make_error(env, "alloc", ENOMEM);
	}
	memcpy(bin.data, &saved, sizeof saved);

	return enif_make_tuple3(env,
				enif_make_atom(env, "ok"),
				enif_make_int(env, fd),
				enif_make_binary(env, &bin));
}

/* --- restore_and_close/2 ------------------------------------------------- */

/* Restore the saved termios on `fd` and close it.
 *
 * Idempotent against already-closed fds: EBADF from either tcsetattr
 * or close is treated as success, so a double-restore from an `after`
 * block stacked on top of an early failure path is safe. */
static ERL_NIF_TERM restore_and_close(ErlNifEnv *env, int argc,
				      const ERL_NIF_TERM argv[])
{
	(void)argc;

	int fd;
	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);

	ErlNifBinary bin;
	if (!enif_inspect_binary(env, argv[1], &bin))
		return enif_make_badarg(env);
	if (bin.size != sizeof(struct termios))
		return enif_make_badarg(env);

	struct termios saved;
	memcpy(&saved, bin.data, sizeof saved);

	int rc = tcsetattr(fd, TCSANOW, &saved);
	int tc_errno = (rc < 0) ? errno : 0;

	int closed = close(fd);
	int close_errno = (closed < 0) ? errno : 0;

	if (tc_errno && tc_errno != EBADF)
		return make_error(env, "tcsetattr", tc_errno);
	if (close_errno && close_errno != EBADF)
		return make_error(env, "close", close_errno);

	return enif_make_atom(env, "ok");
}

/* --- window_size/1, set_window_size/2 ------------------------------------ */

static ERL_NIF_TERM window_size(ErlNifEnv *env, int argc,
				const ERL_NIF_TERM argv[])
{
	(void)argc;

	int fd;
	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);

	struct winsize ws;
	if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
		return make_error(env, "ioctl", errno);

	return enif_make_tuple2(
		env,
		enif_make_atom(env, "ok"),
		enif_make_tuple4(env,
				 enif_make_uint(env, ws.ws_row),
				 enif_make_uint(env, ws.ws_col),
				 enif_make_uint(env, ws.ws_xpixel),
				 enif_make_uint(env, ws.ws_ypixel)));
}

static ERL_NIF_TERM set_window_size(ErlNifEnv *env, int argc,
				    const ERL_NIF_TERM argv[])
{
	(void)argc;

	int fd;
	if (!enif_get_int(env, argv[0], &fd))
		return enif_make_badarg(env);

	int arity;
	const ERL_NIF_TERM *tuple;
	if (!enif_get_tuple(env, argv[1], &arity, &tuple) || arity != 4)
		return enif_make_badarg(env);

	unsigned rows, cols, xpix, ypix;
	if (!enif_get_uint(env, tuple[0], &rows) ||
	    !enif_get_uint(env, tuple[1], &cols) ||
	    !enif_get_uint(env, tuple[2], &xpix) ||
	    !enif_get_uint(env, tuple[3], &ypix))
		return enif_make_badarg(env);

	/* struct winsize uses unsigned short for each field -- the kernel
	 * silently truncates a wider value. Reject obviously-too-big
	 * values up front so the caller sees an EINVAL-shaped error
	 * rather than a confused kernel call. */
	if (rows > 0xFFFF || cols > 0xFFFF || xpix > 0xFFFF || ypix > 0xFFFF)
		return make_error(env, "ioctl", EINVAL);

	struct winsize ws = {
		.ws_row    = (unsigned short)rows,
		.ws_col    = (unsigned short)cols,
		.ws_xpixel = (unsigned short)xpix,
		.ws_ypixel = (unsigned short)ypix,
	};

	if (ioctl(fd, TIOCSWINSZ, &ws) < 0)
		return make_error(env, "ioctl", errno);

	return enif_make_atom(env, "ok");
}

/* --- NIF init ----------------------------------------------------------- */

static ErlNifFunc nif_funcs[] = {
	{ "version",              0, version,              0 },
	{ "open_controlling_raw", 0, open_controlling_raw, 0 },
	{ "restore_and_close",    2, restore_and_close,    0 },
	{ "window_size",          1, window_size,          0 },
	{ "set_window_size",      2, set_window_size,      0 },
};

ERL_NIF_INIT(Elixir.Linx.Tty.Native, nif_funcs, NULL, NULL, NULL, NULL)
