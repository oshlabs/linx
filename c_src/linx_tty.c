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
 * T0 STATUS
 * ---------
 * This is the scaffolding version: the NIF library loads, exposes one
 * round-trip (`version/0`), and that's it. The termios and ioctl
 * functions land in T1+ (see docs/tty/PLAN.md).
 */

#include <erl_nif.h>

#include <string.h>

/* Bumped per shipping milestone -- T0 is the scaffolding marker.
 * `Linx.Tty.version/0` surfaces this string verbatim so tests and
 * smoke checks can see which milestone the running NIF reflects. */
#define LINX_TTY_VERSION "linx_tty 0.1.0 (T0)"

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

static ErlNifFunc nif_funcs[] = {
	{ "version", 0, version, 0 },
};

ERL_NIF_INIT(Elixir.Linx.Tty.Native, nif_funcs, NULL, NULL, NULL, NULL)
