/*
 * linx_mount -- the NIF backing `Linx.Mount`.
 *
 * Wraps the three filesystem-mount syscalls:
 *
 *   - mount(2)        -- mount/4
 *   - umount2(2)      -- umount/2
 *   - pivot_root(2)   -- pivot_root/3 (M4, not in this build)
 *
 * Single-call syscalls operating on the calling thread; a plain
 * (non-dirty) NIF is the right tool -- no scheduler-blocking concern.
 *
 * NAMESPACE TARGETING (M3 -- not yet)
 * -----------------------------------
 * Each fallible function takes an `nsfd` argument. When `nsfd == -1`
 * the syscall runs in the caller's mount namespace (the BEAM's). When
 * `nsfd >= 0` (the future M3 case) the NIF will spawn a throwaway
 * pthread, setns(nsfd, CLONE_NEWNS), perform the syscall, and exit
 * the thread -- same pattern as `linx_netlink_open_in_pidns`. For now
 * we accept the argument and return EOPNOTSUPP on a non-(-1) value
 * so the wire shape is stable from M1 forward.
 *
 * ERROR SHAPE
 * -----------
 * Every fallible function returns either `:ok` or
 * `{:error, ErrnoAtom | ErrnoInt}` (no stage tag -- one syscall per
 * function, so the function name already tells the caller which one
 * failed). Common Linux errnos are mapped to POSIX-style atoms; any
 * errno not in the table falls back to the raw integer.
 */

#include <erl_nif.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

/* Bumped per shipping milestone. */
#define LINX_MOUNT_VERSION "linx_mount 0.1.0 (M1)"

/* --- errno -> atom ------------------------------------------------------- */

static const char *errno_atom(int err)
{
	switch (err) {
	case EACCES:       return "eacces";
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
	default:           return NULL;
	}
}

static ERL_NIF_TERM make_error(ErlNifEnv *env, int err)
{
	const char *name = errno_atom(err);
	ERL_NIF_TERM tag = enif_make_atom(env, "error");
	ERL_NIF_TERM val = name
		? enif_make_atom(env, name)
		: enif_make_int(env, err);
	return enif_make_tuple2(env, tag, val);
}

static ERL_NIF_TERM ok_atom(ErlNifEnv *env)
{
	return enif_make_atom(env, "ok");
}

/* --- string args -------------------------------------------------------- */

/* Copy an Elixir binary into a freshly-allocated null-terminated C
 * string. Caller frees with `enif_free`. Returns NULL on allocation
 * failure or if the term isn't a binary.
 *
 * Mount syscalls expect const char *; binaries from Elixir aren't
 * null-terminated, so we copy. */
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

/* --- mount/6 ------------------------------------------------------------ */

/* Args: source, target, fstype, flags (uint64), data (binary), nsfd (int).
 *
 * `source` and `data` may be empty binaries -- in either case we pass
 * NULL to mount(2). mount(2) accepts either a string or NULL for both
 * arguments (NULL == "use defaults" for many filesystems).
 *
 * `nsfd == -1`: mount in the caller's namespace.
 * `nsfd >= 0`:  M3 -- not yet implemented; returns EOPNOTSUPP. */
static ERL_NIF_TERM nif_mount(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	int nsfd;
	if (!enif_get_int(env, argv[5], &nsfd))
		return enif_make_badarg(env);

	if (nsfd != -1)
		return make_error(env, EOPNOTSUPP);

	ErlNifUInt64 flags;
	if (!enif_get_uint64(env, argv[3], &flags))
		return enif_make_badarg(env);

	char *source = binary_to_cstr(env, argv[0]);
	char *target = binary_to_cstr(env, argv[1]);
	char *fstype = binary_to_cstr(env, argv[2]);
	char *data   = binary_to_cstr(env, argv[4]);

	if (!target || !fstype || !source || !data) {
		enif_free(source);
		enif_free(target);
		enif_free(fstype);
		enif_free(data);
		return enif_make_badarg(env);
	}

	/* Empty string -> NULL for source / data (kernel-idiomatic).
	 * target and fstype must always be non-empty. */
	const char *src_arg  = source[0] ? source : NULL;
	const char *data_arg = data[0]   ? data   : NULL;

	int rc = mount(src_arg, target, fstype, (unsigned long)flags, data_arg);
	int saved_errno = errno;

	enif_free(source);
	enif_free(target);
	enif_free(fstype);
	enif_free(data);

	if (rc < 0)
		return make_error(env, saved_errno);

	return ok_atom(env);
}

/* --- umount/3 ----------------------------------------------------------- */

/* Args: target, flags (int), nsfd (int). */
static ERL_NIF_TERM nif_umount(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	(void)argc;

	int nsfd;
	if (!enif_get_int(env, argv[2], &nsfd))
		return enif_make_badarg(env);

	if (nsfd != -1)
		return make_error(env, EOPNOTSUPP);

	int flags;
	if (!enif_get_int(env, argv[1], &flags))
		return enif_make_badarg(env);

	char *target = binary_to_cstr(env, argv[0]);
	if (!target)
		return enif_make_badarg(env);

	int rc = umount2(target, flags);
	int saved_errno = errno;

	enif_free(target);

	if (rc < 0)
		return make_error(env, saved_errno);

	return ok_atom(env);
}

/* --- NIF init ----------------------------------------------------------- */

static ErlNifFunc nif_funcs[] = {
	{ "version", 0, version,    0 },
	{ "mount",   6, nif_mount,  0 },
	{ "umount",  3, nif_umount, 0 },
};

ERL_NIF_INIT(Elixir.Linx.Mount.Native, nif_funcs, NULL, NULL, NULL, NULL)
