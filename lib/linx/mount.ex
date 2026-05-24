defmodule Linx.Mount do
  @moduledoc """
  Linux filesystem-mount primitives — `mount(2)`, `umount2(2)`,
  `pivot_root(2)`, and the read-side `/proc/.../mountinfo` parser.

  ## Why a separate subsystem

  Mounts are a coherent kernel concept (the filesystem hierarchy a
  process sees) with their own syscalls, their own configuration via
  `/proc/.../mountinfo`, and per-namespace semantics that compose
  cleanly with `Linx.Process`'s `:mount` namespace. Like
  `Linx.Cgroup`, mount primitives are useful even outside the
  cloned-child case — bind-mounting host paths, propagating mount
  changes between namespaces, debugging mount tables.

  ## Cross-namespace via `:in`

  Every mutating verb takes an `:in` option naming the mount
  namespace to operate on:

    * `:self` (default) — the BEAM's mount namespace.
    * `{:pid, n}` — the mount namespace of pid `n`.
    * `{:path, p}` — an explicit path to a namespace file
      (typically `/proc/<n>/ns/mnt`).

  The mechanism is the same throwaway-thread + `setns(2)` trick
  `Linx.Netlink` uses for opening sockets in another netns. It works
  for **any process whose namespace files exist** — parked at a
  `Linx.Process` checkpoint, fully running after `proceed/1`, or any
  other live pid. The `:in` option is lifecycle-agnostic.

  ## Composition with `Linx.Process`

  Mount `/proc` inside a child's fresh `:mount` namespace at the
  checkpoint, then proceed:

      {:ok, c} = Linx.Process.spawn(argv: ["/bin/bash"], namespaces: [:mount, :pid])
      host_pid = receive do {:linx_process, :ready, p} -> p end
      :ok = Linx.Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})
      :ok = Linx.Process.proceed(c)

  The same call works post-`proceed/1` against a running container
  for hot-mounting volumes or remounting paths.

  ## Status

  M0–M1 shipped: `list/0`, `list/1`, the mountinfo parser,
  `mount/4`, `umount/2`, plus `%Linx.Mount.Entry{}` and
  `%Linx.Mount.Error{}`. Convenience verbs (M2), cross-namespace
  `:in` (M3), and `pivot_root/3` (M4) land in follow-ups. See
  `docs/mount/PLAN.md` for the roadmap.
  """

  import Bitwise, only: [|||: 2]

  alias Linx.Mount.{Entry, Error, Native}

  # MS_* mount flag constants from <sys/mount.h>. Stable across Linux
  # versions for ~30 years. Pattern-match atoms in the public API
  # against this table; the OR'd integer goes to the NIF.
  @mount_flags %{
    ro: 0x1,
    nosuid: 0x2,
    nodev: 0x4,
    noexec: 0x8,
    sync: 0x10,
    remount: 0x20,
    mandlock: 0x40,
    dirsync: 0x80,
    noatime: 0x400,
    nodiratime: 0x800,
    bind: 0x1000,
    move: 0x2000,
    rec: 0x4000,
    silent: 0x8000,
    unbindable: 0x20000,
    private: 0x40000,
    slave: 0x80000,
    shared: 0x100000,
    relatime: 0x200000,
    strictatime: 0x1000000,
    lazytime: 0x2000000
  }

  # umount(2) / umount2(2) flag constants from <sys/mount.h>.
  @umount_flags %{
    force: 0x1,
    detach: 0x2,
    expire: 0x4,
    no_follow: 0x8
  }

  @doc false
  def __mount_flags__, do: @mount_flags

  @doc false
  def __umount_flags__, do: @umount_flags

  @typedoc """
  Target of a `list/1` call — either a pid (reads
  `/proc/<pid>/mountinfo`) or an explicit path to a mountinfo file.
  """
  @type list_target :: {:pid, pos_integer()} | {:path, Path.t()}

  @doc """
  Returns the BEAM's mount table by parsing `/proc/self/mountinfo`.

  Returns `{:ok, [%Linx.Mount.Entry{}, ...]}` on success or
  `{:error, posix_atom}` if the file can't be read (extremely
  unusual on a healthy host).
  """
  @spec list() :: {:ok, [Entry.t()]} | {:error, atom()}
  def list, do: read_and_parse("/proc/self/mountinfo")

  @doc """
  Returns the mount table for `target`'s mount namespace.

  `target` is `{:pid, n}` (reads `/proc/<n>/mountinfo`) or
  `{:path, p}` (reads `p` directly — typically used with paths like
  `/proc/<n>/mountinfo` already constructed).

  Returns `{:ok, [%Linx.Mount.Entry{}, ...]}` or `{:error, posix_atom}`;
  common failures: `:enoent` (pid no longer exists), `:eacces`
  (BEAM can't read that pid's `/proc`).

  Note that `list/1` does *not* enter the target's mount namespace
  via setns — it just reads the target's mountinfo file from the
  BEAM's namespace, which is sufficient. The mutating verbs (which
  *do* need setns) are the ones that operate on a separate
  throwaway thread.
  """
  @spec list(list_target()) :: {:ok, [Entry.t()]} | {:error, atom()}
  def list({:pid, n}) when is_integer(n) and n > 0 do
    read_and_parse("/proc/#{n}/mountinfo")
  end

  def list({:path, p}) when is_binary(p), do: read_and_parse(p)

  defp read_and_parse(path) do
    case File.read(path) do
      {:ok, data} -> {:ok, parse_mountinfo(data)}
      {:error, posix} -> {:error, posix}
    end
  end

  @doc false
  # Parses a mountinfo blob into a list of %Linx.Mount.Entry{}.
  # Malformed lines (shouldn't happen from a healthy kernel) are
  # silently skipped -- forward-compatible against the kernel adding
  # new optional-field tags we haven't seen.
  @spec parse_mountinfo(binary()) :: [Entry.t()]
  def parse_mountinfo(data) when is_binary(data) do
    data
    |> String.split("\n", trim: true)
    |> Enum.flat_map(&parse_line/1)
  end

  # Parses one mountinfo line. Returns [entry] on success, [] on a
  # line we don't recognize.
  defp parse_line(line) do
    parts = String.split(line, " ")

    with {:ok, mount_id} <- parse_int(Enum.at(parts, 0)),
         {:ok, parent_id} <- parse_signed_int(Enum.at(parts, 1)),
         device when is_binary(device) <- Enum.at(parts, 2),
         root when is_binary(root) <- Enum.at(parts, 3),
         mount_point when is_binary(mount_point) <- Enum.at(parts, 4),
         mount_options when is_binary(mount_options) <- Enum.at(parts, 5),
         {:ok, propagation, rest} <- parse_optional_fields(Enum.drop(parts, 6)),
         [fstype, source, super_options | _extras] <- rest do
      [
        %Entry{
          mount_id: mount_id,
          parent_id: parent_id,
          device: device,
          root: unescape(root),
          mount_point: unescape(mount_point),
          mount_options: mount_options,
          propagation: propagation,
          fstype: fstype,
          source: unescape(source),
          super_options: super_options
        }
      ]
    else
      _ -> []
    end
  end

  # Reads the optional-fields section (zero or more "tag[:value]"
  # entries) terminated by a "-" separator. Returns
  # {:ok, propagation_list, fields_after_separator} or :error.
  defp parse_optional_fields(parts), do: parse_optional_fields(parts, [])

  defp parse_optional_fields(["-" | rest], acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_optional_fields([tag | rest], acc) do
    case parse_propagation(tag) do
      :skip -> parse_optional_fields(rest, acc)
      entry -> parse_optional_fields(rest, [entry | acc])
    end
  end

  defp parse_optional_fields([], _acc), do: :error

  # One optional-fields entry → tagged value or :skip for an
  # unrecognized tag (forward-compat).
  defp parse_propagation("unbindable"), do: :unbindable

  defp parse_propagation(tag) do
    case String.split(tag, ":", parts: 2) do
      ["shared", n] -> with {:ok, i} <- parse_int(n), do: {:shared, i}, else: (_ -> :skip)
      ["master", n] -> with {:ok, i} <- parse_int(n), do: {:master, i}, else: (_ -> :skip)
      ["propagate_from", n] ->
        with {:ok, i} <- parse_int(n), do: {:propagate_from, i}, else: (_ -> :skip)

      _ ->
        :skip
    end
  end

  defp parse_int(nil), do: :error

  defp parse_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp parse_signed_int(nil), do: :error

  defp parse_signed_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end

  # Decodes mountinfo's octal-escape format. The kernel escapes
  # space (\040), tab (\011), newline (\012), and backslash (\134)
  # in the root, mount_point, and source fields. We handle any
  # \nnn three-digit octal sequence to stay defensive.
  @doc false
  def unescape(s) when is_binary(s), do: unescape(s, <<>>)

  defp unescape(<<>>, acc), do: acc

  defp unescape(
         <<?\\, a, b, c, rest::binary>>,
         acc
       )
       when a in ?0..?7 and b in ?0..?7 and c in ?0..?7 do
    byte = (a - ?0) * 64 + (b - ?0) * 8 + (c - ?0)
    unescape(rest, <<acc::binary, byte>>)
  end

  defp unescape(<<ch, rest::binary>>, acc), do: unescape(rest, <<acc::binary, ch>>)

  # --- mutating verbs ------------------------------------------------------

  @doc """
  Mounts `source` at `target` with filesystem type `fstype`.

  ## Options

    * `:flags` — a list of flag atoms (see the table below).
      Mapped to the OR'd `MS_*` integer the kernel expects.
    * `:data` — a filesystem-specific options string (e.g.
      `"size=64M,mode=755"` for tmpfs). Defaults to `""`.

  ## Flag atoms

  | atom | `MS_*` constant |
  |---|---|
  | `:ro` | `MS_RDONLY` |
  | `:nosuid` | `MS_NOSUID` |
  | `:nodev` | `MS_NODEV` |
  | `:noexec` | `MS_NOEXEC` |
  | `:sync` | `MS_SYNCHRONOUS` |
  | `:remount` | `MS_REMOUNT` (driven by `remount/2` in M2) |
  | `:mandlock` | `MS_MANDLOCK` |
  | `:dirsync` | `MS_DIRSYNC` |
  | `:noatime` | `MS_NOATIME` |
  | `:nodiratime` | `MS_NODIRATIME` |
  | `:bind` | `MS_BIND` (driven by `bind/3` in M2) |
  | `:move` | `MS_MOVE` (driven by `move/2` in M2) |
  | `:rec` | `MS_REC` — recursive variant |
  | `:silent` | `MS_SILENT` |
  | `:private` | `MS_PRIVATE` — propagation |
  | `:shared` | `MS_SHARED` — propagation |
  | `:slave` | `MS_SLAVE` — propagation |
  | `:unbindable` | `MS_UNBINDABLE` — propagation |
  | `:relatime` | `MS_RELATIME` |
  | `:strictatime` | `MS_STRICTATIME` |
  | `:lazytime` | `MS_LAZYTIME` |

  Returns `:ok` or `{:error, %Linx.Mount.Error{operation: :mount}}`
  on failure. Common errnos: `:eperm` (no `CAP_SYS_ADMIN`),
  `:enoent` (source or target missing), `:einval` (incompatible
  flags), `:ebusy` (target is busy), `:enodev` (unknown fstype).

  ## Cross-namespace

  M1 only mounts in the BEAM's own mount namespace. The `:in`
  option for cross-namespace mounts lands in M3.
  """
  @spec mount(String.t(), String.t(), String.t(), keyword()) ::
          :ok | {:error, Error.t() | {:bad_flag, atom()}}
  def mount(source, target, fstype, opts \\ [])
      when is_binary(source) and is_binary(target) and is_binary(fstype) and
             is_list(opts) do
    with {:ok, flags} <- pack_flags(opts[:flags] || [], @mount_flags) do
      data = opts[:data] || ""
      do_mount(source, target, fstype, flags, data)
    end
  end

  @doc """
  Unmounts the filesystem at `target`.

  ## Options

    * `:flags` — a list of flag atoms:
      * `:force` — `MNT_FORCE`. Try harder when the filesystem is
        busy (only meaningful for NFS-style network filesystems).
      * `:detach` — `MNT_DETACH`. Lazy unmount: detach from the
        namespace immediately, clean up when the last user is
        done.
      * `:expire` — `MNT_EXPIRE`. Mark for later auto-unmount.
      * `:no_follow` — `UMOUNT_NOFOLLOW`. Don't follow symlinks at
        `target`.

  Returns `:ok` or `{:error, %Linx.Mount.Error{operation: :umount}}`.

  ## Cross-namespace

  M1 only unmounts in the BEAM's own mount namespace. The `:in`
  option for cross-namespace unmounts lands in M3.
  """
  @spec umount(String.t(), keyword()) ::
          :ok | {:error, Error.t() | {:bad_flag, atom()}}
  def umount(target, opts \\ []) when is_binary(target) and is_list(opts) do
    with {:ok, flags} <- pack_flags(opts[:flags] || [], @umount_flags) do
      do_umount(target, flags)
    end
  end

  defp do_mount(source, target, fstype, flags, data) do
    case Native.mount(source, target, fstype, flags, data, -1) do
      :ok -> :ok
      {:error, posix} when is_atom(posix) ->
        {:error, Error.from_posix(posix, target, :mount)}
      {:error, code} when is_integer(code) ->
        # Unmapped errno -- the atom field carries an `:unknown`
        # marker; the integer is preserved in `:code`. This is rare
        # (only odd Linux variants), but it keeps the Error shape
        # consistent.
        {:error, %Error{path: target, operation: :mount, errno: :unknown, code: code}}
    end
  end

  defp do_umount(target, flags) do
    case Native.umount(target, flags, -1) do
      :ok -> :ok
      {:error, posix} when is_atom(posix) ->
        {:error, Error.from_posix(posix, target, :umount)}
      {:error, code} when is_integer(code) ->
        {:error, %Error{path: target, operation: :umount, errno: :unknown, code: code}}
    end
  end

  # Folds a list of flag atoms into the OR'd integer the kernel
  # expects. An unknown atom returns {:error, {:bad_flag, atom}} so
  # the caller gets a clear error rather than a silently-dropped flag.
  defp pack_flags(flags, table) when is_list(flags) do
    Enum.reduce_while(flags, {:ok, 0}, fn flag, {:ok, acc} ->
      case Map.fetch(table, flag) do
        {:ok, bit} -> {:cont, {:ok, acc ||| bit}}
        :error -> {:halt, {:error, {:bad_flag, flag}}}
      end
    end)
  end

  defp pack_flags(_, _), do: {:error, {:bad_flag, :flags_must_be_a_list}}

  @doc """
  Bind-mounts `source` at `target`.

  Lands in M2.
  """
  @spec bind(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def bind(_source, _target, _opts \\ []), do: {:error, :not_yet_implemented}

  @doc """
  Remounts the filesystem at `target` with new flags.

  Lands in M2.
  """
  @spec remount(String.t(), keyword()) :: :ok | {:error, term()}
  def remount(_target, _opts \\ []), do: {:error, :not_yet_implemented}

  @doc """
  Moves the mount at `source` to `target`.

  Lands in M2.
  """
  @spec move(String.t(), String.t()) :: :ok | {:error, term()}
  def move(_source, _target), do: {:error, :not_yet_implemented}

  @doc """
  Changes the calling thread's root to `new_root`, stashing the old
  one at `put_old`.

  Lands in M4.
  """
  @spec pivot_root(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def pivot_root(_new_root, _put_old, _opts \\ []),
    do: {:error, :not_yet_implemented}
end
