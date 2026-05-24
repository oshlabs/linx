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

  M0 — scaffolding + the read side. `list/0`, `list/1`, and the
  mountinfo parser are functional. The mutating verbs (`mount/4`,
  `umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3`)
  ship in M1–M4. See `docs/mount/PLAN.md` for the roadmap.
  """

  alias Linx.Mount.Entry

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

  # --- M1+ surface stubs ---------------------------------------------------

  @doc """
  Mounts `source` at `target` with filesystem type `fstype`.

  Lands in M1.
  """
  @spec mount(String.t(), String.t(), String.t(), keyword()) ::
          :ok | {:error, term()}
  def mount(_source, _target, _fstype, _opts \\ []),
    do: {:error, :not_yet_implemented}

  @doc """
  Unmounts the filesystem at `target`.

  Lands in M1.
  """
  @spec umount(String.t(), keyword()) :: :ok | {:error, term()}
  def umount(_target, _opts \\ []), do: {:error, :not_yet_implemented}

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
