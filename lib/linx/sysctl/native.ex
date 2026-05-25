defmodule Linx.Sysctl.Native do
  @moduledoc """
  NIF binding for `Linx.Sysctl`'s cross-namespace verbs. Loads
  `priv/linx_sysctl.so` (built by the `:linx_sysctl` Mix compiler).

  Production callers should not use this module directly — go through
  `Linx.Sysctl`, which handles key validation, value rendering, the
  `:in` option, and `%Linx.Sysctl.Error{}` wrapping.

  ## The `ns_paths` argument

  Each fallible function takes an `ns_paths` argument: a list of
  binaries naming `/proc/<pid>/ns/<kind>` files (or any other
  pinned-namespace file). The NIF opens every fd FIRST in the BEAM's
  own namespace (so the paths resolve correctly), then spawns a
  throwaway pthread that `unshare(CLONE_FS)`s + `setns(2)`s each fd
  in order, then performs the I/O, then exits the thread. The BEAM's
  own scheduler threads never enter the target namespaces.

  An empty list (`[]`) skips the setns dance — useful for testing
  the NIF in isolation, though the public `Linx.Sysctl` verbs use
  the pure-Elixir host path in that case.

  ## Error shape

  Every fallible function returns `:ok` / `{:ok, ...}` or
  `{:error, {stage_atom, errno_atom_or_int}}`. Stages:

    * `:read` / `:write` / `:list` — the I/O itself failed.
    * `:open_ns` — couldn't open one of the namespace files
      (target process gone, BEAM lacks read access).
    * `:unshare` — `unshare(CLONE_FS)` failed (vanishingly rare).
    * `:setns` — couldn't enter one of the target namespaces
      (typically `EPERM` in the rootless case).
    * `:thread` — couldn't create the worker thread.
  """

  @on_load :__on_load__

  @doc false
  def __on_load__ do
    :erlang.load_nif(Path.join(:code.priv_dir(:linx), ~c"linx_sysctl"), 0)
  end

  @typedoc """
  Native error shape: `{stage_atom, errno_atom_or_int}`.
  """
  @type stage ::
          :read | :write | :list | :open_ns | :unshare | :setns | :thread

  @type error :: {:error, {stage(), atom() | pos_integer()}}

  @doc """
  Returns the NIF version string.
  """
  @spec version() :: charlist()
  def version, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Reads the procfs file at `path` from inside the target namespace
  stack named by `ns_paths`.

  Returns `{:ok, binary}` with the file's untrimmed bytes (callers
  trim) or `{:error, {stage, errno}}`.
  """
  @spec read_in_ns(binary(), [binary()]) :: {:ok, binary()} | error()
  def read_in_ns(_path, _ns_paths), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Writes `data` to the procfs file at `path` from inside the target
  namespace stack named by `ns_paths`. One write call; no `\\n` is
  appended.
  """
  @spec write_in_ns(binary(), binary(), [binary()]) :: :ok | error()
  def write_in_ns(_path, _data, _ns_paths), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Recursively walks the directory tree rooted at `root` from inside
  the target namespace stack named by `ns_paths`, returning every
  readable regular file as a `{path_binary, value_binary}` tuple.

  Unreadable directories and unreadable files are silently skipped
  (matches the pure-Elixir walker behaviour). A non-existent or
  non-directory `root` returns `{:error, {:list, errno}}`.

  The returned list is in walker-discovery order; callers sort by
  whatever key they want.
  """
  @spec list_in_ns(binary(), [binary()]) ::
          {:ok, [{binary(), binary()}]} | error()
  def list_in_ns(_root, _ns_paths), do: :erlang.nif_error(:nif_not_loaded)
end
