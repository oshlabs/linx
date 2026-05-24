defmodule Linx.Mount.Native do
  @moduledoc """
  NIF binding for `Linx.Mount`. Loads `priv/linx_mount.so` (built by
  the `:linx_mount` Mix compiler) and exposes the small set of
  syscalls the public `Linx.Mount` module wraps: `mount(2)`,
  `umount2(2)`, and (in M4) `pivot_root(2)`.

  Production callers should not use this module directly — go through
  `Linx.Mount`, which validates options, maps flag atoms to the
  kernel's `MS_*` / `MNT_*` constants, resolves the `:in` namespace
  option, and wraps errors in `%Linx.Mount.Error{}`.

  ## The `ns_path` argument

  Each fallible function takes an `ns_path` binary:

    * Empty binary (`""`) — perform the syscall in the caller's
      mount namespace (the BEAM's).
    * Non-empty — path to a namespace file (typically
      `/proc/<pid>/ns/mnt`). The NIF spawns a throwaway pthread,
      opens the path, `setns(2)`s into the target namespace,
      performs the syscall, and exits the thread. The BEAM's own
      scheduler threads never enter the target namespace.

  ## Error shape

  Every fallible function returns `:ok` or
  `{:error, {stage_atom, errno_atom | errno_int}}`. Stages:

    * `:mount` / `:umount` / `:pivot_root` — the target syscall
      itself failed.
    * `:open_ns` — couldn't open the namespace file.
    * `:setns` — couldn't enter the target namespace.
    * `:thread` — couldn't create the worker thread.
  """

  @on_load :__on_load__

  @doc false
  def __on_load__ do
    :erlang.load_nif(Path.join(:code.priv_dir(:linx), "linx_mount"), 0)
  end

  @doc """
  Returns the NIF version string.
  """
  @spec version() :: charlist()
  def version, do: :erlang.nif_error(:nif_not_loaded)

  @typedoc """
  Native error shape: `{stage_atom, errno_atom_or_int}`.
  """
  @type stage :: :mount | :umount | :pivot_root | :open_ns | :setns | :thread

  @type error :: {:error, {stage(), atom() | pos_integer()}}

  @doc """
  Wraps `mount(2)`. `flags` is the OR'd integer of `MS_*` constants;
  `source`, `fstype`, and `data` may be empty binaries (translated to
  `NULL` for the kernel). `ns_path` is `""` for the caller's
  namespace, or a path to a namespace file for cross-namespace.
  """
  @spec mount(binary(), binary(), binary(), non_neg_integer(), binary(), binary()) ::
          :ok | error()
  def mount(_source, _target, _fstype, _flags, _data, _ns_path),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Wraps `umount2(2)`. `flags` is the OR'd integer of `MNT_*` /
  `UMOUNT_*` constants. `ns_path` is `""` for the caller's namespace.
  """
  @spec umount(binary(), integer(), binary()) :: :ok | error()
  def umount(_target, _flags, _ns_path), do: :erlang.nif_error(:nif_not_loaded)
end
