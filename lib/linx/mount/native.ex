defmodule Linx.Mount.Native do
  @moduledoc """
  NIF binding for `Linx.Mount`. Loads `priv/linx_mount.so` (built by
  the `:linx_mount` Mix compiler) and exposes the small set of
  syscalls the public `Linx.Mount` module wraps: `mount(2)`,
  `umount2(2)`, and `pivot_root(2)`.

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
    :code.priv_dir(:linx)
    |> :filename.join(~c"linx_mount")
    |> :erlang.load_nif(0)
  end

  @doc """
  Returns the NIF identifier string.
  """
  @spec version() :: charlist()
  def version, do: :erlang.nif_error(:nif_not_loaded)

  @typedoc """
  Native error shape: `{stage_atom, errno_atom_or_int}`.
  """
  @type stage ::
          :mount
          | :umount
          | :pivot_root
          | :open_ns
          | :unshare
          | :setns
          | :chdir
          | :thread
          | :create
          | :open_pidns
          | :setns_pid
          | :pipe
          | :fork

  @type error :: {:error, {stage(), atom() | pos_integer()}}

  @doc """
  Wraps `mount(2)`. `flags` is the OR'd integer of `MS_*` constants;
  `source`, `fstype`, and `data` may be empty binaries (translated to
  `NULL` for the kernel). `ns_path` is `""` for the caller's
  namespace, or a path to a namespace file for cross-namespace.

  Two setup nuances, both for assembling a container rootfs:

    * `pidns_path` — `""` normally, or a `/proc/<pid>/ns/pid` file. When
      set (alongside a mount `ns_path`), the worker enters that PID
      namespace and `fork`s a child to perform the mount, so a `proc`
      filesystem binds to the container's PID namespace rather than the
      caller's.
    * `create_target` — `0` normally, or `1` to create an empty file at
      `target` (inside the target mount ns) before mounting — a
      placeholder for a device-node bind onto a fresh tmpfs.
  """
  @spec mount(
          binary(),
          binary(),
          binary(),
          non_neg_integer(),
          binary(),
          binary(),
          binary(),
          0 | 1
        ) :: :ok | error()
  def mount(_source, _target, _fstype, _flags, _data, _ns_path, _pidns_path, _create_target),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Wraps `umount2(2)`. `flags` is the OR'd integer of `MNT_*` /
  `UMOUNT_*` constants. `ns_path` is `""` for the caller's namespace.
  """
  @spec umount(binary(), integer(), binary()) :: :ok | error()
  def umount(_target, _flags, _ns_path), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Wraps `pivot_root(2)`. Always runs on a worker thread (even in
  the BEAM-namespace case) because `pivot_root` requires the
  calling thread's CWD to be inside `new_root`, and we don't want
  to mutate the BEAM's CWD. The worker `unshare`s `CLONE_FS`,
  `chdir`s into `new_root`, then calls the syscall.

  `ns_path` is `""` for the caller's namespace, or a path to a
  namespace file for cross-namespace.
  """
  @spec pivot_root(binary(), binary(), binary()) :: :ok | error()
  def pivot_root(_new_root, _put_old, _ns_path),
    do: :erlang.nif_error(:nif_not_loaded)
end
