defmodule Linx.Mount.Native do
  @moduledoc """
  NIF binding for `Linx.Mount`. Loads `priv/linx_mount.so` (built by
  the `:linx_mount` Mix compiler) and exposes the small set of
  syscalls the public `Linx.Mount` module wraps: `mount(2)`,
  `umount2(2)`, and (in M4) `pivot_root(2)`.

  Production callers should not use this module directly — go through
  `Linx.Mount`, which validates options, maps flag atoms to the
  kernel's `MS_*` / `MNT_*` constants, and wraps errors in
  `%Linx.Mount.Error{}`.

  ## The `nsfd` argument

  Each fallible function takes an `nsfd` integer:

    * `-1` — perform the syscall in the caller's namespace
      (the BEAM's). This is what M1 ships.
    * `>= 0` — an fd opened to `/proc/<pid>/ns/mnt`; the NIF spawns
      a throwaway pthread, `setns(2)`s into the target's mount
      namespace, performs the syscall, and exits the thread.
      Ships in M3; today returns `{:error, :eopnotsupp}` to keep
      the wire shape stable.
  """

  @on_load :__on_load__

  @doc false
  def __on_load__ do
    :erlang.load_nif(Path.join(:code.priv_dir(:linx), "linx_mount"), 0)
  end

  @doc """
  Returns the NIF version string. Cheap round-trip used by tests to
  confirm the native library actually loaded.
  """
  @spec version() :: charlist()
  def version, do: :erlang.nif_error(:nif_not_loaded)

  @typedoc """
  Error returned by every fallible NIF call. A POSIX-style atom
  (`:enoent`, `:eacces`, `:ebusy`, …) or the raw errno integer if
  the value isn't in the C-side mapping table.
  """
  @type error :: {:error, atom() | pos_integer()}

  @doc """
  Wraps `mount(2)`. `flags` is the OR'd integer of `MS_*` constants;
  `source` and `data` may be empty binaries (the NIF translates them
  to `NULL` for the kernel). `nsfd` is `-1` for the caller's
  namespace.
  """
  @spec mount(binary(), binary(), binary(), non_neg_integer(), binary(), integer()) ::
          :ok | error()
  def mount(_source, _target, _fstype, _flags, _data, _nsfd),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Wraps `umount2(2)`. `flags` is the OR'd integer of `MNT_*` /
  `UMOUNT_*` constants. `nsfd` is `-1` for the caller's namespace.
  """
  @spec umount(binary(), integer(), integer()) :: :ok | error()
  def umount(_target, _flags, _nsfd), do: :erlang.nif_error(:nif_not_loaded)
end
