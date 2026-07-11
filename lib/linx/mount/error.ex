defmodule Linx.Mount.Error do
  @moduledoc """
  An error returned by a `Linx.Mount` operation.

  Built from a failed `mount(2)` / `umount2(2)` / `pivot_root(2)`
  call against the kernel. The shape:

    * `:path` — the absolute filesystem path the operation targeted
      (the `target` argument of `mount/4`, the `target` of `umount/2`,
      etc.).
    * `:operation` — what we were trying to do, as an atom:
      * `:mount`, `:umount`, `:pivot_root` — the target syscall
        itself failed.
      * `:open_ns` — couldn't open the target namespace file
        (target process is gone, BEAM lacks read access).
      * `:unshare` — couldn't detach the worker thread's
        `fs_struct` from the BEAM's. Prerequisite for `setns` on
        a mount namespace; extremely unlikely to fail.
      * `:setns` — couldn't enter the target namespace (lacks
        `CAP_SYS_ADMIN` in the right user namespace).
      * `:chdir` — couldn't `chdir` into `new_root` before
        `pivot_root`. Typically the path doesn't exist or isn't
        a directory.
      * `:thread` — couldn't create the worker thread that does
        the cross-namespace dance. Rare; typically `EAGAIN` from
        thread-creation pressure.
      * `:create` — couldn't create the `create_target: true`
        placeholder file at the mount target.
      * `:open_pidns`, `:setns_pid`, `:pipe`, `:fork` — failures
        in the PID-namespace fork dance that mounting `proc` with a
        cross-namespace `:in` triggers (see `Linx.Mount.Native.mount/8`).
      The namespace/fork stages only appear when a cross-namespace
      `:in` option was used.
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eacces`,
      `:ebusy`, `:einval`, `:eperm`, …).
    * `:code` — the matching positive errno integer, or `nil` if we
      don't have a mapping for this atom. Included for symmetry with
      `Linx.Cgroup.Error` / `Linx.Netlink.Error` and for callers
      unfamiliar with POSIX mnemonics.

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.Mount.mount("tmpfs", "/mnt/x", "tmpfs") do
        :ok -> :ok
        {:error, %Linx.Mount.Error{errno: :eacces}} ->
          # not enough privilege
          :no_perm
      end

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.
  """

  @enforce_keys [:path, :operation, :errno]
  defexception [:path, :operation, :errno, :code]

  @type operation ::
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

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  @doc """
  Builds a `%Linx.Mount.Error{}` from a posix-atom errno, the
  filesystem path that failed, and the operation we attempted. The
  integer `:code` comes from the shared `Linx.Errno` table.
  """
  @spec from_posix(atom(), Path.t(), operation()) :: t()
  def from_posix(errno, path, operation) when is_atom(errno) do
    %__MODULE__{
      path: path,
      operation: operation,
      errno: errno,
      code: Linx.Errno.code(errno)
    }
  end

  @impl Exception
  def message(%__MODULE__{path: path, operation: op, errno: errno, code: code}) do
    code_part = if code, do: " (errno #{code})", else: ""
    "mount #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
