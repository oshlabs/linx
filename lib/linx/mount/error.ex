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
      * `:thread` — couldn't create the worker thread that does
        the cross-namespace dance. Rare; typically `EAGAIN` from
        thread-creation pressure.
      The last three only appear when a cross-namespace `:in`
      option was used.
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
          | :thread

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  # POSIX errno table for the syscall paths mount operations can land
  # on. An unmapped atom keeps `:code` at `nil` -- the atom is still
  # pattern-matchable and self-describing.
  @code_of %{
    eperm: 1,
    enoent: 2,
    eio: 5,
    enxio: 6,
    ebadf: 9,
    enomem: 12,
    eacces: 13,
    efault: 14,
    enotblk: 15,
    ebusy: 16,
    eexist: 17,
    enodev: 19,
    enotdir: 20,
    eisdir: 21,
    einval: 22,
    enametoolong: 36,
    enolck: 37,
    enosys: 38,
    enotempty: 39,
    eloop: 40,
    erofs: 30,
    eopnotsupp: 95
  }

  @doc """
  Builds a `%Linx.Mount.Error{}` from a posix-atom errno, the
  filesystem path that failed, and the operation we attempted.
  """
  @spec from_posix(atom(), Path.t(), operation()) :: t()
  def from_posix(errno, path, operation) when is_atom(errno) do
    %__MODULE__{
      path: path,
      operation: operation,
      errno: errno,
      code: Map.get(@code_of, errno)
    }
  end

  @impl Exception
  def message(%__MODULE__{path: path, operation: op, errno: errno, code: code}) do
    code_part = if code, do: " (errno #{code})", else: ""
    "mount #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
