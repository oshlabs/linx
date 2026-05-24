defmodule Linx.Cgroup.Error do
  @moduledoc """
  An error returned by a `Linx.Cgroup` operation.

  Built from a failed `File.read/1` / `File.write/2` / `File.mkdir/1` /
  `File.rmdir/1` call against a cgroupfs interface file. The shape:

    * `:path` — the absolute filesystem path the operation targeted.
    * `:operation` — what we were trying to do, as an atom
      (`:create`, `:destroy`, `:read`, `:write`, `:add_process`).
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eacces`,
      `:ebusy`, …). File already hands us atoms; we keep them as
      named.
    * `:code` — the matching positive errno integer, or `nil` if we
      don't have a mapping for this atom. Included for symmetry with
      `Linx.Netlink.Error` and for callers unfamiliar with POSIX
      mnemonics.

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.Cgroup.destroy(cg) do
        :ok -> :ok
        {:error, %Linx.Cgroup.Error{errno: :ebusy}} ->
          # cgroup still has processes -- expected for live workloads
          :not_empty
      end

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.
  """

  @enforce_keys [:path, :operation, :errno]
  defexception [:path, :operation, :errno, :code]

  @type operation ::
          :create | :destroy | :read | :write | :add_process

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  # POSIX errno table for the file-I/O paths cgroupfs operations can
  # land on. An unmapped atom keeps `:code` at `nil` -- the atom is
  # still pattern-matchable and self-describing.
  @code_of %{
    eperm: 1,
    enoent: 2,
    eintr: 4,
    eio: 5,
    enxio: 6,
    ebadf: 9,
    eagain: 11,
    enomem: 12,
    eacces: 13,
    efault: 14,
    ebusy: 16,
    eexist: 17,
    exdev: 18,
    enodev: 19,
    enotdir: 20,
    eisdir: 21,
    einval: 22,
    enfile: 23,
    emfile: 24,
    enospc: 28,
    erofs: 30,
    epipe: 32,
    erange: 34,
    enametoolong: 36,
    enosys: 38,
    enotempty: 39,
    eloop: 40,
    eopnotsupp: 95
  }

  @doc """
  Builds a `%Linx.Cgroup.Error{}` from a posix-atom errno, the
  filesystem path that failed, and the operation we attempted.

  The integer `:code` is looked up from a small POSIX table; an
  atom we don't have a mapping for (kernel-specific errno on
  exotic hosts) keeps `:code` at `nil`.
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
    "cgroup #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
