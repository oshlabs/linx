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
          :create | :destroy | :read | :write | :add_process | :stats

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  @doc """
  Builds a `%Linx.Cgroup.Error{}` from a posix-atom errno, the
  filesystem path that failed, and the operation we attempted.

  The integer `:code` is looked up from the shared `Linx.Errno`
  table; an atom outside it (kernel-specific errno on exotic hosts)
  keeps `:code` at `nil`.
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
    "cgroup #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
