defmodule Linx.Capabilities.Error do
  @moduledoc """
  An error returned by a `Linx.Capabilities` read operation.

  Built from a failed `File.read/1` against `/proc/<pid>/status`,
  or from a parser that couldn't make sense of the contents. The
  shape:

    * `:path` — the procfs path the operation targeted.
    * `:operation` — what we were trying to do, as an atom. The
      read path uses `:read`; future operations would extend this.
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eacces`,
      …), or `:bad_status` if the file existed but didn't contain
      the five `Cap*:` lines we expected.
    * `:code` — the matching positive errno integer, or `nil` for
      atoms outside the POSIX table (`:bad_status` has `code: nil`).

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.Capabilities.read(pid) do
        {:ok, state} ->
          inspect(state)

        {:error, %Linx.Capabilities.Error{errno: :enoent}} ->
          # Target pid is gone.
          :pid_dead

        {:error, %Linx.Capabilities.Error{errno: :eacces}} ->
          # No permission to read /proc/<pid>/status — should be
          # rare; status is usually world-readable.
          :no_perm

        {:error, %Linx.Capabilities.Error{errno: :bad_status}} ->
          # The file existed but didn't have the expected Cap*:
          # lines. Should never happen on a real Linux kernel.
          :unparseable
      end

  Pre-exec failures from the *write* side don't surface as
  `%Linx.Capabilities.Error{}` — they come through
  `Linx.Process`'s `{:linx_process, :error, errno, stage}` shape
  with stage atoms like `:cap_drop_bounding`. This struct is for
  the host-side read path only.

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.
  """

  @enforce_keys [:path, :operation, :errno]
  defexception [:path, :operation, :errno, :code]

  @type operation :: :read

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  @doc """
  Builds a `%Linx.Capabilities.Error{}` from a posix-atom errno,
  the procfs path that failed, and the operation we attempted. The
  integer `:code` comes from the shared `Linx.Errno` table; atoms
  outside it (`:bad_status`) keep `:code` at `nil`.
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
    "capabilities #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
