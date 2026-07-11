defmodule Linx.User.Error do
  @moduledoc """
  An error returned by a `Linx.User` operation.

  Built from a failed `File.read/1` / `File.write/2` against one of
  the user-namespace procfs files (`/proc/<pid>/uid_map`,
  `/proc/<pid>/gid_map`, `/proc/<pid>/setgroups`). The shape:

    * `:path` — the procfs path the operation targeted.
    * `:operation` — what we were trying to do, as an atom
      (`:set_uid_map`, `:set_gid_map`, `:deny_setgroups`,
      `:read_uid_map`, `:read_gid_map`).
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eperm`,
      `:einval`, …).
    * `:code` — the matching positive errno integer, or `nil` if
      we don't have a mapping for this atom. Included for symmetry
      with `Linx.Mount.Error` / `Linx.Cgroup.Error`.

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.User.set_uid_map(pid, [{0, 1000, 1}]) do
        :ok ->
          :mapped

        {:error, %Linx.User.Error{errno: :eperm}} ->
          # No CAP_SETUID in the parent user ns; the map is too
          # broad for an unprivileged caller, or the map was
          # already written (write-once).
          :no_perm

        {:error, %Linx.User.Error{errno: :enoent}} ->
          # The target pid is gone.
          :pid_dead
      end

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.

  Caller-side input mistakes (e.g. a non-list `mappings`,
  negative ids, zero-length entries) surface as
  `{:error, {:bad_map, reason}}` instead — distinct from kernel
  rejections, mirroring `Linx.Mount`'s `:bad_flag` / `%Error{}`
  split.
  """

  @enforce_keys [:path, :operation, :errno]
  defexception [:path, :operation, :errno, :code]

  @type operation ::
          :set_uid_map
          | :set_gid_map
          | :deny_setgroups
          | :read_uid_map
          | :read_gid_map

  @type t :: %__MODULE__{
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  @doc """
  Builds a `%Linx.User.Error{}` from a posix-atom errno, the
  procfs path that failed, and the operation we attempted. The
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
    "user #{op} failed on #{path}: #{errno}#{code_part}"
  end
end
