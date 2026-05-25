defmodule Linx.Sysctl.Error do
  @moduledoc """
  An error returned by a `Linx.Sysctl` operation.

  Built from a failed `File.read/1` / `File.write/2` against a
  `/proc/sys/...` path, or — for the cross-namespace verbs (S3) —
  from a failure during the setns dance the NIF performs on a
  throwaway pthread.

  The shape:

    * `:key` — the dot-form sysctl key the caller passed in, e.g.
      `"net.ipv4.ip_forward"`.
    * `:path` — the resolved procfs path the operation targeted,
      e.g. `"/proc/sys/net/ipv4/ip_forward"`.
    * `:operation` — what we were trying to do, as an atom:
      * `:read`, `:write`, `:list` — the procfs I/O itself failed.
      * `:open_ns`, `:unshare`, `:setns`, `:chdir`, `:thread` —
        namespace-acquisition failures from the S3 NIF (only seen
        when a cross-namespace `:in` option was used).
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eperm`,
      `:eacces`, `:einval`, …).
    * `:code` — the matching positive errno integer, or `nil` if we
      don't have a mapping for this atom. Included for symmetry with
      `Linx.Mount.Error` / `Linx.User.Error` / `Linx.Cgroup.Error`.

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.Sysctl.write("net.ipv4.ip_forward", 1) do
        :ok ->
          :ok

        {:error, %Linx.Sysctl.Error{errno: :eacces}} ->
          # Needs root.
          :no_perm

        {:error, %Linx.Sysctl.Error{errno: :enoent}} ->
          # No such sysctl on this kernel.
          :unknown_knob
      end

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.

  Caller-side input mistakes (a malformed key, a multi-line value
  the kernel would silently truncate) surface as
  `{:error, {:bad_key, reason}}` / `{:error, {:bad_value, reason}}`
  instead — distinct from kernel rejections, mirroring
  `Linx.User`'s `:bad_map` / `%Error{}` split.
  """

  @enforce_keys [:key, :path, :operation, :errno]
  defexception [:key, :path, :operation, :errno, :code]

  @type operation ::
          :read
          | :write
          | :list
          | :open_ns
          | :unshare
          | :setns
          | :chdir
          | :thread

  @type t :: %__MODULE__{
          key: String.t(),
          path: Path.t(),
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  # POSIX errno table for the procfs paths sysctl operations can land
  # on. An unmapped atom keeps `:code` at `nil` -- the atom is still
  # pattern-matchable and self-describing.
  @code_of %{
    eperm: 1,
    enoent: 2,
    esrch: 3,
    eio: 5,
    ebadf: 9,
    enomem: 12,
    eacces: 13,
    efault: 14,
    ebusy: 16,
    eexist: 17,
    enodev: 19,
    einval: 22,
    enospc: 28,
    erofs: 30,
    erange: 34,
    enametoolong: 36,
    enosys: 38,
    eopnotsupp: 95
  }

  @doc """
  Builds a `%Linx.Sysctl.Error{}` from a posix-atom errno, the
  dot-form key, the resolved procfs path, and the operation we
  attempted.
  """
  @spec from_posix(atom(), String.t(), Path.t(), operation()) :: t()
  def from_posix(errno, key, path, operation) when is_atom(errno) do
    %__MODULE__{
      key: key,
      path: path,
      operation: operation,
      errno: errno,
      code: Map.get(@code_of, errno)
    }
  end

  @impl Exception
  def message(%__MODULE__{key: key, path: path, operation: op, errno: errno, code: code}) do
    code_part = if code, do: " (errno #{code})", else: ""
    "sysctl #{op} #{inspect(key)} failed on #{path}: #{errno}#{code_part}"
  end
end
