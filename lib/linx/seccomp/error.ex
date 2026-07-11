defmodule Linx.Seccomp.Error do
  @moduledoc """
  A structured error returned by `Linx.Seccomp` operations.

  Used for two distinct classes of failure:

    * Caller-side build failures from `Linx.Seccomp.from_rules/1` /
      `allow_list/2` / `deny_list/2` / `Linx.Seccomp.Builder.build/1`
      — `:operation` is `:build`. Most build failures use tagged
      tuples (`{:error, {:unknown_syscall, _}}`,
      `{:error, {:bad_action, _}}`, `{:error, {:duplicate_rule, _}}`,
      `{:error, {:unsupported_arch, _}}`); the struct is the home for
      build failures that don't fit those categories (notably
      `:errno` `:e2big` for filters that overflow the 255-instruction
      jump limit; trampoline-based splitting is deferred).

    * Kernel-side install failures from `Linx.Seccomp.install/2`
      that come back through `Linx.Process` as
      `{:linx_process, :error, errno, stage}` where stage is
      `:seccomp_install` or `:seccomp_no_new_privs`. The struct is
      used to normalise those errno-bearing tuples for callers that
      prefer one error type. `:operation` is `:install` or
      `:set_no_new_privs`.

  ## Fields

    * `:operation` — what we were trying to do, as an atom:
      `:build` | `:install` | `:set_no_new_privs`.
    * `:errno` — a POSIX errno as an atom (`:einval`, `:eperm`, …).
      The jump-overflow build failure reports `:e2big` (errno 7),
      following the libseccomp convention for "filter too large".
    * `:code` — the matching positive errno integer, or `nil` for
      atoms outside the POSIX table.

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.
  """

  @enforce_keys [:operation, :errno]
  defexception [:operation, :errno, :code]

  @type operation :: :build | :install | :set_no_new_privs

  @type t :: %__MODULE__{
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil
        }

  @doc """
  Builds a `%Linx.Seccomp.Error{}` from an errno atom and the
  operation that failed. The integer `:code` comes from the shared
  `Linx.Errno` table.
  """
  @spec from_posix(atom(), operation()) :: t()
  def from_posix(errno, operation)
      when is_atom(errno) and is_atom(operation) do
    %__MODULE__{
      operation: operation,
      errno: errno,
      code: Linx.Errno.code(errno)
    }
  end

  @impl Exception
  def message(%__MODULE__{operation: op, errno: errno, code: code}) do
    code_part = if code, do: " (errno #{code})", else: ""
    "seccomp #{op} failed: #{errno}#{code_part}"
  end
end
