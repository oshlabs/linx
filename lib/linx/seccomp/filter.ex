defmodule Linx.Seccomp.Filter do
  @moduledoc """
  A compiled seccomp filter — what `Linx.Seccomp.allow_list/2`,
  `deny_list/2`, `from_rules/1`, and `Linx.Seccomp.Builder.build/1`
  produce, and what `Linx.Seccomp.install/2` consumes.

  ## Fields

    * `:arch` — the target architecture atom (`:x86_64`, `:aarch64`).
      A filter is single-arch: installing it on a different arch is
      a programmer error. Per `docs/seccomp/PLAN.md` D5.

    * `:bpf` — the raw cBPF program as a binary, ready to be packed
      into a `struct sock_fprog` and handed to
      `seccomp(SECCOMP_SET_MODE_FILTER, …)`. Each instruction is 8
      bytes (`struct sock_filter`: u16 code, u8 jt, u8 jf, u32 k).

    * `:rules` — the normalised rules list the filter was built
      from: `[{action, syscall_atom}, ...]` plus a default action.
      Kept around so `Linx.Seccomp.to_rules/1` can introspect a
      filter Linx itself built; lost when the filter comes from a
      raw BPF blob.

    * `:summary` (optional) — a free-form summary string for
      humans. Useful when filters are constructed by builders that
      want to attach a "what this filter is for" hint to the
      struct.

  ## Inspect

  The struct's Inspect impl is compact on purpose — a typical
  filter carries a multi-KB binary in `:bpf` that would drown a
  REPL. We render the arch, the syscall count, and the BPF
  instruction count instead:

      #Linx.Seccomp.Filter<x86_64 41 syscalls, 12 BPF insns>

  Pattern-match on the struct fields directly if you need to
  inspect the raw BPF or the rules list.

  ## Construction

  Don't construct `%Linx.Seccomp.Filter{}` by hand — the BPF blob
  has to match the rules and the arch, and getting that wrong
  either silently allows dangerous syscalls or kills the workload.
  Use `Linx.Seccomp.allow_list/2`, `deny_list/2`, `from_rules/1`,
  or the `Linx.Seccomp.Builder` DSL.
  """

  @enforce_keys [:arch, :bpf, :rules]
  defstruct [:arch, :bpf, :rules, :summary]

  @typedoc """
  A single rule — an action verdict paired with the syscall atom it
  fires on.
  """
  @type rule :: {action(), atom()}

  @typedoc """
  Action verdicts a rule can carry. The `{:errno, _}` form's data
  payload is either a POSIX atom Linx knows (e.g. `:eperm`) or a
  raw non-negative integer for errnos outside Linx's table.
  """
  @type action ::
          :allow
          | :kill_process
          | :kill_thread
          | :trap
          | :log
          | {:errno, atom() | non_neg_integer()}

  @type t :: %__MODULE__{
          arch: atom(),
          bpf: binary(),
          rules: {[rule()], action()} | nil,
          summary: String.t() | nil
        }

  defimpl Inspect do
    def inspect(%Linx.Seccomp.Filter{} = f, _opts) do
      syscall_count =
        case f.rules do
          {rules, _default} when is_list(rules) -> length(rules)
          _ -> 0
        end

      bpf_insns = div(byte_size(f.bpf), 8)

      "#Linx.Seccomp.Filter<" <>
        "#{f.arch} #{syscall_count} syscalls, #{bpf_insns} BPF insns>"
    end
  end
end
