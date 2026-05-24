defmodule Linx.Seccomp.Builder do
  @moduledoc """
  Fluent builder DSL for `%Linx.Seccomp.Filter{}`.

  Sugar over `Linx.Seccomp.from_rules/1` — the rules are accumulated
  in the builder and compiled to BPF on `build/1`. The same
  validation paths (unknown syscalls, malformed actions, duplicate
  rules) apply.

  ## Stub

  S0 ships the call shapes only — `builder/0` returns an empty
  builder; `allow/2` and `deny/3` accumulate rules; `build/1`
  returns `{:error, :not_yet_implemented}`. The compiler lands in
  S1. The accumulation is real so callers can wire the DSL into
  fixtures and tests today.

  ## Example (lands fully with S1)

      Linx.Seccomp.builder()
      |> Linx.Seccomp.Builder.allow(:read)
      |> Linx.Seccomp.Builder.allow(:write)
      |> Linx.Seccomp.Builder.deny(:ptrace, errno: :eperm)
      |> Linx.Seccomp.Builder.deny(:kexec_load, action: :kill_process)
      |> Linx.Seccomp.Builder.build(default: :allow)
      # => {:ok, %Linx.Seccomp.Filter{}}
  """

  alias Linx.Seccomp.Filter

  @enforce_keys [:rules]
  defstruct rules: []

  @typedoc """
  Internal accumulator type for the builder. The `:rules` field is
  a reversed list of `{action, syscall_atom}` tuples; `build/1`
  reverses it back to source order before handing off.
  """
  @type t :: %__MODULE__{rules: [{Filter.action(), atom()}]}

  @doc """
  An empty builder — the starting point for the pipeline.

  Equivalent to `Linx.Seccomp.builder/0`; the latter is the form
  in the headline example.
  """
  @spec new() :: t()
  def new, do: %__MODULE__{rules: []}

  @doc """
  Adds an `:allow` rule for `syscall` to the builder.

  Rules accumulate in source order — duplicate-detection happens
  at `build/1` time, the same place `from_rules/1` does its
  validation.
  """
  @spec allow(t(), atom()) :: t()
  def allow(%__MODULE__{rules: rules} = b, syscall) when is_atom(syscall) do
    %__MODULE__{b | rules: [{:allow, syscall} | rules]}
  end

  @doc """
  Adds a deny rule for `syscall` to the builder.

  Options:

    * `:errno` — short form for `{:errno, atom_or_int}`. The
      default deny action is `{:errno, :eperm}`.
    * `:action` — pass a full action verdict (`:kill_process`,
      `:kill_thread`, `:trap`, `:log`, `{:errno, _}`). Wins over
      `:errno` if both are given.

  ## Examples

      builder |> deny(:ptrace)                       # → {:errno, :eperm}
      builder |> deny(:ptrace, errno: :eacces)        # → {:errno, :eacces}
      builder |> deny(:kexec_load, action: :kill_process)
  """
  @spec deny(t(), atom(), keyword()) :: t()
  def deny(%__MODULE__{rules: rules} = b, syscall, opts \\ [])
      when is_atom(syscall) and is_list(opts) do
    action =
      case Keyword.fetch(opts, :action) do
        {:ok, explicit} ->
          explicit

        :error ->
          case Keyword.fetch(opts, :errno) do
            {:ok, e} -> {:errno, e}
            :error -> {:errno, :eperm}
          end
      end

    %__MODULE__{b | rules: [{action, syscall} | rules]}
  end

  @doc """
  Compiles the accumulated rules to a `%Linx.Seccomp.Filter{}`.

  Options:

    * `:default` — the fallthrough action for syscalls no rule
      matched. Defaults to `:kill_process`, matching
      `Linx.Seccomp.allow_list/2`'s default — builders are
      typically used for tight filters where unknown syscalls
      should fail loudly.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S1 ships. The
  rule-accumulation shape is real; only the BPF emit is stubbed.
  """
  @spec build(t(), keyword()) :: {:ok, Filter.t()} | {:error, term()}
  def build(%__MODULE__{}, _opts \\ []) do
    {:error, :not_yet_implemented}
  end
end
