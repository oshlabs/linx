defmodule Linx.Capabilities.State do
  @moduledoc """
  A snapshot of a process's five Linux capability sets.

  Returned by `Linx.Capabilities.read/1`. Mirrors the kernel's
  per-process cap sets exactly:

    * `:effective` — caps the kernel checks on this thread's
      privileged-operation attempts *right now*.
    * `:permitted` — the upper bound on what the thread can raise
      into `:effective` (or pass to a child via `:inheritable`).
    * `:inheritable` — caps that survive `execve(2)`, subject to
      the executed file's own cap policy.
    * `:bounding` — the hard ceiling on what `:permitted` can ever
      contain on this thread or any of its descendants. Drops are
      one-way.
    * `:ambient` — Linux 4.3+; the "no file caps, no setuid"
      equivalent of `:inheritable` that *does* land in
      `:effective` after `execve`.

  Each field is a `MapSet` of `:cap_*` atoms — never `nil` and
  never an integer bitmask (that representation belongs to
  `Linx.Capabilities.Constants` and the agent's syscalls).

  See `capabilities(7)` for the full semantics, especially
  "Transformation of capabilities during execve()".

  ## Inspect

  Compact rendering shows the count of each set, not the contents —
  useful at-a-glance when most caps are dropped:

      #Linx.Capabilities.State<eff=2 prm=2 inh=0 bnd=41 amb=0>

  `IO.inspect/2` with `:limit` or `:pretty` won't expand it;
  pattern-match on the struct fields directly to inspect the
  contents.
  """

  @enforce_keys [:effective, :permitted, :inheritable, :bounding, :ambient]
  defstruct [:effective, :permitted, :inheritable, :bounding, :ambient]

  @type t :: %__MODULE__{
          effective: MapSet.t(atom()),
          permitted: MapSet.t(atom()),
          inheritable: MapSet.t(atom()),
          bounding: MapSet.t(atom()),
          ambient: MapSet.t(atom())
        }

  defimpl Inspect do
    def inspect(%Linx.Capabilities.State{} = s, _opts) do
      "#Linx.Capabilities.State<" <>
        "eff=#{MapSet.size(s.effective)} " <>
        "prm=#{MapSet.size(s.permitted)} " <>
        "inh=#{MapSet.size(s.inheritable)} " <>
        "bnd=#{MapSet.size(s.bounding)} " <>
        "amb=#{MapSet.size(s.ambient)}>"
    end
  end
end
