[
  # OTP 28's rewritten opacity analysis false-positives on MapSet:
  # `MapSet.t()` return specs are reported as violated even when the set
  # is built via MapSet.new/1, and a MapSet threaded through a recursive
  # private function loses its opacity. Nothing here constructs or
  # inspects MapSet internals.
  {"lib/linx/seccomp/syscalls.ex", :contract_with_opaque},
  {"lib/linx/seccomp.ex", :call_without_opaque},

  # Linx.Tty's :group_leader attach deliberately probes driver state with
  # :prim_tty.output_mode/1 — dialyzer rightly notes the opacity violation.
  # OTP offers no supported way to flip an SSH-fronted prim_tty's output
  # mode (reinit/2 crashes on tty = undefined states), so this skip stays
  # until an upstream OTP API lands. The full rationale, the exact upstream
  # change that would remove it, and the deletion checklist live in the
  # "prim_tty output-mode surgery" section comment in lib/linx/tty.ex.
  {"lib/linx/tty.ex", :call_without_opaque}
]
