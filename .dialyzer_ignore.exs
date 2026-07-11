[
  # OTP 28's rewritten opacity analysis false-positives on MapSet:
  # `MapSet.t()` return specs are reported as violated even when the set
  # is built via MapSet.new/1, and a MapSet threaded through a recursive
  # private function loses its opacity. Nothing here constructs or
  # inspects MapSet internals.
  {"lib/linx/seccomp/syscalls.ex", :contract_with_opaque},
  {"lib/linx/seccomp.ex", :call_without_opaque},

  # Linx.Tty's :group_leader attach deliberately reaches into :prim_tty's
  # opaque state (documented in the moduledoc as OTP-version-sensitive);
  # dialyzer rightly notes the opacity violation.
  {"lib/linx/tty.ex", :call_without_opaque}
]
