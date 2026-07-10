[
  # Deliberate forward-looking clauses: no host-byte-order field is 8 bytes
  # wide today, so the size-8 encode_int_host clause can't currently match.
  # Kept so a future 64-bit meta/ct field encodes instead of crashing.
  {"lib/linx/nft/compiler.ex", :pattern_match},
  {"lib/linx/nft/runtime_compiler.ex", :pattern_match},

  # Defensive `value_meta(other) || meta` fallbacks inside raise_at! error
  # branches: dialyzer proves the fallback arm dead at today's call sites.
  # Kept as belt-and-braces; to revisit in the NFT parity work.
  {"lib/linx/nft/compiler.ex", :guard_fail},

  # Include-cycle detection threads a MapSet through recursive parse
  # functions; dialyzer's opaque tracking loses the type through the
  # context map (known false-positive shape for recursive opaques).
  {"lib/linx/nft.ex", :call_without_opaque},
  {"lib/linx/nft.ex", :call_with_opaque},

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
