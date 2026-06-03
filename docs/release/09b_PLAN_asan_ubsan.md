# 09b — ASan / UBSan over the native code

**Status:** planned · **Gates 0.1.0:** no (fast-follow) · **Topic:** sanitizer coverage for the C layer

Split from `09`. Builds on the privileged integration job: sanitizers are only meaningful
while exercising the kernel paths, which need root + namespaces.

## Problem
The 5 native units (4 NIFs + the `linx_process` port, ~4000 lines of C) are never run under
a memory/UB sanitizer. The `07` zero-length fixes, the fd/resource discipline in
`linx_process`, and the netlink attribute handling are exactly what ASan/UBSan would catch
regressions in — and CI has no such coverage.

## Decision / approach
Build the native code with `-fsanitize=address,undefined` and run the integration suite
under it, in two parts of differing difficulty:

1. **Port first (`linx_process`) — straightforward.** It's a standalone executable, so
   sanitizing it is a normal instrumented build; ASan/UBSan run in its own OS process with
   no BEAM entanglement. Add a sanitizer build flag to `compile.linx_process.ex` (gated by
   an env, e.g. `LINX_SANITIZE=1`) and run the process integration tests against it.
2. **NIFs — fiddly.** A sanitized `.so` loaded into the BEAM needs
   `LD_PRELOAD=$(cc -print-file-name=libasan.so)` (and typically
   `ASAN_OPTIONS=detect_leaks=0:halt_on_error=0` to avoid the BEAM's own allocations
   tripping leak detection). Expect noise; triage real findings from BEAM-runtime
   background. Land this leg only after it's stable enough to be signal, not noise.

Wire both as **non-required** CI legs (same gating philosophy as `09`), or as a manually
triggered `workflow_dispatch` job if the NIF leg proves too noisy for every push.

## Coupling
- `09` — runs on the same privileged runner; sanitizers need the kernel paths exercised.
- `07` — the zero-length / overflow / recursion fixes are the first thing this should
  confirm clean.
- `06` — the sanitizer flag is added via the same compile-task seam touched by the
  preflight (kept minimal there; this adds the flag).

## Concrete changes
- `lib/mix/tasks/compile.*.ex` — optional `-fsanitize=address,undefined` build path behind
  `LINX_SANITIZE` (port first; NIFs when ready).
- `.github/workflows/ci.yml` — a sanitizer leg (non-required or `workflow_dispatch`), with
  `LD_PRELOAD`/`ASAN_OPTIONS` for the NIF case.

## Acceptance check
- The `linx_process` integration tests run green under ASan/UBSan with no real findings
  (the `07` paths included).
- The NIF leg runs under `LD_PRELOAD` libasan and distinguishes genuine findings from BEAM
  background; any real finding is fixed or filed.

## Risk / scope notes
- Fast-follow; the NIF-under-BEAM setup is the hard part and may stay `workflow_dispatch`
  rather than per-push.
- Sanitizer findings here may loop back into `07` or new C fixes; that's the point.
