# 07 — C zero-length edge cases (+ load-bearing comment)

**Status:** done · **Gates 0.1.0:** yes (C correctness, cheap) · **Topic:** native code hardening

Small, localized C edits from the pre-release C review. All four sites are reachable today
only via the public Elixir API (which validates inputs), so these are latent — not live —
bugs; the review flagged the zero-length cases as "fix before release."

## Problem (verified)
- **HIGH — zero-length seccomp blob** (`c_src/linx_process.c:1138`): `bpf =
  malloc((size_t)bsize)` with `bsize` possibly `0` (a `<<>>` filter); `malloc(0)` may
  return `NULL` → `child_fail(…, ENOMEM, STAGE_SECCOMP_INSTALL)`. An empty filter thus dies
  with the *wrong* errno (it's invalid input, not OOM), and `apply_seccomp` already rejects
  `len==0` downstream (`:1010`) anyway.
- **HIGH — empty list / multiply overflow** (`c_src/linx_sysctl.c:170`, repeated at
  `:356,:456,:638`): `enif_alloc(length * sizeof(char *))` — `length==0` → `enif_alloc(0)`
  may return `NULL` → caller treats it as failure → `badarg`; and `length * sizeof(...)` is
  unchecked (overflow on a hostile huge list).
- **MEDIUM — unbounded recursion with a big frame** (`c_src/linx_sysctl.c:560,587`
  recursive `walk_dir`; `:664` `char buf[PATH_MAX]`): one ~4 KiB stack frame per directory
  level, no depth cap. `/proc/sys` is shallow, so bounded in practice.
- **MEDIUM — undocumented load-bearing invariant** (`c_src/linx_process.c:1903`):
  `static char child_stack[CHILD_STACK_SIZE]` is safe **only** because the agent clones
  exactly once per process lifetime; the comment explains frame size but not the
  single-shot invariant.

## Decision / approach
1. **Seccomp zero-length** (`linx_process.c:1138`) — **explicit `EINVAL` guard before
   `malloc`**: if `bsize <= 0`, `child_fail(c2p_w, EINVAL, STAGE_SECCOMP_INSTALL)` (a clean
   validation error), rather than falling into the `ENOMEM` path or relying on the
   downstream reject.
2. **sysctl alloc** (`linx_sysctl.c:170` + `:356,:456,:638`) — handle `length == 0`
   (return a valid empty array / distinct success, never `NULL`-as-failure), and add an
   upper bound on `length` before the multiply to eliminate the overflow path.
3. **walk_dir recursion** (`linx_sysctl.c:560`) — add a recursion **depth cap** with a
   clean bail, so a pathological tree can't blow the worker-thread stack.
4. **child_stack comment** (`linx_process.c:1903`) — extend the comment to state the
   **single-shot invariant**: safe only because the agent clones once per process; looping
   to a second spawn would clobber this static buffer.

Both MEDIUMs are included (cheap, same files as the HIGHs).

## Verification
- These paths are hard to reach from the validated public API, so unit coverage is awkward.
- Primary backstop: **ASan/UBSan over the NIFs (topic `09`)** built with
  `-fsanitize=address,undefined`, plus targeted integration cases — an empty seccomp filter
  and an empty ns list — under `./sudotest.sh`.
- `mix compile` stays warning-clean under `-Wall -Wextra -Wpedantic`.

## Concrete changes
- `c_src/linx_process.c` — EINVAL guard (`:1138`); child_stack comment (`:1903`).
- `c_src/linx_sysctl.c` — `length==0` handling + multiply bound (`:170` and the three
  sibling sites); `walk_dir` depth cap (`:560`).

## Acceptance check
- An empty seccomp filter yields a clean validation error (`EINVAL` → the corresponding
  `%Linx.Process.Error{}` after `02a`), not `ENOMEM`.
- An empty ns list does not produce a spurious `badarg`.
- A crafted deep `/proc/sys`-like tree bails cleanly rather than recursing unbounded.
- Builds warning-clean; ASan/UBSan run (in `09`) reports no new issues on these paths.

## Risk / scope notes
- Low risk; additive guards on edge inputs, no change to the common path.
- Verification is integration/sanitizer-gated (CI doesn't run it — topic `09`); a manual
  `./sudotest.sh` + sanitizer build on the release commit is the gate.
- The separately-noted LOW C items (signalfd-drain EINTR precision; `Tty.version/0`
  badarg-vs-error shape) are **not** in scope here; capture them as post-0.1.0 if desired.
