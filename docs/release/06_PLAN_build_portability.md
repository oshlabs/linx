# 06 — Build UX / portability preflight

**Status:** planned · **Gates 0.1.0:** yes (consumer-facing install UX) · **Topic:** the custom C compilers

For a hex package that compiles C on the consumer's machine, the failure modes on the
wrong machine must be legible. Today they aren't.

## Problem
The 5 compile tasks (`lib/mix/tasks/compile.{netlink_nif,linx_process,linx_tty,linx_mount,linx_sysctl}.ex`)
invoke `cc` with **no platform guard**:
- **Non-Linux** (`mix deps.compile` on macOS/BSD/Windows) → a raw compiler dump (e.g.
  `linux/netlink.h: No such file`) surfaced through `Mix.raise("…: cc failed (exit 1)\n<dump>")`.
- **No C compiler** → `System.cmd("cc", …)` throws a raw `:enoent`/ArgumentError, before any
  friendly message.
- **Old kernel** → compiles fine, then fails at *runtime* with `ENOSYS`.

## Decision / approach (minimal for 0.1.0)
Add a small shared **preflight** helper, called at the top of each task's `run/1`, before
it shells out to `cc`. **Guards only** — the 5 duplicated task bodies are left as-is; the
broader de-duplication of the shared scaffolding (`compile/2`, `stale?/2`, `output_path/0`,
`erts_include_dir/0`) is filed as a **separate post-0.1.0 cleanup**, since it rewrites
build-critical code that CI doesn't exercise well.

Three guards:
1. **OS — hard error on non-Linux.** `:os.type()` ≠ `{:unix, :linux}` →
   `Mix.raise` with: *"Linx provides Linux kernel interfaces and only builds on Linux.
   Detected: <os>. See the README requirements."* Fails fast, before `cc`.
2. **C toolchain — friendly error if `cc` is missing.** `System.find_executable(cc)` (cc =
   `System.get_env("CC", "cc")`) returns `nil` → `Mix.raise` pointing at the README's
   per-distro build prerequisites (the block added in `01`: `build-essential` /
   `base-devel`).
3. **Kernel floor — warn, don't error.** If the build-host kernel
   (`/proc/sys/kernel/osrelease`) is below **6.6 LTS** (the supported floor stated in the
   README), emit a `Mix.shell().info` warning noting the floor and the cross-compile
   caveat — but **proceed** (cross-compiling for a newer target, e.g. Nerves, is valid).
   The ~5.8 syscall-availability floor stays a C-source comment; 6.6 LTS is the single
   stated number.

## Coupling
- `01` adds the per-distro prerequisites the cc-missing message references.
- `09` (CI) — ASan/UBSan build flags and any non-Linux CI leg live there; a non-Linux leg
  would now produce the clean OS message.

## Concrete changes
- New shared helper (e.g. `lib/mix/tasks/linx_compiler_preflight.ex` or a private module)
  with `os_guard/0`, `cc_guard/1`, `kernel_warn/0`.
- Each of the 5 `compile.*.ex` — one preflight call at the top of `run/1`. No other change.

## Acceptance check
- `mix compile` with `:os.type()` stubbed non-Linux raises the friendly OS message, not a
  compiler dump.
- `CC=/nonexistent mix compile` raises the cc-missing message before any compile attempt.
- On a <6.6 kernel, build warns but succeeds.
- All 5 NIFs/port still build unchanged on a supported Linux host.

## Risk / scope notes
- Low risk: guards are additive and run before the existing compile path; no change to how
  the C is actually built.
- Deliberately **not** de-duplicating the compile scaffolding now — tracked as a separate
  cleanup so a build-path rewrite doesn't ride into the release.
- A truly robust pre-floor *runtime* error (clearer than `ENOSYS`) is out of scope; `02a`'s
  structured errors already surface `ENOSYS` as a `%Linx.X.Error{}`.
