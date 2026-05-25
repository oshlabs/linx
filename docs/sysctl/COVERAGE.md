# Linx.Sysctl coverage

What of the kernel's `/proc/sys/` tunable surface `Linx.Sysctl`
exposes today, what is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Lifecycle / detection

| Feature | Status | Notes |
|---|---|---|
| `supported?/0` | ✅ | S0 — true iff `/proc/sys/kernel/ostype` exists (any Linux with procfs) |

## Read side

| Feature | Status | Notes |
|---|---|---|
| `read/1` | ✅ | S1 — trimmed binary; `{:error, %Sysctl.Error{}}` on kernel failure |
| `read_int/1` | ✅ | S1 — `read/1` + `Integer.parse/1`; `:bad_value` on non-integer |
| `read_ints/1` | ✅ | S1 — split on whitespace, parse each (`kernel.printk`, `tcp_rmem`, …) |

## Write side

| Feature | Status | Notes |
|---|---|---|
| `write/2` | ✅ | S1 — accepts integer, binary, list of integers |
| Key validation (`{:bad_key, reason}`) | ✅ | S1 — reject empty, `..`, traversal, non-`[A-Za-z0-9_.-]` |
| Value validation (`{:bad_value, reason}`) | ✅ | S1 — reject newlines / NUL (kernel would silently truncate) |

## Subtree walking

| Feature | Status | Notes |
|---|---|---|
| `list/0` | ✅ | S2 — walks all of `/proc/sys/`, skips unreadable nodes, sorted by key |
| `list/1` | ✅ | S2 — subtree by dot-form prefix; leaf-prefix returns single-element list |
| `Linx.Sysctl.Entry` value type | ✅ | S2 — `%{key, value}` with compact Inspect (60-byte value truncation) |

## Cross-namespace

| Feature | Status | Notes |
|---|---|---|
| `:in :: :self` (default) | ✅ | S3 — pure-Elixir host path |
| `:in :: {:pid, n}` | ✅ | S3 — NIF, setns onto target's namespace stack on a throwaway pthread; same-namespace fds skipped via inode comparison so the EINVAL trap from setns'ing into your own ns doesn't fire |
| `:in :: {:path, p}` | ✅ | S3 — explicit nsfd path; mirrors `Linx.Mount`. No same-ns filter — caller is on their own |
| `Linx.Sysctl.Native` (NIF) | ✅ | S3 — `c_src/linx_sysctl.c` (~430 lines); exposes `read_in_ns/2`, `write_in_ns/3`, `list_in_ns/2`, `version/0` |
| `compile.linx_sysctl` task | ✅ | S3 — sibling of `compile.linx_mount` |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Sysctl.Error{key, path, operation, errno, code}` | ✅ | S1 |
| `Exception` impl for `raise`-able paths | ✅ | S1 |
| `{:bad_key, reason}` / `{:bad_value, reason}` | ✅ | S1 — distinct from kernel-level errors |
| Namespace-acquisition errors (`:open_ns`, `:unshare`, `:setns`, `:thread`) | ✅ | S3 — surfaced as `%Linx.Sysctl.Error{operation: stage}` so consumers can distinguish setns failures from the actual I/O failure |
| `{:bad_in, reason}` for malformed `:in` values | ✅ | S3 — caught before any NIF call |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` checkpoint via `:in: {:pid, host_pid}` | ✅ | S3 — same lifecycle-agnostic shape as `Linx.Mount`. Works between `:ready` and `proceed/1` and post-`proceed/1` |

## Deferred — not in `Linx.Sysctl` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for
the full list with reasoning:

- `sysctl.conf` / `/etc/sysctl.d/*.conf` parsing + applier — belongs
  in a consumer, not in Linx
- Rollback / `with_sysctl/2` transactional helper — easy to write on
  top of `read/1` + `write/2`
- Streaming `list/0..1` (lazy enumerable) — built when a consumer's
  profile demands it
- `inotify` / watching — sysctls aren't inotify-friendly; out of
  scope
- The legacy `sysctl(2)` syscall — removed in Linux 5.5, never
  exposed
- Per-key typed schemas — kernel exposes no machine-readable schema
  for sysctls; out of scope
