# Linx.Sysctl — implementation plan

> 🟡 **Not yet started.** Planning doc only; nothing on disk under
> `lib/linx/sysctl*` or `c_src/linx_sysctl.c` yet. Sequencing is
> S0 (scaffolding) → S1 (host read/write + Error) → S2 (subtree
> walking + value types) → S3 (cross-namespace via `:in`, NIF).
> Each lands as its own commit; `COVERAGE.md` becomes the canonical
> "what's in / what's deferred" tracker as the surface ships.

## Goal

Build the foundations of `Linx.Sysctl`: the kernel's tunable-parameter
surface — `/proc/sys/...` — exposed as Elixir primitives. The driving
use cases are setting `net.ipv4.ip_forward` for routing, `kernel.hostname`
for a container's UTS, and the other ~1500 knobs that the `sysctl(8)`
shell tool exposes today. The library needs to work both **host-side**
(useful from a Nerves application or a normal Elixir release that needs
to flip a kernel knob) and **container-side** at any point in a
`Linx.Process` workload's life — at the checkpoint between `clone(2)`
and `execve(2)`, or post-`proceed/1` against a fully-running namespace.

The motivating compositions:

    # Host: enable IPv4 forwarding from a Nerves app.
    :ok = Linx.Sysctl.write("net.ipv4.ip_forward", 1)

    # Container, at the checkpoint: set hostname before the workload runs.
    {:ok, c} = Linx.Process.spawn(argv: ["/bin/bash"], namespaces: [:uts, :net])
    receive do {:linx_process, :ready, _} -> :ok end
    {:ok, host_pid} = Linx.Process.host_pid(c)
    :ok = Linx.Sysctl.write("kernel.hostname", "ct0", in: {:pid, host_pid})
    :ok = Linx.Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, host_pid})
    Linx.Process.proceed(c)

`Linx.Sysctl` is **not** a sysctls.conf parser, an applier-with-rollback,
or a policy layer. It exposes "read this knob", "write this knob",
"walk this subtree" — host and cross-namespace. A `sysctl.conf` consumer
is a one-screen module on top, and lives in a consumer (or a follow-up).

## Guiding principles

**Mostly pure Elixir.** The kernel exposes sysctls as plain files under
`/proc/sys/`. Reading and writing is `File.read/1` and `File.write/2` —
no NIF needed for the host-side case. The only thing the BEAM can't do
safely on its own is `setns(2)` for the cross-namespace case (S3); that
gets a tiny NIF, same pattern as `Linx.Mount` and `Linx.Netlink`.

**Sysctls are mostly per-namespace.** The kernel routes each
`/proc/sys/...` read or write through the *calling task's* namespace
context, not the procfs mount. Concretely:

| Subtree | Owning namespace | Example knobs |
|---|---|---|
| `net.*` | network | `net.ipv4.ip_forward`, `net.core.somaxconn`, `net.ipv4.tcp_*` |
| `kernel.hostname`, `kernel.domainname` | UTS | hostname / NIS domain |
| `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*` | IPC | sysv-IPC + posix-mq limits |
| `user.max_*_namespaces` | user | per-userns nesting limits |
| `vm.*`, `fs.file-max`, `kernel.printk`, most else | global | host-only |

Trying to traverse `/proc/<pid>/root/proc/sys/...` to "see another
namespace's value" does **not** work — the kernel resolves the value
against the *reader's* namespace, not the path. The only way in is
`setns(2)`.

**`:in :: :self | {:pid, n} | {:path, p}`, same shape as
`Linx.Mount`.** Default is `:self` — the host. For cross-namespace,
`{:pid, n}` joins all of the target's relevant namespaces (net + UTS +
IPC + mount + user) on a throwaway pthread, performs the file I/O,
and exits. We don't dispatch by key prefix — entering the full stack
is uniformly correct and cheaper than asking the caller to think
about which namespace owns which knob. Global sysctls remain
host-only regardless of `:in` (the kernel returns the same value
from any namespace).

**Weak typing on values.** Sysctls are loosely typed at the kernel
level: most are integers, some are space-separated tuples
(`kernel.printk` is `"4 4 1 7"`), some are strings (`kernel.hostname`),
some are `0` / `1` booleans. We don't try to schema them. `read/1`
returns the raw trimmed string; `read_int/1` and `read_ints/1` are
thin convenience wrappers for the common cases. `write/2` accepts
integers, strings, and lists of integers, calling `to_string/1` at
the boundary.

**Keys in dot form.** `net.ipv4.ip_forward`, not
`net_ipv4_ip_forward` and not `["net", "ipv4", "ip_forward"]`. The
dot form is what `sysctl(8)` prints, what `/etc/sysctl.d/*.conf`
contains, and what every other tool in the ecosystem accepts. We
convert dots ↔ slashes internally to map to/from `/proc/sys/...`
paths.

**Errors as structs.** `%Linx.Sysctl.Error{key, path, operation, errno,
code}`, matching the project's convention (`%Linx.Cgroup.Error{}`,
`%Linx.Mount.Error{}`, etc.). Operations: `:read`, `:write`,
`:list`, plus `:open_ns` / `:unshare` / `:setns` / `:thread` for the
S3 cross-namespace failure modes. Caller-side input mistakes (a key
with embedded `..`, an empty string, a non-printable value) come back
as `{:error, {:bad_key, reason}}` or `{:error, {:bad_value, reason}}`
— distinct shape so consumers can match cleanly.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec`
everywhere; structs with `@enforce_keys`; one module per file; cite
`sysctl(8)`, `proc(5)`, and `Documentation/admin-guide/sysctl/`
where interpretation is non-obvious.

## Module structure

```
Linx.Sysctl                     — public API: supported?/0, read/1,
                                  read_int/1, read_ints/1, write/2,
                                  write/3 (with :in), list/0, list/1.

Linx.Sysctl.Entry               — %Linx.Sysctl.Entry{key, value}
                                  returned by list/0..1. Custom
                                  Inspect: #Linx.Sysctl.Entry<
                                  net.ipv4.ip_forward = "1">.

Linx.Sysctl.Error               — %Linx.Sysctl.Error{key, path,
                                  operation, errno, code} +
                                  Exception impl + from_posix/4.

Linx.Sysctl.Native              — (S3 only) tiny NIF for the
                                  setns-on-a-thread cross-namespace
                                  file write. Read side too: reading
                                  another netns's value also needs
                                  setns.

  c_src/linx_sysctl.c           — (S3 only) NIF source: unshare(CLONE_FS)
                                  + setns(target_ns_fds) + read/write +
                                  thread exits.
  lib/mix/tasks/compile.linx_sysctl.ex
                                — (S3 only) sibling to compile.linx_mount.
```

Through S2, no NIF, no C source, no compile task — pure Elixir.

## The procfs surface

| Path shape | Maps to | Read | Write |
|---|---|---|---|
| `/proc/sys/net/ipv4/ip_forward` | `net.ipv4.ip_forward` | `"0\n"` or `"1\n"` | `"0"` or `"1"` |
| `/proc/sys/kernel/hostname` | `kernel.hostname` | hostname string | new hostname |
| `/proc/sys/kernel/printk` | `kernel.printk` | `"4\t4\t1\t7\n"` | four space-or-tab-separated ints |
| `/proc/sys/net/ipv4/tcp_rmem` | `net.ipv4.tcp_rmem` | three ints | three ints |
| (directories) | namespace nodes in the tree | `readdir(2)` for subtree walking | n/a |

Trailing newline handling: the kernel inserts a `\n` after every
scalar value on read. `read/1` trims it; `write/2` doesn't append
one — the kernel accepts either form.

The kernel's documentation for the tree itself is split across
`Documentation/admin-guide/sysctl/{kernel,net,vm,fs,user,abi}.rst`
in the kernel source. Per-protocol details (e.g. all the
`net.ipv4.*` knobs) live in `Documentation/networking/ip-sysctl.rst`.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship
with the code that needs them; commit + push per milestone.

### S0 — Scaffolding

- `Linx.Sysctl` module skeleton (`@moduledoc`, public API stubs
  returning `{:error, :not_yet_implemented}`).
- `Linx.Sysctl.supported?/0` returns `true` iff
  `/proc/sys/kernel/ostype` exists (true on any Linux kernel; the
  knob has been there since before namespaces).
- `docs/sysctl/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md` skeletons
  (this doc; the others stubbed for fill-in as primitives ship).
- Wire `docs/sysctl/*.md` into `mix.exs` `docs.extras` + groups.
- **Tests:** `supported?/0` returns a boolean. Plain `mix test`,
  no root.

### S1 — Host read/write + Error

- `Linx.Sysctl.Error` — struct + `Exception` impl +
  `from_posix/4` builder mapping `File`'s posix atoms to our error
  shape with `key`, `path`, and `operation` set.
- `Linx.Sysctl.read(key)` — reads `/proc/sys/<dot-to-slash>`, trims
  trailing whitespace, returns `{:ok, binary}` or
  `{:error, %Error{}}`.
- `Linx.Sysctl.read_int(key)` — `read/1` + `Integer.parse/1`.
  Returns `{:error, {:bad_value, reason}}` on non-integer
  contents (e.g. someone asking `read_int/1` on `kernel.hostname`).
- `Linx.Sysctl.read_ints(key)` — `read/1` + split on whitespace +
  `Integer.parse/1` per token. For `kernel.printk`,
  `net.ipv4.tcp_rmem`, etc.
- `Linx.Sysctl.write(key, value)` — host-side write. `value` is an
  integer, a binary, or a list of integers (joined with spaces).
- Key validation rejects empty strings, leading/trailing dots,
  double dots, `..` segments (path traversal guard), and any
  character outside `[A-Za-z0-9_.-]`. Failures: `{:error, {:bad_key,
  reason}}`.
- Value validation rejects newlines and `NUL` in binary values;
  the kernel's parsers treat newlines as end-of-input, so passing
  a multi-line string would silently truncate. Failures:
  `{:error, {:bad_value, reason}}`.
- **Tests:**
  - Plain: input validation (bad keys, multi-line values) →
    `:bad_key` / `:bad_value`. Bogus key → `%Error{errno: :enoent}`.
  - Integration (`:integration`, run via `./sudotest.sh`): write
    `net.ipv4.ip_forward` to its current value (no-op round-trip),
    read it back. Read `kernel.ostype` and assert it equals
    `"Linux"`. Read `kernel.printk` via `read_ints/1` and assert
    a 4-element integer list.

### S2 — Subtree walking + `Linx.Sysctl.Entry`

- `Linx.Sysctl.Entry` — `%Linx.Sysctl.Entry{key, value}` with
  `@enforce_keys` on both fields. Custom `Inspect`:
  `#Linx.Sysctl.Entry<net.ipv4.ip_forward = "1">`.
- `Linx.Sysctl.list/0` — walks `/proc/sys/` recursively, reads
  every scalar (skips directories), returns `{:ok,
  [%Entry{}, ...]}`. Skips unreadable nodes (some sysctls return
  `EPERM` on read for unprivileged callers) silently — the
  returned list is "everything I could see", not "everything that
  exists".
- `Linx.Sysctl.list/1` — same with a subtree key prefix:
  `list("net.ipv4")` walks only `/proc/sys/net/ipv4/`. The
  trailing `*` is implicit; we don't accept globs.
- Walking is **lazy-friendly**: list/0 on a typical host returns
  ~1500 entries, which is fine for an `{:ok, [...]}` shape.
  A `stream/0..1` returning an enumerable can come later if a
  consumer asks; not built here.
- **Tests:**
  - Plain: `Entry` Inspect rendering; struct shape.
  - Integration: `list/0` returns a non-empty list containing
    `kernel.ostype`. `list("net.ipv4")` returns only entries
    with that prefix.

### S3 — Cross-namespace via `:in`

- `Linx.Sysctl.Native` — NIF init, `version/0`,
  `read_in_ns/2` (key as binary, ns_fd_list as list of ints),
  `write_in_ns/3` (key, value, ns_fds), `open_nsfd/2`,
  `close_nsfd/1`.
- `c_src/linx_sysctl.c` — minimal NIF. Each cross-ns op spawns
  a throwaway pthread; the thread does `unshare(CLONE_FS)` (so
  CWD changes don't leak), then `setns(fd, 0)` for each fd in
  the list (mount + user + UTS + IPC + net — the kernel accepts
  passing `0` for the second arg, meaning "detect from the file
  type"), then performs the file I/O, then exits. Mirrors
  `c_src/linx_mount.c`'s structure end-to-end.
- `lib/mix/tasks/compile.linx_sysctl.ex` — sibling to
  `compile.linx_mount` and friends.
- `mix.exs` `:compilers` gains `:linx_sysctl`.
- `Linx.Sysctl.read/1`, `read_int/1`, `read_ints/1`, `write/2`,
  `list/0..1` all gain an `:in` option:
  - `:self` (default) — the BEAM's namespaces (pure Elixir path).
  - `{:pid, n}` — joins `/proc/<n>/ns/{net,mnt,uts,ipc,user}`,
    performs the op via the NIF.
  - `{:path, p}` — explicit nsfd path (less common; primarily
    for testing or for callers that already hold a pinned ns
    bind-mount).
- `Linx.Sysctl.Error` gains operations `:open_ns`, `:unshare`,
  `:setns`, `:thread`, `:chdir` — matching `Linx.Mount.Error`'s
  shape — so consumers can distinguish namespace-acquisition
  failures from the real read/write failure.
- **Tests:**
  - Integration: spawn `/bin/sleep 60` with `namespaces: [:net,
    :uts]`, proceed, then:
    - `Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, host_pid})`
      followed by `Sysctl.read_int("net.ipv4.ip_forward",
      in: {:pid, host_pid})` returning `1`, while the host's
      value is unchanged.
    - `Sysctl.write("kernel.hostname", "ct-test", in: {:pid,
      host_pid})` followed by `Sysctl.read("kernel.hostname",
      in: {:pid, host_pid})` returning `"ct-test"`, while
      the host's hostname is unchanged.
  - Integration: the same trick *at* the checkpoint (between
    `:ready` and `proceed/1`) — confirm the value lands before
    the workload `execve`s.
  - Document the `:user` namespace caveat in `EXAMPLES.md`: a
    rootless BEAM trying to write a sysctl into a container in
    a separate user ns where it isn't root in that user ns will
    see `EPERM`. Expected.

## Testing

Same three bands as the other subsystems:

- **Unit.** Module loading, struct shapes, `Error` formatting,
  `Entry` parsing + Inspect, input validation (`:bad_key`,
  `:bad_value`). Plain `mix test`.
- **Integration.** Anything that touches `/proc/sys/...` for
  real-world values, and anything that crosses a namespace —
  `:integration` tag, run via `./sudotest.sh`. Each test that
  mutates a host-level knob round-trips through the original
  value (read first, write back in `on_exit`).
- **Manual / `docs/sysctl/EXAMPLES.md`.** End-to-end
  compositions — the Nerves "enable forwarding" recipe, the
  per-container hostname / forwarding recipe at the checkpoint,
  a `list("net.ipv4")` sample.

## Deferred — architected-for, not built here

- **`sysctl.conf` parser / applier.** `/etc/sysctl.d/*.conf` and
  the `sysctl --system` workflow. One-screen consumer module on
  top of `read/1` + `write/2`; lives outside Linx so distros and
  consumers can pick their own dotfile semantics. (Nerves bakes
  these into the system image; standalone releases tend to want
  programmatic control anyway.)
- **Rollback / transactional writes.** A `with_sysctl/2` helper
  that snapshots a value, runs a body, and restores on exit. Easy
  to write on top of read+write; lives in a consumer when one
  needs it.
- **Streaming `list/0..1`.** Lazy enumerable for callers that
  want to walk `/proc/sys/` without materializing ~1500 entries.
  Built only when a consumer's profile demands it.
- **Watching / notification.** `inotify` on `/proc/sys/...`
  doesn't actually work the way you'd hope (sysctls aren't
  inotify-friendly). A polling helper could come later; out of
  scope.
- **Native sysctl(2) syscall.** Removed from Linux in 5.5
  (deprecated since 2.6.24). We don't expose it at all.
- **Per-key typed schemas.** A registry of "this key is an int,
  that key is a 3-int tuple" — useful for typed config builders
  but enormous scope (sysctls have no machine-readable schema).
  Out of scope. Consumers that know their key's shape use
  `read_int/1` / `read_ints/1` directly.

## Decisions

1. **Mostly pure Elixir.** Pure file I/O on `/proc/sys/...` for
   S0–S2. A tiny NIF arrives in S3 for the cross-namespace case,
   same pattern as `Linx.Mount`.
2. **`:in` option, same shape as `Linx.Mount`.** `:self` /
   `{:pid, n}` / `{:path, p}`. Lifecycle-agnostic: works at the
   checkpoint, post-`proceed/1`, or against any unrelated pid.
3. **Enter the target's whole namespace stack** for cross-ns
   ops, not just the namespace that owns the key's subtree. Simpler
   and the throwaway pthread is cheap; the kernel ignores `setns`
   for namespaces it doesn't route the key through.
4. **Dot-form keys** matching `sysctl(8)` / `sysctl.conf`. Internal
   dot ↔ slash mapping. No globs in `list/1` — prefix only.
5. **Weak typing.** `read/1` → trimmed binary; `read_int/1` and
   `read_ints/1` for the common integer cases; `write/2` accepts
   ints / binaries / int lists. No per-key schema.
6. **Errors as structs.** `%Linx.Sysctl.Error{key, path,
   operation, errno, code}`. Caller-side input failures use
   `{:bad_key, reason}` / `{:bad_value, reason}` — distinct
   shape from kernel errors, matching the `Linx.Mount` / `Linx.User`
   precedent.
7. **No `Linx.Process` change.** No `:sysctls` option on
   `spawn/1`. The checkpoint is the *common* integration window,
   but `Linx.Sysctl` works equally for any post-`proceed/1` time
   — adding subsystem-specific options to `spawn` would couple
   things the design deliberately keeps independent.
8. **No `sysctl.conf` parser in Linx.** Belongs in a consumer.
   The primitive `read/1` + `write/2` covers the actual use case
   from Nerves and from standalone releases; building a full conf
   applier inside Linx would mix policy with mechanism.
