# Linx.Process — implementation plan

> **P0–P5 have shipped**: P0–P4 on branch `process-foundations`, P5
> (`abort/1`) on branch `process-abort`. P0–P4 covered the
> Port-based agent, `Linx.Process.spawn/1` with the checkpoint protocol,
> namespace selection (`:net` verified end-to-end against `Linx.Netlink`),
> structured pre-exec errors, `proceed/1`, `signal/2` (with pre-running
> buffering), `wait/1`/`wait/2`, `enter/2` for joining an existing
> target's namespaces, and `:stdio` plumbing primitives including PTY.
> P5 added `abort/1` — release a parked session without `execve`'ing,
> with a distinct `{:linx_process, :aborted}` terminal event.

## Goal

Build the foundations of `Linx.Process`: a small set of Linux process-lifecycle
**primitives** — spawn a child in fresh namespaces of selected types, join an
existing process's namespaces, wait for exit, send signals. The primitives are
designed to compose with `Linx.Netlink` (so a caller can clone a child with
`CLONE_NEWNET`, drive netlink inside the new netns through the child's pid,
then have the child proceed past the checkpoint to exec).

`Linx.Process` is **not** a container runtime. It provides the primitives a
runtime is built from. Image management, supervision policies, rootfs setup,
stdio capture, cgroup placement and userns id maps belong to a consumer of
Linx, not to Linx itself.

## Guiding principles

**The OS-process boundary is mandatory.** `clone()`/`fork()`/`unshare()` inside
the multithreaded BEAM corrupts the VM — every kernel and runtime source on
the subject agrees. So the actual syscall runs in a small external C agent
spawned via `Port.open`, never in a NIF. This mirrors silo's `silo-init` rule
and is non-negotiable.

**One C binary, two modes.** A single `linx_process_agent` covers both *create*
mode (`clone()` into fresh namespaces) and *enter* mode (`setns()` into an
existing process's namespaces, then `execve`). The two modes share ~all the
code (framing, supervise loop, error reporting); only the few lines of "how
the child enters namespaces" differ.

**A checkpoint protocol over fd 3/4.** Erlang Port with `:nouse_stdio` +
`{:packet, 4}`, payload is ETF. The cloned child reports its host pid
*before* the checkpoint so the orchestrator can address it (move a netlink
interface in, write cgroup state, …) while the child waits at `ready`. When
the orchestrator replies `:proceed`, the child `execve`s the workload. Errors
arrive as `{:error, errno, stage}` — the stage atom names the syscall that
failed.

**Pure primitives.** The Elixir side exposes operations, not policy. A
`Linx.Process.Session` represents one cloned child or exec session; callers
get events on its lifecycle (`:ready`, `:running`, `:exit`, `:error`) and
drive it with `proceed/1`, `signal/2`, `wait/1`. Anything higher-level
(stdio capture, mini-init, rootfs choreography) lives in a consumer.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec` everywhere; structs
with `@enforce_keys`; one module per file; kernel-ABI citations (man page /
UAPI struct / kernel source) in comments.

## Module structure

```
Linx.Process                    — the GenServer + public API:
                                  spawn/1, enter/2, proceed/1, signal/2, wait/1,
                                  info/1, pty_master/1. Owns the Port to
                                  linx_process. No nested Session module — the
                                  GenServer pid IS the session handle.

  build
  c_src/linx_process.c          — the Port binary; clone/setns + checkpoint
  lib/mix/tasks/compile.linx_process.ex
                                — sibling to compile.netlink_nif
```

The C binary's name matches the Elixir namespace exactly — one word names the
whole subsystem, on both sides of the FFI line, and reads cleanly in `ps`
output.

Sequence numbers, atoms, framing details are deliberately not pinned down
here — they emerge during P0/P1 implementation, like the netlink wire
primitives did.

## The agent contract

The Port speaks ETF over fd 3/4 in `{:packet, 4}` frames. Both modes share
the same vocabulary:

**Outbound (agent → BEAM):**

  * `{:status, :spawned, host_pid}` — child cloned (create mode); the
    orchestrator can address it from here on. *Create mode only.*
  * `{:status, :ready, child_pid}` — child reached the checkpoint; namespaces
    created (create mode) or joined (enter mode); waiting for `:proceed`.
  * `{:status, :running, host_pid}` — child has `execve`'d the workload.
  * `{:status, :exited, exit_code}` — workload exited normally.
  * `{:status, :signaled, signum}` — workload killed by a signal.
  * `{:error, errno, stage}` — fatal failure before `execve`. `stage` is the
    syscall atom (`:clone`, `:setns`, `:execve`, …).

**Inbound (BEAM → agent):**

  * `:proceed` — advance past the checkpoint; the child may now `execve`.
  * `{:signal, signum}` — forward signal `signum` to the workload.

The agent owns no rootfs, no cgroup, no mount logic. Its job is *only*
namespace lifecycle, the checkpoint relay, and — when a fd directive asks
for it (P4) — fd plumbing in the child before `execve`.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship with the
code that needs them; commit + push per milestone.

### P0 — Scaffolding & the Port

✅ **Shipped.**

- `Linx.Process` module skeleton with `@moduledoc` and the public API
  function stubs (no logic). The module `use`s `GenServer` from the start —
  no nested Session module; the pid is the handle.
- Binary path resolution helper (private, internal to `Linx.Process`).
- `c_src/linx_process.c` — the smallest useful version: starts up, reads
  one ETF frame on fd 3, writes one ETF frame on fd 4, exits 0.
- `lib/mix/tasks/compile.linx_process.ex` — builds the binary into
  `priv/linx_process`; wired into `mix.exs` `:compilers`.
- **Tests:** spawn the binary, exchange a single round-trip ETF frame
  (e.g. `:ping` → `:pong`), assert clean exit. No root needed.

### P1 — `Linx.Process.spawn/1`: clone into fresh namespaces, checkpoint

✅ **Shipped.**

- Agent (create mode): `clone()` with namespace flags chosen by the request,
  emit `{:status, :spawned, host_pid}`, the child blocks at the checkpoint
  emitting `{:status, :ready, child_pid}`. On `:proceed`, the child runs the
  requested argv via `execve`. On any pre-exec failure, emit
  `{:error, errno, stage}` and exit non-zero.
- Elixir: `Linx.Process.spawn(opts)` returns `{:ok, pid}` — the pid is the
  GenServer that owns the Port and is the session handle. Owner receives:
  - `{:linx_process, :ready, child_pid}`
  - `{:linx_process, :running}`
  - `{:linx_process, :exited, code}` / `{:linx_process, :signaled, signum}`
  - `{:linx_process, :error, errno, stage}`
- `opts`: `:argv` (required), `:namespaces` (list of atoms `:net`, `:mount`,
  `:pid`, `:uts`, `:ipc`, `:user`, `:cgroup`, `:time`), `:env`, `:owner`.
- `Linx.Process.proceed(pid)` sends `:proceed`.
- **Tests:** integration (`:integration`, needs root) — spawn with
  `namespaces: [:net]`, in the checkpoint window open netlink in
  `{:pid, child_pid}` and assert the netns has only `lo`, call
  `proceed/1`, assert the child exec'd and exited cleanly.

### P2 — Lifecycle: `signal/2`, `wait/1`, exit status

✅ **Shipped.**

- `Linx.Process.signal(pid, signum)` — sends `{:signal, signum}` to the
  agent; buffered if the workload hasn't reached `:running` yet
  (matches silo's behaviour). Returns `{:error, :ended}` after the
  workload has finished.
- `Linx.Process.wait(pid, timeout \\ :infinity)` — synchronous wait for
  the terminal event; returns `{:ok, {:exited, code}}` /
  `{:ok, {:signaled, signum}}` / `{:error, %{errno: _, stage: _}}` /
  `{:error, :timeout}` / `{:error, :session_ended}`.
- Agent: SIGCHLD captured via `signalfd(2)` (blocked in the agent,
  unblocked in the child before `execve`), multiplexed against fd 3
  through a single `poll(2)` loop after `:running`. Workload exit
  reaped with `waitpid(2)` and reported as
  `{:status, :exited, code}` or `{:status, :signaled, signum}`.
- The session GenServer stays alive after the agent exits (no
  `{:stop, ...}` on the port's `:exit_status`) so `wait/1` races
  cleanly. Cleanup happens through `start_link`'s link to the spawn
  caller.
- **Tests:** plain — SIGTERM kills `/bin/sleep 60`; signal buffered
  pre-`proceed/1` lands on `:running`; `wait/1` returns immediately
  when the terminal already arrived; `wait/2` times out cleanly with
  `{:error, :timeout}`; `signal/2` after exit returns
  `{:error, :ended}`.

### P3 — `Linx.Process.enter/2`: exec inside an existing process

✅ **Shipped.**

- Agent (enter mode): `setns()` into the target's namespaces (one
  `open(/proc/<target>/ns/<type>, O_RDONLY|O_CLOEXEC)` + `setns(fd, 0)`
  per type, in setns-safe order — user first, pid last), then `fork()`,
  then the same checkpoint + `execve` path the cloned-child uses. The
  agent skips `setns` for any type whose `/proc/<self>/ns/<type>`
  inode already matches the target's (some kernels return `EINVAL` for
  setns-to-self, notably user namespaces).
- Elixir: `Linx.Process.enter(target_pid, opts)` — same event surface
  as `spawn/1`. `opts` accepts `:namespaces` to choose *which* of the
  target's namespaces to join; absent means "all of the target's
  namespace types that exist".
- Pre-exec failures carry namespace-specific stage atoms —
  `:setns_user`, `:open_ns_pid`, etc. — so the BEAM can pinpoint
  which namespace type couldn't be joined.
- **Tests:** plain — input validation (positive pid, argv required).
  Integration — spawn `/bin/sleep 60` in a fresh netns, enter that
  netns with `/bin/sh -c 'test "$(ip -o link | wc -l)" = "1"'` and
  assert `:exited 0` (only `lo` visible inside the target's netns).
  Both `:namespaces` not specified (join all) and `:namespaces: [:net]`
  (explicit) covered.

### P4 — Stdio plumbing primitives (including PTY)

✅ **Shipped.**

The C agent gains an optional `:stdio` directive controlling fd 0/1/2 in
the child before `execve`. *Pure mechanism* — no listener ownership, no
mailbox forwarding, no terminal-mode handling. Higher-level conveniences
belong in a consumer (or, for the PTY pumping loop, in a future
`Linx.Tty` subsystem; see the use case below).

- New option: `:stdio` — either a single atom shorthand (`:inherit`,
  `:devnull`, `:pty`) or a keyword list `[stdin: directive, stdout: …,
  stderr: …]`. Per-fd directives:
  - `:inherit` (default) — child inherits the BEAM's fd.
  - `:devnull` — child opens `/dev/null` and dups it on.
  - `{:connect_unix, path}` — child `connect(2)`s an `AF_UNIX` stream
    socket to the host path, then dups it on. The path's listener is the
    caller's responsibility (and is opened *before* `spawn/1`, so the
    connect succeeds).
  - `{:pty, opts}` — the agent creates a PTY pair in the parent before
    `clone()`, the child closes the master + does `dup2(slave, 0/1/2)` +
    `setsid()` + `ioctl(slave, TIOCSCTTY, 0)`, the parent closes the slave
    and proxies PTY bytes through the existing control channel framed as
    `{:pty_out, bytes}` (agent → BEAM) and `{:pty_in, bytes}` (BEAM →
    agent). `:opts` reserved for `:winsize` and `:termios` (deferred);
    today an empty list is fine.
- Elixir-side accessor: `Linx.Process.pty_master(pid)` returns
  `{:ok, port_or_handle}` exposing the PTY for read/write — when `:pty`
  was chosen. The agent's byte proxying means there is no raw master fd
  in the BEAM; instead, reads come as messages and writes are sent. (A
  later optimization could use `SCM_RIGHTS` to hand the master fd
  directly; not needed for v1.)
- **Tests:**
  - Plain: spawn `/bin/cat` with `stdio: [stdin: {:connect_unix, …},
    stdout: {:connect_unix, …}]`, echo through, verify bytes.
  - Plain: spawn `/bin/sh -c 'echo hi'` with `stdio: :pty`, assert the
    `:pty_out` events deliver `"hi\r\n"`.
  - Integration: spawn in a fresh PID namespace with `stdio: :pty`, run
    `/bin/sh -i`, send commands, observe output.

**Worked use case: iex attached to a containerized shell.**

The scenario: Linx runs on a Nerves device, inside (or alongside) a
container-management application. You SSH into the device, land at an
`iex>` prompt, and want to spawn an Alpine container with `/bin/bash`
inside it — and have your `iex>` *become* that bash until you type
`exit`, at which point you fall back to `iex>`.

This composes `Linx.Process` (P1 + P4) with `Linx.Tty` (a future
subsystem; see "Deferred"). The split:

```elixir
# In iex on the Nerves device:

# Spawn bash inside a freshly-namespaced child with a PTY on stdio.
{:ok, child} =
  Linx.Process.spawn(
    argv: ["/bin/bash"],
    namespaces: [:net, :mount, :pid, :uts, :ipc, :user],
    stdio: :pty
  )

# Host-side setup (e.g. configure the netns via Linx.Netlink) happens here
# while the child waits at the checkpoint. Then proceed/1.
:ok = Linx.Process.proceed(child)

# Hand the iex *controlling tty* over to the PTY master until bash exits.
# Linx.Tty.attach/2 opens /dev/tty, puts it in raw mode, propagates
# SIGWINCH via TIOCGWINSZ/TIOCSWINSZ, and runs the byte-pump loop in both
# directions. Returns when the master reports EOF (the child exited).
:ok = Linx.Tty.attach(:controlling, child)

# bash exited. The iex prompt is back.
```

Two wrinkles worth flagging:

- **iex's IO goes through a group leader.** The right move is to open
  `/dev/tty` directly to grab the actual controlling terminal; iex's
  group leader can continue doing its thing in the background. While
  `attach/2` runs, iex's `read` is blocked waiting for the call to
  return.
- **You're relaying between two PTYs.** SSH already gave you a PTY (the
  iex tty *is* sshd's slave end). The attach loop relays bytes between
  *that* PTY and the container's PTY. SIGWINCH propagation needs to
  happen on both ends.

These aren't blockers — they are exactly what `docker attach`,
`kubectl exec -it`, and `lxc-attach` solve, and the prior art is
plentiful. They land with `Linx.Tty`, not with P4. P4 ships the
primitive end: a child with a PTY on its stdio, with bytes flowing to
and from the BEAM. The interactive pumping is a separate subsystem.

## Testing

Same three bands as netlink, same commit-with-its-tests rule.

- **Unit.** ETF frame encode/decode round-trips, agent path resolution,
  session state transitions. Plain `mix test`.
- **Read / no-state.** P0's ping-pong round-trip. No root.
- **Privileged integration.** `clone()` with namespace flags, `setns()`,
  signal delivery — `:integration` tag, run via `sudotest.sh`. The fixtures
  are self-contained (no external state needed).

CI for the integration tier is deferred until the project has CI, same as
on the netlink side.

## Deferred — architected-for, not built here

- **`Linx.Tty` (future sibling subsystem).** PTY pair creation on the
  Elixir side, terminal mode manipulation (`tcgetattr`/`tcsetattr`, raw /
  cooked), tty ioctls (`TIOCSCTTY`, `TIOCSWINSZ`, …), plus an
  `attach/2` byte-pumping helper that composes with `Linx.Process`'s
  P4 `:pty` directive. The use case driving it is "iex on a Nerves
  device becomes the shell inside a container" (worked out under P4).
  Sketched in its own `docs/tty/PLAN.md` when started.
- **Stdio listener + mailbox forwarding.** Owning the `AF_UNIX` listeners
  for a `{:connect_unix, path}` directive, forwarding bytes into a
  GenServer mailbox, choosing a backpressure strategy — all
  *policy*. Belongs in a consumer (or in a higher-level runtime built on
  Linx). The P4 primitive intentionally stops at the fd boundary.
- **Cgroup placement.** Writing the workload's pid into a cgroup before
  it can spawn is silo's "Class 1" touch-point — needs the agent's
  cooperation. Lands when `Linx.Cgroup` does.
- **User namespace id maps + idmapped rootfs.** A hardening mode; large
  surface; defer until both `Linx.Process` and `Linx.Mount` are stable.
- **`mini_init` PID-1 shim.** A tiny binary that becomes PID 1 of the
  container's PID namespace and supervises the actual workload (running as
  PID 2): reaps orphans, forwards ordinary signals to PID 2, exits when it
  exits. Without one, the workload itself is PID 1 — and the kernel only
  delivers signals it has a handler for to PID 1 (except `SIGKILL` and
  `SIGSTOP`), so e.g. `SIGTERM` is silently dropped on a plain `/bin/bash`.

  **The mechanism is just argv.** `Linx.Process` already supports the
  pattern natively, no option needed: prepend the init binary to argv, and
  it becomes PID 1, your workload becomes PID 2.

      Linx.Process.spawn(
        argv: ["/usr/local/bin/tini", "--", "/bin/bash"],
        namespaces: [..., :pid]
      )

  So the open question isn't *how* Linx supports mini-init — it does, by
  doing nothing special — but *where the binary comes from*. Three options:

  1. **Upstream** — [tini](https://github.com/krallin/tini) (~100 lines of
     C, what `docker run --init` uses by default),
     [dumb-init](https://github.com/Yelp/dumb-init), or
     [catatonit](https://github.com/openSUSE/catatonit). All MIT/BSD,
     well-tested, and exactly the size and scope you want.
  2. **A runtime-project binary.** A container runtime built *on* Linx
     (e.g. a future silo rewritten as a Linx consumer) can bundle its own
     init binary alongside its other on-host artifacts and prepend it to
     argv when the consumer asks for it.
  3. **A future `Linx.Init` sibling library.** A separate, opt-in package
     shipping a tiny init binary and a `Linx.Process` wrapper that
     prepends it. Deferred-of-deferred — punt until a real consumer
     actually wants it bundled.

  `Linx.Process` itself doesn't ship an init binary. The shim is *policy*
  (signal-forwarding set, reaping aggressiveness, edge-case handling), and
  it also requires a path *inside the container's filesystem* — which is
  a mount / rootfs decision belonging to `Linx.Mount` or a consumer, not
  to process-lifecycle primitives.
- **`Linx.Process.unshare/1`.** `unshare()` on the BEAM main process is
  unsafe; from the Port helper it has no use case the existing `spawn/1`
  doesn't cover. Skip unless a real consumer appears.

## Decisions

1. **Port, not NIF** — `clone()` from the BEAM corrupts the VM (see
   silo's DESIGN.md reasoning). One external C binary, two modes.
2. **ETF over fd 3/4, `{:packet, 4}`** — same reasoning as silo: ETF
   means zero codec on the Elixir side; framing handles arbitrary
   message sizes; the channel is typed and nestable so a growing
   vocabulary stays clean.
3. **One binary, two modes** — `create` (P1) and `enter` (P3) share the
   framing and supervise loop; only the few lines of "how the child
   enters namespaces" differ.
4. **The C binary's name matches the Elixir namespace.** `linx_process`
   on both sides — clean in `ps` output, no extra "agent"/"init" word
   that adds nothing.
5. **`Linx.Process` IS the GenServer.** No nested `Session` module; the
   pid is the session handle. Standard Elixir pattern (Phoenix.PubSub,
   GenStage producers). Introspection later via `info/1` returning a
   snapshot map.
6. **No rootfs/mount/cgroup orchestration in the agent.** Those belong
   in their own subsystems (`Linx.Mount`, `Linx.Cgroup`) or in a
   consumer.
7. **PTY support is a primitive at the fd boundary; interactive
   pumping is `Linx.Tty`.** P4 adds `:pty` as a stdio directive and
   proxies bytes through the control channel. The raw-mode select-loop
   that wires it to a controlling tty (and the terminal-mode + tty-ioctl
   surface generally) lives in a future `Linx.Tty` subsystem.
