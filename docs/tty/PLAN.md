# Linx.Tty — implementation plan

> **T0, T1 and T2 have shipped** on branch `tty-foundations`: the NIF
> infrastructure, value-type structs, the termios + ioctl primitives
> (`open_controlling_raw/0`, `restore_and_close/2`, `window_size/1`,
> `set_window_size/2`), and `attach/2` — the byte pump that hands the
> caller's controlling terminal to a `Linx.Process` PTY session and
> shuttles bytes both ways until the workload exits. T3 (window-size
> propagation) is the roadmap.

## Goal

Build the foundations of `Linx.Tty`: the kernel's terminal/PTY surface,
exposed as Elixir primitives — opening and configuring the BEAM's
controlling terminal, manipulating termios (raw / cooked / save /
restore), querying and setting window size — plus the one composition
that motivates the whole subsystem:

**`Linx.Tty.attach/2`** — hand the caller's controlling terminal over to
a `Linx.Process` session's PTY master and pump bytes both ways until the
workload exits, restoring local terminal mode on return. The
`docker attach` / `kubectl exec -it` experience, end-to-end inside the
BEAM.

The driving use case (worked through in `docs/process/PLAN.md` under
P4): on a Nerves device, SSH in, land at `iex>`, type
`{:ok, c} = Linx.Process.spawn(argv: ["/bin/bash"], namespaces: [...],
stdio: :pty); Linx.Process.proceed(c); Linx.Tty.attach(:controlling, c)`
and have the `iex>` *become* the container's `bash` until you `exit`.

`Linx.Tty` is **not** an interactive-shell library or a `Phoenix.LiveView`
substrate. It is a thin wrapper around `termios(3)`, the tty `ioctl(2)`
surface, `/dev/tty`, and `/dev/ptmx` — packaged so a consumer can
compose them into things like `attach/2`.

## Guiding principles

**Primitives, not policy.** Same rule the rest of Linx lives by.
`Linx.Tty` exposes "open `/dev/tty`, get its current termios, set raw
mode, write/read it, set its window size." How a consumer uses those —
attach loops, line editors, ssh wrappers — is their concern.

**`/dev/tty`, not fd 0/1/2.** The BEAM's stdio is mediated by an Erlang
group leader process; the underlying fds are not generally usable from
Elixir code, and even if they were, going through them would race
whatever else the group leader is doing. Opening `/dev/tty` gives a
direct fd to the *controlling terminal* of the BEAM process, which is
what we actually want for raw-mode work — independent of the group
leader, the way `vim` and `less` already grab the tty in C programs.

**Save and restore is mandatory.** Any operation that mutates the local
terminal's state (raw mode in particular) must hand the caller a way to
restore it exactly. If a process crashes mid-attach without restoring,
the user's terminal is wedged until they type `reset(1)` blind. The API
makes the restore step the natural finalisation point of every mutating
operation — there is no `set_raw/1` without a paired `restore/2`.

**One NIF, no Port.** The work is small, syscall-shaped, and on a
private fd that doesn't outlive the call — `termios` and `ioctl` are
sub-microsecond. A NIF (`Linx.Tty.Native`, mirroring
`Linx.Netlink.Socket.Native`) is the right tool. The byte pump in
`attach/2` is pure Elixir on top of `:erlang.open_port({:fd, _, _}, …)`
to wrap the tty fd as a port for `{:data, _}` messages — no separate
process.

**Cross-subsystem composition via `Linx.Process`.** Writing to the
workload's PTY is `Linx.Process.pty_write/2`; reading is the existing
`{:linx_process, :pty_out, _}` event. Setting the workload's window
size requires a new verb on `Linx.Process` (and a new agent command);
that lands here, in T3, as the only intrusion `Linx.Tty` makes on the
process subsystem.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec` everywhere;
domain data as structs with `@enforce_keys`; one module per file;
`termios(3)` / `tty_ioctl(4)` citations in C comments.

## Module structure

```
Linx.Tty                        — public API: open_controlling/0,
                                  set_raw/1, restore/2, window_size/1,
                                  set_window_size/2, attach/2.

Linx.Tty.Native                 — the NIF: opens /dev/tty, gets/sets
                                  termios, runs the tty ioctls. Returns
                                  fds as integers and saved termios as
                                  opaque binaries.

  build
  c_src/linx_tty.c              — NIF source.
  lib/mix/tasks/compile.linx_tty.ex
                                — sibling to compile.netlink_nif.
```

The C binary `linx_process` (the Port-based agent from `Linx.Process`)
gains exactly one new piece of inbound vocabulary at T3:
`{:pty_winsize, {rows, cols, xpix, ypix}}` — fed to
`ioctl(pty_master, TIOCSWINSZ, &ws)`.

## The NIF contract

The NIF surfaces termios and tty ioctls as opaque-binary plus
plain-integer return values, with structured errors:

**`open_controlling_raw() → {:ok, fd, saved} | {:error, {stage, errno}}`**

Opens `/dev/tty` (with `O_RDWR | O_NOCTTY | O_CLOEXEC`), reads the
current termios via `tcgetattr(3)` into `saved` (an opaque binary blob
representing the full `struct termios`), and applies `cfmakeraw(3)`
followed by `tcsetattr(TCSANOW, …)`. Returns the fd integer (for
Elixir to wrap as a port) plus the saved blob (for `restore/2`).
`stage` is one of `:open`, `:tcgetattr`, `:tcsetattr`.

**`restore_and_close(fd, saved) → :ok | {:error, {stage, errno}}`**

`tcsetattr(fd, TCSANOW, &saved)` then `close(fd)`. Idempotent against
already-closed fds (treats `EBADF` on close as success, so a double
restore from an `after` block on an early failure path is safe).

**`window_size(fd) → {:ok, {rows, cols, xpixel, ypixel}} | {:error, errno}`**

`ioctl(fd, TIOCGWINSZ, &ws)`. Reads the current size of the terminal
named by `fd`. Used both for the local terminal (to seed the workload)
and to refresh on `SIGWINCH`.

**`set_window_size(fd, {rows, cols, xpixel, ypixel}) → :ok | {:error, errno}`**

`ioctl(fd, TIOCSWINSZ, &ws)`. Sets the size on a tty fd. *Not* the
common path for setting the workload's size (the master fd lives in
the agent, not BEAM); this is for symmetry and for the rare case where
the caller holds a tty fd directly.

The same NIF stub list and `:safe` decode considerations apply as in
the netlink and process subsystems — stages are pre-loaded as atoms in
the Elixir module.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship with
the code that needs them; commit + push per milestone.

### T0 — Scaffolding & the NIF

✅ **Shipped.**

- `Linx.Tty` module skeleton (`@moduledoc`, public API stubs returning
  `{:error, :not_yet_implemented}`).
- `Linx.Tty.Native` skeleton; `c_src/linx_tty.c` with the bare `erl_nif`
  init + one trivial call (e.g. `version/0` returning a string).
- `lib/mix/tasks/compile.linx_tty.ex` — sibling to
  `compile.netlink_nif`, builds the NIF as a shared library into
  `priv/linx_tty.so`.
- Wire `:linx_tty` into `mix.exs` `:compilers`.
- **Tests:** NIF loads, the trivial call round-trips, stubs all return
  `:not_yet_implemented`. No root needed.

### T1 — Termios primitives + `/dev/tty`

✅ **Shipped.**

- `Linx.Tty.open_controlling_raw/0` — opens `/dev/tty`, saves the
  current termios, applies raw mode, returns
  `{:ok, fd, %Linx.Tty.Saved{...}}` where `Saved` wraps the opaque
  binary so it can't be mistaken for arbitrary bytes.
- `Linx.Tty.restore_and_close/2` — symmetric. Closes the fd, restores
  the saved state. Idempotent against already-closed fds (treats
  `EBADF` from `tcsetattr` and `close` as success).
- `Linx.Tty.window_size/1` — `TIOCGWINSZ` over a tty fd; returns
  `{:ok, %Linx.Tty.WindowSize{...}}` (a struct, so Inspect is legible).
- `Linx.Tty.set_window_size/2` — `TIOCSWINSZ`. Rejects dimensions
  above 65535 (the `struct winsize` field width).
- C-side errno → POSIX-atom mapping (`:enxio`, `:enotty`, `:ebadf`,
  `:einval`, `:eperm`, …); unknown errnos fall back to the raw
  integer.
- **Tests:**
  - Plain: `window_size/1` on a non-tty fd returns
    `{:error, {:ioctl, :enotty}}`; on an invalid fd, `:ebadf`.
    `set_window_size/2` on a non-tty returns `:enotty`; on
    out-of-range dimensions, `:einval`.
  - Plain (guarded round-trip): `open_controlling_raw/0` accepts
    either success (immediately restored) or `{:error, {:open,
    :enxio}}` — covering both the local-terminal `mix test` case
    and CI without a controlling tty.
  - Manual (`docs/tty/EXAMPLES.md`): full open/raw/restore from
    `iex -S mix`, real `window_size/1` numbers.

### T2 — `Linx.Tty.attach/2`

✅ **Shipped.**

- `Linx.Tty.attach(:controlling, session)` — the byte pump:
  1. `open_controlling_raw/0` to grab the local tty in raw mode.
  2. `:erlang.open_port({:fd, fd, fd}, [:binary, :stream])` to wrap
     the tty fd as a port, so user keystrokes arrive as
     `{port, {:data, bytes}}` messages.
  3. Seed the workload's window size: `window_size(local_tty_fd)` →
     (deferred to T3 — without `Linx.Process.pty_set_winsize/2` this
     can only be best-effort logged).
  4. Loop:
     - `{^port, {:data, bytes}}` → `Linx.Process.pty_write(session, bytes)`.
     - `{:linx_process, :pty_out, bytes}` → `Port.command(port, bytes)`.
     - `{:linx_process, :exited, _}` / `:signaled` / `:error` → exit
       the loop, returning the terminal event.
  5. `try/after`: `restore_and_close/2` runs *unconditionally*, even
     on a crash inside the loop, so a wedged terminal is impossible.
- Returns the terminal event ( `{:ok, {:exited, code}}`, etc.) so the
  caller can pattern-match on the result.
- **Tests:** all plain `mix test`, no root needed.
  - End-to-end through a `socketpair` standing in for `/dev/tty`:
    spawn `/bin/cat` with `stdio: :pty`, fake-attach with a fd pair
    we control, send "hello\n", assert the workload echoes (PTY
    line discipline) and the bytes arrive back through the fake-tty
    side. (The socketpair stand-in is the only practical way to
    test `attach/2` without claiming the test runner's real
    terminal.)
  - Restore-on-crash: cause the loop to raise mid-flight, assert the
    NIF restore + close ran (visible via a flag in the saved struct
    or via observing the fd is closed after).

### T3 — Window size propagation

The piece that makes `vim` and `top` usable inside the attached
container.

- `Linx.Process` (one new verb):
  - `Linx.Process.pty_set_winsize(session, %Linx.Tty.WindowSize{...})`
    — sends `{:pty_winsize, {rows, cols, xpix, ypix}}` to the agent.
    Returns `{:error, :no_pty}` if the session wasn't started with
    `stdio: :pty`.
- Agent (`c_src/linx_process.c`): `read_post_running_command` learns
  `{:pty_winsize, _}`; `supervise` calls
  `ioctl(pty_master, TIOCSWINSZ, &ws)`.
- `Linx.Tty.attach/2`: catches `SIGWINCH` via `:os.set_signal/2`,
  re-reads `window_size(local_tty_fd)`, forwards via
  `pty_set_winsize/2`. Initial size is seeded the same way on entry
  to the loop.
- **Tests:** assert the new agent vocabulary parses (plain codec
  round-trip); the SIGWINCH propagation is fundamentally interactive
  and lives in `docs/tty/EXAMPLES.md` rather than `mix test`.

## Testing

Same three bands as the other subsystems; same commit-with-its-tests
rule.

- **Unit.** NIF loading, struct shapes, the no-controlling-tty error
  path, codec round-trips for new agent commands. Plain `mix test`.
- **Plain integration via socketpair.** The `attach/2` byte pump is
  exercised against a `socketpair` standing in for `/dev/tty` —
  letting us drive the "local terminal" side under test control while
  a real `Linx.Process` PTY runs the workload. No root.
- **Manual / `:integration`.** Anything that actually mutates the test
  runner's terminal — the real `open_controlling_raw → restore`
  round-trip, an end-to-end attach in `iex` — lives in
  `docs/tty/EXAMPLES.md` as commands you run by hand. Not safe to put
  in `mix test`.

## Deferred — architected-for, not built here

- **Detach key combinations** (Docker's `Ctrl-P Ctrl-Q`). The byte
  pump in T2 detaches only on workload exit. Detach via in-band magic
  sequence is policy and lives in a consumer (or a future helper);
  the primitive doesn't bake in a particular escape.
- **Termios beyond raw / restore.** Cooked mode, cbreak,
  per-attribute manipulation (echo on/off, etc.). The opaque-blob save
  shape supports it — a consumer wanting cbreak gets the saved blob,
  mutates a few fields, and applies. Future helpers can expose this
  more conveniently if needed.
- **Local pty creation from BEAM.** `posix_openpt` is already done by
  the `Linx.Process` agent for `stdio: :pty`; a standalone
  `Linx.Tty.openpt/0` would be a separate primitive without a current
  consumer. Skip until someone needs it.
- **Job control / process groups.** Setting the foreground process
  group on a tty (`tcsetpgrp(3)`), sending signals via the tty's
  controlling-terminal mechanism. Adjacent to attach but not needed
  for the primary use case.
- **Non-controlling tty fds.** A consumer holding a tty fd from
  elsewhere (e.g. one of two PTY masters they created themselves) and
  wanting `Linx.Tty` operations on it. `set_window_size/2` already
  accepts an arbitrary fd; broader support can grow if asked.
- **`tput`-style terminfo.** That is a different beast entirely
  (escape-sequence database, capability strings); out of scope.

## Decisions

1. **NIF, not Port.** Termios and ioctl are sub-microsecond, on a
   short-lived fd. The throwaway-thread pattern that justifies the
   `Linx.Netlink` NIF doesn't apply here (no netns), so the NIF is
   plain — not dirty — but the call is so short that it doesn't
   matter.
2. **`/dev/tty` not fd 0.** Direct access to the controlling terminal,
   bypassing the BEAM's group leader entirely.
3. **`cfmakeraw(3)` is the raw mode.** No bespoke flag massaging in
   T1/T2 — `cfmakeraw` is what every C program in the ecosystem uses;
   matching its exact effects is the principle of least surprise.
4. **Saved termios is opaque.** Returned as a binary wrapped in a
   `%Saved{}` struct so the type is visible but the contents are not
   manipulated from Elixir. A future consumer that wants to mutate
   the saved blob (e.g. for cbreak) gets a NIF helper, not a
   bytes-poking interface.
5. **`attach/2` is synchronous.** The caller blocks until the
   workload terminates or the loop is interrupted by a port error.
   Asynchronous "attach in the background" can be built by a consumer
   that spawns a Task around `attach/2`; the primitive blocks because
   that's the docker-attach contract callers will expect.
6. **One new verb on `Linx.Process`, no further.** `pty_set_winsize/2`
   is the entirety of the cross-subsystem expansion. The byte-pump
   itself does *not* live in `Linx.Process`; it lives here.
