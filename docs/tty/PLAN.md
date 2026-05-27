# Linx.Tty — implementation plan

> **T0–T5 have shipped** on branch `tty-foundations`: the NIF
> infrastructure, value-type structs, the termios + ioctl primitives,
> `attach/2`, initial window-size propagation, coexistence with
> `iex`'s tty driver (`:prim_tty.disable_reader/1` bracket around the
> pump), and **runtime SIGWINCH-driven resize updates** (a
> `:gen_event` handler on OTP's `:erl_signal_server` forwards
> `:sigwinch` into the pump's mailbox, which re-reads `TIOCGWINSZ` on
> the local tty and pushes the size through
> `Linx.Process.pty_set_winsize/2`). OTP 28's expanded
> `:os.set_signal/2` (which now covers `:sigwinch`) made the
> originally-proposed signalfd NIF unnecessary.
>
> **T6 is in progress** on branch `tty-group-leader-attach`: a sibling
> attach mode (`attach(:group_leader, session)`) that pumps via the
> Erlang I/O protocol through the caller's group leader rather than
> `/dev/tty`, so attach works over SSH (e.g. Nerves' `ssh nerves-foo`
> + iex), inside `:remsh`, and anywhere else the user's terminal is
> not the BEAM's controlling tty.
>
> The 2026-05-27 SSH probes on a Nerves rpi5 (probe #1 + #2 + #3,
> under `docs/tty/probes/`) plus a read of `kernel-10.6.3`'s
> `group.erl` resolved the mechanism entirely:
>
>  * The GL is `kernel`'s `:group` gen_statem — same module local
>    iex uses, just on top of an SSH transport rather than
>    `/dev/tty`.
>  * Detection: `"$ancestors"` in the GL's dictionary contains
>    `:ssh_sup` (OTP `ssh` app top supervisor) and `:sshd_sup`
>    (nerves_ssh's wrapper).
>  * Line-buffering came from `:group` routing input requests to
>    its `:xterm` state (the rich line editor with key_map and
>    history) when `echo=true`. Setting `echo=false` routes through
>    `:dumb` state instead, whose `get_chars_dumb` returns bytes
>    immediately as the driver delivers them.
>  * Probe #3 verified: with `:io.setopts(gl, echo: false)` set,
>    `:io.get_chars(:standard_io, '', 1)` returned `<<"x">>` on a
>    single keypress, no Enter required. SSH transport is
>    byte-oriented.
>
> T6.1's mode-flip is therefore a one-liner of public `:io.setopts/2`
> — no private gen_statem messages, no record-layout coupling beyond
> what T4 already does. **T6 is fully shipped** on
> `tty-group-leader-attach`. T6.1.1 added a `:prim_tty` output-mode
> bracket (`:sys.replace_state/2` on `ssh_cli` to flip `:cooked` to
> `:raw` for the pump's lifetime) so workload backspace echo and
> vim TUI sequences render verbatim through the SSH channel instead
> of being caret-rendered (`\b` → `^(`, etc.) by `:prim_tty`'s
> cooked-mode line editor. T6.1.2 added Ctrl-C forwarding: `ssh_cli`
> swallows `\x03` and turns it into `exit(group, interrupt)`, so the
> reader's `{:error, :interrupted}` reply and the pump's
> `{:EXIT, ^gl, :interrupt}` shape both translate back to a literal
> `<<3>>` byte to the workload's PTY (the workload's line discipline
> then turns it into SIGINT for the foreground process group).
> T6.2 captured the observed end-to-end behaviour in EXAMPLES.md.
> Ready for PR.

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

### T3 — Window size propagation (initial seed)

✅ **Shipped.**

The piece that gives `vim` and `top` correct dimensions at the moment
the workload starts inside the attached container.

- `Linx.Process` (one new verb):
  - `Linx.Process.pty_set_winsize(session, ws)` — accepts a map or
    struct with `:rows`/`:cols`/`:xpixel`/`:ypixel` fields (the
    `Linx.Tty.WindowSize` shape, without taking a Tty dependency) or
    a `{rows, cols, xpix, ypix}` tuple. Sends
    `{:pty_winsize, {rows, cols, xpix, ypix}}` to the agent. Returns
    `{:error, :no_pty}` if the session wasn't started with
    `stdio: :pty`.
- Agent (`c_src/linx_process.c`): `read_post_running_command` learns
  `{:pty_winsize, _}`; `supervise` calls
  `ioctl(pty_master, TIOCSWINSZ, &ws)` best-effort.
- `Linx.Tty.attach/2`: reads `window_size(local_tty_fd)` at entry and
  forwards via `pty_set_winsize/2` before running the pump.
- **Tests:** `pty_set_winsize/2` on a non-PTY session returns
  `{:error, :no_pty}`; on a PTY session, running `stty size` inside
  reports the size we set.

### T5 — Runtime SIGWINCH propagation

✅ **Shipped.** Drag the corner of your terminal emulator while
inside an attached shell and `bash` / `vim` / `top` redraw at the new
size in real time.

#### What changed since the original sketch

The PLAN's original deferred section assumed Erlang's
`:os.set_signal/2` didn't cover `SIGWINCH` (true under OTP 26) and
proposed a `signalfd(2)`-based NIF as the fix. **OTP 28 added
`:sigwinch` to `:os.set_signal/2`**, and `prim_tty_sighandler`
itself uses it for iex's own line-editor refresh. So the
implementation is pure Elixir — no C, no signalfd, no self-pipe.

#### How it works

`SIGWINCH` is delivered to the BEAM by the kernel whenever the
controlling terminal resizes. The BEAM forwards each signal as a
`:gen_event` broadcast on the registered manager
`:erl_signal_server`. Multiple handlers can be registered; each
receives every broadcast. `prim_tty_sighandler` is already on the
list (iex needs the geometry refresh).

`Linx.Tty.SigwinchHandler` is a tiny `:gen_event` handler that
forwards `:sigwinch` to a target pid as `{:linx_tty, :sigwinch}`.
`Linx.Tty.attach/2` registers an instance keyed by
`{Linx.Tty.SigwinchHandler, make_ref()}` on entry and removes it on
exit (in the `try/after`). The `make_ref()` discriminator lets
concurrent attaches coexist trivially.

The pump grew one new `receive` clause:

```elixir
{:linx_tty, :sigwinch} ->
  case window_size(local_fd) do
    {:ok, ws} -> _ = Linx.Process.pty_set_winsize(session, ws)
    {:error, _} -> :ok
  end
  __pump__(port, session, local_fd)
```

`__pump__` gained a third argument (`local_fd`, default `nil`) so the
socketpair test path stays arity-2 and ignores `:sigwinch` cleanly.

#### Acceptance test

Manual, lives in `EXAMPLES.md`: from `iex -S mix`, spawn bash with
`stdio: :pty`, attach, open `vim`, drag the terminal emulator's
corner. vim must redraw at the new size without exiting or
corrupting.

### T4 — Coexisting with iex's tty driver

✅ **Shipped.** Path (3) below was implemented: `attach/2` brackets
its pump with `:prim_tty.disable_reader/1` /
`:prim_tty.enable_reader/1`, reaching into `user_drv`'s state via
`:sys.get_state(:user_drv)` to find the `prim_tty` state record.
The competing reader process parks in its inner `receive` until
attach returns and re-enables it. When the BEAM is not running
under `user_drv` (escripts, non-shell apps), the bracket is a
no-op. Keystrokes now arrive intact.

#### Background — the symptom and diagnosis

Manual sanity test confirmed end-to-end: spawn bash with
`stdio: :pty` + `proceed` + `Tty.attach(:controlling, c)` from
`iex -S mix` lands in a real bash inside the container; typing
`exit` returns to iex with `{:ok, {:exited, 127}}`. But **input
arrives every-other-character** — half the user's keystrokes never
reach bash.

**Root cause (high-confidence diagnosis).** Both readers are open on
the same controlling terminal:

  1. Our `attach/2` wraps `/dev/tty` via `:erlang.open_port({:fd, fd, fd}, …)`
     and reads from it.
  2. Erlang's `user_drv` / `prim_tty` (the new OTP 26+ shell tty
     driver) *also* has `/dev/tty` (or fd 0, which is the same tty)
     open and reads from it — pre-reading input so type-ahead at the
     iex prompt works while iex is busy evaluating something.

Both are blocked on `read(2)` against the same kernel tty buffer.
The kernel hands each keystroke to whichever read is current; with
two readers in tight alternation, you get exactly the observed
every-other-byte split. The keystrokes that go to `user_drv` are
buffered for the next iex `get_line` and never reach bash. The
"extra space" in `p s` was probably a stray echo or filler from
`prim_tty` interpreting its half of the bytes.

**Confirmation test** (cheap, do this first): after `attach/2` returns
from a session where bytes were lost, type some characters at the
iex prompt without pressing Enter. If you see the "lost" bytes
appear, that's `user_drv` replaying its pre-read buffer — definitive
proof of the diagnosis.

#### Why path (3) and not path (4)

The original sketch had five candidate paths in increasing order of
cleanness:

1. **Public docs workaround** — start iex with `--no-shell` so the
   shell input driver isn't there to compete. Loses iex history.
2. **`:io.setopts/2`** — Erlang's documented IO options. Doesn't
   actually expose a "suspend the reader" knob.
3. **`prim_tty` private API** — the actual driver in OTP 26+; it
   must have some pause affordance for `user_drv`'s own job-control
   needs. **This is what shipped.** See "What we built" below.
4. **Foreground-process-group trick** — `tcsetpgrp(2)` to background
   the BEAM. **Rejected as unworkable**: `tcsetpgrp` operates on OS
   process groups, and the BEAM is a single OS process. Both readers
   (ours and `prim_tty`'s) live in the same BEAM and share the same
   pgrp; backgrounding one would background the other.
5. **`Linx.Tty.with_exclusive_tty/1`** — a public wrapper. Made
   unnecessary by (3): the bracket lives inside `attach/2`, no
   caller-visible wrapper needed.

#### What we built

`prim_tty.erl` exports `disable_reader/1` and `enable_reader/1` —
intended for `user_drv`'s own job-control flow (e.g. when it spawns
`$EDITOR`). They send `{Alias, disable}` / `{Alias, enable}`
messages to the reader pid stored inside the `prim_tty` state
record. On `disable`, the reader parks in an inner `receive`
waiting only for `enable`; no further `read(2)` against `/dev/tty`.
Exactly the "pause the competing reader" hook T4 needed.

The implementation in `Linx.Tty.attach/2`:

- `Process.whereis(:user_drv)` → pid (or `nil` for escripts etc.).
- `:sys.get_state(pid)` returns `{state_name, state_record}`;
  `state_record` is `#state{tty, write, read, …}` from
  `user_drv.erl` line 109. Field at tuple-index 1 (after the record
  tag at 0) is the `prim_tty` state.
- `:prim_tty.disable_reader(tty_state)` before the pump.
- `:prim_tty.enable_reader(tty_state)` in `try/after` so iex resumes
  cleanly even on a crash in the pump body.
- Every step is wrapped in a `safe_*` helper that catches and falls
  through to `nil`, so if any of the OTP internals change shape in a
  future release we degrade to "old broken behaviour" rather than
  crashing.

#### Acceptance test

This is fundamentally interactive — hard to assert in `mix test`.
The manual acceptance procedure lives in `docs/tty/EXAMPLES.md`:
spawn bash via `stdio: :pty`, attach, type `hello world<Enter>`,
verify *every character* arrives, observe the shell echoing the
whole line.

#### Coupling to OTP internals

This touches three OTP-private interfaces: the `:user_drv`
registered name, the `#state{}` record layout (specifically that
the `prim_tty` state is at field 1), and the
`disable_reader/enable_reader` exports on `prim_tty`. All three are
stable across OTP 26+ at time of writing, but they are
implementation details. If a future OTP rearranges them, the
fallback path (no bracketing) is taken and the every-other-byte
behaviour returns — visibly broken, but not crashy. That's an
acceptable failure mode; the value of the brackets is too large to
not take this dependency.

### T6 — Attach over SSH / non-controlling-tty environments

⏳ **Sketched, not built.** Branch: `tty-group-leader-attach`.

#### Motivation — the SSH-on-Nerves trap

The motivating Linx workflow is: on a Nerves device, `ssh
nerves-foo.local`, land at `iex>`, spawn a container with
`stdio: :pty`, and attach. That sequence reads naturally as
"attach the *thing I'm typing into* to the workload" — and that's
exactly what `attach(:controlling, session)` doesn't do over SSH.

`Linx.Tty.attach(:controlling, _)` opens `/dev/tty`, which inside
the BEAM resolves to the **BEAM process's actual controlling
terminal**. On Nerves that is the HDMI / UART console set up by
`erlinit` — not the SSH session. Erlang's SSH daemon (`:ssh.daemon`
→ `ssh_cli`) is a pure Erlang/IO-protocol bridge; bytes come off
the SSH transport, the iex shell process consumes them via the
group leader, and outputs go back the same way. There is no
`/dev/pts/N`, no `openpty()`, no kernel tty fd anywhere on the SSH
side. The "is this user's terminal a Linux fd?" assumption that
underpins `:controlling` simply does not hold there.

The observable failure is silent: attach opens the HDMI console
(succeeds — that fd exists), puts *it* in raw mode, runs a pump
between *it* and the workload. The SSH iex blocks forever waiting
on `__pump__`; a user at the physical Pi screen could type into
the workload, but the SSH user sees nothing. Ctrl-C eventually
unwinds the IEx shell evaluator (the `try/after` restores the HDMI
console correctly), and `nerves_ssh` spawns a fresh shell. No
crash, no error message — just "attach is broken over SSH."

The same trap applies to `:remsh` (the GL is a remote shell's IO
server, not a local tty), `iex --hidden`-style escripts wired up
oddly, and any future deployment where the user's terminal is an
Erlang-process abstraction rather than a kernel tty.

#### Surface

A sibling attach mode with the same return shape, different byte
source/sink:

```elixir
@spec attach(:group_leader, session()) ::
        {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
        | {:error, term()}
def attach(:group_leader, session)
```

Selection is explicit — no auto-fallback between `:controlling`
and `:group_leader`. The two modes have meaningfully different
capabilities (raw-mode fidelity, SIGWINCH availability), and
silent fallback would hide the difference from callers.

#### Mechanism

The group leader is an Erlang process that speaks the I/O protocol
(`{io_request, From, ReplyAs, Request}` /
`{io_reply, ReplyAs, Reply}`). The pump talks to whichever pid
`Process.group_leader/0` returns; the I/O protocol is identical
across drivers.

The original sketch assumed the SSH-fronted GL was `ssh_cli`.
**The 2026-05-27 probe (`docs/tty/probes/T6_ssh_probe.exs`,
output captured on Nerves rpi5 / nerves_ssh) found otherwise**:

  * `:proc_lib.translate_initial_call(gl)` → `{:group, :init, 1}`
  * `current_function` → `{:gen_statem, :loop, 3}`
  * GL `$ancestors` chain includes `:sshd_sup`, `:ssh_sup`

So `nerves_ssh` layers Erlang's standard `user_drv` / `:group`
line-editor on top of the SSH transport, *exactly like local iex
does on top of `/dev/tty`*. The GL is `kernel`'s `:group`
gen_statem — same module in both environments; only the byte
source/sink underneath user_drv differs (SSH channel vs prim_tty).

That collapses a lot of complexity: the pump talks to one stable
abstraction (`:group`), not two driver-specific ones.

**Input — a reader sub-process.** `:io.get_chars/3` is synchronous;
the pump must interleave reads with `:pty_out` events from
`Linx.Process`. A linked reader process owns the blocking call and
relays results into the pump's mailbox:

```elixir
defp spawn_reader(gl, parent) do
  spawn_link(fn ->
    Process.group_leader(self(), gl)
    read_loop(parent)
  end)
end

defp read_loop(parent) do
  case :io.get_chars(:standard_io, ~c"", 256) do
    :eof          -> send(parent, {:linx_tty_gl, :eof})
    {:error, why} -> send(parent, {:linx_tty_gl, {:error, why}})
    bytes         -> send(parent, {:linx_tty_gl, :data, IO.iodata_to_binary(bytes)})
                     read_loop(parent)
  end
end
```

**Output — `IO.binwrite`.** Fire-and-forget through the I/O
protocol; no port involved. `IO.binwrite(gl, bytes)` for each
chunk arriving on `{:linx_process, :pty_out, _}`.

**Mode — `:io.setopts(gl, echo: false)`, end of story.** The
`group.erl` source (kernel-10.6.3, line 244) routes input
requests inside `:server` state based on two fields:

```erlang
%% group.erl, server/3:
{next_state,
 if Data#state.dumb orelse not Data#state.echo -> dumb; true -> xterm end,
 ...}
```

`echo=false` (or `dumb=true`) routes to the `:dumb` state. In
`:dumb`, `get_chars_dumb/5` (line 1152) delivers bytes
immediately as they arrive from the driver — no line editor, no
buffering at the `:group` layer. Probe #3 verified end-to-end on
nerves_ssh: a single keystroke returns `<<"x">>` from
`get_chars(_, '', 1)` with no Enter.

`binary: true` is already the default on nerves_ssh (probe #1
confirmed), so we only need to flip `echo`. Saving and restoring
just that one field — *not* the full `:io.getopts/1` result —
matters because `:io.setopts/2` short-circuits on options it
considers `:enotsup` (e.g. `terminal: true|false`), so passing
back the full opts list silently drops the echo restore.

```elixir
saved_echo = Keyword.get(:io.getopts(gl), :echo, true)

try do
  :io.setopts(gl, echo: false)
  run_pump(...)
after
  :io.setopts(gl, echo: saved_echo)
end
```

Side effects of `echo=false` worth noting:

- `:group` stops echoing characters back through the driver
  (line 1160 — the echo write is guarded by `Data#state.echo`).
  That matches what we want anyway: the workload's PTY does its
  own echo when bash/etc. configures `ECHO` on the slave side.
- The local-edit features of `:xterm` state (history recall via
  ↑/↓, line editing, tab completion) are bypassed for the
  duration of attach. The remote terminal emulator and the
  workload's readline (if any) take over. Expected.

The richer `terminal_mode = raw` path in `:dumb` (line 258 —
`collect_chars_eager`) is gated by `Data#state.shell = noshell`,
which we can't satisfy without ripping out the iex shell. We
don't need it: `collect_chars` in `:dumb` already gives us the
behaviour we want.

**Window size.** `:io.columns(gl)` and `:io.rows(gl)` return
integers — the probe got `{:ok, 159}` / `{:ok, 56}`, matching
the SSH client's terminal. The pump calls them at entry and
forwards via `Linx.Process.pty_set_winsize/2` — same downstream
wiring as `:controlling`, sourced from the I/O protocol instead
of `TIOCGWINSZ`.

Runtime resize: there is no SIGWINCH equivalent surfaced through
`:io`. SSH `window-change` requests update the IO server's
internal state without emitting a shell-visible event. T6 ships
**polling** (re-read `:io.columns / :io.rows` every
`:winsize_poll_ms`, default 1000; forward only on change).
Hooked / event-driven resize lands in a deferred follow-up.

#### The raw-mode story — clearer than the original sketch

The original sketch worried that ssh_cli's PTY negotiation locked
in line-discipline at session start and that bytes-perfect raw
mode would require dropping below ssh_cli. The probe reframed
this: the line discipline is in `:group`, *not* in the SSH layer.
ssh_cli passes bytes through; `:group` cooks them. Flipping
`:group` is therefore within reach via the I/O protocol (option
1 above) or, failing that, via the same kind of OTP-internals
manipulation T4 already does for `:prim_tty`.

The user's local `ssh` client does still hold its own
line-discipline (Ctrl-Z, flow control, the terminal emulator's
own buffering of escape sequences) — but the same is true of the
user's *local terminal emulator* in plain `iex -S mix`, and it
hasn't been a problem there. The shipped experience should
match: bash feels native, vim/top redraw correctly, edge cases
exist for unusual key sequences and remain edge cases.

#### Precondition guard on `attach(:controlling, _)`

Regardless of when `:group_leader` lands, the silent-attach-to-HDMI
trap should be closed *now*. T6.0 adds a guard:

```elixir
def attach(:controlling, session) do
  case Linx.Tty.Env.classify_caller_terminal() do
    :local_tty -> attach_via_controlling(session)
    :ssh       -> {:error, :no_local_tty}
    :remsh     -> {:error, :no_local_tty}
    :unknown   -> attach_via_controlling(session)   # preserve current behaviour
  end
end
```

`Linx.Tty.Env.classify_caller_terminal/0` walks
`Process.group_leader/0`. The probe identified the canonical
signal:

```elixir
gl = Process.group_leader()

{:dictionary, dict} = Process.info(gl, :dictionary)
ancestors = Keyword.get(dict, :"$ancestors", [])

cond do
  :ssh_sup in ancestors or :sshd_sup in ancestors ->
    :ssh
  # :remsh and other variants land here once we have a probe
  # confirming their ancestor signatures.
  true ->
    case :proc_lib.translate_initial_call(gl) do
      {:group, :init, _} when whereis_user_drv_present? -> :local_tty
      _ -> :unknown
    end
end
```

Cheap, stable, no record-layout coupling. `:ssh_sup` is the
top-level supervisor of OTP's `ssh` app — anything that fronts
an Erlang shell with the SSH daemon shows it. `:sshd_sup` is
`nerves_ssh`'s wrapping supervisor; both appear in the ancestor
list because nerves_ssh sits *above* the OTP ssh app.

The `:unknown` arm preserves today's behaviour rather than
rejecting on uncertainty, so callers that work today don't
suddenly break. The error message names the alternative:

```
{:error, :no_local_tty}
# Linx.Tty.format_error/1:
# "Your iex appears to be over SSH or :remsh; /dev/tty here is the
#  BEAM's actual controlling terminal (e.g. HDMI console on Nerves),
#  not your remote session. Use Linx.Tty.attach(:group_leader, session)."
```

#### Module structure (incremental)

```
Linx.Tty       — adds attach(:group_leader, _), the reader and
                 pump helpers (private), format_error/1.
Linx.Tty.Env   — classify_caller_terminal/0 + small sniff
                 helpers driven by $ancestors.
```

The reader and pump are two small private functions inside
`Linx.Tty` — no separate module is warranted given the scale.
No NIF changes. No new agent commands — the workload-side path
(`pty_write`, `:pty_out`, `pty_set_winsize`) is unchanged.

#### Sequencing — sub-milestones

Each is an independently reviewable commit; commit + push per
milestone per project convention.

##### T6.0 — Precondition guard

✅ **Shipped** (`d86a8d4`'s child commit on the same branch).

- `Linx.Tty.Env.classify_caller_terminal/0` and `/1` — walk the
  caller's GL `"$ancestors"` and return `:ssh | :local_tty |
  :unknown`. Conservative on uncertainty: returns `:local_tty`
  when no SSH signal is present, so callers that work today
  don't suddenly start refusing.
- `Linx.Tty.attach(:controlling, _)` now branches on the
  classification and returns `{:error, :no_local_tty}` when the
  GL has SSH supervisors in its ancestor chain. `:local_tty`
  and `:unknown` both take the existing path.
- `Linx.Tty.format_error/1` renders `:no_local_tty` as a
  human-readable string naming the SSH alternative; falls back
  to `inspect/1` for other shapes.
- **Tests** (plain `mix test`, no root): `Linx.Tty.Env` against
  fixture GLs with synthesized `"$ancestors"` (both SSH and
  non-SSH); dead-pid edge case → `:unknown`; the guard refusal
  itself; `format_error/1` covers the new atom and falls
  through for unknown shapes.
- The `:remsh` classification is still future work — held in
  the `:unknown` bucket (where current behaviour is preserved)
  until we have a probe that names the signal.

##### T6.1 — `attach(:group_leader, session)`

✅ **Shipped.**

The whole milestone, concretely:

```elixir
def attach(:group_leader, session) when is_pid(session) do
  gl = Process.group_leader()
  saved_echo = Keyword.get(:io.getopts(gl), :echo, true)

  try do
    :io.setopts(gl, echo: false)

    with {:ok, cols} <- :io.columns(gl),
         {:ok, rows} <- :io.rows(gl) do
      _ = Linx.Process.pty_set_winsize(session,
            %WindowSize{rows: rows, cols: cols, xpixel: 0, ypixel: 0})
    end

    reader = spawn_link(__MODULE__, :__gl_reader__, [self(), gl])
    __pump_gl__(reader, gl, session, _winsize_poll_ms = 1000)
  after
    :io.setopts(gl, echo: saved_echo)
  end
end

def __gl_reader__(parent, gl) do
  Process.group_leader(self(), gl)
  gl_reader_loop(parent)
end

defp gl_reader_loop(parent) do
  case :io.get_chars(:standard_io, ~c"", 1024) do
    :eof          -> send(parent, {:linx_tty_gl, :eof})
    {:error, why} -> send(parent, {:linx_tty_gl, {:error, why}})
    bytes ->
      send(parent, {:linx_tty_gl, :data, IO.iodata_to_binary(bytes)})
      gl_reader_loop(parent)
  end
end

def __pump_gl__(reader, gl, session, poll_ms) do
  receive do
    {:linx_tty_gl, :data, bytes} ->
      _ = Linx.Process.pty_write(session, bytes)
      __pump_gl__(reader, gl, session, poll_ms)

    {:linx_process, :pty_out, bytes} ->
      IO.binwrite(gl, bytes)
      __pump_gl__(reader, gl, session, poll_ms)

    {:linx_tty_gl, :eof} ->
      {:error, :gl_eof}

    {:linx_process, :exited, code}     -> {:ok, {:exited, code}}
    {:linx_process, :signaled, signum} -> {:ok, {:signaled, signum}}
    {:linx_process, :error, errno, stage} ->
      {:error, %{errno: errno, stage: stage}}
  after
    poll_ms ->
      maybe_forward_winsize(gl, session)
      __pump_gl__(reader, gl, session, poll_ms)
  end
end
```

Plus a `maybe_forward_winsize/2` that re-reads `:io.columns / :io.rows`
and forwards only on change (memoised per-pump).

- **Tests:** plain `mix test` against a fake group leader (a
  process that consumes `{io_request, …}` and emits `{io_reply,
  …}`, just like the existing socketpair stand-in for the
  `:controlling` path). Verify byte round-trip, eof propagation,
  winsize forwarding on poll. Plus a regression test that the
  `after` block restores `echo` even if the pump body raises.
- **Manual acceptance** (in `EXAMPLES.md` under T6.2): SSH into a
  Nerves device, spawn bash with `stdio: :pty`, attach via
  `:group_leader`, type characters, run `vim`, drag the SSH
  client's terminal corner, observe a clean redraw within ~1s.

##### T6.1.1 — `:prim_tty` raw-output bracket

✅ **Shipped** (`8d0823f`'s child commit).

The first deployed T6.1 worked for typing and command execution
but mangled the *visual* output of in-line editing: backspace
showed `^(` instead of erasing, vim's TUI sequences came out
garbled. Root cause: `ssh_cli` initialises `:prim_tty` with
`output := :cooked` (see `lib/ssh-5.5.2/src/ssh_cli.erl:72`), and
`:prim_tty`'s cooked-mode line-editor renders non-printable bytes
in caret notation (`lib/kernel-10.6.3/src/prim_tty.erl:1395-1399`
— `\b` → `^(`, `\x7F` → `^?`, etc.). Useful for iex's own line
editor; exactly wrong for a pass-through attach.

T6.1.1 brackets the pump with a `:prim_tty` output-mode flip:

- On entry, walk `Process.group_leader/0`'s state for the driver
  pid (the `ssh_cli` channel handler over SSH; `user_drv` locally
  if the user reaches for `:group_leader` there too). Run
  `:sys.replace_state/2` on it with a function that **recursively**
  scans the driver's state record for any tuple element that
  responds to `:prim_tty.output_mode/1` (the SSH driver is an
  `ssh_client_channel` gen_server whose state record wraps
  `ssh_cli`'s `#state{}` as a field, so the `prim_tty` we want
  lives two levels deep at path `[3, 9]`; local `user_drv` has
  it at path `[1]`). Once found, mutate the `:prim_tty` state's
  `options` map in place to set `output: :raw`, rebuild the
  outer state along the same path, and shout the previous mode
  back to the caller via a one-shot ref.
- On exit (inside the existing inner `try/after`, before the echo
  restore), replay the same swap with the saved mode.

**Why direct `options`-map mutation, not `:prim_tty.reinit/2`?**
`reinit/2` ends up calling the `tty_init/2` NIF, which requires
a real terminal fd. SSH-fronted `prim_tty` states have
`tty = undefined` (set up via `prim_tty:init_ssh/3`, not the
`:init/1` path) and the NIF rejects that with `:function_clause`.
The output-mode dispatch at `prim_tty.erl:677` is
`handle_request(State = #state{ options = #{ output := raw } }, ...)`,
so just updating `options.output` is sufficient — no re-init, no
NIF call. The options map is identified by scanning for an
element that's a map with both `:input` and `:output` keys
(distinctive without hard-coding the field index).

Scanning rather than hard-coding the field index makes the
mechanism resilient to ssh_cli / user_drv / `prim_tty`
record-layout reshuffles across OTP versions. Every step is
wrapped in safe helpers; if anything goes wrong (non-`:sys`-
capable driver, no `:prim_tty` field found, no options map),
we fall through to `nil` and the attach proceeds with today's
caret-rendered output — visibly broken, never crashy. A short
200ms timeout on the introspecting `:sys.get_state /
:sys.replace_state` keeps the fall-through cheap when the
driver isn't a `:sys`-capable process (test fakes, escripts).

Same kind of OTP-internals coupling T4 already accepts for
`:prim_tty.disable_reader/1`. The benefit (usable interactive
backspace + vim) is high; the failure mode (cosmetic cooked
rendering) is exactly the pre-T6.1.1 behaviour.

**Tests:** existing 35-test tty suite stays green; the
echo-restoration test exercises the fall-through path (the
fake_gl isn't `:sys`-capable, helpers return `nil`,
restore is a no-op, no test slowdown beyond the 200ms
timeout).

**Manual acceptance:** the user's SSH-iex bash session now
handles backspace as expected. Vim and other TUIs should also
render cleanly; covered by T6.2.

##### T6.1.2 — Ctrl-C forwarding

✅ **Shipped** alongside T6.1.1's final fix.

The first T6.1.1 deploy worked for editing but broke `Ctrl-C`:
the user pressed `^C` during a `sleep 30` and attach exited
with `{:error, {:gl_reader, :interrupted}}` instead of just
interrupting `sleep`.

Root cause: `ssh_cli` (`ssh_cli.erl:408`) intercepts byte `\x03`
from the SSH stream and turns it into `exit(group, interrupt)`
instead of passing the byte through. `group.erl:507-514` then
translates that into either `{:error, :interrupted}` on the
pending input request (the reader's `:io.get_chars`) or
`exit(shell, interrupt)` to the calling iex shell process
(when no input request is pending — a tiny race window
between reader round-trips).

Fix: both paths convert back to a literal `\x03` byte and forward
to the workload's PTY. The workload's line discipline then turns
0x03 into SIGINT for the foreground process group, which is what
users expect from Ctrl-C at a shell prompt.

- Reader's `:io.get_chars` returning `{:error, :interrupted}` →
  the reader sends `{:linx_tty_gl, :data, <<3>>}` to the pump
  and loops, instead of forwarding the error.
- Pump receives `{:EXIT, ^gl, :interrupt}` → writes `<<3>>` via
  `Linx.Process.pty_write` and continues the pump loop.

Both translations covered by `mix test` (37/37 tty): the pump
test injects the EXIT message and observes the workload (cat)
dies from SIGINT (`{:signaled, 2}`) before a backup SIGTERM
fires; the reader test runs against a scripted GL that replies
`:interrupted` then `:eof` and asserts a `<<3>>` data event
arrives in the parent's mailbox.

##### T6.2 — Manual acceptance + docs

✅ **Shipped.**

- `docs/tty/EXAMPLES.md`'s "Attaching to a workload's PTY"
  subtree was rewritten end-to-end against the observed
  behaviour: two-mode intro, `:controlling` walkthrough with
  the coexists-with-iex / refuses-over-SSH notes, full
  `:group_leader` walkthrough including a captured session
  block, the transient side-effects list (echo flip, prim_tty
  raw-output bracket, trap_exit), the `Ctrl-C` handling
  explanation in both of its arrival shapes, polled resize,
  and a "when to pick which mode" table.
- The `^C → exit 130` quirk worth knowing about is documented
  inline: that's `128 + SIGINT(2)`, reported by `sh` from the
  last command's status, not an attach failure.
- All examples are paste-friendly (no `iex>` / `...>` prefixes)
  and use `/bin/sh` — matches the Nerves rpi5 deployment target.

#### Open questions — resolved by the 2026-05-27 probe series

Recorded for posterity; all three are answered.

1. **Does the SSH path line-buffer?** **Yes by default, fixable
   trivially.** Probe #1 confirmed `:io.get_chars(_, '', 1)`
   waits for Enter. Probe #3 confirmed it returns immediately
   after `:io.setopts(gl, echo: false)`. `:group` routes through
   its `:xterm` line editor when echo is on and through `:dumb`
   when echo is off; `:dumb`'s `get_chars_dumb/5` is
   byte-oriented.
2. **Is there a stable SSH-detection signal?** **Yes**: the GL's
   `"$ancestors"` list contains `:ssh_sup` (OTP `ssh` app top
   supervisor) and `:sshd_sup` (nerves_ssh's wrapper). Cleanest
   possible signal — no record-layout coupling, no `:proc_lib`
   shape guessing.
3. **`:remsh` and other GL variants?** Still unknown — a probe
   from a `:remsh` session is the next data point. Not a
   blocker for T6.0/T6.1.

Read `docs/tty/probes/T6_*.exs` for the probe scripts and
captured terminal output. The `group.erl` cross-reference is
under "References" — `kernel-10.6.3/src/group.erl`.

#### Deferred — architected-for, not built in T6

- **`:remsh` and other GL classifications.** Once we have a probe
  from a `:remsh` session, fold its `$ancestors` signature into
  `classify_caller_terminal/0`. Until then it falls in
  `:unknown` and the existing `:controlling` path runs — which
  is wrong over `:remsh` too, but at least it doesn't pretend to
  be the SSH solution.
- **Event-driven resize over SSH.** Replace polling with a hook
  into the user_drv-equivalent's window-change handler so
  resizes propagate within milliseconds, not seconds. T6.1 ships
  with the 1s poll; this would mostly matter for users who
  resize while inside `vim`.
- **A first-class SSH-subsystem attach.** Skip the shell-channel
  layer entirely: expose `Linx.Tty.SshSubsystem` (an
  `ssh_server_channel`) that a consumer wires into their
  `:ssh.daemon` config. Cleanest architecturally, but pushes
  setup into every consumer; deferred until someone needs it.

The earlier T7 "go below ssh_cli for true-raw mode" item is
**dropped**: the probe series showed line-discipline lived in
`:group`, not ssh_cli, and `:io.setopts(echo: false)` already
gives byte-oriented input. There is no obvious additional
fidelity to chase.

#### Why not auto-fallback?

`attach(:controlling, _)` could in principle observe
`{:error, :no_local_tty}` and re-dispatch to `:group_leader`. T6
deliberately doesn't, because the two modes have meaningfully
different capabilities (raw-mode fidelity, SIGWINCH availability,
exit semantics on disconnect). Silent fallback hides those
differences from the caller. Explicit selection — with a
descriptive error pointing at the alternative — keeps the
trade-off visible.

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
