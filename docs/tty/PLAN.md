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
> The 2026-05-27 SSH probe on a Nerves rpi5 confirmed the GL is
> `kernel`'s `:group` gen_statem (same module local iex uses, just
> on top of an SSH transport rather than `/dev/tty`), that
> `"$ancestors"` containing `:ssh_sup` / `:sshd_sup` is the
> detection signal, and that line-buffering comes from `:group`'s
> `:cooked` mode — not the SSH layer. One mechanism question
> remains: which knob (`:io.setopts/2`, a private `:group` event,
> or `:sys.replace_state/2`) flips `:cooked` cleanly. Sketch + probe
> only on the branch; no implementation yet.

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

**Mode — `binary: true` is already on; the open knob is
`:cooked`.** The probe confirmed `:io.getopts(gl)` returns
`binary: true` by default in the nerves_ssh path, so reads come
back as binaries with no setopts needed. The actual obstacle is
that `:group`'s internal `mode` field is `:cooked`: it runs a
full readline-style line editor (the `key_map` in the GL's
process dictionary), echoes locally, and only releases bytes to
the consumer after a line-terminator key. `:io.get_chars(_, '',
1)` against a cooked `:group` returns the *first byte of the
next finished line*, which is hopeless for an attach pump.

Flipping `:group` to non-cooked mode for the duration of attach
is the central T6.1 sub-problem. Three candidate mechanisms, in
order of preference:

  1. **Public `:io.setopts/2` knob.** `{:terminal, false}`,
     `{:echo, false}`, `{:line_history, false}` — singly or in
     combination — may move `:group` out of cooked mode.
     Pending the follow-up probe.
  2. **Private message to the `:group` gen_statem.** Same
     pattern as T4's `:prim_tty.disable_reader/1`: send `:group`
     a cast/event that flips its internal `mode` field. Requires
     finding the right message shape from `group.erl`.
  3. **`:sys.replace_state/2` surgery.** Overwrite the `:cooked`
     atom in the state record directly. Works regardless of
     whether `:group` exposes a hook, but couples to the record
     layout — same kind of OTP-internals dependency T4 already
     accepts for `user_drv`.

Echo suppression is a separate concern, also handled via one of
the above. `:io.setopts(gl, [{:echo, false}])` is the documented
path and very likely works on its own; the probe will confirm.

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
Linx.Tty                          — adds attach(:group_leader, _),
                                    format_error/1 helper.
Linx.Tty.GroupLeaderReader        — the linked reader sub-process
                                    that translates :io.get_chars/3
                                    into pump mailbox messages.
Linx.Tty.Env                      — classify_caller_terminal/0 +
                                    a small set of sniff helpers.
```

No NIF changes. No new agent commands — the workload-side path
(`pty_write`, `:pty_out`, `pty_set_winsize`) is unchanged.

#### Sequencing — sub-milestones

Each is an independently reviewable commit; commit + push per
milestone per project convention.

##### T6.0 — Precondition guard

- `Linx.Tty.Env.classify_caller_terminal/0`.
- Wire into `attach(:controlling, _)`; return
  `{:error, :no_local_tty}` for `:ssh` / `:remsh`.
- `Linx.Tty.format_error/1` returns a human-readable string for
  the new error atom.
- **Tests:** unit tests against a fake group leader. Manual SSH
  validation lives in EXAMPLES.md (under "What happens over SSH").

##### T6.1 — `attach(:group_leader, session)`

- `Linx.Tty.GroupLeaderReader` (reader sub-process).
- `Linx.Tty.attach(:group_leader, _)` — entry, set binary mode,
  spawn reader, initial winsize forward, pump loop, teardown.
- Pump loop (variant of `__pump__/3`):
  ```elixir
  receive do
    {:linx_tty_gl, :data, bytes} ->
      _ = Linx.Process.pty_write(session, bytes)
      __pump_gl__(reader, gl, session, opts)

    {:linx_process, :pty_out, bytes} ->
      IO.binwrite(gl, bytes)
      __pump_gl__(reader, gl, session, opts)

    {:linx_tty_gl, :eof} ->
      {:error, :gl_eof}            # SSH disconnect, etc.

    {:linx_process, :exited, code}    -> {:ok, {:exited, code}}
    {:linx_process, :signaled, signum} -> {:ok, {:signaled, signum}}
    {:linx_process, :error, errno, stage} ->
      {:error, %{errno: errno, stage: stage}}
  after
    poll_ms ->
      maybe_forward_winsize(gl, session, &state)
      __pump_gl__(reader, gl, session, opts)
  end
  ```
  The `after` clause is the polling-resize loop — folded into the
  `receive` to avoid a second process.
- **Tests:** plain `mix test` against a fake group leader (a
  process that consumes `{io_request, …}` and emits
  `{io_reply, …}`, just like the existing socketpair stand-in for
  the `:controlling` path). Verify byte round-trip, eof
  propagation, winsize forwarding on poll.

##### T6.2 — Manual acceptance + docs

- EXAMPLES.md: full "ssh in, attach to bash, type, exit" walkthrough.
- Line-buffering caveat documented; vim/top expected behaviour
  documented; the "Ctrl-C unwinds your local ssh, not the workload"
  surprise noted.

#### Open questions — what the 2026-05-27 probe answered

The first SSH probe (`docs/tty/probes/T6_ssh_probe.exs`) answered
two of the three original open questions:

1. **Does the SSH path line-buffer?** **Yes**, but the culprit is
   `:group`'s `:cooked` mode, not ssh_cli. `:io.get_chars(_, ~c"",
   1)` blocked until Enter; the returned byte was the trailing
   newline of the line that `:group`'s editor finally released.
2. **Is there a stable SSH-detection signal?** **Yes**: the GL's
   `"$ancestors"` list contains `:ssh_sup` (OTP `ssh` app top
   supervisor) and `:sshd_sup` (nerves_ssh's wrapper). Cleanest
   possible signal — no record-layout coupling, no `:proc_lib`
   shape guessing.
3. **`:remsh` and other GL variants?** Still unknown — a probe
   from a `:remsh` session is the next data point. Not a
   blocker for T6.0/T6.1.

The remaining unknown — and the only one blocking a clean
T6.1 implementation — is **how to flip `:group` out of cooked
mode**. The state record's mode field is the atom `:cooked` (the
7th element of the inner `:state` tuple in `:sys.get_state(gl)`).
Three candidate mechanisms are listed under "Mechanism / Mode"
above; the follow-up probe will identify which one ships:

```elixir
# Slated for docs/tty/probes/T6_group_mode.exs
gl = Process.group_leader()
mode = fn -> :sys.get_state(gl, 500) |> elem(1) |> Tuple.to_list()
             |> Enum.find(&(&1 in [:cooked, :raw])) end

IO.inspect(mode.(), label: "initial")
:io.setopts(gl, terminal: false)
IO.inspect(mode.(), label: "after terminal: false")
:io.setopts(gl, echo: false)
IO.inspect(mode.(), label: "after echo: false")
# … plus a get_chars(1) probe at each step, restored at the end.
```

#### Deferred — architected-for, not built in T6

- **`:remsh` and other GL classifications.** Once we have a probe
  from a `:remsh` session, fold its `$ancestors` signature into
  `classify_caller_terminal/0`. Until then it falls in
  `:unknown` and the existing `:controlling` path runs — which
  is wrong over `:remsh` too, but at least it doesn't pretend to
  be the SSH solution.
- **T7 — bytes-perfect raw mode over SSH.** Originally framed as
  "go below ssh_cli." The probe reframes this: `:group` does
  the line-discipline, ssh_cli is just transport. If a chosen
  T6.1 mode flip leaves residual cooked-mode artefacts (special
  keys, control codes), T7 is the deeper surgery on `:group` (or
  on the user_drv equivalent above it) to clear them out.
  Scope is much smaller than the original sketch suggested.
- **Event-driven resize over SSH.** Replace polling with a hook
  into the IO server's window-change handler (probably on the
  user_drv pid sitting between `:group` and the SSH transport)
  so resizes propagate within milliseconds, not seconds.
- **A first-class SSH-subsystem attach.** Skip the shell-channel
  layer entirely: expose `Linx.Tty.SshSubsystem` (an
  `ssh_server_channel`) that a consumer wires into their
  `:ssh.daemon` config. Cleanest architecturally, but pushes
  setup into every consumer; deferred until someone needs it.

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
