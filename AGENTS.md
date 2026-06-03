This is `linx`, an Elixir library providing Linux kernel interfaces (netlink, and more). The code is Elixir, with C in `c_src/` — NIFs and ports.

## Code style

- **Keep it simple.** Prefer the most obvious solution that works. Don't add abstraction, configurability, or generality until a second caller needs it.
- **Comment intent, not mechanics.** A comment explains *why*, or names a non-obvious kernel/runtime constraint — never restate what the code plainly says.

      # BAD: restates the code
      # bump the sequence number
      seq = seq + 1

      # GOOD: explains why
      # The kernel echoes our sequence number back in its ACK; bump it per
      # request so a stale reply can't be mistaken for the current one.
      seq = seq + 1

- Keep comments concise — a sentence or two.
- When implementing an existing protocol or kernel ABI, cite the authoritative spec (man page, RFC, kernel source) in a comment — name the specific section or struct, and link it where a stable URL exists. A reader should be able to check the wire format against the source without guessing.
- Match the style, naming, and comment density of the file you are editing.

## Elixir guidelines

- Every module has a `@moduledoc` (`@moduledoc false` for internal modules); every public function has a `@doc`. Document private functions only when intent isn't obvious.
- **Every public function has a `@spec`** — no exceptions. Add `@type`/`@typep` for non-trivial shapes.
- **Model domain data as structs**, not bare maps or loose tuples. Use `@enforce_keys` for required fields, declare a `@type t`, and tag function heads with `%Mod{}`.

      defmodule Linx.Netlink.Socket do
        @enforce_keys [:fd, :netns]
        defstruct [:fd, :netns]

        @type t :: %__MODULE__{fd: non_neg_integer, netns: :host | {:pid, pos_integer}}
      end

- **Error handling — shape follows how much context the failure carries:**
  - **Context-rich kernel/syscall failure → `%Linx.X.Error{}`** (one struct per subsystem; `defexception` + `message/1`; uniform `errno`/`code`, plus honest extras like `path` only where non-nil). Build via a `from_posix/_` factory.
  - **Context-free condition → a bare atom** (`{:error, :no_process}`), like stdlib `File` / `:gen_tcp`.
  - **Caller input mistake → a tagged tuple** `{:error, {:bad_*, reason}}`. Do **not** `raise` for these — keep them in the `{:ok, _} | {:error, _}` world for `with` pipelines.
  - A staged transport tuple like `{:error, {:send, :eperm}}` is fine — not every errno needs a struct.
- **Never** nest multiple modules in one file — risks cyclic dependencies and compilation errors.
- Don't use `String.to_atom/1` on user or kernel input (memory leak risk).

## C guidelines

C in `c_src/` is one of two kinds:

- **NIFs** — shared libraries loaded *into* the BEAM. Fast, but a bug can take down the whole VM.
- **Ports** — standalone executables as separate OS processes, talking to Elixir over a pipe. Needs a wire protocol, but a crash is contained.

Use a NIF for short, safe, non-blocking work; a **port** for anything dangerous to the VM (e.g. `clone`/`unshare`), long-running, or needing process isolation. When in doubt, prefer the port.

Whichever kind:

- Target C11; build warning-clean under `-Wall -Wextra -Wpedantic`.
- **Check every syscall and library return value.** Report failures as structured errors — never `abort()` or crash silently.
- Release or hand off every resource (fds, threads, allocations) on **every** path, including error paths.
- When you hardcode a kernel/UAPI constant instead of including its header, say why in a comment.

NIFs:

- **Document the term contract** — arguments, returned terms, error-term shape — above the function.
- Turn failures into `{:error, ...}` terms; never crash the OS process.
- **Never block a normal scheduler.** Flag blocking work as a dirty NIF (`ERL_NIF_DIRTY_JOB_IO_BOUND` / `_CPU_BOUND`).

Ports:

- **Document the wire protocol** — framing and every request/response shape — and keep it in sync with the Elixir driver.
- Exit with a distinct status code per failure mode; write a diagnostic to `stderr` first.
- Assume the port may be killed at any moment; hold no state that must survive it.

## Mix guidelines

- **Always run `mix format` before a git commit.**

## Test guidelines

- **Use `start_supervised!/1`** to start processes — it guarantees cleanup between tests.
- **Avoid** `Process.sleep/1` and `Process.alive?/1`:
  - To wait for a process to finish, use `Process.monitor/1` and assert the DOWN message:

        ref = Process.monitor(pid)
        assert_receive {:DOWN, ^ref, :process, ^pid, :normal}

  - To synchronize before the next call, use `_ = :sys.get_state(pid)`.
