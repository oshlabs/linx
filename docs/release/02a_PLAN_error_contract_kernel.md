# 02a — Error contract: kernel failures → structs

**Status:** planned · **Gates 0.1.0:** yes · **Topic:** error contract (bucket 1 — the substantive code change)

Split from `02`. This is the structural half: make every kernel/syscall failure a
`%Linx.X.Error{}` struct, as the README promises. Companion: `02b` (input mistakes,
raises, specs, README wording). Driven by the full error-return audit.

## Problem

Two bucket-1 violations (kernel failure must be a struct, never a raw errno):

### A1 — the netlink wire layer never wraps socket-syscall errnos
Linx builds `%Linx.Netlink.Error{}` for `NLMSG_ERROR` *replies*, but failures at the
**socket-syscall** level (open / setsockopt / send / recv) leak as raw errnos and
propagate through every rtnl/nfnl/netfilter verb. One root cause, library-wide reach:

- `Socket.open/2` → `{:error, {:socket, errno_atom}}` / `{:error, {stage, int}}`
  (`socket.ex:67,78,86`)
- `Socket.add_membership/2`, `drop_membership/2`, `set_rcvbuf/2` → bare errno atom
  (`socket.ex:115,124,142`)
- `Socket.Native.open_in_netns/2`, `bind_netlink/2` → raw integer errno
  (`socket/native.ex:47,71`) — internal NIF boundary
- `Request.talk/4` → `{:error, {:send, errno}}` / `{:error, {:recv, errno}}`
  (`request.ex:59,73`)
- `Nfnl.batch/4` → `{:error, {:send|:recv, errno}}` (`nfnl.ex:137,153`)
- `Netfilter.create_table/2`, `push/3`, `pull/2,3` — the `{:error, other}` arm
  re-emits `{:send|:recv, errno}` (`netfilter.ex:216,268,513,539,556`) even though the
  same functions wrap reply errors correctly
- `Netfilter.subscribe/2`, `Rtnl.Monitor` — `add_membership` failure (e.g. missing
  `CAP_NET_ADMIN`) surfaces as a **bare errno atom** from `init` (`monitor.ex:151`,
  `netfilter.ex:621`)
- `Netfilter.log_listen/2` (`Log` init) — config-send errno from `init`
- `Rtnl.open`, `Nfnl.open`, and all of `Link/Address/Route/Neighbour/Rule/Stats`
  inherit it by propagation.

### A2 — `Mount.list/0,1`
`read_and_parse/1` returns `{:error, posix}` straight from `File.read`
(`mount.ex:148-153`); reached by `list/0` and both `list/1` clauses
(`mount.ex:122,142-146`). A `/proc/.../mountinfo` read failure (`:enoent` = pid gone,
`:eacces`) is a kernel/FS failure and must be a `%Linx.Mount.Error{}`.

## Decision / approach

### A1 — wrap socket-syscall errnos into `%Netlink.Error{}`
Respect the existing design: `Linx.Netlink.Error` has **no `:operation` field** by
deliberate choice (`error.ex:15`), and `from_errno/2` takes a **positive integer**.
So:

1. **Extend the `Netlink.Error` builder** to accept a **posix atom** as well as an
   integer (the `:socket` ops return atoms; the NIF returns integers). Carry the
   syscall/context string (`"send"`, `"recv"`, `"open: bind"`, `"add_membership"`) in
   the struct's **`:message`** field — *not* a new field — consistent with the
   "no `:operation`" decision. (e.g. `Error.from_posix_atom(atom, message)` mapping
   atom→code, alongside the existing integer `from_errno/2`.)
2. **Convert at the syscall boundary**, so every downstream verb inherits the fix for
   free (they already propagate whatever `{:error, _}` they receive):
   - `Socket.open/2`, `add_membership/2`, `drop_membership/2`, `set_rcvbuf/2`
   - `Socket.Native` errno boundaries (`open_in_netns/2`, `bind_netlink/2`)
   - `Request.talk/4` send/recv arms; `Nfnl.batch/4` send/recv arms
   - `Rtnl.Monitor` and `Netfilter.Log` `init` — return `{:error, %Netlink.Error{}}`
     (a clean `{:stop, …}` carrying the struct) instead of a bare errno atom
3. **Netfilter re-stamp arms** (`netfilter.ex:216,268,513,539,556`): the `{:error,
   other}` arm now receives a `%Netlink.Error{}`; re-stamp it as `%Netfilter.Error{}`
   with the correct `operation:` (same as the reply path already does), rather than
   passing the tuple through.

Net effect: no raw errno escapes the wire layer; `{:socket,_}`/`{:send,_}`/`{:recv,_}`
tagged tuples disappear from public returns.

### A2 — wrap `Mount.list`
In `read_and_parse/1`, wrap the `File.read` failure via
`Linx.Mount.Error.from_posix(posix, path, :list)`. Add `:list` to `Mount.Error`'s
`operation` type (`mount/error.ex:53`). Update the two `@spec`s (`mount.ex:121,141`)
and two `@doc` blocks (`mount.ex:117-120,131-133`) that currently advertise
`{:error, atom()}`.

## Concrete changes
- `lib/linx/netlink/error.ex` — add a posix-atom builder; document the `:message`
  convention for syscall context.
- `lib/linx/netlink/socket.ex`, `socket/native.ex`, `request.ex`, `nfnl.ex` —
  convert errnos to structs at the boundary.
- `lib/linx/netlink/rtnl/monitor.ex`, `lib/linx/netfilter/log.ex` — struct from `init`.
- `lib/linx/netfilter.ex` — re-stamp the `{:error, other}` arms.
- `lib/linx/mount.ex`, `lib/linx/mount/error.ex` — A2.
- Specs on the directly-touched functions updated here; the broad spec sweep is `02b`.

## Tests
- Unit: replace assertions that expect `{:socket,_}`/`{:send,_}`/`{:recv,_}` or a bare
  errno; add tests that `Socket.open` to a bogus netns path and `Mount.list` on a
  bogus pid return the correct struct.
- Integration (`./sudotest.sh`): `subscribe`/`log_listen` without `CAP_NET_ADMIN`
  must yield `{:error, %Netlink.Error{}}`; the rtnl mutate paths under a forced errno.
  Real verification lives here — see topic `09`.

## Downstream: Tank compatibility
Tank consumes only Linx's public API and must stay green (its charter as Linx's
acceptance test). For A1/A2 the coupling is **low**:
- `tank/lib/tank/runtime/network.ex:107` passes wire errors through a `{:error, _}`
  **wildcard** — re-shaping wire errors does not break it.
- Tank does not match `{:socket,_}`/`{:send,_}`/`{:recv,_}`/posix atoms anywhere, and
  does not call `Mount.list`.

**Action:** on a Tank feature branch `linx-error-contract` (shared with `02b`), build
against the updated Linx (already a `../linx` path dep), then run **`mix test` and
`./sudotest.sh`**; fix any test that asserts an old shape. Commit + push the branch.
The gate is a green Tank suite, not a code read.

## Acceptance check
- `grep -rn "{:socket\|{:send,\|{:recv," lib/linx/netlink lib/linx/netfilter` → no
  such shapes in public `{:error, _}` returns.
- `Mount.list` on a bogus pid returns `%Linx.Mount.Error{operation: :list}`.
- `mix test --exclude integration` green; `./sudotest.sh` green on the release commit.
- Tank: `mix test` + `./sudotest.sh` green on its `linx-error-contract` branch.

## Risk / scope notes
- **Largest single change in the release.** The wire layer is central; nearly every
  networking verb inherits the new shape. Mitigated by converting at the boundary
  (few sites, broad effect) and by the integration suite.
- The kernel paths that exercise this are integration-gated and **CI does not run
  them** (topic `09`); a manual `./sudotest.sh` on the release commit is mandatory.
- `02b`'s spec sweep finalizes the precise union specs once these struct returns exist.
