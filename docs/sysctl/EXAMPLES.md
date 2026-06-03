# Linx.Sysctl examples

Hands-on examples of `Linx.Sysctl` — the kernel-tunable-parameter
surface, the `/proc/sys/` knobs that `sysctl(8)` reads and writes.

Most read operations work in a plain `iex -S mix` session against
the host's namespace. Writes to global knobs (`vm.*`, `fs.*`, most
`kernel.*`) need root. Per-namespace knobs (`net.*`,
`kernel.hostname`, IPC limits) may be writable as an unprivileged
user *inside* their own namespace — e.g. as `root` inside a
container's user ns — but writes from the BEAM to the host's
namespace still need real root.

## Detecting sysctl support

```elixir
Linx.Sysctl.supported?()
# => true
```

`supported?/0` returns true iff `/proc/sys/kernel/ostype` exists.
The knob predates namespaces; on any Linux system with procfs
mounted, this is always `true`. Returning `false` would mean
procfs isn't mounted at all (which would also break most of the
rest of Linx).

## Reading a sysctl

`read/1` returns the file's contents trimmed of the kernel's trailing
newline:

```elixir
Linx.Sysctl.read("kernel.ostype")
# => {:ok, "Linux"}

Linx.Sysctl.read("net.ipv4.ip_forward")
# => {:ok, "0"}

Linx.Sysctl.read("kernel.hostname")
# => {:ok, "fry"}
```

For the common integer case, `read_int/1` parses for you:

```elixir
Linx.Sysctl.read_int("net.ipv4.ip_forward")
# => {:ok, 0}

Linx.Sysctl.read_int("vm.swappiness")
# => {:ok, 60}

# Non-integer contents come back as {:bad_value, ...}:
Linx.Sysctl.read_int("kernel.hostname")
# => {:error, {:bad_value, {:not_an_integer, "fry"}}}
```

For the tuple-shaped knobs (`kernel.printk`, `net.ipv4.tcp_rmem`,
`net.ipv4.tcp_wmem`, …), `read_ints/1` splits on whitespace and
parses each token:

```elixir
Linx.Sysctl.read_ints("kernel.printk")
# => {:ok, [4, 4, 1, 7]}

Linx.Sysctl.read_ints("net.ipv4.tcp_rmem")
# => {:ok, [4096, 131072, 6291456]}
```

## Writing a sysctl

`write/2` accepts integers, binaries, and lists of integers. Writes
to most knobs need root.

```elixir
Linx.Sysctl.write("net.ipv4.ip_forward", 1)
# => :ok

Linx.Sysctl.write("kernel.hostname", "ct0")
# => :ok

Linx.Sysctl.write("kernel.printk", [4, 4, 1, 7])
# => :ok
```

Common patterns:

```elixir
# Enable IPv4 forwarding from a Nerves app (the original motivation).
:ok = Linx.Sysctl.write("net.ipv4.ip_forward", 1)

# Bump TCP buffer sizes.
:ok = Linx.Sysctl.write("net.ipv4.tcp_rmem", [4096, 262_144, 16_777_216])
:ok = Linx.Sysctl.write("net.ipv4.tcp_wmem", [4096, 262_144, 16_777_216])

# Reduce console log verbosity.
:ok = Linx.Sysctl.write("kernel.printk", [3, 4, 1, 7])
```

## Validation: two error shapes

`Linx.Sysctl` distinguishes caller-side input mistakes from kernel
rejections, mirroring `Linx.User`'s `:bad_map` / `%Error{}` split.

### Caller mistakes — caught before any procfs I/O

```elixir
Linx.Sysctl.read("")
# => {:error, {:bad_key, ""}}

Linx.Sysctl.read("net..ip_forward")
# => {:error, {:bad_key, "net..ip_forward"}}

Linx.Sysctl.read("net.ipv4.../etc/passwd")
# => {:error, {:bad_key, "net.ipv4.../etc/passwd"}}

Linx.Sysctl.write("kernel.hostname", "ct0\nct1")
# => {:error, {:bad_value, {:contains, :newline}}}

Linx.Sysctl.write("kernel.printk", [4, 4, "1", 7])
# => {:error, {:bad_value, {:not_all_integers, [4, 4, "1", 7]}}}
```

Keys must be dot-form `[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*` — no
leading or trailing dots, no consecutive dots (which rules out `..`
traversal), no slashes, no whitespace. Values must not contain `\n`
or `\0`; the kernel's sysctl parser treats newlines as end-of-input
and would silently truncate, so we reject loud-and-early.

### Kernel rejections — `%Linx.Sysctl.Error{}`

```elixir
Linx.Sysctl.read("linx.this.does.not.exist")
# => {:error,
#  %Linx.Sysctl.Error{
#    key: "linx.this.does.not.exist",
#    path: "/proc/sys/linx/this/does/not/exist",
#    operation: :read,
#    errno: :enoent,
#    code: 2
#  }}

Linx.Sysctl.write("net.ipv4.ip_forward", 1)  # unprivileged
# => {:error,
#  %Linx.Sysctl.Error{
#    key: "net.ipv4.ip_forward",
#    path: "/proc/sys/net/ipv4/ip_forward",
#    operation: :write,
#    errno: :eacces,
#    code: 13
#  }}
```

Pattern-match on `:errno` and `:operation` to handle specific
failures:

```elixir
case Linx.Sysctl.write("net.ipv4.ip_forward", 1) do
  :ok ->
    :ok

  {:error, %Linx.Sysctl.Error{errno: :eacces}} ->
    # Needs root.
    :no_perm

  {:error, %Linx.Sysctl.Error{errno: :enoent}} ->
    # No such sysctl on this kernel.
    :unknown_knob

  {:error, %Linx.Sysctl.Error{errno: :einval}} ->
    # Value out of range or wrong shape for this knob.
    :bad_value_for_knob
end
```

The `Exception` impl makes `raise` and `Exception.message/1` work
on `%Linx.Sysctl.Error{}` too:

```elixir
err = Linx.Sysctl.Error.from_posix(:eacces, "net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", :write)
Exception.message(err)
# => "sysctl write \"net.ipv4.ip_forward\" failed on /proc/sys/net/ipv4/ip_forward: eacces (errno 13)"
```

## Walking the sysctl tree

`list/0` walks all of `/proc/sys/` recursively and returns
`{:ok, [%Linx.Sysctl.Entry{}, ...]}` sorted by key. On a typical
Linux host this is ~1500 entries:

```elixir
{:ok, all} = Linx.Sysctl.list()
length(all)
# => 1487

Enum.take(all, 3)
# => [
  #Linx.Sysctl.Entry<abi.vsyscall32 = "1">,
  #Linx.Sysctl.Entry<crypto.fips_enabled = "0">,
  #Linx.Sysctl.Entry<debug.exception-trace = "1">
# ]

Enum.find(all, & &1.key == "kernel.ostype")
#Linx.Sysctl.Entry<kernel.ostype = "Linux">
```

Entries with restrictive permissions (write-only, root-only reads)
are silently skipped — the returned list is "everything I could
see from this process", not "everything the kernel exposes".
For complete coverage as an unprivileged caller, run `Linx.Sysctl`
from a context with sufficient privilege (or check the missing
keys individually with `read/1`).

`list/1` walks a subtree by dot-form prefix — useful for narrowing
down to a specific namespace's knobs:

```elixir
{:ok, net} = Linx.Sysctl.list("net.ipv4")
length(net)
# => 156

Enum.take(net, 4)
# => [
  #Linx.Sysctl.Entry<net.ipv4.cipso_cache_bucket_size = "10">,
  #Linx.Sysctl.Entry<net.ipv4.cipso_cache_enable = "1">,
  #Linx.Sysctl.Entry<net.ipv4.cipso_rbm_optfmt = "0">,
  #Linx.Sysctl.Entry<net.ipv4.cipso_rbm_strictvalid = "1">
# ]
```

`list/1` is convenient for "is this knob present on this kernel?"
without having to remember whether a particular dot-form name is a
directory or a file — if you pass a leaf key, you get back a
single-element list:

```elixir
Linx.Sysctl.list("kernel.ostype")
# => {:ok, [#Linx.Sysctl.Entry<kernel.ostype = "Linux">]}

Linx.Sysctl.list("linx.does.not.exist")
# => {:error,
#  %Linx.Sysctl.Error{
#    key: "linx.does.not.exist",
#    path: "/proc/sys/linx/does/not/exist",
#    operation: :list,
#    errno: :enoent,
#    code: 2
#  }}
```

### The `Entry` value type

Each `%Linx.Sysctl.Entry{}` carries the dot-form `:key` and the
trimmed-binary `:value`. Both fields are `@enforce_keys`-required:

```elixir
[first | _] = elem(Linx.Sysctl.list("net.ipv4"), 1)
first.key
# => "net.ipv4.cipso_cache_bucket_size"
first.value
# => "10"
```

The `Inspect` impl truncates values over 60 bytes for legibility
when looking at large lists — the underlying `:value` field is
never modified, so pattern matching on `:value` always gives you
the full string. The 60-byte limit comfortably accommodates the
tuple-shaped knobs (`kernel.printk`'s 4 ints, `tcp_rmem`'s 3 ints)
and the occasional descriptive string; only pathological cases
hit the truncation.

### Caveat: dots in leaf names

A small number of sysctl files have dots in their leaf names —
notably the per-interface `net.ipv4.conf.<iface>.*` knobs when the
interface name itself contains dots (a VLAN like `eth0.10`). For
those entries the dot-form key produced by `list/0..1` reads
correctly in the output but isn't unambiguously round-trippable
back to a unique procfs path (the string `net.ipv4.conf.eth0.10.proxy_arp`
could in principle resolve to two different files). The value
field is always faithful; consumers that need to act on a specific
file by interface name should keep the procfs path side-channel.

## Cross-namespace reads and writes (the `:in` option)

Every verb takes an `:in` option, mirroring `Linx.Mount`:

| `:in` value | What it targets |
|---|---|
| `:self` (default) | the BEAM's namespaces — pure Elixir, no NIF |
| `{:pid, n}` | the namespace stack of pid `n` (user + mount + UTS + IPC + net) |
| `{:path, p}` | a single explicit nsfd file path |

For `{:pid, n}`, `Linx.Sysctl` stats each `/proc/<n>/ns/<kind>`
against `/proc/self/ns/<kind>` and skips any namespace the target
shares with us. (`setns(2)` to a user namespace you're already in
returns `EINVAL`, so a workload spawned with only `[:net, :uts]`
namespaces would otherwise fail the dance.) If the target shares
*every* namespace with the BEAM, the operation short-circuits back
to the host path.

### Reading the value the container sees

```elixir
alias Linx.Process, as: P
alias Linx.Sysctl

{:ok, c} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net, :uts])
receive do {:linx_process, :ready, _} -> :ok end
{:ok, host_pid} = P.host_pid(c)
P.proceed(c)

# Each side reads its own namespace's value, independently:
Sysctl.read_int("net.ipv4.ip_forward")
# => {:ok, 0}                                              # host

Sysctl.read_int("net.ipv4.ip_forward", in: {:pid, host_pid})
# => {:ok, 0}                                              # container

Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, host_pid})
# => :ok

Sysctl.read_int("net.ipv4.ip_forward", in: {:pid, host_pid})
# => {:ok, 1}                                              # container now 1...

Sysctl.read_int("net.ipv4.ip_forward")
# => {:ok, 0}                                              # ...but host unchanged
```

The setns-on-a-throwaway-pthread dance ensures the BEAM's own
scheduler threads never enter the target namespace; the thread that
performs the I/O is destroyed as soon as it returns.

### Setting the container's hostname

```elixir
Sysctl.write("kernel.hostname", "web-01", in: {:pid, host_pid})
# => :ok

Sysctl.read("kernel.hostname", in: {:pid, host_pid})
# => {:ok, "web-01"}

Sysctl.read("kernel.hostname")
# => {:ok, "fry"}                                         # host's hostname is untouched
```

`kernel.hostname` is per-UTS-namespace; same idea for
`kernel.domainname` (NIS), the various `kernel.shm*`/`kernel.msg*`
IPC limits, and every `net.*` knob.

### Listing a subtree the container sees

`list/2` (with a prefix) and `list/1` (with `:in` opts) both work
cross-namespace:

```elixir
# All net.ipv4.* knobs the container sees -- some, like
# ip_forward, can differ from the host's values.
{:ok, net} = Sysctl.list("net.ipv4", in: {:pid, host_pid})
length(net)
# => 156

Enum.find(net, & &1.key == "net.ipv4.ip_forward")
#Linx.Sysctl.Entry<net.ipv4.ip_forward = "1">

# A leaf prefix returns a single-element list, same as the host path.
Sysctl.list("kernel.hostname", in: {:pid, host_pid})
# => {:ok, [#Linx.Sysctl.Entry<kernel.hostname = "web-01">]}
```

### Composing at the `Linx.Process` checkpoint

`:in` is **lifecycle-agnostic** — it works equally well between
`:ready` and `proceed/1` (the canonical "configure the container
before its first instruction" window) and against a fully-running
container post-`proceed/1`.

```elixir
alias Linx.{Process, Sysctl}
alias Linx.Netlink.Rtnl

{:ok, c} =
  Process.spawn(
    argv: ["/usr/sbin/nginx"],
    namespaces: [:net, :uts]
  )
receive do {:linx_process, :ready, _} -> :ok end
{:ok, host_pid} = Process.host_pid(c)

# Configure the container's network and sysctls together, all at
# the checkpoint, before nginx ever starts:
{:ok, ns} = Rtnl.open({:pid, host_pid})
:ok = Rtnl.Link.set_up(ns, "lo")
:ok = Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, host_pid})
:ok = Sysctl.write("net.ipv4.tcp_rmem", [4096, 262_144, 16_777_216],
                   in: {:pid, host_pid})
:ok = Sysctl.write("kernel.hostname", "ct-web-01", in: {:pid, host_pid})

Process.proceed(c)
```

`Linx.Process` has zero knowledge of `Linx.Sysctl`; the only
coupling is the shared `:ready ↔ proceed/1` window, exactly the
way every other subsystem ties in.

### Errors that only show up cross-namespace

The `%Linx.Sysctl.Error{}` struct gains four additional `:operation`
values from the namespace-acquisition path:

| `:operation` | When |
|---|---|
| `:open_ns` | couldn't open `/proc/<pid>/ns/<kind>` (target pid is gone, BEAM lacks read access) |
| `:unshare` | `unshare(CLONE_FS)` failed (vanishingly rare) |
| `:setns` | `setns(2)` failed (typically `:eperm` for an unprivileged BEAM targeting a child's own user ns) |
| `:thread` | couldn't create the worker pthread |

```elixir
Sysctl.write("kernel.hostname", "x", in: {:pid, 9_999_999})
# => {:error,
#  %Linx.Sysctl.Error{
#    key: "kernel.hostname",
#    path: "/proc/sys/kernel/hostname",
#    operation: :open_ns,
#    errno: :enoent,
#    code: 2
#  }}
```

Pattern-match on `:operation` to tell namespace-acquisition
failures apart from real read/write failures:

```elixir
case Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, container_pid}) do
  :ok ->
    :ok

  {:error, %Sysctl.Error{operation: :open_ns, errno: :enoent}} ->
    :container_gone

  {:error, %Sysctl.Error{operation: :setns, errno: :eperm}} ->
    :no_perm_for_target_ns           # rootless BEAM, container has its own user ns

  {:error, %Sysctl.Error{operation: :write, errno: errno}} ->
    {:write_failed, errno}            # the actual procfs write failed
end
```

### Rootless caveat

If the BEAM is unprivileged and the target container has its own
`:user` namespace, `setns(2)` to the user ns will return `EPERM` —
the kernel requires `CAP_SYS_ADMIN` in the *parent* user ns to
enter a child user ns. Same constraint that affects `Linx.Mount`
cross-namespace ops; same fix when one is needed (have the workload
itself perform the sysctl write inside its own user ns, where it
has full caps).

For the common Linx case (BEAM as system root, container's user ns
is the host's), this isn't a concern.

### `{:path, p}` — bypass the per-pid filter

`{:path, p}` takes a single namespace file path directly, without
the inode comparison `{:pid, n}` does:

```elixir
# Pin a network namespace bind-mount, then use it from many
# operations without holding a process open:
System.cmd("ip", ["netns", "add", "blue"])
Sysctl.write("net.ipv4.ip_forward", 1, in: {:path, "/var/run/netns/blue"})
# => :ok
```

This is the right shape for `ip netns`-style named namespaces and
for callers that have already opened a pinned-namespace file via
some other path. Most callers will use `{:pid, n}` instead.

## Declarative reconciliation

`Linx.Sysctl.Reconcile` turns a desired `%{key => value}` map into the
writes needed to converge the kernel onto it — observe, diff, apply,
once. It is single-shot mechanism: it holds no state and owns no
process. The loop that calls it on a cadence is the consumer's.

```elixir
alias Linx.Sysctl.Reconcile

desired = %{
  "net.ipv4.ip_forward" => 1,
  "net.ipv4.conf.all.rp_filter" => 1,
  "kernel.printk" => [4, 4, 1, 7]
}

# First pass: writes whatever the kernel doesn't already match.
{:ok, r} = Reconcile.reconcile(desired)
r.converged?            # true once every knob matches
r.applied               # the ops that actually hit the kernel this pass
r.failed                # [{op, %Sysctl.Error{}}] for any that errored

# Idempotent: a second pass with the same desired state is a no-op.
{:ok, r2} = Reconcile.reconcile(desired, r.last_applied)
r2.applied == []        # nothing left to do
```

Reconcile is **best-effort** — every knob is attempted, and a failure
on one (say `EACCES` without root) lands in `r.failed` without starving
the rest. Re-running converges anything still wrong; events are hints,
resync is truth.

### `last_applied` — three-way ownership

Thread `r.last_applied` from one pass into the next. It records which
keys you manage and the value each had before you first touched it. Its
job is to do the right thing when a key *leaves* the desired set:

```elixir
# Pass 1 manages two knobs.
{:ok, r1} = Reconcile.reconcile(%{"net.ipv4.ip_forward" => 1, "vm.swappiness" => 10})

# Pass 2 no longer wants vm.swappiness. By default it is released:
# left at its current value, reported as {:release, "vm.swappiness"}.
{:ok, r2} = Reconcile.reconcile(%{"net.ipv4.ip_forward" => 1}, r1.last_applied)

# Opt in to restoring the captured original instead:
{:ok, r3} =
  Reconcile.reconcile(%{"net.ipv4.ip_forward" => 1}, r1.last_applied,
    revert_on_release: true)
```

`last_applied` is reconciler-held and must not be persisted — it
captures live, pre-management values that die with the node. Start each
fresh run from `%{}`.

### Reconciling into a container's namespace

Every verb's `:in` option is forwarded, so reconcile works against a
container's namespace stack exactly like `read/3` and `write/3`:

```elixir
{:ok, r} =
  Reconcile.reconcile(%{"net.ipv4.ip_forward" => 1, "kernel.hostname" => "ct0"},
    %{}, in: {:pid, container_pid})
```

### A long-lived loop (opt-in)

`Reconcile.reconcile/3` is single-shot — you call it, it converges once,
you thread `last_applied` yourself. For a *continuously* converged knob,
add the opt-in `Linx.Reconcile` loop to your own supervision tree via the
sysctl `Source` adapter. The `scope` is the `:in` target:

```elixir
children = [
  {Linx.Reconcile,
   source: Linx.Sysctl.Reconcile.Source,
   scope: :self,
   desired: %{"net.ipv4.ip_forward" => 1},
   name: :host_sysctls}
]
Supervisor.start_link(children, strategy: :one_for_one)
```

It re-converges on a timer (default 5 s; set `interval:`), so a knob
flipped by hand is corrected on the next pass. sysctl has no kernel
multicast, so the loop is timer-only here — exactly right for state that
never changes behind your back. The loop is genuinely optional: it is the
recommended easy path for an app with no supervision tree to roll its own,
but the single-shot verbs work fully standalone without it.
