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

> 🟢 **S0–S1 shipped.** `supported?/0`, `read/1`, `read_int/1`,
> `read_ints/1`, `write/2`, and the `%Linx.Sysctl.Error{}` struct
> are in. Subtree walking lands in S2; the cross-namespace `:in`
> option lands in S3. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out.

## Detecting sysctl support

```elixir
iex> Linx.Sysctl.supported?()
true
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
iex> Linx.Sysctl.read("kernel.ostype")
{:ok, "Linux"}

iex> Linx.Sysctl.read("net.ipv4.ip_forward")
{:ok, "0"}

iex> Linx.Sysctl.read("kernel.hostname")
{:ok, "fry"}
```

For the common integer case, `read_int/1` parses for you:

```elixir
iex> Linx.Sysctl.read_int("net.ipv4.ip_forward")
{:ok, 0}

iex> Linx.Sysctl.read_int("vm.swappiness")
{:ok, 60}

# Non-integer contents come back as {:bad_value, ...}:
iex> Linx.Sysctl.read_int("kernel.hostname")
{:error, {:bad_value, {:not_an_integer, "fry"}}}
```

For the tuple-shaped knobs (`kernel.printk`, `net.ipv4.tcp_rmem`,
`net.ipv4.tcp_wmem`, …), `read_ints/1` splits on whitespace and
parses each token:

```elixir
iex> Linx.Sysctl.read_ints("kernel.printk")
{:ok, [4, 4, 1, 7]}

iex> Linx.Sysctl.read_ints("net.ipv4.tcp_rmem")
{:ok, [4096, 131072, 6291456]}
```

## Writing a sysctl

`write/2` accepts integers, binaries, and lists of integers. Writes
to most knobs need root.

```elixir
iex> Linx.Sysctl.write("net.ipv4.ip_forward", 1)
:ok

iex> Linx.Sysctl.write("kernel.hostname", "ct0")
:ok

iex> Linx.Sysctl.write("kernel.printk", [4, 4, 1, 7])
:ok
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
iex> Linx.Sysctl.read("")
{:error, {:bad_key, ""}}

iex> Linx.Sysctl.read("net..ip_forward")
{:error, {:bad_key, "net..ip_forward"}}

iex> Linx.Sysctl.read("net.ipv4.../etc/passwd")
{:error, {:bad_key, "net.ipv4.../etc/passwd"}}

iex> Linx.Sysctl.write("kernel.hostname", "ct0\nct1")
{:error, {:bad_value, {:contains, :newline}}}

iex> Linx.Sysctl.write("kernel.printk", [4, 4, "1", 7])
{:error, {:bad_value, {:not_all_integers, [4, 4, "1", 7]}}}
```

Keys must be dot-form `[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*` — no
leading or trailing dots, no consecutive dots (which rules out `..`
traversal), no slashes, no whitespace. Values must not contain `\n`
or `\0`; the kernel's sysctl parser treats newlines as end-of-input
and would silently truncate, so we reject loud-and-early.

### Kernel rejections — `%Linx.Sysctl.Error{}`

```elixir
iex> Linx.Sysctl.read("linx.this.does.not.exist")
{:error,
 %Linx.Sysctl.Error{
   key: "linx.this.does.not.exist",
   path: "/proc/sys/linx/this/does/not/exist",
   operation: :read,
   errno: :enoent,
   code: 2
 }}

iex> Linx.Sysctl.write("net.ipv4.ip_forward", 1)  # unprivileged
{:error,
 %Linx.Sysctl.Error{
   key: "net.ipv4.ip_forward",
   path: "/proc/sys/net/ipv4/ip_forward",
   operation: :write,
   errno: :eacces,
   code: 13
 }}
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
iex> err = Linx.Sysctl.Error.from_posix(:eacces, "net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", :write)
iex> Exception.message(err)
"sysctl write \"net.ipv4.ip_forward\" failed on /proc/sys/net/ipv4/ip_forward: eacces (errno 13)"
```

## (Will land with S2 — subtree walking + Entry)

## (Will land with S3 — cross-namespace via `:in`)
