# Linx examples

Hands-on examples of using `Linx.Netlink` against the live Linux kernel.

Read-only operations work in a plain `iex -S mix` session. Anything that
*changes* network state — creating links, adding addresses or routes,
entering another network namespace — needs root: start with `./sudorun.sh`.

## Quick start

```elixir
iex> alias Linx.Netlink.{Rtnl, Socket}
iex> alias Linx.Netlink.Rtnl.Link

iex> {:ok, sock} = Rtnl.open()
{:ok, %Linx.Netlink.Socket{netns: :host, protocol: 0, ...}}

iex> {:ok, links} = Link.list(sock)
iex> Enum.map(links, & &1.name)
["lo", "eth0", "wlan0"]

iex> Socket.close(sock)
:ok
```

Every verb takes a socket as its first argument; structs come back from
reads, `:ok` or `{:error, %Linx.Netlink.Error{}}` from mutations.

## Reading the network

### Links

```elixir
iex> {:ok, lo} = Link.get(sock, "lo")
{:ok, %Link{index: 1, name: "lo", type: 772, flags: 65609, mtu: 65536, ...}}

iex> Link.up?(lo)
true

iex> {:ok, links} = Link.list(sock)
iex> length(links)
4
```

### Addresses

```elixir
iex> alias Linx.Netlink.Rtnl.Address

iex> {:ok, addresses} = Address.list(sock)
iex> length(addresses)
6

iex> {:ok, lo_addrs} = Address.list(sock, "lo")
iex> Enum.map(lo_addrs, & &1.address)
[<<127, 0, 0, 1>>,
 <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>]  # ::1
```

### Routes

```elixir
iex> alias Linx.Netlink.Rtnl.Route

iex> {:ok, routes} = Route.list(sock)
iex> Enum.count(routes, &(&1.family == 2))   # IPv4 routes
3
```

## Creating virtual interfaces

These need `./sudorun.sh`.

### macvlan / ipvlan — a separate network identity riding a parent NIC

A macvlan is a first-class host on the LAN — its own MAC, its own IP, no
NAT. The other container-networking model.

```elixir
iex> Link.create_macvlan(sock, "web0", "eth0", :bridge)
:ok
iex> Link.create_ipvlan(sock, "app0", "eth0", :l3)
:ok
```

### veth — a connected pair

The other container-networking model — two interfaces wired back-to-back,
typically used with a bridge.

```elixir
iex> Link.create_veth(sock, "v0a", "v0b")
:ok
```

### vlan — 802.1Q tagging

```elixir
iex> Link.create_vlan(sock, "eth0.42", "eth0", 42)
:ok
```

### bridge — and enslaving links to it

```elixir
iex> Link.create_bridge(sock, "br0")
:ok
iex> Link.set_master(sock, "v0a", "br0")
:ok
iex> Link.set_master(sock, "v0b", "br0")
:ok
```

### dummy — a no-op interface

Useful as a stable address holder or test fixture.

```elixir
iex> Link.create_dummy(sock, "test0")
:ok
```

## Configuring an interface

```elixir
iex> Link.set_up(sock, "eth0.42")
:ok
iex> Link.set_mtu(sock, "eth0.42", 1400)
:ok
iex> Link.set_address(sock, "eth0.42", "02:aa:bb:cc:dd:ee")
:ok
iex> Link.set_name(sock, "eth0.42", "vlan42")
:ok
iex> Link.set_down(sock, "vlan42")
:ok
iex> Link.delete(sock, "vlan42")
:ok
```

## Addresses

IPv4 and IPv6 alike — the family is detected from the address string:

```elixir
iex> Address.add(sock, "vlan42", "10.0.42.5", 24)
:ok
iex> Address.add(sock, "vlan42", "fc00::42:5", 64)
:ok
iex> Address.delete(sock, "vlan42", "10.0.42.5", 24)
:ok
```

## Routes

```elixir
iex> Route.add(sock, "10.99.0.0", 24, "10.0.42.1")        # via a gateway
:ok
iex> Route.add_default(sock, "10.0.42.1")                 # the default route
:ok
iex> Route.delete(sock, "10.99.0.0", 24, "10.0.42.1")
:ok
iex> Route.delete_default(sock, "10.0.42.1")
:ok
```

IPv6 works through the same API — `Route.add(sock, "fd00::", 64, "fc00::1")`
or `Route.add_default(sock, "fc00::1")`; the family is taken from the
gateway and destination, which must agree.

## Network namespaces

`Rtnl.open/1` chooses the namespace the socket lives in:

```elixir
# the host's own netns (default)
{:ok, host} = Rtnl.open()
{:ok, host} = Rtnl.open(:host)

# inside the netns of process 4242 — e.g. a running container
{:ok, ns} = Rtnl.open({:pid, 4242})

# by file path — anything that names a netns
{:ok, ns} = Rtnl.open({:path, "/var/run/netns/myns"})
```

Every verb then operates in that namespace. To hand a link from one
namespace to another:

```elixir
# host-side: move "web0" into pid 4242's netns
Link.move_to_netns(host, "web0", 4242)

# inside-side: bring loopback up, configure web0, install a default route
Link.set_up(ns, "lo")
Address.add(ns, "web0", "192.168.1.50", 24)
Link.set_up(ns, "web0")
Route.add_default(ns, "192.168.1.1")
```

## Errors

Every netlink verb returns `{:ok, _} | {:error, %Linx.Netlink.Error{}}`:

```elixir
iex> Link.get(sock, "nope0")
{:error, %Linx.Netlink.Error{
   errno: :enodev, code: 19,
   message: "no such interface \"nope0\""
}}
```

`%Linx.Netlink.Error{}` is an `Exception`, so it can be matched, formatted
or raised:

```elixir
iex> {:error, err} = Link.get(sock, "nope0")
iex> err.errno
:enodev
iex> Exception.message(err)
"netlink ENODEV (19): no such interface \"nope0\""
iex> raise err
** (Linx.Netlink.Error) netlink ENODEV (19): no such interface "nope0"
```

When the kernel attaches a description through extended ack
(`NLMSGERR_ATTR_MSG`), it surfaces in `:message` automatically. When it
does not, the verb synthesizes a useful one — `create_macvlan` for example
sharpens "no such interface" into "no such parent interface" so the caller
knows which name was at fault.
