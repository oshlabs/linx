# Linx

**Linux kernel interfaces for Elixir.**

Linx is a growing collection of Elixir libraries for talking to the Linux kernel — netlink sockets, procfs, namespaces, cgroups, and more. The goal is to make low-level Linux features feel as natural to use from Elixir as anything in the standard library.

> ⚠️ **Early days.** Linx is just getting started. Netlink-based networking is the first thing being built. The API is still settling and breaking changes are likely until `1.0`.

## Why Linx?

Building container runtimes, observability tools, network plumbing, or anything that needs to *really* talk to Linux usually means shelling out to `ip`, `nft`, etc. Linx aims to give Elixir a first-class, idiomatic way to do these things directly — structured messages, supervised processes, pattern-matched results, and all the comfort of OTP.

## Installation

Linx is not on Hex yet. Until the first release, depend on it from Git in `mix.exs`:

```elixir
def deps do
  [
    {:linx, github: "oshlabs/linx"}
  ]
end
```

Linx is **Linux-only** — the underlying kernel interfaces don't exist on macOS, BSD, or Windows.

## First up: networking

The initial focus is **`Linx.Netlink`** — a netlink (`NETLINK_ROUTE`) client for the Linux networking stack. It speaks netlink directly over an `AF_NETLINK` socket, encoding and decoding messages in pure Elixir; a small NIF handles the one thing the BEAM can't do safely on its own — entering another network namespace.

Netlink is how userspace really talks to the networking stack: links, addresses, routes, and more. Tools like `ip` and the rest of `iproute2` are thin wrappers over it.

The first release covers a focused slice of rtnetlink:

- Opening sockets in the host netns or inside another, `setns`-correct, by pid or path
- Creating, configuring and deleting links — including `macvlan` / `ipvlan`
- Moving links between network namespaces
- Adding IPv4 addresses and routes

Higher-level networking modules, more protocol families, and multicast event subscription are likely to follow.

Docs will be published to [HexDocs](https://hexdocs.pm/linx) with the first release.

## License

Linx is released under the [MIT License](LICENSE).

