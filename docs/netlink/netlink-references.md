# References

External sources Linx draws on — kernel documentation, prior-art
libraries in C and other languages, and the Elixir conventions that
shaped the API. Anything cited in a moduledoc or referenced in a design
discussion should appear here.

A living doc — add to it when new sources inform a decision.

## Netlink protocol (the kernel side)

The wire format Linx speaks and the message families it knows come from
the kernel:

- [`netlink(7)` man page](https://man7.org/linux/man-pages/man7/netlink.7.html) — the protocol overview.
- [`rtnetlink(7)` man page](https://man7.org/linux/man-pages/man7/rtnetlink.7.html) — `NETLINK_ROUTE`'s message families.
- [`libnetlink(3)` man page](https://man7.org/linux/man-pages/man3/libnetlink.3.html) — `rtnl_talk` and friends; the C convention `Linx.Netlink.Request.talk/4` is named after.

UAPI headers (the authoritative wire definitions; cited inline wherever a
struct appears):

- [`linux/netlink.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h) — `nlmsghdr`, `nlmsgerr`, `NLM_F_*`, `NLMSG_*`.
- [`linux/rtnetlink.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h) — `ifinfomsg`, `rtmsg`, `RTM_*`, `RTA_*`.
- [`linux/if_link.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_link.h) — `IFLA_*` link attributes, kind-specific data (`IFLA_MACVLAN_MODE`, `IFLA_IPVLAN_MODE`, `IFLA_VLAN_*`, `VETH_INFO_PEER`).
- [`linux/if_addr.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h) — `ifaddrmsg`, `IFA_*`.
- [`linux/neighbour.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/neighbour.h) — `ndmsg`, `NDA_*`, `NUD_*`.
- [`linux/fib_rules.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fib_rules.h) — `fib_rule_hdr`, `FRA_*`, `FR_ACT_*`.
- [`linux/if.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if.h) — `IFF_*` interface flags.

## Kernel YAML netlink specs

The kernel ships machine-readable descriptions of netlink protocols.
The target of the future
YAML-driven codegen path for genl families.

- [Netlink protocol specifications](https://docs.kernel.org/userspace-api/netlink/specs.html) — the format.
- [Intro to writing netlink specs](https://docs.kernel.org/userspace-api/netlink/intro-specs.html)
- [The `netlink-raw` schema](https://docs.kernel.org/userspace-api/netlink/netlink-raw.html) — for rtnetlink and other pre-genl protocols.
- [Netlink docs index](https://docs.kernel.org/userspace-api/netlink/index.html)
- [`Documentation/netlink/specs/`](https://github.com/torvalds/linux/tree/master/Documentation/netlink/specs) — the YAML files themselves.
- [`tools/net/ynl/`](https://github.com/torvalds/linux/tree/master/tools/net/ynl) — the C and Python (`pyynl`) codegen tooling; the reference for spec semantics.

## Prior-art C libraries

Studied for the layering Linx adopts (Socket → Message → Attr → Request →
Codec → per-family resources):

- [libmnl](https://www.netfilter.org/projects/libmnl/) — minimalistic netlink helpers; the model for Linx's pure-codec layer.
- [libnl](https://www.infradead.org/~tgr/libnl/) — the larger object/cache library; the model for the high-level resource pattern. `libnl-route` adds typed object support around the core.
- [iproute2's `libnetlink.c`](https://github.com/iproute2/iproute2/blob/main/lib/libnetlink.c) — `rtnl_talk`, `rtnl_dump_filter`. The reference C client.

## Prior-art bindings in other languages

Cross-checked Linx's API shape against these:

- [vishvananda/netlink (Go)](https://github.com/vishvananda/netlink) — top-level `LinkAdd` / `AddrAdd` / `RouteAdd` verbs plus an `nl/` low-level split.
- [pyroute2 (Python)](https://github.com/svinota/pyroute2) ([docs](https://docs.pyroute2.org/)) — the low-level `IPRoute` and high-level `NDB`. The schema-driven message classes (`fields` + `nla_map`) were the most interesting comparison point.
- [rust-netlink](https://github.com/rust-netlink) — the deliberate crate split (`netlink-sys` / `netlink-packet-core` / `netlink-packet-route` / `netlink-proto` / `rtnetlink`). The clearest layering reference; Linx's module groups mirror it.
- [Feuerlabs/netlink (Erlang)](https://github.com/Feuerlabs/netlink) — the cautionary example: `gen_server`-IS-the-socket, twin hand-written codecs, dated C port driver. Its multicast-diff *idea* (subscribe to link / addr / route events) is genuinely useful and is the seed of the planned `Linx.Netlink.Monitor` — rebuilt as a clean layer on top of `Connection`, not baked into the socket.

## Elixir conventions and ecosystem

The API shape — `{:ok, _} | {:error, %Struct{}}`, the `~IP` sigil, error
structs as `defexception` — follows what's established in modern Elixir.

Libraries that use `{:error, %Struct{}}`:

- [`Ecto.Repo.insert/2`](https://hexdocs.pm/ecto/Ecto.Repo.html#c:insert/2) — `{:error, %Ecto.Changeset{}}`, the dominant Elixir error-struct pattern.
- [Req](https://hexdocs.pm/req/Req.html) — `{:error, exception}` (`%Req.TransportError{}`, `%Req.HTTPError{}`).
- [Jason](https://hexdocs.pm/jason/Jason.html) — `{:error, %Jason.DecodeError{}}`.
- [Postgrex](https://hexdocs.pm/postgrex/Postgrex.html) — `{:error, %Postgrex.Error{}}`.
- [Finch](https://hexdocs.pm/finch/Finch.html) — `{:error, %Finch.HTTPError{} | %Finch.TransportError{}}`.
- [Mint.TransportError](https://hexdocs.pm/mint/Mint.TransportError.html) — `defexception` carrying a structured `:reason`.

Background reading on error-handling conventions:

- [Michał Muskała — Error Handling in Elixir Libraries](https://michal.muskala.eu/post/error-handling-in-elixir-libraries/) — recommends `{:error, exception}`, citing Andrea Leopardi.
- [Leandro Pereira — Leveraging Exceptions to handle errors in Elixir](https://leandrocp.com.br/2020/08/leveraging-exceptions-to-handle-errors-in-elixir/)
- [Moxley Stratton — Best Practices For Error Values](https://medium.com/@moxicon/elixir-best-practices-for-error-values-50dc015a06f5)
- [Elixir code anti-patterns](https://hexdocs.pm/elixir/code-anti-patterns.html) — official guide; "normalise errors for `with`".
- [christopheradams/elixir_style_guide](https://github.com/christopheradams/elixir_style_guide) — naming conventions.
