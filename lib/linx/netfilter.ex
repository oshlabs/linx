defmodule Linx.Netfilter do
  @moduledoc """
  Linux netfilter primitives — modern firewall (nf_tables) via the
  `NETLINK_NETFILTER` netlink protocol family, plus live ruleset
  monitoring and packet-event capture (NFLOG).

  ## Why a separate subsystem

  Netfilter is a coherent kernel concept (firewall + connection
  tracking + packet event streams) with its own netlink protocol
  family (`NETLINK_NETFILTER` = 12) and a sprawling but consistent
  surface. Wrapping it as its own concept module — peer to
  `Linx.Process`, `Linx.Cgroup`, `Linx.Mount`, `Linx.User`,
  `Linx.Capabilities`, `Linx.Seccomp`, `Linx.Sysctl` — keeps the
  firewall mental model explicit. The underlying transport,
  `Linx.Netlink.Nfnl`, mirrors `Linx.Netlink.Rtnl`'s shape.

  ## Value, not handle

  `%Linx.Netfilter.Ruleset{}` is plain data: tables containing chains
  containing ordered rules, plus sets/maps/vmaps and named objects.
  Pure Elixir values, freely composable and inspectable. Four verbs:

    * `build` — construct via pipeline DSL or `~NFT` sigil.
    * `push/2` — write to the kernel atomically (`:replace` rebuilds,
      `:reconcile` computes the minimal diff).
    * `pull/1..2` — read kernel state into a ruleset value.
    * `diff/2` — compute the patch between two rulesets.

  Kernel state lives in the kernel; the Elixir value is the Elixir
  value. Mirrors `%Linx.Seccomp.Filter{}` scaled to a larger surface.

  ## Transactions are mandatory

  Every mutation goes through a `NFNL_MSG_BATCH_BEGIN` /
  `NFNL_MSG_BATCH_END` envelope; the kernel applies the whole batch
  atomically or rejects it whole. `push/2` is the only mutator,
  batch-shaped from the outside in.

  Modes:

    * `:replace` (default) — tear down and rebuild the named tables.
      Simple, brief disruption.
    * `:reconcile` — compute the minimal patch between current kernel
      state and the desired Ruleset, emit as one batch.
      LiveView-of-firewalls; no service interruption when only
      adding/removing rules at the margins.

  ## Optimistic concurrency via `NFTA_BATCH_GENID`

  `:reconcile` mode threads the kernel's generation counter through
  the batch: "I computed this against generation N; reject if N has
  moved". The kernel returns `ERESTART` on mismatch — `push/2`
  retries with bounded attempts, surfacing
  `{:error, %Error{errno: :erestart, ruleset_gen: gen}}` on
  exhaustion. Lets Linx cooperate cleanly with `nft` CLI / firewalld /
  any other writer in the same netns.

  ## Owner flag is the default

  `create_table/2` sets `NFT_TABLE_F_OWNER` by default: the table is
  destroyed when the creating netlink socket closes. The supervisor
  that opens the Nfnl socket owns the firewall; if it dies, rules
  vanish. **No other firewall management tool exposes this naturally.**

  Opt out with `persist: true` (uses `NFT_TABLE_F_PERSIST`, 6.9+) for
  policies that should survive the BEAM. Older kernels fall back to
  no-flags, table survives socket close until explicitly deleted.

  ## Per-namespace isolation

  Each netns has fully independent nftables state — own tables, own
  generation counter, own commit mutex, own multicast group.
  `Linx.Netlink.Nfnl.open({:pid, child_pid})` opens the socket inside
  that netns for its whole life; reads/writes through that socket
  land in the child's nftables instance. Same value type, same
  verbs.

  ## Authoring surfaces: peers, not layers

  Two authoring surfaces produce the same `%Ruleset{}`:

    * **Pipeline DSL** —
      `Ruleset.new() |> Ruleset.add_table(...) |> Table.add_chain(...) |> Chain.add_rule(...)` —
      for runtime-shaped rulesets (interfaces discovered at boot,
      IPs from config).
    * **`~NFT` sigil** — `~NFT"table inet myapp { chain ... }"` —
      for compile-time-authored rulesets with safe Elixir
      interpolation and lossless round-trip to `nftables.conf`
      files. Modelled on Phoenix LiveView's HEEx.

  Both call the same validator-setter functions; both produce the
  same value. Pipeline DSL lands in N1; `~NFT` lands in N8.

  ## Composition with `Linx.Process`

  Same shape as every other Linx subsystem: configure the child's
  network and firewall at the checkpoint between `:ready` and
  `proceed/1`, then release the workload with everything in force:

      {:ok, c} = Linx.Process.spawn(argv: [...], namespaces: [:net])
      receive do {:linx_process, :ready, _} -> :ok end
      {:ok, host_pid} = Linx.Process.host_pid(c)

      {:ok, ct_nfnl} = Linx.Netlink.Nfnl.open({:pid, host_pid})
      :ok = Linx.Netfilter.push(ct_nfnl, container_ruleset())

      :ok = Linx.Process.proceed(c)

  `Linx.Process` has zero awareness of netfilter; the checkpoint is
  the only coupling, exactly the way `Linx.Sysctl` / `Linx.Mount` /
  every other subsystem composes.

  ## Status

  N0 — scaffolding only. `supported?/0` is functional;
  `Linx.Netlink.Nfnl` + `Linx.Netlink.Nfnl.Codec` provide the
  transport + `nfgenmsg` / batch / `GETGEN` codec primitives. The
  value-type surface and pipeline DSL land in N1; the wire codec
  for tables/chains/rules + minimal expressions in N2; NAT in N3;
  sets/maps in N4; diff + `:reconcile` + CAS in N5; subscription
  in N6; NFLOG in N7. **v1.0 release** at N7. The `~NFT` sigil +
  `nftables.conf` codec arrives in N8; `mix format` plugin in N9.
  **v1.5 release** at N9.

  See `docs/netfilter/PLAN.md` for the full roadmap and
  `docs/netfilter/COVERAGE.md` for what's in / out per milestone.

  ## References

    * [`include/uapi/linux/netfilter/nf_tables.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h)
    * [`include/uapi/linux/netfilter/nfnetlink.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink.h)
    * [wiki.nftables.org](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
    * [`Documentation/networking/netlink_spec/nftables`](https://docs.kernel.org/networking/netlink_spec/nftables.html)
  """

  alias Linx.Netfilter.Error
  alias Linx.Netlink.{Nfnl, Socket}

  @doc """
  Returns `true` iff the kernel supports nfnetlink (i.e., a
  `NETLINK_NETFILTER` socket can be opened in the current netns).

  Opening the socket verifies the kernel was built with
  `CONFIG_NETFILTER_NETLINK=y` (universal in modern Linux) — every
  real operation against it (`GETGEN`, mutations) requires
  `CAP_NET_ADMIN`, but the socket open itself is unprivileged. So
  this probe answers "would Linx.Netfilter work *if* I had the right
  capabilities", not "do I have the right capabilities" — the latter
  surfaces as a `:eperm` error from the actual verb call when the
  time comes.

  Returns `false` if the kernel module is missing or the BEAM
  process can't allocate a socket. Doesn't distinguish between
  those.
  """
  @spec supported?() :: boolean()
  def supported? do
    case Nfnl.open() do
      {:ok, sock} ->
        Socket.close(sock)
        true

      {:error, _} ->
        false
    end
  end

  @doc """
  Creates a new table in the kernel's nftables instance.

  Lands in N2.
  """
  @spec create_table(Socket.t(), String.t(), keyword()) ::
          {:ok, term()} | {:error, Error.t() | term()}
  def create_table(_sock, _name, _opts \\ []),
    do: {:error, :not_yet_implemented}

  @doc """
  Pushes a Ruleset to the kernel atomically.

  Modes: `:replace` (default) rebuilds the named tables; `:reconcile`
  computes the minimal diff against current kernel state and emits
  it as one batch with `NFTA_BATCH_GENID` for optimistic concurrency.

  Lands in N2 (`:replace`) and N5 (`:reconcile`).
  """
  @spec push(Socket.t(), term(), keyword()) ::
          :ok | {:error, Error.t() | term()}
  def push(_sock, _ruleset, _opts \\ []),
    do: {:error, :not_yet_implemented}

  @doc """
  Pulls the kernel's nftables state into a Ruleset value.

  With no second arg, pulls the whole netns. With a `{family, name}`
  scope, pulls one table.

  Lands in N2.
  """
  @spec pull(Socket.t()) :: {:ok, term()} | {:error, Error.t() | term()}
  def pull(_sock), do: {:error, :not_yet_implemented}

  @spec pull(Socket.t(), {atom(), String.t()}) ::
          {:ok, term()} | {:error, Error.t() | term()}
  def pull(_sock, _scope), do: {:error, :not_yet_implemented}

  @doc """
  Computes a Patch (the minimal sequence of ops) between two
  Rulesets. Identity rules: name for tables/chains/sets/objects,
  tag-or-position for rules within a chain, element value for set
  elements.

  Lands in N5. `dry_run/2` is an alias.
  """
  @spec diff(term(), term()) :: {:ok, term()} | {:error, term()}
  def diff(_from, _to), do: {:error, :not_yet_implemented}

  @doc "Alias for `diff/2`."
  @spec dry_run(term(), term()) :: {:ok, term()} | {:error, term()}
  def dry_run(from, to), do: diff(from, to)

  @doc """
  Subscribes the caller to `NFNLGRP_NFTABLES` multicast events for
  the current netns. Returns a monitor reference; the caller
  receives `{:linx_netfilter, :event, %Event{}}` per ruleset change
  and `{:linx_netfilter, :resync_needed}` on `ENOBUFS`.

  Lands in N6.
  """
  @spec subscribe(pid()) :: {:ok, reference()} | {:error, term()}
  def subscribe(_owner_pid \\ self()), do: {:error, :not_yet_implemented}

  @doc """
  Opens an NFLOG listener bound to `group`. The owner receives
  `{:linx_netfilter, :log, %Log.Event{}}` per logged packet.

  Lands in N7.
  """
  @spec log_listen(pid(), keyword()) :: {:ok, reference()} | {:error, term()}
  def log_listen(_owner_pid, _opts \\ []), do: {:error, :not_yet_implemented}
end
