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

  import Linx.Netlink.Constants

  import Linx.Netfilter.Wire,
    only: [
      nft_msg_getchain: 0,
      nft_msg_getrule: 0,
      nft_msg_getset: 0,
      nft_msg_getsetelem: 0,
      nfta_set_elem_list_table: 0,
      nfta_set_elem_list_set: 0
    ]

  alias Linx.Netfilter.{Decoder, Encoder, Error, Ruleset, Table}
  alias Linx.Netlink.{Message, Nfnl, Request, Socket}
  alias Linx.Netlink.Nfnl.Codec, as: NfnlCodec
  alias Linx.Netlink.Error, as: NetlinkError

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

  ## Options

    * `:family` — `:ip` | `:ip6` | `:inet` | `:arp` | `:bridge` |
      `:netdev`. Default: `:inet` (the firewall sweet spot — one
      table covers both IPv4 and IPv6).
    * `:persist` — `true` to disable the owner flag, leaving the
      table behind when the socket closes. Default `false` (table
      auto-destroys with the socket; see *Owner flag is the default*
      in the moduledoc).

  Returns `{:ok, %Ruleset{}}` — the ruleset has just this one
  table, ready for chains / rules to be added with the
  `Linx.Netfilter.Ruleset` pipeline DSL and then pushed back with
  `push/2`.

  Wire-level failures come back as `{:error, %Linx.Netfilter.Error{}}`
  with the operation set to `:create_table` and the kernel's
  errno / extended-ack message attached. `EEXIST` means the table
  was already present (pass through `Ruleset.pull/2` first if you
  want a "create-or-fetch" pattern).
  """
  @spec create_table(Socket.t(), String.t(), keyword()) ::
          {:ok, Ruleset.t()} | {:error, Error.t() | term()}
  def create_table(%Socket{} = sock, name, opts \\ []) when is_binary(name) and is_list(opts) do
    family = Keyword.get(opts, :family, :inet)
    persist? = Keyword.get(opts, :persist, false)
    flags = if persist?, do: [:persist], else: [:owner]

    with {:ok, table} <- Table.new(family, name, flags: flags) do
      msg = Encoder.table(table)

      case Nfnl.batch(sock, [msg]) do
        :ok ->
          {:ok,
           %Ruleset{tables: %{{family, name} => table}}}

        {:error, {_batch_seq, %NetlinkError{} = err}} ->
          {:error,
           Error.from_posix(err.errno, :create_table,
             subsys: :nftables,
             msg_type: 0x00,
             message: err.message
           )}

        {:error, other} ->
          {:error, other}
      end
    end
  end

  @doc """
  Pushes a Ruleset to the kernel atomically as one batched
  transaction.

  Modes:

    * `:replace` (default, N2) — for each table in `ruleset`, the
      kernel sees `DESTROYTABLE` (silent-if-missing, 6.3+) then
      `NEWTABLE` plus all its chains and rules. Other tables in
      the netns are untouched.
    * `:reconcile` (N5) — minimal-diff push with `NFTA_BATCH_GENID`
      CAS for cooperative concurrency.

  Returns `:ok` on success, or `{:error, %Linx.Netfilter.Error{}}`
  carrying the first inner-message rejection (with `:batch_seq`
  pointing at the offending message position).
  """
  @spec push(Socket.t(), Ruleset.t(), keyword()) ::
          :ok | {:error, Error.t() | term()}
  def push(%Socket{} = sock, %Ruleset{} = ruleset, opts \\ []) do
    case Keyword.get(opts, :mode, :replace) do
      :replace ->
        msgs = Encoder.to_batch(ruleset)
        send_batch(sock, msgs, [])

      :reconcile ->
        push_reconcile(sock, ruleset, opts)

      other ->
        {:error, {:unknown_push_mode, other}}
    end
  end

  defp send_batch(sock, msgs, batch_opts) do
    case Nfnl.batch(sock, msgs, :nftables, batch_opts) do
      :ok ->
        :ok

      {:error, {batch_seq, %NetlinkError{} = err}} ->
        {:error,
         Error.from_posix(err.errno, :push,
           subsys: :nftables,
           batch_seq: batch_seq,
           message: err.message
         )}

      {:error, other} ->
        {:error, other}
    end
  end

  # ----- :reconcile -----

  defp push_reconcile(sock, ruleset, opts) do
    case Linx.Netfilter.Diff.validate_for_reconcile(ruleset) do
      :ok ->
        max_retries = Keyword.get(opts, :retries, 3)
        do_reconcile(sock, ruleset, max_retries, max_retries)

      {:error, {:tag_required, _}} = err ->
        err
    end
  end

  defp do_reconcile(sock, ruleset, retries_left, total_retries) do
    with {:ok, current} <- pull(sock),
         {:ok, gen} <- Linx.Netlink.Nfnl.Codec.get_gen(sock) do
      patch = Linx.Netfilter.Diff.diff(current, ruleset)

      if Linx.Netfilter.Patch.empty?(patch) do
        :ok
      else
        msgs = Encoder.from_patch(patch)

        case send_batch(sock, msgs, genid: gen.id) do
          :ok ->
            :ok

          {:error, %Error{errno: :erestart}} when retries_left > 0 ->
            # Concurrent commit between our pull and our push — back
            # off briefly, then re-pull and re-diff against the
            # newer kernel state.
            backoff_ms = (total_retries - retries_left + 1) * 10
            Process.sleep(backoff_ms)
            do_reconcile(sock, ruleset, retries_left - 1, total_retries)

          {:error, %Error{errno: :erestart} = err} ->
            {:error,
             %Error{
               err
               | message: "concurrent modification, retries exhausted",
                 ruleset_gen: gen.id
             }}

          {:error, _} = err ->
            err
        end
      end
    end
  end

  @doc """
  Pulls the kernel's nftables state into a Ruleset value.

  No-arg form dumps the entire netns — every table, every chain,
  every rule the caller can see. Use `pull/2` for a scoped dump
  (one table by `(family, name)`).

  Implementation: three sequential dumps (`GETTABLE`, `GETCHAIN`,
  `GETRULE`), then `Linx.Netfilter.Decoder.from_msgs/3` assembles
  them into the Ruleset. Dumps are not atomic across types — if a
  table is created between the table dump and the rule dump, its
  rules will be silently dropped during assembly. N5's `:reconcile`
  mode adds `NFTA_BATCH_GENID` for atomicity.
  """
  @spec pull(Socket.t()) :: {:ok, Ruleset.t()} | {:error, Error.t() | term()}
  def pull(%Socket{} = sock) do
    with {:ok, tables} <- dump_tables(sock, :unspec),
         {:ok, chains} <- dump_chains(sock, :unspec),
         {:ok, rules} <- dump_rules(sock, :unspec),
         {:ok, sets} <- dump_sets(sock, :unspec),
         {:ok, set_elems} <- dump_set_elements_for(sock, sets) do
      {:ok, Decoder.from_msgs(tables, chains, rules, sets, set_elems)}
    end
  end

  @doc """
  Pulls a single table (and its chains, rules, sets) by
  `{family, name}`.

  Returns `{:ok, %Ruleset{}}` containing just that table, or
  `{:error, %Linx.Netfilter.Error{errno: :enoent}}` if the table
  doesn't exist.
  """
  @spec pull(Socket.t(), {atom(), String.t()}) ::
          {:ok, Ruleset.t()} | {:error, Error.t() | term()}
  def pull(%Socket{} = sock, {family, name}) when is_atom(family) and is_binary(name) do
    with {:ok, [table]} <- get_table(sock, family, name),
         {:ok, chains} <- dump_chains(sock, family),
         {:ok, rules} <- dump_rules(sock, family),
         {:ok, sets} <- dump_sets(sock, family) do
      # Filter chains + rules + sets to just this table.
      chains = Enum.filter(chains, fn {_, c} -> c.table == name end)
      rules = Enum.filter(rules, fn {_, t, _, _} -> t == name end)
      sets = Enum.filter(sets, fn {_, s} -> entity_table(s) == name end)

      with {:ok, set_elems} <- dump_set_elements_for(sock, sets) do
        {:ok, Decoder.from_msgs([table], chains, rules, sets, set_elems)}
      end
    end
  end

  defp entity_table(%Linx.Netfilter.Set{table: t}), do: t
  defp entity_table(%Linx.Netfilter.Map{table: t}), do: t

  # ----- internals -----

  defp dump_tables(sock, family) do
    msg = Encoder.gettable_dump(family)
    talk_dump(sock, msg, &Decoder.table/1, :pull)
  end

  defp dump_chains(sock, family) do
    msg = %Message{
      type: NfnlCodec.nlmsg_type(NfnlCodec.subsys_nftables(), nft_msg_getchain()),
      flags: nlm_f_dump(),
      payload: NfnlCodec.encode_nfgenmsg(family, 0)
    }

    talk_dump(sock, msg, &Decoder.chain/1, :pull)
  end

  defp dump_rules(sock, family) do
    msg = %Message{
      type: NfnlCodec.nlmsg_type(NfnlCodec.subsys_nftables(), nft_msg_getrule()),
      flags: nlm_f_dump(),
      payload: NfnlCodec.encode_nfgenmsg(family, 0)
    }

    talk_dump(sock, msg, &Decoder.rule/1, :pull)
  end

  defp dump_sets(sock, family) do
    msg = %Message{
      type: NfnlCodec.nlmsg_type(NfnlCodec.subsys_nftables(), nft_msg_getset()),
      flags: nlm_f_dump(),
      payload: NfnlCodec.encode_nfgenmsg(family, 0)
    }

    talk_dump(sock, msg, &Decoder.set/1, :pull)
  end

  defp dump_set_elements_for(sock, sets) do
    # GETSETELEM doesn't support dump-all; it requires NFTA_SET_ELEM_LIST_SET.
    # Issue one request per known set.
    sets
    |> Enum.reduce_while({:ok, []}, fn {family, entity}, {:ok, acc} ->
      case dump_set_elements_one(sock, family, entity_table(entity), entity.name) do
        {:ok, elements} -> {:cont, {:ok, [{family, entity_table(entity), entity.name, elements} | acc]}}
        {:error, %Linx.Netfilter.Error{errno: :enoent}} ->
          # Set vanished between the GETSET dump and this call. Skip.
          {:cont, {:ok, acc}}

        {:error, _} = err ->
          {:halt, err}
      end
    end)
    |> case do
      {:ok, rev} -> {:ok, Enum.reverse(rev)}
      err -> err
    end
  end

  defp dump_set_elements_one(sock, family, table_name, set_name) do
    attrs =
      Linx.Netlink.Attr.encode([
        {nfta_set_elem_list_table(), [table_name, 0]},
        {nfta_set_elem_list_set(), [set_name, 0]}
      ])

    msg = %Message{
      type: NfnlCodec.nlmsg_type(NfnlCodec.subsys_nftables(), nft_msg_getsetelem()),
      flags: nlm_f_dump(),
      payload: NfnlCodec.encode_nfgenmsg(family, 0) <> attrs
    }

    case Request.talk(sock, msg.type, msg.flags, msg.payload) do
      {:ok, messages} ->
        # Each message decodes to {family, table, set, [elements]} —
        # we know table/set already, so just collect element lists.
        elements =
          Enum.flat_map(messages, fn m ->
            {_, _, _, elems} = Decoder.set_elements(m.payload)
            elems
          end)

        {:ok, elements}

      {:error, %NetlinkError{} = err} ->
        {:error,
         Error.from_posix(err.errno, :pull,
           subsys: :nftables,
           message: err.message
         )}

      {:error, other} ->
        {:error, other}
    end
  end

  defp get_table(sock, family, name) do
    msg = Encoder.gettable(family, name)

    case Request.talk(sock, msg.type, msg.flags, msg.payload) do
      {:ok, [%Message{payload: body} | _]} ->
        {:ok, [Decoder.table(body)]}

      {:ok, []} ->
        {:error,
         Error.from_posix(:enoent, :pull,
           subsys: :nftables,
           message: "no such table"
         )}

      {:error, %NetlinkError{} = err} ->
        {:error,
         Error.from_posix(err.errno, :pull,
           subsys: :nftables,
           message: err.message
         )}

      {:error, other} ->
        {:error, other}
    end
  end

  defp talk_dump(sock, %Message{} = msg, decode_fun, op) do
    case Request.talk(sock, msg.type, msg.flags, msg.payload) do
      {:ok, messages} ->
        {:ok, Enum.map(messages, fn m -> decode_fun.(m.payload) end)}

      {:error, %NetlinkError{} = err} ->
        {:error,
         Error.from_posix(err.errno, op,
           subsys: :nftables,
           message: err.message
         )}

      {:error, other} ->
        {:error, other}
    end
  end

  @doc """
  Computes the minimum-mutation `%Linx.Netfilter.Patch{}` between
  two Rulesets — the operations that turn `from` into `to`.

  Identity rules:

    * Tables / chains / sets / maps — `name` (within the relevant
      scope: tables within family, the rest within their table).
    * Rules within a chain — `:tag` when set, positional index
      otherwise. Mixed-tag chains fall back to a full rebuild.
    * Set elements — the element value itself.

  Rule attribute changes use `NLM_F_REPLACE` over the
  kernel-assigned handle carried by `from`'s rule (so you must
  diff against a Ruleset *pulled* from the kernel, not against a
  freshly-built one — otherwise handles are nil).

  Patches are topologically sorted: deletes before creates of
  their dependencies (see `Linx.Netfilter.Patch`).

  See `Linx.Netfilter.Diff` for the underlying implementation.
  """
  @spec diff(Ruleset.t(), Ruleset.t()) :: Linx.Netfilter.Patch.t()
  def diff(%Ruleset{} = from, %Ruleset{} = to), do: Linx.Netfilter.Diff.diff(from, to)

  @doc """
  Alias for `diff/2` — return the patch without sending it. The
  name reads better at call sites where the intent is "show me
  what would change".
  """
  @spec dry_run(Ruleset.t(), Ruleset.t()) :: Linx.Netfilter.Patch.t()
  def dry_run(%Ruleset{} = from, %Ruleset{} = to), do: diff(from, to)

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
