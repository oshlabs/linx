defmodule Linx.Netfilter.KernelAcceptanceTest do
  @moduledoc """
  Kernel acceptance for the encoder's richer paths: pushes one
  DSL-built ruleset exercising each of them through a real netlink
  socket and reads it back. Covers NEWOBJ (counter/quota/limit) +
  objref, inline quota and limit statements, nft_dynset with a
  nested per-element limit, concatenated set keys (declaration,
  elements, and rule-side reg32 loads), pipapo interval+concat
  sets, named and anonymous verdict maps (including a
  ct_state-keyed one), and bitwise flag/mask matching.

  Needs CAP_NET_ADMIN — run via `./sudotest.sh` or the privileged
  CI job.
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  alias Linx.Netfilter.{Chain, Expr, Flowtable, Object, Ruleset, Set, Verdict, Vmap, Wire}
  alias Linx.Netlink.{Nfnl, Socket}

  @table "nft_kernel_acceptance"
  @ref {:inet, @table}

  # meta l4proto tcp / meta nfproto ipv4 guards, as nft's own
  # dependency generation emits them (l4proto 6 = TCP, nfproto 2 =
  # NFPROTO_IPV4).
  defp l4proto_tcp, do: [Expr.meta(:l4proto), Expr.cmp(:eq, <<6>>)]
  defp nfproto_ipv4, do: [Expr.meta(:nfproto), Expr.cmp(:eq, <<2>>)]
  defp tcp_dport(port), do: [Expr.payload(:tcp_dport), Expr.cmp(:eq, <<port::big-16>>)]

  defp ruleset do
    Ruleset.new()
    |> Ruleset.add_table!(:inet, @table)
    |> Ruleset.add_object!(@ref, Object.new!(:counter, "hits", %{packets: 0, bytes: 0}))
    |> Ruleset.add_object!(
      @ref,
      Object.new!(:quota, "monthly", %{bytes: 500 * 1024 * 1024, over: true, used: 0})
    )
    |> Ruleset.add_object!(
      @ref,
      Object.new!(:limit, "slow", %{type: :packets, rate: 10, per: 1, burst: 9, over: false})
    )
    |> Ruleset.add_flowtable!(
      @ref,
      Flowtable.new!("ft", hook: :ingress, priority: 0, devices: ["lo"])
    )
    |> Ruleset.add_set!(
      @ref,
      Set.new!("svc",
        key_type: {:concat, [:ipv4_addr, :inet_service]},
        elements: [["10.96.0.1", 443], ["10.96.0.10", 53]]
      )
    )
    |> Ruleset.add_set!(
      @ref,
      Set.new!("svc_ranges",
        key_type: {:concat, [:ipv4_addr, :inet_service]},
        flags: [:interval],
        elements: [["10.0.0.0/24", {:range, 80, 443}], ["192.168.1.5", {:range, 8000, 9000}]]
      )
    )
    |> Ruleset.add_set!(
      @ref,
      Set.new!("ratelimit",
        key_type: :ipv4_addr,
        flags: [:dynamic, :timeout],
        timeout: :timer.minutes(10)
      )
    )
    |> Ruleset.add_map!(
      @ref,
      Vmap.new!("dispatch",
        key_type: :inet_service,
        elements: [{22, Verdict.accept()}, {23, Verdict.drop()}]
      )
    )
    |> Ruleset.put_chain!(@ref, chain())
  end

  defp chain do
    rules = [
      # ct state vmap { established : accept, invalid : drop }
      [
        Expr.ct(:state),
        Expr.vmap_literal(
          [
            {Wire.ct_state_bits(:established), Verdict.accept()},
            {Wire.ct_state_bits(:invalid), Verdict.drop()}
          ],
          :ct_state
        )
      ],
      # tcp dport vmap @dispatch
      l4proto_tcp() ++ [Expr.payload(:tcp_dport), Expr.lookup("dispatch", dreg: 0)],
      # ip daddr . tcp dport @svc counter accept — concat selector:
      # consecutive reg32 loads from NFT_REG32_00 (8), lookup reads reg 8.
      nfproto_ipv4() ++
        l4proto_tcp() ++
        [
          Expr.payload(:ip_daddr, dreg: 8),
          Expr.payload(:tcp_dport, dreg: 9),
          Expr.lookup("svc", sreg: 8, dreg: nil),
          Expr.counter(),
          Expr.immediate(:accept)
        ],
      # ip daddr . tcp dport @svc_ranges accept (pipapo interval+concat)
      nfproto_ipv4() ++
        l4proto_tcp() ++
        [
          Expr.payload(:ip_daddr, dreg: 8),
          Expr.payload(:tcp_dport, dreg: 9),
          Expr.lookup("svc_ranges", sreg: 8, dreg: nil),
          Expr.immediate(:accept)
        ],
      # tcp dport 22 ct state new add @ratelimit { ip saddr limit rate over 3/minute } drop
      l4proto_tcp() ++
        tcp_dport(22) ++
        [
          Expr.ct(:state),
          Expr.bitwise(<<Wire.ct_state_bits(:new)::big-32>>, <<0::32>>),
          Expr.cmp(:neq, <<0::32>>),
          Expr.meta(:nfproto),
          Expr.cmp(:eq, <<2>>),
          Expr.payload(:ip_saddr),
          Expr.dynset("ratelimit",
            op: :add,
            exprs: [Expr.limit(rate: 3, per: 60, burst: 5, over: true)]
          ),
          Expr.immediate(:drop)
        ],
      # tcp dport 22 counter name "hits" accept
      l4proto_tcp() ++
        tcp_dport(22) ++ [Expr.objref("hits", :counter), Expr.immediate(:accept)],
      # tcp dport 80 quota name "monthly" drop
      l4proto_tcp() ++
        tcp_dport(80) ++ [Expr.objref("monthly", :quota), Expr.immediate(:drop)],
      # tcp dport 443 limit name "slow" accept
      l4proto_tcp() ++
        tcp_dport(443) ++ [Expr.objref("slow", :limit), Expr.immediate(:accept)],
      # quota over 100 mbytes accept (inline nft_quota)
      [Expr.quota(bytes: 100 * 1024 * 1024, over: true), Expr.immediate(:accept)],
      # limit rate 10/second accept (inline nft_limit)
      [Expr.limit(rate: 10), Expr.immediate(:accept)],
      # tcp flags syn tcp dport 8080 accept — implicit bit test:
      # (flags & SYN) != 0
      l4proto_tcp() ++
        [
          Expr.payload(:tcp_flags),
          Expr.bitwise(<<0x02>>, <<0>>),
          Expr.cmp(:neq, <<0>>),
          Expr.payload(:tcp_dport),
          Expr.cmp(:eq, <<8080::big-16>>),
          Expr.immediate(:accept)
        ],
      # tcp flags & (fin|syn|rst|ack) == syn accept — masked compare
      l4proto_tcp() ++
        [
          Expr.payload(:tcp_flags),
          Expr.bitwise(<<0x17>>, <<0>>),
          Expr.cmp(:eq, <<0x02>>),
          Expr.immediate(:accept)
        ],
      # ct mark & 0xff == 0x4 accept — ct mark is host byte order
      [
        Expr.ct(:mark),
        Expr.bitwise(<<0xFF::native-32>>, <<0::32>>),
        Expr.cmp(:eq, <<0x4::native-32>>),
        Expr.immediate(:accept)
      ]
    ]

    chain =
      Chain.new!("input",
        table: @table,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      )

    Enum.reduce(rules, chain, fn exprs, c ->
      {:ok, c2} = Chain.add_rule(c, Linx.Netfilter.Rule.build!(exprs))
      c2
    end)
  end

  test "kernel accepts every DSL-built encoding and the rules read back" do
    {:ok, sock} = Nfnl.open()
    on_exit(fn -> Socket.close(sock) end)

    assert :ok = Linx.Netfilter.push(sock, ruleset())

    {:ok, pulled} = Linx.Netfilter.pull(sock)
    table = pulled.tables[{:inet, @table}]
    assert table, "pushed table not found on pull"
    assert length(table.chains["input"].rules) == 13

    # The pipapo set survived with its interval+concat flags — and,
    # since the KEY_END/concat-id decode landed, its declared key type
    # and authored elements too.
    ranges = table.sets["svc_ranges"]
    assert :interval in ranges.flags
    assert :concat in ranges.flags
    assert ranges.key_type == {:concat, [:ipv4_addr, :inet_service]}

    # Named objects and the flowtable survive pull (GETOBJ /
    # GETFLOWTABLE dumps).
    assert %Object{kind: :counter} = table.objects[{:counter, "hits"}]
    assert %Object{kind: :quota, data: %{over: true}} = table.objects[{:quota, "monthly"}]
    assert %Object{kind: :limit} = table.objects[{:limit, "slow"}]

    ft = table.flowtables["ft"]
    assert %Flowtable{hook: :ingress, devices: ["lo"]} = ft

    # Cleanup: replace with just the (empty) table; the owner flag
    # reaps it when the socket closes.
    empty = Ruleset.new() |> Ruleset.add_table!(:inet, @table)
    assert :ok = Linx.Netfilter.push(sock, empty)
  end
end
