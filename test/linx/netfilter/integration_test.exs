defmodule Linx.Netfilter.IntegrationTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  # End-to-end tests against the real kernel. Need CAP_NET_ADMIN
  # (run via ./sudotest.sh).
  #
  # All tests use uniquely-named tables in :inet family to avoid
  # collision with whatever ruleset the host already has loaded.
  # Tables are created with the owner flag set by default so they
  # clean themselves up on socket close; on test failure they may
  # need manual cleanup with `nft delete table inet linx_n2_*`.

  alias Linx.Netfilter
  alias Linx.Netfilter.{Ruleset, Table}
  alias Linx.Netlink.{Nfnl, Socket}

  defp unique_name(prefix) do
    suffix = :erlang.unique_integer([:positive, :monotonic])
    "linx_n2_#{prefix}_#{suffix}"
  end

  describe "create_table/3 — minimal happy path" do
    test "creates an :inet table and returns a single-table ruleset" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      name = unique_name("ct_basic")
      assert {:ok, %Ruleset{} = rs} = Netfilter.create_table(sock, name)

      # The seeded ruleset has exactly the one table.
      assert [{:inet, ^name, %Table{} = t}] = Ruleset.tables(rs)
      assert t.family == :inet
      assert t.name == name
      assert :owner in t.flags
    end

    test "supports a different family" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      name = unique_name("ct_ip6")
      assert {:ok, %Ruleset{} = rs} = Netfilter.create_table(sock, name, family: :ip6)
      assert [{:ip6, ^name, _}] = Ruleset.tables(rs)
    end

    test "persist: true omits the owner flag" do
      {:ok, sock} = Nfnl.open()

      name = unique_name("ct_persist")
      assert {:ok, %Ruleset{tables: tables}} =
               Netfilter.create_table(sock, name, persist: true)

      [{_, _, t}] = Ruleset.tables(%Ruleset{tables: tables})
      refute :owner in t.flags

      # Clean up explicitly — without :owner the table survives socket close.
      Socket.close(sock)

      # Re-open a socket and delete the table via shell-out (the
      # `nft` CLI is the lowest-friction way to clean up until
      # N2's later passes ship DELTABLE through Linx itself).
      _ = System.cmd("nft", ["delete", "table", "ip", name], stderr_to_stdout: true)
      _ = System.cmd("nft", ["delete", "table", "inet", name], stderr_to_stdout: true)
    end
  end

  describe "create_table/3 — owner-flag cleanup" do
    test "table disappears when the owning socket closes" do
      {:ok, sock} = Nfnl.open()
      name = unique_name("ct_cleanup")

      {:ok, _rs} = Netfilter.create_table(sock, name)

      # Verify the table exists right now (via shell-out to `nft`).
      {nft_out, 0} = System.cmd("nft", ["list", "tables"], stderr_to_stdout: true)
      assert nft_out =~ "inet #{name}"

      # Close the owning socket — kernel atomically destroys the
      # owned table.
      Socket.close(sock)

      # And now it's gone.
      {nft_out2, 0} = System.cmd("nft", ["list", "tables"], stderr_to_stdout: true)
      refute nft_out2 =~ "inet #{name}"
    end
  end

  describe "create_table/3 — error paths" do
    test "duplicate create with NLM_F_CREATE updates (no error)" do
      # The default NLM_F_CREATE (without NLM_F_EXCL) is
      # "create-or-update" — the same name re-create with the same
      # flags is a no-op. This documents the current behaviour.
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      name = unique_name("ct_dup")
      {:ok, _} = Netfilter.create_table(sock, name)

      # Second create — succeeds, same table updated.
      assert {:ok, _} = Netfilter.create_table(sock, name)
    end
  end

  describe "chain encoder + batch" do
    # Lower-level test: push table + chain via the codec directly,
    # before the full push/2 API exists. Validates the chain wire
    # format against the real kernel.

    alias Linx.Netfilter.{Chain, Encoder}
    alias Linx.Netlink.Nfnl

    test "base chain with filter type + input hook + accept policy round-trips" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("ch_base")
      chain_name = "input"

      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])

      {:ok, chain} =
        Chain.new(chain_name,
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept,
          table: table_name
        )

      table_msg = Encoder.table(table)
      chain_msg = Encoder.chain(chain, :inet)

      assert :ok = Nfnl.batch(sock, [table_msg, chain_msg])

      # Verify via shell-out — the chain is there with the expected
      # type/hook/priority/policy.
      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/chain #{chain_name}/
      assert nft_out =~ ~r/type filter hook input priority.*policy accept/
    end

    test "regular chain (no hook) round-trips" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("ch_reg")
      chain_name = "input_extras"

      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, chain} = Chain.new(chain_name, table: table_name)

      table_msg = Encoder.table(table)
      chain_msg = Encoder.chain(chain, :inet)

      assert :ok = Nfnl.batch(sock, [table_msg, chain_msg])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/chain #{chain_name}/
      # Regular chain — no `type ... hook ...` line.
      refute nft_out =~ ~r/chain #{chain_name} \{[^}]*type [a-z]+ hook/s
    end

    test "ingress chain with device round-trips" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("ch_ingress")

      {:ok, table} = Table.new(:netdev, table_name, flags: [:owner])

      {:ok, chain} =
        Chain.new("ingress_drop",
          type: :filter,
          hook: :ingress,
          priority: 0,
          device: "lo",
          table: table_name
        )

      table_msg = Encoder.table(table)
      chain_msg = Encoder.chain(chain, :netdev)

      assert :ok = Nfnl.batch(sock, [table_msg, chain_msg])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "netdev", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/device.*lo/
    end
  end

  describe "rule encoder + batch" do
    alias Linx.Netfilter.{Chain, Encoder, Expr, Rule, Verdict}
    alias Linx.Netlink.Nfnl

    test "single-rule table: 'tcp dport 22 accept'" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("rule_tcp22")

      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, chain} =
        Chain.new("input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop,
          table: table_name
        )

      # tcp dport 22 accept
      {:ok, rule} =
        Rule.build([
          Expr.payload(:tcp_dport),
          Expr.cmp(:eq, <<22::big-16>>),
          Verdict.accept()
        ])

      msgs = [
        Encoder.table(table),
        Encoder.chain(chain, :inet),
        Encoder.rule(rule, :inet, table_name, "input")
      ]

      assert :ok = Nfnl.batch(sock, msgs)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      # nft renders this as `tcp dport 22 accept` if the L4 proto
      # is established by context, else the generic-transport-header
      # form `th dport 22 accept`. Both are correct kernel-level
      # encodings of "match destination port 22 in the transport
      # header"; nft pretty-prints differently based on whether
      # the L4 proto is pinned.
      assert nft_out =~ ~r/(tcp|th) dport 22 accept/
    end

    test "counter expression round-trips" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("rule_counter")
      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, chain} =
        Chain.new("input",
          type: :filter,
          hook: :input,
          priority: 0,
          table: table_name
        )

      {:ok, rule} = Rule.build([Expr.counter(), Verdict.accept()])

      assert :ok =
               Nfnl.batch(sock, [
                 Encoder.table(table),
                 Encoder.chain(chain, :inet),
                 Encoder.rule(rule, :inet, table_name, "input")
               ])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/counter/
      assert nft_out =~ ~r/accept/
    end

    test "ct state matching: ct state established,related accept" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("rule_ct")
      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, chain} =
        Chain.new("input",
          type: :filter,
          hook: :input,
          priority: 0,
          table: table_name
        )

      state_mask = Linx.Netfilter.Wire.ct_state_bits([:established, :related])

      {:ok, rule} =
        Rule.build([
          Expr.ct(:state),
          # Mask the state to just the bits we care about
          Expr.bitwise(<<state_mask::big-32>>, <<0::big-32>>),
          Expr.cmp(:neq, <<0::big-32>>),
          Verdict.accept()
        ])

      assert :ok =
               Nfnl.batch(sock, [
                 Encoder.table(table),
                 Encoder.chain(chain, :inet),
                 Encoder.rule(rule, :inet, table_name, "input")
               ])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/ct state/
      assert nft_out =~ ~r/accept/
    end

    test "reject expression" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("rule_reject")
      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, chain} =
        Chain.new("input",
          type: :filter,
          hook: :input,
          priority: 0,
          table: table_name
        )

      # Plain reject — kernel-default ICMP unreachable
      {:ok, rule} = Rule.build([Expr.reject(:icmpx_unreach)])

      assert :ok =
               Nfnl.batch(sock, [
                 Encoder.table(table),
                 Encoder.chain(chain, :inet),
                 Encoder.rule(rule, :inet, table_name, "input")
               ])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/reject/
    end

    test "push/pull/2 round-trip — single table with one chain + one rule" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Ruleset, Rule}

      table_name = unique_name("roundtrip")

      pushed =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<22::big-16>>),
            Linx.Netfilter.Verdict.accept()
          ])
        )

      assert :ok = Netfilter.push(sock, pushed)

      # Pull just this table back
      assert {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      [{:inet, ^table_name, t}] = Ruleset.tables(pulled)
      assert t.family == :inet
      assert t.name == table_name
      assert :owner in t.flags

      assert map_size(t.chains) == 1
      input_chain = t.chains["input"]
      assert input_chain.type == :filter
      assert input_chain.hook == :input
      assert input_chain.priority == 0
      assert input_chain.policy == :drop

      assert [rule] = input_chain.rules
      assert is_integer(rule.handle) and rule.handle > 0
      assert length(rule.expressions) == 3

      # Round-trip the expressions: payload, cmp, immediate-verdict.
      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 2, len: 2, dreg: 1}},
               %Expr{name: :cmp, data: %{sreg: 1, op: :eq, value: <<22::big-16>>}},
               %Expr{name: :immediate, data: %Linx.Netfilter.Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "pull/2 on a nonexistent table returns :enoent" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      assert {:error, %Linx.Netfilter.Error{errno: :enoent, operation: :pull}} =
               Netfilter.pull(sock, {:inet, "linx_ghost_table_xyzzy"})
    end

    test "pull/1 lists all tables in the netns" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.Ruleset

      # Create two tables; both should appear in the dump.
      n1 = unique_name("dump_a")
      n2 = unique_name("dump_b")
      {:ok, _} = Netfilter.create_table(sock, n1)
      {:ok, _} = Netfilter.create_table(sock, n2)

      assert {:ok, %Ruleset{} = rs} = Netfilter.pull(sock)
      names = rs |> Ruleset.tables() |> Enum.map(fn {_, n, _} -> n end)

      assert n1 in names
      assert n2 in names
    end

    test "DNAT port-forward: tcp dport 8080 → 10.0.0.5:80" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Chain, Encoder, Expr, Rule, Ruleset}

      table_name = unique_name("nat_dnat")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "prerouting",
          type: :nat,
          hook: :prerouting,
          priority: :dstnat
        )
        |> Ruleset.add_rule!(table_name, "prerouting",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<8080::big-16>>),
            Expr.dnat_to({10, 0, 0, 5}, 80)
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/type nat hook prerouting priority dstnat/
      assert nft_out =~ ~r/dnat .* 10\.0\.0\.5(:80)?/
    end

    test "masquerade postrouting" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Chain, Encoder, Expr, Rule, Ruleset}

      table_name = unique_name("nat_masq")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "postrouting",
          type: :nat,
          hook: :postrouting,
          priority: :srcnat
        )
        |> Ruleset.add_rule!(table_name, "postrouting",
          Rule.build!([Expr.masquerade()])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/type nat hook postrouting priority srcnat/
      assert nft_out =~ ~r/masquerade/
    end

    test "masquerade with :random flag" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset}

      table_name = unique_name("nat_masq_random")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "postrouting",
          type: :nat,
          hook: :postrouting,
          priority: :srcnat
        )
        |> Ruleset.add_rule!(table_name, "postrouting",
          Rule.build!([Expr.masquerade(flags: [:random])])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/masquerade .*random/
    end

    test "redirect to local port" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset}

      table_name = unique_name("nat_redir")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "prerouting",
          type: :nat,
          hook: :prerouting,
          priority: :dstnat
        )
        |> Ruleset.add_rule!(table_name, "prerouting",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<80::big-16>>),
            Expr.redirect(port: 8080)
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/redirect/
      assert nft_out =~ ~r/8080/
    end

    test "hairpin NAT: DNAT in prerouting + SNAT in postrouting" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset}

      table_name = unique_name("nat_hairpin")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "prerouting",
          type: :nat,
          hook: :prerouting,
          priority: :dstnat
        )
        |> Ruleset.add_chain!(table_name, "postrouting",
          type: :nat,
          hook: :postrouting,
          priority: :srcnat
        )
        |> Ruleset.add_rule!(table_name, "prerouting",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<8080::big-16>>),
            Expr.dnat_to({10, 0, 0, 5}, 80)
          ])
        )
        |> Ruleset.add_rule!(table_name, "postrouting",
          Rule.build!([
            Expr.payload(:ip_daddr),
            Expr.cmp(:eq, <<10, 0, 0, 5>>),
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<80::big-16>>),
            Expr.snat_to({192, 168, 1, 1})
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      # Both chains and both NAT rules present.
      assert nft_out =~ ~r/chain prerouting/
      assert nft_out =~ ~r/chain postrouting/
      assert nft_out =~ ~r/dnat .* 10\.0\.0\.5/
      assert nft_out =~ ~r/snat .* 192\.168\.1\.1/
    end

    test "NAT round-trip via pull/2" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset}

      table_name = unique_name("nat_roundtrip")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "prerouting",
          type: :nat,
          hook: :prerouting,
          priority: :dstnat
        )
        |> Ruleset.add_rule!(table_name, "prerouting",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<8080::big-16>>),
            Expr.dnat_to({10, 0, 0, 5}, 80)
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)
      assert {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      [{:inet, ^table_name, t}] = Ruleset.tables(pulled)
      assert t.chains["prerouting"].type == :nat
      assert t.chains["prerouting"].hook == :prerouting

      [rule] = t.chains["prerouting"].rules
      # Expressions: payload + cmp + 2 immediates (addr, port) + nat
      assert length(rule.expressions) == 5
      assert Enum.any?(rule.expressions, &match?(%Expr{name: :nat, data: %{type: :dnat}}, &1))
    end

    test "named ipv4_addr set with elements — push, pull, verify" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Set, Verdict}

      table_name = unique_name("set_block")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_set!(
          table_name,
          Set.new!("blocklist",
            key_type: :ipv4_addr,
            elements: [{10, 0, 0, 1}, {10, 0, 0, 2}, {192, 168, 1, 100}]
          )
        )
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:ip_saddr),
            Expr.lookup("blocklist"),
            Verdict.drop()
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      # Verify via shell-out
      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/set blocklist/
      assert nft_out =~ ~r/type ipv4_addr/
      assert nft_out =~ ~r/10\.0\.0\.1/
      assert nft_out =~ ~r/192\.168\.1\.100/

      # Pull back and round-trip elements
      assert {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})
      [{:inet, ^table_name, t}] = Ruleset.tables(pulled)

      blocklist = t.sets["blocklist"]
      assert blocklist.key_type == :ipv4_addr
      # Element order may not match push order; just check set
      # membership.
      element_set = MapSet.new(blocklist.elements)
      assert MapSet.member?(element_set, {10, 0, 0, 1})
      assert MapSet.member?(element_set, {10, 0, 0, 2})
      assert MapSet.member?(element_set, {192, 168, 1, 100})
    end

    test "ipv4_addr → ipv4_addr map (DNAT targets)" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Map, Ruleset}

      table_name = unique_name("map_dnat")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_map!(
          table_name,
          Map.new!("dnat_pool",
            key_type: :inet_service,
            data_type: :ipv4_addr,
            elements: [{80, {10, 0, 0, 5}}, {443, {10, 0, 0, 6}}]
          )
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/map dnat_pool/
      assert nft_out =~ ~r/type inet_service.*ipv4_addr/
      assert nft_out =~ ~r/80 : 10\.0\.0\.5/
      assert nft_out =~ ~r/443 : 10\.0\.0\.6/

      # Round-trip
      assert {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})
      [{:inet, ^table_name, t}] = Ruleset.tables(pulled)
      m = t.maps["dnat_pool"]
      assert m.key_type == :inet_service
      assert m.data_type == :ipv4_addr

      assert {80, {10, 0, 0, 5}} in m.elements
      assert {443, {10, 0, 0, 6}} in m.elements
    end

    test "vmap dispatch — inet_service → verdict (jump to per-service chains)" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict, Vmap}

      table_name = unique_name("vmap_dispatch")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "ssh_in")
        |> Ruleset.add_chain!(table_name, "http_in")
        |> Ruleset.add_map!(
          table_name,
          Vmap.new!("services",
            key_type: :inet_service,
            elements: [
              {22, {:jump, "ssh_in"}},
              {80, {:jump, "http_in"}}
            ]
          )
        )
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.lookup("services", dreg: 0)
          ])
        )
        |> Ruleset.add_rule!(table_name, "ssh_in", [Verdict.accept()])
        |> Ruleset.add_rule!(table_name, "http_in", [Verdict.accept()])

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/map services/
      assert nft_out =~ ~r/type inet_service : verdict/
      assert nft_out =~ ~r/22 : jump ssh_in/
      assert nft_out =~ ~r/80 : jump http_in/
    end

    test "anonymous set in a rule: tcp dport { 22, 80, 443 } accept" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

      table_name = unique_name("anon_set")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.set_literal([22, 80, 443], :inet_service),
            Verdict.accept()
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      # nft renders the anonymous set inline: `{ 22, 80, 443 }`
      assert nft_out =~ ~r/\{ ?22,/
      assert nft_out =~ ~r/80,/
      assert nft_out =~ ~r/443 ?\}/
      assert nft_out =~ ~r/accept/
    end

    test "anonymous set with ipv4 addresses" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

      table_name = unique_name("anon_set_ip")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:ip_saddr),
            Expr.set_literal([{10, 0, 0, 1}, {10, 0, 0, 2}, {192, 168, 1, 100}], :ipv4_addr),
            Verdict.drop()
          ])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      # Without `:key_typeof` userdata, nft renders the set with
      # generic byte-offset / hex notation rather than `ip saddr
      # { 10.0.0.1, ... }`. The set still matches packets correctly;
      # only the display form is generic. 10.0.0.1 = 0x0a000001.
      assert nft_out =~ ~r/(10\.0\.0\.1|0xa000001)/
      assert nft_out =~ ~r/(192\.168\.1\.100|0xc0a80164)/
      assert nft_out =~ ~r/drop/
    end

    test "set with :interval flag for CIDR ranges" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Ruleset, Set}

      table_name = unique_name("set_interval")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_set!(
          table_name,
          Set.new!("blocknets", key_type: :ipv4_addr, flags: [:interval])
        )

      assert :ok = Netfilter.push(sock, ruleset)

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/set blocknets/
      assert nft_out =~ ~r/flags interval/
    end

    test "reconcile: empty patch when ruleset matches kernel state" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Rule, Ruleset}

      table_name = unique_name("reconcile_idemp")

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([Linx.Netfilter.Verdict.accept()], tag: :allow_all)
        )

      assert :ok = Netfilter.push(sock, ruleset)
      assert {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      # Diff against itself (well, against what came back from pull) → empty patch
      assert :ok = Netfilter.push(sock, pulled, mode: :reconcile)
    end

    test "reconcile: changes a single rule via REPLACE" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

      table_name = unique_name("reconcile_replace")

      original =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<22::big-16>>),
            Verdict.accept()
          ], tag: :allow_ssh)
        )

      assert :ok = Netfilter.push(sock, original)

      # Pull current to get handles
      {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      # Build modified ruleset — same shape, but different port
      desired =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<2222::big-16>>),
            Verdict.accept()
          ], tag: :allow_ssh)
        )

      # Verify the patch contains exactly one :replace_rule op
      patch = Netfilter.diff(pulled, desired)
      assert Enum.any?(patch.ops, &match?({:replace_rule, _, _, _, _, _}, &1))
      refute Enum.any?(patch.ops, &match?({:create_rule, _, _, _, _, _}, &1))
      refute Enum.any?(patch.ops, &match?({:delete_rule, _, _, _, _}, &1))

      # Push it
      assert :ok = Netfilter.push(sock, desired, mode: :reconcile)

      # Verify the kernel sees the new port
      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/(tcp|th) dport 2222/
      refute nft_out =~ ~r/(tcp|th) dport 22[^0-9]/
    end

    test "reconcile: tag enforcement rejects untagged rules in multi-rule chains" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Ruleset, Verdict}

      table_name = unique_name("reconcile_untagged")

      bad_ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        # Two rules, first tagged, second untagged → reconcile rejects
        |> Ruleset.add_rule!(table_name, "input", [Verdict.accept()], tag: :allow)
        |> Ruleset.add_rule!(table_name, "input", [Verdict.drop()])

      assert {:error, {:tag_required, {:inet, ^table_name, "input"}}} =
               Netfilter.push(sock, bad_ruleset, mode: :reconcile)
    end

    test "reconcile: tagged rule reordering is a no-op" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

      table_name = unique_name("reconcile_reorder")

      original =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<22::big-16>>),
            Verdict.accept()
          ], tag: :allow_ssh)
        )
        |> Ruleset.add_rule!(table_name, "input",
          Rule.build!([
            Expr.payload(:tcp_dport),
            Expr.cmp(:eq, <<80::big-16>>),
            Verdict.accept()
          ], tag: :allow_http)
        )

      assert :ok = Netfilter.push(sock, original)
      {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      # Same rules, reversed (build a new ruleset programmatically)
      [first_rule, second_rule] = pulled.tables[{:inet, table_name}].chains["input"].rules

      reordered =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, table_name, flags: [:owner])
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!(table_name, "input", second_rule)
        |> Ruleset.add_rule!(table_name, "input", first_rule)

      # Tag-identity → reorder is invisible to diff → empty patch
      patch = Netfilter.diff(pulled, reordered)
      assert Linx.Netfilter.Patch.empty?(patch)

      assert :ok = Netfilter.push(sock, reordered, mode: :reconcile)
    end

    test "dry_run/2 returns the patch without sending" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      alias Linx.Netfilter.{Ruleset, Verdict}

      table_name = unique_name("dry_run")

      {:ok, _} = Netfilter.create_table(sock, table_name)

      {:ok, pulled} = Netfilter.pull(sock, {:inet, table_name})

      desired =
        pulled
        |> Ruleset.add_chain!(table_name, "input",
          type: :filter,
          hook: :input,
          priority: 0
        )

      patch = Netfilter.dry_run(pulled, desired)
      assert Enum.any?(patch.ops, &match?({:create_chain, _, _, _}, &1))

      # Kernel state unchanged
      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      refute nft_out =~ ~r/chain input/
    end

    test "jump verdict to a regular chain" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      table_name = unique_name("rule_jump")
      {:ok, table} = Table.new(:inet, table_name, flags: [:owner])
      {:ok, base} =
        Chain.new("input",
          type: :filter,
          hook: :input,
          priority: 0,
          table: table_name
        )

      {:ok, target} = Chain.new("ssh_in", table: table_name)

      {:ok, rule_in} =
        Rule.build([
          Expr.payload(:tcp_dport),
          Expr.cmp(:eq, <<22::big-16>>),
          Verdict.jump("ssh_in")
        ])

      {:ok, rule_ssh} = Rule.build([Verdict.accept()])

      assert :ok =
               Nfnl.batch(sock, [
                 Encoder.table(table),
                 Encoder.chain(base, :inet),
                 Encoder.chain(target, :inet),
                 Encoder.rule(rule_in, :inet, table_name, "input"),
                 Encoder.rule(rule_ssh, :inet, table_name, "ssh_in")
               ])

      {nft_out, 0} =
        System.cmd("nft", ["list", "table", "inet", table_name], stderr_to_stdout: true)

      assert nft_out =~ ~r/chain ssh_in/
      assert nft_out =~ ~r/jump ssh_in/
    end
  end
end
