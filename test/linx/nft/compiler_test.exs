defmodule Linx.NFT.CompilerTest do
  use ExUnit.Case, async: true

  alias Linx.NFT.{Compiler, Parser, Tokenizer}
  alias Linx.Netfilter.{Chain, Expr, Rule, Ruleset, Table, Verdict}

  defp compile!(source) do
    {:ok, tokens} = Tokenizer.tokenize(source)
    {:ok, ast} = Parser.parse(tokens, source: source)
    {:ok, rs} = Compiler.compile(ast, source: source)
    rs
  end

  defp compile_err(source) do
    {:ok, tokens} = Tokenizer.tokenize(source)
    {:ok, ast} = Parser.parse(tokens, source: source)
    {:error, err} = Compiler.compile(ast, source: source)
    err
  end

  defp fetch_table!(%Ruleset{} = rs, family, name) do
    {:ok, t} = Ruleset.fetch_table(rs, {family, name})
    t
  end

  defp fetch_chain!(%Table{} = t, name) do
    {:ok, c} = Table.fetch_chain(t, name)
    c
  end

  describe "flush ruleset" do
    test "top-level flush ruleset is a compile-time noop" do
      rs =
        compile!("""
        flush ruleset

        table inet t { chain c { accept } }
        """)

      assert %Ruleset{} = rs
      assert {:ok, _table} = Ruleset.fetch_table(rs, {:inet, "t"})
    end
  end

  describe "empty / minimal" do
    test "empty source compiles to an empty ruleset" do
      assert compile!("") == Ruleset.new()
    end

    test "empty table" do
      rs = compile!("table inet myapp { }")
      assert %Table{family: :inet, name: "myapp"} = fetch_table!(rs, :inet, "myapp")
    end
  end

  describe "chains and base headers" do
    test "minimal base chain" do
      rs =
        compile!("""
        table inet t {
          chain input {
            type filter hook input priority 0
          }
        }
        """)

      chain = rs |> fetch_table!(:inet, "t") |> fetch_chain!("input")

      assert %Chain{
               type: :filter,
               hook: :input,
               priority: 0
             } = chain
    end

    test "policy directive" do
      rs =
        compile!("""
        table inet t {
          chain input {
            type filter hook input priority 0
            policy drop
          }
        }
        """)

      chain = rs |> fetch_table!(:inet, "t") |> fetch_chain!("input")
      assert chain.policy == :drop
    end

    test "named priority alias `filter` resolves to 0" do
      rs =
        compile!("""
        table inet t {
          chain input { type filter hook input priority filter }
        }
        """)

      chain = rs |> fetch_table!(:inet, "t") |> fetch_chain!("input")
      assert chain.priority == 0
    end

    test "named priority alias with offset" do
      rs =
        compile!("""
        table inet t {
          chain input { type filter hook input priority filter - 10 }
        }
        """)

      chain = rs |> fetch_table!(:inet, "t") |> fetch_chain!("input")
      assert chain.priority == -10
    end

    test "named priority alias with + offset (m8)" do
      # `+` needed its own tokenizer rule — the parser accepted the shape
      # but every `+` used to die in the tokenizer as an unexpected char.
      rs =
        compile!("""
        table inet t {
          chain input { type filter hook input priority filter + 10 }
        }
        """)

      chain = rs |> fetch_table!(:inet, "t") |> fetch_chain!("input")
      assert chain.priority == 10
    end

    test "unknown priority alias is an error" do
      err =
        compile_err("""
        table inet t {
          chain input { type filter hook input priority wat }
        }
        """)

      assert err.message =~ "unknown priority alias `wat`"
    end
  end

  describe "rules — verdicts" do
    test "bare accept" do
      rs =
        compile!("""
        table inet t {
          chain c { accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules
      assert [%Expr{name: :immediate, data: %Verdict{kind: :accept}}] = rule.expressions
    end

    test "jump to chain" do
      rs =
        compile!("""
        table inet t {
          chain c { jump other }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :immediate, data: %Verdict{kind: :jump, target: "other"}}
             ] = rule.expressions
    end
  end

  describe "rules — payload matches" do
    test "tcp dport 22 accept" do
      rs =
        compile!("""
        table inet t {
          chain c { tcp dport 22 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 2, len: 2}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<22::big-16>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "ip saddr 10.0.0.5 drop" do
      rs =
        compile!("""
        table inet t {
          chain c { ip saddr 10.0.0.5 drop }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :network, offset: 12, len: 4}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<10, 0, 0, 5>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :drop}}
             ] = rule.expressions
    end

    test "ip saddr 10.0.0.0/8 drop expands to bitwise + cmp" do
      rs =
        compile!("""
        table inet t {
          chain c { ip saddr 10.0.0.0/8 drop }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :network, offset: 12, len: 4}},
               %Expr{name: :bitwise, data: %{mask: <<0xFF, 0, 0, 0>>}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<10, 0, 0, 0>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :drop}}
             ] = rule.expressions
    end

    test "tcp dport set ref" do
      rs =
        compile!("""
        table inet t {
          chain c { tcp dport @open_ports accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload},
               %Expr{name: :lookup, data: %{set: "open_ports"}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "tcp dport { 22, 80, 443 } anon set" do
      rs =
        compile!("""
        table inet t {
          chain c { tcp dport { 22, 80, 443 } accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload},
               %Expr{name: :__anon_set, data: %{values: [22, 80, 443], key_type: :inet_service}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end
  end

  describe "rules — meta and ct" do
    test "meta iifname interface match" do
      rs =
        compile!("""
        table inet t {
          chain c { meta iifname "eth0" accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :meta, data: %{key: :iifname}},
               %Expr{name: :cmp, data: %{op: :eq, value: ifname}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      assert byte_size(ifname) == 16
      assert :binary.part(ifname, 0, 4) == "eth0"
    end

    test "meta mark compares host-byte-order bytes (M2)" do
      # The kernel stores the mark host-order and memcmps the native
      # register against the cmp value — big-endian bytes would never
      # match on a little-endian machine.
      rs =
        compile!("""
        table inet t {
          chain c { meta mark 0x1234 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :meta, data: %{key: :mark}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<0x1234::native-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "meta protocol stays network order (a __be16 field)" do
      rs =
        compile!("""
        table inet t {
          chain c { meta protocol 0x0800 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :meta, data: %{key: :protocol}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<0x0800::big-16>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "ct mark compares host-byte-order bytes (M2)" do
      rs =
        compile!("""
        table inet t {
          chain c { ct mark 7 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :ct, data: %{key: :mark}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<7::native-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "a range over a host-order field is refused, not mis-encoded" do
      err =
        compile_err("""
        table inet t {
          chain c { meta mark 10-20 accept }
        }
        """)

      assert err.message =~ "host-byte-order"
    end

    test "ct state established accept (single state → bitwise + cmp_neq_0)" do
      rs =
        compile!("""
        table inet t {
          chain c { ct state established accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :ct, data: %{key: :state}},
               %Expr{name: :bitwise, data: %{mask: mask}},
               %Expr{name: :cmp, data: %{op: :neq, value: <<0::big-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      # Just one bit set in the mask: the ESTABLISHED bit.
      assert :binary.decode_unsigned(mask) > 0
    end

    test "ct state inline-set { established, related } accept" do
      rs =
        compile!("""
        table inet t {
          chain c { ct state { established, related } accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :ct, data: %{key: :state}},
               %Expr{name: :bitwise, data: %{mask: mask}},
               %Expr{name: :cmp, data: %{op: :neq, value: <<0::big-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      # Two bits OR'd together.
      bits = :binary.decode_unsigned(mask)

      assert bits ==
               Bitwise.bor(
                 Linx.Netfilter.Wire.ct_state_bits(:established),
                 Linx.Netfilter.Wire.ct_state_bits(:related)
               )
    end

    test "ct state comma-no-braces established,related accept" do
      rs =
        compile!("""
        table inet t {
          chain c { ct state established,related accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :ct, data: %{key: :state}},
               %Expr{name: :bitwise, data: %{mask: mask}},
               %Expr{name: :cmp, data: %{op: :neq, value: <<0::big-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      bits = :binary.decode_unsigned(mask)

      assert bits ==
               Bitwise.bor(
                 Linx.Netfilter.Wire.ct_state_bits(:established),
                 Linx.Netfilter.Wire.ct_state_bits(:related)
               )
    end

    test "ct state != invalid drop (inverted op → bitwise + cmp_eq_0)" do
      rs =
        compile!("""
        table inet t {
          chain c { ct state != invalid drop }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :ct, data: %{key: :state}},
               %Expr{name: :bitwise, data: %{mask: mask}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<0::big-32>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :drop}}
             ] = rule.expressions

      assert :binary.decode_unsigned(mask) == Linx.Netfilter.Wire.ct_state_bits(:invalid)
    end
  end

  describe "rules — icmpv6" do
    test "icmpv6 type with integer literal" do
      rs =
        compile!("""
        table ip6 t {
          chain c { icmpv6 type 128 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:ip6, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 0, len: 1}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<128>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "icmpv6 type with symbolic name `echo-request`" do
      rs =
        compile!("""
        table ip6 t {
          chain c { icmpv6 type echo-request accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:ip6, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 0, len: 1}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<128>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "icmpv6 type with inline set of symbolic names" do
      rs =
        compile!("""
        table ip6 t {
          chain c {
            icmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert } accept
          }
        }
        """)

      [rule] = (rs |> fetch_table!(:ip6, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 0, len: 1}},
               %Expr{name: :__anon_set, data: %{values: values, key_type: :inet_proto}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      assert values == [128, 129, 133, 134]
    end
  end

  describe "rules — actions" do
    test "counter accept" do
      rs =
        compile!("""
        table inet t {
          chain c { counter accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :counter},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test ~s|log prefix "ssh-attempt" group 5000 accept| do
      rs =
        compile!("""
        table inet t {
          chain c { log prefix "ssh-attempt" group 5000 accept }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :log, data: log_data},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions

      assert log_data[:prefix] == "ssh-attempt"
      assert log_data[:group] == 5000
    end

    test "dnat to 10.0.0.5" do
      rs =
        compile!("""
        table ip t {
          chain c { type nat hook prerouting priority dstnat
                    dnat to 10.0.0.5 }
        }
        """)

      [rule] = (rs |> fetch_table!(:ip, "t") |> fetch_chain!("c")).rules

      assert Enum.any?(rule.expressions, &match?(%Expr{name: :nat, data: %{type: :dnat}}, &1))
    end

    test "masquerade with flags" do
      rs =
        compile!("""
        table ip t {
          chain c { type nat hook postrouting priority srcnat
                    masquerade random persistent }
        }
        """)

      [rule] = (rs |> fetch_table!(:ip, "t") |> fetch_chain!("c")).rules

      assert [
               %Expr{name: :masq, data: %{flags: flags}}
             ] = rule.expressions

      assert :random in flags and :persistent in flags
    end

    test "reject" do
      rs =
        compile!("""
        table inet t {
          chain c { reject }
        }
        """)

      [rule] = (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert [%Expr{name: :reject, data: %{type: :icmp_unreach}}] = rule.expressions
    end
  end

  describe "rule metadata" do
    test "comment is propagated to the Rule struct" do
      rs =
        compile!("""
        table inet t {
          chain c { accept comment "the allow rule" }
        }
        """)

      [%Rule{comment: comment}] =
        (rs |> fetch_table!(:inet, "t") |> fetch_chain!("c")).rules

      assert comment == "the allow rule"
    end
  end

  describe "named sets" do
    test "ipv4_addr set with elements" do
      rs =
        compile!("""
        table inet t {
          set blocklist {
            type ipv4_addr
            flags interval
            elements = { 10.0.0.1, 10.0.0.2 }
          }
        }
        """)

      table = fetch_table!(rs, :inet, "t")
      [set] = table.sets |> Map.values()
      assert set.name == "blocklist"
      assert set.key_type == :ipv4_addr
      assert :interval in set.flags
      assert "10.0.0.1" in set.elements and "10.0.0.2" in set.elements
    end

    test "set missing type is rejected" do
      err =
        compile_err("""
        table inet t {
          set blocklist { flags interval }
        }
        """)

      assert err.message =~ "missing required `type`"
    end
  end

  describe "deferred features" do
    test "limit statement raises a clear error" do
      err =
        compile_err("""
        table inet t {
          chain c { limit rate 10/second accept }
        }
        """)

      assert err.message =~ "limit"
    end

    test "meta mark set raises a clear error" do
      err =
        compile_err("""
        table inet t {
          chain c { meta mark set 0xabc }
        }
        """)

      assert err.message =~ "set"
    end

    test "named object raises a clear error" do
      err =
        compile_err("""
        table inet t {
          counter ctr { }
        }
        """)

      assert err.message =~ "named `counter` objects"
    end

    test "flowtable raises a clear error" do
      err =
        compile_err("""
        table inet t {
          flowtable ft { hook ingress priority filter; devices = { eth0 } }
        }
        """)

      assert err.message =~ "flowtables"
    end
  end

  describe "round-trip: realistic appliance" do
    test "compiles the canonical Nerves-appliance shape" do
      src = """
      table inet appliance {
        chain input {
          type filter hook input priority 0
          policy drop

          ct state established accept
          tcp dport 22 accept
        }

        chain forward {
          type filter hook forward priority 0
          policy drop
        }
      }
      """

      rs = compile!(src)
      table = fetch_table!(rs, :inet, "appliance")

      assert map_size(table.chains) == 2

      input = fetch_chain!(table, "input")
      assert input.type == :filter
      assert input.hook == :input
      assert input.policy == :drop
      assert length(input.rules) == 2

      forward = fetch_chain!(table, "forward")
      assert forward.hook == :forward
      assert forward.policy == :drop
    end
  end

  describe "error reporting" do
    test "carries source line/column from the offending AST node" do
      src = "table inet t {\n  flowtable ft { hook ingress priority 0; devices = { eth0 } }\n}\n"

      err = compile_err(src)
      assert err.line == 2
      assert is_integer(err.column)
      assert err.message =~ "flowtables"
    end
  end
end
