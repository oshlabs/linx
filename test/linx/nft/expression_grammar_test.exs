defmodule Linx.NFT.ExpressionGrammarTest do
  @moduledoc """
  NFT-PLAN.md Phase 1 — expression-grammar features: vmap
  dispatch, selector/element concatenation, NAT targets with
  ports, and interface-index resolution.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.{Parser, ParseError, Tokenizer}
  alias Linx.Netfilter.Expr

  defp tokens!(source) do
    {:ok, tokens} = Tokenizer.tokenize(source)
    tokens
  end

  defp parse!(source) do
    {:ok, tokens} = Tokenizer.tokenize(source)
    {:ok, ast} = Parser.parse(tokens, source: source)
    ast
  end

  defp rule_stmts!(source) do
    [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(source)
    stmts
  end

  describe "vmap expressions" do
    test "named vmap: `tcp dport vmap @dispatch`" do
      stmts = rule_stmts!("table inet t { chain c { tcp dport vmap @dispatch } }")

      assert [{:vmap, {:payload, :tcp, :dport, _}, {:set_ref, "dispatch", _}, _}] = stmts
    end

    test "ct state vmap with inline map" do
      stmts =
        rule_stmts!("""
        table inet t { chain c {
          ct state vmap { established : accept, invalid : drop }
        } }
        """)

      assert [{:vmap, {:ct, :state, _}, {:map_inline, elems, _}, _}] = stmts

      assert [
               {:map_elem, {:identifier, "established", _}, {:verdict, :accept, _}, _},
               {:map_elem, {:identifier, "invalid", _}, {:verdict, :drop, _}, _}
             ] = elems
    end

    test "named vmap compiles to a lookup into the verdict register" do
      src = """
      table inet t {
        vmap dispatch {
          type inet_service : verdict
          elements = { 22 : accept }
        }
        chain c {
          type filter hook input priority 0
          tcp dport vmap @dispatch
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      table = rs.tables[{:inet, "t"}]
      [rule] = table.chains["c"].rules

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :lookup, data: %{set: "dispatch", dreg: 0}} -> true
               _ -> false
             end)
    end

    test "inline vmap lowers to an __anon_vmap sentinel with verdict elements" do
      src = """
      table inet t {
        chain c {
          tcp dport vmap { 22 : accept, 23 : drop }
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      [rule] = rs.tables[{:inet, "t"}].chains["c"].rules

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :__anon_vmap, data: %{key_type: :inet_service, elements: elems}} ->
                 match?(
                   [
                     {22, %Linx.Netfilter.Verdict{kind: :accept}},
                     {23, %Linx.Netfilter.Verdict{kind: :drop}}
                   ],
                   elems
                 )

               _ ->
                 false
             end)
    end

    test "ct state vmap resolves state names to bits" do
      src = """
      table inet t {
        chain c {
          ct state vmap { established : accept, invalid : drop }
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      [rule] = rs.tables[{:inet, "t"}].chains["c"].rules

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :__anon_vmap, data: %{key_type: :ct_state, elements: elems}} ->
                 Enum.all?(elems, fn {bits, %Linx.Netfilter.Verdict{}} -> is_integer(bits) end)

               _ ->
                 false
             end)
    end
  end

  describe "concatenations" do
    test "selector concatenation parses: `ip daddr . tcp dport @svc`" do
      stmts = rule_stmts!("table inet t { chain c { ip daddr . tcp dport @svc } }")

      assert [
               {:match,
                {:concat_lhs, [{:payload, :ip, :daddr, _}, {:payload, :tcp, :dport, _}], _}, :eq,
                {:set_ref, "svc", _}, _}
             ] = stmts
    end

    test "concatenated set elements parse: `10.96.0.1 . 443`" do
      src = """
      table inet t {
        set svc {
          type ipv4_addr . inet_service
          elements = { 10.96.0.1 . 443, 10.96.0.10 . 53 }
        }
      }
      """

      [{:table, _, _, [{:set, "svc", opts, _}], _}] = parse!(src)

      assert [
               {:concat, [{:address, :ipv4, "10.96.0.1", _}, {:integer, 443, _}], _},
               {:concat, [{:address, :ipv4, "10.96.0.10", _}, {:integer, 53, _}], _}
             ] = opts[:elements]
    end

    test "concatenated selectors lower to reg32 loads + lookup at reg 8" do
      src = """
      table inet t {
        set svc {
          type ipv4_addr . inet_service
          elements = { 10.96.0.1 . 443 }
        }
        chain c {
          type filter hook input priority 0
          ip daddr . tcp dport @svc accept
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      table = rs.tables[{:inet, "t"}]

      assert table.sets["svc"].key_type == {:concat, [:ipv4_addr, :inet_service]}
      assert table.sets["svc"].elements == [["10.96.0.1", 443]]

      [rule] = table.chains["c"].rules

      # ip daddr (4 bytes) → reg 8; tcp dport (2 bytes) → reg 9;
      # lookup reads the concatenation starting at reg 8.
      assert [
               %Expr{name: :payload, data: %{base: :network, offset: 16, len: 4, dreg: 8}},
               %Expr{name: :payload, data: %{base: :transport, offset: 2, len: 2, dreg: 9}},
               %Expr{name: :lookup, data: %{set: "svc", sreg: 8}},
               %Expr{name: :immediate}
             ] = rule.expressions
    end

    test "an IPv6 part occupies four 32-bit registers" do
      src = """
      table inet t {
        set svc6 {
          type ipv6_addr . inet_service
        }
        chain c {
          type filter hook input priority 0
          ip6 daddr . tcp dport @svc6 accept
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      [rule] = rs.tables[{:inet, "t"}].chains["c"].rules

      # ip6 daddr (16 bytes) fills regs 8-11; tcp dport lands at 12.
      assert Enum.any?(rule.expressions, fn
               %Expr{name: :payload, data: %{len: 2, dreg: 12}} -> true
               _ -> false
             end)
    end

    test "interval parts inside concatenations are still rejected" do
      src = """
      table inet t {
        set svc {
          type ipv4_addr . inet_service
          elements = { 10.96.0.1 . 100-200 }
        }
      }
      """

      assert {:error, %ParseError{}} = Linx.NFT.parse(src)
    end
  end

  describe "NAT targets with ports" do
    test "tokenizer splits 1.2.3.4:8080 like nft's scanner" do
      assert [{:ipv4, "1.2.3.4", _}, {:colon, _}, {:integer, 8080, _}] =
               tokens!("1.2.3.4:8080")
    end

    test "dnat to addr:port compiles with proto register" do
      src = """
      table ip nat {
        chain pre {
          type nat hook prerouting priority -100
          dnat to 10.0.0.5:8080
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      [rule] = rs.tables[{:ip, "nat"}].chains["pre"].rules

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :immediate, data: %{value: <<8080::big-16>>}} -> true
               _ -> false
             end)
    end

    test "dnat to addr:port_range parses" do
      stmts =
        rule_stmts!("table ip t { chain c { dnat to 10.0.0.5:8080-8090 } }")

      assert [
               {:nat, :dnat,
                {:nat_target, {:address, :ipv4, "10.0.0.5", _},
                 {:range, {:integer, 8080, _}, {:integer, 8090, _}, _}, _}, [], _}
             ] = stmts
    end
  end

  describe "iif/oif interface-index resolution" do
    test "iif \"lo\" resolves the name to an index at compile time, like nft" do
      src = """
      table inet t {
        chain c {
          meta iif "lo" accept
        }
      }
      """

      {:ok, idx} = :net.if_name2index(~c"lo")
      {:ok, rs} = Linx.NFT.parse(src)
      [rule] = rs.tables[{:inet, "t"}].chains["c"].rules

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :cmp, data: %{value: <<n::native-32>>}} -> n == idx
               _ -> false
             end)
    end

    test "unknown interface is a located compiler error suggesting iifname" do
      src = """
      table inet t {
        chain c {
          meta iif "definitely-not-a-nic-0" accept
        }
      }
      """

      assert {:error, %ParseError{line: 3} = err} = Linx.NFT.parse(src)
      assert Exception.message(err) =~ "iifname"
    end
  end
end
