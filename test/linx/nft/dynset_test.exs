defmodule Linx.NFT.DynsetTest do
  @moduledoc """
  NFT-PLAN.md Phase 2 — dynamic-set statements
  (`add`/`update`/`delete @set { … }` → `nft_dynset`).
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.{Parser, Tokenizer}
  alias Linx.Netfilter.Expr

  defp rule_stmts!(source) do
    {:ok, tokens} = Tokenizer.tokenize(source)
    {:ok, ast} = Parser.parse(tokens, source: source)
    [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = ast
    stmts
  end

  defp compile_rule!(source) do
    {:ok, rs} = Linx.NFT.parse(source)
    [table] = Map.values(rs.tables)
    [chain] = for {_, c} <- table.chains, c.rules != [], do: c
    [rule] = chain.rules
    rule
  end

  describe "parsing" do
    test "add with a stateful limit" do
      stmts =
        rule_stmts!("""
        table inet t { chain c {
          add @ratelimit { ip saddr limit rate over 3/minute } drop
        } }
        """)

      assert [
               {:set_update, :add, "ratelimit", {:payload, :ip, :saddr, _}, opts, _},
               {:verdict, :drop, _}
             ] = stmts

      assert [{:stateful, {:limit, {:rate, 3, :minute}, [over: true], _}}] = opts
    end

    test "update with element timeout" do
      stmts =
        rule_stmts!("""
        table inet t { chain c {
          update @seen { ip saddr timeout 90s }
        } }
        """)

      assert [{:set_update, :update, "seen", {:payload, :ip, :saddr, _}, opts, _}] = stmts
      assert [{:timeout, {:time, 90_000, _}}] = opts
    end

    test "delete with a bare key" do
      stmts = rule_stmts!("table inet t { chain c { delete @seen { ip saddr } } }")
      assert [{:set_update, :delete, "seen", {:payload, :ip, :saddr, _}, [], _}] = stmts
    end
  end

  describe "compiling" do
    test "lowers to load + dynset with nested limit" do
      rule =
        compile_rule!("""
        table inet t {
          set ratelimit {
            type ipv4_addr
            flags dynamic, timeout
            timeout 10m
          }
          chain c {
            type filter hook input priority 0
            add @ratelimit { ip saddr limit rate over 3/minute } drop
          }
        }
        """)

      assert [
               %Expr{name: :meta, data: %{key: :nfproto}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<2>>}},
               %Expr{name: :payload, data: %{base: :network, offset: 12, len: 4}},
               %Expr{name: :dynset, data: dynset},
               %Expr{name: :immediate}
             ] = rule.expressions

      assert %{set: "ratelimit", op: :add, sreg_key: 1, timeout: nil} = dynset
      assert [%Expr{name: :limit, data: %{rate: 3, per: 60, over: true}}] = dynset.exprs
    end

    test "element timeout is carried in milliseconds" do
      rule =
        compile_rule!("""
        table inet t {
          set seen {
            type ipv4_addr
            flags dynamic, timeout
          }
          chain c {
            type filter hook input priority 0
            update @seen { ip saddr timeout 5m } accept
          }
        }
        """)

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :dynset, data: %{op: :update, timeout: 300_000}} -> true
               _ -> false
             end)
    end
  end

  describe "formatting" do
    test "round-trips through canonical emit" do
      src = """
      table inet t {
        set ratelimit {
          type ipv4_addr
          flags dynamic, timeout
          timeout 10m
        }
        chain c {
          type filter hook input priority 0
          add @ratelimit { ip saddr limit rate over 3/minute } drop
        }
      }
      """

      {:ok, rs1} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs1)
      assert out =~ "add @ratelimit { ip saddr limit rate over 3/minute } drop"

      {:ok, rs2} = Linx.NFT.parse(out)
      assert rs1 == rs2
    end
  end
end
