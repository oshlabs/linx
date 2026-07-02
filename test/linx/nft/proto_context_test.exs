defmodule Linx.NFT.ProtoContextTest do
  @moduledoc """
  NFT-PLAN.md Phase 6 — protocol-context dependency generation:
  transport matches materialise a `meta l4proto` guard and
  `ip`/`ip6` header matches in an `inet` chain materialise a
  `meta nfproto` guard, exactly like nft's evaluate.c. Explicit
  guards pin the context; contradictions are located errors.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.ParseError
  alias Linx.Netfilter.Expr

  defp rule!(src) do
    {:ok, rs} = Linx.NFT.parse(src)
    [table] = Map.values(rs.tables)
    [chain] = for {_, c} <- table.chains, c.rules != [], do: c
    [rule] = chain.rules
    rule
  end

  defp guards(rule) do
    rule.expressions
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.flat_map(fn
      [%Expr{name: :meta, data: %{key: key}}, %Expr{name: :cmp, data: %{value: <<v>>}}]
      when key in [:l4proto, :nfproto] ->
        [{key, v}]

      _ ->
        []
    end)
  end

  test "udp dport gets an l4proto 17 guard (not 6)" do
    rule = rule!("table inet t { chain c { udp dport 53 accept } }")
    assert {:l4proto, 17} in guards(rule)
  end

  test "a hand-written meta l4proto guard is not duplicated" do
    rule = rule!("table inet t { chain c { meta l4proto tcp tcp dport 22 accept } }")
    assert Enum.count(guards(rule), &match?({:l4proto, _}, &1)) == 1
  end

  test "ip-family tables don't get an nfproto guard for ip headers" do
    rule = rule!("table ip t { chain c { ip saddr 10.0.0.1 accept } }")
    assert guards(rule) == []
  end

  test "two tcp matches in one rule share a single guard" do
    rule = rule!("table inet t { chain c { tcp sport 1024 tcp dport 22 accept } }")
    assert Enum.count(guards(rule), &match?({:l4proto, 6}, &1)) == 1
  end

  test "tcp and udp in the same rule is a located contradiction" do
    assert {:error, %ParseError{} = err} =
             Linx.NFT.parse("table inet t { chain c { tcp dport 22 udp dport 53 accept } }")

    assert Exception.message(err) =~ "conflicts"
  end

  test "icmpv6 in an ip-family table is rejected" do
    assert {:error, %ParseError{} = err} =
             Linx.NFT.parse("table ip t { chain c { icmpv6 type echo-request accept } }")

    assert Exception.message(err) =~ "icmpv6"
  end

  test "ip protocol tcp pins the transport context" do
    rule = rule!("table ip t { chain c { ip protocol tcp tcp dport 22 accept } }")
    refute Enum.any?(guards(rule), &match?({:l4proto, _}, &1))
  end

  describe "formatting" do
    test "the guard folds away and disambiguates udp dport" do
      {:ok, rs} = Linx.NFT.parse("table inet t { chain c { udp dport 53 accept } }")
      out = Linx.NFT.format(rs)
      assert out =~ "udp dport 53 accept"
      refute out =~ "l4proto"
    end

    test "icmpv6 type renders as icmpv6, not icmp" do
      {:ok, rs} =
        Linx.NFT.parse("""
        table inet t {
          chain c { icmpv6 type echo-request accept }
        }
        """)

      out = Linx.NFT.format(rs)
      assert out =~ "icmpv6 type 128"
      refute out =~ "icmp type"
    end

    test "guarded output round-trips to the identical ruleset" do
      src = """
      table inet t {
        chain c {
          type filter hook input priority 0
          udp dport 53 accept
          ip saddr 10.0.0.0/8 drop
          icmpv6 type echo-request accept
        }
      }
      """

      {:ok, rs1} = Linx.NFT.parse(src)
      {:ok, rs2} = Linx.NFT.parse(Linx.NFT.format(rs1))
      assert rs1 == rs2
    end
  end
end
