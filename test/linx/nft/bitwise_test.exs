defmodule Linx.NFT.BitwiseTest do
  @moduledoc """
  NFT-PLAN.md Phase 1 — bitwise / flag matching: `tcp flags syn`
  (implicit bit test), `tcp flags == syn` (exact), masked
  comparisons `tcp flags & (fin|syn|rst|ack) == syn` and
  `ct mark & 0xff == 0x4`.
  """

  use ExUnit.Case, async: true

  alias Linx.Netfilter.Expr

  defp rule!(src) do
    {:ok, rs} = Linx.NFT.parse(src)
    [table] = Map.values(rs.tables)
    [chain] = for {_, c} <- table.chains, c.rules != [], do: c
    [rule] = chain.rules
    rule
  end

  defp exprs_after_proto(rule) do
    # Drop the leading meta l4proto guard for readability.
    Enum.drop_while(rule.expressions, fn
      %Expr{name: :meta} -> true
      %Expr{name: :cmp, data: %{value: <<6>>}} -> true
      _ -> false
    end)
  end

  describe "tcp flags — implicit bit test" do
    test "`tcp flags syn` is flags & syn != 0" do
      rule = rule!("table inet t { chain c { tcp flags syn accept } }")

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 13, len: 1}},
               %Expr{name: :bitwise, data: %{mask: <<0x02>>, xor: <<0>>}},
               %Expr{name: :cmp, data: %{op: :neq, value: <<0>>}},
               %Expr{name: :immediate}
             ] = exprs_after_proto(rule)
    end

    test "an OR-combination sets multiple mask bits" do
      rule = rule!("table inet t { chain c { tcp flags syn|ack accept } }")

      assert Enum.any?(exprs_after_proto(rule), fn
               # syn(2) | ack(16) = 0x12
               %Expr{name: :bitwise, data: %{mask: <<0x12>>}} -> true
               _ -> false
             end)
    end
  end

  describe "tcp flags — exact and masked" do
    test "`tcp flags == syn` is an exact compare" do
      rule = rule!("table inet t { chain c { tcp flags == syn accept } }")

      assert [
               %Expr{name: :payload, data: %{offset: 13}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<0x02>>}},
               %Expr{name: :immediate}
             ] = exprs_after_proto(rule)
    end

    test "`tcp flags & (fin|syn|rst|ack) == syn` masks then compares" do
      rule =
        rule!("table inet t { chain c { tcp flags & (fin|syn|rst|ack) == syn accept } }")

      assert [
               %Expr{name: :payload, data: %{offset: 13}},
               # fin|syn|rst|ack = 0x17
               %Expr{name: :bitwise, data: %{mask: <<0x17>>}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<0x02>>}},
               %Expr{name: :immediate}
             ] = exprs_after_proto(rule)
    end
  end

  describe "ct mark masked comparison" do
    test "`ct mark & 0xff == 0x4` masks the host-order mark" do
      rule = rule!("table inet t { chain c { ct mark & 0xff == 0x4 accept } }")

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :bitwise, data: %{mask: <<0xFF::native-32>>}} -> true
               _ -> false
             end)

      assert Enum.any?(rule.expressions, fn
               %Expr{name: :cmp, data: %{op: :eq, value: <<0x4::native-32>>}} -> true
               _ -> false
             end)
    end
  end

  describe "formatting round-trips" do
    for {label, line} <- [
          {"implicit bit test", "tcp flags syn accept"},
          {"or-combination", "tcp flags syn|ack accept"},
          {"exact", "tcp flags == syn accept"},
          {"masked", "tcp flags & (fin|syn|rst|ack) == syn accept"},
          {"ct mark mask", "ct mark & 0xff == 0x4 accept"}
        ] do
      test "round-trips: #{label}" do
        src = """
        table inet t {
          chain c {
            type filter hook input priority 0
            #{unquote(line)}
          }
        }
        """

        {:ok, rs1} = Linx.NFT.parse(src)
        {:ok, rs2} = Linx.NFT.parse(Linx.NFT.format(rs1))
        assert rs1 == rs2
      end
    end

    test "the implicit bit test renders back as `tcp flags syn`" do
      {:ok, rs} =
        Linx.NFT.parse("table inet t { chain c { tcp flags syn accept } }")

      assert Linx.NFT.format(rs) =~ "tcp flags syn"
    end
  end
end
