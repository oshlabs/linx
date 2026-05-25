defmodule Linx.Netfilter.ExprTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Expr, Verdict}

  describe "new/2" do
    test "constructs an expression with a name and data" do
      e = Expr.new(:counter, %{packets: 0, bytes: 0})
      assert %Expr{name: :counter, data: %{packets: 0, bytes: 0}} = e
    end

    test "data defaults to nil" do
      assert %Expr{name: :marker, data: nil} = Expr.new(:marker)
    end

    test "accepts string names" do
      assert %Expr{name: "payload", data: nil} = Expr.new("payload")
    end
  end

  describe "immediate/1" do
    test "wraps a %Verdict{} as an immediate expression" do
      v = Verdict.accept()
      assert %Expr{name: :immediate, data: ^v} = Expr.immediate(v)
    end

    test "accepts verdict input forms and normalises to %Verdict{}" do
      assert %Expr{name: :immediate, data: %Verdict{kind: :drop}} = Expr.immediate(:drop)

      assert %Expr{name: :immediate, data: %Verdict{kind: :jump, target: "x"}} =
               Expr.immediate({:jump, "x"})
    end

    test "raises ArgumentError on a bad verdict input" do
      assert_raise ArgumentError, fn -> Expr.immediate(:reject) end
    end
  end

  describe "verdict?/1" do
    test "true for immediate-verdict expressions" do
      assert Expr.verdict?(Expr.immediate(:accept))
      assert Expr.verdict?(Expr.immediate(Verdict.jump("x")))
    end

    test "false for other expressions" do
      refute Expr.verdict?(Expr.new(:counter))
      refute Expr.verdict?(Expr.new(:payload, %{}))
      refute Expr.verdict?(Expr.new(:immediate, "not a verdict"))
    end
  end

  describe "Inspect" do
    test "immediate-verdict renders compactly" do
      assert inspect(Expr.immediate(:accept)) ==
               "#Linx.Netfilter.Expr<immediate accept>"

      assert inspect(Expr.immediate({:jump, "x"})) ==
               ~s|#Linx.Netfilter.Expr<immediate jump "x">|

      assert inspect(Expr.immediate({:queue, 7})) ==
               "#Linx.Netfilter.Expr<immediate queue 7>"
    end

    test "generic expressions show name only" do
      assert inspect(Expr.new(:counter)) == "#Linx.Netfilter.Expr<counter>"
      assert inspect(Expr.new(:payload, %{base: :network})) == "#Linx.Netfilter.Expr<payload>"
    end
  end
end
