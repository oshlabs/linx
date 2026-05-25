defmodule Linx.Netfilter.RuleTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Expr, Rule, Verdict}

  describe "build/2 — happy path" do
    test "wraps a list of %Expr{} into a rule" do
      e = Expr.immediate(:accept)
      assert {:ok, %Rule{expressions: [^e]}} = Rule.build([e])
    end

    test "normalises verdict sugar (atoms) to immediate expressions" do
      assert {:ok, %Rule{expressions: [%Expr{name: :immediate, data: %Verdict{kind: :drop}}]}} =
               Rule.build([:drop])
    end

    test "normalises verdict-tuple sugar to immediate expressions" do
      assert {:ok,
              %Rule{
                expressions: [
                  %Expr{name: :immediate, data: %Verdict{kind: :jump, target: "x"}}
                ]
              }} = Rule.build([{:jump, "x"}])
    end

    test "normalises %Verdict{} values to immediate expressions" do
      v = Verdict.queue(42)

      assert {:ok, %Rule{expressions: [%Expr{name: :immediate, data: ^v}]}} =
               Rule.build([v])
    end

    test "accepts an empty expression list (fall-through rule)" do
      assert {:ok, %Rule{expressions: []}} = Rule.build([])
    end

    test "accepts tag, comment, handle, chain via opts" do
      assert {:ok, %Rule{tag: :ssh_in, comment: "ssh", handle: 7, chain: "input"}} =
               Rule.build([:accept], tag: :ssh_in, comment: "ssh", handle: 7, chain: "input")
    end
  end

  describe "build/2 — validation" do
    test "non-list expressions is :bad_rule" do
      assert {:error, {:bad_rule, :expressions_not_a_list}} = Rule.build(:nope)
    end

    test "non-convertible expression element is :bad_rule" do
      assert {:error, {:bad_rule, {:not_an_expression, :reject}}} = Rule.build([:reject])
    end

    test "non-atom tag is :bad_rule" do
      assert {:error, {:bad_rule, {:tag_not_atom, "string"}}} =
               Rule.build([:accept], tag: "string")
    end

    test "non-positive handle is :bad_rule" do
      assert {:error, {:bad_rule, {:handle_not_pos_int, 0}}} =
               Rule.build([:accept], handle: 0)
    end

    test "non-binary comment is :bad_rule" do
      assert {:error, {:bad_rule, {:comment_not_binary, 123}}} =
               Rule.build([:accept], comment: 123)
    end
  end

  describe "build!/2" do
    test "returns the rule on success" do
      assert %Rule{} = Rule.build!([:accept])
    end

    test "raises ArgumentError on failure" do
      assert_raise ArgumentError, ~r/invalid rule/, fn -> Rule.build!([:reject]) end
    end
  end

  describe "verdict/1" do
    test "returns the trailing verdict" do
      {:ok, r} = Rule.build([Expr.new(:counter), :accept])
      assert %Verdict{kind: :accept} = Rule.verdict(r)
    end

    test "returns nil for a fall-through rule" do
      {:ok, r} = Rule.build([Expr.new(:counter)])
      assert Rule.verdict(r) == nil
    end

    test "returns nil for an empty rule" do
      {:ok, r} = Rule.build([])
      assert Rule.verdict(r) == nil
    end
  end

  describe "Inspect" do
    test "renders bracketed expressions" do
      assert Rule.build!([:accept]) |> inspect() ==
               "#Linx.Netfilter.Rule<[immediate accept]>"

      assert Rule.build!([{:jump, "x"}]) |> inspect() ==
               ~s|#Linx.Netfilter.Rule<[immediate jump "x"]>|
    end

    test "includes the tag when set" do
      assert Rule.build!([:drop], tag: :default_deny) |> inspect() ==
               "#Linx.Netfilter.Rule<:default_deny [immediate drop]>"
    end

    test "multiple expressions are comma-separated" do
      assert Rule.build!([Expr.new(:counter), :accept]) |> inspect() ==
               "#Linx.Netfilter.Rule<[counter, immediate accept]>"
    end
  end
end
