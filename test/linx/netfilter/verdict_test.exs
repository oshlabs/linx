defmodule Linx.Netfilter.VerdictTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.Verdict

  describe "simple-verdict constructors" do
    test "accept/0, drop/0, continue/0, return/0 produce verdicts with no target" do
      assert %Verdict{kind: :accept, target: nil} = Verdict.accept()
      assert %Verdict{kind: :drop, target: nil} = Verdict.drop()
      assert %Verdict{kind: :continue, target: nil} = Verdict.continue()
      assert %Verdict{kind: :return, target: nil} = Verdict.return()
    end
  end

  describe "jump/1, goto/1, queue/1" do
    test "jump and goto carry the chain name" do
      assert %Verdict{kind: :jump, target: "input_extras"} = Verdict.jump("input_extras")
      assert %Verdict{kind: :goto, target: "drop_quietly"} = Verdict.goto("drop_quietly")
    end

    test "queue/1 carries the queue number" do
      assert %Verdict{kind: :queue, target: 5} = Verdict.queue(5)
    end

    test "jump/1 raises on empty chain name" do
      assert_raise FunctionClauseError, fn -> Verdict.jump("") end
    end

    test "queue/1 raises on negative integer" do
      assert_raise FunctionClauseError, fn -> Verdict.queue(-1) end
    end
  end

  describe "new/1" do
    test "atoms map to simple verdicts" do
      for k <- [:accept, :drop, :continue, :return] do
        assert {:ok, %Verdict{kind: ^k, target: nil}} = Verdict.new(k)
      end
    end

    test "tuple forms map to parameterised verdicts" do
      assert {:ok, %Verdict{kind: :jump, target: "x"}} = Verdict.new({:jump, "x"})
      assert {:ok, %Verdict{kind: :goto, target: "y"}} = Verdict.new({:goto, "y"})
      assert {:ok, %Verdict{kind: :queue, target: 7}} = Verdict.new({:queue, 7})
    end

    test "%Verdict{} round-trips" do
      v = Verdict.jump("x")
      assert {:ok, ^v} = Verdict.new(v)
    end

    test "unknown atom is :bad_verdict" do
      assert {:error, {:bad_verdict, :reject}} = Verdict.new(:reject)
      assert {:error, {:bad_verdict, :unknown}} = Verdict.new(:unknown)
    end

    test "empty chain name in jump/goto is :bad_verdict" do
      assert {:error, {:bad_verdict, {:jump, ""}}} = Verdict.new({:jump, ""})
      assert {:error, {:bad_verdict, {:goto, ""}}} = Verdict.new({:goto, ""})
    end

    test "negative queue number is :bad_verdict" do
      assert {:error, {:bad_verdict, {:queue, -1}}} = Verdict.new({:queue, -1})
    end
  end

  describe "new!/1" do
    test "returns the verdict on success" do
      assert %Verdict{kind: :accept} = Verdict.new!(:accept)
    end

    test "raises ArgumentError on failure" do
      assert_raise ArgumentError, ~r/invalid verdict: :reject/, fn ->
        Verdict.new!(:reject)
      end
    end
  end

  describe "valid?/1" do
    test "true for well-formed verdicts" do
      assert Verdict.valid?(Verdict.accept())
      assert Verdict.valid?(Verdict.drop())
      assert Verdict.valid?(Verdict.jump("x"))
      assert Verdict.valid?(Verdict.queue(0))
    end

    test "false for malformed verdicts" do
      refute Verdict.valid?(%Verdict{kind: :accept, target: "wrong"})
      refute Verdict.valid?(%Verdict{kind: :jump, target: nil})
      refute Verdict.valid?(%Verdict{kind: :queue, target: -1})
      refute Verdict.valid?(%Verdict{kind: :nope})
    end
  end

  describe "Inspect" do
    test "simple verdicts render without a target" do
      assert inspect(Verdict.accept()) == "#Linx.Netfilter.Verdict<accept>"
      assert inspect(Verdict.drop()) == "#Linx.Netfilter.Verdict<drop>"
    end

    test "jump/goto render with the chain name in quotes" do
      assert inspect(Verdict.jump("x")) == ~s|#Linx.Netfilter.Verdict<jump "x">|
      assert inspect(Verdict.goto("y")) == ~s|#Linx.Netfilter.Verdict<goto "y">|
    end

    test "queue renders with the integer" do
      assert inspect(Verdict.queue(42)) == "#Linx.Netfilter.Verdict<queue 42>"
    end
  end
end
