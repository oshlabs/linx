defmodule Linx.Sysctl.ReconcileTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Sysctl.Error
  alias Linx.Sysctl.Reconcile
  alias Linx.Sysctl.Reconcile.Report

  # --- value comparison (exercised through the pure diff) -------------------

  describe "diff/4 value comparison" do
    test "an integer desired matches its decimal string observed" do
      assert [] == Reconcile.diff(%{"k" => "1"}, %{"k" => 1})
    end

    test "an integer-list desired matches a tab- or space-separated observed" do
      assert [] == Reconcile.diff(%{"k" => "4\t4\t1\t7"}, %{"k" => [4, 4, 1, 7]})

      assert [] ==
               Reconcile.diff(%{"k" => "4096 131072 6291456"}, %{
                 "k" => [4096, 131_072, 6_291_456]
               })
    end

    test "a binary desired compares trailing-trimmed (read/2 trims), interior exact" do
      assert [] == Reconcile.diff(%{"k" => "abc"}, %{"k" => "abc"})

      # read/2 hands back trim_trailing'ed values, so a desired with
      # trailing whitespace must still converge — the old exact compare
      # rewrote such a key on every pass, forever.
      assert [] == Reconcile.diff(%{"k" => "abc"}, %{"k" => "abc\n"})
      assert [] == Reconcile.diff(%{"k" => "abc"}, %{"k" => "abc "})

      # Interior whitespace stays significant for free-form knobs.
      assert [{:set, "k", "a  bc"}] == Reconcile.diff(%{"k" => "a bc"}, %{"k" => "a  bc"})
    end

    test "a differing value yields a :set" do
      assert [{:set, "net.ipv4.ip_forward", 1}] ==
               Reconcile.diff(%{"net.ipv4.ip_forward" => "0"}, %{"net.ipv4.ip_forward" => 1})
    end

    test "an unreadable (absent) observed key always yields a :set" do
      assert [{:set, "k", 1}] == Reconcile.diff(%{}, %{"k" => 1})
    end
  end

  # --- release / revert ownership semantics ---------------------------------

  describe "diff/4 release semantics" do
    test "a key that left the desired set is released (value left untouched) by default" do
      last = %{"k" => %{applied: 1, original: 0}}
      assert [{:release, "k"}] == Reconcile.diff(%{"k" => "1"}, %{}, last)
    end

    test "revert_on_release restores the captured original" do
      last = %{"k" => %{applied: 1, original: 0}}

      assert [{:revert, "k", 0}] ==
               Reconcile.diff(%{"k" => "1"}, %{}, last, revert_on_release: true)
    end

    test "revert falls back to release when no original was captured" do
      last = %{"k" => %{applied: 1, original: nil}}

      assert [{:release, "k"}] ==
               Reconcile.diff(%{"k" => "1"}, %{}, last, revert_on_release: true)
    end

    test "a still-desired owned key is not released" do
      last = %{"k" => %{applied: 1, original: 0}}
      assert [] == Reconcile.diff(%{"k" => "1"}, %{"k" => 1}, last)
    end
  end

  # --- pure diff properties -------------------------------------------------

  defp key,
    do:
      map(
        list_of(string([?a..?z], min_length: 1, max_length: 5), min_length: 1, max_length: 4),
        &Enum.join(&1, ".")
      )

  # A desired map of key => small non-negative integer.
  defp desired_map do
    map_of(key(), integer(0..9999), max_length: 8)
  end

  # The "already converged" observed view of a desired map: each value rendered
  # the way the kernel would read it back.
  defp observed_of(desired), do: Map.new(desired, fn {k, v} -> {k, Integer.to_string(v)} end)

  property "an already-converged observed state produces no :set ops" do
    check all(desired <- desired_map()) do
      ops = Reconcile.diff(observed_of(desired), desired)
      refute Enum.any?(ops, &match?({:set, _, _}, &1))
    end
  end

  property "every desired key whose observed value differs (or is absent) gets exactly one :set" do
    check all(desired <- desired_map(), desired != %{}) do
      # Observe nothing: every desired key must be (re)set.
      ops = Reconcile.diff(%{}, desired)
      set_keys = for {:set, k, _} <- ops, do: k
      assert Enum.sort(set_keys) == Enum.sort(Map.keys(desired))
      assert Enum.uniq(set_keys) == set_keys
    end
  end

  property "diff is idempotent: applying the sets then re-diffing yields no sets" do
    check all(desired <- desired_map()) do
      ops = Reconcile.diff(%{}, desired)
      # Simulate the kernel now holding exactly what we set.
      now = for {:set, k, v} <- ops, into: %{}, do: {k, Integer.to_string(v)}
      assert [] == for(op <- Reconcile.diff(now, desired), match?({:set, _, _}, op), do: op)
    end
  end

  property "exactly the owned keys absent from desired are released; shared keys are not" do
    check all(
            desired <- desired_map(),
            extra <- desired_map(),
            extra != %{}
          ) do
      # Own everything in desired plus the extras; extras are not desired.
      owned_extra = Map.drop(extra, Map.keys(desired))

      last =
        Map.new(Map.merge(desired, owned_extra), fn {k, v} -> {k, %{applied: v, original: v}} end)

      ops = Reconcile.diff(observed_of(desired), desired, last)
      released = for {:release, k} <- ops, do: k

      assert Enum.sort(released) == Enum.sort(Map.keys(owned_extra))
    end
  end

  # --- live reconcile (no root, no mutation) --------------------------------
  #
  # These hit the real kernel but never change a value: a no-op convergence,
  # a write the kernel rejects (read-only knob), and a release that touches
  # nothing. They exercise observe → diff → apply end to end.

  describe "reconcile/3 against the live kernel" do
    setup do
      # kernel.ostype is universally present, read-only, and constant.
      {:ok, ostype} = Linx.Sysctl.read("kernel.ostype")
      %{ostype: ostype}
    end

    test "converges with no ops when the kernel already matches", %{ostype: ostype} do
      assert {:ok, %Report{} = r} = Reconcile.reconcile(%{"kernel.ostype" => ostype})
      assert r.converged?
      assert r.applied == []
      assert r.failed == []
      # A no-op set still claims ownership, capturing the original.
      assert %{"kernel.ostype" => %{original: ^ostype}} = r.last_applied
    end

    test "a rejected write lands in :failed and does not claim ownership" do
      assert {:ok, %Report{} = r} = Reconcile.reconcile(%{"kernel.ostype" => "Mutant"})
      refute r.converged?
      assert r.applied == []
      assert [{{:set, "kernel.ostype", "Mutant"}, %Error{}}] = r.failed
      assert r.last_applied == %{}
    end

    test "a caller-input error (bad key) also lands in :failed, never in converged?" do
      # Sysctl.write reports a malformed key as {:error, {:bad_key, _}} — a
      # tuple, not a %Sysctl.Error{}. It must still fail the pass: a report
      # that silently drops it would claim convergence for a value the
      # kernel never saw.
      assert {:ok, %Report{} = r} = Reconcile.reconcile(%{"kernel..bad" => 1})
      refute r.converged?
      assert r.applied == []
      assert [{{:set, "kernel..bad", 1}, {:bad_key, "kernel..bad"}}] = r.failed
      assert r.last_applied == %{}
    end

    test "releases an owned key that left the desired set, touching nothing", %{ostype: ostype} do
      last = %{"kernel.ostype" => %{applied: "whatever", original: ostype}}
      assert {:ok, %Report{} = r} = Reconcile.reconcile(%{}, last)
      assert r.converged?
      assert r.applied == [{:release, "kernel.ostype"}]
      assert r.failed == []
      assert r.last_applied == %{}
      # Untouched: the kernel still reports the real ostype.
      assert {:ok, ^ostype} = Linx.Sysctl.read("kernel.ostype")
    end
  end
end
