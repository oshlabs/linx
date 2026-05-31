defmodule Linx.Cgroup.ReconcilePropertyTest do
  @moduledoc """
  Property-based diff-correctness for `Linx.Cgroup.Reconcile` — the same
  discipline `Linx.Sysctl.Reconcile` is held to (cgroup limits are
  "sysctl-with-hierarchy"), plus the cgroup-specific value shapes (`:max`,
  `{quota, period}`) and their kernel read-back forms. Pure, no cgroupfs.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Cgroup.Reconcile

  # cgroup interface-file names: a word, a dot, a word (e.g. "memory.max").
  defp file do
    word = string([?a..?z], min_length: 1, max_length: 6)
    map({word, word}, fn {a, b} -> "#{a}.#{b}" end)
  end

  defp int_desired, do: map_of(file(), integer(0..9_999_999), max_length: 8)

  # The already-converged observed view: each integer value as the kernel reads
  # it back (decimal text).
  defp observed_of(desired), do: Map.new(desired, fn {k, v} -> {k, Integer.to_string(v)} end)

  property "an already-converged integer state produces no :set ops" do
    check all(desired <- int_desired()) do
      ops = Reconcile.diff(observed_of(desired), desired)
      refute Enum.any?(ops, &match?({:set, _, _}, &1))
    end
  end

  property "every desired file whose observed value differs (or is absent) gets exactly one :set" do
    check all(desired <- int_desired(), desired != %{}) do
      ops = Reconcile.diff(%{}, desired)
      set_files = for {:set, f, _} <- ops, do: f
      assert Enum.sort(set_files) == Enum.sort(Map.keys(desired))
      assert Enum.uniq(set_files) == set_files
    end
  end

  property "diff is idempotent: applying the sets then re-diffing yields no sets" do
    check all(desired <- int_desired()) do
      ops = Reconcile.diff(%{}, desired)
      now = for {:set, f, v} <- ops, into: %{}, do: {f, Integer.to_string(v)}
      assert [] == for(op <- Reconcile.diff(now, desired), match?({:set, _, _}, op), do: op)
    end
  end

  property "exactly the owned files absent from desired are released; shared files are not" do
    check all(desired <- int_desired(), extra <- int_desired(), extra != %{}) do
      owned_extra = Map.drop(extra, Map.keys(desired))

      last =
        Map.new(Map.merge(desired, owned_extra), fn {k, v} -> {k, %{applied: v, original: "x"}} end)

      ops = Reconcile.diff(observed_of(desired), desired, last)
      released = for {:release, f} <- ops, do: f

      assert Enum.sort(released) == Enum.sort(Map.keys(owned_extra))
    end
  end

  # --- cgroup-specific value shapes -----------------------------------------

  property ":max converges against a single-token \"max\" and cpu.max's \"max <period>\"" do
    check all(period <- integer(1000..1_000_000)) do
      assert Reconcile.diff(%{"memory.max" => "max"}, %{"memory.max" => :max}) == []
      assert Reconcile.diff(%{"cpu.max" => "max #{period}"}, %{"cpu.max" => :max}) == []
    end
  end

  property "{quota, period} converges iff the read-back matches token-for-token" do
    check all(q <- integer(1..1_000_000), p <- integer(1..1_000_000)) do
      assert Reconcile.diff(%{"cpu.max" => "#{q} #{p}"}, %{"cpu.max" => {q, p}}) == []
      # Any mismatch in either token is a :set.
      assert Reconcile.diff(%{"cpu.max" => "#{q} #{p + 1}"}, %{"cpu.max" => {q, p}}) ==
               [{:set, "cpu.max", {q, p}}]
    end
  end
end
