defmodule Linx.Cgroup.ReconcileTest do
  @moduledoc """
  Pure (`diff/4`) and live (`reconcile/4`) coverage for cgroup limits
  reconciliation. The `diff/4` and value-comparison logic needs no root, so it
  lives in the default suite; the apply path writes real cgroupfs interface
  files and so is `:integration` (run via `./sudotest.sh`).
  """
  use ExUnit.Case, async: true

  alias Linx.Cgroup
  alias Linx.Cgroup.Reconcile

  describe "diff/4 — value comparison" do
    test "an integer knob converges against its decimal read-back" do
      observed = %{"memory.max" => "268435456"}
      assert Reconcile.diff(observed, %{"memory.max" => 268_435_456}) == []
    end

    test "an integer knob that differs produces a :set" do
      observed = %{"pids.max" => "100"}
      assert Reconcile.diff(observed, %{"pids.max" => 200}) == [{:set, "pids.max", 200}]
    end

    test ":max converges against a single-token \"max\"" do
      observed = %{"memory.max" => "max"}
      assert Reconcile.diff(observed, %{"memory.max" => :max}) == []
    end

    test ":max converges against cpu.max's two-token \"max <period>\"" do
      observed = %{"cpu.max" => "max 100000"}
      assert Reconcile.diff(observed, %{"cpu.max" => :max}) == []
    end

    test "{quota, period} converges against the kernel's \"quota period\" form" do
      observed = %{"cpu.max" => "50000 100000"}
      assert Reconcile.diff(observed, %{"cpu.max" => {50_000, 100_000}}) == []
    end

    test "{quota, period} that differs produces a :set" do
      observed = %{"cpu.max" => "max 100000"}
      assert Reconcile.diff(observed, %{"cpu.max" => {50_000, 100_000}}) ==
               [{:set, "cpu.max", {50_000, 100_000}}]
    end

    test "an absent observed file always needs a write" do
      assert Reconcile.diff(%{}, %{"memory.max" => 1024}) == [{:set, "memory.max", 1024}]
    end

    test "a raw binary value compares exactly" do
      assert Reconcile.diff(%{"cpu.weight" => "100"}, %{"cpu.weight" => "100"}) == []
      assert Reconcile.diff(%{"cpu.weight" => "100"}, %{"cpu.weight" => "200"}) ==
               [{:set, "cpu.weight", "200"}]
    end
  end

  describe "diff/4 — release and revert" do
    test "a file that leaves the desired set is released by default" do
      last_applied = %{"pids.max" => %{applied: 100, original: "max"}}
      assert Reconcile.diff(%{}, %{}, last_applied) == [{:release, "pids.max"}]
    end

    test "revert_on_release writes the captured original back" do
      last_applied = %{"pids.max" => %{applied: 100, original: "max"}}

      assert Reconcile.diff(%{}, %{}, last_applied, revert_on_release: true) ==
               [{:revert, "pids.max", "max"}]
    end

    test "revert falls back to release when no original was captured" do
      last_applied = %{"pids.max" => %{applied: 100, original: nil}}

      assert Reconcile.diff(%{}, %{}, last_applied, revert_on_release: true) ==
               [{:release, "pids.max"}]
    end

    test "a still-desired file is not released" do
      last_applied = %{"pids.max" => %{applied: 100, original: "max"}}
      observed = %{"pids.max" => "100"}
      assert Reconcile.diff(observed, %{"pids.max" => 100}, last_applied) == []
    end
  end

  describe "C2 limits reconcile integration" do
    @describetag :integration

    # Mirrors the typed-setter integration setup: a child cgroup directly under
    # the root, where systemd hosts delegate memory/pids/cpu by default.
    setup do
      path = "/sys/fs/cgroup/linx-test-#{System.unique_integer([:positive])}"
      on_exit(fn -> _ = File.rmdir(path) end)
      {:ok, ^path} = Cgroup.create(path)
      {:ok, path: path}
    end

    test "converges memory.max and pids.max, and is idempotent", %{path: path} do
      desired = %{"memory.max" => 256 * 1024 * 1024, "pids.max" => 100}

      assert {:ok, r} = Reconcile.reconcile(path, desired)
      assert r.converged?
      assert {:ok, "268435456"} = Cgroup.read(path, "memory.max")
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")

      # A second pass with threaded ownership is a no-op.
      assert {:ok, r2} = Reconcile.reconcile(path, desired, r.last_applied)
      assert r2.converged?
      assert r2.applied == []
    end

    test "self-heals a manual change on the next pass", %{path: path} do
      desired = %{"pids.max" => 100}

      assert {:ok, r1} = Reconcile.reconcile(path, desired)
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")

      # Drift: change it by hand.
      :ok = Cgroup.set_pids_max(path, 50)
      assert {:ok, "50"} = Cgroup.read(path, "pids.max")

      assert {:ok, r2} = Reconcile.reconcile(path, desired, r1.last_applied)
      assert r2.converged?
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")
    end

    test "cpu.max {quota, period} and :max round-trip through reconcile", %{path: path} do
      assert {:ok, r1} = Reconcile.reconcile(path, %{"cpu.max" => {50_000, 100_000}})
      assert r1.converged?
      assert {:ok, "50000 100000"} = Cgroup.read(path, "cpu.max")

      assert {:ok, r2} = Reconcile.reconcile(path, %{"cpu.max" => :max}, r1.last_applied)
      assert r2.converged?
      {:ok, after_max} = Cgroup.read(path, "cpu.max")
      assert String.starts_with?(after_max, "max ")
    end

    test "a released file with revert_on_release restores the captured original", %{path: path} do
      # Capture the pre-management original (unlimited), set a limit, then drop
      # the file from desired with revert_on_release.
      assert {:ok, r1} = Reconcile.reconcile(path, %{"pids.max" => 100})
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")

      assert {:ok, r2} = Reconcile.reconcile(path, %{}, r1.last_applied, revert_on_release: true)
      assert r2.converged?
      assert [{:revert, "pids.max", "max"}] = r2.applied
      assert {:ok, "max"} = Cgroup.read(path, "pids.max")
    end

    test "a write to a missing knob lands in failed, not raising", %{path: path} do
      # No controller delegates this file, so the write fails — best-effort.
      assert {:ok, r} = Reconcile.reconcile(path, %{"nonsense.max" => 1})
      refute r.converged?
      assert [{{:set, "nonsense.max", 1}, %Cgroup.Error{}}] = r.failed
    end

    test "best-effort: a failing knob never starves the others in the same pass", %{path: path} do
      # One valid knob and one bogus one: best-effort attempts both, so the
      # valid one still applies while the bogus one is reported as failed —
      # and pending stays empty (only fail-fast subsystems leave work pending).
      assert {:ok, r} = Reconcile.reconcile(path, %{"pids.max" => 100, "nonsense.max" => 1})

      refute r.converged?
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")
      assert [{:set, "pids.max", 100}] = r.applied
      assert [{{:set, "nonsense.max", 1}, %Cgroup.Error{}}] = r.failed
      assert r.pending == []
      # The successful knob is owned; the failed one is not claimed.
      assert Map.has_key?(r.last_applied, "pids.max")
      refute Map.has_key?(r.last_applied, "nonsense.max")
    end

    test "the opt-in loop drives the cgroup source and self-heals drift", %{path: path} do
      pid =
        start_supervised!(
          {Linx.Reconcile,
           source: Linx.Cgroup.Reconcile.Source,
           scope: path,
           desired: %{"pids.max" => 100},
           interval: 100}
        )

      assert eventually(fn -> Cgroup.read(path, "pids.max") == {:ok, "100"} end)

      # Drift, then let the timer pass restore it.
      :ok = Cgroup.set_pids_max(path, 50)
      assert eventually(fn -> Cgroup.read(path, "pids.max") == {:ok, "100"} end)

      assert {:ok, report} = Linx.Reconcile.reconcile(pid)
      assert report.converged?
    end
  end

  defp eventually(fun, timeout \\ 2_000, step \\ 25) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_eventually(fun, deadline, step)
  end

  defp do_eventually(fun, deadline, step) do
    cond do
      fun.() -> true
      System.monotonic_time(:millisecond) >= deadline -> false
      true -> Process.sleep(step) && do_eventually(fun, deadline, step)
    end
  end
end
