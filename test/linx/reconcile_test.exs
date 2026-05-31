defmodule Linx.ReconcileTest do
  @moduledoc """
  Exercises the generic `Linx.Reconcile` loop mechanics against a fake
  `Linx.Reconcile.Source` — no kernel involved. The subsystem adapters
  (sysctl, rtnl) and their end-to-end self-healing are covered by the
  `:integration` suite (`./sudotest.sh`); here we pin down the loop itself:
  the immediate first pass, `last_applied` threading, desired updates,
  debounced Monitor wakeups, error survival, and the `:unsupported` fallback.
  """
  use ExUnit.Case, async: true

  alias Linx.Reconcile

  # A source whose `reconcile/4` reports each call to a test pid and threads
  # `desired` as the next `last_applied`, so the test can watch state flow.
  # `scope` is a map carrying the test pid and how `subscribe/2` should behave.
  defmodule FakeSource do
    @behaviour Linx.Reconcile.Source

    @impl true
    def reconcile(%{test: test} = scope, desired, last_applied, opts) do
      send(test, {:reconciled, desired, last_applied, opts})

      case scope[:fail] do
        true -> {:error, :boom}
        _ -> {:ok, %{converged?: true, last_applied: desired, applied: [], failed: [], pending: []}}
      end
    end

    @impl true
    # When `:monitor` is a pid, hand it back as the monitor so the loop's
    # wakeup path is active; the test then sends the loop hint messages itself.
    def subscribe(%{monitor: monitor}, _owner) when is_pid(monitor), do: {:ok, monitor}
    def subscribe(_scope, _owner), do: :unsupported
  end

  defp start_loop(overrides) do
    opts =
      [
        source: FakeSource,
        scope: %{test: self()},
        desired: :v1,
        interval: :infinity,
        monitor: false,
        owner: self()
      ]
      |> Keyword.merge(overrides)

    pid = start_supervised!({Reconcile, opts})
    pid
  end

  test "runs an immediate first pass starting from empty last_applied" do
    start_loop([])
    assert_receive {:reconciled, :v1, %{}, []}
  end

  test "threads last_applied from the report into the next pass" do
    pid = start_loop([])
    assert_receive {:reconciled, :v1, %{}, _opts}

    # Force a synchronous second pass; it should carry the prior report's
    # last_applied (which the fake set to the desired value).
    assert {:ok, %{converged?: true}} = Reconcile.reconcile(pid)
    assert_receive {:reconciled, :v1, :v1, _opts}
  end

  test "forwards reconcile_opts verbatim" do
    start_loop(reconcile_opts: [protocol: 99])
    assert_receive {:reconciled, :v1, %{}, [protocol: 99]}
  end

  test "put_desired/2 swaps desired and converges on it" do
    pid = start_loop(debounce: 5)
    assert_receive {:reconciled, :v1, _la, _opts}

    :ok = Reconcile.put_desired(pid, :v2)
    assert_receive {:reconciled, :v2, _la, _opts}
  end

  test "notifies the owner with the report after each pass" do
    start_loop([])
    assert_receive {:linx_reconcile, :report, %{converged?: true, last_applied: :v1}}
  end

  @tag capture_log: true
  test "a failing pass does not crash the loop and keeps prior last_applied" do
    pid = start_loop(scope: %{test: self(), fail: true})

    assert_receive {:reconciled, :v1, %{}, _opts}
    assert_receive {:linx_reconcile, :error, :boom}

    # Still alive, still serving — and last_applied was not advanced past %{}.
    assert {:error, :boom} = Reconcile.reconcile(pid)
    assert_receive {:reconciled, :v1, %{}, _opts}
    assert Process.alive?(pid)
  end

  describe "monitor wakeups" do
    test "a monitor hint triggers a debounced reconcile" do
      pid = start_loop(monitor: true, scope: %{test: self(), monitor: self()}, debounce: 5)
      assert_receive {:reconciled, :v1, _la, _opts}

      # Any message (the loop never inspects the payload) is a "look now" hint.
      send(pid, {:linx_rtnl, :resync_needed})
      assert_receive {:reconciled, :v1, _la, _opts}
    end

    test "a burst of hints collapses into a single pass" do
      pid = start_loop(monitor: true, scope: %{test: self(), monitor: self()}, debounce: 30)
      assert_receive {:reconciled, :v1, _la, _opts}

      for _ <- 1..10, do: send(pid, {:linx_rtnl, :event, :x})

      assert_receive {:reconciled, :v1, _la, _opts}
      refute_receive {:reconciled, _, _, _}, 80
    end

    test "without a monitor, stray messages are ignored" do
      pid = start_loop(monitor: false)
      assert_receive {:reconciled, :v1, _la, _opts}

      send(pid, {:linx_rtnl, :resync_needed})
      refute_receive {:reconciled, _, _, _}, 80
    end

    test "an :unsupported source falls back to timer-only" do
      # monitor: true requested, but the fake returns :unsupported for a scope
      # without a monitor pid → no monitor, hints ignored.
      pid = start_loop(monitor: true, scope: %{test: self()})
      assert_receive {:reconciled, :v1, _la, _opts}

      send(pid, {:linx_rtnl, :resync_needed})
      refute_receive {:reconciled, _, _, _}, 80
    end
  end

  test "the timer drives periodic resync passes" do
    start_loop(interval: 20)
    assert_receive {:reconciled, :v1, _la, _opts}
    assert_receive {:reconciled, :v1, _la, _opts}
    assert_receive {:reconciled, :v1, _la, _opts}
  end

  test "child_spec/1 honours :name as the id and is startable" do
    spec = Reconcile.child_spec(source: FakeSource, scope: %{test: self()}, desired: :v1, name: :foo)
    assert spec.id == :foo
    assert {Reconcile, :start_link, [opts]} = spec.start
    refute Keyword.has_key?(opts, :id)
  end

  test "last_report/1 returns the most recent report" do
    pid = start_loop([])
    assert_receive {:reconciled, :v1, _la, _opts}
    assert %{converged?: true, last_applied: :v1} = Reconcile.last_report(pid)
  end
end
