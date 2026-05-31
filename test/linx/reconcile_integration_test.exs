defmodule Linx.ReconcileIntegrationTest do
  @moduledoc """
  End-to-end self-healing through the opt-in `Linx.Reconcile` loop, driving the
  real sysctl and rtnl `Source` adapters against the live kernel in a throwaway
  network namespace. Needs root and `iproute2`; tagged `:integration` (run via
  `./sudotest.sh`).

  These tests prove the loop's reason to exist: declare desired state, mutate
  the kernel out from under it by hand, and watch it converge back — both on the
  periodic timer (the correctness mechanism) and via a Monitor wakeup (the
  latency layer).
  """
  use ExUnit.Case, async: false

  alias Linx.Netlink.{Rtnl, Socket}
  alias Linx.Netlink.Rtnl.{Address, Link}
  alias Linx.Reconcile

  @moduletag :integration
  @moduletag capture_log: true

  setup do
    netns = "linx_test_#{System.unique_integer([:positive])}"
    {_, 0} = System.cmd("ip", ~w(netns add #{netns}), stderr_to_stdout: true)
    on_exit(fn -> System.cmd("ip", ~w(netns del #{netns})) end)

    {_, 0} = System.cmd("ip", ~w(-n #{netns} link add dummy0 type dummy), stderr_to_stdout: true)

    netns_path = "/var/run/netns/#{netns}"
    {:ok, socket} = Rtnl.open({:path, netns_path})
    on_exit(fn -> Socket.close(socket) end)
    :ok = Link.set_up(socket, "dummy0")

    %{socket: socket, netns_path: netns_path, scope: {:path, netns_path}}
  end

  describe "rtnl source" do
    test "converges the desired address and re-heals a manual deletion (timer)", ctx do
      desired = %{addresses: [{"dummy0", "10.99.0.5", 24}]}

      pid =
        start_supervised!(
          {Reconcile,
           source: Linx.Netlink.Rtnl.Reconcile.Source,
           scope: ctx.scope,
           desired: desired,
           interval: 100,
           monitor: false}
        )

      assert eventually(fn -> address_present?(ctx.socket, "10.99.0.5", 24) end)

      # Drift: delete it behind the loop's back.
      :ok = Address.delete(ctx.socket, "dummy0", "10.99.0.5", 24)
      refute address_present?(ctx.socket, "10.99.0.5", 24)

      # The next timer pass restores it.
      assert eventually(fn -> address_present?(ctx.socket, "10.99.0.5", 24) end)

      assert {:ok, report} = Reconcile.reconcile(pid)
      assert report.converged?
    end

    test "re-heals a manual deletion via a Monitor wakeup (no timer)", ctx do
      desired = %{addresses: [{"dummy0", "10.99.0.7", 24}]}

      start_supervised!(
        {Reconcile,
         source: Linx.Netlink.Rtnl.Reconcile.Source,
         scope: ctx.scope,
         desired: desired,
         interval: :infinity,
         monitor: true,
         debounce: 20}
      )

      assert eventually(fn -> address_present?(ctx.socket, "10.99.0.7", 24) end)

      :ok = Address.delete(ctx.socket, "dummy0", "10.99.0.7", 24)
      # No timer is running, so only the Monitor wakeup can restore it.
      assert eventually(fn -> address_present?(ctx.socket, "10.99.0.7", 24) end)
    end
  end

  describe "sysctl source" do
    test "converges a per-namespace sysctl and re-heals a manual change", ctx do
      key = "net.ipv4.ip_forward"
      desired = %{key => 1}

      pid =
        start_supervised!(
          {Reconcile,
           source: Linx.Sysctl.Reconcile.Source, scope: ctx.scope, desired: desired, interval: 100}
        )

      assert eventually(fn -> Linx.Sysctl.read(key, in: ctx.scope) == {:ok, "1"} end)

      # Drift: flip it back to 0 by hand.
      :ok = Linx.Sysctl.write(key, 0, in: ctx.scope)
      assert eventually(fn -> Linx.Sysctl.read(key, in: ctx.scope) == {:ok, "1"} end)

      assert {:ok, report} = Reconcile.reconcile(pid)
      assert report.converged?
    end
  end

  # --- helpers --------------------------------------------------------------

  defp address_present?(socket, ip, prefixlen) do
    {:ok, want} = Linx.IP.parse(ip)
    {:ok, addrs} = Address.list(socket)
    Enum.any?(addrs, fn a -> a.address == want and a.prefixlen == prefixlen end)
  end

  # Polls `fun` until it returns truthy or the timeout elapses.
  defp eventually(fun, timeout \\ 2_000, step \\ 25) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_eventually(fun, deadline, step)
  end

  defp do_eventually(fun, deadline, step) do
    cond do
      fun.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(step)
        do_eventually(fun, deadline, step)
    end
  end
end
