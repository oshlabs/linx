defmodule Linx.Netlink.Rtnl.ReconcileTest do
  use ExUnit.Case, async: true

  import Linx.IP
  alias Linx.Netlink.Rtnl.{Address, Reconcile, Route}

  # --- pure: normalize ------------------------------------------------------

  describe "normalize/3" do
    @by_name %{"eth0" => 2, "eth1" => 3}

    test "resolves an interface name to its index, parses the address" do
      desired = %{addresses: [{"eth0", "10.0.0.2", 24}]}
      assert {:ok, %{addresses: [addr]}} = Reconcile.normalize(desired, @by_name, 76)
      assert %Address{index: 2, address: ~IP"10.0.0.2", prefixlen: 24, family: 2, scope: 0} = addr
    end

    test "an unknown interface is a normalize error (nothing is built)" do
      desired = %{addresses: [{"wlan9", "10.0.0.2", 24}]}

      assert {:error, {:normalize, {:unknown_interface, "wlan9"}}} =
               Reconcile.normalize(desired, @by_name, 76)
    end

    test "an unparseable address is a normalize error" do
      desired = %{addresses: [{"eth0", "not-an-ip", 24}]}

      assert {:error, {:normalize, {:bad_address, _}}} =
               Reconcile.normalize(desired, @by_name, 76)
    end

    test "routes are built and tagged with the ownership protocol" do
      desired = %{routes: [{"10.50.0.0", 24, "10.0.0.1", table: 100}, {:default, "10.0.0.1"}]}
      assert {:ok, %{routes: [r1, r2]}} = Reconcile.normalize(desired, @by_name, 76)
      assert r1.protocol == 76
      assert Route.target_table(r1) == 100
      assert r2.protocol == 76
      # :default resolves to 0.0.0.0/0.
      assert r2.dst_len == 0
      assert r2.dst == ~IP"0.0.0.0"
    end

    test "the per-route :protocol cannot override the reconciler's ownership tag" do
      desired = %{routes: [{"10.50.0.0", 24, "10.0.0.1", protocol: :kernel}]}
      assert {:ok, %{routes: [r]}} = Reconcile.normalize(desired, @by_name, 76)
      assert r.protocol == 76
    end

    test "a malformed route spec is a normalize error" do
      desired = %{routes: [{"10.0.0.0", 24, "fc00::1"}]}

      assert {:error, {:normalize, {:route, {:family_mismatch, _}}}} =
               Reconcile.normalize(desired, @by_name, 76)
    end

    test "an empty desired normalizes to empty resource lists" do
      assert {:ok, %{addresses: [], routes: []}} = Reconcile.normalize(%{}, @by_name, 76)
    end
  end

  # --- pure: order_ops ------------------------------------------------------

  describe "order_ops/2" do
    test "addresses come up before routes; routes tear down before addresses" do
      addr_c = {:create, %Address{index: 2, address: ~IP"10.0.0.2", prefixlen: 24}}
      addr_d = {:delete, %Address{index: 2, address: ~IP"10.0.0.9", prefixlen: 24}}
      route_c = {:create, %Route{dst: ~IP"10.50.0.0", dst_len: 24}}
      route_u = {:update, %Route{dst: ~IP"10.60.0.0", dst_len: 24}}
      route_d = {:delete, %Route{dst: ~IP"10.70.0.0", dst_len: 24}}

      ordered = Reconcile.order_ops([addr_c, addr_d], [route_c, route_u, route_d])

      assert ordered == [addr_c, route_c, route_u, route_d, addr_d]
    end
  end

  test "default_protocol/0 is 76 (ASCII 'L')" do
    assert Reconcile.default_protocol() == ?L
    assert Reconcile.default_protocol() == 76
  end
end
