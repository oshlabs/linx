defmodule Linx.Netfilter.FlowtableTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.Flowtable

  describe "new/2" do
    test "builds a flowtable" do
      assert {:ok,
              %Flowtable{
                name: "ft1",
                hook: :ingress,
                priority: 0,
                devices: ["eth0", "eth1"]
              }} =
               Flowtable.new("ft1",
                 hook: :ingress,
                 priority: 0,
                 devices: ["eth0", "eth1"]
               )
    end

    test "accepts :hw_offload flag" do
      assert {:ok, %Flowtable{flags: [:hw_offload]}} =
               Flowtable.new("ft1", flags: [:hw_offload])
    end

    test "rejects unknown flag" do
      assert {:error, {:bad_flowtable, {:unknown_flag, :weird}}} =
               Flowtable.new("ft1", flags: [:weird])
    end

    test "rejects empty device strings" do
      assert {:error, {:bad_flowtable, {:bad_device, ""}}} =
               Flowtable.new("ft1", devices: [""])
    end

    test "rejects non-binary devices" do
      assert {:error, {:bad_flowtable, {:bad_device, :eth0}}} =
               Flowtable.new("ft1", devices: [:eth0])
    end

    test "rejects empty name" do
      assert {:error, {:bad_flowtable, :name_empty}} = Flowtable.new("")
    end
  end

  describe "new!/2" do
    test "raises on invalid input" do
      assert_raise ArgumentError, ~r/invalid flowtable/, fn ->
        Flowtable.new!("ft1", flags: [:weird])
      end
    end
  end
end
