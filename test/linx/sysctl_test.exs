defmodule Linx.SysctlTest do
  use ExUnit.Case, async: true

  alias Linx.Sysctl

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(Sysctl.supported?())
    end

    test "agrees with the canonical filesystem check" do
      # supported?/0 is documented to return true iff
      # /proc/sys/kernel/ostype exists. Verify the two answers agree.
      assert Sysctl.supported?() == File.exists?("/proc/sys/kernel/ostype")
    end
  end

  describe "S1-S2 stubs" do
    # Every not-yet-shipped verb returns {:error, :not_yet_implemented}
    # so callers get a recognizable shape now and each function name is
    # visible in ExDoc + IDE completion immediately. The real
    # implementation lands in the milestone listed in the @doc.

    test "read/1" do
      assert {:error, :not_yet_implemented} = Sysctl.read("net.ipv4.ip_forward")
    end

    test "read_int/1" do
      assert {:error, :not_yet_implemented} = Sysctl.read_int("net.ipv4.ip_forward")
    end

    test "read_ints/1" do
      assert {:error, :not_yet_implemented} = Sysctl.read_ints("kernel.printk")
    end

    test "write/2" do
      assert {:error, :not_yet_implemented} = Sysctl.write("net.ipv4.ip_forward", 1)
    end

    test "list/0" do
      assert {:error, :not_yet_implemented} = Sysctl.list()
    end

    test "list/1" do
      assert {:error, :not_yet_implemented} = Sysctl.list("net.ipv4")
    end
  end
end
