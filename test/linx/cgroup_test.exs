defmodule Linx.CgroupTest do
  use ExUnit.Case, async: true

  alias Linx.Cgroup

  describe "supported?/0" do
    test "returns a boolean" do
      # Whether the test host actually has cgroup v2 mounted varies;
      # we just assert the function answers in the expected shape.
      assert is_boolean(Cgroup.supported?())
    end

    test "agrees with the canonical filesystem check" do
      # The function is documented to return true iff
      # /sys/fs/cgroup/cgroup.controllers exists. Verify the two
      # answers agree.
      assert Cgroup.supported?() == File.exists?("/sys/fs/cgroup/cgroup.controllers")
    end
  end

  describe "C1-C4 stubs" do
    # Every not-yet-shipped verb returns {:error, :not_yet_implemented}
    # so callers get a recognizable shape (no MatchError, no NIF
    # exception). Each is replaced with its real implementation in
    # the milestone listed in the @doc.

    test "create/1" do
      assert {:error, :not_yet_implemented} = Cgroup.create("/sys/fs/cgroup/linx-test")
    end

    test "destroy/1" do
      assert {:error, :not_yet_implemented} = Cgroup.destroy("/sys/fs/cgroup/linx-test")
    end

    test "add_process/2" do
      assert {:error, :not_yet_implemented} = Cgroup.add_process("/sys/fs/cgroup/x", 1)
    end

    test "read/2" do
      assert {:error, :not_yet_implemented} = Cgroup.read("/sys/fs/cgroup/x", "memory.current")
    end

    test "write/3" do
      assert {:error, :not_yet_implemented} = Cgroup.write("/sys/fs/cgroup/x", "memory.max", 0)
    end

    test "freeze/1" do
      assert {:error, :not_yet_implemented} = Cgroup.freeze("/sys/fs/cgroup/x")
    end

    test "thaw/1" do
      assert {:error, :not_yet_implemented} = Cgroup.thaw("/sys/fs/cgroup/x")
    end

    test "set_memory_max/2" do
      assert {:error, :not_yet_implemented} = Cgroup.set_memory_max("/sys/fs/cgroup/x", 0)
    end

    test "set_pids_max/2" do
      assert {:error, :not_yet_implemented} = Cgroup.set_pids_max("/sys/fs/cgroup/x", 0)
    end

    test "set_cpu_max/2" do
      assert {:error, :not_yet_implemented} = Cgroup.set_cpu_max("/sys/fs/cgroup/x", :max)
    end

    test "enable_controllers/2" do
      assert {:error, :not_yet_implemented} = Cgroup.enable_controllers("/sys/fs/cgroup/x", [:memory])
    end

    test "stats/1" do
      assert {:error, :not_yet_implemented} = Cgroup.stats("/sys/fs/cgroup/x")
    end
  end
end
