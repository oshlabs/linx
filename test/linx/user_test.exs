defmodule Linx.UserTest do
  use ExUnit.Case, async: true

  alias Linx.User

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(User.supported?())
    end

    test "agrees with the canonical filesystem check" do
      # supported?/0 is documented to return true iff
      # /proc/self/uid_map exists. Verify the two answers agree.
      assert User.supported?() == File.exists?("/proc/self/uid_map")
    end
  end

  describe "U1-U2 stubs" do
    # Every not-yet-shipped verb returns {:error, :not_yet_implemented}
    # so callers get a recognizable shape now and each function name is
    # visible in ExDoc + IDE completion immediately. The real
    # implementation lands in the milestone listed in the @doc.

    test "deny_setgroups/1" do
      assert {:error, :not_yet_implemented} = User.deny_setgroups(1)
    end

    test "set_uid_map/2" do
      assert {:error, :not_yet_implemented} = User.set_uid_map(1, [{0, 1000, 1}])
    end

    test "set_gid_map/2" do
      assert {:error, :not_yet_implemented} = User.set_gid_map(1, [{0, 1000, 1}])
    end

    test "read_uid_map/1" do
      assert {:error, :not_yet_implemented} = User.read_uid_map(1)
    end

    test "read_gid_map/1" do
      assert {:error, :not_yet_implemented} = User.read_gid_map(1)
    end

    test "setup_maps/2" do
      assert {:error, :not_yet_implemented} =
               User.setup_maps(1, uid: [{0, 1000, 1}], gid: [{0, 1000, 1}])
    end
  end
end
