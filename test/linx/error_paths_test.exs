defmodule Linx.ErrorPathsTest do
  use ExUnit.Case, async: true

  # End-to-end error paths through the pure-Elixir read verbs: each drives a
  # real read of a guaranteed-absent procfs / cgroupfs target and asserts the
  # full pipeline produces the right %X.Error{} struct (errno mapped, the
  # operation tagged, a usable message/1). No privilege required — these are
  # reads of nonexistent paths, so they also run in CI.

  # Far above any plausible pid_max, so /proc/<pid> never exists.
  @absent_pid 2_000_000_000
  @absent_cgroup "/sys/fs/cgroup/linx-nonexistent-#{:erlang.unique_integer([:positive])}"

  defp assert_usable_message(err) do
    msg = Exception.message(err)
    assert is_binary(msg) and msg != ""
  end

  test "Linx.Cgroup.stats/1 on an absent cgroup returns an ENOENT error" do
    assert {:error, %Linx.Cgroup.Error{operation: :stats, errno: :enoent} = err} =
             Linx.Cgroup.stats(@absent_cgroup)

    assert_usable_message(err)
  end

  test "Linx.Cgroup.read/2 on an absent interface file returns an ENOENT error" do
    assert {:error, %Linx.Cgroup.Error{operation: :read, errno: :enoent} = err} =
             Linx.Cgroup.read(@absent_cgroup, "memory.current")

    assert_usable_message(err)
  end

  test "Linx.Capabilities.read/1 on an absent pid returns an ENOENT error" do
    assert {:error, %Linx.Capabilities.Error{operation: :read, errno: :enoent} = err} =
             Linx.Capabilities.read(@absent_pid)

    assert_usable_message(err)
  end

  test "Linx.User.read_uid_map/1 on an absent pid returns an ENOENT error" do
    assert {:error, %Linx.User.Error{operation: :read_uid_map, errno: :enoent} = err} =
             Linx.User.read_uid_map(@absent_pid)

    assert_usable_message(err)
  end

  test "Linx.Sysctl.read/1 on a well-formed but absent key returns an ENOENT error" do
    assert {:error, %Linx.Sysctl.Error{operation: :read, errno: :enoent} = err} =
             Linx.Sysctl.read("linx.nonexistent.key")

    assert_usable_message(err)
  end
end
