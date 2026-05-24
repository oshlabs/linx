defmodule Linx.UserTest do
  use ExUnit.Case, async: true

  alias Linx.User
  alias Linx.User.Error

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(User.supported?())
    end

    test "agrees with the canonical filesystem check" do
      assert User.supported?() == File.exists?("/proc/self/uid_map")
    end
  end

  describe "Linx.User.Error" do
    test "@enforce_keys covers path, operation, errno" do
      assert_raise ArgumentError, fn ->
        struct!(Error, %{})
      end
    end

    test "from_posix/3 builds a struct with code looked up from the POSIX table" do
      err = Error.from_posix(:eperm, "/proc/1234/uid_map", :set_uid_map)
      assert %Error{
               path: "/proc/1234/uid_map",
               operation: :set_uid_map,
               errno: :eperm,
               code: 1
             } = err
    end

    test "from_posix/3 leaves :code at nil for unmapped errnos" do
      err = Error.from_posix(:eweirdthing, "/x", :read_uid_map)
      assert %Error{errno: :eweirdthing, code: nil} = err
    end

    test "Exception.message/1 renders cleanly" do
      err = Error.from_posix(:enoent, "/proc/9999/uid_map", :set_uid_map)

      assert Exception.message(err) ==
               "user set_uid_map failed on /proc/9999/uid_map: enoent (errno 2)"
    end

    test "an error can be raised" do
      err = Error.from_posix(:einval, "/proc/1/gid_map", :set_gid_map)

      assert_raise Error,
                   "user set_gid_map failed on /proc/1/gid_map: einval (errno 22)",
                   fn -> raise err end
    end
  end

  describe "set_uid_map/2 input validation (plain)" do
    # These exercise the {:bad_map, reason} path -- no /proc write
    # is attempted, so no root needed and the target pid is
    # irrelevant.

    test "an empty list is rejected" do
      assert {:error, {:bad_map, :empty}} = User.set_uid_map(1, [])
    end

    test "a non-list mappings argument is rejected" do
      assert {:error, {:bad_map, :not_a_list}} = User.set_uid_map(1, :nope)
    end

    test "a non-tuple entry is rejected" do
      assert {:error, {:bad_map, {:bad_entry, :totally_wrong}}} =
               User.set_uid_map(1, [:totally_wrong])
    end

    test "a wrong-arity tuple is rejected" do
      assert {:error, {:bad_map, {:bad_entry, {0, 1000}}}} =
               User.set_uid_map(1, [{0, 1000}])
    end

    test "a negative inside id is rejected" do
      assert {:error, {:bad_map, {:bad_entry, {-1, 1000, 1}}}} =
               User.set_uid_map(1, [{-1, 1000, 1}])
    end

    test "a negative outside id is rejected" do
      assert {:error, {:bad_map, {:bad_entry, {0, -5, 1}}}} =
               User.set_uid_map(1, [{0, -5, 1}])
    end

    test "a zero length is rejected" do
      assert {:error, {:bad_map, {:bad_entry, {0, 1000, 0}}}} =
               User.set_uid_map(1, [{0, 1000, 0}])
    end

    test "a negative length is rejected" do
      assert {:error, {:bad_map, {:bad_entry, {0, 1000, -1}}}} =
               User.set_uid_map(1, [{0, 1000, -1}])
    end

    test "a partially valid list halts on the first bad entry" do
      assert {:error, {:bad_map, {:bad_entry, {-1, 0, 1}}}} =
               User.set_uid_map(1, [{0, 1000, 1}, {-1, 0, 1}, {2, 2000, 1}])
    end
  end

  describe "set_gid_map/2 input validation" do
    test "shares set_uid_map/2's validation -- empty list rejected" do
      assert {:error, {:bad_map, :empty}} = User.set_gid_map(1, [])
    end

    test "shares the bad-entry rejection" do
      assert {:error, {:bad_map, {:bad_entry, {0, -1, 1}}}} =
               User.set_gid_map(1, [{0, -1, 1}])
    end
  end

  describe "verbs against a non-existent pid (plain failure)" do
    # A pid that's well past any live process: /proc/<pid>/ doesn't
    # exist, so we should get a structured error from File.write/2's
    # ENOENT.
    @nope_pid 2_147_483_640

    test "deny_setgroups/1 on a dead pid returns ENOENT" do
      assert {:error, %Error{operation: :deny_setgroups, errno: errno, path: path}} =
               User.deny_setgroups(@nope_pid)

      assert errno in [:enoent, :eacces]
      assert path == "/proc/#{@nope_pid}/setgroups"
    end

    test "set_uid_map/2 on a dead pid returns ENOENT" do
      assert {:error, %Error{operation: :set_uid_map, errno: errno, path: path}} =
               User.set_uid_map(@nope_pid, [{0, 1000, 1}])

      assert errno in [:enoent, :eacces]
      assert path == "/proc/#{@nope_pid}/uid_map"
    end

    test "set_gid_map/2 on a dead pid returns ENOENT" do
      assert {:error, %Error{operation: :set_gid_map, errno: errno, path: path}} =
               User.set_gid_map(@nope_pid, [{0, 1000, 1}])

      assert errno in [:enoent, :eacces]
      assert path == "/proc/#{@nope_pid}/gid_map"
    end
  end

  describe "U2 stubs" do
    # Until U2 lands, the read side + setup_maps/2 return
    # :not_yet_implemented.

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

  describe "U1 integration: rootless mapping at the checkpoint" do
    @describetag :integration

    test "the canonical 'root inside ↔ me outside' rootless dance" do
      # Spawn a workload in a fresh :user namespace. Without any
      # map written, the kernel defaults inside-uid to nobody
      # (65534). With our map, inside-uid 0 (root) maps to the
      # test runner's real uid -- which is what makes the rootless
      # container story work.
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "10"],
          namespaces: [:user]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      # Pre-write: /proc/<host_pid>/uid_map exists but is empty
      # (or shows the default no-mapping shape).
      uid_map_path = "/proc/#{host_pid}/uid_map"
      pre = File.read!(uid_map_path)
      assert String.trim(pre) == ""

      # Find a real uid to map to. Use the test runner's own
      # uid -- since we're running under sudo from sudotest.sh,
      # that's 0 (root). Either way it's a real uid the kernel
      # accepts as a target.
      my_uid = host_uid()
      my_gid = host_gid()

      # Setgroups deny is required before gid_map writes from
      # unprivileged callers; under sudo we're privileged so we
      # could skip it, but exercising the verb is the point of
      # the test.
      assert :ok = Linx.User.deny_setgroups(host_pid)

      assert :ok = Linx.User.set_uid_map(host_pid, [{0, my_uid, 1}])
      assert :ok = Linx.User.set_gid_map(host_pid, [{0, my_gid, 1}])

      # Post-write: /proc/<host_pid>/uid_map shows the kernel's
      # canonical "inside outside length" rendering -- the kernel
      # right-pads each id to 10 chars, so we substring-match
      # rather than equality-match.
      post = File.read!(uid_map_path)
      assert String.contains?(post, "0")
      assert String.contains?(post, Integer.to_string(my_uid))
      assert String.contains?(post, "1\n") or String.contains?(post, " 1\n")

      # gid_map shows the same shape.
      gid_post = File.read!("/proc/#{host_pid}/gid_map")
      assert String.contains?(gid_post, Integer.to_string(my_gid))

      # We don't proceed -- the rootfs would need /bin/sleep to be
      # reachable post-:user-namespace, which it is, but the
      # workload would just run and exit. The interesting
      # observation already happened. Discard the session via
      # abort.
      assert :ok = Linx.Process.abort(c)
      assert_receive {:linx_process, :aborted}, 5_000
    end

    test "set_uid_map/2 is write-once -- a second call returns EPERM" do
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "10"],
          namespaces: [:user]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      assert :ok = Linx.User.set_uid_map(host_pid, [{0, host_uid(), 1}])

      # Second write attempts to remap; kernel refuses.
      assert {:error, %Error{operation: :set_uid_map, errno: :eperm}} =
               Linx.User.set_uid_map(host_pid, [{0, host_uid(), 1}])

      assert :ok = Linx.Process.abort(c)
      assert_receive {:linx_process, :aborted}, 5_000
    end

    test "deny_setgroups/1 is idempotent" do
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "10"],
          namespaces: [:user]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      assert :ok = Linx.User.deny_setgroups(host_pid)
      # Writing "deny" again over an already-denied setgroups is
      # accepted (the kernel sees deny == current state and is
      # happy).
      assert :ok = Linx.User.deny_setgroups(host_pid)

      # /proc/<pid>/setgroups now reads "deny".
      assert "deny" = File.read!("/proc/#{host_pid}/setgroups") |> String.trim()

      assert :ok = Linx.Process.abort(c)
      assert_receive {:linx_process, :aborted}, 5_000
    end
  end

  # Test-runner's host uid/gid; under `./sudotest.sh` these are
  # root's (0/0), under plain `mix test --include integration` they
  # would be the developer's uid. Either way we get a real id the
  # kernel will accept as a map target.
  defp host_uid do
    {out, 0} = System.cmd("id", ["-u"])
    out |> String.trim() |> String.to_integer()
  end

  defp host_gid do
    {out, 0} = System.cmd("id", ["-g"])
    out |> String.trim() |> String.to_integer()
  end
end
