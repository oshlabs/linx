defmodule Linx.CgroupTest do
  use ExUnit.Case, async: true

  alias Linx.Cgroup
  alias Linx.Cgroup.Error

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(Cgroup.supported?())
    end

    test "agrees with the canonical filesystem check" do
      assert Cgroup.supported?() == File.exists?("/sys/fs/cgroup/cgroup.controllers")
    end
  end

  describe "Linx.Cgroup.Error" do
    test "enforces required keys" do
      # path, operation and errno are all @enforce_keys.
      assert_raise ArgumentError, fn ->
        struct!(Error, %{})
      end
    end

    test "from_posix/3 builds a struct with code looked up from the POSIX table" do
      err = Error.from_posix(:eexist, "/sys/fs/cgroup/test", :create)
      assert %Error{path: "/sys/fs/cgroup/test", operation: :create, errno: :eexist, code: 17} =
               err
    end

    test "from_posix/3 leaves :code at nil for unmapped errnos" do
      err = Error.from_posix(:eweirdthing, "/x", :read)
      assert %Error{errno: :eweirdthing, code: nil} = err
    end

    test "Exception.message/1 renders cleanly with errno integer" do
      err = Error.from_posix(:ebusy, "/sys/fs/cgroup/x", :destroy)
      assert Exception.message(err) == "cgroup destroy failed on /sys/fs/cgroup/x: ebusy (errno 16)"
    end

    test "Exception.message/1 renders cleanly without errno integer for unmapped" do
      err = Error.from_posix(:eweirdthing, "/x", :read)
      assert Exception.message(err) == "cgroup read failed on /x: eweirdthing"
    end

    test "an error can be raised" do
      err = Error.from_posix(:enoent, "/sys/fs/cgroup/nope", :read)

      assert_raise Error, "cgroup read failed on /sys/fs/cgroup/nope: enoent (errno 2)", fn ->
        raise err
      end
    end
  end

  describe "C1 verbs against a non-existent path" do
    # These exercise the error-mapping path without needing root.
    # Anything under /sys/fs/cgroup/linx-doesnotexist-* should fail
    # with a structured Error.

    @nope "/sys/fs/cgroup/linx-doesnotexist-#{System.unique_integer([:positive])}"

    test "create/1 in a non-existent parent returns a structured error" do
      # `mkdir /sys/fs/cgroup/this/that/...` should fail with ENOENT
      # (parent missing) or EACCES (not root). Either way: structured.
      path = Path.join(@nope, "child")

      assert {:error, %Error{path: ^path, operation: :create, errno: errno}} =
               Cgroup.create(path)

      assert errno in [:enoent, :eacces, :erofs, :eperm]
    end

    test "destroy/1 of a missing cgroup returns ENOENT" do
      assert {:error, %Error{operation: :destroy, errno: errno}} = Cgroup.destroy(@nope)
      assert errno in [:enoent, :eacces]
    end

    test "read/2 of a missing interface file returns ENOENT" do
      assert {:error, %Error{operation: :read, errno: errno, path: path}} =
               Cgroup.read(@nope, "memory.current")

      assert errno in [:enoent, :eacces]
      assert String.ends_with?(path, "memory.current")
    end

    test "write/3 of a missing interface file returns a structured error" do
      assert {:error, %Error{operation: :write, errno: errno}} =
               Cgroup.write(@nope, "memory.max", 1024)

      assert errno in [:enoent, :eacces]
    end

    test "add_process/2 against a missing cgroup returns a structured error" do
      assert {:error, %Error{operation: :add_process, errno: errno, path: path}} =
               Cgroup.add_process(@nope, 1)

      assert errno in [:enoent, :eacces]
      assert String.ends_with?(path, "cgroup.procs")
    end
  end

  describe "C1 integration round-trip" do
    @moduletag :integration

    # Real cgroup operations against /sys/fs/cgroup. Needs root + a
    # cgroup v2 unified hierarchy. Each test gets its own
    # uniquely-named cgroup under /sys/fs/cgroup/linx-test-N and
    # cleans up via on_exit.

    setup do
      path = "/sys/fs/cgroup/linx-test-#{System.unique_integer([:positive])}"
      on_exit(fn -> _ = File.rmdir(path) end)
      {:ok, path: path}
    end

    test "create → write → read → destroy round-trip", %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)
      assert File.dir?(path)

      # `cgroup.max.descendants` is a writable, harmless interface
      # file present on every v2 cgroup -- a good neutral target for
      # round-trip testing without enabling controllers.
      assert :ok = Cgroup.write(path, "cgroup.max.descendants", 42)
      assert {:ok, "42"} = Cgroup.read(path, "cgroup.max.descendants")

      assert :ok = Cgroup.destroy(path)
      refute File.dir?(path)
    end

    test "create/1 is idempotent against EEXIST", %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)
      assert {:ok, ^path} = Cgroup.create(path)
      assert :ok = Cgroup.destroy(path)
    end

    test "read/2 returns a trimmed string", %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)

      # cgroup.type is read-only and present on every v2 cgroup;
      # the raw content is "domain\n" -- the trim is what we're
      # testing here.
      assert {:ok, "domain"} = Cgroup.read(path, "cgroup.type")

      assert :ok = Cgroup.destroy(path)
    end

    test "destroy/1 fails with EBUSY when the cgroup still has processes",
         %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)

      # Move the test process itself in, then try to destroy --
      # kernel must refuse. Move out by writing back to the root
      # cgroup's procs (cleanup), then destroy succeeds.
      beam_pid = System.pid() |> String.to_integer()
      assert :ok = Cgroup.add_process(path, beam_pid)

      assert {:error, %Error{operation: :destroy, errno: :ebusy}} =
               Cgroup.destroy(path)

      # Restore: move the BEAM back to the root cgroup, then
      # the test cgroup is empty and destroy succeeds.
      :ok = File.write("/sys/fs/cgroup/cgroup.procs", Integer.to_string(beam_pid))
      assert :ok = Cgroup.destroy(path)
    end

    test "add_process/2 with a non-existent pid returns ESRCH", %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)

      # Pick a pid well past anything alive. The kernel returns
      # ESRCH for "no such process" on cgroup.procs writes.
      bogus = 2_147_483_640

      assert {:error, %Error{operation: :add_process, errno: errno}} =
               Cgroup.add_process(path, bogus)

      # Some kernels surface this as :esrch; some give :einval
      # depending on the pid range. Both are correct refusals.
      assert errno in [:esrch, :einval]

      assert :ok = Cgroup.destroy(path)
    end
  end
end
