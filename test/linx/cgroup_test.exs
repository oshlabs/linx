defmodule Linx.CgroupTest do
  use ExUnit.Case, async: true

  alias Linx.Cgroup
  alias Linx.Cgroup.{Error, Stats}

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

    test "freeze/1 against a missing cgroup returns a structured error" do
      assert {:error, %Error{operation: :write, errno: errno, path: path}} =
               Cgroup.freeze(@nope)

      assert errno in [:enoent, :eacces]
      assert String.ends_with?(path, "cgroup.freeze")
    end

    test "thaw/1 against a missing cgroup returns a structured error" do
      assert {:error, %Error{operation: :write, errno: errno}} = Cgroup.thaw(@nope)
      assert errno in [:enoent, :eacces]
    end

    test "set_memory_max/2 against a missing cgroup returns a structured error" do
      assert {:error, %Error{operation: :write, errno: errno, path: path}} =
               Cgroup.set_memory_max(@nope, 1024)

      assert errno in [:enoent, :eacces]
      assert String.ends_with?(path, "memory.max")
    end

    test "set_pids_max/2 accepts :max" do
      assert {:error, %Error{operation: :write, path: path}} = Cgroup.set_pids_max(@nope, :max)
      assert String.ends_with?(path, "pids.max")
    end

    test "set_cpu_max/2 with {quota, period} formats the kernel's expected text" do
      # We can't observe the bytes that would have been written when
      # the path doesn't exist, but the error tells us the right
      # interface file was targeted.
      assert {:error, %Error{operation: :write, path: path}} =
               Cgroup.set_cpu_max(@nope, {50_000, 100_000})

      assert String.ends_with?(path, "cpu.max")
    end

    test "stats/1 against a missing cgroup returns a structured error" do
      assert {:error, %Error{operation: :stats, errno: errno, path: path}} =
               Cgroup.stats(@nope)

      assert errno in [:enoent, :eacces]
      assert path == @nope
    end
  end

  describe "parse_keyed/1 (cpu.stat parsing)" do
    # Plain unit test of the cpu.stat parser, independent of any
    # filesystem state. The format is space-separated "key int" lines.

    test "parses a representative cpu.stat blob" do
      blob = """
      usage_usec 285978284524
      user_usec 215396840656
      system_usec 70581443867
      nr_periods 0
      nr_throttled 7
      throttled_usec 123456
      """

      assert %{
               "usage_usec" => 285_978_284_524,
               "user_usec" => 215_396_840_656,
               "system_usec" => 70_581_443_867,
               "nr_periods" => 0,
               "nr_throttled" => 7,
               "throttled_usec" => 123_456
             } = Cgroup.parse_keyed(blob)
    end

    test "silently drops non-integer / malformed lines" do
      # core_sched.force_idle_usec exists on some kernels; lines we
      # don't understand should be ignored rather than crashing.
      blob = """
      usage_usec 100
      something_weird not_an_int
      another_thing
      """

      assert Cgroup.parse_keyed(blob) == %{"usage_usec" => 100}
    end

    test "nil input returns an empty map" do
      # stats/1 passes nil when cpu.stat is missing entirely.
      assert Cgroup.parse_keyed(nil) == %{}
    end

    test "empty string returns an empty map" do
      assert Cgroup.parse_keyed("") == %{}
    end
  end

  describe "Linx.Cgroup.Stats" do
    test "default struct has every field nil" do
      assert %Stats{} == %Stats{
               cpu_usec: nil,
               cpu_user_usec: nil,
               cpu_system_usec: nil,
               cpu_nr_throttled: nil,
               cpu_throttled_usec: nil,
               memory_current: nil,
               memory_peak: nil,
               pids_current: nil
             }
    end

    test "Inspect omits nil fields" do
      assert inspect(%Stats{}) == "#Linx.Cgroup.Stats<>"
    end

    test "Inspect renders cpu in seconds, memory humanized, pids as int" do
      s = %Stats{
        cpu_usec: 12_345_678,
        memory_current: 256 * 1024 * 1024,
        pids_current: 3
      }

      # 12.345678s → "12.3s" (one decimal); 256 * 1024 * 1024 → "256MiB"
      assert inspect(s) == "#Linx.Cgroup.Stats<cpu=12.3s mem=256MiB pids=3>"
    end

    test "Inspect uses ms / µs / m+s for small / sub-second / multi-minute CPU" do
      assert inspect(%Stats{cpu_usec: 500}) == "#Linx.Cgroup.Stats<cpu=500µs>"
      assert inspect(%Stats{cpu_usec: 150_000}) == "#Linx.Cgroup.Stats<cpu=150ms>"

      # 8 minutes + 12.5 seconds (rendered as 8m12s; sub-second drops
      # when expressed as m+s, intentionally — the m+s form is for
      # readability of long-running workloads).
      assert inspect(%Stats{cpu_usec: 8 * 60_000_000 + 12_500_000}) ==
               "#Linx.Cgroup.Stats<cpu=8m12s>"
    end

    test "Inspect humanizes memory across KiB / MiB / GiB" do
      assert inspect(%Stats{memory_current: 256}) == "#Linx.Cgroup.Stats<mem=256B>"
      assert inspect(%Stats{memory_current: 4096}) == "#Linx.Cgroup.Stats<mem=4KiB>"
      assert inspect(%Stats{memory_current: 4 * 1024 * 1024}) == "#Linx.Cgroup.Stats<mem=4MiB>"

      # 1.5 GiB rounds down to one decimal.
      assert inspect(%Stats{memory_current: div(3 * 1024 * 1024 * 1024, 2)}) ==
               "#Linx.Cgroup.Stats<mem=1.5GiB>"
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

  describe "C2 freeze/thaw integration" do
    @moduletag :integration

    setup do
      path = "/sys/fs/cgroup/linx-test-#{System.unique_integer([:positive])}"
      on_exit(fn -> _ = File.rmdir(path) end)
      {:ok, path: path}
    end

    test "freeze/1 and thaw/1 round-trip through cgroup.freeze", %{path: path} do
      assert {:ok, ^path} = Cgroup.create(path)
      assert {:ok, "0"} = Cgroup.read(path, "cgroup.freeze")

      assert :ok = Cgroup.freeze(path)
      assert {:ok, "1"} = Cgroup.read(path, "cgroup.freeze")

      assert :ok = Cgroup.thaw(path)
      assert {:ok, "0"} = Cgroup.read(path, "cgroup.freeze")

      assert :ok = Cgroup.destroy(path)
    end
  end

  describe "C2 typed limit setters integration" do
    @moduletag :integration

    # The host needs the memory/pids/cpu controllers delegated at the
    # root (/sys/fs/cgroup/cgroup.subtree_control). On systemd hosts
    # this is the default. If a host doesn't have a given controller
    # delegated, the kernel surfaces ENOENT on the write because the
    # interface file (e.g. memory.max) won't exist in the child --
    # those tests will skip with a clear log.

    setup do
      path = "/sys/fs/cgroup/linx-test-#{System.unique_integer([:positive])}"
      on_exit(fn -> _ = File.rmdir(path) end)

      {:ok, ^path} = Cgroup.create(path)
      {:ok, path: path}
    end

    test "set_memory_max/2 with an integer round-trips through read/2",
         %{path: path} do
      assert :ok = Cgroup.set_memory_max(path, 256 * 1024 * 1024)
      assert {:ok, "268435456"} = Cgroup.read(path, "memory.max")

      # And :max clears it back to unlimited.
      assert :ok = Cgroup.set_memory_max(path, :max)
      assert {:ok, "max"} = Cgroup.read(path, "memory.max")

      assert :ok = Cgroup.destroy(path)
    end

    test "set_pids_max/2 with an integer and :max round-trip", %{path: path} do
      assert :ok = Cgroup.set_pids_max(path, 100)
      assert {:ok, "100"} = Cgroup.read(path, "pids.max")

      assert :ok = Cgroup.set_pids_max(path, :max)
      assert {:ok, "max"} = Cgroup.read(path, "pids.max")

      assert :ok = Cgroup.destroy(path)
    end

    test "set_cpu_max/2 formats {quota, period} per the kernel's contract",
         %{path: path} do
      assert :ok = Cgroup.set_cpu_max(path, {50_000, 100_000})
      assert {:ok, "50000 100000"} = Cgroup.read(path, "cpu.max")

      # :max keeps the period the kernel chose at creation time and
      # restores quota to "max".
      assert :ok = Cgroup.set_cpu_max(path, :max)
      {:ok, after_max} = Cgroup.read(path, "cpu.max")
      assert String.starts_with?(after_max, "max ")

      assert :ok = Cgroup.destroy(path)
    end
  end

  describe "C3 stats integration" do
    @moduletag :integration

    setup do
      path = "/sys/fs/cgroup/linx-test-#{System.unique_integer([:positive])}"
      on_exit(fn -> _ = File.rmdir(path) end)

      {:ok, ^path} = Cgroup.create(path)
      {:ok, path: path}
    end

    test "stats/1 returns a Stats struct on a real cgroup", %{path: path} do
      assert {:ok, %Stats{} = s} = Cgroup.stats(path)

      # Every field present on this host (root has the standard
      # controllers delegated) should be a non-negative integer.
      assert is_nil(s.cpu_usec) or (is_integer(s.cpu_usec) and s.cpu_usec >= 0)
      assert is_nil(s.memory_current) or
               (is_integer(s.memory_current) and s.memory_current >= 0)

      assert is_nil(s.pids_current) or
               (is_integer(s.pids_current) and s.pids_current >= 0)

      assert :ok = Cgroup.destroy(path)
    end

    test "stats/1 reflects a populated cgroup", %{path: path} do
      # Move the BEAM in briefly so pids_current is at least 1, then
      # move out again before destroy.
      beam_pid = System.pid() |> String.to_integer()
      :ok = Cgroup.add_process(path, beam_pid)

      assert {:ok, %Stats{pids_current: n}} = Cgroup.stats(path)
      assert is_integer(n) and n >= 1

      # If memory accounting is on, memory.current is > 0 once a
      # real pid lives here.
      {:ok, %Stats{memory_current: mem}} = Cgroup.stats(path)
      assert is_nil(mem) or mem >= 0

      # Restore -- move BEAM back to root cgroup before destroying.
      :ok = File.write("/sys/fs/cgroup/cgroup.procs", Integer.to_string(beam_pid))
      assert :ok = Cgroup.destroy(path)
    end
  end
end
