defmodule Linx.SysctlTest do
  use ExUnit.Case, async: true

  alias Linx.Sysctl
  alias Linx.Sysctl.Entry
  alias Linx.Sysctl.Error

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

  describe "key validation" do
    # Caller-side input mistakes surface as {:error, {:bad_key, ...}}
    # and are caught before any procfs read or write.

    test "rejects empty key" do
      assert {:error, {:bad_key, ""}} = Sysctl.read("")
    end

    test "rejects leading dot" do
      assert {:error, {:bad_key, ".net.ipv4.ip_forward"}} = Sysctl.read(".net.ipv4.ip_forward")
    end

    test "rejects trailing dot" do
      assert {:error, {:bad_key, "net.ipv4.ip_forward."}} = Sysctl.read("net.ipv4.ip_forward.")
    end

    test "rejects consecutive dots (no `..` traversal)" do
      assert {:error, {:bad_key, "net..ip_forward"}} = Sysctl.read("net..ip_forward")
    end

    test "rejects path-traversal attempts via `..` segment" do
      # The regex requires segments to be [A-Za-z0-9_-]+; `..` is
      # rejected because the segment is empty.
      assert {:error, {:bad_key, "net.ipv4.../etc/passwd"}} =
               Sysctl.read("net.ipv4.../etc/passwd")
    end

    test "rejects keys containing slashes" do
      assert {:error, {:bad_key, "net/ipv4/ip_forward"}} = Sysctl.read("net/ipv4/ip_forward")
    end

    test "rejects keys with spaces" do
      assert {:error, {:bad_key, "net.ipv4. ip_forward"}} = Sysctl.read("net.ipv4. ip_forward")
    end

    test "rejects keys with NUL" do
      assert {:error, {:bad_key, "net.ipv4.ip_forward" <> <<0>>}} =
               Sysctl.read("net.ipv4.ip_forward" <> <<0>>)
    end

    test "accepts dashes and underscores in segments" do
      # `net.bridge.bridge-nf-call-iptables` is a real per-netns
      # bridge knob with dashes; underscores are pervasive.
      # The key may or may not exist on this host; what matters is
      # that key validation passed and a :read error came back.
      result = Sysctl.read("net.bridge.bridge-nf-call-iptables")
      refute match?({:error, {:bad_key, _}}, result)
    end

    test "validates keys in read_int/1, read_ints/1, write/2 too" do
      assert {:error, {:bad_key, ""}} = Sysctl.read_int("")
      assert {:error, {:bad_key, ""}} = Sysctl.read_ints("")
      assert {:error, {:bad_key, ""}} = Sysctl.write("", 1)
    end
  end

  describe "value validation" do
    # write/2 validates its value argument before touching procfs.

    test "rejects binary containing newline (kernel would truncate)" do
      assert {:error, {:bad_value, {:contains, :newline}}} =
               Sysctl.write("kernel.hostname", "ct0\nct1")
    end

    test "rejects binary containing NUL" do
      assert {:error, {:bad_value, {:contains, :nul}}} =
               Sysctl.write("kernel.hostname", "ct0" <> <<0>> <> "ct1")
    end

    test "rejects list with a non-integer element" do
      assert {:error, {:bad_value, {:not_all_integers, [4, 4, "1", 7]}}} =
               Sysctl.write("kernel.printk", [4, 4, "1", 7])
    end

    test "rejects unsupported value type (atom)" do
      assert {:error, {:bad_value, {:unsupported_type, :enabled}}} =
               Sysctl.write("net.ipv4.ip_forward", :enabled)
    end

    test "rejects unsupported value type (tuple)" do
      assert {:error, {:bad_value, {:unsupported_type, {1, 2}}}} =
               Sysctl.write("net.ipv4.tcp_rmem", {1, 2})
    end
  end

  describe "kernel-level read errors" do
    test "returns %Sysctl.Error{errno: :enoent} for a nonexistent key" do
      bogus = "linx.this.does.not.exist"
      assert {:error, %Error{} = err} = Sysctl.read(bogus)
      assert err.key == bogus
      assert err.path == "/proc/sys/linx/this/does/not/exist"
      assert err.operation == :read
      assert err.errno == :enoent
      assert err.code == 2
    end

    test "read_int/1 passes through %Sysctl.Error{} from a nonexistent key" do
      assert {:error, %Error{errno: :enoent, operation: :read}} =
               Sysctl.read_int("linx.this.does.not.exist")
    end

    test "read_ints/1 passes through %Sysctl.Error{} from a nonexistent key" do
      assert {:error, %Error{errno: :enoent, operation: :read}} =
               Sysctl.read_ints("linx.this.does.not.exist")
    end
  end

  describe "Linx.Sysctl.Error" do
    test "from_posix/4 builds a struct with the right shape and errno code" do
      err = Error.from_posix(:eperm, "kernel.hostname", "/proc/sys/kernel/hostname", :write)
      assert %Error{} = err
      assert err.key == "kernel.hostname"
      assert err.path == "/proc/sys/kernel/hostname"
      assert err.operation == :write
      assert err.errno == :eperm
      assert err.code == 1
    end

    test "from_posix/4 leaves :code nil for unmapped errno atoms" do
      err = Error.from_posix(:exotic_errno, "x", "/proc/sys/x", :read)
      assert err.code == nil
    end

    test "Exception.message/1 renders key + path + errno + code" do
      err =
        Error.from_posix(:eacces, "net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward", :write)

      assert Exception.message(err) ==
               "sysctl write \"net.ipv4.ip_forward\" failed on /proc/sys/net/ipv4/ip_forward: eacces (errno 13)"
    end

    test "Exception.message/1 omits the (errno N) part when :code is nil" do
      err = Error.from_posix(:weird, "x", "/proc/sys/x", :read)
      assert Exception.message(err) == "sysctl read \"x\" failed on /proc/sys/x: weird"
    end
  end

  describe "Linx.Sysctl.Entry" do
    test "struct enforces both :key and :value" do
      assert_raise ArgumentError, fn ->
        struct!(Entry, key: "net.ipv4.ip_forward")
      end

      assert_raise ArgumentError, fn ->
        struct!(Entry, value: "0")
      end

      e = struct!(Entry, key: "net.ipv4.ip_forward", value: "0")
      assert e.key == "net.ipv4.ip_forward"
      assert e.value == "0"
    end

    test "Inspect renders the key = value form for short values" do
      e = %Entry{key: "net.ipv4.ip_forward", value: "0"}
      assert inspect(e) == ~s(#Linx.Sysctl.Entry<net.ipv4.ip_forward = "0">)
    end

    test "Inspect handles tuple-shaped values verbatim (tabs preserved)" do
      e = %Entry{key: "kernel.printk", value: "4\t4\t1\t7"}
      assert inspect(e) == ~s(#Linx.Sysctl.Entry<kernel.printk = "4\\t4\\t1\\t7">)
    end

    test "Inspect truncates values over 60 bytes with `...`" do
      long = String.duplicate("x", 100)
      e = %Entry{key: "fake.long", value: long}

      rendered = inspect(e)
      assert String.starts_with?(rendered, ~s(#Linx.Sysctl.Entry<fake.long = "))
      # 60 'x' then '...' then closing '">'
      assert rendered ==
               ~s(#Linx.Sysctl.Entry<fake.long = "#{String.duplicate("x", 60)}...">)
    end
  end

  describe "list/1 — plain (no procfs walk)" do
    test "rejects malformed prefix as {:bad_key, ...}" do
      assert {:error, {:bad_key, "net..ipv4"}} = Sysctl.list("net..ipv4")
      assert {:error, {:bad_key, ""}} = Sysctl.list("")
    end

    test "nonexistent prefix returns %Error{errno: :enoent, operation: :list}" do
      assert {:error, %Error{} = err} = Sysctl.list("linx.does.not.exist")
      assert err.key == "linx.does.not.exist"
      assert err.path == "/proc/sys/linx/does/not/exist"
      assert err.operation == :list
      assert err.errno == :enoent
    end
  end

  describe "S1 integration — real procfs reads + ip_forward round-trip" do
    @describetag :integration

    # Real reads and writes against /proc/sys/. Reads of kernel.ostype
    # and kernel.printk need no privilege; the write round-trip on
    # net.ipv4.ip_forward needs root (write-to-current-value is a
    # no-op semantically, but the syscall still requires the
    # privilege).

    test "read/1 returns 'Linux' for kernel.ostype" do
      assert {:ok, "Linux"} = Sysctl.read("kernel.ostype")
    end

    test "read_int/1 returns an integer for vm.swappiness" do
      assert {:ok, n} = Sysctl.read_int("vm.swappiness")
      assert is_integer(n)
      assert n >= 0 and n <= 200
    end

    test "read_ints/1 returns a 4-element list for kernel.printk" do
      assert {:ok, ints} = Sysctl.read_ints("kernel.printk")
      assert length(ints) == 4
      assert Enum.all?(ints, &is_integer/1)
    end

    test "read_ints/1 returns a 3-element list for net.ipv4.tcp_rmem" do
      assert {:ok, ints} = Sysctl.read_ints("net.ipv4.tcp_rmem")
      assert length(ints) == 3
      assert Enum.all?(ints, &is_integer/1)
    end

    test "write/2 round-trips net.ipv4.ip_forward without changing it" do
      # Snapshot, write the same value back, read it again -- the
      # value must be unchanged regardless of whether the host
      # currently has forwarding on or off. on_exit guarantees
      # restoration even if the assertions fail.
      assert {:ok, before} = Sysctl.read_int("net.ipv4.ip_forward")
      on_exit(fn -> _ = Sysctl.write("net.ipv4.ip_forward", before) end)

      assert :ok = Sysctl.write("net.ipv4.ip_forward", before)
      assert {:ok, ^before} = Sysctl.read_int("net.ipv4.ip_forward")
    end
  end

  describe "S2 integration — list/0 + list/1 against real /proc/sys/" do
    @describetag :integration

    # Real walks of /proc/sys/. Reads only; no host state mutated.
    # list/0 on a typical host returns ~1500 entries; the test
    # checks for stable, always-present anchors (kernel.ostype,
    # vm.swappiness) rather than asserting an exact count.

    test "list/0 returns a non-empty list including kernel.ostype" do
      assert {:ok, all} = Sysctl.list()
      assert is_list(all)
      assert length(all) > 100
      assert Enum.all?(all, &match?(%Entry{}, &1))

      ostype = Enum.find(all, &(&1.key == "kernel.ostype"))
      assert ostype, "expected kernel.ostype in list/0 output"
      assert ostype.value == "Linux"
    end

    test "list/0 returns entries sorted by key" do
      assert {:ok, all} = Sysctl.list()
      keys = Enum.map(all, & &1.key)
      assert keys == Enum.sort(keys)
    end

    test "list/1 with a subtree prefix returns only that subtree" do
      assert {:ok, net} = Sysctl.list("net.ipv4")
      assert length(net) > 10
      assert Enum.all?(net, &String.starts_with?(&1.key, "net.ipv4."))
    end

    test "list/1 sorts subtree entries by key" do
      assert {:ok, net} = Sysctl.list("net.ipv4")
      keys = Enum.map(net, & &1.key)
      assert keys == Enum.sort(keys)
    end

    test "list/1 on a leaf returns a single-element list" do
      assert {:ok, [%Entry{key: "kernel.ostype", value: "Linux"}]} =
               Sysctl.list("kernel.ostype")
    end

    test "list/1 stays within the named subtree (no leakage)" do
      # net.core is a sibling of net.ipv4; list("net.ipv4") must
      # not include any net.core.* entries.
      assert {:ok, net} = Sysctl.list("net.ipv4")
      refute Enum.any?(net, &String.starts_with?(&1.key, "net.core."))
    end
  end
end
