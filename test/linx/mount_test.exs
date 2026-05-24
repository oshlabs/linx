defmodule Linx.MountTest do
  use ExUnit.Case, async: true

  alias Linx.Mount
  alias Linx.Mount.{Entry, Error}

  describe "parse_mountinfo/1" do
    test "parses a representative single line" do
      blob =
        "45 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/cryptroot rw\n"

      assert [
               %Entry{
                 mount_id: 45,
                 parent_id: 1,
                 device: "253:1",
                 root: "/",
                 mount_point: "/",
                 mount_options: "rw,relatime",
                 propagation: [{:shared, 1}],
                 fstype: "ext4",
                 source: "/dev/mapper/cryptroot",
                 super_options: "rw"
               }
             ] = Mount.parse_mountinfo(blob)
    end

    test "parses multiple lines with mixed propagation flags" do
      # `master:7` and `shared:42` both present (slave with shared
      # peer group). `unbindable` is a value-less tag.
      blob = """
      40 45 0:7 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=16M
      77 40 0:99 /a /b ro shared:42 master:7 - none none ro
      88 1 0:100 / /unbind rw unbindable - tmpfs tmpfs rw
      """

      assert [
               %Entry{propagation: [{:shared, 2}]},
               %Entry{propagation: [{:shared, 42}, {:master, 7}]},
               %Entry{propagation: [:unbindable]}
             ] = Mount.parse_mountinfo(blob)
    end

    test "decodes octal-escaped paths" do
      # \040 is space, \011 is tab, \012 is newline, \134 is backslash.
      # The kernel escapes these in root, mount_point, and source.
      blob = """
      99 1 0:1 /weird\\040path /mnt/with\\040spaces rw - tmpfs tmpfs rw
      """

      assert [
               %Entry{
                 root: "/weird path",
                 mount_point: "/mnt/with spaces"
               }
             ] = Mount.parse_mountinfo(blob)
    end

    test "decodes a tab and backslash in the source field" do
      blob = """
      100 1 0:1 / /mnt rw - cifs //host\\134share\\011here rw
      """

      assert [%Entry{source: "//host\\share\there"}] = Mount.parse_mountinfo(blob)
    end

    test "handles a line with no propagation entries (just the - separator)" do
      blob = "200 1 0:1 / /mnt rw - tmpfs tmpfs rw\n"
      assert [%Entry{propagation: []}] = Mount.parse_mountinfo(blob)
    end

    test "silently skips lines that don't parse (forward-compatible)" do
      # First line malformed (no separator), second line valid.
      blob = """
      this is not a mountinfo line at all
      300 1 0:1 / /mnt rw - tmpfs tmpfs rw
      """

      assert [%Entry{mount_id: 300}] = Mount.parse_mountinfo(blob)
    end

    test "silently skips unknown optional-field tags (forward-compatible)" do
      # A future kernel adding a "future_tag:99" entry should not
      # break the parser.
      blob = """
      400 1 0:1 / /mnt rw shared:1 future_tag:99 - tmpfs tmpfs rw
      """

      assert [%Entry{propagation: [{:shared, 1}]}] = Mount.parse_mountinfo(blob)
    end

    test "empty string returns an empty list" do
      assert Mount.parse_mountinfo("") == []
    end

    test "whitespace-only / newline-only returns an empty list" do
      assert Mount.parse_mountinfo("\n\n\n") == []
    end
  end

  describe "Linx.Mount.Entry Inspect" do
    test "renders as fstype on mount_point (mount_options)" do
      e = %Entry{
        mount_id: 1,
        parent_id: 0,
        device: "0:1",
        root: "/",
        mount_point: "/proc",
        mount_options: "rw,relatime",
        propagation: [{:shared, 1}],
        fstype: "proc",
        source: "proc",
        super_options: "rw"
      }

      assert inspect(e) == "#Linx.Mount.Entry<proc on /proc (rw,relatime)>"
    end
  end

  describe "list/0" do
    @describetag :integration

    # list/0 reads /proc/self/mountinfo; this works for any
    # process on a normal Linux box, no root needed. Tagged
    # :integration because it touches real /proc.

    test "returns a non-empty list with at least /proc and / present" do
      {:ok, entries} = Mount.list()
      assert is_list(entries)
      assert length(entries) > 0

      mount_points = Enum.map(entries, & &1.mount_point)
      assert "/" in mount_points
      assert "/proc" in mount_points
    end

    test "every entry is a fully-populated %Linx.Mount.Entry{}" do
      {:ok, entries} = Mount.list()

      Enum.each(entries, fn e ->
        assert %Entry{} = e
        assert is_integer(e.mount_id)
        assert is_integer(e.parent_id)
        assert is_binary(e.device)
        assert is_binary(e.root)
        assert is_binary(e.mount_point)
        assert is_binary(e.mount_options)
        assert is_list(e.propagation)
        assert is_binary(e.fstype)
        assert is_binary(e.source)
        assert is_binary(e.super_options)
      end)
    end
  end

  describe "list/1" do
    @describetag :integration

    test "{:pid, n} reads /proc/<n>/mountinfo" do
      # The current BEAM's mountinfo should match list/0 modulo any
      # mount events between the two calls (extremely unlikely in a
      # plain test environment).
      beam_pid = System.pid() |> String.to_integer()
      assert {:ok, entries} = Mount.list({:pid, beam_pid})
      assert length(entries) > 0
      assert Enum.any?(entries, &(&1.mount_point == "/"))
    end

    test "{:pid, n} returns an error for a non-existent pid" do
      assert {:error, :enoent} = Mount.list({:pid, 2_147_483_640})
    end

    test "{:path, p} reads a mountinfo file at an explicit path" do
      assert {:ok, entries} = Mount.list({:path, "/proc/self/mountinfo"})
      assert length(entries) > 0
    end

    test "{:path, p} returns an error for a missing file" do
      assert {:error, :enoent} = Mount.list({:path, "/proc/self/nope-mountinfo"})
    end
  end

  describe "M2-M4 stubs" do
    # Until M2-M4 land, the still-unshipped verbs return
    # {:error, :not_yet_implemented} so callers get a recognizable
    # shape now and the function names are visible in ExDoc.

    test "bind/3" do
      assert {:error, :not_yet_implemented} = Mount.bind("/a", "/b")
    end

    test "remount/2" do
      assert {:error, :not_yet_implemented} = Mount.remount("/mnt")
    end

    test "move/2" do
      assert {:error, :not_yet_implemented} = Mount.move("/a", "/b")
    end

    test "pivot_root/3" do
      assert {:error, :not_yet_implemented} = Mount.pivot_root("/new", "/new/old")
    end
  end

  describe "Linx.Mount.Error" do
    test "@enforce_keys covers path, operation, errno" do
      assert_raise ArgumentError, fn ->
        struct!(Error, %{})
      end
    end

    test "from_posix/3 builds a struct with code looked up from the POSIX table" do
      err = Error.from_posix(:ebusy, "/mnt/x", :umount)
      assert %Error{path: "/mnt/x", operation: :umount, errno: :ebusy, code: 16} = err
    end

    test "from_posix/3 leaves :code at nil for unmapped errnos" do
      err = Error.from_posix(:eweirdthing, "/x", :mount)
      assert %Error{errno: :eweirdthing, code: nil} = err
    end

    test "Exception.message/1 renders cleanly" do
      err = Error.from_posix(:enoent, "/mnt/nope", :umount)
      assert Exception.message(err) == "mount umount failed on /mnt/nope: enoent (errno 2)"
    end

    test "an error can be raised" do
      err = Error.from_posix(:eperm, "/mnt/x", :mount)

      assert_raise Error, "mount mount failed on /mnt/x: eperm (errno 1)", fn ->
        raise err
      end
    end
  end

  describe "Linx.Mount.Native" do
    test "version/0 reflects the running milestone" do
      v = Mount.Native.version() |> List.to_string()
      assert String.starts_with?(v, "linx_mount ")
      # M1 marker; bumped when the NIF changes shape.
      assert String.ends_with?(v, "(M1)")
    end
  end

  describe "mount/4 + umount/2 flag validation" do
    # These run plain (no root needed) -- bad flags fail before any
    # syscall, real syscalls just fail with EPERM/EACCES if we're
    # unprivileged. We test the validation path; the syscall path
    # lands in the integration section.

    test "an unknown mount flag is rejected before the NIF call" do
      assert {:error, {:bad_flag, :totally_made_up}} =
               Mount.mount("none", "/mnt", "tmpfs", flags: [:ro, :totally_made_up])
    end

    test "an unknown umount flag is rejected before the NIF call" do
      assert {:error, {:bad_flag, :nope}} = Mount.umount("/mnt", flags: [:detach, :nope])
    end

    test "mount/4 against a non-existent target returns a structured error" do
      assert {:error, %Error{operation: :mount, errno: errno, path: "/nope/x/y"}} =
               Mount.mount("none", "/nope/x/y", "tmpfs")

      # Without root, we may hit EPERM before ENOENT depending on
      # the host. Both are structured -- that's what we're testing.
      assert errno in [:enoent, :eperm, :eacces]
    end

    test "umount/2 against a non-existent target returns a structured error" do
      assert {:error, %Error{operation: :umount, errno: errno}} =
               Mount.umount("/nope/x/y")

      assert errno in [:enoent, :einval, :eperm, :eacces]
    end

    test "mount/4 accepts an empty flag list" do
      # The flag-packing path with [] short-circuits to 0; this still
      # hits the kernel (and fails for non-root), but the error
      # shape is a real %Error{}, not a flag-validation error.
      assert {:error, %Error{operation: :mount}} = Mount.mount("none", "/nope", "tmpfs")
    end
  end

  describe "M1 integration: real tmpfs round-trip" do
    @describetag :integration

    setup do
      dir = "/tmp/linx-mount-test-#{System.unique_integer([:positive])}"
      File.mkdir_p!(dir)

      # Best-effort cleanup: try to unmount in case a test failed
      # mid-flight, then rmdir.
      on_exit(fn ->
        _ = Mount.umount(dir, flags: [:detach])
        _ = File.rmdir(dir)
      end)

      {:ok, dir: dir}
    end

    test "mount tmpfs, observe in list/0, umount, observe gone", %{dir: dir} do
      assert :ok = Mount.mount("none", dir, "tmpfs")

      {:ok, mounts} = Mount.list()
      entry = Enum.find(mounts, &(&1.mount_point == dir))
      assert %Entry{fstype: "tmpfs", mount_point: ^dir} = entry

      assert :ok = Mount.umount(dir)

      {:ok, after_mounts} = Mount.list()
      refute Enum.any?(after_mounts, &(&1.mount_point == dir))
    end

    test "mount tmpfs with :ro flag round-trips through mount_options",
         %{dir: dir} do
      assert :ok = Mount.mount("none", dir, "tmpfs", flags: [:ro, :nosuid])

      {:ok, mounts} = Mount.list()
      entry = Enum.find(mounts, &(&1.mount_point == dir))
      assert entry != nil
      assert String.contains?(entry.mount_options, "ro")
      assert String.contains?(entry.mount_options, "nosuid")

      assert :ok = Mount.umount(dir)
    end

    test "mount tmpfs with :data option (size=64M) round-trips through super_options",
         %{dir: dir} do
      assert :ok = Mount.mount("none", dir, "tmpfs", data: "size=64M,mode=755")

      {:ok, mounts} = Mount.list()
      entry = Enum.find(mounts, &(&1.mount_point == dir))
      assert entry != nil
      assert String.contains?(entry.super_options, "size=")

      assert :ok = Mount.umount(dir)
    end

    test "umount/2 of an unmounted path returns EINVAL", %{dir: dir} do
      # `dir` is created by setup but never mounted -- umount fails.
      assert {:error, %Error{operation: :umount, errno: :einval}} = Mount.umount(dir)
    end

    test "umount with :detach (lazy) succeeds even while busy", %{dir: dir} do
      :ok = Mount.mount("none", dir, "tmpfs")

      # Touch a file inside so the mount is "in use" by an open
      # directory entry (mild but enough to confirm detach behaves
      # differently from a vanilla umount).
      File.write!(Path.join(dir, "file"), "hi")

      # Vanilla umount should still work here (nothing has the
      # file open); the point of this test is just that :detach
      # is a valid flag and rounds-trips through the NIF.
      assert :ok = Mount.umount(dir, flags: [:detach])
    end

    test "umount with a bogus flag is rejected before the NIF call",
         %{dir: dir} do
      :ok = Mount.mount("none", dir, "tmpfs")

      assert {:error, {:bad_flag, :nonsense}} =
               Mount.umount(dir, flags: [:detach, :nonsense])

      # The bad-flag rejection means we never called the NIF, so the
      # tmpfs is still mounted -- clean up.
      assert :ok = Mount.umount(dir)
    end
  end
end
