defmodule Linx.MountTest do
  use ExUnit.Case, async: true

  alias Linx.Mount
  alias Linx.Mount.Entry

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

  describe "M1-M4 stubs" do
    # Until M1-M4 land, the mutating verbs return
    # {:error, :not_yet_implemented} so callers get a recognizable
    # shape now and the function names are visible in ExDoc.

    test "mount/4" do
      assert {:error, :not_yet_implemented} = Mount.mount("tmpfs", "/mnt", "tmpfs")
    end

    test "umount/2" do
      assert {:error, :not_yet_implemented} = Mount.umount("/mnt")
    end

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
end
