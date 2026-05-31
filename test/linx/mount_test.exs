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

  describe "pivot_root/3 -- plain shape" do
    test "an invalid :in value returns {:error, {:bad_in, _}}" do
      assert {:error, {:bad_in, :wat}} =
               Mount.pivot_root("/new", "/new/old", in: :wat)
    end

    test "pivot_root against a non-existent new_root fails with :chdir" do
      # The chdir into new_root happens before pivot_root itself;
      # a missing path surfaces here with stage :chdir.
      assert {:error, %Error{operation: :chdir, errno: :enoent, path: "/nope-pivot"}} =
               Mount.pivot_root("/nope-pivot", "/nope-pivot/old")
    end

    test "pivot_root with :in to a non-existent pid fails at :open_ns" do
      # Namespace acquisition fails before chdir or pivot_root.
      assert {:error, %Error{operation: :open_ns, errno: :enoent, path: path}} =
               Mount.pivot_root("/new", "/new/old", in: {:pid, 2_147_483_640})

      assert path == "/proc/2147483640/ns/mnt"
    end
  end

  describe "M4 integration: pivot_root inside a container" do
    @describetag :integration

    test "pivot_root inside a child's fresh mount namespace at the checkpoint" do
      # The whole dance to make pivot_root happy:
      #
      #   1. Spawn a workload in a fresh :mount namespace -- it
      #      starts with a COPY of the host's mount table.
      #   2. Mark / private recursively inside the child. The
      #      kernel rejects pivot_root if the parent of new_root
      #      or the current root has shared propagation (which
      #      `/` typically does on systemd hosts -- shared:1 from
      #      the rootfs mount, propagating down to /tmp, etc.).
      #      `mount --make-rprivate /` is the standard runc/docker
      #      detach.
      #   3. Create the rootfs + old_root dirs and bind the rootfs
      #      to itself inside the child's namespace. The bind makes
      #      it a mount point; the fresh-mount-in-child means it
      #      has no peer group with anything on the host.
      #   4. pivot_root: new_root = the rootfs, put_old = old_root.
      #   5. Verify via list/1 that the child's mount table now has
      #      a fresh root mount.
      rootfs = "/tmp/linx-pivot-#{System.unique_integer([:positive])}"
      old_root = Path.join(rootfs, "old_root")
      File.mkdir_p!(rootfs)
      File.mkdir_p!(old_root)

      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "10"],
          namespaces: [:mount]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      on_exit(fn ->
        # Best-effort: the session may already be gone (we called
        # abort/1 in the happy path); signal/2 raises against a
        # dead GenServer -- swallow.
        try do
          _ = Linx.Process.abort(c)
        catch
          _, _ -> :ok
        end

        _ = File.rm_rf(rootfs)
      end)

      # Step 2: detach the child's mount subtree from any shared
      # peer groups inherited from the host.
      assert :ok = Mount.mount("", "/", "", flags: [:private, :rec], in: {:pid, host_pid})

      # Step 3: bind the rootfs to itself inside the child so it's
      # a mount point in the child's namespace with no peer group.
      assert :ok = Mount.bind(rootfs, rootfs, in: {:pid, host_pid})

      # Snapshot the child's root-mount id before pivot.
      {:ok, before} = Mount.list({:pid, host_pid})
      root_before = Enum.find(before, &(&1.mount_point == "/"))
      assert %Entry{} = root_before
      root_id_before = root_before.mount_id

      # Step 4: the pivot itself.
      assert :ok = Mount.pivot_root(rootfs, old_root, in: {:pid, host_pid})

      # Step 5: verify the swap. The child's root mount now points
      # at the rootfs bind, with a different mount_id; /old_root
      # exposes the former root.
      {:ok, after_mounts} = Mount.list({:pid, host_pid})
      root_after = Enum.find(after_mounts, &(&1.mount_point == "/"))
      assert %Entry{} = root_after
      assert root_after.mount_id != root_id_before

      assert Enum.any?(after_mounts, &(&1.mount_point == "/old_root"))

      # We've verified what we came here to verify (the pivot took
      # effect in the child's mount table). Discard the session
      # without running anything in the empty rootfs.
      :ok = Linx.Process.abort(c)
      assert_receive {:linx_process, :aborted}, 5_000
    end
  end

  describe ":in option validation (plain)" do
    test "an invalid :in value returns {:error, {:bad_in, _}}" do
      assert {:error, {:bad_in, :nope}} =
               Mount.mount("none", "/mnt", "tmpfs", in: :nope)
    end

    test "{:pid, n} for a non-existent pid returns an :open_ns error" do
      # No such pid -> /proc/<n>/ns/mnt doesn't exist.
      assert {:error, %Error{operation: :open_ns, errno: :enoent, path: path}} =
               Mount.mount("none", "/mnt", "tmpfs", in: {:pid, 2_147_483_640})

      assert path == "/proc/2147483640/ns/mnt"
    end

    test "{:path, p} pointing at a missing file returns :open_ns" do
      assert {:error, %Error{operation: :open_ns, errno: :enoent, path: "/nope/ns/mnt"}} =
               Mount.mount("none", "/mnt", "tmpfs", in: {:path, "/nope/ns/mnt"})
    end

    test "umount/2 :in is validated the same way" do
      assert {:error, {:bad_in, :wrong}} = Mount.umount("/mnt", in: :wrong)

      assert {:error, %Error{operation: :open_ns}} =
               Mount.umount("/mnt", in: {:pid, 2_147_483_640})
    end

    test "bind/3 forwards :in cleanly to mount/4" do
      assert {:error, %Error{operation: :open_ns}} =
               Mount.bind("/a", "/b", in: {:pid, 2_147_483_640})
    end

    test "remount/2 forwards :in cleanly to mount/4" do
      assert {:error, %Error{operation: :open_ns}} =
               Mount.remount("/mnt", in: {:pid, 2_147_483_640})
    end

    test "move/3 forwards :in cleanly to mount/4" do
      assert {:error, %Error{operation: :open_ns}} =
               Mount.move("/a", "/b", in: {:pid, 2_147_483_640})
    end
  end

  describe "M3 integration: cross-namespace via :in" do
    @describetag :integration

    test "remount /proc inside a child's fresh mount namespace at the checkpoint" do
      # Spawn a workload in a fresh :mount namespace. The kernel
      # gives the child a copy of the host's mount table at spawn
      # time -- /proc inside still maps to the host's /proc.
      # Mounting a fresh proc on top from the host gives the
      # workload its own /proc; mountinfo then shows BOTH (the
      # inherited one shadowed by the new one).
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "5"],
          namespaces: [:mount]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      # Snapshot the mount_ids of any /proc entries in the child
      # before we mount.
      {:ok, before} = Mount.list({:pid, host_pid})
      ids_before = before |> Enum.filter(&(&1.mount_point == "/proc")) |> Enum.map(& &1.mount_id)
      assert length(ids_before) >= 1

      # Mount a fresh proc on top inside the child's mount namespace.
      assert :ok = Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})

      # After: there's a /proc mount with an id we didn't see
      # before. The original inherited /proc is still listed too
      # (Linux retains shadowed mounts in mountinfo).
      {:ok, after_mounts} = Mount.list({:pid, host_pid})

      ids_after =
        after_mounts |> Enum.filter(&(&1.mount_point == "/proc")) |> Enum.map(& &1.mount_id)

      new_ids = ids_after -- ids_before
      assert length(new_ids) >= 1

      # The freshly-added mount has fstype "proc" and source "proc"
      # (the args we passed).
      new_entry = Enum.find(after_mounts, &(&1.mount_id in new_ids))
      assert %Entry{fstype: "proc", source: "proc", mount_point: "/proc"} = new_entry

      # Proceed and let the workload exit naturally.
      :ok = Linx.Process.proceed(c)
      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, _}, 10_000
    end

    test "mounting into a running container post-proceed (lifecycle-agnostic)" do
      # Demonstrates that :in works against any live process whose
      # namespace files exist -- not just at the checkpoint. Spawn,
      # proceed, *then* mount inside, then watch the mount appear
      # in the live container's mountinfo.
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "10"],
          namespaces: [:mount]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000
      :ok = Linx.Process.proceed(c)
      assert_receive {:linx_process, :running}, 2_000

      # Now the workload is running. Bind /tmp into it at /mnt-hot.
      # Create the target directory in the container's view by
      # binding from the host's /tmp first; we need the host's
      # /mnt-hot to be writable through the bind. Simpler: mount a
      # fresh tmpfs at a path that already exists in the
      # container's namespace.
      assert :ok = Mount.mount("none", "/mnt", "tmpfs", in: {:pid, host_pid})

      {:ok, ct_mounts} = Mount.list({:pid, host_pid})

      assert Enum.any?(ct_mounts, fn e ->
               e.mount_point == "/mnt" and e.fstype == "tmpfs"
             end)

      # The host's view -- mounting inside the container does NOT
      # affect the host's mount table.
      {:ok, host_mounts} = Mount.list()
      host_mnt = Enum.find(host_mounts, &(&1.mount_point == "/mnt"))
      # If /mnt happens to exist in the host's mount table, it
      # should be a different mount (different mount_id) than what
      # we just created in the container.
      if host_mnt do
        refute Enum.any?(ct_mounts, fn e ->
                 e.mount_point == "/mnt" and e.mount_id == host_mnt.mount_id
               end)
      end

      Linx.Process.signal(c, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test ":in: {:path, p} with an explicit namespace path works the same" do
      # Equivalent to {:pid, n} but the caller constructs the path
      # themselves -- useful for ns files held elsewhere (mount
      # namespace fds in named-bind storage, etc.).
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "5"],
          namespaces: [:mount]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000
      :ok = Linx.Process.proceed(c)
      assert_receive {:linx_process, :running}, 2_000

      ns_path = "/proc/#{host_pid}/ns/mnt"

      assert :ok =
               Mount.mount("none", "/mnt", "tmpfs", in: {:path, ns_path})

      {:ok, ct_mounts} = Mount.list({:pid, host_pid})
      assert Enum.any?(ct_mounts, &(&1.mount_point == "/mnt"))

      Linx.Process.signal(c, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "umount/2 with :in unmounts inside the container's namespace" do
      {:ok, c} =
        Linx.Process.spawn(
          argv: ["/bin/sleep", "5"],
          namespaces: [:mount]
        )

      assert_receive {:linx_process, :ready, host_pid}, 2_000
      :ok = Linx.Process.proceed(c)
      assert_receive {:linx_process, :running}, 2_000

      # Snapshot /mnt entries before, so we can identify our
      # newly-added one by mount_id (the host may already have
      # /mnt mounted; some distros do).
      {:ok, before} = Mount.list({:pid, host_pid})

      mnt_ids_before =
        before |> Enum.filter(&(&1.mount_point == "/mnt")) |> Enum.map(& &1.mount_id)

      assert :ok = Mount.mount("none", "/mnt", "tmpfs", in: {:pid, host_pid})

      {:ok, with_mnt} = Mount.list({:pid, host_pid})

      mnt_ids_during =
        with_mnt |> Enum.filter(&(&1.mount_point == "/mnt")) |> Enum.map(& &1.mount_id)

      [our_id] = mnt_ids_during -- mnt_ids_before
      # Sanity: our mount is the tmpfs we just made.
      our = Enum.find(with_mnt, &(&1.mount_id == our_id))
      assert %Entry{fstype: "tmpfs", mount_point: "/mnt"} = our

      assert :ok = Mount.umount("/mnt", in: {:pid, host_pid})

      # After umount: our specific mount_id is gone from the list.
      # Other mounts at /mnt (if any) are unaffected.
      {:ok, without_mnt} = Mount.list({:pid, host_pid})
      refute Enum.any?(without_mnt, &(&1.mount_id == our_id))

      Linx.Process.signal(c, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end
  end

  describe "M2 convenience verbs -- plain shape" do
    # Without root we can't do real binds; verify the plumbing
    # surfaces the structured error from mount/4 through cleanly.

    test "bind/3 against a non-existent source returns a structured error" do
      assert {:error, %Error{operation: :mount, errno: errno}} =
               Mount.bind("/nope/source", "/nope/target")

      assert errno in [:enoent, :eperm, :eacces]
    end

    test "bind/3 with a bad flag is rejected before the NIF call" do
      assert {:error, {:bad_flag, :nonsense}} =
               Mount.bind("/a", "/b", flags: [:nonsense])
    end

    test "remount/2 against an unmounted target returns a structured error" do
      assert {:error, %Error{operation: :mount, errno: errno}} =
               Mount.remount("/nope/never-mounted")

      assert errno in [:einval, :enoent, :eperm, :eacces]
    end

    test "move/2 against a non-existent source returns a structured error" do
      assert {:error, %Error{operation: :mount, errno: errno}} =
               Mount.move("/nope/source", "/nope/target")

      assert errno in [:einval, :enoent, :eperm, :eacces]
    end
  end

  describe "M2 integration: bind + remount + move" do
    @describetag :integration

    setup do
      base = "/tmp/linx-mount-test-#{System.unique_integer([:positive])}"
      source = Path.join(base, "src")
      target = Path.join(base, "dst")
      moved = Path.join(base, "moved")

      File.mkdir_p!(source)
      File.mkdir_p!(target)
      File.mkdir_p!(moved)

      on_exit(fn ->
        # Best-effort cleanup -- a failing test might have left
        # mounts behind.
        for p <- [moved, target, source], do: _ = Mount.umount(p, flags: [:detach])
        _ = File.rm_rf(base)
      end)

      {:ok, source: source, target: target, moved: moved}
    end

    test "bind/3 makes source visible at target", %{source: src, target: tgt} do
      File.write!(Path.join(src, "marker"), "hello")

      assert :ok = Mount.bind(src, tgt)

      # The marker file is now visible at the bind-target.
      assert File.read!(Path.join(tgt, "marker")) == "hello"

      # And mountinfo shows the bind. The fstype on a bind mount
      # reports the underlying filesystem -- whatever /tmp lives on.
      {:ok, mounts} = Mount.list()
      entry = Enum.find(mounts, &(&1.mount_point == tgt))
      assert %Entry{root: root, mount_point: ^tgt} = entry
      # The bind's `root` field points at the original directory.
      assert String.ends_with?(root, "/src")

      assert :ok = Mount.umount(tgt)
    end

    test "remount/2 + :ro makes a bind mount read-only", %{source: src, target: tgt} do
      assert :ok = Mount.bind(src, tgt)

      # Initially writable.
      assert :ok = File.write(Path.join(tgt, "before-ro"), "")

      # Remount as read-only. Note the :bind flag is required --
      # without it, the kernel tries to remount the underlying
      # filesystem instead.
      assert :ok = Mount.remount(tgt, flags: [:bind, :ro])

      {:ok, mounts} = Mount.list()
      entry = Enum.find(mounts, &(&1.mount_point == tgt))
      assert String.contains?(entry.mount_options, "ro")

      # Writes now fail with EROFS.
      assert {:error, :erofs} = File.write(Path.join(tgt, "after-ro"), "")

      # ... but the underlying source is still writable.
      assert :ok = File.write(Path.join(src, "still-rw"), "")

      assert :ok = Mount.umount(tgt)
    end

    test "move/2 atomically relocates a bind mount" do
      # The kernel rejects MS_MOVE if the source's mount or its
      # destination's parent has shared propagation. /tmp on most
      # distros is shared:1, so anything mounted under it inherits
      # the shared peer group. Isolate this test by mounting a
      # tmpfs at our own scratch path and marking it private --
      # everything we do under it is then in a fresh propagation
      # group of one, and move/2 works as documented.
      base = "/tmp/linx-mount-test-move-#{System.unique_integer([:positive])}"
      File.mkdir_p!(base)

      on_exit(fn ->
        _ = Mount.umount(base, flags: [:detach])
        _ = File.rmdir(base)
      end)

      assert :ok = Mount.mount("none", base, "tmpfs")
      # Change propagation to private. Propagation flags are *not*
      # combined with MS_REMOUNT -- they're their own call form per
      # the kernel docs. Pass MS_PRIVATE alone.
      assert :ok = Mount.mount("", base, "", flags: [:private])

      src = Path.join(base, "src")
      tgt = Path.join(base, "dst")
      dst = Path.join(base, "moved")
      File.mkdir_p!(src)
      File.mkdir_p!(tgt)
      File.mkdir_p!(dst)

      assert :ok = Mount.bind(src, tgt)

      File.write!(Path.join(src, "marker"), "still here")
      assert File.read!(Path.join(tgt, "marker")) == "still here"

      assert :ok = Mount.move(tgt, dst)

      # tgt is no longer a mount point; dst is.
      {:ok, mounts} = Mount.list()
      refute Enum.any?(mounts, &(&1.mount_point == tgt))
      assert Enum.any?(mounts, &(&1.mount_point == dst))

      # And the contents follow.
      assert File.read!(Path.join(dst, "marker")) == "still here"

      # Cleanup: detach the moved bind, then the wrapper tmpfs.
      assert :ok = Mount.umount(dst)
      assert :ok = Mount.umount(base)
    end

    test "bind/3 with :rec performs a recursive bind",
         %{source: src, target: tgt} do
      # Mount a tmpfs underneath src so there's something for :rec
      # to follow.
      inner = Path.join(src, "inner")
      File.mkdir_p!(inner)
      assert :ok = Mount.mount("none", inner, "tmpfs")
      File.write!(Path.join(inner, "tmpfs-marker"), "")

      # Non-recursive bind: src visible at tgt, but `inner` shows as
      # an empty directory (the tmpfs didn't follow).
      assert :ok = Mount.bind(src, tgt)
      refute File.exists?(Path.join([tgt, "inner", "tmpfs-marker"]))

      assert :ok = Mount.umount(tgt)

      # Recursive bind: the tmpfs follows along.
      assert :ok = Mount.bind(src, tgt, flags: [:rec])
      assert File.exists?(Path.join([tgt, "inner", "tmpfs-marker"]))

      # Cleanup: the recursive bind propagates the unmount of `tgt`
      # to its peer (`src/inner`) via the default shared propagation
      # on /tmp, so `inner` may already be gone by the time we get
      # here. Best-effort detach both -- the assertion that matters
      # is that tgt/inner/tmpfs-marker was visible, which we already
      # checked.
      _ = Mount.umount(tgt, flags: [:detach])
      _ = Mount.umount(inner, flags: [:detach])
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
    test "version/0 returns the NIF identifier" do
      v = Mount.Native.version() |> List.to_string()
      assert v == "linx_mount"
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
