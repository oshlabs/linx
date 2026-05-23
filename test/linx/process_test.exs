defmodule Linx.ProcessTest do
  use ExUnit.Case, async: true

  alias Linx.Process, as: P

  describe "spawn/1 input validation" do
    test "rejects opts without :argv" do
      assert {:error, :argv_required} = P.spawn([])
    end

    test "rejects a non-list :argv" do
      assert {:error, :argv_required} = P.spawn(argv: "/bin/true")
    end

    test "rejects an :argv with non-binary elements" do
      assert {:error, :bad_argv} = P.spawn(argv: ["/bin/true", :nope])
    end

    test "rejects an unknown namespace atom" do
      assert {:error, {:bad_namespaces, [:typo]}} =
               P.spawn(argv: ["/bin/true"], namespaces: [:net, :typo])
    end

    test "rejects a non-list :env" do
      assert {:error, :bad_env} = P.spawn(argv: ["/bin/true"], env: "PATH=/bin")
    end
  end

  describe "spawn/1 → release/1 → exit (no namespaces, no root)" do
    test "runs /bin/true and reports exit 0" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])

      assert_receive {:linx_process, :ready, child_pid}, 2_000
      assert is_integer(child_pid) and child_pid > 0

      :ok = P.release(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert_down(session)
    end

    test "runs /bin/false and reports exit 1" do
      {:ok, session} = P.spawn(argv: ["/bin/false"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.release(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 1}, 2_000

      assert_down(session)
    end

    test "execve failure surfaces as {:linx_process, :error, errno, :execve}" do
      {:ok, session} = P.spawn(argv: ["/this/does/not/exist"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.release(session)

      # ENOENT = 2 on Linux.
      assert_receive {:linx_process, :error, 2, :execve}, 2_000

      assert_down(session)
    end

    test "child argv is honored" do
      # /bin/sh -c 'exit 42' — confirms argv beyond argv[0] reaches the
      # workload and is observable through its exit code.
      {:ok, session} = P.spawn(argv: ["/bin/sh", "-c", "exit 42"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.release(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 42}, 2_000

      assert_down(session)
    end
  end

  describe "spawn/1 with fresh namespaces" do
    # Creating any namespace other than CLONE_NEWUSER needs CAP_SYS_ADMIN.
    # The :integration tag keeps these out of `mix test` by default; run
    # with `./sudotest.sh` or `mix test --include integration` as root.
    @tag :integration
    test "namespaces: [:net] gives the child a fresh, isolated netns" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], namespaces: [:net])

      assert_receive {:linx_process, :ready, child_pid}, 2_000

      # Without :pid in the namespaces list, the pidns-internal pid the
      # child reports is identical to its host pid -- so we can hand it
      # straight to Linx.Netlink, which opens /proc/<pid>/ns/net.
      {:ok, sock} = Linx.Netlink.Rtnl.open({:pid, child_pid})
      assert {:ok, links} = Linx.Netlink.Rtnl.Link.list(sock)

      # A fresh network namespace has loopback only -- nothing else.
      names = links |> Enum.map(& &1.name) |> Enum.sort()
      assert names == ["lo"]

      :ok = Linx.Netlink.Socket.close(sock)

      :ok = P.release(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert_down(session)
    end
  end

  # Block until the GenServer exits. Used after the terminal owner event so
  # tests don't leak processes across runs. `Process.monitor` on a
  # already-dead process delivers `:noproc` immediately rather than
  # `:normal`; accept either — we've already asserted the lifecycle
  # events arrived correctly above, so the only thing to confirm here is
  # the GenServer is gone.
  defp assert_down(pid) do
    ref = Process.monitor(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2_000
  end
end
