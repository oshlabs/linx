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

  describe "spawn/1 → proceed/1 → exit (no namespaces, no root)" do
    test "runs /bin/true and reports exit 0" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])

      assert_receive {:linx_process, :ready, child_pid}, 2_000
      assert is_integer(child_pid) and child_pid > 0

      :ok = P.proceed(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 0}, 2_000
    end

    test "runs /bin/false and reports exit 1" do
      {:ok, session} = P.spawn(argv: ["/bin/false"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 1}, 2_000
    end

    test "execve failure surfaces as {:linx_process, :error, errno, :execve}" do
      {:ok, session} = P.spawn(argv: ["/this/does/not/exist"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)

      # ENOENT = 2 on Linux.
      assert_receive {:linx_process, :error, 2, :execve}, 2_000
    end

    test "child argv is honored" do
      # /bin/sh -c 'exit 42' — confirms argv beyond argv[0] reaches the
      # workload and is observable through its exit code.
      {:ok, session} = P.spawn(argv: ["/bin/sh", "-c", "exit 42"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 42}, 2_000
    end
  end

  describe "signal/2 and wait/1" do
    test "signal/2 delivers SIGTERM to a running workload (-> :signaled)" do
      # /bin/sleep is a plain workload (not PID 1 of a fresh PID
      # namespace), so the kernel delivers SIGTERM with the default
      # action (terminate).
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      :ok = P.signal(session, 15)

      assert_receive {:linx_process, :signaled, 15}, 2_000
      assert {:ok, {:signaled, 15}} = P.wait(session)
    end

    test "signal/2 buffers pre-running and flushes on :running" do
      # /bin/sleep 60 again, but the signal is sent *before* proceed/1.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      # Buffered: not yet running.
      :ok = P.signal(session, 15)

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      # The buffered signal lands -- the workload dies.
      assert_receive {:linx_process, :signaled, 15}, 2_000
      assert {:ok, {:signaled, 15}} = P.wait(session)
    end

    test "wait/1 returns immediately when the terminal already arrived" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:ok, {:exited, 0}} = P.wait(session)
    end

    test "wait/1 blocks until the terminal event arrives" do
      {:ok, session} = P.spawn(argv: ["/bin/sh", "-c", "sleep 0.1; exit 7"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)

      # Don't drain the :running / :exited messages -- wait/1 should
      # block on its own and return when the workload finishes.
      assert {:ok, {:exited, 7}} = P.wait(session, 2_000)
    end

    test "wait/2 returns {:error, :timeout} while the workload is alive" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      # 100 ms is far short of /bin/sleep 60 -- we should time out cleanly.
      assert {:error, :timeout} = P.wait(session, 100)

      # The session is still alive; clean up.
      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "signal/2 after the workload has ended returns {:error, :ended}" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # The workload no longer exists.
      assert {:error, :ended} = P.signal(session, 15)
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

      :ok = P.proceed(session)

      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 0}, 2_000
    end
  end

  describe "stdio plumbing" do
    test "stdio: :inherit is accepted (the default; happy path covered elsewhere)" do
      # All the other tests run with implicit :inherit; this one just
      # confirms passing the atom explicitly also works. Drives the full
      # lifecycle so the agent doesn't linger in await_proceed past the
      # end of the test.
      {:ok, session} = P.spawn(argv: ["/bin/true"], stdio: :inherit)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000
    end

    test "rejects an unknown :stdio atom" do
      assert {:error, :bad_stdio} = P.spawn(argv: ["/bin/true"], stdio: :tty)
    end

    test "rejects an invalid per-fd directive" do
      assert {:error, :bad_stdio} =
               P.spawn(argv: ["/bin/true"], stdio: [stdin: :something_weird])
    end

    test ":devnull silences a chatty workload" do
      # echo writes to stdout; with stdio :devnull the test process should
      # not see "noise" in its mailbox.
      {:ok, session} =
        P.spawn(argv: ["/bin/echo", "noise"], stdio: :devnull)

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 0}, 2_000

      refute_received {:linx_process, :pty_out, _}
    end

    test "{:connect_unix, path} delivers stdout bytes to a host listener" do
      socket_path =
        Path.join(System.tmp_dir!(), "linx_test_#{System.unique_integer([:positive])}.sock")

      _ = File.rm(socket_path)

      {:ok, listener} =
        :gen_tcp.listen(0, [
          {:ifaddr, {:local, socket_path}},
          :binary,
          {:active, false}
        ])

      try do
        {:ok, session} =
          P.spawn(
            argv: ["/bin/echo", "hello-from-the-child"],
            stdio: [stdout: {:connect_unix, socket_path}]
          )

        assert_receive {:linx_process, :ready, _}, 2_000
        :ok = P.proceed(session)

        {:ok, sock} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, "hello-from-the-child\n"} = :gen_tcp.recv(sock, 0, 2_000)
        :gen_tcp.close(sock)

        assert_receive {:linx_process, :exited, 0}, 2_000
      after
        :gen_tcp.close(listener)
        File.rm(socket_path)
      end
    end

    test "stdio: :pty round-trips bytes through the control channel" do
      # /bin/echo writes "hi" + newline to stdout. With stdio :pty the
      # bytes flow back as {:linx_process, :pty_out, _}.
      {:ok, session} = P.spawn(argv: ["/bin/echo", "hi"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000

      assert {:ok, ^session} = P.pty_master(session)

      :ok = P.proceed(session)

      # A PTY in cooked mode translates LF to CRLF on output -- expect "hi\r\n".
      assert_pty_out_contains(session, "hi\r\n", 2_000)

      assert {:ok, {:exited, 0}} = P.wait(session, 2_000)
    end

    test "pty_write/2 errors when the session isn't in PTY mode" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      assert {:error, :no_pty} = P.pty_write(session, "hello")
      assert {:error, :no_pty} = P.pty_master(session)

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000
      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end
  end

  # Collect :pty_out chunks until the cumulative bytes contain `needle` or
  # the timeout expires. The agent emits chunks as the workload writes
  # them, so output can arrive split across messages.
  defp assert_pty_out_contains(_session, needle, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    loop_pty_out("", needle, deadline)
  end

  defp loop_pty_out(seen, needle, deadline) do
    if String.contains?(seen, needle) do
      :ok
    else
      remaining = max(deadline - System.monotonic_time(:millisecond), 0)

      receive do
        {:linx_process, :pty_out, chunk} ->
          loop_pty_out(seen <> chunk, needle, deadline)
      after
        remaining ->
          flunk("expected pty_out containing #{inspect(needle)}, got #{inspect(seen)}")
      end
    end
  end

  describe "enter/2" do
    test "rejects a non-positive target pid" do
      assert_raise FunctionClauseError, fn -> P.enter(0, argv: ["/bin/true"]) end
      assert_raise FunctionClauseError, fn -> P.enter(-1, argv: ["/bin/true"]) end
    end

    test "rejects opts without :argv" do
      assert {:error, :argv_required} = P.enter(1, [])
    end

    # The motivating use case: spawn a child in a fresh netns and then
    # enter that netns from elsewhere to run a probe. Joining
    # CLONE_NEWNET (the target's netns) needs CAP_SYS_ADMIN, so
    # :integration.
    @tag :integration
    test "joins a target's netns and the workload sees only its lo" do
      {:ok, sleeper} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net])
      assert_receive {:linx_process, :ready, target_pid}, 2_000
      :ok = P.proceed(sleeper)
      assert_receive {:linx_process, :running}, 2_000

      # The probe: a fresh netns has only `lo` -- so `ip -o link | wc -l`
      # is exactly 1 inside it. The shell exits 0 iff that holds.
      {:ok, prober} =
        P.enter(target_pid,
          argv: ["/bin/sh", "-c", "test \"$(ip -o link | wc -l)\" = \"1\""]
        )

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(prober)
      assert {:ok, {:exited, 0}} = P.wait(prober, 5_000)

      # Clean up the sleeper.
      :ok = P.signal(sleeper, 9)
      assert_receive {:linx_process, :signaled, 9}, 5_000
    end

    @tag :integration
    test "explicit :namespaces joins only the listed types" do
      {:ok, sleeper} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net])
      assert_receive {:linx_process, :ready, target_pid}, 2_000
      :ok = P.proceed(sleeper)
      assert_receive {:linx_process, :running}, 2_000

      # namespaces: [:net] only -- mount/pid/etc. stay the host's,
      # netns becomes the target's. Same exit-code assertion as above.
      {:ok, prober} =
        P.enter(target_pid,
          namespaces: [:net],
          argv: ["/bin/sh", "-c", "test \"$(ip -o link | wc -l)\" = \"1\""]
        )

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(prober)
      assert {:ok, {:exited, 0}} = P.wait(prober, 5_000)

      :ok = P.signal(sleeper, 9)
      assert_receive {:linx_process, :signaled, 9}, 5_000
    end
  end
end
