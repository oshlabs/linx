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
      assert {:error, {:bad_argv, _}} = P.spawn(argv: ["/bin/true", :nope])
    end

    test "rejects an unknown namespace atom" do
      assert {:error, {:bad_namespaces, [:typo]}} =
               P.spawn(argv: ["/bin/true"], namespaces: [:net, :typo])
    end

    test "rejects a non-list :env" do
      assert {:error, {:bad_env, _}} = P.spawn(argv: ["/bin/true"], env: "PATH=/bin")
    end

    test "rejects a non-binary :cwd" do
      assert {:error, {:bad_cwd, 42}} = P.spawn(argv: ["/bin/true"], cwd: 42)
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

    test ":cwd runs the workload in that directory (chdir before execve)" do
      dir = Path.join(System.tmp_dir!(), "linx-cwd-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      # `touch marker` is relative, so the file lands in :cwd only if the
      # child chdir'd there before execve.
      {:ok, session} = P.spawn(argv: ["/bin/sh", "-c", "touch marker"], cwd: dir)

      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert File.exists?(Path.join(dir, "marker"))
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

    test "signal/2 after the workload has ended returns {:error, :no_process}" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # The workload no longer exists.
      assert {:error, :no_process} = P.signal(session, 15)
    end
  end

  describe "host_pid/1" do
    test "returns the host's view of the child's pid after :ready" do
      # No :pid namespace -> the :ready event's value IS the host
      # pid, so we can cross-check.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "10"])
      assert_receive {:linx_process, :ready, ready_pid}, 2_000

      assert {:ok, host_pid} = P.host_pid(session)
      assert is_integer(host_pid) and host_pid > 0
      assert host_pid == ready_pid

      # Clean up.
      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    @tag :integration
    test "with :pid namespace, :ready carries the host pid; info exposes the in-ns pid" do
      # :ready always reports the workload's *host* pid -- even when :pid is
      # in the namespaces list. The child's own in-namespace view (PID 1 in
      # a fresh pid ns) is surfaced separately, via info/1's :child_pid.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "10"], namespaces: [:pid])
      assert_receive {:linx_process, :ready, ready_pid}, 2_000

      # The :ready value is the host pid (== host_pid/1), not 1.
      assert {:ok, host_pid} = P.host_pid(session)
      assert ready_pid == host_pid
      assert is_integer(host_pid) and host_pid > 1

      # The in-namespace view lives in info/1: the child is PID 1.
      assert {:ok, info} = P.info(session)
      assert info.child_pid == 1
      assert info.host_pid == host_pid

      # And that host_pid actually points at a live process in
      # /proc -- sanity check.
      assert File.exists?("/proc/#{host_pid}")

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "host_pid/1 keeps returning the same value across the lifecycle" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000

      assert {:ok, p1} = P.host_pid(session)

      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # The host pid the session reports doesn't change just
      # because the workload exited -- the stored value persists
      # (useful for post-mortem logging / inspection).
      assert {:ok, p2} = P.host_pid(session)
      assert p1 == p2
    end
  end

  describe "abort/1" do
    test "abort/1 on a :ready parked session discards the workload" do
      # /bin/sleep 60 would normally run for a minute; abort/1 means
      # it never gets to execve, so we see :aborted in milliseconds,
      # not :signaled or :exited.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = P.abort(session)

      assert_receive {:linx_process, :aborted}, 2_000

      # No :running was ever delivered -- the workload never started.
      refute_receive {:linx_process, :running}, 100

      assert {:ok, :aborted} = P.wait(session)
    end

    test "abort/1 before :ready is buffered, fires at the checkpoint" do
      # Race the abort against the agent's :ready emission. The
      # GenServer buffers the abort and delivers it the moment the
      # checkpoint is reached -- same shape as signal/2's pre-:running
      # buffering.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])

      # Don't drain :ready -- send abort straight away. The GenServer
      # receives this call before its handle_info processes the
      # :ready frame from the port; abort is queued in state.
      :ok = P.abort(session)

      # Both :ready and :aborted should arrive; :running should not.
      assert_receive {:linx_process, :ready, _}, 2_000
      assert_receive {:linx_process, :aborted}, 2_000
      refute_receive {:linx_process, :running}, 100

      assert {:ok, :aborted} = P.wait(session)
    end

    test "abort/1 after :running returns {:error, :running}" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      # Past the checkpoint -- abort is no longer the right call;
      # signal/2 is.
      assert {:error, :running} = P.abort(session)

      # Clean up.
      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "abort/1 after the session has terminated returns :no_process" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} = P.abort(session)
    end

    test "proceed/1 after the session has terminated returns :no_process" do
      # Same shape as the abort/1 terminal-guard test -- proceed
      # and abort are sibling checkpoint verbs.
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} = P.proceed(session)
    end

    test "wait/1 with a timeout sees :aborted as a terminal" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = P.abort(session)

      # wait/1 should resolve quickly with the :aborted shape, not
      # block until the (non-existent) workload finishes.
      assert {:ok, :aborted} = P.wait(session, 2_000)
    end
  end

  describe "spawn/1 with fresh namespaces" do
    # Creating any namespace other than CLONE_NEWUSER needs CAP_SYS_ADMIN.
    # The :integration tag keeps these out of `mix test` by default; run
    # with `./sudotest.sh` or `mix test --include integration` as root.
    @tag :integration
    test "namespaces: [:net] gives the child a fresh, isolated netns" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], namespaces: [:net])

      assert_receive {:linx_process, :ready, host_pid}, 2_000

      # The :ready value is the workload's host pid -- hand it straight to
      # Linx.Netlink, which opens /proc/<host_pid>/ns/net.
      {:ok, sock} = Linx.Netlink.Rtnl.open({:pid, host_pid})
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
      assert {:error, {:bad_stdio, _}} = P.spawn(argv: ["/bin/true"], stdio: :tty)
    end

    test "rejects an invalid per-fd directive" do
      assert {:error, {:bad_stdio, _}} =
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

    test "{:connect_unix, path} connects at spawn time and delivers stdout bytes" do
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

        # The agent connects host-side on receipt of the request, so the
        # accept completes while the workload is still parked at the
        # checkpoint — before proceed/1. (This timing is the contract
        # that makes the path immune to checkpoint-window rootfs pivots:
        # the fd exists before the child's mount view can diverge.)
        {:ok, sock} = :gen_tcp.accept(listener, 2_000)
        assert_receive {:linx_process, :ready, _}, 2_000

        # Connected ≠ exec'd: no bytes flow until :proceed.
        assert {:error, :timeout} = :gen_tcp.recv(sock, 0, 100)

        :ok = P.proceed(session)
        assert {:ok, "hello-from-the-child\n"} = :gen_tcp.recv(sock, 0, 2_000)

        assert_receive {:linx_process, :exited, 0}, 2_000

        # The agent closed its copy of the fd after clone, so the workload
        # exiting closes the last writer and the listener side sees EOF.
        assert {:error, :closed} = :gen_tcp.recv(sock, 0, 2_000)
        :gen_tcp.close(sock)
      after
        :gen_tcp.close(listener)
        File.rm(socket_path)
      end
    end

    test "{:connect_unix, path} with nothing at path fails at spawn, before :ready" do
      # The agent's host-side connect fails on receipt of the request —
      # the workload is never created. ENOENT = 2.
      path =
        Path.join(System.tmp_dir!(), "linx_absent_#{System.unique_integer([:positive])}.sock")

      {:ok, _session} = P.spawn(argv: ["/bin/true"], stdio: [stdout: {:connect_unix, path}])

      assert_receive {:linx_process, :error, 2, :connect_unix}, 2_000
      refute_received {:linx_process, :ready, _}
    end

    test "{:connect_unix, path} exceeding sun_path fails with ENAMETOOLONG" do
      # sun_path caps AF_UNIX paths at ~107 bytes; the agent checks before
      # connecting. ENAMETOOLONG = 36.
      long_path = Path.join(System.tmp_dir!(), String.duplicate("x", 200) <> ".sock")

      {:ok, _session} =
        P.spawn(argv: ["/bin/true"], stdio: [stdout: {:connect_unix, long_path}])

      assert_receive {:linx_process, :error, 36, :connect_unix}, 2_000
      refute_received {:linx_process, :ready, _}
    end

    @tag :integration
    test "{:connect_unix, path} crosses fresh :mount and :net namespaces" do
      # The fd is connected before the namespaces even exist, so neither a
      # diverging mount view nor an isolated netns can break it — the
      # workload inherits an already-connected socket on fd 1.
      socket_path =
        Path.join(System.tmp_dir!(), "linx_test_ns_#{System.unique_integer([:positive])}.sock")

      _ = File.rm(socket_path)

      {:ok, listener} =
        :gen_tcp.listen(0, [{:ifaddr, {:local, socket_path}}, :binary, {:active, false}])

      try do
        {:ok, session} =
          P.spawn(
            argv: ["/bin/echo", "hello-across-namespaces"],
            namespaces: [:mount, :net],
            stdio: [stdout: {:connect_unix, socket_path}]
          )

        {:ok, sock} = :gen_tcp.accept(listener, 2_000)
        assert_receive {:linx_process, :ready, _}, 2_000
        :ok = P.proceed(session)

        assert {:ok, "hello-across-namespaces\n"} = :gen_tcp.recv(sock, 0, 2_000)
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
      assert {:error, :no_pty} = P.pty_set_winsize(session, {24, 80, 0, 0})

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000
      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "pty_set_winsize/2 propagates the size to the workload" do
      # /usr/bin/stty (or /bin/stty -- via sh's PATH lookup) prints
      # "<rows> <cols>" on stdout when called with `size`. With the
      # workload running on a PTY, that's an observable signal that
      # TIOCSWINSZ on the master propagated through.
      {:ok, session} =
        P.spawn(argv: ["/bin/sh", "-c", "stty size"], stdio: :pty)

      assert_receive {:linx_process, :ready, _}, 2_000

      # Set the size *before* proceed -- stty reads the size when it
      # starts, so the ioctl needs to land on the master before the
      # child execve's.
      :ok = P.pty_set_winsize(session, {42, 132, 0, 0})

      :ok = P.proceed(session)
      assert_pty_out_contains(session, "42 132", 2_000)
      assert {:ok, {:exited, 0}} = P.wait(session, 2_000)
    end

    test "pty_write/2 refuses with :not_running at the checkpoint (M9)" do
      {:ok, session} = P.spawn(argv: ["/bin/cat"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000

      # The agent's await_proceed treats {:pty_in, _} as a protocol error
      # and kills the parked workload — the session must refuse instead.
      assert {:error, :not_running} = P.pty_write(session, "x")

      # And the refusal must leave the session fully usable.
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000
      :ok = P.pty_write(session, "hello\n")
      assert_pty_out_contains(session, "hello", 2_000)
      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "pty_write/2 splits large writes below the agent frame ceiling (M7)" do
      {:ok, session} = P.spawn(argv: ["/bin/cat"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      # 64 KiB in 1 KiB lines — twice the agent's 32 KiB frame ceiling and
      # far past the ~4 KiB tty input queue. Before chunking + the agent's
      # write buffer this either went out as one oversized frame (agent
      # declares :command_too_big and SIGKILLs the workload) or lost the
      # tail on EAGAIN. Lines stay under the 4095-byte canonical-mode
      # line limit so the tty itself never discards input.
      line = String.duplicate("a", 1023) <> "\n"
      :ok = P.pty_write(session, String.duplicate(line, 64))

      refute_receive {:linx_process, :error, _, :command_too_big}, 200

      # The workload is still alive and interactive after the flood.
      :ok = P.pty_write(session, "marker\n")
      assert_pty_out_contains(session, "marker", 10_000)

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 5_000
    end

    test "pty_write/2 refuses with :no_process after the workload has terminated" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # Workload has exited. Sending pty_write should refuse rather
      # than fire a Port.command at a closing agent.
      assert {:error, :no_process} = P.pty_write(session, "ignored")
    end

    test "pty_set_winsize/2 refuses with :no_process after the workload has terminated" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} = P.pty_set_winsize(session, {24, 80, 0, 0})
    end

    test "pty_set_winsize/2 rejects a malformed size with a tagged tuple" do
      assert {:error, {:bad_winsize, :nope}} = P.pty_set_winsize(self(), :nope)
    end

    test "pty_set_winsize/2 accepts a struct-shaped map" do
      {:ok, session} =
        P.spawn(argv: ["/bin/sh", "-c", "stty size"], stdio: :pty)

      assert_receive {:linx_process, :ready, _}, 2_000

      # Pretending to be %Linx.Tty.WindowSize{} -- Linx.Process duck-types
      # on the field shape so it doesn't need to depend on Linx.Tty.
      ws = %{rows: 21, cols: 99, xpixel: 0, ypixel: 0}
      :ok = P.pty_set_winsize(session, ws)

      :ok = P.proceed(session)
      assert_pty_out_contains(session, "21 99", 2_000)
      assert {:ok, {:exited, 0}} = P.wait(session, 2_000)
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

  describe "set_owner/2" do
    test "redirects lifecycle and pty_out to the new owner, and hands back" do
      {:ok, session} = P.spawn(argv: ["/bin/cat"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      test = self()
      relay = spawn_link(fn -> relay_loop(test) end)
      :ok = P.set_owner(session, relay)

      # The PTY echoes input; that :pty_out now lands on the relay, which
      # forwards it here tagged -- not on this test process directly.
      :ok = P.pty_write(session, "ping\n")
      assert_receive {:relayed, {:linx_process, :pty_out, bytes}}, 2_000
      assert bytes =~ "ping"
      refute_received {:linx_process, :pty_out, _}

      # Hand ownership back; terminal events return to this process.
      :ok = P.set_owner(session, test)
      :ok = P.signal(session, 15)
      assert_receive {:linx_process, :signaled, 15}, 2_000
    end

    test "returns {:error, :no_process} when the session GenServer is gone" do
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      assert_receive {:DOWN, ^ref, :process, ^dead, _}, 1_000

      assert {:error, :no_process} = P.set_owner(dead, self())
    end
  end

  defp relay_loop(dest) do
    receive do
      msg ->
        send(dest, {:relayed, msg})
        relay_loop(dest)
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

    @tag :integration
    test "{:connect_unix, _} stdio connects host-side, before the setns" do
      # Enter mode setns's the *agent itself* into the target's namespaces
      # before forking -- so a connect performed at the child's usual
      # stdio stage would resolve the path in the target's mount/net view.
      # The contract is host-side resolution: the agent connects on
      # receipt of the request, before any setns. Witnessed here by the
      # accept completing against a host listener even though the probe
      # joins a netns-and-mountns-isolated target.
      {:ok, sleeper} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net, :mount])
      assert_receive {:linx_process, :ready, target_pid}, 2_000
      :ok = P.proceed(sleeper)
      assert_receive {:linx_process, :running}, 2_000

      socket_path =
        Path.join(System.tmp_dir!(), "linx_enter_#{System.unique_integer([:positive])}.sock")

      _ = File.rm(socket_path)

      {:ok, listener} =
        :gen_tcp.listen(0, [{:ifaddr, {:local, socket_path}}, :binary, {:active, false}])

      try do
        {:ok, prober} =
          P.enter(target_pid,
            argv: ["/bin/echo", "hello-from-inside"],
            stdio: [stdout: {:connect_unix, socket_path}]
          )

        {:ok, sock} = :gen_tcp.accept(listener, 2_000)
        assert_receive {:linx_process, :ready, _}, 2_000
        :ok = P.proceed(prober)

        assert {:ok, "hello-from-inside\n"} = :gen_tcp.recv(sock, 0, 2_000)
        :gen_tcp.close(sock)

        assert {:ok, {:exited, 0}} = P.wait(prober, 5_000)
      after
        :gen_tcp.close(listener)
        File.rm(socket_path)

        :ok = P.signal(sleeper, 9)
        assert_receive {:linx_process, :signaled, 9}, 5_000
      end
    end
  end

  describe "info/1" do
    alias Linx.Process.Info

    test "returns a %Linx.Process.Info{} with mode: :spawn for spawn sessions" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      assert {:ok, %Info{mode: :spawn} = info} = P.info(session)
      assert info.host_pid > 0
      assert info.child_pid > 0
      assert info.pty? == false
      assert info.result == nil

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "stage progresses :ready -> :running -> :exited" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "0.05"])
      assert_receive {:linx_process, :ready, _}, 2_000

      {:ok, at_ready} = P.info(session)
      assert at_ready.stage == :ready
      assert at_ready.result == nil

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      # Catch the running stage before the workload exits.
      case P.info(session) do
        {:ok, %Info{stage: :running, result: nil}} -> :ok
        # Workload may have already exited if we lost the race; that's
        # also a valid lifecycle observation.
        {:ok, %Info{stage: :exited, result: {:exited, 0}}} -> :ok
      end

      assert_receive {:linx_process, :exited, 0}, 2_000

      {:ok, at_exit} = P.info(session)
      assert at_exit.stage == :exited
      assert at_exit.result == {:exited, 0}
    end

    test "stage is :aborted after abort/1" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000

      assert {:ok, %Info{stage: :aborted, result: :aborted}} = P.info(session)
    end

    test "stage is :signaled with the signal number" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000

      assert {:ok, %Info{stage: :signaled, result: {:signaled, 9}}} =
               P.info(session)
    end

    test "stage is :errored with the error map for pre-exec failures" do
      {:ok, session} = P.spawn(argv: ["/this/does/not/exist"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :error, 2, :execve}, 2_000

      assert {:ok, %Info{stage: :errored} = info} = P.info(session)
      assert info.result == {:error, %Linx.Process.Error{stage: :execve, errno: :enoent, code: 2}}
    end

    test "pty? is true when stdio: :pty" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000

      assert {:ok, %Info{pty?: true}} = P.info(session)

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "session_ended for a dead session" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # spawn/1 uses start_link; unlink before kill so the test
      # process isn't taken down by the EXIT signal.
      Process.unlink(session)
      ref = Process.monitor(session)
      Process.exit(session, :kill)
      assert_receive {:DOWN, ^ref, :process, ^session, _}, 1_000

      assert {:error, :no_process} = P.info(session)
    end
  end

  describe "%Linx.Process.Info{} Inspect" do
    alias Linx.Process.Info

    test "renders mode + stage + host_pid" do
      info = %Info{
        mode: :spawn,
        stage: :ready,
        host_pid: 12345,
        child_pid: 12345,
        pty?: false,
        result: nil
      }

      assert inspect(info) == "#Linx.Process.Info<spawn :ready host=12345>"
    end

    test "renders pty marker when pty? is true" do
      info = %Info{
        mode: :spawn,
        stage: :running,
        host_pid: 12345,
        child_pid: 12345,
        pty?: true,
        result: nil
      }

      assert inspect(info) == "#Linx.Process.Info<spawn :running host=12345 pty>"
    end

    test "renders :exited with the exit code inline" do
      info = %Info{
        mode: :spawn,
        stage: :exited,
        host_pid: 12345,
        child_pid: 12345,
        pty?: false,
        result: {:exited, 0}
      }

      assert inspect(info) ==
               "#Linx.Process.Info<spawn :exited(0) host=12345>"
    end

    test "renders :signaled with the signal number inline" do
      info = %Info{
        mode: :enter,
        stage: :signaled,
        host_pid: 7,
        child_pid: 1,
        pty?: false,
        result: {:signaled, 9}
      }

      assert inspect(info) ==
               "#Linx.Process.Info<enter :signaled(9) host=7>"
    end

    test "renders :errored with stage/errno inline" do
      info = %Info{
        mode: :spawn,
        stage: :errored,
        host_pid: 12345,
        child_pid: nil,
        pty?: false,
        result: {:error, %Linx.Process.Error{stage: :execve, errno: :enoent, code: 2}}
      }

      assert inspect(info) ==
               "#Linx.Process.Info<spawn :errored(execve/2) host=12345>"
    end

    test "renders compactly with no host_pid yet" do
      info = %Info{
        mode: :spawn,
        stage: :starting,
        host_pid: nil,
        child_pid: nil,
        pty?: false,
        result: nil
      }

      assert inspect(info) == "#Linx.Process.Info<spawn :starting>"
    end
  end

  describe "robustness -- defensive handling of unexpected messages" do
    # These exercise the catch-all clauses in handle_info: stray
    # messages, malformed payloads, unrecognised frame shapes, and
    # the synthesised :agent_died terminal on port-exit-without-
    # prior-status. Each starts a real session with /bin/sleep so
    # the GenServer is in a normal state, then injects messages
    # directly into the GenServer's mailbox to simulate the
    # edge case without contriving an actual broken agent.

    import ExUnit.CaptureLog

    test "stray non-port message is logged and ignored" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      log =
        capture_log(fn ->
          send(session, :totally_unexpected)
          # Round-trip a GenServer call to confirm the session is
          # still responsive after the stray message.
          assert {:ok, _} = P.host_pid(session)
        end)

      assert log =~ "ignoring unexpected message"
      assert log =~ ":totally_unexpected"

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "malformed ETF in port-data is logged and dropped" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      port = :sys.get_state(session).port

      log =
        capture_log(fn ->
          send(session, {port, {:data, <<0, 1, 2, 3, 4, 5>>}})
          # GenServer still alive.
          assert {:ok, _} = P.host_pid(session)
        end)

      assert log =~ "malformed agent frame"

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "well-formed but unrecognised frame shape is logged and dropped" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      port = :sys.get_state(session).port
      surprise = :erlang.term_to_binary({:status, :something_new, 42})

      log =
        capture_log(fn ->
          send(session, {port, {:data, surprise}})
          assert {:ok, _} = P.host_pid(session)
        end)

      assert log =~ "unrecognised agent frame"

      :ok = P.abort(session)
      assert_receive {:linx_process, :aborted}, 2_000
    end

    test "port exit before any terminal synthesises :agent_died" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      # Simulate the agent process dying before sending a :status
      # frame -- inject the port {:exit_status, _} directly.
      port = :sys.get_state(session).port
      send(session, {port, {:exit_status, 4}})

      # Owner gets the synthesised error.
      assert_receive {:linx_process, :error, 4, :agent_died}, 2_000

      # wait/1 also sees the synthesised terminal.
      assert {:error, %Linx.Process.Error{stage: :agent_died, code: 4}} =
               P.wait(session, 500)

      # The real workload is still actually running because we faked
      # the port exit; clean up by killing it via the OS so the
      # async test doesn't leak. Use :os.getpid via host_pid? No --
      # host_pid is stored in state but the real port is still
      # alive. Just call P.signal/2 -- if the session GenServer
      # forwards a {:signal, _} to its dead-from-its-pov port, it's
      # a no-op write attempt; if the real port is still alive it
      # delivers SIGKILL to the workload.
      _ = P.signal(session, 9)
    end

    test "port exit AFTER a terminal does not double-fire :agent_died" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      # The agent process exits naturally after :exited; the
      # {:exit_status, 0} arrives at the GenServer. It must NOT
      # synthesise :agent_died -- the terminal is already recorded.
      refute_receive {:linx_process, :error, _, :agent_died}, 200

      # wait/1 still returns the natural exit.
      assert {:ok, {:exited, 0}} = P.wait(session, 500)
    end

    test "real SIGKILL of the agent surfaces :agent_died to the owner" do
      # Exercises the synthesised terminal end-to-end: a real spawned
      # agent gets SIGKILLed from the OS, the BEAM port observes the
      # exit_status, and the owner sees {:linx_process, :error, _,
      # :agent_died} without having received any prior terminal.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      port = :sys.get_state(session).port
      {:os_pid, agent_pid} = Port.info(port, :os_pid)

      # Use the standard `kill` so the test stays portable.
      {_, 0} = System.cmd("kill", ["-9", Integer.to_string(agent_pid)])

      assert_receive {:linx_process, :error, _exit_code, :agent_died}, 2_000

      assert {:error, %Linx.Process.Error{stage: :agent_died}} = P.wait(session, 500)
    end

    test "malformed request: agent emits :malformed_request on its own" do
      # Talk to the linx_process binary directly so we can inject
      # garbage as the first frame (P.spawn would always send a
      # well-formed request, so we bypass it here). Confirms R3's
      # C-side emit_error before `return 2`.
      binary = Path.join(:code.priv_dir(:linx), "linx_process")
      assert File.exists?(binary)

      port =
        Port.open(
          {:spawn_executable, binary},
          [:binary, :nouse_stdio, {:packet, 4}, :exit_status]
        )

      # Not valid Erlang External Term Format -- the agent's
      # ei_decode_version will reject it as a malformed request.
      Port.command(port, <<0, 1, 2, 3, 4>>)

      assert_receive {^port, {:data, payload}}, 2_000
      {:error, errno, stage} = :erlang.binary_to_term(payload)

      # EINVAL = 22 per linux/asm-generic/errno-base.h.
      assert errno == 22
      assert stage == :malformed_request

      assert_receive {^port, {:exit_status, 2}}, 2_000
    end
  end
end
