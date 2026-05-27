defmodule Linx.TtyTest do
  use ExUnit.Case, async: true

  alias Linx.Tty
  alias Linx.Tty.Env

  describe "Env.classify_caller_terminal/1" do
    test "classifies a GL with :ssh_sup in $ancestors as :ssh" do
      gl = spawn_fake_gl(ancestors: [self(), :sshd_sup, :ssh_sup])
      assert Env.classify_caller_terminal(gl) == :ssh
      stop_fake_gl(gl)
    end

    test "classifies a GL with :sshd_sup but no :ssh_sup as :ssh" do
      # nerves_ssh's wrapper supervisor is enough on its own.
      gl = spawn_fake_gl(ancestors: [self(), :sshd_sup])
      assert Env.classify_caller_terminal(gl) == :ssh
      stop_fake_gl(gl)
    end

    test "classifies a GL with neither SSH supervisor as :local_tty" do
      gl = spawn_fake_gl(ancestors: [self(), :kernel_sup])
      assert Env.classify_caller_terminal(gl) == :local_tty
      stop_fake_gl(gl)
    end

    test "classifies a GL with an empty $ancestors as :local_tty" do
      gl = spawn_fake_gl(ancestors: [])
      assert Env.classify_caller_terminal(gl) == :local_tty
      stop_fake_gl(gl)
    end

    test "classifies a dead GL as :unknown" do
      pid = spawn(fn -> :ok end)
      # Wait for it to actually exit.
      ref = Process.monitor(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 500

      assert Env.classify_caller_terminal(pid) == :unknown
    end

    test "zero-arity reads Process.group_leader/0" do
      # In `mix test` the default group leader is ExUnit's IO server,
      # which doesn't have SSH supervisors in its ancestor chain.
      # We can't assert it's exactly :local_tty (depends on which
      # IO server ExUnit installed), but we can assert it's NOT :ssh.
      refute Env.classify_caller_terminal() == :ssh
    end
  end

  describe "attach(:controlling, _) guard (T6.0)" do
    test "refuses with :no_local_tty when called under an SSH-like GL" do
      gl = spawn_fake_gl(ancestors: [self(), :sshd_sup, :ssh_sup])
      original_gl = Process.group_leader()
      Process.group_leader(self(), gl)

      try do
        # The guard runs before any /dev/tty access, so we should get
        # the typed refusal even without a real session pid -- the
        # function only requires the second arg be a pid for the
        # is_pid/1 guard. We synthesise a session pid that we
        # immediately ignore.
        fake_session = spawn_link(fn -> Process.sleep(:infinity) end)
        assert {:error, :no_local_tty} = Tty.attach(:controlling, fake_session)
      after
        Process.group_leader(self(), original_gl)
        stop_fake_gl(gl)
      end
    end

    test "format_error/1 explains the :no_local_tty refusal" do
      msg = Tty.format_error(:no_local_tty)
      assert is_binary(msg)
      assert msg =~ "SSH"
      assert msg =~ "attach(:group_leader, session)"
    end

    test "format_error/1 falls back to inspect for unknown shapes" do
      assert Tty.format_error({:some, :tuple}) == "{:some, :tuple}"
      assert Tty.format_error(:weird_atom) == ":weird_atom"
    end
  end

  describe "NIF scaffolding" do
    test "version/0 reflects the running milestone" do
      v = Tty.version()
      assert is_binary(v)
      assert String.starts_with?(v, "linx_tty ")
      # T3 marker -- bumped per milestone in c_src/linx_tty.c.
      assert String.ends_with?(v, "(T3)")
    end
  end

  describe "window_size/1 (TIOCGWINSZ)" do
    test "returns ENOTTY on a non-tty fd" do
      # fd 0 in `mix test` is the BEAM's stdin, generally not a tty.
      assert {:error, {:ioctl, :enotty}} = Tty.window_size(0)
    end

    test "returns EBADF on a closed/invalid fd" do
      # fd 99999 is far past anything ExUnit holds open.
      assert {:error, {:ioctl, :ebadf}} = Tty.window_size(99_999)
    end
  end

  describe "set_window_size/2 (TIOCSWINSZ)" do
    test "returns ENOTTY on a non-tty fd" do
      ws = %Linx.Tty.WindowSize{rows: 24, cols: 80, xpixel: 0, ypixel: 0}
      assert {:error, {:ioctl, :enotty}} = Tty.set_window_size(0, ws)
    end

    test "rejects window dimensions that wouldn't fit in struct winsize" do
      ws = %Linx.Tty.WindowSize{rows: 24, cols: 80, xpixel: 0, ypixel: 70_000}
      assert {:error, {:ioctl, :einval}} = Tty.set_window_size(0, ws)
    end
  end

  describe "open_controlling_raw/0 + restore_and_close/2" do
    # `mix test` is typically launched from a real terminal, so /dev/tty
    # opens fine. We immediately restore so the user's terminal mode
    # isn't disturbed for more than a few microseconds. If the BEAM has
    # no controlling tty (rare for `mix test`; common in CI), the open
    # returns ENXIO -- accept that cleanly.
    test "round-trips when a controlling tty exists, or errors cleanly when it doesn't" do
      case Tty.open_controlling_raw() do
        {:ok, fd, saved} ->
          assert is_integer(fd) and fd >= 0
          assert %Linx.Tty.Saved{termios: bin} = saved
          assert is_binary(bin) and byte_size(bin) > 0

          # Restoring before we ever leave the test keeps the test
          # runner's terminal mode untouched in practice.
          assert :ok = Tty.restore_and_close(fd, saved)

          # And it's idempotent against the already-closed fd.
          assert :ok =
                   Tty.restore_and_close(fd, saved) or
                     match?({:error, {_, _}}, Tty.restore_and_close(fd, saved))

        {:error, {:open, :enxio}} ->
          :ok

        other ->
          flunk("unexpected open result: #{inspect(other)}")
      end
    end

    test "the saved struct's bytes are opaque to Inspect" do
      # Confirms Saved's Inspect impl doesn't leak the binary contents
      # even when it carries real termios bytes from the NIF.
      case Tty.open_controlling_raw() do
        {:ok, fd, saved} ->
          assert inspect(saved) == "#Linx.Tty.Saved<…>"
          assert :ok = Tty.restore_and_close(fd, saved)

        {:error, {:open, :enxio}} ->
          :ok
      end
    end
  end

  describe "value-type structs" do
    test "Saved.t/0 has an opaque Inspect impl" do
      saved = %Linx.Tty.Saved{termios: <<1, 2, 3>>}
      assert inspect(saved) == "#Linx.Tty.Saved<…>"
    end

    test "WindowSize.t/0 renders as cols x rows" do
      assert inspect(%Linx.Tty.WindowSize{rows: 24, cols: 80, xpixel: 0, ypixel: 0}) ==
               "#Linx.Tty.WindowSize<80x24>"
    end

    test "WindowSize.t/0 includes pixel dimensions when non-zero" do
      assert inspect(%Linx.Tty.WindowSize{rows: 24, cols: 80, xpixel: 800, ypixel: 480}) ==
               "#Linx.Tty.WindowSize<80x24 800x480px>"
    end
  end

  describe "Native.socketpair/0" do
    test "returns two connected fds" do
      assert {:ok, {a, b}} = Linx.Tty.Native.socketpair()
      assert is_integer(a) and is_integer(b)
      assert a != b

      # Sanity: writing to one shows up on the other via a wrapped port.
      port_a = :erlang.open_port({:fd, a, a}, [:binary, :stream])
      port_b = :erlang.open_port({:fd, b, b}, [:binary, :stream])

      Port.command(port_a, "ping")
      assert_receive {^port_b, {:data, "ping"}}, 1_000

      Port.close(port_a)
      Port.close(port_b)
    end
  end

  describe "attach/2 via socketpair stand-in" do
    # PLAN's T2 testing strategy: spawn /bin/cat with stdio: :pty, build
    # a socketpair to stand in for /dev/tty, run the pump on one end and
    # drive the "user side" from a helper process. The test's real
    # terminal is never touched.

    test "round-trips bytes through the pump" do
      # PTY-mode cat -- the session's owner is this test process, so
      # :pty_out events arrive in our mailbox where the pump can read
      # them.
      {:ok, session} = Linx.Process.spawn(argv: ["/bin/cat"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = Linx.Process.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, {user_fd, attach_fd}} = Linx.Tty.Native.socketpair()
      test_pid = self()

      # The "user side" runs in its own process so it can drive the
      # fake-tty independently of the pump (which blocks in this
      # process). It writes "hello\n" and watches for cat's echo;
      # once it sees the echo back, it signals the session so the
      # pump returns with {:signaled, _}.
      _user_pid =
        spawn_link(fn ->
          user_port = :erlang.open_port({:fd, user_fd, user_fd}, [:binary, :stream])
          Port.command(user_port, "hello\n")
          collect_until_seen(user_port, "", "hello", test_pid, session)
        end)

      attach_port = :erlang.open_port({:fd, attach_fd, attach_fd}, [:binary, :stream])

      result = Linx.Tty.__pump__(attach_port, session)

      # The user side caused the signal; the workload was SIGTERM'd.
      assert {:ok, {:signaled, 15}} = result

      # And the user side saw the cat-echoed bytes come back.
      assert_receive {:user_saw, seen}, 2_000
      assert String.contains?(seen, "hello")
    end

    test "returns terminal event when the workload exits naturally" do
      # No bytes-in-flight; just spawn /bin/true via PTY, attach,
      # observe :exited 0 propagating cleanly through the pump.
      {:ok, session} = Linx.Process.spawn(argv: ["/bin/true"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = Linx.Process.proceed(session)
      # /bin/true exits ~immediately; running/exited will arrive in our
      # mailbox to be picked up by the pump.

      {:ok, {_user_fd, attach_fd}} = Linx.Tty.Native.socketpair()
      attach_port = :erlang.open_port({:fd, attach_fd, attach_fd}, [:binary, :stream])

      assert {:ok, {:exited, 0}} = Linx.Tty.__pump__(attach_port, session)
    end

    test "propagates pre-exec errors as {:error, %{errno, stage}}" do
      # execve fails on a missing binary; the session emits
      # {:linx_process, :error, _, :execve}. The pump translates that
      # into the public error shape.
      {:ok, session} = Linx.Process.spawn(argv: ["/does/not/exist"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = Linx.Process.proceed(session)

      {:ok, {_user_fd, attach_fd}} = Linx.Tty.Native.socketpair()
      attach_port = :erlang.open_port({:fd, attach_fd, attach_fd}, [:binary, :stream])

      assert {:error, %{errno: 2, stage: :execve}} =
               Linx.Tty.__pump__(attach_port, session)
    end
  end

  describe "SigwinchHandler" do
    # The gen_event-side machinery is straightforward to test against a
    # bespoke event manager (no need to touch the real
    # `:erl_signal_server` and risk SIGWINCH-while-tests-run flakes).

    test "forwards :sigwinch to the target pid" do
      {:ok, mgr} = :gen_event.start_link()
      :ok = :gen_event.add_handler(mgr, Linx.Tty.SigwinchHandler, self())

      :ok = :gen_event.notify(mgr, :sigwinch)
      assert_receive {:linx_tty, :sigwinch}, 500

      :ok = :gen_event.stop(mgr)
    end

    test "ignores other events" do
      {:ok, mgr} = :gen_event.start_link()
      :ok = :gen_event.add_handler(mgr, Linx.Tty.SigwinchHandler, self())

      :ok = :gen_event.notify(mgr, :sigterm)
      :ok = :gen_event.notify(mgr, :sigchld)
      refute_receive {:linx_tty, _}, 100

      :ok = :gen_event.stop(mgr)
    end

    test "ID-keyed instances coexist (concurrent attaches)" do
      # Each attach uses {SigwinchHandler, ref}; two parallel
      # registrations should both receive the broadcast.
      {:ok, mgr} = :gen_event.start_link()

      ref_a = make_ref()
      ref_b = make_ref()
      :ok = :gen_event.add_handler(mgr, {Linx.Tty.SigwinchHandler, ref_a}, self())
      :ok = :gen_event.add_handler(mgr, {Linx.Tty.SigwinchHandler, ref_b}, self())

      :ok = :gen_event.notify(mgr, :sigwinch)
      # Both handlers fire; both forward to us.
      assert_receive {:linx_tty, :sigwinch}, 500
      assert_receive {:linx_tty, :sigwinch}, 500

      :ok = :gen_event.stop(mgr)
    end
  end

  describe "__pump__/3 sigwinch handling" do
    # Verify the pump's sigwinch clause: when a sigwinch event arrives,
    # if local_fd is nil (test path) it's a no-op; if it's a real tty
    # fd, the pump re-reads window_size and forwards. We test the
    # arity-2 / nil-local_fd path here -- the integration path is
    # covered manually (resize the terminal during an attached vim).

    test "ignores :sigwinch when local_fd is nil" do
      {:ok, session} = Linx.Process.spawn(argv: ["/bin/cat"], stdio: :pty)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = Linx.Process.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, {_user_fd, attach_fd}} = Linx.Tty.Native.socketpair()
      attach_port = :erlang.open_port({:fd, attach_fd, attach_fd}, [:binary, :stream])

      # Inject a sigwinch into our own mailbox. With local_fd
      # defaulting to nil (arity-2 call) the pump should consume it
      # without crashing and continue waiting for other messages.
      send(self(), {:linx_tty, :sigwinch})

      # Helper signals after a moment so the pump returns with a
      # known terminal event.
      spawn_link(fn ->
        Process.sleep(100)
        :ok = Linx.Process.signal(session, 15)
      end)

      assert {:ok, {:signaled, 15}} = Linx.Tty.__pump__(attach_port, session)
    end
  end

  # Spawn a process that parks in receive with the given
  # $ancestors list installed in its process dictionary. Used by
  # the Env tests to drive classify_caller_terminal/1 against
  # fixture pids without depending on real SSH plumbing.
  defp spawn_fake_gl(opts) do
    ancestors = Keyword.get(opts, :ancestors, [])
    parent = self()

    pid =
      spawn_link(fn ->
        Process.put(:"$ancestors", ancestors)
        send(parent, :ready)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive :ready, 500
    pid
  end

  defp stop_fake_gl(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      send(pid, :stop)
    end

    :ok
  end

  # Read from `port` until `seen` contains `needle`, then signal the
  # session (so the pump returns) and forward what we saw back to
  # `test_pid` for assertion.
  defp collect_until_seen(port, acc, needle, test_pid, session) do
    receive do
      {^port, {:data, bytes}} ->
        acc = acc <> bytes

        if String.contains?(acc, needle) do
          send(test_pid, {:user_saw, acc})
          :ok = Linx.Process.signal(session, 15)
        else
          collect_until_seen(port, acc, needle, test_pid, session)
        end
    after
      2_000 ->
        send(test_pid, {:user_saw, acc})
    end
  end
end
