defmodule Linx.TtyTest do
  use ExUnit.Case, async: true

  alias Linx.Tty

  describe "NIF scaffolding" do
    test "version/0 reflects the running milestone" do
      v = Tty.version()
      assert is_binary(v)
      assert String.starts_with?(v, "linx_tty ")
      # T2 marker -- bumped per milestone in c_src/linx_tty.c.
      assert String.ends_with?(v, "(T2)")
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
