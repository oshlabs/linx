defmodule Linx.TtyTest do
  use ExUnit.Case, async: true

  alias Linx.Tty

  describe "NIF scaffolding" do
    test "version/0 reflects the running milestone" do
      v = Tty.version()
      assert is_binary(v)
      assert String.starts_with?(v, "linx_tty ")
      # T1 marker -- bumped per milestone in c_src/linx_tty.c.
      assert String.ends_with?(v, "(T1)")
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

  describe "attach/2 stub" do
    test "attach/2 is not yet implemented (lands in T2)" do
      assert {:error, :not_yet_implemented} = Tty.attach(:controlling, self())
    end
  end
end
