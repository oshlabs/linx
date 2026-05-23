defmodule Linx.TtyTest do
  use ExUnit.Case, async: true

  alias Linx.Tty

  describe "NIF scaffolding (T0)" do
    test "the native library loaded and version/0 round-trips" do
      # The string shape is "linx_tty <version> (<milestone>)"; pinning
      # the exact bytes would fight version bumps, so just sanity-check
      # the prefix and that it is a binary, not :nif_not_loaded.
      v = Tty.version()
      assert is_binary(v)
      assert String.starts_with?(v, "linx_tty ")
    end
  end

  describe "public API stubs" do
    # These verbs land in T1 (open_controlling_raw, restore_and_close,
    # window_size, set_window_size) and T2 (attach/2). For T0 they
    # exist as compilable stubs so callers can see the surface; each
    # returns :not_yet_implemented.

    test "open_controlling_raw/0 is not yet implemented" do
      assert {:error, :not_yet_implemented} = Tty.open_controlling_raw()
    end

    test "restore_and_close/2 is not yet implemented" do
      saved = %Linx.Tty.Saved{termios: <<0::size(64 * 8)>>}
      assert {:error, :not_yet_implemented} = Tty.restore_and_close(0, saved)
    end

    test "window_size/1 and set_window_size/2 are not yet implemented" do
      ws = %Linx.Tty.WindowSize{rows: 24, cols: 80, xpixel: 0, ypixel: 0}
      assert {:error, :not_yet_implemented} = Tty.window_size(0)
      assert {:error, :not_yet_implemented} = Tty.set_window_size(0, ws)
    end

    test "attach/2 is not yet implemented" do
      assert {:error, :not_yet_implemented} = Tty.attach(:controlling, self())
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
end
