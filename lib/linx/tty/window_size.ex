defmodule Linx.Tty.WindowSize do
  @moduledoc """
  The size of a terminal — rows, columns, and optional pixel
  dimensions. The shape of `struct winsize` from `<sys/ioctl.h>`.

  Returned by `Linx.Tty.window_size/1`; passed to
  `Linx.Tty.set_window_size/2` and `Linx.Process.pty_set_winsize/2`.

  `rows` and `cols` are what every terminal-aware program cares about
  (`vim`, `top`, `less`). `xpixel` / `ypixel` are the legacy
  pixel-dimensions fields — almost always reported as `0` by modern
  terminal emulators and ignored by most consumers; included for ABI
  faithfulness so a relay (e.g. `Linx.Tty.attach/2`) can shuttle the
  full struct.
  """

  @enforce_keys [:rows, :cols, :xpixel, :ypixel]
  defstruct [:rows, :cols, :xpixel, :ypixel]

  @type t :: %__MODULE__{
          rows: non_neg_integer(),
          cols: non_neg_integer(),
          xpixel: non_neg_integer(),
          ypixel: non_neg_integer()
        }

  defimpl Inspect do
    def inspect(%{rows: r, cols: c, xpixel: xp, ypixel: yp}, _opts) do
      pixels = if xp == 0 and yp == 0, do: "", else: " #{xp}x#{yp}px"
      "#Linx.Tty.WindowSize<#{c}x#{r}#{pixels}>"
    end
  end
end
