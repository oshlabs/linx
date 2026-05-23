defmodule Linx.Tty.Saved do
  @moduledoc """
  Opaque container for a saved `termios(3)` state.

  Returned by `Linx.Tty.open_controlling_raw/0` and consumed by
  `Linx.Tty.restore_and_close/2`. The wrapped binary is a verbatim
  copy of the kernel's `struct termios` — its bytes are not part of
  the public API. Inspecting or modifying them from Elixir is a bug;
  always hand the struct back to the matching restore function.

  Wrapping it in a struct (rather than handing back a raw binary)
  makes the type visible at call sites and prevents accidentally
  passing the wrong binary as a saved termios.
  """

  @enforce_keys [:termios]
  defstruct [:termios]

  @type t :: %__MODULE__{termios: binary()}

  defimpl Inspect do
    def inspect(_saved, _opts), do: "#Linx.Tty.Saved<…>"
  end
end
