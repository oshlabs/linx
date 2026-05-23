defmodule Linx.Tty.Native do
  @moduledoc """
  NIF binding for `Linx.Tty`. Loads `priv/linx_tty.so` (built by the
  `:linx_tty` Mix compiler) and exposes the small set of `termios(3)`
  / `ioctl(2)` syscalls the public `Linx.Tty` module wraps.

  The functions below are placeholders until the NIF is loaded; calling
  one before `__on_load__/0` runs raises `:nif_not_loaded`. Production
  callers should not use this module directly — go through `Linx.Tty`.
  """

  @on_load :__on_load__

  @doc false
  def __on_load__ do
    :erlang.load_nif(Path.join(:code.priv_dir(:linx), "linx_tty"), 0)
  end

  @doc """
  Returns the NIF version string. Cheap round-trip used by tests to
  confirm the native library actually loaded.
  """
  @spec version() :: binary()
  def version, do: :erlang.nif_error(:nif_not_loaded)
end
