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

  @typedoc """
  Error returned by every fallible NIF call. The first element of the
  inner tuple names the syscall that failed; the second is a POSIX-style
  atom (`:enxio`, `:enotty`, …) or the raw errno integer if the value
  isn't in the C-side mapping table.
  """
  @type error :: {:error, {atom(), atom() | integer()}}

  @doc """
  Opens `/dev/tty`, saves the current `termios`, and switches it to
  raw mode (`cfmakeraw`). Returns the fd integer and the saved blob.
  """
  @spec open_controlling_raw() :: {:ok, non_neg_integer(), binary()} | error()
  def open_controlling_raw, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Writes `saved` back over `fd`'s termios and closes the fd. EBADF
  from either step is swallowed so a double-restore is a no-op.
  """
  @spec restore_and_close(non_neg_integer(), binary()) :: :ok | error()
  def restore_and_close(_fd, _saved), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Reads `fd`'s window size via `TIOCGWINSZ`. Returns
  `{:ok, {rows, cols, xpixel, ypixel}}` on success.
  """
  @spec window_size(non_neg_integer()) ::
          {:ok, {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}}
          | error()
  def window_size(_fd), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Sets `fd`'s window size via `TIOCSWINSZ`. The tuple is
  `{rows, cols, xpixel, ypixel}`.
  """
  @spec set_window_size(
          non_neg_integer(),
          {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}
        ) :: :ok | error()
  def set_window_size(_fd, _ws), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  @spec socketpair() :: {:ok, {non_neg_integer(), non_neg_integer()}} | error()
  def socketpair, do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  @spec close(non_neg_integer()) :: :ok | error()
  def close(_fd), do: :erlang.nif_error(:nif_not_loaded)
end
