defmodule Linx.Tty.Error do
  @moduledoc """
  A failure from one of `Linx.Tty`'s terminal syscalls.

  Returned as `{:error, %Linx.Tty.Error{}}` by `open_controlling_raw/0`,
  `restore_and_close/2`, `window_size/1`, and `set_window_size/2` when the
  underlying `open(2)` / `tcgetattr(3)` / `tcsetattr(3)` / `ioctl(2)` /
  `close(2)` fails.

  ## Fields

    * `:operation` — the syscall stage that failed (`:open`,
      `:tcgetattr`, `:tcsetattr`, `:ioctl`, `:close`).
    * `:errno` — the POSIX errno as an atom (`:enxio`, `:enotty`, …), or
      `:unknown` for an errno Linx hasn't catalogued.
    * `:code` — the raw errno integer, or `nil` if Linx doesn't know the
      number for that atom.

  Implements `Exception`, so it can be `raise`d or rendered with
  `Exception.message/1`.

  Note: the lifecycle conditions `attach/2` reports (`:no_local_tty`,
  `:no_process`, `:gl_eof`) are **not** syscall failures and stay as bare
  atoms — only kernel/syscall errors take this struct.
  """

  @enforce_keys [:operation, :errno]
  defexception [:operation, :errno, :code]

  @type t :: %__MODULE__{operation: atom(), errno: atom(), code: pos_integer() | nil}

  @doc """
  Builds an error from the NIF's `{stage, errno}` pair, where `errno` is
  either a POSIX atom (the NIF mapped it; see errno_atom/1 in
  c_src/linx_tty.c) or a raw integer (it didn't). `Linx.Errno` resolves
  the other direction either way.
  """
  @spec from_nif(atom(), atom() | integer()) :: t()
  def from_nif(stage, errno) when is_atom(errno) do
    %__MODULE__{operation: stage, errno: errno, code: Linx.Errno.code(errno)}
  end

  def from_nif(stage, code) when is_integer(code) do
    %__MODULE__{operation: stage, errno: Linx.Errno.atom(code), code: code}
  end

  @impl Exception
  def message(%__MODULE__{operation: op, errno: :unknown, code: code}) do
    "tty #{op} failed: errno #{code}"
  end

  def message(%__MODULE__{operation: op, errno: errno, code: nil}) do
    "tty #{op} failed: #{errno}"
  end

  def message(%__MODULE__{operation: op, errno: errno, code: code}) do
    "tty #{op} failed: #{errno} (errno #{code})"
  end
end
