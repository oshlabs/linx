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

  # The errnos the linx_tty NIF maps to atoms (see errno_atom/1 in
  # c_src/linx_tty.c). Used both ways: an atom from the NIF gets its
  # number filled in, and a raw integer (an errno the NIF didn't map)
  # gets resolved back to an atom where possible.
  @code_of %{
    eacces: 13,
    ebadf: 9,
    ebusy: 16,
    eintr: 4,
    einval: 22,
    eio: 5,
    enoent: 2,
    enomem: 12,
    enotty: 25,
    enxio: 6,
    eperm: 1
  }

  @doc """
  Builds an error from the NIF's `{stage, errno}` pair, where `errno` is
  either a POSIX atom (the NIF mapped it) or a raw integer (it didn't).
  """
  @spec from_nif(atom(), atom() | integer()) :: t()
  def from_nif(stage, errno) when is_atom(errno) do
    %__MODULE__{operation: stage, errno: errno, code: Map.get(@code_of, errno)}
  end

  def from_nif(stage, code) when is_integer(code) do
    errno = Enum.find_value(@code_of, :unknown, fn {atom, n} -> if n == code, do: atom end)
    %__MODULE__{operation: stage, errno: errno, code: code}
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
