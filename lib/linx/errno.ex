defmodule Linx.Errno do
  @moduledoc """
  The shared POSIX errno table behind every `Linx.*.Error` struct.

  One table, both directions: `code/1` resolves an errno atom to its
  Linux (asm-generic) number, `atom/1` resolves a number back to its
  canonical atom. Every subsystem's error constructor delegates here,
  so an errno that resolves in one subsystem resolves in all of them —
  previously each `Error` module carried its own hand-picked subset,
  and the subsets drifted.

  Numbers are the asm-generic values (`linux/asm-generic/errno-base.h`
  and `errno.h`) — correct for every architecture Linx supports
  (x86_64, aarch64). An atom outside the table gets `code: nil` (it is
  still pattern-matchable and self-describing); a number outside it
  resolves to `:unknown` (the raw integer is preserved in the struct's
  `:code` field by the callers).

  Aliases: Erlang's file layer reports `EOPNOTSUPP` as `:enotsup`, so
  both `:enotsup` and `:eopnotsupp` map to 95; the reverse direction
  yields the canonical Linux name, `:eopnotsupp`.
  """

  # {code, canonical atom}. Keep sorted by code.
  @table [
    {1, :eperm},
    {2, :enoent},
    {3, :esrch},
    {4, :eintr},
    {5, :eio},
    {6, :enxio},
    {7, :e2big},
    {8, :enoexec},
    {9, :ebadf},
    {10, :echild},
    {11, :eagain},
    {12, :enomem},
    {13, :eacces},
    {14, :efault},
    {15, :enotblk},
    {16, :ebusy},
    {17, :eexist},
    {18, :exdev},
    {19, :enodev},
    {20, :enotdir},
    {21, :eisdir},
    {22, :einval},
    {23, :enfile},
    {24, :emfile},
    {25, :enotty},
    {26, :etxtbsy},
    {27, :efbig},
    {28, :enospc},
    {29, :espipe},
    {30, :erofs},
    {31, :emlink},
    {32, :epipe},
    {33, :edom},
    {34, :erange},
    {35, :edeadlk},
    {36, :enametoolong},
    {37, :enolck},
    {38, :enosys},
    {39, :enotempty},
    {40, :eloop},
    {42, :enomsg},
    {61, :enodata},
    {71, :eproto},
    {75, :eoverflow},
    {85, :erestart},
    {88, :enotsock},
    {90, :emsgsize},
    {92, :enoprotoopt},
    {93, :eprotonosupport},
    {95, :eopnotsupp},
    {97, :eafnosupport},
    {98, :eaddrinuse},
    {99, :eaddrnotavail},
    {100, :enetdown},
    {101, :enetunreach},
    {102, :enetreset},
    {103, :econnaborted},
    {104, :econnreset},
    {105, :enobufs},
    {106, :eisconn},
    {107, :enotconn},
    {110, :etimedout},
    {111, :econnrefused},
    {113, :ehostunreach},
    {114, :ealready},
    {115, :einprogress},
    {122, :edquot}
  ]

  @code_of Map.new(@table, fn {code, atom} -> {atom, code} end)
           |> Map.put(:enotsup, 95)
  @atom_of Map.new(@table)

  @doc """
  The Linux errno number for `errno`, or `nil` for an atom outside the
  table.
  """
  @spec code(atom()) :: pos_integer() | nil
  def code(errno) when is_atom(errno), do: Map.get(@code_of, errno)

  @doc """
  The canonical errno atom for a Linux errno number, or `:unknown` for
  a number outside the table.
  """
  @spec atom(integer()) :: atom()
  def atom(code) when is_integer(code), do: Map.get(@atom_of, code, :unknown)
end
