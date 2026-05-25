defmodule Linx.Netlink.Error do
  @moduledoc """
  An error returned by the kernel in response to a netlink request.

  Built from an `NLMSG_ERROR` reply: `code` is the kernel's positive errno,
  `errno` is its POSIX name as an atom (`:enodev`, `:einval`, …), and
  `message` is the human-readable string the kernel attached via extended ack
  (`NLMSGERR_ATTR_MSG`) — `nil` if the kernel did not provide one. Extended
  ack is enabled per socket by `Linx.Netlink.Socket.open/2` (Linux ≥ 4.12).

  Returned in the error tuple by every netlink verb, e.g.

      {:error, %Linx.Netlink.Error{errno: :enodev}} = Link.get(socket, "nope0")

  This module also implements `Exception` so an error can be `raise`d, or
  rendered with `Exception.message/1`.
  """

  @enforce_keys [:errno, :code]
  defexception [:errno, :code, :message]

  @type t :: %__MODULE__{
          errno: atom,
          code: pos_integer,
          message: binary | nil
        }

  # Linux errno numbers Linx is most likely to surface from netlink replies.
  # An unmapped code falls through to :unknown; the integer is still kept in
  # the :code field.
  @posix %{
    1 => :eperm,
    2 => :enoent,
    3 => :esrch,
    4 => :eintr,
    5 => :eio,
    9 => :ebadf,
    11 => :eagain,
    12 => :enomem,
    13 => :eacces,
    14 => :efault,
    16 => :ebusy,
    17 => :eexist,
    18 => :exdev,
    19 => :enodev,
    20 => :enotdir,
    21 => :eisdir,
    22 => :einval,
    23 => :enfile,
    24 => :emfile,
    28 => :enospc,
    32 => :epipe,
    34 => :erange,
    36 => :enametoolong,
    38 => :enosys,
    39 => :enotempty,
    40 => :eloop,
    42 => :enomsg,
    71 => :eproto,
    75 => :eoverflow,
    85 => :erestart,
    90 => :emsgsize,
    92 => :enoprotoopt,
    93 => :eprotonosupport,
    95 => :eopnotsupp,
    97 => :eafnosupport,
    98 => :eaddrinuse,
    99 => :eaddrnotavail,
    100 => :enetdown,
    101 => :enetunreach,
    102 => :enetreset,
    103 => :econnaborted,
    104 => :econnreset,
    105 => :enobufs,
    110 => :etimedout,
    113 => :ehostunreach
  }

  @doc """
  Builds an error from a positive errno `code` and an optional kernel-supplied
  `message` (the `NLMSGERR_ATTR_MSG` string).
  """
  @spec from_errno(pos_integer, binary | nil) :: t
  def from_errno(code, message \\ nil) when is_integer(code) and code > 0 do
    %__MODULE__{errno: Map.get(@posix, code, :unknown), code: code, message: message}
  end

  @impl true
  def message(%__MODULE__{errno: errno, code: code, message: nil}) do
    "netlink #{format_errno(errno, code)}"
  end

  def message(%__MODULE__{errno: errno, code: code, message: text}) do
    "netlink #{format_errno(errno, code)}: #{text}"
  end

  defp format_errno(:unknown, code), do: "errno #{code}"
  defp format_errno(errno, code), do: "#{errno |> Atom.to_string() |> String.upcase()} (#{code})"
end
