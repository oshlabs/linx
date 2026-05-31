defmodule Linx.Netlink.Nfnl.Codec do
  @moduledoc """
  Wire-format helpers for nfnetlink (`NETLINK_NETFILTER`, protocol 12).

  Three pieces of nfnetlink machinery live here:

  ## 1. The `nfgenmsg` header

  Every nfnetlink message body starts with a fixed 4-byte header
  (`include/uapi/linux/netfilter/nfnetlink.h`):

      struct nfgenmsg {
        __u8  nfgen_family;  /* AF_* address family */
        __u8  version;       /* NFNETLINK_V0 = 0 */
        __be16 res_id;       /* subsystem-specific, BIG-ENDIAN on the wire */
      };

  `Linx.Netlink.Codec` defaults to native byte order, but `res_id` is
  documented as `__be16` and is interpreted that way by the kernel —
  notably as the **target subsystem id** on `NFNL_MSG_BATCH_BEGIN` /
  `_END` and as the **group number** for `NFNL_SUBSYS_ULOG` config
  messages. `encode_nfgenmsg/3` and `decode_nfgenmsg/1` handle the
  byte-order asymmetry directly so the generic codec stays
  byte-order-uniform.

  ## 2. Subsys-id multiplexing on `nlmsghdr.type`

  Inside nfnetlink, the netlink message type is
  `(subsys_id << 8) | msg_type` — the high byte selects which
  sub-subsystem the message targets, the low byte selects the operation
  within that subsystem. `nlmsg_type/2` and `split_type/1` are the
  conversion helpers; `subsys_*` constants are the well-known subsys
  ids.

  ## 3. Batched transactions

  Every nf_tables ruleset mutation must sit between an
  `NFNL_MSG_BATCH_BEGIN` and an `NFNL_MSG_BATCH_END` (the global
  envelope types `0x10` / `0x11`, defined in `nfnetlink.h`). The kernel
  applies the inner messages atomically or rejects the batch whole.
  `batch_begin/1..2` and `batch_end/1` produce the envelope messages —
  N1+ stitches them around the inner request stream.

  ## Why this is its own module, not part of `Linx.Netlink.Codec`

  The general codec is byte-order-uniform (native) and per-family
  agnostic. nfnetlink's `__be16 res_id` and high-byte subsys
  multiplexing are netfilter-specific quirks; keeping them here keeps
  the shared codec clean.
  """

  alias Linx.Netlink.{Message, Request, Socket}

  # --- nfnetlink protocol constants -----------------------------------------

  # NFNETLINK_V0 = 0 — the only version of the nfnetlink header that
  # exists. `include/uapi/linux/netfilter/nfnetlink.h`.
  @nfnetlink_v0 0

  # Sub-subsystem ids inside NETLINK_NETFILTER. The four named here are
  # the ones with public accessors / dispatchers below; the full set
  # (NONE=0, CTNETLINK_EXP=2, OSF=5, IPSET=6, ACCT=7,
  # CTNETLINK_TIMEOUT=8, CTHELPER=9, NFT_COMPAT=11, HOOK=12) is
  # documented in the moduledoc table and in
  # `include/uapi/linux/netfilter/nfnetlink.h`.
  @subsys_ctnetlink 1
  @subsys_queue 3
  @subsys_ulog 4
  @subsys_nftables 10

  # NFNL_MSG_BATCH_BEGIN / NFNL_MSG_BATCH_END — the global batch
  # envelope types (NLMSG_MIN_TYPE region in `linux/netlink.h`). Not
  # per-subsystem.
  @batch_begin 0x10
  @batch_end 0x11

  # nf_tables (subsys 10) operation low-bytes. From
  # `include/uapi/linux/netfilter/nf_tables.h` (`enum nf_tables_msg_types`).
  # Only `GETGEN` (request) is used by N0; `NEWGEN` (reply / broadcast)
  # decoding lands in N6 with the monitor socket.
  #
  # The enum values are zero-indexed and dense:
  #   NEWTABLE=0, GETTABLE=1, DELTABLE=2,
  #   NEWCHAIN=3, GETCHAIN=4, DELCHAIN=5,
  #   NEWRULE=6, GETRULE=7, DELRULE=8,
  #   NEWSET=9, GETSET=10, DELSET=11,
  #   NEWSETELEM=12, GETSETELEM=13, DELSETELEM=14,
  #   NEWGEN=15 (0x0f), GETGEN=16 (0x10), TRACE=17 (0x11), ...
  @nft_msg_getgen 0x10

  # Address families (NFPROTO_*). Most nfnetlink messages set
  # `nfgen_family` per-message; for unscoped / family-agnostic
  # operations (GETGEN, BATCH_BEGIN/END), AF_UNSPEC.
  @nfproto_unspec 0
  @nfproto_inet 1
  @nfproto_ipv4 2
  @nfproto_arp 3
  @nfproto_netdev 5
  @nfproto_bridge 7
  @nfproto_ipv6 10

  # --- public constant accessors --------------------------------------------

  @doc "NFNL_SUBSYS_NFTABLES — the nf_tables sub-subsystem id (10)."
  @spec subsys_nftables() :: 10
  def subsys_nftables, do: @subsys_nftables

  @doc "NFNL_SUBSYS_ULOG — the NFLOG sub-subsystem id (4)."
  @spec subsys_ulog() :: 4
  def subsys_ulog, do: @subsys_ulog

  @doc "NFNL_SUBSYS_CTNETLINK — the conntrack sub-subsystem id (1)."
  @spec subsys_ctnetlink() :: 1
  def subsys_ctnetlink, do: @subsys_ctnetlink

  @doc "NFNL_SUBSYS_QUEUE — the NFQUEUE sub-subsystem id (3)."
  @spec subsys_queue() :: 3
  def subsys_queue, do: @subsys_queue

  @doc """
  NFPROTO_* address-family constants for the `nfgen_family` header
  field.
  """
  @spec nfproto(atom) :: 0..255
  def nfproto(:unspec), do: @nfproto_unspec
  def nfproto(:inet), do: @nfproto_inet
  def nfproto(:ipv4), do: @nfproto_ipv4
  def nfproto(:ip), do: @nfproto_ipv4
  def nfproto(:ipv6), do: @nfproto_ipv6
  def nfproto(:ip6), do: @nfproto_ipv6
  def nfproto(:arp), do: @nfproto_arp
  def nfproto(:bridge), do: @nfproto_bridge
  def nfproto(:netdev), do: @nfproto_netdev

  # --- nlmsghdr.type multiplexing -------------------------------------------

  @doc """
  Packs a nfnetlink `(subsys_id, msg_type)` pair into the 16-bit
  `nlmsghdr.type` the wire format uses.

  Inside `NETLINK_NETFILTER`, the high byte is the sub-subsystem id
  and the low byte is the operation. `nlmsg_type(10, 0x10)` (NFTABLES,
  NEWGEN) produces `0x0a10`.
  """
  @spec nlmsg_type(0..255, 0..255) :: 0..0xFFFF
  def nlmsg_type(subsys, msg_type)
      when is_integer(subsys) and subsys in 0..255 and
             is_integer(msg_type) and msg_type in 0..255 do
    import Bitwise
    subsys <<< 8 ||| msg_type
  end

  @doc """
  Splits a `nlmsghdr.type` from nfnetlink back into `{subsys_id, msg_type}`.

  Inverse of `nlmsg_type/2`.
  """
  @spec split_type(0..0xFFFF) :: {0..255, 0..255}
  def split_type(type) when is_integer(type) and type in 0..0xFFFF do
    import Bitwise
    {type >>> 8 &&& 0xFF, type &&& 0xFF}
  end

  # --- nfgenmsg encoding / decoding -----------------------------------------

  @doc """
  Encodes a 4-byte `nfgenmsg` header.

  `family` is one of the `NFPROTO_*` constants (see `nfproto/1`);
  `res_id` is sub-subsystem-specific and is `__be16` on the wire.
  Defaults: `family: :unspec`, `res_id: 0`.

  ## Examples

      iex> Linx.Netlink.Nfnl.Codec.encode_nfgenmsg()
      <<0, 0, 0, 0>>

      # BATCH_BEGIN targeting NFTABLES (res_id = 10, big-endian):
      iex> Linx.Netlink.Nfnl.Codec.encode_nfgenmsg(:unspec, 10)
      <<0, 0, 0, 10>>

      # NFLOG (ULOG) config for group 5000 (res_id big-endian):
      iex> Linx.Netlink.Nfnl.Codec.encode_nfgenmsg(:unspec, 5000)
      <<0, 0, 19, 136>>
  """
  @spec encode_nfgenmsg(atom | 0..255, 0..0xFFFF) :: <<_::32>>
  def encode_nfgenmsg(family \\ :unspec, res_id \\ 0)

  def encode_nfgenmsg(family, res_id) when is_atom(family) do
    encode_nfgenmsg(nfproto(family), res_id)
  end

  def encode_nfgenmsg(family, res_id)
      when is_integer(family) and family in 0..255 and
             is_integer(res_id) and res_id in 0..0xFFFF do
    <<family::8, @nfnetlink_v0::8, res_id::big-unsigned-16>>
  end

  @doc """
  Decodes the leading 4 bytes of a binary as a `nfgenmsg` header.

  Returns `{family, version, res_id, rest}`. `family` is returned as
  the raw integer (caller maps to atom if useful); `res_id` is decoded
  from big-endian.

  Raises `ArgumentError` if the binary is shorter than 4 bytes.
  """
  @spec decode_nfgenmsg(binary) :: {0..255, 0..255, 0..0xFFFF, binary}
  def decode_nfgenmsg(<<family::8, version::8, res_id::big-unsigned-16, rest::binary>>) do
    {family, version, res_id, rest}
  end

  def decode_nfgenmsg(_),
    do: raise(ArgumentError, "binary too short for nfgenmsg header (need ≥ 4 bytes)")

  # --- batch envelopes ------------------------------------------------------

  @doc """
  Constructs a `NFNL_MSG_BATCH_BEGIN` envelope message targeting the
  named sub-subsystem.

  Returns a `%Message{}` with `type` = `NFNL_MSG_BATCH_BEGIN` (0x10),
  `payload` = the 4-byte `nfgenmsg` carrying the target subsys id as
  `res_id`. Caller fills in `seq` before encoding.

  When `genid` is provided, appends `NFNL_BATCH_GENID` (attribute id
  1, u32 BE) to the payload — the kernel rejects the batch with
  `-ERESTART` at commit time if the netns ruleset generation has
  advanced since `genid` was read. Used by `:reconcile`-mode pushes
  for optimistic concurrency.

  ## Examples

      # Begin a batch targeting nf_tables:
      iex> msg = Linx.Netlink.Nfnl.Codec.batch_begin(:nftables)
      iex> msg.type
      16  # NFNL_MSG_BATCH_BEGIN
      iex> msg.payload
      <<0, 0, 0, 10>>  # nfgenmsg with res_id = NFNL_SUBSYS_NFTABLES (10)
  """
  @spec batch_begin(:nftables | :ctnetlink | :queue | :ulog | 0..255, keyword()) :: Message.t()
  def batch_begin(subsys, opts \\ [])

  def batch_begin(:nftables, opts), do: batch_begin(@subsys_nftables, opts)
  def batch_begin(:ctnetlink, opts), do: batch_begin(@subsys_ctnetlink, opts)
  def batch_begin(:queue, opts), do: batch_begin(@subsys_queue, opts)
  def batch_begin(:ulog, opts), do: batch_begin(@subsys_ulog, opts)

  def batch_begin(subsys, opts) when is_integer(subsys) and subsys in 0..255 do
    base = encode_nfgenmsg(:unspec, subsys)

    payload =
      case Keyword.get(opts, :genid) do
        nil ->
          base

        gen when is_integer(gen) and gen >= 0 ->
          # NFNL_BATCH_GENID = 1, u32 BE
          base <> Linx.Netlink.Attr.encode([{1, <<gen::big-unsigned-32>>}])
      end

    %Message{
      type: @batch_begin,
      flags: 0,
      seq: 0,
      payload: payload
    }
  end

  @doc """
  Constructs a `NFNL_MSG_BATCH_END` envelope message closing the batch.

  Returns a `%Message{}` with `type` = `NFNL_MSG_BATCH_END` (0x11). The
  `res_id` mirrors the begin message but the kernel only acts on
  end-of-batch signalling; the value is informational.
  """
  @spec batch_end(:nftables | :ctnetlink | :queue | :ulog | 0..255) :: Message.t()
  def batch_end(subsys)

  def batch_end(:nftables), do: batch_end(@subsys_nftables)
  def batch_end(:ctnetlink), do: batch_end(@subsys_ctnetlink)
  def batch_end(:queue), do: batch_end(@subsys_queue)
  def batch_end(:ulog), do: batch_end(@subsys_ulog)

  def batch_end(subsys) when is_integer(subsys) and subsys in 0..255 do
    %Message{
      type: @batch_end,
      flags: 0,
      seq: 0,
      payload: encode_nfgenmsg(:unspec, subsys)
    }
  end

  # --- NFT_MSG_GETGEN round-trip (N0 bring-up + supported?) ----------------

  @doc """
  Sends `NFT_MSG_GETGEN` and returns the kernel's reply.

  The reply is a single `NFT_MSG_NEWGEN` message carrying `NFTA_GEN_ID`
  (32-bit monotonic generation counter) and — when the kernel was
  built with the relevant config — `NFTA_GEN_PROC_PID` /
  `NFTA_GEN_PROC_NAME` attributes attributing the most recent commit.

  ## Examples

      iex> {:ok, sock} = Linx.Netlink.Nfnl.open()
      iex> {:ok, gen} = Linx.Netlink.Nfnl.Codec.get_gen(sock)
      iex> is_integer(gen.id) and gen.id >= 0
      true
  """
  @spec get_gen(Socket.t()) ::
          {:ok,
           %{id: non_neg_integer, proc_pid: non_neg_integer | nil, proc_name: String.t() | nil}}
          | {:error, term}
  def get_gen(%Socket{} = socket) do
    type = nlmsg_type(@subsys_nftables, @nft_msg_getgen)
    payload = encode_nfgenmsg(:unspec, 0)

    case Request.talk(socket, type, 0, payload) do
      {:ok, [%Message{payload: body}]} -> {:ok, decode_gen(body)}
      {:ok, []} -> {:error, :empty_reply}
      {:error, _} = err -> err
    end
  end

  # NFTA_* tags for the gen message body. The body starts with the
  # nfgenmsg header, then a stream of NLAs. From
  # `include/uapi/linux/netfilter/nf_tables.h`:
  #
  #   NFTA_GEN_ID         = 1   /* u32 */
  #   NFTA_GEN_PROC_PID   = 2   /* u32 */
  #   NFTA_GEN_PROC_NAME  = 3   /* string */
  @nfta_gen_id 1
  @nfta_gen_proc_pid 2
  @nfta_gen_proc_name 3

  defp decode_gen(body) do
    {_family, _version, _res_id, attrs} = decode_nfgenmsg(body)
    decoded = Linx.Netlink.Attr.decode(attrs)

    %{
      id: get_u32(decoded, @nfta_gen_id, 0),
      proc_pid: get_u32(decoded, @nfta_gen_proc_pid, nil),
      proc_name: get_string(decoded, @nfta_gen_proc_name, nil)
    }
  end

  defp get_u32(attrs, tag, default) do
    # nftables (NFTA_*) NLAs are big-endian on the wire — the kernel
    # uses `nla_put_be32` to encode them. Decode the same way.
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::big-unsigned-32>>} -> v
      _ -> default
    end
  end

  defp get_string(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, value} -> String.trim_trailing(value, <<0>>)
      _ -> default
    end
  end
end
