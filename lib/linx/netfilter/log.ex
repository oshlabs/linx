defmodule Linx.Netfilter.Log do
  @moduledoc """
  NFLOG listener — receives per-packet events from the kernel's
  `NFNL_SUBSYS_ULOG` (sub-subsystem 4) for rules that include
  `Linx.Netfilter.Expr.log/1`.

  ## Lifecycle

      {:ok, listener} = Linx.Netfilter.log_listen(self(),
        group: 5000,
        copy_mode: {:packet, 256},
        flags: [:seq])

      receive do
        {:linx_netfilter, :log, %Linx.Netfilter.Log.Event{} = ev} ->
          IO.inspect(ev.prefix, label: "log")
      end

      :ok = Linx.Netfilter.unlog_listen(listener)

  ## Group binding

  Each NFLOG group is independent. On start, the listener sends:

    * `NFULNL_CFG_CMD_BIND` for the chosen group.
    * `NFULNL_CFG_CMD_PF_BIND` for each address family in
      `:families` (default `[:ipv4, :ipv6]`). Required so the
      kernel actually invokes the NFLOG hook for matching
      packets.
    * `NFULA_CFG_MODE` for the copy mode.
    * `NFULA_CFG_FLAGS` for the flag bitmask.
    * Optional `NFULA_CFG_TIMEOUT` and `NFULA_CFG_QTHRESH` for
      batching.

  ## Linx convention: group 5000

  Group ids 1..65535 are caller-supplied. Linx reserves **group
  5000** as the recommended default for "I don't care which group
  as long as it's mine" — documented as convention, not a
  hard-coded default for the API.

  ## ENOBUFS recovery

  Same shape as `Linx.Netfilter.Monitor`: a `:resync_needed`
  message tells the owner that messages were dropped at the
  kernel-socket boundary. The owner can choose to ignore (the
  next event will still arrive) or re-bind for a clean slate.
  """

  use GenServer

  import Bitwise

  alias Linx.Netfilter.Wire
  alias Linx.Netlink.{Attr, Message, Nfnl, Socket}
  alias Linx.Netlink.Nfnl.Codec

  import Linx.Netfilter.Wire,
    only: [
      nfulnl_msg_config: 0,
      nfulnl_msg_packet: 0,
      nfulnl_cfg_cmd_bind: 0,
      nfulnl_cfg_cmd_pf_bind: 0,
      nfula_cfg_cmd: 0,
      nfula_cfg_mode: 0,
      nfula_cfg_qthresh: 0,
      nfula_cfg_timeout: 0,
      nfula_cfg_flags: 0
    ]

  import Linx.Netlink.Constants

  @default_rcvbuf 4 * 1024 * 1024
  @recv_timeout_ms 50
  @recv_size 65_536

  @type opt ::
          {:owner, pid()}
          | {:group, 1..65_535}
          | {:netns, Socket.netns()}
          | {:copy_mode, :none | :meta | :packet | {:packet, non_neg_integer()}}
          | {:qthresh, 1..1024}
          | {:timeout_ms, non_neg_integer()}
          | {:flags, [:seq | :seq_global | :conntrack]}
          | {:families, [:ipv4 | :ipv6 | :bridge | :arp]}
          | {:rcvbuf, pos_integer()}

  @doc """
  Starts a Log listener linked to the caller.

  Required:
    * `:owner` — pid that receives `{:linx_netfilter, :log, %Event{}}`
    * `:group` — NFLOG group (1..65535)

  Optional:
    * `:netns` — namespace; default `:host`
    * `:copy_mode` — `:none` | `:meta` | `:packet` (full packet, up
      to default snaplen) | `{:packet, snaplen_bytes}`. Default `:meta`.
    * `:qthresh` — kernel-side queue threshold (1..1024). Default
      `1` (forward each packet immediately).
    * `:timeout_ms` — kernel-side batching timeout in ms; 0 means
      no time-based batching. Default `0`.
    * `:flags` — `:seq` / `:seq_global` / `:conntrack`.
    * `:families` — protocol families to bind via PF_BIND; default
      `[:ipv4, :ipv6]`.
    * `:rcvbuf` — SO_RCVBUF size in bytes; default 4 MiB.
  """
  @spec start_link([opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Stops the listener (also sends NFULNL_CFG_CMD_UNBIND)."
  @spec stop(pid()) :: :ok
  def stop(listener) when is_pid(listener), do: GenServer.stop(listener)

  # ===========================================================
  # GenServer
  # ===========================================================

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    group = Keyword.fetch!(opts, :group)
    netns = Keyword.get(opts, :netns, :host)
    copy_mode = Keyword.get(opts, :copy_mode, :meta)
    qthresh = Keyword.get(opts, :qthresh, 1)
    timeout_ms = Keyword.get(opts, :timeout_ms, 0)
    flags = Keyword.get(opts, :flags, [])
    families = Keyword.get(opts, :families, [:ipv4, :ipv6])
    rcvbuf = Keyword.get(opts, :rcvbuf, @default_rcvbuf)

    with {:ok, sock} <- Nfnl.open(netns),
         :ok <- send_pf_binds(sock, families),
         :ok <- send_cmd_bind(sock, group),
         :ok <- send_cfg_mode(sock, group, copy_mode),
         :ok <- send_cfg_flags(sock, group, flags),
         :ok <- maybe_send_cfg_qthresh(sock, group, qthresh),
         :ok <- maybe_send_cfg_timeout(sock, group, timeout_ms) do
      _ = Socket.set_rcvbuf(sock, rcvbuf)

      state = %{
        sock: sock,
        owner: owner,
        group: group,
        families: families
      }

      send(self(), :recv)
      {:ok, state}
    end
  end

  @impl true
  def handle_info(:recv, state), do: do_recv(state)

  @impl true
  def terminate(_reason, state) do
    if state.sock do
      _ = send_cmd_unbind(state.sock, state.group)
      _ = send_pf_unbinds(state.sock, state.families)
      Socket.close(state.sock)
    end

    :ok
  end

  # ===========================================================
  # Config-message helpers
  # ===========================================================

  defp send_pf_binds(sock, families) do
    Enum.reduce_while(families, :ok, fn family, :ok ->
      case send_cfg_cmd(sock, family_num_for_log(family), nfulnl_cfg_cmd_pf_bind(), 0) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp send_pf_unbinds(sock, families) do
    Enum.each(families, fn family ->
      # PF_UNBIND
      _ = send_cfg_cmd(sock, family_num_for_log(family), 4, 0)
    end)

    :ok
  end

  defp family_num_for_log(:ipv4), do: 2
  defp family_num_for_log(:ipv6), do: 10
  defp family_num_for_log(:bridge), do: 7
  defp family_num_for_log(:arp), do: 3

  defp send_cmd_bind(sock, group) do
    send_cfg_cmd(sock, 0, nfulnl_cfg_cmd_bind(), group)
  end

  defp send_cmd_unbind(sock, group) do
    # NFULNL_CFG_CMD_UNBIND = 2
    send_cfg_cmd(sock, 0, 2, group)
  end

  # Sends NFULNL_MSG_CONFIG with a NFULA_CFG_CMD attribute. The cmd
  # struct is `__u8 command; __u8 _pad; __be16 pf;` — but the body
  # also carries the nfgenmsg's res_id (group number, BE).
  defp send_cfg_cmd(sock, family, cmd, group) do
    # struct nfulnl_msg_config_cmd { __u8 cmd; } — single-byte cmd
    cmd_attr = {nfula_cfg_cmd(), <<cmd::8>>}

    payload =
      Codec.encode_nfgenmsg(family, group) <>
        Attr.encode([cmd_attr])

    send_config(sock, payload)
  end

  # struct nfulnl_msg_config_mode {
  #   __be32 copy_range;   /* snaplen for COPY_PACKET, 0 otherwise */
  #   __u8   copy_mode;    /* NFULNL_COPY_* */
  #   __u8   _pad;
  # };
  defp send_cfg_mode(sock, group, copy_mode) do
    {mode_int, snaplen} =
      case copy_mode do
        :none -> {0, 0}
        :meta -> {1, 0}
        :packet -> {2, 0xFFFF}
        {:packet, snaplen} -> {2, snaplen}
      end

    mode_struct = <<snaplen::big-unsigned-32, mode_int::8, 0::8>>

    attrs = [
      {nfula_cfg_mode(), mode_struct}
    ]

    payload = Codec.encode_nfgenmsg(:unspec, group) <> Attr.encode(attrs)
    send_config(sock, payload)
  end

  defp send_cfg_flags(_sock, _group, []), do: :ok

  defp send_cfg_flags(sock, group, flags) do
    flags_int = Wire.nfulnl_cfg_flags_int(flags)

    attrs = [
      {nfula_cfg_flags(), <<flags_int::big-unsigned-16>>}
    ]

    payload = Codec.encode_nfgenmsg(:unspec, group) <> Attr.encode(attrs)
    send_config(sock, payload)
  end

  defp maybe_send_cfg_qthresh(_sock, _group, qthresh) when qthresh <= 1, do: :ok

  defp maybe_send_cfg_qthresh(sock, group, qthresh) do
    attrs = [{nfula_cfg_qthresh(), Wire.u32_be(qthresh)}]
    payload = Codec.encode_nfgenmsg(:unspec, group) <> Attr.encode(attrs)
    send_config(sock, payload)
  end

  defp maybe_send_cfg_timeout(_sock, _group, 0), do: :ok

  defp maybe_send_cfg_timeout(sock, group, timeout_ms) do
    # NFULA_CFG_TIMEOUT is in 100ms units per the kernel doc.
    units = max(1, div(timeout_ms, 100))
    attrs = [{nfula_cfg_timeout(), Wire.u32_be(units)}]
    payload = Codec.encode_nfgenmsg(:unspec, group) <> Attr.encode(attrs)
    send_config(sock, payload)
  end

  defp send_config(sock, payload) do
    type = Codec.nlmsg_type(Codec.subsys_ulog(), nfulnl_msg_config())

    msg = %Message{
      type: type,
      flags: nlm_f_request() ||| nlm_f_ack(),
      seq: Socket.next_seq(sock),
      payload: payload
    }

    case :socket.send(sock.socket, Message.encode(msg)) do
      :ok ->
        # Best-effort: drain any ACK that arrives. We don't strictly
        # need to wait — the config takes effect asynchronously.
        case :socket.recv(sock.socket, @recv_size, 50) do
          {:ok, _ack} -> :ok
          {:error, :timeout} -> :ok
          {:error, _} -> :ok
        end

      {:error, reason} ->
        {:error, {:send, reason}}
    end
  end

  # ===========================================================
  # Recv + dispatch
  # ===========================================================

  defp do_recv(%{sock: sock} = state) do
    case :socket.recv(sock.socket, @recv_size, @recv_timeout_ms) do
      {:ok, data} ->
        process_data(data, state)
        send(self(), :recv)
        {:noreply, state}

      {:error, :timeout} ->
        send(self(), :recv)
        {:noreply, state}

      {:error, :enobufs} ->
        send(state.owner, {:linx_netfilter, :resync_needed})
        send(self(), :recv)
        {:noreply, state}

      {:error, :closed} ->
        {:stop, :normal, state}

      {:error, reason} ->
        {:stop, {:recv, reason}, state}
    end
  end

  defp process_data(data, state) do
    data
    |> Message.decode()
    |> Enum.each(&process_message(&1, state))
  end

  defp process_message(%Message{type: type, payload: body}, state) do
    {_subsys, msg_type} = Codec.split_type(type)

    if msg_type == nfulnl_msg_packet() do
      event = __MODULE__.Event.decode(body)
      send(state.owner, {:linx_netfilter, :log, %{event | group: state.group}})
    end
  end

  defmodule Event do
    @moduledoc """
    A decoded NFLOG packet event.

    Fields populated from `NFULA_*` attributes. All optional —
    the kernel only includes attributes it has data for, and
    the consumer's `:copy_mode` controls whether `:payload` is
    present.

      * `:group` — NFLOG group the event came from (filled by
        the listener, not the kernel).
      * `:prefix` — string label from the rule's
        `Expr.log(prefix: ...)`. `nil` if the rule didn't set one.
      * `:hook` — `NF_INET_*` hook number where the packet was
        captured.
      * `:hw_protocol` — Ethernet protocol (`0x0800` = IPv4,
        `0x86dd` = IPv6, etc.).
      * `:mark` — packet mark, if `meta mark` was set on the path.
      * `:timestamp` — `{seconds, microseconds}` since the epoch.
      * `:indev` / `:outdev` — interface ifindex of arrival /
        departure.
      * `:physindev` / `:physoutdev` — for bridged packets.
      * `:hwaddr` — source link-layer address (bytes).
      * `:payload` — packet bytes from the network header down (or
        nil if `:copy_mode` was `:meta`/`:none`).
      * `:uid` / `:gid` — owner of the originating local socket,
        if any (only meaningful for OUTPUT-hook captures).
      * `:seq` / `:seq_global` — sequence numbers if `:seq` /
        `:seq_global` flag was set on the listener.
    """

    defstruct [
      :group,
      :prefix,
      :hook,
      :hw_protocol,
      :mark,
      :timestamp,
      :indev,
      :outdev,
      :physindev,
      :physoutdev,
      :hwaddr,
      :payload,
      :uid,
      :gid,
      :seq,
      :seq_global
    ]

    @type t :: %__MODULE__{
            group: 1..65_535 | nil,
            prefix: String.t() | nil,
            hook: 0..255 | nil,
            hw_protocol: 0..0xFFFF | nil,
            mark: non_neg_integer() | nil,
            timestamp: {non_neg_integer(), non_neg_integer()} | nil,
            indev: non_neg_integer() | nil,
            outdev: non_neg_integer() | nil,
            physindev: non_neg_integer() | nil,
            physoutdev: non_neg_integer() | nil,
            hwaddr: binary() | nil,
            payload: binary() | nil,
            uid: non_neg_integer() | nil,
            gid: non_neg_integer() | nil,
            seq: non_neg_integer() | nil,
            seq_global: non_neg_integer() | nil
          }

    alias Linx.Netlink.Attr
    alias Linx.Netlink.Nfnl.Codec
    import Linx.Netfilter.Wire

    @doc """
    Decodes a `NFULNL_MSG_PACKET` body into a `%Log.Event{}`.
    """
    @spec decode(binary()) :: t()
    def decode(body) when is_binary(body) do
      {_family, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
      attrs = Attr.decode(attrs_bin)

      {hook, hw_protocol} = decode_packet_hdr(attrs)
      {ts_sec, ts_usec} = decode_timestamp(attrs)

      %__MODULE__{
        prefix: get_string(attrs, nfula_prefix()),
        hook: hook,
        hw_protocol: hw_protocol,
        mark: get_u32_be(attrs, nfula_mark()),
        timestamp: ts_sec && {ts_sec, ts_usec},
        indev: get_u32_be(attrs, nfula_ifindex_indev()),
        outdev: get_u32_be(attrs, nfula_ifindex_outdev()),
        physindev: get_u32_be(attrs, nfula_ifindex_physindev()),
        physoutdev: get_u32_be(attrs, nfula_ifindex_physoutdev()),
        hwaddr: decode_hwaddr(get_binary(attrs, nfula_hwaddr())),
        payload: get_binary(attrs, nfula_payload()),
        uid: get_u32_be(attrs, nfula_uid()),
        gid: get_u32_be(attrs, nfula_gid()),
        seq: get_u32_be(attrs, nfula_seq()),
        seq_global: get_u32_be(attrs, nfula_seq_global())
      }
    end

    # struct nfulnl_msg_packet_hdr {
    #   __be16 hw_protocol;
    #   __u8   hook;
    #   __u8   _pad;
    # }
    defp decode_packet_hdr(attrs) do
      case List.keyfind(attrs, nfula_packet_hdr(), 0) do
        {_, <<hw_proto::big-16, hook::8, _pad::8>>} -> {hook, hw_proto}
        _ -> {nil, nil}
      end
    end

    # struct nfulnl_msg_packet_timestamp {
    #   __be64 sec;
    #   __be64 usec;
    # }
    defp decode_timestamp(attrs) do
      case List.keyfind(attrs, nfula_timestamp(), 0) do
        {_, <<sec::big-64, usec::big-64>>} -> {sec, usec}
        _ -> {nil, nil}
      end
    end

    # struct nfulnl_msg_packet_hw {
    #   __be16 hw_addrlen;
    #   __u16  _pad;
    #   __u8   hw_addr[8];
    # }
    defp decode_hwaddr(nil), do: nil

    defp decode_hwaddr(<<len::big-16, _pad::16, addr::binary-size(8)>>) do
      binary_part(addr, 0, len)
    end

    defp decode_hwaddr(_other), do: nil

    defp get_string(attrs, tag) do
      case List.keyfind(attrs, tag, 0) do
        {^tag, value} -> String.trim_trailing(value, <<0>>)
        nil -> nil
      end
    end

    defp get_binary(attrs, tag) do
      case List.keyfind(attrs, tag, 0) do
        {^tag, value} -> value
        nil -> nil
      end
    end

    defp get_u32_be(attrs, tag) do
      case List.keyfind(attrs, tag, 0) do
        {^tag, <<v::big-unsigned-32>>} -> v
        _ -> nil
      end
    end
  end
end
