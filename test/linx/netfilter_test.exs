defmodule Linx.NetfilterTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter
  alias Linx.Netfilter.Error
  alias Linx.Netlink.{Nfnl, Socket}
  alias Linx.Netlink.Nfnl.Codec

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(Netfilter.supported?())
    end

    test "returns true on any modern Linux with nfnetlink" do
      # Opening a NETLINK_NETFILTER socket is unprivileged; this
      # should be true on any kernel built with
      # CONFIG_NETFILTER_NETLINK=y (the default).
      assert Netfilter.supported?() == true
    end
  end

  describe "Linx.Netlink.Nfnl.open/1" do
    test "opens an nfnetlink socket and reports the right protocol" do
      assert {:ok, sock} = Nfnl.open()
      assert %Socket{} = sock
      assert sock.protocol == 12
      assert sock.netns == :host
      assert :ok = Socket.close(sock)
    end
  end

  describe "Linx.Netlink.Nfnl.Codec — nfgenmsg encoding" do
    test "encode_nfgenmsg/2 produces 4 bytes with the family + version + BE res_id" do
      assert Codec.encode_nfgenmsg() == <<0, 0, 0, 0>>
      # AF_INET = 2; res_id = 0
      assert Codec.encode_nfgenmsg(:ipv4) == <<2, 0, 0, 0>>
      # AF_INET6 = 10; res_id = 0
      assert Codec.encode_nfgenmsg(:ipv6) == <<10, 0, 0, 0>>
      # AF_UNSPEC = 0; res_id = NFNL_SUBSYS_NFTABLES (10) — big-endian
      assert Codec.encode_nfgenmsg(:unspec, 10) == <<0, 0, 0, 10>>
      # res_id big-endian: 5000 = 0x1388 → 0x13, 0x88
      assert Codec.encode_nfgenmsg(:unspec, 5000) == <<0, 0, 0x13, 0x88>>
    end

    test "decode_nfgenmsg/1 round-trips encode_nfgenmsg/2" do
      for {family, res_id} <- [{:unspec, 0}, {:ipv4, 10}, {:ipv6, 5000}, {:inet, 65535}] do
        encoded = Codec.encode_nfgenmsg(family, res_id)
        assert {fam_int, 0, ^res_id, <<>>} = Codec.decode_nfgenmsg(encoded)
        assert fam_int == Codec.nfproto(family)
      end
    end

    test "decode_nfgenmsg/1 leaves trailing bytes for downstream decoders" do
      bin = Codec.encode_nfgenmsg(:inet, 10) <> <<1, 2, 3, 4>>
      assert {1, 0, 10, <<1, 2, 3, 4>>} = Codec.decode_nfgenmsg(bin)
    end

    test "decode_nfgenmsg/1 raises on truncated input" do
      assert_raise ArgumentError, fn -> Codec.decode_nfgenmsg(<<0, 0, 0>>) end
    end
  end

  describe "Linx.Netlink.Nfnl.Codec — subsys-id multiplexing" do
    test "nlmsg_type/2 packs (subsys, msg_type) into 16 bits" do
      # NFTABLES = 10 (0x0a), GETGEN = 0x10 → 0x0a10
      assert Codec.nlmsg_type(10, 0x10) == 0x0A10
      # ULOG = 4, NFULNL_MSG_PACKET = 0 → 0x0400
      assert Codec.nlmsg_type(4, 0) == 0x0400
      # NFTABLES, NEWTABLE = 0 → 0x0a00
      assert Codec.nlmsg_type(10, 0) == 0x0A00
    end

    test "split_type/1 inverts nlmsg_type/2" do
      for {subsys, msg_type} <- [{10, 0x11}, {4, 0}, {0, 0x10}, {255, 255}] do
        packed = Codec.nlmsg_type(subsys, msg_type)
        assert Codec.split_type(packed) == {subsys, msg_type}
      end
    end

    test "subsys_* accessors return the canonical values" do
      assert Codec.subsys_nftables() == 10
      assert Codec.subsys_ulog() == 4
      assert Codec.subsys_ctnetlink() == 1
      assert Codec.subsys_queue() == 3
    end

    test "nfproto/1 maps family atoms to NFPROTO_* constants" do
      assert Codec.nfproto(:unspec) == 0
      assert Codec.nfproto(:inet) == 1
      assert Codec.nfproto(:ipv4) == 2
      assert Codec.nfproto(:arp) == 3
      assert Codec.nfproto(:netdev) == 5
      assert Codec.nfproto(:bridge) == 7
      assert Codec.nfproto(:ipv6) == 10
    end
  end

  describe "Linx.Netlink.Nfnl.Codec — batch envelopes" do
    test "batch_begin/1 produces a NFNL_MSG_BATCH_BEGIN (0x10) targeting the subsys" do
      msg = Codec.batch_begin(:nftables)
      # NLMSG_MIN_TYPE region: NFNL_MSG_BATCH_BEGIN = 0x10
      assert msg.type == 0x10
      assert msg.flags == 0
      # nfgenmsg with res_id = 10 (NFTABLES), big-endian
      assert msg.payload == <<0, 0, 0, 10>>

      msg = Codec.batch_begin(:ulog)
      assert msg.payload == <<0, 0, 0, 4>>
    end

    test "batch_end/1 produces a NFNL_MSG_BATCH_END (0x11)" do
      msg = Codec.batch_end(:nftables)
      assert msg.type == 0x11
      assert msg.payload == <<0, 0, 0, 10>>
    end

    test "batch_begin/1 accepts a raw subsys id" do
      assert Codec.batch_begin(10) == Codec.batch_begin(:nftables)
    end
  end

  describe "Linx.Netfilter.Error" do
    test "from_posix/2 builds a struct with the right shape and errno code" do
      err = Error.from_posix(:eperm, :push)
      assert %Error{} = err
      assert err.operation == :push
      assert err.errno == :eperm
      assert err.code == 1
      assert err.message == nil
      assert err.subsys == nil
      assert err.msg_type == nil
      assert err.batch_seq == nil
      assert err.attr_offset == nil
      assert err.ruleset_gen == nil
    end

    test "from_posix/3 carries netfilter-specific context" do
      err =
        Error.from_posix(:eopnotsupp, :newchain,
          subsys: :nftables,
          msg_type: 0x03,
          batch_seq: 7,
          attr_offset: 24,
          ruleset_gen: 42,
          message: "cannot change chain type in place"
        )

      assert err.subsys == :nftables
      assert err.msg_type == 0x03
      assert err.batch_seq == 7
      assert err.attr_offset == 24
      assert err.ruleset_gen == 42
      assert err.message == "cannot change chain type in place"
    end

    test "from_posix/2 leaves :code nil for unmapped errno atoms" do
      err = Error.from_posix(:exotic, :push)
      assert err.code == nil
    end

    test "Exception.message/1 renders operation + errno + code + extack message" do
      err =
        Error.from_posix(:eopnotsupp, :newchain, message: "cannot change chain type in place")

      assert Exception.message(err) ==
               "netfilter newchain failed: eopnotsupp (errno 95) — cannot change chain type in place"
    end

    test "Exception.message/1 omits the extack suffix when :message is nil" do
      err = Error.from_posix(:eperm, :push)
      assert Exception.message(err) == "netfilter push failed: eperm (errno 1)"
    end

    test "Exception.message/1 omits the (errno N) part when :code is nil" do
      err = Error.from_posix(:exotic, :push)
      assert Exception.message(err) == "netfilter push failed: exotic"
    end
  end

  describe "N1-N7 stubs" do
    # The verbs that haven't shipped yet still return
    # {:error, :not_yet_implemented} so the surface is visible in
    # ExDoc + IDE completion. create_table/3, push/3, pull/1, pull/2
    # shipped in N2. diff/2 + dry_run/2 shipped in N5. subscribe/1
    # lands in N6; log_listen/2 in N7.

    test "subscribe/1" do
      assert {:error, :not_yet_implemented} = Netfilter.subscribe(self())
    end

    test "log_listen/2" do
      assert {:error, :not_yet_implemented} = Netfilter.log_listen(self(), group: 5000)
    end
  end

  describe "N0 integration — Linx.Netlink.Nfnl.Codec.get_gen/1 round-trip" do
    @describetag :integration

    # Reading the generation counter requires CAP_NET_ADMIN on most
    # current kernels (the nf_tables_getgen handler is gated on it).
    # Run via ./sudotest.sh.

    test "get_gen/1 returns a non-negative integer and process attribution" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      assert {:ok, gen} = Codec.get_gen(sock)
      assert is_integer(gen.id) and gen.id >= 0
      # proc_pid + proc_name may be nil on some kernels / fresh
      # netns; assert only the types when present.
      if gen.proc_pid, do: assert(is_integer(gen.proc_pid) and gen.proc_pid > 0)
      if gen.proc_name, do: assert(is_binary(gen.proc_name))
    end

    test "two calls in sequence return non-decreasing generation ids" do
      {:ok, sock} = Nfnl.open()
      on_exit(fn -> Socket.close(sock) end)

      assert {:ok, g1} = Codec.get_gen(sock)
      assert {:ok, g2} = Codec.get_gen(sock)
      assert g2.id >= g1.id
    end
  end
end
