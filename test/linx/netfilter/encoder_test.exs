defmodule Linx.Netfilter.EncoderTest do
  use ExUnit.Case, async: true

  # Wire-byte assertions for the set-element layer. The privileged
  # integration suite proves the kernel accepts these messages; these tests
  # pin the exact bytes so a regression is visible in the default suite —
  # round-trip value-equality alone cannot see a mis-encoded key.

  import Linx.Netfilter.Wire

  alias Linx.Netfilter.{
    Chain,
    Decoder,
    Encoder,
    Expr,
    Flowtable,
    Object,
    Patch,
    Ruleset,
    Set,
    Table
  }

  alias Linx.Netlink.Attr
  alias Linx.Netlink.Message
  alias Linx.Netlink.Nfnl.Codec

  # Walks a NEWSETELEM/DELSETELEM message down to its element entries,
  # returning [{key_bytes, flags_int}] in wire order.
  defp element_entries(%Message{payload: payload}) do
    {_family, _ver, _res, attrs_bin} = Codec.decode_nfgenmsg(payload)
    attrs = Attr.decode(attrs_bin)
    {_, list_bin} = List.keyfind(attrs, nfta_set_elem_list_elements(), 0)

    list_bin
    |> Attr.decode()
    |> Enum.map(fn {tag, elem_bin} ->
      assert tag == nfta_list_elem()
      elem_attrs = Attr.decode(elem_bin)

      {_, key_nla} = List.keyfind(elem_attrs, nfta_set_elem_key(), 0)
      {_, key_bytes} = List.keyfind(Attr.decode(key_nla), nfta_data_value(), 0)

      flags =
        case List.keyfind(elem_attrs, nfta_set_elem_flags(), 0) do
          {_, <<f::big-32>>} -> f
          nil -> 0
        end

      {key_bytes, flags}
    end)
  end

  defp elem_keys(msg), do: msg |> element_entries() |> Enum.map(&elem(&1, 0))

  defp set_msg(key_type, elements, flags \\ []) do
    set = Set.new!("s", key_type: key_type, elements: elements, flags: flags, table: "t")
    Encoder.set_elements(set, :inet)
  end

  defp hex(encoded), do: Base.decode16!(encoded, case: :lower)

  @interval_end nft_set_elem_interval_end()

  describe "full-message wire fixtures" do
    # Attribute IDs and nested layouts come from include/uapi/linux/netfilter/nf_tables.h:
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h
    # Pin the nlmsghdr too, so message type/flags and native-order framing are
    # checked alongside the big-endian nf_tables values.
    test "NEWTABLE with the owner flag" do
      message = Encoder.table(Table.new!(:inet, "t", flags: [:owner]))

      assert Message.encode(message) ==
               hex(
                 "24000000000a00040000000000000000" <>
                   "0100000006000100740000000800020000000002"
               )
    end

    test "NEWCHAIN with a nested input hook and drop policy" do
      chain =
        Chain.new!("input",
          table: "t",
          type: :filter,
          hook: :input,
          priority: -10,
          policy: :drop
        )

      assert chain |> Encoder.chain(:inet) |> Message.encode() ==
               hex(
                 "50000000030a00040000000000000000" <>
                   "0100000006000100740000000a000300696e707574000000" <>
                   "14000400080001000000000108000200fffffff6" <>
                   "0b00070066696c74657200000800050000000000"
               )
    end

    test "NEWOBJ counter data keeps 64-bit network byte order" do
      object = Object.new!(:counter, "c", %{bytes: 2, packets: 1})

      assert object |> Encoder.object(:inet, "t") |> Message.encode() ==
               hex(
                 "48000000120a00040000000000000000" <>
                   "0100000006000100740000000600020063000000" <>
                   "08000300000000011c000400" <>
                   "0c00010000000000000000020c0002000000000000000001"
               )
    end

    test "NEWFLOWTABLE preserves nested device-list framing" do
      flowtable =
        Flowtable.new!("f",
          hook: :ingress,
          priority: 0,
          devices: ["eth0", "eth1"],
          flags: [:counter]
        )

      assert flowtable |> Encoder.flowtable(:inet, "t") |> Message.encode() ==
               hex(
                 "5c000000160a00040000000000000000" <>
                   "0100000006000100740000000600020066000000" <>
                   "3000030008000100000000000800020000000000" <>
                   "1c000300090001006574683000000000090001006574683100000000" <>
                   "0800070000000002"
               )
    end
  end

  describe "type-directed key encoding (C4)" do
    test "textual IPv4 elements are parsed to 4 address bytes, not ASCII" do
      # "1.2.3.4" must never hit the wire as its 7 ASCII bytes — that is
      # the fail case that made every sigil-authored IP set kernel-EINVAL.
      assert elem_keys(set_msg(:ipv4_addr, ["1.2.3.4"])) == [<<1, 2, 3, 4>>]
    end

    test "textual IPv6 elements are parsed to 16 address bytes" do
      assert elem_keys(set_msg(:ipv6_addr, ["2001:db8::1"])) ==
               [<<0x20, 0x01, 0x0D, 0xB8, 0::88, 1>>]
    end

    test "tuple and raw-binary address keys are unchanged" do
      assert elem_keys(set_msg(:ipv4_addr, [{10, 0, 0, 5}])) == [<<10, 0, 0, 5>>]
      assert elem_keys(set_msg(:ipv4_addr, [<<10, 0, 0, 6>>])) == [<<10, 0, 0, 6>>]
    end

    test "inet_service keys are 2 bytes network order" do
      assert elem_keys(set_msg(:inet_service, [22, 8080])) == [<<0, 22>>, <<8080::big-16>>]
    end

    test "mark keys are host byte order (kernel memcmps a native u32)" do
      assert elem_keys(set_msg(:mark, [0x1234])) == [<<0x1234::native-32>>]
    end

    test "ifname keys are NUL-padded to the declared 16-byte key length" do
      assert elem_keys(set_msg(:ifname, ["eth0"])) == [<<"eth0", 0::96>>]
    end

    test "an unparseable string for an address type raises" do
      assert_raise ArgumentError, ~r/not a parseable address/, fn ->
        set_msg(:ipv4_addr, ["not-an-ip"])
      end
    end
  end

  describe "interval elements (M1)" do
    test "a range element becomes a start + INTERVAL_END(hi + 1) pair" do
      assert element_entries(set_msg(:inet_service, [{:range, 22, 25}], [:interval])) ==
               [{<<0, 22>>, 0}, {<<0, 26>>, @interval_end}]
    end

    test "a scalar member of an interval set gets its end marker" do
      assert element_entries(set_msg(:inet_service, [80], [:interval])) ==
               [{<<0, 80>>, 0}, {<<0, 81>>, @interval_end}]
    end

    test "a CIDR element becomes the covering address range" do
      assert element_entries(set_msg(:ipv4_addr, ["10.0.0.0/8"], [:interval])) ==
               [{<<10, 0, 0, 0>>, 0}, {<<11, 0, 0, 0>>, @interval_end}]
    end

    test "a range ending at the type max omits the end marker" do
      assert element_entries(set_msg(:inet_service, [{:range, 65_000, 65_535}], [:interval])) ==
               [{<<65_000::big-16>>, 0}]
    end

    test "a range element in a non-interval set raises instead of desyncing" do
      assert_raise ArgumentError, ~r/:interval flag/, fn ->
        set_msg(:inet_service, [{:range, 22, 25}])
      end
    end
  end

  describe "patch element ops carry declared types (M12)" do
    test "a low port in an inet_service set encodes a 2-byte key" do
      # 22 < 256 — shape-based inference used to mis-type this as a 1-byte
      # :inet_proto key, which the kernel rejects against a 2-byte set.
      op = {:add_set_elements, :inet, "t", "s", [22], {:inet_service, nil, false}}
      [msg] = Encoder.from_patch(Patch.new([op]))
      assert elem_keys(msg) == [<<0, 22>>]
    end

    test "delete ops thread the types the same way" do
      op = {:delete_set_elements, :inet, "t", "s", [22], {:inet_service, nil, false}}
      [msg] = Encoder.from_patch(Patch.new([op]))
      assert elem_keys(msg) == [<<0, 22>>]
    end

    test "interval? in the types triple produces end markers" do
      op =
        {:add_set_elements, :inet, "t", "s", [{:range, 22, 25}], {:inet_service, nil, true}}

      [msg] = Encoder.from_patch(Patch.new([op]))

      assert element_entries(msg) == [{<<0, 22>>, 0}, {<<0, 26>>, @interval_end}]
    end

    test "legacy 5-tuple ops still encode via shape inference" do
      op = {:add_set_elements, :inet, "t", "s", [{10, 0, 0, 1}]}
      [msg] = Encoder.from_patch(Patch.new([op]))
      assert elem_keys(msg) == [<<10, 0, 0, 1>>]
    end
  end

  describe "anonymous-set rules encode end-to-end" do
    # These shapes once compiled cleanly but crashed (ranges) or
    # mis-encoded (textual IPs as ASCII) at push time — invisible to
    # value-equality round-trip tests. The rules go through the full
    # to_batch/2 pipeline so the anonymous-set expansion is covered too.
    defp rule_batch!(exprs) do
      Ruleset.new()
      |> Ruleset.add_table!(:inet, "t")
      |> Ruleset.add_chain!({:inet, "t"}, "c", type: :filter, hook: :input, priority: 0)
      |> Ruleset.add_rule!({:inet, "t"}, "c", exprs)
      |> Encoder.to_batch()
    end

    test "port ranges in anonymous sets encode without raising (M1)" do
      msgs =
        rule_batch!([
          Expr.payload(:tcp_dport),
          Expr.set_literal([{:range, 22, 25}], :inet_service, flags: [:interval, :constant]),
          Expr.immediate(:accept)
        ])

      assert Enum.all?(msgs, &match?(%Message{}, &1))
    end

    test "textual IPs in anonymous sets encode as 4-byte keys (C4)" do
      msgs =
        rule_batch!([
          Expr.payload(:ip_saddr),
          Expr.set_literal(["1.2.3.4", "5.6.7.8"], :ipv4_addr),
          Expr.immediate(:drop)
        ])

      # Find the NEWSETELEM message for the anonymous set and check the keys.
      newsetelem = Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newsetelem())
      [elem_msg] = Enum.filter(msgs, &(&1.type == newsetelem))
      assert elem_keys(elem_msg) == [<<1, 2, 3, 4>>, <<5, 6, 7, 8>>]
    end

    test "CIDR inside a set list encodes as an interval pair" do
      msgs =
        rule_batch!([
          Expr.payload(:ip_saddr),
          Expr.set_literal(["10.0.0.0/8"], :ipv4_addr, flags: [:interval, :constant]),
          Expr.immediate(:drop)
        ])

      newsetelem = Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newsetelem())
      [elem_msg] = Enum.filter(msgs, &(&1.type == newsetelem))

      assert element_entries(elem_msg) ==
               [{<<10, 0, 0, 0>>, 0}, {<<11, 0, 0, 0>>, @interval_end}]
    end
  end

  describe "verdict queue numbers (m7)" do
    test "Verdict.queue/1 keeps its queue number across encode → decode" do
      # NF_QUEUE carries the queue number in the high 16 bits of the
      # verdict code; a bare NF_QUEUE silently queues to 0.
      {:ok, vmap} =
        Linx.Netfilter.Map.new("q",
          key_type: :inet_service,
          data_type: :verdict,
          elements: [{80, Linx.Netfilter.Verdict.queue(5)}],
          table: "t"
        )

      msg = Encoder.set_elements(vmap, :inet)
      {:inet, "t", "q", [elem]} = Decoder.set_elements(msg.payload)

      assert {_raw_key, %Linx.Netfilter.Verdict{kind: :queue, target: 5}} = elem
    end
  end

  describe "Decoder.materialize_elements/4 — interval pairing" do
    test "start/end marker pairs collapse back to {:range, lo, hi}" do
      raw = [
        <<0, 22>>,
        {:interval_end, <<0, 26>>},
        <<0, 80>>,
        {:interval_end, <<0, 81>>}
      ]

      assert Decoder.materialize_elements(raw, :inet_service, nil, true) ==
               [{:range, 22, 25}, 80]
    end

    test "a start with no marker runs to the type maximum" do
      assert Decoder.materialize_elements([<<65_000::big-16>>], :inet_service, nil, true) ==
               [{:range, 65_000, 65_535}]
    end

    test "push → pull element shape round-trips for interval sets" do
      elements = [{:range, 22, 25}, 80, {:range, 65_000, 65_535}]
      msg = set_msg(:inet_service, elements, [:interval])

      raw =
        Enum.map(element_entries(msg), fn
          {key, 0} -> key
          {key, @interval_end} -> {:interval_end, key}
        end)

      assert Decoder.materialize_elements(raw, :inet_service, nil, true) == elements
    end
  end

  describe "expression encode ↔ decode symmetry" do
    alias Linx.Netfilter.Rule

    test "log / quota / objref round-trip through rule encode → decode" do
      exprs = [
        Expr.log(prefix: "audit: ", group: 5, flags: [:tcp_seq, :uid]),
        Expr.quota(bytes: 1_000_000, over: true, used: 512),
        Expr.objref("web-quota", :quota)
      ]

      rule = Rule.build!(exprs)
      msg = Encoder.rule(rule, :inet, "t", "c")
      {:inet, "t", "c", decoded} = Decoder.rule(msg.payload)

      assert decoded.expressions == exprs
    end

    test "an expression with no wire encoding raises instead of encoding empty data" do
      rule = Rule.build!([%Expr{name: :exthdr, data: <<1, 2, 3>>}])

      assert_raise ArgumentError, ~r/no wire encoding/, fn ->
        Encoder.rule(rule, :inet, "t", "c")
      end
    end

    test "a pulled-but-undecodable expression (string name) raises on re-encode" do
      rule = Rule.build!([%Expr{name: "fib", data: <<1, 2, 3>>}])

      assert_raise ArgumentError, ~r/cannot re-encode/, fn ->
        Encoder.rule(rule, :inet, "t", "c")
      end
    end

    test "an :__anon_set sentinel outside :replace-mode expansion raises" do
      rule = Rule.build!([Expr.set_literal([80, 443], :inet_service)])

      assert_raise ArgumentError, ~r/no wire encoding/, fn ->
        Encoder.rule(rule, :inet, "t", "c")
      end
    end
  end

  describe "concatenated interval sets round-trip (pipapo)" do
    test "Wire.set_type_atom inverts packed concat type ids" do
      concat = {:concat, [:ipv4_addr, :inet_service]}
      {id, len} = Linx.Netfilter.Wire.set_type_info(concat)

      assert Linx.Netfilter.Wire.set_type_atom(id, len) == concat
      # A packed id with a bogus length stays unknown.
      assert Linx.Netfilter.Wire.set_type_atom(id, len + 4) == {:unknown_type, id, len + 4}
    end

    test "KEY_END elements decode and materialise back to authored parts" do
      elements = [
        [{:range, {10, 0, 0, 1}, {10, 0, 0, 9}}, 443],
        [{192, 168, 1, 1}, 80]
      ]

      {:ok, set} =
        Set.new("svc",
          key_type: {:concat, [:ipv4_addr, :inet_service]},
          flags: [:interval],
          elements: elements,
          table: "t"
        )

      msg = Encoder.set_elements(set, :inet)
      {:inet, "t", "svc", raw} = Decoder.set_elements(msg.payload)

      materialized =
        Decoder.materialize_elements(raw, {:concat, [:ipv4_addr, :inet_service]}, nil, true)

      assert materialized == elements
    end
  end
end
