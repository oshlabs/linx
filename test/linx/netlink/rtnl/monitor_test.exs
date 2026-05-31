defmodule Linx.Netlink.Rtnl.MonitorTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Linx.IP

  alias Linx.Netlink.Message
  alias Linx.Netlink.Rtnl.{Address, Monitor, Route}
  alias Linx.Netlink.Rtnl.Monitor.Event

  # The RTM types the Monitor dispatches (see @rtm in the module).
  @known_types [16, 17, 20, 21, 24, 25, 28, 29, 32, 33]

  defp message(type, payload),
    do: %Message{type: type, flags: 0, seq: 0, pid: 0, payload: payload}

  describe "decode_event/1" do
    test "maps RTM_NEWADDR (20) to :new_addr and decodes the address" do
      addr = %Address{family: 2, index: 2, address: ~IP"10.0.0.2", prefixlen: 24, scope: 0}
      msg = message(20, Address.encode(addr))

      assert %Event{op: :new_addr, resource: %Address{address: ~IP"10.0.0.2", prefixlen: 24}} =
               Monitor.decode_event(msg)
    end

    test "maps RTM_DELADDR (21) to :del_addr" do
      addr = %Address{family: 2, index: 2, address: ~IP"10.0.0.2", prefixlen: 24, scope: 0}
      assert %Event{op: :del_addr} = Monitor.decode_event(message(21, Address.encode(addr)))
    end

    test "maps RTM_DELROUTE (25) to :del_route and decodes the route" do
      {:ok, route} = Route.build("10.50.0.0", 24, "10.0.0.1", 0, [])
      msg = message(25, Route.encode(route))

      assert %Event{op: :del_route, resource: %Route{dst: ~IP"10.50.0.0"}} =
               Monitor.decode_event(msg)
    end

    test "an unrecognised RTM type yields {:unknown, type} with no resource" do
      assert %Event{op: {:unknown, 99}, resource: nil} =
               Monitor.decode_event(message(99, <<>>))
    end

    property "any type outside the dispatch table is {:unknown, type}, never raising" do
      check all(type <- integer(0..65_535), type not in @known_types) do
        assert %Event{op: {:unknown, ^type}, resource: nil} =
                 Monitor.decode_event(message(type, <<>>))
      end
    end
  end

  describe "event ordering" do
    # The recv loop maps decode_event over Message.decode of one datagram and
    # sends each to the owner in turn, so owner-visible order is exactly the
    # frame order in the buffer. This pins that contract: a multi-frame buffer
    # decodes to events in source order.
    test "a multi-frame datagram decodes to events in frame order" do
      addr = %Address{family: 2, index: 2, address: ~IP"10.0.0.2", prefixlen: 24, scope: 0}
      {:ok, route} = Route.build("10.50.0.0", 24, "10.0.0.1", 0, [])

      # Three frames, deliberately interleaved across resource types.
      frames = [
        message(20, Address.encode(addr)),
        message(25, Route.encode(route)),
        message(21, Address.encode(addr))
      ]

      buffer = frames |> Enum.map(&Message.encode/1) |> IO.iodata_to_binary()

      ops =
        buffer
        |> Message.decode()
        |> Enum.map(&Monitor.decode_event/1)
        |> Enum.map(& &1.op)

      assert ops == [:new_addr, :del_route, :del_addr]
    end
  end
end
