defmodule Linx.Netlink.Rtnl.MonitorTest do
  use ExUnit.Case, async: true

  import Linx.IP

  alias Linx.Netlink.Message
  alias Linx.Netlink.Rtnl.{Address, Monitor, Route}
  alias Linx.Netlink.Rtnl.Monitor.Event

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
  end
end
