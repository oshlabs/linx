defmodule Linx.Netlink.Rtnl.RuleTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.{Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Rule

  test "encode/decode round-trip" do
    message = %Rule{
      family: 2,
      src_len: 24,
      dst_len: 0,
      tos: 0,
      table: 100,
      res1: 0,
      res2: 0,
      action: 1,
      flags: 0,
      src: <<10, 0, 0, 0>>
    }

    assert Rule.decode(Rule.encode(message)) == message
  end

  test "list/1 returns the host's policy-routing rules" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, rules} = Rule.list(socket)
    # Every Linux host has at least the three default rules — priorities
    # 0 (local), 32766 (main), 32767 (default).
    assert length(rules) >= 3
    assert Enum.all?(rules, &match?(%Rule{}, &1))

    assert :ok = Socket.close(socket)
  end

  test "target_table/1 prefers FRA_TABLE over the header byte" do
    assert Rule.target_table(%Rule{table: 100}) == 100
    assert Rule.target_table(%Rule{table: 0, table_ext: 1000}) == 1000
    # When both are set the 32-bit form wins — that is how the kernel
    # actually conveys tables above 255.
    assert Rule.target_table(%Rule{table: 0, table_ext: 12345}) == 12345
  end

  test "add/2 rejects an opts list missing :table" do
    {:ok, socket} = Rtnl.open()

    assert {:error, {:missing_option, :table}} = Rule.add(socket, from: "10.0.0.0/24")

    assert :ok = Socket.close(socket)
  end
end
