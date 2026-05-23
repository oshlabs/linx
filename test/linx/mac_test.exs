defmodule Linx.MACTest do
  use ExUnit.Case, async: true

  import Linx.MAC
  alias Linx.MAC

  describe "parse/1" do
    test "parses a lowercase colon-hex MAC" do
      assert {:ok, %MAC{bytes: <<0x00, 0x11, 0x22, 0x33, 0x44, 0x55>>}} =
               MAC.parse("00:11:22:33:44:55")
    end

    test "accepts uppercase hex" do
      assert {:ok, %MAC{bytes: <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>}} =
               MAC.parse("AA:BB:CC:DD:EE:FF")
    end

    test "rejects too-few or too-many octets" do
      assert {:error, {:bad_mac, "00:11:22"}} = MAC.parse("00:11:22")
      assert {:error, {:bad_mac, "00:11:22:33:44:55:66"}} = MAC.parse("00:11:22:33:44:55:66")
    end

    test "rejects garbage octets" do
      assert {:error, {:bad_mac, _}} = MAC.parse("xx:11:22:33:44:55")
    end
  end

  describe "to_string/1" do
    test "renders in lowercase, zero-padded" do
      assert MAC.to_string(~MAC"02:0a:00:0b:00:cc") == "02:0a:00:0b:00:cc"
    end
  end

  describe "~MAC sigil" do
    test "builds a MAC" do
      assert ~MAC"00:11:22:33:44:55" ==
               %MAC{bytes: <<0x00, 0x11, 0x22, 0x33, 0x44, 0x55>>}
    end
  end

  describe "Inspect" do
    test "renders as a ~MAC sigil literal" do
      assert inspect(~MAC"02:aa:bb:cc:dd:ee") == ~s|~MAC"02:aa:bb:cc:dd:ee"|
    end
  end
end
