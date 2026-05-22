defmodule Linx.Netlink.ErrorTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Error

  describe "from_errno/2" do
    test "maps a known errno to its POSIX atom" do
      assert %Error{errno: :enodev, code: 19, message: nil} = Error.from_errno(19)
    end

    test "attaches a kernel-supplied message when given" do
      assert %Error{errno: :enodev, code: 19, message: "Device does not exist"} =
               Error.from_errno(19, "Device does not exist")
    end

    test "keeps the code and reports :unknown for an unmapped errno" do
      assert %Error{errno: :unknown, code: 12_345, message: nil} = Error.from_errno(12_345)
    end
  end

  describe "Exception.message/1" do
    test "renders a known error" do
      assert Exception.message(Error.from_errno(19)) == "netlink ENODEV (19)"
    end

    test "appends the kernel message when present" do
      assert Exception.message(Error.from_errno(19, "Device does not exist")) ==
               "netlink ENODEV (19): Device does not exist"
    end

    test "renders an unmapped errno by its code" do
      assert Exception.message(Error.from_errno(12_345)) == "netlink errno 12345"
    end
  end
end
