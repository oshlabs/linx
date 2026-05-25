defmodule Linx.Netfilter.ObjectTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.Object

  describe "new/4" do
    test "builds a counter object" do
      assert {:ok,
              %Object{
                kind: :counter,
                name: "ssh_attempts",
                data: %{packets: 0, bytes: 0}
              }} = Object.new(:counter, "ssh_attempts", %{packets: 0, bytes: 0})
    end

    test "accepts all canonical kinds" do
      kinds = [
        :counter,
        :quota,
        :limit,
        :ct_helper,
        :ct_timeout,
        :ct_expectation,
        :secmark,
        :synproxy
      ]

      for k <- kinds do
        assert {:ok, %Object{kind: ^k, name: "x"}} = Object.new(k, "x")
      end
    end

    test "rejects unknown kind" do
      assert {:error, {:bad_object, {:unknown_kind, :weird}}} =
               Object.new(:weird, "x")
    end

    test "rejects empty name" do
      assert {:error, {:bad_object, :name_empty}} = Object.new(:counter, "")
    end

    test "data defaults to nil" do
      assert {:ok, %Object{data: nil}} = Object.new(:counter, "x")
    end

    test "data is opaque (N1 doesn't validate per-kind shape)" do
      assert {:ok, %Object{data: "anything"}} = Object.new(:counter, "x", "anything")
    end

    test "carries opts into the struct" do
      assert {:ok, %Object{table: "myapp", comment: "ssh"}} =
               Object.new(:counter, "x", nil, table: "myapp", comment: "ssh")
    end
  end

  describe "new!/4" do
    test "raises on invalid input" do
      assert_raise ArgumentError, fn -> Object.new!(:weird, "x") end
    end
  end
end
