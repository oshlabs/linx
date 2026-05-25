defmodule Linx.Netfilter.SetTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.Set

  describe "new/2" do
    test "builds a basic set" do
      assert {:ok, %Set{name: "blocklist", key_type: :ipv4_addr, elements: [], flags: []}} =
               Set.new("blocklist", key_type: :ipv4_addr)
    end

    test "accepts all valid key types" do
      for kt <- [:ipv4_addr, :ipv6_addr, :ether_addr, :inet_proto, :inet_service, :mark, :ifname] do
        assert {:ok, %Set{key_type: ^kt}} = Set.new("s", key_type: kt)
      end
    end

    test "rejects unknown key type" do
      assert {:error, {:bad_set, {:unknown_key_type, :weird}}} =
               Set.new("s", key_type: :weird)
    end

    test "key_type is required" do
      assert {:error, {:bad_set, :key_type_required}} = Set.new("s", [])
    end

    test "accepts known flags" do
      assert {:ok, %Set{flags: [:timeout, :auto_merge]}} =
               Set.new("s", key_type: :ipv4_addr, flags: [:timeout, :auto_merge])
    end

    test "rejects unknown flag" do
      assert {:error, {:bad_set, {:unknown_flag, :weird}}} =
               Set.new("s", key_type: :ipv4_addr, flags: [:weird])
    end

    test "accepts integer fields" do
      assert {:ok, %Set{timeout: 60_000, size: 1024}} =
               Set.new("s", key_type: :ipv4_addr, timeout: 60_000, size: 1024)
    end

    test "rejects non-positive integer fields" do
      assert {:error, {:bad_set, {:bad_field, :timeout, 0}}} =
               Set.new("s", key_type: :ipv4_addr, timeout: 0)
    end

    test "rejects empty name" do
      assert {:error, {:bad_set, :name_empty}} = Set.new("", key_type: :ipv4_addr)
    end
  end

  describe "elements at construction time" do
    test "accepts well-formed ipv4_addr elements" do
      assert {:ok, %Set{elements: [{10, 0, 0, 1}, "1.2.3.4"]}} =
               Set.new("s", key_type: :ipv4_addr, elements: [{10, 0, 0, 1}, "1.2.3.4"])
    end

    test "accepts well-formed inet_service elements" do
      assert {:ok, %Set{elements: [22, 80, {1000, 2000}]}} =
               Set.new("s", key_type: :inet_service, elements: [22, 80, {1000, 2000}])
    end

    test "rejects out-of-range inet_service element" do
      assert {:error, {:bad_set, {:bad_element, _, _}}} =
               Set.new("s", key_type: :inet_service, elements: [99_999])
    end

    test "rejects bad ipv4_addr tuple" do
      assert {:error, {:bad_set, {:bad_element, _, _}}} =
               Set.new("s", key_type: :ipv4_addr, elements: [{300, 0, 0, 1}])
    end
  end

  describe "add_elements/2" do
    test "appends to the elements list" do
      {:ok, s} = Set.new("s", key_type: :inet_service)
      {:ok, s2} = Set.add_elements(s, [22, 80])
      assert s2.elements == [22, 80]

      {:ok, s3} = Set.add_elements(s2, [443])
      assert s3.elements == [22, 80, 443]
    end

    test "rejects bad-shaped elements with :bad_set_element" do
      {:ok, s} = Set.new("s", key_type: :inet_service)
      assert {:error, {:bad_set_element, _}} = Set.add_elements(s, [:not_a_port])
    end
  end

  describe "delete_elements/2" do
    test "removes matching elements" do
      {:ok, s} = Set.new("s", key_type: :inet_service, elements: [22, 80, 443])
      {:ok, s2} = Set.delete_elements(s, [80])
      assert s2.elements == [22, 443]
    end
  end

  describe "new!/2" do
    test "raises on invalid input" do
      assert_raise ArgumentError, ~r/invalid set/, fn ->
        Set.new!("s", key_type: :weird)
      end
    end
  end
end
