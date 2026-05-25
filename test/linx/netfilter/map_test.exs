defmodule Linx.Netfilter.MapTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Verdict, Vmap}
  alias Linx.Netfilter.Map, as: NMap

  describe "new/2" do
    test "builds a basic ipv4_addr → ipv4_addr map" do
      assert {:ok,
              %NMap{
                name: "dnat_targets",
                key_type: :inet_service,
                data_type: :ipv4_addr,
                elements: []
              }} =
               NMap.new("dnat_targets", key_type: :inet_service, data_type: :ipv4_addr)
    end

    test ":data_type is required" do
      assert {:error, {:bad_map, :data_type_required}} =
               NMap.new("m", key_type: :ipv4_addr)
    end

    test ":key_type is required" do
      assert {:error, {:bad_map, :key_type_required}} =
               NMap.new("m", data_type: :ipv4_addr)
    end

    test "rejects unknown data_type" do
      assert {:error, {:bad_map, {:unknown_data_type, :weird}}} =
               NMap.new("m", key_type: :ipv4_addr, data_type: :weird)
    end

    test "verdict data_type is accepted" do
      assert {:ok, %NMap{data_type: :verdict}} =
               NMap.new("m", key_type: :inet_service, data_type: :verdict)
    end
  end

  describe "elements at construction time" do
    test "non-verdict map elements are checked against data_type" do
      bad = [{22, "not_an_ipv4"}]

      assert {:error, {:bad_map, {:bad_element, _, _}}} =
               NMap.new("m",
                 key_type: :inet_service,
                 data_type: :ether_addr,
                 elements: [{22, :nope}]
               )

      assert {:error, {:bad_map, {:bad_element, _, _}}} =
               NMap.new("m",
                 key_type: :inet_service,
                 data_type: :mark,
                 elements: bad
               )
    end

    test "verdict data values are normalised to %Verdict{}" do
      {:ok, m} =
        NMap.new("m",
          key_type: :inet_service,
          data_type: :verdict,
          elements: [{22, :drop}, {80, {:jump, "http_in"}}]
        )

      assert [{22, %Verdict{kind: :drop}}, {80, %Verdict{kind: :jump, target: "http_in"}}] =
               m.elements
    end

    test "non-verdict data on a verdict map is :bad_map" do
      assert {:error, {:bad_map, {:bad_element, _, {:bad_verdict, _}}}} =
               NMap.new("m",
                 key_type: :inet_service,
                 data_type: :verdict,
                 elements: [{22, :nope}]
               )
    end

    test "non-tuple elements are :element_not_tuple" do
      assert {:error, {:bad_map, {:element_not_tuple, 22}}} =
               NMap.new("m",
                 key_type: :inet_service,
                 data_type: :verdict,
                 elements: [22]
               )
    end
  end

  describe "add_elements/2" do
    test "appends and normalises verdict elements" do
      {:ok, m} = NMap.new("m", key_type: :inet_service, data_type: :verdict)
      {:ok, m2} = NMap.add_elements(m, [{22, :accept}, {80, :drop}])

      assert [{22, %Verdict{kind: :accept}}, {80, %Verdict{kind: :drop}}] = m2.elements
    end

    test "bad elements come back as :bad_map_element" do
      {:ok, m} = NMap.new("m", key_type: :inet_service, data_type: :verdict)
      assert {:error, {:bad_map_element, _}} = NMap.add_elements(m, [{22, :nope}])
    end
  end

  describe "delete_elements/2" do
    test "removes by key (bare or {key, value})" do
      {:ok, m} =
        NMap.new("m",
          key_type: :inet_service,
          data_type: :verdict,
          elements: [{22, :accept}, {80, :drop}, {443, :drop}]
        )

      {:ok, m2} = NMap.delete_elements(m, [80])
      assert length(m2.elements) == 2
      refute Enum.any?(m2.elements, fn {k, _} -> k == 80 end)

      {:ok, m3} = NMap.delete_elements(m, [{443, :anything}])
      refute Enum.any?(m3.elements, fn {k, _} -> k == 443 end)
    end
  end

  describe "Vmap.new/2" do
    test "produces a Map with data_type: :verdict" do
      assert {:ok, %NMap{data_type: :verdict, key_type: :inet_service}} =
               Vmap.new("dispatch",
                 key_type: :inet_service,
                 elements: [{22, :accept}]
               )
    end

    test "Vmap.new!/2 raises on invalid input" do
      assert_raise ArgumentError, ~r/invalid map/, fn ->
        Vmap.new!("m", key_type: :weird)
      end
    end
  end
end
