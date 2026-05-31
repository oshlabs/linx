defmodule Linx.Netfilter.TableTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Chain, Flowtable, Object, Set, Table}
  alias Linx.Netfilter.Map, as: NMap

  describe "new/3" do
    test "builds a table with the given family + name" do
      assert {:ok, %Table{family: :inet, name: "myapp", flags: [], chains: %{}}} =
               Table.new(:inet, "myapp")
    end

    test "accepts all valid families" do
      for f <- [:ip, :ip6, :inet, :arp, :bridge, :netdev] do
        assert {:ok, %Table{family: ^f}} = Table.new(f, "t")
      end
    end

    test "rejects unknown family" do
      assert {:error, {:bad_table, {:unknown_family, :weird}}} = Table.new(:weird, "t")
    end

    test "rejects empty name" do
      assert {:error, {:bad_table, :name_empty}} = Table.new(:inet, "")
    end

    test "accepts known flags" do
      assert {:ok, %Table{flags: [:owner]}} = Table.new(:inet, "t", flags: [:owner])
      assert {:ok, %Table{flags: [:persist]}} = Table.new(:inet, "t", flags: [:persist])
      assert {:ok, %Table{flags: [:dormant]}} = Table.new(:inet, "t", flags: [:dormant])
    end

    test "rejects unknown flag" do
      assert {:error, {:bad_table, {:unknown_flag, :weird}}} =
               Table.new(:inet, "t", flags: [:weird])
    end
  end

  describe "add_chain/2" do
    test "adds a chain and binds its :table field" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, c} = Chain.new("input", type: :filter, hook: :input, priority: 0)

      assert {:ok, %Table{chains: %{"input" => %Chain{table: "myapp"}}}} = Table.add_chain(t, c)
    end

    test "rejects duplicate chain names" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, c} = Chain.new("input", type: :filter, hook: :input, priority: 0)
      {:ok, t} = Table.add_chain(t, c)

      assert {:error, {:bad_table, {:duplicate_chain, "input"}}} = Table.add_chain(t, c)
    end

    test "runs family validation on add" do
      {:ok, t} = Table.new(:arp, "myapp")
      {:ok, c} = Chain.new("c", type: :nat, hook: :prerouting, priority: 0)

      assert {:error, {:bad_chain, {:type_not_valid_for_family, %{type: :nat, family: :arp}}}} =
               Table.add_chain(t, c)
    end
  end

  describe "add_set/2 and add_map/2" do
    test "adds a set" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, s} = Set.new("blocklist", key_type: :ipv4_addr)

      assert {:ok, %Table{sets: %{"blocklist" => %Set{table: "myapp"}}}} = Table.add_set(t, s)
    end

    test "rejects duplicate set names" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, s} = Set.new("s", key_type: :ipv4_addr)
      {:ok, t} = Table.add_set(t, s)

      assert {:error, {:bad_table, {:duplicate_set, "s"}}} = Table.add_set(t, s)
    end

    test "set/map share a namespace — collision rejected" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, s} = Set.new("x", key_type: :ipv4_addr)
      {:ok, m} = NMap.new("x", key_type: :ipv4_addr, data_type: :ipv4_addr)

      {:ok, t} = Table.add_set(t, s)
      assert {:error, {:bad_table, {:set_map_name_collision, "x"}}} = Table.add_map(t, m)
    end
  end

  describe "add_object/2" do
    test "adds an object" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, o} = Object.new(:counter, "ssh")

      assert {:ok, %Table{objects: %{{:counter, "ssh"} => %Object{table: "myapp"}}}} =
               Table.add_object(t, o)
    end

    test "different kinds may share a name" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, counter} = Object.new(:counter, "x")
      {:ok, quota} = Object.new(:quota, "x")

      {:ok, t} = Table.add_object(t, counter)
      assert {:ok, %Table{}} = Table.add_object(t, quota)
    end

    test "duplicate (kind, name) rejected" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, o} = Object.new(:counter, "x")
      {:ok, t} = Table.add_object(t, o)

      assert {:error, {:bad_table, {:duplicate_object, {:counter, "x"}}}} =
               Table.add_object(t, o)
    end
  end

  describe "add_flowtable/2" do
    test "adds a flowtable" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, ft} = Flowtable.new("ft1", hook: :ingress, priority: 0, devices: ["eth0"])

      assert {:ok, %Table{flowtables: %{"ft1" => %Flowtable{table: "myapp"}}}} =
               Table.add_flowtable(t, ft)
    end

    test "duplicate flowtable name rejected" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, ft} = Flowtable.new("ft1")
      {:ok, t} = Table.add_flowtable(t, ft)

      assert {:error, {:bad_table, {:duplicate_flowtable, "ft1"}}} =
               Table.add_flowtable(t, ft)
    end
  end

  describe "fetch_chain/2 and put_chain/2" do
    test "fetch_chain returns the chain or :no_such_chain" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, c} = Chain.new("input", type: :filter, hook: :input, priority: 0)
      {:ok, t} = Table.add_chain(t, c)

      assert {:ok, %Chain{name: "input"}} = Table.fetch_chain(t, "input")
      assert {:error, :no_such_chain} = Table.fetch_chain(t, "nope")
    end

    test "put_chain replaces an existing chain" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, %Chain{} = c} = Chain.new("input", type: :filter, hook: :input, priority: 0)
      {:ok, t} = Table.add_chain(t, c)

      mutated = %{c | priority: 10, table: "myapp"}

      assert {:ok, %Table{chains: %{"input" => %Chain{priority: 10}}}} =
               Table.put_chain(t, mutated)
    end

    test "put_chain on a missing name is :no_such_chain" do
      {:ok, t} = Table.new(:inet, "myapp")
      {:ok, %Chain{} = c} = Chain.new("input", type: :filter, hook: :input, priority: 0)

      assert {:error, {:bad_table, {:no_such_chain, "input"}}} =
               Table.put_chain(t, %{c | table: "myapp"})
    end
  end
end
