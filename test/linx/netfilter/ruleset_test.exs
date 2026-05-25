defmodule Linx.Netfilter.RulesetTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Chain, Expr, Object, Rule, Ruleset, Set, Table, Verdict, Vmap}
  alias Linx.Netfilter.Map, as: NMap

  describe "new/0" do
    test "returns an empty ruleset" do
      assert %Ruleset{tables: tables} = Ruleset.new()
      assert tables == %{}
    end
  end

  describe "add_table/4 + delete_table/2 + fetch_table/2" do
    test "adds a table and keys it by {family, name}" do
      rs = Ruleset.new()
      {:ok, rs} = Ruleset.add_table(rs, :inet, "myapp")
      assert {:ok, %Table{family: :inet, name: "myapp"}} = Ruleset.fetch_table(rs, "myapp")
    end

    test "duplicate (family, name) is :duplicate_table" do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "myapp")

      assert {:error, {:bad_table, {:duplicate_table, {:inet, "myapp"}}}} =
               Ruleset.add_table(rs, :inet, "myapp")
    end

    test "same name in different families coexist" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:ip, "myapp")
        |> Ruleset.add_table!(:ip6, "myapp")

      assert {:ok, %Table{family: :ip}} = Ruleset.fetch_table(rs, {:ip, "myapp"})
      assert {:ok, %Table{family: :ip6}} = Ruleset.fetch_table(rs, {:ip6, "myapp"})
    end

    test "bare name is ambiguous when multiple families share it" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:ip, "x")
        |> Ruleset.add_table!(:ip6, "x")

      assert {:error, {:ambiguous_table_name, "x"}} = Ruleset.fetch_table(rs, "x")
    end

    test "missing table returns :no_such_table" do
      assert {:error, {:no_such_table, "ghost"}} = Ruleset.fetch_table(Ruleset.new(), "ghost")

      assert {:error, {:no_such_table, {:inet, "ghost"}}} =
               Ruleset.fetch_table(Ruleset.new(), {:inet, "ghost"})
    end

    test "delete_table by bare name" do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "x")
      {:ok, rs} = Ruleset.delete_table(rs, "x")
      assert {:error, {:no_such_table, _}} = Ruleset.fetch_table(rs, "x")
    end

    test "delete_table by {family, name}" do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "x")
      {:ok, rs} = Ruleset.delete_table(rs, {:inet, "x"})
      assert rs.tables == %{}
    end
  end

  describe "add_table!/4" do
    test "raises on duplicate" do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "x")
      assert_raise ArgumentError, ~r/duplicate_table/, fn ->
        Ruleset.add_table!(rs, :inet, "x")
      end
    end
  end

  describe "add_chain/4" do
    test "adds a base chain to a table by bare name" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "myapp")
        |> Ruleset.add_chain!("myapp", "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")

      assert %{"input" => %Chain{type: :filter, hook: :input, priority: 0, policy: :drop}} =
               t.chains
    end

    test "add_chain to a missing table is :no_such_table" do
      rs = Ruleset.new()
      assert {:error, {:no_such_table, "ghost"}} = Ruleset.add_chain(rs, "ghost", "x")
    end

    test "family validation propagates through add_chain" do
      rs = Ruleset.new() |> Ruleset.add_table!(:arp, "t")

      assert {:error, {:bad_chain, {:type_not_valid_for_family, _}}} =
               Ruleset.add_chain(rs, "t", "c", type: :nat, hook: :prerouting, priority: 0)
    end
  end

  describe "add_rule/4 — pipeline DSL" do
    setup do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "myapp")
        |> Ruleset.add_chain!("myapp", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )

      {:ok, rs: rs}
    end

    test "appends a rule built from an expression list", %{rs: rs} do
      {:ok, rs} = Ruleset.add_rule(rs, "myapp", "input", [:accept])

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")
      chain = t.chains["input"]
      assert [%Rule{}] = chain.rules
      assert chain.rules |> hd() |> Rule.verdict() |> Map.get(:kind) == :accept
    end

    test "accepts a pre-built %Rule{}", %{rs: rs} do
      {:ok, r} = Rule.build([:drop], tag: :default)
      {:ok, rs} = Ruleset.add_rule(rs, "myapp", "input", r)

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")
      assert [%Rule{tag: :default}] = t.chains["input"].rules
    end

    test "tag uniqueness within chain is enforced", %{rs: rs} do
      rs = Ruleset.add_rule!(rs, "myapp", "input", [:accept], tag: :ssh)

      assert {:error, {:bad_rule, {:duplicate_tag, :ssh}}} =
               Ruleset.add_rule(rs, "myapp", "input", [:drop], tag: :ssh)
    end

    test "untagged rules don't trigger uniqueness checks", %{rs: rs} do
      rs =
        rs
        |> Ruleset.add_rule!("myapp", "input", [:accept])
        |> Ruleset.add_rule!("myapp", "input", [:accept])
        |> Ruleset.add_rule!("myapp", "input", [:drop])

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")
      assert length(t.chains["input"].rules) == 3
    end

    test "missing chain is :no_such_chain", %{rs: rs} do
      assert {:error, {:no_such_chain, "ghost"}} =
               Ruleset.add_rule(rs, "myapp", "ghost", [:accept])
    end

    test "bad rule expression bubbles up :bad_rule", %{rs: rs} do
      assert {:error, {:bad_rule, {:not_an_expression, :reject}}} =
               Ruleset.add_rule(rs, "myapp", "input", [:reject])
    end
  end

  describe "add_set/3, add_map/3, add_object/3, add_flowtable/3" do
    setup do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "myapp")
      {:ok, rs: rs}
    end

    test "add_set binds the set to its table", %{rs: rs} do
      {:ok, s} = Set.new("blocklist", key_type: :ipv4_addr)
      {:ok, rs} = Ruleset.add_set(rs, "myapp", s)

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")
      assert %{"blocklist" => %Set{table: "myapp"}} = t.sets
    end

    test "add_map with vmap data normalises verdicts", %{rs: rs} do
      {:ok, vm} =
        Vmap.new("dispatch", key_type: :inet_service, elements: [{22, :accept}, {80, :drop}])

      {:ok, rs} = Ruleset.add_map(rs, "myapp", vm)
      {:ok, t} = Ruleset.fetch_table(rs, "myapp")

      assert %{"dispatch" => %NMap{data_type: :verdict, elements: elements}} = t.maps
      assert [{22, %Verdict{kind: :accept}}, {80, %Verdict{kind: :drop}}] = elements
    end

    test "add_object binds object to table", %{rs: rs} do
      {:ok, o} = Object.new(:counter, "ssh")
      {:ok, rs} = Ruleset.add_object(rs, "myapp", o)

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")
      assert %{{:counter, "ssh"} => %Object{table: "myapp"}} = t.objects
    end
  end

  describe "tables/1" do
    test "lists tables as {family, name, %Table{}}" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "a")
        |> Ruleset.add_table!(:ip, "b")

      tables = Ruleset.tables(rs)
      assert length(tables) == 2
      assert {:inet, "a", %Table{}} = Enum.find(tables, fn {_, n, _} -> n == "a" end)
      assert {:ip, "b", %Table{}} = Enum.find(tables, fn {_, n, _} -> n == "b" end)
    end
  end

  describe "end-to-end pipeline DSL — headline shape" do
    test "compose a complete small ruleset" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "myapp")
        |> Ruleset.add_chain!("myapp", "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )
        |> Ruleset.add_chain!("myapp", "ssh_in")
        |> Ruleset.add_rule!(
          "myapp",
          "input",
          Rule.build!([Expr.new(:counter), {:jump, "ssh_in"}], tag: :try_ssh)
        )
        |> Ruleset.add_rule!("myapp", "ssh_in", [:accept])
        |> Ruleset.add_set!("myapp", Set.new!("blocklist", key_type: :ipv4_addr))

      {:ok, t} = Ruleset.fetch_table(rs, "myapp")

      assert map_size(t.chains) == 2
      assert map_size(t.sets) == 1
      assert %Chain{rules: [%Rule{tag: :try_ssh}]} = t.chains["input"]
      assert %Chain{rules: [%Rule{}]} = t.chains["ssh_in"]
    end
  end
end
