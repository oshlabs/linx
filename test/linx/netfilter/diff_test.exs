defmodule Linx.Netfilter.DiffTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Diff, Patch, Rule, Ruleset, Set, Verdict}

  describe "identity diffs" do
    test "diff(empty, empty) is empty" do
      assert Diff.diff(Ruleset.new(), Ruleset.new()) |> Patch.empty?()
    end

    test "diff(rs, rs) is empty for a non-trivial ruleset" do
      rs = sample_ruleset()
      assert Diff.diff(rs, rs) |> Patch.empty?()
    end
  end

  describe "table-level ops" do
    test "create_table when target adds a new table" do
      from = Ruleset.new()
      to = Ruleset.new() |> Ruleset.add_table!(:inet, "fw")

      patch = Diff.diff(from, to)
      assert Enum.any?(patch.ops, &match?({:create_table, :inet, %{name: "fw"}}, &1))
    end

    test "tables only in `from` are left alone (scoped to `to`)" do
      # The reconcile diff is scoped to tables in `to`; tables only
      # in `from` are not deleted. This lets Linx coexist with
      # Docker / firewalld / other writers in the same netns.
      from = Ruleset.new() |> Ruleset.add_table!(:inet, "old")
      to = Ruleset.new()

      patch = Diff.diff(from, to)
      assert Patch.empty?(patch)
    end

    test "same name different family creates a separate table" do
      from = Ruleset.new() |> Ruleset.add_table!(:ip, "fw")
      to = from |> Ruleset.add_table!(:ip6, "fw")

      patch = Diff.diff(from, to)
      assert Enum.any?(patch.ops, &match?({:create_table, :ip6, _}, &1))
    end
  end

  describe "chain-level ops" do
    test "create_chain when target adds a chain" do
      from = Ruleset.new() |> Ruleset.add_table!(:inet, "fw")

      to =
        from
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )

      patch = Diff.diff(from, to)
      assert Enum.any?(patch.ops, &match?({:create_chain, :inet, "fw", %{name: "input"}}, &1))
    end

    test "structural chain change → delete + recreate" do
      from =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :accept
        )

      to =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0,
          policy: :drop
        )

      patch = Diff.diff(from, to)
      assert {:delete_chain, :inet, "fw", "input"} in patch.ops
      assert Enum.any?(patch.ops, &match?({:create_chain, :inet, "fw", _}, &1))
    end
  end

  describe "rule-level ops — tagged" do
    setup do
      base =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )

      {:ok, base: base}
    end

    test "added tagged rule → :create_rule", %{base: base} do
      from = base
      to = base |> Ruleset.add_rule!("fw", "input", [:accept], tag: :allow_all)

      patch = Diff.diff(from, to)
      assert Enum.any?(patch.ops, &match?({:create_rule, :inet, "fw", "input", _, :append}, &1))
    end

    test "removed tagged rule → :delete_rule (with handle)", %{base: base} do
      {:ok, r} = Rule.build([:accept], tag: :allow_all, handle: 42)

      from =
        base
        |> Ruleset.add_rule!("fw", "input", r)

      to = base

      patch = Diff.diff(from, to)
      assert {:delete_rule, :inet, "fw", "input", 42} in patch.ops
    end

    test "modified tagged rule → :replace_rule (in-place)", %{base: base} do
      {:ok, r1} = Rule.build([:accept], tag: :try_ssh, handle: 17)
      {:ok, r2} = Rule.build([:drop], tag: :try_ssh)

      from = base |> Ruleset.add_rule!("fw", "input", r1)
      to = base |> Ruleset.add_rule!("fw", "input", r2)

      patch = Diff.diff(from, to)

      assert Enum.any?(patch.ops, fn
               {:replace_rule, :inet, "fw", "input", 17, %Rule{handle: 17, tag: :try_ssh}} -> true
               _ -> false
             end)
    end

    test "unchanged tagged rule → no op", %{base: base} do
      {:ok, r} = Rule.build([:accept], tag: :allow_all, handle: 3)
      rs = base |> Ruleset.add_rule!("fw", "input", r)

      assert Diff.diff(rs, rs) |> Patch.empty?()
    end

    test "reordering tagged rules is a no-op", %{base: base} do
      {:ok, a} = Rule.build([:accept], tag: :a, handle: 1)
      {:ok, b} = Rule.build([:drop], tag: :b, handle: 2)

      from =
        base
        |> Ruleset.add_rule!("fw", "input", a)
        |> Ruleset.add_rule!("fw", "input", b)

      # Same rules, reversed.
      to =
        base
        |> Ruleset.add_rule!("fw", "input", b)
        |> Ruleset.add_rule!("fw", "input", a)

      patch = Diff.diff(from, to)

      # Tag-based identity means reorder is invisible.
      assert Patch.empty?(patch)
    end
  end

  describe "rule-level ops — untagged" do
    setup do
      base =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )

      {:ok, base: base}
    end

    test "untagged rule change → full rebuild", %{base: base} do
      {:ok, r1} = Rule.build([:accept], handle: 1)
      {:ok, r2} = Rule.build([:drop])

      from = base |> Ruleset.add_rule!("fw", "input", r1)
      to = base |> Ruleset.add_rule!("fw", "input", r2)

      patch = Diff.diff(from, to)
      assert Enum.any?(patch.ops, &match?({:delete_rule, _, _, _, 1}, &1))
      assert Enum.any?(patch.ops, &match?({:create_rule, _, _, _, _, :append}, &1))
    end
  end

  describe "set element diff" do
    test "adds and removes elements based on value identity" do
      from =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_set!(
          "fw",
          Set.new!("blk", key_type: :inet_service, elements: [22, 80, 443])
        )

      to =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_set!(
          "fw",
          Set.new!("blk", key_type: :inet_service, elements: [22, 8080])
        )

      patch = Diff.diff(from, to)
      ops = patch.ops

      add_op = Enum.find(ops, &match?({:add_set_elements, :inet, "fw", "blk", _}, &1))
      del_op = Enum.find(ops, &match?({:delete_set_elements, :inet, "fw", "blk", _}, &1))

      assert {:add_set_elements, :inet, "fw", "blk", added} = add_op
      assert MapSet.new(added) == MapSet.new([8080])

      assert {:delete_set_elements, :inet, "fw", "blk", removed} = del_op
      assert MapSet.new(removed) == MapSet.new([80, 443])
    end

    test "identical sets produce no op" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_set!(
          "fw",
          Set.new!("blk", key_type: :inet_service, elements: [22, 80])
        )

      assert Diff.diff(rs, rs) |> Patch.empty?()
    end
  end

  describe "validate_for_reconcile/1" do
    test ":ok when every rule is tagged" do
      {:ok, r1} = Rule.build([:accept], tag: :a)
      {:ok, r2} = Rule.build([:drop], tag: :b)

      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!("fw", "input", r1)
        |> Ruleset.add_rule!("fw", "input", r2)

      assert :ok = Diff.validate_for_reconcile(rs)
    end

    test "single untagged rule per chain is OK" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!("fw", "input", [:accept])

      assert :ok = Diff.validate_for_reconcile(rs)
    end

    test "untagged rule in multi-rule chain → :tag_required" do
      rs =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "fw")
        |> Ruleset.add_chain!("fw", "input",
          type: :filter,
          hook: :input,
          priority: 0
        )
        |> Ruleset.add_rule!("fw", "input", [:accept], tag: :a)
        |> Ruleset.add_rule!("fw", "input", [:drop])

      assert {:error, {:tag_required, {:inet, "fw", "input"}}} =
               Diff.validate_for_reconcile(rs)
    end
  end

  describe "Patch.sort/1 — topological order" do
    test "deletes before creates of overlapping entities" do
      ops = [
        {:create_rule, :inet, "fw", "input", %{}, :append},
        {:delete_rule, :inet, "fw", "input", 1},
        {:create_table, :inet, %{}},
        {:delete_table, :inet, "old"}
      ]

      sorted = Patch.sort(%Patch{ops: ops})

      # Find positions; deletes must precede creates of corresponding kinds.
      positions =
        sorted.ops
        |> Enum.with_index()
        |> Enum.map(fn {op, i} -> {elem(op, 0), i} end)

      delete_rule_idx = Enum.find_value(positions, fn {kind, i} -> kind == :delete_rule && i end)
      create_rule_idx = Enum.find_value(positions, fn {kind, i} -> kind == :create_rule && i end)

      delete_table_idx =
        Enum.find_value(positions, fn {kind, i} -> kind == :delete_table && i end)

      create_table_idx =
        Enum.find_value(positions, fn {kind, i} -> kind == :create_table && i end)

      assert delete_rule_idx < create_rule_idx
      assert delete_table_idx < create_table_idx
      # deletes happen before creates entirely:
      assert delete_rule_idx < create_table_idx
    end
  end

  describe "Patch Inspect" do
    test "renders op counts compactly" do
      patch = %Patch{
        ops: [
          {:create_table, :inet, %{}},
          {:replace_rule, :inet, "fw", "input", 1, %{}},
          {:delete_chain, :inet, "fw", "old"}
        ]
      }

      assert inspect(patch) ==
               "#Linx.Netfilter.Patch<3 ops: 1 create, 1 replace, 1 delete>"
    end

    test "empty patch renders" do
      assert inspect(Patch.new()) == "#Linx.Netfilter.Patch<0 ops: empty>"
    end
  end

  defp sample_ruleset do
    Ruleset.new()
    |> Ruleset.add_table!(:inet, "fw")
    |> Ruleset.add_chain!("fw", "input",
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :accept
    )
    |> Ruleset.add_rule!(
      "fw",
      "input",
      Rule.build!([Verdict.accept()], tag: :allow_all, handle: 1)
    )
  end
end
