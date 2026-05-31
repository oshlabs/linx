defmodule Linx.Netfilter.ChainTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Chain, Rule}

  describe "new/2 — base chain" do
    test "builds a base chain with type+hook+priority" do
      assert {:ok,
              %Chain{
                name: "input",
                type: :filter,
                hook: :input,
                priority: 0,
                policy: :accept,
                rules: []
              }} =
               Chain.new("input",
                 type: :filter,
                 hook: :input,
                 priority: 0,
                 policy: :accept
               )
    end

    test "accepts named-priority atoms" do
      assert {:ok, %Chain{priority: :filter}} =
               Chain.new("input", type: :filter, hook: :input, priority: :filter)
    end

    test "accepts named-with-offset priority tuples" do
      assert {:ok, %Chain{priority: {:filter, -10}}} =
               Chain.new("c", type: :filter, hook: :input, priority: {:filter, -10})
    end

    test "rejects unknown priority atom" do
      assert {:error, {:bad_chain, {:bad_priority, :weird}}} =
               Chain.new("c", type: :filter, hook: :input, priority: :weird)
    end

    test "rejects unknown type" do
      assert {:error, {:bad_chain, {:unknown_type, :weird}}} =
               Chain.new("c", type: :weird, hook: :input, priority: 0)
    end

    test "rejects unknown hook" do
      assert {:error, {:bad_chain, {:unknown_hook, :weird}}} =
               Chain.new("c", type: :filter, hook: :weird, priority: 0)
    end

    test "rejects unknown policy" do
      assert {:error, {:bad_chain, {:bad_policy, :weird}}} =
               Chain.new("c", type: :filter, hook: :input, priority: 0, policy: :weird)
    end

    test "rejects partial base chain (type without hook)" do
      assert {:error, {:bad_chain, {:incomplete_base_chain, _}}} =
               Chain.new("c", type: :filter)
    end

    test "rejects partial base chain (hook without priority)" do
      assert {:error, {:bad_chain, {:incomplete_base_chain, _}}} =
               Chain.new("c", type: :filter, hook: :input)
    end
  end

  describe "new/2 — regular chain" do
    test "builds a regular chain with name only" do
      assert {:ok, %Chain{name: "input_extras", type: nil, hook: nil, priority: nil, policy: nil}} =
               Chain.new("input_extras")
    end

    test "policy on a regular chain is :policy_on_regular_chain" do
      assert {:error, {:bad_chain, :policy_on_regular_chain}} =
               Chain.new("c", policy: :accept)
    end

    test "empty name is rejected" do
      assert {:error, {:bad_chain, :name_empty}} = Chain.new("")
    end
  end

  describe "new/2 — device requirement" do
    test ":ingress hook requires :device" do
      assert {:error, {:bad_chain, {:device_required_for_hook, :ingress}}} =
               Chain.new("c", type: :filter, hook: :ingress, priority: 0)
    end

    test ":egress hook requires :device" do
      assert {:error, {:bad_chain, {:device_required_for_hook, :egress}}} =
               Chain.new("c", type: :filter, hook: :egress, priority: 0)
    end

    test ":device on a non-device hook is rejected" do
      assert {:error, {:bad_chain, {:device_not_allowed_for_hook, :input}}} =
               Chain.new("c", type: :filter, hook: :input, priority: 0, device: "eth0")
    end

    test ":ingress with :device is accepted" do
      assert {:ok, %Chain{device: "eth0", hook: :ingress}} =
               Chain.new("c", type: :filter, hook: :ingress, priority: 0, device: "eth0")
    end
  end

  describe "validate_for_family/2" do
    test ":nat invalid in :arp family" do
      {:ok, c} = Chain.new("c", type: :nat, hook: :prerouting, priority: 0)

      assert {:error, {:bad_chain, {:type_not_valid_for_family, %{type: :nat, family: :arp}}}} =
               Chain.validate_for_family(c, :arp)
    end

    test ":nat invalid in :bridge family" do
      {:ok, c} = Chain.new("c", type: :nat, hook: :prerouting, priority: 0)
      assert {:error, {:bad_chain, _}} = Chain.validate_for_family(c, :bridge)
    end

    test ":nat valid in :ip, :ip6, :inet" do
      {:ok, c} = Chain.new("c", type: :nat, hook: :prerouting, priority: 0)
      assert :ok = Chain.validate_for_family(c, :ip)
      assert :ok = Chain.validate_for_family(c, :ip6)
      assert :ok = Chain.validate_for_family(c, :inet)
    end

    test ":nat on forward hook is :nat_invalid_on_hook" do
      {:ok, c} = Chain.new("c", type: :nat, hook: :forward, priority: 0)

      assert {:error, {:bad_chain, {:nat_invalid_on_hook, :forward}}} =
               Chain.validate_for_family(c, :ip)
    end

    test ":route only valid on :output hook" do
      {:ok, c} = Chain.new("c", type: :route, hook: :input, priority: 0)

      assert {:error, {:bad_chain, {:route_invalid_on_hook, :input}}} =
               Chain.validate_for_family(c, :ip)

      {:ok, c2} = Chain.new("c", type: :route, hook: :output, priority: 0)
      assert :ok = Chain.validate_for_family(c2, :ip)
    end

    test ":route only valid in :ip, :ip6" do
      {:ok, c} = Chain.new("c", type: :route, hook: :output, priority: 0)
      assert :ok = Chain.validate_for_family(c, :ip)
      assert :ok = Chain.validate_for_family(c, :ip6)

      assert {:error, {:bad_chain, {:type_not_valid_for_family, %{type: :route, family: :inet}}}} =
               Chain.validate_for_family(c, :inet)
    end

    test ":arp family allows only :input and :output hooks" do
      {:ok, c_fwd} = Chain.new("c", type: :filter, hook: :forward, priority: 0)

      assert {:error, {:bad_chain, {:hook_not_valid_for_family, _}}} =
               Chain.validate_for_family(c_fwd, :arp)

      {:ok, c_input} = Chain.new("c", type: :filter, hook: :input, priority: 0)
      assert :ok = Chain.validate_for_family(c_input, :arp)
    end

    test ":netdev family allows only :ingress and :egress hooks" do
      {:ok, c} = Chain.new("c", type: :filter, hook: :ingress, priority: 0, device: "eth0")
      assert :ok = Chain.validate_for_family(c, :netdev)

      {:ok, c_input} = Chain.new("c", type: :filter, hook: :input, priority: 0)

      assert {:error, {:bad_chain, {:hook_not_valid_for_family, _}}} =
               Chain.validate_for_family(c_input, :netdev)
    end

    test "regular chains validate trivially for any family" do
      {:ok, c} = Chain.new("input_extras")

      for f <- [:ip, :ip6, :inet, :arp, :bridge, :netdev] do
        assert :ok = Chain.validate_for_family(c, f)
      end
    end

    test "unknown family is :unknown_family" do
      {:ok, c} = Chain.new("c", type: :filter, hook: :input, priority: 0)

      assert {:error, {:bad_chain, {:unknown_family, :weird}}} =
               Chain.validate_for_family(c, :weird)
    end
  end

  describe "base?/1" do
    test "true when type+hook+priority are all set" do
      {:ok, c} = Chain.new("c", type: :filter, hook: :input, priority: 0)
      assert Chain.base?(c)
    end

    test "false when any of type/hook/priority is nil" do
      {:ok, c} = Chain.new("c")
      refute Chain.base?(c)
    end
  end

  describe "add_rule/2" do
    test "appends a rule and sets its :chain field" do
      {:ok, c} = Chain.new("input", type: :filter, hook: :input, priority: 0)
      {:ok, r} = Rule.build([:accept])
      assert {:ok, %Chain{rules: [%Rule{chain: "input"}]}} = Chain.add_rule(c, r)
    end

    test "appends preserve order" do
      {:ok, c} = Chain.new("input", type: :filter, hook: :input, priority: 0)
      {:ok, r1} = Rule.build([:accept], tag: :a)
      {:ok, r2} = Rule.build([:drop], tag: :b)

      {:ok, c2} = Chain.add_rule(c, r1)
      {:ok, c3} = Chain.add_rule(c2, r2)

      assert [%Rule{tag: :a}, %Rule{tag: :b}] = c3.rules
    end

    test "non-rule input is :bad_chain" do
      {:ok, c} = Chain.new("c")
      assert {:error, {:bad_chain, {:not_a_rule, :nope}}} = Chain.add_rule(c, :nope)
    end
  end
end
