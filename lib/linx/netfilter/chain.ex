defmodule Linx.Netfilter.Chain do
  @moduledoc """
  An nftables chain — a named container of rules within a table.

  Chains come in two flavours:

    * **Base chains** carry a `:type` + `:hook` + `:priority` and
      (optionally) a `:policy`. The kernel attaches them to the
      hook point so packets actually flow through them.

    * **Regular chains** have none of those — they are jump/goto
      targets reachable from base chains via verdicts. Pure
      organisational tools.

  ## Fields

    * `:name` — chain name (unique within the table).
    * `:table` — name of the owning table; `nil` for free-standing
      chains, populated when added to a table.
    * `:type` — `:filter` | `:nat` | `:route` for base chains, `nil`
      for regular chains.
    * `:hook` — `:prerouting` | `:input` | `:forward` | `:output` |
      `:postrouting` | `:ingress` | `:egress` for base chains, `nil`
      for regular chains.
    * `:priority` — integer | atom (named priority) |
      `{atom, integer}` (named-with-offset, e.g. `{:filter, -10}`).
      Required for base chains; `nil` for regular chains.
    * `:policy` — `:accept` | `:drop`; default verdict when no rule
      matches. Only meaningful on base chains. `nil` means "no
      explicit policy" (kernel defaults to `:accept`).
    * `:device` — interface name (string). Required for `:ingress`
      and `:egress` hooks; nil otherwise.
    * `:flags` — list (advanced): `:hw_offload` enables hardware
      offload (kernel + driver permitting); other flags reserved
      for future use.
    * `:handle` — kernel-assigned handle; `nil` until pushed.
    * `:rules` — ordered list of `%Linx.Netfilter.Rule{}`.

  ## Validation

  `new/2` validates the chain's intrinsic shape (base-vs-regular
  consistency, required fields). Family-specific validation (e.g.
  `:nat` type only valid in `ip`/`ip6`/`inet` families, `:ingress`
  hook only valid in certain families) lives in `validate_for_family/2`
  and runs when the chain is added to a table (`Linx.Netfilter.Ruleset.add_chain/4`).

  ## Construction

      iex> Chain.new("input", type: :filter, hook: :input, priority: 0, policy: :accept)
      {:ok, %Linx.Netfilter.Chain{name: "input", type: :filter, hook: :input, ...}}

      iex> Chain.new("ingress_drop", type: :filter, hook: :ingress, priority: -500, device: "eth0")
      {:ok, %Linx.Netfilter.Chain{hook: :ingress, device: "eth0", ...}}

      iex> Chain.new("input_extras")
      {:ok, %Linx.Netfilter.Chain{type: nil, hook: nil, ...}}  # regular chain

  Errors come back as `{:error, {:bad_chain, reason}}`.

  ## References

    * [`enum nf_inet_hooks`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter.h)
    * [wiki.nftables.org — Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
  """

  alias Linx.Netfilter.Rule

  @enforce_keys [:name]
  defstruct [
    :name,
    :table,
    :type,
    :hook,
    :priority,
    :policy,
    :device,
    :handle,
    flags: [],
    rules: []
  ]

  @type chain_type :: :filter | :nat | :route
  @type hook ::
          :prerouting | :input | :forward | :output | :postrouting | :ingress | :egress
  @type priority :: integer() | atom() | {atom(), integer()}
  @type policy :: :accept | :drop

  @type t :: %__MODULE__{
          name: String.t(),
          table: String.t() | nil,
          type: chain_type() | nil,
          hook: hook() | nil,
          priority: priority() | nil,
          policy: policy() | nil,
          device: String.t() | nil,
          flags: [atom()],
          handle: pos_integer() | nil,
          rules: [Rule.t()]
        }

  @valid_types [:filter, :nat, :route]
  @valid_hooks [:prerouting, :input, :forward, :output, :postrouting, :ingress, :egress]
  @device_hooks [:ingress, :egress]
  @valid_policies [:accept, :drop]
  @valid_flags [:hw_offload]

  # Named priority atoms commonly used in nft scripts. Bridge has
  # its own set with overlapping names — resolution to integers is
  # the wire codec's job. We accept these atoms here and pass
  # them through.
  @known_priority_names [:raw, :mangle, :dstnat, :filter, :security, :srcnat, :out]

  @doc """
  Builds a chain. Validates intrinsic shape; family-specific
  validation happens at `validate_for_family/2`.
  """
  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, {:bad_chain, term()}}
  def new(name, opts \\ []) when is_binary(name) and is_list(opts) do
    type = Keyword.get(opts, :type)
    hook = Keyword.get(opts, :hook)
    priority = Keyword.get(opts, :priority)
    policy = Keyword.get(opts, :policy)
    device = Keyword.get(opts, :device)
    flags = Keyword.get(opts, :flags, [])
    handle = Keyword.get(opts, :handle)
    table = Keyword.get(opts, :table)
    rules = Keyword.get(opts, :rules, [])

    with :ok <- validate_name(name),
         :ok <- validate_base_consistency(type, hook, priority),
         :ok <- validate_type(type),
         :ok <- validate_hook(hook),
         :ok <- validate_priority(priority),
         :ok <- validate_policy(policy, type, hook),
         :ok <- validate_device(device, hook),
         :ok <- validate_flags(flags),
         :ok <- validate_handle(handle),
         :ok <- validate_table_ref(table),
         :ok <- validate_rules(rules) do
      {:ok,
       %__MODULE__{
         name: name,
         table: table,
         type: type,
         hook: hook,
         priority: priority,
         policy: policy,
         device: device,
         flags: flags,
         handle: handle,
         rules: rules
       }}
    end
  end

  @doc """
  Bang variant of `new/2` — returns the chain or raises
  `ArgumentError`.
  """
  @spec new!(String.t(), keyword()) :: t()
  def new!(name, opts \\ []) do
    case new(name, opts) do
      {:ok, c} -> c
      {:error, {:bad_chain, reason}} -> raise ArgumentError, "invalid chain: #{inspect(reason)}"
    end
  end

  @doc """
  Returns `true` iff `chain` is a base chain (has `:type`, `:hook`,
  and `:priority` set).
  """
  @spec base?(t()) :: boolean()
  def base?(%__MODULE__{type: t, hook: h, priority: p})
      when not is_nil(t) and not is_nil(h) and not is_nil(p),
      do: true

  def base?(%__MODULE__{}), do: false

  @doc """
  Validates the chain against the given family — checks family-specific
  rules that `new/2` can't (since it doesn't know the family).

  Rules enforced:

    * Family-allowed chain types (e.g. `:nat` invalid in `arp`,
      `bridge`, `netdev`; `:route` only in `ip`/`ip6`).
    * Family-allowed hooks (e.g. `arp` only has `:input`/`:output`;
      `netdev` only has `:ingress`/`:egress`).
    * `:nat` chains restricted to NAT-applicable hooks.
    * `:route` chains restricted to `:output` hook.
  """
  @spec validate_for_family(t(), atom()) :: :ok | {:error, {:bad_chain, term()}}
  def validate_for_family(%__MODULE__{} = chain, family) do
    with :ok <- check_family(family),
         :ok <- check_type_for_family(chain.type, family),
         :ok <- check_hook_for_family(chain.hook, family),
         :ok <- check_type_hook(chain.type, chain.hook),
         :ok <- check_priority_for_family(chain.priority, family) do
      :ok
    end
  end

  # Named priorities must resolve for the family — this mirrors the
  # Wire.priority_int/2 clause table exactly. Without the check a
  # chain builds fine (Chain.new is family-agnostic) and the push
  # dies in the encoder with a FunctionClauseError instead of a
  # tagged error.
  @priority_names_for %{
    ip: [:raw, :mangle, :dstnat, :filter, :security, :srcnat],
    ip6: [:raw, :mangle, :dstnat, :filter, :security, :srcnat],
    inet: [:raw, :mangle, :dstnat, :filter, :security, :srcnat],
    bridge: [:dstnat, :filter, :out, :srcnat],
    netdev: [:filter],
    arp: [:filter]
  }

  defp check_priority_for_family(nil, _family), do: :ok
  defp check_priority_for_family(p, _family) when is_integer(p), do: :ok

  defp check_priority_for_family({name, offset}, family) when is_integer(offset),
    do: check_priority_for_family(name, family)

  defp check_priority_for_family(name, family) when is_atom(name) do
    if name in Map.get(@priority_names_for, family, []) do
      :ok
    else
      {:error, {:bad_chain, {:priority_not_valid_for_family, name, family}}}
    end
  end

  # ----- intrinsic validators -----

  defp validate_name(""), do: {:error, {:bad_chain, :name_empty}}
  defp validate_name(name) when is_binary(name), do: :ok

  # Base chain: all three of type/hook/priority must be set.
  # Regular chain: none of the three may be set.
  defp validate_base_consistency(nil, nil, nil), do: :ok

  defp validate_base_consistency(type, hook, priority)
       when not is_nil(type) and not is_nil(hook) and not is_nil(priority),
       do: :ok

  defp validate_base_consistency(type, hook, priority),
    do:
      {:error,
       {:bad_chain, {:incomplete_base_chain, %{type: type, hook: hook, priority: priority}}}}

  defp validate_type(nil), do: :ok
  defp validate_type(t) when t in @valid_types, do: :ok
  defp validate_type(other), do: {:error, {:bad_chain, {:unknown_type, other}}}

  defp validate_hook(nil), do: :ok
  defp validate_hook(h) when h in @valid_hooks, do: :ok
  defp validate_hook(other), do: {:error, {:bad_chain, {:unknown_hook, other}}}

  defp validate_priority(nil), do: :ok
  defp validate_priority(p) when is_integer(p), do: :ok
  defp validate_priority(name) when is_atom(name) and name in @known_priority_names, do: :ok

  defp validate_priority({name, offset})
       when is_atom(name) and name in @known_priority_names and is_integer(offset),
       do: :ok

  defp validate_priority(other), do: {:error, {:bad_chain, {:bad_priority, other}}}

  defp validate_policy(nil, _, _), do: :ok

  defp validate_policy(_policy, nil, _) do
    # Policy set on a regular chain (no type) → invalid.
    {:error, {:bad_chain, :policy_on_regular_chain}}
  end

  defp validate_policy(p, _type, _hook) when p in @valid_policies, do: :ok
  defp validate_policy(other, _, _), do: {:error, {:bad_chain, {:bad_policy, other}}}

  defp validate_device(nil, hook) when hook in @device_hooks,
    do: {:error, {:bad_chain, {:device_required_for_hook, hook}}}

  defp validate_device(nil, _), do: :ok

  defp validate_device(_dev, hook) when hook not in @device_hooks,
    do: {:error, {:bad_chain, {:device_not_allowed_for_hook, hook}}}

  defp validate_device(dev, _hook) when is_binary(dev) and dev != "", do: :ok
  defp validate_device(other, _), do: {:error, {:bad_chain, {:bad_device, other}}}

  defp validate_flags(flags) when is_list(flags) do
    Enum.reduce_while(flags, :ok, fn flag, :ok ->
      if flag in @valid_flags do
        {:cont, :ok}
      else
        {:halt, {:error, {:bad_chain, {:unknown_flag, flag}}}}
      end
    end)
  end

  defp validate_flags(other), do: {:error, {:bad_chain, {:flags_not_list, other}}}

  defp validate_handle(nil), do: :ok
  defp validate_handle(h) when is_integer(h) and h > 0, do: :ok
  defp validate_handle(other), do: {:error, {:bad_chain, {:bad_handle, other}}}

  defp validate_table_ref(nil), do: :ok
  defp validate_table_ref(t) when is_binary(t), do: :ok
  defp validate_table_ref(other), do: {:error, {:bad_chain, {:bad_table_ref, other}}}

  defp validate_rules(rules) when is_list(rules) do
    Enum.reduce_while(rules, :ok, fn
      %Rule{}, :ok -> {:cont, :ok}
      bad, :ok -> {:halt, {:error, {:bad_chain, {:non_rule_in_rules, bad}}}}
    end)
  end

  defp validate_rules(other), do: {:error, {:bad_chain, {:rules_not_list, other}}}

  # ----- family-specific validators -----

  @valid_families [:ip, :ip6, :inet, :arp, :bridge, :netdev]

  defp check_family(f) when f in @valid_families, do: :ok
  defp check_family(other), do: {:error, {:bad_chain, {:unknown_family, other}}}

  # Regular chain — no type/hook to check against family.
  defp check_type_for_family(nil, _family), do: :ok
  defp check_type_for_family(:filter, _family), do: :ok
  defp check_type_for_family(:nat, family) when family in [:ip, :ip6, :inet], do: :ok
  defp check_type_for_family(:route, family) when family in [:ip, :ip6], do: :ok

  defp check_type_for_family(type, family),
    do: {:error, {:bad_chain, {:type_not_valid_for_family, %{type: type, family: family}}}}

  # Regular chain — no hook to check.
  defp check_hook_for_family(nil, _), do: :ok

  defp check_hook_for_family(hook, :arp) when hook in [:input, :output], do: :ok

  defp check_hook_for_family(hook, :netdev) when hook in [:ingress, :egress], do: :ok

  defp check_hook_for_family(hook, :bridge)
       when hook in [:prerouting, :input, :forward, :output, :postrouting],
       do: :ok

  defp check_hook_for_family(hook, family)
       when family in [:ip, :ip6, :inet] and
              hook in [:prerouting, :input, :forward, :output, :postrouting, :ingress],
       do: :ok

  defp check_hook_for_family(hook, family),
    do: {:error, {:bad_chain, {:hook_not_valid_for_family, %{hook: hook, family: family}}}}

  # Type × hook compatibility. nat: no forward. route: output only.
  defp check_type_hook(nil, _), do: :ok
  defp check_type_hook(:filter, _), do: :ok

  defp check_type_hook(:nat, hook) when hook in [:prerouting, :input, :output, :postrouting],
    do: :ok

  defp check_type_hook(:nat, hook),
    do: {:error, {:bad_chain, {:nat_invalid_on_hook, hook}}}

  defp check_type_hook(:route, :output), do: :ok

  defp check_type_hook(:route, hook),
    do: {:error, {:bad_chain, {:route_invalid_on_hook, hook}}}

  @doc """
  Returns a new chain with `rule` appended to its rules list.

  This is a pure data operation — no validation beyond ensuring
  `rule` is a `%Rule{}`. Higher-level validation (tag uniqueness
  within chain) lives in `Linx.Netfilter.Ruleset.add_rule/4`.

  The added rule's `:chain` field is set to the chain's name (so
  free-standing rules pick up their context when inserted).
  """
  @spec add_rule(t(), Rule.t()) :: {:ok, t()} | {:error, {:bad_chain, term()}}
  def add_rule(%__MODULE__{} = chain, %Rule{} = rule) do
    rule_with_chain = %Rule{rule | chain: chain.name}
    {:ok, %__MODULE__{chain | rules: chain.rules ++ [rule_with_chain]}}
  end

  def add_rule(%__MODULE__{}, other),
    do: {:error, {:bad_chain, {:not_a_rule, other}}}

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Chain{} = c, _opts) do
      base = if c.hook, do: " #{c.type}/#{c.hook}", else: ""
      "#Linx.Netfilter.Chain<#{c.name}#{base}: #{length(c.rules)} rules>"
    end
  end
end
