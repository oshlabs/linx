defmodule Linx.Netfilter.Expr do
  @moduledoc """
  A single netfilter expression — one node in a rule's expression
  list.

  Expressions are the kernel's per-rule building blocks: a payload
  extraction, a comparison, a lookup, a verdict load. Each carries
  a `:name` (the kernel's expression-type string, e.g. `"payload"`,
  `"cmp"`, `"immediate"`, `"lookup"`) and `:data` (kind-specific
  arguments — a keyword list, a map, a verdict, …).

  ## N1 scope

  N1 ships the struct shape and a small set of constructors:

    * `immediate/1` — load a verdict (or, in N2+, a constant) into
      the kernel's register 0.
    * `new/2` — generic constructor for arbitrary `(name, data)`
      pairs. Useful for callers building expressions Linx doesn't
      yet have a dedicated helper for.

  The full constructor set (`cmp/3`, `payload/3`, `meta/2`,
  `bitwise/3`, `ct/2`, `lookup/2`, `reject/2`, `counter/1`, NAT
  helpers) lands in N2/N3 alongside the wire encoder. At the
  value-type level the struct shape is final today — the additional
  constructors are extra entry points, not extra fields.

  ## Inspect

      iex> Expr.immediate(Verdict.accept())
      #Linx.Netfilter.Expr<immediate accept>

      iex> Expr.new(:counter, %{packets: 0, bytes: 0})
      #Linx.Netfilter.Expr<counter>

  ## References

    * [`Documentation/networking/netlink_spec/nftables` — Expression
      types](https://docs.kernel.org/networking/netlink_spec/nftables.html)
  """

  alias Linx.Netfilter.Verdict

  @enforce_keys [:name]
  defstruct [:name, :data]

  @type t :: %__MODULE__{name: atom() | String.t(), data: term()}

  # Default register for value-bearing expressions. NFT_REG_1 is the
  # legacy 16-byte register; both reg1 and reg32_00 alias to the
  # same memory in modern kernels. Using reg1 keeps wire-format
  # output identical to libnftnl-emitted rules.
  @reg_value 1

  @doc """
  Generic constructor: an expression named `name` carrying `data`.

  Most callers want one of the kind-specific helpers (`immediate/1`
  here; `cmp/3` / `payload/3` / etc. landing in N2). Use `new/2`
  when you're constructing an expression Linx doesn't yet have a
  dedicated helper for.
  """
  @spec new(atom() | String.t(), term()) :: t()
  def new(name, data \\ nil) when is_atom(name) or is_binary(name),
    do: %__MODULE__{name: name, data: data}

  @doc """
  An `immediate` expression — load a verdict into register 0.

  The data is the verdict struct itself. Accepts a `%Verdict{}` or
  any input form `Verdict.new!/1` understands.

  In N2 this constructor also accepts a constant (a binary or
  integer) for loading a value into a register prior to a `cmp` —
  the kernel uses the same expression for both forms.

      iex> Expr.immediate(Verdict.accept())
      #Linx.Netfilter.Expr<immediate accept>

      iex> Expr.immediate(:drop)
      #Linx.Netfilter.Expr<immediate drop>
  """
  @spec immediate(Verdict.input()) :: t()
  def immediate(%Verdict{} = v), do: %__MODULE__{name: :immediate, data: v}
  def immediate(other), do: %__MODULE__{name: :immediate, data: Verdict.new!(other)}

  @doc """
  Returns `true` if `expr` is an `immediate` expression carrying a
  `%Verdict{}` — i.e. a terminal expression in a rule.

  N2 also recognises wrapped immediate-verdict in the
  `%{dreg: 0, value: %Verdict{}}` shape that the codec uses.
  """
  @spec verdict?(t()) :: boolean()
  def verdict?(%__MODULE__{name: :immediate, data: %Verdict{}}), do: true

  def verdict?(%__MODULE__{name: :immediate, data: %{dreg: 0, value: %Verdict{}}}), do: true

  def verdict?(%__MODULE__{}), do: false

  # ===========================================================
  # N2 expression constructors (cmp / payload / meta / bitwise /
  # ct / lookup / reject / counter)
  # ===========================================================

  @doc """
  Comparison expression. Compares the value in `sreg` against
  `value` using `op`.

  `op` is one of `:eq`, `:neq`, `:lt`, `:lte`, `:gt`, `:gte`.
  `value` is a raw binary of the right length (1/2/4/16 bytes
  depending on what was loaded into `sreg`).

  Most callers don't construct `cmp/3` directly — the high-level
  `~NFT` sigil (N8) and pipeline helpers compose `payload + cmp`
  into the natural "tcp dport 22" shape.

      iex> Expr.cmp(:eq, <<22::big-16>>)
      #Linx.Netfilter.Expr<cmp>
  """
  @spec cmp(atom(), binary(), keyword()) :: t()
  def cmp(op, value, opts \\ []) when is_atom(op) and is_binary(value) and is_list(opts) do
    sreg = Keyword.get(opts, :sreg, @reg_value)
    %__MODULE__{name: :cmp, data: %{sreg: sreg, op: op, value: value}}
  end

  @doc """
  Payload-extraction expression. Reads `len` bytes at `offset` into
  `base`-anchored header data and stores in `dreg`.

  `base` is `:link` / `:network` / `:transport` / `:inner`. Use
  the named shortcuts (`payload(:tcp_dport)`, etc.) for the common
  cases.

      iex> Expr.payload(:transport, 2, 2)
      #Linx.Netfilter.Expr<payload>

      iex> Expr.payload(:tcp_dport)  # equivalent to (:transport, 2, 2)
      #Linx.Netfilter.Expr<payload>
  """
  @spec payload(atom(), non_neg_integer(), pos_integer(), keyword()) :: t()
  def payload(base, offset, len, opts \\ [])
      when is_atom(base) and is_integer(offset) and is_integer(len) and is_list(opts) do
    dreg = Keyword.get(opts, :dreg, @reg_value)
    %__MODULE__{name: :payload, data: %{base: base, offset: offset, len: len, dreg: dreg}}
  end

  @doc """
  Named-shortcut variant of `payload/4` for common header fields.

  Supported aliases:

    * `:ip_saddr` / `:ip_daddr` — IPv4 source / dest address
      (network base, offsets 12 / 16, length 4).
    * `:ip6_saddr` / `:ip6_daddr` — IPv6 source / dest address
      (network base, offsets 8 / 24, length 16).
    * `:ip_protocol` — IPv4 protocol byte (network base, offset 9,
      length 1).
    * `:tcp_sport` / `:tcp_dport` — TCP source / dest port
      (transport base, offsets 0 / 2, length 2). Same wire form as
      `:udp_sport` / `:udp_dport`.
    * `:udp_sport` / `:udp_dport`.
    * `:icmp_type` / `:icmp_code` — (transport base, offsets 0 / 1,
      length 1).
  """
  @spec payload(atom(), keyword()) :: t()
  def payload(field, opts \\ []) when is_atom(field) and is_list(opts) do
    case payload_alias(field) do
      {base, offset, len} -> payload(base, offset, len, opts)
      :unknown -> raise ArgumentError, "unknown payload alias: #{inspect(field)}"
    end
  end

  defp payload_alias(:ip_saddr), do: {:network, 12, 4}
  defp payload_alias(:ip_daddr), do: {:network, 16, 4}
  defp payload_alias(:ip_protocol), do: {:network, 9, 1}
  defp payload_alias(:ip6_saddr), do: {:network, 8, 16}
  defp payload_alias(:ip6_daddr), do: {:network, 24, 16}
  defp payload_alias(:tcp_sport), do: {:transport, 0, 2}
  defp payload_alias(:tcp_dport), do: {:transport, 2, 2}
  defp payload_alias(:udp_sport), do: {:transport, 0, 2}
  defp payload_alias(:udp_dport), do: {:transport, 2, 2}
  defp payload_alias(:icmp_type), do: {:transport, 0, 1}
  defp payload_alias(:icmp_code), do: {:transport, 1, 1}
  defp payload_alias(_), do: :unknown

  @doc """
  Metadata-load expression. Reads `key` from the packet's metadata
  into `dreg`.

  Keys: `:len`, `:protocol`, `:mark`, `:iif`, `:oif`, `:iifname`,
  `:oifname`, `:nfproto`, `:l4proto`, etc. (see
  `Linx.Netfilter.Wire.meta_key_int/1` for the full list N2 knows).
  """
  @spec meta(atom(), keyword()) :: t()
  def meta(key, opts \\ []) when is_atom(key) and is_list(opts) do
    dreg = Keyword.get(opts, :dreg, @reg_value)
    %__MODULE__{name: :meta, data: %{key: key, dreg: dreg}}
  end

  @doc """
  Bitwise AND-with-mask expression. Used most commonly to mask
  CIDR-shaped addresses before a `cmp` comparison.

  `mask` and `xor` must be the same length; `len` is that length
  in bytes (defaults to `byte_size(mask)`).
  """
  @spec bitwise(binary(), binary(), keyword()) :: t()
  def bitwise(mask, xor, opts \\ [])
      when is_binary(mask) and is_binary(xor) and is_list(opts) do
    sreg = Keyword.get(opts, :sreg, @reg_value)
    dreg = Keyword.get(opts, :dreg, @reg_value)
    len = Keyword.get(opts, :len, byte_size(mask))

    %__MODULE__{
      name: :bitwise,
      data: %{sreg: sreg, dreg: dreg, len: len, mask: mask, xor: xor}
    }
  end

  @doc """
  Connection-tracking load expression. Reads `key` (`:state`,
  `:mark`, etc.) from conntrack state into `dreg`.

  N2 ships `:state`-shaped CT loads. CT-state matching uses the
  bitmask integers — wrap the state atom(s) with
  `Linx.Netfilter.Wire.ct_state_bits/1` to produce the comparison
  value:

      [Expr.ct(:state), Expr.cmp(:neq, <<Wire.ct_state_bits(:invalid)::big-32>>)]
  """
  @spec ct(atom(), keyword()) :: t()
  def ct(key, opts \\ []) when is_atom(key) and is_list(opts) do
    dreg = Keyword.get(opts, :dreg, @reg_value)
    %__MODULE__{name: :ct, data: %{key: key, dreg: dreg}}
  end

  @doc """
  Set-lookup expression. Looks up `sreg`'s value in the named set;
  emits a verdict on hit (for plain sets) or loads associated data
  into `dreg` (for maps and vmaps).

  Options:

    * `:sreg` — register to look up from (default 1).
    * `:dreg` — register to store the map's data value in (for
      maps / vmaps). Omitted for plain sets.
    * `:flags` — `[:inv]` to invert match (NFT_LOOKUP_F_INV).
  """
  @spec lookup(String.t(), keyword()) :: t()
  def lookup(set_name, opts \\ []) when is_binary(set_name) and is_list(opts) do
    %__MODULE__{
      name: :lookup,
      data: %{
        set: set_name,
        sreg: Keyword.get(opts, :sreg, @reg_value),
        dreg: Keyword.get(opts, :dreg),
        flags: Keyword.get(opts, :flags, [])
      }
    }
  end

  @doc """
  Reject expression. Produces an explicit rejection response then
  drops the packet.

  Types:

    * `:icmp_unreach` — ICMP destination-unreachable (default for
      `:ip` / `:ip6` / `:inet` families). `:icmp_code` opt sets
      the ICMP code (defaults to 3 — port-unreachable).
    * `:tcp_reset` — TCP RST (only valid for TCP packets).
    * `:icmpx_unreach` — family-agnostic ICMP-unreach (kernel
      picks ICMP vs ICMPv6 based on packet family).
  """
  @spec reject(atom(), keyword()) :: t()
  def reject(type \\ :icmp_unreach, opts \\ []) when is_atom(type) and is_list(opts) do
    code = Keyword.get(opts, :icmp_code)
    %__MODULE__{name: :reject, data: %{type: type, code: code}}
  end

  @doc """
  Counter expression. Per-rule packet + byte counter; the kernel
  increments it on every match. Reads back via `pull/1..2`.
  """
  @spec counter(keyword()) :: t()
  def counter(opts \\ []) when is_list(opts) do
    %__MODULE__{
      name: :counter,
      data: %{
        packets: Keyword.get(opts, :packets, 0),
        bytes: Keyword.get(opts, :bytes, 0)
      }
    }
  end

  defimpl Inspect do
    def inspect(
          %Linx.Netfilter.Expr{name: :immediate, data: %Linx.Netfilter.Verdict{} = v},
          _opts
        ) do
      target = if v.target, do: " #{format_target(v.target)}", else: ""
      "#Linx.Netfilter.Expr<immediate #{v.kind}#{target}>"
    end

    def inspect(%Linx.Netfilter.Expr{name: name, data: nil}, _opts),
      do: "#Linx.Netfilter.Expr<#{name}>"

    def inspect(%Linx.Netfilter.Expr{name: name}, _opts),
      do: "#Linx.Netfilter.Expr<#{name}>"

    defp format_target(t) when is_binary(t), do: inspect(t)
    defp format_target(t) when is_integer(t), do: Integer.to_string(t)
  end
end
