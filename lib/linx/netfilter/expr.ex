defmodule Linx.Netfilter.Expr do
  @moduledoc """
  A single netfilter expression — one node in a rule's expression
  list.

  Expressions are the kernel's per-rule building blocks: a payload
  extraction, a comparison, a lookup, a verdict load. Each carries
  a `:name` (the kernel's expression-type string, e.g. `"payload"`,
  `"cmp"`, `"immediate"`, `"lookup"`) and `:data` (kind-specific
  arguments — a keyword list, a map, a verdict, …).

  ## Constructors

    * `immediate/1` — load a verdict (or a constant) into the
      kernel's register 0.
    * `new/2` — generic constructor for arbitrary `(name, data)`
      pairs. Useful for callers building expressions Linx doesn't
      yet have a dedicated helper for.

  There are also kind-specific helpers (`cmp/3`, `payload/3`,
  `meta/2`, `bitwise/3`, `ct/2`, `lookup/2`, `reject/2`,
  `counter/1`, NAT helpers). They are extra entry points over the
  same struct shape, not extra fields.

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

  Most callers want one of the kind-specific helpers (`immediate/1`,
  `cmp/3`, `payload/3`, etc.). Use `new/2` when you're constructing
  an expression Linx doesn't yet have a dedicated helper for.
  """
  @spec new(atom() | String.t(), term()) :: t()
  def new(name, data \\ nil) when is_atom(name) or is_binary(name),
    do: %__MODULE__{name: name, data: data}

  @doc """
  An `immediate` expression — load a verdict into register 0.

  The data is the verdict struct itself. Accepts a `%Verdict{}` or
  any input form `Verdict.new!/1` understands.

  This constructor also accepts a constant (a binary or integer)
  for loading a value into a register prior to a `cmp` — the kernel
  uses the same expression for both forms.

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

  Also recognises wrapped immediate-verdict in the
  `%{dreg: 0, value: %Verdict{}}` shape that the codec uses.
  """
  @spec verdict?(t()) :: boolean()
  def verdict?(%__MODULE__{name: :immediate, data: %Verdict{}}), do: true

  def verdict?(%__MODULE__{name: :immediate, data: %{dreg: 0, value: %Verdict{}}}), do: true

  def verdict?(%__MODULE__{}), do: false

  # ===========================================================
  # Expression constructors (cmp / payload / meta / bitwise /
  # ct / lookup / reject / counter)
  # ===========================================================

  @doc """
  Comparison expression. Compares the value in `sreg` against
  `value` using `op`.

  `op` is one of `:eq`, `:neq`, `:lt`, `:lte`, `:gt`, `:gte`.
  `value` is a raw binary of the right length (1/2/4/16 bytes
  depending on what was loaded into `sreg`).

  Most callers don't construct `cmp/3` directly — the high-level
  `~NFT` sigil and pipeline helpers compose `payload + cmp`
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
  defp payload_alias(:ip6_nexthdr), do: {:network, 6, 1}
  defp payload_alias(:ip6_hoplimit), do: {:network, 7, 1}
  defp payload_alias(:tcp_sport), do: {:transport, 0, 2}
  defp payload_alias(:tcp_dport), do: {:transport, 2, 2}
  defp payload_alias(:tcp_flags), do: {:transport, 13, 1}
  defp payload_alias(:udp_sport), do: {:transport, 0, 2}
  defp payload_alias(:udp_dport), do: {:transport, 2, 2}
  defp payload_alias(:icmp_type), do: {:transport, 0, 1}
  defp payload_alias(:icmp_code), do: {:transport, 1, 1}
  # ICMPv6 type/code live at the same offsets in the transport
  # header (the headers are structurally identical at byte 0/1).
  defp payload_alias(:icmpv6_type), do: {:transport, 0, 1}
  defp payload_alias(:icmpv6_code), do: {:transport, 1, 1}
  defp payload_alias(_), do: :unknown

  @doc """
  Metadata-load expression. Reads `key` from the packet's metadata
  into `dreg`.

  Keys: `:len`, `:protocol`, `:mark`, `:iif`, `:oif`, `:iifname`,
  `:oifname`, `:nfproto`, `:l4proto`, etc. (see
  `Linx.Netfilter.Wire.meta_key_int/1` for the full list).
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

  CT-state matching uses the bitmask integers — wrap the state
  atom(s) with
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
  Anonymous-set lookup — `tcp dport { 22, 80, 443 } accept`.

  Returns a sentinel `%Expr{name: :__anon_set}` that the encoder
  expands at `to_batch/2` time into an auto-generated
  `NFT_SET_F_ANONYMOUS | NFT_SET_F_CONSTANT` set plus a regular
  `lookup` expression referencing it. The anonymous-set lifecycle
  is tied to the rule — it lives and dies with it.

  `values` is the same shape as a `Linx.Netfilter.Set`'s elements
  list. `key_type` is the same set of atoms `Linx.Netfilter.Set.new!/2` accepts.

      Rule.build([
        Expr.payload(:tcp_dport),
        Expr.set_literal([22, 80, 443], :inet_service),
        Verdict.accept()
      ])

  Options:

    * `:flags` — passed to the auto-generated set (`:interval`,
      `:constant`, etc.). `:anonymous` is always added; `:constant`
      is added by default (anonymous sets are constant unless
      explicitly otherwise).
  """
  @spec set_literal([term()], atom() | {:concat, [atom()]}, keyword()) :: t()
  def set_literal(values, key_type, opts \\ [])
      when is_list(values) and (is_atom(key_type) or is_tuple(key_type)) and is_list(opts) do
    %__MODULE__{
      name: :__anon_set,
      data: %{
        values: values,
        key_type: key_type,
        flags: Keyword.get(opts, :flags, [:constant]),
        sreg: Keyword.get(opts, :sreg, @reg_value)
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

  @doc """
  Limit expression — token-bucket rate limiting (`nft_limit`).
  The rule matches while the rate is *under* the limit; with
  `over: true` the sense inverts (matches once the rate is
  exceeded — the usual shape for `limit rate over N/second drop`).

  Options:

    * `:rate` — units per `:per` window (required, pos integer).
    * `:per` — window in **seconds**: 1 (second), 60 (minute),
      3600 (hour), 86_400 (day), 604_800 (week). Default `1`.
    * `:burst` — token-bucket depth. Defaults to `5` for packet
      limits (nft's own default) and `0` for byte limits.
    * `:type` — `:packets` (default) or `:bytes`.
    * `:over` — invert the match sense (default `false`).

      Expr.limit(rate: 5, per: 60)                 # limit rate 5/minute
      Expr.limit(rate: 10, over: true)             # limit rate over 10/second
  """
  @spec limit(keyword()) :: t()
  def limit(opts) when is_list(opts) do
    type = Keyword.get(opts, :type, :packets)

    unless type in [:packets, :bytes] do
      raise ArgumentError, "limit :type must be :packets or :bytes, got: #{inspect(type)}"
    end

    rate = Keyword.fetch!(opts, :rate)

    unless is_integer(rate) and rate > 0 do
      raise ArgumentError, "limit :rate must be a positive integer, got: #{inspect(rate)}"
    end

    default_burst = if type == :packets, do: 5, else: 0

    %__MODULE__{
      name: :limit,
      data: %{
        rate: rate,
        per: Keyword.get(opts, :per, 1),
        burst: Keyword.get(opts, :burst, default_burst),
        type: type,
        over: Keyword.get(opts, :over, false)
      }
    }
  end

  @doc """
  Quota expression (`nft_quota`) — an inline per-rule byte quota.
  With `over: false` (the default, nft's `until`) the rule matches
  while consumption is under `:bytes`; with `over: true` it starts
  matching once the quota is exceeded.

  Options:

    * `:bytes` — the quota, in bytes (required).
    * `:over` — invert the match sense (default `false`).
    * `:used` — initial consumed bytes (default `0`), useful when
      restoring state.

  For a quota shared across rules, declare a
  `Linx.Netfilter.Object` of kind `:quota` and reference it with
  `objref/2` instead.
  """
  @spec quota(keyword()) :: t()
  def quota(opts) when is_list(opts) do
    bytes = Keyword.fetch!(opts, :bytes)

    unless is_integer(bytes) and bytes > 0 do
      raise ArgumentError, "quota :bytes must be a positive integer, got: #{inspect(bytes)}"
    end

    %__MODULE__{
      name: :quota,
      data: %{
        bytes: bytes,
        over: Keyword.get(opts, :over, false),
        used: Keyword.get(opts, :used, 0)
      }
    }
  end

  @doc """
  Dynamic-set update expression (`nft_dynset`) — adds, updates, or
  deletes an element in a `dynamic`-flagged set at packet-match
  time, keyed by whatever a preceding load expression put in
  `:sreg_key`. This is the `add @ratelimit { ip saddr … }` /
  fail2ban building block.

  Options:

    * `:op` — `:add` (default), `:update`, or `:delete`.
    * `:sreg_key` — register holding the element key (default 1).
    * `:timeout` — per-element timeout in **milliseconds**
      (requires the set to carry the `:timeout` flag).
    * `:exprs` — list of stateful `%Expr{}`s attached to each
      element (e.g. `Expr.limit/1`, `Expr.counter/1`). When such
      an expression stops matching (a limit trips), the rule stops
      matching — the standard rate-limit-per-key shape.

      Expr.dynset("ratelimit", op: :update,
                  exprs: [Expr.limit(rate: 6, per: 60)])
  """
  @spec dynset(String.t(), keyword()) :: t()
  def dynset(set_name, opts \\ []) when is_binary(set_name) and is_list(opts) do
    op = Keyword.get(opts, :op, :add)

    unless op in [:add, :update, :delete] do
      raise ArgumentError, "dynset :op must be :add, :update, or :delete, got: #{inspect(op)}"
    end

    %__MODULE__{
      name: :dynset,
      data: %{
        set: set_name,
        op: op,
        sreg_key: Keyword.get(opts, :sreg_key, 1),
        timeout: Keyword.get(opts, :timeout),
        exprs: Keyword.get(opts, :exprs, [])
      }
    }
  end

  @doc """
  Named-object reference expression (`nft_objref`) — attaches a
  table-level stateful object (declared via
  `Linx.Netfilter.Object`) to this rule: `counter name "hits"`,
  `quota name "monthly"`, etc. All rules referencing the same
  object share its state.

      Expr.objref("http_hits", :counter)
  """
  @spec objref(String.t(), Linx.Netfilter.Object.kind()) :: t()
  def objref(name, kind) when is_binary(name) and is_atom(kind) do
    %__MODULE__{name: :objref, data: %{name: name, kind: kind}}
  end

  # ===========================================================
  # NAT family (nat / masquerade / redirect)
  # ===========================================================

  @doc """
  Low-level NAT expression. Most callers want `dnat_to/2` or
  `snat_to/2` — those construct the accompanying immediate-load
  expressions automatically. Use `nat/2` directly when you need
  fine control over register choices, ranges, or flags.

  Required:

    * `:type` — `:dnat` or `:snat`.
    * `:family` — `:ip` | `:ip6`. Required even in an `:inet`
      table; the NAT expression needs to know the address size.

  Optional:

    * `:reg_addr_min` — register holding the min (or only) target
      address. Defaults to `nil` (no address remap — only
      meaningful for SNAT in some configs).
    * `:reg_addr_max` — register holding the max address of a
      range. `nil` for single-address NAT.
    * `:reg_proto_min` / `:reg_proto_max` — port range registers.
    * `:flags` — `[:random, :fully_random, :persistent, :netmap]`.
      The encoder automatically sets `:map_ips` when address regs
      are present and `:proto_specified` when port regs are
      present.
  """
  @spec nat(atom(), keyword()) :: t()
  def nat(type, opts \\ []) when type in [:dnat, :snat] and is_list(opts) do
    %__MODULE__{
      name: :nat,
      data: %{
        type: type,
        family: Keyword.get(opts, :family, :ip),
        reg_addr_min: Keyword.get(opts, :reg_addr_min),
        reg_addr_max: Keyword.get(opts, :reg_addr_max),
        reg_proto_min: Keyword.get(opts, :reg_proto_min),
        reg_proto_max: Keyword.get(opts, :reg_proto_max),
        flags: Keyword.get(opts, :flags, [])
      }
    }
  end

  @doc """
  Builds a DNAT statement — destination NAT to `addr` (and
  optionally `port`).

  Returns a **list** of `%Expr{}`: an immediate-load of the
  address into a register, an optional immediate-load of the port,
  then the nat expression itself. `Rule.build/2` flattens nested
  lists, so this composes naturally:

      Rule.build([
        Expr.payload(:tcp_dport),
        Expr.cmp(:eq, <<8080::big-16>>),
        Expr.dnat_to({10, 0, 0, 5}, 80)
      ])

  `addr` may be:

    * an IPv4 4-tuple — `{10, 0, 0, 5}`.
    * an IPv6 8-tuple — `{0xfc00, 0, 0, 0, 0, 0, 0, 1}`.
    * a raw binary — 4 bytes for IPv4, 16 for IPv6.
    * a `%Linx.IP{}` struct.
    * a string — `"10.0.0.5"` / `"fc00::1"` (parsed via `Linx.IP.parse/1`).

  `port` is a non-negative integer (encoded big-endian 16-bit), or
  `nil` for address-only NAT.

  Options:

    * `:flags` — passed through to `nat/2` (`:random`, `:persistent`, …).
    * `:reg_addr` / `:reg_port` — override the default register
      choice (`1` for addr, `2` for port).
  """
  @spec dnat_to(addr_input(), pos_integer() | nil, keyword()) :: [t()]
  def dnat_to(addr, port \\ nil, opts \\ []), do: nat_helper(:dnat, addr, port, opts)

  @doc """
  Builds an SNAT statement — source NAT to `addr` (and optionally
  `port`). Same shape as `dnat_to/3`.

  SNAT is meaningful in postrouting chains; the kernel rejects
  SNAT in prerouting / output.
  """
  @spec snat_to(addr_input(), pos_integer() | nil, keyword()) :: [t()]
  def snat_to(addr, port \\ nil, opts \\ []), do: nat_helper(:snat, addr, port, opts)

  @typedoc """
  Address-input forms accepted by `dnat_to/3` / `snat_to/3`.
  """
  @type addr_input ::
          {0..255, 0..255, 0..255, 0..255}
          | {0..0xFFFF, 0..0xFFFF, 0..0xFFFF, 0..0xFFFF, 0..0xFFFF, 0..0xFFFF, 0..0xFFFF,
             0..0xFFFF}
          | <<_::32>>
          | <<_::128>>
          | String.t()
          | Linx.IP.t()

  defp nat_helper(type, addr, port, opts) do
    {addr_bin, family} = normalize_addr(addr)
    reg_addr = Keyword.get(opts, :reg_addr, 1)
    reg_port = Keyword.get(opts, :reg_port, 2)
    flags = Keyword.get(opts, :flags, [])

    immediates =
      [immediate_load(addr_bin, reg_addr)] ++
        if port, do: [immediate_load(<<port::big-16>>, reg_port)], else: []

    nat_opts =
      [
        family: family,
        reg_addr_min: reg_addr,
        flags: flags
      ] ++ if port, do: [reg_proto_min: reg_port], else: []

    immediates ++ [nat(type, nat_opts)]
  end

  defp immediate_load(bin, dreg) when is_binary(bin) do
    %__MODULE__{name: :immediate, data: %{dreg: dreg, value: bin}}
  end

  defp normalize_addr({a, b, c, d})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: {<<a, b, c, d>>, :ip}

  defp normalize_addr({a, b, c, d, e, f, g, h})
       when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and d in 0..0xFFFF and
              e in 0..0xFFFF and f in 0..0xFFFF and g in 0..0xFFFF and h in 0..0xFFFF,
       do: {<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>, :ip6}

  defp normalize_addr(<<_::32>> = bin), do: {bin, :ip}
  defp normalize_addr(<<_::128>> = bin), do: {bin, :ip6}

  defp normalize_addr(%Linx.IP{family: :inet, bytes: bin}), do: {bin, :ip}
  defp normalize_addr(%Linx.IP{family: :inet6, bytes: bin}), do: {bin, :ip6}

  defp normalize_addr(string) when is_binary(string) do
    case Linx.IP.parse(string) do
      {:ok, ip} -> normalize_addr(ip)
      {:error, _} -> raise ArgumentError, "invalid NAT address: #{inspect(string)}"
    end
  end

  defp normalize_addr(other),
    do: raise(ArgumentError, "invalid NAT address: #{inspect(other)}")

  @doc """
  Masquerade expression — SNAT to the outgoing interface's primary
  address. The kernel resolves the address at packet-traversal
  time, which makes this the right choice for setups where the
  outbound IP isn't known at rule-write time (DHCP-assigned WAN,
  PPP links).

  Only valid in postrouting chains.

  Options:

    * `:flags` — `[:random, :fully_random, :persistent]`.
    * `:port_min` / `:port_max` — masquerade with a specific
      port-range remap (rare; kernel default reuses the original
      source port).
  """
  @spec masquerade(keyword()) :: t() | [t()]
  def masquerade(opts \\ []) when is_list(opts) do
    flags = Keyword.get(opts, :flags, [])
    port_min = Keyword.get(opts, :port_min)
    port_max = Keyword.get(opts, :port_max)
    reg_proto = Keyword.get(opts, :reg_proto, 1)

    cond do
      is_nil(port_min) ->
        %__MODULE__{
          name: :masq,
          data: %{flags: flags, reg_proto_min: nil, reg_proto_max: nil}
        }

      is_nil(port_max) or port_max == port_min ->
        [
          immediate_load(<<port_min::big-16>>, reg_proto),
          %__MODULE__{
            name: :masq,
            data: %{flags: flags, reg_proto_min: reg_proto, reg_proto_max: nil}
          }
        ]

      true ->
        [
          immediate_load(<<port_min::big-16>>, reg_proto),
          immediate_load(<<port_max::big-16>>, reg_proto + 1),
          %__MODULE__{
            name: :masq,
            data: %{flags: flags, reg_proto_min: reg_proto, reg_proto_max: reg_proto + 1}
          }
        ]
    end
  end

  @doc """
  Log expression — emits a per-packet event to the NFLOG
  subsystem (`NFNL_SUBSYS_ULOG`) on the named group. Combine with
  `Linx.Netfilter.log_listen/2` for in-BEAM packet observability.

  Options (all optional):

    * `:group` — NFLOG group (1..65535). Defaults to `5000` (the
      Linx convention for "I don't care which group").
    * `:prefix` — string label that shows up in `Event.prefix`;
      useful for tagging rules ("blocked", "audit", …). Max 127
      bytes.
    * `:snaplen` — bytes of packet payload to copy (overrides the
      consumer's copy_mode/snaplen if set on the rule). 0 = no
      packet data.
    * `:qthreshold` — kernel-side queue threshold; packets are
      batched into multipart netlink messages up to this count.
    * `:flags` — `:tcp_seq` / `:tcp_opt` / `:ip_opt` / `:uid` /
      `:macdecode` (NF_LOG_*). Most callers want them set at the
      Log listener side via `:flags` there instead.
  """
  @spec log(keyword()) :: t()
  def log(opts \\ []) when is_list(opts) do
    %__MODULE__{
      name: :log,
      data: %{
        group: Keyword.get(opts, :group, 5000),
        prefix: Keyword.get(opts, :prefix),
        snaplen: Keyword.get(opts, :snaplen),
        qthreshold: Keyword.get(opts, :qthreshold),
        flags: Keyword.get(opts, :flags, [])
      }
    }
  end

  @doc """
  Redirect expression — DNAT to the local machine, optionally
  changing the destination port. The kernel uses the input
  interface's address as the new destination, which makes this
  the right choice for transparent proxies / port-shifting on a
  single host.

  Only valid in prerouting / output chains.

  Options:

    * `:port` — redirect to this port (16-bit). Omit to keep the
      original port.
    * `:flags` — `[:random, :fully_random]`.
  """
  @spec redirect(keyword()) :: t() | [t()]
  def redirect(opts \\ []) when is_list(opts) do
    port = Keyword.get(opts, :port)
    flags = Keyword.get(opts, :flags, [])
    reg_proto = Keyword.get(opts, :reg_proto, 1)

    case port do
      nil ->
        %__MODULE__{
          name: :redir,
          data: %{flags: flags, reg_proto_min: nil, reg_proto_max: nil}
        }

      p when is_integer(p) and p in 0..0xFFFF ->
        [
          immediate_load(<<p::big-16>>, reg_proto),
          %__MODULE__{
            name: :redir,
            data: %{flags: flags, reg_proto_min: reg_proto, reg_proto_max: nil}
          }
        ]
    end
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
