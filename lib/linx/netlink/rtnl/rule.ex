defmodule Linx.Netlink.Rtnl.Rule do
  @moduledoc """
  rtnetlink policy-routing rules — the FIB rules that decide which routing
  table to consult for a given packet, based on source address, destination,
  firewall mark and so on.

  `list/1` reads rules; `add/2` and `delete/2` install and remove them. Rules
  are specified as a keyword list of selectors plus the target table:

      Rtnl.Rule.add(socket, from: "10.0.0.0/24", table: 100)
      Rtnl.Rule.add(socket, fwmark: 0x1,         table: 100, priority: 200)

  `:table` is required; the family is inferred from the address selectors
  (`:from` / `:to`) — or defaults to IPv4 when only non-address selectors
  (`:fwmark`) are used.

  Address-typed fields (`:src`, `:dst`) on a decoded `%Rule{}` are `Linx.IP`
  structs.

  ## The two table representations

  `fib_rule_hdr.table` is a `u8`, so tables above 255 are conveyed via the
  separate `FRA_TABLE` attribute (mapped to `:table_ext`); the kernel sets
  the header byte to `RT_TABLE_UNSPEC` in that case. `target_table/1` returns
  the effective table — taking `:table_ext` when present, falling back to
  `:table`.

  ## Example

      {:ok, sock} = Rtnl.open()

      :ok = Rule.add(sock, from: "10.0.0.0/24", table: 100)
      :ok = Rule.add(sock, fwmark: 0x1, table: 100, priority: 200)

      {:ok, rules} = Rule.list(sock)
      # => [..., #Linx.Netlink.Rtnl.Rule<priority=200 fwmark=0x1 table=100>,
      #     #Linx.Netlink.Rtnl.Rule<from=10.0.0.0/24 table=100>]

      :ok = Rule.delete(sock, from: "10.0.0.0/24", table: 100)

  The wire format — `struct fib_rule_hdr` and the `FRA_*` attributes
  (`include/uapi/linux/fib_rules.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.IP
  alias Linx.Netlink.{Request, Socket}

  # rtnetlink rule message types.
  @rtm_newrule 32
  @rtm_delrule 33
  @rtm_getrule 34

  @af_inet 2
  @af_inet6 10

  # FR_ACT_TO_TBL — the standard rule action: look the packet up in `table`.
  @fr_act_to_tbl 1

  codec do
    # struct fib_rule_hdr — include/uapi/linux/fib_rules.h.
    header do
      field(:family, :u8)
      field(:dst_len, :u8)
      field(:src_len, :u8)
      field(:tos, :u8)
      field(:table, :u8)
      field(:res1, :u8)
      field(:res2, :u8)
      field(:action, :u8)
      field(:flags, :u32)
    end

    # FRA_* — include/uapi/linux/fib_rules.h.
    attr(1, :dst, Linx.IP)
    attr(2, :src, Linx.IP)
    attr(6, :priority, :u32)
    attr(10, :fwmark, :u32)
    attr(15, :table_ext, :u32)
  end

  @doc "Lists every policy-routing rule in the socket's network namespace."
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getrule, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Adds a policy-routing rule.

  Selectors (all optional unless noted):

    * `:from`     — match source `"ip/prefix"` (CIDR string).
    * `:to`       — match destination `"ip/prefix"` (CIDR string).
    * `:fwmark`   — match firewall mark (integer).
    * `:table`    — routing table to consult (1..2^32-1). **Required.**
    * `:priority` — rule priority (smaller wins; integer).
  """
  @spec add(Socket.t(), keyword) :: :ok | {:error, term}
  def add(%Socket{} = socket, opts) when is_list(opts) do
    write(socket, opts, @rtm_newrule, nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack())
  end

  @doc "Deletes the policy-routing rule matching `opts` (same shape as `add/2`)."
  @spec delete(Socket.t(), keyword) :: :ok | {:error, term}
  def delete(%Socket{} = socket, opts) when is_list(opts) do
    write(socket, opts, @rtm_delrule, nlm_f_ack())
  end

  @doc """
  Returns the routing-table number this rule points to.

  Handles both the in-header byte form and the `FRA_TABLE` extension used for
  tables above 255.
  """
  @spec target_table(t()) :: non_neg_integer
  def target_table(%__MODULE__{table_ext: t}) when is_integer(t) and t > 0, do: t
  def target_table(%__MODULE__{table: t}), do: t

  defp write(socket, opts, rtm, flags) do
    with {:ok, message} <- build(opts) do
      case Request.talk(socket, rtm, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp build(opts) do
    table = Keyword.get(opts, :table)

    with :ok <- require_table(table),
         {:ok, {src_family, src, src_len}} <- parse_cidr(Keyword.get(opts, :from)),
         {:ok, {dst_family, dst, dst_len}} <- parse_cidr(Keyword.get(opts, :to)),
         {:ok, family} <- pick_family(src_family, dst_family) do
      message = %__MODULE__{
        family: family_int(family),
        src_len: src_len,
        dst_len: dst_len,
        action: @fr_act_to_tbl,
        table: if(table <= 255, do: table, else: 0),
        table_ext: if(table > 255, do: table, else: nil),
        src: src,
        dst: dst,
        priority: Keyword.get(opts, :priority),
        fwmark: Keyword.get(opts, :fwmark)
      }

      {:ok, message}
    end
  end

  defp require_table(nil), do: {:error, {:missing_option, :table}}
  defp require_table(n) when is_integer(n) and n in 1..0xFFFFFFFF, do: :ok
  defp require_table(n), do: {:error, {:bad_option, :table, n}}

  defp parse_cidr(nil), do: {:ok, {nil, nil, 0}}

  defp parse_cidr(cidr) when is_binary(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_str] ->
        with {prefix, ""} <- Integer.parse(prefix_str),
             {:ok, %IP{family: family} = ip} <- IP.parse(ip_str) do
          {:ok, {family, ip, prefix}}
        else
          _ -> {:error, {:bad_cidr, cidr}}
        end

      [ip_str] ->
        with {:ok, %IP{family: family} = ip} <- IP.parse(ip_str) do
          # No prefix given — treat as the family's full-width prefix.
          prefix = if family == :inet, do: 32, else: 128
          {:ok, {family, ip, prefix}}
        end

      _ ->
        {:error, {:bad_cidr, cidr}}
    end
  end

  defp pick_family(nil, nil), do: {:ok, :inet}
  defp pick_family(f, nil), do: {:ok, f}
  defp pick_family(nil, f), do: {:ok, f}
  defp pick_family(f, f), do: {:ok, f}
  defp pick_family(_, _), do: {:error, :family_mismatch}

  defp family_int(:inet), do: @af_inet
  defp family_int(:inet6), do: @af_inet6

  defimpl Inspect do
    def inspect(rule, _opts) do
      parts =
        [
          rule.priority && "priority=#{rule.priority}",
          rule.src && "from=#{Linx.IP.to_string(rule.src)}/#{rule.src_len}",
          rule.dst && "to=#{Linx.IP.to_string(rule.dst)}/#{rule.dst_len}",
          rule.fwmark && "fwmark=0x#{Integer.to_string(rule.fwmark, 16)}",
          "table=#{Linx.Netlink.Rtnl.Rule.target_table(rule)}"
        ]
        |> Enum.reject(&is_nil/1)
        |> Enum.join(" ")

      "#Linx.Netlink.Rtnl.Rule<#{parts}>"
    end
  end
end
