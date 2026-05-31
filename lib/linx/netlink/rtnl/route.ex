defmodule Linx.Netlink.Rtnl.Route do
  @moduledoc """
  rtnetlink routes — the `RTM_*ROUTE` messages.

  `list/1` reads routes; `add/5`, `add_default/3`, `replace/5`, `delete/5`
  and `delete_default/3` install, update, and remove them. IPv4 and IPv6 are
  both supported — the address family is detected from the destination and
  gateway, which must agree.

  Address-typed fields (`:dst`, `:gateway`) on a decoded `%Route{}` are
  `Linx.IP` structs; verbs accept strings or `Linx.IP`s.

  ## Options

  `add/5`, `replace/5`, `delete/5` (and their `*_default` forms) take an
  options keyword:

    * `:table` — routing table (1..2^32-1). Default `254` (the main table).
    * `:protocol` — the route's origin tag (`rtm_protocol`). An integer
      0..255, or one of `:kernel` (2), `:boot` (3, the default), `:static`
      (4), `:ra` (9), `:dhcp` (16). This is the ownership marker a reconciler
      uses to manage only its own routes (see the reconcile design notes).
    * `:metric` — the route metric / `RTA_PRIORITY` (a `u32`); omitted when
      not given, which the kernel treats as metric 0.

  ## add vs replace

    * `add/5` uses `NLM_F_CREATE | NLM_F_EXCL` — it errors (`:eexist`) if a
      matching route already exists.
    * `replace/5` uses `NLM_F_CREATE | NLM_F_REPLACE` — create-or-replace. It
      installs the route if absent and overwrites it (e.g. a changed gateway)
      if present. This is the idempotent upsert a reconciler applies, and the
      only way to change a route's mutable attributes in place.

  ## The two table representations

  `struct rtmsg`'s `table` is a `u8`, so tables above 255 are conveyed via the
  separate `RTA_TABLE` attribute (mapped to `:table_ext`); the kernel sets the
  header byte to `RT_TABLE_UNSPEC` in that case. `target_table/1` returns the
  effective table — taking `:table_ext` when present, falling back to `:table`.

  ## Example

      {:ok, sock} = Rtnl.open()

      :ok = Route.add_default(sock, "10.0.0.1")
      :ok = Route.add(sock, "192.168.9.0", 24, "10.0.0.254")

      # Change the gateway in place (idempotent upsert):
      :ok = Route.replace(sock, "192.168.9.0", 24, "10.0.0.253")

      # A route in a custom table, tagged with a dedicated protocol:
      :ok = Route.add(sock, "10.50.0.0", 24, "10.0.0.1", table: 100, protocol: 4)

      {:ok, routes} = Route.list(sock)
      {:ok, route} = Route.get(sock, "192.168.9.7")

      :ok = Route.delete_default(sock, "10.0.0.1")

  The wire format — `struct rtmsg` and the `RTA_*` attributes
  (`include/uapi/linux/rtnetlink.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.IP
  alias Linx.Netlink.{Message, Request, Socket}

  # rtnetlink route message types.
  @rtm_newroute 24
  @rtm_delroute 25
  @rtm_getroute 26

  # rtmsg field values — include/uapi/linux/rtnetlink.h.
  @af_inet 2
  @af_inet6 10
  @rt_table_main 254
  @rtprot_boot 3
  @rt_scope_universe 0
  # RT_SCOPE_NOWHERE — used on delete to match a route in any scope.
  @rt_scope_nowhere 255
  @rtn_unicast 1

  # Named rtm_protocol values — include/uapi/linux/rtnetlink.h. A reconciler
  # claims ownership by tagging its routes with a dedicated protocol number
  # and reaping only routes carrying that tag.
  @rtprot %{
    redirect: 1,
    kernel: 2,
    boot: 3,
    static: 4,
    ra: 9,
    dhcp: 16
  }

  codec do
    # struct rtmsg — include/uapi/linux/rtnetlink.h.
    header do
      field(:family, :u8)
      field(:dst_len, :u8)
      field(:src_len, :u8)
      field(:tos, :u8)
      field(:table, :u8)
      field(:protocol, :u8)
      field(:scope, :u8)
      field(:type, :u8)
      field(:flags, :u32)
    end

    # RTA_* attributes — include/uapi/linux/rtnetlink.h.
    attr(1, :dst, Linx.IP)
    attr(4, :oif, :u32)
    attr(5, :gateway, Linx.IP)
    attr(6, :priority, :u32)
    attr(15, :table_ext, :u32)
  end

  @typedoc """
  Options for `add/5`, `replace/5`, and `delete/5`. See the moduledoc.
  """
  @type opts :: [
          table: pos_integer(),
          protocol: 0..255 | atom(),
          metric: non_neg_integer()
        ]

  @doc "Lists every route in the socket's network namespace."
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getroute, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Looks up the route the kernel would use to reach `destination`.

  The kernel-side `ip route get` equivalent: an `RTM_GETROUTE` *without*
  `NLM_F_DUMP`, with `RTA_DST` set, so the kernel resolves the lookup and
  returns the matching `%Route{}`. For an unroutable destination the
  kernel returns `ENETUNREACH` — surfaced as
  `{:error, %Linx.Netlink.Error{}}`.

  `destination` is a string (`"10.0.0.1"`, `"fc00::1"`) or an `Linx.IP`.
  """
  @spec get(Socket.t(), binary | IP.t()) :: {:ok, t()} | {:error, term}
  def get(%Socket{} = socket, destination) do
    with {:ok, %IP{family: family} = dst} <- coerce_ip(destination) do
      message = %__MODULE__{family: family_int(family), dst: dst}

      case Request.talk(socket, @rtm_getroute, 0, encode(message)) do
        {:ok, [%Message{payload: body} | _]} -> {:ok, decode(body)}
        {:ok, []} -> {:error, :no_reply}
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  Adds a route to `destination`/`prefix` via `gateway`.

  Strict create: errors with `:eexist` if a matching route already exists.
  `destination` and `gateway` are each a string or an `Linx.IP`, and must
  share an address family. See the moduledoc for `opts`.
  """
  @spec add(Socket.t(), binary | IP.t(), non_neg_integer, binary | IP.t(), opts) ::
          :ok | {:error, term}
  def add(%Socket{} = socket, destination, prefix, gateway, opts \\ []) when is_integer(prefix) do
    write(
      socket,
      destination,
      prefix,
      gateway,
      @rtm_newroute,
      @rt_scope_universe,
      nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack(),
      opts
    )
  end

  @doc """
  Create-or-replace: installs the route if absent, overwrites it in place
  (e.g. a changed gateway) if present.

  Idempotent — the reconciler's apply verb. Same arguments as `add/5`.
  """
  @spec replace(Socket.t(), binary | IP.t(), non_neg_integer, binary | IP.t(), opts) ::
          :ok | {:error, term}
  def replace(%Socket{} = socket, destination, prefix, gateway, opts \\ [])
      when is_integer(prefix) do
    write(
      socket,
      destination,
      prefix,
      gateway,
      @rtm_newroute,
      @rt_scope_universe,
      nlm_f_create() ||| nlm_f_replace() ||| nlm_f_ack(),
      opts
    )
  end

  @doc """
  Adds the default route (`0.0.0.0/0` for IPv4, `::/0` for IPv6) via
  `gateway`.
  """
  @spec add_default(Socket.t(), binary | IP.t(), opts) :: :ok | {:error, term}
  def add_default(socket, gateway, opts \\ []) do
    with {:ok, %IP{family: family} = gw_ip} <- coerce_ip(gateway) do
      add(socket, default_destination(family), 0, gw_ip, opts)
    end
  end

  @doc """
  Deletes the route to `destination`/`prefix` via `gateway`.

  On delete the kernel filters by an option only when it is set, so by default
  `:protocol` is left unspecified (`RTPROT_UNSPEC`) — the route is matched
  regardless of which protocol installed it. Pass `:protocol` (and `:table` /
  `:metric`) to narrow the match when several routes share a destination.
  """
  @spec delete(Socket.t(), binary | IP.t(), non_neg_integer, binary | IP.t(), opts) ::
          :ok | {:error, term}
  def delete(%Socket{} = socket, destination, prefix, gateway, opts \\ [])
      when is_integer(prefix) do
    write(
      socket,
      destination,
      prefix,
      gateway,
      @rtm_delroute,
      @rt_scope_nowhere,
      nlm_f_ack(),
      # RTPROT_UNSPEC (0) means "match any protocol" for RTM_DELROUTE.
      Keyword.put_new(opts, :protocol, 0)
    )
  end

  @doc "Deletes the default route via `gateway`."
  @spec delete_default(Socket.t(), binary | IP.t(), opts) :: :ok | {:error, term}
  def delete_default(socket, gateway, opts \\ []) do
    with {:ok, %IP{family: family} = gw_ip} <- coerce_ip(gateway) do
      delete(socket, default_destination(family), 0, gw_ip, opts)
    end
  end

  @doc """
  Returns the effective routing table for a route, handling both the in-header
  byte form and the `RTA_TABLE` extension used for tables above 255.
  """
  @spec target_table(t()) :: non_neg_integer
  def target_table(%__MODULE__{table_ext: t}) when is_integer(t) and t > 0, do: t
  def target_table(%__MODULE__{table: t}), do: t

  @doc false
  # Builds the %Route{} message for a write. Pure — no socket, no I/O — so the
  # option resolution and table-splitting are unit-testable, and Phase-3
  # reconcile can construct messages without a verb. `scope` is the rtm scope
  # byte (universe for add/replace, nowhere for delete-match-any).
  @spec build(binary | IP.t(), non_neg_integer, binary | IP.t(), 0..255, opts) ::
          {:ok, t()} | {:error, term}
  def build(destination, prefix, gateway, scope, opts \\ []) do
    with {:ok, %IP{family: family} = dst} <- coerce_ip(destination),
         {:ok, %IP{family: gw_family} = gw} <- coerce_ip(gateway),
         :ok <- check_families(family, gw_family),
         :ok <- check_prefix(family, prefix),
         {:ok, table} <- resolve_table(opts),
         {:ok, protocol} <- resolve_protocol(opts),
         {:ok, metric} <- resolve_metric(opts) do
      message = %__MODULE__{
        family: family_int(family),
        dst_len: prefix,
        table: if(table <= 255, do: table, else: 0),
        table_ext: if(table > 255, do: table, else: nil),
        protocol: protocol,
        scope: scope,
        type: @rtn_unicast,
        dst: dst,
        gateway: gw,
        priority: metric
      }

      {:ok, message}
    end
  end

  defp write(socket, destination, prefix, gateway, rtm, scope, flags, opts) do
    with {:ok, message} <- build(destination, prefix, gateway, scope, opts) do
      case Request.talk(socket, rtm, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp coerce_ip(%IP{} = ip), do: {:ok, ip}
  defp coerce_ip(string) when is_binary(string), do: IP.parse(string)

  defp check_families(family, family), do: :ok
  defp check_families(_, _), do: {:error, :family_mismatch}

  defp check_prefix(:inet, p) when p in 0..32, do: :ok
  defp check_prefix(:inet6, p) when p in 0..128, do: :ok
  defp check_prefix(_, p), do: {:error, {:bad_prefix, p}}

  defp resolve_table(opts) do
    case Keyword.get(opts, :table, @rt_table_main) do
      n when is_integer(n) and n in 1..0xFFFFFFFF -> {:ok, n}
      other -> {:error, {:bad_option, :table, other}}
    end
  end

  defp resolve_protocol(opts) do
    case Keyword.get(opts, :protocol, @rtprot_boot) do
      n when is_integer(n) and n in 0..255 ->
        {:ok, n}

      a when is_atom(a) ->
        case Map.fetch(@rtprot, a) do
          {:ok, n} -> {:ok, n}
          :error -> {:error, {:bad_option, :protocol, a}}
        end

      other ->
        {:error, {:bad_option, :protocol, other}}
    end
  end

  defp resolve_metric(opts) do
    case Keyword.get(opts, :metric) do
      nil -> {:ok, nil}
      n when is_integer(n) and n in 0..0xFFFFFFFF -> {:ok, n}
      other -> {:error, {:bad_option, :metric, other}}
    end
  end

  defp default_destination(:inet), do: "0.0.0.0"
  defp default_destination(:inet6), do: "::"

  defp family_int(:inet), do: @af_inet
  defp family_int(:inet6), do: @af_inet6

  defimpl Inspect do
    alias Linx.Netlink.Rtnl.Route

    def inspect(%Route{} = route, _opts) do
      dst_part =
        cond do
          is_nil(route.dst) and route.dst_len == 0 -> "default"
          route.dst -> "#{Linx.IP.to_string(route.dst)}/#{route.dst_len}"
          true -> "?"
        end

      table = Route.target_table(route)

      extras =
        [
          route.gateway && "via #{Linx.IP.to_string(route.gateway)}",
          route.oif && "oif=#{route.oif}",
          is_integer(table) and table != 254 and "table=#{table}",
          route.priority && "metric=#{route.priority}",
          is_integer(route.protocol) and route.protocol != 3 and "proto=#{route.protocol}"
        ]
        |> Enum.filter(&is_binary/1)

      body = Enum.join([dst_part | extras], " ")
      "#Linx.Netlink.Rtnl.Route<#{body}>"
    end
  end
end
