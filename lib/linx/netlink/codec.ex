defmodule Linx.Netlink.Codec do
  @moduledoc """
  A small DSL for defining netlink message codecs.

  Every netlink message body has the same shape — a fixed C-struct header
  followed by a stream of type-length-value attributes. A module that `use`s
  this one *declares* that shape in a `codec` block, and gets a struct plus an
  `encode/1` and a `decode/1` generated for it:

      defmodule MyMessage do
        use Linx.Netlink.Codec

        codec do
          header do
            field :family, :u8
            pad 1
            field :index, :s32
          end

          attr 1, :name, :string
          attr 2, :mtu, :u32
        end

        # hand-written verbs may follow — the struct is already defined
      end

  `encode/1` turns a `%MyMessage{}` into a message body; `decode/1` turns a
  body back into a struct. Header fields default to `0`; an attribute field is
  `nil` when absent, and a `nil` field is omitted on encode.

  The whole definition is one `codec` block so the struct is defined right
  there, before any hand-written functions below it can refer to it.

  This module is the reference codec backend: the generated `encode/1` and
  `decode/1` are thin wrappers over one shared engine driven by the declared
  schema. The schema is also exposed as data through the generated
  `__codec__/0` — the seam a future kernel-YAML-driven front end would target.

  ## Field and attribute types

  Scalars `:u8`, `:u16`, `:u32`, `:u64`, `:s8`, `:s16`, `:s32`; `:string` (a
  NUL-terminated string); `:binary` (raw bytes).

  ## The escape hatches

  An attribute's type may also be:

    * a **module** that exports `encode/1` and `decode/1`. Pointed at another
      `Linx.Netlink.Codec` module it covers a nested attribute set; pointed at
      a hand-written module it covers any value whose wire form a primitive
      cannot express.
    * a **dispatch table**:
      `{:dispatch, :other_field, %{"k1" => Mod1, "k2" => Mod2, …}}`. The
      sub-codec is chosen at encode and decode time from the *current* value
      of `:other_field` — a sibling attribute on the same struct. The
      dispatching field must be declared *before* the dispatched one, so its
      value is in hand by the time the latter is processed.

  Both let the DSL handle the regular case and step aside, to module-level
  code, for the rest.
  """

  alias Linx.Netlink.Attr

  @scalars [:u8, :u16, :u32, :u64, :s8, :s16, :s32]

  @doc false
  defmacro __using__(_opts) do
    quote do: import(Linx.Netlink.Codec, only: [codec: 1])
  end

  @doc """
  Declares a message codec: a `header` block of `field/2` and `pad/1` calls,
  and `attr/3` declarations. Generates the struct, `encode/1` and `decode/1`.

  A codec with no `header` block is a bare attribute set — the shape a nested
  attribute takes.
  """
  defmacro codec(do: block) do
    {header, attrs} = parse(declarations(block), __CALLER__)
    schema = Macro.escape(%{module: __CALLER__.module, header: header, attrs: attrs})

    quote do
      defstruct unquote(Macro.escape(struct_fields(header, attrs)))

      @type t :: %__MODULE__{}

      @doc false
      def __codec__, do: unquote(schema)

      @doc "Encodes a `t:t/0` into its netlink message body."
      @spec encode(t()) :: binary()
      def encode(%__MODULE__{} = message),
        do: Linx.Netlink.Codec.__encode__(__codec__(), message)

      @doc "Decodes a netlink message body into a `t:t/0`."
      @spec decode(binary()) :: t()
      def decode(body) when is_binary(body),
        do: Linx.Netlink.Codec.__decode__(__codec__(), body)
    end
  end

  # --- compile-time: parse the codec block ------------------------------------

  defp declarations({:__block__, _, list}), do: list
  defp declarations(single), do: [single]

  # Collect header fields (one `header` block) and attributes, in source order.
  defp parse(decls, env) do
    header =
      Enum.flat_map(decls, fn
        {:header, _, [[do: hblock]]} -> Enum.map(declarations(hblock), &header_item/1)
        _ -> []
      end)

    attrs =
      Enum.flat_map(decls, fn
        {:attr, _, [id, name, type]} -> [{id, name, type_to_atom(type, env)}]
        _ -> []
      end)

    {header, attrs}
  end

  defp header_item({:field, _, [name, type]}), do: {:field, name, type}
  defp header_item({:pad, _, [bytes]}), do: {:pad, bytes}

  # A primitive type is a plain atom; a module type arrives as an alias AST,
  # resolved here. A dispatch type is a 3-tuple `{:dispatch, on, table}` whose
  # table is a map literal with alias-AST values — resolved to module atoms.
  defp type_to_atom(type, _env) when is_atom(type), do: type

  defp type_to_atom({:__aliases__, _, _} = alias_ast, env),
    do: Macro.expand(alias_ast, env)

  defp type_to_atom({:{}, _, [:dispatch, on, {:%{}, _, pairs}]}, env) when is_atom(on) do
    table = Map.new(pairs, fn {key, mod_ast} -> {key, Macro.expand(mod_ast, env)} end)
    {:dispatch, on, table}
  end

  defp struct_fields(header, attrs) do
    Enum.map(for({:field, name, _} <- header, do: name), &{&1, 0}) ++
      Enum.map(for({_id, name, _} <- attrs, do: name), &{&1, nil})
  end

  # --- runtime: the codec engine, driven by a declared schema -----------------

  @doc false
  @spec __encode__(map, struct) :: binary
  def __encode__(codec, message) do
    header = encode_header(codec.header, message, [])
    IO.iodata_to_binary([header, Attr.encode(encode_attrs(codec.attrs, message))])
  end

  @doc false
  @spec __decode__(map, binary) :: struct
  def __decode__(codec, body) do
    {header_fields, rest} = decode_header(codec.header, body, [])
    attrs = Attr.decode(rest)

    # Walk attribute specs in declaration order so that a dispatched
    # attribute can see the already-decoded value of its on-field.
    attr_fields = decode_attr_fields(codec.attrs, attrs, [])

    struct(codec.module, header_fields ++ attr_fields)
  end

  defp decode_attr_fields([], _attrs, acc), do: Enum.reverse(acc)

  defp decode_attr_fields([{id, name, type} | rest], attrs, acc) do
    value =
      case List.keyfind(attrs, id, 0) do
        {^id, payload} -> decode_attr_value(type, payload, acc)
        nil -> nil
      end

    decode_attr_fields(rest, attrs, [{name, value} | acc])
  end

  defp encode_header([], _message, acc), do: Enum.reverse(acc)

  defp encode_header([{:pad, n} | rest], message, acc),
    do: encode_header(rest, message, [<<0::size(n * 8)>> | acc])

  defp encode_header([{:field, name, type} | rest], message, acc),
    do: encode_header(rest, message, [scalar(type, Map.fetch!(message, name)) | acc])

  defp decode_header([], rest, acc), do: {Enum.reverse(acc), rest}

  defp decode_header([{:pad, n} | rest], bin, acc) do
    <<_::binary-size(n), tail::binary>> = bin
    decode_header(rest, tail, acc)
  end

  defp decode_header([{:field, name, type} | rest], bin, acc) do
    {value, tail} = unscalar(type, bin)
    decode_header(rest, tail, [{name, value} | acc])
  end

  # A nil attribute field is absent from the wire; everything else is emitted.
  # A dispatched attribute also needs sibling-field access, so this carries
  # the whole message along.
  defp encode_attrs(specs, message) do
    for {id, name, type} <- specs,
        value = Map.fetch!(message, name),
        not is_nil(value) do
      {id, encode_attr_value(type, value, message)}
    end
  end

  defp encode_attr_value({:dispatch, on, table}, value, message) do
    key = Map.fetch!(message, on)

    case Map.fetch(table, key) do
      {:ok, mod} ->
        mod.encode(value)

      :error ->
        raise ArgumentError,
              "no codec registered for #{inspect(on)} = #{inspect(key)} in dispatch table"
    end
  end

  defp encode_attr_value(type, value, _message), do: encode_value(type, value)

  defp decode_attr_value({:dispatch, on, table}, payload, decoded_so_far) do
    case List.keyfind(decoded_so_far, on, 0) do
      {^on, key} ->
        case Map.fetch(table, key) do
          {:ok, mod} -> mod.decode(payload)
          # Unknown kind — keep the raw bytes rather than crashing on a value
          # we have no codec for.
          :error -> payload
        end

      nil ->
        payload
    end
  end

  defp decode_attr_value(type, payload, _decoded), do: decode_value(type, payload)

  defp scalar(:u8, v), do: <<v::native-unsigned-8>>
  defp scalar(:u16, v), do: <<v::native-unsigned-16>>
  defp scalar(:u32, v), do: <<v::native-unsigned-32>>
  defp scalar(:u64, v), do: <<v::native-unsigned-64>>
  defp scalar(:s8, v), do: <<v::native-signed-8>>
  defp scalar(:s16, v), do: <<v::native-signed-16>>
  defp scalar(:s32, v), do: <<v::native-signed-32>>

  defp unscalar(:u8, <<v::native-unsigned-8, r::binary>>), do: {v, r}
  defp unscalar(:u16, <<v::native-unsigned-16, r::binary>>), do: {v, r}
  defp unscalar(:u32, <<v::native-unsigned-32, r::binary>>), do: {v, r}
  defp unscalar(:u64, <<v::native-unsigned-64, r::binary>>), do: {v, r}
  defp unscalar(:s8, <<v::native-signed-8, r::binary>>), do: {v, r}
  defp unscalar(:s16, <<v::native-signed-16, r::binary>>), do: {v, r}
  defp unscalar(:s32, <<v::native-signed-32, r::binary>>), do: {v, r}

  defp encode_value(type, v) when type in @scalars, do: scalar(type, v)
  # netlink string attributes are NUL-terminated.
  defp encode_value(:string, v), do: [v, 0]
  defp encode_value(:binary, v), do: v
  defp encode_value(mod, v) when is_atom(mod), do: mod.encode(v)

  defp decode_value(type, payload) when type in @scalars do
    {value, _rest} = unscalar(type, payload)
    value
  end

  defp decode_value(:string, payload), do: String.trim_trailing(payload, <<0>>)
  defp decode_value(:binary, payload), do: payload
  defp decode_value(mod, payload) when is_atom(mod), do: mod.decode(payload)
end
