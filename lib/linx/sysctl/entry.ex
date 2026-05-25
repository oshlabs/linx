defmodule Linx.Sysctl.Entry do
  @moduledoc """
  A single sysctl read by `Linx.Sysctl.list/0` or
  `Linx.Sysctl.list/1` — one key/value pair from the `/proc/sys/`
  tree.

    * `:key` — the dot-form sysctl key, e.g. `"net.ipv4.ip_forward"`.
    * `:value` — the file's contents with the kernel's trailing
      newline trimmed.

  Both fields are `@enforce_keys`-required; an `%Entry{}` always
  represents a real read.

  ## Inspect

  Renders compactly:

      #Linx.Sysctl.Entry<net.ipv4.ip_forward = "0">

  Values over 60 bytes are truncated with `"..."` for legibility when
  inspecting large lists (the `kernel.printk` / `tcp_*` tuple-shaped
  knobs stay well under the limit; the occasional pathological knob
  like `kernel.version` would hit it). The `:value` field always
  carries the full untruncated string — pattern-match on it directly
  if you need the whole thing.
  """

  @enforce_keys [:key, :value]
  defstruct [:key, :value]

  @type t :: %__MODULE__{
          key: String.t(),
          value: binary()
        }

  defimpl Inspect do
    @value_limit 60

    def inspect(%Linx.Sysctl.Entry{key: key, value: value}, _opts) do
      shown =
        if byte_size(value) > @value_limit do
          binary_part(value, 0, @value_limit) <> "..."
        else
          value
        end

      "#Linx.Sysctl.Entry<#{key} = #{inspect(shown)}>"
    end
  end
end
