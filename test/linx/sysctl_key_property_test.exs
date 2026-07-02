defmodule Linx.SysctlKeyPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Sysctl

  # Sysctl key validation is the security boundary in front of procfs: it
  # must accept dot-form keys (and sysctl(8)-style slash-form keys, where
  # dots are literal — the escape hatch for dotted interface names) and
  # reject anything that could traverse or smuggle (`..` segments,
  # whitespace, NUL, empty/edge dots). `read/1` validates before any
  # filesystem access, so these properties never write and only ever read
  # read-only /proc/sys paths.

  defp segment, do: string([?a..?z, ?A..?Z, ?0..?9, ?_..?_, ?-..?-], min_length: 1, max_length: 8)

  defp valid_key do
    gen all(segs <- list_of(segment(), min_length: 1, max_length: 5)) do
      Enum.join(segs, ".")
    end
  end

  # Slash form: same segments, but any of them may carry literal dots
  # (like a VLAN interface name "eth0.100").
  defp valid_slash_key do
    gen all(segs <- list_of(segment(), min_length: 1, max_length: 5)) do
      segs
      |> Enum.with_index()
      |> Enum.map_join("/", fn
        {seg, i} when rem(i, 2) == 1 -> seg <> "." <> seg
        {seg, _} -> seg
      end)
    end
  end

  defp malformed_key do
    one_of([
      constant(""),
      constant("."),
      constant("/"),
      map(valid_key(), &("." <> &1)),
      map(valid_key(), &(&1 <> ".")),
      map(valid_key(), &(&1 <> "..oops")),
      # Slash form is valid syntax now, but traversal, empty segments,
      # and edge slashes are still rejected.
      map(valid_key(), &(&1 <> "/../etc/passwd")),
      map(valid_key(), &(&1 <> "//oops")),
      map(valid_key(), &("/" <> &1)),
      map(valid_key(), &(&1 <> "/")),
      map(valid_key(), &(&1 <> "/..")),
      map(valid_key(), &(&1 <> " trailing")),
      map(valid_key(), &(&1 <> <<0>>))
    ])
  end

  property "a well-formed dot-form key is never rejected as :bad_key" do
    check all(key <- valid_key()) do
      refute match?({:error, {:bad_key, _}}, Sysctl.read(key))
    end
  end

  property "a well-formed slash-form key is never rejected as :bad_key" do
    check all(key <- valid_slash_key()) do
      refute match?({:error, {:bad_key, _}}, Sysctl.read(key))
    end
  end

  property "a key with traversal / illegal characters is rejected as :bad_key" do
    check all(key <- malformed_key()) do
      assert {:error, {:bad_key, _}} = Sysctl.read(key)
    end
  end
end
