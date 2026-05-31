defmodule Linx.SysctlKeyPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Sysctl

  # Sysctl key validation is the security boundary in front of procfs: it
  # must accept dot-form keys and reject anything that could traverse or
  # smuggle (`..`, slashes, whitespace, NUL, empty/edge dots). `read/1`
  # validates before any filesystem access, so these properties never write
  # and only ever read read-only /proc/sys paths.

  defp segment, do: string([?a..?z, ?A..?Z, ?0..?9, ?_..?_, ?-..?-], min_length: 1, max_length: 8)

  defp valid_key do
    gen all(segs <- list_of(segment(), min_length: 1, max_length: 5)) do
      Enum.join(segs, ".")
    end
  end

  defp malformed_key do
    one_of([
      constant(""),
      constant("."),
      map(valid_key(), &("." <> &1)),
      map(valid_key(), &(&1 <> ".")),
      map(valid_key(), &(&1 <> "..oops")),
      map(valid_key(), &(&1 <> "/etc/passwd")),
      map(valid_key(), &(&1 <> " trailing")),
      map(valid_key(), &(&1 <> <<0>>))
    ])
  end

  property "a well-formed dot-form key is never rejected as :bad_key" do
    check all(key <- valid_key()) do
      refute match?({:error, {:bad_key, _}}, Sysctl.read(key))
    end
  end

  property "a key with traversal / illegal characters is rejected as :bad_key" do
    check all(key <- malformed_key()) do
      assert {:error, {:bad_key, _}} = Sysctl.read(key)
    end
  end
end
