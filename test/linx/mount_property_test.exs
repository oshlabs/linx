defmodule Linx.MountPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Mount
  alias Linx.Mount.Entry

  defp path do
    byte = one_of([integer(?a..?z), member_of([?\s, ?\t, ?\n, ?\\])])
    map(list_of(byte, max_length: 24), &("/" <> List.to_string(&1)))
  end

  defp propagation do
    one_of([
      map(non_negative_integer(), &{:shared, &1}),
      map(non_negative_integer(), &{:master, &1}),
      map(non_negative_integer(), &{:propagate_from, &1}),
      constant(:unbindable)
    ])
  end

  defp mount_entry do
    gen all(
          mount_id <- non_negative_integer(),
          parent_id <- integer(),
          major <- non_negative_integer(),
          minor <- non_negative_integer(),
          root <- path(),
          mount_point <- path(),
          source <- path(),
          propagation <- uniq_list_of(propagation(), max_length: 4),
          fstype_bytes <- binary(min_length: 1, max_length: 12),
          option_bytes <- binary(max_length: 12)
        ) do
      fstype = Base.encode16(fstype_bytes, case: :lower)
      super_options = "rw,context=" <> Base.encode16(option_bytes, case: :lower)

      %Entry{
        mount_id: mount_id,
        parent_id: parent_id,
        device: "#{major}:#{minor}",
        root: root,
        mount_point: mount_point,
        mount_options: "rw,nosuid",
        propagation: propagation,
        fstype: fstype,
        source: source,
        super_options: super_options
      }
    end
  end

  property "kernel-shaped mountinfo entries parse without losing fields" do
    check all(entries <- list_of(mount_entry(), max_length: 24)) do
      mountinfo = entries |> Enum.map_join("\n", &format_entry/1) |> Kernel.<>("\n")
      assert Mount.parse_mountinfo(mountinfo) == entries
    end
  end

  property "unknown optional fields do not disturb known propagation fields" do
    check all(entry <- mount_entry(), unknown_id <- non_negative_integer()) do
      line = format_entry(entry, ["future_tag:#{unknown_id}"])
      assert Mount.parse_mountinfo(line) == [entry]
    end
  end

  defp format_entry(entry, unknown_fields \\ []) do
    optional = Enum.map(entry.propagation, &format_propagation/1) ++ unknown_fields

    [
      Integer.to_string(entry.mount_id),
      Integer.to_string(entry.parent_id),
      entry.device,
      escape(entry.root),
      escape(entry.mount_point),
      entry.mount_options,
      optional,
      "-",
      entry.fstype,
      escape(entry.source),
      escape(entry.super_options)
    ]
    |> List.flatten()
    |> Enum.join(" ")
  end

  defp format_propagation({:shared, id}), do: "shared:#{id}"
  defp format_propagation({:master, id}), do: "master:#{id}"
  defp format_propagation({:propagate_from, id}), do: "propagate_from:#{id}"
  defp format_propagation(:unbindable), do: "unbindable"

  defp escape(binary) do
    binary
    |> String.replace("\\", "\\134")
    |> String.replace(" ", "\\040")
    |> String.replace("\t", "\\011")
    |> String.replace("\n", "\\012")
  end
end
