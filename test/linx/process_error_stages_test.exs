defmodule Linx.ProcessErrorStagesTest do
  use ExUnit.Case, async: true

  # M11: `Linx.Process` decodes agent frames with
  # `:erlang.binary_to_term(payload, [:safe])`, which fails on any atom not
  # already loaded in the VM. @error_stages exists to pre-load every stage
  # atom the C agent can emit — if one is missing there, that error becomes
  # unreachable in production (the frame is dropped and the owner sees
  # :agent_died instead). Tests can't catch that directly because merely
  # *writing* the atom in a test creates it; instead, grep the C source for
  # every emit-stage string and assert the whitelist covers them all.

  @c_source Path.join([File.cwd!(), "c_src", "linx_process.c"])

  test "every stage the C agent can emit is pre-loaded via @error_stages" do
    source = File.read!(@c_source)

    # Direct emits: emit_error(<errno-expr>, "stage").
    literal_stages =
      ~r/emit_error\([^)"]*"([a-z0-9_]+)"\)/
      |> Regex.scan(source)
      |> Enum.map(fn [_, s] -> s end)

    # Child-relayed stages: the stage_name/1 table ("unknown" is its
    # fall-through return).
    stage_table =
      ~r/case STAGE_\w+:\s*return "([a-z0-9_]+)";/
      |> Regex.scan(source)
      |> Enum.map(fn [_, s] -> s end)

    # Dynamic per-namespace templates: "open_ns_%s" / "setns_%s" expanded
    # over the NS_INFO atom column.
    ns_atoms =
      ~r/\{\s*"([a-z]+)",\s*"[a-z]+",\s*CLONE_NEW\w+\s*\}/
      |> Regex.scan(source)
      |> Enum.map(fn [_, s] -> s end)

    assert literal_stages != [], "no emit_error string literals found — regex drift?"
    assert stage_table != [], "no stage_name table entries found — regex drift?"
    assert ns_atoms != [], "no NS_INFO entries found — regex drift?"

    dynamic = for tmpl <- ["open_ns_", "setns_"], ns <- ns_atoms, do: tmpl <> ns

    emitted = Enum.uniq(literal_stages ++ stage_table ++ dynamic ++ ["unknown"])
    whitelist = Enum.map(Linx.Process.__error_stages__(), &Atom.to_string/1)

    missing = emitted -- whitelist

    assert missing == [],
           "stages emitted by the C agent but missing from @error_stages " <>
             "(these errors are unreachable in production): #{inspect(missing)}"
  end
end
