defmodule Linx.NFT.AspirationalTest do
  @moduledoc """
  The measured-coverage corpus (NFT-PLAN.md, "Verification
  strategy"): realistic `nftables.conf` files that use the parts
  of the language we're still landing, in
  `test/linx/nft/fixtures/aspirational/*.nft`.

  Every fixture is genuine nft syntax — the differential leg
  asserts `nft --check` accepts it whenever the binary is
  available. Against our own pipeline each fixture is in one of
  two pinned states:

    * in `@fully_supported` — must parse, compile, format, and
      the formatted output must round-trip. Regressions here fail
      loudly.
    * not in the list — must currently FAIL to parse or compile.
      When you land the feature that makes one pass, this test
      fails and tells you to promote the fixture; the list is the
      measured coverage number, and it only ratchets up.

  Coverage today: see `@fully_supported` vs the fixture count.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT

  @fixtures_dir Path.expand("fixtures/aspirational", __DIR__)
  @fixtures @fixtures_dir |> Path.join("*.nft") |> Path.wildcard() |> Enum.sort()

  for path <- @fixtures do
    @external_resource path
  end

  if @fixtures == [] do
    raise "no aspirational fixtures under #{@fixtures_dir}/*.nft"
  end

  # Ratchet list — fixtures our pipeline fully supports today.
  # Landing a feature that makes another fixture pass? Promote it
  # here (the "must still fail" test below will point you here).
  @fully_supported [
    "a1_debian_default.nft",
    "a2_workstation.nft",
    "a3_server_vmap.nft",
    "a4_nat_router.nft"
  ]

  # What each pending fixture is waiting on (kept in sync with
  # NFT-PLAN.md phases):
  #
  #   (a2_workstation.nft  — landed: limit lowering, iif-by-name,
  #                          icmp/icmpv6 type-name resolution)
  #   (a3_server_vmap.nft  — landed: named + anonymous vmaps,
  #                          named counter objects + objref)
  #   (a4_nat_router.nft   — landed: define/$var + dnat to addr:port)
  #   a5_kube_style.nft    — concatenated set keys/elements,
  #                          dynamic sets with `add @set { … }`
  #                          (Phase 1/2/6)

  for path <- @fixtures do
    basename = Path.basename(path)

    if basename in @fully_supported do
      describe "supported fixture: #{basename}" do
        test "parses, formats, and round-trips" do
          source = File.read!(unquote(path))
          assert {:ok, rs1} = NFT.parse(source, file: unquote(path))
          formatted = NFT.format(rs1)
          assert {:ok, rs2} = NFT.parse(formatted, file: "<formatted>")
          assert rs1 == rs2
        end
      end
    else
      describe "pending fixture: #{basename}" do
        test "still fails (promote to @fully_supported when it passes!)" do
          source = File.read!(unquote(path))

          case NFT.parse(source, file: unquote(path)) do
            {:error, _} ->
              :ok

            {:ok, _} ->
              flunk("""
              #{unquote(basename)} now parses+compiles successfully.

              Nice — a feature landed. Promote it to @fully_supported in
              #{__ENV__.file}
              so it's covered by the strict round-trip assertions from now on.
              """)
          end
        end
      end
    end
  end

  test "coverage ratchet is measured and visible" do
    total = length(@fixtures)
    supported = length(@fully_supported)

    IO.puts(
      "\n[aspirational corpus] #{supported}/#{total} fixtures fully supported " <>
        "(#{div(supported * 100, total)}%)"
    )

    # Every @fully_supported entry must actually exist on disk.
    basenames = Enum.map(@fixtures, &Path.basename/1)
    assert Enum.all?(@fully_supported, &(&1 in basenames))
  end
end
