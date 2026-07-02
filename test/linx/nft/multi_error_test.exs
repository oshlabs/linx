defmodule Linx.NFT.MultiErrorTest do
  @moduledoc """
  NFT-PLAN.md Phase 5 — multi-error reporting: the parser recovers
  at statement boundaries and reports every error it finds (capped
  at 10, like nft's parser_max_errors), instead of stopping at the
  first one.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.ParseError

  test "two malformed rules both get reported, with correct locations" do
    src = """
    table inet t {
      chain c {
        frobnicate 22 accept
        udp dport 53 accept
        wibble wobble
      }
    }
    """

    assert {:error, %ParseError{} = err} = Linx.NFT.parse(src)

    all = [err | err.others]
    assert length(all) == 2
    assert Enum.map(all, & &1.line) == [3, 5]
    assert Exception.message(err) =~ "(2 errors)"
  end

  test "a broken rule in one table doesn't hide errors in the next table" do
    src = """
    table inet one {
      chain c { nonsense here }
    }
    table inet two {
      chain d { more nonsense }
    }
    """

    assert {:error, %ParseError{} = err} = Linx.NFT.parse(src)
    all = [err | err.others]
    assert length(all) == 2
  end

  test "error collection caps at 10, like nft's parser_max_errors" do
    bad_rules = Enum.map_join(1..15, "\n", fn i -> "    badstmt#{i} withargs" end)

    src = """
    table inet t {
      chain c {
    #{bad_rules}
      }
    }
    """

    assert {:error, %ParseError{} = err} = Linx.NFT.parse(src)
    assert length([err | err.others]) == 10
  end

  test "valid rules around a broken one still parse (error doesn't cascade)" do
    src = """
    table inet t {
      chain c {
        tcp dport 22 accept
        garbage in the middle
        udp dport 53 accept
      }
    }
    """

    # The ruleset overall errors (we never compile partial input),
    # but only the broken statement is reported — the valid
    # neighbours parsed cleanly.
    assert {:error, %ParseError{others: []} = err} = Linx.NFT.parse(src)
    assert err.line == 4
  end

  test "a stray closing brace at top level cannot loop the parser" do
    assert {:error, %ParseError{}} = Linx.NFT.parse("}\ntable inet t { }")
  end

  test "single-error reports render exactly as before" do
    assert {:error, %ParseError{others: []} = err} =
             Linx.NFT.parse("table inet t { chain c { ?? } }")

    refute Exception.message(err) =~ "errors)"
  end
end
