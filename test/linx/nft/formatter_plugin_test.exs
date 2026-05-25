defmodule Linx.NFT.FormatterPluginTest do
  @moduledoc """
  Exercises `Linx.NFT.Formatter`'s `Mix.Tasks.Format` behaviour
  callbacks — the `mix format` plugin entry points.

  We test the plugin's `format/2` directly with the
  `formatter_opts` shape `mix format` would pass: `:sigil` for a
  sigil-body invocation, `:extension` for a file invocation.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.Formatter

  describe "features/1" do
    test "advertises the ~NFT sigil and the .nft extension" do
      features = Formatter.features([])
      assert features[:sigils] == [:NFT]
      assert features[:extensions] == [".nft"]
    end
  end

  describe "format/2 — sigil body" do
    test "reformats a static sigil body to the canonical layout" do
      input = "table inet x{chain c{accept}}"
      out = Formatter.format(input, sigil: :NFT, file: "test.ex", line: 1)
      assert out =~ "table inet x"
      assert out =~ "chain c"
      assert out =~ "accept"
      # Trailing newline is trimmed so the closing `"""` of the
      # heredoc doesn't sit after a blank line.
      refute String.ends_with?(out, "\n")
    end

    test "leaves interpolation-bearing sigils unchanged" do
      input = ~s|table inet x { chain c { tcp dport \#{port} accept } }|
      out = Formatter.format(input, sigil: :NFT, file: "test.ex", line: 1)
      assert out == input
    end

    test "passes through unparseable sigil bodies" do
      input = "this is not nft syntax @@@@"
      out = Formatter.format(input, sigil: :NFT, file: "test.ex", line: 1)
      assert out == input
    end

    test "is idempotent on a static body" do
      input = "table inet x{chain c{accept}}"
      once = Formatter.format(input, sigil: :NFT, file: "test.ex", line: 1)
      twice = Formatter.format(once, sigil: :NFT, file: "test.ex", line: 1)
      assert once == twice
    end
  end

  describe "format/2 — .nft file" do
    test "reformats a static .nft file to canonical layout" do
      input = """
      table inet x {
        chain c {accept}
      }
      """

      out = Formatter.format(input, extension: ".nft", file: "x.nft")
      assert out =~ "table inet x {"
      assert out =~ "accept"
    end

    test "is idempotent on a .nft file" do
      input = """
      table inet myapp {
        chain input {
          type filter hook input priority 0
          policy drop

          ct state established accept
          tcp dport 22 accept
        }
      }
      """

      once = Formatter.format(input, extension: ".nft", file: "myapp.nft")
      twice = Formatter.format(once, extension: ".nft", file: "myapp.nft")
      assert once == twice
    end

    test "raises on a malformed .nft file (surface the error visibly)" do
      input = "table inet x { chain c { ? } }"

      assert_raise Linx.NFT.ParseError, ~r/unexpected/, fn ->
        Formatter.format(input, extension: ".nft", file: "bad.nft")
      end
    end
  end

  describe "format/2 — unknown context" do
    test "returns the input unchanged when neither :sigil nor :extension matches" do
      input = "anything goes here"
      assert Formatter.format(input, []) == input
      assert Formatter.format(input, sigil: :S, extension: ".ex") == input
    end
  end

  describe "round-trip via plugin matches direct format/1 path" do
    test "static sigil body through plugin equals format/1 minus trailing newline" do
      src = """
      table inet x {
        chain c {
          type filter hook input priority 0
          policy drop
          accept
        }
      }
      """

      {:ok, ruleset} = Linx.NFT.parse(src)
      direct = ruleset |> Linx.NFT.format() |> String.trim_trailing("\n")
      plugin = Formatter.format(src, sigil: :NFT, file: "test.ex", line: 1)
      assert direct == plugin
    end
  end
end
