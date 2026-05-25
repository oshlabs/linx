defmodule Linx.NFT.ParseErrorTest do
  use ExUnit.Case, async: true

  alias Linx.NFT.ParseError

  describe "code_snippet/2" do
    test "returns empty string when source line is nil" do
      assert ParseError.code_snippet(nil, 5) == ""
    end

    test "renders the source line with a caret at the given column" do
      out = ParseError.code_snippet("tcp dport 22", 5)

      assert out == """
             |
             | tcp dport 22
             |     ^\
             """
    end

    test "column 1 puts the caret under the first character" do
      out = ParseError.code_snippet("table inet x", 1)
      assert String.ends_with?(out, "^")
      assert String.contains?(out, "| ^")
    end
  end

  describe "exception" do
    test "renders header + snippet via Exception.message/1" do
      err = %ParseError{
        file: "rules.nft",
        line: 12,
        column: 8,
        snippet: "  chain ? input {",
        message: "unexpected character"
      }

      msg = Exception.message(err)
      assert msg =~ "rules.nft:12:8: unexpected character"
      assert msg =~ "  chain ? input {"
      assert msg =~ "       ^"
    end

    test "renders header-only when snippet is nil" do
      err = %ParseError{
        file: "nofile",
        line: 1,
        column: 1,
        snippet: nil,
        message: "boom"
      }

      assert Exception.message(err) == "nofile:1:1: boom"
    end
  end

  describe "raise_syntax_error!/2" do
    test "raises a ParseError with carry-over context fields" do
      assert_raise ParseError, ~r/nofile:3:2: oops/, fn ->
        ParseError.raise_syntax_error!(
          %{file: "nofile", line: 3, column: 2, snippet: "  oops"},
          "oops"
        )
      end
    end
  end
end
