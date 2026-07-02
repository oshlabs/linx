defmodule Linx.NFT.TokenizerTest do
  use ExUnit.Case, async: true

  alias Linx.NFT.{ParseError, Tokenizer}

  # Helper: assert that `tokenize/2` succeeds and return tokens.
  defp tokens!(source, opts \\ []) do
    case Tokenizer.tokenize(source, opts) do
      {:ok, tokens} -> tokens
      {:error, err} -> flunk("expected ok, got error: #{Exception.message(err)}")
    end
  end

  # Strip trailing `:stmt_sep` (when present) — most tests don't care
  # about a final separator emitted from a closing newline.
  defp strip_trailing_sep(tokens) do
    case Enum.reverse(tokens) do
      [{:stmt_sep, _} | rest] -> Enum.reverse(rest)
      _ -> tokens
    end
  end

  describe "empty input" do
    test "tokenizes the empty string to an empty list" do
      assert tokens!("") == []
    end

    test "tokenizes pure whitespace to an empty list" do
      assert tokens!("   \t  ") == []
    end
  end

  describe "identifiers" do
    test "single identifier" do
      assert [{:identifier, "table", %{line: 1, column: 1}}] = tokens!("table")
    end

    test "identifier with digits and dashes" do
      assert [{:identifier, "gc-interval", _}] = tokens!("gc-interval")
      assert [{:identifier, "eth0", _}] = tokens!("eth0")
      assert [{:identifier, "auto-merge", _}] = tokens!("auto-merge")
    end

    test "two identifiers separated by whitespace" do
      [a, b] = tokens!("table inet")
      assert {:identifier, "table", %{line: 1, column: 1}} = a
      assert {:identifier, "inet", %{line: 1, column: 7}} = b
    end
  end

  describe "integers" do
    test "decimal" do
      assert [{:integer, 22, _}] = tokens!("22")
      assert [{:integer, 0, _}] = tokens!("0")
      assert [{:integer, 12345, _}] = tokens!("12345")
    end

    test "hex" do
      assert [{:integer, 255, _}] = tokens!("0xff")
      assert [{:integer, 255, _}] = tokens!("0xFF")
      assert [{:integer, 0xDEAD_BEEF, _}] = tokens!("0xdeadbeef")
    end

    test "binary" do
      assert [{:integer, 5, _}] = tokens!("0b101")
      assert [{:integer, 0, _}] = tokens!("0b0")
    end

    test "0x with no digits lexes as 0 + identifier, like nft" do
      # nft's scanner has no `0x`-with-no-digits token: it lexes
      # `0` (a NUM) and then `x` as a string. Mirror that instead
      # of raising.
      assert [{:integer, 0, _}, {:identifier, "x", _}] = tokens!("0x")
    end

    test "leading-zero literals are octal, matching nft's scanner" do
      # scanner.l: `base = yytext[0] == '0' ? 8 : 10`.
      assert [{:integer, 8, _}] = tokens!("010")
      assert [{:integer, 493, _}] = tokens!("0755")
      assert [{:integer, 0, _}] = tokens!("0")
    end

    test "leading-zero literal with 8/9 digits demotes to :symbol, like nft's strtoull" do
      # nft: partial octal conversion (`*end` non-NUL) demotes the
      # lexeme to a plain string token.
      assert [{:symbol, "08", _}] = tokens!("08")
      assert [{:symbol, "0899", _}] = tokens!("0899")
    end
  end

  describe "strings" do
    test "simple string" do
      assert [{:string, "ssh-attempt", _}] = tokens!(~s/"ssh-attempt"/)
    end

    test "empty string" do
      assert [{:string, "", _}] = tokens!(~s/""/)
    end

    test "default mode matches nft exactly: no escape processing" do
      # nft's pattern is `\"[^"]*\"` — a backslash is a literal
      # byte and the string ends at the first `"`.
      assert [{:string, "line1\\nline2", _}] = tokens!(~s/"line1\\nline2"/)
      assert [{:string, "back\\slash", _}] = tokens!(~s/"back\\slash"/)

      # Elixir-style `\"` escapes are NOT file syntax: the string
      # closes at the second quote and the leftovers fail to lex —
      # nft rejects the same input (as a grammar error on JUNK).
      assert {:error, %ParseError{}} = Tokenizer.tokenize(~s/"he said \\"hi\\""/)
    end

    test "escapes?: true (sigil mode) processes Elixir-style escapes" do
      assert [{:string, ~s/he said "hi"/, _}] =
               tokens!(~s/"he said \\"hi\\""/, escapes?: true)

      assert [{:string, "line1\nline2", _}] = tokens!(~s/"line1\\nline2"/, escapes?: true)
      assert [{:string, "tab\there", _}] = tokens!(~s/"tab\\there"/, escapes?: true)
      assert [{:string, "back\\slash", _}] = tokens!(~s/"back\\\\slash"/, escapes?: true)
    end

    test "unterminated string is an error pointing at the opening quote" do
      assert {:error, %ParseError{line: 1, column: 1, message: msg}} =
               Tokenizer.tokenize(~s/"hello/)

      assert msg =~ "unterminated string literal"
    end

    test "raw newline inside string is an error" do
      assert {:error, %ParseError{message: msg}} =
               Tokenizer.tokenize(~s/"foo\nbar"/)

      assert msg =~ "unterminated string literal"
    end
  end

  describe "comments" do
    test "line comment is skipped" do
      assert tokens!("table # the inet family") |> strip_trailing_sep() ==
               [{:identifier, "table", %{line: 1, column: 1}}]
    end

    test "line comment followed by another line" do
      tokens = tokens!("# comment\ntable inet\n") |> strip_trailing_sep()

      assert [
               {:stmt_sep, _},
               {:identifier, "table", %{line: 2}},
               {:identifier, "inet", %{line: 2}}
             ] = tokens
    end

    test "block comment is skipped" do
      assert [{:identifier, "a", _}, {:identifier, "b", _}] =
               tokens!("a /* nope */ b")
    end

    test "nested block comments balance" do
      assert [{:identifier, "a", _}, {:identifier, "b", _}] =
               tokens!("a /* outer /* inner */ still */ b")
    end

    test "unterminated block comment is an error" do
      assert {:error, %ParseError{message: msg}} = Tokenizer.tokenize("/* never closes")
      assert msg =~ "unterminated block comment"
    end
  end

  describe "punctuation" do
    test "single-char punctuation gets its own token kind" do
      assert [
               {:lbrace, _},
               {:rbrace, _},
               {:lparen, _},
               {:rparen, _},
               {:comma, _}
             ] = tokens!("{}(),")
    end

    test "at-sign and dollar-sign" do
      assert [{:at, _}, {:identifier, "blocklist", _}] = tokens!("@blocklist")
      assert [{:dollar, _}, {:identifier, "myvar", _}] = tokens!("$myvar")
    end

    test "multi-char operators win over single-char" do
      assert [{:lshift, _}] = tokens!("<<")
      assert [{:rshift, _}] = tokens!(">>")
      assert [{:lte, _}] = tokens!("<=")
      assert [{:gte, _}] = tokens!(">=")
      assert [{:eq, _}] = tokens!("==")
      assert [{:neq, _}] = tokens!("!=")
    end

    test "lone < > are still individually tokenizable" do
      assert [{:lt, _}, {:identifier, "x", _}, {:gt, _}] = tokens!("<x>")
    end
  end

  describe "statement separators" do
    test "; emits a stmt_sep" do
      assert [{:identifier, "a", _}, {:stmt_sep, _}, {:identifier, "b", _}] =
               tokens!("a;b")
    end

    test "newline emits a stmt_sep" do
      assert [{:identifier, "a", _}, {:stmt_sep, _}, {:identifier, "b", _}] =
               tokens!("a\nb")
    end

    test "consecutive separators collapse" do
      assert [{:identifier, "a", _}, {:stmt_sep, _}, {:identifier, "b", _}] =
               tokens!("a;\n;\nb")
    end

    test "line continuation suppresses the separator" do
      assert [{:identifier, "a", _}, {:identifier, "b", _}] = tokens!("a \\\nb")
    end
  end

  describe "IPv4 / CIDR" do
    test "IPv4 literal" do
      assert [{:ipv4, "192.168.1.1", _}] = tokens!("192.168.1.1")
    end

    test "IPv4 CIDR" do
      assert [{:cidr_v4, "10.0.0.0/24", _}] = tokens!("10.0.0.0/24")
      assert [{:cidr_v4, "0.0.0.0/0", _}] = tokens!("0.0.0.0/0")
    end

    test "invalid IPv4 (out of range octet) demotes to :symbol, like nft" do
      # nft's scanner cannot fail — an unclassifiable run becomes a
      # string token and the grammar/evaluation reject it with a
      # located error. The parser/compiler do the same with :symbol.
      assert [{:symbol, "999.0.0.1", _}] = tokens!("999.0.0.1")
      assert [{:symbol, "1.2.3.4.5", _}] = tokens!("1.2.3.4.5")
    end
  end

  describe "time literals (nft timestring)" do
    test "single-unit forms produce :time tokens in milliseconds" do
      assert [{:time, 30_000, _}] = tokens!("30s")
      assert [{:time, 60_000, _}] = tokens!("1m")
      assert [{:time, 3_600_000, _}] = tokens!("1h")
      assert [{:time, 86_400_000, _}] = tokens!("1d")
      assert [{:time, 250, _}] = tokens!("250ms")
    end

    test "compound forms, matching scanner.l's timestring definition" do
      # ([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?([0-9]+ms)?
      assert [{:time, ms, _}] = tokens!("1h30m10s")
      assert ms == 3_600_000 + 30 * 60_000 + 10_000

      assert [{:time, ms2, _}] = tokens!("2d12h")
      assert ms2 == 2 * 86_400_000 + 12 * 3_600_000

      assert [{:time, 1_500, _}] = tokens!("1s500ms")
    end

    test "units must be strictly descending, like the flex pattern" do
      # `10s5m` cannot match the timestring pattern as ONE token;
      # flex's longest-match lexes it as two consecutive
      # timestrings (`10s`, `5m`) — and so do we.
      assert [{:time, 10_000, _}, {:time, 300_000, _}] = tokens!("10s5m")
    end

    test "nft has no week unit — 5w is not a time literal" do
      # nft lexes `5` (NUM) + `w` (string); a downstream parse
      # error in most positions. We match.
      assert [{:integer, 5, _}, {:identifier, "w", _}] = tokens!("5w")
    end

    test "a digit-led IPv6 hextet ending in d is an address, not N days" do
      # `d` is the only time unit that is also a hex digit, so a first
      # hextet like `830d` followed by `:` must scan as an IPv6 literal,
      # not the time literal "830 days". Regression for the round-trip
      # property finding.
      assert [{:ipv6, "830d:ba45:76cf:7320:8582:4c9:3ab5:d1cb", _}] =
               tokens!("830d:ba45:76cf:7320:8582:4c9:3ab5:d1cb")

      assert [{:cidr_v6, "830d::/16", _}] = tokens!("830d::/16")
    end
  end

  describe "IPv6 / CIDR / MAC" do
    test "full IPv6 literal" do
      assert [{:ipv6, "fe80:0:0:0:0:0:0:1", _}] = tokens!("fe80:0:0:0:0:0:0:1")
    end

    test "compressed IPv6 literal" do
      assert [{:ipv6, "fe80::1", _}] = tokens!("fe80::1")
      assert [{:ipv6, "::1", _}] = tokens!("::1")
      assert [{:ipv6, "::", _}] = tokens!("::")
    end

    test "IPv6 CIDR" do
      assert [{:cidr_v6, "fe80::/10", _}] = tokens!("fe80::/10")
    end

    test "MAC address (6 hex octets joined by :)" do
      assert [{:mac, "aa:bb:cc:dd:ee:ff", _}] = tokens!("aa:bb:cc:dd:ee:ff")
      assert [{:mac, "00:11:22:33:44:55", _}] = tokens!("00:11:22:33:44:55")
    end
  end

  describe "Elixir interpolation" do
    test "is not recognized when interpolation? is false" do
      # `#{...}` is treated as a `#` line comment in this mode.
      assert tokens!("tcp dport \#{port} accept") |> strip_trailing_sep() ==
               [
                 {:identifier, "tcp", %{line: 1, column: 1}},
                 {:identifier, "dport", %{line: 1, column: 5}}
               ]
    end

    test "captures the raw expression when interpolation? is true" do
      tokens = tokens!("tcp dport \#{port} accept", interpolation?: true)

      assert [
               {:identifier, "tcp", _},
               {:identifier, "dport", _},
               {:elixir_expr, "port", %{line: 1}},
               {:identifier, "accept", _}
             ] = tokens
    end

    test "tracks brace depth so nested {} doesn't terminate early" do
      tokens =
        tokens!(~s/dport \#{Enum.map([1, 2], fn x -> {:ok, x} end)} accept/,
          interpolation?: true
        )

      assert [
               {:identifier, "dport", _},
               {:elixir_expr, raw, _},
               {:identifier, "accept", _}
             ] = tokens

      assert raw == "Enum.map([1, 2], fn x -> {:ok, x} end)"
    end

    test "ignores } inside Elixir string literals" do
      tokens = tokens!(~s|prefix \#{"close }"} stop|, interpolation?: true)

      assert [
               {:identifier, "prefix", _},
               {:elixir_expr, raw, _},
               {:identifier, "stop", _}
             ] = tokens

      assert raw == ~s|"close }"|
    end

    test "ignores } inside Elixir line comments" do
      tokens = tokens!("a \#{1 + 1 # close }\n} b", interpolation?: true)

      assert [
               {:identifier, "a", _},
               {:elixir_expr, raw, _},
               {:identifier, "b", _}
             ] = tokens

      assert raw =~ "1 + 1"
      assert raw =~ "close }"
    end

    test "unterminated interpolation reports the opening location" do
      assert {:error, %ParseError{line: 1, column: 3, message: msg}} =
               Tokenizer.tokenize("a \#{port", interpolation?: true)

      assert msg =~ "unterminated Elixir interpolation"
    end
  end

  describe "realistic snippet" do
    test "tokenizes a small table block" do
      src = """
      table inet myapp {
        chain input {
          type filter hook input priority 0; policy drop;
          tcp dport 22 accept
        }
      }
      """

      tokens = tokens!(src)

      # Spot-check a few salient tokens; full structural assertions
      # belong in the parser tests once N8b ships.
      kinds = Enum.map(tokens, &elem(&1, 0))

      assert :identifier in kinds
      assert :integer in kinds
      assert :lbrace in kinds
      assert :rbrace in kinds
      assert :stmt_sep in kinds

      assert Enum.count(tokens, fn
               {:identifier, "table", _} -> true
               _ -> false
             end) == 1

      assert Enum.count(tokens, fn
               {:identifier, "chain", _} -> true
               _ -> false
             end) == 1
    end
  end

  describe "error reporting" do
    test "carries file and snippet from the offending line" do
      src = "table inet x {\nchain ? input {\n}\n}\n"

      assert {:error,
              %ParseError{file: "rules.nft", line: 2, column: 7, snippet: snip, message: msg}} =
               Tokenizer.tokenize(src, file: "rules.nft")

      assert snip == "chain ? input {"
      assert msg =~ "unexpected character"
    end
  end
end
