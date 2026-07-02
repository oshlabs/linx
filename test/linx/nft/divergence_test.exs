defmodule Linx.NFT.DivergenceTest do
  # Pins every place where Linx.NFT deliberately matches — or
  # deliberately diverges from — the official nftables parser
  # (nftables.git src/scanner.l / src/parser_bison.y). Each test
  # cites the upstream behavior it pins so a future "cleanup"
  # can't silently reintroduce a divergence. See NFT-PLAN.md
  # Phase 0.
  use ExUnit.Case, async: true

  import Linx.NFT, only: [sigil_NFT: 2]

  alias Linx.NFT.Tokenizer

  defp tokens!(source, opts \\ []) do
    {:ok, tokens} = Tokenizer.tokenize(source, opts)
    tokens
  end

  describe "octal literals (scanner.l: base = yytext[0] == '0' ? 8 : 10)" do
    test "a leading-zero mark value means base 8, matching nft" do
      src = """
      table inet t {
        chain c {
          meta mark 010 accept
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      # 010 octal = 8 decimal; the formatter always emits decimal.
      assert Linx.NFT.format(rs) =~ "meta mark 8 "
    end
  end

  describe "quoted strings (scanner.l: quotedstring is \\\"[^\"]*\\\" — no escapes)" do
    test "file mode: backslashes in log prefixes are literal bytes" do
      src = """
      table inet t {
        chain c {
          log prefix "pfx\\n" accept
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      # The two bytes `\` and `n` survive verbatim, as nft reads them.
      assert Linx.NFT.format(rs) =~ ~s/prefix "pfx\\n"/
    end

    test "sigil mode keeps Elixir-style escapes as a documented convenience" do
      rs = ~NFT"""
      table inet t {
        chain c {
          log prefix "a\tb" accept
        }
      }
      """

      # The sigil processed \t into a TAB…
      assert Linx.NFT.format(rs) =~ "a\tb"
    end

    test "the formatter never emits a double quote inside a string" do
      # nft has no escape syntax, so a literal `"` cannot appear
      # inside an nft string at all; the formatter substitutes `'`.
      rs = ~NFT"""
      table inet t {
        chain c {
          tcp dport 22 accept comment "say \"hi\""
        }
      }
      """

      out = Linx.NFT.format(rs)
      assert out =~ ~s/comment "say 'hi'"/
      refute out =~ ~s/\\"/
    end
  end

  describe "block comments (scanner.l has none — only # line comments)" do
    test "accepted inbound as a Linx extension" do
      src = """
      table inet t { /* not valid for nft -f! */
        chain c { }
      }
      """

      assert {:ok, _rs} = Linx.NFT.parse(src)
    end

    test "the formatter never emits them" do
      {:ok, rs} =
        Linx.NFT.parse("""
        table inet t {
          chain c {
            type filter hook input priority 0
            policy accept
          }
        }
        """)

      refute Linx.NFT.format(rs) =~ "/*"
    end
  end

  describe "bare strings with ./ (scanner.l string: ({letter}|[_.])({letter}|{digit}|[/\\-_\\.])*)" do
    test "a dotted name is one token, like nft" do
      assert [{:identifier, "example.com", _}] = tokens!("example.com")
      assert [{:identifier, "eth0.10", _}] = tokens!("eth0.10")
    end

    test "a slashed name is one token, like nft" do
      assert [{:identifier, "br-lan/wan0", _}] = tokens!("br-lan/wan0")
    end

    test "a spaced dot is still the concatenation operator" do
      assert [
               {:identifier, "ipv4_addr", _},
               {:dot, _},
               {:identifier, "inet_service", _}
             ] = tokens!("ipv4_addr . inet_service")
    end
  end

  describe "timestring (scanner.l:138) and set-timeout units" do
    test "set timeout survives the wire unit (ms) and round-trips" do
      src = """
      table inet t {
        set s {
          type ipv4_addr
          flags timeout
          timeout 1h30m
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      table = rs.tables[{:inet, "t"}]
      set = table.sets["s"]

      # %Set{}.timeout is documented as milliseconds — the unit the
      # kernel's NFTA_SET_TIMEOUT attribute uses.
      assert set.timeout == 5_400_000
      assert Linx.NFT.format(rs) =~ "timeout 1h30m"
    end

    test "the formatter never emits a week unit (nft's scanner has none)" do
      src = """
      table inet t {
        set s {
          type ipv4_addr
          flags timeout
          timeout 14d
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs)
      assert out =~ "timeout 14d"
      refute out =~ ~r/\d+w/
    end
  end

  describe "binary literals (Linx extension; nft has none)" do
    test "accepted inbound, emitted as decimal" do
      src = """
      table inet t {
        chain c {
          tcp dport 0b10110 accept
        }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs)
      assert out =~ "tcp dport 22"
      refute out =~ "0b"
    end
  end

  describe "lexer totality (scanner.l: <*>. returns JUNK; the scanner cannot fail)" do
    test "unclassifiable literals become located parse errors, not tokenizer crashes" do
      src = """
      table inet t {
        chain c {
          ip saddr 1.2.3.4.5 drop
        }
      }
      """

      assert {:error, err} = Linx.NFT.parse(src)
      assert err.line == 3
      assert Exception.message(err) =~ "1.2.3.4.5"
    end
  end
end
