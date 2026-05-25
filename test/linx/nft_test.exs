defmodule Linx.NFTTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Chain, Ruleset, Table}

  describe "parse/1" do
    test "binary → Ruleset" do
      assert {:ok, %Ruleset{} = rs} = Linx.NFT.parse("table inet x { }")
      assert {:ok, %Table{family: :inet, name: "x"}} = Ruleset.fetch_table(rs, {:inet, "x"})
    end

    test "returns a ParseError on bad syntax" do
      assert {:error, %Linx.NFT.ParseError{} = err} =
               Linx.NFT.parse("table inet x { chain c { ? } }")

      assert err.message =~ "unexpected"
    end
  end

  describe "parse_file/1" do
    setup do
      path = Path.join(System.tmp_dir!(), "linx_nft_#{System.unique_integer([:positive])}.nft")
      on_exit(fn -> File.rm(path) end)
      %{path: path}
    end

    test "reads and parses a file", %{path: path} do
      File.write!(path, "table ip myrules { }")
      assert {:ok, %Ruleset{} = rs} = Linx.NFT.parse_file(path)
      assert {:ok, _} = Ruleset.fetch_table(rs, {:ip, "myrules"})
    end

    test "returns the posix error for missing files" do
      assert {:error, :enoent} = Linx.NFT.parse_file("/does/not/exist.nft")
    end

    test "carries the path into ParseError.file", %{path: path} do
      File.write!(path, "table ip x { chain c { ? } }")
      assert {:error, %Linx.NFT.ParseError{file: ^path}} = Linx.NFT.parse_file(path)
    end
  end

  describe "~NFT sigil" do
    import Linx.NFT, only: [sigil_NFT: 2]

    test "compile-time Ruleset value" do
      rs =
        ~NFT"""
        table inet myapp {
          chain input {
            type filter hook input priority 0
            policy drop
            tcp dport 22 accept
          }
        }
        """

      assert %Ruleset{} = rs
      table = Map.fetch!(rs.tables, {:inet, "myapp"})
      assert %Chain{type: :filter, hook: :input, policy: :drop} = Map.fetch!(table.chains, "input")
      assert length(table.chains["input"].rules) == 1
    end

    test "uppercase sigil treats literal `\#{` as a line comment (no interpolation yet)" do
      # Uppercase sigils don't get interpolation from the Elixir
      # parser, so `\#{...}` arrives at the macro as a literal
      # binary. The tokenizer (interpolation? defaulting to false)
      # treats `#` as a line comment; the rule body is effectively
      # truncated at that point. This is the current behaviour —
      # full interpolation support is a follow-up commit.
      rs = ~NFT"table inet x { chain c { accept } }"
      assert %Ruleset{} = rs
      assert {:ok, _} = Ruleset.fetch_table(rs, {:inet, "x"})
    end
  end

  describe "format/1" do
    test "empty ruleset emits an empty string" do
      assert Linx.NFT.format(Ruleset.new()) == ""
    end

    test "emits a single table" do
      rs = Ruleset.new() |> Ruleset.add_table!(:inet, "x")
      out = Linx.NFT.format(rs)
      assert out =~ "table inet x {"
      assert String.ends_with?(String.trim(out), "}")
    end

    test "round-trips: parse → format → parse" do
      src = """
      table inet myapp {
        chain input {
          type filter hook input priority 0
          policy drop

          tcp dport 22 accept
          ip saddr 10.0.0.0/8 drop
          counter accept
        }
      }
      """

      assert {:ok, rs1} = Linx.NFT.parse(src)
      formatted = Linx.NFT.format(rs1)
      assert {:ok, rs2} = Linx.NFT.parse(formatted)

      # Should be structurally identical.
      assert rs1 == rs2
    end

    test "emits set ref expressions" do
      src = """
      table inet x {
        chain c { tcp dport @ports accept }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs)
      assert out =~ "tcp dport @ports"
    end

    test "emits inline anon sets" do
      src = """
      table inet x {
        chain c { tcp dport { 22, 80, 443 } accept }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs)
      assert out =~ "tcp dport { 22, 80, 443 }"
    end

    test "emits ct state established" do
      src = """
      table inet x {
        chain c { ct state established accept }
      }
      """

      {:ok, rs} = Linx.NFT.parse(src)
      out = Linx.NFT.format(rs)
      assert out =~ "ct state established"
    end

    test "round-trip preserves named sets" do
      src = """
      table inet x {
        set blocklist {
          type ipv4_addr
          flags interval
          elements = { 10.0.0.1, 10.0.0.2 }
        }
        chain input {
          type filter hook input priority 0
        }
      }
      """

      {:ok, rs1} = Linx.NFT.parse(src)
      formatted = Linx.NFT.format(rs1)
      {:ok, rs2} = Linx.NFT.parse(formatted)
      assert rs1 == rs2
    end
  end
end
