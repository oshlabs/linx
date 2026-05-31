defmodule Linx.NFTTest do
  use ExUnit.Case, async: true

  alias Linx.Netfilter.{Chain, Expr, Ruleset, Table, Verdict}

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

      assert %Chain{type: :filter, hook: :input, policy: :drop} =
               Map.fetch!(table.chains, "input")

      assert length(table.chains["input"].rules) == 1
    end

    test "interpolated port becomes a 2-byte BE cmp value at runtime" do
      port = 22

      rs =
        ~NFT"""
        table inet x {
          chain c { tcp dport #{port} accept }
        }
        """

      [rule] =
        rs
        |> Ruleset.fetch_table({:inet, "x"})
        |> elem(1)
        |> then(& &1.chains)
        |> Map.fetch!("c")
        |> then(& &1.rules)

      assert [
               %Expr{name: :payload, data: %{base: :transport, offset: 2, len: 2}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<22::big-16>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :accept}}
             ] = rule.expressions
    end

    test "interpolated IPv4 address (as string)" do
      ip = "10.0.0.5"

      rs =
        ~NFT"""
        table ip x {
          chain c { ip saddr #{ip} drop }
        }
        """

      [rule] =
        rs
        |> Ruleset.fetch_table({:ip, "x"})
        |> elem(1)
        |> then(& &1.chains)
        |> Map.fetch!("c")
        |> then(& &1.rules)

      assert [
               %Expr{name: :payload, data: %{base: :network, offset: 12, len: 4}},
               %Expr{name: :cmp, data: %{op: :eq, value: <<10, 0, 0, 5>>}},
               %Expr{name: :immediate, data: %Verdict{kind: :drop}}
             ] = rule.expressions
    end

    test "interpolated IPv4 address (as 4-tuple)" do
      ip = {10, 0, 0, 7}

      rs = ~NFT"table ip x { chain c { ip daddr #{ip} accept } }"

      [rule] =
        rs
        |> Ruleset.fetch_table({:ip, "x"})
        |> elem(1)
        |> then(& &1.chains)
        |> Map.fetch!("c")
        |> then(& &1.rules)

      assert [_payload, %Expr{name: :cmp, data: %{value: <<10, 0, 0, 7>>}}, _verdict] =
               rule.expressions
    end

    test "interpolated interface name pads to IFNAMSIZ" do
      name = "eth0"

      rs = ~NFT"table inet x { chain c { meta iifname #{name} accept } }"

      [rule] =
        rs
        |> Ruleset.fetch_table({:inet, "x"})
        |> elem(1)
        |> then(& &1.chains)
        |> Map.fetch!("c")
        |> then(& &1.rules)

      assert [
               %Expr{name: :meta, data: %{key: :iifname}},
               %Expr{name: :cmp, data: %{value: ifname_bytes}},
               _verdict
             ] = rule.expressions

      assert byte_size(ifname_bytes) == 16
      assert :binary.part(ifname_bytes, 0, 4) == "eth0"
    end

    test "runtime type error: passing a binary where an integer is expected" do
      bad = "not_a_number"

      assert_raise ArgumentError, ~r/expected non-negative integer/, fn ->
        ~NFT"table inet x { chain c { tcp dport #{bad} accept } }"
      end
    end

    test "no-interpolation sigil still goes through the compile-time static path" do
      # The point: when no `\#{...}` is present, we get a literal
      # value emitted via Macro.escape — verified by checking the
      # AST returned by the macro doesn't contain runtime function
      # calls. Indirect proof: it just compiles to a value.
      rs = ~NFT"table inet x { chain c { accept } }"
      assert %Ruleset{} = rs
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
