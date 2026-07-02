defmodule Linx.NFT.IncludeTest do
  @moduledoc """
  NFT-PLAN.md Phase 4 — `include` resolution: relative to the
  including file, glob support, depth cap, cycle detection,
  located errors, and defines flowing across include boundaries.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT.ParseError

  @moduletag :tmp_dir

  defp write!(dir, name, content) do
    path = Path.join(dir, name)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, content)
    path
  end

  test "include splices the included file at the directive's position", %{tmp_dir: dir} do
    write!(dir, "filter.nft", """
    table inet filter {
      chain input { type filter hook input priority 0; policy drop; }
    }
    """)

    main =
      write!(dir, "main.nft", """
      include "filter.nft"

      table inet extra { }
      """)

    {:ok, rs} = Linx.NFT.parse_file(main)
    assert rs.tables[{:inet, "filter"}]
    assert rs.tables[{:inet, "extra"}]
  end

  test "relative includes resolve against the INCLUDING file's directory", %{tmp_dir: dir} do
    write!(dir, "sub/inner.nft", ~s/table inet inner { }\n/)
    write!(dir, "sub/mid.nft", ~s/include "inner.nft"\n/)
    main = write!(dir, "main.nft", ~s/include "sub\/mid.nft"\n/)

    {:ok, rs} = Linx.NFT.parse_file(main)
    assert rs.tables[{:inet, "inner"}]
  end

  test "glob includes process matches in alphabetical order; empty glob is fine",
       %{tmp_dir: dir} do
    write!(dir, "conf.d/10-a.nft", ~s/table inet a { }\n/)
    write!(dir, "conf.d/20-b.nft", ~s/table inet b { }\n/)

    main =
      write!(dir, "main.nft", """
      include "conf.d/*.nft"
      include "nonexistent.d/*.nft"
      """)

    {:ok, rs} = Linx.NFT.parse_file(main)
    assert rs.tables[{:inet, "a"}]
    assert rs.tables[{:inet, "b"}]
  end

  test "a literal include path that doesn't exist is a located error", %{tmp_dir: dir} do
    main =
      write!(dir, "main.nft", """
      table inet t { }
      include "missing.nft"
      """)

    assert {:error, %ParseError{line: 2} = err} = Linx.NFT.parse_file(main)
    assert Exception.message(err) =~ "file not found"
  end

  test "include cycles are detected", %{tmp_dir: dir} do
    write!(dir, "a.nft", ~s/include "b.nft"\n/)
    write!(dir, "b.nft", ~s/include "a.nft"\n/)
    main = write!(dir, "main.nft", ~s/include "a.nft"\n/)

    assert {:error, %ParseError{} = err} = Linx.NFT.parse_file(main)
    assert Exception.message(err) =~ "cycle"
  end

  test "defines flow across include boundaries in file order", %{tmp_dir: dir} do
    write!(dir, "vars.nft", ~s/define wan = "eth0"\n/)

    main =
      write!(dir, "main.nft", """
      include "vars.nft"

      table inet t {
        chain c { iifname $wan accept }
      }
      """)

    {:ok, rs} = Linx.NFT.parse_file(main)
    assert [_rule] = rs.tables[{:inet, "t"}].chains["c"].rules
  end

  test "errors inside an included file point at the included file", %{tmp_dir: dir} do
    write!(dir, "broken.nft", """
    table inet t {
      chain c { tcp dport ?? accept }
    }
    """)

    main = write!(dir, "main.nft", ~s/include "broken.nft"\n/)

    assert {:error, %ParseError{} = err} = Linx.NFT.parse_file(main)
    assert err.file =~ "broken.nft"
    assert err.line == 2
  end

  test "include inside a ~NFT sigil is rejected with a clear error" do
    src = ~s/include "whatever.nft"\n/
    # The sigil path goes Parser → Compiler directly; simulate it.
    {:ok, tokens} = Linx.NFT.Tokenizer.tokenize(src)
    {:ok, ast} = Linx.NFT.Parser.parse(tokens, source: src)
    {:error, err} = Linx.NFT.Compiler.compile(ast, source: src)
    assert Exception.message(err) =~ "sigil"
  end

  test "include search paths (:include_paths) are tried after the base dir", %{tmp_dir: dir} do
    write!(dir, "library/common.nft", ~s/table inet common { }\n/)
    main = write!(dir, "rules/main.nft", ~s/include "common.nft"\n/)

    {:ok, rs} = Linx.NFT.parse_file(main, include_paths: [Path.join(dir, "library")])
    assert rs.tables[{:inet, "common"}]
  end
end
