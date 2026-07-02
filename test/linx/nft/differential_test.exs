defmodule Linx.NFT.DifferentialTest do
  @moduledoc """
  Differential tests against the real `nft` binary (NFT-PLAN.md,
  "Verification strategy").

  For every fixture in `test/linx/nft/fixtures/*.nft`:

    1. the fixture itself must pass `nft --check -f` — proving the
       corpus is real nft syntax, not a dialect we invented; and
    2. our `format/1` output for it must pass `nft --check -f` —
       the "supersets must not leak" contract: whatever Linx
       accepts, what it *emits* is always loadable by nft.

  `nft --check` needs a netlink socket even though it commits
  nothing, so every invocation runs inside `unshare -r -n` (a
  fresh user+net namespace) — this works unprivileged on any
  kernel with unprivileged user namespaces enabled. When `nft`
  or `unshare` is unavailable the module is skipped, and the CI
  privileged job runs it for certain.
  """

  use ExUnit.Case, async: true

  alias Linx.NFT

  @fixtures_dir Path.expand("fixtures", __DIR__)
  @fixtures @fixtures_dir |> Path.join("*.nft") |> Path.wildcard() |> Enum.sort()

  for path <- @fixtures do
    @external_resource path
  end

  probe_conf = "table inet __linx_probe { }\n"

  nft_available? =
    with nft when is_binary(nft) <- System.find_executable("nft"),
         unshare when is_binary(unshare) <- System.find_executable("unshare") do
      probe =
        Path.join(System.tmp_dir!(), "linx-nft-probe-#{System.unique_integer([:positive])}.nft")

      File.write!(probe, probe_conf)

      try do
        {_out, status} =
          System.cmd("unshare", ["-r", "-n", "nft", "--check", "-f", probe],
            stderr_to_stdout: true
          )

        status == 0
      after
        File.rm(probe)
      end
    else
      _ -> false
    end

  unless nft_available? do
    @moduletag skip: "nft --check unavailable (needs nft + unshare with user namespaces)"
  end

  defp nft_check(source, label) do
    path =
      Path.join(
        System.tmp_dir!(),
        "linx-nft-diff-#{System.unique_integer([:positive])}.nft"
      )

    File.write!(path, source)

    try do
      case System.cmd("unshare", ["-r", "-n", "nft", "--check", "-f", path],
             stderr_to_stdout: true
           ) do
        {_out, 0} -> :ok
        {out, status} -> {:error, "nft --check exited #{status} for #{label}:\n#{out}"}
      end
    after
      File.rm(path)
    end
  end

  defp assert_nft_accepts(source, label) do
    case nft_check(source, label) do
      :ok -> :ok
      {:error, msg} -> flunk(msg <> "\n\nsource was:\n#{source}")
    end
  end

  for path <- @fixtures do
    basename = Path.basename(path)

    describe "fixture: #{basename}" do
      test "the fixture is real nft syntax (nft --check accepts it)" do
        assert_nft_accepts(File.read!(unquote(path)), unquote(basename))
      end

      test "our format/1 output is loadable by nft" do
        {:ok, rs} = NFT.parse(File.read!(unquote(path)), file: unquote(path))
        assert_nft_accepts(NFT.format(rs), "format(#{unquote(basename)})")
      end
    end
  end

  # The aspirational corpus (fixtures using features we haven't
  # landed yet — see AspirationalTest) must also be genuine nft
  # syntax: only the input-validity leg runs here; the format leg
  # joins when the fixture is promoted to fully-supported.
  @aspirational Path.expand("fixtures/aspirational", __DIR__)
                |> Path.join("*.nft")
                |> Path.wildcard()
                |> Enum.sort()

  for path <- @aspirational do
    @external_resource path
    basename = Path.basename(path)

    test "aspirational fixture #{basename} is real nft syntax" do
      assert_nft_accepts(File.read!(unquote(path)), unquote(basename))
    end
  end

  describe "documented Linx supersets are rejected by nft" do
    # These pin that our extensions really are extensions — if nft
    # ever starts accepting one, the divergence docs need updating.

    test "block comments" do
      src = """
      table inet t { /* comment */
        chain c { }
      }
      """

      assert {:ok, _} = NFT.parse(src)
      assert {:error, _} = nft_check(src, "block comment extension")
    end

    test "0b binary literals" do
      src = """
      table inet t {
        chain c {
          tcp dport 0b10110 accept
        }
      }
      """

      assert {:ok, _} = NFT.parse(src)
      assert {:error, _} = nft_check(src, "binary literal extension")
    end
  end

  describe "shared semantics spot-checks" do
    test "octal literal means the same thing to both parsers" do
      # `mark 010` is 8 — if nft --check accepts `mark 8` output
      # produced from `mark 010` input, both sides read base 8.
      src = """
      table inet t {
        chain c {
          meta mark 010 accept
        }
      }
      """

      assert_nft_accepts(src, "octal input")
      {:ok, rs} = NFT.parse(src)
      out = NFT.format(rs)
      assert out =~ "meta mark 8 "
      assert_nft_accepts(out, "octal round-trip output")
    end
  end
end
