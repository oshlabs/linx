defmodule Linx.NFT.RoundTripPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.IP
  alias Linx.NFT

  # The golden_test.exs corpus covers nine curated fixtures example-style.
  # This generates *random* rulesets over the same supported vocabulary, to
  # explore construct/ordering combinations the fixtures don't, and asserts
  # the documented contract: parse -> format -> parse is an identity on the
  # %Ruleset{}, and formatting is idempotent.

  defp verdict, do: member_of(["accept", "drop"])

  defp v4_cidr do
    gen all(bytes <- binary(length: 4), prefix <- integer(1..32)) do
      "#{IP.to_string(IP.decode(bytes))}/#{prefix}"
    end
  end

  defp v6_cidr do
    gen all(bytes <- binary(length: 16), prefix <- integer(1..128)) do
      "#{IP.to_string(IP.decode(bytes))}/#{prefix}"
    end
  end

  defp ct_rule, do: gen(all(v <- verdict()), do: "ct state established #{v}")
  defp tcp_rule, do: gen(all(p <- integer(1..65535), v <- verdict()), do: "tcp dport #{p} #{v}")
  defp udp_rule, do: gen(all(p <- integer(1..65535), v <- verdict()), do: "udp dport #{p} #{v}")

  defp iif_rule,
    do: gen(all(i <- member_of(~w(lo eth0 wlan0 ct0))), do: ~s|meta iifname "#{i}" accept|)

  defp ip4_rule do
    gen all(c <- v4_cidr(), dir <- member_of(~w(saddr daddr)), v <- verdict()) do
      "ip #{dir} #{c} #{v}"
    end
  end

  defp ip6_rule do
    gen all(c <- v6_cidr(), dir <- member_of(~w(saddr daddr)), v <- verdict()) do
      "ip6 #{dir} #{c} #{v}"
    end
  end

  defp rule_for(family) do
    family_specific =
      case family do
        "ip" -> [ip4_rule()]
        "ip6" -> [ip6_rule()]
        "inet" -> [ip4_rule(), ip6_rule()]
      end

    one_of([ct_rule(), tcp_rule(), udp_rule(), iif_rule()] ++ family_specific)
  end

  defp ruleset_source do
    gen all(
          family <- member_of(~w(inet ip ip6)),
          tname <- member_of(~w(filter myapp guard edge)),
          cname <- member_of(~w(input forward output mychain)),
          hook <- member_of(~w(input forward output)),
          priority <- integer(0..300),
          policy <- verdict(),
          rules <- list_of(rule_for(family), max_length: 6)
        ) do
      body =
        ["type filter hook #{hook} priority #{priority}", "policy #{policy}" | rules]
        |> Enum.map_join("\n", &("    " <> &1))

      "table #{family} #{tname} {\n  chain #{cname} {\n#{body}\n  }\n}\n"
    end
  end

  property "a generated ruleset survives parse -> format -> parse unchanged" do
    check all(source <- ruleset_source()) do
      assert {:ok, rs1} = NFT.parse(source)
      text = NFT.format(rs1)

      assert {:ok, rs2} = NFT.parse(text),
             "reformatted output failed to parse:\n#{text}"

      assert rs1 == rs2,
             "structural round-trip mismatch.\n-- source:\n#{source}\n-- reformatted:\n#{text}"

      assert NFT.format(rs2) == text, "formatting is not idempotent for:\n#{text}"
    end
  end
end
