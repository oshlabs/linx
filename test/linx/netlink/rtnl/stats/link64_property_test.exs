defmodule Linx.Netlink.Rtnl.Stats.Link64PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Netlink.Rtnl.Stats.Link64

  @u64_max 0xFFFF_FFFF_FFFF_FFFF
  @counters Link64.__counters__()

  defp full_stats do
    gen all(values <- list_of(integer(0..@u64_max), length: length(@counters))) do
      struct(Link64, Enum.zip(@counters, values))
    end
  end

  property "encode then decode round-trips fully-populated counters" do
    check all(stats <- full_stats()) do
      assert Link64.decode(Link64.encode(stats)) == stats
    end
  end

  property "decode ignores extra trailing bytes from a newer kernel" do
    check all(stats <- full_stats(), extra <- binary()) do
      assert Link64.decode(Link64.encode(stats) <> extra) == stats
    end
  end

  property "the short (pre-5.19) layout leaves the trailing counter nil" do
    short = Enum.drop(@counters, -1)

    check all(values <- list_of(integer(0..@u64_max), length: length(short))) do
      payload = for v <- values, into: <<>>, do: <<v::native-unsigned-64>>
      decoded = Link64.decode(payload)

      assert Map.fetch!(decoded, List.last(@counters)) == nil

      for {name, v} <- Enum.zip(short, values) do
        assert Map.fetch!(decoded, name) == v
      end
    end
  end
end
