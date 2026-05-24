defmodule Linx.CapabilitiesTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Linx.Capabilities
  alias Linx.Capabilities.Constants
  alias Linx.Capabilities.State

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(Capabilities.supported?())
    end

    test "agrees with /proc/self/status containing a CapBnd: line" do
      expected =
        case File.read("/proc/self/status") do
          {:ok, data} -> data =~ ~r/^CapBnd:/m
          {:error, _} -> false
        end

      assert Capabilities.supported?() == expected
    end
  end

  describe "Linx.Capabilities.Constants — the 41-entry table" do
    test "all/0 has 41 entries" do
      assert MapSet.size(Constants.all()) == 41
    end

    test "every entry is a :cap_*-prefixed atom" do
      for cap <- Constants.all() do
        assert is_atom(cap)
        assert Atom.to_string(cap) =~ ~r/^cap_/
      end
    end

    test "last_cap/0 is 40 (:cap_checkpoint_restore)" do
      assert Constants.last_cap() == 40
    end

    test "to_bit/1 returns the canonical bit number for known atoms" do
      assert Constants.to_bit(:cap_chown) == 0
      assert Constants.to_bit(:cap_net_admin) == 12
      assert Constants.to_bit(:cap_sys_admin) == 21
      assert Constants.to_bit(:cap_setfcap) == 31
      assert Constants.to_bit(:cap_checkpoint_restore) == 40
    end

    test "to_bit/1 returns nil for an unknown atom" do
      assert Constants.to_bit(:cap_does_not_exist) == nil
      assert Constants.to_bit(:not_even_a_cap) == nil
    end

    test "from_bit/1 returns the canonical atom for known bits" do
      assert Constants.from_bit(0) == :cap_chown
      assert Constants.from_bit(12) == :cap_net_admin
      assert Constants.from_bit(21) == :cap_sys_admin
      assert Constants.from_bit(40) == :cap_checkpoint_restore
    end

    test "from_bit/1 returns :unknown for bits past last_cap/0" do
      assert Constants.from_bit(41) == :unknown
      assert Constants.from_bit(50) == :unknown
      assert Constants.from_bit(63) == :unknown
    end
  end

  describe "Linx.Capabilities.Constants — MapSet ↔ u64 conversion" do
    test "to_bits/1 turns a MapSet of atoms into the right u64 mask" do
      # bit 0 (:cap_chown) + bit 12 (:cap_net_admin) = 0x1001
      assert Constants.to_bits(MapSet.new([:cap_chown, :cap_net_admin])) ==
               0x1001
    end

    test "to_bits/1 accepts a list as well as a MapSet" do
      assert Constants.to_bits([:cap_chown]) == 1
      assert Constants.to_bits([:cap_chown, :cap_net_admin]) == 0x1001
    end

    test "to_bits/1 of an empty enumerable is 0" do
      assert Constants.to_bits([]) == 0
      assert Constants.to_bits(MapSet.new()) == 0
    end

    test "to_bits/1 raises ArgumentError on an unknown atom" do
      assert_raise ArgumentError,
                   ~r/unknown capability atom: :cap_made_up/,
                   fn -> Constants.to_bits([:cap_made_up]) end
    end

    test "from_bits/1 turns a u64 mask into the right MapSet" do
      assert Constants.from_bits(0x1001) ==
               MapSet.new([:cap_chown, :cap_net_admin])
    end

    test "from_bits/1 of 0 is the empty MapSet" do
      assert Constants.from_bits(0) == MapSet.new()
    end

    test "from_bits/1 filters out unknown (future) bits silently" do
      # Bit 50 isn't a known cap. Should be dropped, not raise, not
      # land in the result.
      assert Constants.from_bits(0x1 ||| 1 <<< 50) == MapSet.new([:cap_chown])
    end

    test "to_bits/1 and from_bits/1 round-trip every known cap individually" do
      for cap <- Constants.all() do
        single = MapSet.new([cap])
        assert Constants.from_bits(Constants.to_bits(single)) == single
      end
    end

    test "to_bits/1 of the full set yields the 41-bit all-ones mask" do
      assert Constants.to_bits(Constants.all()) == (1 <<< 41) - 1
    end

    test "from_bits/1 of the 41-bit mask yields the full set" do
      assert Constants.from_bits((1 <<< 41) - 1) == Constants.all()
    end
  end

  describe "%Linx.Capabilities.State{}" do
    test "@enforce_keys covers all five fields" do
      assert_raise ArgumentError, fn ->
        struct!(State, %{})
      end
    end

    test "constructs cleanly with all five MapSets" do
      state = %State{
        effective: MapSet.new([:cap_chown]),
        permitted: MapSet.new([:cap_chown]),
        inheritable: MapSet.new(),
        bounding: Constants.all(),
        ambient: MapSet.new()
      }

      assert state.effective == MapSet.new([:cap_chown])
      assert state.bounding == Constants.all()
    end

    test "Inspect renders cap counts per set" do
      state = %State{
        effective: MapSet.new([:cap_chown, :cap_net_admin]),
        permitted: MapSet.new([:cap_chown, :cap_net_admin]),
        inheritable: MapSet.new(),
        bounding: Constants.all(),
        ambient: MapSet.new()
      }

      assert inspect(state) ==
               "#Linx.Capabilities.State<eff=2 prm=2 inh=0 bnd=41 amb=0>"
    end

    test "Inspect on an empty-everywhere state renders zeros" do
      state = %State{
        effective: MapSet.new(),
        permitted: MapSet.new(),
        inheritable: MapSet.new(),
        bounding: MapSet.new(),
        ambient: MapSet.new()
      }

      assert inspect(state) ==
               "#Linx.Capabilities.State<eff=0 prm=0 inh=0 bnd=0 amb=0>"
    end
  end

  describe "K1/K2 stubs return :not_yet_implemented" do
    # Sanity-check that the public surface compiles and is shaped
    # right; the stubs go away as K1/K2 land.

    test "read/1 against :self" do
      assert Capabilities.read(:self) == {:error, :not_yet_implemented}
    end

    test "read/1 against a pid" do
      assert Capabilities.read(1) == {:error, :not_yet_implemented}
    end

    test "drop_bounding/2" do
      assert Capabilities.drop_bounding(self(), [:cap_chown]) ==
               {:error, :not_yet_implemented}
    end

    test "set_thread_sets/2" do
      assert Capabilities.set_thread_sets(self(), effective: [:cap_chown]) ==
               {:error, :not_yet_implemented}
    end

    test "set_ambient/2" do
      assert Capabilities.set_ambient(self(), [:cap_chown]) ==
               {:error, :not_yet_implemented}
    end
  end
end
