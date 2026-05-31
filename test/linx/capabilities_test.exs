defmodule Linx.CapabilitiesTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Linx.Capabilities
  alias Linx.Capabilities.Constants
  alias Linx.Capabilities.Error
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

  describe "Linx.Capabilities.Constants.known_mask/0" do
    test "is the 41-bit all-ones mask for the current table" do
      # Contiguous 0..40, so the mask equals (1 <<< 41) - 1.
      assert Constants.known_mask() == (1 <<< 41) - 1
    end

    test "covers every entry in all/0" do
      for cap <- Constants.all() do
        bit = Constants.to_bit(cap)
        assert (Constants.known_mask() &&& 1 <<< bit) != 0
      end
    end
  end

  describe "Linx.Capabilities.Error" do
    test "@enforce_keys covers path, operation, errno" do
      assert_raise ArgumentError, fn -> struct!(Error, %{}) end
    end

    test "from_posix/3 builds a struct with code from the POSIX table" do
      err = Error.from_posix(:eperm, "/proc/1234/status", :read)

      assert %Error{
               path: "/proc/1234/status",
               operation: :read,
               errno: :eperm,
               code: 1
             } = err
    end

    test "from_posix/3 leaves :code at nil for unmapped errnos" do
      err = Error.from_posix(:bad_status, "/proc/x/status", :read)
      assert %Error{errno: :bad_status, code: nil} = err
    end

    test "Exception.message/1 renders cleanly" do
      err = Error.from_posix(:enoent, "/proc/9999/status", :read)

      assert Exception.message(err) ==
               "capabilities read failed on /proc/9999/status: enoent (errno 2)"
    end

    test "an error can be raised" do
      err = Error.from_posix(:eacces, "/proc/1/status", :read)

      assert_raise Error,
                   "capabilities read failed on /proc/1/status: eacces (errno 13)",
                   fn -> raise err end
    end
  end

  describe "parse_status/2 (fixtures, no I/O)" do
    # Canonical kernel format -- five Cap*: lines, hex, tab-separated.
    @full_status """
    Name:\thead
    State:\tR (running)
    CapInh:\t0000000000000000
    CapPrm:\t000001ffffffffff
    CapEff:\t000001ffffffffff
    CapBnd:\t000001ffffffffff
    CapAmb:\t0000000000000000
    """

    @empty_status """
    Name:\tinit
    CapInh:\t0000000000000000
    CapPrm:\t0000000000000000
    CapEff:\t0000000000000000
    CapBnd:\t0000000000000000
    CapAmb:\t0000000000000000
    """

    test "parses a full-caps status into the all/0 set on three sets" do
      assert {:ok,
              %State{
                effective: eff,
                permitted: prm,
                inheritable: inh,
                bounding: bnd,
                ambient: amb
              }} = Capabilities.parse_status(@full_status, "/proc/1/status")

      assert eff == Constants.all()
      assert prm == Constants.all()
      assert inh == MapSet.new()
      assert bnd == Constants.all()
      assert amb == MapSet.new()
    end

    test "parses an all-zeros status into five empty MapSets" do
      assert {:ok, %State{} = state} =
               Capabilities.parse_status(@empty_status, "/proc/1/status")

      for field <- [:effective, :permitted, :inheritable, :bounding, :ambient] do
        assert Map.fetch!(state, field) == MapSet.new()
      end
    end

    test "is tolerant of arbitrary surrounding whitespace" do
      blob = """
      CapInh:   0000000000000001
      CapPrm:\t\t0000000000000001
      CapEff: 0000000000000001
      CapBnd:\t0000000000000001
      CapAmb:    0000000000000001
      """

      assert {:ok, state} = Capabilities.parse_status(blob, "/proc/x/status")
      one = MapSet.new([:cap_chown])
      assert state.effective == one
      assert state.permitted == one
      assert state.inheritable == one
      assert state.bounding == one
      assert state.ambient == one
    end

    test "doesn't care about Cap*: line order" do
      blob = """
      CapBnd:\t000001ffffffffff
      CapEff:\t0000000000000001
      CapAmb:\t0000000000000000
      CapInh:\t0000000000000000
      CapPrm:\t0000000000000001
      """

      assert {:ok, state} = Capabilities.parse_status(blob, "/proc/x/status")
      assert state.effective == MapSet.new([:cap_chown])
      assert state.bounding == Constants.all()
    end

    test "rejects a status missing one of the five Cap*: lines" do
      missing_amb = """
      CapInh:\t0
      CapPrm:\t0
      CapEff:\t0
      CapBnd:\t0
      """

      assert {:error,
              %Error{
                errno: :bad_status,
                operation: :read,
                path: "/proc/x/status",
                code: nil
              }} = Capabilities.parse_status(missing_amb, "/proc/x/status")
    end

    test "rejects a status with no Cap*: lines at all" do
      blob = "Name:\tinit\nState:\tR\n"

      assert {:error, %Error{errno: :bad_status}} =
               Capabilities.parse_status(blob, "/proc/x/status")
    end

    test "silently drops bits past the known table (no error, no crash)" do
      # Bit 50 isn't a known cap. The parser logs and drops it.
      hex = "0004000000000001"
      # 0x4000000000001 = bit 0 + bit 50

      blob = """
      CapInh:\t0000000000000000
      CapPrm:\t0000000000000000
      CapEff:\t0000000000000000
      CapBnd:\t#{hex}
      CapAmb:\t0000000000000000
      """

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, state} =
                   Capabilities.parse_status(blob, "/proc/x/status")

          # bit 0 (:cap_chown) survives; bit 50 is dropped.
          assert state.bounding == MapSet.new([:cap_chown])
        end)

      assert log =~ "capability bits Linx doesn't know about"
    end

    test "parses uppercase hex tolerantly" do
      blob = """
      CapInh:\t0000000000000000
      CapPrm:\t0000000000000000
      CapEff:\t0000000000000000
      CapBnd:\t000001FFFFFFFFFF
      CapAmb:\t0000000000000000
      """

      assert {:ok, state} = Capabilities.parse_status(blob, "/proc/x/status")
      assert state.bounding == Constants.all()
    end
  end

  describe "read/1 against the real procfs" do
    test ":self returns a valid %State{}" do
      assert {:ok, %State{} = state} = Capabilities.read(:self)

      for field <- [:effective, :permitted, :inheritable, :bounding, :ambient] do
        assert is_struct(Map.fetch!(state, field), MapSet)
      end

      # The BEAM almost certainly has the full bounding set; even
      # unprivileged users keep CapBnd full unless they've actively
      # dropped from it. This is a softer assertion -- bounding is
      # non-empty.
      assert MapSet.size(state.bounding) > 0
    end

    test "matches what /proc/self/status actually contains" do
      {:ok, %State{} = state} = Capabilities.read(:self)
      {:ok, raw} = File.read("/proc/self/status")

      # Cross-check: the bounding mask in /proc/self/status, when
      # turned via from_bits, should equal the parsed bounding set.
      [_, hex] = Regex.run(~r/^CapBnd:\s+([0-9a-fA-F]+)/m, raw)
      expected = Constants.from_bits(String.to_integer(hex, 16))

      assert state.bounding == expected
    end

    test "pid 1 (init/systemd) returns a populated state" do
      # /proc/1/status is world-readable on every Linux distro.
      assert {:ok, %State{} = state} = Capabilities.read(1)

      # init/systemd will always have something in bounding.
      assert MapSet.size(state.bounding) > 0
    end

    test "an out-of-range pid returns a structured ENOENT" do
      assert {:error, %Error{errno: :enoent, operation: :read, code: 2}} =
               Capabilities.read(1_234_567_890)
    end
  end

  describe "K2 write verbs — input validation" do
    # These exercise the caller-side validation paths -- no
    # GenServer.call is made (the {:bad_capability, _} /
    # {:bad_thread_sets, _} short-circuit comes back from the
    # public verb before any session interaction), so we can use
    # an arbitrary pid as the session arg.

    test "drop_bounding/2 rejects unknown cap atoms" do
      assert {:error, {:bad_capability, :cap_made_up}} =
               Capabilities.drop_bounding(self(), [:cap_chown, :cap_made_up])
    end

    test "drop_bounding/2 rejects a non-atom in the caps list" do
      assert {:error, {:bad_capability, 12}} =
               Capabilities.drop_bounding(self(), [12])
    end

    test "set_ambient/2 rejects unknown cap atoms" do
      assert {:error, {:bad_capability, :cap_nonsense}} =
               Capabilities.set_ambient(self(), [:cap_nonsense])
    end

    test "set_thread_sets/2 rejects a missing :effective key" do
      assert {:error, {:bad_thread_sets, {:missing, :effective}}} =
               Capabilities.set_thread_sets(self(),
                 permitted: [],
                 inheritable: []
               )
    end

    test "set_thread_sets/2 rejects a missing :permitted key" do
      assert {:error, {:bad_thread_sets, {:missing, :permitted}}} =
               Capabilities.set_thread_sets(self(),
                 effective: [],
                 inheritable: []
               )
    end

    test "set_thread_sets/2 rejects a missing :inheritable key" do
      assert {:error, {:bad_thread_sets, {:missing, :inheritable}}} =
               Capabilities.set_thread_sets(self(),
                 effective: [],
                 permitted: []
               )
    end

    test "set_thread_sets/2 rejects an unknown cap in :effective" do
      assert {:error, {:bad_capability, :cap_zzz}} =
               Capabilities.set_thread_sets(self(),
                 effective: [:cap_zzz],
                 permitted: [],
                 inheritable: []
               )
    end

    test "set_thread_sets/2 rejects an unknown cap in :inheritable" do
      assert {:error, {:bad_capability, :cap_zzz}} =
               Capabilities.set_thread_sets(self(),
                 effective: [],
                 permitted: [],
                 inheritable: [:cap_zzz]
               )
    end
  end

  describe "K2 write verbs — state-machine guards (real sessions)" do
    # These exercise the actual handle_call clauses in Linx.Process
    # by inducing each state with /bin/sleep and /bin/true. No root
    # needed -- the workloads don't use any namespaces.

    alias Linx.Process, as: P

    test "post-execve: drop_bounding returns :running" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      assert {:error, :running} =
               Capabilities.drop_bounding(session, [:cap_chown])

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "post-execve: set_thread_sets returns :running" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      assert {:error, :running} =
               Capabilities.set_thread_sets(session,
                 effective: [],
                 permitted: [],
                 inheritable: []
               )

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "post-execve: set_ambient returns :running" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      assert {:error, :running} = Capabilities.set_ambient(session, [:cap_chown])

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "post-terminal: drop_bounding returns :no_process" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} =
               Capabilities.drop_bounding(session, [:cap_chown])
    end

    test "post-terminal: set_thread_sets returns :no_process" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} =
               Capabilities.set_thread_sets(session,
                 effective: [],
                 permitted: [],
                 inheritable: []
               )
    end

    test "post-terminal: set_ambient returns :no_process" do
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} =
               Capabilities.set_ambient(session, [:cap_chown])
    end
  end

  describe "K2 — actually applying caps on a real workload" do
    @describetag :integration
    # @describetag (not @moduletag) so the integration tag stays
    # scoped to this block. PR_CAPBSET_DROP / capset need
    # CAP_SETPCAP in :effective of the calling thread, which means
    # these tests need root (./sudotest.sh).

    alias Linx.Process, as: P

    test "drop_bounding/2 removes the cap from CapBnd before execve" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      {:ok, host_pid} = P.host_pid(session)

      # Confirm starting state has the cap (root + no drops -> full).
      {:ok, before} = Capabilities.read(host_pid)
      assert MapSet.member?(before.bounding, :cap_sys_admin)

      :ok = Capabilities.drop_bounding(session, [:cap_sys_admin])

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, after_state} = Capabilities.read(host_pid)
      refute MapSet.member?(after_state.bounding, :cap_sys_admin)

      # Untouched sets are still full.
      assert MapSet.member?(after_state.bounding, :cap_chown)

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "drop_bounding/2 with multiple caps drops all of them at once" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      {:ok, host_pid} = P.host_pid(session)

      drop = [:cap_sys_admin, :cap_sys_module, :cap_dac_override]
      :ok = Capabilities.drop_bounding(session, drop)

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, after_state} = Capabilities.read(host_pid)

      for cap <- drop do
        refute MapSet.member?(after_state.bounding, cap),
               "expected #{inspect(cap)} to be dropped from bounding"
      end

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "set_thread_sets/2 reduces effective/permitted/inheritable" do
      # Wrinkle: root (euid 0) running an unprivileged binary like
      # /bin/sleep triggers the "root execve lift" -- effective and
      # permitted get raised back to whatever's in the bounding
      # set (capabilities(7), "Capabilities and execution of
      # programs by root"). So set_thread_sets's effect on those
      # two sets is invisible post-execve unless we also bound
      # them via drop_bounding. We do both here -- this test
      # covers the composition of set_thread_sets + drop_bounding
      # against root-lift.

      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      {:ok, host_pid} = P.host_pid(session)

      keep = [:cap_chown, :cap_net_bind_service]
      drop = MapSet.difference(Constants.all(), MapSet.new(keep))

      :ok = Capabilities.drop_bounding(session, MapSet.to_list(drop))

      :ok =
        Capabilities.set_thread_sets(session,
          effective: keep,
          permitted: keep,
          inheritable: []
        )

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, state} = Capabilities.read(host_pid)

      # bounding shrank to exactly `keep`.
      assert state.bounding == MapSet.new(keep)
      # effective/permitted got root-lifted up to bounding (=keep).
      assert state.effective == MapSet.new(keep)
      assert state.permitted == MapSet.new(keep)
      # inheritable stays where we set it (root-lift doesn't touch it).
      assert state.inheritable == MapSet.new()

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "set_ambient/2 raises a cap into the ambient set" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      {:ok, host_pid} = P.host_pid(session)

      keep = [:cap_net_bind_service]

      # Ambient requires the cap to be in both :permitted and
      # :inheritable, so we have to set those first via thread sets.
      :ok =
        Capabilities.set_thread_sets(session,
          effective: keep,
          permitted: keep,
          inheritable: keep
        )

      :ok = Capabilities.set_ambient(session, keep)

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, state} = Capabilities.read(host_pid)

      assert state.ambient == MapSet.new(keep)

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "drop_bounding/2 is irreversible across execve (root-lift respects bounding)" do
      # drop_bounding doesn't immediately strip caps from
      # :permitted -- bounding is a *future* ceiling, not a live
      # mask on the running thread. What it *does* prevent is
      # the root-lift on execve from restoring the dropped cap.
      # That's what we verify here: drop bounding, drop the cap
      # from permitted too (so the live thread doesn't carry it),
      # proceed -- and the post-execve thread *still* can't have
      # the cap, even though the binary runs as root.

      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      {:ok, host_pid} = P.host_pid(session)

      :ok = Capabilities.drop_bounding(session, [:cap_sys_admin])

      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      {:ok, state} = Capabilities.read(host_pid)

      # Bounding stays dropped (as in the basic drop test).
      refute MapSet.member?(state.bounding, :cap_sys_admin)

      # Even with root-lift on execve, the lift is masked by
      # bounding -- so cap_sys_admin can never be in :effective
      # or :permitted again on this thread (or any descendant).
      refute MapSet.member?(state.effective, :cap_sys_admin)
      refute MapSet.member?(state.permitted, :cap_sys_admin)

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "capset can't add a cap that's not in current permitted" do
      # The kernel's capset rule: the new :permitted must be a
      # subset of the old :permitted. Verifies the agent surfaces
      # an EPERM-style failure cleanly when the BEAM tries to
      # re-add a previously dropped cap.

      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      # Drop everything from permitted.
      :ok =
        Capabilities.set_thread_sets(session,
          effective: [],
          permitted: [],
          inheritable: []
        )

      # Now try to add cap_chown back. Old permitted is empty;
      # new permitted ⊆ old permitted means new permitted must
      # also be empty. capset returns EPERM.
      :ok =
        Capabilities.set_thread_sets(session,
          effective: [:cap_chown],
          permitted: [:cap_chown],
          inheritable: []
        )

      assert_receive {:linx_process, :error, _errno, :cap_set_thread}, 2_000
    end

    test "set_ambient/2 fails cleanly when the cap isn't in permitted+inheritable" do
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      # Strip permitted/inheritable to nothing, then try to raise
      # an ambient cap. Per capabilities(7), the kernel requires
      # the cap to be in both :permitted and :inheritable before
      # raising into :ambient; this should EPERM.
      :ok =
        Capabilities.set_thread_sets(session,
          effective: [],
          permitted: [],
          inheritable: []
        )

      :ok = Capabilities.set_ambient(session, [:cap_chown])

      assert_receive {:linx_process, :error, _errno, :cap_set_ambient}, 2_000
    end

    test "session terminates cleanly after a cap_* failure path" do
      # When the child fails during a cap command, the agent
      # surfaces the error and the session winds down. The BEAM
      # owner gets the :error message and (eventually, when the
      # port closes) any other terminal it needs.
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok =
        Capabilities.set_thread_sets(session,
          effective: [],
          permitted: [],
          inheritable: []
        )

      :ok =
        Capabilities.set_thread_sets(session,
          effective: [:cap_chown],
          permitted: [:cap_chown],
          inheritable: []
        )

      assert_receive {:linx_process, :error, _errno, :cap_set_thread}, 2_000

      # No :running follows -- the child died before execve.
      refute_receive {:linx_process, :running}, 200
    end
  end
end
