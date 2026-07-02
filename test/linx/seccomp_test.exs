defmodule Linx.SeccompTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Linx.Seccomp
  alias Linx.Seccomp.Builder
  alias Linx.Seccomp.Constants
  alias Linx.Seccomp.Filter
  alias Linx.Seccomp.Syscalls

  describe "supported?/0" do
    test "returns a boolean" do
      assert is_boolean(Seccomp.supported?())
    end

    test "agrees with /proc/self/status containing a Seccomp: line" do
      expected =
        case File.read("/proc/self/status") do
          {:ok, data} -> data =~ ~r/^Seccomp:/m
          {:error, _} -> false
        end

      assert Seccomp.supported?() == expected
    end
  end

  describe "arch/0" do
    test "returns one of the known atoms" do
      assert Seccomp.arch() in [:x86_64, :aarch64, :unsupported]
    end

    test "is stable across calls (cached)" do
      a1 = Seccomp.arch()
      a2 = Seccomp.arch()
      assert a1 == a2
    end

    test "matches the BEAM's system architecture token" do
      triple = :erlang.system_info(:system_architecture) |> List.to_string()

      expected =
        cond do
          String.starts_with?(triple, "x86_64") -> :x86_64
          String.starts_with?(triple, "aarch64") -> :aarch64
          true -> :unsupported
        end

      assert Seccomp.arch() == expected
    end
  end

  # ── Linx.Seccomp.Syscalls ────────────────────────────────────

  describe "Linx.Seccomp.Syscalls — x86_64 table" do
    test "to_number/2 maps known atoms to their canonical numbers" do
      # Hand-verified against /usr/include/asm/unistd_64.h.
      assert Syscalls.to_number(:read, :x86_64) == 0
      assert Syscalls.to_number(:write, :x86_64) == 1
      assert Syscalls.to_number(:open, :x86_64) == 2
      assert Syscalls.to_number(:close, :x86_64) == 3
      assert Syscalls.to_number(:mmap, :x86_64) == 9
      assert Syscalls.to_number(:execve, :x86_64) == 59
      assert Syscalls.to_number(:exit_group, :x86_64) == 231
      assert Syscalls.to_number(:openat, :x86_64) == 257
      assert Syscalls.to_number(:setns, :x86_64) == 308
      assert Syscalls.to_number(:seccomp, :x86_64) == 317
      assert Syscalls.to_number(:bpf, :x86_64) == 321
      assert Syscalls.to_number(:clone3, :x86_64) == 435
      assert Syscalls.to_number(:openat2, :x86_64) == 437
      assert Syscalls.to_number(:landlock_create_ruleset, :x86_64) == 444
    end

    test "to_number/2 returns nil for an unknown atom" do
      assert Syscalls.to_number(:not_a_real_syscall, :x86_64) == nil
      assert Syscalls.to_number(:sys_read, :x86_64) == nil
    end

    test "from_number/2 inverts to_number/2 on known entries" do
      assert Syscalls.from_number(0, :x86_64) == :read
      assert Syscalls.from_number(59, :x86_64) == :execve
      assert Syscalls.from_number(231, :x86_64) == :exit_group
      assert Syscalls.from_number(317, :x86_64) == :seccomp
      assert Syscalls.from_number(437, :x86_64) == :openat2
    end

    test "from_number/2 returns :unknown for a number outside the table" do
      assert Syscalls.from_number(999_999, :x86_64) == :unknown
      assert Syscalls.from_number(500, :x86_64) == :unknown
    end

    test "all/1 has at least ~150 syscalls" do
      assert MapSet.size(Syscalls.all(:x86_64)) >= 150
    end

    test "table covers the Docker default-profile denylist" do
      # Sample from https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
      # — the syscalls a real deny-list filter needs to address.
      for s <- ~w(ptrace kexec_load init_module delete_module
                  swapon swapoff mount umount2 pivot_root iopl
                  ioperm reboot bpf)a do
        assert is_integer(Syscalls.to_number(s, :x86_64)),
               "expected :#{s} to be in the x86_64 syscall table"
      end
    end

    test "table covers Linx's own subsystem syscalls" do
      for s <- ~w(setns unshare prctl capget capset seccomp)a do
        assert is_integer(Syscalls.to_number(s, :x86_64))
      end
    end
  end

  describe "Linx.Seccomp.Syscalls — aarch64 table" do
    test "to_number/2 maps known atoms to their canonical numbers" do
      # Hand-verified against include/uapi/asm-generic/unistd.h.
      assert Syscalls.to_number(:read, :aarch64) == 63
      assert Syscalls.to_number(:write, :aarch64) == 64
      assert Syscalls.to_number(:openat, :aarch64) == 56
      assert Syscalls.to_number(:close, :aarch64) == 57
      assert Syscalls.to_number(:mmap, :aarch64) == 222
      assert Syscalls.to_number(:execve, :aarch64) == 221
      assert Syscalls.to_number(:exit_group, :aarch64) == 94
      assert Syscalls.to_number(:setns, :aarch64) == 268
      assert Syscalls.to_number(:seccomp, :aarch64) == 277
      assert Syscalls.to_number(:bpf, :aarch64) == 280
      assert Syscalls.to_number(:clone3, :aarch64) == 435
      assert Syscalls.to_number(:openat2, :aarch64) == 437
      assert Syscalls.to_number(:landlock_create_ruleset, :aarch64) == 444
    end

    test "aarch64 doesn't carry the unsuffixed legacy verbs" do
      # The asm-generic table omits :open / :stat / :poll / :select /
      # :fork / :vfork / :dup2 — callers use the *at / *2 forms.
      assert Syscalls.to_number(:open, :aarch64) == nil
      assert Syscalls.to_number(:stat, :aarch64) == nil
      assert Syscalls.to_number(:poll, :aarch64) == nil
      assert Syscalls.to_number(:select, :aarch64) == nil
      assert Syscalls.to_number(:fork, :aarch64) == nil
      assert Syscalls.to_number(:vfork, :aarch64) == nil
      assert Syscalls.to_number(:dup2, :aarch64) == nil
    end

    test "from_number/2 returns :unknown for a number outside the table" do
      assert Syscalls.from_number(999_999, :aarch64) == :unknown
    end

    test "all/1 has at least ~120 syscalls" do
      assert MapSet.size(Syscalls.all(:aarch64)) >= 120
    end
  end

  describe "Linx.Seccomp.Syscalls — unsupported arch" do
    test "to_number/2 returns nil regardless of syscall" do
      assert Syscalls.to_number(:read, :riscv64) == nil
      assert Syscalls.to_number(:read, :unsupported) == nil
    end

    test "from_number/2 returns :unknown" do
      assert Syscalls.from_number(0, :riscv64) == :unknown
      assert Syscalls.from_number(0, :unsupported) == :unknown
    end

    test "all/1 returns the empty MapSet" do
      assert Syscalls.all(:riscv64) == MapSet.new()
      assert Syscalls.all(:unsupported) == MapSet.new()
    end
  end

  describe "Linx.Seccomp.Syscalls — round-trips" do
    test "x86_64 atoms round-trip through to_number/from_number" do
      for atom <- Syscalls.all(:x86_64) do
        n = Syscalls.to_number(atom, :x86_64)
        assert is_integer(n) and n >= 0
        assert Syscalls.from_number(n, :x86_64) == atom
      end
    end

    test "aarch64 atoms round-trip through to_number/from_number" do
      for atom <- Syscalls.all(:aarch64) do
        n = Syscalls.to_number(atom, :aarch64)
        assert is_integer(n) and n >= 0
        assert Syscalls.from_number(n, :aarch64) == atom
      end
    end

    test "no duplicate numbers within an arch" do
      # If two atoms mapped to the same number, the inverse map
      # would have lost one — count would be smaller than the
      # forward map's count.
      assert map_size_of_inverse(:x86_64) == MapSet.size(Syscalls.all(:x86_64))
      assert map_size_of_inverse(:aarch64) == MapSet.size(Syscalls.all(:aarch64))
    end
  end

  # Build the inverse number → atom map size by going through every
  # atom in the arch's table — a duplicate number would collapse
  # entries and shrink the result.
  defp map_size_of_inverse(arch) do
    Syscalls.all(arch)
    |> Enum.map(fn atom -> Syscalls.to_number(atom, arch) end)
    |> Enum.uniq()
    |> length()
  end

  describe "Linx.Seccomp.Syscalls.arch/0" do
    test "delegates to Linx.Seccomp.arch/0" do
      assert Syscalls.arch() == Seccomp.arch()
    end
  end

  describe "Linx.Seccomp.Syscalls.known?/2" do
    test "reports true/false based on the per-arch table" do
      assert Syscalls.known?(:read, :x86_64)
      assert Syscalls.known?(:read, :aarch64)
      refute Syscalls.known?(:open, :aarch64)
      refute Syscalls.known?(:not_a_real_syscall, :x86_64)
      refute Syscalls.known?(:read, :riscv64)
    end
  end

  # ── Linx.Seccomp.Constants ───────────────────────────────────

  describe "Linx.Seccomp.Constants — BPF opcode primitives" do
    test "instruction classes have the canonical low-3-bit values" do
      assert Constants.bpf_ld() == 0x00
      assert Constants.bpf_ldx() == 0x01
      assert Constants.bpf_jmp() == 0x05
      assert Constants.bpf_ret() == 0x06
    end

    test "size modifiers are in the bits-3-4 slot" do
      assert Constants.bpf_w() == 0x00
      assert Constants.bpf_h() == 0x08
      assert Constants.bpf_b() == 0x10
    end

    test "addressing modes are in the bits-5-7 slot" do
      assert Constants.bpf_abs() == 0x20
      assert Constants.bpf_imm() == 0x00
    end

    test "source operands are in the bit-3 slot" do
      assert Constants.bpf_k() == 0x00
      assert Constants.bpf_x() == 0x08
      assert Constants.bpf_a() == 0x10
    end

    test "jump conditions occupy the bits-4-7 slot" do
      assert Constants.bpf_ja() == 0x00
      assert Constants.bpf_jeq() == 0x10
      assert Constants.bpf_jgt() == 0x20
      assert Constants.bpf_jge() == 0x30
      assert Constants.bpf_jset() == 0x40
    end

    test "load-word-absolute composes as 0x20 (BPF_LD | BPF_W | BPF_ABS)" do
      # The standard opcode used to load fields out of struct
      # seccomp_data in every filter.
      composed = Constants.bpf_ld() ||| Constants.bpf_w() ||| Constants.bpf_abs()
      assert composed == 0x20
    end

    test "return-from-A composes as 0x16 (BPF_RET | BPF_A)" do
      composed = Constants.bpf_ret() ||| Constants.bpf_a()
      assert composed == 0x16
    end

    test "return-from-K composes as 0x06 (BPF_RET | BPF_K)" do
      composed = Constants.bpf_ret() ||| Constants.bpf_k()
      assert composed == 0x06
    end
  end

  describe "Linx.Seccomp.Constants — SECCOMP_RET_* actions" do
    test "action_to_u32/1 maps the simple actions to their canonical values" do
      # Source: include/uapi/linux/seccomp.h.
      assert Constants.action_to_u32(:allow) == 0x7FFF0000
      assert Constants.action_to_u32(:kill_process) == 0x80000000
      assert Constants.action_to_u32(:kill_thread) == 0x00000000
      assert Constants.action_to_u32(:trap) == 0x00030000
      assert Constants.action_to_u32(:log) == 0x7FFC0000
    end

    test "action_to_u32/1 encodes {:errno, atom} in the low 16 bits" do
      assert Constants.action_to_u32({:errno, :eperm}) == 0x00050001
      assert Constants.action_to_u32({:errno, :eacces}) == 0x00050000 + 13
      assert Constants.action_to_u32({:errno, :einval}) == 0x00050000 + 22
    end

    test "action_to_u32/1 encodes {:errno, integer} verbatim" do
      assert Constants.action_to_u32({:errno, 42}) == 0x00050000 + 42
      assert Constants.action_to_u32({:errno, 0}) == 0x00050000
    end

    test "action_to_u32/1 raises on unknown errno atom" do
      assert_raise ArgumentError, ~r/unknown errno atom: :enot_real/, fn ->
        Constants.action_to_u32({:errno, :enot_real})
      end
    end

    test "action_to_u32/1 raises on malformed action" do
      assert_raise ArgumentError, ~r/unrecognised seccomp action/, fn ->
        Constants.action_to_u32(:not_a_real_action)
      end

      assert_raise ArgumentError, ~r/unrecognised seccomp action/, fn ->
        Constants.action_to_u32({:something, :else})
      end
    end

    test "action_from_u32/1 inverts the simple actions" do
      assert Constants.action_from_u32(0x7FFF0000) == :allow
      assert Constants.action_from_u32(0x80000000) == :kill_process
      assert Constants.action_from_u32(0x00000000) == :kill_thread
      assert Constants.action_from_u32(0x00030000) == :trap
      assert Constants.action_from_u32(0x7FFC0000) == :log
    end

    test "action_from_u32/1 maps known errno codes back to atoms" do
      assert Constants.action_from_u32(0x00050001) == {:errno, :eperm}
      assert Constants.action_from_u32(0x00050000 + 13) == {:errno, :eacces}
      assert Constants.action_from_u32(0x00050000 + 22) == {:errno, :einval}
    end

    test "action_from_u32/1 keeps unknown errno codes as integers" do
      assert Constants.action_from_u32(0x00050000 + 200) == {:errno, 200}
    end

    test "action_from_u32/1 wraps unknown actions as {:unknown, _}" do
      # An action value that doesn't match any SECCOMP_RET_* value
      # comes back tagged for the caller to handle.
      assert Constants.action_from_u32(0x12340000) == {:unknown, 0x12340000}
    end

    test "every simple action round-trips" do
      for action <- [:allow, :kill_process, :kill_thread, :trap, :log] do
        assert action |> Constants.action_to_u32() |> Constants.action_from_u32() ==
                 action
      end
    end

    test "{:errno, atom} round-trips for known errnos" do
      for atom <- [:eperm, :enoent, :eio, :ebadf, :enomem, :eacces, :einval] do
        assert {:errno, atom}
               |> Constants.action_to_u32()
               |> Constants.action_from_u32() == {:errno, atom}
      end
    end
  end

  describe "Linx.Seccomp.Constants — AUDIT_ARCH_*" do
    test "audit_arch_x86_64/0 is 0xC000003E" do
      assert Constants.audit_arch_x86_64() == 0xC000003E
    end

    test "audit_arch_aarch64/0 is 0xC00000B7" do
      assert Constants.audit_arch_aarch64() == 0xC00000B7
    end

    test "audit_arch/1 maps arch atoms to their AUDIT_ARCH_* values" do
      assert Constants.audit_arch(:x86_64) == 0xC000003E
      assert Constants.audit_arch(:aarch64) == 0xC00000B7
    end

    test "audit_arch/1 returns nil for unsupported arches" do
      assert Constants.audit_arch(:riscv64) == nil
      assert Constants.audit_arch(:unsupported) == nil
    end
  end

  # ── %Linx.Seccomp.Filter{} ───────────────────────────────────

  describe "%Linx.Seccomp.Filter{}" do
    test "@enforce_keys requires :arch, :bpf, :rules" do
      assert_raise ArgumentError, fn ->
        struct!(Filter, [])
      end

      assert_raise ArgumentError, fn ->
        struct!(Filter, arch: :x86_64)
      end

      assert_raise ArgumentError, fn ->
        struct!(Filter, arch: :x86_64, bpf: <<>>)
      end
    end

    test "construction succeeds with the three required keys" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: {[], :allow}}
      assert f.arch == :x86_64
      assert f.bpf == <<>>
      assert f.rules == {[], :allow}
      assert f.summary == nil
    end

    test "summary is optional and defaults to nil" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil}
      assert f.summary == nil
    end

    test "summary can be set explicitly" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil, summary: "nginx allow-list"}
      assert f.summary == "nginx allow-list"
    end
  end

  describe "%Linx.Seccomp.Filter{} Inspect" do
    test "compact form shows arch, syscall count, and BPF insn count" do
      f = %Filter{
        arch: :x86_64,
        # 3 instructions × 8 bytes each = 24 bytes.
        bpf: :binary.copy(<<0::64>>, 3),
        rules: {[{:allow, :read}, {:allow, :write}], :kill_process}
      }

      assert inspect(f) == "#Linx.Seccomp.Filter<x86_64 2 syscalls, 3 BPF insns>"
    end

    test "shows 0 syscalls when rules are nil (externally-supplied BPF)" do
      f = %Filter{arch: :aarch64, bpf: :binary.copy(<<0::64>>, 5), rules: nil}
      assert inspect(f) == "#Linx.Seccomp.Filter<aarch64 0 syscalls, 5 BPF insns>"
    end

    test "rounds down the BPF instruction count for a half-instruction blob" do
      # Defensive: even if the BPF blob is malformed (not a multiple
      # of 8), the renderer doesn't crash.
      f = %Filter{arch: :x86_64, bpf: <<1, 2, 3, 4>>, rules: nil}
      assert inspect(f) == "#Linx.Seccomp.Filter<x86_64 0 syscalls, 0 BPF insns>"
    end
  end

  # ── Stub verbs ───────────────────────────────────────────────

  # ── Build verbs — happy paths ────────────────────────────────

  describe "Linx.Seccomp.allow_list/2" do
    test "returns a %Filter{} for known syscalls" do
      assert {:ok, %Filter{} = f} = Seccomp.allow_list([:read, :write])
      assert f.arch == Seccomp.arch()
      assert byte_size(f.bpf) > 0
    end

    test "defaults the fallthrough to :kill_process" do
      {:ok, f} = Seccomp.allow_list([:read])
      assert {:ok, {_rules, :kill_process}} = Seccomp.to_rules(f)
    end

    test "honours an explicit :default opt" do
      {:ok, f} = Seccomp.allow_list([:read], default: :log)
      assert {:ok, {_rules, :log}} = Seccomp.to_rules(f)
    end

    test "rules are all {:allow, syscall} in source order" do
      {:ok, f} = Seccomp.allow_list([:read, :write, :openat])
      {:ok, {rules, _}} = Seccomp.to_rules(f)
      assert rules == [{:allow, :read}, {:allow, :write}, {:allow, :openat}]
    end

    test "an empty allow_list compiles to a fall-through-only filter" do
      {:ok, f} = Seccomp.allow_list([], default: :allow)
      # arch prologue (3) + load nr (1) [+ x32 guard (2) on x86_64] +
      # default RET (1).
      expected = if f.arch == :x86_64, do: 7, else: 5
      assert div(byte_size(f.bpf), 8) == expected
    end
  end

  describe "Linx.Seccomp.deny_list/2" do
    test "returns a %Filter{} with the deny action on each listed syscall" do
      {:ok, f} = Seccomp.deny_list([:ptrace, :kexec_load])

      assert {:ok, {rules, :allow}} = Seccomp.to_rules(f)
      assert rules == [{{:errno, :eperm}, :ptrace}, {{:errno, :eperm}, :kexec_load}]
    end

    test "defaults the fallthrough to :allow (Docker-style)" do
      {:ok, f} = Seccomp.deny_list([:ptrace])
      assert {:ok, {_, :allow}} = Seccomp.to_rules(f)
    end

    test "honours :deny_action opt" do
      {:ok, f} = Seccomp.deny_list([:kexec_load], deny_action: :kill_process)
      {:ok, {rules, _}} = Seccomp.to_rules(f)
      assert rules == [{:kill_process, :kexec_load}]
    end

    test "honours both :default and :deny_action opts together" do
      {:ok, f} =
        Seccomp.deny_list([:ptrace], default: :log, deny_action: :kill_thread)

      assert {:ok, {[{:kill_thread, :ptrace}], :log}} = Seccomp.to_rules(f)
    end
  end

  describe "Linx.Seccomp.from_rules/1" do
    test "compiles a mixed rules list to a %Filter{}" do
      rules = [
        {:allow, :read},
        {:allow, :write},
        {{:errno, :eperm}, :ptrace},
        {:kill_process, :kexec_load}
      ]

      assert {:ok, %Filter{} = f} = Seccomp.from_rules({rules, :allow})
      assert {:ok, {^rules, :allow}} = Seccomp.to_rules(f)
    end

    test "preserves source order in the resulting filter's rules" do
      rules = [{:allow, :write}, {:allow, :read}, {:allow, :openat}]
      {:ok, f} = Seccomp.from_rules({rules, :kill_process})
      {:ok, {round_tripped, _}} = Seccomp.to_rules(f)
      assert round_tripped == rules
    end

    test "all valid action shapes pass validation" do
      for action <- [
            :allow,
            :kill_process,
            :kill_thread,
            :trap,
            :log,
            {:errno, :eperm},
            {:errno, :einval},
            {:errno, 42}
          ] do
        assert {:ok, %Filter{}} =
                 Seccomp.from_rules({[{action, :read}], :allow}),
               "expected #{inspect(action)} to validate"
      end
    end

    test "rejects an unknown syscall atom" do
      assert {:error, {:unknown_syscall, :not_a_real_syscall}} =
               Seccomp.from_rules({[{:allow, :not_a_real_syscall}], :allow})
    end

    test "rejects a malformed action" do
      assert {:error, {:bad_action, :not_an_action}} =
               Seccomp.from_rules({[{:not_an_action, :read}], :allow})
    end

    test "rejects a malformed default" do
      assert {:error, {:bad_action, :not_an_action}} =
               Seccomp.from_rules({[{:allow, :read}], :not_an_action})
    end

    test "rejects {:errno, _} with an unknown errno atom" do
      assert {:error, {:bad_action, {:errno, :enot_real}}} =
               Seccomp.from_rules({[{{:errno, :enot_real}, :read}], :allow})
    end

    test "rejects a duplicate syscall" do
      assert {:error, {:duplicate_rule, :read}} =
               Seccomp.from_rules({[{:allow, :read}, {:allow, :read}], :allow})
    end

    test "rejects a duplicate with different actions" do
      # Same syscall, different actions → still a duplicate.
      rules = [{:allow, :read}, {:kill_process, :read}]

      assert {:error, {:duplicate_rule, :read}} =
               Seccomp.from_rules({rules, :allow})
    end

    test "rejects a non-tuple rule" do
      assert {:error, {:bad_rule, :not_a_tuple}} =
               Seccomp.from_rules({[:not_a_tuple], :allow})
    end

    test "rejects a rule with a non-atom syscall" do
      assert {:error, {:bad_rule, {:allow, 0}}} =
               Seccomp.from_rules({[{:allow, 0}], :allow})
    end

    test "rejects a non-tuple argument" do
      assert {:error, {:bad_rules, :nope}} = Seccomp.from_rules(:nope)
    end

    test "short-circuits on the first error" do
      # The :read rule is valid; the :not_real rule fails. Validation
      # stops there.
      rules = [{:allow, :read}, {:allow, :not_real_syscall}, {:allow, :write}]

      assert {:error, {:unknown_syscall, :not_real_syscall}} =
               Seccomp.from_rules({rules, :allow})
    end
  end

  describe "Linx.Seccomp.to_rules/1" do
    test "returns the {rules, default} tuple for a Linx-built filter" do
      rules = [{:allow, :read}, {:allow, :write}]
      {:ok, f} = Seccomp.from_rules({rules, :kill_process})

      assert {:ok, {^rules, :kill_process}} = Seccomp.to_rules(f)
    end

    test "round-trips through from_rules/1" do
      original = [
        {:allow, :read},
        {{:errno, :eacces}, :ptrace},
        {:kill_process, :kexec_load}
      ]

      {:ok, f} = Seccomp.from_rules({original, :log})
      {:ok, round_tripped} = Seccomp.to_rules(f)
      assert round_tripped == {original, :log}
    end

    test "returns {:error, :no_rules} for an externally-supplied filter" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil}
      assert Seccomp.to_rules(f) == {:error, :no_rules}
    end
  end

  describe "Linx.Seccomp.install/2 — input validation" do
    # apply/3 keeps the static type analyser from narrowing the call
    # site; what we want to test is the runtime function-head guard.
    test "requires a %Linx.Seccomp.Filter{} as the second argument" do
      assert_raise FunctionClauseError, fn ->
        apply(Seccomp, :install, [self(), :not_a_filter])
      end
    end

    test "requires a pid as the first argument" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil}

      assert_raise FunctionClauseError, fn ->
        apply(Seccomp, :install, [:not_a_pid, f])
      end
    end
  end

  describe "Linx.Seccomp.install/2 — state-machine guards (real sessions)" do
    # These exercise the actual handle_call clauses in Linx.Process by
    # inducing each state with /bin/sleep and /bin/true. No root needed.
    alias Linx.Process, as: P

    test "post-execve: install returns :running" do
      {:ok, filter} = Seccomp.allow_list([:read, :write, :exit_group])
      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :running}, 2_000

      assert {:error, :running} = Seccomp.install(session, filter)

      :ok = P.signal(session, 9)
      assert_receive {:linx_process, :signaled, 9}, 2_000
    end

    test "post-terminal: install returns :no_process" do
      {:ok, filter} = Seccomp.allow_list([:read, :write, :exit_group])
      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert {:error, :no_process} = Seccomp.install(session, filter)
    end
  end

  describe "Linx.Process.spawn/1 — no_new_privs: opt" do
    alias Linx.Process, as: P

    test "spawn accepts no_new_privs: true and the workload runs to completion" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], no_new_privs: true)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000
    end

    test "spawn accepts no_new_privs: false (the default behaviour)" do
      {:ok, session} = P.spawn(argv: ["/bin/true"], no_new_privs: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(session)
      assert_receive {:linx_process, :exited, 0}, 2_000
    end

    test "spawn rejects a non-boolean :no_new_privs" do
      assert {:error, {:bad_no_new_privs, :yes}} =
               P.spawn(argv: ["/bin/true"], no_new_privs: :yes)
    end
  end

  # ── Linx.Seccomp.Builder ────────────────────────────────────

  describe "Linx.Seccomp.Builder" do
    test "new/0 returns an empty builder" do
      assert Builder.new() == %Builder{rules: []}
    end

    test "Linx.Seccomp.builder/0 is a convenience for Builder.new/0" do
      assert Seccomp.builder() == Builder.new()
    end

    test "allow/2 appends {:allow, syscall}" do
      b = Builder.new() |> Builder.allow(:read) |> Builder.allow(:write)
      # Internal representation is reversed (cons-list build).
      assert b.rules == [{:allow, :write}, {:allow, :read}]
    end

    test "deny/3 defaults to {:errno, :eperm}" do
      b = Builder.new() |> Builder.deny(:ptrace)
      assert b.rules == [{{:errno, :eperm}, :ptrace}]
    end

    test "deny/3 with :errno opt uses the supplied errno atom" do
      b = Builder.new() |> Builder.deny(:ptrace, errno: :eacces)
      assert b.rules == [{{:errno, :eacces}, :ptrace}]
    end

    test "deny/3 with :action opt uses the explicit action" do
      b = Builder.new() |> Builder.deny(:kexec_load, action: :kill_process)
      assert b.rules == [{:kill_process, :kexec_load}]
    end

    test "deny/3 :action wins over :errno when both are given" do
      b = Builder.new() |> Builder.deny(:ptrace, action: :kill_process, errno: :eperm)
      assert b.rules == [{:kill_process, :ptrace}]
    end

    test "rules accumulate across multiple allow/deny calls" do
      b =
        Builder.new()
        |> Builder.allow(:read)
        |> Builder.allow(:write)
        |> Builder.deny(:ptrace)
        |> Builder.deny(:kexec_load, action: :kill_process)

      # Reversed; build/1 reverses back to source order.
      assert b.rules == [
               {:kill_process, :kexec_load},
               {{:errno, :eperm}, :ptrace},
               {:allow, :write},
               {:allow, :read}
             ]
    end

    test "build/1 produces a %Filter{} with rules in source order" do
      assert {:ok, %Filter{} = f} =
               Builder.new()
               |> Builder.allow(:read)
               |> Builder.allow(:write)
               |> Builder.deny(:ptrace)
               |> Builder.build()

      assert {:ok, {rules, :kill_process}} = Seccomp.to_rules(f)

      assert rules == [
               {:allow, :read},
               {:allow, :write},
               {{:errno, :eperm}, :ptrace}
             ]
    end

    test "build/1 defaults the fallthrough to :kill_process" do
      {:ok, f} = Builder.new() |> Builder.allow(:read) |> Builder.build()
      assert {:ok, {_, :kill_process}} = Seccomp.to_rules(f)
    end

    test "build/1 honours the :default opt" do
      {:ok, f} =
        Builder.new()
        |> Builder.deny(:ptrace)
        |> Builder.build(default: :allow)

      assert {:ok, {_, :allow}} = Seccomp.to_rules(f)
    end

    test "build/1 surfaces validation errors from from_rules/1" do
      assert {:error, {:unknown_syscall, :not_a_real_syscall}} =
               Builder.new()
               |> Builder.allow(:not_a_real_syscall)
               |> Builder.build()

      assert {:error, {:duplicate_rule, :read}} =
               Builder.new()
               |> Builder.allow(:read)
               |> Builder.allow(:read)
               |> Builder.build()
    end

    test "build/1 of an empty builder gives a minimal fall-through filter" do
      {:ok, f} = Builder.new() |> Builder.build(default: :allow)
      # 5 insns, +2 for the x32 guard on x86_64.
      expected = if f.arch == :x86_64, do: 7, else: 5
      assert div(byte_size(f.bpf), 8) == expected
    end
  end

  # ── Compiler — direct unit tests (golden bytes) ──────────────

  alias Linx.Seccomp.Compiler

  # The x86_64 prologue carries a 2-insn x32-ABI guard after `ld nr`:
  #   jge 0x40000000, jt=0, jf=1   (x32 bit set, or negative nr)
  #   ret KILL_PROCESS
  @x32_guard <<0x35, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40>> <>
               <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80>>

  describe "Linx.Seccomp.Compiler — empty rules / x86_64" do
    test "empty allow filter is 7 instructions / 56 bytes" do
      {:ok, bpf} = Compiler.compile([], :allow, :x86_64)
      assert byte_size(bpf) == 56
    end

    test "empty allow filter has the canonical bytes" do
      {:ok, bpf} = Compiler.compile([], :allow, :x86_64)

      # Hand-decoded against include/uapi/linux/{filter,seccomp,audit}.h.
      # ld [4] (load arch into A)
      # jeq AUDIT_ARCH_X86_64=0xC000003E, jt=1, jf=0
      # ret KILL_PROCESS = 0x80000000 (arch mismatch fall-through)
      # ld [0] (load syscall nr into A)
      # jge __X32_SYSCALL_BIT=0x40000000, jt=0, jf=1 (x32/negative nr guard)
      # ret KILL_PROCESS (x32 fall-through)
      # ret ALLOW = 0x7FFF0000 (default)
      expected =
        <<0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00>> <>
          <<0x15, 0x00, 0x01, 0x00, 0x3E, 0x00, 0x00, 0xC0>> <>
          <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80>> <>
          <<0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00>> <>
          @x32_guard <>
          <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x7F>>

      assert bpf == expected
    end

    test "empty deny filter (default kill_process) ends with ret KILL_PROCESS" do
      {:ok, bpf} = Compiler.compile([], :kill_process, :x86_64)
      # Last 8 bytes = the default RET instruction.
      <<_::48-bytes, last::binary>> = bpf
      assert last == <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80>>
    end
  end

  describe "Linx.Seccomp.Compiler — x32-ABI guard (C2)" do
    test "every x86_64 filter carries the x32 trap right after ld nr" do
      # A deny-list with default :allow is the fail-open case the guard
      # exists for: without it, `ptrace` entered via the x32 ABI
      # (0x40000000 | 101) matches no JEQ and falls through to ALLOW.
      {:ok, bpf} =
        Compiler.compile([{{:errno, :eperm}, :ptrace}], :allow, :x86_64)

      <<_prologue::32-bytes, guard::16-bytes, _rest::binary>> = bpf
      assert guard == @x32_guard
    end

    test "aarch64 filters carry no x32 guard (no x32 ABI there)" do
      {:ok, bpf} = Compiler.compile([], :allow, :aarch64)
      refute :binary.match(bpf, @x32_guard) != :nomatch
      # 5 insns: arch prologue (3) + ld nr (1) + default RET (1).
      assert div(byte_size(bpf), 8) == 5
    end
  end

  describe "Linx.Seccomp.Compiler — single rule / x86_64" do
    test "[{:allow, :read}] + default :kill_process is 9 insns" do
      {:ok, bpf} = Compiler.compile([{:allow, :read}], :kill_process, :x86_64)
      assert div(byte_size(bpf), 8) == 9
    end

    test "has the canonical byte layout" do
      {:ok, bpf} = Compiler.compile([{:allow, :read}], :kill_process, :x86_64)

      # ld [4]
      # jeq AUDIT_ARCH_X86_64, jt=1, jf=0
      # ret KILL_PROCESS (arch mismatch)
      # ld [0]
      # jge 0x40000000, jt=0, jf=1 (x32 guard)
      # ret KILL_PROCESS (x32)
      # jeq __NR_read=0, jt=1 (skip default RET, land on ALLOW), jf=0
      # ret KILL_PROCESS (default)
      # ret ALLOW (per-rule)
      expected =
        <<0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00>> <>
          <<0x15, 0x00, 0x01, 0x00, 0x3E, 0x00, 0x00, 0xC0>> <>
          <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80>> <>
          <<0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00>> <>
          @x32_guard <>
          <<0x15, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00>> <>
          <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80>> <>
          <<0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x7F>>

      assert bpf == expected
    end
  end

  describe "Linx.Seccomp.Compiler — multi-rule shared actions" do
    test "two :allow rules share one ret ALLOW (10 insns, not 11)" do
      # rules with the same action share one terminal RET, so:
      # 3 (prologue) + 1 (ld nr) + 2 (x32 guard) + 2 (JEQs) + 1 (default RET)
      # + 1 (allow RET) = 10
      {:ok, bpf} =
        Compiler.compile([{:allow, :read}, {:allow, :write}], :kill_process, :x86_64)

      assert div(byte_size(bpf), 8) == 10
    end

    test "two rules with distinct actions get distinct terminal RETs" do
      # 3 + 1 + 2 + 2 + 1 + 2 = 11 insns
      {:ok, bpf} =
        Compiler.compile(
          [{:allow, :read}, {{:errno, :eperm}, :ptrace}],
          :kill_process,
          :x86_64
        )

      assert div(byte_size(bpf), 8) == 11
    end

    test "rule with action == default reuses the default RET" do
      # default :kill_process, rule action :kill_process — no extra RET.
      # 3 + 1 + 2 + 1 + 1 = 8 insns
      {:ok, bpf} =
        Compiler.compile([{:kill_process, :ptrace}], :kill_process, :x86_64)

      assert div(byte_size(bpf), 8) == 8
    end
  end

  describe "Linx.Seccomp.Compiler — aarch64" do
    test "uses AUDIT_ARCH_AARCH64 in the arch check" do
      {:ok, bpf} = Compiler.compile([], :allow, :aarch64)

      # The arch JEQ is at byte offset 8 (second instruction).
      # Its k-field (last 4 bytes of the 8-byte slot) holds AUDIT_ARCH.
      <<_::8-bytes, _::4-bytes, audit::32-little, _::binary>> = bpf
      assert audit == 0xC00000B7
    end

    test "uses aarch64 syscall numbers when resolving rules" do
      {:ok, bpf} = Compiler.compile([{:allow, :read}], :kill_process, :aarch64)
      # The JEQ for :read is the 5th instruction (index 4); its k-field
      # holds the syscall number, which is 63 on aarch64.
      <<_::32-bytes, _::4-bytes, nr::32-little, _::binary>> = bpf
      assert nr == 63
    end
  end

  describe "Linx.Seccomp.Compiler — error paths" do
    test "rejects an unsupported arch" do
      assert {:error, {:unsupported_arch, :riscv64}} =
               Compiler.compile([{:allow, :read}], :allow, :riscv64)
    end

    test "rejects a syscall not in the per-arch table" do
      assert {:error, {:unknown_syscall, :open}} =
               Compiler.compile([{:allow, :open}], :allow, :aarch64)
    end

    test "errors with E2BIG on a jump that would overflow the 8-bit jt slot" do
      # The hand-curated syscall tables (239 entries on x86_64, 214
      # on aarch64) aren't large enough to construct an overflow
      # naturally — we'd need ~256 distinct rules with distinct
      # actions. We exercise the path with synthetic pre-resolved
      # tuples via the doc-false `emit_resolved/3` hook.
      #
      # 280 rules, each with a unique {:errno, i} action — the worst-
      # case rule (the last) has jt = N = 280 > 255 → overflow.
      resolved =
        for i <- 0..279 do
          {{:errno, i}, :synthetic_sc, i + 1000}
        end

      audit_arch_x86_64 = 0xC000003E

      assert {:error, %Linx.Seccomp.Error{operation: :build, errno: :e2big}} =
               Compiler.emit_resolved(resolved, :allow, audit_arch_x86_64)
    end

    test "succeeds at exactly the boundary (jt == 255)" do
      # 255 unique rules → last rule's jt = N = 255 — exactly at the
      # limit, still accepted.
      resolved =
        for i <- 0..254 do
          {{:errno, i}, :synthetic_sc, i + 1000}
        end

      audit_arch_x86_64 = 0xC000003E

      assert {:ok, _bpf} =
               Compiler.emit_resolved(resolved, :allow, audit_arch_x86_64)
    end
  end

  # ── Linx.Seccomp.Error ───────────────────────────────────────

  alias Linx.Seccomp.Error

  describe "Linx.Seccomp.Error" do
    test "@enforce_keys requires :operation and :errno" do
      assert_raise ArgumentError, fn -> struct!(Error, []) end
      assert_raise ArgumentError, fn -> struct!(Error, operation: :build) end
      assert_raise ArgumentError, fn -> struct!(Error, errno: :einval) end
    end

    test "from_posix/2 fills in :code from the POSIX table" do
      e = Error.from_posix(:einval, :build)
      assert e.operation == :build
      assert e.errno == :einval
      assert e.code == 22
    end

    test "from_posix/2 fills in :code as nil for atoms outside the table" do
      e = Error.from_posix(:something_made_up, :install)
      assert e.code == nil
      assert e.errno == :something_made_up
    end

    test "knows :e2big as errno 7 (filter too large)" do
      e = Error.from_posix(:e2big, :build)
      assert e.code == 7
    end

    test "implements Exception" do
      e = Error.from_posix(:einval, :build)
      assert Exception.message(e) =~ "seccomp build failed: einval (errno 22)"
    end

    test "Exception message omits errno code when nil" do
      e = Error.from_posix(:something_made_up, :install)
      assert Exception.message(e) == "seccomp install failed: something_made_up"
    end

    test "can be raised" do
      e = Error.from_posix(:einval, :build)
      assert_raise Error, ~r/seccomp build failed: einval/, fn -> raise e end
    end
  end

  # ── Kernel-acceptance — hand a real filter to seccomp(2) ─────
  #
  # These tests spawn a small Python helper (test/support/seccomp_check.py)
  # that does PR_SET_NO_NEW_PRIVS + seccomp(SECCOMP_SET_MODE_FILTER, …)
  # on a fork()ed child, then exits with 0 on acceptance / errno on
  # rejection. The same syscall path Linx will use from
  # c_src/linx_process.c in S2. They need NO privilege (NNP makes
  # seccomp(2) work unprivileged) — only python3 on PATH — so they run
  # in the default suite and in CI, where they are the only guard
  # against a fail-open miscompile (e.g. a missing x32 trap). Skipped,
  # not excluded, when python3 is absent.

  @moduletag_helper Path.join([
                      File.cwd!(),
                      "test/support/seccomp_check.py"
                    ])

  describe "kernel acceptance (compiled filter installs cleanly)" do
    if System.find_executable("python3") == nil do
      @describetag skip: "python3 not on PATH"
    end

    test "an allow-list with exit_group installs successfully" do
      # exit_group must be allowed so the child can return 0 cleanly
      # after install; without it the child is SIGSYS'd during
      # teardown (which the helper still treats as acceptance, but
      # this test wants the clean path).
      {:ok, filter} = Seccomp.allow_list(~w(exit_group read write)a)

      assert run_helper(filter.bpf) == 0
    end

    test "a deny-list with EPERM-on-ptrace installs successfully" do
      {:ok, filter} = Seccomp.deny_list([:ptrace])

      assert run_helper(filter.bpf) == 0
    end

    test "the empty fall-through-allow filter installs successfully" do
      {:ok, filter} = Seccomp.allow_list([], default: :allow)

      assert run_helper(filter.bpf) == 0
    end

    test "a complex multi-action filter installs successfully" do
      rules = [
        {:allow, :read},
        {:allow, :write},
        {:allow, :exit_group},
        {{:errno, :eperm}, :ptrace},
        {:kill_process, :kexec_load},
        {:log, :openat}
      ]

      {:ok, filter} = Seccomp.from_rules({rules, :allow})

      assert run_helper(filter.bpf) == 0
    end

    test "a Builder-produced filter installs successfully" do
      {:ok, filter} =
        Seccomp.builder()
        |> Builder.allow(:exit_group)
        |> Builder.allow(:read)
        |> Builder.deny(:ptrace)
        |> Builder.build(default: :allow)

      assert run_helper(filter.bpf) == 0
    end

    test "a deliberately malformed blob is rejected with EINVAL (22)" do
      # Eight zero bytes — one "instruction" but with code=0, which the
      # kernel rejects as an invalid BPF program.
      assert run_helper(<<0::64>>) == 22
    end

    test "an empty BPF blob is rejected with EINVAL (22)" do
      assert run_helper(<<>>) == 22
    end
  end

  # ── End-to-end: install a filter on a real workload ──────────
  #
  # These run a workload under a Linx-built seccomp filter and observe
  # the kernel honouring it. The cap-flow analogue lives in
  # test/linx/capabilities_test.exs's "K2 — actually applying caps on
  # a real workload" describe. No privilege needed: the agent auto-sets
  # PR_SET_NO_NEW_PRIVS inside child_read_command if it isn't on, and
  # with NNP seccomp(2) works unprivileged — so these run in the
  # default suite and in CI. Only the caps-composition test below
  # stays :integration (cap_drop_bounding needs root).

  describe "end-to-end: install/2 against a real workload" do
    alias Linx.Process, as: P

    test "malformed BPF surfaces as :seccomp_install with EINVAL" do
      # One all-zero instruction — no RET; the kernel rejects with
      # EINVAL the moment seccomp(2) tries to load it. The
      # {:linx_process, :error, errno, stage} message *is* the
      # terminal event (handle_agent_frame finalises on it).
      bad = %Filter{arch: :x86_64, bpf: <<0::64>>, rules: nil}

      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Seccomp.install(session, bad)

      # 22 = EINVAL.
      assert_receive {:linx_process, :error, 22, :seccomp_install}, 2_000
    end

    test "permissive (default :allow) filter lets /bin/true run to exit 0" do
      # The cheapest end-to-end sanity check: a filter that doesn't
      # deny anything. Just exercises the install path.
      {:ok, filter} = Seccomp.deny_list([], default: :allow)

      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Seccomp.install(session, filter)
      :ok = P.proceed(session)

      assert_receive {:linx_process, :exited, 0}, 5_000
    end

    test "deny :clock_nanosleep with EPERM — /bin/sleep returns non-zero quickly" do
      # /bin/sleep on a modern glibc calls clock_nanosleep (older
      # builds use nanosleep). We deny both so the test is robust.
      {:ok, filter} =
        Seccomp.deny_list([:clock_nanosleep, :nanosleep],
          deny_action: {:errno, :eperm}
        )

      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Seccomp.install(session, filter)
      :ok = P.proceed(session)

      # The sleep syscall returns -1 with errno EPERM. /bin/sleep
      # prints an error and exits non-zero. Should be well under 60s.
      assert_receive {:linx_process, :exited, exit_code}, 5_000
      assert is_integer(exit_code) and exit_code != 0
    end

    test "deny :clock_nanosleep with :kill_process — /bin/sleep dies with SIGSYS" do
      {:ok, filter} =
        Seccomp.deny_list([:clock_nanosleep, :nanosleep],
          deny_action: :kill_process
        )

      {:ok, session} = P.spawn(argv: ["/bin/sleep", "60"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Seccomp.install(session, filter)
      :ok = P.proceed(session)

      # SIGSYS is signal 31 on x86_64/aarch64 Linux.
      assert_receive {:linx_process, :signaled, 31}, 5_000
    end

    test "no_new_privs: true on spawn pre-sets NNP; install still succeeds" do
      {:ok, filter} = Seccomp.deny_list([], default: :allow)

      {:ok, session} =
        P.spawn(argv: ["/bin/true"], no_new_privs: true)

      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Seccomp.install(session, filter)
      :ok = P.proceed(session)

      assert_receive {:linx_process, :exited, 0}, 5_000
    end

    # Root-only: cap_drop_bounding needs CAP_SETPCAP.
    @tag :integration
    test "composition with K2 caps — drop bounding + install, both apply" do
      # Verifies the K2 + S2 stack at the same checkpoint: cap_drop
      # and seccomp_install share the await_proceed dispatch, so a
      # session that uses both exercises the full command-frame
      # multiplexing.
      {:ok, filter} = Seccomp.deny_list([], default: :allow)

      {:ok, session} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000

      :ok = Linx.Capabilities.drop_bounding(session, [:cap_sys_module])
      :ok = Seccomp.install(session, filter)
      :ok = P.proceed(session)

      assert_receive {:linx_process, :exited, 0}, 5_000
    end
  end

  # Spawn the python helper, write `bpf` to a temp file, return the
  # helper's exit code.
  defp run_helper(bpf) do
    helper = @moduletag_helper

    unless File.exists?(helper) do
      flunk("seccomp_check.py helper missing at #{helper}")
    end

    path =
      Path.join(
        System.tmp_dir!(),
        "linx_seccomp_test_#{System.unique_integer([:positive])}.bin"
      )

    File.write!(path, bpf)

    try do
      {_output, exit_code} =
        System.cmd("python3", [helper, path], stderr_to_stdout: true)

      exit_code
    after
      File.rm(path)
    end
  end
end
