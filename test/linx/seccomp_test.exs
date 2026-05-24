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

  describe "stub verbs (S1/S2)" do
    test "Linx.Seccomp.allow_list/2 returns {:error, :not_yet_implemented}" do
      assert Seccomp.allow_list([:read, :write]) ==
               {:error, :not_yet_implemented}

      assert Seccomp.allow_list([:read], default: :kill_process) ==
               {:error, :not_yet_implemented}
    end

    test "Linx.Seccomp.deny_list/2 returns {:error, :not_yet_implemented}" do
      assert Seccomp.deny_list([:ptrace]) ==
               {:error, :not_yet_implemented}
    end

    test "Linx.Seccomp.from_rules/1 returns {:error, :not_yet_implemented}" do
      assert Seccomp.from_rules({[{:allow, :read}], :kill_process}) ==
               {:error, :not_yet_implemented}
    end

    test "Linx.Seccomp.to_rules/1 returns {:error, :not_yet_implemented}" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil}
      assert Seccomp.to_rules(f) == {:error, :not_yet_implemented}
    end

    test "Linx.Seccomp.install/2 returns {:error, :not_yet_implemented}" do
      f = %Filter{arch: :x86_64, bpf: <<>>, rules: nil}
      # We pass a fake PID — the stub doesn't dispatch yet.
      assert Seccomp.install(self(), f) ==
               {:error, :not_yet_implemented}
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

    test "build/1 returns {:error, :not_yet_implemented} (stub)" do
      b = Builder.new() |> Builder.allow(:read)
      assert Builder.build(b) == {:error, :not_yet_implemented}
      assert Builder.build(b, default: :kill_process) ==
               {:error, :not_yet_implemented}
    end
  end
end
