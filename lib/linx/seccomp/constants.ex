defmodule Linx.Seccomp.Constants do
  @moduledoc false
  # Wire-format constants for seccomp's cBPF filter ABI.
  #
  # Two unrelated tables live here:
  #
  #   * BPF opcode primitives — the bit-encoding for cBPF instruction
  #     opcodes (BPF_LD, BPF_W, BPF_ABS, BPF_JEQ, BPF_RET, …) used by
  #     the compiler to emit `struct sock_filter` entries. Sourced
  #     from `include/uapi/linux/bpf_common.h`.
  #
  #   * SECCOMP_RET_* action constants — the high 16 bits of a cBPF
  #     program's return value tell the kernel what to do
  #     (allow / errno / kill_process / kill_thread / trap / log).
  #     Sourced from `include/uapi/linux/seccomp.h`.
  #
  # Plus the AUDIT_ARCH_* constants (from `include/uapi/linux/audit.h`)
  # for the arch-check prologue every seccomp filter starts with.
  #
  # This module is internal — public consumers go through
  # `Linx.Seccomp`. `@moduledoc false` keeps it out of ExDoc, but the
  # test suite asserts the table directly because a wrong constant
  # here means every emitted filter is wrong.

  import Bitwise

  # ── BPF opcode bits ────────────────────────────────────────────
  # Source: include/uapi/linux/bpf_common.h. Each helper returns the
  # bit-mask for one field of an 8-bit BPF opcode; instructions are
  # built by OR-ing the appropriate helpers together (e.g.
  # `bpf_ld() ||| bpf_w() ||| bpf_abs()` = "load a 32-bit word from
  # an absolute offset into A").

  # Instruction class (low 3 bits).
  @doc "BPF_LD = 0x00 — load into A."
  @spec bpf_ld() :: 0x00
  def bpf_ld, do: 0x00

  @doc "BPF_LDX = 0x01 — load into X."
  @spec bpf_ldx() :: 0x01
  def bpf_ldx, do: 0x01

  @doc "BPF_JMP = 0x05 — conditional or unconditional jump."
  @spec bpf_jmp() :: 0x05
  def bpf_jmp, do: 0x05

  @doc "BPF_RET = 0x06 — return from the program."
  @spec bpf_ret() :: 0x06
  def bpf_ret, do: 0x06

  # Size (bits 3–4) — applies to load/store.
  @doc "BPF_W = 0x00 — 32-bit word."
  @spec bpf_w() :: 0x00
  def bpf_w, do: 0x00

  @doc "BPF_H = 0x08 — 16-bit half-word."
  @spec bpf_h() :: 0x08
  def bpf_h, do: 0x08

  @doc "BPF_B = 0x10 — 8-bit byte."
  @spec bpf_b() :: 0x10
  def bpf_b, do: 0x10

  # Addressing mode (bits 5–7).
  @doc "BPF_ABS = 0x20 — absolute offset into the packet (here: into struct seccomp_data)."
  @spec bpf_abs() :: 0x20
  def bpf_abs, do: 0x20

  @doc "BPF_IMM = 0x00 — immediate value."
  @spec bpf_imm() :: 0x00
  def bpf_imm, do: 0x00

  # Source operand (bit 3) for JMP / ALU / RET.
  @doc "BPF_K = 0x00 — operand is the instruction's k field (immediate)."
  @spec bpf_k() :: 0x00
  def bpf_k, do: 0x00

  @doc "BPF_X = 0x08 — operand is the X register."
  @spec bpf_x() :: 0x08
  def bpf_x, do: 0x08

  @doc "BPF_A = 0x10 — operand is the A register (BPF_RET form)."
  @spec bpf_a() :: 0x10
  def bpf_a, do: 0x10

  # Jump condition (bits 4–7) for BPF_JMP.
  @doc "BPF_JA = 0x00 — unconditional jump."
  @spec bpf_ja() :: 0x00
  def bpf_ja, do: 0x00

  @doc "BPF_JEQ = 0x10 — jump if A == operand."
  @spec bpf_jeq() :: 0x10
  def bpf_jeq, do: 0x10

  @doc "BPF_JGT = 0x20 — jump if A > operand."
  @spec bpf_jgt() :: 0x20
  def bpf_jgt, do: 0x20

  @doc "BPF_JGE = 0x30 — jump if A >= operand."
  @spec bpf_jge() :: 0x30
  def bpf_jge, do: 0x30

  @doc "BPF_JSET = 0x40 — jump if A & operand != 0."
  @spec bpf_jset() :: 0x40
  def bpf_jset, do: 0x40

  # ── SECCOMP_RET_* actions ──────────────────────────────────────
  # Source: include/uapi/linux/seccomp.h. The return value of a
  # seccomp BPF program is interpreted by the kernel as
  # `(action << 16) | data`, where `action` selects the verdict and
  # `data` is action-specific (only :errno actually uses data — it
  # carries the errno value to return to the caller).

  # Wire values for the actions Linx supports.
  @seccomp_ret_kill_process 0x80000000
  @seccomp_ret_kill_thread 0x00000000
  @seccomp_ret_trap 0x00030000
  @seccomp_ret_errno 0x00050000
  @seccomp_ret_log 0x7FFC0000
  @seccomp_ret_allow 0x7FFF0000

  # Mask used to split a return value into (action, data).
  @seccomp_ret_action_full 0xFFFF0000
  @seccomp_ret_data 0x0000FFFF

  @doc "The 16-bit-data mask: the low half of every SECCOMP_RET_* value."
  @spec seccomp_ret_data_mask() :: 0xFFFF
  def seccomp_ret_data_mask, do: @seccomp_ret_data

  @doc "The action mask: the high half that names the verdict."
  @spec seccomp_ret_action_mask() :: 0xFFFF0000
  def seccomp_ret_action_mask, do: @seccomp_ret_action_full

  # POSIX errno table for the {:errno, atom} action shape. Kept
  # narrow on purpose — seccomp filters in practice use a handful of
  # values (mostly :eperm and :eacces); callers wanting an obscure
  # errno can pass the integer directly via {:errno, 42}.
  @errno_to_code %{
    eperm: 1,
    enoent: 2,
    eio: 5,
    ebadf: 9,
    enomem: 12,
    eacces: 13,
    efault: 14,
    ebusy: 16,
    enodev: 19,
    einval: 22,
    enosys: 38,
    enotsup: 95,
    eopnotsupp: 95
  }

  @code_to_errno (for {atom, code} <- @errno_to_code,
                      atom not in [:enotsup],
                      into: %{},
                      do: {code, atom})

  @doc """
  Convert a seccomp action to its 32-bit wire value.

  Accepts:

    * `:allow` — `SECCOMP_RET_ALLOW`.
    * `:kill_process` — `SECCOMP_RET_KILL_PROCESS`.
    * `:kill_thread` — `SECCOMP_RET_KILL_THREAD`.
    * `:trap` — `SECCOMP_RET_TRAP`.
    * `:log` — `SECCOMP_RET_LOG`.
    * `{:errno, atom_or_int}` — `SECCOMP_RET_ERRNO | (code & 0xffff)`.
      Atom form uses the small POSIX table baked into this module;
      integer form is passed through unchanged.

  Raises `ArgumentError` on malformed input — caller-side validation
  should catch this before we get here.
  """
  @spec action_to_u32(atom() | {:errno, atom() | non_neg_integer()}) ::
          non_neg_integer()
  def action_to_u32(:allow), do: @seccomp_ret_allow
  def action_to_u32(:kill_process), do: @seccomp_ret_kill_process
  def action_to_u32(:kill_thread), do: @seccomp_ret_kill_thread
  def action_to_u32(:trap), do: @seccomp_ret_trap
  def action_to_u32(:log), do: @seccomp_ret_log

  def action_to_u32({:errno, code}) when is_integer(code) and code >= 0 do
    @seccomp_ret_errno ||| (code &&& @seccomp_ret_data)
  end

  def action_to_u32({:errno, atom}) when is_atom(atom) do
    case Map.fetch(@errno_to_code, atom) do
      {:ok, code} -> @seccomp_ret_errno ||| code
      :error -> raise ArgumentError, "unknown errno atom: #{inspect(atom)}"
    end
  end

  def action_to_u32(other) do
    raise ArgumentError, "unrecognised seccomp action: #{inspect(other)}"
  end

  @doc """
  Convert a 32-bit seccomp return value back to its action atom (or
  `{:errno, atom_or_int}` tuple).

  For `:errno`, the data half is mapped back to a POSIX atom via the
  small table baked into this module; codes outside that table come
  back as the raw integer (forward-compat with future errnos and
  errnos Linx hasn't catalogued).

  An action value the module doesn't recognise comes back as
  `{:unknown, raw_u32}`.
  """
  @spec action_from_u32(non_neg_integer()) ::
          atom()
          | {:errno, atom() | non_neg_integer()}
          | {:unknown, non_neg_integer()}
  def action_from_u32(value) when is_integer(value) and value >= 0 do
    action = value &&& @seccomp_ret_action_full
    data = value &&& @seccomp_ret_data

    case action do
      @seccomp_ret_allow -> :allow
      @seccomp_ret_kill_process -> :kill_process
      @seccomp_ret_kill_thread -> :kill_thread
      @seccomp_ret_trap -> :trap
      @seccomp_ret_log -> :log
      @seccomp_ret_errno -> {:errno, Map.get(@code_to_errno, data, data)}
      _ -> {:unknown, value}
    end
  end

  # ── AUDIT_ARCH_* constants ─────────────────────────────────────
  # Source: include/uapi/linux/audit.h. The first instructions of
  # every seccomp filter check `seccomp_data.arch` against this
  # value; a mismatch falls through to a KILL action. The high byte
  # encodes endianness + 64-bit-ness, the low 24 bits are the
  # `EM_*` ELF machine code for the architecture.

  @doc "AUDIT_ARCH_X86_64 = 0xC000003E (little-endian, 64-bit, EM_X86_64=62)."
  @spec audit_arch_x86_64() :: 0xC000003E
  def audit_arch_x86_64, do: 0xC000003E

  @doc "AUDIT_ARCH_AARCH64 = 0xC00000B7 (little-endian, 64-bit, EM_AARCH64=183)."
  @spec audit_arch_aarch64() :: 0xC00000B7
  def audit_arch_aarch64, do: 0xC00000B7

  @doc """
  Map an arch atom (`:x86_64`, `:aarch64`) to its `AUDIT_ARCH_*`
  numeric value.

  Returns `nil` for any other arch — the seccomp compiler treats
  that as `{:error, {:unsupported_arch, atom}}`.
  """
  @spec audit_arch(atom()) :: non_neg_integer() | nil
  def audit_arch(:x86_64), do: 0xC000003E
  def audit_arch(:aarch64), do: 0xC00000B7
  def audit_arch(_other), do: nil
end
