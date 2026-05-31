defmodule Linx.Seccomp.Compiler do
  @moduledoc false
  # cBPF emitter.
  #
  # Takes a list of validated `{action, syscall_atom}` rules + a
  # default action + a target arch atom and emits a binary cBPF
  # program ready to be packed into `struct sock_fprog` for
  # `seccomp(SECCOMP_SET_MODE_FILTER, …)`.
  #
  # ## Layout
  #
  # Every emitted filter has the same structure (numbers are
  # instruction indices, not byte offsets):
  #
  #     0: ld   [4]            ; load seccomp_data.arch into A
  #     1: jeq  AUDIT_ARCH, jt=1, jf=0
  #     2: ret  KILL_PROCESS   ; arch mismatch (fall-through from 1)
  #     3: ld   [0]            ; load seccomp_data.nr into A
  #     4..3+N: per-rule JEQ block
  #         jeq  nr_i, jt=offset_to_action_i, jf=0
  #         (falls through to the next JEQ on miss; jumps forward to
  #          the action RET on hit)
  #     4+N: ret default       ; nothing matched
  #     4+N+1...: one RET per unique non-default action, in source
  #              order (rules whose action equals the default reuse
  #              the default RET to save instructions)
  #
  # `struct seccomp_data` field offsets (from `linux/seccomp.h`):
  # nr=0 (s32), arch=4 (u32), instruction_pointer=8 (u64),
  # args[6]=16 (6 × u64).
  #
  # ## Wire format
  #
  # `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }` — 8
  # bytes per instruction, little-endian on both x86_64 and aarch64.
  #
  # ## Jump distance limits
  #
  # cBPF jumps are forward-only with 8-bit `jt`/`jf` offsets — max
  # skip of 255 instructions. With ~150 syscalls in the hand-curated
  # table and at most a handful of distinct actions, real filters
  # land far under this; the compiler errors with
  # `Linx.Seccomp.Error{operation: :build, errno: :e2big}` if a
  # filter would overflow. Trampoline-based splitting is deferred.

  import Bitwise

  alias Linx.Seccomp.Constants
  alias Linx.Seccomp.Error
  alias Linx.Seccomp.Syscalls

  # struct seccomp_data offsets.
  @nr_offset 0
  @arch_offset 4

  # 8-bit jt/jf upper bound.
  @max_jump 255

  @doc """
  Compile a normalised rules list to a cBPF binary.

  `rules` is a list of `{action, syscall_atom}` tuples. Both the
  actions and the syscalls must already be validated by the caller
  — the compiler errors only on (1) unsupported arch, (2) syscall
  atoms missing from the per-arch table, or (3) jump overflow.

  Returns `{:ok, bpf}` where `bpf` is the binary in
  `struct sock_filter` array form, or `{:error, term}` where the
  term shapes are:

    * `{:unsupported_arch, arch}`
    * `{:unknown_syscall, atom}`
    * `%Linx.Seccomp.Error{operation: :build, errno: :e2big}` — the
      filter would need a jump > 255 instructions
  """
  @spec compile([{term(), atom()}], term(), atom()) ::
          {:ok, binary()} | {:error, term()}
  def compile(rules, default_action, arch)
      when is_list(rules) and is_atom(arch) do
    with {:ok, audit_arch} <- audit_arch(arch),
         {:ok, resolved} <- resolve_syscalls(rules, arch) do
      emit(resolved, default_action, audit_arch)
    end
  end

  defp audit_arch(arch) do
    case Constants.audit_arch(arch) do
      nil -> {:error, {:unsupported_arch, arch}}
      n -> {:ok, n}
    end
  end

  # Resolve every rule's syscall atom to a number on the target arch
  # while preserving source order. Halts on the first unknown atom.
  defp resolve_syscalls(rules, arch) do
    resolved =
      Enum.reduce_while(rules, [], fn {action, syscall}, acc ->
        case Syscalls.to_number(syscall, arch) do
          nil -> {:halt, {:error, {:unknown_syscall, syscall}}}
          n -> {:cont, [{action, syscall, n} | acc]}
        end
      end)

    case resolved do
      {:error, _} = e -> e
      list -> {:ok, Enum.reverse(list)}
    end
  end

  @doc false
  # Emit a filter from rules already resolved to `{action, syscall_atom, nr}`
  # tuples + an explicit AUDIT_ARCH numeric value. Exposed only so the
  # jump-overflow path can be exercised with synthetic inputs that
  # would otherwise require a syscall table > 256 entries — the
  # hand-curated tables are smaller, so the overflow is currently
  # unreachable via `compile/3` proper.
  def emit_resolved(resolved, default_action, audit_arch_value)
      when is_list(resolved) and is_integer(audit_arch_value) do
    emit(resolved, default_action, audit_arch_value)
  end

  # Emit the full filter program for the resolved rules.
  defp emit(resolved, default_action, audit_arch_value) do
    arch_check_size = 3
    load_nr_size = 1
    jeq_count = length(resolved)
    default_index = arch_check_size + load_nr_size + jeq_count

    # Walk the rules in source order, assigning a RET-index to each
    # unique action. The default action already lives at
    # `default_index`; per-rule actions equal to the default reuse
    # that slot (no separate RET needed). Other actions get fresh
    # slots immediately after the default RET, in first-seen order.
    {action_to_index, action_list_rev, _} =
      Enum.reduce(resolved, {%{default_action => default_index}, [], 0}, fn
        {action, _, _}, {acc, list, n} ->
          if Map.has_key?(acc, action) do
            {acc, list, n}
          else
            {Map.put(acc, action, default_index + 1 + n), [action | list], n + 1}
          end
      end)

    action_list = Enum.reverse(action_list_rev)

    # Compute jt for each JEQ. jt counts instructions to skip on a
    # match — PC after the JEQ is at pos+1, so a jt of k lands at
    # pos+1+k. Hence jt = target - pos - 1.
    jeq_specs =
      resolved
      |> Enum.with_index()
      |> Enum.map(fn {{action, _syscall, nr}, i} ->
        pos = arch_check_size + load_nr_size + i
        target = Map.fetch!(action_to_index, action)
        {nr, target - pos - 1}
      end)

    case Enum.find(jeq_specs, fn {_nr, jt} -> jt > @max_jump end) do
      nil ->
        {:ok, encode(jeq_specs, action_list, default_action, audit_arch_value)}

      _overflow ->
        {:error, Error.from_posix(:e2big, :build)}
    end
  end

  defp encode(jeq_specs, action_list, default_action, audit_arch_value) do
    kill_u32 = Constants.action_to_u32(:kill_process)
    default_u32 = Constants.action_to_u32(default_action)

    prologue = [
      bpf_ld_word_abs(@arch_offset),
      bpf_jeq_k(audit_arch_value, 1, 0),
      bpf_ret_k(kill_u32),
      bpf_ld_word_abs(@nr_offset)
    ]

    jeq_insns = Enum.map(jeq_specs, fn {nr, jt} -> bpf_jeq_k(nr, jt, 0) end)

    default_ret = bpf_ret_k(default_u32)

    action_insns =
      Enum.map(action_list, fn action ->
        bpf_ret_k(Constants.action_to_u32(action))
      end)

    IO.iodata_to_binary(prologue ++ jeq_insns ++ [default_ret] ++ action_insns)
  end

  # ── BPF instruction helpers ────────────────────────────────────
  # struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; } — packed,
  # little-endian on both supported arches.

  defp bpf_ld_word_abs(offset) do
    code = Constants.bpf_ld() ||| Constants.bpf_w() ||| Constants.bpf_abs()
    insn(code, 0, 0, offset)
  end

  defp bpf_jeq_k(k, jt, jf) do
    code = Constants.bpf_jmp() ||| Constants.bpf_jeq() ||| Constants.bpf_k()
    insn(code, jt, jf, k)
  end

  defp bpf_ret_k(k) do
    code = Constants.bpf_ret() ||| Constants.bpf_k()
    insn(code, 0, 0, k)
  end

  defp insn(code, jt, jf, k) do
    <<code::16-little, jt::8, jf::8, k::32-little>>
  end
end
