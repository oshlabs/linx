defmodule Linx.SeccompCompilerPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Seccomp.{Compiler, Constants, Syscalls}

  defp action do
    one_of([
      member_of([:allow, :kill_process, :kill_thread, :trap, :log]),
      map(integer(0..0xFFFF), &{:errno, &1})
    ])
  end

  defp filter_case do
    gen all(
          arch <- member_of([:x86_64, :aarch64]),
          rules <- list_of(tuple({action(), syscall(arch)}), max_length: 32),
          default <- action(),
          queried_syscall <- syscall(arch)
        ) do
      {arch, rules, default, queried_syscall}
    end
  end

  defp syscall(arch), do: arch |> Syscalls.all() |> Enum.to_list() |> member_of()

  property "compiled filters return the first matching rule or the default" do
    check all({arch, rules, default, queried_syscall} <- filter_case()) do
      assert {:ok, bpf} = Compiler.compile(rules, default, arch)

      expected =
        rules
        |> Enum.find_value(default, fn
          {action, ^queried_syscall} -> action
          _other -> nil
        end)
        |> Constants.action_to_u32()

      nr = Syscalls.to_number(queried_syscall, arch)
      assert evaluate(bpf, Constants.audit_arch(arch), nr) == expected
    end
  end

  property "the architecture prologue kills mismatched architectures" do
    check all({arch, rules, default, queried_syscall} <- filter_case()) do
      assert {:ok, bpf} = Compiler.compile(rules, default, arch)
      other_arch = if arch == :x86_64, do: :aarch64, else: :x86_64
      nr = Syscalls.to_number(queried_syscall, arch)

      assert evaluate(bpf, Constants.audit_arch(other_arch), nr) ==
               Constants.action_to_u32(:kill_process)
    end
  end

  property "x86_64 filters kill every x32 syscall number" do
    check all(
            rules <- list_of(tuple({action(), syscall(:x86_64)}), max_length: 32),
            default <- action(),
            syscall <- syscall(:x86_64)
          ) do
      assert {:ok, bpf} = Compiler.compile(rules, default, :x86_64)
      x32_nr = 0x40000000 + Syscalls.to_number(syscall, :x86_64)

      assert evaluate(bpf, Constants.audit_arch_x86_64(), x32_nr) ==
               Constants.action_to_u32(:kill_process)
    end
  end

  # Interpreter for the four cBPF instruction forms emitted by Compiler.
  # PC jumps use the kernel's "next instruction + offset" convention.
  defp evaluate(bpf, arch, nr) do
    instructions =
      for <<code::16-little, jt::8, jf::8, k::32-little <- bpf>>, do: {code, jt, jf, k}

    run(instructions, 0, 0, %{0 => nr, 4 => arch})
  end

  defp run(instructions, pc, accumulator, data) do
    case Enum.fetch!(instructions, pc) do
      {0x20, 0, 0, offset} ->
        run(instructions, pc + 1, Map.fetch!(data, offset), data)

      {0x15, jt, jf, value} ->
        offset = if accumulator == value, do: jt, else: jf
        run(instructions, pc + 1 + offset, accumulator, data)

      {0x35, jt, jf, value} ->
        offset = if accumulator >= value, do: jt, else: jf
        run(instructions, pc + 1 + offset, accumulator, data)

      {0x06, 0, 0, value} ->
        value
    end
  end
end
