defmodule Mix.Linx.Preflight do
  @moduledoc false
  # Shared preflight for the native compilers (`compile.netlink_nif`,
  # `compile.linx_process`, etc.). Run at the top of each task's `run/1`, before
  # any `cc` invocation, so a build on the wrong machine fails (or warns) with a
  # clear, actionable message instead of a raw compiler dump.
  #
  # Guards only — the shared compile scaffolding lives in `Mix.Linx.CC`.

  # The supported kernel floor, matching the README. The C syscall-availability
  # floor is lower (~5.8); this is the version Linx is built and tested against.
  @kernel_floor {6, 6}

  @doc "Platform/toolchain preflight. `cc` is the C compiler command."
  @spec check!(String.t()) :: :ok
  def check!(cc) do
    os_guard!()
    cc_guard!(cc)
    kernel_warn()
    :ok
  end

  defp os_guard! do
    case :os.type() do
      {:unix, :linux} ->
        :ok

      other ->
        Mix.raise(
          "Linx provides Linux kernel interfaces and only builds on Linux. " <>
            "Detected: #{inspect(other)}. See the README requirements."
        )
    end
  end

  defp cc_guard!(cc) do
    if System.find_executable(cc) do
      :ok
    else
      Mix.raise(
        "Linx needs a C compiler (`#{cc}`) to build its native code, but none was " <>
          "found on PATH. Install one — Debian/Ubuntu: `sudo apt install build-essential`; " <>
          "Arch: `sudo pacman -S base-devel` — or set the `CC` environment variable. " <>
          "See the README build prerequisites."
      )
    end
  end

  # Warn (do not fail) when the build-host kernel is below the supported floor:
  # cross-compiling for a newer target (e.g. Nerves) is legitimate. Emitted once
  # per `mix compile`, not once per native compiler.
  defp kernel_warn do
    if :persistent_term.get({__MODULE__, :warned}, false) do
      :ok
    else
      :persistent_term.put({__MODULE__, :warned}, true)
      maybe_warn_kernel()
    end
  end

  defp maybe_warn_kernel do
    with {:ok, raw} <- File.read("/proc/sys/kernel/osrelease"),
         rel = String.trim(raw),
         [maj, min | _] <- String.split(rel, "."),
         {maj, _} <- Integer.parse(maj),
         {min, _} <- Integer.parse(min),
         true <- {maj, min} < @kernel_floor do
      {fmaj, fmin} = @kernel_floor

      Mix.shell().info(
        "[linx] building on kernel #{rel}; Linx targets #{fmaj}.#{fmin} LTS or newer. " <>
          "Older kernels may hit ENOSYS at runtime (ignore if cross-compiling for a newer target)."
      )
    else
      _ -> :ok
    end
  end
end
