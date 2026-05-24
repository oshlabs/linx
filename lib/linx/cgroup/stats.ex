defmodule Linx.Cgroup.Stats do
  @moduledoc """
  A snapshot of a cgroup's resource counters.

  Returned by `Linx.Cgroup.stats/1`. Each field is `nil` if its
  source isn't available on this cgroup — either because the
  controller isn't delegated to the parent (so the interface file
  doesn't exist) or because the kernel is too old to expose it
  (e.g. `memory.peak` requires Linux ≥ 5.19).

  ## Fields

    * `:cpu_usec` — total CPU time in microseconds (user + kernel),
      from `cpu.stat`'s `usage_usec`.
    * `:cpu_user_usec` — userspace CPU time in microseconds.
    * `:cpu_system_usec` — kernel CPU time in microseconds.
    * `:cpu_nr_throttled` — number of times the cgroup was
      throttled by `cpu.max`. Always 0 unless a CPU limit is set.
    * `:cpu_throttled_usec` — total time the cgroup spent
      throttled, in microseconds.
    * `:memory_current` — current memory usage in bytes
      (`memory.current`).
    * `:memory_peak` — high-water memory usage in bytes
      (`memory.peak`; requires Linux ≥ 5.19).
    * `:pids_current` — current number of processes (`pids.current`).

  ## Inspect

  Renders compactly, showing only the fields that are populated:

      #Linx.Cgroup.Stats<cpu=12.3s mem=42MiB pids=3>
  """

  defstruct [
    :cpu_usec,
    :cpu_user_usec,
    :cpu_system_usec,
    :cpu_nr_throttled,
    :cpu_throttled_usec,
    :memory_current,
    :memory_peak,
    :pids_current
  ]

  @type t :: %__MODULE__{
          cpu_usec: non_neg_integer() | nil,
          cpu_user_usec: non_neg_integer() | nil,
          cpu_system_usec: non_neg_integer() | nil,
          cpu_nr_throttled: non_neg_integer() | nil,
          cpu_throttled_usec: non_neg_integer() | nil,
          memory_current: non_neg_integer() | nil,
          memory_peak: non_neg_integer() | nil,
          pids_current: non_neg_integer() | nil
        }

  defimpl Inspect do
    def inspect(%Linx.Cgroup.Stats{} = stats, _opts) do
      parts =
        []
        |> add(stats.cpu_usec, &"cpu=#{format_seconds(&1)}")
        |> add(stats.memory_current, &"mem=#{format_bytes(&1)}")
        |> add(stats.pids_current, &"pids=#{&1}")
        |> Enum.reverse()
        |> Enum.join(" ")

      "#Linx.Cgroup.Stats<#{parts}>"
    end

    defp add(acc, nil, _fun), do: acc
    defp add(acc, v, fun), do: [fun.(v) | acc]

    # Microseconds → "12.3s" / "150ms" / "8m12.3s" depending on scale.
    defp format_seconds(usec) when usec >= 60_000_000 do
      s = div(usec, 1_000_000)
      m = div(s, 60)
      rem_s = rem(s, 60)
      "#{m}m#{rem_s}s"
    end

    defp format_seconds(usec) when usec >= 1_000_000 do
      whole = div(usec, 1_000_000)
      tenths = div(rem(usec, 1_000_000), 100_000)
      "#{whole}.#{tenths}s"
    end

    defp format_seconds(usec) when usec >= 1_000 do
      "#{div(usec, 1_000)}ms"
    end

    defp format_seconds(usec), do: "#{usec}µs"

    # Bytes → "42MiB" / "1.5GiB" / "768KiB" / "256B"
    defp format_bytes(b) when b >= 1024 * 1024 * 1024 do
      whole = div(b, 1024 * 1024 * 1024)
      tenths = div(rem(b, 1024 * 1024 * 1024) * 10, 1024 * 1024 * 1024)
      if tenths == 0, do: "#{whole}GiB", else: "#{whole}.#{tenths}GiB"
    end

    defp format_bytes(b) when b >= 1024 * 1024,
      do: "#{div(b, 1024 * 1024)}MiB"

    defp format_bytes(b) when b >= 1024, do: "#{div(b, 1024)}KiB"
    defp format_bytes(b), do: "#{b}B"
  end
end
