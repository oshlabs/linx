defmodule Linx.Capabilities.Constants do
  @moduledoc false
  # The 41-entry atom ↔ bit table for Linux capabilities, plus the
  # MapSet ↔ u64-mask conversions that bridge "idiomatic Elixir" and
  # "kernel ABI."
  #
  # Source of truth: include/uapi/linux/capability.h in the kernel
  # tree. Each `:cap_*` atom is the lowercase form of the matching
  # `CAP_*` constant; the bit number is the integer the kernel
  # macros use directly (CAP_NET_ADMIN = 12 means bit 12 of the
  # 64-bit cap mask).
  #
  # This module is internal — public consumers go through
  # `Linx.Capabilities`. It is `@moduledoc false` so ExDoc skips it,
  # but the test suite hits it directly to assert the table is right.

  import Bitwise

  # The canonical table. Order doesn't matter — we materialise the
  # inverse map and the all-atoms MapSet at compile time below.
  @atoms_to_bits %{
    cap_chown: 0,
    cap_dac_override: 1,
    cap_dac_read_search: 2,
    cap_fowner: 3,
    cap_fsetid: 4,
    cap_kill: 5,
    cap_setgid: 6,
    cap_setuid: 7,
    cap_setpcap: 8,
    cap_linux_immutable: 9,
    cap_net_bind_service: 10,
    cap_net_broadcast: 11,
    cap_net_admin: 12,
    cap_net_raw: 13,
    cap_ipc_lock: 14,
    cap_ipc_owner: 15,
    cap_sys_module: 16,
    cap_sys_rawio: 17,
    cap_sys_chroot: 18,
    cap_sys_ptrace: 19,
    cap_sys_pacct: 20,
    cap_sys_admin: 21,
    cap_sys_boot: 22,
    cap_sys_nice: 23,
    cap_sys_resource: 24,
    cap_sys_time: 25,
    cap_sys_tty_config: 26,
    cap_mknod: 27,
    cap_lease: 28,
    cap_audit_write: 29,
    cap_audit_control: 30,
    cap_setfcap: 31,
    cap_mac_override: 32,
    cap_mac_admin: 33,
    cap_syslog: 34,
    cap_wake_alarm: 35,
    cap_block_suspend: 36,
    cap_audit_read: 37,
    cap_perfmon: 38,
    cap_bpf: 39,
    cap_checkpoint_restore: 40
  }

  @bits_to_atoms (for {atom, bit} <- @atoms_to_bits, into: %{}, do: {bit, atom})

  @all_atoms MapSet.new(Map.keys(@atoms_to_bits))

  @last_cap 40

  # OR of every bit Linx knows about — used by the read-side parser
  # to detect "kernel reports caps newer than our table." Computed
  # at compile time from the same source as @atoms_to_bits so the
  # two can't drift.
  @known_mask Enum.reduce(@atoms_to_bits, 0, fn {_atom, bit}, acc ->
                acc ||| 1 <<< bit
              end)

  @doc """
  Every known capability atom, as a `MapSet`. Mirrors the kernel's
  `CAP_LAST_CAP + 1` count (41 on every kernel ≥ 5.8, the kernel
  Linx targets).
  """
  @spec all() :: MapSet.t(atom())
  def all, do: @all_atoms

  @doc """
  The kernel's `CAP_LAST_CAP` value — the highest bit number for
  which a named capability exists in this build (40 = the bit for
  `:cap_checkpoint_restore`).
  """
  @spec last_cap() :: non_neg_integer()
  def last_cap, do: @last_cap

  @doc """
  The bitmask of every cap bit Linx knows about — `OR` of
  `1 <<< to_bit(c)` for every `c` in `all/0`.

  Used by the K1 procfs parser: if `kernel_mask &&& bnot(known_mask)`
  is non-zero, the kernel is reporting bits past Linx's table
  (likely a newer kernel with caps Linx hasn't catalogued).
  """
  @spec known_mask() :: non_neg_integer()
  def known_mask, do: @known_mask

  @doc """
  Capability atom → bit number.

  Returns `nil` for an unknown atom; callers that want a strict
  reject should match `nil` and raise their own error (the public
  write verbs translate this to `{:bad_capability, atom}`).
  """
  @spec to_bit(atom()) :: non_neg_integer() | nil
  def to_bit(atom) when is_atom(atom), do: Map.get(@atoms_to_bits, atom)

  @doc """
  Bit number → capability atom.

  Returns `:unknown` for any bit ≥ `last_cap/0` (or any bit Linx's
  table doesn't recognise) — forward-compatible with kernels that
  add new caps Linx hasn't seen yet. Callers that want to flag this
  (e.g. the `/proc/<pid>/status` parser) compare against
  `:unknown`.
  """
  @spec from_bit(non_neg_integer()) :: atom()
  def from_bit(bit) when is_integer(bit) and bit >= 0 do
    Map.get(@bits_to_atoms, bit, :unknown)
  end

  @doc """
  Set of capability atoms → 64-bit kernel mask.

  Accepts any `Enumerable` of `:cap_*` atoms (`MapSet`, list, …).
  Raises `ArgumentError` on an unknown atom — caller-side input
  validation should catch this before we get here, but we'd rather
  blow up loudly than silently drop a cap the workload meant to
  grant.
  """
  @spec to_bits(Enumerable.t()) :: non_neg_integer()
  def to_bits(caps) do
    Enum.reduce(caps, 0, fn cap, acc ->
      case to_bit(cap) do
        nil ->
          raise ArgumentError, "unknown capability atom: #{inspect(cap)}"

        bit ->
          acc ||| 1 <<< bit
      end
    end)
  end

  @doc """
  64-bit kernel mask → `MapSet` of capability atoms.

  Iterates only over bits Linx knows about, so bits the kernel
  reports for caps newer than this table are silently dropped. The
  K1 procfs parser surfaces this as a `Logger.warning` so consumers
  can notice the kernel has outpaced Linx's table.
  """
  @spec from_bits(non_neg_integer()) :: MapSet.t(atom())
  def from_bits(bits) when is_integer(bits) and bits >= 0 do
    Enum.reduce(@bits_to_atoms, MapSet.new(), fn {bit, atom}, acc ->
      if (bits &&& 1 <<< bit) != 0 do
        MapSet.put(acc, atom)
      else
        acc
      end
    end)
  end
end
