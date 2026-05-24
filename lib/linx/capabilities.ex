defmodule Linx.Capabilities do
  @moduledoc """
  Linux per-process capability primitives — the kernel's five
  capability sets (effective, permitted, inheritable, bounding,
  ambient) and the syscalls that manipulate them.

  ## Why a separate subsystem

  Linux capabilities partition the historical "root vs not-root"
  binary into ~41 fine-grained powers (`CAP_NET_ADMIN`,
  `CAP_SYS_ADMIN`, `CAP_NET_BIND_SERVICE`, …). A security-conscious
  container runtime drops everything the workload doesn't need
  *before* `execve`, so a compromise of e.g. nginx can't reach for
  arbitrary kernel surface. `Linx.Capabilities` is the primitive
  that makes that drop possible from Elixir.

  This is not a security-policy engine. It exposes "read these
  caps" and "drop these caps from this set on this session." What
  each workload should have is policy and lives in a consumer.

  ## Two layers — read and write

  The read side is host-side, pure Elixir `File.read/1` against
  `/proc/<pid>/status`. Works against any live process without
  cooperation from the target.

  The write side is fundamentally different: capability
  manipulation is **per-thread** — `capset(2)`, `prctl(PR_CAPBSET_*)`,
  and `prctl(PR_CAP_AMBIENT_*)` all operate on the *calling thread*.
  So the child agent in `Linx.Process` has to do its own cap
  configuration. The K2 write verbs (`drop_bounding/2`,
  `set_thread_sets/2`, `set_ambient/2`) are checkpoint-bound: only
  valid in the `:ready` (parked) state, same shape as
  `Linx.Process.proceed/1` / `abort/1`.

  ## MapSets of `:cap_*` atoms

  Cap sets are 64-bit kernel bitmasks. In Elixir they show up as
  `MapSet`s of `:cap_*` atoms (the lowercase form of the kernel's
  `CAP_*` constants):

      MapSet.new([:cap_net_admin, :cap_sys_admin])

  Set operations (`MapSet.union/2`, `MapSet.difference/2`) come for
  free; pattern-matching on cap atoms is natural; the bitmask
  conversion happens in one place (`Linx.Capabilities.Constants`).
  The `:cap_` prefix is kept so the atom is unambiguous in a
  mailbox of mixed message types.

  ## Composition with `Linx.Process`

  The motivating composition:

      {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"], stdio: :pty)
      receive do {:linx_process, :ready, _} -> :ok end

      # Strip everything except the one cap nginx actually needs.
      keep = [:cap_net_bind_service]
      :ok = Linx.Capabilities.set_thread_sets(c,
              effective: keep, permitted: keep, inheritable: [])
      :ok = Linx.Capabilities.drop_bounding(c,
              MapSet.difference(Linx.Capabilities.Constants.all(),
                                MapSet.new(keep)))

      :ok = Linx.Process.proceed(c)

  After `proceed/1`, the workload runs with exactly
  `cap_net_bind_service` — even if its binary has file caps that
  would otherwise grant more, because `:cap_setpcap` was dropped
  from `:bounding` too.

  ## Status

  Skeleton — K0 ships `supported?/0`, the constants table
  (`Linx.Capabilities.Constants`), and the read-side value type
  (`Linx.Capabilities.State`). The read verbs (`read/1`) land in
  K1; the write verbs (`drop_bounding/2`, `set_thread_sets/2`,
  `set_ambient/2`) in K2. See `docs/capabilities/PLAN.md` for the
  full plan, `COVERAGE.md` for the ship/defer split.
  """

  alias Linx.Capabilities.State

  @self_status "/proc/self/status"

  @typedoc """
  A capability atom — the lowercase form of a kernel `CAP_*`
  constant, prefixed with `:cap_`. Examples:

      :cap_net_admin
      :cap_sys_admin
      :cap_net_bind_service

  See `Linx.Capabilities.Constants.all/0` for the full set.
  """
  @type cap :: atom()

  @typedoc """
  A set of capabilities — a `MapSet` of `:cap_*` atoms. The public
  write verbs accept any `Enumerable` of caps (list, MapSet,
  Stream) for convenience; the canonical representation is
  `MapSet`.
  """
  @type cap_set :: MapSet.t(cap())

  @doc """
  Returns `true` iff Linux capabilities are inspectable on this
  host — i.e. `/proc/self/status` contains a `CapBnd:` line.

  True on every Linux ≥ 2.6.25 (every kernel Linx targets).
  Useful as a precondition guard or in setup checks; this module's
  verbs don't gate on it themselves.
  """
  @spec supported?() :: boolean()
  def supported? do
    case File.read(@self_status) do
      {:ok, data} -> data =~ ~r/^CapBnd:/m
      {:error, _} -> false
    end
  end

  @doc """
  Reads a process's capability sets from `/proc/<pid>/status`.

  Accepts a positive integer pid, or `:self` as a convenience for
  the BEAM's own status. Returns
  `{:ok, %Linx.Capabilities.State{}}` on success, or
  `{:error, %Linx.Capabilities.Error{}}` if the procfs read failed
  (target pid gone, no permission, etc.).

  Lands with K1 — currently returns `{:error, :not_yet_implemented}`.
  """
  @spec read(pos_integer() | :self) :: {:ok, State.t()} | {:error, term()}
  def read(:self), do: {:error, :not_yet_implemented}
  def read(pid) when is_integer(pid) and pid > 0, do: {:error, :not_yet_implemented}

  @doc """
  Drops capabilities from the calling thread's bounding set on a
  parked `Linx.Process` session.

  `caps` is a `MapSet` or list of `:cap_*` atoms. The operation is
  one-way (`prctl(PR_CAPBSET_DROP)`); the kernel will refuse to
  re-add a dropped cap via any subsequent verb on the same thread.

  Only valid in the `:ready` state — same rules as
  `Linx.Process.proceed/1`. Returns `{:error, :running}` post-execve,
  `{:error, :not_ready}` pre-checkpoint,
  `{:error, :already_terminated}` post.

  Lands with K2 — currently returns `{:error, :not_yet_implemented}`.
  """
  @spec drop_bounding(Linx.Process.t(), Enumerable.t()) ::
          :ok | {:error, term()}
  def drop_bounding(session, _caps) when is_pid(session) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Sets the calling thread's effective, permitted, and inheritable
  capability sets on a parked `Linx.Process` session.

  `opts` is a keyword list; any subset of `:effective`,
  `:permitted`, `:inheritable` may be supplied (omitted sets are
  left unchanged). Each value is a `MapSet` or list of `:cap_*`
  atoms.

  Implemented via `capset(2)` in the agent. The kernel enforces the
  invariants documented in `capabilities(7)` — notably that
  `:effective ⊆ :permitted` and `:inheritable ⊆ :permitted ∪ I_old`.

  Lands with K2 — currently returns `{:error, :not_yet_implemented}`.
  """
  @spec set_thread_sets(Linx.Process.t(), keyword()) :: :ok | {:error, term()}
  def set_thread_sets(session, opts) when is_pid(session) and is_list(opts) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Sets the calling thread's ambient capability set on a parked
  `Linx.Process` session.

  `caps` is a `MapSet` or list of `:cap_*` atoms. The ambient set
  is *replaced* (the kernel only exposes per-cap RAISE and a global
  CLEAR_ALL, so this is the natural shape — internally we
  `PR_CAP_AMBIENT_CLEAR_ALL` then `PR_CAP_AMBIENT_RAISE` each cap).

  Lands with K2 — currently returns `{:error, :not_yet_implemented}`.
  """
  @spec set_ambient(Linx.Process.t(), Enumerable.t()) :: :ok | {:error, term()}
  def set_ambient(session, _caps) when is_pid(session) do
    {:error, :not_yet_implemented}
  end
end
