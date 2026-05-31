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
  configuration. The write verbs (`drop_bounding/2`,
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

  See `docs/capabilities/EXAMPLES.md` for end-to-end recipes.
  """

  require Logger

  import Bitwise

  alias Linx.Capabilities.Constants
  alias Linx.Capabilities.Error
  alias Linx.Capabilities.State

  @proc "/proc"
  @self_status Path.join([@proc, "self", "status"])

  # Regex to extract the five Cap*: hex masks from /proc/<pid>/status.
  # The kernel writes them as one tab-separated key:value line each;
  # we accept any whitespace for tolerance against future format
  # tweaks. Ordering in the file is deterministic (Inh/Prm/Eff/Bnd/Amb)
  # but we don't rely on it — we key by the tag.
  @cap_line_regex ~r/^Cap(Inh|Prm|Eff|Bnd|Amb):\s+([0-9a-fA-F]+)/m

  @cap_tags %{
    "Inh" => :inheritable,
    "Prm" => :permitted,
    "Eff" => :effective,
    "Bnd" => :bounding,
    "Amb" => :ambient
  }

  @required_fields MapSet.new([
                     :effective,
                     :permitted,
                     :inheritable,
                     :bounding,
                     :ambient
                   ])

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
  or the file didn't contain the five `Cap*:` lines we expected.

  ## Examples

      iex> {:ok, %Linx.Capabilities.State{} = state} = Linx.Capabilities.read(:self)
      iex> is_struct(state.effective, MapSet) and is_struct(state.bounding, MapSet)
      true

      # Bogus pid -> structured error.
      iex> {:error, %Linx.Capabilities.Error{errno: :enoent}} =
      ...>   Linx.Capabilities.read(1_234_567_890)
      iex> true
      true

  ## Forward compatibility

  If the kernel reports a bit that isn't in Linx's 41-entry table
  (a newer kernel adding caps Linx hasn't catalogued), the bit is
  silently dropped from the returned `MapSet`s and a single
  `Logger.warning/1` is emitted. The returned `%State{}` is still
  valid for every cap Linx *does* know about.
  """
  @spec read(pos_integer() | :self) ::
          {:ok, State.t()} | {:error, Error.t()}
  def read(:self), do: read_status(@self_status)

  def read(pid) when is_integer(pid) and pid > 0 do
    read_status(Path.join([@proc, Integer.to_string(pid), "status"]))
  end

  defp read_status(path) do
    case File.read(path) do
      {:ok, data} -> parse_status(data, path)
      {:error, posix} -> {:error, Error.from_posix(posix, path, :read)}
    end
  end

  @doc false
  # Parses the five `Cap*:` lines out of a /proc/<pid>/status blob.
  # Exposed only for the unit tests' fixture-based assertions —
  # external consumers call read/1.
  @spec parse_status(binary(), Path.t()) ::
          {:ok, State.t()} | {:error, Error.t()}
  def parse_status(data, path) when is_binary(data) and is_binary(path) do
    found =
      @cap_line_regex
      |> Regex.scan(data, capture: :all_but_first)
      |> Enum.reduce(%{}, fn [tag, hex], acc ->
        Map.put(acc, Map.fetch!(@cap_tags, tag), String.to_integer(hex, 16))
      end)

    if MapSet.equal?(MapSet.new(Map.keys(found)), @required_fields) do
      maybe_warn_unknown_bits(found, path)

      {:ok,
       %State{
         effective: Constants.from_bits(found.effective),
         permitted: Constants.from_bits(found.permitted),
         inheritable: Constants.from_bits(found.inheritable),
         bounding: Constants.from_bits(found.bounding),
         ambient: Constants.from_bits(found.ambient)
       }}
    else
      {:error, Error.from_posix(:bad_status, path, :read)}
    end
  end

  # A kernel reporting bits past CAP_LAST_CAP (e.g. a future cap
  # Linx hasn't catalogued) is forward-compat noise, not an error.
  # We log once per read; the returned State is still valid.
  defp maybe_warn_unknown_bits(found, path) do
    all_bits =
      found
      |> Map.values()
      |> Enum.reduce(0, &(&1 ||| &2))

    extra = all_bits &&& bnot(Constants.known_mask())

    if extra != 0 do
      Logger.warning(
        "Linx.Capabilities: #{path} reports capability bits Linx doesn't know about " <>
          "(0x#{Integer.to_string(extra, 16)}). Kernel may have caps newer than this Linx build."
      )
    end
  end

  @doc """
  Drops capabilities from the child thread's bounding set on a
  parked `Linx.Process` session.

  `caps` is a `MapSet` or list of `:cap_*` atoms. The operation is
  one-way (`prctl(PR_CAPBSET_DROP)`) — the kernel will refuse to
  re-add a dropped cap via any subsequent verb on the same thread,
  even via `set_thread_sets/2`.

  ## Errors

    * `{:error, :not_ready}` — session not yet at the checkpoint.
    * `{:error, :running}` — past `proceed/1`, the child is in
      `execve`'d land.
    * `{:error, :no_process}` — session has ended.
    * `{:error, {:bad_capability, atom}}` — `caps` contains an
      atom Linx doesn't recognise. Validation happens before
      anything is sent to the agent.

  Kernel-level failures (the workload didn't have the required
  privilege to drop a particular cap, etc.) arrive asynchronously
  as `{:linx_process, :error, errno, :cap_drop_bounding}` on the
  session's owner mailbox, the same shape as other pre-`execve`
  failures.

  ## Example

      :ok = Linx.Capabilities.drop_bounding(session,
        [:cap_sys_admin, :cap_sys_module, :cap_dac_override])
  """
  @spec drop_bounding(Linx.Process.t(), Enumerable.t()) ::
          :ok
          | {:error,
             :not_ready
             | :running
             | :no_process
             | {:bad_capability, term()}}
  def drop_bounding(session, caps) when is_pid(session) do
    with {:ok, mask} <- caps_to_mask(caps) do
      GenServer.call(session, {:cap_drop_bounding, mask})
    end
  end

  @doc """
  Sets the child thread's effective, permitted, and inheritable
  capability sets on a parked `Linx.Process` session.

  `opts` is a keyword list with **all three** required keys:
  `:effective`, `:permitted`, `:inheritable`. Each value is a
  `MapSet` or list of `:cap_*` atoms (use `[]` or `MapSet.new()`
  to clear a set).

  Implemented via `capset(2)` in the agent. The kernel enforces the
  invariants documented in `capabilities(7)` — notably that
  `:effective ⊆ :permitted` and `:inheritable ⊆ :permitted ∪ I_old`.
  Violations arrive as `{:linx_process, :error, :einval,
  :cap_set_thread}` on the owner mailbox.

  > #### "Leave unchanged" not yet supported {: .info}
  > A future revision will accept missing keys as "leave this set
  > as-is" (the agent would read its own `/proc/self/status` to
  > fill in). For now, callers that want one set unchanged must
  > read it first via `Linx.Capabilities.read(host_pid)` and pass
  > it back through here.

  ## Errors

  Same shape as `drop_bounding/2`. Additional caller-side errors:

    * `{:error, {:bad_thread_sets, {:missing, key}}}` — one of
      `:effective`, `:permitted`, `:inheritable` was omitted.
    * `{:error, {:bad_capability, atom}}` — any of the three
      values contained an unknown cap atom.
  """
  @spec set_thread_sets(Linx.Process.t(), keyword()) ::
          :ok
          | {:error,
             :not_ready
             | :running
             | :no_process
             | {:bad_capability, term()}
             | {:bad_thread_sets, {:missing, atom()}}}
  def set_thread_sets(session, opts) when is_pid(session) and is_list(opts) do
    with {:ok, e} <- fetch_set(opts, :effective),
         {:ok, p} <- fetch_set(opts, :permitted),
         {:ok, i} <- fetch_set(opts, :inheritable),
         {:ok, e_mask} <- caps_to_mask(e),
         {:ok, p_mask} <- caps_to_mask(p),
         {:ok, i_mask} <- caps_to_mask(i) do
      GenServer.call(session, {:cap_set_thread, e_mask, p_mask, i_mask})
    end
  end

  @doc """
  Sets the child thread's ambient capability set on a parked
  `Linx.Process` session.

  `caps` is a `MapSet` or list of `:cap_*` atoms. The ambient set
  is *replaced* (the kernel only exposes per-cap RAISE/LOWER plus
  a global CLEAR_ALL, so the natural shape is "clear then raise
  each requested cap").

  Ambient caps are the mechanism that lets a non-root, no-file-cap
  binary still inherit capabilities across `execve` — useful when
  you want a workload to start with e.g. `:cap_net_bind_service`
  but don't want to put file caps on the binary or run it as root.
  See `capabilities(7)` "Ambient capabilities" for the full rules
  (notably: every ambient cap must also be in the permitted and
  inheritable sets, or the raise fails).

  ## Errors

  Same shape as `drop_bounding/2`. Kernel failures (a raise that
  fails because the cap isn't in permitted+inheritable, etc.)
  arrive as `{:linx_process, :error, errno, :cap_set_ambient}`.
  """
  @spec set_ambient(Linx.Process.t(), Enumerable.t()) ::
          :ok
          | {:error,
             :not_ready
             | :running
             | :no_process
             | {:bad_capability, term()}}
  def set_ambient(session, caps) when is_pid(session) do
    with {:ok, mask} <- caps_to_mask(caps) do
      GenServer.call(session, {:cap_set_ambient, mask})
    end
  end

  # Validate an Enumerable of cap atoms and convert it to a u64 mask
  # for the wire. Any unknown atom (or non-atom) short-circuits with
  # a structured error -- Constants.to_bits/1 itself raises on
  # unknown atoms, but we want a clean tagged tuple at this layer
  # rather than letting a typo blow up a GenServer.call.
  defp caps_to_mask(caps) do
    Enum.reduce_while(caps, 0, fn cap, acc ->
      cond do
        not is_atom(cap) ->
          {:halt, {:error, {:bad_capability, cap}}}

        is_nil(Constants.to_bit(cap)) ->
          {:halt, {:error, {:bad_capability, cap}}}

        true ->
          {:cont, acc ||| 1 <<< Constants.to_bit(cap)}
      end
    end)
    |> case do
      mask when is_integer(mask) -> {:ok, mask}
      {:error, _} = err -> err
    end
  end

  defp fetch_set(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:bad_thread_sets, {:missing, key}}}
    end
  end
end
