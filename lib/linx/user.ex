defmodule Linx.User do
  @moduledoc """
  Linux user-namespace configuration primitives — `/proc/<pid>/uid_map`,
  `/proc/<pid>/gid_map`, `/proc/<pid>/setgroups`.

  ## Why a separate subsystem

  User namespaces are a coherent kernel concept (per-namespace
  uid/gid mappings + capability translation) with their own procfs
  surface for configuration. `Linx.Process` creates user namespaces
  via `clone(CLONE_NEWUSER)`; what the workload's identity *looks
  like* inside that namespace — root vs unprivileged, mapped vs the
  kernel-default "nobody" — is configured by writing the mapping
  files this module wraps.

  ## procfs is the API

  Every operation here is plain `File.read/1` / `File.write/2`
  against:

    * `/proc/<pid>/uid_map` — write-once user-id mapping
    * `/proc/<pid>/gid_map` — write-once group-id mapping
    * `/proc/<pid>/setgroups` — `"allow"` / `"deny"` gate

  No NIF, no Port, no `setns(2)` dance — the kernel handles all
  the namespace targeting based on the path. The write-once
  semantics are a kernel rule, not a Linx choice: once a map has
  been set for a user ns, subsequent writes return EPERM.

  ## No `:in` option

  Unlike `Linx.Mount` (where the syscall must be called from
  inside the target's mount namespace), uid/gid map writes happen
  via the *host's* view of procfs. Verbs take a `pid` as their
  first argument — the target child's host pid, typically obtained
  from `{:linx_process, :ready, host_pid}`.

  ## The setgroups order

  When an unprivileged caller (no `CAP_SETGID` in the parent user
  ns) writes `gid_map`, the kernel requires
  `/proc/<pid>/setgroups` first contain `"deny"`. Skipping it
  returns EPERM. `deny_setgroups/1` is the primitive; the
  `setup_maps/2` convenience (lands in U2) does this in the right
  order automatically.

  ## Composition with `Linx.Process`

  The canonical rootless flow:

      {:ok, c} = Linx.Process.spawn(
                   argv: ["/bin/bash"],
                   namespaces: [:user, :mount, :pid, :uts, :ipc],
                   stdio: :pty)

      host_pid = receive do {:linx_process, :ready, p} -> p end

      # "root inside ↔ me outside" -- the canonical rootless mapping.
      :ok = Linx.User.deny_setgroups(host_pid)
      :ok = Linx.User.set_uid_map(host_pid, [{0, my_host_uid, 1}])
      :ok = Linx.User.set_gid_map(host_pid, [{0, my_host_gid, 1}])

      :ok = Linx.Process.proceed(c)

  `Linx.Process` has zero awareness of user-namespace mappings;
  the checkpoint between `:ready` and `proceed/1` is the only
  coupling, exactly the way `Linx.Netlink` / `Linx.Cgroup` /
  `Linx.Mount` integration works.

  ## Status

  All foundation milestones shipped (U0–U2): `supported?/0`,
  `deny_setgroups/1`, `set_uid_map/2`, `set_gid_map/2`,
  `read_uid_map/1`, `read_gid_map/1`, `setup_maps/2`, plus the
  `Linx.User.Error` and `Linx.User.Map` shapes.
  """

  alias Linx.User.Error
  alias Linx.User.Map, as: UserMap

  @proc "/proc"
  @self_uid_map Path.join([@proc, "self", "uid_map"])

  @typedoc """
  Host pid of a target process. Typically the value carried in
  `{:linx_process, :ready, host_pid}` from a `Linx.Process` session
  spawned with the `:user` namespace.
  """
  @type pid_target :: pos_integer()

  @typedoc """
  One mapping entry: `{inside_id, outside_id, length}` — all
  non-negative integers; `length > 0`.
  """
  @type mapping :: {non_neg_integer(), non_neg_integer(), pos_integer()}

  @doc """
  Returns `true` iff user namespaces are configurable on this host.

  Canonical check: `/proc/self/uid_map` exists, which is true on
  every Linux kernel ≥ 3.8 with `CONFIG_USER_NS=y` (the default for
  every mainline distribution kernel).
  """
  @spec supported?() :: boolean()
  def supported?, do: File.exists?(@self_uid_map)

  @doc """
  Writes `"deny"` to `/proc/<pid>/setgroups`.

  **Required before `set_gid_map/2`** for unprivileged callers (no
  `CAP_SETGID` in the parent user ns) — the kernel rejects the
  gid_map write otherwise. Privileged callers may skip it; the
  effect is idempotent (re-writing `"deny"` over an already-denied
  setgroups returns `:ok`).

  Common failure modes:

    * `{:error, %Linx.User.Error{errno: :enoent}}` — the target pid
      no longer exists.
    * `{:error, %Linx.User.Error{errno: :eperm}}` — calling at the
      wrong moment (some kernel versions; rare in modern setups).
  """
  @spec deny_setgroups(pid_target()) :: :ok | {:error, Error.t()}
  def deny_setgroups(pid) when is_integer(pid) and pid > 0 do
    path = Path.join([@proc, Integer.to_string(pid), "setgroups"])
    write_or_error(path, "deny", :deny_setgroups)
  end

  @doc """
  Writes a uid mapping to `/proc/<pid>/uid_map`.

  `mappings` is a non-empty list of `{inside_id, outside_id, length}`
  non-negative-integer tuples (with `length > 0`). The kernel
  serialises it as one line per entry; we render and write the whole
  blob in one syscall.

  The write is **write-once** per user namespace — a second call
  returns `EPERM`. Plan your mapping fully before calling.

  ## Examples

      # The canonical rootless "root inside ↔ me outside" mapping:
      :ok = Linx.User.set_uid_map(host_pid, [{0, my_uid, 1}])

      # A multi-range identity map (needs CAP_SETUID or
      # newuidmap(1) — deferred U3 territory):
      :ok = Linx.User.set_uid_map(host_pid,
        [{0, 0, 1}, {1, 100_000, 65_536}])

  ## Errors

    * `{:error, {:bad_map, reason}}` — caller-side input mistake
      (not a list, wrong-arity tuple, negative id, zero length).
    * `{:error, %Linx.User.Error{}}` — kernel-level rejection.
      Common: `:eperm` (write-once already done; map too broad for
      an unprivileged caller), `:einval` (overlapping or invalid
      range), `:enoent` (target pid is gone).
  """
  @spec set_uid_map(pid_target(), [mapping()]) ::
          :ok | {:error, Error.t() | {:bad_map, term()}}
  def set_uid_map(pid, mappings) when is_integer(pid) and pid > 0 do
    write_map(pid, "uid_map", mappings, :set_uid_map)
  end

  @doc """
  Writes a gid mapping to `/proc/<pid>/gid_map`. Same shape and
  write-once semantics as `set_uid_map/2`.

  **Unprivileged callers must call `deny_setgroups/1` first** —
  the kernel returns `EPERM` otherwise. The
  `Linx.User.setup_maps/2` convenience (lands in U2) does this
  sequence automatically.
  """
  @spec set_gid_map(pid_target(), [mapping()]) ::
          :ok | {:error, Error.t() | {:bad_map, term()}}
  def set_gid_map(pid, mappings) when is_integer(pid) and pid > 0 do
    write_map(pid, "gid_map", mappings, :set_gid_map)
  end

  defp write_map(pid, file, mappings, operation) do
    with {:ok, blob} <- render_map(mappings) do
      path = Path.join([@proc, Integer.to_string(pid), file])
      write_or_error(path, blob, operation)
    end
  end

  # Renders a list of {inside, outside, length} into the
  # kernel's "inside outside length\n" format. Validates strictly
  # before producing any output -- partial maps are not allowed
  # (the kernel takes the whole blob in one write or rejects).
  defp render_map([]), do: {:error, {:bad_map, :empty}}

  defp render_map(mappings) when is_list(mappings) do
    Enum.reduce_while(mappings, {:ok, []}, fn entry, {:ok, acc} ->
      case validate_entry(entry) do
        {:ok, line} -> {:cont, {:ok, [line | acc]}}
        {:error, reason} -> {:halt, {:error, {:bad_map, reason}}}
      end
    end)
    |> case do
      {:ok, lines} -> {:ok, lines |> Enum.reverse() |> IO.iodata_to_binary()}
      {:error, _} = err -> err
    end
  end

  defp render_map(_other), do: {:error, {:bad_map, :not_a_list}}

  defp validate_entry({inside, outside, length})
       when is_integer(inside) and inside >= 0 and
            is_integer(outside) and outside >= 0 and
            is_integer(length) and length > 0 do
    {:ok, "#{inside} #{outside} #{length}\n"}
  end

  defp validate_entry(other), do: {:error, {:bad_entry, other}}

  defp write_or_error(path, blob, operation) do
    case File.write(path, blob) do
      :ok -> :ok
      {:error, posix} -> {:error, Error.from_posix(posix, path, operation)}
    end
  end

  @doc """
  Reads and parses `/proc/<pid>/uid_map` into a list of
  `%Linx.User.Map{}` entries.

  A user namespace whose maps haven't been written yet returns
  `{:ok, []}` — the file exists but is empty.

  ## Examples

      iex> Linx.User.read_uid_map(host_pid)
      {:ok, [#Linx.User.Map<0 -> 1000>]}

      iex> Linx.User.read_uid_map(host_pid)  # multi-range
      {:ok, [
        #Linx.User.Map<0 -> 0>,
        #Linx.User.Map<1..65535 -> 100000..165535>
      ]}
  """
  @spec read_uid_map(pid_target()) :: {:ok, [UserMap.t()]} | {:error, Error.t()}
  def read_uid_map(pid) when is_integer(pid) and pid > 0 do
    read_map(pid, "uid_map", :read_uid_map)
  end

  @doc """
  Reads and parses `/proc/<pid>/gid_map` into a list of
  `%Linx.User.Map{}` entries. Same shape as `read_uid_map/1`.
  """
  @spec read_gid_map(pid_target()) :: {:ok, [UserMap.t()]} | {:error, Error.t()}
  def read_gid_map(pid) when is_integer(pid) and pid > 0 do
    read_map(pid, "gid_map", :read_gid_map)
  end

  defp read_map(pid, file, operation) do
    path = Path.join([@proc, Integer.to_string(pid), file])

    case File.read(path) do
      {:ok, data} -> {:ok, parse_map(data)}
      {:error, posix} -> {:error, Error.from_posix(posix, path, operation)}
    end
  end

  @doc false
  # Parses the kernel's uid_map / gid_map format into a list of
  # %Linx.User.Map{} structs. The format is one "inside outside
  # length" triple per line; the kernel right-pads each field to
  # 10 chars, so we split on whitespace and ignore padding.
  # Lines that don't parse as three integers are silently dropped
  # (forward-compat against any future kernel additions).
  @spec parse_map(binary()) :: [UserMap.t()]
  def parse_map(data) when is_binary(data) do
    for line <- String.split(data, "\n", trim: true),
        [a, b, c | _] <- [String.split(line, ~r/\s+/, trim: true)],
        {inside, ""} <- [Integer.parse(a)],
        {outside, ""} <- [Integer.parse(b)],
        {length, ""} <- [Integer.parse(c)],
        inside >= 0 and outside >= 0 and length > 0 do
      %UserMap{inside: inside, outside: outside, length: length}
    end
  end

  @doc """
  Applies the canonical map-setup sequence in one call:
  `deny_setgroups/1` → `set_uid_map/2` → `set_gid_map/2`.

  ## Options

    * `:uid` (required) — mappings list for uid_map; same shape as
      `set_uid_map/2`.
    * `:gid` (required) — mappings list for gid_map.
    * `:setgroups` (default `:deny`) — whether to write
      `"deny"` to `/proc/<pid>/setgroups` before the gid_map
      write. `:skip` is for privileged callers who don't need
      the kernel's setgroups gate.

  Returns `:ok` if every step succeeded, or the first error
  encountered (with the failing step's `:operation`):

      :ok                                                 -- everything worked
      {:error, %Linx.User.Error{operation: :deny_setgroups, ...}}
      {:error, %Linx.User.Error{operation: :set_uid_map, ...}}
      {:error, %Linx.User.Error{operation: :set_gid_map, ...}}
      {:error, {:bad_map, _}}                             -- bad uid/gid input
      {:error, {:bad_setgroups, value}}                   -- bad :setgroups opt

  Steps that ran successfully before a later step failed are
  **not** rolled back — the kernel's write-once semantics mean
  uid_map / gid_map can't be undone, and `deny_setgroups` is
  idempotent anyway. The error tells you exactly where the
  sequence stopped.

  ## Example

      :ok = Linx.User.setup_maps(host_pid,
        uid: [{0, my_uid, 1}],
        gid: [{0, my_gid, 1}]
      )
  """
  @spec setup_maps(pid_target(), keyword()) ::
          :ok
          | {:error,
             Error.t() | {:bad_map, term()} | {:bad_setgroups, term()}}
  def setup_maps(pid, opts) when is_integer(pid) and pid > 0 and is_list(opts) do
    with {:ok, uid} <- fetch_required(opts, :uid),
         {:ok, gid} <- fetch_required(opts, :gid),
         {:ok, setgroups_mode} <- validate_setgroups(Keyword.get(opts, :setgroups, :deny)),
         :ok <- maybe_deny_setgroups(pid, setgroups_mode),
         :ok <- set_uid_map(pid, uid),
         :ok <- set_gid_map(pid, gid) do
      :ok
    end
  end

  defp fetch_required(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:bad_setup, {:missing, key}}}
    end
  end

  defp validate_setgroups(:deny), do: {:ok, :deny}
  defp validate_setgroups(:skip), do: {:ok, :skip}
  defp validate_setgroups(other), do: {:error, {:bad_setgroups, other}}

  defp maybe_deny_setgroups(_pid, :skip), do: :ok
  defp maybe_deny_setgroups(pid, :deny), do: deny_setgroups(pid)
end
