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

  U0 — scaffolding only. `supported?/0` is functional; the
  write-side and read-side verbs land in U1–U2. See
  `docs/user/PLAN.md` for the roadmap.
  """

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
  gid_map write otherwise. Privileged callers may skip it.

  Lands in U1.
  """
  @spec deny_setgroups(pid_target()) :: :ok | {:error, term()}
  def deny_setgroups(_pid), do: {:error, :not_yet_implemented}

  @doc """
  Writes a uid mapping to `/proc/<pid>/uid_map`.

  `mappings` is a list of `{inside_id, outside_id, length}`
  non-negative integer tuples. The kernel writes are **write-once**
  per user namespace — a second call returns `EPERM`.

  Lands in U1.
  """
  @spec set_uid_map(pid_target(), [mapping()]) :: :ok | {:error, term()}
  def set_uid_map(_pid, _mappings), do: {:error, :not_yet_implemented}

  @doc """
  Writes a gid mapping to `/proc/<pid>/gid_map`. Same shape and
  write-once semantics as `set_uid_map/2`.

  Unprivileged callers must call `deny_setgroups/1` first.

  Lands in U1.
  """
  @spec set_gid_map(pid_target(), [mapping()]) :: :ok | {:error, term()}
  def set_gid_map(_pid, _mappings), do: {:error, :not_yet_implemented}

  @doc """
  Reads and parses `/proc/<pid>/uid_map` into a list of
  `%Linx.User.Map{}` entries.

  A user namespace whose maps haven't been written yet returns
  `{:ok, []}` — the file exists but is empty.

  Lands in U2.
  """
  @spec read_uid_map(pid_target()) :: {:ok, [term()]} | {:error, term()}
  def read_uid_map(_pid), do: {:error, :not_yet_implemented}

  @doc """
  Reads and parses `/proc/<pid>/gid_map` into a list of
  `%Linx.User.Map{}` entries.

  Lands in U2.
  """
  @spec read_gid_map(pid_target()) :: {:ok, [term()]} | {:error, term()}
  def read_gid_map(_pid), do: {:error, :not_yet_implemented}

  @doc """
  Applies the canonical map-setup sequence in one call:
  `deny_setgroups/1` → `set_uid_map/2` → `set_gid_map/2`.

  ## Options

    * `:uid` — mappings list for uid_map (required)
    * `:gid` — mappings list for gid_map (required)
    * `:setgroups` — `:deny` (default) or `:skip` for privileged
      callers who don't need the setgroups gate

  Lands in U2.
  """
  @spec setup_maps(pid_target(), keyword()) :: :ok | {:error, term()}
  def setup_maps(_pid, _opts), do: {:error, :not_yet_implemented}
end
