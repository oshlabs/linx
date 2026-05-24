defmodule Linx.Cgroup do
  @moduledoc """
  cgroup v2 primitives — create a cgroup, place processes into it,
  set resource limits, read counters, freeze and thaw.

  ## Why a separate subsystem

  cgroups are a coherent kernel concept (per-process resource
  accounting and limits) with their own filesystem-shaped interface
  under `/sys/fs/cgroup`. `Linx.Process` spawns workloads, but the
  question of "constrain this workload to 256 MiB of memory and at
  most 100 processes" is cgroup-shaped, not clone-shaped — and these
  primitives are useful even when no clone is involved (Erlang
  processes themselves can be supervised by cgroups, for instance).

  ## cgroupfs is the API

  cgroup v2 exposes its entire interface as a read/write filesystem
  under `/sys/fs/cgroup`. Every operation here is plain
  `File.read/1` / `File.write/2` against an interface file. No NIF,
  no Port, no `:os.cmd("cgcreate ...")` — just the filesystem the
  kernel already exposes.

  ## v2 only

  Linx targets modern Linux. cgroup v1 (the legacy
  controller-per-mount hierarchy) is *not* supported.
  `supported?/0` returns `true` iff the unified hierarchy is
  mounted at `/sys/fs/cgroup`.

  ## Primitives, not policy

  The caller chooses the path. Linx does *not* bake in
  `/sys/fs/cgroup/linx/<name>` as a parent. A container engine built
  on Linx picks `/sys/fs/cgroup/myengine/...`; a workload supervisor
  picks something else. Naming convention is the consumer's choice.

  ## Composition with `Linx.Process`

  Place a workload into a cgroup at the checkpoint — the same window
  `Linx.Netlink` uses to configure a child's netns from the host
  before `proceed/1`:

      {:ok, c} = Linx.Process.spawn(argv: [...], namespaces: [...])
      host_pid = receive do {:linx_process, :ready, p} -> p end

      {:ok, cg} = Linx.Cgroup.create("/sys/fs/cgroup/myorg/web-42")
      :ok = Linx.Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
      :ok = Linx.Cgroup.add_process(cg, host_pid)

      :ok = Linx.Process.proceed(c)

  `Linx.Process` itself has no awareness of cgroups; the checkpoint
  is the integration surface and that is enough.

  ## Status

  C0 — scaffolding only. `supported?/0` is functional; the
  lifecycle / limit / stats verbs land in C1–C4. See
  `docs/cgroup/PLAN.md` for the roadmap.
  """

  @cgroupfs "/sys/fs/cgroup"
  @controllers_file Path.join(@cgroupfs, "cgroup.controllers")

  @typedoc """
  Absolute path to a cgroup under `/sys/fs/cgroup`. Returned by
  `create/1`; accepted by every other verb. The path *is* the handle —
  there is no opaque struct or process wrapping it.
  """
  @type cgroup :: String.t()

  @doc """
  Returns `true` iff the cgroup v2 unified hierarchy is mounted.

  Canonical check: `/sys/fs/cgroup/cgroup.controllers` only exists
  on the v2 hierarchy (on v1, `/sys/fs/cgroup` is a tmpfs with
  per-controller subdirectories instead). A `true` return here is
  the prerequisite for everything else in this module.
  """
  @spec supported?() :: boolean()
  def supported?, do: File.exists?(@controllers_file)

  @doc """
  Creates a cgroup at `path` (and any missing ancestors that are
  themselves valid cgroup parents).

  Idempotent: an already-existing cgroup is treated as success.

  Lands in C1.
  """
  @spec create(Path.t()) :: {:ok, cgroup()} | {:error, term()}
  def create(_path), do: {:error, :not_yet_implemented}

  @doc """
  Removes the cgroup at `path`.

  Succeeds only once the cgroup is empty (the kernel enforces this
  via `EBUSY` on `rmdir`).

  Lands in C1.
  """
  @spec destroy(cgroup()) :: :ok | {:error, term()}
  def destroy(_cg), do: {:error, :not_yet_implemented}

  @doc """
  Moves OS process `pid` (and so its future children) into `cg` by
  writing the pid to `<cg>/cgroup.procs`.

  Lands in C1.
  """
  @spec add_process(cgroup(), pos_integer()) :: :ok | {:error, term()}
  def add_process(_cg, _pid), do: {:error, :not_yet_implemented}

  @doc """
  Reads cgroup interface file `file` (e.g. `"memory.current"`) under
  `cg`. Returns `{:ok, trimmed_string}` or `{:error, %Linx.Cgroup.Error{}}`.

  Raw escape hatch for fields without a typed reader. Lands in C1.
  """
  @spec read(cgroup(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def read(_cg, _file), do: {:error, :not_yet_implemented}

  @doc """
  Writes `value` (any term `to_string/1` can render) to cgroup
  interface file `file` (e.g. `"memory.max"`) under `cg`.

  Raw escape hatch for fields without a typed setter. Lands in C1.
  """
  @spec write(cgroup(), String.t(), term()) :: :ok | {:error, term()}
  def write(_cg, _file, _value), do: {:error, :not_yet_implemented}

  @doc """
  Freezes every process in `cg` (`cgroup.freeze` ← `"1"`).

  Lands in C2.
  """
  @spec freeze(cgroup()) :: :ok | {:error, term()}
  def freeze(_cg), do: {:error, :not_yet_implemented}

  @doc """
  Thaws a previously-frozen cgroup (`cgroup.freeze` ← `"0"`).

  Lands in C2.
  """
  @spec thaw(cgroup()) :: :ok | {:error, term()}
  def thaw(_cg), do: {:error, :not_yet_implemented}

  @doc """
  Sets the memory limit for `cg` (`memory.max`).

  Accepts an integer (bytes) or the atom `:max` (unlimited).

  Lands in C2.
  """
  @spec set_memory_max(cgroup(), pos_integer() | :max) :: :ok | {:error, term()}
  def set_memory_max(_cg, _value), do: {:error, :not_yet_implemented}

  @doc """
  Sets the pids limit for `cg` (`pids.max`).

  Accepts an integer or the atom `:max`.

  Lands in C2.
  """
  @spec set_pids_max(cgroup(), pos_integer() | :max) :: :ok | {:error, term()}
  def set_pids_max(_cg, _value), do: {:error, :not_yet_implemented}

  @doc """
  Sets the CPU limit for `cg` (`cpu.max`).

  Accepts `{quota_us, period_us}` (microseconds) or `:max`.

  Lands in C2.
  """
  @spec set_cpu_max(cgroup(), {pos_integer(), pos_integer()} | :max) ::
          :ok | {:error, term()}
  def set_cpu_max(_cg, _value), do: {:error, :not_yet_implemented}

  @doc """
  Enables controllers (e.g. `[:memory, :pids, :cpu]`) on `cg` by
  writing `"+memory +pids +cpu"` to `<cg>/cgroup.subtree_control`.

  Lands in C4.
  """
  @spec enable_controllers(cgroup(), [atom()]) ::
          :ok | {:partial, list()} | {:error, term()}
  def enable_controllers(_cg, _controllers), do: {:error, :not_yet_implemented}

  @doc """
  Reads a curated snapshot of `cg`'s resource counters as a
  `Linx.Cgroup.Stats` struct.

  Lands in C3.
  """
  @spec stats(cgroup()) :: {:ok, term()} | {:error, term()}
  def stats(_cg), do: {:error, :not_yet_implemented}
end
