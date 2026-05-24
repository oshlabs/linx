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

  C0–C1 shipped: `supported?/0`, `create/1`, `destroy/1`,
  `add_process/2`, `read/2`, `write/3`, plus the
  `Linx.Cgroup.Error` shape. Limits, stats, and delegation land in
  C2–C4. See `docs/cgroup/PLAN.md` for the roadmap.
  """

  alias Linx.Cgroup.Error

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
  Creates a cgroup at `path`.

  Idempotent: an already-existing cgroup (`EEXIST`) is treated as
  success — calling `create/1` twice in a row is safe. Other
  failures (e.g. parent missing, no permission) return
  `{:error, %Linx.Cgroup.Error{}}`.

  Returns `{:ok, path}` so the path can flow into the rest of the
  API by piping: `Linx.Cgroup.create(path) |> elem(1) |>
  Linx.Cgroup.add_process(pid)`.
  """
  @spec create(Path.t()) :: {:ok, cgroup()} | {:error, Error.t()}
  def create(path) when is_binary(path) do
    case File.mkdir(path) do
      :ok -> {:ok, path}
      {:error, :eexist} -> {:ok, path}
      {:error, posix} -> {:error, Error.from_posix(posix, path, :create)}
    end
  end

  @doc """
  Removes the cgroup at `path`.

  Succeeds only once the cgroup is empty — the kernel returns
  `EBUSY` while any process is still in the cgroup, surfaced as
  `{:error, %Linx.Cgroup.Error{errno: :ebusy}}`. Pattern-match on
  that to handle "still has live processes" without surprise.
  """
  @spec destroy(cgroup()) :: :ok | {:error, Error.t()}
  def destroy(path) when is_binary(path) do
    case File.rmdir(path) do
      :ok -> :ok
      {:error, posix} -> {:error, Error.from_posix(posix, path, :destroy)}
    end
  end

  @doc """
  Moves OS process `pid` (and so its future children) into `cg` by
  writing the pid's decimal text to `<cg>/cgroup.procs`.

  The classic checkpoint composition with `Linx.Process`:

      host_pid = receive do {:linx_process, :ready, p} -> p end
      :ok = Linx.Cgroup.add_process(cg, host_pid)
      :ok = Linx.Process.proceed(c)

  The pid the kernel accepts is in the cgroup's *own namespace* —
  on a `:cgroup`-namespaced workload this matters; outside one
  it's the global pid.
  """
  @spec add_process(cgroup(), pos_integer()) :: :ok | {:error, Error.t()}
  def add_process(cg, pid) when is_binary(cg) and is_integer(pid) and pid > 0 do
    write_at(cg, "cgroup.procs", Integer.to_string(pid), :add_process)
  end

  @doc """
  Reads cgroup interface file `file` (e.g. `"memory.current"`) under
  `cg`. Returns `{:ok, trimmed_string}` — cgroupfs interface files
  end in newlines that the caller almost never wants — or
  `{:error, %Linx.Cgroup.Error{}}`.

  Raw escape hatch for fields without a typed reader.
  """
  @spec read(cgroup(), String.t()) :: {:ok, String.t()} | {:error, Error.t()}
  def read(cg, file) when is_binary(cg) and is_binary(file) do
    full = Path.join(cg, file)

    case File.read(full) do
      {:ok, data} -> {:ok, String.trim(data)}
      {:error, posix} -> {:error, Error.from_posix(posix, full, :read)}
    end
  end

  @doc """
  Writes `value` to cgroup interface file `file` (e.g.
  `"memory.max"`) under `cg`. `value` is rendered via
  `to_string/1`, so atoms (`:max`), integers, and binaries all work
  directly.

  Raw escape hatch for fields without a typed setter.
  """
  @spec write(cgroup(), String.t(), term()) :: :ok | {:error, Error.t()}
  def write(cg, file, value) when is_binary(cg) and is_binary(file) do
    write_at(cg, file, to_string(value), :write)
  end

  # Shared write helper used by add_process/2 (operation: :add_process)
  # and write/3 (operation: :write). Keeps the operation tag accurate
  # for Linx.Cgroup.Error consumers pattern-matching on it.
  defp write_at(cg, file, value, operation) do
    full = Path.join(cg, file)

    case File.write(full, value) do
      :ok -> :ok
      {:error, posix} -> {:error, Error.from_posix(posix, full, operation)}
    end
  end

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
