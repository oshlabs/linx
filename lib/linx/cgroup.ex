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

  All foundation milestones shipped (C0–C4): `supported?/0`,
  `create/1`, `destroy/1`, `add_process/2`, `read/2`, `write/3`,
  `freeze/1`, `thaw/1`, `set_memory_max/2`, `set_pids_max/2`,
  `set_cpu_max/2`, `stats/1`, `enable_controllers/2`, plus the
  `Linx.Cgroup.Error` and `Linx.Cgroup.Stats` shapes.
  """

  alias Linx.Cgroup.{Error, Stats}

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
  Freezes every process in `cg` by writing `"1"` to
  `<cg>/cgroup.freeze`.

  All processes in the cgroup (and its descendants) are suspended
  by the kernel — they stop scheduling but stay resident. Pair
  with `thaw/1`. Always available on cgroup v2; no controller
  needs to be enabled.
  """
  @spec freeze(cgroup()) :: :ok | {:error, Error.t()}
  def freeze(cg) when is_binary(cg) do
    write_at(cg, "cgroup.freeze", "1", :write)
  end

  @doc """
  Thaws a previously-frozen cgroup by writing `"0"` to
  `<cg>/cgroup.freeze`. Idempotent on an already-thawed cgroup.
  """
  @spec thaw(cgroup()) :: :ok | {:error, Error.t()}
  def thaw(cg) when is_binary(cg) do
    write_at(cg, "cgroup.freeze", "0", :write)
  end

  @doc """
  Sets the memory limit for `cg` (`memory.max`).

  Accepts an integer (bytes — the kernel's `memory.max` unit) or
  the atom `:max` to clear the limit.

  Requires the `memory` controller to be enabled in the parent's
  `cgroup.subtree_control` (see `enable_controllers/2`, landing in
  C4). If the controller isn't delegated, the kernel returns
  ENOENT on the write because the interface file doesn't exist.
  """
  @spec set_memory_max(cgroup(), non_neg_integer() | :max) :: :ok | {:error, Error.t()}
  def set_memory_max(cg, :max) when is_binary(cg),
    do: write_at(cg, "memory.max", "max", :write)

  def set_memory_max(cg, bytes) when is_binary(cg) and is_integer(bytes) and bytes >= 0,
    do: write_at(cg, "memory.max", Integer.to_string(bytes), :write)

  @doc """
  Sets the pids limit for `cg` (`pids.max`).

  Accepts an integer (maximum number of processes) or the atom
  `:max` to clear the limit. Requires the `pids` controller to be
  enabled in the parent.
  """
  @spec set_pids_max(cgroup(), non_neg_integer() | :max) :: :ok | {:error, Error.t()}
  def set_pids_max(cg, :max) when is_binary(cg),
    do: write_at(cg, "pids.max", "max", :write)

  def set_pids_max(cg, n) when is_binary(cg) and is_integer(n) and n >= 0,
    do: write_at(cg, "pids.max", Integer.to_string(n), :write)

  @doc """
  Sets the CPU bandwidth limit for `cg` (`cpu.max`).

  Accepts either:

    * `{quota_us, period_us}` — both microseconds. The cgroup may
      use `quota_us` of CPU time per `period_us` of wall time.
      `{50_000, 100_000}` is "half a CPU".
    * `:max` — clear the limit (the kernel default).

  Requires the `cpu` controller to be enabled in the parent.
  """
  @spec set_cpu_max(cgroup(), {pos_integer(), pos_integer()} | :max) ::
          :ok | {:error, Error.t()}
  def set_cpu_max(cg, :max) when is_binary(cg),
    do: write_at(cg, "cpu.max", "max", :write)

  def set_cpu_max(cg, {quota, period})
      when is_binary(cg) and is_integer(quota) and quota > 0 and
             is_integer(period) and period > 0,
      do: write_at(cg, "cpu.max", "#{quota} #{period}", :write)

  @doc """
  Enables controllers on `cg` so its children can use them.

  Each controller in `controllers` is written individually as
  `"+<name>"` to `<cg>/cgroup.subtree_control`. Writing
  controllers one at a time means a single rejected name doesn't
  lose the controllers that *did* take — the partial state is
  surfaced to the caller for them to act on.

  Returns:

    * `:ok` — every controller in the list was accepted (or the
      list was empty).
    * `{:partial, failures}` — one or more controllers were
      rejected. `failures` is a non-empty list of
      `{controller_atom, %Linx.Cgroup.Error{}}` tuples for the
      ones that failed. Controllers not in the list are not
      touched. Common failures: the controller is not available
      in `<cg>/cgroup.controllers` (not delegated from the parent
      → `EINVAL` / `ENOENT`), or the kernel doesn't recognize the
      name.

  Accepts standard cgroup v2 controller atoms: `:cpu`, `:cpuset`,
  `:io`, `:memory`, `:pids`, `:rdma`, `:hugetlb`, `:misc`. The
  atom is rendered with `to_string/1` so any new controller a
  future kernel adds is reachable without code changes here.

  ## Why one-at-a-time

  The kernel rejects the *whole* write if any controller in a
  space-separated `"+a +b +c"` blob is invalid. Writing one at a
  time lets us tell the caller exactly which controllers landed
  and which didn't, instead of all-or-nothing.
  """
  @spec enable_controllers(cgroup(), [atom()]) ::
          :ok | {:partial, [{atom(), Error.t()}]}
  def enable_controllers(cg, controllers)
      when is_binary(cg) and is_list(controllers) do
    failures =
      for name <- controllers,
          {:error, %Error{} = err} <-
            [write_at(cg, "cgroup.subtree_control", "+#{name}", :write)],
          do: {name, err}

    case failures do
      [] -> :ok
      _ -> {:partial, failures}
    end
  end

  @doc """
  Reads a curated snapshot of `cg`'s resource counters as a
  `Linx.Cgroup.Stats` struct.

  Returns `{:ok, %Linx.Cgroup.Stats{}}` if the cgroup exists. Each
  field is `nil` if its source isn't available — either because
  the controller isn't delegated to the parent (interface file
  missing) or the kernel is too old to expose it.

  Returns `{:error, %Linx.Cgroup.Error{operation: :stats}}` if the
  cgroup directory itself doesn't exist or isn't readable.
  """
  @spec stats(cgroup()) :: {:ok, Stats.t()} | {:error, Error.t()}
  def stats(cg) when is_binary(cg) do
    case File.stat(cg) do
      {:ok, _} ->
        cpu = parse_keyed(read_raw(cg, "cpu.stat"))

        {:ok,
         %Stats{
           cpu_usec: cpu["usage_usec"],
           cpu_user_usec: cpu["user_usec"],
           cpu_system_usec: cpu["system_usec"],
           cpu_nr_throttled: cpu["nr_throttled"],
           cpu_throttled_usec: cpu["throttled_usec"],
           memory_current: read_int(cg, "memory.current"),
           memory_peak: read_int(cg, "memory.peak"),
           pids_current: read_int(cg, "pids.current")
         }}

      {:error, posix} ->
        {:error, Error.from_posix(posix, cg, :stats)}
    end
  end

  # `cpu.stat` is space-separated key/value lines:
  #
  #     usage_usec 285978284524
  #     user_usec  215396840656
  #     ...
  #
  # Build a %{key => integer} map; lines that don't parse as
  # `key int` are silently dropped (forward-compatible with any new
  # keys the kernel adds).
  @doc false
  def parse_keyed(nil), do: %{}

  def parse_keyed(text) when is_binary(text) do
    for line <- String.split(text, "\n", trim: true),
        [key, value] <- [String.split(line, " ", parts: 2)],
        {n, ""} <- [Integer.parse(value)],
        into: %{} do
      {key, n}
    end
  end

  # Best-effort raw read: `nil` on any failure. Used by stats/1 to
  # nil-fill fields whose interface files aren't present.
  defp read_raw(cg, file) do
    case File.read(Path.join(cg, file)) do
      {:ok, data} -> data
      {:error, _} -> nil
    end
  end

  # Best-effort integer read: `nil` if missing/unreadable/unparsable.
  defp read_int(cg, file) do
    with data when is_binary(data) <- read_raw(cg, file),
         {n, _rest} <- Integer.parse(String.trim(data)) do
      n
    else
      _ -> nil
    end
  end
end
