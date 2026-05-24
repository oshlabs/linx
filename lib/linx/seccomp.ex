defmodule Linx.Seccomp do
  @moduledoc """
  Linux seccomp ("SECure COMPuting") primitives — per-thread cBPF
  syscall-filter facilities exposed as Elixir verbs.

  ## What seccomp is

  A seccomp filter is a small cBPF program the kernel runs on every
  syscall entry. Its return value tells the kernel whether to allow
  the syscall, return an errno, kill the calling process or thread,
  raise SIGSYS, or log and proceed. Filters install per-thread; they
  never come off once on; and they only get looser via reset, never
  tighter, after install. Together those properties let a workload
  drop its syscall envelope to a small documented set before
  `execve`, so a 0-day in the kernel's capability check still can't
  reach the relevant code path if the syscall is gated.

  See `seccomp(2)` and the kernel's
  `Documentation/userspace-api/seccomp_filter.rst` for the canonical
  reference.

  ## What Linx exposes — and what it doesn't

  This module is a *primitive*. It exposes:

    * **Detection.** `supported?/0` (whether the kernel has the
      facility at all) and `arch/0` (which architecture we're
      building filters for).

    * **Filter construction.** Two layers (per
      `docs/seccomp/PLAN.md` D7):

      - **Sugar:** `allow_list/2` ("only these syscalls"),
        `deny_list/2` ("not these"), and the fluent
        `Linx.Seccomp.Builder` DSL.

      - **Data:** `from_rules/1` for consumers (like the Silo
        application) that translate external policies — Docker
        `seccomp.json`, custom DSLs, runtime policy — into a
        plain `[{action, syscall_atom}, ...]` Elixir list and hand
        it to Linx. `to_rules/1` is the inverse for filters Linx
        itself built.

    * **Install.** `install/2` is checkpoint-bound, the same shape
      as `Linx.Capabilities.drop_bounding/2` — it's the K2 commit
      pattern, because the kernel forbids cross-thread seccomp
      installation. The child agent in `linx_process.c` does the
      actual `seccomp(2)` call at the parked checkpoint.

  Higher-level concerns — parsing JSON profiles, looking up which
  syscalls nginx 1.24 needs, tracking workload-to-filter mappings —
  are policy and orchestration. Those live in consumers; the
  natural home is the **Silo** project that builds on Linx.

  ## Motivating composition

  Lands fully at S2 (currently in flight):

      {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"],
                                    no_new_privs: true)
      receive do {:linx_process, :ready, _} -> :ok end

      {:ok, filter} = Linx.Seccomp.allow_list(
        ~w(read write openat close fstat brk mmap munmap mprotect
           accept4 bind listen socket connect setsockopt
           rt_sigaction rt_sigprocmask rt_sigreturn exit_group)a,
        default: :kill_process
      )

      :ok = Linx.Seccomp.install(c, filter)
      :ok = Linx.Process.proceed(c)

  After `proceed/1`, nginx runs with that exact syscall envelope.
  A bug that tries `execve(2)` (not on the list) kills the process;
  the kernel never enters `do_execve`.

  ## Status

  S0 is shipped: `supported?/0`, `arch/0`, the constants table
  (`Linx.Seccomp.Constants`), the per-arch syscall table
  (`Linx.Seccomp.Syscalls`), and `%Linx.Seccomp.Filter{}`. The
  build verbs (`allow_list/2`, `deny_list/2`, `from_rules/1`,
  `to_rules/1`) and `Linx.Seccomp.Builder` are stubs that return
  `{:error, :not_yet_implemented}` until S1 lands. `install/2`
  follows in S2 alongside the agent-side patch to
  `c_src/linx_process.c`. See `docs/seccomp/PLAN.md` for the
  roadmap and `COVERAGE.md` for the ship/defer split.
  """

  alias Linx.Seccomp.Builder
  alias Linx.Seccomp.Filter

  @proc_self_status "/proc/self/status"

  # `:persistent_term` key for the cached arch atom. Resolved on
  # first call to `arch/0` and never changes for the lifetime of the
  # VM — the host arch can't change without a reboot, and even then
  # the BEAM was compiled against the boot arch.
  @arch_cache_key {__MODULE__, :arch}

  @typedoc """
  An architecture atom. Linx v1 supports `:x86_64` and `:aarch64`;
  any other host arch yields `:unsupported` and the filter-build
  verbs reject it.
  """
  @type arch :: :x86_64 | :aarch64 | :unsupported

  @doc """
  Returns `true` iff the running kernel exposes seccomp filtering —
  i.e. `/proc/self/status` contains a `Seccomp:` line.

  True on every Linux ≥ 3.5, which is every kernel Linx targets.
  Useful as a precondition guard in setup checks; this module's
  build verbs don't gate on it themselves (a missing line would
  manifest as an install-time `ENOSYS` from the agent).
  """
  @spec supported?() :: boolean()
  def supported? do
    case File.read(@proc_self_status) do
      {:ok, data} -> data =~ ~r/^Seccomp:/m
      {:error, _} -> false
    end
  end

  @doc """
  The current host architecture as an atom — `:x86_64`, `:aarch64`,
  or `:unsupported`.

  Resolved on first call from
  `:erlang.system_info(:system_architecture)` and cached in
  `:persistent_term` for the rest of the VM's life (the host arch
  can't change). Cheap on every subsequent call.

  ## Examples

      iex> Linx.Seccomp.arch() in [:x86_64, :aarch64, :unsupported]
      true
  """
  @spec arch() :: arch()
  def arch do
    case :persistent_term.get(@arch_cache_key, :__none__) do
      :__none__ ->
        resolved = resolve_arch()
        :persistent_term.put(@arch_cache_key, resolved)
        resolved

      cached ->
        cached
    end
  end

  # `:erlang.system_info(:system_architecture)` returns a charlist
  # like `'x86_64-pc-linux-gnu'` or `'aarch64-unknown-linux-gnu'` —
  # the BEAM's build triple. We pattern-match on the leading arch
  # token. (The BEAM is compiled against one arch and runs there
  # only, so this token matches the host arch by construction.)
  defp resolve_arch do
    triple = :erlang.system_info(:system_architecture) |> List.to_string()

    cond do
      String.starts_with?(triple, "x86_64") -> :x86_64
      String.starts_with?(triple, "aarch64") -> :aarch64
      true -> :unsupported
    end
  end

  @doc """
  Convenience for `Linx.Seccomp.Builder.new/0` — start an empty
  builder pipeline.

  ## Example (lands fully with S1)

      Linx.Seccomp.builder()
      |> Linx.Seccomp.Builder.allow(:read)
      |> Linx.Seccomp.Builder.deny(:ptrace)
      |> Linx.Seccomp.Builder.build(default: :kill_process)
  """
  @spec builder() :: Builder.t()
  def builder, do: Builder.new()

  @doc """
  Build an allow-list filter: every listed syscall gets `:allow`,
  every other syscall gets the default action.

  Options:

    * `:default` — the action for non-listed syscalls. Defaults to
      `:kill_process` per `docs/seccomp/PLAN.md` D1: allow-lists are
      contracts ("I have enumerated what's safe"); a syscall outside
      is a bug or attack and should fail loudly.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S1 ships. The
  shape is locked in.

  ## Example (lands with S1)

      {:ok, filter} = Linx.Seccomp.allow_list(
        ~w(read write openat close exit_group)a,
        default: :kill_process
      )
  """
  @spec allow_list(Enumerable.t(), keyword()) ::
          {:ok, Filter.t()} | {:error, term()}
  def allow_list(_syscalls, _opts \\ []) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Build a deny-list filter: every listed syscall gets the deny
  action, every other syscall gets the default action.

  Options:

    * `:default` — the action for non-listed syscalls. Defaults to
      `:allow` per `docs/seccomp/PLAN.md` D1: deny-lists are
      graceful-degradation shapes (Docker's default profile).

    * `:deny_action` — the action for listed syscalls. Defaults to
      `{:errno, :eperm}`.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S1 ships.

  ## Example (lands with S1)

      {:ok, filter} = Linx.Seccomp.deny_list(
        ~w(kexec_load init_module delete_module ptrace)a
      )
  """
  @spec deny_list(Enumerable.t(), keyword()) ::
          {:ok, Filter.t()} | {:error, term()}
  def deny_list(_syscalls, _opts \\ []) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Build a filter from a normalised rules list — the data-layer API.

  Accepts `{rules, default_action}` where `rules` is a list of
  `{action, syscall_atom}` tuples and `default_action` is the
  fallthrough verdict. The seam external consumers (Silo's
  `seccomp.json` adapter, custom DSLs, runtime policy) use to hand
  fully-resolved policy to Linx.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S1 ships. The
  shape is locked in.

  ## Example (lands with S1)

      rules = [
        {:allow, :read},
        {:allow, :write},
        {{:errno, :eperm}, :ptrace},
        {:kill_process, :kexec_load}
      ]
      {:ok, filter} = Linx.Seccomp.from_rules({rules, :allow})
  """
  @spec from_rules({[Filter.rule()], Filter.action()}) ::
          {:ok, Filter.t()} | {:error, term()}
  def from_rules(_rules_and_default) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Inverse of `from_rules/1` — extract the rules list from a filter
  Linx itself built.

  Filters that came from a raw BPF blob (a future Silo use case
  for loading externally-supplied filters) don't carry rule
  metadata; for those this returns `{:error, :no_rules}`.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S1 ships.
  """
  @spec to_rules(Filter.t()) ::
          {:ok, {[Filter.rule()], Filter.action()}}
          | {:error, term()}
  def to_rules(%Filter{}) do
    {:error, :not_yet_implemented}
  end

  @doc """
  Install a compiled filter on a parked `Linx.Process` session.

  Checkpoint-bound — the same shape as
  `Linx.Capabilities.drop_bounding/2`. The kernel forbids
  cross-thread `seccomp(2)`, so the child agent in `linx_process.c`
  does the actual install at the checkpoint window before
  `execve`.

  ## Stub

  Returns `{:error, :not_yet_implemented}` until S2 ships. S2
  lands the agent-side `apply_seccomp` plus the
  `{:seccomp_install, bpf_blob}` checkpoint command.

  ## Example (lands with S2)

      {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"],
                                    no_new_privs: true)
      receive do {:linx_process, :ready, _} -> :ok end

      {:ok, filter} = Linx.Seccomp.allow_list(~w(read write …)a)
      :ok = Linx.Seccomp.install(c, filter)
      :ok = Linx.Process.proceed(c)
  """
  @spec install(Linx.Process.t(), Filter.t()) ::
          :ok | {:error, term()}
  def install(_session, %Filter{}) do
    {:error, :not_yet_implemented}
  end
end
