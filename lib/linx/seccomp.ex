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

    * **Filter construction.** Two layers:

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

  S0 + S1 + S2 shipped: detection (`supported?/0`, `arch/0`),
  constants (`Linx.Seccomp.Constants`), the per-arch syscall table
  (`Linx.Seccomp.Syscalls`), `%Linx.Seccomp.Filter{}`,
  `%Linx.Seccomp.Error{}`, the build verbs (`allow_list/2`,
  `deny_list/2`, `from_rules/1`, `to_rules/1`),
  `Linx.Seccomp.Builder`, and `install/2` against a parked
  `Linx.Process` session (with the matching `no_new_privs:` opt on
  `Linx.Process.spawn/1` / `enter/2`). Per-argument matching
  (`allow_if/3`) is the deferred S1.5 surface; multi-arch routing
  and `SECCOMP_USER_NOTIF` are deferred to future work.
  """

  alias Linx.Seccomp.Builder
  alias Linx.Seccomp.Compiler
  alias Linx.Seccomp.Constants
  alias Linx.Seccomp.Filter
  alias Linx.Seccomp.Syscalls

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
      `:kill_process` — allow-lists are
      contracts ("I have enumerated what's safe"); a syscall outside
      is a bug or attack and should fail loudly.

  ## Errors

  Same shape as `from_rules/1`. See its docs for the full list.

  ## Examples

      {:ok, filter} = Linx.Seccomp.allow_list(
        ~w(read write openat close exit_group)a,
        default: :kill_process
      )

      # Looser default — useful when the goal is to log unlisted
      # syscalls for profiling rather than killing the workload.
      {:ok, filter} = Linx.Seccomp.allow_list([:read, :write],
                                              default: :log)
  """
  @spec allow_list(Enumerable.t(), keyword()) ::
          {:ok, Filter.t()} | {:error, term()}
  def allow_list(syscalls, opts \\ []) do
    default = Keyword.get(opts, :default, :kill_process)
    rules = Enum.map(syscalls, &{:allow, &1})
    from_rules({rules, default})
  end

  @doc """
  Build a deny-list filter: every listed syscall gets the deny
  action, every other syscall gets the default action.

  Options:

    * `:default` — the action for non-listed syscalls. Defaults to
      `:allow` — deny-lists are
      graceful-degradation shapes (Docker's default profile).

    * `:deny_action` — the action for listed syscalls. Defaults to
      `{:errno, :eperm}`.

  ## Errors

  Same shape as `from_rules/1`.

  ## Examples

      # Docker-style: deny the dangerous syscalls, allow the rest.
      {:ok, filter} = Linx.Seccomp.deny_list(
        ~w(kexec_load init_module delete_module ptrace mount)a
      )

      # Same denies but with a sharper edge — kill instead of EPERM.
      {:ok, filter} = Linx.Seccomp.deny_list(
        [:kexec_load, :init_module],
        deny_action: :kill_process
      )
  """
  @spec deny_list(Enumerable.t(), keyword()) ::
          {:ok, Filter.t()} | {:error, term()}
  def deny_list(syscalls, opts \\ []) do
    default = Keyword.get(opts, :default, :allow)
    deny_action = Keyword.get(opts, :deny_action, {:errno, :eperm})
    rules = Enum.map(syscalls, &{deny_action, &1})
    from_rules({rules, default})
  end

  @doc """
  Build a filter from a normalised rules list — the data-layer API.

  Accepts `{rules, default_action}` where `rules` is a list of
  `{action, syscall_atom}` tuples and `default_action` is the
  fallthrough verdict. The seam external consumers (Silo's
  `seccomp.json` adapter, custom DSLs, runtime policy) use to hand
  fully-resolved policy to Linx — Silo's job is "translate JSON to
  this list shape"; Linx's job starts here.

  The filter targets the current host architecture (see `arch/0`).
  Filters built for one arch don't install on another; multi-arch
  filters are deferred.

  ## Returns

    * `{:ok, %Linx.Seccomp.Filter{}}` on success — the filter's
      `:rules` field carries the normalised `{rules, default}` so
      `to_rules/1` can introspect it later.

    * `{:error, {:unsupported_arch, arch}}` — the host arch isn't
      in Linx's supported list (`:x86_64`, `:aarch64`).
    * `{:error, {:bad_action, term}}` — the default or one of the
      per-rule actions isn't a recognised verdict.
    * `{:error, {:unknown_syscall, atom}}` — a rule names a syscall
      atom that isn't in the per-arch table. See
      `Linx.Seccomp.Syscalls` "Extending this table" for how to
      add one.
    * `{:error, {:duplicate_rule, atom}}` — the same syscall
      appears in more than one rule.
    * `{:error, {:bad_rule, term}}` — an element of the rules list
      isn't a `{action, syscall_atom}` tuple.
    * `{:error, %Linx.Seccomp.Error{operation: :build, errno: :e2big}}`
      — the filter would need a jump > 255 instructions
      (jump-trampoline support is deferred; the current
      ~150-syscall table fits comfortably under this limit).

  ## Examples

      rules = [
        {:allow, :read},
        {:allow, :write},
        {{:errno, :eperm}, :ptrace},
        {:kill_process, :kexec_load}
      ]
      {:ok, filter} = Linx.Seccomp.from_rules({rules, :allow})

      # Errors are caller-actionable atoms:
      Linx.Seccomp.from_rules({[{:allow, :not_a_real_syscall}], :allow})
      # => {:error, {:unknown_syscall, :not_a_real_syscall}}
  """
  @spec from_rules({[Filter.rule()], Filter.action()}) ::
          {:ok, Filter.t()} | {:error, term()}
  def from_rules({rules, default}) when is_list(rules) do
    arch = arch()

    with :ok <- validate_arch(arch),
         :ok <- validate_action(default),
         :ok <- validate_rules(rules, arch),
         {:ok, bpf} <- Compiler.compile(rules, default, arch) do
      {:ok,
       %Filter{
         arch: arch,
         bpf: bpf,
         rules: {rules, default}
       }}
    end
  end

  def from_rules(other) do
    {:error, {:bad_rules, other}}
  end

  @doc """
  Inverse of `from_rules/1` — extract the rules list from a filter
  Linx itself built.

  Filters whose `:rules` field is `nil` (which would arise from a
  future Silo path that loads externally-supplied raw BPF blobs)
  return `{:error, :no_rules}`. The current build verbs always
  populate `:rules`, so this is reliable for any filter Linx
  itself produced.

  ## Examples

      iex> {:ok, f} = Linx.Seccomp.allow_list([:read, :write])
      iex> {:ok, {rules, default}} = Linx.Seccomp.to_rules(f)
      iex> rules
      [{:allow, :read}, {:allow, :write}]
      iex> default
      :kill_process
  """
  @spec to_rules(Filter.t()) ::
          {:ok, {[Filter.rule()], Filter.action()}}
          | {:error, :no_rules}
  def to_rules(%Filter{rules: nil}), do: {:error, :no_rules}
  def to_rules(%Filter{rules: {rules, default}}), do: {:ok, {rules, default}}

  @doc """
  Install a compiled filter on a parked `Linx.Process` session.

  Checkpoint-bound — the same shape as
  `Linx.Capabilities.drop_bounding/2`. The kernel forbids
  cross-thread `seccomp(2)`, so the child agent in `linx_process.c`
  does the actual install at the checkpoint window before
  `execve`.

  If `PR_SET_NO_NEW_PRIVS` isn't already on (either because the
  caller didn't pass `no_new_privs: true` to `Linx.Process.spawn/1`
  or because the workload isn't privileged enough to install
  without NNP), the agent sets it automatically before the
  `seccomp(2)` call — the "be helpful" path. Callers who want the principled
  posture should still pass the spawn opt; the auto-set is just a
  fallback so an unprivileged caller who forgot doesn't get a
  confusing `EPERM`.

  ## Errors

    * `{:error, :not_ready}` — session hasn't reached the checkpoint
      yet. Wait for `{:linx_process, :ready, _}` first.
    * `{:error, :running}` — past `proceed/1`, the child has
      `execve`'d; installing now is too late.
    * `{:error, :no_process}` — the session emitted its
      terminal event.

  Kernel-level install failures arrive asynchronously as
  `{:linx_process, :error, errno, :seccomp_install}` or
  `{:linx_process, :error, errno, :seccomp_no_new_privs}` on the
  session's owner mailbox, the same shape as other pre-`execve`
  failures.

  ## Examples

      {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"],
                                    no_new_privs: true)
      receive do {:linx_process, :ready, _} -> :ok end

      {:ok, filter} = Linx.Seccomp.allow_list(~w(read write …)a)
      :ok = Linx.Seccomp.install(c, filter)
      :ok = Linx.Process.proceed(c)
  """
  @spec install(Linx.Process.t(), Filter.t()) ::
          :ok
          | {:error,
             :not_ready
             | :running
             | :no_process}
  def install(session, %Filter{bpf: bpf}) when is_pid(session) and is_binary(bpf) do
    GenServer.call(session, {:seccomp_install, bpf})
  end

  # ── Validation helpers ────────────────────────────────────────
  # Used by from_rules/1 + the sugar verbs. Tagged-tuple errors for
  # caller-side validation (unknown syscall, bad action, duplicate rule).

  defp validate_arch(:unsupported), do: {:error, {:unsupported_arch, :unsupported}}
  defp validate_arch(arch) when is_atom(arch), do: :ok

  # Walk the rules list, accumulating seen syscalls to detect
  # duplicates. Short-circuits on the first malformed rule / unknown
  # syscall / duplicate per the PLAN's S1 contract.
  defp validate_rules(rules, arch) do
    do_validate_rules(rules, arch, MapSet.new())
  end

  defp do_validate_rules([], _arch, _seen), do: :ok

  defp do_validate_rules([{action, syscall} | rest], arch, seen)
       when is_atom(syscall) do
    cond do
      not valid_action?(action) ->
        {:error, {:bad_action, action}}

      not Syscalls.known?(syscall, arch) ->
        {:error, {:unknown_syscall, syscall}}

      MapSet.member?(seen, syscall) ->
        {:error, {:duplicate_rule, syscall}}

      true ->
        do_validate_rules(rest, arch, MapSet.put(seen, syscall))
    end
  end

  defp do_validate_rules([bad | _rest], _arch, _seen) do
    {:error, {:bad_rule, bad}}
  end

  @doc false
  # Exported because the Builder needs the same validation predicate.
  @spec validate_action(term()) :: :ok | {:error, {:bad_action, term()}}
  def validate_action(action) do
    if valid_action?(action) do
      :ok
    else
      {:error, {:bad_action, action}}
    end
  end

  # `Linx.Seccomp.Constants.action_to_u32/1` raises on a bad action;
  # we use that as the oracle so the two stay in sync. Validation is
  # build-time, not hot-path — rescue cost is irrelevant here.
  defp valid_action?(action) do
    _ = Constants.action_to_u32(action)
    true
  rescue
    ArgumentError -> false
  end
end
