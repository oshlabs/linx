defmodule Linx.Process do
  @moduledoc """
  Linux process-lifecycle primitives — `clone(2)` with namespace flags,
  `setns(2)`, `execve(2)`, signal delivery and exit-status reporting —
  exposed through one GenServer per spawned child.

  ## Why a separate OS process

  `clone()`, `fork()` and `unshare()` performed inside the multithreaded
  BEAM corrupt the VM. So the actual syscalls live in a small external C
  binary — `priv/linx_process`, built from `c_src/linx_process.c` by the
  `:linx_process` Mix compiler — spawned via `Port.open` with
  `:nouse_stdio` and `{:packet, 4}` framing. Control traffic is Erlang
  External Term Format on fd 3 (BEAM → binary) and fd 4 (binary → BEAM);
  fd 0/1/2 stay free for the workload's stdio.

  This module IS the GenServer. The pid returned by `spawn/1` (and later
  `enter/2`) is the session handle: pass it to `proceed/1`, `signal/2`,
  `wait/1`, `info/1`, and `pty_master/1`.

  ## Owner events

  The owner (the caller of `spawn/1`, or `:owner` explicitly) receives
  these messages over the course of a session:

    * `{:linx_process, :ready, child_pid}` — the child reached the
      checkpoint. `child_pid` is the child's pid *as the child sees it*
      (1 inside a fresh PID namespace; otherwise the host pid). Use
      `host_pid/1` for the host's view.
    * `{:linx_process, :running}` — the child has `execve`'d the
      workload.
    * `{:linx_process, :exited, code}` — the workload exited normally.
    * `{:linx_process, :signaled, signum}` — the workload was killed
      by a signal.
    * `{:linx_process, :aborted}` — `abort/1` succeeded; the workload
      never reached `execve`.
    * `{:linx_process, :pty_out, binary}` — PTY mode only; bytes the
      workload wrote to its terminal.
    * `{:linx_process, :error, errno, stage}` — a pre-exec failure or
      a transport-level problem; see the stage table below.

  Each session emits exactly one terminal event (`:exited` /
  `:signaled` / `:aborted` / `:error`) and then no further owner
  messages follow. The GenServer stays alive so `wait/1` callers
  blocked on it can still receive the recorded answer; it terminates
  with the linked `spawn/1` caller.

  ## Error stages

  The `stage` atom in `{:linx_process, :error, errno, stage}` names
  what failed. The `errno` is a POSIX errno integer (per
  `linux/asm-generic/errno-base.h`), with two exceptions noted below.

  ### Syscall failures in the agent (pre-clone setup)

    * `:posix_openpt`, `:ptsetup`, `:ptsname`, `:pts_open` — PTY pair
      creation (PTY mode only).
    * `:sigprocmask`, `:pipe2`, `:signalfd` — internal pipe and signal
      plumbing.

  ### Process creation

    * `:clone` — `clone(2)` failed (spawn mode).
    * `:fork` — `fork(2)` failed (enter mode).

  ### Namespace entry (enter mode only)

    * `:open_ns_<type>` — `/proc/<target>/ns/<type>` couldn't be
      opened. `<type>` is one of `user mnt uts ipc cgroup net time pid`.
    * `:setns_<type>` — `setns(2)` failed for that namespace.

  ### Child-side pre-exec failures (post-checkpoint)

    * `:stdio` — `apply_stdio` failed (dup2 onto 0/1/2, AF_UNIX
      connect for `{:connect_unix, _}`, or the PTY slave's `TIOCSCTTY`).
    * `:execve` — `execve(2)` returned (i.e. failed).
    * `:cap_drop_bounding`, `:cap_set_thread`, `:cap_set_ambient` —
      one of the K2 capability syscalls failed in the child
      (`Linx.Capabilities`).
    * `:seccomp_install` — `seccomp(SECCOMP_SET_MODE_FILTER, …)` failed
      in the child (`Linx.Seccomp.install/2`). Common errno is `EINVAL`
      (22) for a malformed cBPF blob; `EPERM` (1) when the caller is
      unprivileged and `PR_SET_NO_NEW_PRIVS` isn't on (and the
      "be helpful" auto-set also failed).
    * `:seccomp_no_new_privs` — `prctl(PR_SET_NO_NEW_PRIVS, 1)` failed
      in the child. Rare; the only documented failure mode is `EINVAL`
      under an exotic LSM policy.

  ### Transport (BEAM ↔ agent wire)

    * `:malformed_request` — the agent couldn't parse the
      `{:spawn, _}` / `{:enter, _}` request. `errno` is `EINVAL` (22).
    * `:request_too_big` — the request exceeded the agent's 32 KiB
      buffer. `errno` is `EMSGSIZE` (90).
    * `:command_too_big` — a post-`:running` command exceeded the
      buffer; the session is torn down. `errno` is `EMSGSIZE`.
    * `:ready_frame` — couldn't read the `{:ready, _}` frame from
      the child (child died early, internal pipe broke). `errno` is
      the underlying I/O error or `EIO` on EOF.
    * `:malformed_ready` — got bytes but couldn't decode them as a
      `{:ready, _}` ei frame. `errno` is `EPROTO` (71).
    * `:exec_outcome` — couldn't read the post-`:proceed` outcome
      from the child. `errno` is `EIO`.

  ### Catastrophic agent failure (BEAM-side synthesised)

    * `:agent_died` — the agent process exited without sending any
      terminal status frame (segfault, OOM-kill, hard `_exit` from
      an unanticipated path). **The second element is the agent's
      exit code**, not a POSIX errno; the `:agent_died` stage tag
      is the signal that interpretation differs. This message is
      synthesised by the BEAM-side GenServer on
      `{port, {:exit_status, _}}` when no other terminal has been
      recorded yet, so the owner never hangs.

  ## Status

  P0–P6 shipped: scaffolding, `spawn/1` with the checkpoint protocol,
  `signal/2` / `wait/1`, `enter/2` (setns + fork into a target's
  namespaces), PTY mode (`stdio: :pty` + `pty_master/1` /
  `pty_write/2` / `pty_set_winsize/3`), `abort/1`, `host_pid/1`. The
  K2 cap commands (`drop_bounding/2` / `set_thread_sets/2` /
  `set_ambient/2`) live in `Linx.Capabilities` but hook into this
  module's checkpoint window. `info/1` is still a stub. See
  `docs/process/PLAN.md` for the roadmap.
  """

  use GenServer

  require Logger

  # The pid that `spawn/1` and `enter/2` return is the GenServer pid.
  @type t :: pid()

  # The kinds of namespace the child may be cloned into (P1) or join (P3).
  # Each maps to a CLONE_NEW* flag in the C agent.
  @type namespace :: :net | :mount | :pid | :uts | :ipc | :user | :cgroup | :time

  @valid_namespaces ~w(net mount pid uts ipc user cgroup time)a
  @valid_stdio_atoms ~w(inherit devnull pty)a
  @valid_per_fd_atoms ~w(inherit devnull)a

  # Atoms the C agent can send back as the `stage` field of {:error, errno,
  # stage}. The Port's data is decoded with `:safe`, which requires every
  # atom in the term to already exist in the BEAM — so this list exists
  # solely to ensure these atoms are loaded at module compile time. (Naming
  # mirrors what the agent emits: `setns_<ns>` / `open_ns_<ns>` per type.)
  @error_stages [
    :execve,
    :clone,
    :fork,
    :stdio,
    :posix_openpt,
    :ptsetup,
    :ptsname,
    :pts_open,
    :setns_user,
    :setns_mount,
    :setns_uts,
    :setns_ipc,
    :setns_cgroup,
    :setns_net,
    :setns_time,
    :setns_pid,
    :open_ns_user,
    :open_ns_mount,
    :open_ns_uts,
    :open_ns_ipc,
    :open_ns_cgroup,
    :open_ns_net,
    :open_ns_time,
    :open_ns_pid,
    :seccomp_install,
    :seccomp_no_new_privs
  ]

  @doc false
  def __error_stages__, do: @error_stages

  @doc """
  Spawns a child process via `clone(2)`, optionally into fresh namespaces.

  Returns `{:ok, pid}` — the pid of the GenServer that owns the child and
  is the session handle.

  `opts`:

    * `:argv` (required) — the workload argv as a list of binaries. The
      first element is the absolute path of the executable; no `$PATH`
      lookup is performed.
    * `:namespaces` — list of `t:namespace/0` atoms to create fresh.
      Defaults to `[]` (share all of the BEAM's namespaces).
    * `:env` — environment as a list of `"KEY=VALUE"` binaries. Defaults
      to inheriting the BEAM's environment.
    * `:owner` — pid to receive lifecycle events. Defaults to the caller.
    * `:stdio` — workload fd 0/1/2 plumbing. See "Stdio plumbing" below.

  ## Stdio plumbing

  `:stdio` is either a single atom shorthand applying to all three fds,
  or a keyword list giving per-fd directives.

  **Shorthand atoms:**

    * `:inherit` (default) — the workload inherits the BEAM's stdio.
    * `:devnull` — all three fds are `/dev/null`.
    * `:pty` — the agent creates a PTY pair; the workload becomes
      session leader with the slave as its controlling terminal, with
      0/1/2 dup'd onto it. The master end stays in the agent and the
      bytes are proxied through the existing control channel: writes
      via `pty_write/2`, reads delivered to the owner as
      `{:linx_process, :pty_out, bytes}`.

  **Per-fd keyword list** — `[stdin: dir, stdout: dir, stderr: dir]`,
  each `dir` one of:

    * `:inherit` — leave that fd untouched.
    * `:devnull` — dup `/dev/null` onto it.
    * `{:connect_unix, "/path/to/socket"}` — the workload connects an
      `AF_UNIX` stream socket to `path` and dup2's it onto the fd. The
      listener at `path` is the caller's responsibility (must be
      `:gen_tcp.listen`-ing before `spawn/1`).

  Per-fd PTY directives are not supported — a PTY is one device shared
  across all three fds; use the `:pty` shorthand.
  """
  @spec spawn(keyword) :: {:ok, t()} | {:error, term}
  def spawn(opts) do
    owner = Keyword.get(opts, :owner, self())

    with {:ok, request} <- build_spawn_request(opts) do
      GenServer.start_link(__MODULE__, {{:spawn, request}, owner})
    end
  end

  @doc """
  Runs a new process *inside* an existing target's namespaces via
  `setns(2)` + `execve(2)`.

  The agent opens `/proc/<target_pid>/ns/<type>` for each namespace
  type and `setns(2)`s into each, then `fork(2)`s — the child inherits
  the target's namespaces and `execve`s the workload there. Same
  checkpoint protocol as `spawn/1`: the owner gets `:ready` →
  `proceed/1` → `:running` → terminal.

  `target_pid` is the *host* pid of the process whose namespaces you
  want to join (the pid you saw in `{:linx_process, :ready, _}` when
  `:pid` was *not* in that session's `:namespaces`, or the host pid
  reported by `Linx.Process.info/1` for sessions that include
  `:pid`).

  `opts`:

    * `:argv` (required) — the workload argv.
    * `:namespaces` — which of the target's namespaces to join.
      Defaults to *all* — every namespace type the target has under
      `/proc/<target>/ns/`. Pass a list (e.g. `[:net]`) to join only
      those.
    * `:env` — workload environment as `["KEY=VAL", …]`. Defaults to
      inherit.
    * `:owner` — pid to receive lifecycle events. Defaults to the
      caller.
  """
  @spec enter(pos_integer, keyword) :: {:ok, t()} | {:error, term}
  def enter(target_pid, opts)
      when is_integer(target_pid) and target_pid > 0 and is_list(opts) do
    owner = Keyword.get(opts, :owner, self())

    with {:ok, request} <- build_enter_request(target_pid, opts) do
      GenServer.start_link(__MODULE__, {{:enter, request}, owner})
    end
  end

  @doc """
  Advances the child past the checkpoint: the agent forwards `:proceed`
  to the cloned child, which then `execve`s the workload.

  The wire-level command this sends is `:proceed`, which is also the
  Elixir verb name — one word for the same action on both sides of
  the Port boundary.

  Returns `:ok`, `{:error, :not_ready}` if the agent has not yet
  reported `:ready` (i.e. there is no checkpoint to advance past),
  or `{:error, :no_process}` if the workload has already
  reached a terminal stage — calling `proceed/1` on a session
  whose workload has already exited / aborted / errored is a
  no-op the GenServer refuses cleanly rather than sending a
  stale `:proceed` to an agent that's been collected.
  """
  @spec proceed(t()) :: :ok | {:error, term}
  def proceed(session) when is_pid(session) do
    GenServer.call(session, :proceed)
  end

  @doc """
  Sends OS signal `signum` to the workload.

  Signals delivered before the workload has `execve`'d (between
  `spawn/1` and `proceed/1`, or before the agent emits `:running`) are
  buffered and flushed in order at the moment of `:running`. Signals
  delivered after the workload has exited return `{:error, :no_process}`.

  This is fire-and-forget — `signal/2` returns as soon as the signal
  has been handed to the agent (or buffered), without waiting for the
  kernel to deliver it. Use `wait/1` to observe the workload's
  response.
  """
  @spec signal(t(), pos_integer) :: :ok | {:error, term}
  def signal(session, signum) when is_pid(session) and is_integer(signum) and signum > 0 do
    GenServer.call(session, {:signal, signum})
  end

  @doc """
  Releases a parked session **without** running the workload. The
  alternative to `proceed/1` from the `:ready` state.

  When the agent is parked at the checkpoint (post-`:ready`,
  pre-`:running`), `abort/1` tells it to discard the cloned child
  rather than letting it `execve`. The agent closes the child's
  unblock pipe so the child sees EOF and `_exit`s, reaps it, and
  emits `{:status, :aborted, child_pid}` over the control channel.
  The owner then receives `{:linx_process, :aborted}` and the
  session moves to its terminal state.

  ## Use cases

    * **Setup-time rollback.** A container engine starts spawning,
      discovers setup can't complete (cgroup creation fails, a
      bind mount errors, …), and wants to cancel the workload
      cleanly without it running for even one instruction.
    * **Checkpoint-only verification.** A test or health check
      that wants to confirm namespace setup *worked* without
      actually running the workload — e.g. an integration test
      that pivots `/proc` inside a fresh mount namespace and just
      wants to verify via mountinfo.
    * **Race-with-decision.** The owner's "should I proceed?"
      logic returns false; `abort/1` is the clean discard.

  ## State semantics

    * **Pre-`:ready`** — buffered; fires the moment `:ready`
      arrives. Same shape as `signal/2`'s pre-`:running`
      buffering.
    * **`:ready` (parked)** — primary case; immediate abort.
    * **`:running`** — `{:error, :running}`. The workload is
      past the checkpoint; use `signal/2` to terminate it.
    * **Already terminal** — `{:error, :no_process}`.

  Fire-and-forget — `abort/1` returns as soon as the agent has
  the request. Use `wait/1` to block on the `:aborted` terminal
  event.
  """
  @spec abort(t()) :: :ok | {:error, :running | :no_process}
  def abort(session) when is_pid(session) do
    GenServer.call(session, :abort)
  end

  @doc """
  Returns the workload's pid **as the host sees it**.

  `Linx.Process` delivers two different pid views via lifecycle
  events:

    * `{:linx_process, :ready, child_pid}` — the *child's own* view
      of its pid. When `:pid` is in the namespaces list, this is
      `1` (the child is PID 1 inside its fresh PID namespace).
      Without `:pid`, it equals the host pid.
    * The host's view of the child's pid is reported by the agent
      separately (via `:spawned`, before `:ready`) and stored in
      the session's state. `host_pid/1` returns it.

  Use `host_pid/1` when you need to address the workload from
  the host — typically for procfs paths like
  `/proc/<host_pid>/{ns,uid_map,gid_map,setgroups,mountinfo}`.
  Every cross-namespace primitive in Linx (`Linx.Mount`'s
  `:in: {:pid, _}`, `Linx.User.set_uid_map/2`, `Linx.User.setup_maps/2`)
  wants the host pid.

  ## Returns

    * `{:ok, host_pid}` — the agent has reported `:spawned` (which
      arrives before `:ready`), so the value is available.
    * `{:error, :not_ready}` — the spawn hasn't progressed far
      enough yet. Typically only possible if you call `host_pid/1`
      synchronously after `spawn/1` without first awaiting any
      lifecycle event. Once you've seen `:ready`, `host_pid/1`
      always succeeds.

  ## Example

      {:ok, c} = Linx.Process.spawn(argv: [...], namespaces: [:user, :pid])
      receive do {:linx_process, :ready, _child_view} -> :ok end
      {:ok, host_pid} = Linx.Process.host_pid(c)
      :ok = Linx.User.setup_maps(host_pid, uid: [...], gid: [...])
  """
  @spec host_pid(t()) :: {:ok, pos_integer()} | {:error, :not_ready}
  def host_pid(session) when is_pid(session) do
    GenServer.call(session, :host_pid)
  end

  @doc """
  Synchronously waits for the workload's terminal event.

  Returns one of:

    * `{:ok, {:exited, code}}` — workload exited with `code`.
    * `{:ok, {:signaled, signum}}` — workload was killed by `signum`.
    * `{:ok, :aborted}` — `abort/1` was called from the checkpoint;
      the workload never ran.
    * `{:error, %{errno: errno, stage: stage}}` — a pre-exec failure;
      the workload never ran.
    * `{:error, :timeout}` — `timeout` elapsed before any terminal
      event arrived. The session is still alive; call `wait/1` again.
    * `{:error, :no_process}` — the session GenServer is gone (e.g.
      the agent crashed before reporting a terminal event).

  Multiple processes may wait on the same session concurrently; all
  receive the same answer when it arrives.
  """
  @spec wait(t(), timeout()) ::
          {:ok, {:exited, non_neg_integer} | {:signaled, pos_integer} | :aborted}
          | {:error, term}
  def wait(session, timeout \\ :infinity)

  def wait(session, timeout) when is_pid(session) do
    GenServer.call(session, :wait, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _ -> {:error, :no_process}
  end

  @doc """
  Returns a snapshot of the session's state as a `%Linx.Process.Info{}`.

  Cheap — a single `GenServer.call` returning the relevant fields
  from the GenServer's internal state. Safe to call at any point
  in the lifecycle, including post-terminal.

  ## Examples

      iex> {:ok, c} = Linx.Process.spawn(argv: ["/bin/sleep", "10"])
      iex> {:ok, info} = Linx.Process.info(c)
      iex> info.mode
      :spawn
      iex> info.stage in [:starting, :spawned, :ready]
      true

  See `Linx.Process.Info` for the full field list and the eight
  possible `:stage` atoms.
  """
  @spec info(t()) :: {:ok, Linx.Process.Info.t()} | {:error, term}
  def info(session) when is_pid(session) do
    GenServer.call(session, :info)
  catch
    :exit, _ -> {:error, :no_process}
  end

  @doc """
  Writes bytes to the workload's PTY master, which the workload sees as
  input on its stdin.

  Returns `{:error, :no_pty}` if the session was not started with
  `stdio: :pty`; `{:error, :no_process}` if the workload has already
  terminated (reached any of `:exited` / `:signaled` / `:aborted` /
  `:errored`) — the call refuses immediately rather than firing a
  Port.command at an agent that's been collected or is about to be.

  Fire-and-forget on the happy path — bytes are handed to the agent
  (and from there to the PTY); there is no acknowledgement.
  """
  @spec pty_write(t(), iodata()) :: :ok | {:error, term}
  def pty_write(session, bytes) when is_pid(session) do
    GenServer.call(session, {:pty_write, IO.iodata_to_binary(bytes)})
  end

  @doc """
  Sets the workload's PTY window size (`TIOCSWINSZ` on the master end,
  via the agent).

  Accepts either a 4-tuple `{rows, cols, xpixel, ypixel}` or any map
  / struct exposing those fields (`Linx.Tty.WindowSize` is the
  canonical such struct, but `Linx.Process` deliberately doesn't
  depend on `Linx.Tty` — duck-typing on the field shape avoids the
  cross-subsystem dependency).

  Best-effort on the agent side: the workload will see `SIGWINCH` and
  the new size on its next `TIOCGWINSZ`, but no error is propagated
  back if the ioctl fails.

  Returns `{:error, :no_pty}` if the session wasn't started with
  `stdio: :pty`; `{:error, :no_process}` if the workload has
  already terminated.
  """
  @spec pty_set_winsize(
          t(),
          {non_neg_integer, non_neg_integer, non_neg_integer, non_neg_integer}
          | %{
              :rows => non_neg_integer,
              :cols => non_neg_integer,
              :xpixel => non_neg_integer,
              :ypixel => non_neg_integer,
              optional(any) => any
            }
        ) :: :ok | {:error, term}
  def pty_set_winsize(session, {rows, cols, xpix, ypix})
      when is_pid(session) and is_integer(rows) and is_integer(cols) and
             is_integer(xpix) and is_integer(ypix) and
             rows >= 0 and cols >= 0 and xpix >= 0 and ypix >= 0 do
    GenServer.call(session, {:pty_winsize, {rows, cols, xpix, ypix}})
  end

  def pty_set_winsize(session, %{rows: r, cols: c, xpixel: xp, ypixel: yp}) do
    pty_set_winsize(session, {r, c, xp, yp})
  end

  @doc """
  Returns `{:ok, session}` if the session was started with `stdio: :pty`
  — the session pid is itself the handle to read from (via
  `{:linx_process, :pty_out, _}` events on the owner) and to write to
  (via `pty_write/2`). Returns `{:error, :no_pty}` otherwise.

  A future `Linx.Tty` subsystem will likely return something richer here
  — a struct wrapping the session, terminal-mode helpers, etc. For
  now it just confirms PTY-mode-ness.
  """
  @spec pty_master(t()) :: {:ok, t()} | {:error, term}
  def pty_master(session) when is_pid(session) do
    GenServer.call(session, :pty_master)
  end

  # --- input validation -----------------------------------------------------

  defp build_spawn_request(opts) do
    with {:ok, argv} <- fetch_argv(opts),
         {:ok, namespaces} <- fetch_namespaces(opts),
         {:ok, env} <- fetch_env(opts),
         {:ok, stdio} <- fetch_stdio(opts),
         {:ok, nnp} <- fetch_no_new_privs(opts) do
      request = %{argv: argv, namespaces: namespaces}
      request = if env, do: Map.put(request, :env, env), else: request
      request = if stdio, do: Map.put(request, :stdio, stdio), else: request
      request = if nnp, do: Map.put(request, :no_new_privs, true), else: request
      {:ok, request}
    end
  end

  # Enter mode omits :namespaces from the request map when the caller did
  # not specify one — the C side treats an absent :namespaces key as
  # "join every namespace the target has under /proc/<pid>/ns/".
  defp build_enter_request(target_pid, opts) do
    with {:ok, argv} <- fetch_argv(opts),
         {:ok, namespaces} <- fetch_optional_namespaces(opts),
         {:ok, env} <- fetch_env(opts),
         {:ok, stdio} <- fetch_stdio(opts),
         {:ok, nnp} <- fetch_no_new_privs(opts) do
      request = %{target: target_pid, argv: argv}
      request = if namespaces, do: Map.put(request, :namespaces, namespaces), else: request
      request = if env, do: Map.put(request, :env, env), else: request
      request = if stdio, do: Map.put(request, :stdio, stdio), else: request
      request = if nnp, do: Map.put(request, :no_new_privs, true), else: request
      {:ok, request}
    end
  end

  # Boolean opt; absent or false → omit from the wire request entirely.
  # The agent's default is "NNP off" and we want the wire shape to match
  # callers that don't think about this opt at all.
  defp fetch_no_new_privs(opts) do
    case Keyword.fetch(opts, :no_new_privs) do
      :error -> {:ok, false}
      {:ok, true} -> {:ok, true}
      {:ok, false} -> {:ok, false}
      {:ok, _other} -> {:error, :bad_no_new_privs}
    end
  end

  defp fetch_argv(opts) do
    case Keyword.get(opts, :argv) do
      [head | _] = argv when is_binary(head) ->
        if Enum.all?(argv, &is_binary/1),
          do: {:ok, argv},
          else: {:error, :bad_argv}

      _ ->
        {:error, :argv_required}
    end
  end

  defp fetch_namespaces(opts) do
    case Keyword.get(opts, :namespaces, []) do
      list when is_list(list) ->
        if Enum.all?(list, &(&1 in @valid_namespaces)),
          do: {:ok, list},
          else: {:error, {:bad_namespaces, list -- @valid_namespaces}}

      _ ->
        {:error, :bad_namespaces}
    end
  end

  # As above, but `:error` from Keyword.fetch — "key absent" — passes
  # through as `{:ok, nil}` so build_enter_request can elide :namespaces
  # from the wire request altogether.
  defp fetch_optional_namespaces(opts) do
    case Keyword.fetch(opts, :namespaces) do
      :error ->
        {:ok, nil}

      {:ok, list} when is_list(list) ->
        if Enum.all?(list, &(&1 in @valid_namespaces)),
          do: {:ok, list},
          else: {:error, {:bad_namespaces, list -- @valid_namespaces}}

      _ ->
        {:error, :bad_namespaces}
    end
  end

  defp fetch_env(opts) do
    case Keyword.fetch(opts, :env) do
      :error ->
        {:ok, nil}

      {:ok, list} when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, list},
          else: {:error, :bad_env}

      _ ->
        {:error, :bad_env}
    end
  end

  # Decode the :stdio option into a shape the C agent can parse:
  # either an atom (:inherit / :devnull / :pty), or a keyword list of
  # per-fd directives. Returns {:ok, nil} if the key was absent (so the
  # agent uses its built-in default, :inherit).
  defp fetch_stdio(opts) do
    case Keyword.fetch(opts, :stdio) do
      :error -> {:ok, nil}
      {:ok, atom} when atom in @valid_stdio_atoms -> {:ok, atom}
      {:ok, list} when is_list(list) -> validate_per_fd_stdio(list)
      _ -> {:error, :bad_stdio}
    end
  end

  defp validate_per_fd_stdio(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      {fd, directive}, {:ok, acc} when fd in [:stdin, :stdout, :stderr] ->
        case validate_per_fd_directive(directive) do
          :ok -> {:cont, {:ok, [{fd, directive} | acc]}}
          {:error, _} = err -> {:halt, err}
        end

      _other, _ ->
        {:halt, {:error, :bad_stdio}}
    end)
    |> case do
      {:ok, pairs} -> {:ok, Enum.reverse(pairs)}
      {:error, _} = err -> err
    end
  end

  defp validate_per_fd_directive(atom) when atom in @valid_per_fd_atoms, do: :ok

  defp validate_per_fd_directive({:connect_unix, path}) when is_binary(path),
    do: :ok

  defp validate_per_fd_directive(_), do: {:error, :bad_stdio}

  # --- GenServer ------------------------------------------------------------

  @impl true
  def init({command, owner}) when is_tuple(command) and tuple_size(command) == 2 do
    binary = Path.join(:code.priv_dir(:linx), "linx_process")

    if not File.exists?(binary) do
      {:stop, {:missing_binary, binary}}
    else
      port =
        Port.open(
          {:spawn_executable, binary},
          [:binary, :nouse_stdio, {:packet, 4}, :exit_status]
        )

      Port.command(port, :erlang.term_to_binary(command))

      {tag, _} = command

      state = %{
        port: port,
        owner: owner,
        mode: tag,
        host_pid: nil,
        child_pid: nil,
        running?: false,
        pending_signals: [],
        pending_abort?: false,
        waiters: [],
        result: nil,
        pty?: pty?(command)
      }

      {:ok, state}
    end
  end

  # A spawn/enter request is in PTY mode iff its :stdio key is exactly :pty.
  # Per-fd keyword lists never carry PTY (PTY needs all three fds wired to
  # the same slave).
  defp pty?({_tag, %{stdio: :pty}}), do: true
  defp pty?(_), do: false

  @impl true
  # Terminal first -- mirrors abort/1's guard so the two checkpoint
  # verbs respond consistently. Without this clause the child_pid
  # match below fires post-terminal (child_pid stays set after
  # :ready) and Port.command lands on a collected agent.
  def handle_call(:proceed, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call(:proceed, _from, %{port: port, child_pid: child_pid} = state)
      when child_pid != nil do
    Port.command(port, :erlang.term_to_binary(:proceed))
    {:reply, :ok, state}
  end

  def handle_call(:proceed, _from, state) do
    {:reply, {:error, :not_ready}, state}
  end

  # Terminal event already arrived -- nothing to abort.
  def handle_call(:abort, _from, %{result: result} = state) when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  # Already past the checkpoint -- abort is only valid pre-execve.
  def handle_call(:abort, _from, %{running?: true} = state) do
    {:reply, {:error, :running}, state}
  end

  # Parked at :ready -- forward :abort to the agent immediately.
  def handle_call(:abort, _from, %{port: port, child_pid: child_pid} = state)
      when child_pid != nil do
    Port.command(port, :erlang.term_to_binary(:abort))
    {:reply, :ok, state}
  end

  # Pre-:ready -- buffer the abort. The :ready handler in handle_info
  # fires it the moment the checkpoint is reached. Matches signal/2's
  # pre-:running buffering shape.
  def handle_call(:abort, _from, %{child_pid: nil} = state) do
    {:reply, :ok, %{state | pending_abort?: true}}
  end

  # K2 -- Linx.Capabilities write verbs. Three commands, all only
  # valid at the :ready checkpoint (between `:ready` and `proceed/1` /
  # `abort/1`). State-machine guards mirror what's documented on the
  # Linx.Capabilities verbs: :no_process > :running >
  # :not_ready > forward.
  for cmd_arity <- [{:cap_drop_bounding, 2}, {:cap_set_ambient, 2}, {:cap_set_thread, 4}] do
    {cmd, arity} = cmd_arity

    # Terminal first.
    def handle_call({unquote(cmd), _} = _call, _from, %{result: result} = state)
        when result != nil and unquote(arity) == 2 do
      {:reply, {:error, :no_process}, state}
    end

    def handle_call({unquote(cmd), _, _, _} = _call, _from, %{result: result} = state)
        when result != nil and unquote(arity) == 4 do
      {:reply, {:error, :no_process}, state}
    end

    # Past the checkpoint -- the agent is no longer in await_proceed.
    def handle_call({unquote(cmd), _} = _call, _from, %{running?: true} = state)
        when unquote(arity) == 2 do
      {:reply, {:error, :running}, state}
    end

    def handle_call({unquote(cmd), _, _, _} = _call, _from, %{running?: true} = state)
        when unquote(arity) == 4 do
      {:reply, {:error, :running}, state}
    end

    # Pre-checkpoint -- the agent hasn't gotten to the await_proceed
    # loop yet, so the command would be dropped or misordered.
    def handle_call({unquote(cmd), _} = _call, _from, %{child_pid: nil} = state)
        when unquote(arity) == 2 do
      {:reply, {:error, :not_ready}, state}
    end

    def handle_call({unquote(cmd), _, _, _} = _call, _from, %{child_pid: nil} = state)
        when unquote(arity) == 4 do
      {:reply, {:error, :not_ready}, state}
    end
  end

  # Parked at :ready -- forward each cap command to the agent. The
  # agent (await_proceed) forwards the same ei frame to the child
  # over the p2c pipe; the child applies via capset/prctl. Failures
  # come back asynchronously as {:linx_process, :error, errno,
  # :cap_*} via the existing pre-exec error path.
  def handle_call({:cap_drop_bounding, mask} = call, _from, %{port: port} = state)
      when is_integer(mask) and mask >= 0 do
    Port.command(port, :erlang.term_to_binary(call))
    {:reply, :ok, state}
  end

  def handle_call({:cap_set_ambient, mask} = call, _from, %{port: port} = state)
      when is_integer(mask) and mask >= 0 do
    Port.command(port, :erlang.term_to_binary(call))
    {:reply, :ok, state}
  end

  def handle_call(
        {:cap_set_thread, e, p, i} = call,
        _from,
        %{port: port} = state
      )
      when is_integer(e) and e >= 0 and is_integer(p) and p >= 0 and
             is_integer(i) and i >= 0 do
    Port.command(port, :erlang.term_to_binary(call))
    {:reply, :ok, state}
  end

  # S2 -- Linx.Seccomp.install/2. Same state-machine guards as the
  # K2 cap commands (:no_process > :running > :not_ready >
  # forward). The wire frame is {:seccomp_install, <<bpf>>}; the
  # agent forwards it verbatim to the child, which sets NNP (if not
  # on) and calls seccomp(SECCOMP_SET_MODE_FILTER) before execve.
  # Failures surface asynchronously as
  # {:linx_process, :error, errno, :seccomp_install | :seccomp_no_new_privs}.

  def handle_call({:seccomp_install, _bpf}, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call({:seccomp_install, _bpf}, _from, %{running?: true} = state) do
    {:reply, {:error, :running}, state}
  end

  def handle_call({:seccomp_install, _bpf}, _from, %{child_pid: nil} = state) do
    {:reply, {:error, :not_ready}, state}
  end

  def handle_call({:seccomp_install, bpf} = call, _from, %{port: port} = state)
      when is_binary(bpf) do
    Port.command(port, :erlang.term_to_binary(call))
    {:reply, :ok, state}
  end

  # host_pid/1 -- the value is set by handle_info on :spawned, which
  # arrives before :ready. If the caller asks before :spawned has
  # been processed (race-y but possible), they get :not_ready.
  def handle_call(:host_pid, _from, %{host_pid: nil} = state) do
    {:reply, {:error, :not_ready}, state}
  end

  def handle_call(:host_pid, _from, %{host_pid: host_pid} = state) do
    {:reply, {:ok, host_pid}, state}
  end

  # Snapshot of the session's lifecycle-relevant state, projected
  # through %Linx.Process.Info{}. Internal fields (port, owner,
  # pending queues, waiters) are deliberately omitted.
  def handle_call(:info, _from, state) do
    info = %Linx.Process.Info{
      mode: state.mode,
      stage: compute_stage(state),
      host_pid: state.host_pid,
      child_pid: state.child_pid,
      pty?: state.pty?,
      result: state.result
    }

    {:reply, {:ok, info}, state}
  end

  # The workload has already terminated; sending a signal would have no
  # target.
  def handle_call({:signal, _signum}, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  # Pre-running: buffer signals; flushed in handle_info on :running.
  def handle_call({:signal, signum}, _from, %{running?: false} = state) do
    {:reply, :ok, %{state | pending_signals: [signum | state.pending_signals]}}
  end

  # Running: forward directly to the agent.
  def handle_call({:signal, signum}, _from, %{port: port} = state) do
    Port.command(port, :erlang.term_to_binary({:signal, signum}))
    {:reply, :ok, state}
  end

  # Terminal event already arrived -- answer immediately.
  def handle_call(:wait, _from, %{result: result} = state) when result != nil do
    {:reply, normalise_result(result), state}
  end

  # Otherwise enqueue the caller; reply when the terminal event arrives.
  def handle_call(:wait, from, state) do
    {:noreply, %{state | waiters: [from | state.waiters]}}
  end

  # PTY write -- only valid when the session is in PTY mode and
  # the workload hasn't terminated yet. The result-set check runs
  # first so a pty_write on an exited / signaled / aborted /
  # errored session refuses immediately, instead of firing a
  # Port.command at an agent that's been collected or is about
  # to be.
  def handle_call({:pty_write, _bytes}, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call({:pty_write, bytes}, _from, %{pty?: true, port: port} = state)
      when port != nil do
    Port.command(port, :erlang.term_to_binary({:pty_in, bytes}))
    {:reply, :ok, state}
  end

  def handle_call({:pty_write, _bytes}, _from, %{pty?: false} = state) do
    {:reply, {:error, :no_pty}, state}
  end

  def handle_call({:pty_write, _bytes}, _from, state) do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call(:pty_master, _from, %{pty?: true} = state) do
    {:reply, {:ok, self()}, state}
  end

  def handle_call(:pty_master, _from, state) do
    {:reply, {:error, :no_pty}, state}
  end

  # Winsize forwarding -- only meaningful in PTY mode and only
  # while the workload is alive. Same result-set first ordering
  # as pty_write/2: refuses on terminated sessions without
  # firing a no-op Port.command at a closing agent.
  def handle_call({:pty_winsize, _ws}, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call({:pty_winsize, _ws}, _from, %{pty?: false} = state) do
    {:reply, {:error, :no_pty}, state}
  end

  def handle_call({:pty_winsize, _ws}, _from, %{port: nil} = state) do
    {:reply, {:error, :no_process}, state}
  end

  def handle_call({:pty_winsize, ws}, _from, %{port: port} = state) do
    Port.command(port, :erlang.term_to_binary({:pty_winsize, ws}))
    {:reply, :ok, state}
  end

  # Map the internal result tuple onto the shape `wait/1` documents.
  defp normalise_result({:exited, _} = r), do: {:ok, r}
  defp normalise_result({:signaled, _} = r), do: {:ok, r}
  defp normalise_result(:aborted), do: {:ok, :aborted}
  defp normalise_result({:error, _} = error), do: error

  # Collapse the four lifecycle bits (host_pid / child_pid / running? /
  # result) into one stage atom for %Linx.Process.Info{}. Terminal
  # stages win over pre-terminal -- once `result` is set, that's the
  # answer regardless of the other fields.
  defp compute_stage(%{result: {:exited, _}}), do: :exited
  defp compute_stage(%{result: {:signaled, _}}), do: :signaled
  defp compute_stage(%{result: :aborted}), do: :aborted
  defp compute_stage(%{result: {:error, _}}), do: :errored
  defp compute_stage(%{running?: true}), do: :running
  defp compute_stage(%{child_pid: pid}) when pid != nil, do: :ready
  defp compute_stage(%{host_pid: pid}) when pid != nil, do: :spawned
  defp compute_stage(_), do: :starting

  @impl true
  def handle_info({port, {:data, payload}}, %{port: port} = state) do
    case safe_decode(payload) do
      {:ok, frame} ->
        handle_agent_frame(frame, state)

      :error ->
        Logger.warning(
          "Linx.Process: dropped malformed agent frame (#{byte_size(payload)} bytes)"
        )

        {:noreply, state}
    end
  end

  # Agent died without ever recording a terminal status (e.g. crashed on
  # `return 2` for a malformed request, OOM-killed, segfaulted, …).
  # Synthesise an :agent_died error so the owner and any wait/1 callers
  # see a clean terminal instead of hanging. The second element of the
  # 4-tuple is the agent's process exit code, not a POSIX errno; the
  # :agent_died stage atom is the signal that interpretation differs.
  def handle_info(
        {port, {:exit_status, code}},
        %{port: port, result: nil} = state
      ) do
    send(state.owner, {:linx_process, :error, code, :agent_died})

    {:noreply, finalise(%{state | port: nil}, {:error, %{errno: code, stage: :agent_died}})}
  end

  def handle_info({port, {:exit_status, _code}}, %{port: port} = state) do
    # Terminal already recorded -- the agent exiting after :exited /
    # :signaled / :aborted / :error is the normal teardown path. Just
    # drop the port handle; wait/1 callers already have their answer
    # from the recorded result.
    {:noreply, %{state | port: nil}}
  end

  # Catch-all for stray messages: misroutes, late timer refs, monitor
  # notifications we didn't ask for, etc. Log and drop -- a bare
  # function_clause crash would take the session down and lose any
  # already-recorded terminal state.
  def handle_info(msg, state) do
    Logger.warning("Linx.Process: ignoring unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # Wrap binary_to_term/2 so a malformed payload doesn't crash the
  # GenServer. With :safe, decoding is bounded; the rescue is for the
  # truly malformed case where the framing itself is bad.
  defp safe_decode(payload) do
    {:ok, :erlang.binary_to_term(payload, [:safe])}
  rescue
    _ -> :error
  end

  # One clause per known agent frame shape. The fallthrough at the bottom
  # logs and drops, so a future C-side emit that the BEAM hasn't learned
  # about yet doesn't crash the GenServer.

  defp handle_agent_frame({:status, :spawned, host_pid}, state) do
    {:noreply, %{state | host_pid: host_pid}}
  end

  defp handle_agent_frame({:status, :ready, child_pid}, state) do
    send(state.owner, {:linx_process, :ready, child_pid})
    state = %{state | child_pid: child_pid}

    # Fire a buffered abort: an `abort/1` that landed before the
    # checkpoint is forwarded the moment the agent is parked there.
    state =
      if state.pending_abort? do
        Port.command(state.port, :erlang.term_to_binary(:abort))
        %{state | pending_abort?: false}
      else
        state
      end

    {:noreply, state}
  end

  defp handle_agent_frame({:status, :running}, state) do
    send(state.owner, {:linx_process, :running})
    flush_pending_signals(state)
    {:noreply, %{state | running?: true, pending_signals: []}}
  end

  defp handle_agent_frame({:status, :exited, code}, state) do
    send(state.owner, {:linx_process, :exited, code})
    {:noreply, finalise(state, {:exited, code})}
  end

  defp handle_agent_frame({:status, :signaled, signum}, state) do
    send(state.owner, {:linx_process, :signaled, signum})
    {:noreply, finalise(state, {:signaled, signum})}
  end

  defp handle_agent_frame({:status, :aborted, _child_pid}, state) do
    send(state.owner, {:linx_process, :aborted})
    {:noreply, finalise(state, :aborted)}
  end

  defp handle_agent_frame({:error, errno, stage}, state) do
    send(state.owner, {:linx_process, :error, errno, stage})
    {:noreply, finalise(state, {:error, %{errno: errno, stage: stage}})}
  end

  defp handle_agent_frame({:pty_out, bytes}, state) do
    send(state.owner, {:linx_process, :pty_out, bytes})
    {:noreply, state}
  end

  defp handle_agent_frame(other, state) do
    Logger.warning("Linx.Process: unrecognised agent frame: #{inspect(other)}")
    {:noreply, state}
  end

  # Any waiters still in the queue when the GenServer goes down -- e.g.
  # the spawn/1 caller dies before a terminal event arrives -- get
  # :no_process so they don't sit blocked forever.
  @impl true
  def terminate(_reason, state) do
    Enum.each(state.waiters, &GenServer.reply(&1, {:error, :no_process}))
    :ok
  end

  # Drain pending_signals to the agent in the order they were queued.
  defp flush_pending_signals(%{port: port, pending_signals: signals}) do
    Enum.each(Enum.reverse(signals), fn signum ->
      Port.command(port, :erlang.term_to_binary({:signal, signum}))
    end)
  end

  # Store the terminal result and answer every blocked wait/1 caller.
  defp finalise(state, result) do
    answer = normalise_result(result)
    Enum.each(state.waiters, &GenServer.reply(&1, answer))
    %{state | result: result, waiters: []}
  end
end
