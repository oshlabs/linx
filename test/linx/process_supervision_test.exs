defmodule Linx.ProcessSupervisionTest do
  use ExUnit.Case, async: true

  # Abnormal exits (the supervised-restart cases) log crash reports by design;
  # capture them so expected failures don't clutter the suite output.
  @moduletag capture_log: true

  alias Linx.Process, as: P
  alias Linx.Process.Error

  # Phase 6: supervision ergonomics — child_spec/1, outcome-derived exit
  # reasons (linger: false), auto_proceed, and reliable OS-process reaping.
  # All unprivileged: plain /bin workloads, no namespaces, no root.

  describe "child_spec/1" do
    test "builds a worker spec that runs spawn/1 with linger: false" do
      spec = P.child_spec(argv: ["/bin/true"])

      assert %{id: Linx.Process, restart: :permanent, shutdown: 5_000, type: :worker} = spec
      assert {Linx.Process, :spawn, [opts]} = spec.start
      assert opts[:argv] == ["/bin/true"]
      assert opts[:linger] == false
    end

    test "honours :id/:restart/:shutdown and keeps an explicit :linger" do
      spec =
        P.child_spec(
          argv: ["/bin/true"],
          id: :myd,
          restart: :transient,
          shutdown: 1_000,
          linger: true
        )

      assert spec.id == :myd
      assert spec.restart == :transient
      assert spec.shutdown == 1_000

      {Linx.Process, :spawn, [opts]} = spec.start
      assert opts[:linger] == true
      # The child-spec controls are stripped from the spawn opts.
      refute Keyword.has_key?(opts, :id)
      refute Keyword.has_key?(opts, :restart)
    end
  end

  describe "linger: false — outcome-derived exit reasons" do
    setup do
      # spawn/1 links the session to us; trap exits so an abnormal stop is a
      # message, not a crash of the test.
      Process.flag(:trap_exit, true)
      :ok
    end

    test "a clean exit (0) stops the session :normal" do
      {:ok, s} = P.spawn(argv: ["/bin/true"], linger: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(s)
      assert_receive {:EXIT, ^s, :normal}, 2_000
    end

    test "a non-zero exit stops with {:exited, code}" do
      {:ok, s} = P.spawn(argv: ["/bin/sh", "-c", "exit 7"], linger: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(s)
      assert_receive {:EXIT, ^s, {:exited, 7}}, 2_000
    end

    test "a killed workload stops with {:signaled, signum}" do
      {:ok, s} = P.spawn(argv: ["/bin/sleep", "60"], linger: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(s)
      assert_receive {:linx_process, :running}, 2_000
      :ok = P.signal(s, 9)
      assert_receive {:EXIT, ^s, {:signaled, 9}}, 2_000
    end

    test "an abort at the checkpoint stops with {:shutdown, :aborted}" do
      {:ok, s} = P.spawn(argv: ["/bin/true"], linger: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.abort(s)
      assert_receive {:EXIT, ^s, {:shutdown, :aborted}}, 2_000
    end

    test "an execve failure stops with {:error, %Error{}}" do
      {:ok, s} = P.spawn(argv: ["/this/does/not/exist"], linger: false)
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(s)
      assert_receive {:EXIT, ^s, {:error, %Error{stage: :execve, errno: :enoent}}}, 2_000
    end
  end

  describe "linger: true (default)" do
    test "keeps the session alive after exit, so wait/1 still answers" do
      {:ok, s} = P.spawn(argv: ["/bin/true"])
      assert_receive {:linx_process, :ready, _}, 2_000
      :ok = P.proceed(s)
      assert_receive {:linx_process, :exited, 0}, 2_000

      assert Process.alive?(s)
      assert {:ok, {:exited, 0}} = P.wait(s)
    end
  end

  describe "auto_proceed" do
    test "advances past the checkpoint with no external proceed/1" do
      {:ok, _s} = P.spawn(argv: ["/bin/sh", "-c", "exit 3"], auto_proceed: true)
      assert_receive {:linx_process, :ready, _}, 2_000
      # No proceed/1 call — auto_proceed drives it.
      assert_receive {:linx_process, :running}, 2_000
      assert_receive {:linx_process, :exited, 3}, 2_000
    end
  end

  describe "OS-process reaping" do
    test "a graceful stop reaps the running workload (no leak)" do
      {:ok, s} = P.spawn(argv: ["/bin/sleep", "60"], auto_proceed: true)
      assert_receive {:linx_process, :running}, 2_000
      {:ok, host_pid} = P.host_pid(s)
      assert File.dir?("/proc/#{host_pid}")

      # Graceful stop runs terminate/2, which tells the agent to SIGKILL +
      # waitpid the workload before the port closes.
      :ok = GenServer.stop(s)

      assert await_gone("/proc/#{host_pid}", 100)
    end

    test "supervisor :shutdown (an exit signal, not GenServer.stop) reaps" do
      {:ok, sup} = start_supervised({DynamicSupervisor, strategy: :one_for_one})

      spec = P.child_spec(argv: ["/bin/sleep", "60"], owner: self(), auto_proceed: true)
      {:ok, s} = DynamicSupervisor.start_child(sup, spec)

      assert_receive {:linx_process, :running}, 2_000
      {:ok, host_pid} = P.host_pid(s)
      assert File.dir?("/proc/#{host_pid}")

      # terminate_child delivers exit(:shutdown) — only a trap_exit'ing
      # session runs terminate/2 (and thus reaps) on this path.
      :ok = DynamicSupervisor.terminate_child(sup, s)

      assert await_gone("/proc/#{host_pid}", 100)
    end

    test "a crashing linked spawn/1 caller reaps (no orphan)" do
      parent = self()

      helper =
        spawn(fn ->
          {:ok, s} = P.spawn(argv: ["/bin/sleep", "60"], auto_proceed: true)

          receive do
            {:linx_process, :running} -> :ok
          end

          {:ok, host_pid} = P.host_pid(s)
          send(parent, {:session, s, host_pid})

          receive do
            :crash -> exit(:boom)
          end
        end)

      assert_receive {:session, s, host_pid}, 2_000
      assert File.dir?("/proc/#{host_pid}")

      ref = Process.monitor(s)
      send(helper, :crash)

      # The caller's exit signal propagates over the link; the session must
      # terminate with the same reason *after* reaping the workload.
      assert_receive {:DOWN, ^ref, :process, ^s, :boom}, 2_000
      assert await_gone("/proc/#{host_pid}", 100)
    end
  end

  describe "under a DynamicSupervisor" do
    test "restarts on abnormal exit, with the same arguments (:transient)" do
      # max_restarts high so the (intentionally looping) child doesn't trip the
      # supervisor's intensity limit during the test; ExUnit tears it down.
      {:ok, sup} =
        start_supervised({DynamicSupervisor, strategy: :one_for_one, max_restarts: 1_000})

      spec =
        P.child_spec(
          # A brief sleep slows the restart loop so it stays tidy.
          argv: ["/bin/sh", "-c", "sleep 0.05; exit 7"],
          owner: self(),
          auto_proceed: true,
          restart: :transient
        )

      {:ok, _} = DynamicSupervisor.start_child(sup, spec)

      # First run exits 7 (abnormal) → supervisor restarts → second run, same
      # argv, exits 7 again.
      assert_receive {:linx_process, :exited, 7}, 3_000
      assert_receive {:linx_process, :exited, 7}, 3_000
    end

    test "does not restart on a clean exit (:transient)" do
      {:ok, sup} = start_supervised({DynamicSupervisor, strategy: :one_for_one})

      spec =
        P.child_spec(argv: ["/bin/true"], owner: self(), auto_proceed: true, restart: :transient)

      {:ok, _} = DynamicSupervisor.start_child(sup, spec)

      assert_receive {:linx_process, :exited, 0}, 3_000
      refute_receive {:linx_process, :exited, 0}, 500
    end
  end

  defp await_gone(_path, 0), do: false

  defp await_gone(path, attempts) do
    if File.exists?(path) do
      Process.sleep(20)
      await_gone(path, attempts - 1)
    else
      true
    end
  end
end
