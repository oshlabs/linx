defmodule Linx.ProcessTest do
  use ExUnit.Case, async: true

  describe "linx_process binary (P0 scaffolding)" do
    test "round-trips one ETF frame and exits cleanly" do
      binary = Path.join(:code.priv_dir(:linx), "linx_process")
      assert File.exists?(binary), "expected priv/linx_process to be built by mix compile"

      port =
        Port.open(
          {:spawn_executable, binary},
          [:binary, :nouse_stdio, {:packet, 4}, :exit_status]
        )

      # The P0 binary ignores the inbound frame and always replies :pong;
      # use :ping as the convention for what the real protocol will look
      # like in P1+.
      Port.command(port, :erlang.term_to_binary(:ping))

      assert_receive {^port, {:data, data}}, 1_000
      assert :erlang.binary_to_term(data, [:safe]) == :pong

      assert_receive {^port, {:exit_status, 0}}, 1_000
    end
  end

  describe "public API stubs" do
    # These verbs land in P1 (spawn/release), P2 (signal/wait), P3 (enter),
    # and P4 (pty_master). For P0 they exist as compilable stubs so callers
    # can see the surface; each returns :not_yet_implemented.

    test "spawn/1 is not yet implemented" do
      assert {:error, :not_yet_implemented} = Linx.Process.spawn(argv: ["/bin/true"])
    end

    test "enter/2 is not yet implemented" do
      assert {:error, :not_yet_implemented} = Linx.Process.enter(1, argv: ["/bin/true"])
    end

    test "release/1, signal/2, wait/1, info/1, pty_master/1 are not yet implemented" do
      sentinel = self()
      assert {:error, :not_yet_implemented} = Linx.Process.release(sentinel)
      assert {:error, :not_yet_implemented} = Linx.Process.signal(sentinel, 15)
      assert {:error, :not_yet_implemented} = Linx.Process.wait(sentinel)
      assert {:error, :not_yet_implemented} = Linx.Process.info(sentinel)
      assert {:error, :not_yet_implemented} = Linx.Process.pty_master(sentinel)
    end
  end
end
