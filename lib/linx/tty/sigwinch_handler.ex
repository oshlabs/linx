defmodule Linx.Tty.SigwinchHandler do
  @moduledoc false
  # Tiny `:gen_event` handler attached to OTP's `:erl_signal_server`.
  # Forwards `:sigwinch` events to a target pid as
  # `{:linx_tty, :sigwinch}` so `Linx.Tty.attach/2`'s pump can pick them
  # up alongside its other messages.
  #
  # `:gen_event` broadcasts each event to *every* registered handler,
  # so we coexist cleanly with `prim_tty_sighandler` -- the same
  # SIGWINCH signal can drive both iex's line-editor geometry refresh
  # and our forward-to-the-workload's-PTY path.
  #
  # Handler IDs (the `{__MODULE__, ref}` shape used by
  # `Linx.Tty.attach/2` callers) make multiple concurrent attaches a
  # non-issue: each one registers its own pid-bound instance and
  # removes only its own on teardown.

  @behaviour :gen_event

  @impl true
  def init(pid) when is_pid(pid), do: {:ok, pid}

  @impl true
  def handle_event(:sigwinch, pid) do
    send(pid, {:linx_tty, :sigwinch})
    {:ok, pid}
  end

  def handle_event(_other, pid), do: {:ok, pid}

  @impl true
  def handle_call(_req, pid), do: {:ok, :ok, pid}

  @impl true
  def terminate(_arg, _pid), do: :ok

  @impl true
  def code_change(_old, pid, _extra), do: {:ok, pid}
end
