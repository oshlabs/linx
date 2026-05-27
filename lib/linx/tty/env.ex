defmodule Linx.Tty.Env do
  @moduledoc false
  # Classify the caller's terminal environment so `Linx.Tty.attach/2`
  # can pick the right strategy (or refuse cleanly when `:controlling`
  # would silently grab the wrong tty).
  #
  # The classification walks `Process.group_leader/0`'s process
  # dictionary `"$ancestors"` list. The probe captured on a Nerves
  # rpi5 over `nerves_ssh` (2026-05-27, see
  # `docs/tty/probes/T6_ssh_probe.exs`) confirmed `:ssh_sup` and
  # `:sshd_sup` appear in the ancestor chain whenever the GL is
  # fronted by Erlang's SSH daemon. That's the signal we key off.
  #
  # The classifier is conservative: when uncertain, it returns
  # `:local_tty` rather than `:unknown`, so callers that work today
  # don't suddenly start refusing. The only environment that gets
  # `:ssh` is one where we have a clear ancestor-based signal.

  @typedoc "Where the calling process's terminal lives."
  @type classification :: :local_tty | :ssh | :unknown

  @doc """
  Classify the environment of `Process.group_leader/0`.

  Returns one of:

    * `:ssh` — the group leader is fronted by Erlang's SSH daemon
      (matched by `:ssh_sup` or `:sshd_sup` appearing in the GL's
      `"$ancestors"` chain). `Linx.Tty.attach(:controlling, _)`
      refuses with `{:error, :no_local_tty}` in this case;
      callers should use `attach(:group_leader, _)` instead.
    * `:local_tty` — no SSH-supervisor ancestors and a readable
      process dictionary. The typical local iex / Nerves HDMI
      console case. `attach(:controlling, _)` proceeds as normal.
    * `:unknown` — the group leader has no readable info (dead
      process, etc.). `attach(:controlling, _)` proceeds as normal
      to preserve current behaviour on uncertainty.
  """
  @spec classify_caller_terminal() :: classification()
  def classify_caller_terminal, do: classify_caller_terminal(Process.group_leader())

  @doc """
  Variant of `classify_caller_terminal/0` taking an explicit pid —
  exposed so tests can drive the classifier against a fixture
  process with a synthesized `"$ancestors"` list.
  """
  @spec classify_caller_terminal(pid()) :: classification()
  def classify_caller_terminal(gl) when is_pid(gl) do
    with {:dictionary, dict} <- Process.info(gl, :dictionary),
         ancestors when is_list(ancestors) <- Keyword.get(dict, :"$ancestors", []) do
      if :ssh_sup in ancestors or :sshd_sup in ancestors do
        :ssh
      else
        :local_tty
      end
    else
      _ -> :unknown
    end
  end
end
