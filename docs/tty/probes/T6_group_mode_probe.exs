# Linx.Tty T6 follow-up probe — can :io.setopts/2 flip :group out
# of :cooked mode?
#
# The previous probe (T6_ssh_probe.exs) established that:
#   * The GL is :group (gen_statem, kernel app), both locally and
#     over nerves_ssh.
#   * :group's :state record holds the atom :cooked at position 7
#     (1-indexed from the :state record tag) — this is the
#     line-discipline mode and the reason get_chars(_, '', 1)
#     line-buffers.
#
# This probe answers the remaining mechanism question: does some
# combination of :io.setopts/2 options move :cooked to something
# else (likely :raw, :undefined, or a state-name change)? If yes,
# T6.1's attach can flip mode via the documented setopts API and
# we're done. If not, we know to reach for mechanism 2 (a private
# gen_statem event) or 3 (:sys.replace_state surgery).
#
# Paste-friendly: this probe does NO :io.get_chars and asks for no
# keystrokes. It introspects :sys.get_state(gl) before and after
# each setopts trial, restores the original options at the end, and
# lists :group module exports as a hint for mechanism 2.
#
# Safe to run anywhere; particularly informative when run over SSH
# on the Nerves target where T6.1 needs to work.

(fn ->
  gl = Process.group_leader()

  inspect_mode = fn label ->
    case :sys.get_state(gl, 500) do
      {state_name, state_data} when is_tuple(state_data) ->
        atoms = state_data |> Tuple.to_list() |> Enum.filter(&is_atom/1)
        seventh = if tuple_size(state_data) >= 8, do: elem(state_data, 7), else: :__missing__
        IO.puts(
          "  [#{label}] state_name=#{inspect(state_name)} " <>
            "field7=#{inspect(seventh)} all_atoms=#{inspect(atoms)}"
        )

      other ->
        IO.puts("  [#{label}] UNEXPECTED :sys.get_state shape: #{inspect(other)}")
    end
  end

  IO.puts("\n========== :group state-flip probe ==========")

  saved_opts = :io.getopts(gl)
  IO.puts("saved opts:")
  IO.inspect(saved_opts, limit: :infinity)

  inspect_mode.("initial")

  # Each trial: restore baseline, apply the trial opts, dump state.
  # Restoring between trials means each row is independent — we're
  # measuring "what does THIS setopts call do from baseline?", not
  # "what does the cumulative chain do?".
  trials = [
    [terminal: false],
    [echo: false],
    [line_history: false],
    [terminal: false, echo: false],
    [echo: false, line_history: false],
    [terminal: false, echo: false, line_history: false]
  ]

  IO.puts("\n----- single + combined setopts trials -----")

  for opts <- trials do
    :io.setopts(gl, saved_opts)

    setopts_result =
      try do
        :io.setopts(gl, opts)
      rescue
        e -> {:error, e}
      catch
        kind, reason -> {:caught, kind, reason}
      end

    IO.puts("\n  trial: #{inspect(opts)} → setopts returned #{inspect(setopts_result)}")
    inspect_mode.("after #{inspect(opts)}")
  end

  IO.puts("\n----- restoring saved opts -----")
  :io.setopts(gl, saved_opts)
  inspect_mode.("restored")

  IO.puts("\n========== :group module exports ==========")
  IO.puts("(useful for mechanism 2 — a private message to flip mode)")

  case Code.ensure_loaded(:group) do
    {:module, _} ->
      :group.module_info(:exports)
      |> Enum.sort()
      |> IO.inspect(label: ":group.module_info(:exports)", limit: :infinity)

    {:error, reason} ->
      IO.puts("  :group not loaded? #{inspect(reason)}")
  end

  IO.puts("\n========== :user_drv module exports ==========")
  IO.puts("(parent of :group; alternative target for reader-suspend)")

  case Code.ensure_loaded(:user_drv) do
    {:module, _} ->
      :user_drv.module_info(:exports)
      |> Enum.sort()
      |> IO.inspect(label: ":user_drv.module_info(:exports)", limit: :infinity)

    {:error, reason} ->
      IO.puts("  :user_drv not loaded? #{inspect(reason)}")
  end

  IO.puts("\n========== Interpretation guide ==========")

  IO.puts("""
    Look at each "after [opts]" line:

      * If field7 changed away from :cooked (e.g. to :raw, :undefined,
        :otp_raw, …) for ANY trial → T6.1 can flip mode via that
        setopts permutation. Cleanest possible outcome.

      * If state_name changed from :server to something else for any
        trial → :group transitioned to a different gen_statem state;
        also fine, T6.1 keys off that.

      * If neither moved for any trial → setopts alone won't do it.
        Pick a likely callback name from the :group / :user_drv
        export lists above and write probe #3 to try sending it as
        a gen_statem cast. Or fall back to :sys.replace_state/2.

    Either way, this run is non-interactive and has fully restored
    your iex's options before returning. Safe to keep going.
  """)

  :probe_done
end).()
