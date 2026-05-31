# Linx.Tty T6 probe — answers the three empirical questions about the
# T6 SSH-path handling.
#
# Paste this whole block into an `iex` session reached *over SSH* on
# the target Nerves device (i.e. `ssh nerves-foo.local`, then iex).
# Each section is wrapped in a safe/0 helper, so a surprise crash in
# one inspection won't lose the others.
#
# Caveats:
#
#   * The last section (line-buffering probe) blocks on
#     `:io.get_chars/3`. You're expected to type ONE character (no
#     Enter) and observe whether it returns immediately or only after
#     you press Enter. If it doesn't return at all and your iex
#     wedges, Ctrl-C ends the shell evaluator — nerves_ssh will spawn
#     a fresh one on the same SSH session.
#
#   * `:sys.get_state(gl, 500)` may dump a multi-kilobyte ssh_cli
#     state record. Scroll through it for `pty`, `mode`, `term`-type
#     fields; that's the negotiated PTY config we want to inspect.

(fn ->
  gl = Process.group_leader()

  safe = fn label, f ->
    result =
      try do
        f.()
      rescue
        e -> {:error, e}
      catch
        kind, reason -> {:caught, kind, reason}
      end

    IO.inspect(result, label: label, limit: :infinity, printable_limit: :infinity)
  end

  IO.puts("\n========== Q2 — GL identity ==========")
  IO.inspect(gl, label: "group_leader/0")
  safe.("registered_name", fn -> Process.info(gl, :registered_name) end)
  safe.("initial_call (raw)", fn -> Process.info(gl, :initial_call) end)
  safe.(":proc_lib.translate_initial_call", fn -> :proc_lib.translate_initial_call(gl) end)
  safe.("dictionary", fn -> Process.info(gl, :dictionary) end)
  safe.("current_function", fn -> Process.info(gl, :current_function) end)
  safe.("status", fn -> Process.info(gl, :status) end)
  safe.("links", fn -> Process.info(gl, :links) end)
  safe.("monitors", fn -> Process.info(gl, :monitors) end)
  safe.("monitored_by", fn -> Process.info(gl, :monitored_by) end)
  safe.("trap_exit", fn -> Process.info(gl, :trap_exit) end)

  IO.puts("\n========== Winsize via I/O protocol ==========")
  safe.(":io.columns(gl)", fn -> :io.columns(gl) end)
  safe.(":io.rows(gl)", fn -> :io.rows(gl) end)

  IO.puts("\n========== :io.getopts ==========")
  safe.("getopts (before)", fn -> :io.getopts(gl) end)

  IO.puts("\n========== :io.setopts(binary: true) ==========")
  safe.("setopts(binary: true)", fn -> :io.setopts(gl, binary: true) end)
  safe.("getopts (after)", fn -> :io.getopts(gl) end)

  IO.puts("\n========== ssh_cli internal state (best-effort) ==========")
  safe.(":sys.get_state(gl, 500)", fn -> :sys.get_state(gl, 500) end)

  IO.puts("\n========== Q1 — line-buffering probe ==========")
  IO.puts("Type ONE character — do NOT press Enter. Watch for the")
  IO.puts("'returned' inspect line below.")
  IO.puts("  - Returns immediately on your single keypress → byte-oriented; good for T6.1.")
  IO.puts("  - Returns only after you press Enter → line-buffered; T6.1 needs to go below ssh_cli.")
  IO.puts("If the probe never returns at all, Ctrl-C and report that.")
  IO.write("waiting for 1 byte > ")
  t0 = System.monotonic_time(:millisecond)

  result =
    try do
      :io.get_chars(:standard_io, ~c"", 1)
    rescue
      e -> {:error, e}
    catch
      kind, reason -> {:caught, kind, reason}
    end

  dt = System.monotonic_time(:millisecond) - t0
  IO.puts("")
  IO.inspect(result, label: "returned")
  IO.puts("elapsed: #{dt}ms (measured from probe start; what matters is whether you had to press Enter)")

  :probe_done
end).()
