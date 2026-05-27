# Linx.Tty T6 deciding probe — does :io.setopts(echo: false) give
# byte-oriented input over the nerves_ssh path?
#
# Reading kernel-10.6.3/src/group.erl gave us the mechanism:
# in :group's server/3 (line 244), input requests are routed to
# the :dumb state when `echo=false`, and :dumb's get_chars_dumb/5
# (line 1152) returns bytes immediately as they arrive from the
# driver — no line editor, no waiting for newlines. This probe
# verifies that end-to-end on a real nerves_ssh session.
#
# Paste into iex over SSH. Type ONE character — do NOT press Enter.
# Then read the elapsed/got fields:
#
#   - got: "x" (single-byte binary), elapsed = your reaction time
#       → SSH transport is byte-oriented; T6.1's mode flip is
#         just :io.setopts(echo: false). This is the outcome the
#         2026-05-27 run got.
#
#   - got returned only after you pressed Enter
#       → byte stream is still line-buffered somewhere below
#         :group (likely the user_drv-equivalent or ssh_cli's
#         pty-mode handling); need a separate probe of that layer.
#
# The probe restores echo to true on exit. It does NOT restore
# other opts (line_history etc.) that earlier probes may have
# left at false — reconnect SSH for a clean iex if you care.

(fn ->
  gl = Process.group_leader()
  saved = :io.getopts(gl)
  IO.inspect(saved, label: "saved opts (for reference; we only restore :echo)")

  try do
    IO.inspect(:io.setopts(gl, echo: false, binary: true),
      label: "setopts(echo: false, binary: true)"
    )

    IO.puts("\nType ONE character — do NOT press Enter.")
    IO.write("  > ")
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
    IO.inspect(result, label: "got")
    IO.puts("elapsed: #{dt}ms (your reaction time if byte-oriented; >> reaction time if line-buffered)")
  after
    IO.inspect(:io.setopts(gl, echo: true), label: "restore echo: true")
  end

  :probe_done
end).()
