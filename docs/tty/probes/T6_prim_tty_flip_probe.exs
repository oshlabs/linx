# Linx.Tty T6.1.1 diagnostic probe — does our prim_tty mode flip
# actually find and flip the right state?
#
# The first deploy of T6.1.1 (commit 2e87517) had a top-level-only
# scanner that missed ssh_cli's prim_tty (nested inside
# ssh_client_channel's state). Commit 6c4656a fixed that with a
# recursive walk. This probe verifies the fixed walk reaches the
# right prim_tty state on the user's actual nerves_ssh path,
# without needing the rest of attach to run.
#
# Paste into iex over SSH AFTER hot-loading /tmp/Elixir.Linx.Tty.beam.

(fn ->
  IO.puts("\n========== beam freshness ==========")

  beam_md5 =
    "/tmp/Elixir.Linx.Tty.beam"
    |> File.read!()
    |> :erlang.md5()
    |> Base.encode16(case: :lower)

  IO.puts("/tmp/Elixir.Linx.Tty.beam md5 = #{beam_md5}")
  IO.puts("(expected after T6.1.1 recursive-scanner fix: 21eab7b98b49759932c0ce47f853e0b9)")

  IO.puts("\n========== GL identity ==========")
  gl = Process.group_leader()
  IO.inspect(gl, label: "group_leader/0")

  IO.puts("\n========== group state ==========")

  {state_name, group_state} = :sys.get_state(gl, 500)
  IO.inspect(state_name, label: "group state_name")
  IO.puts("group state arity = #{tuple_size(group_state)}")

  drv = elem(group_state, 2)
  IO.inspect(drv, label: "driver pid (group_state[2])")

  IO.puts("\n========== driver state ==========")

  drv_state =
    try do
      :sys.get_state(drv, 500)
    catch
      kind, reason -> {:caught, kind, reason}
    end

  IO.inspect(drv_state, label: "driver state (truncated)", limit: 8, printable_limit: 80)

  IO.puts("\n========== recursive prim_tty walk ==========")

  walk = fn walk, term, path ->
    cond do
      is_tuple(term) ->
        case (try do
                {:ok, :prim_tty.output_mode(term)}
              catch
                _, _ -> :error
              end) do
          {:ok, mode} ->
            {:found, Enum.reverse(path), mode}

          :error ->
            term
            |> Tuple.to_list()
            |> Enum.with_index()
            |> Enum.find_value(:not_found, fn {field, idx} ->
              case walk.(walk, field, [idx | path]) do
                :not_found -> false
                found -> found
              end
            end)
        end

      true ->
        :not_found
    end
  end

  result = walk.(walk, drv_state, [])
  IO.inspect(result, label: "walk result")

  case result do
    {:found, path, current_mode} ->
      IO.puts("found prim_tty at path #{inspect(path)} with output mode #{inspect(current_mode)}")

      IO.puts("\n========== try the flip via :sys.replace_state ==========")

      ref = make_ref()
      parent = self()

      swap = fn state ->
        # Reproduce find + reinit + put_in_tuple_path inline.
        walked = walk.(walk, state, [])

        case walked do
          {:found, [], old_tty} ->
            try do
              new_tty = :prim_tty.reinit(old_tty, %{output: :raw})
              send(parent, {ref, {:ok, :prim_tty.output_mode(old_tty)}})
              new_tty
            catch
              kind, reason ->
                send(parent, {ref, {:caught_reinit, kind, reason}})
                state
            end

          {:found, path, old_tty} ->
            try do
              new_tty = :prim_tty.reinit(old_tty, %{output: :raw})

              # Rebuild along the path.
              rebuild = fn rebuild, st, [], new -> new
                          rebuild, st, [idx | rest], new when is_tuple(st) ->
                            inner = elem(st, idx)
                            put_elem(st, idx, rebuild.(rebuild, inner, rest, new))
                        end

              send(parent, {ref, {:ok, :prim_tty.output_mode(old_tty)}})
              rebuild.(rebuild, state, path, new_tty)
            catch
              kind, reason ->
                send(parent, {ref, {:caught_reinit, kind, reason}})
                state
            end

          _ ->
            send(parent, {ref, :walk_failed_inside})
            state
        end
      end

      try do
        _ = :sys.replace_state(drv, swap, 1000)

        receive do
          {^ref, payload} -> IO.inspect(payload, label: "replace_state inner result")
        after
          1000 -> IO.puts("replace_state ran but inner message never arrived")
        end
      catch
        kind, reason ->
          IO.inspect({kind, reason}, label: "replace_state crashed")
      end

      IO.puts("\n========== verify new mode ==========")

      new_state =
        try do
          :sys.get_state(drv, 500)
        catch
          kind, reason -> {:caught, kind, reason}
        end

      after_walk = walk.(walk, new_state, [])
      IO.inspect(after_walk, label: "walk result AFTER flip")

      IO.puts("\nIf 'after' mode is :raw, the flip works — the rest of T6.1.1's wiring is the suspect.")
      IO.puts("If 'after' mode is still :cooked, :sys.replace_state didn't persist — deeper issue.")

      # Restore so we don't leave the SSH iex in a weird state.
      _ =
        :sys.replace_state(
          drv,
          fn s ->
            case walk.(walk, s, []) do
              {:found, [], old} ->
                :prim_tty.reinit(old, %{output: :cooked})

              {:found, p, old} ->
                rebuild = fn rebuild, st, [], new -> new
                            rebuild, st, [idx | rest], new when is_tuple(st) ->
                              put_elem(st, idx, rebuild.(rebuild, elem(st, idx), rest, new))
                          end

                rebuild.(rebuild, s, p, :prim_tty.reinit(old, %{output: :cooked}))

              _ ->
                s
            end
          end,
          500
        )

      IO.puts("\n(prim_tty restored to :cooked after the probe.)")

    other ->
      IO.inspect(other, label: "walk returned something unexpected — no flip attempted")
  end

  :probe_done
end).()
