defmodule Mix.Tasks.Compile.LinxProcess do
  # Mix compiler for the `linx_process` Port binary.
  #
  # Compiles `c_src/linx_process.c` into a standalone executable in the
  # application's `priv/` directory, where `Linx.Process` spawns it via
  # `Port.open`. Runs as part of `mix compile` (and therefore `iex -S mix`,
  # `mix test`, releases), so there is no separate Makefile step.
  #
  # Set `LINX_DEBUG=1` to build with `-g -O0`. Override the compiler with
  # the `CC` environment variable.
  @moduledoc false
  use Mix.Task.Compiler

  @source "c_src/linx_process.c"
  @artifact "linx_process"

  @impl true
  def run(_args) do
    source = Path.absname(@source)
    output = output_path()

    cond do
      not File.exists?(source) ->
        Mix.raise("linx_process: missing C source #{@source}")

      stale?(source, output) ->
        File.mkdir_p!(Path.dirname(output))
        compile(source, output)

      true ->
        :noop
    end
  end

  @impl true
  def clean do
    File.rm(output_path())
    :ok
  end

  # The executable lives in the build's priv dir, where :code.priv_dir/1
  # finds it at runtime; nothing is written into the source tree.
  defp output_path do
    Path.join([Mix.Project.app_path(), "priv", @artifact])
  end

  defp stale?(source, output) do
    case {File.stat(source), File.stat(output)} do
      {{:ok, src}, {:ok, out}} -> src.mtime > out.mtime
      _ -> true
    end
  end

  defp compile(source, output) do
    cc = System.get_env("CC", "cc")

    debug =
      if System.get_env("LINX_DEBUG") in ~w(1 true yes),
        do: ~w(-g -O0),
        else: ~w(-O2)

    args =
      ~w(-std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE) ++
        debug ++
        ["-o", output, source]

    Mix.shell().info("compiling #{@source} -> priv/#{@artifact}")

    case System.cmd(cc, args, stderr_to_stdout: true) do
      {_output, 0} ->
        :ok

      {output, status} ->
        Mix.raise("linx_process: #{cc} failed (exit #{status})\n#{output}")
    end
  end
end
