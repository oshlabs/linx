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
    Mix.Linx.Preflight.check!(cc)

    debug =
      if System.get_env("LINX_DEBUG") in ~w(1 true yes),
        do: ~w(-g -O0),
        else: ~w(-O2)

    args =
      ~w(-std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE) ++
        debug ++
        ["-I", ei_include_dir(), "-L", ei_lib_dir()] ++
        ["-o", output, source] ++
        ~w(-lei -lpthread)

    Mix.shell().info("compiling #{@source} -> priv/#{@artifact}")

    case System.cmd(cc, args, stderr_to_stdout: true) do
      {_output, 0} ->
        :ok

      {output, status} ->
        Mix.raise("linx_process: #{cc} failed (exit #{status})\n#{output}")
    end
  end

  # erl_interface ships with OTP under `erl_interface-<version>/`; libei.a
  # is the static archive we link in. :code.lib_dir/1 is unreliable here
  # (the app may not be loaded during `mix compile`), so we resolve the
  # directory by globbing under the OTP root -- same strategy
  # `compile.netlink_nif` uses for the erts include dir.
  #
  # Cross-compile setups (notably Nerves) point `ERL_EI_INCLUDE_DIR` and
  # `ERL_EI_LIBDIR` at the *target* Erlang's erl_interface; honour those
  # before falling back to the host OTP layout so we don't link the host
  # libei.a into a cross-built binary.
  defp ei_dir do
    case Path.wildcard(Path.join(:code.root_dir(), "lib/erl_interface-*")) do
      [] -> Mix.raise("linx_process: erl_interface not found under #{:code.root_dir()}")
      dirs -> dirs |> Enum.sort() |> List.last()
    end
  end

  defp ei_include_dir do
    case System.get_env("ERL_EI_INCLUDE_DIR") do
      nil -> Path.join(ei_dir(), "include")
      "" -> Path.join(ei_dir(), "include")
      dir -> dir
    end
  end

  defp ei_lib_dir do
    case System.get_env("ERL_EI_LIBDIR") do
      nil -> Path.join(ei_dir(), "lib")
      "" -> Path.join(ei_dir(), "lib")
      dir -> dir
    end
  end
end
