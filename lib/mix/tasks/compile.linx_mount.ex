defmodule Mix.Tasks.Compile.LinxMount do
  # Mix compiler for the `linx_mount` NIF.
  #
  # Compiles `c_src/linx_mount.c` into a shared library in the
  # application's `priv/` directory, where `Linx.Mount.Native` loads
  # it with `:erlang.load_nif/2`. Runs as part of `mix compile` (and
  # therefore `iex -S mix`, `mix test`, releases), so there is no
  # separate Makefile step.
  #
  # Sibling to `compile.linx_tty` and `compile.netlink_nif` -- same
  # shape, same conventions.
  #
  # Set `LINX_DEBUG=1` to build with `-g -O0`. Override the compiler
  # with the `CC` environment variable.
  @moduledoc false
  use Mix.Task.Compiler

  @source "c_src/linx_mount.c"
  @artifact "linx_mount.so"

  @impl true
  def run(_args) do
    source = Path.absname(@source)
    output = output_path()

    cond do
      not File.exists?(source) ->
        Mix.raise("linx_mount: missing C source #{@source}")

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
      ~w(-std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE -fPIC -shared) ++
        debug ++
        ["-isystem", erts_include_dir()] ++
        ["-o", output, source]

    Mix.shell().info("compiling #{@source} -> priv/#{@artifact}")

    case System.cmd(cc, args, stderr_to_stdout: true) do
      {_output, 0} ->
        :ok

      {output, status} ->
        Mix.raise("linx_mount: #{cc} failed (exit #{status})\n#{output}")
    end
  end

  # Same ERTS include lookup the other Linx NIF compilers use.
  defp erts_include_dir do
    root = List.to_string(:code.root_dir())
    version = List.to_string(:erlang.system_info(:version))
    dir = Path.join([root, "erts-#{version}", "include"])

    cond do
      File.dir?(dir) ->
        dir

      true ->
        case Path.wildcard(Path.join(root, "erts-*/include")) do
          [] -> Mix.raise("linx_mount: ERTS include dir not found under #{root}")
          dirs -> dirs |> Enum.sort() |> List.last()
        end
    end
  end
end
