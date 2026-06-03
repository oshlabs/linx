defmodule Mix.Tasks.Compile.NetlinkNif do
  # Mix compiler for the native `netlink_socket` NIF.
  #
  # Compiles `c_src/netlink_socket.c` into a shared library in the
  # application's `priv/` directory, where `Linx.Netlink.Socket.Native` loads
  # it with `:erlang.load_nif/2`. It runs as part of `mix compile` (and
  # therefore `iex -S mix`, `mix test`, releases), so there is no separate
  # Makefile step.
  #
  # Set `LINX_DEBUG=1` to build with `-g -O0`. Override the compiler with the
  # `CC` environment variable.
  @moduledoc false
  use Mix.Task.Compiler

  @source "c_src/netlink_socket.c"
  @artifact "netlink_socket.so"

  @impl true
  def run(_args) do
    source = Path.absname(@source)
    output = output_path()

    cond do
      not File.exists?(source) ->
        Mix.raise("netlink_nif: missing C source #{@source}")

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

  # The shared library lives in the build's priv dir, where :code.priv_dir/1
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
      ~w(-std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE -fPIC -shared) ++
        debug ++
        ["-isystem", erts_include_dir()] ++
        ["-o", output, source]

    Mix.shell().info("compiling #{@source} -> priv/#{@artifact}")

    case System.cmd(cc, args, stderr_to_stdout: true) do
      {_output, 0} ->
        :ok

      {output, status} ->
        Mix.raise("netlink_nif: #{cc} failed (exit #{status})\n#{output}")
    end
  end

  # erl_nif.h ships in the ERTS include directory under the OTP root. The
  # exact erts-<version> is given by :erlang.system_info/1; the wildcard is a
  # fallback for unusual layouts.
  #
  # Cross-compile setups (notably Nerves) export `ERTS_INCLUDE_DIR` pointing
  # at the *target* Erlang's headers; honour it before falling back to the
  # host OTP layout so we don't compile against the wrong erl_nif.h.
  defp erts_include_dir do
    case System.get_env("ERTS_INCLUDE_DIR") do
      env when is_binary(env) and env != "" ->
        env

      _ ->
        root = List.to_string(:code.root_dir())
        version = List.to_string(:erlang.system_info(:version))
        dir = Path.join([root, "erts-#{version}", "include"])

        cond do
          File.dir?(dir) ->
            dir

          true ->
            case Path.wildcard(Path.join(root, "erts-*/include")) do
              [] -> Mix.raise("netlink_nif: ERTS include dir not found under #{root}")
              dirs -> dirs |> Enum.sort() |> List.last()
            end
        end
    end
  end
end
