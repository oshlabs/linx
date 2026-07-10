defmodule Mix.Linx.CC do
  # Shared C-build engine behind the five Mix.Tasks.Compile.Linx* /
  # Compile.NetlinkNif compilers. One implementation of the concerns that
  # were previously copy-pasted (and subtly broken) per task:
  #
  #   * **Staleness is fingerprint-based, not mtime-based.** A build
  #     fingerprint (source content, compiler, full flag set, OTP release
  #     + ERTS version, include/lib dirs) is stored next to the artifact;
  #     any change triggers a rebuild. mtime comparison missed: changing
  #     `CC`/`LINX_DEBUG`/`CFLAGS`, upgrading OTP (new `erl_nif.h` under
  #     an unchanged source), and Hex tarballs (which ship epoch-2000
  #     mtimes, so a stale surviving artifact always looked fresh).
  #
  #   * **Compile to a temp path, then rename.** `cc -o <final>` writes
  #     the final artifact in place: an interrupted build left a partial
  #     `.so`/binary *newer than its source* that mtime logic never
  #     rebuilt, and a concurrent `mix compile` could load a half-written
  #     artifact. rename(2) within one directory is atomic.
  #
  #   * **`CFLAGS` is honored** (appended after the built-in flags, so a
  #     packager / cross-builder can override `-O2`, inject `-march`,
  #     sysroots, etc.). `CC` selects the compiler, as before.
  #
  #   * **Hardening flags** — this C parses kernel wire formats and runs
  #     clone/execve as root: `-fstack-protector-strong`,
  #     `-D_FORTIFY_SOURCE=2` (needs optimisation, so skipped under
  #     `LINX_DEBUG`'s `-O0`), and full RELRO (`-z relro -z now`).
  #     The Port binary is additionally built PIE (`-fPIE -pie`) so the
  #     one artifact that runs as root gets ASLR of its own text/data
  #     regardless of the host compiler's default; NIFs are inherently
  #     position-independent (`-fPIC -shared`).
  @moduledoc false

  @base_flags ~w(-std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE)
  @harden_compile ~w(-fstack-protector-strong)
  @harden_fortify ~w(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
  @harden_link ~w(-Wl,-z,relro -Wl,-z,now)

  @doc """
  Builds one C artifact if its fingerprint says it is stale.

  Options:

    * `:name` — task label for messages, e.g. `"linx_mount"`.
    * `:source` — repo-relative C source path.
    * `:artifact` — file name under the app's `priv/`.
    * `:mode` — `:nif` (`-shared -fPIC`, ERTS include) or `:port_binary`
      (standalone executable linked against `-lei -lpthread`).

  Returns `:ok` (rebuilt) or `:noop` (fresh).
  """
  def build!(opts) do
    name = Keyword.fetch!(opts, :name)
    source = Path.absname(Keyword.fetch!(opts, :source))
    mode = Keyword.fetch!(opts, :mode)
    output = output_path(Keyword.fetch!(opts, :artifact))

    if not File.exists?(source) do
      Mix.raise("#{name}: missing C source #{Keyword.fetch!(opts, :source)}")
    end

    cc = System.get_env("CC", "cc")
    args = build_args(mode, source, output)
    fingerprint = fingerprint(source, cc, args)

    if stale?(output, fingerprint) do
      Mix.Linx.Preflight.check!(cc)
      File.mkdir_p!(Path.dirname(output))
      do_compile(name, cc, args, source, output, fingerprint)
      :ok
    else
      :noop
    end
  end

  @doc "Removes the artifact and its fingerprint (the task's `clean/0`)."
  def clean!(artifact) do
    output = output_path(artifact)
    File.rm(output)
    File.rm(fingerprint_path(output))
    :ok
  end

  # The artifact lives in the build's priv dir, where :code.priv_dir/1
  # finds it at runtime; nothing is written into the source tree.
  defp output_path(artifact) do
    Path.join([Mix.Project.app_path(), "priv", artifact])
  end

  defp fingerprint_path(output), do: output <> ".fingerprint"

  defp build_args(mode, source, output) do
    debug? = System.get_env("LINX_DEBUG") in ~w(1 true yes)
    opt = if debug?, do: ~w(-g -O0), else: ~w(-O2)
    # _FORTIFY_SOURCE needs optimisation; glibc warns it away under -O0.
    fortify = if debug?, do: [], else: @harden_fortify

    cflags =
      case System.get_env("CFLAGS") do
        nil -> []
        env -> String.split(env)
      end

    case mode do
      :nif ->
        @base_flags ++
          ~w(-fPIC -shared) ++
          opt ++
          @harden_compile ++
          fortify ++
          cflags ++
          ["-isystem", erts_include_dir()] ++
          @harden_link ++
          ["-o", output, source]

      :port_binary ->
        @base_flags ++
          ~w(-fPIE -pie) ++
          opt ++
          @harden_compile ++
          fortify ++
          cflags ++
          ["-I", ei_include_dir(), "-L", ei_lib_dir()] ++
          @harden_link ++
          ["-o", output, source] ++
          ~w(-lei -lpthread)
    end
  end

  # Everything that determines the artifact's bytes: source *content*
  # (not mtime — Hex tarballs ship epoch mtimes), compiler, the exact
  # arg vector (which folds in mode, debug/CFLAGS, include dirs), and
  # the OTP identity (a new erl_nif.h / libei under the same source
  # must rebuild).
  defp fingerprint(source, cc, args) do
    otp =
      "otp-#{:erlang.system_info(:otp_release)}-erts-#{:erlang.system_info(:version)}"

    :crypto.hash(:sha256, [File.read!(source), 0, cc, 0, Enum.join(args, "\x00"), 0, otp])
    |> Base.encode16(case: :lower)
  end

  defp stale?(output, fingerprint) do
    not File.exists?(output) or File.read(fingerprint_path(output)) != {:ok, fingerprint}
  end

  defp do_compile(name, cc, args, source, output, fingerprint) do
    # Compile to a sibling temp path, rename into place on success. The
    # final artifact is either the complete old build or the complete
    # new one — never a torso a concurrent BEAM might load.
    tmp = "#{output}.tmp.#{System.unique_integer([:positive])}"
    args = Enum.map(args, fn a -> if a == output, do: tmp, else: a end)

    rel_source = Path.relative_to_cwd(source)
    Mix.shell().info("compiling #{rel_source} -> priv/#{Path.basename(output)}")

    try do
      case System.cmd(cc, args, stderr_to_stdout: true) do
        {_out, 0} ->
          File.rename!(tmp, output)
          File.write!(fingerprint_path(output), fingerprint)

        {out, status} ->
          Mix.raise("#{name}: #{cc} failed (exit #{status})\n#{out}")
      end
    after
      File.rm(tmp)
    end
  end

  # ERTS include lookup — `ERTS_INCLUDE_DIR` (Nerves and friends) takes
  # precedence over the host OTP layout.
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
              [] -> Mix.raise("linx: ERTS include dir not found under #{root}")
              dirs -> dirs |> Enum.sort() |> List.last()
            end
        end
    end
  end

  # erl_interface ships with OTP under `erl_interface-<version>/`; libei.a
  # is the static archive the Port binary links in. :code.lib_dir/1 is
  # unreliable here (the app may not be loaded during `mix compile`), so
  # resolve by globbing under the OTP root.
  #
  # Cross-compile setups (notably Nerves) point `ERL_EI_INCLUDE_DIR` and
  # `ERL_EI_LIBDIR` at the *target* Erlang's erl_interface; honour those
  # before falling back to the host OTP layout so we don't link the host
  # libei.a into a cross-built binary.
  defp ei_dir do
    case Path.wildcard(Path.join(:code.root_dir(), "lib/erl_interface-*")) do
      [] -> Mix.raise("linx: erl_interface not found under #{:code.root_dir()}")
      dirs -> dirs |> Enum.sort() |> List.last()
    end
  end

  defp ei_include_dir do
    case System.get_env("ERL_EI_INCLUDE_DIR") do
      dir when is_binary(dir) and dir != "" -> dir
      _ -> Path.join(ei_dir(), "include")
    end
  end

  defp ei_lib_dir do
    case System.get_env("ERL_EI_LIBDIR") do
      dir when is_binary(dir) and dir != "" -> dir
      _ -> Path.join(ei_dir(), "lib")
    end
  end
end
