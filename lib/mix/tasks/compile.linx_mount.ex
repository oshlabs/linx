defmodule Mix.Tasks.Compile.LinxMount do
  # Mix compiler for the `linx_mount` NIF: compiles `c_src/linx_mount.c`
  # into a shared library in the application's `priv/` directory, where
  # `Linx.Mount.Native` loads it with `:erlang.load_nif/2`. Runs as part
  # of `mix compile` (and therefore `iex -S mix`, `mix test`, releases),
  # so there is no separate Makefile step.
  #
  # All build mechanics — fingerprint-based staleness, compile-to-temp-
  # then-rename, `CC` / `CFLAGS` / `LINX_DEBUG` handling, hardening
  # flags — live in `Mix.Linx.CC`, shared by the five Linx C compilers.
  @moduledoc false
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    Mix.Linx.CC.build!(
      name: "linx_mount",
      source: "c_src/linx_mount.c",
      artifact: "linx_mount.so",
      mode: :nif
    )
  end

  @impl true
  def clean, do: Mix.Linx.CC.clean!("linx_mount.so")
end
