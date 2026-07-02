defmodule Mix.Tasks.Compile.LinxTty do
  # Mix compiler for the `linx_tty` NIF: compiles `c_src/linx_tty.c`
  # into a shared library in the application's `priv/` directory, where
  # `Linx.Tty.Native` loads it with `:erlang.load_nif/2`.
  #
  # All build mechanics — fingerprint-based staleness, compile-to-temp-
  # then-rename, `CC` / `CFLAGS` / `LINX_DEBUG` handling, hardening
  # flags — live in `Mix.Linx.CC`, shared by the five Linx C compilers.
  @moduledoc false
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    Mix.Linx.CC.build!(
      name: "linx_tty",
      source: "c_src/linx_tty.c",
      artifact: "linx_tty.so",
      mode: :nif
    )
  end

  @impl true
  def clean, do: Mix.Linx.CC.clean!("linx_tty.so")
end
