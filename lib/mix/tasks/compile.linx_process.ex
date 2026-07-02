defmodule Mix.Tasks.Compile.LinxProcess do
  # Mix compiler for the `linx_process` Port binary: compiles
  # `c_src/linx_process.c` into a standalone executable in the
  # application's `priv/` directory, where `Linx.Process` spawns it via
  # `Port.open`. Linked against erl_interface's `libei` for the ei-frame
  # wire protocol.
  #
  # All build mechanics — fingerprint-based staleness, compile-to-temp-
  # then-rename, `CC` / `CFLAGS` / `LINX_DEBUG` handling, hardening
  # flags, and the `ERL_EI_INCLUDE_DIR` / `ERL_EI_LIBDIR` cross-compile
  # overrides — live in `Mix.Linx.CC`, shared by the five Linx C
  # compilers.
  @moduledoc false
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    Mix.Linx.CC.build!(
      name: "linx_process",
      source: "c_src/linx_process.c",
      artifact: "linx_process",
      mode: :port_binary
    )
  end

  @impl true
  def clean, do: Mix.Linx.CC.clean!("linx_process")
end
