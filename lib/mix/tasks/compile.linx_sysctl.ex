defmodule Mix.Tasks.Compile.LinxSysctl do
  # Mix compiler for the `linx_sysctl` NIF: compiles `c_src/linx_sysctl.c`
  # into a shared library in the application's `priv/` directory, where
  # `Linx.Sysctl.Native` loads it with `:erlang.load_nif/2`.
  #
  # All build mechanics — fingerprint-based staleness, compile-to-temp-
  # then-rename, `CC` / `CFLAGS` / `LINX_DEBUG` handling, hardening
  # flags — live in `Mix.Linx.CC`, shared by the five Linx C compilers.
  @moduledoc false
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    Mix.Linx.CC.build!(
      name: "linx_sysctl",
      source: "c_src/linx_sysctl.c",
      artifact: "linx_sysctl.so",
      mode: :nif
    )
  end

  @impl true
  def clean, do: Mix.Linx.CC.clean!("linx_sysctl.so")
end
