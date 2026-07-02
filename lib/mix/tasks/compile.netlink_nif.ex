defmodule Mix.Tasks.Compile.NetlinkNif do
  # Mix compiler for the native `netlink_socket` NIF: compiles
  # `c_src/netlink_socket.c` into a shared library in the application's
  # `priv/` directory, where `Linx.Netlink.Socket.Native` loads it with
  # `:erlang.load_nif/2`.
  #
  # All build mechanics — fingerprint-based staleness, compile-to-temp-
  # then-rename, `CC` / `CFLAGS` / `LINX_DEBUG` handling, hardening
  # flags — live in `Mix.Linx.CC`, shared by the five Linx C compilers.
  @moduledoc false
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    Mix.Linx.CC.build!(
      name: "netlink_nif",
      source: "c_src/netlink_socket.c",
      artifact: "netlink_socket.so",
      mode: :nif
    )
  end

  @impl true
  def clean, do: Mix.Linx.CC.clean!("netlink_socket.so")
end
