defmodule Linx.NFT.KernelAcceptanceTest do
  @moduledoc """
  Kernel acceptance for the encoder paths the ~NFT compiler
  emits (NFT-PLAN.md, "Verification strategy"): pushes a ruleset
  exercising every recently-landed encoding through a real netlink
  socket and reads it back.

  Needs CAP_NET_ADMIN — run via `./sudotest.sh` or the privileged
  CI job. (The same check runs unprivileged during development via
  `unshare -r -n`; see the scratchpad kernel_smoke script pattern.)
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  alias Linx.Netlink.{Nfnl, Socket}

  @table "nft_kernel_acceptance"

  # One ruleset covering: NEWOBJ (counter) + objref, nft_limit,
  # nft_dynset with a nested per-element limit, a concatenated set
  # (declaration, elements, and rule-side reg32 loads), and named +
  # anonymous verdict maps (including a ct_state-keyed one).
  @src """
  table inet #{@table} {
    counter hits {
      packets 0 bytes 0
    }

    set svc {
      type ipv4_addr . inet_service
      elements = { 10.96.0.1 . 443, 10.96.0.10 . 53 }
    }

    set ratelimit {
      type ipv4_addr
      flags dynamic, timeout
      timeout 10m
    }

    vmap dispatch {
      type inet_service : verdict
      elements = { 22 : accept, 23 : drop }
    }

    chain input {
      type filter hook input priority 0
      policy accept
      ct state vmap { established : accept, invalid : drop }
      tcp dport vmap @dispatch
      ip daddr . tcp dport @svc counter accept
      tcp dport 22 ct state new add @ratelimit { ip saddr limit rate over 3/minute } drop
      tcp dport 22 counter name "hits" accept
      limit rate 10/second accept
    }
  }
  """

  test "kernel accepts every ~NFT-emitted encoding and the rules read back" do
    {:ok, rs} = Linx.NFT.parse(@src)
    {:ok, sock} = Nfnl.open()
    on_exit(fn -> Socket.close(sock) end)

    assert :ok = Linx.Netfilter.push(sock, rs)

    {:ok, pulled} = Linx.Netfilter.pull(sock)
    table = pulled.tables[{:inet, @table}]
    assert table, "pushed table not found on pull"
    assert length(table.chains["input"].rules) == 6

    # Cleanup: push an empty replacement... deleting the table is
    # enough — replace-mode push of a ruleset without the table
    # doesn't touch it, so drop it explicitly via a fresh empty
    # ruleset containing just the (empty) table, then delete.
    {:ok, empty} = Linx.NFT.parse("table inet #{@table} { }")
    assert :ok = Linx.Netfilter.push(sock, empty)
  end
end
