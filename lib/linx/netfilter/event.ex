defmodule Linx.Netfilter.Event do
  @moduledoc """
  A single multicast event from `NFNLGRP_NFTABLES` — a
  notification the kernel broadcasts after every successful
  ruleset commit.

  Each committed transaction generates a sequence of events on
  the multicast group:

    1. One event per entity created, modified, or deleted in the
       commit (`NFT_MSG_NEWTABLE`, `NFT_MSG_DELRULE`, …).
    2. One closing `NFT_MSG_NEWGEN` with the new generation id and
       the committing process's pid / name.

  `Linx.Netfilter.Monitor` buffers the entity events until the
  closing `NEWGEN` arrives, then stamps them with its `gen_id` /
  `proc_pid` / `proc_name` — so each `%Event{}` carries the full
  context of "who changed this and when".

  ## Fields

    * `:gen_id` — the ruleset generation this event belongs to
      (matches the gen returned by `Linx.Netlink.Nfnl.Codec.get_gen/1`
      at the moment of the commit). Nil only for `:new_gen` events
      that precede any committed change in the stream — rare.
    * `:proc_pid` — pid of the process that committed; nil if the
      kernel didn't include it (some configs / older kernels).
    * `:proc_name` — comm string of the committer (e.g. `"nft"`,
      `"beam.smp"`).
    * `:op` — what happened. One of:
      * `:new_gen` — the commit itself (gen-bump). `entity` is
        `%{id, proc_pid, proc_name}` redundantly.
      * `:new_table` / `:del_table` — table created / destroyed.
      * `:new_chain` / `:del_chain` — chain created / destroyed.
      * `:new_rule` / `:del_rule` — rule appended / removed.
      * `:new_set` / `:del_set`.
      * `:new_set_element` / `:del_set_element`.
      * `:new_obj` / `:del_obj`.
      * `:new_flowtable` / `:del_flowtable`.
    * `:entity` — the decoded value. The shape depends on `:op`:
      * `:new_table` / `:del_table` → `%Linx.Netfilter.Table{}`.
      * `:new_chain` / `:del_chain` → `{family, %Linx.Netfilter.Chain{}}`.
      * `:new_rule` / `:del_rule` → `{family, table_name, chain_name,
        %Linx.Netfilter.Rule{}}`.
      * `:new_set` / `:del_set` → `{family, %Set{} | %Map{}}`.
      * `:new_set_element` / `:del_set_element` →
        `{family, table_name, set_name, [elements]}`.
      * `:new_gen` → `%{id, proc_pid, proc_name}`.
      * Other ops → opaque binary payload (decoder fallback).

  ## Inspect

      #Linx.Netfilter.Event<gen=1247 nft new_rule inet/myapp/input>
  """

  @enforce_keys [:op]
  defstruct [:op, :entity, :gen_id, :proc_pid, :proc_name]

  @type op ::
          :new_gen
          | :new_table
          | :del_table
          | :new_chain
          | :del_chain
          | :new_rule
          | :del_rule
          | :new_set
          | :del_set
          | :new_set_element
          | :del_set_element
          | :new_obj
          | :del_obj
          | :new_flowtable
          | :del_flowtable
          | {:unknown, non_neg_integer()}

  @type t :: %__MODULE__{
          op: op(),
          entity: term(),
          gen_id: non_neg_integer() | nil,
          proc_pid: non_neg_integer() | nil,
          proc_name: String.t() | nil
        }

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Event{} = e, _opts) do
      who = if e.proc_name, do: "#{e.proc_name} ", else: ""
      gen = if e.gen_id, do: "gen=#{e.gen_id} ", else: ""
      where = render_where(e.op, e.entity)
      "#Linx.Netfilter.Event<#{gen}#{who}#{e.op}#{where}>"
    end

    defp render_where(:new_gen, _), do: ""

    defp render_where(op, _) when op in [:new_table, :del_table] do
      ""
    end

    defp render_where(op, {family, %{table: t, name: n}})
         when op in [:new_chain, :del_chain, :new_set, :del_set] do
      " #{family}/#{t}/#{n}"
    end

    defp render_where(op, {family, table, chain, _rule})
         when op in [:new_rule, :del_rule] do
      " #{family}/#{table}/#{chain}"
    end

    defp render_where(op, {family, table, set, _elems})
         when op in [:new_set_element, :del_set_element] do
      " #{family}/#{table}/#{set}"
    end

    defp render_where(_, _), do: ""
  end
end
