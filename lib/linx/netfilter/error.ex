defmodule Linx.Netfilter.Error do
  @moduledoc """
  An error returned by a `Linx.Netfilter` operation.

  Built from a failed netlink request or a rejected batch (`NLMSG_ERROR`
  reply from the kernel). The shape mirrors `Linx.Mount.Error` /
  `Linx.User.Error` / `Linx.Sysctl.Error` for `:operation`, `:errno`,
  `:code`, and `:message`, plus netfilter-specific context fields
  that are populated when the kernel surfaces them:

    * `:operation` — what we were trying to do, as an atom. Covers
      every public verb and every wire-level stage:

      * Public-API stages: `:open`, `:close`, `:get_gen`, `:push`,
        `:pull`, `:diff`, `:subscribe`, `:log_listen`.
      * Wire-level batch stages: `:batch_begin`, `:batch_end`,
        `:newtable`, `:newchain`, `:newrule`, `:newset`,
        `:newsetelem`, `:newobj`, `:newflowtable`, `:delgen`.
      * Namespace-acquisition stages (when opening a socket in
        another netns): `:open_ns`, `:setns`, `:unshare`, `:thread`.

    * `:errno` — the POSIX errno as an atom (`:enoent`, `:eperm`,
      `:eacces`, `:einval`, `:erestart`, `:eopnotsupp`, …).

    * `:code` — the matching positive errno integer, or `nil` if we
      don't have a mapping for this atom. Symmetric with the other
      Linx error structs.

    * `:message` — kernel's extended-ack message (NLMSGERR_ATTR_MSG),
      a human-readable string explaining what was wrong with the
      offending message. `nil` when the kernel didn't include one.

    * `:subsys` — `:nftables` | `:ctnetlink` | `:queue` | `:ulog` |
      `nil`. Which nfnetlink sub-subsystem the failure was for.

    * `:msg_type` — the low-byte nfnetlink message type that
      failed, when the error came from a specific inner message
      (e.g. `0x06` for NFT_MSG_NEWRULE). `nil` for non-batch
      failures.

    * `:batch_seq` — sequence number of the offending inner message
      within the batch. `nil` for non-batch failures.

    * `:attr_offset` — byte offset into the offending message at
      which the kernel detected the problem (from
      NLMSGERR_ATTR_OFFS, kernel ≥ 4.12). `nil` when not provided.

    * `:ruleset_gen` — the ruleset generation at which the error
      occurred. Useful for `ERESTART` (BATCH_GENID mismatch)
      diagnostics. `nil` when not relevant.

  Pattern-match on `:errno` and `:operation` to handle specific
  failures:

      case Linx.Netfilter.push(nfnl, ruleset) do
        :ok ->
          :ok

        {:error, %Linx.Netfilter.Error{errno: :eacces}} ->
          # No CAP_NET_ADMIN; can't mutate the kernel's nftables.
          :no_perm

        {:error, %Linx.Netfilter.Error{errno: :erestart, ruleset_gen: gen}} ->
          # BATCH_GENID mismatch — another writer committed between
          # our pull and our push. Re-pull, recompute, retry.
          {:concurrent_modification, gen}

        {:error, %Linx.Netfilter.Error{errno: :eopnotsupp, msg_type: t}} ->
          # The kernel doesn't support this op on this entity —
          # typically an in-place modification that requires
          # delete+recreate.
          {:not_supported, t}
      end

  Implements `Exception`, so an error can be `raise`d or rendered
  with `Exception.message/1`.

  Caller-side input mistakes (invalid Ruleset shape, bad opts) come
  back as tagged tuples (`{:error, {:bad_chain, _}}`,
  `{:error, {:bad_rule, _}}`, `{:error, {:bad_set_element, _}}`,
  `{:error, {:tag_required, _}}`) — distinct from kernel rejections,
  matching the convention every other Linx subsystem uses.
  """

  @enforce_keys [:operation, :errno]
  defexception [
    :operation,
    :errno,
    :code,
    :message,
    :subsys,
    :msg_type,
    :batch_seq,
    :attr_offset,
    :ruleset_gen
  ]

  # Public-API stages
  @type operation ::
          :open
          | :close
          | :get_gen
          | :push
          | :pull
          | :diff
          | :subscribe
          | :log_listen
          # Wire-level batch stages
          | :batch_begin
          | :batch_end
          | :newtable
          | :newchain
          | :newrule
          | :newset
          | :newsetelem
          | :newobj
          | :newflowtable
          | :delgen
          # Namespace-acquisition stages
          | :open_ns
          | :setns
          | :unshare
          | :thread

  @type subsys :: :nftables | :ctnetlink | :queue | :ulog | nil

  @type t :: %__MODULE__{
          operation: operation(),
          errno: atom(),
          code: pos_integer() | nil,
          message: String.t() | nil,
          subsys: subsys(),
          msg_type: 0..255 | nil,
          batch_seq: non_neg_integer() | nil,
          attr_offset: non_neg_integer() | nil,
          ruleset_gen: non_neg_integer() | nil
        }

  # POSIX errno table for the netlink paths netfilter operations can
  # land on. Unmapped atoms keep `:code` at `nil`; the atom is still
  # self-describing.
  @code_of %{
    eperm: 1,
    enoent: 2,
    esrch: 3,
    eio: 5,
    ebadf: 9,
    eagain: 11,
    enomem: 12,
    eacces: 13,
    efault: 14,
    ebusy: 16,
    eexist: 17,
    enodev: 19,
    einval: 22,
    enospc: 28,
    erofs: 30,
    erange: 34,
    enametoolong: 36,
    enosys: 38,
    eopnotsupp: 95,
    eaddrinuse: 98,
    erestart: 85,
    enobufs: 105,
    eprotonosupport: 93
  }

  @doc """
  Builds a `%Linx.Netfilter.Error{}` from a posix-atom errno and the
  operation we attempted.

  Optional opts populate the netfilter-specific context fields when
  the caller has them (typically populated from decoded `NLMSG_ERROR`
  attributes by the request engine).
  """
  @spec from_posix(atom(), operation(), keyword()) :: t()
  def from_posix(errno, operation, opts \\ []) when is_atom(errno) do
    %__MODULE__{
      operation: operation,
      errno: errno,
      code: Map.get(@code_of, errno),
      message: Keyword.get(opts, :message),
      subsys: Keyword.get(opts, :subsys),
      msg_type: Keyword.get(opts, :msg_type),
      batch_seq: Keyword.get(opts, :batch_seq),
      attr_offset: Keyword.get(opts, :attr_offset),
      ruleset_gen: Keyword.get(opts, :ruleset_gen)
    }
  end

  @impl Exception
  def message(%__MODULE__{operation: op, errno: errno, code: code, message: msg}) do
    code_part = if code, do: " (errno #{code})", else: ""
    suffix = if msg, do: " — #{msg}", else: ""
    "netfilter #{op} failed: #{errno}#{code_part}#{suffix}"
  end
end
