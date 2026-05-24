defmodule Linx.User.Map do
  @moduledoc """
  One uid/gid mapping entry from a user namespace's `uid_map` or
  `gid_map`.

  Returned by `Linx.User.read_uid_map/1` / `Linx.User.read_gid_map/1`
  as a list of `%Linx.User.Map{}` — one struct per line in the
  kernel's procfs file. The shape mirrors the kernel's
  `inside_id outside_id length` triple exactly:

    * `:inside` — the first id in the range as the workload sees
      it (inside the user namespace).
    * `:outside` — the corresponding first id in the parent user
      namespace (outside).
    * `:length` — how many ids the range covers (≥ 1).

  ## Inspect

  Compact rendering, chosen by length:

      # length = 1 -- just the two ids, no range syntax.
      #Linx.User.Map<0 -> 1000>

      # length > 1 -- range form on both sides.
      #Linx.User.Map<0..65535 -> 100000..165535>

  ## Equivalence with write-side input

  The 3-tuple `{inside, outside, length}` accepted by
  `Linx.User.set_uid_map/2` / `set_gid_map/2` and the
  `%Linx.User.Map{}` returned by the read verbs carry exactly the
  same information. A consumer that wants a clean round-trip can
  convert:

      maps = [%Linx.User.Map{inside: 0, outside: 1000, length: 1}]
      mappings = Enum.map(maps, &{&1.inside, &1.outside, &1.length})
      :ok = Linx.User.set_uid_map(other_pid, mappings)
  """

  @enforce_keys [:inside, :outside, :length]
  defstruct [:inside, :outside, :length]

  @type t :: %__MODULE__{
          inside: non_neg_integer(),
          outside: non_neg_integer(),
          length: pos_integer()
        }

  defimpl Inspect do
    def inspect(%Linx.User.Map{inside: i, outside: o, length: 1}, _opts) do
      "#Linx.User.Map<#{i} -> #{o}>"
    end

    def inspect(%Linx.User.Map{inside: i, outside: o, length: l}, _opts) do
      "#Linx.User.Map<#{i}..#{i + l - 1} -> #{o}..#{o + l - 1}>"
    end
  end
end
