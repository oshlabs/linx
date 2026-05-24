defmodule Linx.Mount.Entry do
  @moduledoc """
  A single parsed line from `/proc/<pid>/mountinfo` — one mount in
  the namespace's mount table.

  The shape mirrors `proc(5)`'s mountinfo format exactly:

      36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue
      (1)(2)(3)  (4)   (5)         (6)         (7)    (8) (9) (10)      (11)

      1.  mount_id        — unique within the namespace
      2.  parent_id       — points at another Entry; -1 if this is the root
      3.  device          — major:minor of st_dev (kept as a string)
      4.  root            — path of this mount's root in the filesystem
      5.  mount_point     — where this mount appears in the namespace
      6.  mount_options   — per-mount options (raw comma-list, e.g. "rw,noatime")
      7.  propagation     — list of {:shared, n} / {:master, n} / {:propagate_from, n} / :unbindable
      9.  fstype          — filesystem type ("ext4", "tmpfs", …)
      10. source          — mount source (block device path, "tmpfs", …)
      11. super_options   — per-superblock options (raw comma-list)

  Field 8, the literal `-`, separates the per-mount fields from the
  per-superblock fields and is not retained.

  `mount_options` and `super_options` are exposed verbatim as binaries.
  A consumer wanting to parse them into a map (e.g. `"rw"` vs `"ro"`,
  `"relatime"` flag) is welcome to; we don't bake a particular shape
  in.

  Paths (`:root`, `:mount_point`, `:source`) are decoded from
  mountinfo's octal-escape format — kernel writes `\\040` for space,
  `\\011` for tab, `\\012` for newline, `\\134` for backslash; we
  decode them back to their actual character before populating the
  struct.

  ## Inspect

  Renders compactly:

      #Linx.Mount.Entry<ext4 on / (rw,relatime)>
  """

  @enforce_keys [
    :mount_id,
    :parent_id,
    :device,
    :root,
    :mount_point,
    :mount_options,
    :propagation,
    :fstype,
    :source,
    :super_options
  ]

  defstruct [
    :mount_id,
    :parent_id,
    :device,
    :root,
    :mount_point,
    :mount_options,
    :propagation,
    :fstype,
    :source,
    :super_options
  ]

  @typedoc """
  Propagation entries from the optional-fields section. Per
  `mount_namespaces(7)`:

    * `{:shared, peer_group}` — this mount is in shared peer group
      `peer_group` (an integer).
    * `{:master, peer_group}` — this mount is a slave of peer group
      `peer_group`.
    * `{:propagate_from, peer_group}` — propagation source for slave
      mounts; rare.
    * `:unbindable` — bind mounts of this mount aren't allowed.
  """
  @type propagation_entry ::
          {:shared, non_neg_integer()}
          | {:master, non_neg_integer()}
          | {:propagate_from, non_neg_integer()}
          | :unbindable

  @type t :: %__MODULE__{
          mount_id: non_neg_integer(),
          parent_id: integer(),
          device: String.t(),
          root: String.t(),
          mount_point: String.t(),
          mount_options: String.t(),
          propagation: [propagation_entry()],
          fstype: String.t(),
          source: String.t(),
          super_options: String.t()
        }

  defimpl Inspect do
    def inspect(%Linx.Mount.Entry{} = e, _opts) do
      "#Linx.Mount.Entry<#{e.fstype} on #{e.mount_point} (#{e.mount_options})>"
    end
  end
end
