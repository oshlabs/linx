defmodule Linx.Sysctl do
  @moduledoc """
  Linux kernel tunable parameters — the `/proc/sys/` surface, the same
  knobs `sysctl(8)` reads and writes.

  ## Why a separate subsystem

  Sysctls are a coherent kernel concept (~1500 named scalar tunables
  spanning networking, VM, filesystem, IPC, and kernel-wide policy)
  with their own procfs surface and their own per-namespace routing
  rules. Reading `net.ipv4.ip_forward` from inside a container
  doesn't yield the host's value — it yields the *container's
  network namespace's* value. Wrapping the surface as its own module
  keeps that routing model explicit instead of scattering procfs
  paths through every caller.

  Driving use cases:

    * **Host-side, from a Nerves application or a normal release** —
      flip a knob like `net.ipv4.ip_forward` programmatically.
    * **Container-side, at the `Linx.Process` checkpoint** — set
      `kernel.hostname`, enable per-netns `net.*` knobs, configure
      `kernel.shm*` IPC limits, before the workload `execve`s.
    * **Container-side, at runtime** — same verbs against a fully
      running namespace via the `:in` option (lands in S3).

  ## procfs is the API

  Every sysctl is a file under `/proc/sys/`. Dots in the key map to
  slashes in the path:

      net.ipv4.ip_forward  ->  /proc/sys/net/ipv4/ip_forward
      kernel.hostname      ->  /proc/sys/kernel/hostname
      vm.swappiness        ->  /proc/sys/vm/swappiness

  Reads return the file's contents (kernel always appends a `\\n`,
  which we trim). Writes accept integers, strings, and lists of
  integers (for space-separated tuple-shaped knobs like
  `kernel.printk` or `net.ipv4.tcp_rmem`).

  The legacy `sysctl(2)` syscall was removed from Linux in 5.5 and
  has been deprecated since 2.6.24; we don't expose it. procfs is
  the only API.

  ## Per-namespace vs global

  The kernel routes each read or write through the *calling task's*
  namespace context:

  | Subtree | Owning namespace |
  |---|---|
  | `net.*` | network |
  | `kernel.hostname`, `kernel.domainname` | UTS |
  | `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*` | IPC |
  | `user.max_*_namespaces` | user |
  | `vm.*`, `fs.file-max`, `kernel.printk`, most else | global (host-only) |

  Trying to traverse `/proc/<pid>/root/proc/sys/...` to "see another
  namespace's value" does **not** work — the kernel resolves the
  value against the *reader's* namespace, not the path. The `:in`
  option (S3) is the supported way to read or write a non-host
  value: the NIF enters the target's full namespace stack on a
  throwaway pthread, performs the file I/O, and exits. Global
  sysctls return the same value from any namespace regardless of
  `:in`.

  ## Composition with `Linx.Process`

  Same shape as `Linx.Mount`'s `:in: {:pid, _}` — write knobs into
  a child's namespace while it's parked at the checkpoint, then
  proceed:

      {:ok, c} =
        Linx.Process.spawn(argv: ["/bin/bash"], namespaces: [:net, :uts])

      receive do {:linx_process, :ready, _} -> :ok end
      {:ok, host_pid} = Linx.Process.host_pid(c)

      :ok = Linx.Sysctl.write("net.ipv4.ip_forward", 1, in: {:pid, host_pid})
      :ok = Linx.Sysctl.write("kernel.hostname", "ct0", in: {:pid, host_pid})

      :ok = Linx.Process.proceed(c)

  `Linx.Process` has zero awareness of sysctls; the checkpoint
  between `:ready` and `proceed/1` is the only coupling, exactly
  the way `Linx.Netlink` / `Linx.Cgroup` / `Linx.Mount` / `Linx.User`
  integration works. Cross-namespace verbs also work post-`proceed/1`
  against any live pid — `:in` is lifecycle-agnostic.

  ## Status

  S0 — scaffolding only. `supported?/0` is functional; the host
  read/write surface lands in S1, subtree walking in S2, and the
  cross-namespace `:in` option in S3. See `docs/sysctl/PLAN.md`
  for the roadmap.
  """

  @proc "/proc"
  @self_ostype Path.join([@proc, "sys", "kernel", "ostype"])

  @typedoc """
  A sysctl key in dot form, e.g. `"net.ipv4.ip_forward"` or
  `"kernel.hostname"`. Maps internally to a `/proc/sys/<slashed>`
  path.
  """
  @type key :: String.t()

  @typedoc """
  A value to write to a sysctl. Integers and binaries cover the
  vast majority of knobs; lists of integers cover the
  space-separated tuple shapes (`kernel.printk`,
  `net.ipv4.tcp_rmem`, etc.).
  """
  @type value :: integer() | binary() | [integer()]

  @doc """
  Returns `true` iff the kernel exposes a `/proc/sys/` tree on this
  host.

  Canonical check: `/proc/sys/kernel/ostype` exists. The knob has
  been present since before namespaces existed; on any Linux kernel
  with procfs mounted at `/proc`, this is `true`.
  """
  @spec supported?() :: boolean()
  def supported?, do: File.exists?(@self_ostype)

  @doc """
  Reads a sysctl as a trimmed binary.

  Returns `{:ok, value}` where `value` is the file's contents with
  trailing whitespace stripped (the kernel always appends a `\\n`),
  or `{:error, %Linx.Sysctl.Error{}}` on kernel-level failure.

  Lands in S1.
  """
  @spec read(key()) :: {:ok, binary()} | {:error, term()}
  def read(_key), do: {:error, :not_yet_implemented}

  @doc """
  Reads a sysctl and parses it as a single integer.

  Convenience for the common case (`net.ipv4.ip_forward`,
  `vm.swappiness`, every `*_max` / `*_min` knob). Returns
  `{:error, {:bad_value, reason}}` on non-integer contents.

  Lands in S1.
  """
  @spec read_int(key()) :: {:ok, integer()} | {:error, term()}
  def read_int(_key), do: {:error, :not_yet_implemented}

  @doc """
  Reads a sysctl and parses it as a list of integers, split on
  whitespace.

  Convenience for the tuple-shaped knobs: `kernel.printk` is four
  ints, `net.ipv4.tcp_rmem` / `tcp_wmem` are three each. Returns
  `{:error, {:bad_value, reason}}` if any token doesn't parse.

  Lands in S1.
  """
  @spec read_ints(key()) :: {:ok, [integer()]} | {:error, term()}
  def read_ints(_key), do: {:error, :not_yet_implemented}

  @doc """
  Writes a value to a sysctl.

  `value` may be an integer, a binary, or a list of integers
  (rendered space-separated for the tuple-shaped knobs). Returns
  `:ok` or `{:error, %Linx.Sysctl.Error{}}`.

  In S1 this writes to the host's namespace context. In S3 it
  gains an `:in` option (`:self` / `{:pid, n}` / `{:path, p}`) for
  cross-namespace writes against a target process's namespace
  stack — same shape as `Linx.Mount`'s `:in` option.

  Lands in S1.
  """
  @spec write(key(), value()) :: :ok | {:error, term()}
  def write(_key, _value), do: {:error, :not_yet_implemented}

  @doc """
  Walks `/proc/sys/` and returns every readable scalar as a list of
  `%Linx.Sysctl.Entry{}` structs.

  Unreadable nodes (some sysctls return `EPERM` for unprivileged
  callers) are silently skipped — the returned list is "everything
  I could see", not "everything that exists".

  Lands in S2.
  """
  @spec list() :: {:ok, [term()]} | {:error, term()}
  def list, do: {:error, :not_yet_implemented}

  @doc """
  Walks a subtree of `/proc/sys/` named by a dot-form key prefix.

  `list("net.ipv4")` returns every readable scalar under
  `/proc/sys/net/ipv4/`. The trailing `*` is implicit; globs are
  not accepted.

  Lands in S2.
  """
  @spec list(key()) :: {:ok, [term()]} | {:error, term()}
  def list(_key_prefix), do: {:error, :not_yet_implemented}
end
