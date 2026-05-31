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
      running namespace via the `:in` option.

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

  ## Primitives, not a config applier

  `Linx.Sysctl` reads, writes, and lists knobs; it is deliberately
  not a `sysctl.conf` parser or applier. Parsing `/etc/sysctl.d/*.conf`,
  apply ordering, and reload policy belong to a consumer built on
  these primitives, not to Linx.

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
  option is the supported way to read or write a non-host value:
  `Linx.Sysctl.Native` opens the target's namespace stack (user,
  mount, UTS, IPC, net) and `setns(2)`s into all five on a throwaway
  pthread, then performs the file I/O, then exits. Global sysctls
  return the same value from any namespace regardless of `:in`.

  ## The `:in` option

  Every verb in this module accepts an `:in` option, mirroring
  `Linx.Mount`'s shape:

    * `:self` (default) — the BEAM's namespaces. Pure-Elixir file
      I/O over `/proc/sys/`; no NIF, no thread.
    * `{:pid, n}` — the namespace stack of pid `n`. Joins
      `/proc/<n>/ns/{user,mnt,uts,ipc,net}` on a throwaway pthread.
    * `{:path, p}` — a single explicit nsfd file path (less common;
      primarily for testing or for callers that already hold a
      pinned-namespace bind mount).

  `:in` is **lifecycle-agnostic**: it works equally well between
  `Linx.Process`'s `:ready` event and `proceed/1` (the checkpoint
  window) and against a fully running container post-`proceed/1`.

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
  integration works.

  ## Status

  S0–S3 shipped: `supported?/0`, host-side `read/1..2`,
  `read_int/1..2`, `read_ints/1..2`, `write/2..3`, subtree walking
  via `list/0..2`, cross-namespace via the `:in` option, plus the
  `%Linx.Sysctl.Entry{}` and `%Linx.Sysctl.Error{}` value types.
  """

  alias Linx.Sysctl.Entry
  alias Linx.Sysctl.Error
  alias Linx.Sysctl.Native

  @procsys "/proc/sys"
  @self_ostype Path.join(@procsys, "kernel/ostype")

  # Dot-form sysctl keys: each `.`-separated segment is one or more
  # of [A-Za-z0-9_-]; segments can't be empty (rules out leading /
  # trailing / consecutive dots and the `..` path-traversal case).
  @key_regex ~r/\A[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\z/

  # Canonical namespace order for setns. user first so an unprivileged
  # caller would gain CAP_SYS_ADMIN in the target user ns before
  # trying to enter mount; for our typical root-BEAM case the order
  # doesn't matter, but consistency keeps the rootless path open.
  @ns_kinds ~w(user mnt uts ipc net)

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

  @typedoc """
  Target namespace for an operation:

    * `:self` (default) — the BEAM's namespaces.
    * `{:pid, n}` — the namespace stack of pid `n`.
    * `{:path, p}` — an explicit nsfd path.
  """
  @type in_target ::
          :self
          | {:pid, pos_integer()}
          | {:path, String.t()}

  @typedoc """
  Options accepted by every verb in this module.

    * `:in` — target namespace, default `:self`. See `t:in_target/0`.
  """
  @type opts :: [in: in_target()]

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
  trailing whitespace stripped (the kernel always appends a `\\n`).

  ## Options

    * `:in` — `:self` (default), `{:pid, n}`, or `{:path, p}`.
      Routes the read through the target's namespace stack on a
      throwaway pthread.

  ## Examples

      iex> Linx.Sysctl.read("kernel.ostype")
      {:ok, "Linux"}

      iex> Linx.Sysctl.read("net.ipv4.ip_forward")
      {:ok, "0"}

      # Read the value the container sees, not the host's:
      iex> Linx.Sysctl.read("net.ipv4.ip_forward", in: {:pid, container_pid})
      {:ok, "1"}

  ## Errors

    * `{:error, {:bad_key, reason}}` — caller-side input mistake.
    * `{:error, {:bad_in, reason}}` — malformed `:in` value.
    * `{:error, %Linx.Sysctl.Error{}}` — kernel-level failure.
      Common: `:enoent` (no such sysctl), `:eacces` (procfs denied
      the read), or — with `:in: {:pid, _}` — `:open_ns` / `:setns`
      / `:unshare` / `:thread` from the namespace-acquisition path.
  """
  @spec read(key(), opts()) ::
          {:ok, binary()}
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()}}
  def read(key, opts \\ []) when is_binary(key) and is_list(opts) do
    with {:ok, path} <- resolve_key(key),
         {:ok, target} <- resolve_in(opts) do
      do_read(key, path, target)
    end
  end

  defp do_read(key, path, :self) do
    case File.read(path) do
      {:ok, data} -> {:ok, String.trim_trailing(data)}
      {:error, posix} -> {:error, Error.from_posix(posix, key, path, :read)}
    end
  end

  defp do_read(key, path, {:cross, ns_paths}) do
    case Native.read_in_ns(path, ns_paths) do
      {:ok, data} -> {:ok, String.trim_trailing(data)}
      {:error, {stage, errno}} -> {:error, native_error(stage, errno, key, path)}
    end
  end

  @doc """
  Reads a sysctl and parses it as a single integer.

  Convenience for the common case (`net.ipv4.ip_forward`,
  `vm.swappiness`, every `*_max` / `*_min` knob).

  Accepts the same `:in` option as `read/2`.

  ## Examples

      iex> Linx.Sysctl.read_int("net.ipv4.ip_forward")
      {:ok, 0}

      iex> Linx.Sysctl.read_int("kernel.hostname")  # not an integer
      {:error, {:bad_value, {:not_an_integer, "fry"}}}
  """
  @spec read_int(key(), opts()) ::
          {:ok, integer()}
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()} | {:bad_value, term()}}
  def read_int(key, opts \\ []) when is_binary(key) and is_list(opts) do
    with {:ok, raw} <- read(key, opts) do
      case Integer.parse(raw) do
        {n, ""} -> {:ok, n}
        _ -> {:error, {:bad_value, {:not_an_integer, raw}}}
      end
    end
  end

  @doc """
  Reads a sysctl and parses it as a list of integers, split on
  whitespace.

  Convenience for the tuple-shaped knobs: `kernel.printk` is four
  ints, `net.ipv4.tcp_rmem` / `tcp_wmem` are three each.

  Accepts the same `:in` option as `read/2`.

  ## Examples

      iex> Linx.Sysctl.read_ints("kernel.printk")
      {:ok, [4, 4, 1, 7]}

      iex> Linx.Sysctl.read_ints("net.ipv4.tcp_rmem")
      {:ok, [4096, 131072, 6291456]}
  """
  @spec read_ints(key(), opts()) ::
          {:ok, [integer()]}
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()} | {:bad_value, term()}}
  def read_ints(key, opts \\ []) when is_binary(key) and is_list(opts) do
    with {:ok, raw} <- read(key, opts) do
      raw
      |> String.split(~r/\s+/, trim: true)
      |> Enum.reduce_while({:ok, []}, fn token, {:ok, acc} ->
        case Integer.parse(token) do
          {n, ""} -> {:cont, {:ok, [n | acc]}}
          _ -> {:halt, {:error, {:bad_value, {:not_an_integer, token}}}}
        end
      end)
      |> case do
        {:ok, ints} -> {:ok, Enum.reverse(ints)}
        {:error, _} = err -> err
      end
    end
  end

  @doc """
  Writes a value to a sysctl.

  `value` may be:

    * an integer — rendered with `Integer.to_string/1`.
    * a binary — written verbatim. Must not contain `\\n` or `\\0`:
      the kernel's sysctl parser treats newlines as end-of-input
      and would silently truncate a multi-line string. We reject
      these before the write so the failure is loud.
    * a list of integers — rendered space-separated. For the
      tuple-shaped knobs like `kernel.printk`, `net.ipv4.tcp_rmem`,
      `net.ipv4.tcp_wmem`.

  We don't append a trailing `\\n` — the kernel accepts either form.

  ## Options

    * `:in` — `:self` (default), `{:pid, n}`, or `{:path, p}`.
      With `{:pid, _}`, the write lands in the target's namespace
      stack via the same setns dance as `read/2`.

  ## Examples

      iex> Linx.Sysctl.write("net.ipv4.ip_forward", 1)
      :ok

      iex> Linx.Sysctl.write("kernel.printk", [4, 4, 1, 7])
      :ok

      # Set the container's hostname without touching the host's.
      iex> Linx.Sysctl.write("kernel.hostname", "ct0", in: {:pid, container_pid})
      :ok

  ## Errors

    * `{:error, {:bad_key, reason}}` — malformed key.
    * `{:error, {:bad_value, reason}}` — bad value shape or content.
    * `{:error, {:bad_in, reason}}` — malformed `:in` value.
    * `{:error, %Linx.Sysctl.Error{}}` — kernel-level failure.
      Common: `:eacces` / `:eperm` (need root), `:enoent` (no such
      sysctl), `:einval` (value out of range / wrong shape).
  """
  @spec write(key(), value(), opts()) ::
          :ok
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()} | {:bad_value, term()}}
  def write(key, value, opts \\ []) when is_binary(key) and is_list(opts) do
    with {:ok, path} <- resolve_key(key),
         {:ok, blob} <- render_value(value),
         {:ok, target} <- resolve_in(opts) do
      do_write(key, path, blob, target)
    end
  end

  defp do_write(key, path, blob, :self) do
    case File.write(path, blob) do
      :ok -> :ok
      {:error, posix} -> {:error, Error.from_posix(posix, key, path, :write)}
    end
  end

  defp do_write(key, path, blob, {:cross, ns_paths}) do
    case Native.write_in_ns(path, blob, ns_paths) do
      :ok -> :ok
      {:error, {stage, errno}} -> {:error, native_error(stage, errno, key, path)}
    end
  end

  # Dot-form key → /proc/sys/.../slash/path. The regex check
  # rules out anything that could escape /proc/sys/ via traversal,
  # so the Path.join below is safe.
  defp resolve_key(key) do
    if Regex.match?(@key_regex, key) do
      {:ok, Path.join(@procsys, String.replace(key, ".", "/"))}
    else
      {:error, {:bad_key, key}}
    end
  end

  defp render_value(int) when is_integer(int), do: {:ok, Integer.to_string(int)}

  defp render_value(bin) when is_binary(bin) do
    cond do
      String.contains?(bin, "\n") -> {:error, {:bad_value, {:contains, :newline}}}
      String.contains?(bin, <<0>>) -> {:error, {:bad_value, {:contains, :nul}}}
      true -> {:ok, bin}
    end
  end

  defp render_value(list) when is_list(list) do
    if Enum.all?(list, &is_integer/1) do
      {:ok, Enum.map_join(list, " ", &Integer.to_string/1)}
    else
      {:error, {:bad_value, {:not_all_integers, list}}}
    end
  end

  defp render_value(other), do: {:error, {:bad_value, {:unsupported_type, other}}}

  # :in opt -> :self | {:cross, [ns_path_binary]}. For {:pid, _} we
  # filter out namespaces the target shares with us by comparing
  # the inode of /proc/<pid>/ns/<kind> against /proc/self/ns/<kind>:
  # `setns(2)` to a user namespace you're already in returns EINVAL,
  # so a workload spawned with namespaces: [:net, :uts] (no own user
  # ns) would fail the setns step on user/mnt/ipc otherwise. Only
  # cross what actually needs crossing.
  #
  # If the target shares all namespaces with us (the filtered list
  # is empty), short-circuit back to :self -- the operation is then
  # functionally identical to a host-side call.
  defp resolve_in(opts) do
    case Keyword.get(opts, :in, :self) do
      :self ->
        {:ok, :self}

      {:pid, n} when is_integer(n) and n > 0 ->
        case differing_ns_paths_for_pid(n) do
          [] -> {:ok, :self}
          paths -> {:ok, {:cross, paths}}
        end

      {:path, p} when is_binary(p) ->
        {:ok, {:cross, [p]}}

      other ->
        {:error, {:bad_in, other}}
    end
  end

  defp differing_ns_paths_for_pid(pid) do
    for k <- @ns_kinds, namespace_differs?(pid, k) do
      "/proc/#{pid}/ns/#{k}"
    end
  end

  # Each /proc/<pid>/ns/<kind> entry is a special file whose stat
  # inode uniquely identifies the namespace; two processes in the
  # same namespace see the same inode. If we can't stat one side
  # (target pid is gone, etc.) we include the path anyway and let
  # the NIF surface the resulting open_ns error.
  defp namespace_differs?(pid, kind) do
    target = File.stat("/proc/#{pid}/ns/#{kind}")
    mine = File.stat("/proc/self/ns/#{kind}")

    case {target, mine} do
      {{:ok, t}, {:ok, m}} -> t.inode != m.inode
      _ -> true
    end
  end

  # Convert a {stage, errno_atom_or_int} from the NIF into an
  # %Error{}. Posix atoms map straight through; the rare unmapped
  # integer becomes errno: :unknown with the int preserved in :code.
  defp native_error(stage, errno, key, path) when is_atom(errno) do
    Error.from_posix(errno, key, path, stage)
  end

  defp native_error(stage, errno_int, key, path) when is_integer(errno_int) do
    %Error{key: key, path: path, operation: stage, errno: :unknown, code: errno_int}
  end

  @doc """
  Walks `/proc/sys/` and returns every readable scalar as a list of
  `%Linx.Sysctl.Entry{}` structs, sorted by key.

  Unreadable nodes (some sysctls return `EACCES` / `EPERM` for
  unprivileged callers, write-only knobs return `EIO`) are silently
  skipped — the returned list is "everything I could see", not
  "everything that exists". On a typical Linux host expect ~1500
  entries.

  See `list/1` for the prefix-or-options variant, and `list/2` for
  the explicit prefix-plus-options form. Walking another process's
  namespace stack is `list(in: {:pid, n})` or
  `list("net.ipv4", in: {:pid, n})`.

  ## Examples

      iex> {:ok, all} = Linx.Sysctl.list()
      iex> Enum.find(all, & &1.key == "kernel.ostype")
      #Linx.Sysctl.Entry<kernel.ostype = "Linux">

  Note: a few sysctl files have dots in their leaf names (interface
  names like `eth0.10` for VLANs). For those entries the dot-form
  key isn't unambiguously round-trippable back to a single procfs
  path. The string is still a faithful representation of where the
  value came from; consumers that need to act on those should keep
  the procfs path side-channel.
  """
  @spec list() :: {:ok, [Entry.t()]} | {:error, term()}
  def list, do: do_list(@procsys, :self)

  @doc """
  Either `list(prefix)` to walk a subtree of `/proc/sys/`, or
  `list(opts)` to walk all of `/proc/sys/` with options.

  Dispatch is by argument type: a binary is a dot-form prefix,
  a keyword list is an options list.

  ## list(prefix) — subtree walk

  `list("net.ipv4")` returns every readable scalar under
  `/proc/sys/net/ipv4/`, sorted by key. The trailing `*` is implicit;
  globs are not accepted. If the prefix names a leaf rather than a
  subtree (e.g. `list("kernel.ostype")`), the result is a
  single-element list containing that entry.

      iex> {:ok, net} = Linx.Sysctl.list("net.ipv4")
      iex> Enum.all?(net, &String.starts_with?(&1.key, "net.ipv4."))
      true

      iex> Linx.Sysctl.list("kernel.ostype")  # leaf, not subtree
      {:ok, [#Linx.Sysctl.Entry<kernel.ostype = "Linux">]}

  ## list(opts) — full walk with options

  `list(in: {:pid, n})` walks all of `/proc/sys/` in the target's
  namespace stack. Equivalent to `list("/", in: {:pid, n})` if such
  a "root prefix" were allowed.

      iex> Linx.Sysctl.list(in: {:pid, container_pid})
      {:ok, [...]}
  """
  @spec list(key() | opts()) ::
          {:ok, [Entry.t()]}
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()}}
  def list(arg) when is_list(arg) do
    with {:ok, target} <- resolve_in(arg) do
      do_list(@procsys, target)
    end
  end

  def list(prefix) when is_binary(prefix), do: list(prefix, [])

  @doc """
  Walks the subtree of `/proc/sys/` named by `prefix` with options.

  Same prefix semantics as `list/1` (subtree → walk, leaf → single
  entry); same `:in` option as the other verbs.

  ## Examples

      # Read every net.ipv4 knob the container sees.
      iex> Linx.Sysctl.list("net.ipv4", in: {:pid, container_pid})
      {:ok, [...]}

      # The container's view of its own hostname (a single-leaf prefix).
      iex> Linx.Sysctl.list("kernel.hostname", in: {:pid, container_pid})
      {:ok, [#Linx.Sysctl.Entry<kernel.hostname = "ct0">]}
  """
  @spec list(key(), opts()) ::
          {:ok, [Entry.t()]}
          | {:error, Error.t() | {:bad_key, term()} | {:bad_in, term()}}
  def list(prefix, opts) when is_binary(prefix) and is_list(opts) do
    with {:ok, path} <- resolve_key(prefix),
         {:ok, target} <- resolve_in(opts) do
      do_list_with_prefix(prefix, path, target)
    end
  end

  defp do_list(root, :self) do
    {:ok, root |> walk() |> Enum.sort_by(& &1.key)}
  end

  defp do_list(root, {:cross, ns_paths}) do
    case Native.list_in_ns(root, ns_paths) do
      {:ok, raw_entries} ->
        {:ok,
         raw_entries
         |> Enum.map(fn {path, value} ->
           %Entry{key: path_to_key(path), value: String.trim_trailing(value)}
         end)
         |> Enum.sort_by(& &1.key)}

      {:error, {stage, errno}} ->
        {:error, native_error(stage, errno, "", root)}
    end
  end

  defp do_list_with_prefix(prefix, path, :self) do
    cond do
      File.dir?(path) ->
        {:ok, path |> walk() |> Enum.sort_by(& &1.key)}

      File.regular?(path) ->
        case File.read(path) do
          {:ok, data} ->
            {:ok, [%Entry{key: prefix, value: String.trim_trailing(data)}]}

          {:error, posix} ->
            {:error, Error.from_posix(posix, prefix, path, :list)}
        end

      true ->
        {:error, Error.from_posix(:enoent, prefix, path, :list)}
    end
  end

  defp do_list_with_prefix(prefix, path, {:cross, ns_paths}) do
    case Native.list_in_ns(path, ns_paths) do
      {:ok, raw_entries} ->
        {:ok,
         raw_entries
         |> Enum.map(fn {p, value} ->
           %Entry{key: path_to_key(p), value: String.trim_trailing(value)}
         end)
         |> Enum.sort_by(& &1.key)}

      {:error, {:list, :enotdir}} ->
        # Prefix names a leaf in the target ns. Fall back to a single
        # read so callers see the same shape as the :self path.
        case Native.read_in_ns(path, ns_paths) do
          {:ok, data} ->
            {:ok, [%Entry{key: prefix, value: String.trim_trailing(data)}]}

          {:error, {stage, errno}} ->
            {:error, native_error(stage, errno, prefix, path)}
        end

      {:error, {stage, errno}} ->
        {:error, native_error(stage, errno, prefix, path)}
    end
  end

  # Recursive walker for the :self path. Skips unreadable directories
  # and unreadable files silently per the PLAN ("everything I could
  # see"). Builds an unsorted list of %Entry{}; callers sort_by it.
  defp walk(root), do: walk(root, [])

  defp walk(root, acc) do
    case File.ls(root) do
      {:ok, names} ->
        Enum.reduce(names, acc, fn name, acc ->
          path = Path.join(root, name)

          cond do
            File.dir?(path) ->
              walk(path, acc)

            File.regular?(path) ->
              case File.read(path) do
                {:ok, data} ->
                  [%Entry{key: path_to_key(path), value: String.trim_trailing(data)} | acc]

                {:error, _posix} ->
                  acc
              end

            true ->
              acc
          end
        end)

      {:error, _posix} ->
        acc
    end
  end

  defp path_to_key(path) do
    path
    |> Path.relative_to(@procsys)
    |> String.replace("/", ".")
  end
end
