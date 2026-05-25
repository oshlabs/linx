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

  S0–S2 shipped. `supported?/0`, host-side `read/1`, `read_int/1`,
  `read_ints/1`, `write/2`, subtree walking via `list/0` / `list/1`
  returning `[%Linx.Sysctl.Entry{}]`, and structured
  `%Linx.Sysctl.Error{}` results are in. The cross-namespace `:in`
  option lands in S3. See `docs/sysctl/PLAN.md` for the roadmap.
  """

  alias Linx.Sysctl.Entry
  alias Linx.Sysctl.Error

  @procsys "/proc/sys"
  @self_ostype Path.join(@procsys, "kernel/ostype")

  # Dot-form sysctl keys: each `.`-separated segment is one or more
  # of [A-Za-z0-9_-]; segments can't be empty (rules out leading /
  # trailing / consecutive dots and the `..` path-traversal case).
  @key_regex ~r/\A[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\z/

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
  trailing whitespace stripped (the kernel always appends a `\\n`).

  ## Examples

      iex> Linx.Sysctl.read("kernel.ostype")
      {:ok, "Linux"}

      iex> Linx.Sysctl.read("net.ipv4.ip_forward")
      {:ok, "0"}

  ## Errors

    * `{:error, {:bad_key, reason}}` — caller-side input mistake
      (empty key, illegal characters, leading/trailing/consecutive
      dots). Caught before any procfs read.
    * `{:error, %Linx.Sysctl.Error{}}` — kernel-level failure.
      Common: `:enoent` (no such sysctl on this kernel),
      `:eacces` (procfs denied the read).
  """
  @spec read(key()) ::
          {:ok, binary()} | {:error, Error.t() | {:bad_key, term()}}
  def read(key) when is_binary(key) do
    with {:ok, path} <- resolve_key(key) do
      case File.read(path) do
        {:ok, data} -> {:ok, String.trim_trailing(data)}
        {:error, posix} -> {:error, Error.from_posix(posix, key, path, :read)}
      end
    end
  end

  @doc """
  Reads a sysctl and parses it as a single integer.

  Convenience for the common case (`net.ipv4.ip_forward`,
  `vm.swappiness`, every `*_max` / `*_min` knob).

  ## Examples

      iex> Linx.Sysctl.read_int("net.ipv4.ip_forward")
      {:ok, 0}

      iex> Linx.Sysctl.read_int("kernel.hostname")  # not an integer
      {:error, {:bad_value, {:not_an_integer, "fry"}}}
  """
  @spec read_int(key()) ::
          {:ok, integer()} | {:error, Error.t() | {:bad_key, term()} | {:bad_value, term()}}
  def read_int(key) when is_binary(key) do
    with {:ok, raw} <- read(key) do
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

  ## Examples

      iex> Linx.Sysctl.read_ints("kernel.printk")
      {:ok, [4, 4, 1, 7]}

      iex> Linx.Sysctl.read_ints("net.ipv4.tcp_rmem")
      {:ok, [4096, 131072, 6291456]}
  """
  @spec read_ints(key()) ::
          {:ok, [integer()]} | {:error, Error.t() | {:bad_key, term()} | {:bad_value, term()}}
  def read_ints(key) when is_binary(key) do
    with {:ok, raw} <- read(key) do
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

  In S1 this writes to the host's namespace context. In S3 it
  gains an `:in` option (`:self` / `{:pid, n}` / `{:path, p}`) for
  cross-namespace writes against a target process's namespace
  stack — same shape as `Linx.Mount`'s `:in` option.

  ## Examples

      iex> Linx.Sysctl.write("net.ipv4.ip_forward", 1)
      :ok

      iex> Linx.Sysctl.write("kernel.printk", [4, 4, 1, 7])
      :ok

      iex> Linx.Sysctl.write("kernel.hostname", "ct0")
      :ok

  ## Errors

    * `{:error, {:bad_key, reason}}` — malformed key.
    * `{:error, {:bad_value, reason}}` — value contains a newline
      or NUL, or a list element isn't an integer, or the type isn't
      one of the three supported shapes above.
    * `{:error, %Linx.Sysctl.Error{}}` — kernel-level failure.
      Common: `:eacces` / `:eperm` (need root for most knobs),
      `:enoent` (no such sysctl on this kernel), `:einval` (value
      out of range or wrong shape for this knob).
  """
  @spec write(key(), value()) ::
          :ok | {:error, Error.t() | {:bad_key, term()} | {:bad_value, term()}}
  def write(key, value) when is_binary(key) do
    with {:ok, path} <- resolve_key(key),
         {:ok, blob} <- render_value(value) do
      case File.write(path, blob) do
        :ok -> :ok
        {:error, posix} -> {:error, Error.from_posix(posix, key, path, :write)}
      end
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

  @doc """
  Walks `/proc/sys/` and returns every readable scalar as a list of
  `%Linx.Sysctl.Entry{}` structs, sorted by key.

  Unreadable nodes (some sysctls return `EACCES` / `EPERM` for
  unprivileged callers, write-only knobs return `EIO`) are silently
  skipped — the returned list is "everything I could see", not
  "everything that exists". On a typical Linux host expect ~1500
  entries.

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
  def list, do: {:ok, @procsys |> walk() |> Enum.sort_by(& &1.key)}

  @doc """
  Walks a subtree of `/proc/sys/` named by a dot-form key prefix.

  `list("net.ipv4")` returns every readable scalar under
  `/proc/sys/net/ipv4/`, sorted by key. The trailing `*` is
  implicit; globs are not accepted.

  If the prefix names a leaf rather than a subtree (e.g.
  `list("kernel.ostype")`), the result is a single-element list
  containing that entry — convenient if a caller doesn't know in
  advance whether a given dot-form name is a directory or a file.

  ## Examples

      iex> {:ok, net} = Linx.Sysctl.list("net.ipv4")
      iex> Enum.all?(net, &String.starts_with?(&1.key, "net.ipv4."))
      true

      iex> Linx.Sysctl.list("kernel.ostype")  # leaf, not subtree
      {:ok, [#Linx.Sysctl.Entry<kernel.ostype = "Linux">]}

      iex> Linx.Sysctl.list("linx.does.not.exist")
      {:error,
       %Linx.Sysctl.Error{
         key: "linx.does.not.exist",
         path: "/proc/sys/linx/does/not/exist",
         operation: :list,
         errno: :enoent,
         code: 2
       }}
  """
  @spec list(key()) ::
          {:ok, [Entry.t()]} | {:error, Error.t() | {:bad_key, term()}}
  def list(prefix) when is_binary(prefix) do
    with {:ok, path} <- resolve_key(prefix) do
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
  end

  # Recursive walker. Skips unreadable directories and unreadable
  # files silently per the PLAN ("everything I could see"). Builds
  # an unsorted list of %Entry{}; callers Enum.sort_by it at the
  # top level.
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
