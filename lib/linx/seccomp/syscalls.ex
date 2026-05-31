defmodule Linx.Seccomp.Syscalls do
  @moduledoc false
  # Hand-curated per-arch syscall atom ↔ number tables.
  #
  # Two maps live here, one per supported architecture:
  #
  #   * `@x86_64`  — sourced from `arch/x86/entry/syscalls/syscall_64.tbl`
  #     in the kernel tree (or `/usr/include/asm/unistd_64.h` locally).
  #     Each line of the .tbl file is
  #     `<number> <abi> <name> <entry-point>`; we take the `<name>` and
  #     `<number>` from the `common` and `64` abi rows.
  #
  #   * `@aarch64` — sourced from `include/uapi/asm-generic/unistd.h`
  #     (aarch64 uses the generic table). Numbers are defined as
  #     `#define __NR_<name> <number>`.
  #
  # The table is intentionally **not** complete — we ship ~150
  # syscalls per arch, covering:
  #
  #   1. The common workload subset (read / write / openat / mmap /
  #      socket / connect / accept4 / clone / execve / exit / …).
  #   2. The Docker default-profile deny-list (ptrace, kexec_load,
  #      init_module, delete_module, swapon, swapoff, mount, umount2,
  #      pivot_root, iopl, ioperm, reboot, …).
  #   3. The namespace / capability / seccomp / bpf syscalls Linx
  #      itself uses.
  #
  # ## Extending this table
  #
  # To add a syscall, look up its number in the source above for each
  # arch (you typically need both) and add an entry to the per-arch
  # map below. Then run `mix test test/linx/seccomp_test.exs` — the
  # round-trip tests catch table inconsistencies (duplicate numbers,
  # atoms missing from one arch, etc.).
  #
  # Syscalls that exist on one arch but not the other (e.g. legacy
  # `:open` on x86_64; aarch64 doesn't carry the unsuffixed verbs)
  # appear in exactly one map. `to_number/2` returns `nil` for an
  # atom that's unknown on the requested arch.

  # ── x86_64 ─────────────────────────────────────────────────────
  # arch/x86/entry/syscalls/syscall_64.tbl
  @x86_64 %{
    # I/O fundamentals.
    read: 0,
    write: 1,
    open: 2,
    close: 3,
    stat: 4,
    fstat: 5,
    lstat: 6,
    poll: 7,
    lseek: 8,
    mmap: 9,
    mprotect: 10,
    munmap: 11,
    brk: 12,
    rt_sigaction: 13,
    rt_sigprocmask: 14,
    rt_sigreturn: 15,
    ioctl: 16,
    pread64: 17,
    pwrite64: 18,
    readv: 19,
    writev: 20,
    access: 21,
    pipe: 22,
    select: 23,
    sched_yield: 24,
    mremap: 25,
    msync: 26,
    mincore: 27,
    madvise: 28,
    dup: 32,
    dup2: 33,
    pause: 34,
    nanosleep: 35,
    getpid: 39,
    socket: 41,
    connect: 42,
    accept: 43,
    sendto: 44,
    recvfrom: 45,
    sendmsg: 46,
    recvmsg: 47,
    shutdown: 48,
    bind: 49,
    listen: 50,
    getsockname: 51,
    getpeername: 52,
    socketpair: 53,
    setsockopt: 54,
    getsockopt: 55,
    clone: 56,
    fork: 57,
    vfork: 58,
    execve: 59,
    exit: 60,
    wait4: 61,
    kill: 62,
    uname: 63,
    fcntl: 72,
    flock: 73,
    fsync: 74,
    fdatasync: 75,
    truncate: 76,
    ftruncate: 77,
    getcwd: 79,
    chdir: 80,
    fchdir: 81,
    rename: 82,
    mkdir: 83,
    rmdir: 84,
    unlink: 87,
    symlink: 88,
    readlink: 89,
    chmod: 90,
    fchmod: 91,
    chown: 92,
    fchown: 93,
    umask: 95,
    gettimeofday: 96,
    sysinfo: 99,
    getuid: 102,
    getgid: 104,
    setuid: 105,
    setgid: 106,
    geteuid: 107,
    getegid: 108,
    setpgid: 109,
    getppid: 110,
    setreuid: 113,
    setregid: 114,
    getgroups: 115,
    setgroups: 116,
    setresuid: 117,
    getresuid: 118,
    setresgid: 119,
    getresgid: 120,
    getpgid: 121,
    setfsuid: 122,
    setfsgid: 123,
    getsid: 124,
    capget: 125,
    capset: 126,
    rt_sigpending: 127,
    rt_sigtimedwait: 128,
    rt_sigqueueinfo: 129,
    rt_sigsuspend: 130,
    sigaltstack: 131,
    statfs: 137,
    fstatfs: 138,
    sched_setparam: 142,
    sched_getparam: 143,
    sched_setscheduler: 144,
    sched_getscheduler: 145,
    sched_get_priority_max: 146,
    sched_get_priority_min: 147,
    prctl: 157,
    arch_prctl: 158,
    setrlimit: 160,
    chroot: 161,
    mount: 165,
    umount2: 166,
    swapon: 167,
    swapoff: 168,
    reboot: 169,
    iopl: 172,
    ioperm: 173,
    init_module: 175,
    delete_module: 176,
    gettid: 186,
    tkill: 200,
    futex: 202,
    sched_setaffinity: 203,
    sched_getaffinity: 204,
    getdents64: 217,
    set_tid_address: 218,
    restart_syscall: 219,
    fadvise64: 221,
    clock_settime: 227,
    clock_gettime: 228,
    clock_getres: 229,
    clock_nanosleep: 230,
    exit_group: 231,
    epoll_wait: 232,
    epoll_ctl: 233,
    tgkill: 234,
    waitid: 247,
    kexec_load: 246,
    inotify_init: 253,
    inotify_add_watch: 254,
    inotify_rm_watch: 255,
    openat: 257,
    mkdirat: 258,
    mknodat: 259,
    fchownat: 260,
    newfstatat: 262,
    unlinkat: 263,
    renameat: 264,
    linkat: 265,
    symlinkat: 266,
    readlinkat: 267,
    fchmodat: 268,
    faccessat: 269,
    pselect6: 270,
    ppoll: 271,
    unshare: 272,
    set_robust_list: 273,
    get_robust_list: 274,
    splice: 275,
    tee: 276,
    utimensat: 280,
    epoll_pwait: 281,
    signalfd: 282,
    timerfd_create: 283,
    eventfd: 284,
    fallocate: 285,
    timerfd_settime: 286,
    timerfd_gettime: 287,
    accept4: 288,
    signalfd4: 289,
    eventfd2: 290,
    epoll_create1: 291,
    dup3: 292,
    pipe2: 293,
    inotify_init1: 294,
    preadv: 295,
    pwritev: 296,
    perf_event_open: 298,
    recvmmsg: 299,
    prlimit64: 302,
    syncfs: 306,
    sendmmsg: 307,
    setns: 308,
    getcpu: 309,
    process_vm_readv: 310,
    process_vm_writev: 311,
    renameat2: 316,
    seccomp: 317,
    getrandom: 318,
    memfd_create: 319,
    kexec_file_load: 320,
    bpf: 321,
    execveat: 322,
    userfaultfd: 323,
    membarrier: 324,
    mlock2: 325,
    copy_file_range: 326,
    pkey_mprotect: 329,
    pkey_alloc: 330,
    pkey_free: 331,
    statx: 332,
    rseq: 334,
    pidfd_send_signal: 424,
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
    open_tree: 428,
    move_mount: 429,
    fsopen: 430,
    fsconfig: 431,
    fsmount: 432,
    fspick: 433,
    pidfd_open: 434,
    clone3: 435,
    close_range: 436,
    openat2: 437,
    pidfd_getfd: 438,
    faccessat2: 439,
    process_madvise: 440,
    epoll_pwait2: 441,
    mount_setattr: 442,
    landlock_create_ruleset: 444,
    landlock_add_rule: 445,
    landlock_restrict_self: 446,
    pivot_root: 155,
    mlock: 149,
    munlock: 150,
    mlockall: 151,
    munlockall: 152,
    ptrace: 101,
    syslog: 103
  }

  # ── aarch64 ────────────────────────────────────────────────────
  # include/uapi/asm-generic/unistd.h. The asm-generic table omits
  # legacy unsuffixed variants (open / stat / fork / vfork / dup2 /
  # poll / select / epoll_create / epoll_wait / mkdir / unlink /
  # rename / ...) — callers on aarch64 use the *at / *2 forms.
  @aarch64 %{
    getcwd: 17,
    eventfd2: 19,
    epoll_create1: 20,
    epoll_ctl: 21,
    epoll_pwait: 22,
    dup: 23,
    dup3: 24,
    fcntl: 25,
    inotify_init1: 26,
    inotify_add_watch: 27,
    inotify_rm_watch: 28,
    ioctl: 29,
    flock: 32,
    mknodat: 33,
    mkdirat: 34,
    unlinkat: 35,
    symlinkat: 36,
    linkat: 37,
    umount2: 39,
    mount: 40,
    pivot_root: 41,
    statfs: 43,
    fstatfs: 44,
    truncate: 45,
    ftruncate: 46,
    fallocate: 47,
    faccessat: 48,
    chdir: 49,
    fchdir: 50,
    chroot: 51,
    fchmod: 52,
    fchmodat: 53,
    fchownat: 54,
    fchown: 55,
    openat: 56,
    close: 57,
    pipe2: 59,
    getdents64: 61,
    lseek: 62,
    read: 63,
    write: 64,
    readv: 65,
    writev: 66,
    pread64: 67,
    pwrite64: 68,
    preadv: 69,
    pwritev: 70,
    sendfile: 71,
    pselect6: 72,
    ppoll: 73,
    signalfd4: 74,
    splice: 76,
    tee: 77,
    readlinkat: 78,
    newfstatat: 79,
    fstat: 80,
    fsync: 82,
    fdatasync: 83,
    timerfd_create: 85,
    timerfd_settime: 86,
    timerfd_gettime: 87,
    utimensat: 88,
    capget: 90,
    capset: 91,
    exit: 93,
    exit_group: 94,
    waitid: 95,
    set_tid_address: 96,
    unshare: 97,
    futex: 98,
    set_robust_list: 99,
    get_robust_list: 100,
    nanosleep: 101,
    kexec_load: 104,
    init_module: 105,
    delete_module: 106,
    clock_settime: 112,
    clock_gettime: 113,
    clock_getres: 114,
    clock_nanosleep: 115,
    syslog: 116,
    ptrace: 117,
    sched_setparam: 118,
    sched_setscheduler: 119,
    sched_getscheduler: 120,
    sched_getparam: 121,
    sched_setaffinity: 122,
    sched_getaffinity: 123,
    sched_yield: 124,
    sched_get_priority_max: 125,
    sched_get_priority_min: 126,
    restart_syscall: 128,
    kill: 129,
    tkill: 130,
    tgkill: 131,
    sigaltstack: 132,
    rt_sigsuspend: 133,
    rt_sigaction: 134,
    rt_sigprocmask: 135,
    rt_sigpending: 136,
    rt_sigtimedwait: 137,
    rt_sigqueueinfo: 138,
    rt_sigreturn: 139,
    reboot: 142,
    setregid: 143,
    setgid: 144,
    setreuid: 145,
    setuid: 146,
    setresuid: 147,
    getresuid: 148,
    setresgid: 149,
    getresgid: 150,
    setfsuid: 151,
    setfsgid: 152,
    setpgid: 154,
    getpgid: 155,
    getsid: 156,
    setsid: 157,
    getgroups: 158,
    setgroups: 159,
    uname: 160,
    umask: 166,
    prctl: 167,
    getcpu: 168,
    gettimeofday: 169,
    getpid: 172,
    getppid: 173,
    getuid: 174,
    geteuid: 175,
    getgid: 176,
    getegid: 177,
    gettid: 178,
    sysinfo: 179,
    socket: 198,
    socketpair: 199,
    bind: 200,
    listen: 201,
    accept: 202,
    connect: 203,
    getsockname: 204,
    getpeername: 205,
    sendto: 206,
    recvfrom: 207,
    setsockopt: 208,
    getsockopt: 209,
    shutdown: 210,
    sendmsg: 211,
    recvmsg: 212,
    brk: 214,
    munmap: 215,
    mremap: 216,
    clone: 220,
    execve: 221,
    mmap: 222,
    fadvise64: 223,
    swapon: 224,
    swapoff: 225,
    mprotect: 226,
    msync: 227,
    mlock: 228,
    munlock: 229,
    mlockall: 230,
    munlockall: 231,
    mincore: 232,
    madvise: 233,
    perf_event_open: 241,
    accept4: 242,
    recvmmsg: 243,
    wait4: 260,
    prlimit64: 261,
    syncfs: 267,
    setns: 268,
    sendmmsg: 269,
    process_vm_readv: 270,
    process_vm_writev: 271,
    finit_module: 273,
    renameat2: 276,
    seccomp: 277,
    getrandom: 278,
    memfd_create: 279,
    bpf: 280,
    execveat: 281,
    userfaultfd: 282,
    membarrier: 283,
    mlock2: 284,
    copy_file_range: 285,
    pkey_mprotect: 288,
    pkey_alloc: 289,
    pkey_free: 290,
    statx: 291,
    rseq: 293,
    kexec_file_load: 294,
    pidfd_send_signal: 424,
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
    open_tree: 428,
    move_mount: 429,
    fsopen: 430,
    fsconfig: 431,
    fsmount: 432,
    fspick: 433,
    pidfd_open: 434,
    clone3: 435,
    close_range: 436,
    openat2: 437,
    pidfd_getfd: 438,
    faccessat2: 439,
    process_madvise: 440,
    epoll_pwait2: 441,
    mount_setattr: 442,
    landlock_create_ruleset: 444,
    landlock_add_rule: 445,
    landlock_restrict_self: 446
  }

  @x86_64_inv (for {atom, n} <- @x86_64, into: %{}, do: {n, atom})
  @aarch64_inv (for {atom, n} <- @aarch64, into: %{}, do: {n, atom})

  @x86_64_atoms MapSet.new(Map.keys(@x86_64))
  @aarch64_atoms MapSet.new(Map.keys(@aarch64))

  @doc """
  The current host architecture as an atom — wraps
  `Linx.Seccomp.arch/0`. Returned values: `:x86_64`, `:aarch64`,
  `:unsupported`.
  """
  @spec arch() :: atom()
  def arch, do: Linx.Seccomp.arch()

  @doc """
  Syscall atom → number on the given arch. Returns `nil` if the atom
  isn't in the table for that arch, or if the arch is unsupported.

  ## Examples

      iex> Linx.Seccomp.Syscalls.to_number(:read, :x86_64)
      0
      iex> Linx.Seccomp.Syscalls.to_number(:read, :aarch64)
      63
      iex> Linx.Seccomp.Syscalls.to_number(:open, :aarch64)
      nil
      iex> Linx.Seccomp.Syscalls.to_number(:read, :riscv64)
      nil
  """
  @spec to_number(atom(), atom()) :: non_neg_integer() | nil
  def to_number(syscall, :x86_64) when is_atom(syscall),
    do: Map.get(@x86_64, syscall)

  def to_number(syscall, :aarch64) when is_atom(syscall),
    do: Map.get(@aarch64, syscall)

  def to_number(_syscall, _arch), do: nil

  @doc """
  Number → syscall atom on the given arch.

  Returns `:unknown` for any number not in this arch's table —
  forward-compat with kernels that ship syscalls Linx hasn't
  catalogued yet, and graceful behaviour for an unsupported arch.
  """
  @spec from_number(non_neg_integer(), atom()) :: atom()
  def from_number(n, :x86_64) when is_integer(n) and n >= 0,
    do: Map.get(@x86_64_inv, n, :unknown)

  def from_number(n, :aarch64) when is_integer(n) and n >= 0,
    do: Map.get(@aarch64_inv, n, :unknown)

  def from_number(_n, _arch), do: :unknown

  @doc """
  Every known syscall on the given arch, as a `MapSet`. Returns the
  empty MapSet for an unsupported arch.
  """
  @spec all(atom()) :: MapSet.t(atom())
  def all(:x86_64), do: @x86_64_atoms
  def all(:aarch64), do: @aarch64_atoms
  def all(_arch), do: MapSet.new()

  @doc """
  Whether `syscall` is in the curated table for `arch`. Convenience
  for the rule validators in `Linx.Seccomp` / the builder.
  """
  @spec known?(atom(), atom()) :: boolean()
  def known?(syscall, arch), do: not is_nil(to_number(syscall, arch))
end
