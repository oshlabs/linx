defmodule Linx.ErrorModelTest do
  use ExUnit.Case, async: true

  # Exercises the shared errno table (Linx.Errno) and the parts of the
  # error structs unit tests for the happy path never touch: the
  # constructor mapping clauses, message/1, and the cross-subsystem
  # uniformity contract every %Linx.X.Error{} promises.

  alias Linx.Process.Error, as: PErr
  alias Linx.Tty.Error, as: TErr

  describe "Linx.Errno" do
    # Golden pairs pinned against asm-generic errno numbers — a typo in
    # the shared table would silently mis-label kernel errors everywhere.
    @pairs %{
      eperm: 1,
      enoent: 2,
      esrch: 3,
      eintr: 4,
      eio: 5,
      enxio: 6,
      e2big: 7,
      ebadf: 9,
      eagain: 11,
      enomem: 12,
      eacces: 13,
      efault: 14,
      ebusy: 16,
      eexist: 17,
      enodev: 19,
      enotdir: 20,
      eisdir: 21,
      einval: 22,
      emfile: 24,
      enotty: 25,
      efbig: 27,
      enospc: 28,
      erofs: 30,
      erange: 34,
      enametoolong: 36,
      enosys: 38,
      enotempty: 39,
      eloop: 40,
      eproto: 71,
      erestart: 85,
      emsgsize: 90,
      eprotonosupport: 93,
      eopnotsupp: 95,
      eaddrinuse: 98,
      enobufs: 105,
      etimedout: 110
    }

    test "code/1 and atom/1 agree on the golden pairs, both directions" do
      for {errno, code} <- @pairs do
        assert Linx.Errno.code(errno) == code
        assert Linx.Errno.atom(code) == errno
      end
    end

    test "an unknown atom has no code; an unknown code is :unknown" do
      assert Linx.Errno.code(:eweird) == nil
      assert Linx.Errno.atom(4242) == :unknown
    end

    test ":enotsup (Erlang file convention) aliases EOPNOTSUPP; reverse is canonical" do
      assert Linx.Errno.code(:enotsup) == 95
      assert Linx.Errno.atom(95) == :eopnotsupp
    end
  end

  describe "Linx.Tty.Error" do
    test "from_nif maps a POSIX atom to its numeric code and back" do
      for {errno, code} <- %{enotty: 25, enxio: 6, eperm: 1} do
        assert %TErr{operation: :open, errno: ^errno, code: ^code} = TErr.from_nif(:open, errno)
        assert %TErr{operation: :open, errno: ^errno, code: ^code} = TErr.from_nif(:open, code)
      end
    end

    test "an unmapped integer code yields :unknown but keeps the code" do
      assert %TErr{operation: :ioctl, errno: :unknown, code: 4242} = TErr.from_nif(:ioctl, 4242)
    end

    test "an atom not in the table has no numeric code" do
      assert %TErr{operation: :tcsetattr, errno: :eweird, code: nil} =
               TErr.from_nif(:tcsetattr, :eweird)
    end

    test "message/1 is a non-empty string naming the operation, in every clause" do
      for err <- [
            TErr.from_nif(:open, :enoent),
            TErr.from_nif(:ioctl, 4242),
            TErr.from_nif(:tcsetattr, :eweird)
          ] do
        msg = Exception.message(err)
        assert is_binary(msg) and msg != ""
        assert msg =~ Atom.to_string(err.operation)
      end
    end

    test "behaves as a raisable exception" do
      assert_raise TErr, fn -> raise TErr, operation: :open, errno: :enoent end
    end
  end

  describe "Linx.Process.Error" do
    test "from_agent maps a kernel errno code to its POSIX atom for a normal stage" do
      for {errno, code} <- %{enoent: 2, eproto: 71, emsgsize: 90} do
        assert %PErr{stage: :execve, errno: ^errno, code: ^code} = PErr.from_agent(code, :execve)
      end
    end

    test "an unmapped code falls through to :unknown but keeps the code" do
      assert %PErr{stage: :execve, errno: :unknown, code: 4242} = PErr.from_agent(4242, :execve)
    end

    test "the :agent_died stage carries the exit status, not an errno" do
      assert %PErr{stage: :agent_died, errno: :unknown, code: 137} =
               PErr.from_agent(137, :agent_died)
    end

    test "message/1 is a non-empty string in every clause" do
      for err <- [
            PErr.from_agent(2, :execve),
            PErr.from_agent(4242, :execve),
            PErr.from_agent(137, :agent_died)
          ] do
        msg = Exception.message(err)
        assert is_binary(msg) and msg != ""
      end
    end
  end

  describe "cross-subsystem uniformity" do
    # One representative struct per subsystem, built through the public
    # constructor. The contract: every %Linx.X.Error{} is an Exception,
    # carries an :errno atom plus a :code from the shared Linx.Errno
    # table, and renders a non-empty message. A new or reworked Error
    # module that drifts from the shape fails here.
    defp samples do
      [
        Linx.Process.Error.from_agent(2, :execve),
        Linx.Tty.Error.from_nif(:open, :enoent),
        Linx.Netlink.Error.from_errno(1),
        Linx.Cgroup.Error.from_posix(:enoent, "/sys/fs/cgroup/x", :read),
        Linx.Mount.Error.from_posix(:enoent, "/mnt/x", :mount),
        Linx.User.Error.from_posix(:eperm, "/proc/1/uid_map", :set_uid_map),
        Linx.Capabilities.Error.from_posix(:enoent, "/proc/1/status", :read),
        Linx.Seccomp.Error.from_posix(:einval, :build),
        Linx.Sysctl.Error.from_posix(
          :enoent,
          "net.ipv4.ip_forward",
          "/proc/sys/net/ipv4/ip_forward",
          :read
        ),
        Linx.Netfilter.Error.from_posix(:eperm, :push)
      ]
    end

    test "every subsystem error is an Exception with :errno + :code from the shared table" do
      for err <- samples() do
        assert is_exception(err), "#{inspect(err.__struct__)} is not an Exception"
        assert is_atom(err.errno)
        assert err.code == Linx.Errno.code(err.errno)

        msg = Exception.message(err)
        assert is_binary(msg) and msg != ""
      end
    end
  end
end
