defmodule Linx.ErrorModelTest do
  use ExUnit.Case, async: true

  # Exercises the Phase-1 error structs whose value is in their mapping
  # tables and message/1 clauses — the parts unit tests for the happy path
  # never touch. Covers Linx.Tty.Error (bidirectional errno<->code) and
  # Linx.Process.Error (agent code -> POSIX atom).

  alias Linx.Process.Error, as: PErr
  alias Linx.Tty.Error, as: TErr

  describe "Linx.Tty.Error" do
    # The known errno<->code pairs; from_nif must map both directions.
    @pairs %{
      eacces: 13,
      ebadf: 9,
      ebusy: 16,
      eintr: 4,
      einval: 22,
      eio: 5,
      enoent: 2,
      enomem: 12,
      enotty: 25,
      enxio: 6,
      eperm: 1
    }

    test "from_nif maps a POSIX atom to its numeric code and back" do
      for {errno, code} <- @pairs do
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
    @posix %{
      1 => :eperm,
      2 => :enoent,
      4 => :eintr,
      5 => :eio,
      9 => :ebadf,
      11 => :eagain,
      12 => :enomem,
      13 => :eacces,
      14 => :efault,
      22 => :einval,
      71 => :eproto,
      90 => :emsgsize
    }

    test "from_agent maps a kernel errno code to its POSIX atom for a normal stage" do
      for {code, errno} <- @posix do
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
end
