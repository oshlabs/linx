defmodule Linx.Process.Error do
  @moduledoc """
  A pre-exec or transport-level failure from a `Linx.Process` session.

  Stored as the session's terminal result and returned by
  `Linx.Process.wait/1` (and surfaced via `Linx.Process.info/1`) as
  `{:error, %Linx.Process.Error{}}`.

  The *same* failure is also delivered to the session owner as the
  positional event `{:linx_process, :error, errno, stage}` — where
  `errno` is a raw integer. That event stays positional to match its
  sibling lifecycle events (`{:linx_process, :exited, code}` etc.); this
  struct is the richer, `Exception`-implementing form on the synchronous
  return path, consistent with the other `%Linx.X.Error{}` types.

  ## Fields

    * `:stage` — the clone→exec stage that failed (`:execve`, `:clone`,
      `:seccomp_install`, …) — the Process analogue of the `:operation`
      field other error structs carry. See the stage table in
      `Linx.Process`.
    * `:errno` — the POSIX errno as an atom (`:enoent`, `:einval`, …),
      or `:unknown` for an errno Linx hasn't catalogued.
    * `:code` — the raw integer. The kernel errno for ordinary failures;
      for `stage: :agent_died` it is the agent's **process exit code**,
      not an errno (and `:errno` is `:unknown`), mirroring the documented
      `:agent_died` convention.

  Implements `Exception`, so it can be `raise`d or rendered with
  `Exception.message/1`.
  """

  @enforce_keys [:stage, :errno, :code]
  defexception [:stage, :errno, :code]

  @type t :: %__MODULE__{stage: atom(), errno: atom(), code: integer() | nil}

  # POSIX errno numbers the agent realistically reports across its stage
  # table (linux/asm-generic/errno-base.h). An unmapped code falls
  # through to :unknown; the integer is still kept in :code.
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

  @doc """
  Builds an error from the agent's integer `code` and the `stage` atom.

  For ordinary stages `code` is a kernel errno and `errno` is its POSIX
  name (or `:unknown`). For `:agent_died`, `code` is the agent's exit
  status — not an errno — so `errno` is `:unknown`.
  """
  @spec from_agent(integer(), atom()) :: t()
  def from_agent(code, :agent_died) when is_integer(code) do
    %__MODULE__{stage: :agent_died, errno: :unknown, code: code}
  end

  def from_agent(code, stage) when is_integer(code) and is_atom(stage) do
    %__MODULE__{stage: stage, errno: Map.get(@posix, code, :unknown), code: code}
  end

  @impl Exception
  def message(%__MODULE__{stage: :agent_died, code: code}) do
    "process agent died without reporting a terminal status (exit code #{code})"
  end

  def message(%__MODULE__{stage: stage, errno: :unknown, code: code}) do
    "process #{stage} failed: errno #{code}"
  end

  def message(%__MODULE__{stage: stage, errno: errno, code: code}) do
    "process #{stage} failed: #{errno} (errno #{code})"
  end
end
