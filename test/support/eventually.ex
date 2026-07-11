defmodule Linx.TestSupport.Eventually do
  @moduledoc false
  # Bounded polling for integration assertions on asynchronous kernel
  # state. Shared by the reconcile test suites; import it rather than
  # copying the loop into another test module.

  @doc "Polls `fun` until it returns truthy or the timeout elapses."
  def eventually(fun, timeout \\ 2_000, step \\ 25) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_eventually(fun, deadline, step)
  end

  defp do_eventually(fun, deadline, step) do
    cond do
      fun.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(step)
        do_eventually(fun, deadline, step)
    end
  end
end
