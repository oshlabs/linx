defmodule LinxTest do
  use ExUnit.Case
  doctest Linx

  test "greets the world" do
    assert Linx.hello() == :world
  end
end
