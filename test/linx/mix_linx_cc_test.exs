defmodule Mix.Linx.CCTest do
  use ExUnit.Case, async: true

  test "CFLAGS parsing preserves quoted arguments" do
    assert Mix.Linx.CC.split_flags(~s(-DNAME="hello world" --sysroot "/opt/sdk root" -O3)) == [
             "-DNAME=hello world",
             "--sysroot",
             "/opt/sdk root",
             "-O3"
           ]
  end

  test "CFLAGS parsing honors escaped whitespace" do
    assert Mix.Linx.CC.split_flags(~S(-I/opt/my\ headers -DMODE=debug)) == [
             "-I/opt/my headers",
             "-DMODE=debug"
           ]
  end

  test "an unbalanced quote fails with an error that names CFLAGS" do
    assert_raise Mix.Error, ~r/CFLAGS/, fn ->
      Mix.Linx.CC.split_flags(~s(-DVENDOR=O'Brien -O2))
    end
  end
end
