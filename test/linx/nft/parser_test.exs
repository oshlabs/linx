defmodule Linx.NFT.ParserTest do
  use ExUnit.Case, async: true

  alias Linx.NFT.{Parser, Tokenizer}

  defp parse!(source, opts \\ []) do
    {:ok, tokens} = Tokenizer.tokenize(source, opts)

    case Parser.parse(tokens, file: Keyword.get(opts, :file, "nofile"), source: source) do
      {:ok, items} -> items
      {:error, err} -> flunk("expected ok, got error: #{Exception.message(err)}")
    end
  end

  defp parse_err(source, opts \\ []) do
    {:ok, tokens} = Tokenizer.tokenize(source, opts)
    {:error, err} = Parser.parse(tokens, file: Keyword.get(opts, :file, "nofile"), source: source)
    err
  end

  describe "flush ruleset" do
    test "stand-alone flush ruleset directive" do
      assert [{:flush_ruleset, _meta}] = parse!("flush ruleset")
    end

    test "flush ruleset followed by a table definition" do
      src = """
      flush ruleset

      table inet t { chain c { } }
      """

      assert [{:flush_ruleset, _}, {:table, :inet, "t", _, _}] = parse!(src)
    end
  end

  describe "empty / whitespace" do
    test "empty source produces an empty AST" do
      assert parse!("") == []
      assert parse!("\n\n  \n") == []
    end
  end

  describe "tables" do
    test "empty table" do
      assert [{:table, :inet, "myapp", [], _meta}] = parse!("table inet myapp { }")
    end

    test "all families" do
      for fam <- ~w(ip ip6 inet arp bridge netdev)a do
        src = "table #{fam} t { }"
        assert [{:table, ^fam, "t", [], _}] = parse!(src)
      end
    end

    test "rejects unknown family" do
      err = parse_err("table foobar t { }")
      assert err.message =~ "expected table family"
      assert err.line == 1
      assert err.column == 7
    end

    test "table with comment" do
      assert [{:table, :inet, "t", [{:comment, "hello"}], _}] =
               parse!(~s/table inet t { comment "hello"\n }/)
    end

    test "missing `{` after name" do
      err = parse_err("table inet t")
      assert err.message =~ "expected `{` after table name"
    end

    test "missing `}` is reported" do
      err = parse_err("table inet t {\n  chain c { type filter hook input priority 0;")
      assert err.message =~ "expected" or err.message =~ "end of input"
    end
  end

  describe "chains — base headers" do
    test "type filter hook input priority 0" do
      src = "table inet t {\n  chain input {\n    type filter hook input priority 0\n  }\n}\n"

      assert [{:table, :inet, "t", [{:chain, "input", opts, [], _}], _}] = parse!(src)
      assert {:type, :filter} in opts
      assert {:hook, :input} in opts
      assert {:priority, {:integer, 0, _}} = List.keyfind(opts, :priority, 0)
    end

    test "negative integer priority" do
      src = "table inet t { chain c { type nat hook prerouting priority -150 } }"
      assert [{:table, _, _, [{:chain, _, opts, _, _}], _}] = parse!(src)
      assert {:priority, {:integer, -150, _}} = List.keyfind(opts, :priority, 0)
    end

    test "named priority alias with offset" do
      src = "table inet t { chain c { type filter hook input priority filter - 10 } }"
      assert [{:table, _, _, [{:chain, _, opts, _, _}], _}] = parse!(src)
      assert {:priority, {:alias, "filter", -10, _}} = List.keyfind(opts, :priority, 0)
    end

    test "policy directive" do
      src = "table inet t { chain c { type filter hook input priority 0; policy drop } }"
      assert [{:table, _, _, [{:chain, _, opts, _, _}], _}] = parse!(src)
      assert {:policy, :drop} in opts
    end
  end

  describe "rules — verdicts" do
    test "bare accept / drop / continue / return / queue" do
      for v <- ~w(accept drop continue return queue)a do
        src = "table inet t { chain c { #{v} } }"

        assert [
                 {:table, _, _,
                  [
                    {:chain, _, _, [{:rule, [{:verdict, ^v, _}], [], _}], _}
                  ], _}
               ] = parse!(src)
      end
    end

    test "jump and goto" do
      src = "table inet t { chain c { jump other_chain; goto other_chain } }"

      assert [{:table, _, _, [{:chain, _, _, rules, _}], _}] = parse!(src)

      assert [
               {:rule, [{:verdict, {:jump, "other_chain"}, _}], _, _},
               {:rule, [{:verdict, {:goto, "other_chain"}, _}], _, _}
             ] = rules
    end
  end

  describe "rules — simple matches" do
    test "tcp dport 22 accept" do
      src = "table inet t { chain c { tcp dport 22 accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :tcp, :dport, _}, :eq, {:integer, 22, _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "tcp dport != 22 drop" do
      src = "table inet t { chain c { tcp dport != 22 drop } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :tcp, :dport, _}, :neq, {:integer, 22, _}, _},
               {:verdict, :drop, _}
             ] = stmts
    end

    test "ip saddr CIDR drop" do
      src = "table inet t { chain c { ip saddr 10.0.0.0/8 drop } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :ip, :saddr, _}, :eq, {:address, :cidr_v4, "10.0.0.0/8", _},
                _},
               {:verdict, :drop, _}
             ] = stmts
    end

    test "tcp dport range" do
      src = "table inet t { chain c { tcp dport 8000-9000 accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :tcp, :dport, _}, :eq,
                {:range, {:integer, 8000, _}, {:integer, 9000, _}, _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "tcp dport inline set" do
      src = "table inet t { chain c { tcp dport { 22, 80, 443 } accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :tcp, :dport, _}, :eq,
                {:set_inline,
                 [
                   {:integer, 22, _},
                   {:integer, 80, _},
                   {:integer, 443, _}
                 ], _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "tcp dport @set_ref" do
      src = "table inet t { chain c { tcp dport @open_ports accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:payload, :tcp, :dport, _}, :eq, {:set_ref, "open_ports", _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "bare iifname shorthand (no `meta` prefix)" do
      src = ~s|table inet t { chain c { iifname "lo" accept } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:meta, :iifname, _}, :eq, {:string, "lo", _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "bare oifname shorthand" do
      src = ~s|table inet t { chain c { oifname "eth0" accept } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:meta, :oifname, _}, :eq, {:string, "eth0", _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "bare iifname with inline set" do
      src = ~s|table inet t { chain c { iifname { "eth0", "wg0" } accept } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:meta, :iifname, _}, :eq,
                {:set_inline, [{:string, "eth0", _}, {:string, "wg0", _}], _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "meta iif match" do
      src = ~s|table inet t { chain c { meta iif "eth0" accept } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:meta, :iif, _}, :eq, {:string, "eth0", _}, _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "ct state inline-set" do
      src = "table inet t { chain c { ct state { established, related } accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:match, {:ct, :state, _}, :eq,
                {:set_inline, [{:identifier, "established", _}, {:identifier, "related", _}], _},
                _},
               {:verdict, :accept, _}
             ] = stmts
    end
  end

  describe "rules — actions" do
    test "counter" do
      src = "table inet t { chain c { counter accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:counter, [], _},
               {:verdict, :accept, _}
             ] = stmts
    end

    test "log with prefix and group" do
      src = ~s|table inet t { chain c { log prefix "ssh-attempt" group 5000 accept } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:log, opts, _},
               {:verdict, :accept, _}
             ] = stmts

      assert opts[:prefix] == "ssh-attempt"
      assert opts[:group] == 5000
    end

    test "limit rate per second" do
      src = "table inet t { chain c { limit rate 10/second accept } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:limit, {:rate, 10, :second}, opts, _},
               {:verdict, :accept, _}
             ] = stmts

      assert opts[:over] == false
    end

    test "dnat to address" do
      src = "table inet t { chain c { dnat to 10.0.0.5 } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:nat, :dnat, {:address, :ipv4, "10.0.0.5", _}, [], _}
             ] = stmts
    end

    test "masquerade with flags" do
      src = "table inet t { chain c { masquerade random persistent } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:nat, :masquerade, nil, [:random, :persistent], _}
             ] = stmts
    end

    test "meta mark set" do
      src = "table inet t { chain c { meta mark set 0xdeadbeef } }"

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, _, _}], _}], _}] = parse!(src)

      assert [
               {:meta_set, :mark, {:integer, 0xDEAD_BEEF, _}, _}
             ] = stmts
    end
  end

  describe "rules — comments and tags" do
    test "rule-level comment" do
      src = ~s|table inet t { chain c { accept comment "ok" } }|

      assert [{:table, _, _, [{:chain, _, _, [{:rule, stmts, opts, _}], _}], _}] = parse!(src)

      assert [{:verdict, :accept, _}] = stmts
      assert opts == [{:comment, "ok"}]
    end
  end

  describe "named collections" do
    test "set with type and flags" do
      src = """
      table inet t {
        set blocklist {
          type ipv4_addr
          flags interval, timeout
          timeout 1h
        }
      }
      """

      assert [{:table, _, _, [{:set, "blocklist", opts, _}], _}] = parse!(src)
      assert opts[:type] == :ipv4_addr
      assert opts[:flags] == [:interval, :timeout]
      # :time tokens carry milliseconds (the kernel's set-timeout unit).
      assert {:time, 3_600_000, _} = opts[:timeout]
    end

    test "map with concatenated key" do
      src = """
      table inet t {
        map svc {
          type ipv4_addr . inet_service : verdict
        }
      }
      """

      assert [{:table, _, _, [{:map, "svc", opts, _}], _}] = parse!(src)
      assert opts[:type] == {:map_type, {:concat, [:ipv4_addr, :inet_service]}, :verdict}
    end

    test "elements list" do
      src = """
      table inet t {
        set blocklist {
          type ipv4_addr
          elements = { 10.0.0.1, 10.0.0.2 }
        }
      }
      """

      assert [{:table, _, _, [{:set, _, opts, _}], _}] = parse!(src)

      assert [
               {:address, :ipv4, "10.0.0.1", _},
               {:address, :ipv4, "10.0.0.2", _}
             ] = opts[:elements]
    end

    test "vmap with verdict elements" do
      src = """
      table inet t {
        vmap dispatch {
          type ipv4_addr : verdict
          elements = { 10.0.0.1 : jump web, 10.0.0.2 : drop }
        }
      }
      """

      assert [{:table, _, _, [{:vmap, "dispatch", opts, _}], _}] = parse!(src)

      assert [
               {:map_elem, {:address, :ipv4, "10.0.0.1", _}, {:verdict, {:jump, "web"}, _}, _},
               {:map_elem, {:address, :ipv4, "10.0.0.2", _}, {:verdict, :drop, _}, _}
             ] = opts[:elements]
    end
  end

  describe "error reporting" do
    test "unexpected token in chain body" do
      err = parse_err("table inet t { chain c { ! } }")
      assert err.message =~ "expected"
      assert is_integer(err.line) and err.line == 1
    end

    test "missing chain name" do
      err = parse_err("table inet t { chain { } }")
      assert err.message =~ "expected chain name"
    end
  end

  describe "realistic ruleset round-trip" do
    test "tokenize + parse the canonical Nerves-appliance shape" do
      src = """
      table inet appliance {
        chain input {
          type filter hook input priority 0
          policy drop

          ct state { established, related } accept
          tcp dport 22 log prefix "ssh-attempt" group 5000 accept
          ip saddr 10.0.0.0/8 accept
        }

        chain forward {
          type filter hook forward priority 0
          policy drop
        }
      }
      """

      assert [{:table, :inet, "appliance", body, _}] = parse!(src)
      assert length(body) == 2

      [{:chain, "input", input_opts, input_rules, _}, {:chain, "forward", forward_opts, _, _}] =
        body

      assert {:type, :filter} in input_opts
      assert {:hook, :input} in input_opts
      assert {:policy, :drop} in input_opts
      assert length(input_rules) == 3

      assert {:policy, :drop} in forward_opts
    end
  end
end
