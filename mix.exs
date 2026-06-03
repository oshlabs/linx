defmodule Linx.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/oshlabs/linx"

  def project do
    [
      app: :linx,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      # Custom compilers for the project's native code, run as part of
      # `mix compile`:
      #   * :netlink_nif    -- the netlink_socket NIF (Linx.Netlink)
      #   * :linx_process   -- the linx_process Port binary (Linx.Process)
      #   * :linx_tty       -- the linx_tty NIF (Linx.Tty)
      #   * :linx_mount     -- the linx_mount NIF (Linx.Mount)
      #   * :linx_sysctl    -- the linx_sysctl NIF (Linx.Sysctl)
      # See lib/mix/tasks/compile.*.ex.
      compilers:
        Mix.compilers() ++
          [:netlink_nif, :linx_process, :linx_tty, :linx_mount, :linx_sysctl],
      deps: deps(),
      name: "Linx",
      description:
        "Linux kernel interface primitives for Elixir: netlink/rtnetlink/nf_tables, " <>
          "process & namespace lifecycle, PTY, cgroup v2, mounts, user namespaces, " <>
          "capabilities, seccomp, and sysctl.",
      source_url: @source_url,
      package: package(),
      docs: docs()
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      # Ship the C sources (c_src) so the NIF/Port custom compilers can build
      # them on the consumer's machine. priv/ artifacts are built per-machine
      # and never shipped; the docs/ extras are dev-time `mix docs` material,
      # omitted to keep the package lean.
      files: ~w(lib c_src mix.exs README.md LICENSE),
      maintainers: ["Leon de Rooij"]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:stream_data, "~> 1.0", only: :test, runtime: false}
    ]
  end

  # Injects mermaid.js so ```mermaid code blocks in the docs render as diagrams.
  defp mermaid_script(:html) do
    """
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
    <script>
      document.addEventListener("DOMContentLoaded", function () {
        mermaid.initialize({startOnLoad: false});
        let id = 0;
        for (const code of document.querySelectorAll("pre code.mermaid")) {
          const pre = code.parentElement;
          const graph = code.textContent;
          mermaid.render("mermaid-graph-" + id++, graph).then(({svg, bindFunctions}) => {
            const div = document.createElement("div");
            div.className = "mermaid";
            div.innerHTML = svg;
            if (bindFunctions) bindFunctions(div);
            pre.replaceWith(div);
          });
        }
      });
    </script>
    """
  end

  defp mermaid_script(_), do: ""

  defp docs do
    [
      main: "readme",
      # Generated HTML lands under _build/, alongside other build artefacts,
      # so the top-level `doc/` slot stays free for the `docs/` source tree.
      output: "_build/docs",
      # Render ```mermaid fenced blocks as diagrams (GitHub does this natively;
      # ex_doc needs this script injected).
      before_closing_body_tag: &mermaid_script/1,
      extras: [
        "README.md",
        "docs/netlink/EXAMPLES.md",
        "docs/netlink/REFERENCES.md",
        {"docs/process/README.md", filename: "process-overview"},
        "docs/process/EXAMPLES.md",
        "docs/process/REFERENCES.md",
        "docs/tty/EXAMPLES.md",
        "docs/tty/REFERENCES.md",
        "docs/cgroup/EXAMPLES.md",
        "docs/cgroup/REFERENCES.md",
        "docs/mount/EXAMPLES.md",
        "docs/mount/REFERENCES.md",
        "docs/user/EXAMPLES.md",
        "docs/user/REFERENCES.md",
        "docs/capabilities/EXAMPLES.md",
        "docs/capabilities/REFERENCES.md",
        "docs/seccomp/EXAMPLES.md",
        "docs/seccomp/REFERENCES.md",
        "docs/sysctl/EXAMPLES.md",
        "docs/sysctl/REFERENCES.md",
        "docs/netfilter/EXAMPLES.md",
        "docs/netfilter/DESIGN.md",
        "docs/netfilter/REFERENCES.md",
        "docs/reconcile/EXAMPLES.md",
        {:LICENSE, [title: "License"]}
      ],
      source_ref: "v#{@version}",
      # Per-subsystem pages: EXAMPLES.md (recipes) + REFERENCES.md
      # (citations). The retired PLAN.md/COVERAGE.md design docs moved
      # into the moduledocs; Netfilter keeps a forward-looking DESIGN.md.
      groups_for_extras: [
        Netlink: ["docs/netlink/EXAMPLES.md", "docs/netlink/REFERENCES.md"],
        Process: [
          "docs/process/README.md",
          "docs/process/EXAMPLES.md",
          "docs/process/REFERENCES.md"
        ],
        Tty: ["docs/tty/EXAMPLES.md", "docs/tty/REFERENCES.md"],
        Cgroup: ["docs/cgroup/EXAMPLES.md", "docs/cgroup/REFERENCES.md"],
        Mount: ["docs/mount/EXAMPLES.md", "docs/mount/REFERENCES.md"],
        User: ["docs/user/EXAMPLES.md", "docs/user/REFERENCES.md"],
        Capabilities: ["docs/capabilities/EXAMPLES.md", "docs/capabilities/REFERENCES.md"],
        Seccomp: ["docs/seccomp/EXAMPLES.md", "docs/seccomp/REFERENCES.md"],
        Sysctl: ["docs/sysctl/EXAMPLES.md", "docs/sysctl/REFERENCES.md"],
        Netfilter: [
          "docs/netfilter/EXAMPLES.md",
          "docs/netfilter/DESIGN.md",
          "docs/netfilter/REFERENCES.md"
        ],
        Reconcile: ["docs/reconcile/EXAMPLES.md"]
      ],
      groups_for_modules: [
        "Public types": [
          Linx.IP,
          Linx.IP.Subnet,
          Linx.MAC
        ],
        Process: [
          Linx.Process,
          Linx.Process.Error,
          Linx.Process.Info
        ],
        Tty: [
          Linx.Tty,
          Linx.Tty.Error,
          Linx.Tty.Saved,
          Linx.Tty.WindowSize,
          Linx.Tty.Native
        ],
        Cgroup: [
          Linx.Cgroup,
          Linx.Cgroup.Error,
          Linx.Cgroup.Stats
        ],
        Mount: [
          Linx.Mount,
          Linx.Mount.Entry,
          Linx.Mount.Error,
          Linx.Mount.Native
        ],
        User: [
          Linx.User,
          Linx.User.Error,
          Linx.User.Map
        ],
        Capabilities: [
          Linx.Capabilities,
          Linx.Capabilities.Error,
          Linx.Capabilities.State
        ],
        Seccomp: [
          Linx.Seccomp,
          Linx.Seccomp.Builder,
          Linx.Seccomp.Error,
          Linx.Seccomp.Filter
        ],
        Sysctl: [
          Linx.Sysctl,
          Linx.Sysctl.Entry,
          Linx.Sysctl.Error,
          Linx.Sysctl.Native
        ],
        Netfilter: [
          Linx.Netfilter,
          Linx.Netfilter.Error,
          Linx.Netfilter.Ruleset,
          Linx.Netfilter.Table,
          Linx.Netfilter.Chain,
          Linx.Netfilter.Rule,
          Linx.Netfilter.Expr,
          Linx.Netfilter.Verdict,
          Linx.Netfilter.Set,
          Linx.Netfilter.Map,
          Linx.Netfilter.Vmap,
          Linx.Netfilter.Object,
          Linx.Netfilter.Flowtable,
          Linx.Netfilter.Patch,
          Linx.Netfilter.Diff,
          Linx.Netfilter.Event,
          Linx.Netfilter.Monitor,
          Linx.Netfilter.Log,
          Linx.Netfilter.Log.Event,
          Linx.Netfilter.Encoder,
          Linx.Netfilter.Decoder,
          Linx.Netfilter.Wire
        ],
        "Netfilter — ~NFT sigil": [
          Linx.NFT,
          Linx.NFT.ParseError,
          Linx.NFT.Tokenizer,
          Linx.NFT.Parser,
          Linx.NFT.Compiler,
          Linx.NFT.RuntimeCompiler,
          Linx.NFT.Runtime,
          Linx.NFT.Formatter
        ],
        "Netlink core": [
          Linx.Netlink,
          Linx.Netlink.Socket,
          Linx.Netlink.Socket.Native,
          Linx.Netlink.Attr,
          Linx.Netlink.Message,
          Linx.Netlink.Request,
          Linx.Netlink.Constants,
          Linx.Netlink.Codec,
          Linx.Netlink.Error
        ],
        nfnetlink: [
          Linx.Netlink.Nfnl,
          Linx.Netlink.Nfnl.Codec
        ],
        rtnetlink: [
          Linx.Netlink.Rtnl,
          Linx.Netlink.Rtnl.Link,
          Linx.Netlink.Rtnl.LinkInfo,
          Linx.Netlink.Rtnl.LinkInfo.Macvlan,
          Linx.Netlink.Rtnl.LinkInfo.Ipvlan,
          Linx.Netlink.Rtnl.LinkInfo.Vlan,
          Linx.Netlink.Rtnl.LinkInfo.Veth,
          Linx.Netlink.Rtnl.Address,
          Linx.Netlink.Rtnl.Route,
          Linx.Netlink.Rtnl.Neighbour,
          Linx.Netlink.Rtnl.Rule,
          Linx.Netlink.Rtnl.Stats,
          Linx.Netlink.Rtnl.Stats.Link64
        ]
      ]
    ]
  end
end
