defmodule Linx.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/oshlabs/linx"

  def project do
    [
      app: :linx,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      # Custom compilers for the project's native code, run as part of
      # `mix compile`:
      #   * :netlink_nif    -- the netlink_socket NIF (Linx.Netlink)
      #   * :linx_process   -- the linx_process Port binary (Linx.Process)
      #   * :linx_tty       -- the linx_tty NIF (Linx.Tty)
      #   * :linx_mount     -- the linx_mount NIF (Linx.Mount)
      # See lib/mix/tasks/compile.*.ex.
      compilers: Mix.compilers() ++ [:netlink_nif, :linx_process, :linx_tty, :linx_mount],
      deps: deps(),
      name: "Linx",
      description: "Linux kernel interfaces for Elixir — netlink, and more.",
      source_url: @source_url,
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      main: "readme",
      # Generated HTML lands under _build/, alongside other build artefacts,
      # so the top-level `doc/` slot stays free for the `docs/` source tree.
      output: "_build/docs",
      extras: [
        "README.md",
        "AGENTS.md",
        "docs/netlink/EXAMPLES.md",
        "docs/netlink/PLAN.md",
        "docs/netlink/COVERAGE.md",
        "docs/netlink/REFERENCES.md",
        "docs/process/EXAMPLES.md",
        "docs/process/PLAN.md",
        "docs/process/COVERAGE.md",
        "docs/process/REFERENCES.md",
        "docs/tty/EXAMPLES.md",
        "docs/tty/PLAN.md",
        "docs/tty/COVERAGE.md",
        "docs/tty/REFERENCES.md",
        "docs/cgroup/EXAMPLES.md",
        "docs/cgroup/PLAN.md",
        "docs/cgroup/COVERAGE.md",
        "docs/cgroup/REFERENCES.md",
        "docs/mount/EXAMPLES.md",
        "docs/mount/PLAN.md",
        "docs/mount/COVERAGE.md",
        "docs/mount/REFERENCES.md",
        "docs/user/EXAMPLES.md",
        "docs/user/PLAN.md",
        "docs/user/COVERAGE.md",
        "docs/user/REFERENCES.md",
        "docs/capabilities/EXAMPLES.md",
        "docs/capabilities/PLAN.md",
        "docs/capabilities/COVERAGE.md",
        "docs/capabilities/REFERENCES.md"
      ],
      source_ref: "v#{@version}",
      groups_for_extras: [
        "Netlink — guides": ["docs/netlink/EXAMPLES.md"],
        "Netlink — design": [
          "docs/netlink/PLAN.md",
          "docs/netlink/COVERAGE.md",
          "docs/netlink/REFERENCES.md"
        ],
        "Process — guides": ["docs/process/EXAMPLES.md"],
        "Process — design": [
          "docs/process/PLAN.md",
          "docs/process/COVERAGE.md",
          "docs/process/REFERENCES.md"
        ],
        "Tty — guides": ["docs/tty/EXAMPLES.md"],
        "Tty — design": [
          "docs/tty/PLAN.md",
          "docs/tty/COVERAGE.md",
          "docs/tty/REFERENCES.md"
        ],
        "Cgroup — guides": ["docs/cgroup/EXAMPLES.md"],
        "Cgroup — design": [
          "docs/cgroup/PLAN.md",
          "docs/cgroup/COVERAGE.md",
          "docs/cgroup/REFERENCES.md"
        ],
        "Mount — guides": ["docs/mount/EXAMPLES.md"],
        "Mount — design": [
          "docs/mount/PLAN.md",
          "docs/mount/COVERAGE.md",
          "docs/mount/REFERENCES.md"
        ],
        "User — guides": ["docs/user/EXAMPLES.md"],
        "User — design": [
          "docs/user/PLAN.md",
          "docs/user/COVERAGE.md",
          "docs/user/REFERENCES.md"
        ],
        "Capabilities — guides": ["docs/capabilities/EXAMPLES.md"],
        "Capabilities — design": [
          "docs/capabilities/PLAN.md",
          "docs/capabilities/COVERAGE.md",
          "docs/capabilities/REFERENCES.md"
        ],
        "Repo-wide": ["AGENTS.md"]
      ],
      groups_for_modules: [
        "Public types": [
          Linx.IP,
          Linx.IP.Subnet,
          Linx.MAC
        ],
        Process: [
          Linx.Process,
          Linx.Process.Info
        ],
        Tty: [
          Linx.Tty,
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
