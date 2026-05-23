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
      # The :netlink_nif compiler builds the netlink_socket NIF as part of
      # `mix compile`. See lib/mix/tasks/compile.netlink_nif.ex.
      compilers: Mix.compilers() ++ [:netlink_nif],
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
      extras: ["README.md", "EXAMPLES.md", "PLAN.md", "COVERAGE.md", "AGENTS.md"],
      source_ref: "v#{@version}",
      groups_for_extras: [
        Guides: ["EXAMPLES.md"],
        Design: ["PLAN.md", "COVERAGE.md", "AGENTS.md"]
      ],
      groups_for_modules: [
        "Public types": [
          Linx.IP,
          Linx.IP.Subnet,
          Linx.MAC
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
          Linx.Netlink.Rtnl.Rule
        ]
      ]
    ]
  end
end
