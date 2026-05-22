#!/bin/sh
# Run the test suite as root, including the :integration tests (which need
# CAP_NET_ADMIN and iproute2). Extra arguments are passed through to
# `mix test`, e.g. ./sudotest.sh test/linx/netlink/rtnl/integration_test.exs
sudo --preserve-env=PATH,HOME,ASDF_DIR env "PATH=$PATH" "$(which mix)" test --include integration "$@"
