#!/bin/sh
# Start an `iex -S mix` session as root — needed to exercise the privileged
# netlink operations (creating links, entering network namespaces). Preserves
# the asdf-managed Elixir toolchain across sudo.
sudo --preserve-env=PATH,HOME,ASDF_DIR env "PATH=$PATH" "$(which iex)" -S mix
