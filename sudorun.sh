#!/bin/sh
# Start an `iex -S mix` session as root — needed to exercise the privileged
# netlink operations (creating links, entering network namespaces).
#
# Compile as the invoking user first so root only executes (root-built
# artifacts in `_build/` break later non-root compiles); chown back whatever
# root leaves behind on exit. asdf *shims* fail under sudo unless the whole
# asdf env survives, so resolve the real iex/erl binaries up front. MIX_HOME
# is forwarded because the Hex archive lives there and provides the SCM for
# hex deps.
set -e

mix deps.get
mix compile

IEX_BIN="$(command -v iex)"
MIX_BIN="$(command -v mix)"
SUDO_PATH="$PATH"
if command -v asdf >/dev/null 2>&1; then
	IEX_BIN="$(asdf which iex)"
	MIX_BIN="$(asdf which mix)"
	SUDO_PATH="$(dirname "$IEX_BIN"):$(dirname "$(asdf which erl)"):$PATH"
fi

MIX_HOME_RESOLVED="${MIX_HOME:-$("$MIX_BIN" run --no-mix-exs -e 'IO.puts(Mix.Utils.mix_home())' | tail -n 1)}"

status=0
sudo --preserve-env=HOME \
	env "PATH=$SUDO_PATH" "MIX_HOME=$MIX_HOME_RESOLVED" \
	"$IEX_BIN" -S mix || status=$?

sudo chown -R "$(id -u):$(id -g)" _build deps 2>/dev/null || true
exit $status
