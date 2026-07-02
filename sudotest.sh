#!/bin/sh
# Run the test suite as root, including the :integration tests (which need
# CAP_NET_ADMIN and iproute2). Extra arguments are passed through to
# `mix test`, e.g. ./sudotest.sh test/linx/netlink/rtnl/integration_test.exs
#
# Root's job is scoped to *executing* the suite: everything is fetched and
# compiled as the invoking user first, so `deps/` and `_build/` are never
# built by root — and any artifacts root does leave behind (test manifests,
# tmp files) are chown'd back afterwards, so the next plain `mix compile`
# isn't broken by root-owned files.
#
# Toolchain notes: asdf *shims* fail under sudo unless the whole asdf env
# survives, so resolve the real mix/erl binaries up front. MIX_HOME is
# forwarded because the Hex archive lives there and provides the SCM for
# hex deps — without it, root can't even load the project.
set -e

export MIX_ENV=test
mix deps.get
mix compile

MIX_BIN="$(command -v mix)"
SUDO_PATH="$PATH"
if command -v asdf >/dev/null 2>&1; then
	MIX_BIN="$(asdf which mix)"
	SUDO_PATH="$(dirname "$MIX_BIN"):$(dirname "$(asdf which erl)"):$PATH"
fi

MIX_HOME_RESOLVED="${MIX_HOME:-$("$MIX_BIN" run --no-mix-exs -e 'IO.puts(Mix.Utils.mix_home())' | tail -n 1)}"

status=0
sudo --preserve-env=HOME,MIX_ENV \
	env "PATH=$SUDO_PATH" "MIX_HOME=$MIX_HOME_RESOLVED" \
	"$MIX_BIN" test --include integration "$@" || status=$?

sudo chown -R "$(id -u):$(id -g)" _build deps 2>/dev/null || true
exit $status
