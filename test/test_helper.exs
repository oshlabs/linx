# Tests tagged :integration need CAP_NET_ADMIN and/or network namespaces;
# they are excluded by default. Run them with `mix test --include integration`.
ExUnit.start(exclude: [:integration])
