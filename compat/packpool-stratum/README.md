# PackPool Stratum compatibility mode

The official MinerAgent binary speaks ViaBTC's private `agent.*` upstream
protocol. PackPool exposes ordinary Stratum (`mining.subscribe`,
`mining.authorize`, `mining.notify`, and `mining.submit`), so changing only the
upstream host is not sufficient.

This small compatibility adapter is intentionally separate from the official
Agent path. It relays standard Stratum line frames and keeps the existing
ViaBTC Agent configuration untouched. It is a compatibility/test component,
not yet the high-scale fan-out Agent implementation.

Example:

```text
go run ./compat/packpool-stratum --listen 127.0.0.1:2235 --upstream btc.pecpool.cc:8443
```

The adapter does not contain credentials. Miner authorization is forwarded to
the selected upstream. Use TLS only when the upstream explicitly documents a
TLS Stratum endpoint.
