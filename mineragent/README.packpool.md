# Linux standard Stratum compatibility

The default `stratum_protocol` remains `viabtc_agent`. For a standard Stratum
upstream such as PackPool, set the runtime Linux config to:

```json
{
  "stratum_protocol": "standard_stratum",
  "stratum_host": "btc.pecpool.cc",
  "stratum_port": 8443,
  "stratum_user": "POOL_ACCOUNT",
  "stratum_password": "x"
}
```

In this mode the upstream `mining.subscribe` response supplies the
`extranonce2` size and the Agent uses standard `mining.notify` and
`mining.submit` frames. Credentials belong only in runtime config and are not
committed here. This Linux path is experimental until multi-miner extranonce
allocation and upstream submit-result correlation are verified.
