### Http-Proxy

Node Proxy for http/https/websockets.

For http/ws proxying, uses `http-proxy` with a custom `http.Agent` 

For https proxying, uses simple stream forwarding via `proxyCircuitStreamDuplex` / `circuitStreamToNodeDuplex`


### requirements

this currently expects a chutney testnet running the `basic-min` network in the background

### usage

start the proxy server (on port :1234)

```bash
yarn start
```

in another window, make a proxied curl request

```bash
curl -v -x http://localhost:1234 https://kumavis.me > /dev/null
```