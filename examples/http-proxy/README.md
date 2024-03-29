### http-proxy

Node Proxy Server for http/https/websockets over tor.

For http/ws proxying, uses `http-proxy` with a Node HTTP Agent.
For https proxying, uses simple stream forwarding via `proxyCircuitStreamDuplex` / `circuitStreamToNodeDuplex`

This demo establishes a single tor circuit and on it opens up new a tor stream for each request.

### usage

start the proxy server (on port :1234)

```bash
yarn start
```

in another window, look up ip via tor proxied curl request + normal curl

```bash
URL=https://api.ipify.org \
&& echo "normal:" \
&& curl "$URL" \
&& echo "\ntor:" \
&& curl -x localhost:1234 "$URL"
```

plumbing for http and https are different -- try http as well

```bash
URL=http://api.ipify.org \
&& echo "normal:" \
&& curl "$URL" \
&& echo "\ntor:" \
&& curl -x localhost:1234 "$URL"
```
