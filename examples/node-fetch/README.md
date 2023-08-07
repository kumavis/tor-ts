### node-fetch

Node fetch over tor. Uses `node-fetch` package to enable use of the tor `http.Agent`.


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