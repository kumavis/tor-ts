### node-fetch

Node fetch over tor. Uses `node-fetch` package to enable use of the tor `http.Agent`.


### requirements

this currently expects a chutney testnet running the `basic-min` network in the background

### usage

start the client

```bash
yarn start
```

compare ip address with curl

```bash
curl 'https://api.ipify.org'
```