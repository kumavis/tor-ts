# HTTP Proxy Server over Tor

This example demonstrates how to create an HTTP proxy server that routes traffic through Tor.

## How it works

1. Establishes a Tor circuit
2. Creates an HTTP proxy server using `http-proxy`
3. Routes incoming HTTP requests through the Tor circuit

## Usage

Run the example/test:

```bash
yarn test:live
```

## Code

See `index.spec.ts` for the full example:

```typescript
import http from 'http';
import httpProxy from 'http-proxy';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

// Establish a Tor circuit
const circuit = await connectRandomCircuitWithSafeBootstrap();

// Create a proxy server
const proxy = httpProxy.createProxyServer();

const server = http.createServer((req, res) => {
  const target = req.url;
  const agent = getTorAgentForUrl(circuit, target);
  proxy.web(req, res, { target, agent });
});

server.listen(1234, () => {
  console.log('Proxy server listening on port 1234');
});

// Use with: curl -x localhost:1234 http://example.com
```
