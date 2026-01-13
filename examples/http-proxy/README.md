# HTTP Requests through Tor (Node.js http module)

This example demonstrates how to make HTTP requests through Tor using Node's native `http` module.

## How it works

1. Establishes a Tor circuit using the safe bootstrap method
2. Creates an HTTP agent that routes traffic through the circuit
3. Makes requests using Node's `http.get()` with the Tor agent

## Usage

Run the example/test:

```bash
yarn test:live
```

## Code

See `index.spec.ts` for the full example:

```typescript
import http from 'http';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

// Establish a Tor circuit
const circuit = await connectRandomCircuitWithSafeBootstrap();

// Create an agent for the target URL
const target = 'http://example.com';
const agent = getTorAgentForUrl(circuit, target);

// Make the request through Tor
http.get(target, { agent }, (res) => {
  res.on('data', (chunk) => console.log(chunk.toString()));
});

// Clean up when done
circuit.destroy();
```

## Building a Proxy Server

To build a full HTTP proxy server that routes all traffic through Tor, you can use the `http-proxy` package:

```typescript
import http from 'http';
import httpProxy from 'http-proxy';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

const circuit = await connectRandomCircuitWithSafeBootstrap();
const proxy = httpProxy.createProxyServer();

const server = http.createServer((req, res) => {
  const target = req.url;
  const agent = getTorAgentForUrl(circuit, target);
  proxy.web(req, res, { target, agent });
});

server.listen(1234);
// Use with: curl -x localhost:1234 http://example.com
```
