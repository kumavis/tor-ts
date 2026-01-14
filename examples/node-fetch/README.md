# node-fetch over Tor

This example demonstrates how to make HTTP requests through Tor using the `node-fetch` package.

## How it works

1. Establishes a Tor circuit using the safe bootstrap method
2. Creates an HTTP agent that routes traffic through the circuit
3. Makes fetch requests that go through Tor

## Usage

Run the example/test:

```bash
yarn test:live
```

## Code

See `index.spec.ts` for the full example:

```typescript
import fetch from 'node-fetch';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

// Establish a Tor circuit
const circuit = await connectRandomCircuitWithSafeBootstrap();

// Create an agent for the target URL
const target = 'http://example.com';
const agent = getTorAgentForUrl(circuit, target);

// Make the request through Tor
const response = await fetch(target, { agent });
const body = await response.text();

// Clean up
circuit.destroy();
```
