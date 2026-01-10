# tor

TypeScript implementation of the Tor protocol.

## Installation

```bash
yarn add tor
```

## Quick Start

```typescript
import { mainnet } from 'tor';

// Safe bootstrap using hardcoded fallback directories
const circuit = await mainnet.connectRandomCircuitWithSafeBootstrap();

// Use the circuit...
const stream = await circuit.open('example.com:80');
```

## Fallback Directories

This package includes hardcoded fallback directories from the Tor Project for safe bootstrap. These are updated periodically from:

https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/fallback_dirs.inc

### Updating Fallback Directories

```bash
yarn update:fallback-dirs
```

This fetches the latest `fallback_dirs.inc` from the Tor Project and regenerates `src/fallback-dirs.json`.

### Using Fallback Data

```typescript
import { 
  getRandomFallbackDirectory,
  fallbackToPeerInfo,
  FALLBACK_DIRS_DATA,
} from 'tor';

// Get metadata
console.log(`${FALLBACK_DIRS_DATA.entries.length} fallbacks`);
console.log(`Version: ${FALLBACK_DIRS_DATA.version}`);

// Use for bootstrap
const fallback = getRandomFallbackDirectory();
const peerInfo = fallbackToPeerInfo(fallback);
```

## Development

Requires Node.js 18+ with corepack enabled:

```bash
corepack enable
yarn install
yarn test
```
