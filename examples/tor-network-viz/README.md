# Tor Network Visualizer

A real-time force-directed graph visualization of the Tor relay network with **actual Tor connectivity** via Snowflake transport. This is not a simulation - it connects to the real Tor network!

## Features

### Real Tor Connectivity

- **Snowflake Transport**: Connects to Tor via WebSocket-based Snowflake bridge
- **Live Consensus**: Downloads the actual network consensus over an encrypted Tor circuit
- **Safe Bootstrap**: All directory lookups happen over encrypted circuits (RELAY_BEGIN_DIR)
- **Real Circuits**: Build actual multi-hop encrypted circuits through the Tor network

### Network Visualization

- **Force-directed graph** using D3.js displaying real relay data
- **Node type differentiation** with distinct colors and sizes:
  - 🟣 **Authority** nodes (directory authorities)
  - 🟢 **Guard** nodes (entry relays)
  - 🟠 **Exit** nodes (exit relays)
  - 🟡 **Guard + Exit** nodes (dual-purpose)
  - 🔵 **Relay** nodes (middle relays)
- **Zoom and pan** for exploring large networks
- **Drag nodes** to manually position them

### Manual Circuit Construction

- **Click nodes** to view detailed information
- **Shift+click or right-click** to add nodes to your circuit path
- Build circuits with your **exact chosen path**
- Or create **random circuits** following Tor best practices (Guard → Middle → Exit)
- Animated circuit paths showing the connection flow
- Multiple simultaneous circuits supported

### Node Information

- Real data from the Tor network consensus:
  - Nickname and fingerprint
  - IP address and ports (OR, Dir)
  - Tor version
  - Bandwidth capacity
  - All service flags (Guard, Exit, Stable, Fast, HSDir, etc.)

### Controls

- **Display limit**: Control number of nodes shown (20-500)
- **Flag filters**: Show/hide nodes by their flags
- **Graph physics**: Adjust link distance and charge strength
- **Toggle labels**: Show/hide node nicknames

## How It Works

### Bootstrap Process

1. **Snowflake Connection**: Establishes WebSocket connection to Snowflake relay
2. **TLS Handshake**: Negotiates TLS with the relay (identity verified via Tor protocol)
3. **Bootstrap Circuit**: Creates 1-hop circuit using CREATE_FAST (no onion key needed)
4. **Consensus Download**: Fetches microdesc consensus over encrypted circuit
5. **Ready**: Now you can explore the network and build circuits

### Building Circuits

When you build a circuit:

1. **Entry Node**: Always the Snowflake relay you're connected through
2. **Additional Hops**: Nodes you select (or random selection)
3. **Descriptor Lookup**: Each relay's onion key is fetched over the bootstrap circuit
4. **EXTEND2 Cells**: Circuit is extended hop-by-hop with ntor handshakes
5. **Connected**: Full end-to-end encrypted path established

## Getting Started

### Prerequisites

- Node.js 18+
- Yarn (the workspace uses Yarn 4)
- A browser that supports WebSocket and WebRTC (for Snowflake)

### Installation

From the workspace root:

```bash
# Install all dependencies
yarn install

# Navigate to this example
cd examples/tor-network-viz

# Start development server
yarn dev
```

The app will open at http://localhost:3001

### Building for Production

```bash
yarn build
yarn preview
```

## Usage

### Connecting to Tor

1. Click **"Connect to Tor"**
2. Wait for Snowflake connection (may take 10-30 seconds)
3. Bootstrap circuit is automatically established
4. Network consensus is downloaded and displayed

### Exploring the Network

- **Zoom**: Scroll wheel
- **Pan**: Drag the background
- **Move nodes**: Drag individual nodes
- **View details**: Click any node

### Building Circuits

#### Random Circuit

1. Select circuit length (2-5 hops)
2. Click **"Create Random Circuit"**
3. Watch the circuit build in the log
4. Animated path appears on graph

#### Manual Circuit

1. **Shift+click** or **right-click** nodes to add to path
2. Nodes show their position number in the circuit
3. Review the path preview in the Circuit Controls panel
4. Click **"Build"** to create the circuit

### Circuit Status

- 🟢 **connected**: Circuit is active and usable
- 🟡 **building**: Circuit creation in progress
- 🔴 **failed**: Circuit creation failed (see log for details)

## Technical Details

### Stack

- **Vite** - Build tool and dev server
- **TypeScript** - Type-safe implementation
- **D3.js** - Force-directed graph visualization
- **browser package** - Tor connectivity via Snowflake
- **tor package** - Core Tor protocol implementation

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Browser                           │
├─────────────────────────────────────────────────────┤
│  TorClient                                           │
│  ├── SnowflakeBrowserChannel (WebSocket + TLS)      │
│  ├── Bootstrap Circuit (1-hop, CREATE_FAST)         │
│  ├── DirectoryClient (consensus over circuit)       │
│  └── User Circuits (multi-hop, ntor handshakes)     │
├─────────────────────────────────────────────────────┤
│  D3.js Visualization                                │
│  ├── Force simulation                               │
│  ├── Node/link rendering                            │
│  └── Circuit path animation                         │
└─────────────────────────────────────────────────────┘
```

### Security Notes

- **Not for production use**: This is educational/experimental
- **Signature verification disabled**: Browser lacks RSA crypto for consensus verification
- **Single entry point**: All circuits share the same Snowflake connection
- **Fingerprintable**: Browser Tor clients have distinct characteristics

## Troubleshooting

### "Connection failed"

- Snowflake bridges may be temporarily unavailable
- Try again after a few seconds
- Check browser console for detailed errors

### "No relays found in consensus"

- The consensus download may have been truncated
- Reconnect to try again

### Circuit building fails

- Some relays may be offline or unreachable
- The relay's descriptor may not be available
- Try building a circuit with different nodes

## License

MIT - See the main repository LICENSE file.
