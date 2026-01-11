# Tor Network Visualizer

A force-directed graph visualization of the Tor relay network. This interactive webapp allows you to explore the Tor network topology, visualize circuits, and examine individual relay nodes.

## Features

### Network Visualization

- **Force-directed graph** using D3.js for intuitive network layout
- **Node type differentiation** with distinct colors and sizes:
  - 🟣 **Authority** nodes (directory authorities)
  - 🟢 **Guard** nodes (entry relays)
  - 🟠 **Exit** nodes (exit relays)
  - 🟡 **Guard + Exit** nodes (dual-purpose)
  - 🔵 **Relay** nodes (middle relays)
  - 🩵 **Snowflake** nodes (pluggable transport support)
- **Zoom and pan** for exploring large networks
- **Drag nodes** to manually position them

### Circuit Visualization

- Create random circuits with configurable hop count (2-5 hops)
- Animated circuit paths showing data flow direction
- Color-coded circuits for easy identification
- Circuit list panel with one-click removal

### Node Information

- Click any node to view detailed information:
  - Nickname and node type
  - IP address and ports
  - Fingerprint (RSA identity)
  - Tor version
  - Bandwidth capacity
  - Service flags (Guard, Exit, Stable, Fast, HSDir, etc.)
  - Snowflake transport support

### Controls

- **Data source**: Demo data (offline) or live Onionoo API
- **Display limit**: Control number of nodes shown (20-500)
- **Flag filters**: Show/hide nodes by their flags
- **Graph physics**: Adjust link distance and charge strength
- **Toggle labels**: Show/hide node nicknames

### Status & Logging

- Real-time connection status indicator
- Activity log for tracking operations
- Network statistics (total nodes, guards, exits, circuits)

## Getting Started

### Prerequisites

- Node.js 18+
- Yarn (the workspace uses Yarn 4)

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

1. **Load Network Data**: Click "Load Network" to fetch relay data
   - **Demo Data**: Generates realistic offline sample data
   - **Onionoo API**: Fetches live data from Tor Project's API

2. **Explore the Graph**:
   - Zoom with scroll wheel
   - Pan by dragging the background
   - Drag nodes to reposition them

3. **Examine Nodes**: Click any node to see its details in the info panel

4. **Create Circuits**:
   - Select circuit length (2-5 hops)
   - Click "Create Random Circuit"
   - Watch the animated path appear

5. **Filter Nodes**: Use checkbox filters to show specific node types

6. **Adjust Physics**: Use sliders to tune the graph layout

## Data Sources

### Demo Mode

Generates synthetic network data for offline exploration. Includes realistic distribution of:

- Directory authorities
- Guard nodes
- Exit nodes
- Middle relays
- Snowflake-enabled nodes

### Onionoo API

Fetches live data from the [Onionoo service](https://metrics.torproject.org/onionoo.html), the official Tor network status protocol. Data includes:

- Running relays sorted by consensus weight
- All service flags
- Bandwidth measurements
- Version information

## Technical Details

### Stack

- **Vite** - Build tool and dev server
- **TypeScript** - Type-safe JavaScript
- **D3.js** - Force-directed graph visualization
- **CSS** - Custom dark theme styling

### Architecture

The app uses a single-page architecture with:

- Reactive state management
- D3 force simulation for graph physics
- Event-driven UI updates
- Modular code organization

## Screenshots

The visualizer displays:

- A central graph area with the network topology
- Left sidebar with network and circuit controls
- Right sidebar with node info and activity log
- Bottom stats bar with network statistics
- Legend showing node type colors

## License

MIT - See the main repository LICENSE file.
