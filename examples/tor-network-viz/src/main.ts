/**
 * Tor Network Visualizer
 *
 * A force-directed graph visualization of the Tor relay network.
 * Uses real Snowflake connections to explore the network and build circuits.
 */

import * as d3 from 'd3';
import {
  TorClient,
  type MicroDescNodeInfo,
  type ManagedCircuit,
  type ConnectionState,
} from './tor-client.ts';

// ============================================
// Types
// ============================================

interface GraphNode extends MicroDescNodeInfo {
  // D3 simulation properties
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
  index?: number;
  // Computed
  nodeType: NodeType;
}

interface GraphLink {
  source: GraphNode | string;
  target: GraphNode | string;
  isCircuit?: boolean;
  circuitId?: number;
}

type NodeType = 'guard' | 'exit' | 'guard-exit' | 'authority' | 'relay' | 'snowflake-entry';

// Circuit colors
const CIRCUIT_COLORS = [
  '#ec4899',
  '#8b5cf6',
  '#06b6d4',
  '#84cc16',
  '#f43f5e',
  '#f59e0b',
  '#10b981',
  '#6366f1',
];

// ============================================
// State
// ============================================

const torClient = new TorClient({
  onStateChange: handleStateChange,
  onLog: handleLog,
  onConsensusLoaded: handleConsensusLoaded,
  onCircuitUpdate: handleCircuitUpdate,
});

interface AppState {
  graphNodes: GraphNode[];
  selectedNodes: Set<string>; // fingerprints
  selectedForCircuit: GraphNode[];
  simulation: d3.Simulation<GraphNode, GraphLink> | null;
}

const state: AppState = {
  graphNodes: [],
  selectedNodes: new Set(),
  selectedForCircuit: [],
  simulation: null,
};

// ============================================
// DOM Elements
// ============================================

const elements = {
  // Status
  connectionStatus: document.getElementById('connection-status')!,

  // Controls
  dataSource: document.getElementById('data-source') as HTMLSelectElement,
  loadNetworkBtn: document.getElementById('load-network-btn') as HTMLButtonElement,
  nodeLimit: document.getElementById('node-limit') as HTMLInputElement,
  nodeLimitValue: document.getElementById('node-limit-value')!,

  // Filters
  filterGuard: document.getElementById('filter-guard') as HTMLInputElement,
  filterExit: document.getElementById('filter-exit') as HTMLInputElement,
  filterStable: document.getElementById('filter-stable') as HTMLInputElement,
  filterFast: document.getElementById('filter-fast') as HTMLInputElement,
  filterAuthority: document.getElementById('filter-authority') as HTMLInputElement,
  filterHsdir: document.getElementById('filter-hsdir') as HTMLInputElement,

  // Circuit controls
  circuitLength: document.getElementById('circuit-length') as HTMLSelectElement,
  createCircuitBtn: document.getElementById('create-circuit-btn') as HTMLButtonElement,
  clearCircuitsBtn: document.getElementById('clear-circuits-btn') as HTMLButtonElement,
  circuitList: document.getElementById('circuit-list')!,

  // Graph physics
  linkDistance: document.getElementById('link-distance') as HTMLInputElement,
  linkDistanceValue: document.getElementById('link-distance-value')!,
  chargeStrength: document.getElementById('charge-strength') as HTMLInputElement,
  chargeStrengthValue: document.getElementById('charge-strength-value')!,
  showLabels: document.getElementById('show-labels') as HTMLInputElement,

  // Stats
  statTotal: document.getElementById('stat-total')!,
  statGuards: document.getElementById('stat-guards')!,
  statExits: document.getElementById('stat-exits')!,
  statCircuits: document.getElementById('stat-circuits')!,

  // Node info
  nodeInfoContent: document.getElementById('node-info-content')!,

  // Log
  logContent: document.getElementById('log-content')!,
  clearLogBtn: document.getElementById('clear-log-btn')!,

  // Graph
  svg: d3.select('#network-graph'),

  // Tooltip
  tooltip: document.getElementById('tooltip')!,
};

// ============================================
// Event Handlers for TorClient
// ============================================

function handleStateChange(connectionState: ConnectionState, message: string): void {
  const dot = elements.connectionStatus.querySelector('.status-dot')!;
  const textEl = elements.connectionStatus.querySelector('.status-text')!;

  let dotClass = 'disconnected';
  if (connectionState === 'connected') dotClass = 'connected';
  else if (connectionState === 'error') dotClass = 'error';
  else if (connectionState !== 'disconnected') dotClass = 'connecting';

  dot.className = `status-dot ${dotClass}`;
  textEl.textContent = message;

  // Update button states
  const isConnected = connectionState === 'connected';
  elements.createCircuitBtn.disabled = !isConnected;
  elements.loadNetworkBtn.disabled =
    connectionState !== 'disconnected' &&
    connectionState !== 'error' &&
    connectionState !== 'connected';

  if (isConnected) {
    const btnText = elements.loadNetworkBtn.querySelector('.btn-text') as HTMLElement;
    btnText.textContent = 'Reconnect';
  }
}

function handleLog(message: string, level: 'info' | 'success' | 'error' | 'warning'): void {
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false });

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-message ${level}">${escapeHtml(message)}</span>
  `;
  elements.logContent.appendChild(entry);
  elements.logContent.scrollTop = elements.logContent.scrollHeight;

  console.log(`[${level.toUpperCase()}] ${message}`);
}

function handleConsensusLoaded(): void {
  const consensus = torClient.consensus;
  if (!consensus) return;

  // Convert to graph nodes
  const limit = parseInt(elements.nodeLimit.value, 10);
  state.graphNodes = consensus.relays.slice(0, limit).map((relay) => ({
    ...relay,
    nodeType: getNodeType(relay),
  }));

  renderGraph();
  updateStats();
}

function handleCircuitUpdate(circuits: ManagedCircuit[]): void {
  renderCircuitList(circuits);
  renderGraph(); // Re-render to show circuit paths
  updateStats();
}

// ============================================
// Helpers
// ============================================

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function getNodeType(node: MicroDescNodeInfo): NodeType {
  const flags = node.flags || [];
  if (flags.includes('Authority')) return 'authority';
  if (flags.includes('Guard') && flags.includes('Exit')) return 'guard-exit';
  if (flags.includes('Guard')) return 'guard';
  if (flags.includes('Exit')) return 'exit';
  return 'relay';
}

function getNodeColor(nodeType: NodeType): string {
  switch (nodeType) {
    case 'authority':
      return '#a855f7';
    case 'guard-exit':
      return '#eab308';
    case 'guard':
      return '#22c55e';
    case 'exit':
      return '#f97316';
    case 'snowflake-entry':
      return '#06b6d4';
    default:
      return '#3b82f6';
  }
}

function getNodeRadius(node: GraphNode): number {
  const flags = node.flags || [];
  if (flags.includes('Authority')) return 12;
  if (flags.includes('Guard') && flags.includes('Exit')) return 10;
  if (flags.includes('Guard') || flags.includes('Exit')) return 8;
  return 6;
}

function updateStats(): void {
  const nodes = state.graphNodes;
  const guards = nodes.filter((n) => n.flags?.includes('Guard')).length;
  const exits = nodes.filter((n) => n.flags?.includes('Exit')).length;

  elements.statTotal.textContent = nodes.length.toString();
  elements.statGuards.textContent = guards.toString();
  elements.statExits.textContent = exits.toString();
  elements.statCircuits.textContent = torClient.circuits.length.toString();
}

function formatBandwidth(bytes: number): string {
  if (bytes >= 1000000000) return (bytes / 1000000000).toFixed(1) + ' GB/s';
  if (bytes >= 1000000) return (bytes / 1000000).toFixed(1) + ' MB/s';
  if (bytes >= 1000) return (bytes / 1000).toFixed(1) + ' KB/s';
  return bytes + ' B/s';
}

// ============================================
// Graph Visualization
// ============================================

function initializeGraph(): void {
  const container = document.getElementById('graph-wrapper')!;
  const width = container.clientWidth;
  const height = container.clientHeight;

  elements.svg.attr('width', width).attr('height', height).attr('viewBox', [0, 0, width, height]);

  // Add zoom behavior
  const zoom = d3
    .zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.1, 4])
    .on('zoom', (event) => {
      elements.svg.select('g.graph-content').attr('transform', event.transform);
    });

  elements.svg.call(zoom);

  // Create main group for graph content
  elements.svg.append('g').attr('class', 'graph-content');

  // Add arrow marker definition for circuits
  const defs = elements.svg.append('defs');

  CIRCUIT_COLORS.forEach((color, i) => {
    defs
      .append('marker')
      .attr('id', `arrow-${i}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', color);
  });

  handleLog('Graph canvas initialized', 'info');
}

function renderGraph(): void {
  const container = document.getElementById('graph-wrapper')!;
  const width = container.clientWidth;
  const height = container.clientHeight;

  // Filter nodes based on current filters
  const filteredNodes = filterNodes(state.graphNodes);

  // Generate links between nodes (for visual structure only)
  const structureLinks: GraphLink[] = generateStructureLinks(filteredNodes);

  // Add circuit links
  const circuitLinks: GraphLink[] = [];
  const circuits = torClient.circuits.filter((c) => c.state === 'connected');

  circuits.forEach((circuit) => {
    // First hop is always Snowflake entry (not in our graph)
    // So we show connections between the nodes we selected
    for (let i = 0; i < circuit.nodes.length - 1; i++) {
      const sourceId = circuit.nodes[i]!.rsaIdDigest.toString('hex');
      const targetId = circuit.nodes[i + 1]!.rsaIdDigest.toString('hex');
      circuitLinks.push({
        source: sourceId,
        target: targetId,
        isCircuit: true,
        circuitId: circuit.id,
      });
    }
  });

  // Clear existing graph
  const graphContent = elements.svg.select('g.graph-content');
  graphContent.selectAll('*').remove();

  // Create link group
  const linkGroup = graphContent.append('g').attr('class', 'links');

  // Create node group
  const nodeGroup = graphContent.append('g').attr('class', 'nodes');

  // Create circuit link group (on top of regular links)
  const circuitLinkGroup = graphContent.append('g').attr('class', 'circuit-links');

  // Initialize simulation
  const linkDistance = parseInt(elements.linkDistance.value, 10);
  const chargeStrength = parseInt(elements.chargeStrength.value, 10);

  state.simulation = d3
    .forceSimulation<GraphNode>(filteredNodes)
    .force(
      'link',
      d3
        .forceLink<GraphNode, GraphLink>(structureLinks)
        .id((d) => d.rsaIdDigest.toString('hex'))
        .distance(linkDistance)
        .strength(0.1)
    )
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force(
      'collision',
      d3.forceCollide().radius((d) => getNodeRadius(d as GraphNode) + 2)
    );

  // Render regular links
  const links = linkGroup
    .selectAll<SVGLineElement, GraphLink>('line')
    .data(structureLinks)
    .join('line')
    .attr('class', 'link');

  // Render circuit links
  const circuitLinksSelection = circuitLinkGroup
    .selectAll<SVGLineElement, GraphLink>('line')
    .data(circuitLinks)
    .join('line')
    .attr('class', 'circuit-link animated')
    .attr('stroke', (d) => {
      const idx = circuits.findIndex((c) => c.id === d.circuitId);
      return CIRCUIT_COLORS[idx % CIRCUIT_COLORS.length] || '#ec4899';
    })
    .attr('marker-end', (d) => {
      const idx = circuits.findIndex((c) => c.id === d.circuitId);
      return `url(#arrow-${idx % CIRCUIT_COLORS.length})`;
    });

  // Render nodes
  const isSelectedForCircuit = (node: GraphNode) =>
    state.selectedForCircuit.some((n) => n.rsaIdDigest.equals(node.rsaIdDigest));

  const nodes = nodeGroup
    .selectAll<SVGGElement, GraphNode>('g')
    .data(filteredNodes)
    .join('g')
    .attr('class', (d) => {
      const selected = state.selectedNodes.has(d.rsaIdDigest.toString('hex'));
      const forCircuit = isSelectedForCircuit(d);
      return `node ${d.nodeType}${selected ? ' selected' : ''}${forCircuit ? ' circuit-selected' : ''}`;
    })
    .call(drag(state.simulation) as any);

  // Node circles
  nodes
    .append('circle')
    .attr('class', 'node-circle')
    .attr('r', (d) => getNodeRadius(d))
    .attr('fill', (d) => getNodeColor(d.nodeType))
    .attr('stroke', (d) => (isSelectedForCircuit(d) ? '#ec4899' : 'rgba(255,255,255,0.2)'))
    .attr('stroke-width', (d) => (isSelectedForCircuit(d) ? 3 : 2));

  // Circuit order numbers
  nodes
    .filter((d) => isSelectedForCircuit(d))
    .append('text')
    .attr('class', 'circuit-order')
    .attr('dy', 4)
    .attr('text-anchor', 'middle')
    .attr('fill', 'white')
    .attr('font-size', '10px')
    .attr('font-weight', 'bold')
    .text((d) => {
      const idx = state.selectedForCircuit.findIndex((n) => n.rsaIdDigest.equals(d.rsaIdDigest));
      return idx >= 0 ? (idx + 1).toString() : '';
    });

  // Node labels (conditionally shown)
  const showLabels = elements.showLabels.checked;
  if (showLabels) {
    nodes
      .append('text')
      .attr('class', 'node-label')
      .attr('dy', (d) => getNodeRadius(d) + 12)
      .text((d) => d.nickname.slice(0, 10));
  }

  // Node interactions
  nodes
    .on('click', (event, d) => {
      event.stopPropagation();
      if (event.shiftKey) {
        // Shift+click to add to circuit path
        toggleNodeForCircuit(d);
      } else {
        // Regular click to select and show info
        selectNode(d);
      }
    })
    .on('contextmenu', (event, d) => {
      event.preventDefault();
      toggleNodeForCircuit(d);
    })
    .on('mouseover', (event, d) => {
      showTooltip(event, d);
    })
    .on('mouseout', () => {
      hideTooltip();
    });

  // Click on background to deselect
  elements.svg.on('click', () => {
    state.selectedNodes.clear();
    renderGraph();
    elements.nodeInfoContent.innerHTML =
      '<p class="empty-message">Click on a node to view details<br><small>Shift+click or right-click to add to circuit path</small></p>';
  });

  // Update on simulation tick
  state.simulation.on('tick', () => {
    links
      .attr('x1', (d) => (d.source as GraphNode).x!)
      .attr('y1', (d) => (d.source as GraphNode).y!)
      .attr('x2', (d) => (d.target as GraphNode).x!)
      .attr('y2', (d) => (d.target as GraphNode).y!);

    circuitLinksSelection
      .attr('x1', (d) => {
        const sourceNode = filteredNodes.find(
          (n) =>
            n.rsaIdDigest.toString('hex') ===
            (typeof d.source === 'string'
              ? d.source
              : (d.source as GraphNode).rsaIdDigest.toString('hex'))
        );
        return sourceNode?.x || 0;
      })
      .attr('y1', (d) => {
        const sourceNode = filteredNodes.find(
          (n) =>
            n.rsaIdDigest.toString('hex') ===
            (typeof d.source === 'string'
              ? d.source
              : (d.source as GraphNode).rsaIdDigest.toString('hex'))
        );
        return sourceNode?.y || 0;
      })
      .attr('x2', (d) => {
        const targetNode = filteredNodes.find(
          (n) =>
            n.rsaIdDigest.toString('hex') ===
            (typeof d.target === 'string'
              ? d.target
              : (d.target as GraphNode).rsaIdDigest.toString('hex'))
        );
        return targetNode?.x || 0;
      })
      .attr('y2', (d) => {
        const targetNode = filteredNodes.find(
          (n) =>
            n.rsaIdDigest.toString('hex') ===
            (typeof d.target === 'string'
              ? d.target
              : (d.target as GraphNode).rsaIdDigest.toString('hex'))
        );
        return targetNode?.y || 0;
      });

    nodes.attr('transform', (d) => `translate(${d.x},${d.y})`);
  });
}

function filterNodes(nodes: GraphNode[]): GraphNode[] {
  return nodes.filter((node) => {
    const flags = node.flags || [];
    const checks = [
      elements.filterGuard.checked && flags.includes('Guard'),
      elements.filterExit.checked && flags.includes('Exit'),
      elements.filterStable.checked && flags.includes('Stable'),
      elements.filterFast.checked && flags.includes('Fast'),
      elements.filterAuthority.checked && flags.includes('Authority'),
      elements.filterHsdir.checked && flags.includes('HSDir'),
    ];

    const anyChecked =
      elements.filterGuard.checked ||
      elements.filterExit.checked ||
      elements.filterStable.checked ||
      elements.filterFast.checked ||
      elements.filterAuthority.checked ||
      elements.filterHsdir.checked;

    if (!anyChecked) return true;
    return checks.some((c) => c);
  });
}

function generateStructureLinks(nodes: GraphNode[]): GraphLink[] {
  const links: GraphLink[] = [];

  const guards = nodes.filter((n) => n.flags?.includes('Guard'));
  const exits = nodes.filter((n) => n.flags?.includes('Exit') && !n.flags?.includes('Guard'));
  const relays = nodes.filter((n) => !n.flags?.includes('Guard') && !n.flags?.includes('Exit'));
  const authorities = nodes.filter((n) => n.flags?.includes('Authority'));

  // Connect authorities to guards
  authorities.forEach((auth) => {
    const connectedGuards = guards.slice(0, Math.min(3, guards.length));
    connectedGuards.forEach((guard) => {
      if (!auth.rsaIdDigest.equals(guard.rsaIdDigest)) {
        links.push({
          source: auth.rsaIdDigest.toString('hex'),
          target: guard.rsaIdDigest.toString('hex'),
        });
      }
    });
  });

  // Connect guards to relays (sparse)
  guards.forEach((guard, i) => {
    const startIdx = (i * 2) % Math.max(1, relays.length);
    for (let j = 0; j < Math.min(2, relays.length); j++) {
      const relay = relays[(startIdx + j) % relays.length];
      if (relay) {
        links.push({
          source: guard.rsaIdDigest.toString('hex'),
          target: relay.rsaIdDigest.toString('hex'),
        });
      }
    }
  });

  // Connect relays to exits (sparse)
  relays.forEach((relay, i) => {
    if (exits.length > 0 && i % 3 === 0) {
      const exit = exits[i % exits.length];
      if (exit) {
        links.push({
          source: relay.rsaIdDigest.toString('hex'),
          target: exit.rsaIdDigest.toString('hex'),
        });
      }
    }
  });

  return links;
}

function drag(simulation: d3.Simulation<GraphNode, GraphLink>) {
  function dragstarted(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }

  function dragged(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }

  function dragended(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }

  return d3
    .drag<SVGGElement, GraphNode>()
    .on('start', dragstarted)
    .on('drag', dragged)
    .on('end', dragended);
}

// ============================================
// Node Selection
// ============================================

function selectNode(node: GraphNode): void {
  state.selectedNodes.clear();
  state.selectedNodes.add(node.rsaIdDigest.toString('hex'));
  renderNodeInfo(node);
  renderGraph();
}

function toggleNodeForCircuit(node: GraphNode): void {
  const idx = state.selectedForCircuit.findIndex((n) => n.rsaIdDigest.equals(node.rsaIdDigest));
  if (idx >= 0) {
    state.selectedForCircuit.splice(idx, 1);
    handleLog(`Removed ${node.nickname} from circuit path`, 'info');
  } else {
    state.selectedForCircuit.push(node);
    handleLog(
      `Added ${node.nickname} to circuit path (position ${state.selectedForCircuit.length})`,
      'info'
    );
  }
  updateCircuitPathUI();
  renderGraph();
}

function updateCircuitPathUI(): void {
  const pathDisplay = state.selectedForCircuit.map((n) => n.nickname).join(' → ');
  if (state.selectedForCircuit.length > 0) {
    handleLog(`Circuit path: Snowflake → ${pathDisplay}`, 'info');
  }
}

function renderNodeInfo(node: GraphNode): void {
  const iconColor = getNodeColor(node.nodeType);
  const typeLabel =
    node.nodeType.charAt(0).toUpperCase() + node.nodeType.slice(1).replace('-', ' + ');
  const flags = node.flags || [];

  const flagBadges = flags
    .map((flag) => {
      const flagClass = flag.toLowerCase();
      return `<span class="flag-badge ${flagClass}">${flag}</span>`;
    })
    .join('');

  const bandwidth = node.bandwidthStats?.Bandwidth || 0;
  const isInCircuitPath = state.selectedForCircuit.some((n) =>
    n.rsaIdDigest.equals(node.rsaIdDigest)
  );

  elements.nodeInfoContent.innerHTML = `
    <div class="node-info-header">
      <div class="node-info-icon" style="background: ${iconColor}">🧅</div>
      <div class="node-info-title">
        <div class="node-info-nickname">${escapeHtml(node.nickname)}</div>
        <div class="node-info-type">${typeLabel} Node</div>
      </div>
    </div>

    <div class="node-info-section">
      <h4>Connection</h4>
      <div class="node-info-row">
        <span class="node-info-label">IP Address</span>
        <span class="node-info-value">${escapeHtml(node.ip_address)}</span>
      </div>
      <div class="node-info-row">
        <span class="node-info-label">OR Port</span>
        <span class="node-info-value">${node.onion_router_port}</span>
      </div>
      <div class="node-info-row">
        <span class="node-info-label">Dir Port</span>
        <span class="node-info-value">${node.directory_server_port || 'N/A'}</span>
      </div>
    </div>

    <div class="node-info-section">
      <h4>Identity</h4>
      <div class="node-info-row">
        <span class="node-info-label">Fingerprint</span>
        <span class="node-info-value" title="${node.rsaIdDigest.toString('hex').toUpperCase()}">${node.rsaIdDigest.toString('hex').slice(0, 16).toUpperCase()}...</span>
      </div>
      ${
        node.version
          ? `
      <div class="node-info-row">
        <span class="node-info-label">Version</span>
        <span class="node-info-value">${escapeHtml(node.version)}</span>
      </div>
      `
          : ''
      }
    </div>

    <div class="node-info-section">
      <h4>Performance</h4>
      <div class="node-info-row">
        <span class="node-info-label">Bandwidth</span>
        <span class="node-info-value">${formatBandwidth(bandwidth)}</span>
      </div>
    </div>

    <div class="node-info-section">
      <h4>Flags</h4>
      <div class="node-flags">${flagBadges}</div>
    </div>

    <div class="node-info-section">
      <h4>Actions</h4>
      <button class="btn ${isInCircuitPath ? 'secondary' : 'success'} small" id="toggle-circuit-node">
        ${isInCircuitPath ? 'Remove from Circuit' : 'Add to Circuit Path'}
      </button>
    </div>
  `;

  // Add event listener
  document.getElementById('toggle-circuit-node')?.addEventListener('click', () => {
    toggleNodeForCircuit(node);
    renderNodeInfo(node); // Re-render to update button
  });
}

// ============================================
// Tooltip
// ============================================

function showTooltip(event: MouseEvent, node: GraphNode): void {
  const tooltip = elements.tooltip;
  const typeLabel =
    node.nodeType.charAt(0).toUpperCase() + node.nodeType.slice(1).replace('-', ' + ');
  const flags = node.flags || [];

  tooltip.innerHTML = `
    <div class="tooltip-title">${escapeHtml(node.nickname)}</div>
    <div class="tooltip-subtitle">${typeLabel} • ${flags.length} flags</div>
  `;

  tooltip.hidden = false;
  tooltip.style.left = `${event.clientX + 15}px`;
  tooltip.style.top = `${event.clientY + 15}px`;
}

function hideTooltip(): void {
  elements.tooltip.hidden = true;
}

// ============================================
// Circuit Management
// ============================================

async function createCircuit(random: boolean): Promise<void> {
  if (!torClient.isConnected) {
    handleLog('Not connected to Tor network', 'error');
    return;
  }

  const btn = elements.createCircuitBtn;
  btn.disabled = true;

  try {
    if (random) {
      const hopCount = parseInt(elements.circuitLength.value, 10);
      await torClient.buildRandomCircuit(hopCount);
    } else {
      if (state.selectedForCircuit.length === 0) {
        handleLog(
          'No nodes selected for circuit. Shift+click or right-click nodes to add them.',
          'warning'
        );
        return;
      }
      await torClient.buildCircuit(state.selectedForCircuit);
      state.selectedForCircuit = [];
    }
  } catch {
    // Error already logged by TorClient
  } finally {
    btn.disabled = false;
  }
}

function renderCircuitList(circuits: ManagedCircuit[]): void {
  if (circuits.length === 0) {
    elements.circuitList.innerHTML = `
      <p class="empty-message">No circuits created yet</p>
      ${
        state.selectedForCircuit.length > 0
          ? `
        <p class="circuit-path-preview">
          <strong>Path:</strong> Snowflake → ${state.selectedForCircuit.map((n) => n.nickname).join(' → ')}
          <button class="btn secondary small" id="build-manual-circuit">Build This Circuit</button>
          <button class="btn secondary small" id="clear-path">Clear</button>
        </p>
      `
          : ''
      }
    `;

    document
      .getElementById('build-manual-circuit')
      ?.addEventListener('click', () => createCircuit(false));
    document.getElementById('clear-path')?.addEventListener('click', () => {
      state.selectedForCircuit = [];
      renderCircuitList(circuits);
      renderGraph();
    });

    elements.clearCircuitsBtn.disabled = true;
    return;
  }

  elements.clearCircuitsBtn.disabled = false;

  let html = circuits
    .map((circuit, idx) => {
      const color = CIRCUIT_COLORS[idx % CIRCUIT_COLORS.length];
      const path = circuit.nodes.map((n) => n.nickname.slice(0, 8)).join(' → ');
      const stateClass =
        circuit.state === 'connected'
          ? 'success'
          : circuit.state === 'building'
            ? 'warning'
            : 'error';

      return `
      <div class="circuit-item">
        <span class="circuit-color" style="background: ${color}"></span>
        <span class="circuit-path" title="Snowflake → ${circuit.nodes.map((n) => n.nickname).join(' → ')}">
          ${path}
        </span>
        <span class="circuit-state ${stateClass}">${circuit.state}</span>
        <button class="circuit-remove" data-id="${circuit.id}" title="Destroy circuit">✕</button>
      </div>
    `;
    })
    .join('');

  // Add manual path preview if nodes are selected
  if (state.selectedForCircuit.length > 0) {
    html += `
      <p class="circuit-path-preview">
        <strong>Next:</strong> Snowflake → ${state.selectedForCircuit.map((n) => n.nickname).join(' → ')}
        <button class="btn success small" id="build-manual-circuit">Build</button>
        <button class="btn secondary small" id="clear-path">Clear</button>
      </p>
    `;
  }

  elements.circuitList.innerHTML = html;

  // Add event listeners
  elements.circuitList.querySelectorAll('.circuit-remove').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const id = parseInt((e.target as HTMLElement).dataset.id || '0', 10);
      torClient.destroyCircuit(id);
    });
  });

  document
    .getElementById('build-manual-circuit')
    ?.addEventListener('click', () => createCircuit(false));
  document.getElementById('clear-path')?.addEventListener('click', () => {
    state.selectedForCircuit = [];
    renderCircuitList(torClient.circuits);
    renderGraph();
  });
}

// ============================================
// Event Handlers
// ============================================

async function handleLoadNetwork(): Promise<void> {
  const btn = elements.loadNetworkBtn;
  const btnText = btn.querySelector('.btn-text') as HTMLElement;
  const btnLoading = btn.querySelector('.btn-loading') as HTMLElement;

  btn.disabled = true;
  btnText.hidden = true;
  btnLoading.hidden = false;

  try {
    // Disconnect if already connected
    if (torClient.isConnected) {
      torClient.disconnect();
    }

    await torClient.connect();
  } catch {
    // Error already handled by TorClient
  } finally {
    btn.disabled = false;
    btnText.hidden = false;
    btnLoading.hidden = true;
  }
}

function handleNodeLimitChange(): void {
  elements.nodeLimitValue.textContent = `${elements.nodeLimit.value} nodes`;

  // If we have consensus, re-slice and re-render
  if (torClient.consensus) {
    const limit = parseInt(elements.nodeLimit.value, 10);
    state.graphNodes = torClient.consensus.relays.slice(0, limit).map((relay) => ({
      ...relay,
      nodeType: getNodeType(relay),
    }));
    renderGraph();
    updateStats();
  }
}

function handlePhysicsChange(): void {
  elements.linkDistanceValue.textContent = elements.linkDistance.value;
  elements.chargeStrengthValue.textContent = elements.chargeStrength.value;

  if (state.simulation) {
    const linkDistance = parseInt(elements.linkDistance.value, 10);
    const chargeStrength = parseInt(elements.chargeStrength.value, 10);

    state.simulation
      .force('link', d3.forceLink<GraphNode, GraphLink>().distance(linkDistance).strength(0.1))
      .force('charge', d3.forceManyBody().strength(chargeStrength))
      .alpha(0.3)
      .restart();
  }
}

function handleFilterChange(): void {
  if (state.graphNodes.length > 0) {
    renderGraph();
  }
}

function handleShowLabelsChange(): void {
  if (state.graphNodes.length > 0) {
    renderGraph();
  }
}

function handleClearLog(): void {
  elements.logContent.innerHTML = '';
}

function handleResize(): void {
  const container = document.getElementById('graph-wrapper')!;
  const width = container.clientWidth;
  const height = container.clientHeight;

  elements.svg.attr('width', width).attr('height', height).attr('viewBox', [0, 0, width, height]);

  if (state.simulation) {
    state.simulation.force('center', d3.forceCenter(width / 2, height / 2));
    state.simulation.alpha(0.1).restart();
  }
}

// ============================================
// Initialization
// ============================================

function init(): void {
  // Remove demo option - this is a real Tor client now
  elements.dataSource.innerHTML = '<option value="snowflake">Snowflake (Live Tor Network)</option>';

  // Update button text
  const btnText = elements.loadNetworkBtn.querySelector('.btn-text') as HTMLElement;
  btnText.textContent = 'Connect to Tor';

  // Initialize graph canvas
  initializeGraph();

  // Event listeners - Controls
  elements.loadNetworkBtn.addEventListener('click', handleLoadNetwork);
  elements.nodeLimit.addEventListener('input', handleNodeLimitChange);

  // Event listeners - Filters
  elements.filterGuard.addEventListener('change', handleFilterChange);
  elements.filterExit.addEventListener('change', handleFilterChange);
  elements.filterStable.addEventListener('change', handleFilterChange);
  elements.filterFast.addEventListener('change', handleFilterChange);
  elements.filterAuthority.addEventListener('change', handleFilterChange);
  elements.filterHsdir.addEventListener('change', handleFilterChange);

  // Event listeners - Circuit controls
  elements.createCircuitBtn.addEventListener('click', () => createCircuit(true));
  elements.clearCircuitsBtn.addEventListener('click', () => torClient.destroyAllCircuits());

  // Event listeners - Physics
  elements.linkDistance.addEventListener('input', handlePhysicsChange);
  elements.chargeStrength.addEventListener('input', handlePhysicsChange);
  elements.showLabels.addEventListener('change', handleShowLabelsChange);

  // Event listeners - Log
  elements.clearLogBtn.addEventListener('click', handleClearLog);

  // Window resize
  window.addEventListener('resize', handleResize);

  // Update initial node info
  elements.nodeInfoContent.innerHTML =
    '<p class="empty-message">Click on a node to view details<br><small>Shift+click or right-click to add to circuit path</small></p>';

  // Initial log
  handleLog('Tor Network Visualizer initialized', 'success');
  handleLog('Click "Connect to Tor" to connect via Snowflake', 'info');
  handleLog('This uses real Tor connections - no simulation!', 'info');
}

// Start the application
init();
