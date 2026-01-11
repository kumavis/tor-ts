/**
 * Tor Network Visualizer
 *
 * A force-directed graph visualization of the Tor relay network.
 * Displays node types, flags, circuits, and allows interactive exploration.
 */

import * as d3 from 'd3';

// ============================================
// Types
// ============================================

interface TorNode {
  id: string;
  nickname: string;
  fingerprint: string;
  ipAddress: string;
  orPort: number;
  dirPort: number;
  flags: string[];
  bandwidth: number;
  version?: string;
  protocols?: Record<string, string>;
  // Computed properties
  isGuard: boolean;
  isExit: boolean;
  isAuthority: boolean;
  isStable: boolean;
  isFast: boolean;
  isHSDir: boolean;
  isSnowflake: boolean;
  nodeType: NodeType;
  // D3 simulation properties
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
  index?: number;
}

interface TorLink {
  source: TorNode | string;
  target: TorNode | string;
  isCircuit?: boolean;
  circuitId?: number;
}

interface Circuit {
  id: number;
  nodes: TorNode[];
  color: string;
}

type NodeType = 'guard' | 'exit' | 'guard-exit' | 'authority' | 'relay' | 'snowflake';

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

interface AppState {
  nodes: TorNode[];
  links: TorLink[];
  circuits: Circuit[];
  selectedNode: TorNode | null;
  connectionStatus: ConnectionStatus;
  simulation: d3.Simulation<TorNode, TorLink> | null;
}

// Circuit colors
const CIRCUIT_COLORS = [
  '#ec4899', // pink
  '#8b5cf6', // purple
  '#06b6d4', // cyan
  '#84cc16', // lime
  '#f43f5e', // rose
  '#f59e0b', // amber
  '#10b981', // emerald
  '#6366f1', // indigo
];

// ============================================
// State
// ============================================

const state: AppState = {
  nodes: [],
  links: [],
  circuits: [],
  selectedNode: null,
  connectionStatus: 'disconnected',
  simulation: null,
};

let nextCircuitId = 1;

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
// Logging
// ============================================

function log(message: string, type: 'info' | 'success' | 'error' | 'warning' = 'info'): void {
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false });

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-message ${type}">${escapeHtml(message)}</span>
  `;
  elements.logContent.appendChild(entry);
  elements.logContent.scrollTop = elements.logContent.scrollHeight;

  console.log(`[${type.toUpperCase()}] ${message}`);
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// Status Updates
// ============================================

function setConnectionStatus(status: ConnectionStatus, text: string): void {
  state.connectionStatus = status;
  const dot = elements.connectionStatus.querySelector('.status-dot')!;
  const textEl = elements.connectionStatus.querySelector('.status-text')!;

  dot.className = `status-dot ${status}`;
  textEl.textContent = text;
}

function updateStats(): void {
  const guards = state.nodes.filter((n) => n.isGuard).length;
  const exits = state.nodes.filter((n) => n.isExit).length;

  elements.statTotal.textContent = state.nodes.length.toString();
  elements.statGuards.textContent = guards.toString();
  elements.statExits.textContent = exits.toString();
  elements.statCircuits.textContent = state.circuits.length.toString();
}

// ============================================
// Demo Data Generation
// ============================================

function generateDemoNodes(count: number): TorNode[] {
  const nodes: TorNode[] = [];
  const nicknames = [
    'TorRelay',
    'Guardian',
    'ExitNode',
    'Router',
    'Onion',
    'Proxy',
    'Anonymizer',
    'Privacy',
    'Freedom',
    'Liberty',
    'Secure',
    'Safe',
    'Hidden',
    'Shadow',
    'Phantom',
    'Ghost',
    'Stealth',
    'Cipher',
    'Crypto',
    'Shield',
    'Fortress',
    'Bastion',
    'Sentinel',
    'Watch',
  ];

  const countries = ['US', 'DE', 'FR', 'NL', 'GB', 'CA', 'CH', 'SE', 'NO', 'FI'];

  // Generate some authority nodes first
  const authorityCount = Math.min(9, Math.floor(count * 0.02));
  for (let i = 0; i < authorityCount; i++) {
    nodes.push(createDemoNode(i, nicknames, countries, true, false));
  }

  // Generate guard + exit nodes
  const guardExitCount = Math.floor(count * 0.05);
  for (let i = 0; i < guardExitCount; i++) {
    const node = createDemoNode(authorityCount + i, nicknames, countries, false, false);
    node.flags = [
      'Authority',
      'Exit',
      'Fast',
      'Guard',
      'HSDir',
      'Running',
      'Stable',
      'V2Dir',
      'Valid',
    ];
    processNodeFlags(node);
    nodes.push(node);
  }

  // Generate guard nodes
  const guardCount = Math.floor(count * 0.15);
  for (let i = 0; i < guardCount; i++) {
    const node = createDemoNode(
      authorityCount + guardExitCount + i,
      nicknames,
      countries,
      false,
      false
    );
    node.flags = ['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid'];
    processNodeFlags(node);
    nodes.push(node);
  }

  // Generate exit nodes
  const exitCount = Math.floor(count * 0.1);
  for (let i = 0; i < exitCount; i++) {
    const node = createDemoNode(
      authorityCount + guardExitCount + guardCount + i,
      nicknames,
      countries,
      false,
      false
    );
    node.flags = ['Exit', 'Fast', 'Running', 'Stable', 'V2Dir', 'Valid'];
    processNodeFlags(node);
    nodes.push(node);
  }

  // Generate snowflake nodes
  const snowflakeCount = Math.floor(count * 0.03);
  for (let i = 0; i < snowflakeCount; i++) {
    nodes.push(
      createDemoNode(
        authorityCount + guardExitCount + guardCount + exitCount + i,
        nicknames,
        countries,
        false,
        true
      )
    );
  }

  // Fill remaining with regular relays
  const remainingCount = count - nodes.length;
  for (let i = 0; i < remainingCount; i++) {
    const node = createDemoNode(nodes.length + i, nicknames, countries, false, false);
    node.flags = ['Fast', 'Running', 'Stable', 'V2Dir', 'Valid'];
    processNodeFlags(node);
    nodes.push(node);
  }

  return nodes;
}

function createDemoNode(
  index: number,
  nicknames: string[],
  countries: string[],
  isAuthority: boolean,
  isSnowflake: boolean
): TorNode {
  const nickname = nicknames[index % nicknames.length]! + (index + 1);
  const country = countries[index % countries.length]!;
  const fingerprint = generateRandomFingerprint();

  let flags: string[];
  if (isAuthority) {
    flags = ['Authority', 'Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid'];
  } else if (isSnowflake) {
    flags = ['Fast', 'Running', 'Stable', 'V2Dir', 'Valid'];
  } else {
    flags = ['Fast', 'Running', 'Stable', 'V2Dir', 'Valid'];
  }

  const node: TorNode = {
    id: fingerprint,
    nickname: `${nickname}${country}`,
    fingerprint,
    ipAddress: generateRandomIP(),
    orPort: 9001 + (index % 100),
    dirPort: 9030 + (index % 100),
    flags,
    bandwidth: Math.floor(Math.random() * 50000) + 1000,
    version: `0.4.${Math.floor(Math.random() * 3) + 7}.${Math.floor(Math.random() * 10)}`,
    isGuard: false,
    isExit: false,
    isAuthority: isAuthority,
    isStable: true,
    isFast: true,
    isHSDir: false,
    isSnowflake: isSnowflake,
    nodeType: 'relay',
  };

  processNodeFlags(node);
  return node;
}

function processNodeFlags(node: TorNode): void {
  node.isGuard = node.flags.includes('Guard');
  node.isExit = node.flags.includes('Exit');
  node.isAuthority = node.flags.includes('Authority');
  node.isStable = node.flags.includes('Stable');
  node.isFast = node.flags.includes('Fast');
  node.isHSDir = node.flags.includes('HSDir');

  // Determine node type
  if (node.isAuthority) {
    node.nodeType = 'authority';
  } else if (node.isSnowflake) {
    node.nodeType = 'snowflake';
  } else if (node.isGuard && node.isExit) {
    node.nodeType = 'guard-exit';
  } else if (node.isGuard) {
    node.nodeType = 'guard';
  } else if (node.isExit) {
    node.nodeType = 'exit';
  } else {
    node.nodeType = 'relay';
  }
}

function generateRandomFingerprint(): string {
  const chars = '0123456789ABCDEF';
  let result = '';
  for (let i = 0; i < 40; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function generateRandomIP(): string {
  return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

// ============================================
// Data Fetching
// ============================================

async function fetchNetworkData(): Promise<TorNode[]> {
  const source = elements.dataSource.value;
  const limit = parseInt(elements.nodeLimit.value, 10);

  if (source === 'demo') {
    log('Generating demo network data...', 'info');
    await sleep(500); // Simulate network delay
    const nodes = generateDemoNodes(limit);
    log(`Generated ${nodes.length} demo nodes`, 'success');
    return nodes;
  }

  // Fetch from Onionoo API
  log('Fetching data from Onionoo API...', 'info');

  try {
    const response = await fetch(
      `https://onionoo.torproject.org/details?limit=${limit}&running=true&order=-consensus_weight`
    );

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const relays = data.relays || [];

    const nodes: TorNode[] = relays.map((relay: any) => {
      const fingerprint = relay.fingerprint || '';
      const flags = relay.flags || [];

      const node: TorNode = {
        id: fingerprint,
        nickname: relay.nickname || 'Unnamed',
        fingerprint,
        ipAddress: relay.or_addresses?.[0]?.split(':')[0] || '',
        orPort: parseInt(relay.or_addresses?.[0]?.split(':')[1] || '9001', 10),
        dirPort: relay.dir_address ? parseInt(relay.dir_address.split(':')[1] || '0', 10) : 0,
        flags,
        bandwidth: relay.observed_bandwidth || relay.bandwidth_rate || 0,
        version: relay.version,
        isGuard: false,
        isExit: false,
        isAuthority: false,
        isStable: false,
        isFast: false,
        isHSDir: false,
        isSnowflake: relay.transports?.includes('snowflake') || false,
        nodeType: 'relay',
      };

      processNodeFlags(node);
      return node;
    });

    log(`Fetched ${nodes.length} relays from Onionoo`, 'success');
    return nodes;
  } catch (error) {
    log(`Failed to fetch from Onionoo: ${error instanceof Error ? error.message : error}`, 'error');
    throw error;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

  log('Graph canvas initialized', 'info');
}

function getNodeColor(node: TorNode): string {
  switch (node.nodeType) {
    case 'authority':
      return '#a855f7';
    case 'guard-exit':
      return '#eab308';
    case 'guard':
      return '#22c55e';
    case 'exit':
      return '#f97316';
    case 'snowflake':
      return '#06b6d4';
    default:
      return '#3b82f6';
  }
}

function getNodeRadius(node: TorNode): number {
  if (node.isAuthority) return 12;
  if (node.isSnowflake) return 9;
  if (node.isGuard && node.isExit) return 10;
  if (node.isGuard || node.isExit) return 8;
  return 6;
}

function renderGraph(): void {
  const container = document.getElementById('graph-wrapper')!;
  const width = container.clientWidth;
  const height = container.clientHeight;

  // Filter nodes based on current filters
  const filteredNodes = filterNodes(state.nodes);

  // Generate links between nodes (for visual structure only)
  // In a real implementation, this could be based on actual circuit data
  const structureLinks: TorLink[] = generateStructureLinks(filteredNodes);

  // Combine with circuit links
  const circuitLinks: TorLink[] = [];
  state.circuits.forEach((circuit) => {
    for (let i = 0; i < circuit.nodes.length - 1; i++) {
      circuitLinks.push({
        source: circuit.nodes[i]!.id,
        target: circuit.nodes[i + 1]!.id,
        isCircuit: true,
        circuitId: circuit.id,
      });
    }
  });

  const allLinks = [...structureLinks, ...circuitLinks];

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
    .forceSimulation<TorNode>(filteredNodes)
    .force(
      'link',
      d3
        .forceLink<TorNode, TorLink>(structureLinks)
        .id((d) => d.id)
        .distance(linkDistance)
        .strength(0.1)
    )
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force(
      'collision',
      d3.forceCollide().radius((d) => getNodeRadius(d) + 2)
    );

  // Render regular links
  const links = linkGroup
    .selectAll<SVGLineElement, TorLink>('line')
    .data(structureLinks)
    .join('line')
    .attr('class', 'link');

  // Render circuit links
  const circuitLinksSelection = circuitLinkGroup
    .selectAll<SVGLineElement, TorLink>('line')
    .data(circuitLinks)
    .join('line')
    .attr('class', 'circuit-link animated')
    .attr('stroke', (d) => {
      const circuit = state.circuits.find((c) => c.id === d.circuitId);
      return circuit?.color || '#ec4899';
    })
    .attr('marker-end', (d) => {
      const circuit = state.circuits.find((c) => c.id === d.circuitId);
      const colorIndex = CIRCUIT_COLORS.indexOf(circuit?.color || '#ec4899');
      return `url(#arrow-${colorIndex >= 0 ? colorIndex : 0})`;
    });

  // Render nodes
  const nodes = nodeGroup
    .selectAll<SVGGElement, TorNode>('g')
    .data(filteredNodes)
    .join('g')
    .attr('class', (d) => `node ${d.nodeType}${state.selectedNode?.id === d.id ? ' selected' : ''}`)
    .call(drag(state.simulation) as any);

  // Node circles
  nodes
    .append('circle')
    .attr('class', 'node-circle')
    .attr('r', (d) => getNodeRadius(d))
    .attr('fill', (d) => getNodeColor(d));

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
      selectNode(d);
    })
    .on('mouseover', (event, d) => {
      showTooltip(event, d);
    })
    .on('mouseout', () => {
      hideTooltip();
    });

  // Click on background to deselect
  elements.svg.on('click', () => {
    selectNode(null);
  });

  // Update on simulation tick
  state.simulation.on('tick', () => {
    links
      .attr('x1', (d) => (d.source as TorNode).x!)
      .attr('y1', (d) => (d.source as TorNode).y!)
      .attr('x2', (d) => (d.target as TorNode).x!)
      .attr('y2', (d) => (d.target as TorNode).y!);

    circuitLinksSelection
      .attr('x1', (d) => {
        const sourceNode = filteredNodes.find(
          (n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id)
        );
        return sourceNode?.x || 0;
      })
      .attr('y1', (d) => {
        const sourceNode = filteredNodes.find(
          (n) => n.id === (typeof d.source === 'string' ? d.source : d.source.id)
        );
        return sourceNode?.y || 0;
      })
      .attr('x2', (d) => {
        const targetNode = filteredNodes.find(
          (n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id)
        );
        return targetNode?.x || 0;
      })
      .attr('y2', (d) => {
        const targetNode = filteredNodes.find(
          (n) => n.id === (typeof d.target === 'string' ? d.target : d.target.id)
        );
        return targetNode?.y || 0;
      });

    nodes.attr('transform', (d) => `translate(${d.x},${d.y})`);
  });

  updateStats();
  log(`Rendered ${filteredNodes.length} nodes and ${allLinks.length} links`, 'info');
}

function filterNodes(nodes: TorNode[]): TorNode[] {
  return nodes.filter((node) => {
    // At least one of the checked filters must match
    const checks = [
      elements.filterGuard.checked && node.isGuard,
      elements.filterExit.checked && node.isExit,
      elements.filterStable.checked && node.isStable,
      elements.filterFast.checked && node.isFast,
      elements.filterAuthority.checked && node.isAuthority,
      elements.filterHsdir.checked && node.isHSDir,
    ];

    // If all filters are unchecked, show all nodes
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

function generateStructureLinks(nodes: TorNode[]): TorLink[] {
  const links: TorLink[] = [];

  // Create a sparse connectivity structure for visualization
  // Connect guards to some relays, relays to exits, etc.
  const guards = nodes.filter((n) => n.isGuard);
  const exits = nodes.filter((n) => n.isExit && !n.isGuard);
  const relays = nodes.filter((n) => !n.isGuard && !n.isExit);
  const authorities = nodes.filter((n) => n.isAuthority);

  // Connect authorities to guards
  authorities.forEach((auth) => {
    const connectedGuards = guards.slice(0, Math.min(3, guards.length));
    connectedGuards.forEach((guard) => {
      if (auth.id !== guard.id) {
        links.push({ source: auth.id, target: guard.id });
      }
    });
  });

  // Connect guards to relays (sparse)
  guards.forEach((guard, i) => {
    const startIdx = (i * 2) % relays.length;
    for (let j = 0; j < Math.min(2, relays.length); j++) {
      const relay = relays[(startIdx + j) % relays.length];
      if (relay) {
        links.push({ source: guard.id, target: relay.id });
      }
    }
  });

  // Connect relays to exits (sparse)
  relays.forEach((relay, i) => {
    if (exits.length > 0 && i % 3 === 0) {
      const exit = exits[i % exits.length];
      if (exit) {
        links.push({ source: relay.id, target: exit.id });
      }
    }
  });

  return links;
}

function drag(simulation: d3.Simulation<TorNode, TorLink>) {
  function dragstarted(event: d3.D3DragEvent<SVGGElement, TorNode, TorNode>) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }

  function dragged(event: d3.D3DragEvent<SVGGElement, TorNode, TorNode>) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }

  function dragended(event: d3.D3DragEvent<SVGGElement, TorNode, TorNode>) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }

  return d3
    .drag<SVGGElement, TorNode>()
    .on('start', dragstarted)
    .on('drag', dragged)
    .on('end', dragended);
}

// ============================================
// Node Selection & Info Panel
// ============================================

function selectNode(node: TorNode | null): void {
  state.selectedNode = node;

  // Update node classes
  elements.svg.selectAll('.node').classed('selected', (d: any) => d.id === node?.id);

  // Update info panel
  if (node) {
    renderNodeInfo(node);
    log(`Selected node: ${node.nickname}`, 'info');
  } else {
    elements.nodeInfoContent.innerHTML =
      '<p class="empty-message">Click on a node to view details</p>';
  }
}

function renderNodeInfo(node: TorNode): void {
  const iconColor = getNodeColor(node);
  const typeLabel =
    node.nodeType.charAt(0).toUpperCase() + node.nodeType.slice(1).replace('-', ' + ');

  const flagBadges = node.flags
    .map((flag) => {
      const flagClass = flag.toLowerCase();
      return `<span class="flag-badge ${flagClass}">${flag}</span>`;
    })
    .join('');

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
        <span class="node-info-value">${escapeHtml(node.ipAddress)}</span>
      </div>
      <div class="node-info-row">
        <span class="node-info-label">OR Port</span>
        <span class="node-info-value">${node.orPort}</span>
      </div>
      <div class="node-info-row">
        <span class="node-info-label">Dir Port</span>
        <span class="node-info-value">${node.dirPort || 'N/A'}</span>
      </div>
    </div>
    
    <div class="node-info-section">
      <h4>Identity</h4>
      <div class="node-info-row">
        <span class="node-info-label">Fingerprint</span>
        <span class="node-info-value" title="${node.fingerprint}">${node.fingerprint.slice(0, 16)}...</span>
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
        <span class="node-info-value">${formatBandwidth(node.bandwidth)}</span>
      </div>
    </div>
    
    <div class="node-info-section">
      <h4>Flags</h4>
      <div class="node-flags">${flagBadges}</div>
    </div>
    
    ${
      node.isSnowflake
        ? `
    <div class="node-info-section">
      <h4>Transport</h4>
      <div class="node-info-row">
        <span class="node-info-label">Snowflake</span>
        <span class="node-info-value" style="color: #06b6d4">✓ Supported</span>
      </div>
    </div>
    `
        : ''
    }
  `;
}

function formatBandwidth(bytes: number): string {
  if (bytes >= 1000000000) return (bytes / 1000000000).toFixed(1) + ' GB/s';
  if (bytes >= 1000000) return (bytes / 1000000).toFixed(1) + ' MB/s';
  if (bytes >= 1000) return (bytes / 1000).toFixed(1) + ' KB/s';
  return bytes + ' B/s';
}

// ============================================
// Tooltip
// ============================================

function showTooltip(event: MouseEvent, node: TorNode): void {
  const tooltip = elements.tooltip;
  const typeLabel =
    node.nodeType.charAt(0).toUpperCase() + node.nodeType.slice(1).replace('-', ' + ');

  tooltip.innerHTML = `
    <div class="tooltip-title">${escapeHtml(node.nickname)}</div>
    <div class="tooltip-subtitle">${typeLabel} • ${node.flags.length} flags</div>
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

function createRandomCircuit(): void {
  const length = parseInt(elements.circuitLength.value, 10);
  const filteredNodes = filterNodes(state.nodes);

  if (filteredNodes.length < length) {
    log(`Not enough nodes (${filteredNodes.length}) to create a ${length}-hop circuit`, 'error');
    return;
  }

  // Select nodes for circuit
  const guards = filteredNodes.filter((n) => n.isGuard);
  const exits = filteredNodes.filter((n) => n.isExit);
  const relays = filteredNodes.filter((n) => !n.isGuard && !n.isExit);

  const circuitNodes: TorNode[] = [];

  // First hop: prefer guard
  if (guards.length > 0) {
    circuitNodes.push(guards[Math.floor(Math.random() * guards.length)]!);
  } else {
    circuitNodes.push(filteredNodes[Math.floor(Math.random() * filteredNodes.length)]!);
  }

  // Middle hops: prefer relays
  const middleCount = length - 2;
  const availableMiddle = [...relays, ...guards].filter((n) => !circuitNodes.includes(n));
  for (let i = 0; i < middleCount && availableMiddle.length > 0; i++) {
    const idx = Math.floor(Math.random() * availableMiddle.length);
    circuitNodes.push(availableMiddle.splice(idx, 1)[0]!);
  }

  // Last hop: prefer exit
  const availableExits = exits.filter((n) => !circuitNodes.includes(n));
  if (availableExits.length > 0) {
    circuitNodes.push(availableExits[Math.floor(Math.random() * availableExits.length)]!);
  } else {
    const remaining = filteredNodes.filter((n) => !circuitNodes.includes(n));
    if (remaining.length > 0) {
      circuitNodes.push(remaining[Math.floor(Math.random() * remaining.length)]!);
    }
  }

  // Create circuit
  const colorIndex = state.circuits.length % CIRCUIT_COLORS.length;
  const circuit: Circuit = {
    id: nextCircuitId++,
    nodes: circuitNodes,
    color: CIRCUIT_COLORS[colorIndex]!,
  };

  state.circuits.push(circuit);

  // Update UI
  renderCircuitList();
  renderGraph();

  const path = circuitNodes.map((n) => n.nickname).join(' → ');
  log(`Created circuit ${circuit.id}: ${path}`, 'success');
}

function removeCircuit(circuitId: number): void {
  const idx = state.circuits.findIndex((c) => c.id === circuitId);
  if (idx !== -1) {
    state.circuits.splice(idx, 1);
    renderCircuitList();
    renderGraph();
    log(`Removed circuit ${circuitId}`, 'info');
  }
}

function clearAllCircuits(): void {
  state.circuits = [];
  renderCircuitList();
  renderGraph();
  log('Cleared all circuits', 'info');
}

function renderCircuitList(): void {
  if (state.circuits.length === 0) {
    elements.circuitList.innerHTML = '<p class="empty-message">No circuits created yet</p>';
    elements.clearCircuitsBtn.disabled = true;
    return;
  }

  elements.clearCircuitsBtn.disabled = false;

  const html = state.circuits
    .map((circuit) => {
      const path = circuit.nodes.map((n) => n.nickname.slice(0, 8)).join(' → ');
      return `
      <div class="circuit-item">
        <span class="circuit-color" style="background: ${circuit.color}"></span>
        <span class="circuit-path" title="${circuit.nodes.map((n) => n.nickname).join(' → ')}">${path}</span>
        <button class="circuit-remove" data-id="${circuit.id}" title="Remove circuit">✕</button>
      </div>
    `;
    })
    .join('');

  elements.circuitList.innerHTML = html;

  // Add remove handlers
  elements.circuitList.querySelectorAll('.circuit-remove').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const id = parseInt((e.target as HTMLElement).dataset.id || '0', 10);
      removeCircuit(id);
    });
  });

  updateStats();
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
  setConnectionStatus('connecting', 'Loading...');

  try {
    state.nodes = await fetchNetworkData();
    state.circuits = [];
    nextCircuitId = 1;

    renderGraph();
    renderCircuitList();

    setConnectionStatus('connected', `${state.nodes.length} nodes loaded`);
    elements.createCircuitBtn.disabled = false;
  } catch (error) {
    setConnectionStatus('error', 'Failed to load');
    log(`Error: ${error instanceof Error ? error.message : error}`, 'error');
  } finally {
    btn.disabled = false;
    btnText.hidden = false;
    btnLoading.hidden = true;
  }
}

function handleNodeLimitChange(): void {
  elements.nodeLimitValue.textContent = `${elements.nodeLimit.value} nodes`;
}

function handlePhysicsChange(): void {
  elements.linkDistanceValue.textContent = elements.linkDistance.value;
  elements.chargeStrengthValue.textContent = elements.chargeStrength.value;

  if (state.simulation) {
    const linkDistance = parseInt(elements.linkDistance.value, 10);
    const chargeStrength = parseInt(elements.chargeStrength.value, 10);

    state.simulation
      .force('link', d3.forceLink<TorNode, TorLink>().distance(linkDistance).strength(0.1))
      .force('charge', d3.forceManyBody().strength(chargeStrength))
      .alpha(0.3)
      .restart();
  }
}

function handleFilterChange(): void {
  if (state.nodes.length > 0) {
    renderGraph();
  }
}

function handleShowLabelsChange(): void {
  if (state.nodes.length > 0) {
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
  elements.createCircuitBtn.addEventListener('click', createRandomCircuit);
  elements.clearCircuitsBtn.addEventListener('click', clearAllCircuits);

  // Event listeners - Physics
  elements.linkDistance.addEventListener('input', handlePhysicsChange);
  elements.chargeStrength.addEventListener('input', handlePhysicsChange);
  elements.showLabels.addEventListener('change', handleShowLabelsChange);

  // Event listeners - Log
  elements.clearLogBtn.addEventListener('click', handleClearLog);

  // Window resize
  window.addEventListener('resize', handleResize);

  // Initial log
  log('Tor Network Visualizer initialized', 'success');
  log('Click "Load Network" to fetch relay data', 'info');
}

// Start the application
init();
