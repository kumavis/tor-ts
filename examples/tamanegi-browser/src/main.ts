/**
 * TamanegiBrowser - Main Application
 * Uses Snowflake to browse the web through Tor entirely in the browser.
 * Tor client runs in a service worker; this page communicates via postMessage.
 */

import { getConsensusCacheStatus, isOnionAddress } from 'browser';
import type { DownloadProgress, MicrodescProgressCallback } from 'browser';
import type { TorServiceWorkerClient } from './tor-sw-client.ts';
import { registerTorServiceWorker } from './service-worker-client.ts';

// Types
type ViewMode = 'info' | 'browser';
type NodeState = 'waiting' | 'connecting' | 'connected';

// DOM Elements
const urlInput = document.getElementById('url-input') as HTMLInputElement;
const browseBtn = document.getElementById('browse-btn') as HTMLButtonElement;
const btnText = browseBtn.querySelector('.btn-text') as HTMLElement;
const btnLoading = browseBtn.querySelector('.btn-loading') as HTMLElement;
const backBtn = document.getElementById('back-btn') as HTMLButtonElement;
const forwardBtn = document.getElementById('forward-btn') as HTMLButtonElement;
const statusIndicator = document.getElementById('status-indicator') as HTMLElement;
const statusText = document.getElementById('status-text') as HTMLElement;

// Mode tabs
const tabInfo = document.getElementById('tab-info') as HTMLButtonElement;
const tabBrowser = document.getElementById('tab-browser') as HTMLButtonElement;
const modeInfo = document.getElementById('mode-info') as HTMLElement;
const modeBrowser = document.getElementById('mode-browser') as HTMLElement;

// Circuit elements
const circuitStatus = document.getElementById('circuit-status') as HTMLElement;
const snowflakeName = document.getElementById('snowflake-name') as HTMLElement;
const snowflakeStatus = document.getElementById('snowflake-status') as HTMLElement;
const guardName = document.getElementById('guard-name') as HTMLElement;
const guardStatus = document.getElementById('guard-status') as HTMLElement;
const middleName = document.getElementById('middle-name') as HTMLElement;
const middleStatus = document.getElementById('middle-status') as HTMLElement;
const exitName = document.getElementById('exit-name') as HTMLElement;
const exitStatus = document.getElementById('exit-status') as HTMLElement;
const exitLabel = document.getElementById('exit-label') as HTMLElement;
const exitIcon = document.getElementById('exit-icon') as HTMLElement;
const destinationName = document.getElementById('destination-name') as HTMLElement;
const destinationStatus = document.getElementById('destination-status') as HTMLElement;
const destProtocol = document.getElementById('dest-protocol') as HTMLElement;

// Node elements for border styling
const nodeSnowflake = document.getElementById('node-snowflake') as HTMLElement;
const nodeGuard = document.getElementById('node-guard') as HTMLElement;
const nodeMiddle = document.getElementById('node-middle') as HTMLElement;
const nodeExit = document.getElementById('node-exit') as HTMLElement;
const nodeDestination = document.getElementById('node-destination') as HTMLElement;

// Consensus panel
const consensusPanel = document.getElementById('consensus-panel') as HTMLElement;
const consensusTitle = document.getElementById('consensus-title') as HTMLElement;
const consensusStatusText = document.getElementById('consensus-status-text') as HTMLElement;
const consensusCached = document.getElementById('consensus-cached') as HTMLElement;
const consensusDownloading = document.getElementById('consensus-downloading') as HTMLElement;
const cachedStatusBadge = document.getElementById('cached-status-badge') as HTMLElement;
const cachedValidUntil = document.getElementById('cached-valid-until') as HTMLElement;
const consensusRefreshBtn = document.getElementById('consensus-refresh') as HTMLButtonElement;
const progressBar = document.getElementById('progress-bar') as HTMLElement;
const progressBytes = document.getElementById('progress-bytes') as HTMLElement;
const progressSpeed = document.getElementById('progress-speed') as HTMLElement;
const progressEta = document.getElementById('progress-eta') as HTMLElement;

// Log panel
const logContent = document.getElementById('log-content') as HTMLElement;
const logClear = document.getElementById('log-clear') as HTMLButtonElement;

// Browser panel (iframe persists across mode switches)
const contentIframe = document.getElementById('content-iframe') as HTMLIFrameElement;

// Warning banner
const warningBanner = document.getElementById('warning-banner') as HTMLElement;
const warningDismiss = document.getElementById('warning-dismiss') as HTMLButtonElement;

// State
let swClient: TorServiceWorkerClient | null = null;
let connectedPromise: Promise<void> | null = null;
let connectedResolve: (() => void) | null = null;
let isConnecting = false;
let currentPageUrl: URL | null = null;
let linkMap: Map<number, string> = new Map();
let _currentMode: ViewMode = 'info';
let hasLoadedContent = false;
let _isOnionSite = false;

// Navigation history
let historyStack: string[] = [];
let historyIndex = -1;
let isNavigatingHistory = false; // Flag to prevent adding to history during back/forward

// Mode switching - preserves iframe content
function setMode(mode: ViewMode): void {
  _currentMode = mode;

  // Update tabs
  tabInfo.classList.toggle('active', mode === 'info');
  tabBrowser.classList.toggle('active', mode === 'browser');

  // Toggle panels visibility (using hidden attribute, not removing from DOM)
  modeInfo.hidden = mode !== 'info';
  modeBrowser.hidden = mode !== 'browser';
}

// Navigation history management
function updateNavButtons(): void {
  backBtn.disabled = historyIndex <= 0;
  forwardBtn.disabled = historyIndex >= historyStack.length - 1;
}

function addToHistory(url: string): void {
  // Don't add to history if we're navigating via back/forward
  if (isNavigatingHistory) {
    isNavigatingHistory = false;
    return;
  }

  // If we're not at the end of history, truncate forward history
  if (historyIndex < historyStack.length - 1) {
    historyStack = historyStack.slice(0, historyIndex + 1);
  }

  // Add new URL to history
  historyStack.push(url);
  historyIndex = historyStack.length - 1;
  updateNavButtons();
}

function navigateBack(): void {
  if (historyIndex > 0) {
    historyIndex--;
    isNavigatingHistory = true;
    const url = historyStack[historyIndex];
    urlInput.value = url;
    browsePage(url);
    updateNavButtons();
  }
}

function navigateForward(): void {
  if (historyIndex < historyStack.length - 1) {
    historyIndex++;
    isNavigatingHistory = true;
    const url = historyStack[historyIndex];
    urlInput.value = url;
    browsePage(url);
    updateNavButtons();
  }
}

// Logging
function log(message: string, type: 'info' | 'success' | 'error' = 'info'): void {
  const now = new Date();
  const time = now.toLocaleTimeString('en-US', { hour12: false });

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-message ${type}">${escapeHtml(message)}</span>
  `;
  logContent.appendChild(entry);
  logContent.scrollTop = logContent.scrollHeight;
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Status updates
function setStatus(
  status: 'disconnected' | 'connecting' | 'connected' | 'error',
  text: string
): void {
  statusIndicator.className = `status-indicator ${status}`;
  statusText.textContent = text;
}

function setLoading(loading: boolean): void {
  isConnecting = loading;
  browseBtn.disabled = loading;
  btnText.hidden = loading;
  btnLoading.hidden = !loading;
}

// Circuit node updates
function setNodeState(
  nameEl: HTMLElement,
  statusEl: HTMLElement,
  nodeEl: HTMLElement,
  state: NodeState,
  name?: string
): void {
  // Update name
  if (name) {
    nameEl.textContent = name;
  } else if (state === 'waiting') {
    nameEl.textContent = 'Waiting...';
  }

  // Update status indicator
  statusEl.className = 'node-status';
  if (state === 'connected') {
    statusEl.classList.add('connected');
    nodeEl.classList.add('connected');
    nodeEl.classList.remove('connecting');
  } else if (state === 'connecting') {
    statusEl.classList.add('connecting');
    nodeEl.classList.add('connecting');
    nodeEl.classList.remove('connected');
  } else {
    nodeEl.classList.remove('connected', 'connecting');
  }
}

function updateCircuitStatus(text: string): void {
  circuitStatus.textContent = text;
}

/** Reset circuit visualization when the SW reports disconnection. */
function resetCircuitVisualization(): void {
  setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'waiting', 'Waiting...');
  setNodeState(guardName, guardStatus, nodeGuard, 'waiting', 'Waiting...');
  setNodeState(middleName, middleStatus, nodeMiddle, 'waiting', 'Waiting...');
  setNodeState(exitName, exitStatus, nodeExit, 'waiting', 'Waiting...');
  setNodeState(destinationName, destinationStatus, nodeDestination, 'waiting', 'Not set');
  updateCircuitStatus('Not connected');
}

// Update circuit display labels for hidden service vs clearnet mode
function setCircuitMode(mode: 'clearnet' | 'onion'): void {
  if (mode === 'onion') {
    exitLabel.textContent = 'Rendezvous';
    exitIcon.textContent = '🔗';
    nodeExit.classList.add('rendezvous');
    nodeExit.classList.remove('exit');
  } else {
    exitLabel.textContent = 'Exit';
    exitIcon.textContent = '🌐';
    nodeExit.classList.add('exit');
    nodeExit.classList.remove('rendezvous');
  }
}

// Consensus panel state management
type ConsensusState = 'none' | 'cached' | 'downloading';

function setConsensusState(
  state: ConsensusState,
  cacheInfo?: { isFresh?: boolean; validUntil: Date }
): void {
  consensusPanel.classList.remove('cached', 'downloading');
  consensusCached.hidden = true;
  consensusDownloading.hidden = true;

  if (state === 'cached' && cacheInfo) {
    consensusPanel.classList.add('cached');
    consensusTitle.textContent = '📦 Network Consensus';

    // Show "Fresh" if still fresh, "Valid" if past fresh-until but still valid
    if (cacheInfo.isFresh) {
      consensusStatusText.textContent = 'Fresh';
      cachedStatusBadge.textContent = '✓ Fresh';
      cachedStatusBadge.className = 'stat-value cached-badge fresh';
      consensusRefreshBtn.hidden = true;
    } else {
      consensusStatusText.textContent = 'Valid';
      cachedStatusBadge.textContent = '✓ Valid';
      cachedStatusBadge.className = 'stat-value cached-badge valid';
      consensusRefreshBtn.hidden = false; // Show refresh button when stale
    }

    consensusCached.hidden = false;
    cachedValidUntil.textContent = formatDateTime(cacheInfo.validUntil);
  } else if (state === 'downloading') {
    consensusPanel.classList.add('downloading');
    consensusTitle.textContent = '📥 Downloading Consensus';
    consensusStatusText.textContent = 'In progress...';
    consensusDownloading.hidden = false;
  } else {
    consensusTitle.textContent = '📦 Network Consensus';
    consensusStatusText.textContent = 'Not loaded';
  }
}

function formatDateTime(date: Date): string {
  return (
    date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }) +
    ' ' +
    date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    })
  );
}

// Check and display cached consensus status on startup
function checkCachedConsensus(): void {
  const status = getConsensusCacheStatus();
  if (status.cached && status.validUntil) {
    setConsensusState('cached', {
      isFresh: status.isFresh,
      validUntil: status.validUntil,
    });
  } else {
    setConsensusState('none');
  }
}

// Format bytes to human-readable string
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// Format milliseconds to human-readable time
function formatTime(ms: number): string {
  if (ms < 1000) return 'less than 1s';
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

// Update consensus download progress UI
function updateConsensusProgress(progress: DownloadProgress): void {
  setConsensusState('downloading');

  // Update progress bar
  // Consensus is typically ~3.35MB, use that as estimate if not provided
  const estimatedTotal = progress.estimatedTotalBytes ?? 3.35 * 1024 * 1024;
  const percent = Math.min((progress.bytesReceived / estimatedTotal) * 100, 100);
  progressBar.style.width = `${percent}%`;

  // Update stats
  progressBytes.textContent = formatBytes(progress.bytesReceived);
  progressSpeed.textContent = `${formatBytes(progress.speedBytesPerSec)}/s`;
  consensusStatusText.textContent = `${Math.round(percent)}%`;

  if (progress.estimatedRemainingMs !== null && progress.estimatedRemainingMs > 0) {
    progressEta.textContent = formatTime(progress.estimatedRemainingMs);
  } else if (progress.speedBytesPerSec > 0) {
    // Calculate our own ETA if not provided
    const remainingBytes = estimatedTotal - progress.bytesReceived;
    const etaMs = (remainingBytes / progress.speedBytesPerSec) * 1000;
    progressEta.textContent = etaMs > 0 ? formatTime(etaMs) : 'Almost done...';
  } else {
    progressEta.textContent = 'Calculating...';
  }
}

// Microdesc progress tracking state
let microdescProgressState: {
  startTime: number;
  startFetched: number;
  lastFetched: number;
  lastTime: number;
  speedItemsPerSec: number;
} | null = null;

// Update microdescriptor download progress UI (shown when navigating to .onion)
function updateMicrodescProgress(progress: Parameters<MicrodescProgressCallback>[0]): void {
  const { fetched, total, cached } = progress;

  // Skip if nothing to show
  if (total === 0 && cached === 0) return;

  const now = Date.now();

  // Initialize or reset tracking state
  if (!microdescProgressState || fetched < microdescProgressState.lastFetched) {
    microdescProgressState = {
      startTime: now,
      startFetched: fetched,
      lastFetched: fetched,
      lastTime: now,
      speedItemsPerSec: 0,
    };
  }

  // Calculate speed (exponential moving average for smoothing)
  const timeDelta = now - microdescProgressState.lastTime;
  if (timeDelta > 100) {
    // Update at least every 100ms
    const itemsDelta = fetched - microdescProgressState.lastFetched;
    const instantSpeed = timeDelta > 0 ? (itemsDelta / timeDelta) * 1000 : 0;

    // Smooth the speed with EMA (alpha = 0.3)
    microdescProgressState.speedItemsPerSec =
      microdescProgressState.speedItemsPerSec * 0.7 + instantSpeed * 0.3;

    microdescProgressState.lastFetched = fetched;
    microdescProgressState.lastTime = now;
  }

  // Show the progress in the consensus panel (reusing it for microdesc downloads)
  consensusPanel.classList.remove('cached');
  consensusPanel.classList.add('downloading');
  consensusTitle.textContent = '📥 Downloading Relay Info';
  consensusCached.hidden = true;
  consensusDownloading.hidden = false;

  const totalItems = total + cached;
  const doneItems = fetched + cached;
  const percent = totalItems > 0 ? Math.min((doneItems / totalItems) * 100, 100) : 100;

  // Update progress bar
  progressBar.style.width = `${percent}%`;

  // Update stats
  progressBytes.textContent = `${doneItems.toLocaleString()} / ${totalItems.toLocaleString()}`;
  consensusStatusText.textContent = `${Math.round(percent)}%`;

  // Speed display
  const speed = microdescProgressState.speedItemsPerSec;
  if (speed > 0) {
    progressSpeed.textContent = `${Math.round(speed)} relays/s`;
  } else if (cached > 0) {
    progressSpeed.textContent = `${cached.toLocaleString()} cached`;
  } else {
    progressSpeed.textContent = 'Starting...';
  }

  // ETA calculation
  const remaining = total - fetched;
  if (remaining <= 0) {
    progressEta.textContent = 'Done!';
    microdescProgressState = null; // Reset for next download
  } else if (speed > 0) {
    const etaMs = (remaining / speed) * 1000;
    progressEta.textContent = formatTime(etaMs);
  } else {
    progressEta.textContent = 'Calculating...';
  }
}

// Update consensus panel to show cached state after download completes
function showConsensusCached(): void {
  const status = getConsensusCacheStatus();
  if (status.cached && status.validUntil) {
    setConsensusState('cached', {
      isFresh: status.isFresh,
      validUntil: status.validUntil,
    });
  }
}

// Parse status messages to update circuit display
function parseStatusMessage(status: string): void {
  // Snowflake connection
  if (status.includes('Connecting to Snowflake relay')) {
    setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connecting', 'Connecting...');
    updateCircuitStatus('Connecting to Snowflake...');
  }

  // Bootstrap circuit (1-hop to guard via Snowflake)
  if (status.includes('Building bootstrap circuit')) {
    setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connected', 'Connected');
    setNodeState(guardName, guardStatus, nodeGuard, 'connecting', 'Bootstrap...');
    updateCircuitStatus('Building bootstrap circuit...');
  }

  // Consensus - either cached or downloading
  if (status.includes('Using cached network consensus')) {
    setNodeState(guardName, guardStatus, nodeGuard, 'connected', 'Guard');
    updateCircuitStatus('Using cached consensus');
    showConsensusCached();
  } else if (status.includes('Downloading network consensus')) {
    setNodeState(guardName, guardStatus, nodeGuard, 'connected', 'Guard');
    setConsensusState('downloading');
    updateCircuitStatus('Downloading consensus...');
  }

  // Node selection - extract and display nicknames
  const middleMatch = status.match(/Selected middle node: (.+)/);
  if (middleMatch) {
    setNodeState(middleName, middleStatus, nodeMiddle, 'waiting', middleMatch[1]);
    updateCircuitStatus('Selecting relays...');
  }

  const exitMatch = status.match(/Selected exit node: (.+)/);
  if (exitMatch) {
    setNodeState(exitName, exitStatus, nodeExit, 'waiting', exitMatch[1]);
  }

  // Looking up descriptors
  if (status.includes('Looking up relay descriptors')) {
    updateCircuitStatus('Looking up descriptors...');
  }

  // Building full 3-hop circuit
  if (status.includes('Building full 3-hop circuit')) {
    setNodeState(middleName, middleStatus, nodeMiddle, 'connecting');
    setNodeState(exitName, exitStatus, nodeExit, 'connecting');
    updateCircuitStatus('Building circuit...');
  }

  // Circuit complete
  if (status.includes('Circuit established')) {
    setNodeState(middleName, middleStatus, nodeMiddle, 'connected');
    setNodeState(exitName, exitStatus, nodeExit, 'connected');
    updateCircuitStatus('Circuit ready');
  }
}

// Wait for the service worker Tor client to be connected (connects if needed)
async function getClient(): Promise<void> {
  if (connectedPromise) {
    return connectedPromise;
  }

  if (!swClient) {
    throw new Error('Service worker not ready');
  }

  setStatus('connecting', 'Connecting...');
  log('Initializing Tor connection via Snowflake...', 'info');
  updateCircuitStatus('Initializing...');

  connectedPromise = new Promise<void>((resolve) => {
    connectedResolve = resolve;
  });

  swClient.connect();
  return connectedPromise;
}

// Fetch and display page
async function browsePage(url: string): Promise<void> {
  if (isConnecting) return;

  // Validate URL
  let parsedUrl: URL;
  try {
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      // Check if it looks like an onion address (before we have a full URL)
      const looksLikeOnion = url.split('/')[0]?.endsWith('.onion');
      // Default to HTTP for onion (Tor provides encryption), HTTPS for clearnet
      url = (looksLikeOnion ? 'http://' : 'https://') + url;
    }
    parsedUrl = new URL(url);

    // For .onion addresses with explicit https, warn that many don't support it
    const isOnion = isOnionAddress(parsedUrl.hostname);
    if (isOnion && parsedUrl.protocol === 'https:') {
      log('Note: Using HTTPS for .onion (some sites may only support HTTP)', 'info');
    }
  } catch {
    log(`Invalid URL: ${url}`, 'error');
    return;
  }

  setLoading(true);
  const isOnion = isOnionAddress(parsedUrl.hostname);
  _isOnionSite = isOnion;

  // Update circuit display mode
  setCircuitMode(isOnion ? 'onion' : 'clearnet');

  if (isOnion) {
    log(`Connecting to hidden service: ${parsedUrl.hostname}`, 'info');
  } else {
    log(`Fetching: ${parsedUrl.href}`, 'info');
  }

  // Update destination in circuit display
  destinationName.textContent = parsedUrl.hostname;
  destProtocol.textContent = isOnion ? 'Onion' : parsedUrl.protocol === 'https:' ? 'HTTPS' : 'HTTP';
  setNodeState(
    destinationName,
    destinationStatus,
    nodeDestination,
    'connecting',
    parsedUrl.hostname
  );

  try {
    // Ensure SW Tor client is connected
    await getClient();

    // Update UI for onion sites (HS connection takes time)
    if (isOnion) {
      updateCircuitStatus('Connecting to hidden service...');
      setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connected', 'Connected');
      setNodeState(guardName, guardStatus, nodeGuard, 'connecting', 'Connecting...');
      setNodeState(middleName, middleStatus, nodeMiddle, 'waiting', 'Waiting...');
      setNodeState(exitName, exitStatus, nodeExit, 'waiting', 'Rendezvous');
    }

    log('Sending request through Tor...', 'info');

    // Unified fetch via service worker (clearnet and onion)
    const timeout = isOnion ? 120000 : 60000;
    const result = await swClient!.fetch(parsedUrl.href, { timeout });
    const html = result.html;

    // Update UI after successful fetch
    if (isOnion) {
      setStatus('connected', 'Connected (Onion)');
      setNodeState(guardName, guardStatus, nodeGuard, 'connected', 'Guard');
      setNodeState(middleName, middleStatus, nodeMiddle, 'connected', 'Middle');
      setNodeState(exitName, exitStatus, nodeExit, 'connected', 'Rendezvous');
      updateCircuitStatus('Hidden service connected');
    }

    log(`Received ${html.length} bytes`, 'success');

    // Mark destination as connected
    setNodeState(
      destinationName,
      destinationStatus,
      nodeDestination,
      'connected',
      parsedUrl.hostname
    );

    // Display in iframe using srcdoc
    displayContent(parsedUrl.href, html);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`Error: ${message}`, 'error');
    setStatus('error', 'Error');
    setNodeState(destinationName, destinationStatus, nodeDestination, 'waiting', 'Failed');
  } finally {
    setLoading(false);
  }
}

// Parse hidden service status messages
// TODO: this needs to be wired up again
function _parseHsStatusMessage(status: string): void {
  if (status.includes('Connecting to Snowflake')) {
    setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connecting', 'Connecting...');
    updateCircuitStatus('Connecting to Snowflake...');
  }

  if (status.includes('Building bootstrap circuit')) {
    setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connected', 'Connected');
    setNodeState(guardName, guardStatus, nodeGuard, 'connecting', 'Bootstrap...');
    updateCircuitStatus('Building bootstrap circuit...');
  }

  if (status.includes('Using cached network consensus')) {
    setNodeState(guardName, guardStatus, nodeGuard, 'connected', 'Guard');
    updateCircuitStatus('Using cached consensus');
    showConsensusCached();
  }

  if (status.includes('Downloading network consensus')) {
    setNodeState(guardName, guardStatus, nodeGuard, 'connected', 'Guard');
    setConsensusState('downloading');
    updateCircuitStatus('Downloading consensus...');
  }

  if (status.includes('Locating hidden service directory')) {
    updateCircuitStatus('Locating HSDir nodes...');
  }

  if (status.includes('Fetching hidden service descriptor')) {
    updateCircuitStatus('Fetching HS descriptor...');
  }

  if (status.includes('Decrypting hidden service descriptor')) {
    updateCircuitStatus('Decrypting descriptor...');
  }

  if (status.includes('Building rendezvous circuit')) {
    setNodeState(middleName, middleStatus, nodeMiddle, 'connecting', 'Building...');
    updateCircuitStatus('Building rendezvous circuit...');
  }

  if (status.includes('Establishing rendezvous point')) {
    setNodeState(middleName, middleStatus, nodeMiddle, 'connected', 'Middle');
    setNodeState(exitName, exitStatus, nodeExit, 'connecting', 'Rendezvous');
    updateCircuitStatus('Establishing rendezvous...');
  }

  if (status.includes('Building introduction circuit')) {
    updateCircuitStatus('Building intro circuit...');
  }

  if (status.includes('Sending introduction')) {
    updateCircuitStatus('Sending introduction...');
  }

  if (status.includes('Waiting for rendezvous completion')) {
    updateCircuitStatus('Waiting for rendezvous...');
  }

  if (status.includes('Connected to hidden service')) {
    setNodeState(exitName, exitStatus, nodeExit, 'connected', 'Rendezvous');
    updateCircuitStatus('Hidden service connected');
  }
}

function displayContent(url: string, html: string): void {
  // Update URL bar with current page URL
  urlInput.value = url;

  // Parse the URL for resolving relative links
  currentPageUrl = new URL(url);

  // Sanitize HTML: inject CSP to block external resources, rewrite links for interception
  const sanitized = sanitizeHtml(html, currentPageUrl);
  linkMap = sanitized.links;

  // Set the iframe content
  contentIframe.srcdoc = sanitized.html;

  // Attach click handler after iframe loads to intercept link clicks.
  // This works because sandbox="allow-same-origin" lets us access contentDocument.
  // Scripts are NOT enabled, so this is safe - we're just adding our own handler.
  contentIframe.onload = () => {
    attachLinkHandler();
  };

  hasLoadedContent = true;
  log(`Content displayed (${linkMap.size} links found)`, 'success');

  // Add to navigation history
  addToHistory(url);

  // Switch to browser mode on successful content load
  setMode('browser');
}

function attachLinkHandler(): void {
  const doc = contentIframe.contentDocument;
  if (!doc) {
    log('Warning: Could not access iframe document for link interception', 'error');
    return;
  }

  // Listen for clicks on the iframe document.
  // Since allow-scripts is not set, inline onclick handlers in the HTML won't work,
  // but our handler attached from the parent WILL fire.
  doc.addEventListener(
    'click',
    (e: MouseEvent) => {
      const target = e.target as Element;
      const link = target.closest('a[href^="#tor-link-"]');

      if (link) {
        e.preventDefault();
        e.stopPropagation();

        const href = link.getAttribute('href');
        if (!href) return;

        const match = href.match(/^#tor-link-(\d+)$/);
        if (!match) return;

        const index = parseInt(match[1], 10);
        const targetUrl = linkMap.get(index);

        if (targetUrl) {
          log(`Link clicked: ${targetUrl}`, 'info');
          // Update the URL input and fetch via Tor
          urlInput.value = targetUrl;
          browsePage(targetUrl);
        }
      }
    },
    true // Use capture phase to intercept before any default behavior
  );
}

function sanitizeHtml(html: string, baseUrl: URL): { html: string; links: Map<number, string> } {
  // Content Security Policy to block ALL external resources.
  // This prevents the iframe from making any network requests that would bypass Tor.
  // - default-src 'none': Block everything by default
  // - style-src 'unsafe-inline': Allow inline styles so pages render
  // - img-src 'none': Block all images (they would leak requests outside Tor)
  // - font-src 'none': Block all fonts
  // - connect-src 'none': Block fetch/XHR (redundant without scripts, but explicit)
  // - frame-src 'none': Block nested iframes
  // - media-src 'none': Block audio/video
  // - object-src 'none': Block plugins/embeds
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">`;

  // Rewrite all links to hash-based navigation and build a link map.
  // This allows us to intercept clicks from the parent and fetch via Tor.
  const links = new Map<number, string>();
  let linkIndex = 0;

  // More robust regex that handles:
  // - href as first attribute or with preceding attributes
  // - Single quotes, double quotes, or no quotes around href value
  // - Newlines and whitespace within the tag
  // - Various attribute orderings
  let result = html.replace(
    /<a\s([^>]*?\s)?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))([^>]*)>/gi,
    (match, before = '', hrefDouble, hrefSingle, hrefUnquoted, after = '') => {
      const href = hrefDouble ?? hrefSingle ?? hrefUnquoted ?? '';

      // Skip empty hrefs, javascript:, and anchor-only links
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) {
        return match;
      }

      // Resolve relative URLs against the base URL
      let absoluteUrl: string;
      try {
        absoluteUrl = new URL(href, baseUrl).href;
      } catch {
        // Invalid URL, leave as-is but make unclickable
        return `<a ${before}href="#"${after}>`;
      }

      const index = linkIndex++;
      links.set(index, absoluteUrl);

      // Replace href with hash link for interception
      return `<a ${before}href="#tor-link-${index}" data-tor-href="${escapeAttr(absoluteUrl)}"${after}>`;
    }
  );

  // Inject CSP at the very beginning of <head> (must be before any resource loads)
  if (result.includes('<head')) {
    result = result.replace(/<head([^>]*)>/i, `<head$1>${csp}`);
  } else if (result.includes('<html')) {
    result = result.replace(/<html([^>]*)>/i, `<html$1><head>${csp}</head>`);
  } else {
    // No html structure, prepend CSP
    result = `<head>${csp}</head>${result}`;
  }

  return { html: result, links };
}

function escapeAttr(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function clearLog(): void {
  logContent.innerHTML = '';
}

// Event listeners
browseBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (url) {
    browsePage(url);
  }
});

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const url = urlInput.value.trim();
    if (url) {
      browsePage(url);
    }
  }
});

// Mode tab clicks
tabInfo.addEventListener('click', () => setMode('info'));
tabBrowser.addEventListener('click', () => {
  // Only switch to browser mode if content has been loaded
  if (hasLoadedContent) {
    setMode('browser');
  }
});

// Navigation buttons
backBtn.addEventListener('click', navigateBack);
forwardBtn.addEventListener('click', navigateForward);

logClear.addEventListener('click', clearLog);
warningDismiss.addEventListener('click', () => {
  warningBanner.hidden = true;
});

// Consensus refresh button - asks service worker to refresh consensus
consensusRefreshBtn.addEventListener('click', () => {
  if (isConnecting || !swClient) return;

  log('Refreshing consensus...', 'info');
  setStatus('connecting', 'Refreshing...');
  updateCircuitStatus('Refreshing consensus...');
  setLoading(true);

  swClient.refreshConsensus();

  // Stop loading after a delay (SW does not send a dedicated "refreshed" message)
  setTimeout(() => {
    setLoading(false);
    setStatus('connected', 'Connected');
    updateCircuitStatus('Client ready');
  }, 8000);
});

// Initialize consensus panel state (check if we have a cached consensus)
checkCachedConsensus();

// Initial log
log('TamanegiBrowser ready. Enter a URL to browse anonymously.', 'info');
log('Supports both clearnet and .onion addresses.', 'info');
log('Powered by Snowflake pluggable transport.', 'info');

// Service worker registration and Tor client proxy setup
async function initServiceWorker(): Promise<void> {
  // Dev: SW is served at /src/sw.ts. Production/GitHub Pages: SW at {base}sw.js so scope can match base.
  const base = import.meta.env.BASE_URL;
  const scope = base.endsWith('/') ? base : base + '/';
  const swUrl = import.meta.env.DEV
    ? new URL('./sw.ts', import.meta.url).href
    : `${base}sw.js`;
  const client = await registerTorServiceWorker(swUrl, { scope });

  if (!client) {
    log('Service worker not available', 'error');
    return;
  }

  swClient = client;

  swClient.onStatus = (message) => {
    log(message, 'info');
    parseStatusMessage(message);
  };
  swClient.onConsensusProgress = updateConsensusProgress;
  swClient.onMicrodescProgress = updateMicrodescProgress;
  swClient.onConnected = () => {
    if (connectedResolve) {
      connectedResolve();
      connectedResolve = null;
    }
    showConsensusCached();
    setStatus('connected', 'Connected');
    log('Successfully connected to Tor network!', 'success');
    setNodeState(snowflakeName, snowflakeStatus, nodeSnowflake, 'connected');
    setNodeState(guardName, guardStatus, nodeGuard, 'connected');
    setNodeState(middleName, middleStatus, nodeMiddle, 'connected');
    setNodeState(exitName, exitStatus, nodeExit, 'connected');
    updateCircuitStatus('Client ready');
  };
  swClient.onDisconnected = (reason) => {
    connectedPromise = null;
    connectedResolve = null;
    resetCircuitVisualization();
    setStatus('disconnected', 'Disconnected');
    log(`Circuit closed: ${reason}`, 'info');
  };
  swClient.onError = (error) => {
    log(`Error: ${error}`, 'error');
    setStatus('error', 'Error');
  };
}

void initServiceWorker();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  swClient?.destroy();
});
