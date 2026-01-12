/**
 * Tor Browser-in-Browser - Main Application
 * Uses Snowflake to browse the web through Tor entirely in the browser.
 */

import { connectBrowserCircuit, fetchHtml } from 'browser';
import type { BrowserCircuit, DownloadProgress } from 'browser';

// DOM Elements
const urlInput = document.getElementById('url-input') as HTMLInputElement;
const browseBtn = document.getElementById('browse-btn') as HTMLButtonElement;
const btnText = browseBtn.querySelector('.btn-text') as HTMLElement;
const btnLoading = browseBtn.querySelector('.btn-loading') as HTMLElement;
const statusIndicator = document.getElementById('status-indicator') as HTMLElement;
const statusText = document.getElementById('status-text') as HTMLElement;
const consensusPanel = document.getElementById('consensus-panel') as HTMLElement;
const progressBar = document.getElementById('progress-bar') as HTMLElement;
const progressBytes = document.getElementById('progress-bytes') as HTMLElement;
const progressSpeed = document.getElementById('progress-speed') as HTMLElement;
const progressEta = document.getElementById('progress-eta') as HTMLElement;
const circuitPanel = document.getElementById('circuit-panel') as HTMLElement;
const _middleNode = document
  .getElementById('middle-node')
  ?.querySelector('.node-label') as HTMLElement;
const _exitNode = document.getElementById('exit-node')?.querySelector('.node-label') as HTMLElement;
const destinationNode = document
  .getElementById('destination-node')
  ?.querySelector('.node-label') as HTMLElement;
const logContent = document.getElementById('log-content') as HTMLElement;
const logClear = document.getElementById('log-clear') as HTMLButtonElement;
const contentPanel = document.getElementById('content-panel') as HTMLElement;
const contentUrl = document.getElementById('content-url') as HTMLElement;
const contentClose = document.getElementById('content-close') as HTMLButtonElement;
const contentIframe = document.getElementById('content-iframe') as HTMLIFrameElement;

// State
let currentCircuit: BrowserCircuit | null = null;
let isConnecting = false;

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
  consensusPanel.hidden = false;

  // Update progress bar
  // Consensus is typically ~3.35MB, use that as estimate if not provided
  const estimatedTotal = progress.estimatedTotalBytes ?? 3.35 * 1024 * 1024;
  const percent = Math.min((progress.bytesReceived / estimatedTotal) * 100, 100);
  progressBar.style.width = `${percent}%`;

  // Update stats
  progressBytes.textContent = formatBytes(progress.bytesReceived);
  progressSpeed.textContent = `${formatBytes(progress.speedBytesPerSec)}/s`;

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

// Hide consensus panel
function hideConsensusProgress(): void {
  consensusPanel.hidden = true;
}

// Circuit connection
async function connectToTor(): Promise<BrowserCircuit> {
  if (currentCircuit) {
    return currentCircuit;
  }

  setStatus('connecting', 'Connecting...');
  log('Initializing Tor connection via Snowflake...', 'info');

  const circuit = await connectBrowserCircuit({
    onStatus: (status) => {
      log(status, 'info');
      // Show consensus panel when starting download
      if (status.includes('Downloading network consensus')) {
        consensusPanel.hidden = false;
      }
    },
    onConsensusProgress: (progress) => {
      updateConsensusProgress(progress);
    },
    // TODO: Browser signature verification not yet fully implemented
    // (Web Crypto API doesn't support Tor's unprefixed PKCS#1 v1.5 signatures)
    dangerouslySkipSignatureVerification: true,
  });

  // Hide consensus panel, show circuit panel
  hideConsensusProgress();
  currentCircuit = circuit;
  setStatus('connected', 'Connected');
  log('Successfully connected to Tor network!', 'success');

  // Show circuit panel
  circuitPanel.hidden = false;

  return circuit;
}

// Fetch and display page
async function browsePage(url: string): Promise<void> {
  if (isConnecting) return;

  // Validate URL
  let parsedUrl: URL;
  try {
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    parsedUrl = new URL(url);
  } catch {
    log(`Invalid URL: ${url}`, 'error');
    return;
  }

  setLoading(true);
  log(`Fetching: ${parsedUrl.href}`, 'info');

  try {
    // Connect if not already connected
    const { circuit } = await connectToTor();

    // Update destination in circuit display
    destinationNode.textContent = parsedUrl.hostname;

    // Fetch the page with timeout
    log('Sending request through Tor circuit...', 'info');

    // Add a race with timeout for better error reporting
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Request timeout after 60s')), 60000);
    });

    const html = await Promise.race([fetchHtml(circuit, parsedUrl.href), timeoutPromise]);

    log(`Received ${html.length} bytes`, 'success');

    // Display in iframe using srcdoc
    displayContent(parsedUrl.href, html);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`Error: ${message}`, 'error');
    setStatus('error', 'Error');

    // Reset circuit on error
    if (currentCircuit) {
      currentCircuit.destroy();
      currentCircuit = null;
    }
  } finally {
    setLoading(false);
  }
}

function displayContent(url: string, html: string): void {
  contentUrl.textContent = url;

  // Inject HTML into iframe using srcdoc
  // Note: This won't load external resources (images, CSS, JS) correctly
  // as they would need to be fetched through Tor too
  const sanitizedHtml = sanitizeHtml(html);
  contentIframe.srcdoc = sanitizedHtml;

  contentPanel.hidden = false;
  log('Content displayed in iframe', 'success');
}

function sanitizeHtml(html: string): string {
  // Add base tag to help with relative URLs (won't work for external resources)
  // Add a notice about limited functionality
  const notice = `
    <div style="
      background: #1a1a2e; 
      color: #eee; 
      padding: 12px 20px; 
      font-family: system-ui, sans-serif;
      font-size: 13px;
      border-bottom: 1px solid #333;
      position: sticky;
      top: 0;
      z-index: 9999;
    ">
      ⚠️ <strong>Note:</strong> This page was fetched through Tor. 
      External resources (images, CSS, JS) may not load as they require additional Tor requests.
    </div>
  `;

  // Insert notice at the beginning of body or html
  if (html.includes('<body')) {
    return html.replace(/<body([^>]*)>/i, `<body$1>${notice}`);
  } else if (html.includes('<html')) {
    return html.replace(/<html([^>]*)>/i, `<html$1>${notice}`);
  } else {
    return notice + html;
  }
}

function closeContent(): void {
  contentPanel.hidden = true;
  contentIframe.srcdoc = '';
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

contentClose.addEventListener('click', closeContent);
logClear.addEventListener('click', clearLog);

// Initial log
log('Tor Browser-in-Browser ready. Enter a URL to browse anonymously.', 'info');
log('Powered by Snowflake pluggable transport.', 'info');

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  if (currentCircuit) {
    currentCircuit.destroy();
  }
});
