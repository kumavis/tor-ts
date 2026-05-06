// Tor stream lifecycle state machine (verified core).
//
// Each stream within a circuit has its own state independent of the
// circuit it travels on. A stream is opened by the client sending a
// BEGIN cell (TCP connection) or RESOLVE cell (DNS lookup); the exit
// answers with CONNECTED / RESOLVED on success or END with a reason
// on failure. While open, the two endpoints exchange DATA cells
// freely. Either side can tear down the stream by sending END.
//
// Spec source: tor-spec.txt §6.1 (streams), §6.4 (RELAY_RESOLVED).
//
// This module models the lifecycle as a 5-state DU. Like the channel
// and circuit modules, the seam adapter parses cells using the
// already-verified primitives in core and feeds the resulting
// StreamInput to `step`. The same shape constraints (helper
// functions per state, const-bind before DU construction) apply.

type StreamState =
  | { kind: 'init' }
  | { kind: 'awaiting_connected' }
  | { kind: 'awaiting_resolved' }
  // RESOLVED has been received; the spec follows it with a RELAY_END
  // (typically REASON_DONE) before the stream is fully closed. Real
  // tor-ts code waits for that END rather than tearing down on
  // RESOLVED alone, so we model that explicitly: this is a "received
  // the answer, awaiting the formal close" phase that accepts END
  // (or local close) and rejects everything else.
  | { kind: 'resolved' }
  | { kind: 'open' }
  | { kind: 'closed'; reason: bigint };

type StreamInput =
  | { kind: 'local_begin' } //     client sent BEGIN
  | { kind: 'local_resolve' } //   client sent RESOLVE
  | { kind: 'recv_connected' } //  exit replied CONNECTED
  | { kind: 'recv_resolved' } //   exit replied RESOLVED
  | { kind: 'recv_data' } //       exit / client DATA cell
  | { kind: 'recv_end'; reason: bigint }
  | { kind: 'local_close'; reason: bigint };

/** Reason code used when an unexpected cell arrives for the current phase. */
const REASON_PROTOCOL_ERROR: bigint = 1n;

/** Reason recorded when a RESOLVE round-trip completes successfully. */
const REASON_DNS_DONE: bigint = 6n; // matches REASON_DONE in relayEndReason

// ----------------------------------------------------------------------------
// Per-state transition helpers.
// ----------------------------------------------------------------------------

/** @total */
function stepFromInit(input: StreamInput): StreamState {
  switch (input.kind) {
    case 'local_begin':
      return { kind: 'awaiting_connected' };
    case 'local_resolve':
      return { kind: 'awaiting_resolved' };
    case 'recv_connected':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_resolved':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_data':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_end': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
  }
}

/** @total */
function stepFromAwaitingConnected(input: StreamInput): StreamState {
  switch (input.kind) {
    case 'recv_connected':
      return { kind: 'open' };
    case 'recv_end': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_begin':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_resolve':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_resolved':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_data':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromAwaitingResolved(input: StreamInput): StreamState {
  switch (input.kind) {
    case 'recv_resolved':
      // RESOLVED moves us into `resolved`, where we wait for the
      // RELAY_END that the spec says always follows. We do NOT tear
      // down here, because real Tor exits send the END separately
      // and the stream is only formally closed after that END is
      // observed.
      return { kind: 'resolved' };
    case 'recv_end': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_begin':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_resolve':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_connected':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_data':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/**
 * After RELAY_RESOLVED, the stream is in `resolved` and the only
 * spec-correct next inputs are the follow-up RELAY_END from the exit
 * or a local close. Anything else is a protocol error.
 */
/** @total */
function stepFromResolved(input: StreamInput): StreamState {
  switch (input.kind) {
    case 'recv_end': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_begin':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_resolve':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_connected':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_resolved':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_data':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromOpen(input: StreamInput): StreamState {
  switch (input.kind) {
    case 'recv_data':
      // Data cells leave the state unchanged — the byte transfer is
      // outside the lifecycle layer.
      return { kind: 'open' };
    case 'recv_end': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_begin':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_resolve':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_connected':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_resolved':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

// ----------------------------------------------------------------------------
// Top-level step.
// ----------------------------------------------------------------------------

/** @total */
function step(state: StreamState, input: StreamInput): StreamState {
  switch (state.kind) {
    case 'init':
      return stepFromInit(input);
    case 'awaiting_connected':
      return stepFromAwaitingConnected(input);
    case 'awaiting_resolved':
      return stepFromAwaitingResolved(input);
    case 'resolved':
      return stepFromResolved(input);
    case 'open':
      return stepFromOpen(input);
    case 'closed':
      return state;
  }
}

// ----------------------------------------------------------------------------
// Phase predicates.
// ----------------------------------------------------------------------------

/** @total */
function isInit(s: StreamState): boolean {
  switch (s.kind) {
    case 'init':
      return true;
    case 'awaiting_connected':
      return false;
    case 'awaiting_resolved':
      return false;
    case 'resolved':
      return false;
    case 'open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isAwaiting(s: StreamState): boolean {
  switch (s.kind) {
    case 'awaiting_connected':
      return true;
    case 'awaiting_resolved':
      return true;
    case 'init':
      return false;
    case 'resolved':
      return false;
    case 'open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isResolved(s: StreamState): boolean {
  switch (s.kind) {
    case 'resolved':
      return true;
    case 'init':
      return false;
    case 'awaiting_connected':
      return false;
    case 'awaiting_resolved':
      return false;
    case 'open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isOpen(s: StreamState): boolean {
  switch (s.kind) {
    case 'open':
      return true;
    case 'init':
      return false;
    case 'awaiting_connected':
      return false;
    case 'awaiting_resolved':
      return false;
    case 'resolved':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isClosed(s: StreamState): boolean {
  switch (s.kind) {
    case 'closed':
      return true;
    case 'init':
      return false;
    case 'awaiting_connected':
      return false;
    case 'awaiting_resolved':
      return false;
    case 'resolved':
      return false;
    case 'open':
      return false;
  }
}
