// Tor v3 hidden-service client lifecycle (verified core).
//
// The HSv3 client connects to a hidden service through a 4-stage
// dance (rend-spec-v3.txt §1, §3, §4):
//
//   1. Fetch the service descriptor from an HSDir.
//   2. Send INTRODUCE1 through an introduction-point circuit.
//   3. Wait for the introduction point's INTRODUCE_ACK (success or
//      a numeric failure reason).
//   4. Wait for RENDEZVOUS2 on the rendezvous-point circuit, which
//      carries the server's half of the hs-ntor handshake.
//
// On RENDEZVOUS2 the client computes the shared keys and the
// rendezvous circuit becomes a normal Tor stream-carrying circuit.
//
// Mirrors the lifecycle in `packages/tor/src/hidden-service.ts`. The
// rendezvous-point setup (ESTABLISH_RENDEZVOUS / RENDEZVOUS_ESTABLISHED)
// is folded into the impure shell — the verified core models the
// observable client lifecycle, which the seam drives by parsing cells
// and emitting `HsClientInput` events.

type HsClientState =
  | { kind: 'awaiting_descriptor' }
  | { kind: 'descriptor_ready' }
  | { kind: 'awaiting_introduce_ack' }
  | { kind: 'awaiting_rendezvous2' }
  | { kind: 'open' }
  | { kind: 'closed'; reason: bigint };

type HsClientInput =
  // The HSDir returned a parseable, signature-valid descriptor.
  | { kind: 'descriptor_received' }
  // The descriptor fetch failed (HSDir down, signature bad, etc.).
  | { kind: 'descriptor_fetch_failed'; reason: bigint }
  // The seam built the IP circuit and sent INTRODUCE1 on it.
  | { kind: 'local_send_introduce1' }
  // INTRODUCE_ACK arrived; status 0 = success.
  | { kind: 'recv_introduce_ack_success' }
  // INTRODUCE_ACK arrived with a non-zero status code.
  | { kind: 'recv_introduce_ack_failure'; reason: bigint }
  // RENDEZVOUS2 arrived on the RP circuit with the server's hs-ntor.
  | { kind: 'recv_rendezvous2' }
  // Either circuit was destroyed by a peer.
  | { kind: 'recv_destroy'; reason: bigint }
  // Local close (the application gave up).
  | { kind: 'local_close'; reason: bigint };

const REASON_PROTOCOL_ERROR: bigint = 1n;

// ----------------------------------------------------------------------------
// Per-state helpers.
// ----------------------------------------------------------------------------

/** @total */
function stepFromAwaitingDescriptor(input: HsClientInput): HsClientState {
  switch (input.kind) {
    case 'descriptor_received':
      return { kind: 'descriptor_ready' };
    case 'descriptor_fetch_failed': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_send_introduce1':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_success':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_failure':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_rendezvous2':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromDescriptorReady(input: HsClientInput): HsClientState {
  switch (input.kind) {
    case 'local_send_introduce1':
      return { kind: 'awaiting_introduce_ack' };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'descriptor_received':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'descriptor_fetch_failed':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_success':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_failure':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_rendezvous2':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromAwaitingIntroduceAck(input: HsClientInput): HsClientState {
  switch (input.kind) {
    case 'recv_introduce_ack_success':
      return { kind: 'awaiting_rendezvous2' };
    case 'recv_introduce_ack_failure': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'descriptor_received':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'descriptor_fetch_failed':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_send_introduce1':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_rendezvous2':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromAwaitingRendezvous2(input: HsClientInput): HsClientState {
  switch (input.kind) {
    case 'recv_rendezvous2':
      return { kind: 'open' };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'descriptor_received':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'descriptor_fetch_failed':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_send_introduce1':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_success':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce_ack_failure':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromOpen(input: HsClientInput): HsClientState {
  switch (input.kind) {
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'descriptor_received':
      return { kind: 'open' };
    case 'descriptor_fetch_failed':
      return { kind: 'open' };
    case 'local_send_introduce1':
      return { kind: 'open' };
    case 'recv_introduce_ack_success':
      return { kind: 'open' };
    case 'recv_introduce_ack_failure':
      return { kind: 'open' };
    case 'recv_rendezvous2':
      return { kind: 'open' };
  }
}

// ----------------------------------------------------------------------------
// Top-level step.
// ----------------------------------------------------------------------------

/** @total */
function step(state: HsClientState, input: HsClientInput): HsClientState {
  switch (state.kind) {
    case 'awaiting_descriptor':
      return stepFromAwaitingDescriptor(input);
    case 'descriptor_ready':
      return stepFromDescriptorReady(input);
    case 'awaiting_introduce_ack':
      return stepFromAwaitingIntroduceAck(input);
    case 'awaiting_rendezvous2':
      return stepFromAwaitingRendezvous2(input);
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
function isHandshaking(s: HsClientState): boolean {
  switch (s.kind) {
    case 'awaiting_descriptor':
      return true;
    case 'descriptor_ready':
      return true;
    case 'awaiting_introduce_ack':
      return true;
    case 'awaiting_rendezvous2':
      return true;
    case 'open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isOpen(s: HsClientState): boolean {
  switch (s.kind) {
    case 'open':
      return true;
    case 'awaiting_descriptor':
      return false;
    case 'descriptor_ready':
      return false;
    case 'awaiting_introduce_ack':
      return false;
    case 'awaiting_rendezvous2':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isClosed(s: HsClientState): boolean {
  switch (s.kind) {
    case 'closed':
      return true;
    case 'awaiting_descriptor':
      return false;
    case 'descriptor_ready':
      return false;
    case 'awaiting_introduce_ack':
      return false;
    case 'awaiting_rendezvous2':
      return false;
    case 'open':
      return false;
  }
}
