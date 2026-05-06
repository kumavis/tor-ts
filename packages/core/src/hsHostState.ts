// Tor v3 hidden-service host (server) lifecycle (verified core).
//
// The HSv3 host's per-introduction-circuit dance (rend-spec-v3.txt
// §3, §4):
//
//   1. The host opens an introduction-point circuit and sends
//      ESTABLISH_INTRO with its long-term IPT auth key.
//   2. The introduction point answers with INTRO_ESTABLISHED.
//   3. The introduction point now silently forwards INTRODUCE2
//      cells from clients. For each one:
//      a. The host decrypts the inner INTRODUCE1 payload.
//      b. The host opens a rendezvous-point circuit to the cookie
//         the client supplied.
//      c. The host sends RENDEZVOUS1 (carrying the server's
//         hs-ntor handshake half) on the rendezvous circuit.
//   4. The rendezvous circuit becomes a normal stream-carrying
//      circuit serving that client.
//
// This module models the per-introduction-point lifecycle. A single
// host typically maintains several introduction points and many
// rendezvous circuits; verifying each individual lifecycle is the
// natural unit. The seam adapter parses cells and dispatches per-IPT
// `HsHostInput` events.

type HsHostState =
  | { kind: 'awaiting_intro_established' }
  // ESTABLISH_INTRO sent, INTRO_ESTABLISHED received → ready for INTRODUCE2
  | { kind: 'intro_open' }
  // INTRODUCE2 received and decrypted; opening the rendezvous circuit
  | { kind: 'spawning_rendezvous' }
  // RENDEZVOUS1 sent on the new RP circuit; the rendezvous link is up
  | { kind: 'rendezvous_open' }
  | { kind: 'closed'; reason: bigint };

type HsHostInput =
  // The introduction point answered ESTABLISH_INTRO.
  | { kind: 'recv_intro_established' }
  // A client's INTRODUCE2 arrived; the seam has already decrypted it.
  | { kind: 'recv_introduce2' }
  // The seam built the rendezvous circuit and sent RENDEZVOUS1 on it.
  | { kind: 'local_send_rendezvous1' }
  // The introduction or rendezvous circuit was destroyed by a peer.
  | { kind: 'recv_destroy'; reason: bigint }
  // Local close.
  | { kind: 'local_close'; reason: bigint };

const REASON_PROTOCOL_ERROR: bigint = 1n;

// ----------------------------------------------------------------------------
// Per-state helpers.
// ----------------------------------------------------------------------------

/** @total */
function stepFromAwaitingIntroEstablished(input: HsHostInput): HsHostState {
  switch (input.kind) {
    case 'recv_intro_established':
      return { kind: 'intro_open' };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_introduce2':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_send_rendezvous1':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromIntroOpen(input: HsHostInput): HsHostState {
  switch (input.kind) {
    case 'recv_introduce2':
      return { kind: 'spawning_rendezvous' };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_intro_established':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'local_send_rendezvous1':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromSpawningRendezvous(input: HsHostInput): HsHostState {
  switch (input.kind) {
    case 'local_send_rendezvous1':
      return { kind: 'rendezvous_open' };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_intro_established':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
    case 'recv_introduce2':
      return { kind: 'closed', reason: REASON_PROTOCOL_ERROR };
  }
}

/** @total */
function stepFromRendezvousOpen(input: HsHostInput): HsHostState {
  switch (input.kind) {
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'closed', reason: r };
    }
    case 'recv_intro_established':
      return { kind: 'rendezvous_open' };
    case 'recv_introduce2':
      return { kind: 'rendezvous_open' };
    case 'local_send_rendezvous1':
      return { kind: 'rendezvous_open' };
  }
}

// ----------------------------------------------------------------------------
// Top-level step.
// ----------------------------------------------------------------------------

/** @total */
function step(state: HsHostState, input: HsHostInput): HsHostState {
  switch (state.kind) {
    case 'awaiting_intro_established':
      return stepFromAwaitingIntroEstablished(input);
    case 'intro_open':
      return stepFromIntroOpen(input);
    case 'spawning_rendezvous':
      return stepFromSpawningRendezvous(input);
    case 'rendezvous_open':
      return stepFromRendezvousOpen(input);
    case 'closed':
      return state;
  }
}

// ----------------------------------------------------------------------------
// Phase predicates.
// ----------------------------------------------------------------------------

/** @total */
function isIntroductionPhase(s: HsHostState): boolean {
  switch (s.kind) {
    case 'awaiting_intro_established':
      return true;
    case 'intro_open':
      return true;
    case 'spawning_rendezvous':
      return false;
    case 'rendezvous_open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isServingClient(s: HsHostState): boolean {
  switch (s.kind) {
    case 'spawning_rendezvous':
      return true;
    case 'rendezvous_open':
      return true;
    case 'awaiting_intro_established':
      return false;
    case 'intro_open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isClosed(s: HsHostState): boolean {
  switch (s.kind) {
    case 'closed':
      return true;
    case 'awaiting_intro_established':
      return false;
    case 'intro_open':
      return false;
    case 'spawning_rendezvous':
      return false;
    case 'rendezvous_open':
      return false;
  }
}
