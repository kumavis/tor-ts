// Tor circuit lifecycle state machine (verified core).
//
// A Tor circuit is built by chaining N hops via CREATE2 (first hop)
// and N-1 EXTEND2 / EXTENDED2 round-trips (subsequent hops). After
// the last hop is acknowledged the circuit is `open` and ready to
// carry RELAY cells. A circuit is torn down by either side via a
// DESTROY cell or by local close.
//
// This module models the high-level lifecycle as a 3-state DU plus a
// pure step function. The seam adapter parses incoming RELAY-cell
// commands (using `relayCommand.ts` and the byte primitives in core),
// extracts the relevant signal, and feeds it as a `CircuitInput` to
// `step`.
//
// Like `channelState.ts`, this avoids redeclaring all wire-vocabulary
// types here (Thales 0.5 has no `import` — issue 5). The seam
// translates "got CREATED2 or EXTENDED2" into `recv_hop_built` and
// "got DESTROY with reason r" into `recv_destroy r`, then dispatches.

type CircuitState =
  | { kind: 'building'; hopsBuilt: bigint; targetHops: bigint }
  | { kind: 'open'; hops: bigint }
  | { kind: 'destroyed'; reason: bigint };

type CircuitInput =
  // CREATED2 or EXTENDED2 — one hop of the chain is now established.
  | { kind: 'recv_hop_built' }
  // Peer-initiated tear-down (DESTROY cell with a reason code).
  | { kind: 'recv_destroy'; reason: bigint }
  // Local-initiated tear-down (we sent DESTROY, time-out, etc.).
  | { kind: 'local_close'; reason: bigint };

/** Reason code used when an EXTENDED2 arrives on an already-open circuit. */
const REASON_UNEXPECTED_EXTEND: bigint = 100n;

// ----------------------------------------------------------------------------
// Building-phase advance.
//
// Receiving the next hop's ack moves us either to a wider `building`
// state or, once we hit the target, to `open`. Extracted as a separate
// helper so the construction of the `'building'` DU happens after the
// arithmetic on `hopsBuilt` (issue 8 workaround).
// ----------------------------------------------------------------------------

/** @total */
function advanceBuilding(hopsBuilt: bigint, targetHops: bigint): CircuitState {
  if (hopsBuilt + 1n >= targetHops) {
    return { kind: 'open', hops: targetHops };
  }
  const newHops = hopsBuilt + 1n;
  return { kind: 'building', hopsBuilt: newHops, targetHops };
}

// ----------------------------------------------------------------------------
// Per-state transition helpers.
// ----------------------------------------------------------------------------

/** @total */
function stepFromBuilding(
  hopsBuilt: bigint,
  targetHops: bigint,
  input: CircuitInput
): CircuitState {
  switch (input.kind) {
    case 'recv_hop_built':
      return advanceBuilding(hopsBuilt, targetHops);
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'destroyed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'destroyed', reason: r };
    }
  }
}

/** @total */
function stepFromOpen(hops: bigint, input: CircuitInput): CircuitState {
  switch (input.kind) {
    case 'recv_hop_built':
      // Protocol error: the peer sent EXTENDED2 (or CREATED2) on an
      // already-built circuit. Tear it down.
      return { kind: 'destroyed', reason: REASON_UNEXPECTED_EXTEND };
    case 'recv_destroy': {
      const r = input.reason;
      return { kind: 'destroyed', reason: r };
    }
    case 'local_close': {
      const r = input.reason;
      return { kind: 'destroyed', reason: r };
    }
  }
}

// ----------------------------------------------------------------------------
// Top-level step.
// ----------------------------------------------------------------------------

/** @total */
function step(state: CircuitState, input: CircuitInput): CircuitState {
  switch (state.kind) {
    case 'building': {
      const hb = state.hopsBuilt;
      const th = state.targetHops;
      return stepFromBuilding(hb, th, input);
    }
    case 'open': {
      const h = state.hops;
      return stepFromOpen(h, input);
    }
    case 'destroyed':
      return state;
  }
}

// ----------------------------------------------------------------------------
// Phase predicates and accessors.
// ----------------------------------------------------------------------------

/** @total */
function isBuilding(state: CircuitState): boolean {
  switch (state.kind) {
    case 'building':
      return true;
    case 'open':
      return false;
    case 'destroyed':
      return false;
  }
}

/** @total */
function isOpen(state: CircuitState): boolean {
  switch (state.kind) {
    case 'open':
      return true;
    case 'building':
      return false;
    case 'destroyed':
      return false;
  }
}

/** @total */
function isDestroyed(state: CircuitState): boolean {
  switch (state.kind) {
    case 'destroyed':
      return true;
    case 'building':
      return false;
    case 'open':
      return false;
  }
}

/**
 * Number of fully-established hops in the current state. For
 * `building` returns the count built so far (not the target);
 * for `open` returns the total; for `destroyed` returns 0.
 */
/** @total */
function hopCount(state: CircuitState): bigint {
  switch (state.kind) {
    case 'building':
      return state.hopsBuilt;
    case 'open':
      return state.hops;
    case 'destroyed':
      return 0n;
  }
}
