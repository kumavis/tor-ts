// Tor SENDME flow-control window arithmetic (verified core).
//
// Tor maintains a sliding window for flow control at TWO layers, with
// DIFFERENT spec constants:
//
//                     INITIAL  INCREMENT  THRESHOLD
//   circuit window     1000      100        900
//   stream window       500       50        450
//
// (tor-spec.txt §7.3.1; mirrored in packages/tor/src/circuit.ts as
//  CIRCUIT_WINDOW_START / CIRCUIT_SENDME_INCREMENT and
//  STREAM_WINDOW_START / STREAM_SENDME_INCREMENT.)
//
// Both windows obey the same arithmetic rules — only the numeric
// constants differ. So this module exposes:
//
//   * The four spec constants for each layer.
//   * Generic predicates parameterized over `increment` / `threshold`
//     / `max`. Spec/SendmeWindow.lean proves invariants over the
//     parameterized form, plus concrete-value witnesses for both the
//     circuit and stream constants so the seam can use the bare
//     constants without having to re-prove anything.
//
// The decrement / depletion predicates are constant-free and work for
// either layer unchanged.

// ----------------------------------------------------------------------------
// Spec constants.
// ----------------------------------------------------------------------------

/** Initial circuit-level window (tor-spec §7.3.1). */
const CIRCUIT_WINDOW_INITIAL: bigint = 1000n;

/** Circuit-level SENDME-cell increment. */
const CIRCUIT_SENDME_INCREMENT: bigint = 100n;

/** Deliver-side circuit threshold = INITIAL − INCREMENT. */
const CIRCUIT_SENDME_THRESHOLD: bigint = 900n;

/** Initial stream-level window. */
const STREAM_WINDOW_INITIAL: bigint = 500n;

/** Stream-level SENDME-cell increment. */
const STREAM_SENDME_INCREMENT: bigint = 50n;

/** Deliver-side stream threshold = INITIAL − INCREMENT. */
const STREAM_SENDME_THRESHOLD: bigint = 450n;

// ----------------------------------------------------------------------------
// Constant-free single-step arithmetic.
// ----------------------------------------------------------------------------

/** Window state after sending or receiving one RELAY_DATA cell. */
/** @total */
function decrementWindow(window: bigint): bigint {
  return window - 1n;
}

/**
 * Window state after receiving (or being credited by) one SENDME with
 * the given increment. Use `CIRCUIT_SENDME_INCREMENT` for circuit
 * windows and `STREAM_SENDME_INCREMENT` for stream windows.
 */
/** @total */
function applySendme(window: bigint, increment: bigint): bigint {
  return window + increment;
}

// ----------------------------------------------------------------------------
// Constant-free predicates.
// ----------------------------------------------------------------------------

/**
 * The package window is depleted: any further data send would violate
 * the spec. The sender must wait for a SENDME before continuing.
 */
/** @total */
function isWindowDepleted(window: bigint): boolean {
  return window <= 0n;
}

/**
 * "Can I safely send one more data cell?" — the package window must
 * be strictly positive.
 */
/** @total */
function canSendData(packageWindow: bigint): boolean {
  return packageWindow > 0n;
}

/**
 * "Did this incoming data cell exhaust my deliver window?" — true if
 * decrementing would push us at or below zero.
 */
/** @total */
function wouldDeplete(window: bigint): boolean {
  return window <= 1n;
}

// ----------------------------------------------------------------------------
// Parameterized threshold/validity predicates.
//
// Each takes the layer-appropriate constant explicitly. The seam picks
// CIRCUIT_* or STREAM_* per the call site.
// ----------------------------------------------------------------------------

/**
 * The deliver window has dropped to (or below) the SENDME threshold:
 * time to emit a SENDME of our own to replenish the peer's package
 * window.
 */
/** @total */
function shouldEmitSendme(window: bigint, threshold: bigint): boolean {
  return window <= threshold;
}

/**
 * The window is in its valid range `[0, max]`. A window outside this
 * range indicates a protocol violation: either an under-flow (the peer
 * sent more data than allowed) or an over-flow (we received an
 * unsolicited SENDME).
 */
/** @total */
function isValidWindow(window: bigint, max: bigint): boolean {
  return 0n <= window && window <= max;
}

// ----------------------------------------------------------------------------
// Layer-specific shorthands.
//
// Each pair below specializes the parameterized predicates above to
// the circuit and stream constants, so callers in the seam can use a
// single function name per layer without having to thread the
// constants through.
// ----------------------------------------------------------------------------

/** @total */
function shouldEmitCircuitSendme(window: bigint): boolean {
  return shouldEmitSendme(window, CIRCUIT_SENDME_THRESHOLD);
}

/** @total */
function shouldEmitStreamSendme(window: bigint): boolean {
  return shouldEmitSendme(window, STREAM_SENDME_THRESHOLD);
}

/** @total */
function isValidCircuitWindow(window: bigint): boolean {
  return isValidWindow(window, CIRCUIT_WINDOW_INITIAL);
}

/** @total */
function isValidStreamWindow(window: bigint): boolean {
  return isValidWindow(window, STREAM_WINDOW_INITIAL);
}

/** @total */
function applyCircuitSendme(window: bigint): bigint {
  return applySendme(window, CIRCUIT_SENDME_INCREMENT);
}

/** @total */
function applyStreamSendme(window: bigint): bigint {
  return applySendme(window, STREAM_SENDME_INCREMENT);
}
