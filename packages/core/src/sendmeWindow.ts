// Tor SENDME flow-control window arithmetic (verified core).
//
// Each Tor circuit and stream maintains a sliding window for flow
// control. Two windows per direction:
//
//   * package_window (sender side): starts at 1000; decremented by 1
//                                   for each RELAY_DATA sent; the peer
//                                   replenishes it with +100 by sending
//                                   us a SENDME cell.
//   * deliver_window (receiver side): starts at 1000; decremented by 1
//                                   for each RELAY_DATA received; we
//                                   emit a SENDME ourselves once it
//                                   drops to 900 or below, replenishing
//                                   the peer's package_window.
//
// Spec source: tor-spec.txt §7.3 (flow-control), prop324 for the
// stream-level mechanism.
//
// This module captures the arithmetic on a single window: decrement,
// SENDME-receive, depletion check, "should-emit-sendme" predicate, and
// a "valid-range" invariant predicate. The state-machine layer can
// compose these per-direction; the seam adapter dispatches RELAY_DATA
// / RELAY_SENDME cells to the right window functions.

/** Initial window value. tor-spec §7.3.1. */
const SENDME_INITIAL: bigint = 1000n;

/** SENDME-cell increment. Each SENDME announces +100 cells of capacity. */
const SENDME_INCREMENT: bigint = 100n;

/** Deliver-side threshold. When deliver_window drops to this or below,
    we emit a SENDME. INITIAL - INCREMENT = 900. */
const SENDME_THRESHOLD: bigint = 900n;

// ----------------------------------------------------------------------------
// Single-step arithmetic.
// ----------------------------------------------------------------------------

/** Window state after sending or receiving one RELAY_DATA cell. */
/** @total */
function decrementWindow(window: bigint): bigint {
  return window - 1n;
}

/** Window state after receiving (or being credited by) one SENDME. */
/** @total */
function applySendme(window: bigint): bigint {
  return window + SENDME_INCREMENT;
}

// ----------------------------------------------------------------------------
// Predicates.
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
 * The deliver window has dropped to the SENDME threshold: time to emit
 * a SENDME of our own to replenish the peer's package window.
 */
/** @total */
function shouldEmitSendme(window: bigint): boolean {
  return window <= SENDME_THRESHOLD;
}

/**
 * The window is in its valid range `[0, INITIAL]`. A window outside
 * this range indicates a protocol violation: either an under-flow (the
 * peer sent more data than allowed) or an over-flow (we received an
 * unsolicited SENDME).
 */
/** @total */
function isValidWindow(window: bigint): boolean {
  return 0n <= window && window <= SENDME_INITIAL;
}

// ----------------------------------------------------------------------------
// Combined predicates over the two window directions.
// ----------------------------------------------------------------------------

/**
 * "Can I safely send one more data cell?" — the package window must be
 * strictly positive.
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
