// RELAY_END reason codes and retry policy (verified core).
//
// The Tor relay protocol terminates streams with a numeric "reason" that
// signals why. Spec source: tor-spec.txt §6.3 and path-spec/handling-
// failure.md. Mirrors `RelayEndReasons` and `getStreamRetryBehavior` from
// `packages/tor/src/relay-cell.ts`.
//
// The TS-side caller passes `BigInt(numericReason)` and pattern-matches
// the returned DU at the seam.

type RelayEndReason =
  | { kind: 'REASON_MISC' }
  | { kind: 'REASON_RESOLVEFAILED' }
  | { kind: 'REASON_CONNECTREFUSED' }
  | { kind: 'REASON_EXITPOLICY' }
  | { kind: 'REASON_DESTROY' }
  | { kind: 'REASON_DONE' }
  | { kind: 'REASON_TIMEOUT' }
  | { kind: 'REASON_NOROUTE' }
  | { kind: 'REASON_HIBERNATING' }
  | { kind: 'REASON_INTERNAL' }
  | { kind: 'REASON_RESOURCELIMIT' }
  | { kind: 'REASON_CONNRESET' }
  | { kind: 'REASON_TORPROTOCOL' }
  | { kind: 'REASON_NOTDIRECTORY' };

type StreamRetryBehavior =
  | { kind: 'retry_circuit' }
  | { kind: 'retry_exit' }
  | { kind: 'no_retry' };

// ----------------------------------------------------------------------------
// Wire-format encoding: numeric code ↔ DU.
//
// Codes are spec-fixed in the range 1–14. `relayEndReasonFromCode` returns
// `null` for any other input, including 0; the seam adapter substitutes
// REASON_MISC at its discretion.
// ----------------------------------------------------------------------------

/** @total */
function relayEndReasonCode(reason: RelayEndReason): bigint {
  switch (reason.kind) {
    case 'REASON_MISC':
      return 1n;
    case 'REASON_RESOLVEFAILED':
      return 2n;
    case 'REASON_CONNECTREFUSED':
      return 3n;
    case 'REASON_EXITPOLICY':
      return 4n;
    case 'REASON_DESTROY':
      return 5n;
    case 'REASON_DONE':
      return 6n;
    case 'REASON_TIMEOUT':
      return 7n;
    case 'REASON_NOROUTE':
      return 8n;
    case 'REASON_HIBERNATING':
      return 9n;
    case 'REASON_INTERNAL':
      return 10n;
    case 'REASON_RESOURCELIMIT':
      return 11n;
    case 'REASON_CONNRESET':
      return 12n;
    case 'REASON_TORPROTOCOL':
      return 13n;
    case 'REASON_NOTDIRECTORY':
      return 14n;
  }
}

/** @total */
function relayEndReasonFromCode(code: bigint): RelayEndReason | null {
  if (code === 1n) return { kind: 'REASON_MISC' };
  if (code === 2n) return { kind: 'REASON_RESOLVEFAILED' };
  if (code === 3n) return { kind: 'REASON_CONNECTREFUSED' };
  if (code === 4n) return { kind: 'REASON_EXITPOLICY' };
  if (code === 5n) return { kind: 'REASON_DESTROY' };
  if (code === 6n) return { kind: 'REASON_DONE' };
  if (code === 7n) return { kind: 'REASON_TIMEOUT' };
  if (code === 8n) return { kind: 'REASON_NOROUTE' };
  if (code === 9n) return { kind: 'REASON_HIBERNATING' };
  if (code === 10n) return { kind: 'REASON_INTERNAL' };
  if (code === 11n) return { kind: 'REASON_RESOURCELIMIT' };
  if (code === 12n) return { kind: 'REASON_CONNRESET' };
  if (code === 13n) return { kind: 'REASON_TORPROTOCOL' };
  if (code === 14n) return { kind: 'REASON_NOTDIRECTORY' };
  return null;
}

// ----------------------------------------------------------------------------
// Retry classification — which kinds of failure are recoverable, and how.
//
// 'retry_exit'    - exit-relay-specific (policy, hibernation, no route to
//                   destination); same circuit body, different exit.
// 'retry_circuit' - transient (timeout, resource limit, anything ambiguous);
//                   try a fresh circuit.
// 'no_retry'      - permanent (refused, normal close, internal error,
//                   protocol violation, wrong relay type).
//
// Per path-spec/handling-failure.md.
// ----------------------------------------------------------------------------

/** @total */
function getStreamRetryBehavior(reason: RelayEndReason): StreamRetryBehavior {
  switch (reason.kind) {
    // Exit-specific issues — try a different exit.
    case 'REASON_RESOLVEFAILED':
      return { kind: 'retry_exit' };
    case 'REASON_EXITPOLICY':
      return { kind: 'retry_exit' };
    case 'REASON_NOROUTE':
      return { kind: 'retry_exit' };
    case 'REASON_HIBERNATING':
      return { kind: 'retry_exit' };

    // Transient — try a new circuit.
    case 'REASON_TIMEOUT':
      return { kind: 'retry_circuit' };
    case 'REASON_RESOURCELIMIT':
      return { kind: 'retry_circuit' };

    // Ambiguous — try one new circuit (matches tor-ts policy).
    case 'REASON_MISC':
      return { kind: 'retry_circuit' };
    case 'REASON_CONNRESET':
      return { kind: 'retry_circuit' };

    // Permanent or normal close — don't retry.
    case 'REASON_CONNECTREFUSED':
      return { kind: 'no_retry' };
    case 'REASON_DESTROY':
      return { kind: 'no_retry' };
    case 'REASON_DONE':
      return { kind: 'no_retry' };
    case 'REASON_INTERNAL':
      return { kind: 'no_retry' };
    case 'REASON_TORPROTOCOL':
      return { kind: 'no_retry' };
    case 'REASON_NOTDIRECTORY':
      return { kind: 'no_retry' };
  }
}

/** @total */
function isRetryableEndReason(reason: RelayEndReason): boolean {
  // Inlined: switch on `reason.kind` directly. Switching on
  // `getStreamRetryBehavior(reason).kind` (or even on a `const`-bound
  // copy) silently emits `()` in Thales 0.5 — see the bug filed in
  // docs/thales-issues.md. The two functions are still proved
  // equivalent in Spec/RelayEndReason.lean.
  switch (reason.kind) {
    case 'REASON_RESOLVEFAILED':
      return true;
    case 'REASON_EXITPOLICY':
      return true;
    case 'REASON_NOROUTE':
      return true;
    case 'REASON_HIBERNATING':
      return true;
    case 'REASON_TIMEOUT':
      return true;
    case 'REASON_RESOURCELIMIT':
      return true;
    case 'REASON_MISC':
      return true;
    case 'REASON_CONNRESET':
      return true;
    case 'REASON_CONNECTREFUSED':
      return false;
    case 'REASON_DESTROY':
      return false;
    case 'REASON_DONE':
      return false;
    case 'REASON_INTERNAL':
      return false;
    case 'REASON_TORPROTOCOL':
      return false;
    case 'REASON_NOTDIRECTORY':
      return false;
  }
}
