// CIRCUIT_DESTROY reason codes (verified core).
//
// When a Tor relay terminates a circuit it sends a DESTROY cell with
// a 1-byte reason code (tor-spec.txt §5.4). Mirrors
// `DestroyReasonNames` from `packages/tor/src/circuit.ts`.
//
// Same shape as `relayEndReason.ts`: discriminated union plus
// code-to-DU and DU-to-code functions plus a round-trip theorem in
// Spec/DestroyReason.lean.

type DestroyReason =
  | { kind: 'NONE' } //           0
  | { kind: 'PROTOCOL' } //       1
  | { kind: 'INTERNAL' } //       2
  | { kind: 'REQUESTED' } //      3
  | { kind: 'HIBERNATING' } //    4
  | { kind: 'RESOURCELIMIT' } //  5
  | { kind: 'CONNECTFAILED' } //  6
  | { kind: 'OR_IDENTITY' } //    7
  | { kind: 'CHANNEL_CLOSED' } // 8
  | { kind: 'FINISHED' } //       9
  | { kind: 'TIMEOUT' } //        10
  | { kind: 'DESTROYED' } //      11
  | { kind: 'NOSUCHSERVICE' }; //  12

/** @total */
function destroyReasonCode(r: DestroyReason): bigint {
  switch (r.kind) {
    case 'NONE':
      return 0n;
    case 'PROTOCOL':
      return 1n;
    case 'INTERNAL':
      return 2n;
    case 'REQUESTED':
      return 3n;
    case 'HIBERNATING':
      return 4n;
    case 'RESOURCELIMIT':
      return 5n;
    case 'CONNECTFAILED':
      return 6n;
    case 'OR_IDENTITY':
      return 7n;
    case 'CHANNEL_CLOSED':
      return 8n;
    case 'FINISHED':
      return 9n;
    case 'TIMEOUT':
      return 10n;
    case 'DESTROYED':
      return 11n;
    case 'NOSUCHSERVICE':
      return 12n;
  }
}

/** @total */
function destroyReasonFromCode(code: bigint): DestroyReason | null {
  if (code === 0n) return { kind: 'NONE' };
  if (code === 1n) return { kind: 'PROTOCOL' };
  if (code === 2n) return { kind: 'INTERNAL' };
  if (code === 3n) return { kind: 'REQUESTED' };
  if (code === 4n) return { kind: 'HIBERNATING' };
  if (code === 5n) return { kind: 'RESOURCELIMIT' };
  if (code === 6n) return { kind: 'CONNECTFAILED' };
  if (code === 7n) return { kind: 'OR_IDENTITY' };
  if (code === 8n) return { kind: 'CHANNEL_CLOSED' };
  if (code === 9n) return { kind: 'FINISHED' };
  if (code === 10n) return { kind: 'TIMEOUT' };
  if (code === 11n) return { kind: 'DESTROYED' };
  if (code === 12n) return { kind: 'NOSUCHSERVICE' };
  return null;
}

// ----------------------------------------------------------------------------
// Classification: which destroy reasons are *requests* vs *errors*?
// ----------------------------------------------------------------------------
//
// Per tor-spec.txt §5.4: NONE/REQUESTED/FINISHED indicate clean
// teardowns initiated by the peer. The rest indicate failure or
// involuntary loss.

/** @total */
function isCleanDestroy(r: DestroyReason): boolean {
  switch (r.kind) {
    case 'NONE':
      return true;
    case 'REQUESTED':
      return true;
    case 'FINISHED':
      return true;

    case 'PROTOCOL':
      return false;
    case 'INTERNAL':
      return false;
    case 'HIBERNATING':
      return false;
    case 'RESOURCELIMIT':
      return false;
    case 'CONNECTFAILED':
      return false;
    case 'OR_IDENTITY':
      return false;
    case 'CHANNEL_CLOSED':
      return false;
    case 'TIMEOUT':
      return false;
    case 'DESTROYED':
      return false;
    case 'NOSUCHSERVICE':
      return false;
  }
}
