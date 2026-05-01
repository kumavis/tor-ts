// Tor relay-cell command codes (verified core).
//
// Once a Tor link cell is identified as a RELAY (or RELAY_EARLY) cell,
// the inner relay payload begins with a 1-byte relay command that
// determines what the rest of the relay payload means. These commands
// span four distinct ranges in the spec:
//
//   1..15   regular relay commands           (tor-spec.txt §6)
//   32..40  hidden-service commands          (rend-spec-v3.txt §1.2)
//   41..42  circuit padding negotiation      (padding-spec.txt §3)
//   43..44  stream-level flow control        (proposal 324)
//
// Mirrors `RelayCell` from `packages/tor/src/relay-cell.ts`. The 28
// spec-defined commands are modeled here as a discriminated union, with
// the wire round-trip and the four range classifiers proved in
// Spec/RelayCommand.lean.

type RelayCommand =
  // Regular relay commands (1..15)
  | { kind: 'BEGIN' } // 1
  | { kind: 'DATA' } // 2
  | { kind: 'END' } // 3
  | { kind: 'CONNECTED' } // 4
  | { kind: 'SENDME' } // 5
  | { kind: 'EXTEND' } // 6
  | { kind: 'EXTENDED' } // 7
  | { kind: 'TRUNCATE' } // 8
  | { kind: 'TRUNCATED' } // 9
  | { kind: 'DROP' } // 10
  | { kind: 'RESOLVE' } // 11
  | { kind: 'RESOLVED' } // 12
  | { kind: 'BEGIN_DIR' } // 13
  | { kind: 'EXTEND2' } // 14
  | { kind: 'EXTENDED2' } // 15

  // Hidden service relay commands (32..40)
  | { kind: 'ESTABLISH_INTRO' } // 32
  | { kind: 'ESTABLISH_RENDEZVOUS' } // 33
  | { kind: 'INTRODUCE1' } // 34
  | { kind: 'INTRODUCE2' } // 35
  | { kind: 'RENDEZVOUS1' } // 36
  | { kind: 'RENDEZVOUS2' } // 37
  | { kind: 'INTRO_ESTABLISHED' } // 38
  | { kind: 'RENDEZVOUS_ESTABLISHED' } // 39
  | { kind: 'INTRODUCE_ACK' } // 40

  // Circuit padding negotiation (41..42)
  | { kind: 'PADDING_NEGOTIATE' } // 41
  | { kind: 'PADDING_NEGOTIATED' } // 42

  // Stream-level flow control (43..44)
  | { kind: 'XON' } // 43
  | { kind: 'XOFF' }; // 44

// ----------------------------------------------------------------------------
// Wire-format encoding: numeric code <-> DU.
// ----------------------------------------------------------------------------

/** @total */
function relayCommandCode(c: RelayCommand): bigint {
  switch (c.kind) {
    case 'BEGIN':
      return 1n;
    case 'DATA':
      return 2n;
    case 'END':
      return 3n;
    case 'CONNECTED':
      return 4n;
    case 'SENDME':
      return 5n;
    case 'EXTEND':
      return 6n;
    case 'EXTENDED':
      return 7n;
    case 'TRUNCATE':
      return 8n;
    case 'TRUNCATED':
      return 9n;
    case 'DROP':
      return 10n;
    case 'RESOLVE':
      return 11n;
    case 'RESOLVED':
      return 12n;
    case 'BEGIN_DIR':
      return 13n;
    case 'EXTEND2':
      return 14n;
    case 'EXTENDED2':
      return 15n;
    case 'ESTABLISH_INTRO':
      return 32n;
    case 'ESTABLISH_RENDEZVOUS':
      return 33n;
    case 'INTRODUCE1':
      return 34n;
    case 'INTRODUCE2':
      return 35n;
    case 'RENDEZVOUS1':
      return 36n;
    case 'RENDEZVOUS2':
      return 37n;
    case 'INTRO_ESTABLISHED':
      return 38n;
    case 'RENDEZVOUS_ESTABLISHED':
      return 39n;
    case 'INTRODUCE_ACK':
      return 40n;
    case 'PADDING_NEGOTIATE':
      return 41n;
    case 'PADDING_NEGOTIATED':
      return 42n;
    case 'XON':
      return 43n;
    case 'XOFF':
      return 44n;
  }
}

/** @total */
function relayCommandFromCode(code: bigint): RelayCommand | null {
  if (code === 1n) return { kind: 'BEGIN' };
  if (code === 2n) return { kind: 'DATA' };
  if (code === 3n) return { kind: 'END' };
  if (code === 4n) return { kind: 'CONNECTED' };
  if (code === 5n) return { kind: 'SENDME' };
  if (code === 6n) return { kind: 'EXTEND' };
  if (code === 7n) return { kind: 'EXTENDED' };
  if (code === 8n) return { kind: 'TRUNCATE' };
  if (code === 9n) return { kind: 'TRUNCATED' };
  if (code === 10n) return { kind: 'DROP' };
  if (code === 11n) return { kind: 'RESOLVE' };
  if (code === 12n) return { kind: 'RESOLVED' };
  if (code === 13n) return { kind: 'BEGIN_DIR' };
  if (code === 14n) return { kind: 'EXTEND2' };
  if (code === 15n) return { kind: 'EXTENDED2' };
  if (code === 32n) return { kind: 'ESTABLISH_INTRO' };
  if (code === 33n) return { kind: 'ESTABLISH_RENDEZVOUS' };
  if (code === 34n) return { kind: 'INTRODUCE1' };
  if (code === 35n) return { kind: 'INTRODUCE2' };
  if (code === 36n) return { kind: 'RENDEZVOUS1' };
  if (code === 37n) return { kind: 'RENDEZVOUS2' };
  if (code === 38n) return { kind: 'INTRO_ESTABLISHED' };
  if (code === 39n) return { kind: 'RENDEZVOUS_ESTABLISHED' };
  if (code === 40n) return { kind: 'INTRODUCE_ACK' };
  if (code === 41n) return { kind: 'PADDING_NEGOTIATE' };
  if (code === 42n) return { kind: 'PADDING_NEGOTIATED' };
  if (code === 43n) return { kind: 'XON' };
  if (code === 44n) return { kind: 'XOFF' };
  return null;
}

// ----------------------------------------------------------------------------
// Range-class predicates.
//
// Each predicate decides "is this command from the <range> family?".
// Spec/RelayCommand.lean proves each iff with the corresponding numeric
// range, so any addition to the wire vocabulary forces matching changes
// to all three places (the type, the predicate, and the theorem) — they
// can't drift.
// ----------------------------------------------------------------------------

/** @total */
function isHiddenServiceCommand(c: RelayCommand): boolean {
  switch (c.kind) {
    case 'ESTABLISH_INTRO':
      return true;
    case 'ESTABLISH_RENDEZVOUS':
      return true;
    case 'INTRODUCE1':
      return true;
    case 'INTRODUCE2':
      return true;
    case 'RENDEZVOUS1':
      return true;
    case 'RENDEZVOUS2':
      return true;
    case 'INTRO_ESTABLISHED':
      return true;
    case 'RENDEZVOUS_ESTABLISHED':
      return true;
    case 'INTRODUCE_ACK':
      return true;

    case 'BEGIN':
      return false;
    case 'DATA':
      return false;
    case 'END':
      return false;
    case 'CONNECTED':
      return false;
    case 'SENDME':
      return false;
    case 'EXTEND':
      return false;
    case 'EXTENDED':
      return false;
    case 'TRUNCATE':
      return false;
    case 'TRUNCATED':
      return false;
    case 'DROP':
      return false;
    case 'RESOLVE':
      return false;
    case 'RESOLVED':
      return false;
    case 'BEGIN_DIR':
      return false;
    case 'EXTEND2':
      return false;
    case 'EXTENDED2':
      return false;
    case 'PADDING_NEGOTIATE':
      return false;
    case 'PADDING_NEGOTIATED':
      return false;
    case 'XON':
      return false;
    case 'XOFF':
      return false;
  }
}

/** @total */
function isPaddingCommand(c: RelayCommand): boolean {
  switch (c.kind) {
    case 'PADDING_NEGOTIATE':
      return true;
    case 'PADDING_NEGOTIATED':
      return true;

    case 'BEGIN':
      return false;
    case 'DATA':
      return false;
    case 'END':
      return false;
    case 'CONNECTED':
      return false;
    case 'SENDME':
      return false;
    case 'EXTEND':
      return false;
    case 'EXTENDED':
      return false;
    case 'TRUNCATE':
      return false;
    case 'TRUNCATED':
      return false;
    case 'DROP':
      return false;
    case 'RESOLVE':
      return false;
    case 'RESOLVED':
      return false;
    case 'BEGIN_DIR':
      return false;
    case 'EXTEND2':
      return false;
    case 'EXTENDED2':
      return false;
    case 'ESTABLISH_INTRO':
      return false;
    case 'ESTABLISH_RENDEZVOUS':
      return false;
    case 'INTRODUCE1':
      return false;
    case 'INTRODUCE2':
      return false;
    case 'RENDEZVOUS1':
      return false;
    case 'RENDEZVOUS2':
      return false;
    case 'INTRO_ESTABLISHED':
      return false;
    case 'RENDEZVOUS_ESTABLISHED':
      return false;
    case 'INTRODUCE_ACK':
      return false;
    case 'XON':
      return false;
    case 'XOFF':
      return false;
  }
}

/** @total */
function isFlowControlCommand(c: RelayCommand): boolean {
  switch (c.kind) {
    case 'XON':
      return true;
    case 'XOFF':
      return true;

    case 'BEGIN':
      return false;
    case 'DATA':
      return false;
    case 'END':
      return false;
    case 'CONNECTED':
      return false;
    case 'SENDME':
      return false;
    case 'EXTEND':
      return false;
    case 'EXTENDED':
      return false;
    case 'TRUNCATE':
      return false;
    case 'TRUNCATED':
      return false;
    case 'DROP':
      return false;
    case 'RESOLVE':
      return false;
    case 'RESOLVED':
      return false;
    case 'BEGIN_DIR':
      return false;
    case 'EXTEND2':
      return false;
    case 'EXTENDED2':
      return false;
    case 'ESTABLISH_INTRO':
      return false;
    case 'ESTABLISH_RENDEZVOUS':
      return false;
    case 'INTRODUCE1':
      return false;
    case 'INTRODUCE2':
      return false;
    case 'RENDEZVOUS1':
      return false;
    case 'RENDEZVOUS2':
      return false;
    case 'INTRO_ESTABLISHED':
      return false;
    case 'RENDEZVOUS_ESTABLISHED':
      return false;
    case 'INTRODUCE_ACK':
      return false;
    case 'PADDING_NEGOTIATE':
      return false;
    case 'PADDING_NEGOTIATED':
      return false;
  }
}
