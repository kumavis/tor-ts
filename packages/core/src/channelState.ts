// Tor link-channel handshake state machine (verified core).
//
// The channel handshake (tor-spec.txt §4) is a 4-step exchange:
//
//   client                             server
//   ------ VERSIONS ----------------->
//                <----- VERSIONS  ----
//                <----- CERTS  -------
//                <----- AUTH_CHALLENGE
//                <----- NETINFO  -----
//   ------ NETINFO ----------------->
//                                       (channel open)
//
// From the *client's* perspective (which is the only side `tor-ts`
// implements), the receive-side handshake has four expected
// transitions: VERSIONS, CERTS, AUTH_CHALLENGE, NETINFO. After
// NETINFO the channel is open and ready for circuit cells.
//
// This module models that as a DU + pure `step` function. The seam
// adapter parses incoming bytes (using cellHeader + messageCellType
// already in core) and feeds the resulting `ChannelInput` to `step`,
// then dispatches the returned state.
//
// Modeling notes:
//   * `step` is implemented as a per-state helper that takes the
//     unpacked state fields, then `step` itself dispatches on
//     `state.kind` and calls the right helper. This avoids the
//     nested-switch narrowing bug (Thales issue 6) and the field-access-
//     inside-DU-constructor bug (issue 8).
//   * Closed states carry a `reason` code so theorems can talk about
//     *why* the channel terminated (mismatched cell type, etc.) rather
//     than just "closed".

type ChannelState =
  | { kind: 'awaiting_versions' }
  | { kind: 'awaiting_certs'; linkVersion: bigint }
  | { kind: 'awaiting_auth_challenge'; linkVersion: bigint }
  | { kind: 'awaiting_netinfo'; linkVersion: bigint }
  | { kind: 'open'; linkVersion: bigint }
  | { kind: 'closed'; reason: bigint };

type ChannelInput =
  // Server's VERSIONS reply, with the negotiated link protocol version
  // already extracted by the seam (it picks max(common(client, server))).
  | { kind: 'recv_versions'; serverVersion: bigint }
  | { kind: 'recv_certs' }
  | { kind: 'recv_auth_challenge' }
  | { kind: 'recv_netinfo' }
  // Catch-all for any cell that doesn't match the expected next step.
  | { kind: 'recv_unexpected'; observedCommandCode: bigint };

/** Closed-state reason codes. Internal to this module. */
const REASON_UNEXPECTED_CELL: bigint = 1n;

// ----------------------------------------------------------------------------
// Per-state transition helpers.
// ----------------------------------------------------------------------------

/** @total */
function stepFromAwaitingVersions(input: ChannelInput): ChannelState {
  switch (input.kind) {
    case 'recv_versions': {
      const v = input.serverVersion;
      return { kind: 'awaiting_certs', linkVersion: v };
    }
    case 'recv_certs':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_auth_challenge':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_netinfo':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_unexpected':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
  }
}

/** @total */
function stepFromAwaitingCerts(linkVersion: bigint, input: ChannelInput): ChannelState {
  switch (input.kind) {
    case 'recv_certs':
      return { kind: 'awaiting_auth_challenge', linkVersion };
    case 'recv_versions':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_auth_challenge':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_netinfo':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_unexpected':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
  }
}

/** @total */
function stepFromAwaitingAuthChallenge(linkVersion: bigint, input: ChannelInput): ChannelState {
  switch (input.kind) {
    case 'recv_auth_challenge':
      return { kind: 'awaiting_netinfo', linkVersion };
    case 'recv_versions':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_certs':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_netinfo':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_unexpected':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
  }
}

/** @total */
function stepFromAwaitingNetInfo(linkVersion: bigint, input: ChannelInput): ChannelState {
  switch (input.kind) {
    case 'recv_netinfo':
      return { kind: 'open', linkVersion };
    case 'recv_versions':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_certs':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_auth_challenge':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
    case 'recv_unexpected':
      return { kind: 'closed', reason: REASON_UNEXPECTED_CELL };
  }
}

// ----------------------------------------------------------------------------
// Top-level step.
// ----------------------------------------------------------------------------

/**
 * Apply one input to the channel state and return the new state.
 * `open` and `closed` are terminal: any input leaves them unchanged.
 */
/** @total */
function step(state: ChannelState, input: ChannelInput): ChannelState {
  switch (state.kind) {
    case 'awaiting_versions':
      return stepFromAwaitingVersions(input);
    case 'awaiting_certs': {
      const v = state.linkVersion;
      return stepFromAwaitingCerts(v, input);
    }
    case 'awaiting_auth_challenge': {
      const v = state.linkVersion;
      return stepFromAwaitingAuthChallenge(v, input);
    }
    case 'awaiting_netinfo': {
      const v = state.linkVersion;
      return stepFromAwaitingNetInfo(v, input);
    }
    case 'open':
      return state;
    case 'closed':
      return state;
  }
}

// ----------------------------------------------------------------------------
// Phase predicates.
// ----------------------------------------------------------------------------

/** @total */
function isHandshaking(state: ChannelState): boolean {
  switch (state.kind) {
    case 'awaiting_versions':
      return true;
    case 'awaiting_certs':
      return true;
    case 'awaiting_auth_challenge':
      return true;
    case 'awaiting_netinfo':
      return true;
    case 'open':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isOpen(state: ChannelState): boolean {
  switch (state.kind) {
    case 'open':
      return true;
    case 'awaiting_versions':
      return false;
    case 'awaiting_certs':
      return false;
    case 'awaiting_auth_challenge':
      return false;
    case 'awaiting_netinfo':
      return false;
    case 'closed':
      return false;
  }
}

/** @total */
function isClosed(state: ChannelState): boolean {
  switch (state.kind) {
    case 'closed':
      return true;
    case 'awaiting_versions':
      return false;
    case 'awaiting_certs':
      return false;
    case 'awaiting_auth_challenge':
      return false;
    case 'awaiting_netinfo':
      return false;
    case 'open':
      return false;
  }
}

/**
 * Return the negotiated link protocol version, or `null` for states
 * that don't yet have one (`awaiting_versions`, `closed`).
 */
/** @total */
function linkVersionOf(state: ChannelState): bigint | null {
  switch (state.kind) {
    case 'awaiting_versions':
      return null;
    case 'awaiting_certs':
      return state.linkVersion;
    case 'awaiting_auth_challenge':
      return state.linkVersion;
    case 'awaiting_netinfo':
      return state.linkVersion;
    case 'open':
      return state.linkVersion;
    case 'closed':
      return null;
  }
}
