-- Specification theorems for the `channelState` module.
--
-- The headlines:
--   * Once `open`, the channel stays open under any input.
--   * Once `closed`, the channel stays closed under any input.
--   * The handshake is a strict 4-step linear progression — only the
--     spec-prescribed input at each phase advances; everything else
--     transitions to `closed`.
--   * The full happy-path sequence drives `awaiting_versions` to
--     `open` while preserving the negotiated link version.
--   * `linkVersionOf` is invariant across handshake-internal
--     transitions (the version negotiated in step 1 is what ends up
--     on the open channel).

import Generated.ChannelState
import Thales.TS.Runtime

open Thales.TS

namespace Spec.ChannelState

open _root_.ChannelState

deriving instance DecidableEq for ChannelState
deriving instance DecidableEq for ChannelInput

----------------------------------------------------------------------------
-- Terminal states are stable
----------------------------------------------------------------------------

/-- **Open is stable.** Once the channel is open, any input leaves it
    open and preserves the link version. -/
theorem step_open_stable (v : Int) (i : ChannelInput) :
    step (.open v) i = .open v := by
  simp [step]

/-- **Closed is stable.** Once the channel has terminated, any input
    leaves it closed with the same reason. -/
theorem step_closed_stable (r : Int) (i : ChannelInput) :
    step (.closed r) i = .closed r := by
  simp [step]

----------------------------------------------------------------------------
-- Each handshake state advances on exactly one input
----------------------------------------------------------------------------

/-- VERSIONS advances `awaiting_versions` to `awaiting_certs`,
    carrying the negotiated link version. -/
theorem step_awaiting_versions_recv_versions (v : Int) :
    step .awaiting_versions (.recv_versions v) = .awaiting_certs v := by
  simp [step, stepFromAwaitingVersions]

/-- Anything else from `awaiting_versions` closes the channel. -/
theorem step_awaiting_versions_certs :
    step .awaiting_versions .recv_certs = .closed 1 := by
  simp [step, stepFromAwaitingVersions, REASON_UNEXPECTED_CELL]

theorem step_awaiting_versions_auth :
    step .awaiting_versions .recv_auth_challenge = .closed 1 := by
  simp [step, stepFromAwaitingVersions, REASON_UNEXPECTED_CELL]

theorem step_awaiting_versions_netinfo :
    step .awaiting_versions .recv_netinfo = .closed 1 := by
  simp [step, stepFromAwaitingVersions, REASON_UNEXPECTED_CELL]

/-- CERTS advances `awaiting_certs` to `awaiting_auth_challenge`,
    preserving the link version. -/
theorem step_awaiting_certs_recv_certs (v : Int) :
    step (.awaiting_certs v) .recv_certs = .awaiting_auth_challenge v := by
  simp [step, stepFromAwaitingCerts]

/-- AUTH_CHALLENGE advances `awaiting_auth_challenge` to
    `awaiting_netinfo`. -/
theorem step_awaiting_auth_challenge_recv (v : Int) :
    step (.awaiting_auth_challenge v) .recv_auth_challenge =
      .awaiting_netinfo v := by
  simp [step, stepFromAwaitingAuthChallenge]

/-- NETINFO advances `awaiting_netinfo` to `open`. -/
theorem step_awaiting_netinfo_recv (v : Int) :
    step (.awaiting_netinfo v) .recv_netinfo = .open v := by
  simp [step, stepFromAwaitingNetInfo]

----------------------------------------------------------------------------
-- The full happy-path handshake reaches `open` with the negotiated version
----------------------------------------------------------------------------

/-- **Full handshake.** Applying the spec-prescribed inputs in order
    drives `awaiting_versions` all the way to `open` with the link
    version the server announced. -/
theorem full_handshake_reaches_open (v : Int) :
    step (step (step (step .awaiting_versions
        (.recv_versions v))
        .recv_certs)
        .recv_auth_challenge)
        .recv_netinfo
      = .open v := by
  rw [step_awaiting_versions_recv_versions v,
      step_awaiting_certs_recv_certs v,
      step_awaiting_auth_challenge_recv v,
      step_awaiting_netinfo_recv v]

----------------------------------------------------------------------------
-- Phase predicates
----------------------------------------------------------------------------

/-- `isHandshaking`, `isOpen`, `isClosed` form a 3-way partition over
    all states. -/
theorem phase_partition (s : ChannelState) :
    (isHandshaking s = true ∧ isOpen s = false ∧ isClosed s = false) ∨
    (isHandshaking s = false ∧ isOpen s = true ∧ isClosed s = false) ∨
    (isHandshaking s = false ∧ isOpen s = false ∧ isClosed s = true) := by
  cases s <;> simp [isHandshaking, isOpen, isClosed]

theorem isHandshaking_awaiting_versions :
    isHandshaking .awaiting_versions = true := rfl

theorem isOpen_open (v : Int) :
    isOpen (.open v) = true := rfl

theorem isClosed_closed (r : Int) :
    isClosed (.closed r) = true := rfl

----------------------------------------------------------------------------
-- linkVersionOf invariants
----------------------------------------------------------------------------

/-- Once the link version is negotiated (`awaiting_certs` onward
    through `open`), `linkVersionOf` returns it. -/
theorem linkVersionOf_awaiting_certs (v : Int) :
    linkVersionOf (.awaiting_certs v) = some v := rfl

theorem linkVersionOf_open (v : Int) :
    linkVersionOf (.open v) = some v := rfl

theorem linkVersionOf_awaiting_versions :
    linkVersionOf .awaiting_versions = none := rfl

theorem linkVersionOf_closed (r : Int) :
    linkVersionOf (.closed r) = none := rfl

/-- **Invariance under successful handshake transitions.** If `step`
    advances the handshake (the input is the expected one for the
    current phase), the link version is preserved. -/
theorem linkVersionOf_preserved_by_certs (v : Int) :
    linkVersionOf (step (.awaiting_certs v) .recv_certs) =
      linkVersionOf (.awaiting_certs v) := by
  rw [step_awaiting_certs_recv_certs v]
  simp [linkVersionOf]

theorem linkVersionOf_preserved_by_auth (v : Int) :
    linkVersionOf (step (.awaiting_auth_challenge v) .recv_auth_challenge) =
      linkVersionOf (.awaiting_auth_challenge v) := by
  rw [step_awaiting_auth_challenge_recv v]
  simp [linkVersionOf]

theorem linkVersionOf_preserved_by_netinfo (v : Int) :
    linkVersionOf (step (.awaiting_netinfo v) .recv_netinfo) =
      linkVersionOf (.awaiting_netinfo v) := by
  rw [step_awaiting_netinfo_recv v]
  simp [linkVersionOf]

----------------------------------------------------------------------------
-- Closed cannot un-close
----------------------------------------------------------------------------

/-- **One-way closure.** A closed channel never returns to an open or
    handshaking state. -/
theorem closed_does_not_reopen (r : Int) (i : ChannelInput) :
    isOpen (step (.closed r) i) = false ∧
    isHandshaking (step (.closed r) i) = false := by
  rw [step_closed_stable r i]
  refine ⟨?_, ?_⟩ <;> simp [isOpen, isHandshaking]

end Spec.ChannelState
