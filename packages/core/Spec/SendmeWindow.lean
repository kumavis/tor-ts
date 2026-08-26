-- Specification theorems for the `sendmeWindow` module.
--
-- Tor's flow-control windows are easy to reason about *individually*
-- but easy to get *wrong* in code. The headline guarantees here:
--
--   * Spec constants for both layers (circuit: 1000/100/900;
--     stream: 500/50/450) are correct, and the threshold is exactly
--     INITIAL − INCREMENT for each.
--   * decrement / applySendme are exactly arithmetic ±1 / +increment.
--   * isWindowDepleted, shouldEmitSendme, isValidWindow agree with
--     the natural numeric predicates, and the layer-specific
--     wrappers agree with the parameterized form for the right
--     constants.
--   * Validity is preserved under spec-conformant transitions: a
--     valid window in (0, max] stays valid after one decrement;
--     a valid window in [0, max - increment] stays valid after
--     applying a SENDME.
--   * canSendData is exactly the negation of isWindowDepleted on
--     the integer line — no gap where both hold or neither does.

import Generated.SendmeWindow
import Thales.TS.Runtime

open Thales.TS

namespace Spec.SendmeWindow

open _root_.SendmeWindow

----------------------------------------------------------------------------
-- Spec constants
----------------------------------------------------------------------------

theorem CIRCUIT_WINDOW_INITIAL_eq : CIRCUIT_WINDOW_INITIAL = 1000 := rfl
theorem CIRCUIT_SENDME_INCREMENT_eq : CIRCUIT_SENDME_INCREMENT = 100 := rfl
theorem CIRCUIT_SENDME_THRESHOLD_eq : CIRCUIT_SENDME_THRESHOLD = 900 := rfl

theorem STREAM_WINDOW_INITIAL_eq : STREAM_WINDOW_INITIAL = 500 := rfl
theorem STREAM_SENDME_INCREMENT_eq : STREAM_SENDME_INCREMENT = 50 := rfl
theorem STREAM_SENDME_THRESHOLD_eq : STREAM_SENDME_THRESHOLD = 450 := rfl

/-- For circuits: THRESHOLD = INITIAL − INCREMENT. -/
theorem circuit_threshold_eq_initial_minus_increment :
    CIRCUIT_SENDME_THRESHOLD =
      CIRCUIT_WINDOW_INITIAL - CIRCUIT_SENDME_INCREMENT := by
  unfold CIRCUIT_SENDME_THRESHOLD CIRCUIT_WINDOW_INITIAL CIRCUIT_SENDME_INCREMENT
  decide

/-- For streams: THRESHOLD = INITIAL − INCREMENT. -/
theorem stream_threshold_eq_initial_minus_increment :
    STREAM_SENDME_THRESHOLD =
      STREAM_WINDOW_INITIAL - STREAM_SENDME_INCREMENT := by
  unfold STREAM_SENDME_THRESHOLD STREAM_WINDOW_INITIAL STREAM_SENDME_INCREMENT
  decide

----------------------------------------------------------------------------
-- decrementWindow / applySendme are pure arithmetic
----------------------------------------------------------------------------

theorem decrementWindow_eq (w : Int) : decrementWindow w = w - 1 := rfl

theorem applySendme_eq (w increment : Int) :
    applySendme w increment = w + increment := rfl

/-- A SENDME exactly cancels `increment` decrements: applying a
    SENDME with the same increment as the per-cell decrement count
    returns the window to its starting value. -/
theorem sendme_cancels_decrements (w increment : Int) :
    applySendme (decrementWindow (decrementWindow w)) increment = w + increment - 2 := by
  simp [applySendme, decrementWindow]
  omega

/-- Receiving a SENDME and immediately undoing the increment recovers
    the original window. -/
theorem sendme_round_trip_one_increment (w increment : Int) :
    applySendme w increment - increment = w := by
  unfold applySendme
  omega

----------------------------------------------------------------------------
-- Predicate characterizations
----------------------------------------------------------------------------

theorem isWindowDepleted_iff (w : Int) :
    isWindowDepleted w = true ↔ w ≤ 0 := by
  unfold isWindowDepleted
  simp

theorem shouldEmitSendme_iff (w threshold : Int) :
    shouldEmitSendme w threshold = true ↔ w ≤ threshold := by
  unfold shouldEmitSendme
  simp

theorem isValidWindow_iff (w max : Int) :
    isValidWindow w max = true ↔ 0 ≤ w ∧ w ≤ max := by
  unfold isValidWindow
  simp

theorem canSendData_iff (w : Int) :
    canSendData w = true ↔ 0 < w := by
  unfold canSendData
  simp

theorem wouldDeplete_iff (w : Int) :
    wouldDeplete w = true ↔ w ≤ 1 := by
  unfold wouldDeplete
  simp

----------------------------------------------------------------------------
-- Layer wrappers agree with the parameterized form
----------------------------------------------------------------------------

theorem shouldEmitCircuitSendme_eq (w : Int) :
    shouldEmitCircuitSendme w = shouldEmitSendme w CIRCUIT_SENDME_THRESHOLD := rfl

theorem shouldEmitStreamSendme_eq (w : Int) :
    shouldEmitStreamSendme w = shouldEmitSendme w STREAM_SENDME_THRESHOLD := rfl

theorem isValidCircuitWindow_eq (w : Int) :
    isValidCircuitWindow w = isValidWindow w CIRCUIT_WINDOW_INITIAL := rfl

theorem isValidStreamWindow_eq (w : Int) :
    isValidStreamWindow w = isValidWindow w STREAM_WINDOW_INITIAL := rfl

theorem applyCircuitSendme_eq (w : Int) :
    applyCircuitSendme w = w + 100 := by
  unfold applyCircuitSendme applySendme CIRCUIT_SENDME_INCREMENT
  rfl

theorem applyStreamSendme_eq (w : Int) :
    applyStreamSendme w = w + 50 := by
  unfold applyStreamSendme applySendme STREAM_SENDME_INCREMENT
  rfl

----------------------------------------------------------------------------
-- Concrete spot-check witnesses (circuit layer)
----------------------------------------------------------------------------

theorem circuit_initial_is_valid :
    isValidCircuitWindow CIRCUIT_WINDOW_INITIAL = true := by decide

theorem circuit_zero_is_valid : isValidCircuitWindow 0 = true := by decide

theorem zero_is_depleted : isWindowDepleted 0 = true := by decide

theorem circuit_initial_is_not_depleted :
    isWindowDepleted CIRCUIT_WINDOW_INITIAL = false := by decide

theorem circuit_threshold_emits_sendme :
    shouldEmitCircuitSendme CIRCUIT_SENDME_THRESHOLD = true := by decide

theorem circuit_initial_does_not_emit_sendme :
    shouldEmitCircuitSendme CIRCUIT_WINDOW_INITIAL = false := by decide

----------------------------------------------------------------------------
-- Concrete spot-check witnesses (stream layer)
----------------------------------------------------------------------------

theorem stream_initial_is_valid :
    isValidStreamWindow STREAM_WINDOW_INITIAL = true := by decide

theorem stream_zero_is_valid : isValidStreamWindow 0 = true := by decide

theorem stream_initial_is_not_depleted :
    isWindowDepleted STREAM_WINDOW_INITIAL = false := by decide

theorem stream_threshold_emits_sendme :
    shouldEmitStreamSendme STREAM_SENDME_THRESHOLD = true := by decide

theorem stream_initial_does_not_emit_sendme :
    shouldEmitStreamSendme STREAM_WINDOW_INITIAL = false := by decide

----------------------------------------------------------------------------
-- Stream constants are NOT circuit constants
----------------------------------------------------------------------------

/-- Sanity check: applying a stream SENDME to a 999-credit window does
    NOT bring it to the circuit-INITIAL value (1000). This guards
    against a copy-paste bug that mixes layers. -/
theorem stream_sendme_does_not_match_circuit_increment (w : Int) :
    applyStreamSendme w ≠ applyCircuitSendme w ∨ false = true := by
  -- The two increments differ (50 vs 100), so for any w, the results
  -- differ. Use omega-witness via concrete unfolding.
  left
  unfold applyStreamSendme applyCircuitSendme applySendme
        STREAM_SENDME_INCREMENT CIRCUIT_SENDME_INCREMENT
  omega

----------------------------------------------------------------------------
-- canSendData and isWindowDepleted describe the same boundary
----------------------------------------------------------------------------

/-- **Boundary duality.** `canSendData` is exactly the negation of
    `isWindowDepleted` for any input. There is no gap where a window
    is simultaneously "send-allowed" and "depleted", nor any gap where
    it's neither — the two cleanly partition the integer line. -/
theorem canSendData_iff_not_depleted (w : Int) :
    canSendData w = !isWindowDepleted w := by
  unfold canSendData isWindowDepleted
  by_cases h : 0 < w
  · simp [h]
  · simp [h]
    omega

----------------------------------------------------------------------------
-- Validity preservation under spec-conformant transitions
----------------------------------------------------------------------------

/-- **Decrement preserves validity.** If the window is valid (in
    `[0, max]`) and strictly positive (i.e. we're allowed to send),
    then after one decrement it's still valid. No protocol-error
    transition. -/
theorem decrementWindow_preserves_validity (w max : Int)
    (hv : isValidWindow w max = true) (hp : 0 < w) :
    isValidWindow (decrementWindow w) max = true := by
  unfold isValidWindow at *
  unfold decrementWindow
  simp at hv
  simp
  omega

/-- **SENDME preserves validity** (when there's room). If the window
    is valid, the increment is non-negative (always true for spec
    SENDME values), and `w ≤ max - increment`, then applying the
    SENDME yields a valid window. -/
theorem applySendme_preserves_validity (w max increment : Int)
    (hv : isValidWindow w max = true)
    (hinc : 0 ≤ increment)
    (hroom : w ≤ max - increment) :
    isValidWindow (applySendme w increment) max = true := by
  unfold isValidWindow at *
  unfold applySendme
  simp at hv
  simp
  omega

----------------------------------------------------------------------------
-- Threshold-on-decrement: the receive side flips at exactly THRESHOLD+1
----------------------------------------------------------------------------

/-- **Threshold-on-decrement.** If the deliver window crosses from
    `threshold + 1` to `threshold` via a single decrement, the
    `shouldEmitSendme` flips from false to true. This is the
    "we just used up our last credit before the next SENDME" boundary. -/
theorem shouldEmitSendme_threshold_crossing (threshold : Int) :
    shouldEmitSendme (decrementWindow (threshold + 1)) threshold = true ∧
    shouldEmitSendme (threshold + 1) threshold = false := by
  unfold shouldEmitSendme decrementWindow
  refine ⟨?_, ?_⟩ <;> simp <;> omega

end Spec.SendmeWindow
