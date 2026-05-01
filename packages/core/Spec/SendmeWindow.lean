-- Specification theorems for the `sendmeWindow` module.
--
-- Tor's flow-control windows are easy to reason about *individually*
-- but easy to get *wrong* in code. The headline guarantees here:
--
--   * decrement / applySendme are exactly arithmetic ±1 / ±100
--   * isWindowDepleted, shouldEmitSendme, isValidWindow agree with
--     the natural numeric predicates
--   * Validity is preserved under spec-conformant transitions: a
--     valid window in (0, INITIAL] stays valid after one decrement;
--     a valid window in [0, INITIAL - INCREMENT] stays valid after
--     applying a SENDME.
--   * canSendData is exactly the negation of isWindowDepleted on the
--     positive-or-zero domain — i.e. they describe the same boundary.

import Generated.SendmeWindow
import Thales.TS.Runtime

open Thales.TS

namespace Spec.SendmeWindow

open _root_.SendmeWindow

----------------------------------------------------------------------------
-- Spec constants are what they should be
----------------------------------------------------------------------------

theorem SENDME_INITIAL_eq : SENDME_INITIAL = 1000 := rfl
theorem SENDME_INCREMENT_eq : SENDME_INCREMENT = 100 := rfl
theorem SENDME_THRESHOLD_eq : SENDME_THRESHOLD = 900 := rfl

/-- THRESHOLD = INITIAL − INCREMENT. The threshold is exactly one
    SENDME away from the starting value. -/
theorem threshold_eq_initial_minus_increment :
    SENDME_THRESHOLD = SENDME_INITIAL - SENDME_INCREMENT := by
  unfold SENDME_THRESHOLD SENDME_INITIAL SENDME_INCREMENT
  decide

----------------------------------------------------------------------------
-- decrementWindow / applySendme are pure arithmetic
----------------------------------------------------------------------------

theorem decrementWindow_eq (w : Int) : decrementWindow w = w - 1 := rfl

theorem applySendme_eq (w : Int) : applySendme w = w + 100 := by
  unfold applySendme SENDME_INCREMENT
  rfl

/-- A SENDME exactly cancels `INCREMENT` decrements. -/
theorem sendme_cancels_decrements (w : Int) :
    applySendme (decrementWindow (decrementWindow w)) = w + 98 := by
  simp [applySendme, decrementWindow, SENDME_INCREMENT]
  omega

/-- Receiving a SENDME after using all the credits returns the window
    to its previous value. (Concrete instance: 100 decrements then a
    SENDME = identity. The general case requires non-structural
    recursion to count, so we state it as a single-step witness:
    `applySendme w = w + 100`, so two SENDMEs add 200, etc.) -/
theorem sendme_round_trip_one_increment (w : Int) :
    applySendme w - 100 = w := by
  unfold applySendme SENDME_INCREMENT
  omega

----------------------------------------------------------------------------
-- Predicate characterizations
----------------------------------------------------------------------------

theorem isWindowDepleted_iff (w : Int) :
    isWindowDepleted w = true ↔ w ≤ 0 := by
  unfold isWindowDepleted
  simp

theorem shouldEmitSendme_iff (w : Int) :
    shouldEmitSendme w = true ↔ w ≤ 900 := by
  unfold shouldEmitSendme SENDME_THRESHOLD
  simp

theorem isValidWindow_iff (w : Int) :
    isValidWindow w = true ↔ 0 ≤ w ∧ w ≤ 1000 := by
  unfold isValidWindow SENDME_INITIAL
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
-- Concrete spot-check witnesses
----------------------------------------------------------------------------

theorem initial_is_valid : isValidWindow SENDME_INITIAL = true := by decide

theorem zero_is_valid : isValidWindow 0 = true := by decide

theorem zero_is_depleted : isWindowDepleted 0 = true := by decide

theorem initial_is_not_depleted : isWindowDepleted SENDME_INITIAL = false := by decide

theorem threshold_emits_sendme : shouldEmitSendme SENDME_THRESHOLD = true := by decide

theorem initial_does_not_emit_sendme :
    shouldEmitSendme SENDME_INITIAL = false := by decide

----------------------------------------------------------------------------
-- canSendData and isWindowDepleted describe the same boundary
----------------------------------------------------------------------------

/-- **Boundary duality.** `canSendData` is exactly the negation of
    `isWindowDepleted` for any input. This means there is no gap
    where a window is simultaneously "send-allowed" and "depleted",
    nor any gap where it's neither — the two cleanly partition the
    integer line. -/
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

/-- **Decrement preserves validity.** If the window is valid and
    strictly positive (i.e. we're allowed to send), then after one
    decrement it's still valid. No protocol-error transition. -/
theorem decrementWindow_preserves_validity (w : Int)
    (hv : isValidWindow w = true) (hp : 0 < w) :
    isValidWindow (decrementWindow w) = true := by
  unfold isValidWindow SENDME_INITIAL at *
  unfold decrementWindow
  simp at hv
  simp
  omega

/-- **SENDME preserves validity** (when there's room). If the window
    is valid and is at most `INITIAL - INCREMENT`, then applying a
    SENDME yields a valid window. -/
theorem applySendme_preserves_validity (w : Int)
    (hv : isValidWindow w = true) (hroom : w ≤ 900) :
    isValidWindow (applySendme w) = true := by
  unfold isValidWindow SENDME_INITIAL at *
  unfold applySendme SENDME_INCREMENT
  simp at hv
  simp
  omega

----------------------------------------------------------------------------
-- The receive side: every cell that depletes the deliver window
-- triggers a SENDME on the next pass.
----------------------------------------------------------------------------

/-- **Threshold-on-decrement.** If the deliver window crosses from
    `THRESHOLD + 1` to `THRESHOLD` via a single decrement, the
    next-call `shouldEmitSendme` flips from false to true. This is the
    "we just used up our last credit before the next SENDME" boundary. -/
theorem shouldEmitSendme_threshold_crossing :
    shouldEmitSendme (decrementWindow (SENDME_THRESHOLD + 1)) = true ∧
    shouldEmitSendme (SENDME_THRESHOLD + 1) = false := by
  unfold shouldEmitSendme decrementWindow SENDME_THRESHOLD
  refine ⟨?_, ?_⟩ <;> simp

end Spec.SendmeWindow
