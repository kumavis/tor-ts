-- Specification theorems for the `destroyReason` module.

import Generated.DestroyReason
import Thales.TS.Runtime

open Thales.TS

namespace Spec.DestroyReason

open _root_.DestroyReason

deriving instance DecidableEq for DestroyReason

----------------------------------------------------------------------------
-- Wire codes are in [0, 12]
----------------------------------------------------------------------------

theorem destroyReasonCode_in_range (r : DestroyReason) :
    0 ≤ destroyReasonCode r ∧ destroyReasonCode r ≤ 12 := by
  cases r <;> (constructor <;> decide)

----------------------------------------------------------------------------
-- Round-trip
----------------------------------------------------------------------------

/-- **Round-trip.** -/
theorem destroyReasonFromCode_destroyReasonCode (r : DestroyReason) :
    destroyReasonFromCode (destroyReasonCode r) = some r := by
  cases r <;> decide

theorem destroyReasonFromCode_isSome
    (c : Int) (hlo : 0 ≤ c) (hhi : c ≤ 12) :
    destroyReasonFromCode c ≠ none := by
  have henum : c = 0 ∨ c = 1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6 ∨
               c = 7 ∨ c = 8 ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 := by omega
  rcases henum with h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

theorem destroyReasonFromCode_neg :
    destroyReasonFromCode (-1) = none := by decide

theorem destroyReasonFromCode_above :
    destroyReasonFromCode 13 = none := by decide

----------------------------------------------------------------------------
-- isCleanDestroy
----------------------------------------------------------------------------

/-- **Clean-destroy characterization.** A destroy reason is clean iff
    its wire code is 0 (NONE), 3 (REQUESTED), or 9 (FINISHED). -/
theorem isCleanDestroy_iff (r : DestroyReason) :
    isCleanDestroy r = true ↔
      destroyReasonCode r = 0 ∨ destroyReasonCode r = 3 ∨ destroyReasonCode r = 9 := by
  cases r <;> simp [isCleanDestroy, destroyReasonCode]

theorem isCleanDestroy_NONE : isCleanDestroy .NONE = true := by decide

theorem isCleanDestroy_REQUESTED : isCleanDestroy .REQUESTED = true := by decide

theorem isCleanDestroy_FINISHED : isCleanDestroy .FINISHED = true := by decide

theorem isCleanDestroy_PROTOCOL : isCleanDestroy .PROTOCOL = false := by decide

end Spec.DestroyReason
