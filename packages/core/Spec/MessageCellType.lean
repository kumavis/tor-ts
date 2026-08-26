-- Specification theorems for the `messageCellType` module.
--
-- Headlines:
--   * Wire codes for the 18 spec-defined cell types round-trip through
--     encode/decode without loss.
--   * `isVariableLengthCell` agrees with the spec predicate
--     "code = 7 OR code ≥ 128" — no hand-maintained list of variable-
--     length cells can drift from the wire definition without Lean
--     catching it.

import Generated.MessageCellType
import Thales.TS.Runtime

open Thales.TS

namespace Spec.MessageCellType

open _root_.MessageCellType

-- Thales emits inductives with `deriving Repr` only.
deriving instance DecidableEq for MessageCellType

----------------------------------------------------------------------------
-- Wire codes are in the spec ranges {0..12, 128..132}
----------------------------------------------------------------------------

/-- Every cell type's wire code is either in 0..12 or in 128..132 —
    no codes in the gap 13..127 (which is reserved for variable-length
    expansion in future spec revisions). -/
theorem messageCellTypeCode_in_range (t : MessageCellType) :
    (0 ≤ messageCellTypeCode t ∧ messageCellTypeCode t ≤ 12) ∨
    (128 ≤ messageCellTypeCode t ∧ messageCellTypeCode t ≤ 132) := by
  cases t <;> (first | (left; constructor <;> decide)
                     | (right; constructor <;> decide))

----------------------------------------------------------------------------
-- Round-trip: every constructor survives encode/decode
----------------------------------------------------------------------------

/-- **Encoding round-trip.** Every `MessageCellType` value, encoded to
    its numeric code and parsed back, yields the same value. -/
theorem messageCellTypeFromCode_messageCellTypeCode (t : MessageCellType) :
    messageCellTypeFromCode (messageCellTypeCode t) = some t := by
  cases t <;> decide

/-- **Decoding totality on valid codes (low range).** Every code in
    `[0, 12]` decodes to some constructor. -/
theorem messageCellTypeFromCode_isSome_low
    (c : Int) (hlo : 0 ≤ c) (hhi : c ≤ 12) :
    messageCellTypeFromCode c ≠ none := by
  have henum : c = 0 ∨ c = 1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6 ∨
               c = 7 ∨ c = 8 ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 := by omega
  rcases henum with h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

/-- **Decoding totality on valid codes (high range).** Every code in
    `[128, 132]` decodes to some constructor. -/
theorem messageCellTypeFromCode_isSome_high
    (c : Int) (hlo : 128 ≤ c) (hhi : c ≤ 132) :
    messageCellTypeFromCode c ≠ none := by
  have henum : c = 128 ∨ c = 129 ∨ c = 130 ∨ c = 131 ∨ c = 132 := by omega
  rcases henum with h|h|h|h|h <;> subst h <;> decide

----------------------------------------------------------------------------
-- Out-of-range spot checks
----------------------------------------------------------------------------

theorem messageCellTypeFromCode_neg :
    messageCellTypeFromCode (-1) = none := by decide

theorem messageCellTypeFromCode_gap_low :
    messageCellTypeFromCode 13 = none := by decide

theorem messageCellTypeFromCode_gap_mid :
    messageCellTypeFromCode 64 = none := by decide

theorem messageCellTypeFromCode_gap_high :
    messageCellTypeFromCode 127 = none := by decide

theorem messageCellTypeFromCode_above :
    messageCellTypeFromCode 133 = none := by decide

theorem messageCellTypeFromCode_thousand :
    messageCellTypeFromCode 1000 = none := by decide

----------------------------------------------------------------------------
-- isVariableLengthCell agrees with the spec predicate
----------------------------------------------------------------------------

/-- **The headline theorem.** `isVariableLengthCell t = true` iff the
    cell's wire code is exactly 7 (`VERSIONS`) or at least 128. This is
    the precise spec predicate from tor-spec.txt §3 — proving the two
    formulations agree means the hand-maintained variant list and the
    wire predicate cannot drift. -/
theorem isVariableLengthCell_iff (t : MessageCellType) :
    isVariableLengthCell t = true ↔
      (messageCellTypeCode t = 7 ∨ 128 ≤ messageCellTypeCode t) := by
  cases t <;> simp [isVariableLengthCell, messageCellTypeCode]

/-- The contrapositive: fixed-length cells have codes in `0..6` or
    `8..12`. -/
theorem isVariableLengthCell_false_iff (t : MessageCellType) :
    isVariableLengthCell t = false ↔
      ((0 ≤ messageCellTypeCode t ∧ messageCellTypeCode t ≤ 6) ∨
       (8 ≤ messageCellTypeCode t ∧ messageCellTypeCode t ≤ 12)) := by
  cases t <;> simp [isVariableLengthCell, messageCellTypeCode]

----------------------------------------------------------------------------
-- Witness theorems for both length classes
----------------------------------------------------------------------------

theorem variable_witness_versions :
    isVariableLengthCell .VERSIONS = true := by decide

theorem variable_witness_certs :
    isVariableLengthCell .CERTS = true := by decide

theorem fixed_witness_relay :
    isVariableLengthCell .RELAY = false := by decide

theorem fixed_witness_destroy :
    isVariableLengthCell .DESTROY = false := by decide

end Spec.MessageCellType
