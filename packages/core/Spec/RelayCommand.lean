-- Specification theorems for the `relayCommand` module.
--
-- Headlines:
--   * Wire codes for the 28 spec-defined relay commands round-trip
--     through encode/decode.
--   * Each range-class predicate (`isHiddenServiceCommand`,
--     `isPaddingCommand`, `isFlowControlCommand`) agrees with the
--     corresponding numeric-range claim, so the type, the predicate,
--     and the spec range cannot drift.

import Generated.RelayCommand
import Thales.TS.Runtime

open Thales.TS

namespace Spec.RelayCommand

open _root_.RelayCommand

-- Thales emits inductives with `deriving Repr` only.
deriving instance DecidableEq for RelayCommand

----------------------------------------------------------------------------
-- Wire codes are in {1..15} ∪ {32..44}
----------------------------------------------------------------------------

theorem relayCommandCode_in_range (c : RelayCommand) :
    (1 ≤ relayCommandCode c ∧ relayCommandCode c ≤ 15) ∨
    (32 ≤ relayCommandCode c ∧ relayCommandCode c ≤ 44) := by
  cases c <;> (first | (left; constructor <;> decide)
                     | (right; constructor <;> decide))

----------------------------------------------------------------------------
-- Round-trip: every constructor survives encode/decode
----------------------------------------------------------------------------

/-- **Encoding round-trip.** Every `RelayCommand` value, encoded to its
    numeric code and parsed back, yields the same value. -/
theorem relayCommandFromCode_relayCommandCode (c : RelayCommand) :
    relayCommandFromCode (relayCommandCode c) = some c := by
  cases c <;> decide

/-- **Decoding totality on regular commands.** Every code in `[1, 15]`
    decodes to some constructor. -/
theorem relayCommandFromCode_isSome_regular
    (n : Int) (hlo : 1 ≤ n) (hhi : n ≤ 15) :
    relayCommandFromCode n ≠ none := by
  have henum : n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 ∨ n = 5 ∨ n = 6 ∨ n = 7 ∨
               n = 8 ∨ n = 9 ∨ n = 10 ∨ n = 11 ∨ n = 12 ∨ n = 13 ∨ n = 14 ∨
               n = 15 := by omega
  rcases henum with h|h|h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

/-- **Decoding totality on hidden-service / padding / flow-control
    commands.** Every code in `[32, 44]` decodes to some constructor. -/
theorem relayCommandFromCode_isSome_extended
    (n : Int) (hlo : 32 ≤ n) (hhi : n ≤ 44) :
    relayCommandFromCode n ≠ none := by
  have henum : n = 32 ∨ n = 33 ∨ n = 34 ∨ n = 35 ∨ n = 36 ∨ n = 37 ∨
               n = 38 ∨ n = 39 ∨ n = 40 ∨ n = 41 ∨ n = 42 ∨ n = 43 ∨
               n = 44 := by omega
  rcases henum with h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

----------------------------------------------------------------------------
-- Out-of-range spot checks
----------------------------------------------------------------------------

theorem relayCommandFromCode_zero :
    relayCommandFromCode 0 = none := by decide

theorem relayCommandFromCode_neg :
    relayCommandFromCode (-1) = none := by decide

/-- The reserved gap 16..31 (UDP / Conflux per relay-spec.txt) is unmapped. -/
theorem relayCommandFromCode_gap_low :
    relayCommandFromCode 16 = none := by decide

theorem relayCommandFromCode_gap_high :
    relayCommandFromCode 31 = none := by decide

theorem relayCommandFromCode_above :
    relayCommandFromCode 45 = none := by decide

theorem relayCommandFromCode_thousand :
    relayCommandFromCode 1000 = none := by decide

----------------------------------------------------------------------------
-- isHiddenServiceCommand iff code ∈ [32, 40]
----------------------------------------------------------------------------

/-- **Hidden-service range characterization.** A command is a
    hidden-service command iff its wire code is in `[32, 40]`. -/
theorem isHiddenServiceCommand_iff (c : RelayCommand) :
    isHiddenServiceCommand c = true ↔
      (32 ≤ relayCommandCode c ∧ relayCommandCode c ≤ 40) := by
  cases c <;> simp [isHiddenServiceCommand, relayCommandCode]

----------------------------------------------------------------------------
-- isPaddingCommand iff code ∈ [41, 42]
----------------------------------------------------------------------------

theorem isPaddingCommand_iff (c : RelayCommand) :
    isPaddingCommand c = true ↔
      (41 ≤ relayCommandCode c ∧ relayCommandCode c ≤ 42) := by
  cases c <;> simp [isPaddingCommand, relayCommandCode]

----------------------------------------------------------------------------
-- isFlowControlCommand iff code ∈ [43, 44]
----------------------------------------------------------------------------

theorem isFlowControlCommand_iff (c : RelayCommand) :
    isFlowControlCommand c = true ↔
      (43 ≤ relayCommandCode c ∧ relayCommandCode c ≤ 44) := by
  cases c <;> simp [isFlowControlCommand, relayCommandCode]

----------------------------------------------------------------------------
-- The three classifiers partition the extended range [32, 44]
----------------------------------------------------------------------------

/-- **Classifier disjointness.** No command is in more than one
    range-class — the three classifiers partition the codes. -/
theorem classifiers_disjoint (c : RelayCommand) :
    ¬(isHiddenServiceCommand c = true ∧ isPaddingCommand c = true) ∧
    ¬(isHiddenServiceCommand c = true ∧ isFlowControlCommand c = true) ∧
    ¬(isPaddingCommand c = true ∧ isFlowControlCommand c = true) := by
  cases c <;> simp [isHiddenServiceCommand, isPaddingCommand, isFlowControlCommand]

----------------------------------------------------------------------------
-- Spot witnesses (one per classifier)
----------------------------------------------------------------------------

theorem hs_witness_introduce1 :
    isHiddenServiceCommand (.INTRODUCE1) = true := by decide

theorem padding_witness_negotiate :
    isPaddingCommand (.PADDING_NEGOTIATE) = true := by decide

theorem flow_witness_xon :
    isFlowControlCommand (.XON) = true := by decide

theorem regular_negative_begin :
    isHiddenServiceCommand (.BEGIN) = false ∧
    isPaddingCommand (.BEGIN) = false ∧
    isFlowControlCommand (.BEGIN) = false := by
  refine ⟨?_, ?_, ?_⟩ <;> decide

end Spec.RelayCommand
