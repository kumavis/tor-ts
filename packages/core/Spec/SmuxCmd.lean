-- Specification theorems for the `smuxCmd` module.

import Generated.SmuxCmd
import Thales.TS.Runtime

open Thales.TS

namespace Spec.SmuxCmd

open _root_.SmuxCmd

deriving instance DecidableEq for SmuxCmd

----------------------------------------------------------------------------
-- Constants
----------------------------------------------------------------------------

theorem SMUX_HEADER_SIZE_eq : SMUX_HEADER_SIZE = 8 := rfl
theorem SMUX_UPD_PAYLOAD_SIZE_eq : SMUX_UPD_PAYLOAD_SIZE = 8 := rfl

----------------------------------------------------------------------------
-- Wire codes are in [0, 4]
----------------------------------------------------------------------------

theorem smuxCmdCode_in_range (c : SmuxCmd) :
    0 ≤ smuxCmdCode c ∧ smuxCmdCode c ≤ 4 := by
  cases c <;> (constructor <;> decide)

----------------------------------------------------------------------------
-- Round-trip
----------------------------------------------------------------------------

theorem smuxCmdFromCode_smuxCmdCode (c : SmuxCmd) :
    smuxCmdFromCode (smuxCmdCode c) = some c := by
  cases c <;> decide

theorem smuxCmdFromCode_isSome
    (n : Int) (hlo : 0 ≤ n) (hhi : n ≤ 4) :
    smuxCmdFromCode n ≠ none := by
  have henum : n = 0 ∨ n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 := by omega
  rcases henum with h | h | h | h | h <;> subst h <;> decide

theorem smuxCmdFromCode_neg :
    smuxCmdFromCode (-1) = none := by decide

theorem smuxCmdFromCode_above :
    smuxCmdFromCode 5 = none := by decide

----------------------------------------------------------------------------
-- smuxCarriesPayload iff cmd is PSH or UPD
----------------------------------------------------------------------------

theorem smuxCarriesPayload_iff (c : SmuxCmd) :
    smuxCarriesPayload c = true ↔
      (smuxCmdCode c = 2 ∨ smuxCmdCode c = 4) := by
  cases c <;> simp [smuxCarriesPayload, smuxCmdCode]

theorem smuxCarriesPayload_PSH : smuxCarriesPayload .PSH = true := by decide
theorem smuxCarriesPayload_UPD : smuxCarriesPayload .UPD = true := by decide
theorem smuxCarriesPayload_SYN : smuxCarriesPayload .SYN = false := by decide

----------------------------------------------------------------------------
-- smuxIsStreamLifecycle iff cmd is SYN or FIN
----------------------------------------------------------------------------

theorem smuxIsStreamLifecycle_iff (c : SmuxCmd) :
    smuxIsStreamLifecycle c = true ↔
      (smuxCmdCode c = 0 ∨ smuxCmdCode c = 1) := by
  cases c <;> simp [smuxIsStreamLifecycle, smuxCmdCode]

theorem smuxIsStreamLifecycle_SYN : smuxIsStreamLifecycle .SYN = true := by decide
theorem smuxIsStreamLifecycle_FIN : smuxIsStreamLifecycle .FIN = true := by decide

----------------------------------------------------------------------------
-- Classifier disjointness
----------------------------------------------------------------------------

/-- No SMUX command both carries a payload and is a stream-lifecycle
    event — the two classifiers are disjoint. -/
theorem classifiers_disjoint (c : SmuxCmd) :
    ¬(smuxCarriesPayload c = true ∧ smuxIsStreamLifecycle c = true) := by
  cases c <;> simp [smuxCarriesPayload, smuxIsStreamLifecycle]

end Spec.SmuxCmd
