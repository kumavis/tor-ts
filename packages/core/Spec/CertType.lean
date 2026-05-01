-- Specification theorems for the `certType` module.

import Generated.CertType
import Thales.TS.Runtime

open Thales.TS

namespace Spec.CertType

open _root_.CertType

deriving instance DecidableEq for CertType

----------------------------------------------------------------------------
-- Wire codes are in [1, 10]
----------------------------------------------------------------------------

theorem certTypeCode_in_range (c : CertType) :
    1 ≤ certTypeCode c ∧ certTypeCode c ≤ 10 := by
  cases c <;> (constructor <;> decide)

----------------------------------------------------------------------------
-- Round-trip
----------------------------------------------------------------------------

/-- **Round-trip.** -/
theorem certTypeFromCode_certTypeCode (c : CertType) :
    certTypeFromCode (certTypeCode c) = some c := by
  cases c <;> decide

theorem certTypeFromCode_isSome
    (n : Int) (hlo : 1 ≤ n) (hhi : n ≤ 10) :
    certTypeFromCode n ≠ none := by
  have henum : n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 ∨ n = 5 ∨ n = 6 ∨ n = 7 ∨
               n = 8 ∨ n = 9 ∨ n = 10 := by omega
  rcases henum with h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

theorem certTypeFromCode_zero :
    certTypeFromCode 0 = none := by decide

theorem certTypeFromCode_above :
    certTypeFromCode 11 = none := by decide

----------------------------------------------------------------------------
-- isLegacyX509Cert iff code ∈ [1, 3]
----------------------------------------------------------------------------

/-- **Legacy-X509 characterization.** -/
theorem isLegacyX509Cert_iff (c : CertType) :
    isLegacyX509Cert c = true ↔
      (1 ≤ certTypeCode c ∧ certTypeCode c ≤ 3) := by
  cases c <;> simp [isLegacyX509Cert, certTypeCode]

----------------------------------------------------------------------------
-- isHiddenServiceCert iff code ∈ {8, 9}
----------------------------------------------------------------------------

/-- **Hidden-service cert characterization.** -/
theorem isHiddenServiceCert_iff (c : CertType) :
    isHiddenServiceCert c = true ↔
      (certTypeCode c = 8 ∨ certTypeCode c = 9) := by
  cases c <;> simp [isHiddenServiceCert, certTypeCode]

/-- **Disjointness.** No cert is both legacy and hidden-service. -/
theorem legacy_and_hs_disjoint (c : CertType) :
    ¬(isLegacyX509Cert c = true ∧ isHiddenServiceCert c = true) := by
  cases c <;> simp [isLegacyX509Cert, isHiddenServiceCert]

end Spec.CertType
