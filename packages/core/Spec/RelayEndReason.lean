-- Specification theorems for the `relayEndReason` module.
--
-- The headlines:
--   * Wire codes for the 14 spec-defined reasons round-trip through
--     encode/decode without loss.
--   * `isRetryableEndReason` agrees with `getStreamRetryBehavior`: it's
--     true exactly when the policy isn't `no_retry`. Even though
--     Thales 0.5 made us inline the switch (workaround for the bug
--     described in `docs/thales-issues.md`), the two formulations are
--     proved equivalent here.

import Generated.RelayEndReason
import Thales.TS.Runtime

open Thales.TS

namespace Spec.RelayEndReason

open _root_.RelayEndReason

-- Thales emits the inductives with `deriving Repr` only; we need
-- decidable equality on both to drive `decide` and `simp` in proofs
-- below.
deriving instance DecidableEq for RelayEndReason
deriving instance DecidableEq for StreamRetryBehavior

----------------------------------------------------------------------------
-- Wire codes are in the spec range [1, 14]
----------------------------------------------------------------------------

theorem relayEndReasonCode_in_range (r : RelayEndReason) :
    1 ≤ relayEndReasonCode r ∧ relayEndReasonCode r ≤ 14 := by
  cases r <;> (constructor <;> decide)

----------------------------------------------------------------------------
-- Round-trip: every constructor survives encode/decode
----------------------------------------------------------------------------

/-- **Encoding round-trip.** Every `RelayEndReason` value, encoded to
    its numeric code and parsed back, yields the same value. The lookup
    table on the wire is faithful. -/
theorem relayEndReasonFromCode_relayEndReasonCode (r : RelayEndReason) :
    relayEndReasonFromCode (relayEndReasonCode r) = some r := by
  cases r <;> decide

/-- **Decoding totality on valid codes.** Every spec-defined code
    in `[1, 14]` decodes to some constructor (i.e., parsing never
    fails on a well-formed code). -/
theorem relayEndReasonFromCode_isSome
    (c : Int) (hlo : 1 ≤ c) (hhi : c ≤ 14) :
    relayEndReasonFromCode c ≠ none := by
  have henum : c = 1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6 ∨ c = 7 ∨
               c = 8 ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 ∨ c = 13 ∨ c = 14 := by
    omega
  rcases henum with h|h|h|h|h|h|h|h|h|h|h|h|h|h <;> subst h <;> decide

----------------------------------------------------------------------------
-- Concrete out-of-range spot checks
----------------------------------------------------------------------------

theorem relayEndReasonFromCode_zero : relayEndReasonFromCode 0 = none := by decide
theorem relayEndReasonFromCode_neg : relayEndReasonFromCode (-1) = none := by decide
theorem relayEndReasonFromCode_fifteen : relayEndReasonFromCode 15 = none := by decide
theorem relayEndReasonFromCode_thousand : relayEndReasonFromCode 1000 = none := by decide

----------------------------------------------------------------------------
-- isRetryableEndReason agrees with getStreamRetryBehavior
----------------------------------------------------------------------------

/-- **Consistency theorem.** `isRetryableEndReason r = true` iff
    `getStreamRetryBehavior r` is anything other than `.no_retry`.
    Even though Thales 0.5 forced us to inline the switch (rather than
    delegate to `getStreamRetryBehavior`), the two formulations are
    semantically identical. -/
theorem isRetryableEndReason_iff_not_no_retry (r : RelayEndReason) :
    isRetryableEndReason r = true ↔ getStreamRetryBehavior r ≠ .no_retry := by
  cases r <;> simp [isRetryableEndReason, getStreamRetryBehavior]

/-- The contrapositive: a non-retryable reason has `no_retry` policy. -/
theorem not_isRetryableEndReason_iff_no_retry (r : RelayEndReason) :
    isRetryableEndReason r = false ↔ getStreamRetryBehavior r = .no_retry := by
  cases r <;> simp [isRetryableEndReason, getStreamRetryBehavior]

----------------------------------------------------------------------------
-- Spot checks: each retry class is non-empty (sanity for the trichotomy)
----------------------------------------------------------------------------

theorem retry_exit_witness :
    getStreamRetryBehavior (.REASON_EXITPOLICY) = .retry_exit := rfl

theorem retry_circuit_witness :
    getStreamRetryBehavior (.REASON_TIMEOUT) = .retry_circuit := rfl

theorem no_retry_witness :
    getStreamRetryBehavior (.REASON_DONE) = .no_retry := rfl

end Spec.RelayEndReason
