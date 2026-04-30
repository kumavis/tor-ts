-- Specification theorems for the `exitPolicy` module.
--
-- This file imports the Thales-emitted sidecar from `Generated/` and
-- proves behavioural properties of its exported functions. Anything that
-- compiles here has been kernel-checked by Lean — that is what
-- "verified" means in `tor-core`.

import Generated.ExitPolicy
import Thales.TS.Runtime

open Thales.TS

namespace Spec.ExitPolicy

open _root_.ExitPolicy  -- namespace Thales generates from `exitPolicy.ts`

----------------------------------------------------------------------------
-- portInRange
----------------------------------------------------------------------------

/-- `portInRange` is exactly membership in the closed interval
    `[start, endPort]`. -/
theorem portInRange_iff (p : Int) (r : PortRange) :
    portInRange p r = true ↔ r.start ≤ p ∧ p ≤ r.endPort := by
  simp [portInRange]

/-- A port is always in a degenerate range that contains exactly itself. -/
theorem portInRange_singleton (p : Int) :
    portInRange p ⟨p, p⟩ = true := by
  simp [portInRange]

/-- A range with `start > endPort` is empty: no port is in it. -/
theorem portInRange_empty (p s e : Int) (h : e < s) :
    portInRange p ⟨s, e⟩ = false := by
  simp [portInRange]
  intro hsp
  omega

----------------------------------------------------------------------------
-- anyRangeContainsPort
----------------------------------------------------------------------------

/-- An empty list never contains a port. -/
theorem anyRangeContainsPort_nil (p : Int) :
    anyRangeContainsPort p .nil = false := by
  simp [anyRangeContainsPort]

/-- Cons-case unfolding: it's a port-in-head OR port-in-tail. -/
theorem anyRangeContainsPort_cons (p : Int) (r : PortRange) (rs : PortRangeList) :
    anyRangeContainsPort p (.cons r rs) =
      (portInRange p r || anyRangeContainsPort p rs) := by
  simp [anyRangeContainsPort]

/-- If the head matches, the whole list matches — regardless of tail. -/
theorem anyRangeContainsPort_head (p : Int) (r : PortRange) (rs : PortRangeList)
    (h : portInRange p r = true) :
    anyRangeContainsPort p (.cons r rs) = true := by
  simp [anyRangeContainsPort, h]

----------------------------------------------------------------------------
-- policyAllowsPort
----------------------------------------------------------------------------

/-- Accept policies are permissive iff the port hits the list. -/
theorem policyAllowsPort_accept (p : Int) (rs : PortRangeList) :
    policyAllowsPort (.accept rs) p = anyRangeContainsPort p rs := by
  simp [policyAllowsPort]

/-- Reject policies are permissive iff the port misses the list. -/
theorem policyAllowsPort_reject (p : Int) (rs : PortRangeList) :
    policyAllowsPort (.reject rs) p = !anyRangeContainsPort p rs := by
  simp [policyAllowsPort]

/-- An accept policy with an empty range list rejects every port. -/
theorem policyAllowsPort_accept_empty (p : Int) :
    policyAllowsPort (.accept .nil) p = false := by
  simp [policyAllowsPort, anyRangeContainsPort]

/-- A reject policy with an empty range list permits every port. -/
theorem policyAllowsPort_reject_empty (p : Int) :
    policyAllowsPort (.reject .nil) p = true := by
  simp [policyAllowsPort, anyRangeContainsPort]

/-- Accept and reject of the same range list are exact complements. -/
theorem policyAllowsPort_accept_reject_complement (p : Int) (rs : PortRangeList) :
    policyAllowsPort (.accept rs) p = !policyAllowsPort (.reject rs) p := by
  simp [policyAllowsPort]

end Spec.ExitPolicy
