-- Specification theorems for the `portRange` module.
--
-- This file imports the Thales-emitted sidecar from `Generated/` and
-- proves behavioural properties of its exported functions. Anything that
-- compiles here has been kernel-checked by Lean — that is what
-- "verified" means in `tor-core`.

import Generated.PortRange
import Thales.TS.Runtime

open Thales.TS

namespace Spec.PortRange

open _root_.PortRange  -- the namespace Thales generates from `portRange.ts`

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

end Spec.PortRange
