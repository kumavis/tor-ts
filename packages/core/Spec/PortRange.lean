-- Specification theorems for the `portRange` module.
--
-- This file imports the Thales-emitted sidecar (in `Generated/`) and proves
-- behavioural properties of the exported functions. Anything that compiles
-- here has been kernel-checked by Lean — that is what "verified" means in
-- `tor-core`.
--
-- The exact import path on the next line is what Thales emits for
-- `src/portRange.ts` once the verify script has run. If the emitter
-- changes its naming convention, this import is the place to update.

import Generated.PortRange
import Thales.TS.Runtime

open Thales.TS

namespace Spec.PortRange

/-- Smoke theorem: the proof harness compiles.
    Replaced with real properties of `portInRange` once we have observed
    the emitted shape on a first CI run. -/
theorem proofHarness_compiles : True := trivial

end Spec.PortRange
