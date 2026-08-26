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

----------------------------------------------------------------------------
-- policyAllowsAllPorts
----------------------------------------------------------------------------

/-- Empty input list is vacuously satisfied. -/
theorem policyAllowsAllPorts_nil (policy : ExitPolicy) :
    policyAllowsAllPorts policy .nil = true := by
  simp [policyAllowsAllPorts]

/-- Cons-case unfolding: every port allowed iff head allowed AND tail allowed. -/
theorem policyAllowsAllPorts_cons (policy : ExitPolicy) (h : Int) (t : PortList) :
    policyAllowsAllPorts policy (.cons h t) =
      (policyAllowsPort policy h && policyAllowsAllPorts policy t) := by
  simp [policyAllowsAllPorts]

/-- A single-port list reduces to the per-port predicate. -/
theorem policyAllowsAllPorts_singleton (policy : ExitPolicy) (p : Int) :
    policyAllowsAllPorts policy (.cons p .nil) = policyAllowsPort policy p := by
  simp [policyAllowsAllPorts]

----------------------------------------------------------------------------
-- policyAllowsAnyPort
----------------------------------------------------------------------------

/-- Empty input short-circuits to true (matches the existing TS quirk). -/
theorem policyAllowsAnyPort_nil (policy : ExitPolicy) :
    policyAllowsAnyPort policy .nil = true := by
  simp [policyAllowsAnyPort]

/-- Cons-case unfolding. -/
theorem policyAllowsAnyPort_cons (policy : ExitPolicy) (h : Int) (t : PortList) :
    policyAllowsAnyPort policy (.cons h t) =
      (policyAllowsPort policy h || policyAllowsAnyPort policy t) := by
  simp [policyAllowsAnyPort]

----------------------------------------------------------------------------
-- isPortRangeListEmpty / isFullPortRange
----------------------------------------------------------------------------

theorem isPortRangeListEmpty_nil :
    isPortRangeListEmpty .nil = true := by
  simp [isPortRangeListEmpty]

theorem isPortRangeListEmpty_cons (r : PortRange) (rs : PortRangeList) :
    isPortRangeListEmpty (.cons r rs) = false := by
  simp [isPortRangeListEmpty]

theorem isFullPortRange_nil :
    isFullPortRange .nil = false := by
  simp [isFullPortRange]

theorem isFullPortRange_cons_full (tail : PortRangeList) :
    isFullPortRange (.cons ⟨1, 65535⟩ tail) = isPortRangeListEmpty tail := by
  simp [isFullPortRange]

----------------------------------------------------------------------------
-- policyRejectsAll
----------------------------------------------------------------------------

/-- Accept policy with empty range list rejects everything. -/
theorem policyRejectsAll_accept_empty :
    policyRejectsAll (.accept .nil) = true := by
  simp [policyRejectsAll, isPortRangeListEmpty]

/-- Accept policy with any non-empty range list does not reject all. -/
theorem policyRejectsAll_accept_cons (r : PortRange) (rs : PortRangeList) :
    policyRejectsAll (.accept (.cons r rs)) = false := by
  simp [policyRejectsAll, isPortRangeListEmpty]

/-- Reject policy with empty range list does not reject all (it accepts all). -/
theorem policyRejectsAll_reject_empty :
    policyRejectsAll (.reject .nil) = false := by
  simp [policyRejectsAll, isFullPortRange]

/-- Reject policy with the full range [1, 65535] rejects all. -/
theorem policyRejectsAll_reject_full :
    policyRejectsAll (.reject (.cons ⟨1, 65535⟩ .nil)) = true := by
  simp [policyRejectsAll, isFullPortRange, isPortRangeListEmpty]

/-- **Strong correctness theorem.** If `policyRejectsAll p` reports `true`,
    then no port in the valid Tor port range `[1, 65535]` is allowed.
    This is the security-meaningful claim: the function lives up to its
    name on the domain that matters. -/
theorem policyRejectsAll_implies_rejects_valid_port
    (p : ExitPolicy) (port : Int)
    (hr : policyRejectsAll p = true)
    (h1 : 1 ≤ port) (h2 : port ≤ 65535) :
    policyAllowsPort p port = false := by
  cases p with
  | accept ports =>
    cases ports with
    | nil => simp [policyAllowsPort, anyRangeContainsPort]
    | cons head tail =>
      simp [policyRejectsAll, isPortRangeListEmpty] at hr
  | reject ports =>
    cases ports with
    | nil => simp [policyRejectsAll, isFullPortRange] at hr
    | cons head tail =>
      cases tail with
      | cons headT tailT =>
        simp [policyRejectsAll, isFullPortRange, isPortRangeListEmpty] at hr
      | nil =>
        simp [policyRejectsAll, isFullPortRange, isPortRangeListEmpty] at hr
        obtain ⟨hs, he⟩ := hr
        simp [policyAllowsPort, anyRangeContainsPort, portInRange, hs, he]
        omega

end Spec.ExitPolicy
