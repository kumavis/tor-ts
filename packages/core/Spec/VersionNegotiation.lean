-- Specification theorems for the `versionNegotiation` module.

import Generated.VersionNegotiation
import Thales.TS.Runtime

open Thales.TS

namespace Spec.VersionNegotiation

open _root_.VersionNegotiation

deriving instance DecidableEq for VersionList
deriving instance DecidableEq for MaxAcc

----------------------------------------------------------------------------
-- containsVersion
----------------------------------------------------------------------------

theorem containsVersion_nil (v : Int) :
    containsVersion .nil v = false := rfl

/-- The head of a list is always contained in the list. -/
theorem containsVersion_cons_head (v : Int) (t : VersionList) :
    containsVersion (.cons v t) v = true := by
  simp [containsVersion]

/-- A non-head element is contained iff it's contained in the tail. -/
theorem containsVersion_cons_other (v h : Int) (t : VersionList) (hne : v ≠ h) :
    containsVersion (.cons h t) v = containsVersion t v := by
  simp [containsVersion]
  intro heq
  exfalso
  exact hne heq.symm

----------------------------------------------------------------------------
-- updateMax
----------------------------------------------------------------------------

theorem updateMax_none (c : Int) :
    updateMax .none c = .some c := by
  simp [updateMax]

/-- A SENDME-style update: when the candidate is no greater than the
    current max, keep the current. -/
theorem updateMax_keeps (v c : Int) (h : v ≥ c) :
    updateMax (.some v) c = .some v := by
  simp [updateMax, h]

theorem updateMax_replaces (v c : Int) (h : v < c) :
    updateMax (.some v) c = .some c := by
  simp [updateMax]
  intro hge
  omega

----------------------------------------------------------------------------
-- maxCommonVersion: empty input cases
----------------------------------------------------------------------------

theorem maxCommonVersion_nil_client (server : VersionList) :
    maxCommonVersion .nil server = .none := by
  simp [maxCommonVersion, maxCommonVersionAux]

/-- Walking any client list against an empty server list yields the
    accumulator unchanged, by induction on the client list. -/
theorem maxCommonVersionAux_nil_server (client : VersionList) (acc : MaxAcc) :
    maxCommonVersionAux client .nil acc = acc := by
  induction client generalizing acc with
  | nil => simp [maxCommonVersionAux]
  | cons head tail ih =>
    simp [maxCommonVersionAux, containsVersion]
    exact ih acc

theorem maxCommonVersion_nil_server (client : VersionList) :
    maxCommonVersion client .nil = .none := by
  unfold maxCommonVersion
  rw [maxCommonVersionAux_nil_server client .none]

----------------------------------------------------------------------------
-- maxCommonVersion: concrete spot checks
----------------------------------------------------------------------------

/-- Both sides offering only version 3 → max common is 3. -/
theorem maxCommonVersion_singleton_match :
    maxCommonVersion (.cons 3 .nil) (.cons 3 .nil) = .some 3 := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

/-- Disjoint singletons → no overlap. -/
theorem maxCommonVersion_singleton_disjoint :
    maxCommonVersion (.cons 3 .nil) (.cons 4 .nil) = .none := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

/-- The headline use case: client {3,4,5}, server {3,4,5} → max common 5. -/
theorem maxCommonVersion_default_link_versions :
    maxCommonVersion
      (.cons 3 (.cons 4 (.cons 5 .nil)))
      (.cons 3 (.cons 4 (.cons 5 .nil)))
      = .some 5 := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

/-- Client {3,4,5}, server {3,4} → max common 4. -/
theorem maxCommonVersion_subset :
    maxCommonVersion
      (.cons 3 (.cons 4 (.cons 5 .nil)))
      (.cons 3 (.cons 4 .nil))
      = .some 4 := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

/-- Client only knows version 1; server only knows 4. No overlap. -/
theorem maxCommonVersion_no_overlap :
    maxCommonVersion
      (.cons 1 .nil)
      (.cons 4 (.cons 5 .nil))
      = .none := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

----------------------------------------------------------------------------
-- Order-independence on the client side
----------------------------------------------------------------------------

/-- Reordering a 2-element client list doesn't change the negotiated
    maximum. (A spot check on the order-irrelevance property; the
    general permutation-invariance is harder to state without
    permutation infrastructure.) -/
theorem maxCommonVersion_order_independent_pair :
    maxCommonVersion
      (.cons 4 (.cons 5 .nil))
      (.cons 3 (.cons 4 (.cons 5 .nil)))
      =
    maxCommonVersion
      (.cons 5 (.cons 4 .nil))
      (.cons 3 (.cons 4 (.cons 5 .nil))) := by
  simp [maxCommonVersion, maxCommonVersionAux, containsVersion, updateMax]

end Spec.VersionNegotiation
