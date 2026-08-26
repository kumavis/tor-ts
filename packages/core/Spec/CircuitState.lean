-- Specification theorems for the `circuitState` module.
--
-- The headlines:
--   * `destroyed` is stable.
--   * `open` rejects extension attempts (a built circuit cannot be
--     re-extended; a peer trying it triggers tear-down).
--   * Building progresses by exactly one hop on each `recv_hop_built`,
--     until the target is met, at which point it transitions to `open`.
--   * `hopCount` is monotone-non-decreasing across successful
--     `recv_hop_built` transitions during building.

import Generated.CircuitState
import Thales.TS.Runtime

open Thales.TS

namespace Spec.CircuitState

open _root_.CircuitState

deriving instance DecidableEq for CircuitState
deriving instance DecidableEq for CircuitInput

----------------------------------------------------------------------------
-- Terminal state is stable
----------------------------------------------------------------------------

/-- **Destroyed is stable.** Once a circuit is torn down, no input
    revives it. -/
theorem step_destroyed_stable (r : Int) (i : CircuitInput) :
    step (.destroyed r) i = .destroyed r := by
  simp [step]

----------------------------------------------------------------------------
-- Building advances on hop_built
----------------------------------------------------------------------------

/-- **Last hop completes the circuit.** When the next hop would meet
    or exceed the target, building transitions to `open` with the
    target hop count. -/
theorem advanceBuilding_at_target (built target : Int) (h : built + 1 ≥ target) :
    advanceBuilding built target = .open target := by
  unfold advanceBuilding
  rw [if_pos h]

/-- **Mid-build advance.** Below the target, building advances by one
    hop and keeps the same target. -/
theorem advanceBuilding_below_target (built target : Int) (h : built + 1 < target) :
    advanceBuilding built target = .building (built + 1) target := by
  unfold advanceBuilding
  rw [if_neg (by omega : ¬(built + 1 ≥ target))]

/-- A 1-hop circuit completes on the first `recv_hop_built`. -/
theorem step_building_zero_one_hop_built :
    step (.building 0 1) .recv_hop_built = .open 1 := by
  simp [step, stepFromBuilding, advanceBuilding]

/-- A 3-hop circuit at hopsBuilt=2 completes on the next hop_built. -/
theorem step_building_two_three_hop_built :
    step (.building 2 3) .recv_hop_built = .open 3 := by
  simp [step, stepFromBuilding, advanceBuilding]

/-- A 3-hop circuit at hopsBuilt=0 advances to hopsBuilt=1. -/
theorem step_building_zero_three_hop_built :
    step (.building 0 3) .recv_hop_built = .building 1 3 := by
  simp [step, stepFromBuilding, advanceBuilding]

----------------------------------------------------------------------------
-- DESTROY tears down from any non-terminal state
----------------------------------------------------------------------------

theorem step_building_destroy (built target r : Int) :
    step (.building built target) (.recv_destroy r) = .destroyed r := by
  simp [step, stepFromBuilding]

theorem step_building_local_close (built target r : Int) :
    step (.building built target) (.local_close r) = .destroyed r := by
  simp [step, stepFromBuilding]

theorem step_open_destroy (h r : Int) :
    step (.open h) (.recv_destroy r) = .destroyed r := by
  simp [step, stepFromOpen]

theorem step_open_local_close (h r : Int) :
    step (.open h) (.local_close r) = .destroyed r := by
  simp [step, stepFromOpen]

----------------------------------------------------------------------------
-- Open rejects further extensions
----------------------------------------------------------------------------

/-- **Built circuits don't accept more hops.** A `recv_hop_built` on an
    open circuit (the peer sent a CREATED2/EXTENDED2 it shouldn't have)
    tears it down. -/
theorem step_open_hop_built_destroys (h : Int) :
    isDestroyed (step (.open h) .recv_hop_built) = true := by
  simp [step, stepFromOpen, isDestroyed]

----------------------------------------------------------------------------
-- Phase-partition invariant
----------------------------------------------------------------------------

/-- The three phase predicates partition every state. -/
theorem phase_partition (s : CircuitState) :
    (isBuilding s = true ∧ isOpen s = false ∧ isDestroyed s = false) ∨
    (isBuilding s = false ∧ isOpen s = true ∧ isDestroyed s = false) ∨
    (isBuilding s = false ∧ isOpen s = false ∧ isDestroyed s = true) := by
  cases s <;> simp [isBuilding, isOpen, isDestroyed]

----------------------------------------------------------------------------
-- hopCount monotone across successful build steps
----------------------------------------------------------------------------

/-- **Hop count never decreases on a successful build step.** When
    `building` accepts a `recv_hop_built`, the resulting state's
    `hopCount` is at least one more than before. -/
theorem hopCount_monotone_on_hop_built
    (built target : Int)
    (ht : built < target) :
    hopCount (step (.building built target) .recv_hop_built) ≥ built + 1 := by
  simp [step, stepFromBuilding, advanceBuilding]
  by_cases h : built + 1 ≥ target
  · rw [if_pos h]
    simp [hopCount]
    omega
  · rw [if_neg h]
    simp [hopCount]

/-- `hopCount` of `open` matches the carried hop count. -/
theorem hopCount_open (h : Int) : hopCount (.open h) = h := rfl

/-- `hopCount` of `building` is `hopsBuilt`. -/
theorem hopCount_building (built target : Int) :
    hopCount (.building built target) = built := rfl

/-- `hopCount` of `destroyed` is zero. -/
theorem hopCount_destroyed (r : Int) : hopCount (.destroyed r) = 0 := rfl

----------------------------------------------------------------------------
-- Closure: destroyed never reopens
----------------------------------------------------------------------------

theorem destroyed_does_not_reopen (r : Int) (i : CircuitInput) :
    isOpen (step (.destroyed r) i) = false ∧
    isBuilding (step (.destroyed r) i) = false := by
  rw [step_destroyed_stable r i]
  refine ⟨?_, ?_⟩ <;> simp [isOpen, isBuilding]

end Spec.CircuitState
