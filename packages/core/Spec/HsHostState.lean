-- Specification theorems for the `hsHostState` module.

import Generated.HsHostState
import Thales.TS.Runtime

open Thales.TS

namespace Spec.HsHostState

open _root_.HsHostState

deriving instance DecidableEq for HsHostState
deriving instance DecidableEq for HsHostInput

----------------------------------------------------------------------------
-- Closed is stable
----------------------------------------------------------------------------

theorem step_closed_stable (r : Int) (i : HsHostInput) :
    step (.closed r) i = .closed r := by
  simp [step]

----------------------------------------------------------------------------
-- Each phase advances on its expected input
----------------------------------------------------------------------------

theorem step_awaiting_intro_established_recv :
    step .awaiting_intro_established .recv_intro_established = .intro_open := by
  simp [step, stepFromAwaitingIntroEstablished]

theorem step_intro_open_recv_introduce2 :
    step .intro_open .recv_introduce2 = .spawning_rendezvous := by
  simp [step, stepFromIntroOpen]

theorem step_spawning_rendezvous_send_rendezvous1 :
    step .spawning_rendezvous .local_send_rendezvous1 = .rendezvous_open := by
  simp [step, stepFromSpawningRendezvous]

----------------------------------------------------------------------------
-- Full happy path: introduction setup + serving one client
----------------------------------------------------------------------------

/-- **Full HSv3 host serving sequence.** From an empty
    `awaiting_intro_established` state, three inputs (
    INTRO_ESTABLISHED, INTRODUCE2, then local RENDEZVOUS1) drive the
    machine all the way to a serving rendezvous link. -/
theorem full_serving_sequence :
    step (step (step .awaiting_intro_established
        .recv_intro_established)
        .recv_introduce2)
        .local_send_rendezvous1
      = .rendezvous_open := by
  rw [step_awaiting_intro_established_recv,
      step_intro_open_recv_introduce2,
      step_spawning_rendezvous_send_rendezvous1]

----------------------------------------------------------------------------
-- Protocol-error transitions
----------------------------------------------------------------------------

/-- INTRODUCE2 before INTRO_ESTABLISHED is a protocol error. -/
theorem step_awaiting_intro_introduce2_protocol_error :
    step .awaiting_intro_established .recv_introduce2 = .closed 1 := by
  simp [step, stepFromAwaitingIntroEstablished, REASON_PROTOCOL_ERROR]

/-- A second INTRO_ESTABLISHED in `intro_open` is a protocol error. -/
theorem step_intro_open_second_established_protocol_error :
    step .intro_open .recv_intro_established = .closed 1 := by
  simp [step, stepFromIntroOpen, REASON_PROTOCOL_ERROR]

/-- RENDEZVOUS1 before INTRODUCE2 is a protocol error. -/
theorem step_intro_open_rendezvous1_protocol_error :
    step .intro_open .local_send_rendezvous1 = .closed 1 := by
  simp [step, stepFromIntroOpen, REASON_PROTOCOL_ERROR]

----------------------------------------------------------------------------
-- DESTROY teardown carries the peer's reason
----------------------------------------------------------------------------

theorem step_destroy_from_awaiting_intro (r : Int) :
    step .awaiting_intro_established (.recv_destroy r) = .closed r := by
  simp [step, stepFromAwaitingIntroEstablished]

theorem step_destroy_from_intro_open (r : Int) :
    step .intro_open (.recv_destroy r) = .closed r := by
  simp [step, stepFromIntroOpen]

theorem step_destroy_from_spawning (r : Int) :
    step .spawning_rendezvous (.recv_destroy r) = .closed r := by
  simp [step, stepFromSpawningRendezvous]

theorem step_destroy_from_rendezvous (r : Int) :
    step .rendezvous_open (.recv_destroy r) = .closed r := by
  simp [step, stepFromRendezvousOpen]

----------------------------------------------------------------------------
-- Phase partition + one-way closure
----------------------------------------------------------------------------

theorem phase_partition (s : HsHostState) :
    (isIntroductionPhase s = true ∧ isServingClient s = false ∧ isClosed s = false) ∨
    (isIntroductionPhase s = false ∧ isServingClient s = true ∧ isClosed s = false) ∨
    (isIntroductionPhase s = false ∧ isServingClient s = false ∧ isClosed s = true) := by
  cases s <;> simp [isIntroductionPhase, isServingClient, isClosed]

theorem closed_does_not_reopen (r : Int) (i : HsHostInput) :
    isIntroductionPhase (step (.closed r) i) = false ∧
    isServingClient (step (.closed r) i) = false := by
  rw [step_closed_stable r i]
  refine ⟨?_, ?_⟩ <;> simp [isIntroductionPhase, isServingClient]

end Spec.HsHostState
