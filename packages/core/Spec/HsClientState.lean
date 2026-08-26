-- Specification theorems for the `hsClientState` module.

import Generated.HsClientState
import Thales.TS.Runtime

open Thales.TS

namespace Spec.HsClientState

open _root_.HsClientState

deriving instance DecidableEq for HsClientState
deriving instance DecidableEq for HsClientInput

----------------------------------------------------------------------------
-- Closed is stable
----------------------------------------------------------------------------

theorem step_closed_stable (r : Int) (i : HsClientInput) :
    step (.closed r) i = .closed r := by
  simp [step]

----------------------------------------------------------------------------
-- Each handshake state advances on its expected input
----------------------------------------------------------------------------

theorem step_awaiting_descriptor_recv :
    step .awaiting_descriptor .descriptor_received = .descriptor_ready := by
  simp [step, stepFromAwaitingDescriptor]

theorem step_descriptor_ready_send_introduce1 :
    step .descriptor_ready .local_send_introduce1 = .awaiting_introduce_ack := by
  simp [step, stepFromDescriptorReady]

theorem step_awaiting_introduce_ack_success :
    step .awaiting_introduce_ack .recv_introduce_ack_success = .awaiting_rendezvous2 := by
  simp [step, stepFromAwaitingIntroduceAck]

theorem step_awaiting_rendezvous2_recv :
    step .awaiting_rendezvous2 .recv_rendezvous2 = .open := by
  simp [step, stepFromAwaitingRendezvous2]

----------------------------------------------------------------------------
-- Full happy path
----------------------------------------------------------------------------

/-- **Full HSv3 client handshake.** Applying the spec-prescribed inputs
    in order drives `awaiting_descriptor` to `open`. -/
theorem full_handshake_reaches_open :
    step (step (step (step .awaiting_descriptor
        .descriptor_received)
        .local_send_introduce1)
        .recv_introduce_ack_success)
        .recv_rendezvous2
      = .open := by
  rw [step_awaiting_descriptor_recv,
      step_descriptor_ready_send_introduce1,
      step_awaiting_introduce_ack_success,
      step_awaiting_rendezvous2_recv]

----------------------------------------------------------------------------
-- INTRODUCE_ACK failure carries its reason into `closed`
----------------------------------------------------------------------------

theorem step_awaiting_introduce_ack_failure (r : Int) :
    step .awaiting_introduce_ack (.recv_introduce_ack_failure r) = .closed r := by
  simp [step, stepFromAwaitingIntroduceAck]

theorem step_awaiting_descriptor_fetch_failed (r : Int) :
    step .awaiting_descriptor (.descriptor_fetch_failed r) = .closed r := by
  simp [step, stepFromAwaitingDescriptor]

----------------------------------------------------------------------------
-- Protocol-error transitions: out-of-order inputs close
----------------------------------------------------------------------------

/-- INTRODUCE_ACK before the descriptor is fetched is a protocol error. -/
theorem step_awaiting_descriptor_introduce_ack_protocol_error :
    step .awaiting_descriptor .recv_introduce_ack_success = .closed 1 := by
  simp [step, stepFromAwaitingDescriptor, REASON_PROTOCOL_ERROR]

/-- RENDEZVOUS2 before INTRODUCE_ACK is a protocol error. -/
theorem step_descriptor_ready_rendezvous2_protocol_error :
    step .descriptor_ready .recv_rendezvous2 = .closed 1 := by
  simp [step, stepFromDescriptorReady, REASON_PROTOCOL_ERROR]

/-- A second descriptor delivery in `descriptor_ready` is also an error. -/
theorem step_descriptor_ready_second_descriptor_protocol_error :
    step .descriptor_ready .descriptor_received = .closed 1 := by
  simp [step, stepFromDescriptorReady, REASON_PROTOCOL_ERROR]

----------------------------------------------------------------------------
-- DESTROY tears down from any non-terminal state
----------------------------------------------------------------------------

theorem step_destroy_from_awaiting_descriptor (r : Int) :
    step .awaiting_descriptor (.recv_destroy r) = .closed r := by
  simp [step, stepFromAwaitingDescriptor]

theorem step_destroy_from_descriptor_ready (r : Int) :
    step .descriptor_ready (.recv_destroy r) = .closed r := by
  simp [step, stepFromDescriptorReady]

theorem step_destroy_from_awaiting_introduce_ack (r : Int) :
    step .awaiting_introduce_ack (.recv_destroy r) = .closed r := by
  simp [step, stepFromAwaitingIntroduceAck]

theorem step_destroy_from_awaiting_rendezvous2 (r : Int) :
    step .awaiting_rendezvous2 (.recv_destroy r) = .closed r := by
  simp [step, stepFromAwaitingRendezvous2]

theorem step_destroy_from_open (r : Int) :
    step .open (.recv_destroy r) = .closed r := by
  simp [step, stepFromOpen]

----------------------------------------------------------------------------
-- Phase partition + one-way closure
----------------------------------------------------------------------------

theorem phase_partition (s : HsClientState) :
    (isHandshaking s = true ∧ isOpen s = false ∧ isClosed s = false) ∨
    (isHandshaking s = false ∧ isOpen s = true ∧ isClosed s = false) ∨
    (isHandshaking s = false ∧ isOpen s = false ∧ isClosed s = true) := by
  cases s <;> simp [isHandshaking, isOpen, isClosed]

theorem closed_does_not_reopen (r : Int) (i : HsClientInput) :
    isOpen (step (.closed r) i) = false ∧
    isHandshaking (step (.closed r) i) = false := by
  rw [step_closed_stable r i]
  refine ⟨?_, ?_⟩ <;> simp [isOpen, isHandshaking]

end Spec.HsClientState
