-- Specification theorems for the `streamState` module.

import Generated.StreamState
import Thales.TS.Runtime

open Thales.TS

namespace Spec.StreamState

open _root_.StreamState

deriving instance DecidableEq for StreamState
deriving instance DecidableEq for StreamInput

----------------------------------------------------------------------------
-- Closed is stable
----------------------------------------------------------------------------

theorem step_closed_stable (r : Int) (i : StreamInput) :
    step (.closed r) i = .closed r := by
  simp [step]

----------------------------------------------------------------------------
-- BEGIN happy path: init → awaiting_connected → open
----------------------------------------------------------------------------

theorem step_init_local_begin :
    step .init .local_begin = .awaiting_connected := by
  simp [step, stepFromInit]

theorem step_init_local_resolve :
    step .init .local_resolve = .awaiting_resolved := by
  simp [step, stepFromInit]

theorem step_awaiting_connected_recv_connected :
    step .awaiting_connected .recv_connected = .open := by
  simp [step, stepFromAwaitingConnected]

/-- **TCP happy path.** A 2-step sequence (BEGIN, then CONNECTED)
    drives an `init` stream to `open`. -/
theorem tcp_happy_path :
    step (step .init .local_begin) .recv_connected = .open := by
  rw [step_init_local_begin, step_awaiting_connected_recv_connected]

----------------------------------------------------------------------------
-- RESOLVE one-shot: init → awaiting_resolved → closed (DNS_DONE)
----------------------------------------------------------------------------

theorem step_awaiting_resolved_recv_resolved :
    step .awaiting_resolved .recv_resolved = .closed 6 := by
  simp [step, stepFromAwaitingResolved, REASON_DNS_DONE]

/-- **DNS happy path.** A 2-step sequence (RESOLVE, then RESOLVED)
    drives an `init` stream to `closed` with `REASON_DNS_DONE`. The
    stream never enters `open` for DNS — it's a one-shot exchange. -/
theorem dns_happy_path :
    step (step .init .local_resolve) .recv_resolved = .closed 6 := by
  rw [step_init_local_resolve, step_awaiting_resolved_recv_resolved]

----------------------------------------------------------------------------
-- DATA in open is a no-op
----------------------------------------------------------------------------

/-- **DATA preserves open.** Data cells in `open` don't change the
    stream's lifecycle state — the bytes are at a different layer. -/
theorem step_open_recv_data :
    step .open .recv_data = .open := by
  simp [step, stepFromOpen]

/-- N data cells in `open` still leave the stream open. -/
theorem step_open_recv_data_twice :
    step (step .open .recv_data) .recv_data = .open := by
  rw [step_open_recv_data, step_open_recv_data]

----------------------------------------------------------------------------
-- END / local_close transition any non-closed state to closed with reason
----------------------------------------------------------------------------

theorem step_open_recv_end (r : Int) :
    step .open (.recv_end r) = .closed r := by
  simp [step, stepFromOpen]

theorem step_open_local_close (r : Int) :
    step .open (.local_close r) = .closed r := by
  simp [step, stepFromOpen]

theorem step_awaiting_connected_recv_end (r : Int) :
    step .awaiting_connected (.recv_end r) = .closed r := by
  simp [step, stepFromAwaitingConnected]

theorem step_init_recv_end (r : Int) :
    step .init (.recv_end r) = .closed r := by
  simp [step, stepFromInit]

----------------------------------------------------------------------------
-- Protocol-error transitions: unexpected cells in non-open phases close
----------------------------------------------------------------------------

/-- **Protocol error in init.** Receiving CONNECTED before BEGIN
    closes the stream with the protocol-error reason. -/
theorem step_init_recv_connected_protocol_error :
    step .init .recv_connected = .closed 1 := by
  simp [step, stepFromInit, REASON_PROTOCOL_ERROR]

theorem step_init_recv_data_protocol_error :
    step .init .recv_data = .closed 1 := by
  simp [step, stepFromInit, REASON_PROTOCOL_ERROR]

theorem step_open_recv_connected_protocol_error :
    step .open .recv_connected = .closed 1 := by
  simp [step, stepFromOpen, REASON_PROTOCOL_ERROR]

----------------------------------------------------------------------------
-- Phase partition
----------------------------------------------------------------------------

/-- The four phase predicates partition every state. -/
theorem phase_partition (s : StreamState) :
    (isInit s = true ∧ isAwaiting s = false ∧ isOpen s = false ∧ isClosed s = false) ∨
    (isInit s = false ∧ isAwaiting s = true ∧ isOpen s = false ∧ isClosed s = false) ∨
    (isInit s = false ∧ isAwaiting s = false ∧ isOpen s = true ∧ isClosed s = false) ∨
    (isInit s = false ∧ isAwaiting s = false ∧ isOpen s = false ∧ isClosed s = true) := by
  cases s <;> simp [isInit, isAwaiting, isOpen, isClosed]

----------------------------------------------------------------------------
-- One-way closure
----------------------------------------------------------------------------

/-- A closed stream never goes back to any non-closed phase. -/
theorem closed_does_not_reopen (r : Int) (i : StreamInput) :
    isOpen (step (.closed r) i) = false ∧
    isAwaiting (step (.closed r) i) = false ∧
    isInit (step (.closed r) i) = false := by
  rw [step_closed_stable r i]
  refine ⟨?_, ?_, ?_⟩ <;> simp [isOpen, isAwaiting, isInit]

end Spec.StreamState
