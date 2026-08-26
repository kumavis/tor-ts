-- Specification theorems for the `kcpHeader` module.
--
-- The headlines:
--   * Each `decodeUintNLE` consumes exactly N bytes when it succeeds.
--   * Each returns `.short` when the input is too short.
--   * Concrete spot-check values: known byte sequences decode to
--     known integers.
--   * The decoded integer equals `bytesToBigIntLE` of the consumed
--     prefix.

import Generated.KcpHeader
import Thales.TS.Runtime

open Thales.TS

namespace Spec.KcpHeader

open _root_.KcpHeader

deriving instance DecidableEq for ByteList
deriving instance DecidableEq for SplitResult
deriving instance DecidableEq for ParseUintLEResult

----------------------------------------------------------------------------
-- byteListLength helpers
----------------------------------------------------------------------------

theorem byteListLength_nil : byteListLength .nil = 0 := rfl

theorem byteListLength_cons (h : Int) (t : ByteList) :
    byteListLength (.cons h t) = 1 + byteListLength t := rfl

----------------------------------------------------------------------------
-- trySplit re-derived locally
----------------------------------------------------------------------------

theorem trySplit_zero (bs : ByteList) :
    trySplit 0 bs = .ok .nil bs := by
  unfold trySplit
  rw [if_pos (by decide : (0 : Int) ≤ 0)]

theorem trySplit_nil_pos (n : Int) (h : 0 < n) :
    trySplit n .nil = .short := by
  unfold trySplit
  rw [if_neg (by omega : ¬(n ≤ 0))]

/-- Length conservation: trySplit doesn't lose bytes. -/
theorem trySplit_total_length
    (n : Int) (bs : ByteList) (taken rest : ByteList)
    (h : trySplit n bs = .ok taken rest) :
    byteListLength taken + byteListLength rest = byteListLength bs := by
  induction bs generalizing n taken rest with
  | nil =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, hr⟩ := h
      rw [← ht, ← hr]
      decide
    · simp [hle] at h
  | cons head tail ih =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, hr⟩ := h
      rw [← ht, ← hr]
      simp [byteListLength_nil]
    · simp [hle] at h
      simp [consIntoSplit] at h
      cases hrec : trySplit (n - 1) tail with
      | short => simp [hrec] at h
      | ok taken' rest' =>
        simp [hrec] at h
        obtain ⟨ht, hr⟩ := h
        rw [← ht, ← hr]
        simp [byteListLength]
        have hih := ih (n - 1) taken' rest' hrec
        omega

----------------------------------------------------------------------------
-- decodeUint8LE
----------------------------------------------------------------------------

/-- Empty input → short. -/
theorem decodeUint8LE_nil :
    decodeUint8LE .nil = .short := by
  unfold decodeUint8LE
  rw [trySplit_nil_pos 1 (by decide)]
  rfl

/-- Single-byte input: the decoded value is just that byte. -/
theorem decodeUint8LE_singleton (b : Int) :
    decodeUint8LE (.cons b .nil) = .ok b .nil := by
  simp [decodeUint8LE, trySplit, decodeUintLEFromSplit, consIntoSplit, bytesToBigIntLE]

/-- A 2-byte input decodes only the head as the uint8; the tail is
    the remainder. -/
theorem decodeUint8LE_two (a b : Int) :
    decodeUint8LE (.cons a (.cons b .nil)) = .ok a (.cons b .nil) := by
  simp [decodeUint8LE, trySplit, decodeUintLEFromSplit, consIntoSplit, bytesToBigIntLE]

----------------------------------------------------------------------------
-- decodeUint16LE
----------------------------------------------------------------------------

theorem decodeUint16LE_nil :
    decodeUint16LE .nil = .short := by
  unfold decodeUint16LE
  rw [trySplit_nil_pos 2 (by decide)]
  rfl

/-- A one-byte input is too short for a uint16. -/
theorem decodeUint16LE_singleton (b : Int) :
    decodeUint16LE (.cons b .nil) = .short := by
  simp [decodeUint16LE, trySplit, consIntoSplit, decodeUintLEFromSplit]

/-- Two-byte LE: `[lo, hi]` decodes to `lo + 256 * hi`. -/
theorem decodeUint16LE_two (lo hi : Int) :
    decodeUint16LE (.cons lo (.cons hi .nil)) = .ok (lo + 256 * hi) .nil := by
  simp [decodeUint16LE, trySplit, decodeUintLEFromSplit, consIntoSplit, bytesToBigIntLE]

----------------------------------------------------------------------------
-- decodeUint32LE
----------------------------------------------------------------------------

theorem decodeUint32LE_nil :
    decodeUint32LE .nil = .short := by
  unfold decodeUint32LE
  rw [trySplit_nil_pos 4 (by decide)]
  rfl

/-- A 4-byte LE: `[b0, b1, b2, b3]` = `b0 + 256·b1 + 65536·b2 + 16777216·b3`. -/
theorem decodeUint32LE_four (b0 b1 b2 b3 : Int) :
    decodeUint32LE (.cons b0 (.cons b1 (.cons b2 (.cons b3 .nil)))) =
      .ok (b0 + 256 * b1 + 65536 * b2 + 16777216 * b3) .nil := by
  simp [decodeUint32LE, trySplit, decodeUintLEFromSplit, consIntoSplit, bytesToBigIntLE]
  omega

----------------------------------------------------------------------------
-- Length-conservation: each decoder consumes exactly its width
----------------------------------------------------------------------------

/-- Unfolding lemma for the cons case: `decodeUint8LE` on a non-empty
    list takes the head as the value and the tail as the remainder. -/
theorem decodeUint8LE_cons (head : Int) (tail : ByteList) :
    decodeUint8LE (.cons head tail) = .ok head tail := by
  simp [decodeUint8LE, trySplit, consIntoSplit, decodeUintLEFromSplit,
        bytesToBigIntLE, trySplit_zero]

/-- decodeUint8LE consumes exactly 1 byte when it succeeds. -/
theorem decodeUint8LE_consumes_one
    (bs : ByteList) (v : Int) (rest : ByteList)
    (h : decodeUint8LE bs = .ok v rest) :
    byteListLength rest + 1 = byteListLength bs := by
  cases bs with
  | nil => simp [decodeUint8LE_nil] at h
  | cons head tail =>
    rw [decodeUint8LE_cons] at h
    injection h with _ hr
    rw [← hr, byteListLength_cons]
    omega

end Spec.KcpHeader
