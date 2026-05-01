-- Specification theorems for the `bytes` module.
--
-- The headlines:
--   * `byteListLength` is non-negative and additive over `byteListConcat`.
--   * `byteListConcat` has `.nil` as a two-sided identity and is
--     associative.
--   * `trySplit n bs` either returns `.ok` whose `taken` has length `n`
--     and whose `taken ++ rest` recovers `bs` exactly, or `.short` when
--     `bs` is shorter than `n`. Bytes are not silently lost.
--   * `bigEndianUint` reads a base-256 numeral left-to-right.

import Generated.Bytes
import Thales.TS.Runtime

open Thales.TS

namespace Spec.Bytes

open _root_.Bytes

deriving instance DecidableEq for ByteList
deriving instance DecidableEq for SplitResult

----------------------------------------------------------------------------
-- byteListLength
----------------------------------------------------------------------------

theorem byteListLength_nil : byteListLength .nil = 0 := rfl

theorem byteListLength_cons (h : Int) (t : ByteList) :
    byteListLength (.cons h t) = 1 + byteListLength t := rfl

theorem byteListLength_nonneg (bs : ByteList) :
    0 ≤ byteListLength bs := by
  induction bs with
  | nil => decide
  | cons head tail ih =>
    show 0 ≤ 1 + byteListLength tail
    omega

----------------------------------------------------------------------------
-- byteListConcat
----------------------------------------------------------------------------

theorem byteListConcat_nil_left (b : ByteList) :
    byteListConcat .nil b = b := rfl

/-- `.nil` is a right identity (proved by induction). -/
theorem byteListConcat_nil_right (a : ByteList) :
    byteListConcat a .nil = a := by
  induction a with
  | nil => rfl
  | cons head tail ih => simp [byteListConcat, ih]

/-- Concat is associative. -/
theorem byteListConcat_assoc (a b c : ByteList) :
    byteListConcat (byteListConcat a b) c =
      byteListConcat a (byteListConcat b c) := by
  induction a with
  | nil => rfl
  | cons head tail ih => simp [byteListConcat, ih]

/-- **Length is additive.** Concatenation preserves the byte count. -/
theorem byteListConcat_length (a b : ByteList) :
    byteListLength (byteListConcat a b) = byteListLength a + byteListLength b := by
  induction a with
  | nil => simp [byteListConcat, byteListLength]
  | cons head tail ih =>
    simp [byteListConcat, byteListLength, ih]
    omega

----------------------------------------------------------------------------
-- trySplit
----------------------------------------------------------------------------

theorem trySplit_zero (bs : ByteList) :
    trySplit 0 bs = .ok .nil bs := by
  unfold trySplit
  rw [if_pos (by decide : (0 : Int) ≤ 0)]

theorem trySplit_neg (n : Int) (bs : ByteList) (h : n < 0) :
    trySplit n bs = .ok .nil bs := by
  unfold trySplit
  rw [if_pos (by omega : n ≤ 0)]

theorem trySplit_nil_pos (n : Int) (h : 0 < n) :
    trySplit n .nil = .short := by
  unfold trySplit
  rw [if_neg (by omega : ¬(n ≤ 0))]

----------------------------------------------------------------------------
-- The key trySplit theorems: split is faithful (no bytes lost or invented)
----------------------------------------------------------------------------

/-- If `trySplit` succeeds, the taken prefix has length exactly `n`.
    (Provided `n ≥ 0`; for negative `n` the function returns `.ok .nil bs`,
    matching the early-return for `n ≤ 0`.) -/
theorem trySplit_taken_length
    (n : Int) (bs : ByteList) (taken rest : ByteList)
    (hn : 0 ≤ n) (h : trySplit n bs = .ok taken rest) :
    byteListLength taken = n := by
  induction bs generalizing n taken rest with
  | nil =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, _⟩ := h
      rw [← ht, byteListLength_nil]
      omega
    · simp [hle] at h
  | cons head tail ih =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, _⟩ := h
      rw [← ht, byteListLength_nil]
      omega
    · simp [hle] at h
      simp [consIntoSplit] at h
      cases hrec : trySplit (n - 1) tail with
      | short => simp [hrec] at h
      | ok taken' rest' =>
        simp [hrec] at h
        obtain ⟨ht, _⟩ := h
        rw [← ht]
        simp [byteListLength]
        have hih : byteListLength taken' = n - 1 := by
          apply ih
          · omega
          · exact hrec
        omega

/-- **Split is faithful.** When `trySplit n bs` succeeds, gluing the
    pieces back via `byteListConcat` recovers `bs` exactly — no bytes
    are dropped, duplicated, or invented. This is the headline property
    every parser built on `trySplit` inherits. -/
theorem trySplit_concat
    (n : Int) (bs : ByteList) (taken rest : ByteList)
    (h : trySplit n bs = .ok taken rest) :
    byteListConcat taken rest = bs := by
  induction bs generalizing n taken rest with
  | nil =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, hr⟩ := h
      rw [← ht, ← hr]
      rfl
    · simp [hle] at h
  | cons head tail ih =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, hr⟩ := h
      rw [← ht, ← hr, byteListConcat_nil_left]
    · simp [hle] at h
      simp [consIntoSplit] at h
      cases hrec : trySplit (n - 1) tail with
      | short => simp [hrec] at h
      | ok taken' rest' =>
        simp [hrec] at h
        obtain ⟨ht, hr⟩ := h
        rw [← ht, ← hr]
        simp [byteListConcat]
        exact ih (n - 1) taken' rest' hrec

----------------------------------------------------------------------------
-- bigEndianUint
----------------------------------------------------------------------------

theorem bigEndianUint_nil : bigEndianUint .nil = 0 := rfl

/-- A single-byte BE encoding is the byte itself. -/
theorem bigEndianUint_singleton (b : Int) :
    bigEndianUint (.cons b .nil) = b := by
  simp [bigEndianUint, bigEndianUintAux]

/-- Two-byte BE: `[hi, lo]` decodes to `hi*256 + lo`. -/
theorem bigEndianUint_two (hi lo : Int) :
    bigEndianUint (.cons hi (.cons lo .nil)) = hi * 256 + lo := by
  simp [bigEndianUint, bigEndianUintAux]

end Spec.Bytes
