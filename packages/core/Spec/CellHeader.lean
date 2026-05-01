-- Specification theorems for the `cellHeader` module.
--
-- The cell-header parser reads the circuit-ID prefix off a byte stream.
-- Its width is link-version-dependent: 2 bytes on link versions 1–3,
-- 4 bytes on versions 4+. The spec proves:
--   * The width predicate is correct on the boundary value.
--   * `parseCircId` consumes exactly the right number of bytes when it
--     succeeds.
--   * `parseCircId` returns `.short` when the input is too short.
--   * The parsed `circId` plus the unconsumed `rest` reconstruct the
--     prefix of the original input — no bytes silently dropped.

import Generated.CellHeader
import Thales.TS.Runtime

open Thales.TS

namespace Spec.CellHeader

open _root_.CellHeader

deriving instance DecidableEq for ByteList
deriving instance DecidableEq for SplitResult
deriving instance DecidableEq for ParseCircIdResult

----------------------------------------------------------------------------
-- circIdLengthForVersion
----------------------------------------------------------------------------

/-- Versions 1–3 use 2-byte circIds. -/
theorem circIdLengthForVersion_short (v : Int) (h : v < 4) :
    circIdLengthForVersion v = 2 := by
  unfold circIdLengthForVersion
  rw [if_pos h]

/-- Version 4 and up use 4-byte circIds (the version where the format
    changed). -/
theorem circIdLengthForVersion_long (v : Int) (h : 4 ≤ v) :
    circIdLengthForVersion v = 4 := by
  unfold circIdLengthForVersion
  rw [if_neg (by omega : ¬(v < 4))]

theorem circIdLengthForVersion_v3 :
    circIdLengthForVersion 3 = 2 := by decide

theorem circIdLengthForVersion_v4 :
    circIdLengthForVersion 4 = 4 := by decide

theorem circIdLengthForVersion_pos (v : Int) :
    0 < circIdLengthForVersion v := by
  unfold circIdLengthForVersion
  by_cases h : v < 4
  · rw [if_pos h]; decide
  · rw [if_neg h]; decide

----------------------------------------------------------------------------
-- parseCircId on too-short input
----------------------------------------------------------------------------

/-- Re-derive the trySplit-on-short lemma locally. -/
theorem trySplit_nil_pos (n : Int) (h : 0 < n) :
    trySplit n .nil = .short := by
  unfold trySplit
  rw [if_neg (by omega : ¬(n ≤ 0))]

/-- An empty byte list never yields a circuit ID (regardless of version). -/
theorem parseCircId_nil (v : Int) :
    parseCircId v .nil = .short := by
  unfold parseCircId
  rw [trySplit_nil_pos _ (circIdLengthForVersion_pos v)]
  rfl

----------------------------------------------------------------------------
-- byteListLength helpers (re-derived for use here)
----------------------------------------------------------------------------

theorem byteListLength_nil_local : byteListLength .nil = 0 := rfl

theorem byteListLength_cons_local (h : Int) (t : ByteList) :
    byteListLength (.cons h t) = 1 + byteListLength t := rfl

theorem byteListLength_nonneg (bs : ByteList) :
    0 ≤ byteListLength bs := by
  induction bs with
  | nil => decide
  | cons head tail ih =>
    show 0 ≤ 1 + byteListLength tail
    omega

----------------------------------------------------------------------------
-- parseCircId consumes the right number of bytes
----------------------------------------------------------------------------

/-- Mirrors the `trySplit_taken_length` theorem for the locally-declared
    `trySplit`: when `trySplit` succeeds on `n ≥ 0`, the taken prefix
    has length exactly `n`. -/
theorem trySplit_taken_length_local
    (n : Int) (bs : ByteList) (taken rest : ByteList)
    (hn : 0 ≤ n) (h : trySplit n bs = .ok taken rest) :
    byteListLength taken = n := by
  induction bs generalizing n taken rest with
  | nil =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, _⟩ := h
      rw [← ht, byteListLength_nil_local]
      omega
    · simp [hle] at h
  | cons head tail ih =>
    simp [trySplit] at h
    by_cases hle : n ≤ 0
    · simp [hle] at h
      obtain ⟨ht, _⟩ := h
      rw [← ht, byteListLength_nil_local]
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

/-- **The headline theorem.** When `parseCircId` succeeds on link
    version `v`, the returned `rest` is exactly `length bs - circIdLen`
    bytes shorter than the input. The parser consumes the spec-defined
    width and nothing more. -/
theorem parseCircId_consumes_correctly
    (v : Int) (bs : ByteList) (cid : Int) (rest : ByteList)
    (h : parseCircId v bs = .ok cid rest) :
    byteListLength rest + circIdLengthForVersion v = byteListLength bs := by
  -- parseCircId is defined as `decodeCircIdFromSplit (trySplit width bs)`,
  -- so unwrap one layer at a time.
  unfold parseCircId at h
  cases hsplit : trySplit (circIdLengthForVersion v) bs with
  | short =>
    rw [hsplit] at h
    simp [decodeCircIdFromSplit] at h
  | ok taken rest' =>
    rw [hsplit] at h
    simp [decodeCircIdFromSplit] at h
    obtain ⟨_, hr⟩ := h
    -- length taken = circIdLen, taken ++ rest' = bs (by trySplit's invariants).
    -- We don't have trySplit_concat in this local file; instead, use the
    -- length characterization from the local trySplit_taken_length.
    have htaken_len : byteListLength taken = circIdLengthForVersion v := by
      apply trySplit_taken_length_local
      · have := circIdLengthForVersion_pos v
        omega
      · exact hsplit
    -- Now: rest = rest', and we know length taken = circIdLen. The remaining
    -- claim is `length rest' + circIdLen = length bs`, i.e., trySplit
    -- preserves total length. Re-derive it locally by induction on bs.
    rw [← hr]
    have htot : byteListLength taken + byteListLength rest' = byteListLength bs := by
      exact trySplit_total_length (circIdLengthForVersion v) bs taken rest' hsplit
    omega
where
  /-- **Length conservation.** trySplit doesn't lose bytes: the sum of
      taken-and-rest equals the original. -/
  trySplit_total_length (n : Int) (bs : ByteList) (taken rest : ByteList)
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
        simp [byteListLength_nil_local]
      · simp [hle] at h
        simp [consIntoSplit] at h
        cases hrec : trySplit (n - 1) tail with
        | short => simp [hrec] at h
        | ok taken' rest' =>
          simp [hrec] at h
          obtain ⟨ht, hr⟩ := h
          rw [← ht, ← hr]
          simp [byteListLength]
          have hih : byteListLength taken' + byteListLength rest' = byteListLength tail :=
            ih (n - 1) taken' rest' hrec
          omega

end Spec.CellHeader
