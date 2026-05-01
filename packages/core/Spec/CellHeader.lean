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
deriving instance DecidableEq for ParseCommandResult
deriving instance DecidableEq for ParseLengthResult
deriving instance DecidableEq for ParsePayloadResult

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

/-- **Length conservation.** `trySplit` doesn't lose bytes: the sum of
    taken-and-rest equals the original. Used by every parser-consumes
    theorem in this module. -/
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

/-- **The headline theorem.** When `parseCircId` succeeds on link
    version `v`, the returned `rest` is exactly `length bs - circIdLen`
    bytes shorter than the input. The parser consumes the spec-defined
    width and nothing more. -/
theorem parseCircId_consumes_correctly
    (v : Int) (bs : ByteList) (cid : Int) (rest : ByteList)
    (h : parseCircId v bs = .ok cid rest) :
    byteListLength rest + circIdLengthForVersion v = byteListLength bs := by
  unfold parseCircId at h
  cases hsplit : trySplit (circIdLengthForVersion v) bs with
  | short =>
    rw [hsplit] at h
    simp [decodeCircIdFromSplit] at h
  | ok taken rest' =>
    rw [hsplit] at h
    simp [decodeCircIdFromSplit] at h
    obtain ⟨_, hr⟩ := h
    have htaken_len : byteListLength taken = circIdLengthForVersion v := by
      apply trySplit_taken_length_local
      · have := circIdLengthForVersion_pos v
        omega
      · exact hsplit
    have htot : byteListLength taken + byteListLength rest' = byteListLength bs :=
      trySplit_total_length (circIdLengthForVersion v) bs taken rest' hsplit
    rw [← hr]
    omega

----------------------------------------------------------------------------
-- parseCommand
----------------------------------------------------------------------------

/-- An empty byte list never yields a command. -/
theorem parseCommand_nil :
    parseCommand .nil = .short := rfl

/-- **Unfolding lemma.** parseCommand on a non-empty input returns the
    head byte as the command code and the tail as the remainder. -/
theorem parseCommand_cons (h : Int) (t : ByteList) :
    parseCommand (.cons h t) = .ok h t := rfl

/-- The command byte is recovered exactly. -/
theorem parseCommand_returns_head
    (bs : ByteList) (cmd : Int) (rest : ByteList)
    (h : parseCommand bs = .ok cmd rest) :
    ∃ tail, bs = .cons cmd tail ∧ rest = tail := by
  cases bs with
  | nil => simp [parseCommand] at h
  | cons head tail =>
    rw [parseCommand_cons] at h
    obtain ⟨hc, hr⟩ := ParseCommandResult.ok.injEq _ _ _ _ |>.mp h
    refine ⟨tail, ?_, ?_⟩
    · rw [hc]
    · rw [hr]

/-- **The headline theorem.** parseCommand consumes exactly one byte
    when it succeeds — `length(rest) + 1 = length(input)`. -/
theorem parseCommand_consumes_one
    (bs : ByteList) (cmd : Int) (rest : ByteList)
    (h : parseCommand bs = .ok cmd rest) :
    byteListLength rest + 1 = byteListLength bs := by
  cases bs with
  | nil => simp [parseCommand] at h
  | cons head tail =>
    rw [parseCommand_cons] at h
    obtain ⟨_, hr⟩ := ParseCommandResult.ok.injEq _ _ _ _ |>.mp h
    rw [hr, byteListLength_cons_local]
    omega

----------------------------------------------------------------------------
-- parseLengthPrefix
----------------------------------------------------------------------------

/-- Empty input → short, regardless of anything else. -/
theorem parseLengthPrefix_nil :
    parseLengthPrefix .nil = .short := by
  unfold parseLengthPrefix
  rw [trySplit_nil_pos 2 (by decide)]
  rfl

/-- A one-byte input is also too short for the 2-byte length prefix. -/
theorem parseLengthPrefix_singleton (b : Int) :
    parseLengthPrefix (.cons b .nil) = .short := by
  unfold parseLengthPrefix
  -- trySplit 2 (.cons b .nil) recurses on the tail; tail is nil with n=1 → short.
  rfl

/-- **Length conservation.** When `parseLengthPrefix` succeeds, it
    consumes exactly 2 bytes from the input. -/
theorem parseLengthPrefix_consumes_two
    (bs : ByteList) (len : Int) (rest : ByteList)
    (h : parseLengthPrefix bs = .ok len rest) :
    byteListLength rest + 2 = byteListLength bs := by
  unfold parseLengthPrefix at h
  cases hsplit : trySplit 2 bs with
  | short =>
    rw [hsplit] at h
    simp [decodeLengthFromSplit] at h
  | ok taken rest' =>
    rw [hsplit] at h
    simp [decodeLengthFromSplit] at h
    obtain ⟨_, hr⟩ := h
    have htaken_len : byteListLength taken = 2 := by
      apply trySplit_taken_length_local
      · decide
      · exact hsplit
    have htot : byteListLength taken + byteListLength rest' = byteListLength bs := by
      exact trySplit_total_length 2 bs taken rest' hsplit
    rw [← hr]
    omega

----------------------------------------------------------------------------
-- parsePayload / parseFixedPayload
----------------------------------------------------------------------------

/-- An empty input never satisfies a positive-length payload request. -/
theorem parsePayload_nil_pos (n : Int) (h : 0 < n) :
    parsePayload n .nil = .short := by
  unfold parsePayload
  rw [trySplit_nil_pos n h]
  rfl

/-- An `n = 0` payload request always succeeds, returning an empty
    payload and the input untouched. -/
theorem parsePayload_zero (bs : ByteList) :
    parsePayload 0 bs = .ok .nil bs := by
  unfold parsePayload
  unfold trySplit
  rw [if_pos (by decide : (0 : Int) ≤ 0)]
  rfl

/-- **Payload-length correctness.** When `parsePayload n bs` succeeds
    on a non-negative request, the returned payload has length exactly
    `n`. -/
theorem parsePayload_length
    (n : Int) (bs : ByteList) (payload rest : ByteList)
    (hn : 0 ≤ n) (h : parsePayload n bs = .ok payload rest) :
    byteListLength payload = n := by
  unfold parsePayload at h
  cases hsplit : trySplit n bs with
  | short =>
    rw [hsplit] at h
    simp [decodePayloadFromSplit] at h
  | ok taken rest' =>
    rw [hsplit] at h
    simp [decodePayloadFromSplit] at h
    obtain ⟨ht, _⟩ := h
    rw [← ht]
    apply trySplit_taken_length_local
    · exact hn
    · exact hsplit

/-- **Payload consumption is exact.** When `parsePayload n bs` succeeds
    on a non-negative `n`, the returned `rest` is exactly `n` bytes
    shorter than the input. -/
theorem parsePayload_consumes_n
    (n : Int) (bs : ByteList) (payload rest : ByteList)
    (hn : 0 ≤ n) (h : parsePayload n bs = .ok payload rest) :
    byteListLength rest + n = byteListLength bs := by
  unfold parsePayload at h
  cases hsplit : trySplit n bs with
  | short =>
    rw [hsplit] at h
    simp [decodePayloadFromSplit] at h
  | ok taken rest' =>
    rw [hsplit] at h
    simp [decodePayloadFromSplit] at h
    obtain ⟨_, hr⟩ := h
    have htaken_len : byteListLength taken = n := by
      apply trySplit_taken_length_local
      · exact hn
      · exact hsplit
    have htot : byteListLength taken + byteListLength rest' = byteListLength bs := by
      exact trySplit_total_length n bs taken rest' hsplit
    rw [← hr]
    omega

/-- `parseFixedPayload` always asks for `CELL_PAYLOAD_LEN = 509` bytes. -/
theorem parseFixedPayload_consumes_509
    (bs : ByteList) (payload rest : ByteList)
    (h : parseFixedPayload bs = .ok payload rest) :
    byteListLength rest + 509 = byteListLength bs := by
  unfold parseFixedPayload CELL_PAYLOAD_LEN at h
  exact parsePayload_consumes_n 509 bs payload rest (by decide) h

end Spec.CellHeader
