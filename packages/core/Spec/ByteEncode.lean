-- Specification theorems for the `byteEncode` module.
--
-- These are the first *round-trip* theorems in core. Every other Spec
-- file states a one-directional property of a decoder — bytes consumed,
-- ranges respected, splits faithful. Here we have both directions, so we
-- can say the thing that actually matters about a wire format:
--
--   * `encodeUintLE_roundtrip` / `encodeUintBE_roundtrip` — for any
--     value that fits the field, decoding its encoding returns the
--     value. Nothing is lost, reordered, or corrupted.
--   * `decode_encode_stream_LE` — the same, but reading the field off
--     the *front of a stream*: the value comes back and so does the
--     untouched remainder. This is the shape a real parser uses.
--
-- Supporting cast: both encoders emit exactly `widthValue w` bytes, and
-- `capacity` is the field's value space.

import Generated.ByteEncode
import Thales.TS.Runtime

open Thales.TS

namespace Spec.ByteEncode

open _root_.ByteEncode

deriving instance DecidableEq for ByteList
deriving instance DecidableEq for SplitResult
deriving instance DecidableEq for Width

----------------------------------------------------------------------------
-- truncMod: the MIGRATION-F2 workaround is the mathematical remainder
----------------------------------------------------------------------------

/-- Same bridging lemma as in `Spec/Seq32.lean`, at the divisor this
    module uses. Stated at the literal so `simp` can fire before it
    unfolds anything. -/
@[simp] theorem truncMod_256 (x : Int) : truncMod x 256 = x % 256 := by
  unfold truncMod; omega

----------------------------------------------------------------------------
-- Width arithmetic
----------------------------------------------------------------------------

theorem widthValue_zero : widthValue .zero = 0 := rfl

theorem widthValue_succ (w : Width) :
    widthValue (.succ w) = 1 + widthValue w := rfl

theorem widthValue_nonneg (w : Width) : 0 ≤ widthValue w := by
  induction w with
  | zero => decide
  | succ pred ih => rw [widthValue_succ]; omega

theorem capacity_zero : capacity .zero = 1 := rfl

theorem capacity_succ (w : Width) :
    capacity (.succ w) = 256 * capacity w := rfl

/-- A field always has room for at least one value, so `capacity` is a
    legal divisor and `v < capacity w` is a meaningful bound. -/
theorem capacity_pos (w : Width) : 0 < capacity w := by
  induction w with
  | zero => decide
  | succ pred ih => rw [capacity_succ]; omega

/-- The concrete widths line up with their byte counts. -/
theorem widthValue_width1 : widthValue width1 = 1 := by decide
theorem widthValue_width2 : widthValue width2 = 2 := by decide
theorem widthValue_width4 : widthValue width4 = 4 := by decide

/-- …and with their value spaces: 2^8, 2^16, 2^32. -/
theorem capacity_width1 : capacity width1 = 256 := by decide
theorem capacity_width2 : capacity width2 = 65536 := by decide
theorem capacity_width4 : capacity width4 = 4294967296 := by decide

----------------------------------------------------------------------------
-- Byte-list lemmas
--
-- Re-derived rather than imported: the `ByteList` duplicated into this
-- module is a *distinct* Lean inductive from `Bytes.ByteList`, so
-- nothing in `Spec/Bytes.lean` applies to it. This duplication is the
-- direct cost of thales-issues.md #14, and it is what §6 of
-- docs/NEXT-STEPS.md deletes once that lands.
----------------------------------------------------------------------------

theorem byteListLength_nonneg (bs : ByteList) : 0 ≤ byteListLength bs := by
  induction bs with
  | nil => decide
  | cons h t ih => simp only [byteListLength]; omega

theorem byteListConcat_length (a b : ByteList) :
    byteListLength (byteListConcat a b) = byteListLength a + byteListLength b := by
  induction a with
  | nil => simp [byteListConcat, byteListLength]
  | cons h t ih => simp only [byteListConcat, byteListLength, ih]; omega

theorem bytesToBigIntLE_cons (h : Int) (t : ByteList) :
    bytesToBigIntLE (.cons h t) = h + 256 * bytesToBigIntLE t := rfl

----------------------------------------------------------------------------
-- Zeta-reduced equations for the encoders
--
-- Both emitted definitions bind `let pred`/`let lo`/`let hi` before
-- building the result, and Lean 4.33's `simp only`/`split` do not see
-- through those binders (same wrinkle as `asInt32_eq` in Spec/Seq32).
-- The binders are definitionally transparent, so `rfl` hands back the
-- flattened form to rewrite with.
----------------------------------------------------------------------------

theorem encodeUintLE_zero (v : Int) : encodeUintLE v .zero = .nil := rfl

theorem encodeUintLE_succ (v : Int) (w : Width) :
    encodeUintLE v (.succ w) = .cons (truncMod v 256) (encodeUintLE (v / 256) w) := rfl

theorem encodeUintBE_zero (v : Int) : encodeUintBE v .zero = .nil := rfl

theorem encodeUintBE_succ (v : Int) (w : Width) :
    encodeUintBE v (.succ w)
      = byteListConcat (encodeUintBE (v / 256) w) (.cons (truncMod v 256) .nil) := rfl

----------------------------------------------------------------------------
-- Both encoders emit exactly the requested number of bytes
--
-- This is what lets a serializer compute frame sizes up front, and what
-- the stream round-trip below needs in order to know where the field
-- ends.
----------------------------------------------------------------------------

theorem encodeUintLE_length (w : Width) :
    ∀ v : Int, byteListLength (encodeUintLE v w) = widthValue w := by
  induction w with
  | zero => intro v; rfl
  | succ pred ih =>
    intro v
    rw [encodeUintLE_succ]
    simp only [byteListLength, widthValue, ih (v / 256)]

theorem encodeUintBE_length (w : Width) :
    ∀ v : Int, byteListLength (encodeUintBE v w) = widthValue w := by
  induction w with
  | zero => intro v; rfl
  | succ pred ih =>
    intro v
    rw [encodeUintBE_succ, byteListConcat_length, ih (v / 256)]
    simp only [byteListLength, widthValue]
    omega

----------------------------------------------------------------------------
-- Round-trip: little-endian
----------------------------------------------------------------------------

/-- **Decoding an encoding returns the value.** For any `v` that fits in
    a `w`-byte field, `bytesToBigIntLE (encodeUintLE v w) = v`.

    This is the strongest statement core can make about the LE wire
    format, and it is what the `decodeUint*LE` family in `kcpHeader.ts`
    inherits: the KCP `conv`/`ts`/`sn`/`una`/`len` fields survive a
    serialize/parse cycle unchanged. -/
theorem encodeUintLE_roundtrip (w : Width) :
    ∀ v : Int, 0 ≤ v → v < capacity w → bytesToBigIntLE (encodeUintLE v w) = v := by
  induction w with
  | zero =>
    intro v h0 hlt
    rw [capacity_zero] at hlt
    have hv : v = 0 := by omega
    rw [encodeUintLE_zero, hv]
    rfl
  | succ pred ih =>
    intro v h0 hlt
    rw [capacity_succ] at hlt
    have hcp : 0 < capacity pred := capacity_pos pred
    -- `omega` knows `Int` division by the literal 256, so both side
    -- conditions for the inductive hypothesis fall out of `0 ≤ v` and
    -- `v < 256 * capacity pred`.
    have hd0 : 0 ≤ v / 256 := by omega
    have hdlt : v / 256 < capacity pred := by omega
    rw [encodeUintLE_succ, bytesToBigIntLE_cons, ih (v / 256) hd0 hdlt, truncMod_256]
    omega

----------------------------------------------------------------------------
-- Round-trip: big-endian
----------------------------------------------------------------------------

/-- `bigEndianUintAux` is a left fold, so it splits over concatenation:
    running it across `a ++ b` is running it across `a` and feeding the
    result into `b`. -/
theorem bigEndianUintAux_concat (a : ByteList) :
    ∀ (acc : Int) (b : ByteList),
      bigEndianUintAux acc (byteListConcat a b)
        = bigEndianUintAux (bigEndianUintAux acc a) b := by
  induction a with
  | nil => intro acc b; rfl
  | cons h t ih =>
    intro acc b
    simp only [byteListConcat, bigEndianUintAux, ih (acc * 256 + h) b]

/-- Appending one byte shifts the accumulated numeral left by a byte. -/
theorem bigEndianUint_snoc (a : ByteList) (b : Int) :
    bigEndianUint (byteListConcat a (.cons b .nil)) = bigEndianUint a * 256 + b := by
  unfold bigEndianUint
  rw [bigEndianUintAux_concat a 0 (.cons b .nil)]
  rfl

/-- **Decoding an encoding returns the value**, big-endian side. This is
    the direction Tor's own cell format uses, so it covers `parseCircId`
    and `parseLengthPrefix` in `cellHeader.ts`. -/
theorem encodeUintBE_roundtrip (w : Width) :
    ∀ v : Int, 0 ≤ v → v < capacity w → bigEndianUint (encodeUintBE v w) = v := by
  induction w with
  | zero =>
    intro v h0 hlt
    rw [capacity_zero] at hlt
    have hv : v = 0 := by omega
    rw [encodeUintBE_zero, hv]
    rfl
  | succ pred ih =>
    intro v h0 hlt
    rw [capacity_succ] at hlt
    have hcp : 0 < capacity pred := capacity_pos pred
    have hd0 : 0 ≤ v / 256 := by omega
    have hdlt : v / 256 < capacity pred := by omega
    rw [encodeUintBE_succ, bigEndianUint_snoc, ih (v / 256) hd0 hdlt, truncMod_256]
    omega

----------------------------------------------------------------------------
-- Round-trip through a stream
--
-- The two theorems above decode an encoding that sits alone. A real
-- parser reads a field off the front of a longer buffer and hands the
-- remainder to the next decoder, so what it needs is: splitting at the
-- field width recovers *both* the field and an untouched remainder.
----------------------------------------------------------------------------

/-- Splitting `a ++ b` at exactly `a`'s length gives back `a` and `b`.

    This is the converse of `trySplit_concat` in `Spec/Bytes.lean`: that
    one says a successful split can be glued back together, this one
    says a glued-together buffer splits back apart. -/
theorem trySplit_length_concat (a : ByteList) :
    ∀ b : ByteList, trySplit (byteListLength a) (byteListConcat a b) = .ok a b := by
  induction a with
  | nil =>
    intro b
    show trySplit 0 b = _
    unfold trySplit
    rw [if_pos (by decide : (0 : Int) ≤ 0)]
  | cons h t ih =>
    intro b
    have hnn : 0 ≤ byteListLength t := byteListLength_nonneg t
    show (if byteListLength (.cons h t) ≤ 0 then _ else _) = _
    rw [if_neg (by simp only [byteListLength]; omega)]
    simp only [byteListLength]
    -- The recursive call is at `1 + length t - 1`; normalise it to
    -- `length t` so the inductive hypothesis applies.
    rw [show (1 + byteListLength t - 1) = byteListLength t by omega, ih b]
    rfl

/-- **A `w`-byte little-endian field survives a serialize/parse cycle,
    remainder included.** Encode `v` at width `w`, put anything after it,
    then split at the field width: the bytes come back, and the trailing
    buffer is untouched. -/
theorem split_encodeUintLE (v : Int) (w : Width) (rest : ByteList) :
    trySplit (widthValue w) (byteListConcat (encodeUintLE v w) rest)
      = .ok (encodeUintLE v w) rest := by
  rw [← encodeUintLE_length w v]
  exact trySplit_length_concat (encodeUintLE v w) rest

/-- The same, for big-endian fields. -/
theorem split_encodeUintBE (v : Int) (w : Width) (rest : ByteList) :
    trySplit (widthValue w) (byteListConcat (encodeUintBE v w) rest)
      = .ok (encodeUintBE v w) rest := by
  rw [← encodeUintBE_length w v]
  exact trySplit_length_concat (encodeUintBE v w) rest

/-- **The full decoder round-trip.** Reading a `w`-byte LE field off the
    front of `encode v w ++ rest` yields exactly `v`, and leaves exactly
    `rest`. This is `parse (serialize v) = some v` in the form a
    streaming parser actually uses it. -/
theorem decode_encode_stream_LE
    (v : Int) (w : Width) (rest : ByteList)
    (h0 : 0 ≤ v) (hlt : v < capacity w) :
    trySplit (widthValue w) (byteListConcat (encodeUintLE v w) rest)
        = .ok (encodeUintLE v w) rest
      ∧ bytesToBigIntLE (encodeUintLE v w) = v :=
  ⟨split_encodeUintLE v w rest, encodeUintLE_roundtrip w v h0 hlt⟩

/-- Big-endian counterpart — the direction Tor's own cell header uses. -/
theorem decode_encode_stream_BE
    (v : Int) (w : Width) (rest : ByteList)
    (h0 : 0 ≤ v) (hlt : v < capacity w) :
    trySplit (widthValue w) (byteListConcat (encodeUintBE v w) rest)
        = .ok (encodeUintBE v w) rest
      ∧ bigEndianUint (encodeUintBE v w) = v :=
  ⟨split_encodeUintBE v w rest, encodeUintBE_roundtrip w v h0 hlt⟩

----------------------------------------------------------------------------
-- The concrete field widths
--
-- Corollaries at the widths Tor and KCP actually use, so a caller gets
-- the round-trip without instantiating `Width` by hand.
----------------------------------------------------------------------------

theorem encodeUint8_roundtrip (v : Int) (h0 : 0 ≤ v) (hlt : v < 256) :
    bytesToBigIntLE (encodeUint8 v) = v :=
  encodeUintLE_roundtrip width1 v h0 (by rw [capacity_width1]; omega)

theorem encodeUint16LE_roundtrip (v : Int) (h0 : 0 ≤ v) (hlt : v < 65536) :
    bytesToBigIntLE (encodeUint16LE v) = v :=
  encodeUintLE_roundtrip width2 v h0 (by rw [capacity_width2]; omega)

theorem encodeUint32LE_roundtrip (v : Int) (h0 : 0 ≤ v) (hlt : v < 4294967296) :
    bytesToBigIntLE (encodeUint32LE v) = v :=
  encodeUintLE_roundtrip width4 v h0 (by rw [capacity_width4]; omega)

theorem encodeUint16BE_roundtrip (v : Int) (h0 : 0 ≤ v) (hlt : v < 65536) :
    bigEndianUint (encodeUint16BE v) = v :=
  encodeUintBE_roundtrip width2 v h0 (by rw [capacity_width2]; omega)

theorem encodeUint32BE_roundtrip (v : Int) (h0 : 0 ≤ v) (hlt : v < 4294967296) :
    bigEndianUint (encodeUint32BE v) = v :=
  encodeUintBE_roundtrip width4 v h0 (by rw [capacity_width4]; omega)

/-- Field widths, concretely. A KCP header is 24 bytes precisely because
    these add up: 4 + 1 + 1 + 2 + 4 + 4 + 4 + 4. -/
theorem encodeUint8_length (v : Int) : byteListLength (encodeUint8 v) = 1 := by
  unfold encodeUint8; rw [encodeUintLE_length width1 v]; decide

theorem encodeUint16LE_length (v : Int) : byteListLength (encodeUint16LE v) = 2 := by
  unfold encodeUint16LE; rw [encodeUintLE_length width2 v]; decide

theorem encodeUint32LE_length (v : Int) : byteListLength (encodeUint32LE v) = 4 := by
  unfold encodeUint32LE; rw [encodeUintLE_length width4 v]; decide

theorem encodeUint16BE_length (v : Int) : byteListLength (encodeUint16BE v) = 2 := by
  unfold encodeUint16BE; rw [encodeUintBE_length width2 v]; decide

theorem encodeUint32BE_length (v : Int) : byteListLength (encodeUint32BE v) = 4 := by
  unfold encodeUint32BE; rw [encodeUintBE_length width4 v]; decide

----------------------------------------------------------------------------
-- serializeCircId
--
-- The inverse of `parseCircId` in `cellHeader.ts`. Both split on the
-- same link-version boundary: 2 bytes through link v3, 4 bytes from
-- v4 on (tor-spec §3, "CIRCID_LEN").
----------------------------------------------------------------------------

theorem serializeCircId_eq (lv circId : Int) :
    serializeCircId lv circId
      = if lv ≥ 4 then encodeUintBE circId width4 else encodeUintBE circId width2 := rfl

/-- Link v4+ circuit IDs occupy 4 bytes. -/
theorem serializeCircId_length_modern (lv circId : Int) (h : lv ≥ 4) :
    byteListLength (serializeCircId lv circId) = 4 := by
  rw [serializeCircId_eq, if_pos h, encodeUintBE_length width4 circId]
  decide

/-- Link v1–v3 circuit IDs occupy 2. -/
theorem serializeCircId_length_legacy (lv circId : Int) (h : ¬(lv ≥ 4)) :
    byteListLength (serializeCircId lv circId) = 2 := by
  rw [serializeCircId_eq, if_neg h, encodeUintBE_length width2 circId]
  decide

/-- **A circuit ID survives serialization at either link version**, so
    long as it fits the width that version allows. -/
theorem serializeCircId_roundtrip_modern
    (lv circId : Int) (h : lv ≥ 4) (h0 : 0 ≤ circId) (hlt : circId < 4294967296) :
    bigEndianUint (serializeCircId lv circId) = circId := by
  rw [serializeCircId_eq, if_pos h]
  exact encodeUintBE_roundtrip width4 circId h0 (by rw [capacity_width4]; omega)

theorem serializeCircId_roundtrip_legacy
    (lv circId : Int) (h : ¬(lv ≥ 4)) (h0 : 0 ≤ circId) (hlt : circId < 65536) :
    bigEndianUint (serializeCircId lv circId) = circId := by
  rw [serializeCircId_eq, if_neg h]
  exact encodeUintBE_roundtrip width2 circId h0 (by rw [capacity_width2]; omega)

end Spec.ByteEncode
