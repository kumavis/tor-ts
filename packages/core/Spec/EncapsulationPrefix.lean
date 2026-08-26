-- Specification theorems for the `encapsulationPrefix` module.

import Generated.EncapsulationPrefix
import Thales.TS.Runtime

open Thales.TS

namespace Spec.EncapsulationPrefix

open _root_.EncapsulationPrefix

deriving instance DecidableEq for ByteList
deriving instance DecidableEq for ParsePrefixResult

----------------------------------------------------------------------------
-- Bit helpers
----------------------------------------------------------------------------

/-- `truncMod` exists only because Thales 0.7 cannot lower `%` on
    `bigint` (MIGRATION.md F2). These pin it to Lean's `Int` remainder
    at the two divisors this module uses, so the workaround is itself
    verified and the bit-extraction theorems below read as before.
    `omega` needs a literal divisor, hence one lemma per constant. -/
@[simp] theorem truncMod_128 (b : Int) : truncMod b 128 = b % 128 := by
  unfold truncMod; omega

@[simp] theorem truncMod_64 (b : Int) : truncMod b 64 = b % 64 := by
  unfold truncMod; omega

theorem highBitSet_iff (b : Int) : highBitSet b = true ↔ b ≥ 128 := by
  simp [highBitSet]

theorem low7Bits_eq (b : Int) : low7Bits b = b % 128 := by
  simp [low7Bits]

theorem low6Bits_eq (b : Int) : low6Bits b = b % 64 := by
  simp [low6Bits]

theorem secondHighBitSet_iff (b : Int) :
    secondHighBitSet b = true ↔ b % 128 ≥ 64 := by
  simp [secondHighBitSet]

----------------------------------------------------------------------------
-- Empty input always short
----------------------------------------------------------------------------

theorem parseEncapsulationPrefix_nil :
    parseEncapsulationPrefix .nil = .short := by
  simp [parseEncapsulationPrefix]

----------------------------------------------------------------------------
-- Single-byte short prefix: when the first byte has the "more" bit
-- clear, the parser returns ok with 1 header byte and the right fields
----------------------------------------------------------------------------

/-- 0x05 = 5: high bit clear (padding), more bit clear, length 5,
    no continuation. Decode of [0x05] should return ok padding length 5. -/
theorem parseEncapsulationPrefix_padding_short_concrete :
    parseEncapsulationPrefix (.cons 5 .nil) =
      .ok false 5 1 .nil := by
  simp [parseEncapsulationPrefix, highBitSet, secondHighBitSet,
        low6Bits, low7Bits]

/-- 0x82 = 0x80 | 0x02 = 130: data bit set, more bit clear, length 2.
    Decode of [0x82] = ok data length 2 in 1 header byte. -/
theorem parseEncapsulationPrefix_data_short_concrete :
    parseEncapsulationPrefix (.cons 130 .nil) =
      .ok true 2 1 .nil := by
  simp [parseEncapsulationPrefix, highBitSet, secondHighBitSet,
        low6Bits, low7Bits]

/-- The remainder is the input's tail when the prefix is 1 byte. -/
theorem parseEncapsulationPrefix_short_keeps_tail (b : Int) (tail : ByteList)
    (h_no_more : ¬(b % 128 ≥ 64)) :
    ∃ isData len, parseEncapsulationPrefix (.cons b tail) = .ok isData len 1 tail := by
  refine ⟨highBitSet b, low6Bits b, ?_⟩
  simp [parseEncapsulationPrefix, secondHighBitSet, h_no_more]

----------------------------------------------------------------------------
-- Two-byte prefix: 0xC0 | high6, then the continuation byte gives 7 more
-- bits of length
----------------------------------------------------------------------------

/-- 0xC1 (more set, low6=1) followed by 0x10 (more clear, low7=0x10).
    Decoded length = 1 << 7 | 0x10 = 128 + 16 = 144. -/
theorem parseEncapsulationPrefix_two_byte_concrete :
    parseEncapsulationPrefix (.cons 193 (.cons 16 .nil)) =
      .ok true 144 2 .nil := by
  simp [parseEncapsulationPrefix, continuePrefix,
        highBitSet, secondHighBitSet, low6Bits, low7Bits]

----------------------------------------------------------------------------
-- Too-long: a 4-byte prefix (3 continuations after the first) is rejected
----------------------------------------------------------------------------

/-- A 4th continuation byte is rejected as too_long. -/
theorem parseEncapsulationPrefix_too_long :
    parseEncapsulationPrefix
      (.cons 192 (.cons 128 (.cons 128 (.cons 128 .nil)))) = .too_long := by
  simp [parseEncapsulationPrefix, continuePrefix,
        highBitSet, secondHighBitSet, low6Bits, low7Bits]

----------------------------------------------------------------------------
-- Continuation: short input mid-prefix
----------------------------------------------------------------------------

/-- A first byte with `more` set but no second byte → short. -/
theorem parseEncapsulationPrefix_short_after_first :
    parseEncapsulationPrefix (.cons 192 .nil) = .short := by
  simp [parseEncapsulationPrefix, continuePrefix,
        highBitSet, secondHighBitSet, low6Bits, low7Bits]

end Spec.EncapsulationPrefix
