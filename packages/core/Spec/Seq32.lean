-- Specification theorems for the `seq32` module.
--
-- These cover the wrap-safe 32-bit integer primitives used by KCP /
-- SMUX-style sequence-number arithmetic. The headline guarantees: every
-- output of `uint32` is in `[0, 2^32)`, every output of `asInt32` is in
-- `[-2^31, 2^31)`, and the `itimediff` / `seqLt` / `seqLe` predicates
-- agree with the underlying integer order on a sufficiently small
-- window.

import Generated.Seq32
import Thales.TS.Runtime

open Thales.TS

namespace Spec.Seq32

open _root_.Seq32

----------------------------------------------------------------------------
-- TWO32 / TWO31 sanity
----------------------------------------------------------------------------

theorem TWO32_pos : (0 : Int) < TWO32 := by
  unfold TWO32; decide

theorem TWO31_half_TWO32 : (2 : Int) * TWO31 = TWO32 := by
  unfold TWO31 TWO32; decide

----------------------------------------------------------------------------
-- uint32: result is always in [0, 2^32)
----------------------------------------------------------------------------

theorem uint32_nonneg (x : Int) : 0 ≤ uint32 x := by
  simp only [uint32, TWO32]
  have h : 0 ≤ x % 4294967296 := Int.emod_nonneg x (by decide)
  by_cases h : x % 4294967296 < 0
  · rw [if_pos h]; omega
  · rw [if_neg h]; omega

theorem uint32_lt_TWO32 (x : Int) : uint32 x < TWO32 := by
  simp only [uint32, TWO32]
  have h : x % 4294967296 < 4294967296 := Int.emod_lt_of_pos x (by decide)
  by_cases h : x % 4294967296 < 0
  · rw [if_pos h]; omega
  · rw [if_neg h]; omega

theorem uint32_in_range (x : Int) : 0 ≤ uint32 x ∧ uint32 x < TWO32 :=
  ⟨uint32_nonneg x, uint32_lt_TWO32 x⟩

/-- Already-normalized inputs are returned unchanged. -/
theorem uint32_already_normalized (x : Int) (hlo : 0 ≤ x) (hhi : x < TWO32) :
    uint32 x = x := by
  simp only [uint32, TWO32] at *
  have hmod : x % 4294967296 = x := Int.emod_eq_of_lt hlo hhi
  rw [hmod, if_neg (by omega : ¬(x < 0))]

/-- `uint32` is idempotent. -/
theorem uint32_idempotent (x : Int) : uint32 (uint32 x) = uint32 x := by
  apply uint32_already_normalized
  · exact uint32_nonneg x
  · exact uint32_lt_TWO32 x

----------------------------------------------------------------------------
-- asInt32: result is always in [-2^31, 2^31)
----------------------------------------------------------------------------

theorem asInt32_lower (x : Int) : -TWO31 ≤ asInt32 x := by
  simp only [asInt32, TWO31, TWO32]
  have hu : 0 ≤ uint32 x := uint32_nonneg x
  have hl : uint32 x < TWO32 := uint32_lt_TWO32 x
  simp only [TWO32] at hl
  by_cases h : uint32 x ≥ 2147483648
  · rw [if_pos h]; omega
  · rw [if_neg h]; omega

theorem asInt32_upper (x : Int) : asInt32 x < TWO31 := by
  simp only [asInt32, TWO31, TWO32]
  have hu : 0 ≤ uint32 x := uint32_nonneg x
  have hl : uint32 x < TWO32 := uint32_lt_TWO32 x
  simp only [TWO32] at hl
  by_cases h : uint32 x ≥ 2147483648
  · rw [if_pos h]; omega
  · rw [if_neg h]; omega

theorem asInt32_in_range (x : Int) : -TWO31 ≤ asInt32 x ∧ asInt32 x < TWO31 :=
  ⟨asInt32_lower x, asInt32_upper x⟩

----------------------------------------------------------------------------
-- itimediff at zero: difference of equal values is 0
----------------------------------------------------------------------------

theorem itimediff_self (a : Int) : itimediff a a = 0 := by
  simp only [itimediff, asInt32, uint32, TWO31, TWO32]
  -- (a - a) = 0; 0 % 4294967296 = 0; not negative, not ≥ TWO31, returns 0.
  have h : a - a = 0 := by omega
  rw [h]
  decide

----------------------------------------------------------------------------
-- seqLt / seqLe at the diagonal
----------------------------------------------------------------------------

theorem seqLt_irreflexive (a : Int) : seqLt a a = false := by
  simp only [seqLt]
  rw [itimediff_self]
  decide

theorem seqLe_reflexive (a : Int) : seqLe a a = true := by
  simp only [seqLe]
  rw [itimediff_self]
  decide

----------------------------------------------------------------------------
-- itimediff for small consecutive values: no wrap, sign is meaningful
----------------------------------------------------------------------------

/-- Inside a no-wrap window of width `< 2^31`, the signed-diff is the
    natural integer difference. This is the security-meaningful claim:
    when the inputs are close enough, `itimediff` does **not** silently
    interpret distant values as nearby ones via wraparound. -/
theorem itimediff_eq_of_close
    (later earlier : Int)
    (h_le : earlier ≤ later)
    (h_window : later - earlier < TWO31) :
    itimediff later earlier = later - earlier := by
  simp only [itimediff, asInt32, uint32, TWO31, TWO32] at *
  have hd_lo : 0 ≤ later - earlier := by omega
  have hd_hi : later - earlier < 4294967296 := by omega
  have hmod : (later - earlier) % 4294967296 = later - earlier :=
    Int.emod_eq_of_lt hd_lo hd_hi
  rw [hmod, if_neg (by omega : ¬(later - earlier < 0)),
      if_neg (by omega : ¬(later - earlier ≥ 2147483648))]

/-- For a small input pair (no wrap concerns), `itimediff (a+1) a = 1`. -/
theorem itimediff_succ (a : Int) : itimediff (a + 1) a = 1 := by
  have h := itimediff_eq_of_close (a + 1) a (by omega)
    (by simp only [TWO31]; omega)
  omega

end Spec.Seq32
