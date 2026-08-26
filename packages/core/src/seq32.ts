// Wrap-safe 32-bit sequence arithmetic (verified core).
//
// KCP and SMUX maintain sequence-number-style fields stored as 32-bit
// unsigned integers. Comparisons must use a signed wrap-aware difference,
// or the comparison stops working once the counter rolls over (every ~49
// days for millisecond timestamps). The kcp-go reference implementation
// inlines this as `((now - resendts) | 0) >= 0`; the equivalent helper
// in `packages/snowflake/src/kcp/session.ts:261` does the same.
//
// This module hosts the primitives in their own verifiable form. The
// TS-side caller passes `BigInt(jsNumber)` at the seam.

const TWO32: bigint = 4294967296n; // 2^32
const TWO31: bigint = 2147483648n; // 2^31

/**
 * Truncated remainder — the value `a % b` would have.
 *
 * Written without `%` because Thales 0.7 lowers `%` on `bigint` to the
 * Float helper `jsMod`, which produces uncompilable Lean (see
 * MIGRATION.md F2 / thales-issues.md #13). Both TS `bigint /` and Lean
 * `Int./` truncate toward zero, so `a - (a / b) * b` is exactly the
 * truncated remainder on both paths. `Spec/Seq32.lean` pins this to
 * the mathematical identity so the workaround is itself verified.
 */
/** @total */
function truncMod(a: bigint, b: bigint): bigint {
  return a - (a / b) * b;
}

/** Normalize an integer to the unsigned 32-bit range [0, 2^32). */
/** @total */
function uint32(x: bigint): bigint {
  // Truncated remainder (so `-1n` maps to `-1n`, not `4294967295n`);
  // the branch then normalizes the negative case into `[0, 2^32)`.
  const r = truncMod(x, TWO32);
  if (r < 0n) {
    return r + TWO32;
  }
  return r;
}

/** Wrap-safe modular addition. */
/** @total */
function add32(a: bigint, b: bigint): bigint {
  return uint32(a + b);
}

/** Wrap-safe modular subtraction. */
/** @total */
function sub32(a: bigint, b: bigint): bigint {
  return uint32(a - b);
}

/**
 * Reinterpret a uint32 as int32: values in `[2^31, 2^32)` become negative
 * counterparts in `[-2^31, 0)`. The result is always in `[-2^31, 2^31)`.
 */
/** @total */
function asInt32(x: bigint): bigint {
  const u = uint32(x);
  if (u >= TWO31) {
    return u - TWO32;
  }
  return u;
}

/**
 * `itimediff`: kcp-go's signed 32-bit difference.
 * Equivalent to `(int32_t)((uint32_t)later - (uint32_t)earlier)` in C.
 *
 * For inputs whose true distance is less than 2^31, the sign of the
 * result tells you which value comes "later" in cyclic ordering. Larger
 * gaps are ambiguous by design — that's the wraparound budget.
 */
/** @total */
function itimediff(later: bigint, earlier: bigint): bigint {
  return asInt32(later - earlier);
}

/**
 * Wrap-safe ordering: `seqLt(a, b)` is true iff `a` is logically before
 * `b` in the 32-bit cyclic order. Equivalent to `itimediff(b, a) > 0`.
 */
/** @total */
function seqLt(a: bigint, b: bigint): boolean {
  return itimediff(b, a) > 0n;
}

/** Wrap-safe ≤. */
/** @total */
function seqLe(a: bigint, b: bigint): boolean {
  return itimediff(b, a) >= 0n;
}
