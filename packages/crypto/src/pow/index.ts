/**
 * Hidden-service proof-of-work (proposal 327 / hspow-spec v1: Equi-X + Blake2b).
 *
 * Pure-TypeScript port of the HashX + Equi-X reference implementations, plus
 * the hspow client/verifier. Exposed through `tor-crypto` so both the Node and
 * browser Tor clients can solve the PoW required by DoS-protected onion
 * services.
 */

export { hashxMake, hashxExecValue, hashxExecDigest, type HashxProgram } from './hashx.ts';
export {
  equixSolve,
  equixVerify,
  packEquixSolution,
  unpackEquixSolution,
  EquixResult,
  EQUIX_NUM_IDX,
  EQUIX_MAX_SOLS,
} from './equix.ts';
export {
  solveHsPow,
  verifyHsPow,
  HS_POW_PSTRING,
  type HsPowSolution,
  type SolveHsPowOptions,
} from './hspow.ts';
