/**
 * Hidden-service proof-of-work client (rend-spec / hspow-spec v1, "Equi-X and
 * Blake2b"; proposal 327). Builds the Equi-X challenge from the descriptor's
 * pow-params, solves it at a chosen effort, and validates the solution the same
 * way the service will.
 *
 * Challenge:  P || ID || C || N || htonl(E)
 *   P  = "Tor hs intro v1\0"          (16 bytes)
 *   ID = blinded service identity key (32 bytes)
 *   C  = pow-params seed              (32 bytes)
 *   N  = nonce                        (16 bytes, little-endian counter)
 *   E  = effort                       (uint32, network byte order)
 *
 * A solution is valid iff R * E <= UINT32_MAX where
 *   R = ntohl(blake2b_32(challenge || solution_bytes)).
 *
 * Cross-checked against C Tor's hs_pow.c and its test vectors (see pow.spec.ts).
 */

import { blake2b } from '../hashes.ts';
import { hashxMake } from './hashx.ts';
import {
  equixSolve,
  packEquixSolution,
  unpackEquixSolution,
  equixVerify,
  EquixResult,
} from './equix.ts';

export const HS_POW_PSTRING = 'Tor hs intro v1\0';
const HS_POW_NONCE_LEN = 16;
const HS_POW_SEED_LEN = 32;
const HS_POW_ID_LEN = 32;
const HS_POW_SEED_HEAD_LEN = 4;
const HS_POW_HASH_LEN = 4;
const UINT32_MAX = 0xffffffffn;

const PSTRING = Buffer.from(HS_POW_PSTRING, 'ascii'); // 16 bytes incl. trailing NUL

function buildChallenge(blindedId: Buffer, seed: Buffer, nonce: Buffer, effort: number): Buffer {
  const e = Buffer.alloc(4);
  e.writeUInt32BE(effort >>> 0);
  return Buffer.concat([PSTRING, blindedId, seed, nonce, e]);
}

/** R = ntohl(blake2b_32(challenge || solution_bytes)) — big-endian read of a 4-byte BLAKE2b. */
function powHashR(challenge: Buffer, solutionBytes: Buffer): number {
  const h = blake2b(Buffer.concat([challenge, solutionBytes]), { dkLen: HS_POW_HASH_LEN });
  return h.readUInt32BE(0);
}

/** Validate a solution against the effort target: R * E <= UINT32_MAX. */
function validEffort(challenge: Buffer, solutionBytes: Buffer, effort: number): boolean {
  const R = powHashR(challenge, solutionBytes);
  return BigInt(R) * BigInt(effort >>> 0) <= UINT32_MAX;
}

/** Increment a 16-byte nonce as a little-endian integer, in place. */
function incrementNonce(nonce: Buffer): void {
  for (let i = 0; i < HS_POW_NONCE_LEN; i++) {
    nonce[i] = (nonce[i]! + 1) & 0xff;
    if (nonce[i] !== 0) break; // no carry out of this byte
  }
}

/** The proof-of-work solution to embed in an INTRODUCE1 cell. */
export interface HsPowSolution {
  /** 16-byte nonce N. */
  nonce: Buffer;
  /** Effort E actually solved for. */
  effort: number;
  /** First 4 bytes of the seed C (POW_SEED). */
  seedHead: Buffer;
  /** 16-byte packed Equi-X solution (POW_SOLUTION). */
  solution: Buffer;
}

export interface SolveHsPowOptions {
  /** 32-byte pow-params seed C. */
  seed: Buffer;
  /** 32-byte blinded service identity key (KP_hs_blind_id). */
  blindedId: Buffer;
  /** Target effort E. Higher = more work and higher intro-queue priority. */
  effort: number;
  /** Random-bytes source (defaults injected by the crypto package export). */
  randomBytes: (n: number) => Uint8Array;
  /** Stop after this wall-clock time (ms). Default 60000. Returns null if exceeded. */
  timeoutMs?: number;
  /** Hard cap on nonces tried. Default: unlimited (bounded by timeoutMs). */
  maxNonces?: number;
  /** Progress callback: (noncesTried) each time a nonce is exhausted. */
  onProgress?: (noncesTried: number) => void;
  /** Monotonic clock, ms. Defaults to Date.now; injectable for tests. */
  now?: () => number;
  /**
   * Cooperative yield between nonce attempts. Solving is CPU-bound and each
   * nonce takes a noticeable slice of time, so on a single-threaded host (e.g.
   * a browser service worker) this lets pending events run between attempts.
   * Defaults to a macrotask yield (`setTimeout(0)`) when available, else a
   * microtask.
   */
  yieldFn?: () => Promise<void>;
}

function defaultYield(): Promise<void> {
  if (typeof setTimeout === 'function') {
    return new Promise((resolve) => setTimeout(resolve, 0));
  }
  return Promise.resolve();
}

/**
 * Solve the hidden-service PoW for a given seed/effort. Returns the solution to
 * place in INTRODUCE1, or null if the budget (timeout / maxNonces) was
 * exhausted before a solution at the requested effort was found.
 *
 * Effort 0 always succeeds on the first solution found (R * 0 == 0). Async and
 * cooperative: it yields between nonce attempts so it doesn't monopolise a
 * single-threaded event loop for the whole budget.
 */
export async function solveHsPow(opts: SolveHsPowOptions): Promise<HsPowSolution | null> {
  if (opts.seed.length !== HS_POW_SEED_LEN)
    throw new Error(`pow seed must be ${HS_POW_SEED_LEN} bytes`);
  if (opts.blindedId.length !== HS_POW_ID_LEN)
    throw new Error(`pow blindedId must be ${HS_POW_ID_LEN} bytes`);

  const now = opts.now ?? Date.now;
  const deadline = now() + (opts.timeoutMs ?? 60_000);
  const maxNonces = opts.maxNonces ?? Number.POSITIVE_INFINITY;
  const effort = opts.effort >>> 0;
  const yieldFn = opts.yieldFn ?? defaultYield;

  const nonce = Buffer.from(opts.randomBytes(HS_POW_NONCE_LEN));
  let tried = 0;

  while (tried < maxNonces && now() <= deadline) {
    const challenge = buildChallenge(opts.blindedId, opts.seed, nonce, effort);
    const program = hashxMake(challenge);
    if (program) {
      const sols = equixSolve(program);
      for (const sol of sols) {
        const solutionBytes = packEquixSolution(sol);
        if (validEffort(challenge, solutionBytes, effort)) {
          return {
            nonce: Buffer.from(nonce),
            effort,
            seedHead: Buffer.from(opts.seed.subarray(0, HS_POW_SEED_HEAD_LEN)),
            solution: solutionBytes,
          };
        }
      }
    }
    tried++;
    opts.onProgress?.(tried);
    incrementNonce(nonce);
    if (tried < maxNonces && now() <= deadline) {
      await yieldFn();
    }
  }
  return null;
}

/**
 * Verify a hidden-service PoW solution end-to-end (Equi-X validity + effort).
 * Mirrors the service-side check in hs_pow.c; used by tests and the HS host.
 */
export function verifyHsPow(params: {
  seed: Buffer;
  blindedId: Buffer;
  nonce: Buffer;
  effort: number;
  solution: Buffer;
}): boolean {
  const challenge = buildChallenge(params.blindedId, params.seed, params.nonce, params.effort);
  const program = hashxMake(challenge);
  if (!program) return false;
  if (equixVerify(program, unpackEquixSolution(params.solution)) !== EquixResult.OK) return false;
  return validEffort(challenge, params.solution, params.effort);
}
