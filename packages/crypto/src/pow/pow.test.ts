/**
 * Tests for the hidden-service proof-of-work primitives (HashX + Equi-X + the
 * hspow client), validated against the reference implementations and C Tor.
 *
 * Sources of the vectors:
 *  - HashX digests: tevador/hashx `src/tests.c`.
 *  - Equi-X golden solver output: generated from tevador/equix's reference
 *    solver for a fixed challenge (deterministic).
 *  - hspow verification vectors: C Tor `src/test/test_hs_pow.c`.
 */

import { describe, it, expect } from 'vitest';
import {
  hashxMake,
  hashxExecDigest,
  equixSolve,
  equixVerify,
  EquixResult,
  packEquixSolution,
  unpackEquixSolution,
  solveHsPow,
  verifyHsPow,
  randomBytes,
  blake2b,
} from 'tor-crypto';

// Only run the full Equi-X solve (~a few seconds of BigInt work) under Node, so
// the browser suite stays fast. The verification-only tests run everywhere.
// Require the absence of `window` too: the browser build polyfills `process`,
// so `process.versions.node` alone can be truthy there.
const NODE =
  typeof window === 'undefined' && typeof process !== 'undefined' && !!process.versions?.node;

const P = Buffer.from('Tor hs intro v1\0', 'ascii');
function challenge(idHex: string, seedHex: string, nonceHex: string, effort: number): Buffer {
  const e = Buffer.alloc(4);
  e.writeUInt32BE(effort >>> 0);
  return Buffer.concat([
    P,
    Buffer.from(idHex, 'hex'),
    Buffer.from(seedHex, 'hex'),
    Buffer.from(nonceHex, 'hex'),
    e,
  ]);
}

describe('HashX', () => {
  const vectors: Array<[string, bigint, string]> = [
    [
      'This is a test\0',
      123456n,
      'aebdd50aa67c93afb82a4c534603b65e46decd584c55161c526ebc099415ccf1',
    ],
    ['This is a test\0', 0n, '2b2f54567dcbea98fdb5d5e5ce9a65983c4a4e35ab1464b1efb61e83b7074bb2'],
    [
      'Lorem ipsum dolor sit amet\0',
      123456n,
      'ab3d155bf4bbb0aa3a71b7801089826186e44300e6932e6ffd287cf302bbb0ba',
    ],
    [
      'Lorem ipsum dolor sit amet\0',
      987654321123456789n,
      '8dfef0497c323274a60d1d93292b68d9a0496379ba407b4341cf868a14d30113',
    ],
  ];
  for (const [seed, ctr, expected] of vectors) {
    it(`matches reference digest for seed=${JSON.stringify(seed)} ctr=${ctr}`, () => {
      const prog = hashxMake(Buffer.from(seed, 'ascii'));
      expect(prog).not.toBeNull();
      expect(hashxExecDigest(prog!, ctr).toString('hex')).toBe(expected);
    });
  }
});

describe('Equi-X', () => {
  // Golden challenge: P || id(0x11*32) || seed(0xaa*32) || nonce(0x55*16) || htonl(0)
  const goldenChallenge = challenge('11'.repeat(32), 'aa'.repeat(32), '55'.repeat(16), 0);
  const goldenSolutions = [
    '4312f87ceab844c78e1c793a913812d7',
    'a15e4ca0410d26aa0d3587464c0f90f0',
    'ac2cc635264b6d8d5f5ed677f6069fd8',
    '3f5f1090ea7576b5631ab51cd4256dd5',
    '4d51c17d5b462ab4ce32e748687caece',
    '075ae97ab4b065b2c42a8069e6007ad6',
  ];

  it.runIf(NODE)('solver reproduces the reference solutions in order', () => {
    const prog = hashxMake(goldenChallenge)!;
    const sols = equixSolve(prog).map((s) => packEquixSolution(s).toString('hex'));
    expect(sols).toEqual(goldenSolutions);
  });

  it.runIf(NODE)('every found solution verifies as OK', () => {
    const prog = hashxMake(goldenChallenge)!;
    for (const s of equixSolve(prog)) {
      expect(equixVerify(prog, s)).toBe(EquixResult.OK);
    }
  });

  it('verifies a known-good solution and rejects reordered indices', () => {
    const prog = hashxMake(goldenChallenge)!;
    const idx = unpackEquixSolution(Buffer.from(goldenSolutions[0]!, 'hex'));
    expect(equixVerify(prog, idx)).toBe(EquixResult.OK);
    // Swapping the first pair breaks canonical ordering.
    const swapped = Uint16Array.from(idx);
    [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
    expect(equixVerify(prog, swapped)).toBe(EquixResult.ORDER);
  });

  it('pack/unpack round-trips', () => {
    const idx = unpackEquixSolution(Buffer.from(goldenSolutions[2]!, 'hex'));
    expect(packEquixSolution(idx).toString('hex')).toBe(goldenSolutions[2]);
  });
});

describe('hspow client (C Tor test vectors)', () => {
  // From src/test/test_hs_pow.c: (blinded_id, seed, nonce, effort, solution).
  const valid = [
    {
      name: 'zero-effort',
      id: '11'.repeat(32),
      seed: 'aa'.repeat(32),
      nonce: '55'.repeat(16),
      effort: 0,
      solution: '4312f87ceab844c78e1c793a913812d7',
    },
    {
      name: 'high-effort (1e6)',
      id: '11'.repeat(32),
      seed: 'aa'.repeat(32),
      nonce: '59217255555555555555555555555555',
      effort: 1000000,
      solution: '0f3db97b9cac20c1771680a1a34848d3',
    },
    {
      name: 'real keys (1e5)',
      id: 'bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed',
      seed: '86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f',
      nonce: '2eff9fdbc34326d9d2f18ed277469c63',
      effort: 100000,
      solution: '400cb091139f86b352119f6e131802d6',
    },
  ];

  for (const v of valid) {
    it(`verifies ${v.name}`, () => {
      expect(
        verifyHsPow({
          seed: Buffer.from(v.seed, 'hex'),
          blindedId: Buffer.from(v.id, 'hex'),
          nonce: Buffer.from(v.nonce, 'hex'),
          effort: v.effort,
          solution: Buffer.from(v.solution, 'hex'),
        })
      ).toBe(true);
    });
  }

  it('rejects a corrupted nonce', () => {
    expect(
      verifyHsPow({
        seed: Buffer.from(
          '86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f',
          'hex'
        ),
        blindedId: Buffer.from(
          'bfd298428562e530c52bdb36d81a0e293ef4a0e94d787f0f8c0c611f4f9e78ed',
          'hex'
        ),
        // one nibble flipped vs the valid vector above
        nonce: Buffer.from('2eff9fdbc34326d9a2f18ed277469c63', 'hex'),
        effort: 100000,
        solution: Buffer.from('400cb091139f86b352119f6e131802d6', 'hex'),
      })
    ).toBe(false);
  });

  it.runIf(NODE)(
    'solves an effort-0 puzzle that round-trips through verification',
    async () => {
      const seed = Buffer.from('aa'.repeat(32), 'hex');
      const blindedId = Buffer.from('11'.repeat(32), 'hex');
      const sol = await solveHsPow({ seed, blindedId, effort: 0, randomBytes });
      expect(sol).not.toBeNull();
      expect(sol!.seedHead.toString('hex')).toBe('aaaaaaaa');
      expect(
        verifyHsPow({
          seed,
          blindedId,
          nonce: sol!.nonce,
          effort: sol!.effort,
          solution: sol!.solution,
        })
      ).toBe(true);
    },
    30_000
  );

  it.runIf(NODE)(
    'rejects a structurally-valid Equi-X solution that misses the effort target',
    () => {
      // Distinct from the corrupted-nonce case (which fails at the Equi-X stage):
      // here the solution IS a valid Equi-X solution (equixVerify == OK) but its
      // R*E exceeds UINT32_MAX, so the effort check must reject it. Use the max
      // effort so essentially every solution for the nonce misses the target.
      const seed = Buffer.from('aa'.repeat(32), 'hex');
      const blindedId = Buffer.from('11'.repeat(32), 'hex');
      const nonce = Buffer.from('55'.repeat(16), 'hex');
      const effort = 0xffffffff;
      const ch = challenge('11'.repeat(32), 'aa'.repeat(32), '55'.repeat(16), effort);
      const prog = hashxMake(ch)!;
      let found = false;
      for (const s of equixSolve(prog)) {
        if (equixVerify(prog, s) !== EquixResult.OK) continue;
        const solBytes = packEquixSolution(s);
        const R = BigInt(blake2b(Buffer.concat([ch, solBytes]), { dkLen: 4 }).readUInt32BE(0));
        if (R * BigInt(effort) <= 0xffffffffn) continue; // this one happens to meet the target
        // Valid Equi-X solution, but effort target missed -> verifyHsPow must reject.
        expect(equixVerify(prog, s)).toBe(EquixResult.OK);
        expect(verifyHsPow({ seed, blindedId, nonce, effort, solution: solBytes })).toBe(false);
        found = true;
        break;
      }
      expect(found).toBe(true);
    },
    30_000
  );

  it.runIf(NODE)('respects the solve budget and returns null when exhausted', async () => {
    // A huge effort with a 1-nonce budget cannot be met -> null (no throw).
    const sol = await solveHsPow({
      seed: Buffer.from('aa'.repeat(32), 'hex'),
      blindedId: Buffer.from('11'.repeat(32), 'hex'),
      effort: 0xffffffff,
      randomBytes,
      maxNonces: 1,
    });
    expect(sol).toBeNull();
  });
});
