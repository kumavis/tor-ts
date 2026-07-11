/**
 * Equi-X — a CPU-friendly client puzzle (Equihash-60/3 over HashX).
 *
 * Faithful TypeScript port of tevador's reference C solver/verifier
 * (https://github.com/tevador/equix), the variant used by C Tor's v3
 * onion-service proof-of-work (proposal 327). A solution is eight 16-bit
 * indices whose HashX values sum to zero mod 2^60 with the required partial
 * sums, in canonical tree order.
 *
 * The solver is a direct port of Wagner's-algorithm collision search over a
 * fixed-size hash table heap. Validated against the reference: HashX vectors +
 * a golden (challenge -> solutions) vector + Tor's hspow verification vectors
 * (see pow.spec.ts).
 */

import { hashxExecValue, type HashxProgram } from './hashx.ts';

export const EQUIX_NUM_IDX = 8;
export const EQUIX_MAX_SOLS = 8;

export const enum EquixResult {
  OK = 0,
  CHALLENGE = 1,
  ORDER = 2,
  PARTIAL_SUM = 3,
  FINAL_SUM = 4,
}

const EQUIX_STAGE1_MASK = (1n << 15n) - 1n;
const EQUIX_STAGE2_MASK = (1n << 30n) - 1n;
const EQUIX_FULL_MASK = (1n << 60n) - 1n;

const INDEX_SPACE = 1 << 16; // 65536
const NUM_COARSE_BUCKETS = 256;
const NUM_FINE_BUCKETS = 128;
const COARSE_BUCKET_ITEMS = 336;
const FINE_BUCKET_ITEMS = 12;

/** Pre-allocated solver scratch space (~2 MB), reusable across solves. */
class SolverHeap {
  readonly stage1IdxCounts = new Uint16Array(NUM_COARSE_BUCKETS);
  readonly stage1Idx = new Uint16Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly stage1Data = new BigUint64Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly stage2IdxCounts = new Uint16Array(NUM_COARSE_BUCKETS);
  readonly stage2Idx = new Uint32Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly stage2Data = new Float64Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly stage3IdxCounts = new Uint16Array(NUM_COARSE_BUCKETS);
  readonly stage3Idx = new Uint32Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly stage3Data = new Float64Array(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS);
  readonly scratchCounts = new Uint8Array(NUM_FINE_BUCKETS);
  readonly scratch = new Uint16Array(NUM_FINE_BUCKETS * FINE_BUCKET_ITEMS);
}

let sharedHeap: SolverHeap | null = null;

function invertBucket(idx: number): number {
  return (NUM_COARSE_BUCKETS - (idx % NUM_COARSE_BUCKETS)) % NUM_COARSE_BUCKETS;
}
function invertScratch(idx: number): number {
  return (NUM_FINE_BUCKETS - (idx % NUM_FINE_BUCKETS)) % NUM_FINE_BUCKETS;
}
function makeItem(bucket: number, left: number, right: number): number {
  return ((left << 17) | (right << 8) | bucket) >>> 0;
}
function itemBucket(item: number): number {
  return item % NUM_COARSE_BUCKETS;
}
function itemLeftIdx(item: number): number {
  return item >>> 17;
}
function itemRightIdx(item: number): number {
  return (item >>> 8) & 511;
}

// Tree-order comparisons on a solution's 16-bit index array.
function load32(idx: Uint16Array, o: number): number {
  return (idx[o]! | (idx[o + 1]! << 16)) >>> 0;
}
function load64Idx(idx: Uint16Array, o: number): bigint {
  return (
    BigInt(idx[o]!) |
    (BigInt(idx[o + 1]!) << 16n) |
    (BigInt(idx[o + 2]!) << 32n) |
    (BigInt(idx[o + 3]!) << 48n)
  );
}
function treeCmp1(idx: Uint16Array, l: number, r: number): boolean {
  return idx[l]! <= idx[r]!;
}
function treeCmp2(idx: Uint16Array, l: number, r: number): boolean {
  return load32(idx, l) <= load32(idx, r);
}
function treeCmp4(idx: Uint16Array, l: number, r: number): boolean {
  return load64Idx(idx, l) <= load64Idx(idx, r);
}

function swap(idx: Uint16Array, a: number, b: number): void {
  const t = idx[a]!;
  idx[a] = idx[b]!;
  idx[b] = t;
}

function solveStage0(program: HashxProgram, heap: SolverHeap): void {
  heap.stage1IdxCounts.fill(0);
  for (let i = 0; i < INDEX_SPACE; ++i) {
    const value = hashxExecValue(program, BigInt(i));
    const bucketIdx = Number(value % 256n);
    const itemIdx = heap.stage1IdxCounts[bucketIdx]!;
    if (itemIdx >= COARSE_BUCKET_ITEMS) continue;
    heap.stage1IdxCounts[bucketIdx] = itemIdx + 1;
    const off = bucketIdx * COARSE_BUCKET_ITEMS + itemIdx;
    heap.stage1Idx[off] = i;
    heap.stage1Data[off] = value / 256n;
  }
}

function solveStage1(heap: SolverHeap): void {
  heap.stage2IdxCounts.fill(0);
  const makePairs1 = (bucketIdx: number, cplBucket: number, itemIdx: number): void => {
    const carry = bucketIdx !== 0 ? 1n : 0n;
    const value = heap.stage1Data[bucketIdx * COARSE_BUCKET_ITEMS + itemIdx]! + carry;
    const fineBuckIdx = Number(value % 128n);
    const fineCplBucket = invertScratch(fineBuckIdx);
    const fineCplSize = heap.scratchCounts[fineCplBucket]!;
    for (let fineIdx = 0; fineIdx < fineCplSize; ++fineIdx) {
      const cplIndex = heap.scratch[fineCplBucket * FINE_BUCKET_ITEMS + fineIdx]!;
      const cplValue = heap.stage1Data[cplBucket * COARSE_BUCKET_ITEMS + cplIndex]!;
      let sum = value + cplValue;
      sum /= 128n; // 45-50 bits
      const sumN = Number(sum);
      const s2BuckId = sumN % NUM_COARSE_BUCKETS;
      const s2ItemId = heap.stage2IdxCounts[s2BuckId]!;
      if (s2ItemId >= COARSE_BUCKET_ITEMS) continue;
      heap.stage2IdxCounts[s2BuckId] = s2ItemId + 1;
      const off = s2BuckId * COARSE_BUCKET_ITEMS + s2ItemId;
      heap.stage2Idx[off] = makeItem(bucketIdx, itemIdx, cplIndex);
      heap.stage2Data[off] = Math.floor(sumN / NUM_COARSE_BUCKETS); // 37 bits
    }
  };
  for (let bucketIdx = 0; bucketIdx < NUM_COARSE_BUCKETS / 2 + 1; ++bucketIdx) {
    const cplBucket = invertBucket(bucketIdx);
    heap.scratchCounts.fill(0);
    const cplBuckSize = heap.stage1IdxCounts[cplBucket]!;
    for (let itemIdx = 0; itemIdx < cplBuckSize; ++itemIdx) {
      const value = heap.stage1Data[cplBucket * COARSE_BUCKET_ITEMS + itemIdx]!;
      const fineBuckIdx = Number(value % 128n);
      const fineItemIdx = heap.scratchCounts[fineBuckIdx]!;
      if (fineItemIdx >= FINE_BUCKET_ITEMS) continue;
      heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1;
      heap.scratch[fineBuckIdx * FINE_BUCKET_ITEMS + fineItemIdx] = itemIdx;
      if (cplBucket === bucketIdx) makePairs1(bucketIdx, cplBucket, itemIdx);
    }
    if (cplBucket !== bucketIdx) {
      const buckSize = heap.stage1IdxCounts[bucketIdx]!;
      for (let itemIdx = 0; itemIdx < buckSize; ++itemIdx)
        makePairs1(bucketIdx, cplBucket, itemIdx);
    }
  }
}

function solveStage2(heap: SolverHeap): void {
  heap.stage3IdxCounts.fill(0);
  const makePairs2 = (bucketIdx: number, cplBucket: number, itemIdx: number): void => {
    const carry = bucketIdx !== 0 ? 1 : 0;
    const value = heap.stage2Data[bucketIdx * COARSE_BUCKET_ITEMS + itemIdx]! + carry;
    const fineBuckIdx = value % NUM_FINE_BUCKETS;
    const fineCplBucket = invertScratch(fineBuckIdx);
    const fineCplSize = heap.scratchCounts[fineCplBucket]!;
    for (let fineIdx = 0; fineIdx < fineCplSize; ++fineIdx) {
      const cplIndex = heap.scratch[fineCplBucket * FINE_BUCKET_ITEMS + fineIdx]!;
      const cplValue = heap.stage2Data[cplBucket * COARSE_BUCKET_ITEMS + cplIndex]!;
      let sum = value + cplValue;
      sum = Math.floor(sum / NUM_FINE_BUCKETS); // 30 bits
      const s3BuckId = sum % NUM_COARSE_BUCKETS;
      const s3ItemId = heap.stage3IdxCounts[s3BuckId]!;
      if (s3ItemId >= COARSE_BUCKET_ITEMS) continue;
      heap.stage3IdxCounts[s3BuckId] = s3ItemId + 1;
      const off = s3BuckId * COARSE_BUCKET_ITEMS + s3ItemId;
      heap.stage3Idx[off] = makeItem(bucketIdx, itemIdx, cplIndex);
      heap.stage3Data[off] = Math.floor(sum / NUM_COARSE_BUCKETS); // 22 bits
    }
  };
  for (let bucketIdx = 0; bucketIdx < NUM_COARSE_BUCKETS / 2 + 1; ++bucketIdx) {
    const cplBucket = invertBucket(bucketIdx);
    heap.scratchCounts.fill(0);
    const cplBuckSize = heap.stage2IdxCounts[cplBucket]!;
    for (let itemIdx = 0; itemIdx < cplBuckSize; ++itemIdx) {
      const value = heap.stage2Data[cplBucket * COARSE_BUCKET_ITEMS + itemIdx]!;
      const fineBuckIdx = value % NUM_FINE_BUCKETS;
      const fineItemIdx = heap.scratchCounts[fineBuckIdx]!;
      if (fineItemIdx >= FINE_BUCKET_ITEMS) continue;
      heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1;
      heap.scratch[fineBuckIdx * FINE_BUCKET_ITEMS + fineItemIdx] = itemIdx;
      if (cplBucket === bucketIdx) makePairs2(bucketIdx, cplBucket, itemIdx);
    }
    if (cplBucket !== bucketIdx) {
      const buckSize = heap.stage2IdxCounts[bucketIdx]!;
      for (let itemIdx = 0; itemIdx < buckSize; ++itemIdx)
        makePairs2(bucketIdx, cplBucket, itemIdx);
    }
  }
}

function buildSolutionStage1(idx: Uint16Array, o: number, heap: SolverHeap, root: number): void {
  const bucket = itemBucket(root);
  const bucketInv = invertBucket(bucket);
  const leftParent = heap.stage1Idx[bucket * COARSE_BUCKET_ITEMS + itemLeftIdx(root)]!;
  const rightParent = heap.stage1Idx[bucketInv * COARSE_BUCKET_ITEMS + itemRightIdx(root)]!;
  idx[o] = leftParent;
  idx[o + 1] = rightParent;
  if (!treeCmp1(idx, o, o + 1)) swap(idx, o, o + 1);
}

function buildSolutionStage2(idx: Uint16Array, o: number, heap: SolverHeap, root: number): void {
  const bucket = itemBucket(root);
  const bucketInv = invertBucket(bucket);
  const leftParent = heap.stage2Idx[bucket * COARSE_BUCKET_ITEMS + itemLeftIdx(root)]!;
  const rightParent = heap.stage2Idx[bucketInv * COARSE_BUCKET_ITEMS + itemRightIdx(root)]!;
  buildSolutionStage1(idx, o, heap, leftParent);
  buildSolutionStage1(idx, o + 2, heap, rightParent);
  if (!treeCmp2(idx, o, o + 2)) {
    swap(idx, o, o + 2);
    swap(idx, o + 1, o + 3);
  }
}

function buildSolution(heap: SolverHeap, left: number, right: number): Uint16Array {
  const idx = new Uint16Array(EQUIX_NUM_IDX);
  buildSolutionStage2(idx, 0, heap, left);
  buildSolutionStage2(idx, 4, heap, right);
  if (!treeCmp4(idx, 0, 4)) {
    swap(idx, 0, 4);
    swap(idx, 1, 5);
    swap(idx, 2, 6);
    swap(idx, 3, 7);
  }
  return idx;
}

function solveStage3(heap: SolverHeap): Uint16Array[] {
  const out: Uint16Array[] = [];
  const makePairs3 = (bucketIdx: number, cplBucket: number, itemIdx: number): boolean => {
    const carry = bucketIdx !== 0 ? 1 : 0;
    const value = heap.stage3Data[bucketIdx * COARSE_BUCKET_ITEMS + itemIdx]! + carry;
    const fineBuckIdx = value % NUM_FINE_BUCKETS;
    const fineCplBucket = invertScratch(fineBuckIdx);
    const fineCplSize = heap.scratchCounts[fineCplBucket]!;
    for (let fineIdx = 0; fineIdx < fineCplSize; ++fineIdx) {
      const cplIndex = heap.scratch[fineCplBucket * FINE_BUCKET_ITEMS + fineIdx]!;
      const cplValue = heap.stage3Data[cplBucket * COARSE_BUCKET_ITEMS + cplIndex]!;
      let sum = value + cplValue;
      sum = Math.floor(sum / NUM_FINE_BUCKETS); // 15 bits
      if ((BigInt(sum) & EQUIX_STAGE1_MASK) === 0n) {
        const itemLeft = heap.stage3Idx[bucketIdx * COARSE_BUCKET_ITEMS + itemIdx]!;
        const itemRight = heap.stage3Idx[cplBucket * COARSE_BUCKET_ITEMS + cplIndex]!;
        out.push(buildSolution(heap, itemLeft, itemRight));
        if (out.length >= EQUIX_MAX_SOLS) return true;
      }
    }
    return false;
  };
  for (let bucketIdx = 0; bucketIdx < NUM_COARSE_BUCKETS / 2 + 1; ++bucketIdx) {
    const cplBucket = (-bucketIdx & (NUM_COARSE_BUCKETS - 1)) >>> 0;
    heap.scratchCounts.fill(0);
    const cplBuckSize = heap.stage3IdxCounts[cplBucket]!;
    for (let itemIdx = 0; itemIdx < cplBuckSize; ++itemIdx) {
      const value = heap.stage3Data[cplBucket * COARSE_BUCKET_ITEMS + itemIdx]!;
      const fineBuckIdx = value % NUM_FINE_BUCKETS;
      const fineItemIdx = heap.scratchCounts[fineBuckIdx]!;
      if (fineItemIdx >= FINE_BUCKET_ITEMS) continue;
      heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1;
      heap.scratch[fineBuckIdx * FINE_BUCKET_ITEMS + fineItemIdx] = itemIdx;
      if (cplBucket === bucketIdx) {
        if (makePairs3(bucketIdx, cplBucket, itemIdx)) return out;
      }
    }
    if (cplBucket !== bucketIdx) {
      const buckSize = heap.stage3IdxCounts[bucketIdx]!;
      for (let itemIdx = 0; itemIdx < buckSize; ++itemIdx) {
        if (makePairs3(bucketIdx, cplBucket, itemIdx)) return out;
      }
    }
  }
  return out;
}

/**
 * Find Equi-X solutions for a challenge whose HashX program is `program`.
 * Returns 0..EQUIX_MAX_SOLS solutions, each an 8-element Uint16Array of indices
 * in canonical order (matching the reference solver's output and ordering).
 */
export function equixSolve(program: HashxProgram): Uint16Array[] {
  if (!sharedHeap) sharedHeap = new SolverHeap();
  const heap = sharedHeap;
  solveStage0(program, heap);
  solveStage1(heap);
  solveStage2(heap);
  return solveStage3(heap);
}

function verifyOrder(idx: Uint16Array): boolean {
  return (
    treeCmp4(idx, 0, 4) &&
    treeCmp2(idx, 0, 2) &&
    treeCmp2(idx, 4, 6) &&
    treeCmp1(idx, 0, 1) &&
    treeCmp1(idx, 2, 3) &&
    treeCmp1(idx, 4, 5) &&
    treeCmp1(idx, 6, 7)
  );
}

function sumPair(program: HashxProgram, left: number, right: number): bigint {
  return (
    (hashxExecValue(program, BigInt(left)) + hashxExecValue(program, BigInt(right))) &
    ((1n << 64n) - 1n)
  );
}

/**
 * Verify an Equi-X solution against its HashX program. Mirrors
 * `equix_verify`: checks canonical ordering, the stage partial sums, and the
 * final zero sum mod 2^60.
 */
export function equixVerify(program: HashxProgram, idx: Uint16Array): EquixResult {
  if (!verifyOrder(idx)) return EquixResult.ORDER;
  const MASK = (1n << 64n) - 1n;
  const pair0 = sumPair(program, idx[0]!, idx[1]!);
  if (pair0 & EQUIX_STAGE1_MASK) return EquixResult.PARTIAL_SUM;
  const pair1 = sumPair(program, idx[2]!, idx[3]!);
  if (pair1 & EQUIX_STAGE1_MASK) return EquixResult.PARTIAL_SUM;
  const pair4 = (pair0 + pair1) & MASK;
  if (pair4 & EQUIX_STAGE2_MASK) return EquixResult.PARTIAL_SUM;
  const pair2 = sumPair(program, idx[4]!, idx[5]!);
  if (pair2 & EQUIX_STAGE1_MASK) return EquixResult.PARTIAL_SUM;
  const pair3 = sumPair(program, idx[6]!, idx[7]!);
  if (pair3 & EQUIX_STAGE1_MASK) return EquixResult.PARTIAL_SUM;
  const pair5 = (pair2 + pair3) & MASK;
  if (pair5 & EQUIX_STAGE2_MASK) return EquixResult.PARTIAL_SUM;
  const pair6 = (pair4 + pair5) & MASK;
  if (pair6 & EQUIX_FULL_MASK) return EquixResult.FINAL_SUM;
  return EquixResult.OK;
}

/** Serialize an Equi-X solution to 16 bytes: 8 little-endian uint16 indices. */
export function packEquixSolution(idx: Uint16Array): Buffer {
  const out = Buffer.alloc(16);
  for (let i = 0; i < EQUIX_NUM_IDX; ++i) {
    out[i * 2] = idx[i]! & 0xff;
    out[i * 2 + 1] = (idx[i]! >> 8) & 0xff;
  }
  return out;
}

/** Parse 16 solution bytes (8 little-endian uint16 indices) into an index array. */
export function unpackEquixSolution(bytes: Buffer | Uint8Array): Uint16Array {
  const idx = new Uint16Array(EQUIX_NUM_IDX);
  for (let i = 0; i < EQUIX_NUM_IDX; ++i) {
    idx[i] = (bytes[i * 2]! | (bytes[i * 2 + 1]! << 8)) & 0xffff;
  }
  return idx;
}
