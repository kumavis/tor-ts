/**
 * HashX — a keyed, pseudo-randomly generated hash function.
 *
 * Faithful TypeScript port of tevador's reference C implementation
 * (https://github.com/tevador/hashx), the same code vendored by C Tor as
 * `src/ext/equix/hashx` and used by the v3 onion-service proof-of-work scheme
 * (proposal 327 / hspow-spec). Each seed deterministically generates a unique
 * straight-line integer program; hashing an input runs that program over eight
 * 64-bit registers.
 *
 * This is the interpreted variant (the C "compiled" JIT path is irrelevant in
 * JS). Validated byte-for-byte against the reference `hashx-tests` vectors —
 * see pow.spec.ts.
 *
 * All 64-bit arithmetic uses BigInt masked to 64 bits. This is not fast, but
 * it is exact; performance is bounded by the caller's effort budget.
 */

import { blake2b } from '../hashes.ts';

const MASK64 = (1n << 64n) - 1n;
const u64 = (x: bigint): bigint => x & MASK64;

function rotl64(x: bigint, b: bigint): bigint {
  return u64((x << b) | (x >> (64n - b)));
}

/** SipHash round on a 4-element BigInt register array (mutates in place). */
function sipround(v: bigint[]): void {
  let [v0, v1, v2, v3] = v;
  v0 = u64(v0! + v1!);
  v2 = u64(v2! + v3!);
  v1 = rotl64(v1!, 13n);
  v3 = rotl64(v3!, 16n);
  v1 ^= v0;
  v3 ^= v2;
  v0 = rotl64(v0, 32n);
  v2 = u64(v2 + v1);
  v0 = u64(v0 + v3);
  v1 = rotl64(v1, 17n);
  v3 = rotl64(v3, 21n);
  v1 ^= v2;
  v3 ^= v0;
  v2 = rotl64(v2, 32n);
  v[0] = v0;
  v[1] = v1;
  v[2] = v2;
  v[3] = v3;
}

export interface SiphashState {
  v0: bigint;
  v1: bigint;
  v2: bigint;
  v3: bigint;
}

/** hashx_siphash13_ctr */
function siphash13Ctr(input: bigint, keys: SiphashState): bigint {
  const v = [keys.v0, keys.v1, keys.v2, keys.v3 ^ input];
  sipround(v);
  v[0] = v[0]! ^ input;
  v[2] = v[2]! ^ 0xffn;
  sipround(v);
  sipround(v);
  sipround(v);
  return u64(v[0]! ^ v[1]! ^ (v[2]! ^ v[3]!));
}

/** hashx_siphash24_ctr_state512 — produces the 8 initial registers. */
function siphash24CtrState512(keys: SiphashState, input: bigint): bigint[] {
  const v = [keys.v0, keys.v1 ^ 0xeen, keys.v2, keys.v3 ^ input];
  sipround(v);
  sipround(v);
  v[0] = v[0]! ^ input;
  v[2] = v[2]! ^ 0xeen;
  sipround(v);
  sipround(v);
  sipround(v);
  sipround(v);
  const out = [v[0]!, v[1]!, v[2]!, v[3]!, 0n, 0n, 0n, 0n];
  v[1] = v[1]! ^ 0xddn;
  sipround(v);
  sipround(v);
  sipround(v);
  sipround(v);
  out[4] = v[0]!;
  out[5] = v[1]!;
  out[6] = v[2]!;
  out[7] = v[3]!;
  return out;
}

/** siphash_rng — pseudo-random stream used by the program generator. */
class SiphashRng {
  private keys: SiphashState;
  private counter = 0n;
  private buffer8 = 0n;
  private buffer32 = 0n;
  private count8 = 0;
  private count32 = 0;

  constructor(state: SiphashState) {
    this.keys = state;
  }

  u8(): number {
    if (this.count8 === 0) {
      this.buffer8 = siphash13Ctr(this.counter, this.keys);
      this.counter = u64(this.counter + 1n);
      this.count8 = 8;
    }
    this.count8--;
    return Number((this.buffer8 >> BigInt(this.count8 * 8)) & 0xffn);
  }

  u32(): number {
    if (this.count32 === 0) {
      this.buffer32 = siphash13Ctr(this.counter, this.keys);
      this.counter = u64(this.counter + 1n);
      this.count32 = 2;
    }
    this.count32--;
    return Number((this.buffer32 >> BigInt(this.count32 * 32)) & 0xffffffffn) >>> 0;
  }
}

// ============================================================================
// Instruction set (mirrors instruction.h)
// ============================================================================

const enum Op {
  UMULH_R = 0,
  SMULH_R = 1,
  MUL_R = 2,
  SUB_R = 3,
  XOR_R = 4,
  ADD_RS = 5,
  ROR_C = 6,
  ADD_C = 7,
  XOR_C = 8,
  TARGET = 9,
  BRANCH = 10,
}

interface Instruction {
  opcode: Op;
  src: number;
  dst: number;
  imm32: number;
  opPar: number;
}

// Execution ports (Ivy Bridge P0/P1/P5 model).
const PORT_NONE = 0;
const PORT_P0 = 1;
const PORT_P1 = 2;
const PORT_P5 = 4;
const PORT_P01 = PORT_P0 | PORT_P1;
const PORT_P05 = PORT_P0 | PORT_P5;
const PORT_P015 = PORT_P0 | PORT_P1 | PORT_P5;

interface InstrTemplate {
  type: Op;
  latency: number;
  uop1: number;
  uop2: number;
  immediateMask: number;
  group: Op;
  immCanBeZero: boolean;
  distinctDst: boolean;
  opParSrc: boolean;
  hasSrc: boolean;
  hasDst: boolean;
}

const BRANCH_MASK = 0x80000000;

const tpl_umulh_r: InstrTemplate = {
  type: Op.UMULH_R,
  latency: 4,
  uop1: PORT_P1,
  uop2: PORT_P5,
  immediateMask: 0,
  group: Op.UMULH_R,
  immCanBeZero: false,
  distinctDst: false,
  opParSrc: false,
  hasSrc: true,
  hasDst: true,
};
const tpl_smulh_r: InstrTemplate = {
  type: Op.SMULH_R,
  latency: 4,
  uop1: PORT_P1,
  uop2: PORT_P5,
  immediateMask: 0,
  group: Op.SMULH_R,
  immCanBeZero: false,
  distinctDst: false,
  opParSrc: false,
  hasSrc: true,
  hasDst: true,
};
const tpl_mul_r: InstrTemplate = {
  type: Op.MUL_R,
  latency: 3,
  uop1: PORT_P1,
  uop2: PORT_NONE,
  immediateMask: 0,
  group: Op.MUL_R,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: true,
  hasSrc: true,
  hasDst: true,
};
const tpl_sub_r: InstrTemplate = {
  type: Op.SUB_R,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_NONE,
  immediateMask: 0,
  group: Op.ADD_RS,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: true,
  hasSrc: true,
  hasDst: true,
};
const tpl_xor_r: InstrTemplate = {
  type: Op.XOR_R,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_NONE,
  immediateMask: 0,
  group: Op.XOR_R,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: true,
  hasSrc: true,
  hasDst: true,
};
const tpl_add_rs: InstrTemplate = {
  type: Op.ADD_RS,
  latency: 1,
  uop1: PORT_P01,
  uop2: PORT_NONE,
  immediateMask: 3,
  group: Op.ADD_RS,
  immCanBeZero: true,
  distinctDst: true,
  opParSrc: true,
  hasSrc: true,
  hasDst: true,
};
const tpl_ror_c: InstrTemplate = {
  type: Op.ROR_C,
  latency: 1,
  uop1: PORT_P05,
  uop2: PORT_NONE,
  immediateMask: 63,
  group: Op.ROR_C,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: false,
  hasSrc: false,
  hasDst: true,
};
const tpl_add_c: InstrTemplate = {
  type: Op.ADD_C,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_NONE,
  immediateMask: 0xffffffff,
  group: Op.ADD_C,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: false,
  hasSrc: false,
  hasDst: true,
};
const tpl_xor_c: InstrTemplate = {
  type: Op.XOR_C,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_NONE,
  immediateMask: 0xffffffff,
  group: Op.XOR_C,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: false,
  hasSrc: false,
  hasDst: true,
};
const tpl_target: InstrTemplate = {
  type: Op.TARGET,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_P015,
  immediateMask: 0,
  group: Op.TARGET,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: false,
  hasSrc: false,
  hasDst: false,
};
const tpl_branch: InstrTemplate = {
  type: Op.BRANCH,
  latency: 1,
  uop1: PORT_P015,
  uop2: PORT_P015,
  immediateMask: BRANCH_MASK,
  group: Op.BRANCH,
  immCanBeZero: false,
  distinctDst: true,
  opParSrc: false,
  hasSrc: false,
  hasDst: false,
};

const instr_lookup = [
  tpl_ror_c,
  tpl_xor_c,
  tpl_add_c,
  tpl_add_c,
  tpl_sub_r,
  tpl_xor_r,
  tpl_xor_c,
  tpl_add_rs,
];
const wide_mul_lookup = [tpl_smulh_r, tpl_umulh_r];

interface ProgramItem {
  templates: InstrTemplate[];
  mask0: number;
  mask1: number;
  duplicates: boolean;
}

const item_mul: ProgramItem = { templates: [tpl_mul_r], mask0: 0, mask1: 0, duplicates: true };
const item_target: ProgramItem = { templates: [tpl_target], mask0: 0, mask1: 0, duplicates: true };
const item_branch: ProgramItem = { templates: [tpl_branch], mask0: 0, mask1: 0, duplicates: true };
const item_wide_mul: ProgramItem = {
  templates: wide_mul_lookup,
  mask0: 1,
  mask1: 1,
  duplicates: true,
};
const item_any: ProgramItem = { templates: instr_lookup, mask0: 7, mask1: 3, duplicates: false };

// prettier-ignore
const program_layout: ProgramItem[] = [
  item_mul, item_target, item_any, item_mul, item_any, item_any,
  item_mul, item_any, item_any, item_mul, item_any, item_any,
  item_wide_mul, item_any, item_any, item_mul, item_any, item_any,
  item_mul, item_branch, item_any, item_mul, item_any, item_any,
  item_wide_mul, item_any, item_any, item_mul, item_any, item_any,
  item_mul, item_any, item_any, item_mul, item_any, item_any,
];

const TARGET_CYCLE = 192;
const REQUIREMENT_SIZE = 512;
const REQUIREMENT_MUL_COUNT = 192;
const REQUIREMENT_LATENCY = 195;
const REGISTER_NEEDS_DISPLACEMENT = 5;
const PORT_MAP_SIZE = TARGET_CYCLE + 4;
const NUM_PORTS = 3;
const MAX_RETRIES = 1;
const LOG2_BRANCH_PROB = 4;
const HASHX_PROGRAM_MAX_SIZE = 512;

function isMul(type: Op): boolean {
  return type <= Op.MUL_R;
}

interface RegisterInfo {
  latency: number;
  lastOp: number; // Op or -1
  lastOpPar: number; // uint32 or 0xffffffff sentinel
}

interface GeneratorCtx {
  cycle: number;
  subCycle: number;
  mulCount: number;
  chainMul: boolean;
  latency: number;
  gen: SiphashRng;
  registers: RegisterInfo[];
  ports: Int32Array[]; // [PORT_MAP_SIZE][NUM_PORTS]
}

function selectTemplate(ctx: GeneratorCtx, lastInstr: number, attempt: number): InstrTemplate {
  const item = program_layout[ctx.subCycle % 36]!;
  let tpl: InstrTemplate;
  do {
    const index = item.mask0 ? ctx.gen.u8() & (attempt > 0 ? item.mask1 : item.mask0) : 0;
    tpl = item.templates[index]!;
  } while (!item.duplicates && tpl.group === lastInstr);
  return tpl;
}

function branchMask(gen: SiphashRng): number {
  let mask = 0;
  let popcnt = 0;
  while (popcnt < LOG2_BRANCH_PROB) {
    const bit = gen.u8() % 32;
    const bitmask = (1 << bit) >>> 0;
    if (!(mask & bitmask)) {
      mask = (mask | bitmask) >>> 0;
      popcnt++;
    }
  }
  return mask >>> 0;
}

function instrFromTemplate(tpl: InstrTemplate, gen: SiphashRng, instr: Instruction): void {
  instr.opcode = tpl.type;
  if (tpl.immediateMask) {
    if (tpl.immediateMask === BRANCH_MASK) {
      instr.imm32 = branchMask(gen);
    } else {
      do {
        instr.imm32 = (gen.u32() & tpl.immediateMask) >>> 0;
      } while (instr.imm32 === 0 && !tpl.immCanBeZero);
    }
  }
  if (!tpl.opParSrc) {
    if (tpl.distinctDst) {
      instr.opPar = 0xffffffff;
    } else {
      instr.opPar = gen.u32();
    }
  }
  if (!tpl.hasSrc) instr.src = -1;
  if (!tpl.hasDst) instr.dst = -1;
}

function selectRegister(availableRegs: number[], regsCount: number, gen: SiphashRng): number {
  if (regsCount === 0) return -1;
  const index = regsCount > 1 ? gen.u32() % regsCount : 0;
  return availableRegs[index]!;
}

function selectDestination(
  tpl: InstrTemplate,
  instr: Instruction,
  ctx: GeneratorCtx,
  cycle: number
): boolean {
  const availableRegs: number[] = new Array(8).fill(0);
  let regsCount = 0;
  for (let i = 0; i < 8; ++i) {
    let available = ctx.registers[i]!.latency <= cycle;
    available = available && (!tpl.distinctDst || i !== instr.src);
    available =
      available &&
      (ctx.chainMul || tpl.group !== Op.MUL_R || ctx.registers[i]!.lastOp !== Op.MUL_R);
    available =
      available &&
      (ctx.registers[i]!.lastOp !== tpl.group || ctx.registers[i]!.lastOpPar !== instr.opPar);
    available = available && (instr.opcode !== Op.ADD_RS || i !== REGISTER_NEEDS_DISPLACEMENT);
    availableRegs[regsCount] = available ? i : 0;
    regsCount += available ? 1 : 0;
  }
  const reg = selectRegister(availableRegs, regsCount, ctx.gen);
  if (reg < 0) return false;
  instr.dst = reg;
  return true;
}

function selectSource(
  tpl: InstrTemplate,
  instr: Instruction,
  ctx: GeneratorCtx,
  cycle: number
): boolean {
  const availableRegs: number[] = [];
  let regsCount = 0;
  for (let i = 0; i < 8; ++i) {
    if (ctx.registers[i]!.latency <= cycle) availableRegs[regsCount++] = i;
  }
  if (regsCount === 2 && instr.opcode === Op.ADD_RS) {
    if (
      availableRegs[0] === REGISTER_NEEDS_DISPLACEMENT ||
      availableRegs[1] === REGISTER_NEEDS_DISPLACEMENT
    ) {
      instr.opPar = instr.src = REGISTER_NEEDS_DISPLACEMENT;
      return true;
    }
  }
  const reg = selectRegister(availableRegs, regsCount, ctx.gen);
  if (reg >= 0) {
    instr.src = reg;
    if (tpl.opParSrc) instr.opPar = instr.src;
    return true;
  }
  return false;
}

function scheduleUop(uop: number, ctx: GeneratorCtx, cycleStart: number, commit: boolean): number {
  for (let cycle = cycleStart; cycle < PORT_MAP_SIZE; ++cycle) {
    const p = ctx.ports[cycle]!;
    if (uop & PORT_P5 && !p[2]) {
      if (commit) p[2] = uop;
      return cycle;
    }
    if (uop & PORT_P0 && !p[0]) {
      if (commit) p[0] = uop;
      return cycle;
    }
    if ((uop & PORT_P1) !== 0 && !p[1]) {
      if (commit) p[1] = uop;
      return cycle;
    }
  }
  return -1;
}

function scheduleInstr(tpl: InstrTemplate, ctx: GeneratorCtx, commit: boolean): number {
  if (tpl.uop2 === PORT_NONE) {
    return scheduleUop(tpl.uop1, ctx, ctx.cycle, commit);
  }
  for (let cycle = ctx.cycle; cycle < PORT_MAP_SIZE; ++cycle) {
    const cycle1 = scheduleUop(tpl.uop1, ctx, cycle, false);
    const cycle2 = scheduleUop(tpl.uop2, ctx, cycle, false);
    if (cycle1 >= 0 && cycle1 === cycle2) {
      if (commit) {
        scheduleUop(tpl.uop1, ctx, cycle, true);
        scheduleUop(tpl.uop2, ctx, cycle, true);
      }
      return cycle1;
    }
  }
  return -1;
}

/**
 * Precompiled, execution-friendly form of a program: parallel typed arrays plus
 * per-instruction BigInt constants. Built once per program and reused across
 * the ~65536 executions a single Equi-X solve performs, avoiding per-instruction
 * object-property and helper-call overhead in the hot loop.
 */
interface CompiledProgram {
  ops: Uint8Array;
  dst: Int8Array;
  src: Int8Array;
  bigA: bigint[]; // ADD_RS shift; ROR right amount; ADD_C/XOR_C sign-extended constant
  bigB: bigint[]; // ROR left amount (64 - right)
  brMask: Int32Array; // BRANCH imm32 mask
  n: number;
}

/**
 * A compiled HashX program: the instruction list plus the finalization keys.
 * Produced by {@link hashxMake}; run with {@link hashxExecRegisters}.
 */
export interface HashxProgram {
  code: Instruction[];
  keys: SiphashState; // ctx->keys (keys[1]) — used for register init and finalization
  /** Lazily-built precompiled form (see {@link CompiledProgram}). */
  compiled?: CompiledProgram;
}

function compile(program: HashxProgram): CompiledProgram {
  const code = program.code;
  const n = code.length;
  const ops = new Uint8Array(n);
  const dst = new Int8Array(n);
  const src = new Int8Array(n);
  const brMask = new Int32Array(n);
  const bigA: bigint[] = new Array(n).fill(0n);
  const bigB: bigint[] = new Array(n).fill(0n);
  for (let i = 0; i < n; i++) {
    const ins = code[i]!;
    ops[i] = ins.opcode;
    dst[i] = ins.dst;
    src[i] = ins.src;
    switch (ins.opcode) {
      case Op.ADD_RS:
        bigA[i] = BigInt(ins.imm32);
        break;
      case Op.ROR_C:
        bigA[i] = BigInt(ins.imm32);
        bigB[i] = BigInt(64 - ins.imm32);
        break;
      case Op.ADD_C:
      case Op.XOR_C:
        bigA[i] = signExtend2sCompl(ins.imm32);
        break;
      case Op.BRANCH:
        brMask[i] = ins.imm32 | 0;
        break;
    }
  }
  return { ops, dst, src, bigA, bigB, brMask, n };
}

/** hashx_program_generate — returns the program, or null if it fails the uniform-complexity requirement. */
function programGenerate(key: SiphashState): Instruction[] | null {
  const ctx: GeneratorCtx = {
    cycle: 0,
    subCycle: 0,
    mulCount: 0,
    chainMul: false,
    latency: 0,
    gen: new SiphashRng(key),
    registers: Array.from({ length: 8 }, () => ({ latency: 0, lastOp: -1, lastOpPar: 0xffffffff })),
    ports: Array.from({ length: PORT_MAP_SIZE }, () => new Int32Array(NUM_PORTS)),
  };

  const code: Instruction[] = [];
  let attempt = 0;
  let lastInstr = -1;

  while (code.length < HASHX_PROGRAM_MAX_SIZE) {
    const instr: Instruction = { opcode: Op.UMULH_R, src: -1, dst: -1, imm32: 0, opPar: 0 };

    const tpl = selectTemplate(ctx, lastInstr, attempt);
    lastInstr = tpl.group;

    instrFromTemplate(tpl, ctx.gen, instr);

    let scheduleCycle = scheduleInstr(tpl, ctx, false);
    if (scheduleCycle < 0) break;

    ctx.chainMul = attempt > 0;

    if (tpl.hasSrc) {
      if (!selectSource(tpl, instr, ctx, scheduleCycle)) {
        if (attempt++ < MAX_RETRIES) continue;
        ctx.subCycle += 3;
        ctx.cycle = Math.floor(ctx.subCycle / 3);
        attempt = 0;
        continue;
      }
    }

    if (tpl.hasDst) {
      if (!selectDestination(tpl, instr, ctx, scheduleCycle)) {
        if (attempt++ < MAX_RETRIES) continue;
        ctx.subCycle += 3;
        ctx.cycle = Math.floor(ctx.subCycle / 3);
        attempt = 0;
        continue;
      }
    }
    attempt = 0;

    scheduleCycle = scheduleInstr(tpl, ctx, true);
    if (scheduleCycle < 0) break;
    if (scheduleCycle >= TARGET_CYCLE) break;

    if (tpl.hasDst) {
      const ri = ctx.registers[instr.dst]!;
      const retireCycle = scheduleCycle + tpl.latency;
      ri.latency = retireCycle;
      ri.lastOp = tpl.group;
      ri.lastOpPar = instr.opPar;
      ctx.latency = Math.max(retireCycle, ctx.latency);
    }

    code.push(instr);
    ctx.mulCount += isMul(instr.opcode) ? 1 : 0;
    ctx.subCycle++;
    if (tpl.uop2 !== PORT_NONE) ctx.subCycle++;
    ctx.cycle = Math.floor(ctx.subCycle / 3);
  }

  const ok =
    code.length === REQUIREMENT_SIZE &&
    ctx.mulCount === REQUIREMENT_MUL_COUNT &&
    ctx.latency === REQUIREMENT_LATENCY - 1;
  return ok ? code : null;
}

/** BLAKE2b parameter block salt used by HashX: the ASCII string "HashX v1" padded to 16 bytes. */
const HASHX_SALT = (() => {
  const s = new Uint8Array(16);
  s.set(Buffer.from('HashX v1', 'ascii'));
  return s;
})();

function readState(buf: Buffer, off: number): SiphashState {
  return {
    v0: buf.readBigUInt64LE(off),
    v1: buf.readBigUInt64LE(off + 8),
    v2: buf.readBigUInt64LE(off + 16),
    v3: buf.readBigUInt64LE(off + 24),
  };
}

/**
 * hashx_make — derive a HashX program from a seed.
 *
 * @returns the compiled program, or null if the (rare, <1/10000) seed fails
 *          the uniform-complexity requirement and must be rejected.
 */
export function hashxMake(seed: Buffer | Uint8Array): HashxProgram | null {
  // blake2b(seed) with the HashX parameter block -> 64 bytes = two siphash states.
  const keysBuf = blake2b(seed, { dkLen: 64, salt: HASHX_SALT });
  const key0 = readState(keysBuf, 0);
  const key1 = readState(keysBuf, 32);
  const code = programGenerate(key0);
  if (!code) return null;
  return { code, keys: key1 };
}

function signExtend2sCompl(x: number): bigint {
  // (int64_t)(int32_t)x
  return u64(BigInt.asIntN(32, BigInt(x >>> 0)));
}

/**
 * hashx_exec — run a HashX program over a 64-bit counter input and return the
 * eight output registers already finalized. The Equi-X layer uses the first
 * register pair (`out[0]`) as the 64-bit hash value; the full 32-byte digest
 * is `out[0..3]` little-endian.
 */
export function hashxExecRegisters(program: HashxProgram, input: bigint): bigint[] {
  const r = siphash24CtrState512(program.keys, u64(input));
  const c = (program.compiled ??= compile(program));
  const { ops, dst, src, bigA, bigB, brMask, n } = c;
  const M = MASK64;

  let target = 0;
  let branchEnable = true;
  let result = 0; // uint32 (bit pattern; only wide-mul updates it, per the reference)

  for (let i = 0; i < n; ++i) {
    const d = dst[i]!;
    switch (ops[i]) {
      case Op.UMULH_R: {
        const v = ((r[d]! * r[src[i]!]!) >> 64n) & M;
        r[d] = v;
        result = Number(v & 0xffffffffn);
        break;
      }
      case Op.SMULH_R: {
        const a = BigInt.asIntN(64, r[d]!);
        const b = BigInt.asIntN(64, r[src[i]!]!);
        const v = ((a * b) >> 64n) & M;
        r[d] = v;
        result = Number(v & 0xffffffffn);
        break;
      }
      case Op.MUL_R:
        r[d] = (r[d]! * r[src[i]!]!) & M;
        break;
      case Op.SUB_R:
        r[d] = (r[d]! - r[src[i]!]!) & M;
        break;
      case Op.XOR_R:
        r[d] = r[d]! ^ r[src[i]!]!;
        break;
      case Op.ADD_RS:
        r[d] = (r[d]! + ((r[src[i]!]! << bigA[i]!) & M)) & M;
        break;
      case Op.ROR_C: {
        const x = r[d]!;
        r[d] = ((x >> bigA[i]!) | (x << bigB[i]!)) & M;
        break;
      }
      case Op.ADD_C:
        r[d] = (r[d]! + bigA[i]!) & M;
        break;
      case Op.XOR_C:
        r[d] = r[d]! ^ bigA[i]!;
        break;
      case Op.TARGET:
        target = i;
        break;
      case Op.BRANCH:
        if (branchEnable && (result & brMask[i]!) === 0) {
          i = target;
          branchEnable = false;
        }
        break;
    }
  }

  // Finalization (hashx.c): add keys back in, two SipRounds, xor register pairs.
  const k = program.keys;
  r[0] = u64(r[0]! + k.v0);
  r[1] = u64(r[1]! + k.v1);
  r[6] = u64(r[6]! + k.v2);
  r[7] = u64(r[7]! + k.v3);
  const a = [r[0]!, r[1]!, r[2]!, r[3]!];
  const b = [r[4]!, r[5]!, r[6]!, r[7]!];
  sipround(a);
  sipround(b);
  return [a[0]! ^ b[0]!, a[1]! ^ b[1]!, a[2]! ^ b[2]!, a[3]! ^ b[3]!];
}

/** The 64-bit Equi-X hash value for an index (equivalent to C `load64(hashx_exec(...))`). */
export function hashxExecValue(program: HashxProgram, input: bigint): bigint {
  return hashxExecRegisters(program, input)[0]!;
}

/** The full 32-byte HashX digest (little-endian register pairs), used by the test vectors. */
export function hashxExecDigest(program: HashxProgram, input: bigint): Buffer {
  const out = hashxExecRegisters(program, input);
  const buf = Buffer.alloc(32);
  buf.writeBigUInt64LE(out[0]!, 0);
  buf.writeBigUInt64LE(out[1]!, 8);
  buf.writeBigUInt64LE(out[2]!, 16);
  buf.writeBigUInt64LE(out[3]!, 24);
  return buf;
}
