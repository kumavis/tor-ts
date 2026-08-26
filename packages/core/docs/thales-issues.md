# Thales issue tracker (downstream view)

Bugs and gaps found while building `tor-core`, with their upstream
status. Drafts marked **LIVE** are ready to paste into
<https://github.com/jessealama/thales/issues/new>.

**Last reconciled against upstream `3c71913` (0.7-forthcoming).** Every
status below was re-measured against that build, not inferred from
changelogs — the probes are reproducible per
[`MIGRATION.md`](MIGRATION.md).

GitHub access from the dev sandbox is scoped to `kumavis/tor-ts`, so
filing is manual.

---

## Status

| #      | Subject                                                            | Upstream                                              | Status                                          |
| ------ | ------------------------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------- |
| 1      | Lean reserved keywords as field names                              | [#11](https://github.com/jessealama/thales/issues/11) | ✅ fixed & closed                               |
| 2      | Single-record `type` alias → `Unit`                                | [#13](https://github.com/jessealama/thales/issues/13) | ✅ fixed & closed                               |
| 3      | Object literals → `(unsupported expr)`                             | [#15](https://github.com/jessealama/thales/issues/15) | ✅ **fixed**, issue still open — _ask to close_ |
| 4      | Array stdlib not callable from TS                                  | [#16](https://github.com/jessealama/thales/issues/16) | ⚠️ **partially fixed** — see 15                 |
| 5      | `import`/`export` rejected                                         | [#18](https://github.com/jessealama/thales/issues/18) | ✅ fixed & closed                               |
| 6      | `switch` on `f(x).kind` emits `()`                                 | [#19](https://github.com/jessealama/thales/issues/19) | ✅ fixed & closed                               |
| 7      | Tuple returns emit as `Array`, not `Prod`                          | —                                                     | 🔴 **LIVE**, unfiled                            |
| 8      | Field access on narrowed DU inside a constructor expression        | —                                                     | 🔴 **LIVE**, unfiled                            |
| 9      | `@decreasing` parsed but ignored                                   | —                                                     | 🔴 **LIVE**, unfiled                            |
| 10     | `partial def` emit lacks `deriving Nonempty`                       | —                                                     | 🔴 **LIVE**, unfiled                            |
| 11     | Null-narrowing doesn't survive an early return                     | —                                                     | 🔴 **LIVE**, unfiled                            |
| 12     | `T \| null` helper call double-wrapped in `.some`                  | —                                                     | 🔴 **LIVE**, unfiled                            |
| **13** | **`%` on `bigint` lowers to the Float `jsMod`**                    | —                                                     | 🔴 **LIVE**, new — **file first**               |
| **14** | **Exported DU types cannot be pattern-matched**                    | —                                                     | 🔴 **LIVE**, new — **file first**               |
| **15** | **`subset.md` documents array `.slice`/`.concat`; neither exists** | —                                                     | 🔴 **LIVE**, new (doc + surface)                |

**File 13 and 14 first.** 13 is a regression that blocks the 0.7
migration outright; 14 blocks cross-module composition, which is the
single biggest thing standing between this project and a full verified
cell parser. 15 is lower-stakes but cheap to fix and actively
misleading as written.

---

## 13 — `%` on `bigint` lowers to the Float `jsMod` _(new, regression)_

**Title:** `` `%` on bigint emits `jsMod` (Float → Float → Float), producing uncompilable Lean ``

**Body:**

The remainder operator on two `bigint` operands lowers to `jsMod`, the
ES2023 Float remainder helper in `Thales.TS.Runtime`. Since `bigint`
maps to Lean `Int`, the emitted application is ill-typed and the file
does not compile. This is an accept-then-uncompilable emit hole.

It is a **regression**: the same source compiled under 0.5.

### Minimal repro

```ts
function modBig(x: bigint): bigint {
  return x % 256n;
}

function modNum(x: number): number {
  return x % 256;
}
```

Emitted:

```lean
partial def modBig (x : Int) : Int :=
  (jsMod x 256)              -- ✗ jsMod : Float → Float → Float

partial def modNum (x : Float) : Float :=
  (jsMod x 256.000000)       -- ✓ correct for number
```

Lean:

```
error: Application type mismatch: The argument
  x
has type
  Int
but is expected to have type
  Float
in the application
  jsMod x
```

### Scope

Only `%` is affected. Every other `bigint` operator lowers correctly:

```lean
partial def ops (a : Int) (b : Int) : Int :=
  let add := (a + b)        -- ✓
  let sub := (a - b)        -- ✓
  let mul := (a * b)        -- ✓
  let div := (a / b)        -- ✓
  let mod := (jsMod a b)    -- ✗
  …
```

Comparisons (`<`, `<=`, `>`, `>=`, `===`) also lower correctly.

### Suggested fix

Select the lowering by operand type: emit Lean's `Int` `%` (or
`Int.emod`, whichever matches TS `bigint` semantics — TS `%` truncates
toward zero, i.e. `Int.tmod`) when both operands are `Int`, and reserve
`jsMod` for `Float` operands.

### Workaround

Both TS `bigint /` and Lean `Int./` truncate toward zero, so
`a - (a / b) * b` reproduces TS `%` exactly and compiles.

### Impact

Blocks two `tor-core` modules (`seq32.ts` — wrap-safe 32-bit sequence
arithmetic; `encapsulationPrefix.ts` — Snowflake length-prefix decoding)
that both do bit-field extraction via `%`. Bitwise operators on `bigint`
are not lowered either, so `%`/`/` are the only route to bit
manipulation on `Int`.

---

## 14 — Exported DU types cannot be pattern-matched _(new)_

**Title:** `Exported discriminated-union types cannot be matched: switch is rejected (TH0041/TH9005) and the if/else form emits an uncompilable .kind projection`

**Body:**

A discriminated union that is `export`ed can be constructed and passed
around, but cannot be _destructured_ by any available form. `switch` is
rejected, and the `if (x.kind === '…')` alternative emits an `x.kind`
field projection that Lean has no accessor for (the type lowers to an
`inductive`, which has constructors, not a `.kind` field).

Since ESM landed in #18, sharing a type across modules is the natural
next step — but for DUs, which are the subset's primary modelling tool,
it does not work.

### Repro matrix

Given a recursive DU and a function that dispatches on its
discriminant:

```ts
type L = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: L };
function len(bs: L): bigint {
  switch (bs.kind) {
    case 'nil':
      return 0n;
    case 'cons':
      return 1n + len(bs.tail);
  }
}
```

| variant                                                     | subset check | emit                            | Lean      |
| ----------------------------------------------------------- | ------------ | ------------------------------- | --------- |
| local type, local fn                                        | ok           | ok                              | **ok**    |
| local type, `export function`                               | ok           | ok (type → `private inductive`) | **ok**    |
| `export type`, local fn                                     | **TH0041**   | —                               | —         |
| `export type`, `export function`                            | ok           | **TH9005**                      | —         |
| `export type`, `if (bs.kind === 'nil')` instead of `switch` | ok           | ok                              | **fails** |
| `export type`, never destructured                           | ok           | ok                              | ok        |
| `export interface` + field reads                            | ok           | ok                              | ok        |

The two failure messages:

```
TH0041: Switch not supported here: dispatch on a discriminated-union
field (e.g. `switch (shape.kind)`) with every arm ending in `return`
```

```
TH9005: Internal: the emitter produced unlowerable construct(s)
(switch not lowerable); this is a subset gap — the program was accepted
but cannot be emitted. Please report it.
```

(TH9005's own text asks for this report.)

And for the `if`/`else` variant, which emits but does not compile:

```lean
partial def isNil (bs : L) : Bool :=
  if (bs.kind == "nil") then true else false
```

```
error: Invalid field `kind`: The environment does not contain `G.L.kind`,
so it is not possible to project the field `kind` from an expression
```

### Note on the inconsistency

`export type` + local function fails _earlier_ (TH0041, at subset check)
than `export type` + `export function` (TH9005, at emit). Both should
presumably behave the same way; whichever is correct, the two paths
disagree.

### Suggested fix

Lower a `switch` on an exported DU exactly as for a local one — the
emitted `match` does not depend on the type's visibility. If there is a
real obstacle (e.g. the discriminant metadata is dropped for exported
types), then the `if (x.kind === …)` form needs to lower to a `match`
too, rather than emitting a `.kind` projection that cannot typecheck.

### Impact

This is the blocker for us. `tor-core` has 20 verified modules; four of
them (`bytes`, `cellHeader`, `kcpHeader`, `encapsulationPrefix`) each
redeclare an identical `ByteList` DU plus its primitives, because the
type cannot be shared. Composing them into a full Tor cell parser — the
next substantive verification target — needs one shared byte type.

---

## 7 — Tuple returns emit as `Array`, not `Prod` _(live)_

**Title:** `Tuple-typed function returns emit an Array literal instead of a product`

Re-measured on 0.7: **still broken.**

```ts
function pair(a: bigint, b: bigint): [bigint, bigint] {
  return [a, b];
}
```

The signature translates to `Int × Int`, but the body emits an `Array`
literal, so Lean reports a type mismatch. `subset.md` lists tuples as
in-scope (`[A, B] → Lean × / fixed structures`) with no further
specification; tuple _indexing_ is separately deferred out of 0.7 per
ADR-0002.

Either the value-side lowering should match the signature-side
(`(a, b)` / `Prod.mk`), or tuples should be documented as not yet
delivered.

**Workaround:** return a two-field DU. That is what `tor-core` does
(`SplitResult = { kind: 'ok'; taken; rest } | { kind: 'short' }`), and
it reads better in proofs anyway.

---

## 8 — Field access on a narrowed DU inside a constructor expression _(live)_

**Title:** `Field access on a switch-narrowed DU emits the source projection inside constructor expressions instead of the pattern-bound name`

Re-measured on 0.7: **still broken.**

```ts
type R = { kind: 'ok'; value: bigint } | { kind: 'err' };
function bump(r: R): R {
  switch (r.kind) {
    case 'ok':
      return { kind: 'ok', value: r.value + 1n };
    case 'err':
      return { kind: 'err' };
  }
}
```

```lean
partial def bump (r : R) : R :=
  match r with
    | .ok value => (.ok ((r.value + 1)))   -- ← uses `r.value`, not `value`
    | .err => .err
```

```
error: Invalid field `value`: The environment does not contain `I8.R.value`
```

The `match` branch already binds `value`; the body just needs to use it.
The same access in arithmetic or direct-return position emits correctly
— it is specifically the constructor-expression context.

**Workaround:** bind to a local first.

```ts
case 'ok': {
  const v = r.value;
  return { kind: 'ok', value: v + 1n };
}
```

This is mechanical but pervasive — every `tor-core` state machine and
parser carries it.

---

## 12 — `T | null` helper call double-wrapped in `.some` _(live)_

**Title:** `Returning the result of a nullable-union-returning helper wraps it in an extra .some`

Re-measured on 0.7: **still broken.**

```ts
type A = { kind: 'none' } | { kind: 'some'; value: bigint };
function unwrap(a: A): bigint | null { … }
function top(a: A): bigint | null { return unwrap(a); }
```

`top` emits `(.some (unwrap a))` — `Option (Option Int)` where
`Option Int` was intended. Lean reports an application type mismatch.

The `.some` lift is only needed when raising `T` to `Option T`; a call
already returning `Option T` should pass through.

**Workaround:** expose the DU to the caller and unwrap at the seam
instead of composing two nullable-returning functions
(`versionNegotiation.ts` does this).

---

## 11 — Null-narrowing doesn't survive an early return _(live)_

**Title:** `Post-if control-flow narrowing is not applied to Option-typed bindings`

Still the case on 0.7, and now documented as such upstream
("post-`if` control-flow narrowing is not implemented"), so this may be
a known limitation rather than a bug. Filing is still worthwhile because
`tsc --strict` accepts the same source, which puts it against the
conformance contract ("every program Thales accepts is also accepted by
`tsc --strict`" — this is the converse direction, but the asymmetry is
surprising).

```ts
function updateMax(current: bigint | null, c: bigint): bigint {
  if (current === null) return c;
  if (current >= c) return current; // ✗ TS2322: bigint | null
  return c;
}
```

**Workaround:** a `{ kind: 'none' } | { kind: 'some'; value: T }`
accumulator DU and a `switch`.

---

## 9 — `@decreasing` parsed but ignored _(live)_

**Title:** `@decreasing has no effect on emit; docs disagree on whether it is implemented`

The annotation is accepted but no `termination_by` / `decreasing_by` is
emitted and the function still comes out `partial def`.

The docs contradict each other: `subset.md` TH0050 instructs you to add
`@decreasing` and shows an example; `errors.md` TH0050 lists it as
future work. One of the two should be corrected.

**Partly mitigated at 0.7:** the canonical `for (let i = 0; i < B; i++)`
shape _is_ `@total`-friendly, so bounded numeric iteration now has a
supported route that does not need `@decreasing`. That lowers the
priority of this one considerably.

---

## 10 — `partial def` emit lacks `deriving Nonempty` _(live)_

**Title:** `partial def returning a user-defined inductive fails Lean's nonempty check`

Emitted inductives carry `deriving Repr` only. Lean requires the return
type of a `partial def` to be `Nonempty`, and cannot infer it without a
derived instance, so a `partial def` returning a user inductive fails to
compile:

```
failed to compile 'partial' definition `M.f`, could not prove that the
type Int → T is nonempty
```

Lean's own error text suggests the fix: add `Nonempty` to the `deriving`
clause. It can be derived automatically for any inductive with at least
one constructor, and Thales already rejects empty DUs at the subset
level.

**Not currently hit by `tor-core`** — nothing in core recurses
numerically into a DU return — but it is a one-line emitter change that
removes a whole failure class.

---

## Housekeeping

- **#15 and #16 are fixed but still open upstream.** Object literals on
  `interface` types now emit and compile; the array stdlib is genuinely
  callable (`map`/`filter`/`reduce`/`concat`/`slice`/`length`, plus a
  conditionally-lowered tier governed by TH0085). Worth commenting on
  both so they can be closed.
- **Crypto FFI is a feature request we have not yet made.** Calling
  SHA-3 / SHAKE256 / Curve25519 / Ed25519 from verified code needs
  Lean-side `extern` declarations the runtime does not supply. This
  gates the most security-critical code in `tor-ts` (`ntor`,
  consensus-signature verification, hs-ntor). Worth opening as a
  discussion rather than a bug.

---

## 15 — `subset.md` documents array `.slice`/`.concat`; neither exists _(new)_

**Title:** `docs/subset.md` lists array `.slice` and `.concat` as supported, but they are not in the array builtin table

**Body:**

`docs/subset.md` advertises `.slice` and `.concat` on arrays in three
places, but neither method is present on any array type. They are
`string`-only. The result is that documented, load-bearing advice cannot
be followed.

### Where the docs promise them

1. The **Stdlib** row of the subset table:

   > `Option<T>`, `Result<T, E>`, array `.map`/`.filter`/`.reduce`/`.concat`/`.length`/`.slice`

2. **TH0002**'s own remedy text — the diagnostic tells you to use a
   method that does not exist:

   > ### TH0002 — Cannot assign to array element; use `.concat` or return a new array

3. The `@total` section, which discusses `xs.slice(1)` on arrays as a
   _termination_ failure — implying it type-checks and reaches the
   termination checker at all:

   > `xs.slice(1)` on arrays: Lean cannot prove the sliced array is smaller. Lean rejects.

### Minimal repro

```ts
function dropN(a: number[], n: number): number[] {
  return a.slice(n);
}

function glue(a: number[], b: number[]): number[] {
  return a.concat(b);
}
```

```
error TS2339: Property 'slice' does not exist on type 'number[]'
error TS2339: Property 'concat' does not exist on type 'number[]'
```

Identical for `bigint[]`, `string[]`, and `boolean[]` — this is not
element-type-specific.

### Root cause

`Thales/TypeCheck/Builtins.lean` has one `match` arm per supported array
method. As of `3c71913` the arms are:

```
length, forEach, map, filter, reduce,
join, indexOf, includes, lastIndexOf, some, every, findIndex
```

There is no `slice` arm and no `concat` arm. Both names _are_ handled a
few lines earlier for `string` receivers, which is presumably where the
doc claim came from.

### Impact

Without `slice`/`concat` there is no way to take a prefix of an array
and keep the remainder, so arrays cannot express the split-and-continue
shape every incremental parser needs. Downstream (`tor-core`) this was
the deciding factor in keeping a hand-rolled cons-cell list as the byte
buffer representation rather than moving to `Byte[]`, even though arrays
would otherwise have been preferable — they are not discriminated
unions, so unlike our DUs they can be shared across modules despite #14.

### Suggested fix

Either implement the two arms, or correct all three doc sites. If they
are deferred rather than dropped, the Stdlib row saying so explicitly
would be enough — the current text reads as a present-tense guarantee,
and TH0002's remedy needs rewording regardless.
