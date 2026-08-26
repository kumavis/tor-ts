# `tor-core` patterns

Conventions and recipes for adding to the verified core.

**Target: Thales 0.7-forthcoming (`3c71913`), Lean 4.33.0.** This file
was rewritten for 0.7; most of the 0.5-era workarounds it used to
document are obsolete because upstream fixed them. Where a rule is a
workaround for a _current_ limitation, the finding is cited from
[`MIGRATION.md`](MIGRATION.md) or the draft in
[`thales-issues.md`](thales-issues.md).

---

## The two rules that shape everything

Most of the house style falls out of these:

1. **A discriminated union you pattern-match on must stay module-local.**
   Exporting it breaks matching in both available forms (MIGRATION F3).
   You may `export` the _functions_; the type becomes a `private
inductive` in the emitted Lean, which is fine.
2. **Don't use `%` on `bigint`.** It lowers to the Float `jsMod` and
   produces uncompilable Lean (MIGRATION F2). Use the `truncMod` helper
   pattern below.

Everything else is either ordinary Thales-subset discipline or a
now-lifted restriction you no longer have to think about.

---

## File layout

```
src/<camelCase>.ts          ← Thales subset, also valid TS
Generated/<PascalCase>.lean ← emitted by Thales (gitignored)
Spec/<PascalCase>.lean      ← hand-written theorems
```

Thales pascalises the source basename (`exitPolicy.ts` →
`ExitPolicy.lean`). Mirror that when naming the `Spec/` file.

`Spec/<X>.lean` boilerplate:

```lean
import Generated.<X>
import Thales.TS.Runtime
open Thales.TS

namespace Spec.<X>
open _root_.<X>   -- `_root_` required; bare `open <X>` collides with
                  -- the enclosing `Spec.<X>` namespace

deriving instance DecidableEq for <EachEmittedType>
```

Thales emits inductives with `deriving Repr` only. Add `DecidableEq`
yourself for any type that appears in a `decide`-closed equality or in a
`cases h : … with` over its constructors.

---

## Types

### Discriminated unions for anything you match on — and keep them local

The DU + `switch (x.kind)` shape is still the workhorse, and it is the
_only_ shape whose Lean output we can reason about comfortably. But as
of 0.7 the type must not be exported:

```ts
// ✓ local type, exported functions — the type becomes `private
//   inductive` in Lean and the functions are importable
type ByteList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: ByteList };

export function byteListLength(bs: ByteList): bigint { … }
```

```ts
// ✗ TH0041 (subset check) or TH9005 (emit) — see MIGRATION F3
export type ByteList = { kind: 'nil' } | { kind: 'cons'; … };
function byteListLength(bs: ByteList): bigint {
  switch (bs.kind) { … }
}
```

The consequence: a DU that several modules need still has to be
**redeclared per module**, with a `// Mirrored from <file> — keep in
sync` header. That is what `cellHeader.ts`, `kcpHeader.ts`, and
`encapsulationPrefix.ts` do for `ByteList`. It is annoying and it is
tracked — when F3 lands upstream, those duplicates collapse.

`export interface` **does** work, including field reads, so
non-matched record types can be shared.

### `bigint` for wire integers

`number` → Lean `Float`; `bigint` → Lean `Int`. Bit-exact wire
arithmetic over `Float` is wrong. Use `bigint` for every wire integer
field, byte value, sequence number, length, and code point. The TS-side
seam adapter does `BigInt(x)` at the boundary.

### Consider `Byte` / `Natural` for range-carrying values

New in 0.6: `@thales/prelude` exports `Integer`, `Natural`, `Byte`
(`0..255`), and `Bit`, as compile-time-enforced refinements of `number`
(chain `Bit ⊆ Byte ⊆ Natural ⊆ Integer ⊆ number`). Evidence to enter a
refinement comes from a guard (`isByte(x)`), a throwing constructor
(`asByte(x)`), or an in-range literal.

**Do not reach for these on wire values.** Our `ByteList` carries "each
element is a `bigint` in `[0, 256)`" as a _comment_, and `Byte` would
make it a type — but the refinements are `Float` subtypes
(`Byte := { x : Float // isByte x = true }`), so adopting one moves the
value off `Int`, and `omega` does not apply to `Float` at all. Every
arithmetic theorem in `Spec/` is `Int` + `omega`. Arithmetic also widens
back to `number`, so each operation needs re-narrowing via a guard or
constructor.

That is a TS-side correctness gain paid for with a Lean-side proof
collapse, and the Lean side is the whole point. Measured and rejected —
see [`MIGRATION.md` F5](MIGRATION.md).

They remain reasonable for values that never enter a proof.

### Tuples: still avoid

`[A, B]` is nominally in the subset and maps to `Prod`, but tuple
_indexing_ is explicitly deferred out of 0.7 and the docs specify
nothing else about them. Keep using a result DU:

```ts
type SplitResult = { kind: 'ok'; taken: ByteList; rest: ByteList } | { kind: 'short' };
```

This also reads better in proofs — theorems mention `.ok` / `.short`
rather than "the first component".

---

## Functions

### `switch` on a parameter; one lowerable shape (TH0041)

Exactly one `switch` shape lowers: a non-computed `ident.field`
scrutinee resolving to a discriminated union keyed on that field, with
**every** arm — including any `default` — returning on every path.

```ts
// ✓
switch (state.kind) {
  case 'open': return …;
  case 'closed': return …;
}
```

Rejected: plain-identifier scrutinee (`switch (s)` on a string),
non-union scrutinee, switch on a non-discriminator field, and any arm
that falls through via `break` or an empty grouped `case`.

Spell out one `return` per case; don't group labels.

Dispatching on a _computed_ DU (`switch (f(x).kind)`) was broken at 0.5
and is fixed — but prefer a helper taking the value as a parameter
anyway, since it reads better and keeps the emitted `match` flat.

### Declare before use (TH0105)

tsc lets a function call one declared below it. Thales does not — the
emitted Lean is in source order. **Order top-level declarations
declare-before-use.** Inside a class, the same rule applies to methods
(TH0101).

### Conditions must be `boolean` (TH0026)

Every condition position — `if`, `while`, `do`/`while`, `for` test,
ternary — **and the operands of `!`, `&&`, `||`** must be `boolean`.

```ts
if (n) …            // ✗ TH0026
if (n !== 0n) …     // ✓
s || 'fallback'     // ✗ TH0026
s !== '' ? s : 'fallback'  // ✓
x ?? y              // ✓ (Option handling, not truthiness)
```

### No `typeof` / `void` / `delete` (TH0092)

Anywhere, including in guards. Use discriminated unions.

### No shadowing declarations (TH0032)

An inner `const n` shadowing an outer `n` inside the same function is
rejected — the emitter flattens blocks, so the shadow would capture
outer references. Nested function/arrow params and `catch` params are
fine (genuinely fresh scopes).

### Local mutation is fine now

Since upstream #24, a binding whose every reference stays inside the
declaring function may be reassigned; the function lowers to `Id.run do`
with `let mut`. Parameters count as locals.

Still rejected (TH0001): module-level reassignment; `&&=`/`||=`/`??=`;
reassigning a `let` with no initializer; reassigning a variable whose
narrowing the emitter relies on; mutation inside arrow/function-expression
bodies (only _declared_ functions take the do-mode path); mutation in a
function containing `try`/`catch` or an unlowerable `switch`.

Also: TH0006 — assignment only in statement position (`return n++` is
out; write `n++; return n - 1;`). TH0005 — a binding is mutable only if
no nested function even _mentions_ it.

### Loops are fine now — mind `@total` (TH0068)

Admitted inside do-mode-lowerable declared functions:

- **`for-of`** over an array identifier or literal; loop var is a simple
  `const`/`let` identifier, not reassigned in the body. Lowers to
  `for x in xs do`.
- **Canonical `for`** — exactly `for (let i = 0; i < B; i++)` where `B`
  is a non-negative integer literal or `arr.length` for an array-typed
  binding. Lowers to `for i in [0:B] do`. **`@total`-friendly.**
- **`while` / `do-while`** — any boolean test. Backed by a partial
  combinator, so **mutually exclusive with `@total`** (TH0068).

Module-level loops are still TH0010, as are loops in class
constructors/methods.

For `@total` code, **prefer structural recursion over loops** — and not
just for termination. A loop lowers into `Id.run do` with `let mut`, and
the canonical `for` additionally shims its index to `Float`
(`let i : Float := i.toFloat`). Neither is reachable by `omega`, and
without Mathlib there is no loop-invariant machinery to fall back on. A
loop that Lean accepts as terminating can still be a function you cannot
prove anything about. See `src/byteEncode.ts` for the escape hatch when
the thing you are recursing on is a count rather than a structure.

### Arrays are usable now — but you cannot split one

`map`, `filter`, `reduce`, `forEach`, `length` are in the subset.
`join`, `indexOf`, `includes`, `lastIndexOf`, `some`, `every`,
`findIndex` lower **only** when the receiver is an identifier the
emitter statically resolves to `number[]` or `string[]` (TH0085) — a
call result or a `boolean[]` receiver is rejected.

**`slice` and `concat` do not exist on arrays**, on any element type,
despite `subset.md` listing both. Verified against the builtin table;
see [issue 15](thales-issues.md). So there is no array `trySplit` — no
way to take a prefix and keep the remainder — which is why core's byte
buffers are a cons-cell DU and not `Byte[]`
([`MIGRATION.md` F5](MIGRATION.md)).

Arrays do have one property our DUs lack: **an exported array-typed
alias can be imported and used**, including `.length` and indexing, so
arrays sidestep the exported-DU gap entirely. Worth remembering for a
type that is never pattern-matched.

`arr[i]` is `T | undefined` (TH0083 for non-array bracket access). Bind
then narrow:

```ts
const hit = xs[i];
if (hit !== undefined) {
  /* hit : T */
}
```

Using a possibly-undefined value in arithmetic or a comparison is
TH0082; equality is exempt because that's the narrowing primitive.

Mutating methods remain TH0004 and `arr[i] = v` remains TH0002.

### Strings are still nearly unusable

`length`, `startsWith`, `endsWith`, `split` — and nothing else
(TH0087). No `indexOf`, `slice`, `charCodeAt`, `trim`, `toLowerCase`,
`replace`. `parseFloat` exists in the runtime; **`parseInt` and
`Number()` do not**. `s[0]` is TH0083.

`split` alone covers a surprising amount of simple list parsing — but
check the method surface before planning any parser.

### Nullable narrowing

`T | null` / `T | undefined` → `Option T`. Working narrowing is an
explicit equality guard on a **variable**:

```ts
if (x === null) { … } else { /* x : T */ }
```

Not working:

- truthiness (`if (x)`) — does not narrow, and is TH0026 anyway;
- **post-`if` control-flow narrowing** — after `if (x === null) return;`
  the checker still sees `Option T`. This is why accumulator helpers use
  a `{ kind: 'none' } | { kind: 'some'; value: T }` DU instead of
  `T | null` (see `versionNegotiation.ts`);
- a definedness test whose subject is a call or member access (TH0086) —
  bind it to a variable first;
- a definedness test on an unannotated local whose type the emitter
  can't record (TH0084) — annotate it.

`const u = undefined;` needs an annotation (TH0104), and `undefined` may
not be used as a binding name (TH0103).

### `bigint` modulo: use `truncMod`

`%` on `bigint` is broken (MIGRATION F2). Both TS `bigint /` and Lean
`Int./` truncate toward zero, so:

```ts
/** Truncated remainder. Replaces `a % b`, which Thales 0.7 lowers to
    the Float `jsMod` and cannot compile for `bigint`. */
/** @total */
function truncMod(a: bigint, b: bigint): bigint {
  return a - (a / b) * b;
}
```

Give it a `Spec` theorem pinning it to the mathematical remainder so the
workaround is itself verified, then call it everywhere `%` was wanted.

### Classes: available, rarely what you want

Immutable class declarations lower to a Lean `structure` plus a
`namespace` of receiver-first functions. The shape is narrow: no
`extends`/generics/`abstract`/`implements`; every field `readonly x: T`
with no initializer; exactly one constructor whose body is only
`this.f = …` assignments; methods must be public, non-static, annotated,
and may only reference methods declared earlier; **no loops in
constructors or methods**; a method may never be read as a value
(TH0102, checked name-wise across the whole program).

For core's purposes a DU plus free functions is almost always the better
fit. Classes matter mainly if we ever mirror a `tor-ts` class API shape
directly.

---

## Recursion and `@total`

Default emission is `partial def` — accepted without a termination
proof. `@total` opts into Lean's checker and emits a plain `def`.

- **Structural recursion over a DU** is the reliable `@total` shape.
- **A counter argument alongside a structural one** is fine —
  `f(state, list.tail, n - 1n)` is accepted because `list.tail` is
  structurally smaller.
- **Numeric-only recursion** (`f(n - 1n)`) is _not_ `@total`-provable;
  Lean sees no structural decrease. It is fine as a `partial def`.
- **No `termination_by` / `decreasing_by` is emitted**, and `@decreasing`
  is documented inconsistently upstream — treat it as not working until
  measured.

`@total` also forbids `@throws` (TH0066), uncaught throws (TH0067), and
`while`/`do-while` (TH0068).

### Recursing on a count: make the count a unary DU

The rule above says numeric-only recursion is not `@total`-provable.
The canonical `for` loop is the obvious escape, but it buys termination
at the cost of provability (see "Loops"). There is a better move when
the count is small and known: **turn the number into a structure.**

```ts
type Width = { kind: 'zero' } | { kind: 'succ'; pred: Width };
```

Recursion on `Width` is structural, so Lean's checker takes it and the
function emits as a plain `def`. In Lean you get an induction principle
for free, which is exactly what a round-trip proof wants:

```ts
/** @total */
function encodeUintLE(value: bigint, w: Width): ByteList {
  switch (w.kind) {
    case 'zero':
      return { kind: 'nil' };
    case 'succ': {
      const pred = w.pred;
      const lo = truncMod(value, 256n);
      const hi = value / 256n;
      return { kind: 'cons', head: lo, tail: encodeUintLE(hi, pred) };
    }
  }
}
```

Pair it with a `widthValue(w): bigint` so theorems can talk about the
count, and expose named constructors (`width1()`, `width2()`, `width4()`)
so callers never build one by hand. Unary is only viable for genuinely
small counts — Tor's field widths are 1, 2 and 4 bytes, so it costs
nothing. This is what unblocked `byteEncode.ts` after the note at the
bottom of `bytes.ts` had written the encoders off as unreachable.

---

## Spec / Lean recipes

Lean 4.33, with `batteries` and `Regex` via Thales. **Mathlib is not a
dependency** — pulling it in would balloon CI.

| want                     | have                                                                                                                | don't have             |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| linear arithmetic        | `omega`                                                                                                             | `linarith`, `polyrith` |
| polynomial equality      | (manual / `omega`)                                                                                                  | `ring`, `ring_nf`      |
| split an `if`            | `by_cases h : …` + `if_pos`/`if_neg`                                                                                | `split_ifs`            |
| finite `Int` range split | `rcases` over an `omega`-derived disjunction                                                                        | `interval_cases`       |
| the rest                 | `simp`, `simp only`, `rw`, `unfold`, `apply`, `intro`, `cases`, `induction`, `obtain`, `injection`, `rfl`, `decide` |                        |

Finite case split over an `Int` range:

```lean
have henum : c = 1 ∨ c = 2 ∨ c = 3 := by omega
rcases henum with h | h | h <;> subst h <;> decide
```

Splitting an `if`:

```lean
by_cases h : 0 ≤ x
· rw [if_pos h]; …
· rw [if_neg h]; …
```

**`decide` needs closed terms.** With a free variable in the goal, use
`rfl` when the definition reduces regardless:

```lean
theorem isClosed_closed (r : Int) : isClosed (.closed r) = true := rfl
```

**Emitted constants are `def`s, not literals.** Name them in the simp
set when unfolding: `simp [step, stepFromOpen, REASON_PROTOCOL_ERROR]`.

**Generalize the accumulator** when inducting over a fold:
`induction xs generalizing acc with …`.

---

## Adding a module

1. Pick one conceptual unit (a DU + its functions, a state machine, a
   related arithmetic family).
2. Write `src/<name>.ts` following the rules above.
3. `bash scripts/verify.sh` — transpiles and Lean-builds everything.
4. If Thales rejects, check [`thales-issues.md`](thales-issues.md) for a
   known workaround. If it's new, **add a draft there** — that file is
   the record.
5. Write `Spec/<Name>.lean`: concrete values and unfolding lemmas first,
   then invariants and round-trips.
6. `bash scripts/verify.sh` again — `lake build` gates on every theorem.
7. `npx prettier --write src/<name>.ts`.
8. Update the module table in `README.md`.
9. Commit.

---

## Still out of reach

- **Sharing a matched DU across modules** — MIGRATION F3. The single
  highest-leverage upstream fix for this project; it unblocks the full
  cell parser.
- **`async`/`await`** (TH0012) — and always will be. This is what the
  seam architecture exists for.
- **Most string methods** (TH0087), `parseInt`, `Number()`.
- **Crypto primitives** — calling SHA-3 / SHAKE / Curve25519 from
  verified code needs Lean-side `extern` declarations the Thales runtime
  does not supply.
- **`deriving Nonempty`** on emitted inductives — still absent, so a
  `partial def` returning a user inductive can still fail Lean's
  nonempty check. Not currently hit, because nothing in core recurses
  numerically into a DU return.

Don't work around these one module at a time — file upstream and move on.
