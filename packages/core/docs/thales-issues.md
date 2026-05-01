# Thales issue drafts

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a` (current
tip as of filing). None of these duplicate any of the 10 existing issues
(#1 closed, #2–#10 are 0.6 refinement-types milestones). Issues 1, 2, 3,
6, 7, and 8 are silent emit failures (input accepted, output broken).
Issue 4 is a visible TS error (the documented runtime stdlib isn't
actually callable from TS). Issue 5 is the export/import gap that
gates downstream adoption.

GitHub MCP access in this environment is scoped to `kumavis/tor-ts`, so
these drafts are intended to be copy-pasted into
<https://github.com/jessealama/thales/issues/new>.

---

## Issue 1: Lean reserved keywords as field names emit silently broken Lean

**Title:** `Lean reserved keywords used as TS field names produce uncompilable Lean (no escaping at emit time)`

**Body:**

Thales (latest `main`, `31f3004`) accepts TypeScript field names that are
Lean 4 reserved keywords and emits them verbatim into `structure` /
`inductive` declarations. The emitted Lean then fails to compile.

### Minimal repro

```ts
interface PortRange {
  start: bigint;
  end: bigint;
}

function portInRange(port: bigint, range: PortRange): boolean {
  return range.start <= port && port <= range.end;
}
```

```bash
$ thales --overwrite -o out repro.ts
emitted: out/Repro.lean
```

Emitted:

```lean
structure PortRange where
  start : Int
  end : Int        -- ← Lean keyword
  deriving Repr, BEq

partial def portInRange (port : Int) (range : PortRange) : Bool :=
  ((range.start <= port) && (port <= range.end))
```

Lean output:

```
error: Repro.lean:11:2: Missing name after `end`: Expected the current scope name `Repro`
error: Repro.lean:11:6: unexpected token ':'; expected command
error: Repro.lean:12:10: unexpected identifier; expected 'instance'
error: Repro.lean:15:43: Invalid field `end`: The environment does not contain `Repro.PortRange.end`
```

### Scope

I tested 14 Lean keywords as field names. **11** are accepted by Thales and
silently produce uncompilable Lean:

| keyword | thales | Lean compile |
|---|---|---|
| `match` | accepts | rejects |
| `where` | accepts | rejects |
| `mut` | accepts | rejects |
| `fun` | accepts | rejects |
| `structure` | accepts | rejects |
| `inductive` | accepts | rejects |
| `theorem` | accepts | rejects |
| `section` | accepts | rejects |
| `namespace` | accepts | rejects |
| `then` | accepts | rejects |
| `end` | accepts | rejects |
| `do` | rejected at parse (TS) | — |
| `let` | rejected at parse (TS) | — |
| `if` / `else` | rejected at parse (TS) | — |

### Suggested fix

At emit time, wrap any field identifier that collides with a Lean keyword in
French quotes (`«end»`) or otherwise escape it. The fix needs to apply to:

- `structure` field names
- `inductive` constructor field labels
- Field-projection expressions (`range.end` → `range.«end»`)

### Why this is bad

Failures are silent at the Thales layer — there's no `TH####` diagnostic;
the TS subset check passes; the emitter writes the file; only `lake build`
catches it. A user who only runs `thales --no-emit` would think their code
verifies.

---

## Issue 2: Single-record `type X = { … }` aliases emit as `abbrev X := Unit`

**Title:** `Single-record type aliases collapse to Unit (only interface declarations emit struct definitions)`

**Body:**

Single-record `type` aliases are emitted as `abbrev X := Unit`, which
makes any `.field` projection on values of that type fail to compile.
The published subset doc lists both `interface declarations and type
aliases with nominal typing by declaration` as supported, so the two
should be interchangeable.

### Minimal repro

```ts
type PortRange = { start: bigint; endPort: bigint };

function portInRange(port: bigint, range: PortRange): boolean {
  return range.start <= port && port <= range.endPort;
}
```

Emitted:

```lean
abbrev PortRange := Unit

partial def portInRange (port : Int) (range : PortRange) : Bool :=
  ((range.start <= port) && (port <= range.endPort))
```

Lean rejects:

```
error: Invalid field `start`: The environment does not contain `PUnit.start`
error: Invalid field `endPort`: The environment does not contain `PUnit.endPort`
```

### Scope

Tested three forms in one file:

| form | emits | works |
|---|---|---|
| `type T = { x; y }`              (single record) | `abbrev T := Unit` | **broken** |
| `interface T { x; y }`           (single record) | `structure T where x ; y` | works |
| `type T = {kind:'a';x} \| {kind:'b';y}`  (DU) | `inductive T where ...` | works |

So the bug is specifically for single-record `type` aliases — DU `type`
aliases emit correctly. Easiest workaround for users today is to use
`interface` instead.

### README impact

The headline "quick taste" in `README.md` uses a single-record
`type` alias as its very first example:

```ts
type User = { name: string; age: number };
```

Combined with issue 3 (object literals), this entire example fails to
compile end-to-end on `main`.

### Suggested fix

The emitter path that handles `interface T { … }` should also handle
`type T = { … };`. They have the same surface semantics in TS.

---

## Issue 3: Object-literal expressions emit as the literal string `(unsupported expr)`

**Title:** `Object literals for interface/single-record types emit "(unsupported expr)"; the README's quick-taste example doesn't compile`

**Body:**

Constructing a value of an `interface`-typed (or single-record
`type`-aliased) record with an object literal `{ ... }` emits the literal
string `(unsupported expr)` into the Lean output, which Lean then rejects.
This breaks the function in the README's headline example.

### Minimal repro

```ts
interface Pair { x: bigint; y: bigint }

function makePairLong(x: bigint, y: bigint): Pair {
  return { x: x, y: y };
}

function makePairShort(x: bigint, y: bigint): Pair {
  return { x, y };
}
```

Emitted:

```lean
structure Pair where
  x : Int
  y : Int

partial def makePairLong (x : Int) (y : Int) : Pair :=
  (unsupported expr)

partial def makePairShort (x : Int) (y : Int) : Pair :=
  (unsupported expr)
```

Lean rejects with `unknown identifier 'unsupported'`.

### Scope

I exercised several expression forms to localize the bug:

| expression | emits |
|---|---|
| `42n`                                      | `42` (works) |
| `"hello"`                                  | `"hello"` (works) |
| `a + b`                                    | `(a + b)` (works) |
| `p` (identifier)                           | `p` (works) |
| `{ x, y }`                **interface**    | `(unsupported expr)` |
| `{ x: x, y: y }`          **interface**    | `(unsupported expr)` |
| `{ kind: 'some', value: v }` **DU**        | `(.some v)` (works) |
| `{ kind: 'none' }`        **DU**           | `.none` (works) |
| `{ kind: 'cons', head, tail }` **DU**      | `(.cons head tail)` (works) |

So discriminated-union construction works (it's lowered to constructor
application), but constructing an `interface` (or single-record `type`)
value via an object literal does not. This means `interface` types can be
**consumed** but not **constructed** inside Thales — every helper that
builds a record has to be moved into the impure shell.

### README example

The function `makeUser` from the README's "quick taste" tries to build a
`User` with `{ name, age }`. Combined with issue 2, the whole example
emits broken Lean:

```ts
type User = { name: string; age: number };
function makeUser(name: string, age: number): User {
  if (age < 0) throw new RangeError('age must be non-negative');
  return { name, age };
}
```

emits

```lean
abbrev User := Unit

partial def makeUser (name : String) (age : Float) : (Except RangeError User) :=
  if (age < 0.000000) then (.error ((Thales.TS.RangeError.mk "age must be non-negative")))
                      else (.ok (unsupported expr))
```

### Suggested fix

The emitter should lower `{ a: x, b: y }` of `interface T { a; b }` to
`{ T. a := x, b := y : T }` or `T.mk x y`, matching how it currently
lowers DU constructors via the `kind` discriminator.

### Why this is bad

Like issue 1, this is silent at the Thales layer: the file emits, no
`TH####` diagnostic is reported. Only `lake build` catches it.

---

## Issue 4: Array combinators in `runtime.md` aren't actually callable from TS

**Title:** `Documented array stdlib (.map/.filter/.reduce/.concat/.slice) is in the Lean runtime but not declared in the TS prelude or lowered by the emitter`

**Body:**

`docs/runtime.md` and `docs/subset.md` advertise array combinators as part
of the standard library. The Lean-side runtime in
`Thales/TS/Runtime.lean` (lines 143–154) provides them under
`Thales.TS.ArrayOps`. But `Thales/TS/Prelude.d.ts` doesn't declare them on
the `T[]` surface, so `tsc` rejects every call site, and the emitter has
no path to lower `arr.reduce(...)` to `Thales.TS.ArrayOps.reduce arr ...`.

### Minimal repro

```ts
function len(xs: bigint[]): bigint { return BigInt(xs.length); }
function elem(xs: bigint[]): bigint | undefined { return xs[0]; }
function mapDouble(xs: bigint[]): bigint[] { return xs.map(x => x + x); }
function filterPos(xs: bigint[]): bigint[] { return xs.filter(x => x > 0n); }
function sumAll(xs: bigint[]): bigint { return xs.reduce((acc, x) => acc + x, 0n); }
function concat(a: bigint[], b: bigint[]): bigint[] { return a.concat(b); }
function head3(xs: bigint[]): bigint[] { return xs.slice(0, 3); }
```

```
$ thales --no-emit array.ts
array.ts(1,45): error TS2304: Cannot find name 'BigInt'
array.ts(3,53): error TS2339: Property 'map' does not exist on type 'bigint[]'
array.ts(4,53): error TS2339: Property 'filter' does not exist on type 'bigint[]'
array.ts(5,48): error TS2339: Property 'reduce' does not exist on type 'bigint[]'
array.ts(6,62): error TS2339: Property 'concat' does not exist on type 'bigint[]'
array.ts(7,49): error TS2339: Property 'slice' does not exist on type 'bigint[]'
```

`xs.length` and `xs[0]` work; the iteration combinators don't.

### Doc references

`docs/subset.md` (subset doc, "Standard Library" section):

> Standard Library: `Option<T>`, `Result<T, E>`, array methods (`.map`,
> `.filter`, `.reduce`, `.concat`, `.length`, `.slice`)

`docs/runtime.md` (lines 116–126):

> Array methods live in `Thales.TS.ArrayOps` and are referenced by the
> emitter via their qualified names:
> ```
> ArrayOps.map    : Array α → (α → β) → Array β
> ArrayOps.filter : Array α → (α → Bool) → Array α
> ArrayOps.reduce : Array α → β → (β → α → β) → β
> ArrayOps.concat : Array α → Array α → Array α
> ArrayOps.length : Array α → Nat
> ArrayOps.slice  : Array α → Nat → Nat → Array α
> ```

`Thales/TS/Prelude.d.ts` itself acknowledges the gap (line 3):

> // intentionally minimal: the full standard library is v6+

### Suggested fix

Either:
1. Implement the surface — declare the methods in `Prelude.d.ts` and add
   emitter cases that lower `xs.method(...)` to
   `Thales.TS.ArrayOps.method xs ...`.
2. Or update the docs to reflect what 0.5 actually ships, e.g. tag the
   "Standard Library" line in `subset.md` with `(planned for v0.6+)` and
   add a "What 0.5 actually exposes" subsection.

### Practical impact

Without these methods, any code that needs to iterate over a sequence has
to model the sequence as a discriminated-union cons-cell list
(`{ kind: 'nil' } | { kind: 'cons'; head; tail }`) and recurse with
`switch`. That works fine — it's the `total-recursion.ts` example pattern
— but it forces a TS `T[]` ↔ `TList` conversion at the seam between
verified and impure code.

---

## Issue 5: `import` and `export` declarations rejected by the parser

**Title:** `Parser rejects \`import\` and \`export\` declarations even though subset.md lists them as supported (no multi-file Thales modules possible)`

**Body:**

`docs/subset.md` lists `Modules: import/export of values and types` under
"Allowed Features", but every form of `import` and `export` I've tried is
rejected at parse time. This forces every verified module to be a single
self-contained file, which is fine for proofs but makes composition
impossible: a downstream module that wants to reuse a type or function
from a verified neighbor has no way to pull it in.

### Minimal repro

`a.ts`:
```ts
export interface Foo { x: bigint }

export function makeFoo(x: bigint): Foo {
  return { x };
}
```

`b.ts`:
```ts
import { makeFoo } from './a';

function useFoo(): bigint {
  return makeFoo(42n).x;
}
```

```
$ thales --no-emit a.ts
a.ts(1,1): error TS2304: Cannot find name 'export'
a.ts(3,1): error TS2304: Cannot find name 'export'

$ thales --no-emit b.ts
b.ts(4,10): error TS2304: Cannot find name 'makeFoo'
```

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a`.

### Forms tested (all rejected)

| form | result |
|---|---|
| `export function f() {…}`           | `TS2304: Cannot find name 'export'` |
| `export type T = …;`                | `TS2304: Cannot find name 'export'` |
| `export interface I {…}`            | `TS2304: Cannot find name 'export'` |
| `export { f };` (trailing)          | `Parse error: Expected type name` |
| `export {};` (module marker only)   | `TS2304: Cannot find name 'export'` |
| `import { f } from './a';`          | bare TS error: identifier `f` unbound |

The parser fixtures under `examples/` and `Test/Examples/fixtures/`
confirm this — none use `export` or cross-file `import`.

### Doc reference

`docs/subset.md`, "Allowed Features" section:

> **Modules:** `import`/`export` of values and types

### Practical impact

`tor-core` is currently a verified-pure subset of `tor-ts`
(packages/core, https://github.com/kumavis/tor-ts/tree/claude/tor-thales-conversion-plan-ZV3bm/packages/core).
Every file in `src/` is in the Thales subset and emits a Lean sidecar
checked at build time. The seam strategy in `docs/thales-conversion-plan.md`
calls for an impure shell that **imports** from this verified core and
adapts effectful APIs (sockets, timers, EventEmitter) onto pure step
functions.

Without `export`, the verified modules can't be imported by the impure
shell — so the plan's seam is currently blocked at the integration step.
Inside core itself, types like `PortRange` end up duplicated in every
file that uses them, and helpers like `isPortRangeListEmpty` can't be
factored out into a shared utility module. Two modules so far
(`exitPolicy.ts`, `seq32.ts`) — composition pressure will only grow.

The DU + structural-recursion pattern from `total-recursion.ts` works
cleanly for self-contained modules, so the rest of the subset is plenty
useful in isolation. It's just that the "use this in production" story
needs `import`/`export` to land.

### Suggested fix shape

For a minimal first pass that unblocks downstream consumers:

1. **`export` on top-level declarations** — accept `export function`,
   `export type`, `export interface`, `export const`. Lower to making
   the corresponding Lean definition non-`private` (i.e., visible at
   `import` sites).
2. **Bare `import { name } from './sibling'`** — accept an import-clause
   with named bindings; lower to a Lean `import Sibling`.
3. **Re-export-only files** are not needed for v1.

Default-imports, namespace-imports, and `import * as ns` can wait —
named imports are sufficient for the seam pattern. The Lean side
already handles `import` cleanly (Generated/ and Spec/ already cross-
import in the test project), so the work is on the TS-parser /
emitter side.

### Why this is medium-priority and not low-priority

This isn't a "the emitter writes broken Lean" failure mode like #1, #2,
#3 — `--no-emit` reports a clean TS error and stops. But the absence
makes Thales un-deployable in any project beyond a single-file demo,
which is a much more visible adoption gate than the silent-emit bugs.

---

## Issue 6: Switching on a non-parameter discriminant silently emits `()`

**Title:** `switch on \`f(x).kind\` or on a \`const\`-bound DU value emits empty body \`()\` (silent — accepted by subset checker)`

**Body:**

When a `switch` discriminates on something other than a direct parameter
of a discriminated-union type — specifically, on a property of a function
call result, or on a property of a `const`-bound DU — Thales 0.5 silently
emits `()` (Lean's `Unit`) as the function body. The subset checker
reports no diagnostic; the file emits; only `lake build` then catches
that the body type doesn't match the declared return type.

### Minimal repro

```ts
type T = { kind: 'a' } | { kind: 'b' };

function id(t: T): T { return t; }

// (1) switch on direct DU parameter — works
function f1(t: T): boolean {
  switch (t.kind) {
    case 'a': return true;
    case 'b': return false;
  }
}

// (2) switch on a `const`-bound copy — silently broken
function f2(t: T): boolean {
  const x = id(t);
  switch (x.kind) {
    case 'a': return true;
    case 'b': return false;
  }
}

// (3) switch on `f(t).kind` directly — silently broken
function f3(t: T): boolean {
  switch (id(t).kind) {
    case 'a': return true;
    case 'b': return false;
  }
}
```

Emitted Lean:

```lean
partial def f1 (t : T) : Bool :=
  match t with
    | .a => true
    | .b => false

partial def f2 (t : T) : Bool :=
  let x := (id t)
  ()

partial def f3 (t : T) : Bool :=
  ()
```

`f2` and `f3` ignore the `switch` body entirely and emit `()`, which
fails Lean compilation with a type-mismatch (`Unit` vs `Bool`).

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a`.

### Practical impact

This affects any helper that wants to derive a result from a *computed*
DU value. Concrete example from `tor-core`: a function `isRetryableEndReason(r)`
that asks "is `getStreamRetryBehavior(r)` anything other than `.no_retry`?"
cannot be written in the natural delegating form

```ts
function isRetryableEndReason(reason: RelayEndReason): boolean {
  switch (getStreamRetryBehavior(reason).kind) {
    case 'retry_circuit': return true;
    case 'retry_exit':    return true;
    case 'no_retry':      return false;
  }
}
```

It has to be inlined into a 14-case switch on `reason.kind` directly,
duplicating the policy logic, and a separate Lean theorem then proves
the inlined version agrees with `getStreamRetryBehavior`.

### Suggested fix

Either:

1. Lift the discriminant into a `let`/`match` in the emitter — Lean
   accepts arbitrary discriminants in `match`. The current behavior
   suggests the emitter recognizes only the `<param>.kind` shape and
   falls through to a generic "I don't know how to translate this
   expression" branch that emits `()`.
2. Or, more conservatively: emit a `TH####` diagnostic when the
   discriminant isn't a recognized form, instead of silently emitting
   `()`.

(2) at minimum, since silent failures here are the same hazard as
issues 1, 2, 3.

---

## Issue 7: Tuple `[a, b]` returns emit as Lean `Array`, not `Prod`

**Title:** `tuple-typed function returns emit as \`#[a, b]\` (Lean Array) instead of \`(a, b)\` (Prod), causing type-mismatch at Lean compile`

**Body:**

A function declared to return a tuple type `[A, B]` emits the body as a
Lean `Array` literal (`#[a, b]`) rather than a tuple constructor
(`(a, b)`). The signature on the Lean side is correctly translated to
`A × B`, so the body's `Array` type doesn't match.

### Minimal repro

```ts
type IntList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: IntList };

function dupTuple(xs: IntList): [IntList, IntList] {
  return [xs, xs];
}
```

Emitted:

```lean
partial def dupTuple (xs : IntList) : (IntList × IntList) :=
  (List.toArray ((List.cons xs ((List.cons xs List.nil)))))
```

Lean rejects with:
```
has type
  Array IntList
but is expected to have type
  IntList × IntList
```

The subset doc lists tuples as supported — `Tuples: Fixed-size tuples
like [A, B, C] map to Lean product types`. The signature-side
translation works; the value-side translation should match.

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a`.

### Suggested fix

Emit `(a, b)` (or `Prod.mk a b`) for tuple-typed positions instead of
the array literal that Thales currently emits. The literal `[a, b]` in
TypeScript is overloaded between array and tuple; the emitter should
look at the declared type to decide which Lean form to use.

### Practical impact

Bites any parser-result helper that wants to return both a parsed value
and the rest of the input. `tor-core` works around it by routing the
"two-output" shape through DU types like
`{ kind: 'ok'; taken; rest } | { kind: 'short' }`, but tuples would be
more idiomatic for this shape.

---

## Issue 8: Field access on a DU param inside a constructor expression emits broken `r.field` instead of the bound pattern name

**Title:** `Field access on a switch-narrowed DU parameter emits \`r.field\` inside DU constructor expressions, but Lean inductives have no auto-projections (works fine in arithmetic / direct returns)`

**Body:**

When a function pattern-matches on a DU parameter via `switch`, then
uses a field of that parameter inside another DU's constructor
expression, Thales emits the source-side `r.field` projection instead
of the pattern-bound local name. Lean rejects because `inductive` types
don't auto-derive field accessors (only `structure` does). The same
field access in arithmetic position (`p.a + p.b`) works correctly —
the bug is specifically about the constructor-expression context.

### Minimal repro

```ts
type Result = { kind: 'ok'; v: bigint } | { kind: 'err' };

// Broken:
function bumpVal(r: Result): Result {
  switch (r.kind) {
    case 'ok':
      return { kind: 'ok', v: r.v + 1n };  // ← `r.v` inside ctor
    case 'err':
      return { kind: 'err' };
  }
}

// Workaround that compiles:
function bumpVal2(r: Result): Result {
  switch (r.kind) {
    case 'ok': {
      const old = r.v;                     // ← bind first
      return { kind: 'ok', v: old + 1n };
    }
    case 'err':
      return { kind: 'err' };
  }
}
```

Emitted:

```lean
partial def bumpVal (r : Result) : Result :=
  match r with
    | .ok v => (.ok ((r.v + 1)))           -- ← uses `r.v`, not `v`
    | .err => .err

partial def bumpVal2 (r : Result) : Result :=
  match r with
    | .ok v => let old := v                 -- ← uses bound name
               (.ok ((old + 1)))
    | .err => .err
```

Lean rejects `bumpVal`:
```
error: Invalid field `v`: The environment does not contain `Result.v`,
so it is not possible to project the field `v` from an expression
  r
of type `Result`
```

The `match` branch already binds `v` (the field name from the
constructor), but the emitter doesn't substitute that bound name into
the body — it preserves the source-side `r.v` reference. The same
function written using direct `bigint` arithmetic on field accesses
emits correctly:

```ts
function pairSum(p: { kind: 'pair'; a: bigint; b: bigint }
                  | { kind: 'none' }): bigint {
  switch (p.kind) {
    case 'pair': return p.a + p.b;  // → match | .pair a b => (a + b)  -- works
    case 'none': return 0n;
  }
}
```

So the emitter handles `r.field` correctly in some positions but not
in DU-constructor positions.

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a`.

### Suggested fix

Inside a `case` branch of a `switch (r.kind)`, the emitter should
substitute every `r.fieldName` with the corresponding pattern-bound
name. The `match` it emits already binds the right names; the body
just needs to use them.

### Practical impact

Same hazard as Issues 1, 2, 3, 6 — accepted by the subset checker,
emit succeeds, only `lake build` catches the broken Lean. Workaround
(bind to a local `const` first) adds a line per field access but is
mechanical. Bites any function that *transforms* a DU value while
preserving structure — common shape in parser-style code.

---

In an earlier iteration I considered filing a fourth issue about Thales's
docs not telling downstream Lake projects to pin by SHA. After
re-reading, this is more accurately framed as: **Thales doesn't document
downstream-dependency usage at all** (the README only covers building
Thales standalone). It's worth a docs feature request — "Add a 'Using
Thales as a Lake dependency' section to README" — but it's a different
kind of issue from the four bugs above, and it's blocked by issues 1–4
being fixed (otherwise the documented dependency pattern would still
emit broken Lean). Recommend filing after the bugs land.
