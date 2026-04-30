# Thales issue drafts

Verified against `main` at `31f300449ea4514e1975fa559011d18793ee1a7a` (current
tip as of filing). None of these duplicate any of the 10 existing issues
(#1 closed, #2–#10 are 0.6 refinement-types milestones). All four produce
silently or visibly broken Lean from input that Thales accepts.

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

## Skipping the original "lakefile reproducibility" item

In an earlier iteration I considered filing a fourth issue about Thales's
docs not telling downstream Lake projects to pin by SHA. After
re-reading, this is more accurately framed as: **Thales doesn't document
downstream-dependency usage at all** (the README only covers building
Thales standalone). It's worth a docs feature request — "Add a 'Using
Thales as a Lake dependency' section to README" — but it's a different
kind of issue from the four bugs above, and it's blocked by issues 1–4
being fixed (otherwise the documented dependency pattern would still
emit broken Lean). Recommend filing after the bugs land.
