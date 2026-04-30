# `tor-core`

The verified pure core of `tor-ts`.

Every TypeScript file under `src/` is written in the
[Thales TypeScript subset](https://github.com/jessealama/thales/blob/main/docs/subset.md)
so it can be transpiled to Lean 4 and kernel-checked. Specification
theorems live under `Spec/` and are checked by `lake build` in CI. If a
file in this package fails either step, the build fails.

The seam strategy and per-package conversion plan live in
[`docs/thales-conversion-plan.md`](../../docs/thales-conversion-plan.md).

## Layout

```
packages/core/
├── src/                  TypeScript source (Thales subset, runs as JS)
│   └── exitPolicy.ts
├── Generated/            Thales-emitted Lean sidecars (gitignored)
├── Spec/                 Hand-written Lean theorems
│   └── ExitPolicy.lean
├── lakefile.lean         Lean project; `require`s Thales
├── lean-toolchain        Pinned Lean version
├── tsconfig.json         Strict TS settings
└── scripts/verify.sh     Build Thales → emit sidecars → `lake build`
```

## Running locally

You need [`elan`](https://github.com/leanprover/elan) on `$PATH`. Then:

```bash
yarn workspace tor-core verify
```

The first run clones and builds Thales into `packages/core/.thales/`,
which takes a few minutes (~57 build steps); subsequent runs reuse the
binary as long as `THALES_REV` is unchanged.

## What's inside

| Module | Functions | Theorems in `Spec/` |
|---|---|---|
| `exitPolicy.ts` | `portInRange`, `anyRangeContainsPort`, `policyAllowsPort` | 10 |

The intent is to port modules into here incrementally per the conversion
plan, **rejecting any addition that isn't fully Thales-eligible and
proven**.

## Known limitations & quirks

These were discovered during the first end-to-end run; capturing them so
later modules don't re-learn the same things.

- **No `export` keyword.** Thales 0.5's parser rejects
  `export function …` / `export type …` / trailing `export {}`. The
  subset doc lists `import`/`export` as supported, but the implementation
  doesn't agree yet. Until that lands upstream, files in `src/` are
  module-local — they can be verified, but they aren't importable from
  the rest of the workspace. This is fine for now (the goal is to grow
  the verified surface; integration with the impure shell comes later).
- **Lean reserved field names.** Thales emits TypeScript field names
  verbatim into Lean structs. Lean treats `end` as a keyword, so a TS
  field named `end` produces uncompilable Lean. Any verified module that
  needs a field called `end`, `match`, `mut`, `do`, etc. must rename it
  on the TS side.
- **`type X = { … }` collapses to `Unit`.** Thales 0.5 only emits
  full struct definitions for `interface` declarations, not record-shaped
  type aliases. Use `interface` for verified records.
- **`bigint` not `number`.** Thales maps `number` to Lean `Float` and
  `bigint` to Lean `Int`. Anything that wants integer reasoning (port
  numbers, byte values, sequence numbers, lengths) should be `bigint`.
  The TS-side adapter does `BigInt(x)` at the seam.
- **No `import` between Thales files.** The Thales 0.5 parser rejects
  `import` statements in user files just like it rejects `export`. Each
  verified module must be self-contained. Cross-module composition waits
  for an upstream Thales fix.
- **No array methods yet.** Despite the subset doc listing `.map`,
  `.filter`, `.reduce`, etc., the Thales 0.5 prelude only exposes
  `Option<T>` / `Result<T, E>`. Iteration over a sequence is done via a
  discriminated-union cons-cell list (`{ kind: 'nil' } | { kind: 'cons';
  head; tail }`) and structural recursion with `switch (xs.kind)`. The
  TS-side seam adapter converts arrays at the boundary. This is the
  pattern `total-recursion.ts` uses in the upstream Thales examples and
  is what compiles cleanly to `inductive` types in Lean.
