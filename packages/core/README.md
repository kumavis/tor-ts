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
│   └── portRange.ts
├── Generated/            Thales-emitted Lean sidecars (gitignored)
├── Spec/                 Hand-written Lean theorems
│   └── PortRange.lean
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
which takes a few minutes; subsequent runs reuse the binary.

## What's inside (so far)

| Module | Status |
|---|---|
| `portRange.ts` — `PortRange` type and `portInRange` predicate | scaffolded; smoke-checked in CI |

This is the first slice. The intent is to port modules into here
incrementally per the conversion plan, **rejecting any addition that
isn't fully Thales-eligible and proven**.
