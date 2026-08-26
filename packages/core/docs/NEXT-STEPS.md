# Next steps

Ordered, concrete actions for picking this work back up. Written at the
point where the Thales 0.7 migration has landed locally
(20 modules / 365 theorems, `verify.sh` green) but is **not yet pushed**.

Background for any of these: [`MIGRATION.md`](MIGRATION.md) has the
measurements, [`PATTERNS.md`](PATTERNS.md) has the house rules,
[`thales-issues.md`](thales-issues.md) has the upstream bug drafts, and
[`../../../docs/thales-conversion-plan.md`](../../../docs/thales-conversion-plan.md)
has the per-package roadmap.

---

## 0. Push the branch — blocked, needs a human

**Status: blocked on credentials, not on work.**

Three commits sit on `claude/tor-thales-conversion-plan-ZV3bm` ahead of
what was last pushed (`949c5c9`):

```
9d004ba  docs(core): rewrite plan/patterns/issues for Thales 0.7; add MIGRATION.md
fe56e13  feat(core): migrate to Thales 0.7 + Lean 4.33 (365 theorems)
<this>   docs(core): add NEXT-STEPS.md
```

The dev sandbox lost its git-proxy credentials mid-session, so `git push`
fails with `could not read Username`. `git fetch` still works — it is
specifically push auth. A bundle was produced instead; see
**Applying the bundle** at the bottom.

Once pushed, CI's `verify_core` job re-runs. Its cache key hashes
`scripts/verify.sh`, and that file's `THALES_REV` changed, so the Thales
build cache invalidates automatically — expect the first run to take a
few extra minutes while it rebuilds Thales at the new pin.

**Acceptance:** all six CI checks green on the PR.

---

## 1. File the two new upstream bugs

Drafts are complete and ready to paste from
[`thales-issues.md`](thales-issues.md). File in this order:

1. **#14 — Exported DU types cannot be pattern-matched.** Highest
   leverage of anything on this list. It blocks cross-module composition,
   which blocks the full cell parser, which is the next substantive
   verification target. The draft includes the full 7-row repro matrix.
   TH9005's own error text asks for the report.
2. **#13 — `%` on `bigint` lowers to the Float `jsMod`.** A regression
   that we have worked around, but the workaround costs a helper plus a
   bridging theorem in every module that needs bit extraction.

Then comment on the two stale-open issues asking for closure — both are
verified fixed:

- [#15](https://github.com/jessealama/thales/issues/15) object literals
- [#16](https://github.com/jessealama/thales/issues/16) array stdlib

**Also worth opening as a discussion, not a bug:** crypto FFI. Calling
SHA-3 / SHAKE256 / Curve25519 / Ed25519 from verified code needs
Lean-side `extern` declarations the runtime does not supply. This gates
the most security-critical code in `tor-ts` (`ntor.ts`,
consensus-signature verification, hs-ntor key derivation) and there is
currently no path to it at any Thales version.

**Acceptance:** two issues filed, two closure requests posted.

---

## 2. Cell encoders — the best available next module

Unblocked _now_; does not depend on anything upstream.

Every decoder in core currently has no inverse. Adding encoders unlocks
**round-trip theorems** of the form `parse (serialize c) = some c`,
which is the strongest property this codebase can state about its wire
format — strictly stronger than the per-direction invariants we have.

What changed to make this possible: the canonical
`for (let i = 0; i < B; i++)` loop shape is `@total`-friendly, so
length-driven byte emission is now writable. At 0.5 this was blocked by
the `@decreasing` / `Nonempty` gap (issues 9 and 10).

Suggested order, smallest first:

| target                       | pairs with                                           | notes                                   |
| ---------------------------- | ---------------------------------------------------- | --------------------------------------- |
| `encodeUintBE(value, width)` | `bigEndianUint` in `bytes.ts`                        | the primitive everything else needs     |
| `encodeUintLE(value, width)` | `decodeUint*LE` in `kcpHeader.ts`                    | same shape, LE order                    |
| `serializeCircId(v, circId)` | `parseCircId` in `cellHeader.ts`                     | width depends on link version           |
| `serializeCellHeader(...)`   | `parseCircId` + `parseCommand` + `parseLengthPrefix` | composition — may want §3 settled first |

**Watch for:** the canonical `for` requires the bound to be a
non-negative integer literal or `arr.length` on an array-typed binding.
A `bigint` width parameter is neither, so either take the width as
`number`/`Natural` or restructure. Prototype `encodeUintBE` first and
confirm it takes `@total` before writing the rest.

**Acceptance:** at least one encoder/decoder pair with a
`parse (serialize x) = some x` theorem.

---

## 3. Decide the byte representation: `ByteList` vs `Byte[]`

This is a **decision**, not a task — do it before §2's composition step
and before any further byte-layer work, because it is expensive to
reverse.

Core models byte buffers as a cons-cell DU. That was forced at 0.5.
At 0.7 `Byte[]` is viable and has one decisive advantage:

> `Byte[]` is not a discriminated union, so it **sidesteps issue #14
> entirely** — an array type can be exported and shared across modules
> today, with no upstream fix required.

Against that: ~60 existing theorems assume the cons-cell shape and would
need rewriting, and `@total` recursion over arrays needs the canonical
`for` or `slice` recursion rather than natural structural recursion.

**Method:** port `kcpHeader.ts` (smallest byte consumer, 15 theorems) to
`Byte[]` on a scratch branch. Compare:

- proof ergonomics — is `omega`/`simp` still enough, or does array
  reasoning need lemmas we do not have without Mathlib?
- whether `@total` survives
- whether the seam adapter genuinely simplifies (no list↔array
  marshalling)

Then decide. Do **not** migrate the whole byte layer speculatively.

**Acceptance:** a written decision in `MIGRATION.md` with the prototype
as evidence, either way.

---

## 4. Adopt `Byte` for byte values (contingent on §3)

`@thales/prelude` ships `Integer` / `Natural` / `Byte` / `Bit` as
compile-time range-enforced refinements. Our `ByteList` carries "each
element is a `bigint` in `[0, 256)`" as a **comment**. `Byte` makes it a
type — a real correctness upgrade to the most-used type in core.

**Blocker to resolve first:** refinements are `Float` subtypes and do
**not** compose with `bigint`. Adopting `Byte` means moving byte values
off `bigint`, which affects every decode function. Arithmetic also
widens back to `number`, so every operation needs re-narrowing via a
guard or constructor.

This is why §3 and §4 should be evaluated together — if the prototype
moves to `Byte[]`, the refinement question is already answered.

---

## 5. Rebase onto `tor-ts` main

The branch is 7 commits behind `origin/main`, which added:

- an **HS proof-of-work client** (Equi-X, proposal 327) in
  `packages/crypto` + `packages/tor`
- strict tsconfig flags across all packages
- HS connection-robustness fixes

Rebase before planning further conversion work. Then assess PoW as a
core candidate — it is pure, deterministic, and arithmetic-heavy, with
checkable invariants (effort/difficulty relationships, solution
verification). It may be the strongest remaining candidate that needs no
upstream fix.

**Watch for:** the strict-tsconfig commit may touch
`packages/core/tsconfig.json`; ours is already maximally strict, so
expect either a no-op or a trivial conflict.

---

## 6. Revisit if/when issue #14 lands

The moment exported DUs can be matched:

1. Delete the duplicated `ByteList` + primitives from `cellHeader.ts`,
   `kcpHeader.ts`, and `encapsulationPrefix.ts` (~200 lines), importing
   from `bytes.ts` instead.
2. Collapse the correspondingly duplicated Lean lemmas —
   `trySplit_total_length` is currently re-derived in both
   `Spec/CellHeader.lean` and `Spec/KcpHeader.lean`.
3. Compose the full `parseCell` from the existing primitives — this is
   the thing the whole byte layer was built toward.
4. Update `PATTERNS.md`: the "keep matched DUs local" rule is rule #1
   there, and it goes away.

---

## Environment reconstruction

The sandbox is ephemeral and this took real time to rediscover. To get a
working verification environment:

```bash
# zstd is not preinstalled and Lean tarballs need it
apt-get install -y zstd

# release.lean-lang.org is firewalled in this sandbox, so elan cannot
# resolve toolchains itself. Fetch from GitHub releases and link.
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
  | sh -s -- -y --default-toolchain none
export PATH="$HOME/.elan/bin:$PATH"

mkdir -p /tmp/lean433 && cd /tmp/lean433
curl -sL -o lean.tar.zst \
  https://github.com/leanprover/lean4/releases/download/v4.33.0/lean-4.33.0-linux.tar.zst
tar --use-compress-program='zstd -d' -xf lean.tar.zst
elan toolchain link v4.33.0-linked /tmp/lean433/lean-4.33.0-linux

# point the package at it, then verify
cd <repo>/packages/core
elan override set v4.33.0-linked
bash scripts/verify.sh
```

`verify.sh` clones and builds Thales itself on first run (a few
minutes). To test a _candidate_ Thales without touching the committed
pin, use `scripts/migration-probe.sh` — see MIGRATION.md.

---

## Applying the bundle

If the branch still has not been pushed, the three commits are in a git
bundle. It is incremental against `949c5c9`, which is already on the
remote.

```bash
git bundle verify tor-core-thales-0.7.bundle
git fetch tor-core-thales-0.7.bundle \
  claude/tor-thales-conversion-plan-ZV3bm:thales-0.7-migration
git checkout claude/tor-thales-conversion-plan-ZV3bm
git merge --ff-only thales-0.7-migration
git push origin claude/tor-thales-conversion-plan-ZV3bm
```

Verify the result matches what was tested here:

```bash
cd packages/core && bash scripts/verify.sh   # expect 45/45 jobs
grep -chE '^theorem |^@\[simp\] theorem ' Spec/*.lean | paste -sd+ | bc
# expect 365
```
