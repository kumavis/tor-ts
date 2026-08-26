# Next steps

Ordered, concrete actions for picking this work back up, from the point
where the Thales 0.7 migration has landed (20 modules / 365 theorems,
`verify.sh` green).

Background for any of these: [`MIGRATION.md`](MIGRATION.md) has the
measurements, [`PATTERNS.md`](PATTERNS.md) has the house rules,
[`thales-issues.md`](thales-issues.md) has the upstream bug drafts, and
[`../../../docs/thales-conversion-plan.md`](../../../docs/thales-conversion-plan.md)
has the per-package roadmap.

---

## 0. Push the branch — **done**

Pushed to `claude/tor-thales-conversion-plan-ZV3bm` at `b236d07`:

```
9d004ba  docs(core): rewrite plan/patterns/issues for Thales 0.7; add MIGRATION.md
fe56e13  feat(core): migrate to Thales 0.7 + Lean 4.33 (365 theorems)
b236d07  docs(core): add NEXT-STEPS.md
```

All 12 check runs green, `verify_core` among them. That job is the one
worth noting: it built Thales at the new pin from scratch in a clean
container and kernel-checked all 365 theorems in ~84s, which confirms
the migration does not depend on anything hand-assembled in a dev
sandbox. Its cache key hashes `scripts/verify.sh`, whose `THALES_REV`
changed, so the stale Thales cache invalidated automatically.

---

## 1. File the new upstream bugs

**This is now the top of the list.** Drafts are complete and ready to
paste from [`thales-issues.md`](thales-issues.md). File in this order:

1. **#14 — Exported DU types cannot be pattern-matched.** Highest
   leverage of anything on this list. It blocks cross-module composition,
   which blocks the full cell parser, which is the next substantive
   verification target. The draft includes the full 7-row repro matrix.
   TH9005's own error text asks for the report.
2. **#13 — `%` on `bigint` lowers to the Float `jsMod`.** A regression
   that we have worked around, but the workaround costs a helper plus a
   bridging theorem in every module that needs bit extraction — now
   three modules, since `byteEncode.ts` needs it too.
3. **#15 — array `.slice`/`.concat` documented but absent.** Cheapest
   of the three to fix and the most actively misleading: TH0002's own
   remedy text recommends `.concat`, which does not exist. This is the
   finding that closed §3/§4.

Then comment on the stale-open issues:

- [#15](https://github.com/jessealama/thales/issues/15) object literals
  — verified fixed, **ask to close**.
- [#16](https://github.com/jessealama/thales/issues/16) array stdlib —
  **only partially fixed.** `map`/`filter`/`reduce`/`length` and friends
  are callable now, but `slice`/`concat` never landed. Either reopen the
  scope there or let our #15 supersede it; do not ask to close it as-is.

**Also worth opening as a discussion, not a bug:** crypto FFI. Calling
SHA-3 / SHAKE256 / Curve25519 / Ed25519 from verified code needs
Lean-side `extern` declarations the runtime does not supply. This gates
the most security-critical code in `tor-ts` (`ntor.ts`,
consensus-signature verification, hs-ntor key derivation) and there is
currently no path to it at any Thales version.

**Acceptance:** three issues filed, both stale-open issues commented on.

---

## 2. Cell encoders — **done**

Landed as `src/byteEncode.ts` + `Spec/ByteEncode.lean`, 46 theorems.
Core now has its first round-trip results:

| theorem                                        | says                                                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `encodeUintLE_roundtrip`                       | `bytesToBigIntLE (encodeUintLE v w) = v` for any `v` that fits width `w`                            |
| `encodeUintBE_roundtrip`                       | same, big-endian — the direction Tor's own cell header uses                                         |
| `decode_encode_stream_LE` / `_BE`              | reading the field off the front of `encode v w ++ rest` returns `v` **and** leaves `rest` untouched |
| `serializeCircId_roundtrip_modern` / `_legacy` | a circuit ID survives serialization at either link-protocol width                                   |

Plus `encodeUint{8,16,32}{LE,BE}` corollaries at the concrete widths, and
exact-length theorems for each.

**The approach that worked was not the one this section predicted.** The
plan assumed the canonical `for` loop would carry length-driven byte
emission. It does not: loops lower into `Id.run do` with `let mut`, and
the canonical form shims the index to `Float` — `omega` cannot touch
either, and there is no Mathlib here to supply loop-invariant reasoning.

What worked instead: make the **width** a unary DU
(`Width = zero | succ Width`). Recursion on it is structural, so Lean's
own termination checker accepts every encoder as `@total` — no
`@decreasing`, no `partial def`, no `Nonempty` gap. Tor's field widths
are 1, 2 and 4 bytes, so unary costs nothing. The round-trip proofs get
a clean induction principle for free.

That leaves `serializeCellHeader` as the one item not done, since it
wants cross-module composition — see §6.

---

## 3 & 4. Byte representation and `Byte` — **decided: no change**

Both questions are closed. Full evidence in
[`MIGRATION.md` F5](MIGRATION.md); the short version:

- **`.slice` and `.concat` do not exist on arrays.** Not on `bigint[]`,
  not on `number[]` — the array builtin table has no arm for either,
  despite `subset.md` promising both in three places
  ([issue 15](thales-issues.md)). Without `slice` there is no array
  `trySplit`, and without `trySplit` the whole parser style is
  unavailable. Decisive on its own.
- **`@total` does not survive array recursion** even given `slice`, and
  the loop alternative is proof-hostile (see §2).
- **`Byte` is a `Float` subtype** (`{ x : Float // isByte x = true }`),
  so adopting it moves byte values off `Int` and out of `omega`'s reach.
  It is a TS-side correctness upgrade and a Lean-side downgrade.

Arrays do win one real thing — an exported array-typed alias can be
imported and indexed across modules, sidestepping #14 entirely, which is
exactly what this section hoped for. But that buys deduplicating ~200
lines at the cost of structural recursion, `@total`, and `omega`.

`ByteList` stays. Revisit only if `slice`/`concat` land upstream.

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
   `kcpHeader.ts`, `encapsulationPrefix.ts`, and `byteEncode.ts`
   (~260 lines), importing from `bytes.ts` instead.
2. Collapse the correspondingly duplicated Lean lemmas —
   `trySplit_total_length` is re-derived in both `Spec/CellHeader.lean`
   and `Spec/KcpHeader.lean`, and `Spec/ByteEncode.lean` re-derives
   `byteListConcat_length` and `byteListLength_nonneg` for the same
   reason.
3. Compose the full `parseCell` from the existing primitives — this is
   the thing the whole byte layer was built toward — and
   `serializeCellHeader` alongside it, which is the one §2 item left
   undone. With both, `parseCell (serializeCell c) = some c` becomes
   reachable: the round-trip for a whole cell rather than a field.
4. Update `PATTERNS.md`: the "keep matched DUs local" rule is rule #1
   there, and it goes away.

---

## Environment reconstruction

The sandbox is ephemeral and this took real time to rediscover. To get a
working verification environment:

```bash
# zstd is not preinstalled and Lean tarballs need it
apt-get install -y zstd

# elan can usually resolve toolchains itself. If releases.lean-lang.org
# is unreachable (it has been, intermittently, in these sandboxes),
# fetch from GitHub releases and link instead — the steps below work
# either way.
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

## Checking a working tree against the known-good state

```bash
cd packages/core && bash scripts/verify.sh   # expect 47/47 jobs
grep -chE '^theorem |^@\[simp\] theorem ' Spec/*.lean | paste -sd+ | bc
# expect 411
```
