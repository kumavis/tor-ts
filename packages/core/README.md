# `tor-core`

The verified pure core of `tor-ts`.

Every TypeScript file under `src/` is written in the
[Thales TypeScript subset](https://github.com/jessealama/thales/blob/main/docs/subset.md)
so it can be transpiled to Lean 4 and kernel-checked. Specification
theorems live under `Spec/` and are checked by `lake build` in CI. If a
file in this package fails either step, the build fails.

**20 modules / 365 theorems**, against Thales `3c71913` (0.7-forthcoming)
and Lean 4.33.0.

## Docs

|                                                                                |                                                                   |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| [`docs/PATTERNS.md`](docs/PATTERNS.md)                                         | Conventions and recipes for adding a module. **Read this first.** |
| [`docs/MIGRATION.md`](docs/MIGRATION.md)                                       | Thales 0.5 → 0.7 findings and the staged plan                     |
| [`docs/NEXT-STEPS.md`](docs/NEXT-STEPS.md)                                     | Ordered next actions for picking this work back up                |
| [`docs/thales-issues.md`](docs/thales-issues.md)                               | Upstream bug tracker (downstream view)                            |
| [`../../docs/thales-conversion-plan.md`](../../docs/thales-conversion-plan.md) | Seam strategy and per-package roadmap                             |

## Layout

```
packages/core/
├── src/                     TypeScript source (Thales subset, runs as JS)
├── Generated/               Thales-emitted Lean sidecars (gitignored)
├── Spec/                    Hand-written Lean theorems
├── docs/                    See table above
├── lakefile.lean            Lean project; `require`s Thales at a pinned SHA
├── lean-toolchain           Pinned Lean version
├── tsconfig.json            Strict TS settings
└── scripts/
    ├── verify.sh            Build Thales → emit sidecars → `lake build`
    └── migration-probe.sh   Probe a candidate Thales without touching the pin
```

`src/<camelCase>.ts` ⇄ `Generated/<PascalCase>.lean` ⇄
`Spec/<PascalCase>.lean`.

## Running locally

You need [`elan`](https://github.com/leanprover/elan) on `$PATH`. Then:

```bash
yarn workspace tor-core verify
```

The first run clones and builds Thales into `packages/core/.thales/`,
which takes a few minutes; subsequent runs reuse the binary as long as
`THALES_REV` is unchanged.

## What's inside

### Wire vocabulary

Numeric wire codes as discriminated unions, each with a kernel-checked
code ⇄ constructor round-trip and range/classifier theorems.

| Module               | Covers                                                            | Theorems |
| -------------------- | ----------------------------------------------------------------- | -------: |
| `messageCellType.ts` | Link-cell types (tor-spec §3); fixed vs variable-length predicate |       16 |
| `relayCommand.ts`    | 28 relay commands across four spec ranges                         |       18 |
| `relayEndReason.ts`  | RELAY_END reasons + stream retry policy                           |       12 |
| `destroyReason.ts`   | DESTROY reasons + clean-teardown predicate                        |       10 |
| `certType.ts`        | Cert types; legacy-X509 and hidden-service classifiers            |        8 |
| `wireTypes.ts`       | Address, link-specifier, handshake, resolved-record types         |       24 |
| `smuxCmd.ts`         | SMUX commands + payload/lifecycle classifiers                     |       15 |

### Byte primitives and parsers

| Module                   | Covers                                                       | Theorems |
| ------------------------ | ------------------------------------------------------------ | -------: |
| `bytes.ts`               | `ByteList`, length, concat, `trySplit`, BE/LE integer decode |       20 |
| `cellHeader.ts`          | circuit ID, command byte, length prefix, payload             |       25 |
| `kcpHeader.ts`           | KCP little-endian uint8/16/32 field decoders                 |       15 |
| `encapsulationPrefix.ts` | Snowflake 1–3 byte variable-length prefix                    |       13 |

Headline: `trySplit_concat` — when the splitter succeeds, gluing the
pieces back recovers the input exactly. Every parser built on it
inherits that, and each parser has its own byte-counting invariant
(`parseCircId_consumes_correctly`, `parsePayload_consumes_n`, …).

### Protocol state machines

Each is a `step(state, input)` function with terminal-state stability,
protocol-error transitions, a phase partition, and a composed happy-path
theorem.

| Module             | Covers                                                      | Theorems |
| ------------------ | ----------------------------------------------------------- | -------: |
| `channelState.ts`  | Link handshake: VERSIONS → CERTS → AUTH_CHALLENGE → NETINFO |       22 |
| `circuitState.ts`  | Circuit build → open → destroyed, with hop counting         |       17 |
| `streamState.ts`   | Stream lifecycle incl. the RESOLVE → RESOLVED → END path    |       22 |
| `hsClientState.ts` | HSv3 client: descriptor → INTRODUCE → RENDEZVOUS2           |       18 |
| `hsHostState.ts`   | HSv3 host per-introduction-point lifecycle                  |       14 |

### Policy and arithmetic

| Module                  | Covers                                                 | Theorems |
| ----------------------- | ------------------------------------------------------ | -------: |
| `exitPolicy.ts`         | Exit-policy evaluation; `policyRejectsAll` correctness |       25 |
| `seq32.ts`              | Wrap-safe 32-bit sequence arithmetic (KCP `itimediff`) |       17 |
| `sendmeWindow.ts`       | SENDME flow control, both circuit and stream constants |       39 |
| `versionNegotiation.ts` | Link-protocol max-common-version selection             |       15 |

Two worth calling out:

- `policyRejectsAll_implies_rejects_valid_port` — if the predicate says
  a policy rejects everything, no port in `[1, 65535]` is allowed.
- `itimediff_eq_of_close` — inside a window narrower than `2^31`, the
  signed difference is the true integer difference; wraparound cannot
  make distant sequence numbers look adjacent.

## Contributing

Read [`docs/PATTERNS.md`](docs/PATTERNS.md) — the Thales subset has
sharp edges and that file records the ones we've hit. New additions must
be fully Thales-eligible **and** proven; `verify.sh` gates on both.
