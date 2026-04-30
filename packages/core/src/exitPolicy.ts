// Exit-policy evaluation for Tor relay selection (verified core).
//
// Mirrors the relevant logic from `packages/tor/src/exit-policy.ts`. Wire
// formats and consensus rules use these structures to decide whether an
// exit relay will accept a given destination port. The TS-side caller in
// `packages/tor` performs `BigInt(portNumber)` and the array→list
// conversion at the seam.
//
// Modeling notes:
// - Ports are `bigint` so Lean reasons over `Int` rather than `Float`.
// - The list of ranges is a discriminated-union cons-cell list rather
//   than `PortRange[]`. Thales 0.5's runtime does not yet implement
//   `.reduce` / `.map` / `.filter` on TS arrays, so iteration uses
//   structural recursion on an inductive type instead.
// - `endPort` rather than `end` because `end` is a reserved keyword in
//   Lean and Thales emits TS field names verbatim.

interface PortRange {
  start: bigint;
  endPort: bigint;
}

type PortRangeList =
  | { kind: 'nil' }
  | { kind: 'cons'; head: PortRange; tail: PortRangeList };

type ExitPolicy =
  | { kind: 'accept'; ports: PortRangeList }
  | { kind: 'reject'; ports: PortRangeList };

/** @total */
function portInRange(port: bigint, range: PortRange): boolean {
  return range.start <= port && port <= range.endPort;
}

/** @total */
function anyRangeContainsPort(port: bigint, ranges: PortRangeList): boolean {
  switch (ranges.kind) {
    case 'nil':
      return false;
    case 'cons':
      return (
        portInRange(port, ranges.head) ||
        anyRangeContainsPort(port, ranges.tail)
      );
  }
}

/** @total */
function policyAllowsPort(policy: ExitPolicy, port: bigint): boolean {
  switch (policy.kind) {
    case 'accept':
      return anyRangeContainsPort(port, policy.ports);
    case 'reject':
      return !anyRangeContainsPort(port, policy.ports);
  }
}
