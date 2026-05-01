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

type PortRangeList = { kind: 'nil' } | { kind: 'cons'; head: PortRange; tail: PortRangeList };

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
      return portInRange(port, ranges.head) || anyRangeContainsPort(port, ranges.tail);
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

// ----------------------------------------------------------------------------
// Quantified port-list queries.
//
// `PortList` is a separate cons-cell list of single ports (not ranges). The
// existing TS implementation in `packages/tor/src/exit-policy.ts` returns
// `true` for both `policyAllowsAllPorts` and `policyAllowsAnyPort` on an
// empty input array — that quirk is preserved here for behavioural parity.
// ----------------------------------------------------------------------------

type PortList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: PortList };

/** @total */
function policyAllowsAllPorts(policy: ExitPolicy, ports: PortList): boolean {
  switch (ports.kind) {
    case 'nil':
      return true;
    case 'cons':
      return policyAllowsPort(policy, ports.head) && policyAllowsAllPorts(policy, ports.tail);
  }
}

/** @total */
function policyAllowsAnyPort(policy: ExitPolicy, ports: PortList): boolean {
  switch (ports.kind) {
    case 'nil':
      // Matches the existing TS: empty list short-circuits to true.
      return true;
    case 'cons':
      return policyAllowsPort(policy, ports.head) || policyAllowsAnyPort(policy, ports.tail);
  }
}

// ----------------------------------------------------------------------------
// `policyRejectsAll`: the policy denies every valid port.
//
// True when the accept list is empty (nothing matches → nothing accepted) or
// when the reject list is exactly the single range [1, 65535] (every valid
// port matches → every valid port rejected). The strong correctness theorem
// in Spec/ExitPolicy.lean proves: if this returns `true`, no port in
// [1, 65535] is allowed.
// ----------------------------------------------------------------------------

/** @total */
function isPortRangeListEmpty(ranges: PortRangeList): boolean {
  switch (ranges.kind) {
    case 'nil':
      return true;
    case 'cons':
      return false;
  }
}

/** @total */
function isFullPortRange(ranges: PortRangeList): boolean {
  switch (ranges.kind) {
    case 'nil':
      return false;
    case 'cons':
      return (
        ranges.head.start === 1n &&
        ranges.head.endPort === 65535n &&
        isPortRangeListEmpty(ranges.tail)
      );
  }
}

/** @total */
function policyRejectsAll(policy: ExitPolicy): boolean {
  switch (policy.kind) {
    case 'accept':
      return isPortRangeListEmpty(policy.ports);
    case 'reject':
      return isFullPortRange(policy.ports);
  }
}
