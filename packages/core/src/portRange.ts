// Port-range membership.
//
// This is the smallest meaningful piece of `packages/tor/src/exit-policy.ts`
// — the predicate `port ∈ [range.start, range.end]` — extracted into the
// verified core. Wire formats and consensus rules use these ranges to
// decide whether an exit relay will accept a given destination port.
//
// Ports are modeled as `bigint` so Lean reasons over `Int` rather than
// `Float`. The TS shell that uses this module passes `BigInt(portNumber)`
// at the seam.

export type PortRange = {
  start: bigint;
  end: bigint;
};

/** @total */
export function portInRange(port: bigint, range: PortRange): boolean {
  return range.start <= port && port <= range.end;
}
