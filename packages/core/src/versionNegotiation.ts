// Tor link-protocol version negotiation (verified core).
//
// Both endpoints exchange VERSIONS cells listing the link-layer
// versions they understand; both then pick the maximum version that
// appears in both lists. Per tor-spec.txt §4.1:
//
//   "Either party MUST close the connection if there is no overlap.
//    The two parties choose the highest version of the protocol that
//    both endpoints support."
//
// Currently used in `packages/tor/src/channel.ts` as a literal
// `defaultLinkSupportedVersions = [3, 4, 5]`. The intersection-and-
// max logic is inline today; the verified core captures the algorithm
// and the seam adapter passes the right `VersionList`s in.

type VersionList = { kind: 'nil' } | { kind: 'cons'; head: bigint; tail: VersionList };

// ----------------------------------------------------------------------------
// List membership.
// ----------------------------------------------------------------------------

/** @total */
function containsVersion(list: VersionList, v: bigint): boolean {
  switch (list.kind) {
    case 'nil':
      return false;
    case 'cons':
      if (list.head === v) {
        return true;
      }
      return containsVersion(list.tail, v);
  }
}

// ----------------------------------------------------------------------------
// Accumulator type for "max so far" with explicit "no value yet".
//
// We use a DU rather than `bigint | null` because Thales 0.5's
// null-narrowing doesn't propagate through follow-up comparisons —
// after `if (x === null) return …`, a subsequent `x >= candidate`
// still trips a `bigint | null` is not assignable to `bigint` error.
// ----------------------------------------------------------------------------

type MaxAcc = { kind: 'none' } | { kind: 'some'; value: bigint };

/** @total */
function updateMax(current: MaxAcc, candidate: bigint): MaxAcc {
  switch (current.kind) {
    case 'none':
      return { kind: 'some', value: candidate };
    case 'some': {
      const v = current.value;
      if (v >= candidate) {
        return current;
      }
      return { kind: 'some', value: candidate };
    }
  }
}

// ----------------------------------------------------------------------------
// Max-common: walk the client list, check each entry against the server
// list, track the max found so far.
// ----------------------------------------------------------------------------

/** @total */
function maxCommonVersionAux(client: VersionList, server: VersionList, currentMax: MaxAcc): MaxAcc {
  switch (client.kind) {
    case 'nil':
      return currentMax;
    case 'cons': {
      const head = client.head;
      const tail = client.tail;
      if (containsVersion(server, head)) {
        const newMax = updateMax(currentMax, head);
        return maxCommonVersionAux(tail, server, newMax);
      }
      return maxCommonVersionAux(tail, server, currentMax);
    }
  }
}

/**
 * Return the highest version that appears in both `client` and
 * `server`, or `null` if there is no overlap. Per tor-spec.txt §4.1,
 * a `null` result means the connection MUST be closed.
 */
/**
 * Return the highest version that appears in both `client` and
 * `server`. Per tor-spec.txt §4.1, the `'none'` constructor means
 * "no overlap" and the connection MUST be closed.
 *
 * Returns `MaxAcc` rather than `bigint | null` because Thales 0.5
 * mis-lowers nullable-union returns from helper calls (it wraps the
 * call site in an extra `.some`, producing `Option (Option Int)`).
 * The seam unwraps `MaxAcc` to whatever shape the impure shell
 * prefers.
 */
/** @total */
function maxCommonVersion(client: VersionList, server: VersionList): MaxAcc {
  return maxCommonVersionAux(client, server, { kind: 'none' });
}
