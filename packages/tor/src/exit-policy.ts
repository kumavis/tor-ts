/**
 * Exit policy parsing and matching for Tor relay selection.
 *
 * Exit policies in microdescriptors use a compact summary format:
 *   p accept 80,443,8000-9000
 *   p reject 25,119,135-139,445
 *
 * The format is: `p accept|reject PortList` where PortList is comma-separated
 * ports or port ranges. Whether it shows accepted or rejected ports depends
 * on which list is shorter.
 *
 * @see https://spec.torproject.org/dir-spec/computing-consensus.html#exit-summary
 */

/**
 * A port range, inclusive on both ends.
 */
export type PortRange = {
  start: number;
  end: number;
};

/**
 * Parsed exit policy summary from a microdescriptor.
 */
export type ExitPolicy = {
  /** Whether this is an accept or reject list */
  type: 'accept' | 'reject';
  /** List of port ranges */
  ports: PortRange[];
};

/**
 * Parse a port list string into port ranges.
 *
 * @example
 * parsePortList("80,443,8000-9000")
 * // => [{ start: 80, end: 80 }, { start: 443, end: 443 }, { start: 8000, end: 9000 }]
 */
export function parsePortList(portList: string): PortRange[] {
  if (!portList || portList.trim() === '') {
    return [];
  }

  const ranges: PortRange[] = [];
  const parts = portList.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;

    if (trimmed.includes('-')) {
      const [startStr, endStr] = trimmed.split('-');
      const start = parseInt(startStr!, 10);
      const end = parseInt(endStr!, 10);
      if (!isNaN(start) && !isNaN(end) && start >= 1 && end <= 65535 && start <= end) {
        ranges.push({ start, end });
      }
    } else {
      const port = parseInt(trimmed, 10);
      if (!isNaN(port) && port >= 1 && port <= 65535) {
        ranges.push({ start: port, end: port });
      }
    }
  }

  return ranges;
}

/**
 * Parse an exit policy summary line from a microdescriptor.
 *
 * @param line - The policy line, e.g., "p accept 80,443" or "accept 80,443"
 * @returns Parsed exit policy, or null if parsing fails
 *
 * @example
 * parseExitPolicySummary("p accept 80,443,8000-9000")
 * // => { type: 'accept', ports: [...] }
 */
export function parseExitPolicySummary(line: string): ExitPolicy | null {
  const trimmed = line.trim();

  // Handle both "p accept ..." and "accept ..." formats
  let rest = trimmed;
  if (rest.startsWith('p ')) {
    rest = rest.slice(2);
  }

  const spaceIdx = rest.indexOf(' ');
  if (spaceIdx === -1) {
    // Handle "accept" or "reject" with no ports (edge case)
    if (rest === 'accept' || rest === 'reject') {
      return { type: rest, ports: [] };
    }
    return null;
  }

  const typeStr = rest.slice(0, spaceIdx).toLowerCase();
  const portListStr = rest.slice(spaceIdx + 1);

  if (typeStr !== 'accept' && typeStr !== 'reject') {
    return null;
  }

  const ports = parsePortList(portListStr);
  return { type: typeStr, ports };
}

/**
 * Check if a port is within any of the given port ranges.
 */
function portInRanges(port: number, ranges: PortRange[]): boolean {
  for (const range of ranges) {
    if (port >= range.start && port <= range.end) {
      return true;
    }
  }
  return false;
}

/**
 * Check if an exit policy allows a specific port.
 *
 * @param policy - The parsed exit policy
 * @param port - The port number to check
 * @returns true if the policy allows the port
 *
 * @example
 * const policy = parseExitPolicySummary("p accept 80,443");
 * policyAllowsPort(policy, 80);  // true
 * policyAllowsPort(policy, 22);  // false
 */
export function policyAllowsPort(policy: ExitPolicy | null | undefined, port: number): boolean {
  if (!policy) {
    // No policy info - be conservative and assume it might work
    // (will get REASON_EXITPOLICY if wrong)
    return true;
  }

  const inList = portInRanges(port, policy.ports);

  if (policy.type === 'accept') {
    // Accept list: port must be in the list
    return inList;
  } else {
    // Reject list: port must NOT be in the list
    return !inList;
  }
}

/**
 * Check if an exit policy allows all of the specified ports.
 *
 * @param policy - The parsed exit policy
 * @param ports - Array of port numbers to check
 * @returns true if the policy allows all ports
 */
export function policyAllowsAllPorts(
  policy: ExitPolicy | null | undefined,
  ports: number[]
): boolean {
  if (ports.length === 0) {
    return true;
  }
  return ports.every((port) => policyAllowsPort(policy, port));
}

/**
 * Check if an exit policy allows any of the specified ports.
 *
 * @param policy - The parsed exit policy
 * @param ports - Array of port numbers to check
 * @returns true if the policy allows at least one port
 */
export function policyAllowsAnyPort(
  policy: ExitPolicy | null | undefined,
  ports: number[]
): boolean {
  if (ports.length === 0) {
    return true;
  }
  return ports.some((port) => policyAllowsPort(policy, port));
}

/**
 * Check if an exit policy rejects all ports (equivalent to "reject 1-65535").
 */
export function policyRejectsAll(policy: ExitPolicy | null | undefined): boolean {
  if (!policy) {
    return false;
  }

  if (policy.type === 'reject') {
    // Check if reject list covers all ports
    return (
      policy.ports.length === 1 && policy.ports[0]!.start === 1 && policy.ports[0]!.end === 65535
    );
  } else {
    // Accept list with no ports means reject all
    return policy.ports.length === 0;
  }
}

/**
 * Default target ports for web traffic (HTTP and HTTPS).
 */
export const DEFAULT_TARGET_PORTS = [80, 443];
