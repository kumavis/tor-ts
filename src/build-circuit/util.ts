import { MicroDescNodeInfo } from "./directory"

export function filterRelaysByFlags (relays: MicroDescNodeInfo[], flags: string[], ignoreList: MicroDescNodeInfo[] = []): MicroDescNodeInfo[] {
  const matchingRelays = relays.filter(relayInfo => {
    const flagMatches = flags.every(flag => relayInfo.flags.includes(flag))
    if (!flagMatches) return false
    const isIgnored = ignoreList.find(ignoredNodeInfo => {
      return ignoredNodeInfo === relayInfo || ignoredNodeInfo.rsaIdDigest.equals(relayInfo.rsaIdDigest)
    })
    if (isIgnored) return false
    return true
  })
  return matchingRelays
}

export function pickRelayWithFlags (relays: MicroDescNodeInfo[], flags: string[], ignoreList: MicroDescNodeInfo[] = []) {
  const matchingRelays = filterRelaysByFlags(relays, flags, ignoreList)
  if (matchingRelays.length === 0) {
    throw new Error(`Failed to find any matching relays for [${flags}] from ${relays.length} relays`)
  }
  // console.log(`matching`, flags, matchingRelays)
  const randomIndex = Math.floor(Math.random() * matchingRelays.length)
  return matchingRelays[randomIndex]
}