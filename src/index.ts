// const circuitPeerInfos = await getStandardChutneyCircuitPath()

// const gatewayPeerInfo = circuitPeerInfos[0]
// const gatewayAddress = linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0])

// const channel = new TlsChannelConnection()
// await channel.connect(gatewayAddress)
// const circuit = new Circuit({
//   path: circuitPeerInfos,
//   channel,
// })

export * as chutney from './build-circuit/chutney'
// export * as messaging from './messaging'
// export * as circuit from './circuit'
// export * as channel from './channel'
export { Circuit } from './circuit'
export { TlsChannelConnection } from './channel'