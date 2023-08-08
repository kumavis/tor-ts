import http from 'http'
import httpProxy from 'http-proxy'
import { Circuit, TlsChannelConnection } from '../../src/index'
import { getCircuitAgentForUrl, proxyCircuitStreamDuplex } from '../../src/node'
import { getRandomCircuitPath } from '../../src/build-circuit/mainnet'

main()

async function main () {
  const circuit = await setupTor()
  setupCircuitProxyServer(circuit)
}

async function setupTor () {
  // choose relays
  const circuitPeerInfos = await getRandomCircuitPath()
  const gatewayPeerInfo = circuitPeerInfos[0]
  const channel = new TlsChannelConnection()
  await channel.connectPeerInfo(gatewayPeerInfo)
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  })
  await circuit.connect()
  console.log('circuit established')
  return circuit
}

function setupCircuitProxyServer (circuit) {
  const port = 1234

  //
  // Setup our server to proxy standard HTTP requests
  //
  const proxy = new httpProxy.createProxyServer()
  const proxyServer = http.createServer(function (req, res) {
    const target = req.url
    console.log(`Proxying HTTP request to: ${target}`)
    const agent = getCircuitAgentForUrl(circuit, target, { skipTls: true })
    // forward request to target and back
    proxy.web(req, res, { target, agent })
  })

  //
  // Listen to the `upgrade` event and proxy the
  // WebSocket requests as well.
  //
  proxyServer.on('upgrade', function (req, socket, head) {
    proxy.ws(req, socket, head)
  })

  // Handle HTTPS traffic
  proxyServer.on('connect', (req, res, head) => {
    const target = req.url
    console.log(`Proxying TCP connection to: ${target}`)
    const circuitStream = circuit.openStream(target)

    // forward request to target and back
    proxyCircuitStreamDuplex(circuitStream, res)
    // TODO: use this instead - but it doesnt seem to work for some reason
    // const duplexNodeStream = circuitStreamToNodeDuplex(circuitStream)
    // req
    // .pipe(duplexNodeStream)
    // .pipe(res)

    // manually respond with connect success
    res.write(
      'HTTP/1.1 200 Connection Established\r\n' +
      'Proxy-agent: Node.js-Proxy\r\n' +
      '\r\n'
    )

    process.on('SIGINT', () => {
      req.destroy()
    })
  })

  proxyServer.listen(port, () => {
    console.log(`Server started and listening on port ${port}`)
  })


  process.on('SIGINT', () => {
    // close your server or any open resources here
    proxyServer.close(() => {
      console.log('Shut down gracefully')
      process.exit(0)
    })
  })

}
