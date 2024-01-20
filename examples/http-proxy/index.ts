import http from 'http'
import httpProxy from 'http-proxy'
import { Circuit } from '../../src/index'
import { getTorAgentForUrl, proxyCircuitStreamDuplex } from '../../src/node'
import { connectRandomCircuit } from '../../src/build-circuit/mainnet'

main()

async function main () {
  const circuit = await setupTor()
  setupCircuitProxyServer(circuit)
}

async function setupTor () {
  const circuit = await connectRandomCircuit()
  console.log('circuit established')
  return circuit
}

function setupCircuitProxyServer (circuit: Circuit) {
  const port = 1234;
  const proxy = new httpProxy.createProxyServer();

  const proxyHttpRequest = (req, res) => {
    const target = req.url;
    console.log(`Proxying HTTP request to: ${target}`);
    const agent = getTorAgentForUrl(circuit, target);
    // forward request to target and back
    proxy.web(req, res, { target, agent });
  }

  const proxyWsRequest = (req, socket, head) => {
    proxy.ws(req, socket, head);
  }

  const proxyHttpsRequest = (req, res) => {
    const target = req.url;
    console.log(`Proxying TCP connection to: ${target}`);
    const circuitStream = circuit.openStream(target);

    // forward request to target and back
    proxyCircuitStreamDuplex(circuitStream, res);
    // TODO: use this instead - but it doesnt seem to work for some reason
    // const duplexNodeStream = circuitStreamToNodeDuplex(circuitStream);
    // req
    // .pipe(duplexNodeStream)
    // .pipe(res);

    // manually respond with connect success
    res.write(
      'HTTP/1.1 200 Connection Established\r\n' +
      'Proxy-agent: Node.js-Proxy\r\n' +
      '\r\n'
    );

    process.on('SIGINT', () => {
      req.destroy();
    });
  }

  // HTTP: Setup our proxy server to proxy standard HTTP proxy requests
  const proxyServer = http.createServer(proxyHttpRequest);
  // HTTPS: proxy tcp circuit
  proxyServer.on('connect', proxyHttpsRequest);
  // WebSocket: Listen to the `upgrade` event and proxy the ws request
  proxyServer.on('upgrade', proxyWsRequest);

  proxyServer.listen(port, () => {
    console.log(`Server started and listening on port ${port}`);
  });

  process.on('SIGINT', () => {
    // close your server or any open resources here
    proxyServer.close(() => {
      console.log('Shut down gracefully');
      process.exit(0);
    });
  });

}
