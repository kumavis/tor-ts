import WebSocket from 'ws';
import { ChannelConnection } from './channel';

export class TlsChannelConnection extends ChannelConnection {
  socket?: WebSocket;

  // async connectPeerInfo (gatewayPeerInfo: PeerInfo, additonalOptions?: { localPort: number }) {
  async connectPeerInfo () {
    return this.connect(
      // linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0]),
      // additonalOptions
    )
  }

  // async connect (server: AddressAndPort, additonalOptions?: { localPort: number }) {
  async connect () {
    const socket = new WebSocket('wss://snowflake.torproject.net/', {
      // disable compression bc idk
      perMessageDeflate: false
    });
    // might not do anything in node
    socket.binaryType = 'arraybuffer';
    this.socket = socket;

    const socketReadyP = new Promise<void>((resolve) => {
      socket.on('open', resolve);
    });
    socket.on('message', (data) => {
      this.onData(data)
    });
    // socket.on('end',() => { console.log('end') });
    // socket.on('close',() => { console.log('close') });
    // socket.on('error', (err) => { console.log('error', err) });
    await socketReadyP;
    // perform handshake
    // this.peerConnectionDetails = {
    //   cert: socket.getPeerCertificate(true),
    //   addressInfo: socket.address() as NodejsPeerAddressInfo,
    // }
    await this.performHandshake()
  }

  sendData (data: Buffer) {
    // console.log(`> sending data (${data.length} bytes)`)
    if (!this.socket) {
      throw new Error('socket is undefined')
    }
    this.socket.send(data)
  }

  destroy(): void {
    super.destroy()
    this.socket?.destroy()
  }
}

// ws.on('error', console.error);

// ws.on('open', function open() {
//   console.log('connected');
//   // ws.send(Buffer.from(Array(1000).fill(0)));
// });

// ws.on('close', function close() {
//   console.log('closed');
// });

// ws.on('message', function message(data) {
//   console.log('received: %s', data);
// });

