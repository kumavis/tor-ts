// import net from 'net'

// export class TcpServer {
//   private server: net.Server
//   _onData: (data: Buffer) => void

//   constructor({ onData }: { onData: (data: Buffer) => void }) {
//     this.server = net.createServer()
//     this._onData = onData
//   }

//   public start(port: number) {
//     this.server.listen(port, () => {
//       console.log(`Server started and listening on port ${port}`)
//     })

//     this.server.on('connection', (socket) => {
//       this.
//       console.log('New client connected')
      
//       // When we receive data, we can also write data back to the client.
//       socket.on('data', (data) => {
//         console.log(`Received data: ${data}`)
//         const reply = 'Server reply: ' + data
//         console.log(`Sending reply: ${reply}`)
//         socket.write(reply)
//       })

//       socket.on('end', () => {
//         console.log('Client disconnected')
//       })
//     })
//   }

//   public write() {
//     socket.write(reply)
//   }
// }

// const tcpServer = new TcpServer()
// tcpServer.start(8000)