# browser

Browser-side glue for `tor-ts`: composes the Snowflake transport and the Tor
client into an in-process, 100% TypeScript stack that runs entirely in a tab
or service worker. This package is what the `tamanegi-browser` example sits on
top of.

Nothing here runs in a native binary: there is no `tor`, no `snowflake-client`,
no `obfs4proxy`. Everything happens inside JavaScript, which is what makes the
implementation interesting — and what makes it the second known client-side
implementation of the Snowflake stack anywhere (the canonical Go client is
the first; Arti shells out to it via PT v2.1).

## Protocol stack

```
┌─────────────────────────────────────────────────────────────────────────┐
│ tab / service worker                                                     │
│   app code (fetch URL → display HTML)                                    │
│     └─ HTTP/1.1                             packages/browser/http-fetch  │
│         └─ Tor RELAY_DATA cells             packages/tor/relay-cell      │
│             └─ Tor circuit (ntor/RELAY)     packages/tor/circuit         │
│                 └─ Tor CHANNEL (CELL frame) packages/tor/channel         │
│                     └─ TLS 1.3              packages/browser/shims/tls   │
│                         └─ SMUX v2 stream   packages/snowflake/smux      │
│                             └─ KCP session  packages/snowflake/kcp       │
│                                 └─ Snowflake encapsulation               │
│                                     └─ Turbotunnel preamble              │
│                                         └─ WebSocket (browser `ws`)      │
│                                             └─ TCP/TLS to Snowflake srv  │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                 wss://snowflake.torproject.net/  (Tor-operated relay)
                                     │
                                     ▼
                 guard/middle/exit relays inside the Tor network
```

Canonical references for each layer:

| Layer                        | Canonical impl                                                                | Language |
| ---------------------------- | ----------------------------------------------------------------------------- | -------- |
| WebSocket carrier            | `tpo/anti-censorship/pluggable-transports/snowflake` (`client/lib/webrtc.go`) | Go       |
| Turbotunnel preamble         | `snowflake/common/turbotunnel`                                                | Go       |
| Encapsulation (d/pad frames) | `snowflake/common/encapsulation`                                              | Go       |
| KCP reliable-over-packet     | `xtaci/kcp-go` (`kcp.go`, `sess.go`)                                          | Go       |
| SMUX v2 multiplexer          | `xtaci/smux`                                                                  | Go       |
| Tor link protocol (channel)  | `tor` (C ref impl, `src/core/or/`); `arti/tor-proto`                          | C / Rust |
| Tor circuit / relay cells    | `tor` (`src/core/or/relay.c`); `arti/tor-proto/src/circuit.rs`                | C / Rust |

Arti does **not** implement Snowflake in-process; when configured with
`Bridge ... snowflake ...` lines, `tor-ptmgr` spawns the Go
`snowflake-client` as an external process per the PT v2.1 spec. So the Go
Snowflake stack is the only reference implementation — both C-Tor and
Rust-Arti defer to it.

## How a byte travels (bottom up)

1. **WebSocket (`ws-downlink.ts`).** Single persistent
   `wss://snowflake.torproject.net/` connection. Binary frames only,
   `perMessageDeflate: false` (matches canonical). Each inbound WS message
   is fed to `EncapsulationDecoder.push()`; each outbound KCP packet is
   wrapped with `encodeEncapsulatedData()` and sent as one WS frame.
2. **Turbotunnel preamble (`turbotunnel.ts`).** The very first bytes on the
   WS are the 8-byte magic token `0x1293605d278175f5` followed by an 8-byte
   random `ClientID`. This opts the server (`snowflake/server/lib/http.go`,
   `turbotunnelMode`) into long-lived session mode, where every subsequent
   byte is an encapsulation frame carrying KCP datagrams. The `ClientID`
   keys the server's `QueuePacketConn` so packets survive reconnects.
3. **Encapsulation (`encapsulation.ts`).** Variable-length prefix
   (`10xxxxxx` / `11xxxxxx 0yyyyyyy` / `11xxxxxx 1yyyyyyy 0zzzzzzz`)
   where the `d` bit distinguishes data chunks (1) from padding (0). Max
   payload 0xfffff = 1 048 575 bytes. Each chunk carries exactly one KCP
   packet. The decoder silently skips padding chunks.
4. **KCP (`kcp/session.ts`, `kcp/segment.ts`).** KCP is a reliable,
   ARQ-style protocol originally built to run over UDP. Snowflake uses it
   so that a session survives losing/swapping the underlying packet
   carrier (in stock Snowflake the carrier is a short-lived WebRTC
   DataChannel; here it is a single long-lived WebSocket). Each 24-byte
   segment header carries `conv` (session id), `cmd`
   (`PUSH`/`ACK`/`WASK`/`WINS`), `sn`, `una`, `wnd`, `ts`. Multiple
   segments can be concatenated into one KCP "packet" and those get
   wrapped in one encapsulation frame.
5. **SMUX v2 (`smux/session.ts`, `smux/protocol.ts`).** An 8-byte-header
   multiplexer layered on top of the KCP byte stream. Commands: `SYN`
   (0), `FIN` (1), `PSH` (2), `NOP` (3), `UPD` (4). v2 adds credit-based
   flow control: each stream has a 256 KiB initial receive window; peers
   emit `UPD(consumed, window)` frames to slide the sender's permitted
   `numWritten − peerConsumed` window.
6. **TLS 1.3 (`shims/tls.ts`).** `@reclaimprotocol/tls` over the SMUX
   stream (wrapped as a Node-style `Duplex` by `shims/smux-duplex.ts`).
   Tor relays are self-signed: `rejectUnauthorized: false` is intentional;
   identity is verified later by the Tor CERTS cell. SNI is randomized
   (`www.<hex>.net`) to resist fingerprinting.
7. **Tor CHANNEL (`packages/tor/channel.ts`).** Inside TLS we speak the
   Tor v3–v5 link protocol: `VERSIONS`, `CERTS`, `AUTH_CHALLENGE`,
   `NETINFO`, then `CELL`/`VARCELL` framing with the chosen `CIRC_ID_LEN`.
   Link-level netflow padding (per padding-spec.md §2) is scheduled on
   `U[1500,9500] ms` idle windows.
8. **Tor CIRCUIT + RELAY (`packages/tor/circuit.ts`, `relay-cell.ts`).**
   `CREATE2` (ntor) with the guard; then zero or more `EXTEND2` hops;
   once built, each byte of TLS-tunnelled HTTP is a
   `RELAY_BEGIN` / `RELAY_DATA` / `RELAY_END` payload, onion-encrypted
   outbound hop-by-hop. During bootstrap the client opens a 1-hop
   circuit just to the guard and issues a directory `RELAY_BEGIN_DIR` to
   fetch the consensus microdesc flavor.

## Canonical-diff findings

Earlier versions of this stack had a class of intermittent hangs with no
error — most often during the 1-hop consensus download. Layers 6–8 are
the same for every Tor client; the divergences were almost all in the
Snowflake stack (layers 1–5). The findings below are the concrete
divergences against the Go canonical implementation that were addressed.

### 1. KCP retransmission

The previous KCP implementation explicitly omitted RTO, fast-retransmit,
`snd_buf` flushing and periodic `update()`, on the assumption that the
WebSocket carrier was lossless.

That assumption does not hold end-to-end: the **server**
(`snowflake/common/turbotunnel/queuepacketconn.go`, `consts.go:14`) receives
KCP packets into a bounded channel of `queueSize = 512`. When that queue is
full — easy to hit during the ~3.35 MB consensus microdesc download — the
server **silently drops** the packet (`queuepacketconn.go:70`:
`default: Restore`). Canonical KCP recovers; the original implementation
did not. The `recvLoop` in `smux/session.ts` would block on
`readExactly()` waiting for bytes that would never arrive — exactly the
"hang with no error" pattern.

Status: fixed. `MinimalKcpSession` now holds segments in `sndBuf`,
runs a periodic `update()` flush, and retransmits on RTO expiry.

### 2. SMUX write-side flow control

The canonical `Stream.writeV2` (`smux/stream.go:533`) blocks on
`chUpdate`/`chWriterWakeup` whenever
`numWritten − peerConsumed ≥ peerWindow`. Without that interlock the
client would keep handing `PSH` frames to KCP even after the server's
256 KiB per-stream buffer was full.

Status: fixed. `SmuxStream.write` now waits on the peer-window credit
before emitting each `PSH`.

### 3. SMUX keepalive / dead-session detection

Canonical `smux/session.go:519-543` sends a `cmdNOP` every
`KeepAliveInterval` and closes the session if no inbound frame arrived
within the timeout (snowflake client uses `KeepAliveInterval=10s`,
`KeepAliveTimeout=10min`).

Status: fixed. `SmuxSession` now runs a NOP keepalive timer and a
stale-session check.

### 4. SMUX `UPD` throttling

Canonical (`smux/stream.go:260-300`): `UPD` is only emitted when
`incr ≥ MaxStreamBuffer / 2`, or on the very first read. The previous
implementation sent a `UPD` on every read, which during the consensus
download became dozens of extra packets per relay-cell read.

Status: fixed. `UPD` is now gated on the canonical threshold.

### 5. KCP stream-mode coalescing

Canonical (`kcp-go/kcp.go:383-413`) with `SetStreamMode(true)` appends
bytes to the last non-full segment in the send queue, so many small
writes become fewer MSS-sized segments.

Status: fixed. `MinimalKcpSession.write` coalesces consecutive writes
within the same microtask batch into MSS-sized PUSH segments.

### 6. KCP `una` advancement

Canonical consumers advance sender state from `seg.una` on every
incoming segment (not only on explicit ACKs). The original code only
processed explicit ACK commands.

Status: fixed. `inputPacket` now calls `advancePeerUna(seg.una)` for
every segment regardless of `cmd`.

### 7. Turbotunnel preamble random padding

Canonical (`client/lib/snowflake.go:350-361`) appends 1900–2099 bytes
of encapsulation-padding after the 16-byte `Token+ClientID` so the
fixed signature isn't trivially fingerprintable on the wire.

Status: open. Not a hang cause; tracked as a fingerprinting
regression.

### Layers that look correct

- `encapsulation.ts` matches the Go reference bit-for-bit (data/padding
  bits, 1/2/3-byte length prefixes, max 0xfffff). Spec-tests cover it.
- `turbotunnel.ts` token and ClientID length (8/8) match.
- KCP segment codec: header size 24, field widths and endianness match
  `kcp-go/kcp.go` packing.
- SMUX frame codec: 8-byte header, little-endian `len/sid`, command ids
  match `smux/frame.go`.
- Tor link layer (`packages/tor/channel.ts`) implements netflow padding
  with the canonical `U[NF_ITO_LOW, NF_ITO_HIGH]` distribution and
  `KeepalivePeriod` per padding-spec.md.
