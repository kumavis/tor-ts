# TamanegiBrowser

A static website that uses Snowflake to browse web pages through Tor entirely in the browser. ("Tamanegi" 🧅 is Japanese for "onion")

## Features

- **Pure Browser Implementation**: No server-side component required
- **Snowflake Transport**: Uses WebSocket-based Snowflake pluggable transport
- **3-Hop Tor Circuit**: Builds a proper Tor circuit through entry, middle, and exit nodes
- **Visual Circuit Display**: Shows the path your traffic takes through the Tor network
- **Live Connection Log**: Real-time status updates during connection and fetching

## How It Works

1. **Snowflake Connection**: Connects to the Tor network via a Snowflake WebSocket relay
2. **TLS 1.3**: Uses @reclaimprotocol/tls for TLS 1.3 encryption in the browser
3. **Circuit Building**: Extends the circuit through randomly selected middle and exit nodes
4. **HTTP Fetching**: Constructs raw HTTP/1.1 requests over the Tor circuit
5. **Content Display**: Injects fetched HTML into an iframe using `srcdoc`

## Limitations

- **External Resources**: Images, CSS, and JavaScript from external sources won't load automatically (they would need additional Tor fetches)
- **JavaScript Execution**: Dynamic page content that requires JavaScript may not work correctly
- **CORS/CSP**: Some pages may have restrictions that prevent proper display
- **Performance**: Tor routing adds latency; expect slower page loads

## Development

```bash
# Install dependencies (from repo root)
yarn install

# Start development server
cd examples/tamanegi-browser
yarn dev
```

The development server will start at `http://localhost:3000`.

## Protocol Stack

This browser composes an in-process, 100% TypeScript implementation of every
layer between the browser tab and a Tor guard relay. Nothing runs in a native
binary: there is no `tor`, no `snowflake-client`, no `obfs4proxy`. The full
stack, top to bottom:

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

Canonical references for each layer (also mirrored locally under
`/tmp/canonical/` while debugging):

| Layer                        | Canonical impl                                                                | Language |
|------------------------------|-------------------------------------------------------------------------------|----------|
| WebSocket carrier            | `tpo/anti-censorship/pluggable-transports/snowflake` (`client/lib/webrtc.go`) | Go       |
| Turbotunnel preamble         | `snowflake/common/turbotunnel`                                                | Go       |
| Encapsulation (d/pad frames) | `snowflake/common/encapsulation`                                              | Go       |
| KCP reliable-over-packet     | `xtaci/kcp-go` (`kcp.go`, `sess.go`)                                          | Go       |
| SMUX v2 multiplexer          | `xtaci/smux`                                                                  | Go       |
| Tor link protocol (channel)  | `tor` (C ref impl, `src/core/or/`); `arti/tor-proto`                          | C / Rust |
| Tor circuit / relay cells    | `tor` (`src/core/or/relay.c`); `arti/tor-proto/src/circuit.rs`                | C / Rust |

Arti does **not** implement Snowflake in-process; when you use it with
`Bridge ... snowflake ...` lines, `tor-ptmgr` spawns the Go
`snowflake-client` as an external process per the PT v2.1 spec. That means
the Go Snowflake stack is the *only* reference implementation — both C-Tor
and Rust-Arti defer to it. This TS tree is, as far as we know, the second
implementation anywhere of the client-side Snowflake stack.

### How a byte travels (bottom up)

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
   Tor v3–v5 link protocol: `VERSIONS`, `CERTS`,
   `AUTH_CHALLENGE`, `NETINFO`, then `CELL`/`VARCELL` framing with the
   chosen `CIRC_ID_LEN`. Link-level netflow padding (per
   padding-spec.md §2) is scheduled on `U[1500,9500] ms` idle windows.
8. **Tor CIRCUIT + RELAY (`packages/tor/circuit.ts`, `relay-cell.ts`).**
   `CREATE2` (ntor) with the guard; then zero or more `EXTEND2` hops;
   once built, each byte of TLS-tunnelled HTTP is a
   `RELAY_BEGIN` / `RELAY_DATA` / `RELAY_END` payload, onion-encrypted
   outbound hop-by-hop. During bootstrap the client opens a 1-hop
   circuit just to the guard and issues a directory `RELAY_BEGIN_DIR` to
   fetch the consensus microdesc flavor.

The flakiness we see — intermittent hangs with no error, often even during
the 1-hop consensus download — is almost certainly *not* in layers 6–8
(those are the same for every Tor client, and retrying usually works on
the same circuit/TLS state). It is almost certainly in our Snowflake
stack (layers 1–5), where this codebase is the *only* independent
implementation and diverges from the canonical Go in ways that matter the
moment a packet is dropped or a window closes.

## Canonical-diff findings (flakiness suspects)

The layers were compared against the Go canonical implementations. Each
finding below is a concrete divergence that can strand a Snowflake
session indefinitely with no visible error, matching the observed
symptom.

### 1. KCP has no retransmission (high-confidence root cause)

`kcp/session.ts` explicitly omits RTO, fast-retransmit, `snd_buf` flushing
and periodic `update()`:

> "This is *not* a full KCP implementation: it assumes no loss/reordering
> at the carrier layer and therefore omits retransmission logic."

Canonical behaviour (`kcp-go/sess.go:802`, `kcp.go:876-900`):
a `SystemTimedSched` ticker calls `kcp.flush(IKCP_FLUSH_FULL)` every
`interval` ms; segments stay in `snd_buf` and are resent on RTO expiry
or after `fastresend` duplicate ACKs. The KCP wire format carries `una`
so the peer can trim acknowledged segments.

Why that matters here even though WebSocket is TCP-reliable: the
**server** (`snowflake/common/turbotunnel/queuepacketconn.go`,
`consts.go:14`) receives KCP packets into a bounded channel of
`queueSize = 512`. When that queue is full — which is easy to hit during
a bulk transfer like the ~3.35 MB consensus microdesc — the server
**silently drops** the packet (`queuepacketconn.go:70`: `default: Restore`).
Canonical KCP recovers; our KCP does not. The `recvLoop` in
`smux/session.ts:77` blocks on `readExactly()` waiting for bytes that
will never arrive — exactly the "hang with no error" pattern. This is a
hard-stop for any non-trivial transfer and is the most likely primary
cause.

Fix direction: implement minimum-viable KCP with RTO + fast-retransmit,
or at least an `update()` ticker that retransmits `snd_buf` on a fixed
interval; alternatively advertise much more conservatively to the peer
so the 512-packet queue cannot overflow (see §3, §4).

### 2. SMUX has no write-side flow control (high-confidence)

`smux/session.ts:202-205`:

> "We currently *do not* block on peerWindow; we only track it."

The canonical `Stream.writeV2` (`smux/stream.go:533`) blocks on
`chUpdate`/`chWriterWakeup` whenever `numWritten − peerConsumed ≥
peerWindow`. With that interlock removed, our client will keep handing
`PSH` frames to KCP even after the server's 256 KiB per-stream buffer is
full; the server simply stops emitting `UPD`s and/or drops at the KCP
layer. Combined with finding §1 the stream then never recovers.

Fix direction: add an `await` on a `peerWindow` change channel in
`SmuxStream.write` before emitting each `PSH`.

### 3. SMUX has no keepalive / dead-session detection (high-confidence)

Canonical `smux/session.go:519-543`:
- sends a `cmdNOP` every `KeepAliveInterval` (snowflake client sets this
  leg to the default 10 s; `KeepAliveTimeout = 10 min` — see
  `client/lib/snowflake.go:394`);
- closes the session if no inbound frame arrived within the timeout and
  the bucket is non-empty (`sessionIsActive` CAS).

Our `SmuxSession` has no keepalive goroutine/interval timer at all. If
the KCP carrier silently stalls (e.g. §1 above, or a proxy dropping the
WS without a close frame), nothing ever fires — no error, no reconnect,
just a forever-pending `readExactly`.

Fix direction: add a setInterval that sends `NOP`, and a stale-session
timer that rejects the session if no frame arrived within
`KeepAliveTimeout`.

### 4. SMUX `UPD` flood amplifies KCP packet count

Canonical (`smux/stream.go:260-300`): `UPD` is only emitted when
`incr ≥ MaxStreamBuffer / 2`, or on the very first read. Our
`SmuxStream.readExactly / readSome` sends a `UPD` **on every read**
(`smux/session.ts:214-217`, unconditional `sendUpd()` whenever `out > 0`).

Each `UPD` is a 16-byte smux frame that becomes its own `PSH` in our
unreliable-KCP-without-coalescing path. During the consensus download
this is dozens of extra packets per relay-cell read, directly filling
the server's 512-packet queue from §1. Even without a retransmission
fix this change alone should substantially reduce hangs.

Fix direction: gate `sendUpd()` on `bytesReadSinceLastUpd ≥
maxStreamBuffer / 2 || numRead === bytesInThisCall`.

### 5. KCP stream-mode coalescing missing

Canonical (`kcp-go/kcp.go:383-413`) with `SetStreamMode(true)` appends
bytes to the last non-full segment in the send queue, so many small
writes become fewer MSS-sized segments. The Snowflake client sets
`SetStreamMode(true)` explicitly (`client/lib/snowflake.go:379`).

Our `MinimalKcpSession.write` always allocates a fresh PUSH segment per
call, even for 1-byte writes. Combined with §4 (UPD flood) and SMUX
frames landing as separate writes, we emit O(N) KCP segments where
canonical emits O(bytes / MSS). Same blast radius into the 512-packet
queue.

Fix direction: coalesce partial segments at the tail of `unacked`/send
queue when the caller writes less than `mss`.

### 6. KCP `una` / `wnd` ignored (window stays hardcoded)

Canonical consumers read the peer's `wnd` out of each segment to adjust
the sender's allowed window (`kcp.go:Input`). Our `inputPacket` reads
`seg.wnd` into the decoder struct but never acts on it, and never
advances sender state from incoming `seg.una`. That means we never
respect the server's congestion signal either, compounding §1/§2.

Fix direction: once §1 exists, wire `peerRwnd = seg.wnd` and gate
new-segment emission on `sendSn − peerUna < min(snd_wnd, peerRwnd)`.

### 7. Turbotunnel preamble lacks the canonical random padding

Canonical (`client/lib/snowflake.go:350-361`):

```go
// Calculate padding size between 1900-2099 bytes
paddingSize := 1900 + (int(randomByte[0]) % 200)
_, err = encapsulation.WritePadding(buf, paddingSize)
```

This padding hides the fixed 16-byte `Token+ClientID` signature that
would otherwise fingerprint every new Snowflake session at the network
level. Our `buildTurbotunnelPreamble` writes just the 16 bytes.

This alone does not cause hangs but is a fingerprinting regression
worth fixing.

### 8. KCP `conv` picked with `crypto.randomBytes(4).readUInt32LE`

Minor, but worth noting: canonical `kcp.NewConn2` uses
`crypto/rand.Read` too — ours matches. However we never swap carriers
so the `conv` could also be derived deterministically. Leave as-is.

### 9. `SmuxStreamDuplex` read loop has no cancellation signal

`packages/browser/src/shims/smux-duplex.ts:27-46` loops on
`await this.smux.readSome(16384)`. If the smux stream stalls for §1–§4
reasons, this loop *cannot* observe a timeout or an inbound-close event
— it is suspended on the ByteQueue promise forever. The TLS socket sits
above this awaiting `data`, and reclaim-tls has no handshake timeout of
its own. End result: browser UI shows "Connecting…" indefinitely.

Fix direction: expose a `close()`/`destroy()` on `SmuxStream` that
rejects the pending `waitForAtLeast` promise; have `destroy()`
propagate up through the duplex.

### 10. TLS write queue swallows errors silently

`shims/tls.ts:207-220`: writes are serialised through
`this.writeQueue.then(...)`; any rejection is caught and emitted as
`'error'`. If the underlying SMUX duplex is backpressured *and* stalled
(see §9), the writeQueue never progresses — no error, no rejection — and
every subsequent `socket.write(...)` just appends to a dead chain.

This amplifies the silent-hang symptom but is not a root cause on its
own.

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
  `KeepalivePeriod` per padding-spec.md — this is not the flaky layer.

### Priority of fixes

If you only fix one thing, fix §1 (KCP retransmission) — every other
item becomes soft/non-blocking once packet loss is recoverable. If you
fix two, add §3 (smux keepalive/timeout) so even unrecoverable stalls
surface as an error instead of a silent hang. §2 and §4 are cheap wins
that reduce the rate at which we trigger §1 in the first place.

## Security Notes

- This is a proof-of-concept/educational tool
- Certificate validation is relaxed for compatibility
- The Tor circuit provides anonymity for your browsing
- External resources not loaded through Tor may leak information
