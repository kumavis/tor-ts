cant parse the cert
maybe dont need to parse the cert?
marked as obsolete in arti

want to establish connection
sending my certs results in connection close
  why?
    maybe certs are bad (eg no ed25519)
    maybe response needs to include certs AND auth challenge response
    
could run a client and get it to log connection failures?

trying to read the arti source
https://gitlab.torproject.org/tpo/core/arti/-/blob/6703f3d52a7b4b55c91caabbd88c9dab13e01362/crates/tor-proto/src/channel/handshake.rs#L160

//! To launch a channel:
//!
//!  * Create a TLS connection as an object that implements AsyncRead
//!    + AsyncWrite, and pass it to a [ChannelBuilder].  This will
//!    yield an [handshake::OutboundClientHandshake] that represents
//!    the state of the handshake.
//!  * Call [handshake::OutboundClientHandshake::connect] on the result
//!    to negotiate the rest of the handshake.  This will verify
//!    syntactic correctness of the handshake, but not its cryptographic
//!    integrity.
//!  * Call [handshake::UnverifiedChannel::check] on the result.  This
//!    finishes the cryptographic checks.
//!  * Call [handshake::VerifiedChannel::finish] on the result. This
//!    completes the handshake and produces an open channel and Reactor.
//!  * Launch an asynchronous task to call the reactor's run() method.
//!


verify handshake
https://gitlab.torproject.org/tpo/core/arti/-/blob/6703f3d52a7b4b55c91caabbd88c9dab13e01362/crates/tor-proto/src/channel/handshake.rs#L351-564