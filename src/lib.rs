//! # facio - A RCON Library
//!
//! `facio` is meant to be a two-folded RCON library, implementing the RCON protocol
//! as stated in [Valvesoftware's RCON Protocol Spec](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol)
//! (which is called "protocol" or "spec" in the following) by providing a low-level packet type
//! [`RawPacket`](raw_packet/struct.RawPacket.html) and a higher-level client type [`RconClient`](client/struct.RconClient.html).
//!
//! The `RawPacket` type gives a wrapper around the packets sent through rcon connections
//! which can be also be used on the server-side of things.
//!
//! The `RconClient` type provides a higher-level entry point for building a RCON client.
//!
//! After all, there is low-level part in [`facio::ll`](ll/index.html) which provides low-level
//! functions to send and receive `RawPacket` via a `TcpStream`.

/// Wrapper around RCON packet byte structure
pub mod raw_packet;

/// High-Level RCON client
pub mod client;

/// Low-Level RCON network functions
pub mod ll;
