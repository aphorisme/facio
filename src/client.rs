//! # Client
//!
//! Using the [`RawPacket`](../raw_packet/struct.RawPacket.html) as its underlying data model and a common
//! [`TcpStream`](https://doc.rust-lang.org/std/net/struct.TcpStream.html) from the
//! standard library, this part of the library implements a RCON client.
//!
//! As of now (which means: before `async/await` is stable), this client is
//! synchronous only. It is a future project to extend this to an async client,
//! whenever the feature hits stable.
//!
//! ## Example
//!
//! ```
//! use facio::{raw_packet::*, client::*};
//!
//! fn main() -> std::io::Result<()> {
//!    // open the rcon connection where `mypass` is the password and
//!    // echoing `echo` is used as the safe/check command (see below).
//!    // The last `None` denotes that the connection attempt has no timeout.
//!    let mut rcon =
//!        RconClient::open("127.0.0.1:38742",
//!                         "mypass",
//!                         Some("echo"),
//!                         None).expect("Cannot open rcon");
//!
//!    // now execute the command `/help`.
//!    if let Some(s) = rcon.exec("/help").ok() {
//!        println!("/help from server:\n{}", s);
//!    } else {
//!        println!("Error?");
//!    }
//! 
//! } // connection is closed here.
//! ```
//!
//! ## Safe/Check Command
//!
//! Since the protocol allows multi-packet response but does not provide any solution to
//! detect those, finding any response as beginning, part and end of a multi-packet response
//! is a bit tricky.
//!
//! The wiki on the protocol gives an idea (see [here](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Multiple-packet_Responses))
//! but to a full extend this is based on a specific implementation detail of the server. My experience with RCON server-side
//! implementations has shown that this is mostly not working.
//! Anyways, the basic idea seems to work throughout: an RCON server processes the requests
//! it got in the order they arrived. Also, the packet id of a request is used as the id of the
//! response to this very request. Insofar, to check if a response packet marks the end of a response,
//! with every sent request, there is right behind another request sent *of which it is sure that the
//! server responses* with exactly one packet.
//! 
//! This second request packet (the safe or check packet) is sent with a different id then the
//! actual request. By checking the response packet id it can be determined whether the received
//! packet is a response for the check request and therefore the packet before marks an end
//! to the original response, or it is still part of the response.
//!
//!  - send request packet (with normal id)
//!  - send check packet (with check id)
//!  - receive packet while id is not check id
//!  - when packet with check id is received, everything is received
//!      from the original request, where all packets with normal id
//!      belong to the original response.
//!
//! ## Authentication
//!
//! Authentication can become tricky as well, since some servers do not comply the protocol in every
//! detail. The protocol defines that following a `SERVERDATA_AUTH` packet, i.e. a auth request, the
//! server sends back an empty `SERVERDATA_RESPONSE_VALUE` packet, followed by a `SERVERDATA_AUTH_RESPONSE`
//! packet. Some servers do implement this in this way. Some just send a `SERVERDATA_AUTH_RESPONSE` back.
//! Authentication as provided by the `open` function supports both by checking the type of the received
//! packet.
//!
//! ## Using packet ids
//!
//! To solve the multi-packet response problem, packet ids are used in a certain way. This occupies the
//! packet ids; they are not longer visible from the outside of the higher-level abstraction
//! around `exec`.
//!
//! As a lower-level entry point which does not manage multi-packet responses but allows
//! for an own implementation, there is the [`ll`](../ll/index.html) module.

use super::ll::*;
use super::raw_packet::*;

use std::net::{SocketAddr};
use std::io;
use std::time::Duration;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;

const CONTROL_ID: i32 = -1; // used as the id for check packets
const START_ID: i32 = 0; // used as the id for normal packets


// The hole next section is kind of a hack. Some RCON Servers implement a double back response
// for an auth request. They send first a ResponseValue, then a ResponseAuth. Some servers just
// send a ResponseAuth.
// The recv_auth functions allows both ways.
//
// This might result in a blocking call, if the server just sends a ResponseValue without a follow-up.
enum AuthCheck {
    Invalid, NoAuth, Valid
}
fn check_auth(packet_id: i32, packet: &RawPacket) -> AuthCheck {
    if packet.response_type() == Some(PacketType::ResponseAuth) {
        if packet.pid == packet_id {
            AuthCheck::Valid
        } else {
            AuthCheck::Invalid
        }
    } else {
        AuthCheck::NoAuth
    }
}

fn recv_auth(stream: &mut TcpStream, packet_id: i32) -> io::Result<bool> {
    let response =
        recv_packet(stream)?;

    match check_auth(packet_id, &response) {
        AuthCheck::NoAuth => {
            let response_auth =
                recv_packet(stream)?;
            match check_auth(packet_id, &response_auth) {
                AuthCheck::NoAuth =>
                    Err(
                        Error::new(ErrorKind::Other,
                                   "No valid authentication protocol by server.")),
                AuthCheck::Invalid =>
                    Ok(false),
                AuthCheck::Valid =>
                    Ok(true),
            }
        },
        AuthCheck::Valid => Ok(true),
        AuthCheck::Invalid => Ok(false),
    } 
}


/// The basic type to connect to a RCON server
/// and execute commands.
///
/// It is certainly *not* safe to share this in concurrent
/// applications. There should always be only *one* thread at
/// a time which submits commands, etc.
pub struct RconClient {
    open_stream: TcpStream,
    //last_id: i32,
    /// The [`control_packet`] is used to determine wether the end of a possible
    /// multi-packet response is reached by sending it right after any submit of
    /// a command and reading back the response ids.
    ///
    /// It is important to have its [`pid`] always different then any possible [`last_id`].
    control_packet: RawPacket,
}
impl RconClient {
    /// Submits a command to the open RCON stream. Submit means, that
    /// it sends the package via stream, followed by the [`control_packet`],
    /// then waits for returning packets until a response packet with a
    /// packet id fitting the [`control_packet`] packet id is received.
    ///
    /// All packets inbetween are considered to be an answer to the provided
    /// [`RawPacket`] and their values are combined into one string. 
    pub fn exec<T: Into<String>>(&mut self, command: T) -> io::Result<String> {
        let command_id = START_ID;
        let packet =
            RawPacket::new_exec(command_id, command)
            .map_err(|e| e.to_io_error())?;

        send_packet(&mut self.open_stream, &packet)?; // send command
        send_packet(&mut self.open_stream, &self.control_packet)?; // send control_packet

        let mut response_str: String;
        let response =
            recv_packet(&mut self.open_stream)?;
        response_str = response.pbody;
        

        // recv responses while its not the response from the control_packet.
        while {
            let control =
                recv_packet(&mut self.open_stream)?;
            if control.pid != CONTROL_ID {
                response_str = response_str + &control.pbody;
                true
            } else {
                false
            }
        } {}

        //self.last_id = self.last_id + 1;

        Ok(response_str)

    }


    /// Opens up a connection to an RCON server by connection via TCP/IP and authenticated
    /// with provided `pass`.
    ///
    /// A `safe_command` can be specified which needs to be a domain-specific RCON command
    /// for which it is guaranteed to receive exactly one packet as an answer, i.e. it needs
    /// to be a command which has an *short* answer.
    ///
    /// If no `safe_command` is specified, the `SERVERDATA_RESPONSE_VALUE` trick is used, where
    /// after every command an empty `SERVERDATA_RESPONSE_VALUE` packet is sent to the server to
    /// trigger a `RESPONSE_VALUE` packet as a response and test for the end of command response.
    /// (See the [section](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Multiple-packet_Responses)
    /// in this issue there.)
    ///
    /// As a last parameter a `timeout` can be specified to let the function return with an error
    /// after a certain number of seconds while no connection can be established.
    pub fn open<A: Into<String>,
                P: Into<String>,
                C: Into<String>>(addr: A,
                                 pass: P,
                                 safe_command: Option<C>,
                                 timeout: Option<Duration>) -> io::Result<RconClient> {
        // building address:
        let s_addr: String = addr.into();
        let sock_addr: SocketAddr =
            s_addr.parse().map_err(|_|
                                   Error::new(ErrorKind::Other,
                                              format!("cannot parse internet address.")))?;
        // building package and data:
        let auth_packet =
            RawPacket::new(START_ID, 3, pass)
            .map_err(|e|
                     Error::new(ErrorKind::Other,
                                format!("auth packet creation error: '{}'", e)))?;

        println!("Connection to rcon server.");
        //connect:
        let mut stream = {
            if let Some(dur) = timeout {
                TcpStream::connect_timeout(&sock_addr, dur)?
            } else {
                TcpStream::connect(&sock_addr)?
            }
        };

        // sending auth 
        send_packet(&mut stream, &auth_packet)?;
        // ... and recv result:
        let auth =
            recv_auth(&mut stream, START_ID)?;
        // this ^^ function is somewhat a hack to satisfy sloppy(?) written servers.

        if auth {
            // either use the `safe_command` or the `RESPONSE_VALUE` trick.
            let control_packet = {
                if let Some(cmd) = safe_command {
                    RawPacket::new_exec(CONTROL_ID, cmd)
                        .map_err(|e| e.to_io_error())?
                } else {
                    RawPacket::new_response_value(CONTROL_ID, "")
                        .map_err(|e| e.to_io_error())?
                }
            };

            Ok( RconClient { open_stream: stream, control_packet })

        } else {
            Err(
                Error::new(ErrorKind::Other,
                           "Authentication failed. Wrong password."))
        }
    }
}
