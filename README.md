# facio -- rust RCON library

Small RCON client/lib written in rust, providing a RCON packet wrapper and a
higher-level RCON client type.

[![Crates.io][crates-badge]][crates-url]
[![Docs.io][docs-badge]][docs-url]


[docs-badge]: https://docs.rs/facio/badge.svg
[docs-url]: https://docs.rs/facio

[crates-badge]: https://img.shields.io/crates/v/facio.svg
[crates-url]: https://crates.io/crates/facio

## Client usage example

The client API is based on `TcpStream` from the standard library. It's main goal
is to provide easy to use functions. 

```
use facio::{raw_packet::*, client::*};
//!
fn main() -> std::io::Result<()> {
   // open the rcon connection where `mypass` is the password and
   // echoing `echo` is used as the safe/check command (see below).
   // The last `None` denotes that the connection attempt has no timeout.
   let mut rcon =
       RconClient::open("127.0.0.1:38742",
                        "mypass",
                        Some("echo"),
                        None).expect("Cannot open rcon");
//!
   // now execute the command `/help`.
   if let Some(s) = rcon.exec("/help").ok() {
       println!("/help from server:\n{}", s);
   } else {
       println!("Error?");
   }

} // connection is closed here.
```

## Further Development

This project was basically a small study on how to work with Rust. Future plans
involve making the client API async by using the `async/await` language
features, once they are stable.
