use std::net::TcpStream;
use super::raw_packet::*;
use std::io;

/// Uses the `Write` of `TcpStream` to send a packet.
pub fn send_packet(stream: &mut TcpStream, packet: &RawPacket) -> io::Result<()> {
    packet.serialize(stream)
}

/// Uses the `Read` of `TcpStream` to receive a packet.
pub fn recv_packet(stream: &mut TcpStream) -> io::Result<RawPacket> {
    RawPacket::deserialize(stream)
}

