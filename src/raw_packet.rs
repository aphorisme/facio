use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use std::io::{Write, Read, Error, ErrorKind};
use std::fmt;

/// Gives the underlying structure of a packet of any type.
/// There are serialization and deserialization functions
/// defined. No application level consistency is checked, besides
/// that the body cannot be larger then 4086 (which is 4096-10).
///
/// Within the spec, only ASCII is allowed where in this implementation
/// the body is of type `String` so generally UTF-8 is possible which the
/// server-side might not support when sticking to the protocol.
///
/// Entities of this type are introduced through the `new` functions; they
/// calculate a suitable `psize` according to the spec. The field `psize` is
/// kept private; this library treats it as an implementation detail provided
/// by the spec.
///
/// # Example
/// 
/// ```
/// use facio::raw_packet::*;
///
/// // create an auth packet with id `0` and `"mypass"` as password.
/// let auth_request_packet =
///    RawPacket::new_auth(0, "mypass").unwrap();
///
/// assert_eq!(auth_request_packet.pbody, "mypass");
/// assert_eq!(auth_request_packet.ptype, PacketType::RequestAuth.as_i32());
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct RawPacket {
    psize: i32,
    pub pid: i32,
    pub ptype: i32,
    pub pbody: String,
}

/// When creating a `RawPacket` consistency checks may apply
/// which may fail with a `RawPacketCreationError`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RawPacketCreationError {
    //NegativeID,
    BodyTooLarge,
}

impl fmt::Display for RawPacketCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
           // RawPacketCreationError::NegativeID => 
           //     write!(f, "Packet-ID is negative."),
            RawPacketCreationError::BodyTooLarge =>
                write!(f, "Provided body data is too large."),
        }
    }
}

impl std::error::Error for RawPacketCreationError {
    fn description(&self) -> &str {
        match self {
            RawPacketCreationError::BodyTooLarge =>
                "Provided body data is too large."
        }
    }
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

}


impl RawPacketCreationError {
    /// Converts the [`RawPacketCreationError`] to a [`std::io::Error`].
    pub fn to_io_error(&self) -> Error {
        Error::new(ErrorKind::InvalidData,
                   format!("Cannot create RawPacket: '{}'", self))
    }
}

impl RawPacket {
    /// Creates a new raw packet, which is consistent with the spec, expect
    /// for the type, which is allowed to be any number. In other words: this
    /// creates a `RawPacket` with a suitable `psize`.
    pub fn new<T: Into<String>>(id: i32,
                                raw_type: i32,
                                body: T) -> Result<RawPacket, RawPacketCreationError> {
        // get as a genuine string, what ever it was:
        let body_str : String = body.into();

        //*******************
        // CONSISTENCY CHECKS
        //*******************
        // check if the packet size is sufficient:
        let len = body_str.len() as i32;
        if len > 4086 {
            return Err(RawPacketCreationError::BodyTooLarge);
        }
        // CONSISTENCY CHECKS: END

        // calculate the size, according to protocol.
        let psize : i32 =
            len + 10;

        Ok(
            RawPacket {
                psize,
                pid: id,
                ptype: raw_type,
                pbody: body_str,
            })
    }

    /// Serialization according to the spec. This means:
    ///
    /// - Write `psize` as little endian `i32`.
    /// - Write `pid` as little endian `i32`.
    /// - Write `ptype` as little endian `i32`.
    /// - Write the body as null-terminated string.
    /// - Add another null to end the packet.
    ///
    /// Since `String` isn't null-terminated, this null is added manually
    /// after writing the body.
    pub fn serialize<T: Write>(&self, w: &mut T) -> std::io::Result<()> {
        w.write_i32::<LittleEndian>(self.psize)?;
        w.write_i32::<LittleEndian>(self.pid)?;
        w.write_i32::<LittleEndian>(self.ptype)?;

        // body needs to be null-terminated string.
        // Strings in rust aren't null-terminated.
        w.write(self.pbody.as_bytes())?; // write bytes
        w.write_u8(0)?; // write the null for this string

        // protocol wants another null afterwards.
        w.write_u8(0)?;

        w.flush()?;

        Ok(())
        
    }

    /// Deserialization according to the spec. See [`serialize`](struct.RawPacket.html#method.serialize).
    pub fn deserialize<T: Read>(r: &mut T) -> std::io::Result<RawPacket> {
        let psize = r.read_i32::<LittleEndian>()?;
        let pid = r.read_i32::<LittleEndian>()?;
        let ptype = r.read_i32::<LittleEndian>()?;

        // body size is the packet size
        // - 4 (id field)
        // - 4 (type field)
        // - 1 (terminating null of string)
        // - 1 (terminating null for packet)
        // = -10
        let body_length : usize = (psize as usize) - 10;
        let mut body_buffer = Vec::with_capacity(body_length);

        r.take(body_length as u64).read_to_end(&mut body_buffer)?;
        let pbody = String::from_utf8(body_buffer)
            .map_err(|e| Error::new(ErrorKind::Other,
                                    format!("Cannot from_utf8 on body_buffer: {}", e)))?;

        r.read_u8()?; // string null
        r.read_u8()?; // packet null

        let packet = 
            RawPacket::new(pid, ptype, pbody)
            .map_err(|e| e.to_io_error())?;

        Ok(packet)
    }

    /// Provides the base line for all convenience functions to create packets of a specific type
    /// using [`PacketType`](enum.PacketType.html).
    ///
    /// # Example
    ///
    /// ```
    /// use facio::raw_packet::*;
    ///
    /// // create with id as stated in spec
    /// let exec_packet_generic =
    ///      RawPacket::new(0, 2, "/version").unwrap();
    /// // create using the `PacketType` enum
    /// let exec_packet_ftype =
    ///      RawPacket::new_from_type(0, "/version", &PacketType::RequestExecCommand).unwrap();
    /// // create using the convenience function
    /// let exec_packet_conv =
    ///      RawPacket::new_exec(0, "/version").unwrap();
    ///
    /// assert_eq!(exec_packet_generic, exec_packet_ftype);
    /// assert_eq!(exec_packet_ftype, exec_packet_conv);
    /// // and hence by transitivity ... 
    /// ```
    pub fn new_from_type<T: Into<String>>(id: i32,
                                          raw_body: T,
                                          ptype: &PacketType) -> Result<RawPacket, RawPacketCreationError> {
        Self::new(id, ptype.as_i32(), raw_body)
    }

    pub fn new_auth<T: Into<String>>(id: i32, pass: T) -> Result<RawPacket, RawPacketCreationError> {
        Self::new_from_type(id, pass, &PacketType::RequestAuth)
    }

    pub fn new_exec<T: Into<String>>(id: i32, command: T) -> Result<RawPacket, RawPacketCreationError> {
        Self::new_from_type(id, command, &PacketType::RequestExecCommand)
    }

    pub fn new_response_auth<T: Into<String>>(id: i32, value: T) -> Result<RawPacket, RawPacketCreationError> {
        Self::new_from_type(id, value, &PacketType::ResponseAuth)
    }

    pub fn new_response_value<T: Into<String>>(id: i32, value: T) -> Result<RawPacket, RawPacketCreationError> {
        Self::new_from_type(id, value, &PacketType::ResponseValue)
    }

    /// Retrieves the `ptype` as a `PacketType`, where the packet is
    /// seen as a response. (See [`PacketType`](enum.PacketType.html) for more
    /// information.)
    pub fn response_type(&self) -> Option<PacketType> {
        PacketType::from_response_i32(self.ptype)
    }

    /// Retrieves the `ptype` as a `PacketType`, where the packet is seen as a
    /// request. 
    pub fn request_type(&self) -> Option<PacketType> {
        PacketType::from_request_i32(self.ptype)
    }
}


/// Defines the four basic types as stated in the protocol.
///
/// The protocol defines the types as names for certain values
/// of an `i32`. A difficulty arises here, since two different
/// packet types are given the same value: a `RESPONSE_AUTH` and a
/// `REQUEST_EXEC_COMMAND` are both given the value `2`. They can
/// be distinguished by interpreting them either as a response or a
/// request. This is what this library does.
#[derive(Eq, PartialEq, Debug)]
pub enum PacketType {
    ResponseAuth,
    ResponseValue,

    RequestAuth,
    RequestExecCommand,
}

impl PacketType {
    /// Encodes the `PacketType` into its `i32` form, as stated in the protocol.
    pub fn as_i32(&self) -> i32 {
        match self {
            PacketType::ResponseAuth => 2,
            PacketType::ResponseValue => 0,
            PacketType::RequestAuth => 3,
            PacketType::RequestExecCommand => 2,
        }
    }

    /// Decodes the `ptype` field of a `RawPacket` into a `PacketType`
    /// where the packet id in question is seen as an id from a response
    /// packet from a server.
    ///
    /// Fails with `None` if the provided `raw_id` cannot be decoded in any of
    /// the standard packet types.
    pub fn from_response_i32(raw_id: i32) -> Option<PacketType> {
        if raw_id == 0 {
            return Some(PacketType::ResponseValue);
        }

        if raw_id == 2 {
            return Some(PacketType::ResponseAuth);
        }
        None
    }

    /// En-pendant to `from_response_i32` but seeing the id as an id of a request
    /// packet to a server.
    pub fn from_request_i32(raw_id: i32) -> Option<PacketType> {
        if raw_id == 3 {
            return Some(PacketType::RequestAuth);
        }
        if raw_id == 2 {
            return Some(PacketType::RequestExecCommand);
        }
        None
    }
}
