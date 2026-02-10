use crate::ipc_vlq::{vlq_decode_reader, vlq_encode};

const PAYLOAD_LENGTH_LIMIT: u64 = 4 * 1024 * 1024;

/// A struct representing a request packet in IPC.
pub struct RequestPacket {
    version: u8,
    method_id: u64,
    payload: Vec<u8>,
}

impl RequestPacket {
    /// Creates a new instance of RequestPacket.
    pub fn new(version: u8, method_id: u64, payload: Vec<u8>) -> Self {
        Self { version, method_id, payload }
    }

    /// Serializes the packet into a vector of bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&vlq_encode(self.version as u64));
        buf.extend_from_slice(&vlq_encode(self.method_id));
        buf.extend_from_slice(&vlq_encode(self.payload.len() as u64));
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// A struct representing a response packet in IPC.
pub struct ResponsePacket {
    version: u8,
    error_code: u64,
    payload: Vec<u8>,
}

impl ResponsePacket {
    /// Returns the version number of the packet.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the error code of the packet.
    pub fn error_code(&self) -> u64 {
        self.error_code
    }

    /// Returns a reference to the payload of the packet.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Reads a response packet from a reader.
    pub fn read_from<R: std::io::Read>(reader: &mut R) -> Result<Self, String> {
        let version = vlq_decode_reader(reader)? as u8;
        let error_code = vlq_decode_reader(reader)?;
        let payload_length = vlq_decode_reader(reader)?;
        if payload_length > PAYLOAD_LENGTH_LIMIT {
            return Err("Payload exceeds limit".to_string());
        }
        let mut payload = vec![0u8; payload_length as usize];
        reader.read_exact(&mut payload[..]).map_err(|e| e.to_string())?;
        Ok(ResponsePacket { version, error_code, payload })
    }
}
