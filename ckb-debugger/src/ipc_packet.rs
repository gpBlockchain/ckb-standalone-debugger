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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_packet_serialize() {
        let req = RequestPacket::new(0, 1, b"hello".to_vec());
        let data = req.serialize();
        // version=0 (1 byte), method_id=1 (1 byte), payload_length=5 (1 byte), payload="hello" (5 bytes)
        assert_eq!(data.len(), 1 + 1 + 1 + 5);
    }

    #[test]
    fn test_response_packet_read_from() {
        // Construct a response packet manually:
        // version=0, error_code=0, payload_length=5, payload="world"
        let mut data = vec![];
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(0)); // version
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(0)); // error_code
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(5)); // payload_length
        data.extend_from_slice(b"world"); // payload

        let mut cursor = std::io::Cursor::new(data);
        let resp = ResponsePacket::read_from(&mut cursor).unwrap();
        assert_eq!(resp.version(), 0);
        assert_eq!(resp.error_code(), 0);
        assert_eq!(resp.payload(), b"world");
    }

    #[test]
    fn test_response_packet_roundtrip() {
        // Create a request packet, serialize it, then read it back as if it were a response
        // (they have the same format: version, id/code, payload)
        let req = RequestPacket::new(1, 42, b"test payload".to_vec());
        let serialized = req.serialize();

        // Read as response (version, error_code=method_id, payload)
        let mut cursor = std::io::Cursor::new(serialized);
        let resp = ResponsePacket::read_from(&mut cursor).unwrap();
        assert_eq!(resp.version(), 1);
        assert_eq!(resp.error_code(), 42);
        assert_eq!(resp.payload(), b"test payload");
    }

    #[test]
    fn test_response_packet_payload_limit() {
        let mut data = vec![];
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(0));
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(0));
        data.extend_from_slice(&crate::ipc_vlq::vlq_encode(5 * 1024 * 1024)); // exceeds 4MB limit

        let mut cursor = std::io::Cursor::new(data);
        assert!(ResponsePacket::read_from(&mut cursor).is_err());
    }
}
