/// Encodes an integer using VLQ (Variable-Length Quantity) encoding.
pub fn vlq_encode(value: u64) -> Vec<u8> {
    let mut value = value;
    let mut buffer = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buffer.push(byte);
        if value == 0 {
            break;
        }
    }
    buffer
}

/// Decodes a VLQ (Variable-Length Quantity) encoded byte slice into an integer.
pub fn vlq_decode(bytes: &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0;
    for &byte in bytes {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err("VLQ decode overflow".to_string());
        }
    }
    Err("Incomplete VLQ sequence".to_string())
}

/// Decodes a VLQ (Variable-Length Quantity) number from a reader.
pub fn vlq_decode_reader(reader: &mut impl std::io::Read) -> Result<u64, String> {
    let mut peek = [0u8; 1];
    let mut buf = vec![];
    loop {
        let n = reader.read(&mut peek).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.push(peek[0]);
        if peek[0] & 0x80 == 0 {
            break;
        }
    }
    vlq_decode(&buf)
}
