use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use std::io::Read;

const COMPRESS_THRESHOLD: usize = 1024;

/// Serialize a GossipMessage to a serde_json::Value, compressing if large.
/// Small messages are sent as plain JSON; large ones as `{"z":"<base64>"}`.
pub fn compress_message(msg: &crate::network::messages::GossipMessage) -> anyhow::Result<serde_json::Value> {
    let json_bytes = serde_json::to_vec(msg)?;
    if json_bytes.len() < COMPRESS_THRESHOLD {
        return Ok(serde_json::from_slice(&json_bytes)?);
    }
    let mut encoder = ZlibEncoder::new(&json_bytes[..], Compression::best());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed)?;
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &compressed);
    tracing::debug!(
        "Compressed message: {} -> {} bytes ({:.0}%)",
        json_bytes.len(),
        compressed.len(),
        (compressed.len() as f64 / json_bytes.len() as f64) * 100.0
    );
    Ok(serde_json::json!({ "z": b64 }))
}

/// Decode a serde_json::Value back to a GossipMessage, decompressing if needed.
pub fn decompress_message(value: &serde_json::Value) -> anyhow::Result<crate::network::messages::GossipMessage> {
    if let Some(b64) = value.get("z").and_then(|v| v.as_str()) {
        let compressed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)?;
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut json_bytes = Vec::new();
        decoder.read_to_end(&mut json_bytes)?;
        Ok(serde_json::from_slice(&json_bytes)?)
    } else {
        Ok(serde_json::from_value(value.clone())?)
    }
}

/// Returns true if the value can be decoded as a (possibly compressed) GossipMessage.
pub fn is_valid_message(value: &serde_json::Value) -> bool {
    decompress_message(value).is_ok()
}
