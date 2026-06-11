//! Content-hash keys and vector math for the semantic index.
//!
//! The key recipes are byte-for-byte compatible with the localizer prototype
//! (`localize_sft_core.py`: `component_key` / `composed_vector_key`): keys are
//! sha256 digests, and the composed-key payload embeds the child/parent keys as
//! urlsafe base64 (no padding) of their digests, exactly like the prototype's
//! `sha256_b64` strings.

use sha2::{Digest, Sha256};

use super::{COMPONENT_CONTRACT_VERSION, PARENT_ALPHA, REPRESENTATION_KIND};

pub type Key = [u8; 32];

/// Key addressing `E(text)` for a single embedded text.
pub fn component_key(text: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Key addressing the parent-averaged composed vector for a chunk.
pub fn composed_key(child: &Key, parent: &Key) -> Key {
    let payload = format!(
        "{REPRESENTATION_KIND}\0{}\0{}\0alpha={PARENT_ALPHA}",
        b64_urlsafe_nopad(child),
        b64_urlsafe_nopad(parent),
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}

/// Hash of raw file bytes, used for change detection in the `files` table.
pub fn content_hash(bytes: &[u8]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// urlsafe base64 without padding, matching python's
/// `base64.urlsafe_b64encode(digest).rstrip("=")`.
fn b64_urlsafe_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        }
    }
    out
}

/// L2-normalize in place; vectors of zero norm are left untouched.
pub fn l2_normalize(vector: &mut [f32]) {
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in vector.iter_mut() {
            *v /= norm;
        }
    }
}

/// `l2_normalize(alpha*child + (1-alpha)*parent)` with alpha = PARENT_ALPHA.
pub fn compose(child: &[f32], parent: &[f32]) -> Vec<f32> {
    debug_assert_eq!(child.len(), parent.len());
    let alpha = PARENT_ALPHA as f32;
    let mut composed: Vec<f32> = child
        .iter()
        .zip(parent)
        .map(|(c, p)| alpha * c + (1.0 - alpha) * p)
        .collect();
    l2_normalize(&mut composed);
    composed
}

/// Inner product; on L2-normalized vectors this is cosine similarity.
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Little-endian f32 encoding for the sqlite vector BLOB columns.
pub fn vector_to_blob(vector: &[f32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(vector.len() * 4);
    for v in vector {
        blob.extend_from_slice(&v.to_le_bytes());
    }
    blob
}

pub fn blob_to_vector(blob: &[u8]) -> Vec<f32> {
    blob.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(key: &Key) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Golden values computed with the prototype's python recipe:
    //   component_key("hello world"), component_key("parent text"),
    //   composed_vector_key(child, parent, alpha=0.5)
    #[test]
    fn component_key_matches_prototype() {
        assert_eq!(
            hex(&component_key("hello world")),
            "be4ea5527990dc8a01f1a738400ab73b898dac380f03c028d7eaeb59a37c132d"
        );
    }

    #[test]
    fn composed_key_matches_prototype() {
        let child = component_key("hello world");
        let parent = component_key("parent text");
        assert_eq!(
            hex(&composed_key(&child, &parent)),
            "c5c9daee54eaa32349472196cad2865a4e9a8dfc562000a2f2581bf5a834f103"
        );
    }

    #[test]
    fn b64_matches_python_urlsafe_nopad() {
        let child = component_key("hello world");
        assert_eq!(
            b64_urlsafe_nopad(&child),
            "vk6lUnmQ3IoB8ac4QAq3O4mNrDgPA8Ao1-rrWaN8Ey0"
        );
    }

    #[test]
    fn compose_averages_and_normalizes() {
        let composed = compose(&[1.0, 0.0], &[0.0, 1.0]);
        let expected = 1.0 / 2.0_f32.sqrt();
        assert!((composed[0] - expected).abs() < 1e-6);
        assert!((composed[1] - expected).abs() < 1e-6);
        assert!((dot(&composed, &composed) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn blob_round_trip() {
        let vector = vec![0.25_f32, -1.5, 3.75, f32::MIN_POSITIVE];
        assert_eq!(blob_to_vector(&vector_to_blob(&vector)), vector);
    }

    #[test]
    fn l2_normalize_handles_zero_vector() {
        let mut zero = vec![0.0_f32; 4];
        l2_normalize(&mut zero);
        assert_eq!(zero, vec![0.0; 4]);
    }
}
