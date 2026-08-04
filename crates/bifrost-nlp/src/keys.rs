//! Content-hash keys and vector math for the semantic index.

use sha2::{Digest, Sha256};

use super::DOCUMENT_CONTRACT_VERSION;

pub type Key = [u8; 32];

/// Key addressing the direct embedding of one canonical document.
pub fn document_key(text: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(DOCUMENT_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// L2-normalize in place; vectors of zero norm are left untouched.
pub fn l2_normalize(vector: &mut [f32]) {
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in vector.iter_mut() {
            *value /= norm;
        }
    }
}

/// Inner product; on L2-normalized vectors this is cosine similarity.
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(left, right)| left * right).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_key_is_stable_and_text_sensitive() {
        assert_eq!(document_key("hello world"), document_key("hello world"));
        assert_ne!(document_key("hello world"), document_key("hello world\n"));
    }

    #[test]
    fn l2_normalize_handles_zero_vector() {
        let mut zero = vec![0.0_f32; 4];
        l2_normalize(&mut zero);
        assert_eq!(zero, vec![0.0; 4]);
    }
}
