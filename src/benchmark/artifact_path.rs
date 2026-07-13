use sha2::{Digest, Sha256};

pub(super) fn sanitize_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "repo".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn unique_component(value: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
    format!("{}-{}", sanitize_component(value), &digest[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_components_distinguish_lossy_sanitizer_collisions() {
        assert_eq!(sanitize_component("foo/bar"), sanitize_component("foo?bar"));
        assert_ne!(unique_component("foo/bar"), unique_component("foo?bar"));
    }

    #[test]
    fn sanitizer_has_a_nonempty_fallback() {
        assert_eq!(sanitize_component("///"), "repo");
    }
}
