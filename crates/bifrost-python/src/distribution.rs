//! Distribution metadata helpers. Import module identities are separate.

/// PEP 503 normalization collapses every run of '-', '_' and '.'.
pub fn normalize_distribution_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for ch in name.trim().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !normalized.ends_with('-') {
                normalized.push('-');
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
        }
    }
    normalized
}

pub fn metadata_header(metadata: &str, name: &str) -> Option<String> {
    metadata
        .lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.eq_ignore_ascii_case(name) && !value.trim().is_empty())
                .then(|| value.trim().to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distribution_normalization_and_metadata_body_boundary() {
        assert_eq!(normalize_distribution_name("Foo__...--Bar"), "foo-bar");
        assert_eq!(
            metadata_header("Name: Foo\nVersion: 1\n\nName: body\n", "name").as_deref(),
            Some("Foo")
        );
        assert!(metadata_header("Description: text\n\nVersion: 9\n", "Version").is_none());
    }
}
