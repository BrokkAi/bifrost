//! Per-language analysis epoch.
//!
//! The epoch is a stable fingerprint of every input that, if changed, would
//! invalidate previously-persisted analyzer payloads. Today that means:
//!
//! - the analyzer payload wire-format version (see `payload::PAYLOAD_VERSION`)
//! - the analyzer crate version (`CARGO_PKG_VERSION`)
//! - the language's tree-sitter grammar crate version
//! - the contents of the language's bundled `.scm` query files
//!
//! When any of these change, every row written under the previous epoch is
//! treated as logically dirty regardless of mtime/size.

use crate::analyzer::Language;
use crate::analyzer::persistence::payload::PAYLOAD_VERSION;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the analysis epoch for a language as a hex string.
pub(crate) fn epoch_for(language: Language) -> &'static str {
    match language {
        Language::Java => epoch_cell::<Java>(),
        Language::Go => epoch_cell::<Go>(),
        Language::Cpp => epoch_cell::<Cpp>(),
        Language::JavaScript => epoch_cell::<JavaScript>(),
        Language::TypeScript => epoch_cell::<TypeScript>(),
        Language::Python => epoch_cell::<Python>(),
        Language::Rust => epoch_cell::<Rust>(),
        Language::Php => epoch_cell::<Php>(),
        Language::Scala => epoch_cell::<Scala>(),
        Language::CSharp => epoch_cell::<CSharp>(),
        Language::None => "",
    }
}

trait LanguageEpoch {
    const NAME: &'static str;
    const GRAMMAR_VERSION: &'static str;
    const QUERY_DIR: &'static str;
    fn cell() -> &'static OnceLock<String>;
}

fn epoch_cell<L: LanguageEpoch>() -> &'static str {
    L::cell().get_or_init(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost-analyzer-epoch-v1\n");
        hasher.update(ANALYZER_VERSION.as_bytes());
        hasher.update(b"\n");
        hasher.update(PAYLOAD_VERSION.to_le_bytes());
        hasher.update(b"\n");
        hasher.update(L::NAME.as_bytes());
        hasher.update(b"\n");
        hasher.update(L::GRAMMAR_VERSION.as_bytes());
        hasher.update(b"\n");
        for (path, contents) in EMBEDDED_QUERIES {
            if path.starts_with(L::QUERY_DIR) {
                hasher.update(path.as_bytes());
                hasher.update(b"\0");
                hasher.update(contents.as_bytes());
                hasher.update(b"\0");
            }
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    })
}

/// Compile-time embedded `.scm` query files. Each entry is `(relative_path,
/// contents)`. Adding/removing or editing a query file rebuilds the crate and
/// changes the per-language epoch.
const EMBEDDED_QUERIES: &[(&str, &str)] = &[
    // Java
    ("treesitter/java/definitions.scm", include_str!("../../../resources/treesitter/java/definitions.scm")),
    ("treesitter/java/imports.scm", include_str!("../../../resources/treesitter/java/imports.scm")),
    ("treesitter/java/identifiers.scm", include_str!("../../../resources/treesitter/java/identifiers.scm")),
    // Python
    ("treesitter/python/definitions.scm", include_str!("../../../resources/treesitter/python/definitions.scm")),
    ("treesitter/python/imports.scm", include_str!("../../../resources/treesitter/python/imports.scm")),
    ("treesitter/python/identifiers.scm", include_str!("../../../resources/treesitter/python/identifiers.scm")),
    // Go
    ("treesitter/go/definitions.scm", include_str!("../../../resources/treesitter/go/definitions.scm")),
    ("treesitter/go/imports.scm", include_str!("../../../resources/treesitter/go/imports.scm")),
    ("treesitter/go/identifiers.scm", include_str!("../../../resources/treesitter/go/identifiers.scm")),
    // Rust
    ("treesitter/rust/definitions.scm", include_str!("../../../resources/treesitter/rust/definitions.scm")),
    ("treesitter/rust/imports.scm", include_str!("../../../resources/treesitter/rust/imports.scm")),
    // JavaScript
    ("treesitter/javascript/definitions.scm", include_str!("../../../resources/treesitter/javascript/definitions.scm")),
    ("treesitter/javascript/imports.scm", include_str!("../../../resources/treesitter/javascript/imports.scm")),
    ("treesitter/javascript/identifiers.scm", include_str!("../../../resources/treesitter/javascript/identifiers.scm")),
    // TypeScript
    ("treesitter/typescript/definitions.scm", include_str!("../../../resources/treesitter/typescript/definitions.scm")),
    ("treesitter/typescript/imports.scm", include_str!("../../../resources/treesitter/typescript/imports.scm")),
    ("treesitter/typescript/identifiers.scm", include_str!("../../../resources/treesitter/typescript/identifiers.scm")),
    // C++
    ("treesitter/cpp/definitions.scm", include_str!("../../../resources/treesitter/cpp/definitions.scm")),
    ("treesitter/cpp/imports.scm", include_str!("../../../resources/treesitter/cpp/imports.scm")),
    ("treesitter/cpp/identifiers.scm", include_str!("../../../resources/treesitter/cpp/identifiers.scm")),
    // C#
    ("treesitter/c_sharp/definitions.scm", include_str!("../../../resources/treesitter/c_sharp/definitions.scm")),
    ("treesitter/c_sharp/imports.scm", include_str!("../../../resources/treesitter/c_sharp/imports.scm")),
    // PHP
    ("treesitter/php/definitions.scm", include_str!("../../../resources/treesitter/php/definitions.scm")),
    ("treesitter/php/imports.scm", include_str!("../../../resources/treesitter/php/imports.scm")),
    // Scala
    ("treesitter/scala/definitions.scm", include_str!("../../../resources/treesitter/scala/definitions.scm")),
    ("treesitter/scala/imports.scm", include_str!("../../../resources/treesitter/scala/imports.scm")),
];

macro_rules! lang_epoch {
    ($struct:ident, $name:literal, $version:literal, $dir:literal) => {
        struct $struct;
        impl LanguageEpoch for $struct {
            const NAME: &'static str = $name;
            const GRAMMAR_VERSION: &'static str = $version;
            const QUERY_DIR: &'static str = $dir;
            fn cell() -> &'static OnceLock<String> {
                static CELL: OnceLock<String> = OnceLock::new();
                &CELL
            }
        }
    };
}

lang_epoch!(Java, "java", "0.23.5", "treesitter/java/");
lang_epoch!(Go, "go", "0.25.0", "treesitter/go/");
lang_epoch!(Cpp, "cpp", "0.23.4", "treesitter/cpp/");
lang_epoch!(JavaScript, "javascript", "0.25.0", "treesitter/javascript/");
lang_epoch!(TypeScript, "typescript", "0.23.2", "treesitter/typescript/");
lang_epoch!(Python, "python", "0.25.0", "treesitter/python/");
lang_epoch!(Rust, "rust", "0.24.0", "treesitter/rust/");
lang_epoch!(Php, "php", "0.23.11", "treesitter/php/");
lang_epoch!(Scala, "scala", "0.25.0", "treesitter/scala/");
lang_epoch!(CSharp, "csharp", "0.23.1", "treesitter/c_sharp/");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_stable_across_calls() {
        let a = epoch_for(Language::Python);
        let b = epoch_for(Language::Python);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn epochs_differ_per_language() {
        let py = epoch_for(Language::Python);
        let go = epoch_for(Language::Go);
        assert_ne!(py, go);
    }

    #[test]
    fn no_epoch_for_language_none() {
        assert_eq!(epoch_for(Language::None), "");
    }
}
