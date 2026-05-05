//! Per-language analysis epoch.
//!
//! The epoch is a stable fingerprint of every input that, if changed, would
//! invalidate previously-persisted analyzer payloads. It folds in:
//!
//! - the analyzer payload wire-format version (see `payload::PAYLOAD_VERSION`)
//! - the analyzer crate version (`CARGO_PKG_VERSION`)
//! - the language adapter's actual `tree_sitter::Language` fingerprint
//!   (ABI version + every node kind name + every field name)
//! - the contents of the language's bundled `.scm` query files
//!
//! When any of these change, every row written under the previous epoch is
//! treated as logically dirty regardless of mtime/size.
//!
//! The grammar fingerprint is taken from the live `Language` rather than a
//! hard-coded crate version literal: Cargo.toml uses semver ranges, so a
//! patch update to a tree-sitter-X grammar can change parser behavior
//! (and node tables) without changing the version literal we type here.
//! Hashing the live `Language` makes the epoch follow the parser instead.

use crate::analyzer::Language;
use crate::analyzer::persistence::payload::PAYLOAD_VERSION;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tree_sitter::Language as TsLanguage;

const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the analysis epoch for a language as a hex string.
///
/// `ts_language` is the language adapter's parser; the per-language
/// `OnceLock` caches the resulting hash, so callers must always pass the
/// canonical parser for `language` (every `LanguageAdapter` already does).
pub(crate) fn epoch_for(language: Language, ts_language: &TsLanguage) -> &'static str {
    match language {
        Language::Java => epoch_cell::<Java>(ts_language),
        Language::Go => epoch_cell::<Go>(ts_language),
        Language::Cpp => epoch_cell::<Cpp>(ts_language),
        Language::JavaScript => epoch_cell::<JavaScript>(ts_language),
        Language::TypeScript => epoch_cell::<TypeScript>(ts_language),
        Language::Python => epoch_cell::<Python>(ts_language),
        Language::Rust => epoch_cell::<Rust>(ts_language),
        Language::Php => epoch_cell::<Php>(ts_language),
        Language::Scala => epoch_cell::<Scala>(ts_language),
        Language::CSharp => epoch_cell::<CSharp>(ts_language),
        Language::None => "",
    }
}

trait LanguageEpoch {
    const NAME: &'static str;
    const QUERY_DIR: &'static str;
    fn cell() -> &'static OnceLock<String>;
}

fn epoch_cell<L: LanguageEpoch>(ts_language: &TsLanguage) -> &'static str {
    L::cell().get_or_init(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost-analyzer-epoch-v1\n");
        hasher.update(ANALYZER_VERSION.as_bytes());
        hasher.update(b"\n");
        hasher.update(PAYLOAD_VERSION.to_le_bytes());
        hasher.update(b"\n");
        hasher.update(L::NAME.as_bytes());
        hasher.update(b"\n");
        hash_grammar(&mut hasher, ts_language);
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

/// Fingerprint a `tree_sitter::Language` so the epoch follows the
/// resolved grammar crate version, not a hand-edited literal. Any
/// node/field added or renamed by a grammar update changes this hash.
fn hash_grammar(hasher: &mut Sha256, lang: &TsLanguage) {
    hasher.update(b"abi:");
    hasher.update((lang.abi_version() as u64).to_le_bytes());

    let node_count = lang.node_kind_count();
    hasher.update(b"\nnodes:");
    hasher.update((node_count as u64).to_le_bytes());
    for id in 0..node_count {
        let id_u16 = id as u16;
        if let Some(name) = lang.node_kind_for_id(id_u16) {
            hasher.update(name.as_bytes());
        }
        hasher.update([if lang.node_kind_is_named(id_u16) {
            1u8
        } else {
            0u8
        }]);
        hasher.update(b"\0");
    }

    let field_count = lang.field_count();
    hasher.update(b"\nfields:");
    hasher.update((field_count as u64).to_le_bytes());
    // Field IDs are 1-indexed in tree-sitter; 0 is reserved for "no field".
    for id in 1..=field_count {
        if let Some(name) = lang.field_name_for_id(id as u16) {
            hasher.update(name.as_bytes());
        }
        hasher.update(b"\0");
    }
}

/// Compile-time embedded `.scm` query files. Each entry is `(relative_path,
/// contents)`. Adding/removing or editing a query file rebuilds the crate and
/// changes the per-language epoch.
const EMBEDDED_QUERIES: &[(&str, &str)] = &[
    // Java
    (
        "treesitter/java/definitions.scm",
        include_str!("../../../resources/treesitter/java/definitions.scm"),
    ),
    (
        "treesitter/java/imports.scm",
        include_str!("../../../resources/treesitter/java/imports.scm"),
    ),
    (
        "treesitter/java/identifiers.scm",
        include_str!("../../../resources/treesitter/java/identifiers.scm"),
    ),
    // Python
    (
        "treesitter/python/definitions.scm",
        include_str!("../../../resources/treesitter/python/definitions.scm"),
    ),
    (
        "treesitter/python/imports.scm",
        include_str!("../../../resources/treesitter/python/imports.scm"),
    ),
    (
        "treesitter/python/identifiers.scm",
        include_str!("../../../resources/treesitter/python/identifiers.scm"),
    ),
    // Go
    (
        "treesitter/go/definitions.scm",
        include_str!("../../../resources/treesitter/go/definitions.scm"),
    ),
    (
        "treesitter/go/imports.scm",
        include_str!("../../../resources/treesitter/go/imports.scm"),
    ),
    (
        "treesitter/go/identifiers.scm",
        include_str!("../../../resources/treesitter/go/identifiers.scm"),
    ),
    // Rust
    (
        "treesitter/rust/definitions.scm",
        include_str!("../../../resources/treesitter/rust/definitions.scm"),
    ),
    (
        "treesitter/rust/imports.scm",
        include_str!("../../../resources/treesitter/rust/imports.scm"),
    ),
    // JavaScript
    (
        "treesitter/javascript/definitions.scm",
        include_str!("../../../resources/treesitter/javascript/definitions.scm"),
    ),
    (
        "treesitter/javascript/imports.scm",
        include_str!("../../../resources/treesitter/javascript/imports.scm"),
    ),
    (
        "treesitter/javascript/identifiers.scm",
        include_str!("../../../resources/treesitter/javascript/identifiers.scm"),
    ),
    // TypeScript
    (
        "treesitter/typescript/definitions.scm",
        include_str!("../../../resources/treesitter/typescript/definitions.scm"),
    ),
    (
        "treesitter/typescript/imports.scm",
        include_str!("../../../resources/treesitter/typescript/imports.scm"),
    ),
    (
        "treesitter/typescript/identifiers.scm",
        include_str!("../../../resources/treesitter/typescript/identifiers.scm"),
    ),
    // C++
    (
        "treesitter/cpp/definitions.scm",
        include_str!("../../../resources/treesitter/cpp/definitions.scm"),
    ),
    (
        "treesitter/cpp/imports.scm",
        include_str!("../../../resources/treesitter/cpp/imports.scm"),
    ),
    (
        "treesitter/cpp/identifiers.scm",
        include_str!("../../../resources/treesitter/cpp/identifiers.scm"),
    ),
    // C#
    (
        "treesitter/c_sharp/definitions.scm",
        include_str!("../../../resources/treesitter/c_sharp/definitions.scm"),
    ),
    (
        "treesitter/c_sharp/imports.scm",
        include_str!("../../../resources/treesitter/c_sharp/imports.scm"),
    ),
    // PHP
    (
        "treesitter/php/definitions.scm",
        include_str!("../../../resources/treesitter/php/definitions.scm"),
    ),
    (
        "treesitter/php/imports.scm",
        include_str!("../../../resources/treesitter/php/imports.scm"),
    ),
    // Scala
    (
        "treesitter/scala/definitions.scm",
        include_str!("../../../resources/treesitter/scala/definitions.scm"),
    ),
    (
        "treesitter/scala/imports.scm",
        include_str!("../../../resources/treesitter/scala/imports.scm"),
    ),
];

macro_rules! lang_epoch {
    ($struct:ident, $name:literal, $dir:literal) => {
        struct $struct;
        impl LanguageEpoch for $struct {
            const NAME: &'static str = $name;
            const QUERY_DIR: &'static str = $dir;
            fn cell() -> &'static OnceLock<String> {
                static CELL: OnceLock<String> = OnceLock::new();
                &CELL
            }
        }
    };
}

lang_epoch!(Java, "java", "treesitter/java/");
lang_epoch!(Go, "go", "treesitter/go/");
lang_epoch!(Cpp, "cpp", "treesitter/cpp/");
lang_epoch!(JavaScript, "javascript", "treesitter/javascript/");
lang_epoch!(TypeScript, "typescript", "treesitter/typescript/");
lang_epoch!(Python, "python", "treesitter/python/");
lang_epoch!(Rust, "rust", "treesitter/rust/");
lang_epoch!(Php, "php", "treesitter/php/");
lang_epoch!(Scala, "scala", "treesitter/scala/");
lang_epoch!(CSharp, "csharp", "treesitter/c_sharp/");

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_python() -> TsLanguage {
        tree_sitter_python::LANGUAGE.into()
    }

    fn ts_go() -> TsLanguage {
        tree_sitter_go::LANGUAGE.into()
    }

    #[test]
    fn epoch_is_stable_across_calls() {
        let a = epoch_for(Language::Python, &ts_python());
        let b = epoch_for(Language::Python, &ts_python());
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn epochs_differ_per_language() {
        let py = epoch_for(Language::Python, &ts_python());
        let go = epoch_for(Language::Go, &ts_go());
        assert_ne!(py, go);
    }

    #[test]
    fn no_epoch_for_language_none() {
        assert_eq!(epoch_for(Language::None, &ts_python()), "");
    }
}
