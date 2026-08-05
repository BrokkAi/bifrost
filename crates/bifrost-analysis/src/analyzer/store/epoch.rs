//! Per-language analysis epoch.
//!
//! The epoch is a stable fingerprint of every input that, if changed, would
//! invalidate previously-persisted analyzer payloads. It folds in:
//!
//! - the analyzer store epoch salt
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
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::OnceLock;
use tree_sitter::Language as TsLanguage;

const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
// v7: `ImportInfo` gained `binder_span` (#1600), which changes the bincode
// layout of every persisted import row.
const STORE_EPOCH_SALT: &str = "analyzer-blob-store-v7-import-binder-span";

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
        Language::Ruby => epoch_cell::<Ruby>(ts_language),
        Language::Kotlin => epoch_cell::<Kotlin>(ts_language),
        Language::None => "",
    }
}

trait LanguageEpoch {
    const NAME: &'static str;
    const QUERY_DIR: &'static str;
    /// Manual per-language invalidation knob. Bump this when an analyzer code
    /// change alters a language's emitted identities (e.g. `fq_name`) without
    /// touching the grammar, queries, or wire format that the epoch otherwise
    /// tracks automatically. Empty for languages that have never needed it.
    const SALT: &'static str;
    fn cell() -> &'static OnceLock<String>;
}

fn epoch_cell<L: LanguageEpoch>(ts_language: &TsLanguage) -> &'static str {
    L::cell().get_or_init(|| compute_epoch::<L>(ts_language, L::SALT))
}

fn compute_epoch<L: LanguageEpoch>(ts_language: &TsLanguage, language_salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost-analyzer-epoch-v2\n");
    hasher.update(ANALYZER_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(STORE_EPOCH_SALT.as_bytes());
    hasher.update(b"\n");
    hasher.update(L::NAME.as_bytes());
    hasher.update(b"\n");
    hasher.update(language_salt.as_bytes());
    hasher.update(b"\n");
    hash_grammar(&mut hasher, ts_language);
    hasher.update(b"\n");
    for (path, contents) in EMBEDDED_QUERIES {
        if path.starts_with(L::QUERY_DIR) {
            hasher.update(path.as_bytes());
            hasher.update(b"\0");
            hasher.update(normalized_query_contents(contents).as_bytes());
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
}

/// Uses the repository's canonical LF representation for embedded query text.
///
/// Git commonly checks out text as CRLF on Windows. Query contents are part of
/// the persisted-cache compatibility key, so hashing those checkout-specific
/// bytes would create different cache epochs for the same revision.
fn normalized_query_contents(contents: &str) -> Cow<'_, str> {
    if contents.contains("\r\n") {
        Cow::Owned(contents.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(contents)
    }
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
    // Ruby
    (
        "treesitter/ruby/definitions.scm",
        include_str!("../../../resources/treesitter/ruby/definitions.scm"),
    ),
    (
        "treesitter/ruby/imports.scm",
        include_str!("../../../resources/treesitter/ruby/imports.scm"),
    ),
    (
        "treesitter/ruby/identifiers.scm",
        include_str!("../../../resources/treesitter/ruby/identifiers.scm"),
    ),
];

macro_rules! lang_epoch {
    ($struct:ident, $name:literal, $dir:literal) => {
        lang_epoch!($struct, $name, $dir, "");
    };
    ($struct:ident, $name:literal, $dir:literal, $salt:literal) => {
        struct $struct;
        impl LanguageEpoch for $struct {
            const NAME: &'static str = $name;
            const QUERY_DIR: &'static str = $dir;
            const SALT: &'static str = $salt;
            fn cell() -> &'static OnceLock<String> {
                static CELL: OnceLock<String> = OnceLock::new();
                &CELL
            }
        }
    };
}

// Salt bumped (#1611): Java `ImportInfo` paths now record a static import as
// `StructuredImportPathKind::StaticMember`. Rows persisted before this change
// labeled every import `Namespace`, and consumers that now branch on the kind
// would read a warm workspace's static imports as ordinary type imports.
lang_epoch!(
    Java,
    "java",
    "treesitter/java/",
    "synthetic-file-scope-code-units-2026-07;no-implicit-constructor-units-2026-07;source-backed-package-modules-2026-07;ast-test-detection-2026-07;callable-arity-metadata-2026-07;annotated-spread-parameter-metadata-2026-07;compact-record-constructors-2026-07;fq-interned-segments-2026-07;field-modifier-metadata-2026-08;static-import-path-kind-2026-08"
);
// Salt bumped: Go `package_name` is now the canonical import path, changing
// every persisted Go `fq_name`. Forces stale rows to be re-analyzed.
lang_epoch!(
    Go,
    "go",
    "treesitter/go/",
    "go-canonical-import-path-fqn-2026-06;synthetic-file-scope-code-units-2026-07;raw-package-qualifier-2026-07;fq-interned-segments-2026-07;return-expression-list-value-identity-2026-07"
);
// Salt bumped: out-of-line member definitions whose owner class is named with
// no namespace segment of its own (`Class::method` under an in-effect `using
// namespace X;` rather than an enclosing `namespace {}` block) now resolve
// their package from the visible using-directive instead of staying
// unqualified, so their `fq_name` matches their header declaration's (#1093).
// Forces stale rows using the old (split) identity to be re-analyzed.
// Salt bumped again (#1120): a bare free-function call from such an out-of-line
// member now recovers the member's true enclosing scope from the indexed
// definition, so the inverted usage graph records call edges (to global- and
// namespace-scope free functions) it previously dropped as unresolved.
// Salt bumped again (#1121): out-of-line nested-class members defined inside a
// `namespace {}` block now index their owner as the class-nesting chain
// (`Outer$Inner`) instead of dropping all but the last owner segment, changing
// persisted identities for those definitions.
// Salt bumped again (#1208): recovered export-macro class bodies now publish
// the declarator name of a displaced `typedef` (`BASE_CLASS`) instead of the
// qualified aliased type's terminal (`Filter`). This changes persisted C++
// declaration identities and must hide pre-fix parsed blobs.
// Salt bumped again (#1530): declarations following a macro field whose parser
// recovery absorbs the owning class terminator are now re-owned by the enclosing
// namespace, changing their persisted identities and navigation ranges.
// Salt bumped again (#1560): fragmented namespace-sentinel classes can now
// retain their complete member tail, changing persisted declaration ownership
// and removing phantom members emitted by the truncated parse.
// Salt bumped again (#1536): a sentinel-swallowed class is now recovered when
// tree-sitter preserves a later member callable on the malformed envelope,
// restoring the class and its nested declaration identities.
// Salt bumped again (#1572): complete fragmented-class member signatures with
// structured annotation errors are retained, restoring the owning class on
// late overloads and fields that were previously emitted as flat identities.
// Salt bumped again (#1000): structurally bounded plain-class fragments and
// split constraint-macro constructors retain their nested class ownership.
// Salt bumped again (#1000): later parser-visible siblings inside those plain
// fragments are re-owned by the recovered class when full-body reparse is not
// safe, changing persisted member and inherited nested-type identities.
// Salt bumped again (#1593): fragmented export constructors with initializer
// lists now keep initializer names as fields instead of synthetic callables,
// changing persisted declaration ownership and identities.
// Salt bumped again (#1593 follow-up): the structured sibling boundary for
// those fragmented constructors now remains stable across the full header,
// invalidating blobs written before the final recovery boundary.
// Salt bumped again (#1665): a later macro-export class lifted through a
// preprocessor container keeps the namespace scope of its preceding sibling.
// Salt bumped again (#1670): macro-decorated template classes recovered from
// sentinel envelopes now retain their real class identity and member scope.
lang_epoch!(
    Cpp,
    "cpp",
    "treesitter/cpp/",
    "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-ownership-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08"
);

#[cfg(test)]
pub(super) fn cpp_epoch_before_sentinel_class_before_member_callable() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_plain_fragmented_class_sibling_ownership() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_fragmented_export_sibling_class_parent_scope() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-ownership-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_decorated_template_class_scope() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-ownership-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_recovered_typedef_base() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_complete_sentinel_class_tail() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08",
    )
}

#[cfg(test)]
pub(super) fn scala_epoch_before_scalachess_fqn_recovery() -> String {
    compute_epoch::<Scala>(
        &crate::analyzer::scala::language::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07",
    )
}

#[cfg(test)]
mod query_content_tests {
    use super::normalized_query_contents;

    #[test]
    fn normalizes_embedded_query_crlf_for_cross_platform_epochs() {
        assert_eq!(
            normalized_query_contents("(node) @capture\r\n(comment) @comment\r\n"),
            "(node) @capture\n(comment) @comment\n"
        );
    }
}
// JS/TS salts bumped: anonymous `export default` expressions/declarations now
// emit a synthetic `default` code unit, changing each file's persisted unit set.
// JS salt bumped again (#1167): a `<ns>.object({...})` schema-builder call
// (zod/yup/valibot/...) assigned to a non-exported local `const` now gets
// shape-preserving field indexing, same as TS already did - previously such
// locals materialized no child fields at all. Changes the persisted unit set
// for files with local schema-builder bindings.
lang_epoch!(
    JavaScript,
    "javascript",
    "treesitter/javascript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07"
);
// TS salt bumped again (#1167): `is_simple_ts_initializer` now includes
// `regex` (a regex-initialized binding renders its initializer inline in the
// skeleton instead of dropping it, matching JS), and a module-scope
// `const x = function(){}` is now classified as a Function instead of a
// Field (matching JS's `arrow_function | function_expression` check).
// The classification change alters CodeUnitType, short_name/fq shape, and
// signature rendering for every such binding.
lang_epoch!(
    TypeScript,
    "typescript",
    "treesitter/typescript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07"
);
lang_epoch!(
    Python,
    "python",
    "treesitter/python/",
    "synthetic-file-scope-code-units-2026-07;structured-python-import-paths-2026-07;fq-interned-segments-2026-07"
);
lang_epoch!(
    Rust,
    "rust",
    "treesitter/rust/",
    "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08"
);
// Salt bumped after #1420: namespace-level structural traversal now emits
// conditionally declared free functions that older PHP blobs omitted.
lang_epoch!(
    Php,
    "php",
    "treesitter/php/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07;conditional-free-function-declarations-2026-07"
);

#[cfg(test)]
pub(super) fn php_epoch_before_conditional_free_function_declarations() -> String {
    compute_epoch::<Php>(
        &tree_sitter_php::LANGUAGE_PHP.into(),
        "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07",
    )
}
// The live grammar fingerprint does not include parser tables. Keep the
// vendored Scala revision in the salt so conflict-resolution-only grammar
// changes cannot reuse analysis produced by an older parser.
lang_epoch!(
    Scala,
    "scala",
    "treesitter/scala/",
    "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07"
);
lang_epoch!(
    CSharp,
    "csharp",
    "treesitter/c_sharp/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;static-using-type-identifiers-2026-07;as-expression-type-identifiers-2026-07;generic-type-identity-2026-07;attribute-type-identifiers-2026-07;callable-arity-and-static-import-metadata-2026-07;generic-method-arity-identity-2026-07;structured-return-type-metadata-2026-07;tuple-element-type-identifiers-2026-07;nameof-type-identifiers-2026-07;callable-dispatch-extensibility-metadata-2026-07;fq-interned-segments-2026-07"
);
lang_epoch!(
    Ruby,
    "ruby",
    "treesitter/ruby/",
    "synthetic-file-scope-code-units-2026-07;attr-macro-accessor-identities-2026-07;fq-interned-segments-2026-07"
);
// The live grammar fingerprint does not include parser tables. Keep the
// vendored Kotlin revision in the salt so conflict-resolution-only grammar
// changes cannot reuse analysis produced by an older parser.
// Salt bumped (#1345): Kotlin callables now publish their written return type
// and, for an extension, the receiver type they extend; Kotlin properties now
// carry `SignatureMetadata` at all. Persisted rows written before this change
// have neither, and a consumer that reads the published fact instead of
// re-parsing would read a warm workspace as "no return type written".
// `kotlin-companion-object-marker-2026-07` (issue #1239, milestone 3): a Kotlin
// `companion object` now publishes `SignatureMetadata::is_companion_object`, so
// consumers can ask whether an owner's members answer to the enclosing class's
// own name without re-parsing the declaring file. A companion indexed before
// this change carries no metadata at all, and a warm workspace would read every
// companion as an ordinary nested object — losing every `Base.of()` edge.
lang_epoch!(
    Kotlin,
    "kotlin",
    "treesitter/kotlin/",
    "tree-sitter-kotlin-fwcd-c8ac3d26-2026-07;kotlin-core-indexing-2026-07;kotlin-class-parameter-default-arity-2026-07;kotlin-backtick-identifier-names-2026-07;kotlin-jvm-realm-imports-supertypes-2026-07;kotlin-signature-returns-receivers-2026-07;kotlin-companion-object-marker-2026-07"
);

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
