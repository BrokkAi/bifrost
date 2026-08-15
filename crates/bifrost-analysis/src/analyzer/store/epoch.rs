//! Per-language analysis epoch.
//!
//! The epoch is a stable fingerprint of every input that, if changed, would
//! invalidate previously-persisted analyzer payloads. It folds in:
//!
//! - the analyzer store epoch salt
//! - the language adapter's actual `tree_sitter::Language` fingerprint
//!   (ABI version + every node kind name + every field name)
//! - the contents of the language's bundled `.scm` query files
//!
//! When any of these change, every row written under the previous epoch is
//! treated as logically dirty regardless of mtime/size.
//!
//! The crate version is deliberately not an input. Analyzer behavior changes
//! are tracked by the store salt, the per-language salts, the grammar
//! fingerprint, and the query files. A release that changes none of these
//! keeps the warm cache valid.
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

// v11 is the last salt this struct will ever cost. Signature metadata now
// lives in the typed columns that migration 0023 created, so a new signature
// fact is an `ALTER TABLE ... ADD COLUMN ... DEFAULT ...` in a new migration
// and never a field on a serialized struct. Add the column; do not bump this
// salt. A migration re-keys the store file by schema version and invalidates
// nothing, while a salt bump throws away every analyzer row for every language
// in every cache on every machine.
//
// v11: merge of two v10 bumps made independently on both sides of a branch.
// One added `SignatureMetadata::field_has_initializer`; the other added the
// declaration-backed structured underlying type identity for Go named
// containers (#2069). The merged bincode shape matches rows written under
// neither v10 salt, so both generations turn over here. Semantic chunks and
// vectors have a separate identity and remain valid.
//
// v9: migration 0019 merged `import_details` into `import_statements`, so an
// import is one row per binding instead of a raw statement plus a bincode
// `ImportInfo`. What the writer records changed as well as where: Go segments
// its import path, C# records a structured path and its `global using` flag,
// and Scala and TypeScript now emit one row per binding rather than one per
// declaration. `binder_span` (#1600) rides along as a column on that row
// rather than as a bincode field, because the blob it used to live in is gone.
const STORE_EPOCH_SALT: &str = "analyzer-blob-store-v11-signature-metadata-merge";

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
    hasher.update(STORE_EPOCH_SALT.as_bytes());
    hasher.update(b"\n");
    hasher.update(L::NAME.as_bytes());
    hasher.update(b"\n");
    hasher.update(language_salt.as_bytes());
    hasher.update(b"\n");
    hash_grammar(&mut hasher, ts_language);
    hasher.update(b"\n");
    for (path, contents) in EMBEDDED_QUERIES
        .iter()
        .chain(brokk_bifrost_cpp::queries::CPP_QUERY_ASSETS)
        .chain(brokk_bifrost_csharp::queries::CSHARP_QUERY_ASSETS)
        .chain(brokk_bifrost_go::queries::GO_QUERY_ASSETS)
        .chain(brokk_bifrost_js_ts::queries::JS_TS_QUERY_ASSETS)
        .chain(brokk_bifrost_jvm::queries::JVM_QUERY_ASSETS)
        .chain(brokk_bifrost_php::queries::PHP_QUERY_ASSETS)
        .chain(brokk_bifrost_python::queries::PYTHON_QUERY_ASSETS)
        .chain(brokk_bifrost_ruby::queries::RUBY_QUERY_ASSETS)
        .chain(brokk_bifrost_rust::queries::RUST_QUERY_ASSETS)
    {
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
///
/// This table is now empty: every language's assets moved with its language
/// knowledge into its own crate, and they are chained in above under the same
/// `treesitter/<lang>/` prefixes they had here, so the per-language filter stays
/// one rule. JavaScript's and TypeScript's were the last two, and their
/// departure also removed `brokk-bifrost-analysis/resources/` entirely.
///
/// The table and the loader stay so that a future analysis-resident asset has a
/// home; the comment stubs record where each language's went.
const EMBEDDED_QUERIES: &[(&str, &str)] = &[
    // C++
    // C#
    // Java
    // JavaScript
    // PHP
    // Scala
    // TypeScript
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
// Salt bumped again (#1548 stage 3 fleet): the Java `.scm` query assets moved
// from this crate's `resources/treesitter/java/` into `brokk-bifrost-jvm`, so
// the salted content now comes from a different crate's `include_str!`. The
// bytes are unchanged, which is exactly why the salt has to carry the
// relocation.
// Salt bumped again (#1905): Java class-like signature metadata now records
// explicit and implicit static nested declarations. Warm rows without this
// fact would admit illegal outer-instance member resolution.
// Salt bumped again (#2045): the Java declaration walk now emits two kinds of
// owner it used to drop. A class declared local to a method body and an
// anonymous `new Base() { ... }` body each become a class scope with their own
// members, and an enum's `enum_body_declarations` members are no longer
// skipped. A warm workspace holds rows without any of those declarations, and
// a forward field lookup against them reports `no_indexed_definition` for a
// field the source plainly declares.
// Salt bumped again (#2161): two persisted Java facts change. A scope written
// in an anonymous body's field initializer no longer repeats that body's own
// `$anon$line:column` marker, so every name under a nested anonymous owner
// changes, and a type argument is no longer recorded as a raw supertype, so a
// warm workspace holds hierarchy edges from a class to its own element type.
lang_epoch!(
    Java,
    "java",
    "treesitter/java/",
    "synthetic-file-scope-code-units-2026-07;no-implicit-constructor-units-2026-07;source-backed-package-modules-2026-07;ast-test-detection-2026-07;callable-arity-metadata-2026-07;annotated-spread-parameter-metadata-2026-07;compact-record-constructors-2026-07;fq-interned-segments-2026-07;field-modifier-metadata-2026-08;static-import-path-kind-2026-08;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;class-like-static-metadata-2026-08;native-callable-modifier-metadata-2026-08;local-anonymous-and-enum-body-owners-2026-08;nested-anonymous-owner-identity-2026-08"
);
// Salt bumped: Go `package_name` is now the canonical import path, changing
// every persisted Go `fq_name`. Forces stale rows to be re-analyzed.
// Salt bumped again (#1548 stage 3 pilot): the Go `.scm` query assets moved
// from this crate's `resources/treesitter/go/` into `brokk-bifrost-go`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
lang_epoch!(
    Go,
    "go",
    "treesitter/go/",
    "go-canonical-import-path-fqn-2026-06;synthetic-file-scope-code-units-2026-07;raw-package-qualifier-2026-07;fq-interned-segments-2026-07;return-expression-list-value-identity-2026-07;go-query-assets-in-brokk-bifrost-go-2026-08;named-type-underlying-identity-2026-08"
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
// Salt bumped again (#1548 stage 3 fleet): the C++ `.scm` query assets moved
// from this crate's `resources/treesitter/cpp/` into `brokk-bifrost-cpp`, so
// the salted content now comes from that crate's `resources/`.
// Salt bumped again (#1705): typedef extraction now reads tree-sitter's
// declarator fields and recovers a split macro typedef from its structured
// sibling. This removes false aliases and changes persisted ranges.
// Salt bumped again: enum enumerators are owned children of their enum, no
// longer duplicated into the persisted top-level declaration list, and an
// ERROR-envelope sentinel class recovery no longer drops the envelope's
// sibling declarations after the recovered class close.
// Salt bumped again (#1827): the C++ identity signature now reads a callable's
// trailing cv/ref/noexcept qualifiers from the declarator's grammar fields
// instead of splitting its text, and drops the top-level cv-qualifiers on a
// value parameter per [dcl.fct]/5. Both change persisted signatures, and rows
// written under the old rules would keep a declaration and its out-of-line
// definition apart.
// Salt bumped again (#2177): a plain class fragmented by an unknown attribute
// macro now reparses through its displaced close and persists the real members
// after that inline body. This removes a phantom call-shaped member signature
// and restores the typed, cv-qualified identity of the following declaration.
// Salt bumped again (#914): that plain-class fragment can make tree-sitter use
// the class close as a namespace close and eject later namespace declarations.
// The structured displaced boundary now restores the missing class members and
// namespace ownership, changing persisted identities and navigation ranges.
// Salt bumped again (#1961): templated plain-class fragments now retain their
// parser-visible prefix declarations and re-own lifted member siblings through
// the displaced namespace boundary. This restores class-owned alias identities.
// Salt bumped again (#2197): when a declaration macro displaces a scalar return
// type into the function declarator, the structured recovery now persists the
// real callable name and return type instead of a callable named for the return
// type. This adds the missing overload identity and changes signature metadata.
lang_epoch!(
    Cpp,
    "cpp",
    "treesitter/cpp/",
    "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08;conditional-alias-physical-ranges-2026-08;macro-argument-typedef-declarator-2026-08;enum-enumerator-child-ownership-2026-08;sentinel-error-envelope-sibling-recovery-2026-08;cpp-query-assets-in-brokk-bifrost-cpp-2026-08;structural-declarator-qualifier-suffix-and-top-level-parameter-cv-2026-08;macro-fragmented-plain-class-member-signatures-2026-08;namespaced-plain-fragment-boundary-2026-08;templated-plain-fragment-prefix-and-sibling-ownership-2026-08;macro-displaced-scalar-return-callable-name-2026-08"
);

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_displaced_callable_name() -> String {
    cpp_epoch_before_salt_marker("macro-displaced-scalar-return-callable-name-2026-08")
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_templated_plain_fragment_ownership() -> String {
    cpp_epoch_before_salt_marker("templated-plain-fragment-prefix-and-sibling-ownership-2026-08")
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_namespaced_plain_fragment_boundary() -> String {
    cpp_epoch_before_salt_marker("namespaced-plain-fragment-boundary-2026-08")
}

#[cfg(test)]
fn cpp_epoch_before_salt_marker(marker: &str) -> String {
    let marker = format!(";{marker}");
    let (prior, _) = Cpp::SALT
        .split_once(&marker)
        .unwrap_or_else(|| panic!("the current C++ salt carries the {marker} bump"));
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

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
pub(super) fn cpp_epoch_before_conditional_alias_physical_ranges() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08",
    )
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_argument_typedef_declarator() -> String {
    compute_epoch::<Cpp>(
        &tree_sitter_cpp::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08;conditional-alias-physical-ranges-2026-08",
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
pub(super) fn scala_epoch_before_tree_sitter_scala_0_26_2() -> String {
    compute_epoch::<Scala>(
        &crate::analyzer::scala::language::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08",
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
// Salt bumped again (#1548 stage 3 fleet): the JavaScript `.scm` query assets
// moved from this crate's `resources/treesitter/javascript/` into
// `brokk-bifrost-js-ts`, so the salted content now comes from a different
// crate's `include_str!`.
// Salt bumped again (#1926): JavaScript `field_definition` uses the structured
// `property` field. Reading it now indexes public and private class fields.
// Salt bumped again (#1658): the TypeScript declaration walk now records
// declaration-only signature metadata for overload signatures and ambient
// declarations. `.js` files can be parsed through the TS grammar, so both
// dialect salts carry the bump; rows persisted before it read every stub as
// runnable.
// Salt bumped again (#1862): plain top-level fields in scripts now use the
// shared program-scope identity. Warm rows used a file-qualified identity.
lang_epoch!(
    JavaScript,
    "javascript",
    "treesitter/javascript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;structured-class-field-properties-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08"
);
// TS salt bumped again (#1167): `is_simple_ts_initializer` now includes
// `regex` (a regex-initialized binding renders its initializer inline in the
// skeleton instead of dropping it, matching JS), and a module-scope
// `const x = function(){}` is now classified as a Function instead of a
// Field (matching JS's `arrow_function | function_expression` check).
// The classification change alters CodeUnitType, short_name/fq shape, and
// signature rendering for every such binding.
// Salt bumped again (#1548 stage 3 fleet): the TypeScript `.scm` query assets
// moved from this crate's `resources/treesitter/typescript/` into
// `brokk-bifrost-js-ts` alongside JavaScript's -- one crate holds both dialects.
// Salt bumped again (#1658): overload signatures and ambient declarations now
// persist declaration-only signature metadata. Rows written before this change
// read every stub as runnable behavior, the da26602 regression.
// Salt bumped again (#1862): plain top-level fields in scripts now use the
// shared program-scope identity. Warm rows used a file-qualified identity.
lang_epoch!(
    TypeScript,
    "typescript",
    "treesitter/typescript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08"
);
// Salt bumped (#1548 stage 3 fleet): the Python `.scm` query assets moved from
// this crate's `resources/treesitter/python/` into `brokk-bifrost-python`, so
// the salted content now comes from a different crate's `include_str!`. The
// bytes are unchanged, which is exactly why the salt has to carry the
// relocation.
// Salt bumped again (#1971): Python module identity now starts at a nested
// setuptools import root declared in pyproject.toml.
// Salt bumped again (#2052): repeated assignments to one logical class field
// now retain every physical navigation range so class-body lookup can select
// the binding active at the reference site.
lang_epoch!(
    Python,
    "python",
    "treesitter/python/",
    "synthetic-file-scope-code-units-2026-07;structured-python-import-paths-2026-07;fq-interned-segments-2026-07;python-query-assets-in-brokk-bifrost-python-2026-08;python-setuptools-import-roots-2026-08;python-class-rebinding-navigation-ranges-2026-08"
);
// Salt bumped (#1548 stage 3 fleet): the Rust `.scm` query assets moved from
// this crate's `resources/treesitter/rust/` into `brokk-bifrost-rust`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
// Rust salt bumped twice: impl owners and their members now persist an anchor plus a
// content-stable tail instead of the extracting mount's path-derived package
// text, so cached Rust rows carry package prefixes the new reader will not
// reproduce; and Rust packages are now anchored on the Cargo crate name rather
// than the extracting mount's directory path, so cached names differ outright.
// No other language's persisted encoding changed.
// Rust salt bumped again (#1898): an `impl` owner path rooted at a renamed
// import (`use crate::model as m;` then `impl Trait for m::Writer`) now routes
// through the binding's module and imported name. Rows written while that root
// resolved as a bare module name carry the phantom owner package (`impls.m`)
// for every member of such an impl, so a warm workspace would answer the alias
// spelling and never the real owner (`model.Writer.act`).
// Rust salt bumped again (Phase 2 of
// `.agents/plans/port-optimization-arc-to-upstream.md`): the Rust walk now
// records per-file usage facts (`rust_exports`, `rust_import_targets`,
// `rust_modules`, `rust_identifier_occurrences`) and per-file Cargo module
// routes (`rust_module_scopes`, `rust_module_routes`,
// `rust_module_route_gates`, `rust_item_macros`) alongside its declarations.
// A blob analyzed before this change carries none of those rows, and a reader
// cannot tell that blob from one whose file genuinely declares nothing, so the
// old rows must not be reused.
// Rust salt bumped again (Phase 2 step 4 of the same plan): each persisted
// `rust_import_targets` row now carries the `#[cfg(...)]` predicate the `use`
// was written under and whether it came from `extern crate`. A row written
// before this change defaults to 'always' and to a `use`, which would claim an
// unguarded import for a `#[cfg]`-gated one (making two disjoint cfg
// alternatives look like one ambiguity, #1377) and would let an extern-crate
// alias also bind a same-named local module.
// Rust salt bumped again (#2033): named fields of enum struct variants now
// persist beneath the exact variant identity (`Enum.Variant.field`). Warm rows
// written before this change contain the variant but omit all of those fields.
// Rust salt bumped again (#2035): callable signature metadata now persists each
// parameter type spelling. Associated trait-call applicability must not read a
// warm row that predates that declaration-side discriminator.
// Rust salt bumped again (#2128): Cargo module route facts now canonicalize raw
// identifiers such as `mod r#struct;`. Warm rows retain the source spelling and
// cannot connect the declaration to its physical `struct.rs` child.
lang_epoch!(
    Rust,
    "rust",
    "treesitter/rust/",
    "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08;anchored-fq-encoding-2026-08;crate-aware-packages-2026-08;rust-query-assets-in-brokk-bifrost-rust-2026-08;renamed-import-impl-owner-route-2026-08;per-file-usage-facts-2026-08;cargo-route-facts-2026-08;include-edge-facts-2026-08;import-cfg-and-extern-crate-2026-08;enum-variant-named-fields-2026-08;callable-parameter-type-spellings-2026-08;raw-identifier-cargo-module-routes-2026-08"
);

#[cfg(test)]
pub(super) fn rust_epoch_before_anchored_fq_encoding() -> String {
    compute_epoch::<Rust>(
        &tree_sitter_rust::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08",
    )
}
// Salt bumped after #1420: namespace-level structural traversal now emits
// conditionally declared free functions that older PHP blobs omitted.
// Salt bumped again (#1548 stage 3 fleet): the PHP `.scm` query assets moved from
// this crate's `resources/treesitter/php/` into `brokk-bifrost-php`, so the
// salted content now comes from a different crate's `include_str!`. The bytes are
// unchanged, which is exactly why the salt has to carry the relocation.
lang_epoch!(
    Php,
    "php",
    "treesitter/php/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07;conditional-free-function-declarations-2026-07;php-query-assets-in-brokk-bifrost-php-2026-08"
);

/// The PHP epoch as it stood before the #1420 conditional-free-function bump.
///
/// The literal below is a historical pin and must never be edited: it is what
/// `php_conditional_free_function_epoch_invalidates_prior_parsed_blobs` writes a
/// blob under before asserting the current epoch evicts it. Later salt segments
/// (the 2026-08 asset relocation above) are deliberately absent from it.
#[cfg(test)]
pub(super) fn php_epoch_before_conditional_free_function_declarations() -> String {
    compute_epoch::<Php>(
        &tree_sitter_php::LANGUAGE_PHP.into(),
        "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07",
    )
}
// The live grammar fingerprint does not include parser tables. Keep the Scala
// release revision in the salt so grammar changes cannot reuse analysis
// produced by an older parser.
// Salt bumped (#1548 stage 3 fleet): the Scala `.scm` query assets and the
// Scala grammar itself moved from this crate into `brokk-bifrost-jvm`, so
// the salted content now comes from a different crate's `include_str!`. The
// bytes are unchanged, which is exactly why the salt has to carry the
// relocation.
// Salt bumped again (#2082): a `package object p` body is now a package scope,
// so the package prefixes in scope at a byte include `<clause>.p`. Two
// persisted facts follow that value: an import declared inside a package
// object records those prefixes in `import_lexical_prefixes`, and an anonymous
// instance declared there records them in its supertype lookup path. A warm
// workspace holds both without the package object's own package, so a
// relative import and a supertype written inside a package object resolve
// against the wrong scope.
lang_epoch!(
    Scala,
    "scala",
    "treesitter/scala/",
    "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;tree-sitter-scala-0.26.2-2026-08;scala-anonymous-template-code-units-2026-08;package-object-package-scope-2026-08"
);
// Salt bumped (#1548 stage 3 fleet): the C# `.scm` query assets moved from this
// crate's `resources/treesitter/c_sharp/` into `brokk-bifrost-csharp`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
// Salt bumped again (#1735): C# callable metadata now treats the interop
// OptionalAttribute as omittable. Warm rows recorded the old exact arity and
// would make persisted inverse usage search reject valid omitted arguments.
// Salt bumped again (#1478): C# callable metadata now records the declaration's
// modifiers -- static, constructor, and written accessibility. Rows persisted
// before this change say "nobody read the modifiers", and a consumer that
// distinguishes a static callable from an instance one would read every warm
// C# callable as undecided.
// Salt bumped again (#2061): `csharp_type_reference_root` no longer reads the
// `pointer_type` half of a multiplication the grammar mis-parsed as an
// out-argument declaration expression. Rows persisted before this change hold a
// type reference for the left operand of every `Math.Abs(Width * Height)`, and
// nothing at query time can tell that bogus reference from a real one.
// Salt bumped again (#2064): the verbatim-identifier `@` escape is now
// normalized off declaration names and off every type-name segment, so a
// `class @Wrapper` is indexed as `Wrapper` and its references match it. Rows
// persisted before this change hold `@`-prefixed short names, fq segments, and
// type identifiers, which no query-time normalization can reconcile with the
// canonical spellings written afterwards.
lang_epoch!(
    CSharp,
    "csharp",
    "treesitter/c_sharp/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;static-using-type-identifiers-2026-07;as-expression-type-identifiers-2026-07;generic-type-identity-2026-07;attribute-type-identifiers-2026-07;callable-arity-and-static-import-metadata-2026-07;generic-method-arity-identity-2026-07;structured-return-type-metadata-2026-07;tuple-element-type-identifiers-2026-07;nameof-type-identifiers-2026-07;callable-dispatch-extensibility-metadata-2026-07;fq-interned-segments-2026-07;csharp-query-assets-in-brokk-bifrost-csharp-2026-08;interop-optional-callable-arity-2026-08;callable-modifier-metadata-2026-08;preprocessor-directive-aware-parsing-2026-08;multiplication-not-pointer-type-reference-2026-08;verbatim-identifier-canonical-declaration-names-2026-08"
);
// Salt bumped (#1548 stage 3 fleet): the Ruby `.scm` query assets moved from
// this crate's `resources/treesitter/ruby/` into `brokk-bifrost-ruby`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
lang_epoch!(
    Ruby,
    "ruby",
    "treesitter/ruby/",
    "synthetic-file-scope-code-units-2026-07;attr-macro-accessor-identities-2026-07;fq-interned-segments-2026-07;ruby-query-assets-in-brokk-bifrost-ruby-2026-08"
);
// The live grammar fingerprint does not include parser tables. Keep the exact
// Kotlin crate release in the salt so parser-only grammar changes cannot reuse
// analysis produced by an older parser.
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
// Salt bumped (#1548 stage 3 fleet): Kotlin's `highlights.scm` and grammar
// binding moved from this crate into `brokk-bifrost-jvm`. Unlike Java's and
// Scala's, this bump is not forced by the mechanism -- `treesitter/kotlin/`
// selects no entry in the salted asset set, because Kotlin is
// declaration-walk-only and neither of its `.scm` files has ever been in
// `EMBEDDED_QUERIES`. It is here for consistency with its two realm peers.
lang_epoch!(
    Kotlin,
    "kotlin",
    "treesitter/kotlin/",
    "brokk-tree-sitter-kotlin-0.4.0-2026-08;kotlin-core-indexing-2026-07;kotlin-class-parameter-default-arity-2026-07;kotlin-backtick-identifier-names-2026-07;kotlin-jvm-realm-imports-supertypes-2026-07;kotlin-signature-returns-receivers-2026-07;kotlin-companion-object-marker-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08"
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
