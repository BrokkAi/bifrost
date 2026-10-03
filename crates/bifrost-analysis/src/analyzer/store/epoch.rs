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

// Signature metadata now lives in the typed columns that migration 0023
// created, so adding a signature fact does not justify an epoch bump: add a
// column with a compatible default. Bump this salt only when existing content
// rows cannot be transformed by SQL, as in v12 and v13 below.
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
// v12: schema 26 makes `code_unit_fq_segments` the authoritative structured
// identity and adds indexed content-tail projections. SQL cannot backfill the
// FQ2 blob into rows, so old generations must be republished once.
// v13: schema 63 persists exact metadata-to-signature ordinal pairs captured
// at shared construction. Independent label/metadata deduplication means SQL
// cannot reconstruct those identities by ordinal, label, or declaration range.
// Remaining M4 language salts include canonical primary source ownership.
// Nullable legacy family markers preserve old schema rows; their old epochs
// must become dirty so ordinary primary analysis publishes the required facts.
// Scoped malformed-syntax coverage replaces persisted fragment-wide gaps in
// the common lowering. Every language must republish its sealed coverage rows.
// The lazy interior's tier-1 headers (`resolution_identities`,
// `resolution_blob_identities`, `resolution_path_endpoint_headers`,
// `resolution_path_terminal_headers`, `resolution_candidate_gap_headers`) join
// the persisted bundle, so every blob's sealed interior digest changes and
// every language must republish.
// `resolution_gaps.gap` is a dense per-blob ordinal in a key space of its own
// instead of a semantic catalog key (#3737), and the catalog no longer holds
// one identity per gap, so every blob's sealed interior changes and every
// language must republish.
const STORE_EPOCH_SALT: &str = concat!(
    "analyzer-blob-store-v13-signature-metadata-pairs;scoped-malformed-coverage-2026-09;",
    "lazy-interior-tier-1-headers-li3-2026-09-14;gap-ordinals-3737-2026-09-29;",
    "gap-reasons-without-catalog-rows-3737-2026-09-29"
);

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
    // Persisted structural facts carry this version, and a reader does not
    // repair an indexed source whose facts are at another version. A bump
    // must therefore invalidate every language's rows by itself, rather than
    // relying on a grammar, query or salt change landing beside it.
    hasher.update(
        format!(
            "structural-facts-v{}",
            crate::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION
        )
        .as_bytes(),
    );
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
    ($struct:ident, $name:literal, $dir:literal, $salt:literal, $append:literal) => {
        struct $struct;
        impl LanguageEpoch for $struct {
            const NAME: &'static str = $name;
            const QUERY_DIR: &'static str = $dir;
            const SALT: &'static str = concat!($salt, $append);
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
// Salt bumped again: the persisted `type_identifiers` family is now one
// superset for both of its readings. The ordinary Java walk used to record only
// written and qualified type names, so a class spelled as a static or value
// qualifier (`Owner.INSTANCE`) was invisible to the file dependency graph's
// same-package tier. Warm rows hold the narrow set and would lose those edges.
// Salt bumped again (#2271, #2272, #2273): enum-constant-specific class bodies
// and their nested declarations are now persisted, and method-local classes
// carry a source-coordinate identity that separates same-named locals in
// overloaded methods. Warm rows either omit the enum-body owners entirely or
// retain the old collapsed local-class FQNs.
// Salt bumped again: Java resolution facts now explicitly declare the
// visibility-eligible definition inventory consumed by common typed lowering.
// Warm parsed blobs do not carry those authority rows.
// Salt bumped again: root-import facts now retain their typed route anchor.
// Warm parsed blobs omit that source-owned authority.
// Salt bumped again (#1651): a type declaration's signature metadata now
// records the declaration's own type-parameter list, which
// `canonical_identity_of` projects as the identity's generic arity. A warm row
// carries no such record, so a cached declaration would compare unequal to the
// same declaration reparsed from unchanged source.
// Salt bumped (#3410): a try-with-resources statement is now a persisted
// `resource_release` structural fact, and its implicit close is lowered on
// both continuations. Warm rows carry neither.
// Static imports now publish source-owned root demands; reparse old blobs.
lang_epoch!(
    Java,
    "java",
    "treesitter/java/",
    "synthetic-file-scope-code-units-2026-07;no-implicit-constructor-units-2026-07;source-backed-package-modules-2026-07;ast-test-detection-2026-07;callable-arity-metadata-2026-07;annotated-spread-parameter-metadata-2026-07;compact-record-constructors-2026-07;fq-interned-segments-2026-07;field-modifier-metadata-2026-08;static-import-path-kind-2026-08;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;class-like-static-metadata-2026-08;native-callable-modifier-metadata-2026-08;local-anonymous-and-enum-body-owners-2026-08;nested-anonymous-owner-identity-2026-08;enum-constant-body-and-coordinate-local-class-owners-2026-08;same-package-type-identifier-facts-2026-08;native-resolution-visibility-eligibility-2026-09;native-resolution-root-import-anchors-2026-09;declaration-type-parameter-arity-2026-09;coordinated-canonical-source-production-2026-09;structured-package-identity-2026-09;source-owned-declaration-visibility-2026-09;canonical-visibility-storage-2026-09;shared-java-declaration-shapes-2026-09;canonical-java-declaration-types-2026-09;implicit-resource-release-3410;native-static-import-root-demands-2026-09-28;java-array-type-components-2026-09"
);
// Package names now use the shared directive AST interpretation. Old text-based
// names can contain comments or omit annotated declarations; reparse their units.
// Java and Go now publish occurrence, declaration, import, structural, and
// native links from one coordinated producer. SQL cannot recover the missing
// AST identities from old display rows; both language salts require reparse.
// Salt bumped: Go `package_name` is now the canonical import path, changing
// every persisted Go `fq_name`. Forces stale rows to be re-analyzed.
// Salt bumped again (#1548 stage 3 pilot): the Go `.scm` query assets moved
// from this crate's `resources/treesitter/go/` into `brokk-bifrost-go`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
// Salt bumped again: root-import facts now retain their typed route anchor.
// Warm parsed blobs omit that source-owned authority.
// Salt bumped again (#3325): a Go 1.26 `new(expr)` call no longer leaves its
// argument -- and, in an assignment, the whole statement that follows -- inside
// an ERROR node. Those regions now yield ordinary declarations, references, and
// structural facts, so every blob parsed before the repair holds a different
// reading of the same bytes. The grammar itself is unchanged, which is why the
// fingerprint cannot carry this and the salt must.
// Salt bumped again (#3370): string literals now lower to the structured
// `ConstantString` value kind with their exact source text instead of the
// payload-free `Constant`. Warm semantic rows hold the old kind, and the race
// solver's exact map-key pairing must not silently misread them.
// Salt bumped again (#3455): the Go walk now records callable modifier
// metadata, and it recorded none before. A blob persisted under the prior
// epoch deserializes as "nobody read the modifiers", so `receiver_contract_of`
// reports no contract, `modeled_procedure_key_for_unit` refuses every Go
// workspace declaration, and every Go procedure summary stays inert on a warm
// workspace with no error raised anywhere. The same gap was bumped for
// JavaScript and TypeScript (#2597), for PHP and Ruby (#2912), and for Python
// (#3451).
// Unnamed input/receiver facts and result-list separation change native rows.
// Selector assignment targets now emit member reference facts, and Go package
// lookup names now reach reverse discovery headers; warm rows lacked both.
// Bare call identifiers also retain Go's type-conversion namespace ambiguity.
// If conditions now emit structured references from their expression operands.
// Direct Go calls now publish argument-independent name binding and no
// unsupported-route placeholder for their callee; warm bundles carry different
// typed resolution facts and must be rebuilt.
// Selector callees and references inside function literals now have complete
// source owners, so warm bundles lack the call and graph identity facts.
lang_epoch!(
    Go,
    "go",
    "treesitter/go/",
    "go-canonical-import-path-fqn-2026-06;synthetic-file-scope-code-units-2026-07;raw-package-qualifier-2026-07;fq-interned-segments-2026-07;return-expression-list-value-identity-2026-07;go-query-assets-in-brokk-bifrost-go-2026-08;named-type-underlying-identity-2026-08;native-resolution-root-import-anchors-2026-09;coordinated-canonical-source-production-2026-09;canonical-go-declaration-source-2026-09;empty-interface-map-key-identity-2026-09;go-1-26-new-expression-parse-2026-09;go-constant-string-values-2026-09;go-callable-modifier-metadata-2026-09;native-unnamed-signatures-and-result-arity-2026-09-28;go-container-type-components-2026-09;native-go-selector-assignment-references-2026-09-30;native-go-call-type-conversion-identities-2026-09-30;native-go-if-condition-reference-traversal-2026-09-30;go-universe-call-name-binding-2026-09;native-go-selector-callees-and-reference-owners-2026-09-30"
);

/// The Go epoch as it stood before the #3455 callable-modifier bump.
#[cfg(test)]
pub(super) fn go_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(Go::SALT, "go-callable-modifier-metadata-2026-09");
    compute_epoch::<Go>(&tree_sitter_go::LANGUAGE.into(), prior)
}
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
// Salt bumped again (#2202): C++23 explicit object parameters remain part of a
// callable's identity signature but no longer count as ordinary call arguments.
// Warm rows carry the old callable-arity metadata and would keep rejecting
// receiver-supplied calls.
// Salt bumped again (#2203): the C++ declaration walk now persists callable
// parameter types taken from the AST parameter list. Warm rows lack this fact
// and would fall back to misreading template-constraint macro parentheses as
// the invocation parameter list.
// Salt bumped again (#2207): a declaration macro followed by a template return
// type can make tree-sitter insert a missing scope separator before a free
// function name. The structured recovery now persists the callable at namespace
// scope instead of as a false member of its return type.
// Salt bumped again (#2269): the structured declarator walk now handles
// `abstract_reference_declarator`, so an unnamed `const T&` parameter and a
// `type_descriptor`-shaped trailing return (`auto f() -> int&`) keep their
// reference wrapper in the persisted structured type identity. Warm rows hold
// the reference-less identity for those declarations.
// Salt bumped again (#1970): a `.c` translation unit is now extracted with C tag
// scope, so a struct/union/enum tag declared inside another aggregate's member
// list is minted at the enclosing non-aggregate scope instead of as a nested
// `outer$inner` class. Warm rows hold the C++ nested identity for every such
// declaration in every `.c` file. The bump covers both C/C++ storage language
// keys: they share this epoch cell (`CppAdapter::storage_language_keys`), and
// the `.c` key is new anyway.
// Salt bumped again (#2532): macro declarations now carry their structured
// directive signature in CodeUnit identity, so a same-file #undef/redefinition
// sequence persists each distinct replacement and temporal lookup can select
// the active physical range. Warm rows collapse every name to the first range.
// Salt bumped again: `#include` directives are collected by a preorder sweep
// instead of by the declaration walk, so a directive written inside a class
// body (Eigen's `EIGEN_DENSEBASE_PLUGIN`) or a function body (llama.cpp's
// `sycl/info/aspects.def`) is now an include claim. Warm rows omit them, so the
// include graph misses those edges and `.inc` fragments they claim stay
// unadopted.
// Salt bumped again (#2557): a recovered function-like export-macro class is
// now named by its position in the class head instead of by spelling, so a
// class named in capitals (`X509_CA`) and a class behind an object-like macro
// (`OTHER_MACRO Name`) are persisted. Warm rows hold no declaration for them.
// Salt bumped again (#3084): a namespace head that parse recovery collapsed
// into an ERROR node now names the scope its brace opens, so every declaration
// the collapsed namespace holds is published under that namespace. Warm rows
// hold those declarations under a shorter package (Catch2's
// `catch_decomposer.hpp` published `ITransientExpression`, not
// `Catch.ITransientExpression`), so their identity changes.
// Salt bumped again (#3098): an aggregate whose member list a field-list macro
// invocation collapsed now records the range it is defined at even when a
// typedef or forward declaration already introduced the tag, and an aggregate
// the parser folded into the declaration before it is recovered with its
// members. Warm rows hold the tag with only its forward range, and hold no
// declaration at all for the folded aggregate (libuv's `struct uv_handle_s`).
// Salt bumped again (#3301): an anonymous struct/union declares no tag, so its
// members are now extracted in both dialects instead of only in a `.c`
// translation unit. A `.cpp`/`.hpp` file's promoted anonymous-union fields, the
// receiver class minted for `struct { ... } sock;`, and the generated owner of
// a function-local anonymous aggregate are all new rows; a member function body
// written inline now carries the same block scope an out-of-line body already
// had, so its local owners are new as well. Warm rows hold none of them.
// Salt bumped again (#3298): a class-scope function-like macro invocation that
// expands to declarations is no longer published as a member field. The
// invocation keeps no terminator of its own, so the parser invented one and
// read the macro name as the member type and its argument as a parenthesized
// declarator; `DISABLE_COPY_ASSIGN_MOVE(ClosedDetect)` then held a field named
// `ClosedDetect` beside the real constructor under the same fully qualified
// name. Warm rows hold that field.
// Salt bumped again (#3309): a namespace whose head parse recovery collapsed
// into an `ERROR` now records the `namespace Name { ... }` construct it is
// written as, from the keyword through the close the brace stack paired with
// its `{`. The orphaned-namespace recovery declared the Module at whichever
// declaration the walk was visiting when it restored the scope, so the Module
// took its first member's range (simdjson's `parse_api_tests` held 458..458 for
// a namespace written on 457 and closed on 804). Warm rows hold those member
// ranges.
// Salt bumped again (#3328): the brace stack no longer answers a close for any
// open in a file whose brace token stream lost a scope-opening token. Severe
// recovery can leave a `{` the source writes out of the tree entirely (the
// C++26 reflection in simdjson's `compile_time_json-inl.h` re-lexes
// `case '<punct>': {` and consumes eight statement braces as char-literal
// characters), and every close after such a loss belongs one level in. A
// recovered namespace level and a recovered exported class now keep the range
// they are written at instead of an extent the pairing cannot prove; warm rows
// hold the interior close (that file published `simdjson` as 35..883 and
// `simdjson::compile_time` as 36..880 for namespaces closed on 1128 and 1127).
// Salt bumped again (#3466): the callee token of a C or C++ free-function call
// is now a `ValueReference` occurrence, so a call site whose callee stays
// unindexed publishes the row `candidates_of` joins its boundary route
// against. Warm rows hold only the call's member-position occurrence (for
// member calls) or no occurrence at the callee token at all, and the adapter
// reported `ValueReference` as unsupported for the language.
// Salt bumped again (#3493): the C and C++ walk now records callable modifier
// metadata, and it recorded none before. A blob persisted under the prior epoch
// deserializes as "nobody read the modifiers", so `receiver_contract_of`
// reports no contract, `modeled_procedure_key_for_unit` refuses every C and C++
// workspace declaration, and every effect or taint walk that reaches one
// reports `callee_unkeyable` on a warm workspace with no error raised anywhere.
// The same gap was bumped for JavaScript and TypeScript (#2597), for PHP and
// Ruby (#2912), for Python (#3451), for Kotlin (#3453) and for Go (#3455).
// Salt bumped again (#3508): an in-class member prototype is a real source
// declaration, so it now keeps the ordinary code-unit identity instead of the
// synthetic one the walk minted for a class-body declaration. Warm rows hold
// the synthetic identity, which is a different `CodeUnit` (equality includes
// the flag), refuses `modeled_procedure_key_for_unit` on identity grounds, and
// keeps the prototype's occurrences in a unit no definition can join.
// Salt bumped again (#3507): the persisted `dispatch_extensibility` answer the
// extractor records for a C++ callable changed, so a warm row holds the older
// answer. A class-body member of a class that writes a base clause now records
// `open`, because a base may declare a virtual member of the same name, and a
// qualified out-of-line definition records no answer of its own and takes the
// include-visible class body's instead of answering from its own subtree. The
// query-time discharge in the dispatch oracle persists nothing and does not
// move this salt.
// Salt bumped again (#3633): a namespace the brace stack restored for a
// collapsed head now stops owning declarations at the close the stack paired
// with its `{`, and a parsed namespace whose own `{` and `}` are real tokens is
// kept when a recovered path is empty. Declarations after such a close lose
// the restored prefix (simdjson's `basictests.cpp` published
// `type_tests::validate_tests`), so a warm row holds the older qualified name
// and Module ownership.
// #3806: quoted native header paths now publish structured include facts.
// Retire prior rows even if the public node/field fingerprint stays unchanged.
lang_epoch!(
    Cpp,
    "cpp",
    "treesitter/cpp/",
    "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08;conditional-alias-physical-ranges-2026-08;macro-argument-typedef-declarator-2026-08;enum-enumerator-child-ownership-2026-08;sentinel-error-envelope-sibling-recovery-2026-08;cpp-query-assets-in-brokk-bifrost-cpp-2026-08;structural-declarator-qualifier-suffix-and-top-level-parameter-cv-2026-08;macro-fragmented-plain-class-member-signatures-2026-08;namespaced-plain-fragment-boundary-2026-08;templated-plain-fragment-prefix-and-sibling-ownership-2026-08;macro-displaced-scalar-return-callable-name-2026-08;explicit-object-callable-arity-2026-08;structured-callable-parameter-types-2026-08;macro-template-return-free-function-ownership-2026-08;abstract-reference-declarator-identity-2026-08;c-tag-scope-2026-08;c-header-projection-2026-08;temporal-macro-definition-identity-2026-08;nested-include-claims-2026-08;recovered-named-class-member-linkage-2026-09;positional-export-macro-class-names-2026-09;collapsed-namespace-head-scope-2026-09;collapsed-aggregate-definition-ranges-2026-09;lexical-container-partition-2026-09;function-macro-replacement-local-scope-2026-09;canonical-primary-source-ownership-2026-09;canonical-field-activation-and-recovered-context-2026-09;canonical-generated-field-types-and-context-2026-09;canonical-recovered-field-types-and-callable-bodies-2026-09;forward-declared-class-declaration-ranges-2026-09;unterminated-macro-invocation-fields-2026-09;anonymous-aggregate-members-in-both-dialects-2026-09;recovered-namespace-header-ranges-2026-09;unproven-brace-pairing-extents-2026-09;free-function-callee-value-references-2026-09;cpp-callable-modifier-metadata-2026-09;cpp-declared-access-separate-from-linkage-2026-09;cpp-source-member-prototype-units-2026-09;cpp-member-dispatch-extensibility-2026-09;namespace-recovery-ancestry-authority-2026-09;cpp-completed-callable-guard-proof-2771-2026-09-26;raw-quoted-include-header-paths-3806-2026-10"
);

/// The C and C++ epoch before native quoted header paths were parsed correctly.
#[cfg(test)]
pub(super) fn cpp_epoch_before_raw_quoted_include_header_paths() -> String {
    let prior = salt_before_bump(Cpp::SALT, "raw-quoted-include-header-paths-3806-2026-10");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

/// The C and C++ epoch as it stood before the #3508 source member-prototype bump.
#[cfg(test)]
pub(super) fn cpp_epoch_before_source_member_prototype_units() -> String {
    let prior = salt_before_bump(Cpp::SALT, "cpp-source-member-prototype-units-2026-09");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_namespace_recovery_ancestry_authority() -> String {
    let prior = salt_before_bump(Cpp::SALT, "namespace-recovery-ancestry-authority-2026-09");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

/// The salt as it stood immediately before `bump` was appended.
///
/// A language salt is an ordered `;`-separated registry of semantic bump
/// names. Each historical-invalidation test pins one boundary in that
/// sequence: it needs every bump that precedes its own and nothing after it.
/// Deriving the prefix from the named bump keeps every pin at its intended
/// boundary when a later bump is appended, which stripping the test's own
/// bump off the tail of the salt cannot do.
#[cfg(test)]
pub(super) fn salt_before_bump<'a>(salt: &'a str, bump: &str) -> &'a str {
    let mut offset = 0usize;
    let mut start = None;
    for entry in salt.split(';') {
        if entry == bump {
            assert!(
                start.is_none(),
                "salt bump {bump} is registered more than once in {salt}"
            );
            start = Some(offset);
        }
        offset += entry.len() + 1;
    }
    let start =
        start.unwrap_or_else(|| panic!("salt does not register the bump {bump}; salt is {salt}"));
    assert!(
        start > 0,
        "salt bump {bump} is the first registered bump, so there is no earlier salt"
    );
    &salt[..start - 1]
}

/// The C and C++ epoch as it stood before the #3493 callable-modifier bump.
#[cfg(test)]
pub(super) fn cpp_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(Cpp::SALT, "cpp-callable-modifier-metadata-2026-09");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_nested_include_claims() -> String {
    let prior = salt_before_bump(Cpp::SALT, "nested-include-claims-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_c_header_projection() -> String {
    let prior = salt_before_bump(Cpp::SALT, "c-header-projection-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_c_tag_scope() -> String {
    let prior = salt_before_bump(Cpp::SALT, "c-tag-scope-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_abstract_reference_declarator_identity() -> String {
    let prior = salt_before_bump(Cpp::SALT, "abstract-reference-declarator-identity-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_template_return_free_function_ownership() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "macro-template-return-free-function-ownership-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_structured_callable_parameter_types() -> String {
    let prior = salt_before_bump(Cpp::SALT, "structured-callable-parameter-types-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_explicit_object_callable_arity() -> String {
    let prior = salt_before_bump(Cpp::SALT, "explicit-object-callable-arity-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_displaced_callable_name() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "macro-displaced-scalar-return-callable-name-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_templated_plain_fragment_ownership() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "templated-plain-fragment-prefix-and-sibling-ownership-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_namespaced_plain_fragment_boundary() -> String {
    let prior = salt_before_bump(Cpp::SALT, "namespaced-plain-fragment-boundary-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_sentinel_class_before_member_callable() -> String {
    let prior = salt_before_bump(Cpp::SALT, "sentinel-class-before-member-callable-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_plain_fragmented_class_sibling_ownership() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "plain-fragmented-class-sibling-ownership-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_fragmented_export_sibling_class_parent_scope() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "fragmented-export-sibling-class-parent-scope-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_decorated_template_class_scope() -> String {
    let prior = salt_before_bump(Cpp::SALT, "macro-decorated-template-class-scope-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_recovered_typedef_base() -> String {
    let prior = salt_before_bump(Cpp::SALT, "recovered-typedef-base-alias-identity-2026-07");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_complete_sentinel_class_tail() -> String {
    let prior = salt_before_bump(Cpp::SALT, "complete-sentinel-class-tail-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_conditional_alias_physical_ranges() -> String {
    let prior = salt_before_bump(Cpp::SALT, "conditional-alias-physical-ranges-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn cpp_epoch_before_macro_argument_typedef_declarator() -> String {
    let prior = salt_before_bump(Cpp::SALT, "macro-argument-typedef-declarator-2026-08");
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn kotlin_epoch_before_type_alias_type_identity() -> String {
    let prior = salt_before_bump(Kotlin::SALT, "kotlin-type-alias-type-identity-2026-09");
    compute_epoch::<Kotlin>(&crate::analyzer::kotlin::language::LANGUAGE.into(), prior)
}

/// The Kotlin epoch as it stood before the #3453 callable-modifier bump.
#[cfg(test)]
pub(super) fn kotlin_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(Kotlin::SALT, "kotlin-callable-modifier-metadata-2026-09");
    compute_epoch::<Kotlin>(&crate::analyzer::kotlin::language::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn scala_epoch_before_type_alias_type_identity() -> String {
    let prior = salt_before_bump(Scala::SALT, "scala-type-alias-type-identity-2026-09");
    compute_epoch::<Scala>(&crate::analyzer::scala::language::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn scala_epoch_before_top_level_extension_declarations() -> String {
    let prior = salt_before_bump(Scala::SALT, "top-level-extension-declarations-2026-08");
    compute_epoch::<Scala>(&crate::analyzer::scala::language::LANGUAGE.into(), prior)
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
// Salt bumped again (#2597): the JavaScript and TypeScript declaration walks
// now record callable modifier metadata -- static, constructor, and the fact
// that the adapter read the modifier nodes at all. Both dialect salts carry the
// bump: `.js` files can be parsed through the TS grammar, and both walks
// changed. Rows persisted before it deserialize as "nobody read the modifiers",
// so `receiver_contract_of` reports no contract and every JS/TS procedure
// summary stays inert on a warm workspace with no error raised anywhere.
// Salt bumped again (#2593): a `receiver.#name = value` assignment no longer
// mints a Field declaration. A private name is only legal inside a class body
// that already declares it, so those rows were parentless duplicates of the
// field #1926 already indexes under its class; chains rooted through a private
// segment (`child.#out.length`) are gone too. Only JavaScript's salt moves:
// the walk that changed is the JavaScript assignment walk, and the TypeScript
// walk indexes assigned fields only through a `this` receiver, which never
// accepted a private name. Rows persisted before the bump still carry the
// duplicate declarations.
// Salt bumped again: structured ESLint RuleTester suites now persist
// `contains_tests = true`. Warm rows written before this change retain false
// for those files even though their source and imports are unchanged, so both
// JS and TS generations must turn over.
// Salt bumped again: JS/TS test classification no longer searches raw source
// substrings and now recognizes narrowly gated Node runner paths. Both true
// and false persisted `contains_tests` values can therefore be stale.
// Salt bumped again: local nested object-literal properties are now indexed on
// their complete structured receiver path for definition lookup.
// Salt bumped again (#3322): `.jsx` is a dialect of its own, parsed with the
// TSX grammar because tree-sitter-javascript cannot parse a reserved word as a
// JSX attribute name and one `<div class="x">` costs every declaration below
// it. Its rows move to the `javascript:jsx` storage key, whose epoch folds in
// the TSX grammar fingerprint; this salt retires the `.jsx` rows the plain
// `javascript` key still holds from before the split, which were extracted
// from ERROR-recovery soup. Only JavaScript's salt moves: TypeScript's two
// dialects and its walk are untouched.
// Salt bumped again (#3342): Brokk's tree-sitter-javascript 0.25.1 accepts
// reserved words as JSX identifier-like names. Standard `.js` files that
// contain `<div class="x">` now persist real elements, attributes,
// declarations and usages instead of upstream 0.25.0's recovery tree.
// Salt bumped again (#3386): a JS/TS augmented assignment now derives its
// stored value from the target and operand values, and a template string or
// substitution now derives its value from its substituted expressions.
// Persisted value-flow rows written before carry an isolated result for both.
lang_epoch!(
    JavaScript,
    "javascript",
    "treesitter/javascript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;structured-class-field-properties-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08;js-ts-callable-modifier-metadata-2026-08;js-private-name-assignment-is-not-a-declaration-2026-08;structured-rule-tester-test-detection-2026-08;structured-js-ts-test-classification-2026-08;canonical-primary-source-ownership-2026-09;js-nested-object-literal-property-indexing-2026-09;jsx-dialect-parsed-with-tsx-grammar-2026-09;js-grammar-reserved-word-jsx-names-2026-09;js-ts-augmented-template-operand-flows-3386;js-primary-walk-alias-and-local-object-metadata-2771-2026-09-26"
);

#[cfg(test)]
pub(super) fn javascript_epoch_before_structured_test_classification() -> String {
    let prior = salt_before_bump(
        JavaScript::SALT,
        "structured-js-ts-test-classification-2026-08",
    );
    compute_epoch::<JavaScript>(&tree_sitter_javascript::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn javascript_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(JavaScript::SALT, "js-ts-callable-modifier-metadata-2026-08");
    compute_epoch::<JavaScript>(&tree_sitter_javascript::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn javascript_epoch_before_private_name_assignment_declarations() -> String {
    let prior = salt_before_bump(
        JavaScript::SALT,
        "js-private-name-assignment-is-not-a-declaration-2026-08",
    );
    compute_epoch::<JavaScript>(&tree_sitter_javascript::LANGUAGE.into(), prior)
}
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
// Salt bumped again (#2159): a function whose return type is written as an
// inline object type now publishes that type's members as synthetic members of
// the function, so the persisted unit set for such a file gains rows that warm
// rows do not have. Only TypeScript's salt moves: the walk that changed reads
// a type annotation, which `.js` and `.jsx` files cannot carry.
// Salt bumped again (#2597): callable modifier metadata, described at the
// JavaScript salt above. Both dialects changed, so both salts move.
// Salt bumped again with JavaScript: RuleTester classification is a persisted
// file fact shared by both adapters.
// Salt bumped again with JavaScript: the structured DSL and Node runner
// classifier changes the same persisted file fact for both adapters.
// Salt bumped again (#2911): a `type` alias now mints a `Class` code unit whose
// own segment is a `Type` segment, the same identity rule a class, an interface
// and an enum use. `declaration_id` hashes segment kinds, so every warm row
// holds the old `Field`/`Member` identity for every TypeScript type alias --
// and, where an alias and a module-scope `const` share one name, holds only one
// of the two declarations. Only TypeScript's salt moves: the JavaScript grammar
// spells no `type_alias_declaration`.
// Salt bumped again (#3502): the Brokk TypeScript grammar repairs import-type
// member arguments, keyword property names, and abstract-override fields.
// These precedence and external-scanner changes can alter declaration ranges
// without changing the grammar's node-kind or field inventory, so the live
// grammar fingerprint alone cannot retire rows parsed through ERROR recovery.
lang_epoch!(
    TypeScript,
    "typescript",
    "treesitter/typescript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08;ts-inline-return-type-members-2026-08;js-ts-callable-modifier-metadata-2026-08;structured-rule-tester-test-detection-2026-08;structured-js-ts-test-classification-2026-08;ts-type-alias-type-identity-2026-09;canonical-primary-source-ownership-2026-09;js-ts-augmented-template-operand-flows-3386;ts-grammar-declaration-correctness-3502"
);

#[cfg(test)]
pub(super) fn typescript_epoch_before_type_alias_type_identity() -> String {
    let prior = salt_before_bump(TypeScript::SALT, "ts-type-alias-type-identity-2026-09");
    compute_epoch::<TypeScript>(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), prior)
}

#[cfg(test)]
pub(super) fn typescript_epoch_before_structured_test_classification() -> String {
    let prior = salt_before_bump(
        TypeScript::SALT,
        "structured-js-ts-test-classification-2026-08",
    );
    compute_epoch::<TypeScript>(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), prior)
}

#[cfg(test)]
pub(super) fn typescript_epoch_before_inline_return_type_members() -> String {
    let prior = salt_before_bump(TypeScript::SALT, "ts-inline-return-type-members-2026-08");
    compute_epoch::<TypeScript>(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), prior)
}

#[cfg(test)]
pub(super) fn typescript_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(TypeScript::SALT, "js-ts-callable-modifier-metadata-2026-08");
    compute_epoch::<TypeScript>(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), prior)
}
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
// Salt bumped (#3075): static setup.py packaging evidence establishes import roots.
// Salt bumped again: a subscripted base (`Base[T]`) now records its generic
// origin and an unnameable base (a call, an unpacked list) records its source
// spelling. Persisted rows written before this omitted both, so a cached class
// looks like it has fewer bases than it declares.
// Salt bumped again: an instance attribute assigned through a bracketed
// unpacking target (`(self.a, self.b) = ...`) is now collected. Cached rows
// omitted every such attribute, so a class looks like it declares fewer.
// Salt bumped again: a chained assignment (`encrypt = decrypt = process`) now
// declares every target it binds. Cached rows carry only the outermost one.
// Salt bumped (#3123): class-qualified semantic calls retain descriptor receiver contracts.
// Salt bumped (#3124): type-flow class identity resolves proven builtin names.
// Salt bumped (#3131): unmodeled instance guards retain named incomplete evidence.
// Salt bumped (#3135): Python semantic calls with a declared `NoReturn` or
// `Never` result now persist an absent normal continuation.
// Salt bumped (#3410): a `with` statement is now a persisted
// `resource_release` structural fact, its body is lowered, and its implicit
// `__exit__` is published as a call site on both continuations. Warm rows
// carry none of that.
// Salt bumped (#3386): an augmented assignment now derives its stored value
// from the target and operand values, and a formatted or concatenated string
// now derives its value from its interpolated or literal parts. Persisted
// value-flow rows written before carry an isolated unknown result for both.
// Salt bumped (#3451): the Python declaration walk now records callable
// modifier metadata -- whether a `def` declares `@staticmethod` or
// `@classmethod`, and the fact that the adapter read the declaration shape at
// all. Rows persisted before it deserialize as "nobody read the modifiers", so
// `receiver_contract_of` reports no contract, `modeled_procedure_key_for_unit`
// refuses every Python workspace declaration, and every Python procedure
// summary stays inert on a warm workspace with no error raised anywhere. The
// same gap was bumped for JavaScript and TypeScript (#2597) and for PHP and
// Ruby (#2912).
lang_epoch!(
    Python,
    "python",
    "treesitter/python/",
    "synthetic-file-scope-code-units-2026-07;structured-python-import-paths-2026-07;fq-interned-segments-2026-07;python-query-assets-in-brokk-bifrost-python-2026-08;python-setuptools-import-roots-2026-08;python-class-rebinding-navigation-ranges-2026-08;python-setup-py-import-roots-2026-09;coordinated-python-source-production-2026-09;canonical-python-declaration-annotations-2026-09;python-source-only-callable-annotations-2026-09;python-subscripted-and-unnameable-bases-2026-09;python-bracketed-unpacking-self-attributes-2026-09;python-chained-assignment-targets-2026-09;python-class-qualified-call-binding-2026-09;python-type-flow-builtin-class-identities-2026-09;python-type-flow-unmodeled-guards-2026-09;python-scoped-dynamic-writes-3129;python-declared-diverging-calls-3135;python-structured-refinement-targets-3196;canonical-python-generic-return-owner-2026-09;python-implicit-resource-release-3410;python-augmented-string-operand-flows-3386;python-callable-modifier-metadata-2026-09;python-replacement-owned-metadata-links-2771-2026-09-26"
);

/// The Python epoch as it stood before the #3451 callable-modifier bump.
#[cfg(test)]
pub(super) fn python_epoch_before_callable_modifier_metadata() -> String {
    let prior = salt_before_bump(Python::SALT, "python-callable-modifier-metadata-2026-09");
    compute_epoch::<Python>(&tree_sitter_python::LANGUAGE.into(), prior)
}
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
// Rust salt bumped again (#2351): a `const`, `static`, field, or type alias
// whose source text runs past 8 KiB now renders a label that elides the
// initializer instead of copying it. For an impl member that rendering is also
// its identity signature, so a warm row written before this change carries a
// spelling the new reader will not reproduce.
// Salt bumped again: the persisted `imports` family now holds every `use` and
// `extern crate` the file writes, not only the ones at its top level. Warm rows
// omit a `use` written inside `mod tests { ... }` or any other inline module,
// so the coarse file graph loses the file edges those imports name.
// Rust salt bumped again: parsed blobs now carry the first nonempty common
// native-resolution tranche. Resolution facts are intentionally not hydrated,
// so advancing only the resolution-bundle epoch would republish an old parsed
// blob with an empty bundle and would also erase its non-hydrated Rust usage
// rows. Advancing the language epoch forces one source parse that republishes
// both structured families together.
// Rust salt bumped again: public top-level items and supported named `use`
// declarations now emit native root-route halves. Resolution facts are still
// not hydrated, so an old parsed blob cannot be reused to prepare this richer
// bundle without reparsing the source-owned facts.
// Rust salt bumped again: cfg-owned regions that the content-only producer
// cannot activate are skipped with explicit gaps instead of publishing binders,
// references, imports, or root exports from a potentially disabled subtree.
// Resolution facts are still not hydrated, so this semantic correction needs
// the language epoch as well as the resolution-bundle epoch.
// Rust salt bumped again: a root wildcard import now emits a finite common
// route whose demands come from supported references in the importing module.
// Old parsed blobs cannot hydrate those added resolution rows.
// Rust salt bumped again: bare structured type operands now emit common Type
// references and therefore add exact consumer-glob demands.
// Rust salt bumped again: item macro declarations and simple invocations now
// emit source-ordered Macro bindings, references, and root exports.
// Rust salt bumped again: supported native definitions now retain their exact
// parsed CodeUnit crosswalk for selected consumer projection.
// Rust salt bumped again: the whole-file unsupported marker now belongs only
// to reference enumeration. Point gaps remain local to syntax the producer
// actually skipped, so old non-hydrated resolution facts must be reparsed.
// Rust salt bumped again: procedural item attributes and unsupported
// trait/impl members now withhold transformed or mis-scoped declarations and
// publish exact fail-closed boundaries. Old parsed blobs can otherwise retain
// false root binders for methods or declarations replaced by an attribute
// macro.
// Rust salt bumped again: top-level `const` and `static` items now emit native
// Value declarations and their exact parser-unit crosswalks. Old parsed blobs
// cannot hydrate either source-owned resolution fact from cached content.
// Rust salt bumped again: root `extern crate` declarations no longer emit
// bogus lexical Value references. Their declaration surface remains an
// enumeration-only boundary while selected Cargo topology owns exact aliases.
// Rust salt bumped again: closures, for loops, and match arms now own exact
// pattern scopes, while generic item interiors are withheld so their lexical
// parameters cannot bind to same-named module declarations.
// Rust salt bumped again: direct if-let and while-let patterns now activate in
// only their consequence or loop body. Let chains remain an exact enumeration
// boundary until their staged pattern scopes are represented.
// Rust salt bumped again: repeated binder spellings in an or-pattern now share
// one source-ordered semantic binder instead of becoming equal-rank ambiguity.
// Their multiple declaration spellings retain enumeration-only uncertainty.
// Rust salt bumped again: foreign function signatures now produce module
// callable declarations rather than leaving their calls falsely absent.
// Rust salt bumped again: union declarations now enter the parser-unit and
// lexical indexes at every item position, completing native target projection.
// Rust salt bumped again: block-local items and foreign types are withheld
// behind point boundaries because the parser-unit contract cannot project them.
// Bare if/while conditions, assignment sides, and range bounds now emit native
// Value references instead of leaving their exact source ranges unavailable.
// Rust salt bumped again: tuple and unit structs now publish their existing
// semantic definition in both the Type and Value namespaces. Old parsed blobs
// cannot hydrate the additional namespace or its public root-export half.
// Rust salt bumped again: generic item interiors now retain supported ordinary
// references while unprojectable type-parameter uses carry exact point gaps.
// Old parsed blobs omit both kinds of positioned reference.
// Rust salt bumped again: unqualified const-generic uses now carry positioned
// Value-reference gaps instead of binding a same-named module constant.
// Rust salt bumped again: callable Value binding, type-alias/module domains,
// macro source-order hoisting, and visibility eligibility are explicit
// producer authority rows. Warm parsed blobs still depend on evaluator rules.
// Rust salt bumped again: the terminal tokens of qualified callable and type
// paths now carry positioned reference sites with explicit qualifier slots.
// Old blobs omit those sites and could falsely certify a complete absence.
// Item-position macro invocations now carry a binder-surface boundary rather
// than only an expression boundary, so an unexpanded generated declaration
// cannot turn into a complete absence either.
// Cfg-owned module and import declarations now retain route-placement
// boundaries instead of fragment-wide route gaps, allowing a proven nearer
// lexical binding to win without treating a conditional route as absent.
// Rust salt bumped again: reference enumeration now records exact unsupported
// identifier sites instead of one unconditional whole-file gap. Warm parsed
// blobs would otherwise retain the blanket gap and could never certify a
// complete selected binding world.
// Rust salt bumped again: the built-in `test` attribute is source-preserving,
// so its function declarations and references no longer sit behind a false
// procedural-macro boundary. Cargo manifest fact v4 also distinguishes custom
// target configuration from default-layout targets.
// Rust salt bumped again: inline-module scope rows now persist source
// visibility, and selected reachability composes cfg activation through every
// inline ancestor before publishing descendants or external routes.
// Rust salt bumped again: include splices now derive their host module and
// included membership from the AST-owned inline scope containing the macro.
// Rust salt bumped again: leading-absolute use-tree leaves retain their typed
// anchor in both private topology facts and common root-import facts.
// Rust salt bumped again: method callees retain exact qualified terminals,
// and computed callees retain expression-local uncertainty instead of
// poisoning all selected lexical bindings with a fragment-level route gap.
// Skipped associated-member surfaces now retain dedicated enumeration and
// reverse-inventory gaps without claiming unknown free lexical binders.
// Inherent impl callables now retain exact crosswalks and body references with
// deferred owner frontiers, without publishing lexical method binders.
// Canonical source facts now publish Rust structural rows and native source
// identities from one primary analysis, so older parsed blobs cannot satisfy
// the migrated provider from their legacy structural snapshot.
// Salt bumped again (#1651): a type declaration's signature metadata now
// records the declaration's own type-parameter list, which
// `canonical_identity_of` projects as the identity's generic arity. A warm row
// carries no such record, so a cached declaration would compare unequal to the
// same declaration reparsed from unchanged source.
// Salt bumped again (#2911): a `type` alias and a trait or impl
// `associated_type` now mint a `Class` code unit whose own segment is a `Type`
// segment, the same identity rule a `struct`, an `enum`, a `union`, and a
// `trait` use. `declaration_id` hashes segment kinds, so every warm row holds
// the old `Field`/`Member` identity for every Rust type alias -- and, where an
// alias and a `const` share one owner and one name, holds only one of the two
// declarations.
// Salt bumped again (#3080): Rust underscore imports now retain their target
// in usage facts while carrying no local binding name, and eligible `pub use`
// rows preserve those unnamed exports. Warm rows carry the old producer
// semantics and must be re-extracted before the new reader can use them.
// Salt bumped again (#3081): external module signatures retain the source
// declaration item instead of a fabricated inline-module header.
// Salt bumped again (#3072): a `#[proc_macro]` function is now persisted in
// the macro namespace instead of the function namespace, and an `extern
// crate` import fact now records whether `#[macro_use]` imports that crate's
// exported macros. Warm rows carry the old declaration identity and omit the
// import route needed to resolve the macro through a facade re-export.
// Rust reference and raw-pointer wrappers now carry distinct proven-reference
// indirection in native resolution transfers. Cached source facts cannot hydrate
// that added provenance, so they must be extracted again.
// Untyped Rust let bindings now retain their direct call initializer as an
// explicit Initialization transfer. Cached source facts omit that declaration
// type producer and must be extracted again.
// Rust source facts now retain exact named-leaf and wildcard demand target
// provenance. Warm rows cannot reconstruct grouped leaf ownership.
// Salt bumped: a declared type's unmodelled generic arguments now record
// `UnsupportedTypeSyntax` instead of `UnsupportedScopeOrBinder`, so a warm
// row would still claim an omitted binder in the attachment scope and make
// every lookup there incomplete.
// Salt bumped: a declared `Box<T>`, `Arc<T>` or `Rc<T>` now projects its
// payload as the declared type, `Option<T>` and `Result<T, E>` project theirs
// behind one unproven indirection layer, and `?`, `.unwrap()` and `.expect(..)`
// in a let initializer record an `Unwrap` transfer that removes exactly that
// layer. Cached source facts carry the old declared-type head and omit the
// unwrap transfers, so they must be extracted again.
// Salt bumped: a cfg-gated `use`, `mod`, or `extern crate` declared inside a
// block, callable, or type body now records `UnsupportedScopeOrBinder` in
// that scope instead of `UnsupportedPlacementBoundary`. Selected placement
// never discharges a binding that lives inside a block, and a warm row keeps
// the old placement gap, which lowering rejects on a non-root attachment
// scope and which aborts preparation of the whole file.
// Salt bumped: a value-position member chain now lowers every member as a
// qualified reference with its receiver transfer; every path prefix below a
// scoped or anchored path's head publishes its own root route, while the head
// and any anchor keyword publish none; and a named struct or union field is a
// member declaration with a binder in its owner's type body scope, a
// member-owner row, and its declared value type. Cached source facts hold the
// old lowering, where only a path terminal and a bare path's first segment had
// a reference, a member read had only an unlowered boundary, and a field had no
// declaration at all, so selected resolution kept reporting a missing native
// reference for `util` and for every member of `outer.inner.value`.
// Salt bumped: a qualified-type projection path (`<Service as Runner>::Output`)
// now lowers the type syntax inside its head as ordinary type references and
// its member as a qualified reference with an unqueried receiver and a
// type-shaped gap. Cached source facts hold `MalformedSyntax` for the whole
// path, which blocks the file's fragment, so every definition query in the file
// answered Incomplete.
// Salt bumped: named fields without parser CodeUnits now retain their canonical
// lexical field source projection, including fields of block-local structs.
// Salt bumped again (#3187): capital-`Self` occurrences are again extracted
// as semantic type references to their enclosing implementation owner. Warm
// Rust analysis created under the regressed extraction contract must not be
// reused as evidence that those references are absent.
// Salt bumped: crate export candidates are derived once per member blob and
// reused by visibility, module/enum exports, variants, and activation gaps.
// Salt bumped: a cfg-gated inline module (`#[cfg(test)] mod tests { .. }`) no
// longer records an `UnsupportedPlacementBoundary`; only a cfg-gated
// `mod name;` that routes into another compilation unit does. Warm rows keep
// the old placement gap, which opens the reverse candidate inventory for the
// whole workspace, so every reverse answer anywhere keeps reporting
// `InverseIndexResolutionIncomplete`.
// Salt bumped: a bare `self` method receiver (`self.method()`) now publishes
// its own value reference site, the way a `self.field` chain already did. Warm
// rows hold no reference at that token, so a request there answers
// `native_reference_missing` instead of the method's receiver parameter.
// Salt bumped: `let value = Type { .. };` now takes its declared value type
// from the initializer's own `name` field. Warm rows give that binding no
// declared type at all, so every later `value.member()` answers
// `UnsupportedSemantic` and contributes neither an edge nor a usage.
// Salt bumped: a block that declares items now carries an item scope above
// its local scope, so a nested item no longer sees the block's locals and
// still sees its sibling items. Warm rows hold the old single scope, in
// which a name inside a nested `fn` binds to the enclosing function's
// local instead of the item that name really denotes.
// Salt bumped: every trait and impl member body is lowered, and an
// item-position token tree of a definition-less macro is enumerated for
// references. Warm rows hold neither: a reference written inside a trait
// default body, inside a member of an impl whose subject type syntax is
// unsupported, inside an associated constant's value, or inside
// `criterion_group!(benches, bench)` has no site at all in them, so a request
// at that token answers `native_reference_missing` and the reverse route finds
// no candidate. One token covers both mechanisms; they land together.
// Salt bumped (#3746): a bare `Self` value now carries the enclosing impl's
// type identity. Warm rows answer it `no_indexed_definition`.
// Salt bumped (#3746): a member whose receiver is `x.unwrap()` or
// `x.expect(..)` over a call or member chain now takes that operand's payload
// through `Unwrap` transfers. Warm rows route it through std's `unwrap`.
// Salt bumped (#3746, U1): a grouped `{self}` import leaf binds only the type
// namespace and its target site is the `self` token; a private associated
// const or type of an inherent impl keeps its declared visibility; and
// `impl crate::m::Type` binds a standard `self` receiver. Warm rows hold a
// value-namespace import site on the prefix token, a public const, and no
// `self` binder in a path-subject impl.
// Salt bumped (#3746, U1): a parenthesized type (`&(dyn Trait + Send)`, which
// the grammar parses as a one-element `tuple_type`) lowers as its inner type.
// Warm rows hold an `UnsupportedTypeSyntax` gap there.
// Salt bumped (#3746): the subject frontier of an impl whose target type has
// no nominal head (`impl Trait for &[u8]`) no longer records a reference
// enumeration gap; the names that type spells are enumerated elsewhere. Warm
// rows keep the gap, which makes every reverse answer in such a file report
// `InverseIndexResolutionIncomplete`.
// Salt bumped again (#3746): consecutive `tt` bindings of a matched macro arm
// are one run of source for static-path publication, so `wanted::free` in
// `consume!(wanted::free())` under `$($tokens:tt)*` is a positioned
// reference. Warm rows hold no site at that token.
// Salt bumped again (#3746): a `macro_rules!` definition inside an attributed
// inline module (`#[macro_use] mod child { .. }`) is a macro definition, not
// malformed syntax. Warm rows give it no declaration and an enumeration gap.
// Salt bumped again (#3746): a static call path in a macro `tt` run
// (`EventInfo::default()`) is lowered as a call, with its call site and
// result slot. Warm rows hold only a bare callable reference.
// Salt bumped (#3746): a static path from matched `tt` bindings is published
// only when replay proves it is emitted in order in an expression/path role.
// Salt bumped (#3746): an explicitly typed closure parameter now carries
// its declared value type. Warm rows give it none, so its uses answer an
// incomplete type frontier.
// Salt bumped again: an impl whose generic target arguments are exactly its
// unconstrained type parameters no longer carries a spurious owner gap.
// Salt bumped (#3746, f): per-arm no-item proofs and scoped inline-module
// macro invocation names now contribute to Rust resolution.
// Salt bumped (#3746): lower emitted bare macro-transcriber references and
// the pattern operand of the standard `matches!` macro.
// Salt bumped (#3746, c): mapped generic alias arguments retain target identity.
// Salt bumped (#3746): restore expression-reference enumeration for unindexed
// macros; only a selected workspace transcriber can establish pattern roles.
// Salt bumped (#3746): lower the unindexed `matches!` pattern operand as a
// refutable pattern so enum variants and fallback binders keep their roles.
lang_epoch!(
    Rust,
    "rust",
    "treesitter/rust/",
    "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08;anchored-fq-encoding-2026-08;crate-aware-packages-2026-08;rust-query-assets-in-brokk-bifrost-rust-2026-08;renamed-import-impl-owner-route-2026-08;per-file-usage-facts-2026-08;cargo-route-facts-2026-08;include-edge-facts-2026-08;import-cfg-and-extern-crate-2026-08;enum-variant-named-fields-2026-08;callable-parameter-type-spellings-2026-08;raw-identifier-cargo-module-routes-2026-08;bounded-declaration-labels-2026-08;nested-and-extern-crate-import-facts-2026-08;declaration-type-parameter-arity-2026-09;rust-type-alias-type-identity-2026-09;unnamed-rust-import-binding-facts-2026-09;source-external-module-signatures-2026-09;proc-macro-kind-and-macro-use-extern-facts-2026-09;module-cfg-and-exported-macro-facts-2026-09;native-resolution-first-tranche-2026-09;native-resolution-root-route-halves-2026-09;native-resolution-cfg-fail-closed-2026-09;native-resolution-root-glob-demands-2026-09;native-resolution-type-references-2026-09;native-resolution-item-macros-2026-09;native-resolution-definition-unit-crosswalks-2026-09;native-resolution-point-gap-authority-2026-09;native-resolution-proc-macro-member-boundaries-2026-09;native-resolution-const-static-values-2026-09;native-resolution-extern-crate-routes-2026-09;native-resolution-local-pattern-scopes-2026-09;native-resolution-direct-let-condition-scopes-2026-09;native-resolution-or-pattern-binders-2026-09;native-resolution-foreign-functions-2026-09;native-resolution-union-types-2026-09;native-resolution-unprojectable-item-boundaries-2026-09;native-resolution-bare-condition-assignment-references-2026-09;native-resolution-struct-value-constructors-2026-09;native-resolution-generic-item-interiors-2026-09;native-resolution-const-generic-boundaries-2026-09;native-resolution-declared-rule-authority-2026-09;native-resolution-qualified-reference-boundaries-2026-09;native-resolution-item-macro-surface-boundaries-2026-09;native-resolution-cfg-route-placement-boundaries-2026-09;native-resolution-exact-reference-enumeration-gaps-2026-09;native-resolution-builtin-test-attribute-2026-09;cargo-manifest-default-target-inventory-2026-09;native-resolution-module-cycle-guard-2026-09;native-resolution-include-cycle-guard-2026-09;native-resolution-inline-module-ancestry-2026-09;native-resolution-inline-visibility-and-parent-cfg-2026-09;native-resolution-inline-include-scope-2026-09;native-resolution-inline-module-root-bridge-2026-09;native-resolution-inline-import-scope-2026-09;native-resolution-let-chain-scopes-2026-09;native-resolution-leading-absolute-imports-2026-09;native-resolution-positioned-call-callees-2026-09;native-resolution-member-scope-gaps-2026-09|native-resolution-root-references-2026-09;native-resolution-inherent-callable-bodies-2026-09;canonical-source-facts-2026-09;structured-extern-crate-import-form-2026-09;canonical-import-source-occurrences-2026-09;canonical-import-module-segments-2026-09;canonical-generic-import-spans-2026-09;canonical-import-properties-2026-09;canonical-rust-import-contexts-2026-09;canonical-embedded-declaration-identities-2026-09;canonical-rust-declaration-properties-2026-09;canonical-rust-declaration-classification-2026-09;canonical-rust-declaration-boundaries-2026-09;canonical-primary-module-properties-2026-09;shared-secondary-module-properties-2026-09;canonical-module-source-links-2026-09;ast-signature-header-boundaries-2026-09;source-owned-impl-type-construction-2026-09;shared-embedded-source-occurrences-2026-09;ast-parameter-label-spans-2026-09;primary-item-source-inventory-2026-09;secondary-item-source-inventory-2026-09;embedded-import-source-contexts-2026-09;normalized-item-syntax-2026-09;canonical-item-type-source-publication-2026-09;canonical-recovered-tree-root-contexts-2026-09;canonical-macro-source-position-2026-09;canonical-declaration-annotations-2026-09;canonical-generic-type-contexts-2026-09;canonical-macro-definition-patterns-2026-09;canonical-trait-type-forms-2026-09;canonical-macro-contexts-2026-09;canonical-native-declaration-bridge-publication-2026-09;native-resolution-reference-indirection-provenance-2026-09;native-resolution-let-initialization-2026-09;native-resolution-exact-import-demand-targets-2026-09;native-resolution-generic-argument-type-syntax-2026-09;native-resolution-wrapper-payload-projection-and-unwraps-2026-09;native-resolution-block-local-cfg-route-binders-2026-09;native-resolution-path-prefix-and-field-chain-occurrences-2026-09;native-resolution-qualified-type-projection-references-2026-09;native-resolution-detached-crate-module-trees-2026-09;native-resolution-enum-variant-members-2026-09;canonical-local-field-source-projections-2026-09;native-resolution-qualified-value-projections-2026-09;native-resolution-producer-reference-enumeration-b3-2026-09;native-resolution-census-ch-lexical-import-bindings-2026-09;native-resolution-selected-cfg-activation-2026-09;native-resolution-scoped-single-name-imports-and-serde-helpers-2026-09;native-resolution-trait-impl-bodies-ty-a-2026-09;native-resolution-type-alias-frontiers-ty-b-2026-09;native-resolution-associated-types-ty-c-2026-09;native-resolution-trait-bound-receivers-ty-d-2026-09-r2;native-resolution-macro-matcher-replay-mc-a-2026-09;native-resolution-macro-routes-mc-canonical-inputs-2026-09;native-resolution-include-splice-scopes-and-macros-mc-b-2026-09;transfer-owned-type-identity-observations-2026-09-13;native-resolution-enum-constructor-members-2026-09;native-resolution-terminal-prefix-qualifiers-ec-2026-09;native-resolution-enum-runtime-receivers-ec-2026-09;native-resolution-expression-name-focus-ec-2026-09;native-resolution-explicit-module-anchor-preservation-ec-2026-09;native-resolution-macro-callee-prefix-preservation-ec-2026-09;native-resolution-compound-member-receiver-enumeration-2026-09-13;native-resolution-initializer-field-reference-enumeration-2026-09-13;native-resolution-pattern-path-and-field-enumeration-2026-09-13;native-resolution-compound-type-operand-enumeration-2026-09-13;native-resolution-use-module-prefix-enumeration-2026-09-13;native-resolution-macro-use-module-body-enumeration-2026-09-13;native-resolution-literal-receiver-reference-enumeration-2026-09-13;native-resolution-unified-pending-receivers-reconciliation-2026-09-13;rust-crate-row-schema-cr-r8-1-2026-09;rust-crate-reconcile-cr-r8-2-2026-09;rust-crate-derivation-cr-r8-3-2026-09;rust-single-name-import-binder-cr-2026-09;rust-source-visibility-cr-2026-09;rust-conditional-module-definition-sites-cr-2026-09;rust-signature-source-links-cr-2026-09;rust-crate-target-dependencies-cr-2026-09;rust-canonical-visibility-evidence-cr-2026-09;rust-lexical-macro-access-cr-2026-09;rust-crate-blob-repair-cr-2026-09;rust-crate-held-blob-repair-cr-2026-09;rust-crate-module-sources-and-scoped-imports-cr-2026-09-13;rust-crate-glob-reexport-subtype-cr-2026-09-13;tuple-positional-field-receivers-2026-09-13;tuple-field-empty-name-anchors-2026-09-13;macro-fragment-source-node-identity-2026-09-13;rust-crate-public-use-binders-fw-2026-09-13;rust-crate-reexport-alias-identity-fw-2026-09-13;rust-crate-transitive-import-namespaces-fw-2026-09-13;rust-crate-inline-declaration-names-fw-2026-09-13;rust-crate-open-export-inventory-fw-2026-09-13;rust-crate-file-naming-fw-2026-09-13;rust-crate-local-reexport-inventory-routes-fw-2026-09-13;rust-crate-unknown-export-activation-fw-2026-09-13;rust-crate-2015-explicit-self-routes-fw-2026-09-13;rust-crate-import-placement-keys-fw-2026-09-13;rust-crate-canonical-restricted-visibility-fw-2026-09-13;rust-crate-external-import-gap-classification-fw-2026-09-13;rust-crate-external-bare-import-gap-fw-2026-09-13;rust-enum-export-containers-v1;native-resolution-tier-1-discovery-headers-li3-2026-09-14;native-resolution-root-demand-headers-rv-2026-09;native-resolution-crate-import-reexport-namespaces-rv-2026-09;native-resolution-sparse-reverse-lookup-identities-rv-2026-09;rust-crate-relative-import-roots-rv-2026-09;rust-crate-import-placement-key-rv-2026-09;root-path-route-segments-rv-2026-09;rust-crate-root-reference-routes-rv-2026-09",
    ";rust-crate-per-blob-declaration-candidates-rc-2026-09-14;rust-crate-import-head-staging-rc-2026-09-14;native-resolution-dense-rekey-source-identities-dg-2026-09-14;native-resolution-inline-cfg-module-placement-mr-2026-09-14;native-resolution-tier-2-families-not-persisted-li4-2026-09-15;native-resolution-tier-1-root-routes-li5-2026-09-15;native-resolution-definition-less-macro-argument-enumeration-mc2-2026-09-15;native-resolution-self-receiver-value-reference-g6-2026-09-16;native-resolution-struct-literal-let-initializer-dc-2026-09-16;native-resolution-block-local-item-scopes-pr-2026-09-17;native-resolution-member-bodies-and-item-macro-arguments-pm-2026-09-17;m8-batch-one-self-root-routes-anchors-derive-surface-lifetime-args-initializers-root-scopes-2026-09-21;m8-batch-two-conditional-binder-sites-cfg-inline-module-exports-2026-09-22;m8-batch-three-trait-body-self-sites-open-member-surface-type-bindings-item-groups-2026-09-22;m8-batch-four-impl-declaration-rows-decided-macro-decorations-inline-modules-owning-traits-2026-09-24;capital-self-type-references-2026-09;primitive-spelled-impl-owners-2026-09;scoped-generated-rust-model-declarations-2026-09;attributed-impl-member-declarations-2026-09;rust-stack-graph-batch-five-macro-export-context-2771-2026-09-26;rust-method-values-enum-field-visibility-2771-2026-09-27;rust-attributed-member-owner-2771-2026-09-27;rust-self-constructor-binding-2771-2026-09-27;rust-conditional-file-module-exports-2771-2026-09-27;rust-inert-test-attributes-2771-2026-09-27;rust-alias-nominal-identity-2771-2026-09-27;rust-projection-outputs-unsafe-attributes-2771-2026-09-27;rust-import-anchor-occurrences-2771-2026-09-27;rust-function-signature-owners-2771-2026-09-27;rust-trait-signature-owners-2771-2026-09-27;rust-declaration-reference-owners-2771-2026-09-27;rust-shared-unit-type-identity-2771-2026-09-27;rust-impl-bound-and-turbofish-reference-owners-2771-2026-09-27;rust-computed-receiver-members-enumerated-3764-2026-09-29;rust-struct-constructor-root-exports-3746-2026-09;rust-struct-pattern-variant-field-owner-3746-2026-09;rust-unit-self-value-identity-3746-2026-09-29;rust-unwrapped-member-receivers-3746-2026-09-29;rust-u1-3746-producer-2026-09-29;rust-u1-3746-parenthesized-types-2026-09-29;rust-impl-subject-frontier-resolution-gap-3746-2026-09-29;rust-tt-binding-runs-3746-2026-09-29;rust-attributed-inline-module-macros-3746-2026-09-29;rust-tt-static-call-facts-3746-2026-09-29;rust-tt-transcriber-output-proof-3746-2026-09-30;rust-closure-parameter-declared-types-3746-2026-09-30;rust-impl-generic-parameter-owner-c-2026-09-30;rust-macro-scope-f-3746-2026-09-30;rust-u2-bare-transcriber-references-matches-pattern-2026-09-30-a;rust-generic-alias-target-identity-3746-2026-09-30;rust-unindexed-macro-argument-enumeration-restored-2026-09-30-a;rust-unindexed-matches-refutable-patterns-2026-09-30-a"
);

#[cfg(test)]
pub(super) fn rust_epoch_before_type_alias_type_identity() -> String {
    let prior = salt_before_bump(Rust::SALT, "rust-type-alias-type-identity-2026-09");
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn rust_epoch_before_nested_and_extern_crate_import_facts() -> String {
    let prior = salt_before_bump(Rust::SALT, "nested-and-extern-crate-import-facts-2026-08");
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

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
// Salt bumped again: callable and property signature metadata now carries the
// parser-derived, namespace- and alias-resolved nominal return identity. Warm
// rows contain only display text and cannot serve the relational second phase.
// Salt bumped again (#2912): the PHP declaration walk now records callable
// modifier metadata -- static, and the fact that the adapter read the modifier
// nodes at all. Rows persisted before it deserialize as "nobody read the
// modifiers", so `receiver_contract_of` reports no contract and every PHP
// procedure summary stays inert on a warm workspace with no error raised
// anywhere.
// Salt bumped again (#1713): the PHP declaration walk now records the file's
// imported type names in `type_identifiers`, resolved to absolute FQ names
// through the namespace and `use` context they are written in. PHP wrote no
// row of that family at all before, so a warm workspace answers
// `imported_code_units_of` with the empty set for every file and loses the
// whole PHP import graph.
// Salt bumped again (#3104): an unbraced `namespace N;` now governs the
// statements that FOLLOW it, so a file holding more than one of them publishes
// each declaration under the namespace it is written in, and a declaration
// above the first namespace keeps the global one. Warm rows hold every
// declaration of such a file under the file's first namespace (the old #2430
// pin's fixture published `Monolog.Test.MongoDBFormatterTest`, not
// `Demo.MongoDBFormatterTest`), and the file-level qualifier those rows carry
// is that same first namespace, so both identities change.
lang_epoch!(
    Php,
    "php",
    "treesitter/php/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07;conditional-free-function-declarations-2026-07;php-query-assets-in-brokk-bifrost-php-2026-08;structured-declared-return-identities-2026-08;php-callable-modifier-metadata-2026-09;php-imported-type-names-2026-09;php-per-statement-namespace-scope-2026-09;canonical-primary-source-ownership-2026-09"
);

#[cfg(test)]
pub(super) fn php_epoch_before_imported_type_names() -> String {
    let prior = salt_before_bump(Php::SALT, "php-imported-type-names-2026-09");
    compute_epoch::<Php>(&tree_sitter_php::LANGUAGE_PHP.into(), prior)
}

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
// object records those prefixes in `source_import_prefixes`, and an anonymous
// instance declared there records them in its supertype lookup path. A warm
// workspace holds both without the package object's own package, so a
// relative import and a supertype written inside a package object resolve
// against the wrong scope.
// Salt bumped: the ordinary Scala walk now records the same leaf-identifier
// `type_identifiers` family the file-graph walk records. Rows written by the
// ordinary walk carried none at all, so a warm workspace loses every
// same-package file dependency edge.
// Salt bumped again: an `extension` group written at the top level of a
// compilation unit now yields its members as package-level declarations. The
// ordinary walk handled `extension` only inside a template body, which is not
// where Scala 3 usually writes one, so warm rows hold no declaration at all for
// a file whose only content is top-level extension methods.
// Salt bumped again (#1651): a type declaration's signature metadata now
// records the declaration's own type-parameter list, which
// `canonical_identity_of` projects as the identity's generic arity. A warm row
// carries no such record, so a cached declaration would compare unequal to the
// same declaration reparsed from unchanged source.
// Salt bumped again (#2878): a `type` alias now mints a `Class` code unit whose
// own segment is a `Type` segment, the same identity rule classes and traits
// use. `declaration_id` hashes segment kinds, so every warm row holds the old
// `Field`/`Member` identity for every Scala type alias -- and, where an alias
// and a `val` share one owner and one name, holds only one of the two
// declarations.
// Salt bumped again (#3108): a named Scala 3 `given` now yields a declaration.
// The walk recorded none at all, so a warm workspace holds no code unit for a
// given at package level or in a template body, and every consumer that reads
// the declaration inventory -- navigation, the unused-import derivation's
// import-target lookup, the Scala pack producer -- would read the absence as
// "there is nothing there".
// Salt bumped again (#3303): a type header recovered out of an ERROR node now
// records the 1-based line range every other Scala declaration records. Rows
// written before this change hold a 0-based one for that header, so a warm
// workspace reports it a line early -- and the source mtime and size that
// gate reanalysis are unchanged, so nothing else evicts those rows.
lang_epoch!(
    Scala,
    "scala",
    "treesitter/scala/",
    "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;tree-sitter-scala-0.26.2-2026-08;scala-anonymous-template-code-units-2026-08;package-object-package-scope-2026-08;same-package-type-identifier-facts-2026-08;top-level-extension-declarations-2026-08;declaration-type-parameter-arity-2026-09;scala-type-alias-type-identity-2026-09;callable-modifiers-parameter-types-and-trait-marker-2026-09;canonical-primary-source-ownership-2026-09;recovered-type-header-one-based-range-2026-09;named-given-declarations-2026-09;abstract-val-var-declarations-export-selector-3499-2026-09"
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
// Salt bumped again: C# runnable-test classification is now confined to parsed
// method attributes, recognizes the standard xUnit/NUnit/MSTest method forms,
// and admits custom xUnit-style names ending in Fact or Theory. Prior rows can
// therefore hold either stale false or stale true `contains_tests` values.
// Salt bumped again: C# type declarations now retain their structured base
// lists in file-dependency mode and directly attributed test owners are marked
// per type. Analyzer-level classification propagates that evidence to derived
// test classes, so prior rows lack both inputs even when `contains_tests` for
// the base file itself was true.
// Salt bumped again: canonical using targets now ignore tree-sitter comment
// extras. Previously sealed imports can omit valid comment-separated directives.
// Salt bumped again (#1651): a type declaration's signature metadata now
// records the declaration's own type-parameter list, which
// `canonical_identity_of` projects as the identity's generic arity. A warm row
// carries no such record, so a cached declaration would compare unequal to the
// same declaration reparsed from unchanged source.
// Salt bumped again (#2225): a C# callable now publishes the written type of
// each of its parameters, and a C# type declaration now publishes whether it
// is an interface. Both are read as published facts rather than reparsed, so a
// warm row would answer "no parameter types recorded" and "not an interface"
// for source that says otherwise. The Brokk grammar also accepts contextual
// `async` identifiers where upstream recovery could swallow later members, so
// cached declaration rows from the prior grammar must not survive the switch.
// #3197: grammar 0.23.6 repairs static local-function parsing. Node and field
// names can stay unchanged when grammar precedence changes, so explicitly
// invalidate declaration rows parsed with the broken production.
// Grammar 0.23.7 admits contextual `partial` and `required` identifiers in
// expressions, preventing assignment recovery from swallowing later members.
// Invalidate rows parsed with the older grammar even though the node-kind
// fingerprint is unchanged.
// Salt bumped again (#3300): a generic attribute name's `Attribute` shorthand
// spelling now carries the suffix on the identifier rather than after the
// arity marker, so a declaration's recorded type identifiers say
// `CacheAttribute`1` where warm rows say `Cache`1Attribute`, a spelling no
// declaration can ever match.
// Salt bumped again (#3326): a member declaration parser recovery detaches
// from a truncated type body is now indexed as that type's member, and the
// type's recorded range grows to contain it, so warm rows hold neither the
// member row nor the owner's real extent.
lang_epoch!(
    CSharp,
    "csharp",
    "treesitter/c_sharp/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;static-using-type-identifiers-2026-07;as-expression-type-identifiers-2026-07;generic-type-identity-2026-07;attribute-type-identifiers-2026-07;callable-arity-and-static-import-metadata-2026-07;generic-method-arity-identity-2026-07;structured-return-type-metadata-2026-07;tuple-element-type-identifiers-2026-07;nameof-type-identifiers-2026-07;callable-dispatch-extensibility-metadata-2026-07;fq-interned-segments-2026-07;csharp-query-assets-in-brokk-bifrost-csharp-2026-08;interop-optional-callable-arity-2026-08;callable-modifier-metadata-2026-08;preprocessor-directive-aware-parsing-2026-08;multiplication-not-pointer-type-reference-2026-08;verbatim-identifier-canonical-declaration-names-2026-08;structured-csharp-runnable-test-classification-2026-08;csharp-inherited-test-classification-2026-08;declaration-type-parameter-arity-2026-09;callable-parameter-types-and-interface-marker-2026-09;callable-override-modifier-2026-09;comment-aware-canonical-using-targets-2026-09;brokk-csharp-grammar-0.23.5-2026-09;static-local-function-grammar-0.23.6-2026-09;generic-attribute-shorthand-identity-2026-09;recovered-type-member-ownership-2026-09;contextual-partial-required-grammar-0.23.7-2026-09"
);

#[cfg(test)]
pub(super) fn csharp_epoch_before_inherited_test_classification() -> String {
    let prior = salt_before_bump(CSharp::SALT, "csharp-inherited-test-classification-2026-08");
    compute_epoch::<CSharp>(&tree_sitter_c_sharp::LANGUAGE.into(), prior)
}

#[cfg(test)]
pub(super) fn csharp_epoch_before_structured_runnable_test_classification() -> String {
    let prior = salt_before_bump(
        CSharp::SALT,
        "structured-csharp-runnable-test-classification-2026-08",
    );
    compute_epoch::<CSharp>(&tree_sitter_c_sharp::LANGUAGE.into(), prior)
}
// Salt bumped (#1548 stage 3 fleet): the Ruby `.scm` query assets moved from
// this crate's `resources/treesitter/ruby/` into `brokk-bifrost-ruby`, so the
// salted content now comes from a different crate's `include_str!`. The bytes
// are unchanged, which is exactly why the salt has to carry the relocation.
// Salt bumped again (#2912): the Ruby declaration walk now records callable
// modifier metadata for every `def` -- singleton (static) or instance, and the
// fact that the adapter read the declaration shape at all. Rows persisted
// before it deserialize as "nobody read the modifiers", so
// `receiver_contract_of` reports no contract and every Ruby procedure summary
// stays inert on a warm workspace with no error raised anywhere.
// Salt bumped again (#3459): a receiver written as a constant path
// (`Net::HTTP.get(uri)`) now lowers to the `Constant` value kind instead of
// the payload-free `Temporary` fallback. Warm semantic rows hold the old kind,
// and the dispatch rule that reads it -- the written path names the receiver
// object itself -- would never see the receiver as fixed in the source and
// would keep every such call open forever.
lang_epoch!(
    Ruby,
    "ruby",
    "treesitter/ruby/",
    "synthetic-file-scope-code-units-2026-07;attr-macro-accessor-identities-2026-07;fq-interned-segments-2026-07;ruby-query-assets-in-brokk-bifrost-ruby-2026-08;ruby-callable-modifier-metadata-2026-09;canonical-ruby-primary-load-runtime-source-2026-09-static-loads;ruby-constant-receiver-value-kind-2026-09"
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
// `kotlin-structured-signature-types-2026-08`: the same parser-derived return,
// property and extension-receiver names are now persisted as structured type
// identities. Graph resolution consumes those component vectors and must not
// read an older row as if the structured identity were genuinely absent.
// Salt bumped (#1548 stage 3 fleet): Kotlin's `highlights.scm` and grammar
// binding moved from this crate into `brokk-bifrost-jvm`. Unlike Java's and
// Scala's, this bump is not forced by the mechanism -- `treesitter/kotlin/`
// selects no entry in the salted asset set, because Kotlin is
// declaration-walk-only and neither of its `.scm` files has ever been in
// `EMBEDDED_QUERIES`. It is here for consistency with its two realm peers.
// `kotlin-constructor-callable-metadata-2026-08`: primary and secondary
// constructors now publish `SignatureMetadata::callable_is_constructor`.
// Candidate discovery consumes that fact to avoid the impossible polymorphic
// descendant expansion for constructor usage scans, so warm rows with the
// compatible false default must be re-extracted.
// `brokk-tree-sitter-kotlin-0.4.6`: grammar changes can alter parse trees and
// derived declarations, so persisted Kotlin rows from older parser releases
// must be rebuilt.
// Salt bumped again (#1651): a type declaration's signature metadata now
// records the declaration's own type-parameter list, which
// `canonical_identity_of` projects as the identity's generic arity. A warm row
// carries no such record, so a cached declaration would compare unequal to the
// same declaration reparsed from unchanged source.
// Salt bumped again (#2892): a `typealias` now mints a `Class` code unit whose
// own segment is a `Type` segment, the same identity rule classes and objects
// use. `declaration_id` hashes segment kinds, so every warm row holds the old
// `Field`/`Member` identity for every Kotlin type alias -- and, where an alias
// and a `val` share one owner and one name, holds only one of the two
// declarations.
// Salt bumped (#3202): written constructors are source declarations, so
// their binding signatures and dispatch targets retain source identity.
// Salt bumped (#3453): the Kotlin declaration walk now records callable
// modifier metadata -- the declared visibility, and whether the owning type
// scope is an `object`/`companion object` singleton, whose members bind no
// receiver value. Rows persisted before it deserialize as "nobody read the
// modifiers", so `receiver_contract_of` reports no contract,
// `modeled_procedure_key_for_unit` refuses every Kotlin workspace
// declaration, and every Kotlin procedure summary stays inert on a warm
// workspace with no error raised anywhere. The same gap was bumped for
// JavaScript and TypeScript (#2597), PHP and Ruby (#2912), and Python
// (#3451).
lang_epoch!(
    Kotlin,
    "kotlin",
    "treesitter/kotlin/",
    "brokk-tree-sitter-kotlin-0.4.6-2026-09;kotlin-core-indexing-2026-07;kotlin-class-parameter-default-arity-2026-07;kotlin-backtick-identifier-names-2026-07;kotlin-jvm-realm-imports-supertypes-2026-07;kotlin-signature-returns-receivers-2026-07;kotlin-companion-object-marker-2026-07;kotlin-structured-signature-types-2026-08;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;kotlin-constructor-callable-metadata-2026-08;declaration-type-parameter-arity-2026-09;kotlin-type-alias-type-identity-2026-09;kotlin-coordinated-source-facts-parameter-names-enum-types-2026-09;kotlin-call-binding-constructor-identity-2026-09;kotlin-callable-modifier-metadata-2026-09"
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
