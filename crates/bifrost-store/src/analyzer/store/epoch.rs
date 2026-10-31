//! Per-language analysis epoch.
//!
//! The epoch is a stable fingerprint of every input that, if changed, would
//! invalidate previously-persisted analyzer payloads. It folds in:
//!
//! - the analyzer store epoch salt
//! - the language adapter's actual `tree_sitter::Language` fingerprint
//!   (ABI version + every node kind name + every field name)
//! - the contents of the language's bundled `.scm` query files
//! - C/C++ and Python's effective source-admission policy and finite limits
//!
//! When any of these change, every row written under the previous epoch is
//! treated as logically dirty regardless of mtime/size.
//!
//! The crate version is deliberately not an input. Analyzer behavior changes
//! are tracked by the store salt, the per-language salts, the grammar
//! fingerprint, and the query files. A release that changes none of these
//! keeps the warm cache valid.
//!
//! The grammar fingerprint follows the resolved `Language` ABI, node kinds,
//! and field names rather than a hard-coded crate version. It does not hash
//! generated parse tables. A grammar correction can change parser behavior
//! without changing those tables of names; rotate the affected language salts
//! in that case (#5336). Semantic artifact adapter versions are a separate
//! invalidation boundary when the changed parse affects their output.

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
    "gap-reasons-without-catalog-rows-3737-2026-09-29;bounded-declared-head-activation-j3f-2026-10"
);

#[doc(hidden)]
pub fn base_epoch_for(language: Language, ts_language: &TsLanguage) -> &'static str {
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

#[doc(hidden)]
pub trait LanguageEpoch {
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

#[doc(hidden)]
pub fn compute_epoch<L: LanguageEpoch>(ts_language: &TsLanguage, language_salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost-analyzer-epoch-v2\n");
    hasher.update(STORE_EPOCH_SALT.as_bytes());
    hasher.update(b"\n");
    hasher.update(L::NAME.as_bytes());
    hasher.update(b"\n");
    hasher.update(language_salt.as_bytes());
    // Intrinsic inventories certify absence during JVM resolution. A changed
    // generated closure must never reuse results certified by older names.
    if matches!(L::NAME, "java" | "kotlin" | "scala") {
        hasher.update(brokk_bifrost_jvm::intrinsics::INVENTORY_EPOCH_INPUT.as_bytes());
    }

    hasher.update(b"\n");
    // Persisted structural facts carry this version, and a reader does not
    // repair an indexed source whose facts are at another version. A bump
    // must therefore invalidate every language's rows by itself, rather than
    // relying on a grammar, query or salt change landing beside it.
    hasher.update(
        format!(
            "structural-facts-v{}",
            crate::analyzer::store::structural_vocabulary::STRUCTURAL_FACTS_VERSION
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

/// Fingerprint the resolved grammar's ABI, node kinds, and field names.
/// Parse-table-only behavior changes require a language salt rotation.
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
    ($visibility:vis $struct:ident, $name:literal, $dir:literal) => {
        lang_epoch!($visibility $struct, $name, $dir, "");
    };
    ($visibility:vis $struct:ident, $name:literal, $dir:literal, $salt:literal) => {
        #[doc(hidden)]
        $visibility struct $struct;
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
    ($visibility:vis $struct:ident, $name:literal, $dir:literal, $salt:literal, $append:literal) => {
        #[doc(hidden)]
        $visibility struct $struct;
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
// Salt bumped: Java method callable signatures now publish their declared
// result type slots. Warm rows with empty result lists cannot project nested
// source-call results into argument applicability.
// Salt bumped: Java callable metadata now records whether final, private,
// static, constructor, and final-owner declarations close method dispatch.
// Warm rows with no dispatch fact cannot prove those target sets complete.
// Salt bumped: expression-context simple-name type candidates now publish
// same-package references through the type/value lookup choice.
// #4366: underscore patterns are identifier facts; warm rows lack them.
// #6803: gap-reason provenance now follows minting, including uncovered reasons.
// Quicksilver round 5: anonymous-return evidence now stops at local records,
// enums and annotation types as well as classes, interfaces and lambdas, so
// a return inside a local type no longer counts for the enclosing method.
// Warm anonymous-return rows for unchanged bytes hold the old attribution.
// #7547: Java structural facts now publish decoded ordinary string values.
// #7024: a super::method reference lowers through the superclass receiver
// route like super.method(), so persisted sites, slots and transfers change
// for unchanged bytes.
// #7576: reference casts now publish their lowered target as the expression type.
// #7720: statement conditions and all unary operands now publish expression facts.
// #7187: regenerate JVM structural type-parameter occurrence roles.
lang_epoch!(
    Java,
    "java",
    "treesitter/java/",
    "java-gap-reason-mint-provenance-6803-2026-10-24;synthetic-file-scope-code-units-2026-07;no-implicit-constructor-units-2026-07;source-backed-package-modules-2026-07;ast-test-detection-2026-07;callable-arity-metadata-2026-07;annotated-spread-parameter-metadata-2026-07;compact-record-constructors-2026-07;fq-interned-segments-2026-07;field-modifier-metadata-2026-08;static-import-path-kind-2026-08;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;class-like-static-metadata-2026-08;native-callable-modifier-metadata-2026-08;local-anonymous-and-enum-body-owners-2026-08;nested-anonymous-owner-identity-2026-08;enum-constant-body-and-coordinate-local-class-owners-2026-08;same-package-type-identifier-facts-2026-08;native-resolution-visibility-eligibility-2026-09;native-resolution-root-import-anchors-2026-09;declaration-type-parameter-arity-2026-09;coordinated-canonical-source-production-2026-09;structured-package-identity-2026-09;source-owned-declaration-visibility-2026-09;canonical-visibility-storage-2026-09;shared-java-declaration-shapes-2026-09;canonical-java-declaration-types-2026-09;implicit-resource-release-3410;native-static-import-root-demands-2026-09-28;java-array-type-components-2026-09;annotation-and-class-literal-reference-sites-2026-10;java-callable-result-types-2026-10;java-callable-dispatch-extensibility-2026-10;java-same-package-type-or-value-references-2026-10;java-recovered-missing-identifier-gaps-4290-4364-4391-2026-10-03;java-underscore-pattern-identifiers-4366-2026-10;java-package-lookups-cover-placement-j1a-2026-10;java-declaration-parts-bind-nothing-j1b-2026-10;java-default-constructor-site-j1c-2026-10;java-anonymous-written-type-reference-j2a-2026-10;java-for-loop-scope-j3a-2026-10;java-enhanced-for-binder-j3b-2026-10;java-resource-binder-j3c-2026-10;java-record-pattern-arm-binders-j3d-2026-10;java-module-service-type-occurrences-j3e-2026-10;java-resource-initializer-exclusion-j3f-2026-10;java-positioned-canonical-import-segment-references-l2-2026-10;local-write-value-joins-5015-2026-10;unknown-local-incoming-values-5015-2026-10;root-import-kind-facts-5658-2026-10;java-complete-provider-inventory-absence-above-v49-2026-10;java-producer-rules-port-6291-2026-10-23;quicksilver-round5-java-local-type-return-scopes-2026-10;java-super-method-reference-7024-2026-10;java-regex-facts-4365-2026-10;java-structural-expression-statement-kinds-4365-2026-10;java-string-literal-values-7547-2026-10;java-reference-cast-types-7576-2026-10;java-condition-expression-lowering-7720-2026-10;canonical-overload-discriminator-7505-v1;7187-jvm-type-parameter-bindings;scala-as-instance-of-expression-type-7577-2026-10"
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
// Named and blank imports plus qualified type syntax now rely on their
// structured root-import routes; only dot imports leave name inventory open.
// Warm bundles retain false unsupported-route gaps on imported call/type sites.
// Function literals now own lexical scopes, named result binders, and ordered
// return observations; prior facts treated each literal and its returns as
// inventory-blocking frontiers.
// Generic indexed callees now retain their terminal call name and receiver in
// structural facts; warm rows otherwise classify the exact generic call as a
// field access and cannot project its call relation.
// Generic applications retain an exact base-name reference while the full
// application semantics remain an explicit unsupported frontier.
// Go publishes package references through the shared source-owned helper and
// scopes placement gaps to package declaration endpoints. Warm parsed facts
// still contain the fragment-wide gap and must be re-extracted.
// Anonymous struct field layouts and tags now have source facts and native
// identity bridges; local named type owners also have source projections.
// #6803: gap-reason provenance now follows minting, including memberless packages.
// #6958: references inside Go type bodies skip member binders when resolving lexically.
// Unchanged Go bytes now produce corrected generic embeddings, value signatures,
// literal kinds, unescaped import paths, array element types, structural discard
// rows, and pointer source types; go.mod/go.work reject raw strings.
// #7544: Receiver wrappers and type arguments skip extras before binding positions.
// #7391: Assertion expressions publish their result type and comma-ok bool.
lang_epoch!(
    Go,
    "go",
    "treesitter/go/",
    "go-array-length-lexical-scope-6958-2026-10-26;go-type-syntax-member-scope-exclusion-6925-2026-10-25;go-gap-reason-mint-provenance-6803-2026-10-24;go-interface-members-anonymous-owners-parenthesized-conversions-6524-2026-10-22;go-method-result-applicability-independent-2026-10;go-canonical-import-path-fqn-2026-06;synthetic-file-scope-code-units-2026-07;raw-package-qualifier-2026-07;fq-interned-segments-2026-07;return-expression-list-value-identity-2026-07;go-query-assets-in-brokk-bifrost-go-2026-08;named-type-underlying-identity-2026-08;native-resolution-root-import-anchors-2026-09;coordinated-canonical-source-production-2026-09;canonical-go-declaration-source-2026-09;empty-interface-map-key-identity-2026-09;go-1-26-new-expression-parse-2026-09;go-constant-string-values-2026-09;go-callable-modifier-metadata-2026-09;native-unnamed-signatures-and-result-arity-2026-09-28;go-container-type-components-2026-09;native-go-selector-assignment-references-2026-09-30;native-go-call-type-conversion-identities-2026-09-30;native-go-if-condition-reference-traversal-2026-09-30;go-universe-call-name-binding-2026-09;native-go-selector-callees-and-reference-owners-2026-09-30;go-exact-named-qualified-import-routes-2026-10;go-positioned-callee-projections-direct-type-switch-defaults-4284-4285-2026-10-03;go-expression-reference-type-frontiers-2026-10-04;go-function-literal-callable-scopes-2026-10-04;go-statement-binder-reference-frontiers-2026-10-04;go-interface-and-function-types-2026-10-04;go-call-composite-reference-enumeration-frontiers-2026-10-04;go-anonymous-interface-dot-import-switch-reference-routes-2026-10-04;go-indexed-generic-call-structural-names-2026-10;go-generic-navigation-formals-applications-receivers-2026-10-04;go-function-type-parameter-owner-exclusion-2026-10-04;go-type-answer-parity-2026-10-04;go-explicit-generic-type-substitution-2026-10-05;go-generic-application-frontiers-2026-10-05;go-source-membership-digest-2026-10;go-source-owned-package-lookups-and-scoped-placement-gaps-2026-10;go-argument-independent-call-reference-coverage-2026-10;go-anonymous-struct-fields-tags-and-local-owners-5074-2026-10;go-anonymous-struct-integrated-producer-5074-2026-10-17;local-write-value-joins-5015-2026-10;isolated-mutation-gaps-5015-2026-10;go-clause-static-type-isolation-5015-2026-10;unknown-local-incoming-values-5015-2026-10;go-index-slice-component-projections-stable-transfer-codes-2026-10;qualified-call-or-conversion-callees-2026-10-17;go-quicksilver-round11-survivor-fixes-2026-10;go-receiver-comment-nodes-7544-2026-10;go-type-body-selector-scope-7571-2026-10;go-func-literal-signature-types-7647-2026-10;go-field-receiver-origins-7517-2026-10;go-switch-alias-variadic-slots-7509-2026-10;go-type-assertion-results-7391-2026-10"
);

/// The Go epoch as it stood before the #3455 callable-modifier bump.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn go_epoch_before_callable_modifier_metadata() -> String {
    compute_epoch_before_bump::<Go>(
        &tree_sitter_go::LANGUAGE.into(),
        "go-callable-modifier-metadata-2026-09",
    )
}

/// The Go epoch immediately before the transient-placement membership digest.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn go_epoch_before_source_membership_digest() -> String {
    let prior = salt_before_bump(
        Go::SALT,
        "go-source-owned-package-lookups-and-scoped-placement-gaps-2026-10",
    );
    let prior = salt_before_bump(prior, "go-source-membership-digest-2026-10");
    compute_epoch::<Go>(&tree_sitter_go::LANGUAGE.into(), prior)
}

/// The Go epoch immediately before source-owned package lookup facts.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn go_epoch_before_source_owned_package_lookups() -> String {
    let prior = salt_before_bump(
        Go::SALT,
        "go-source-owned-package-lookups-and-scoped-placement-gaps-2026-10",
    );
    compute_epoch::<Go>(&tree_sitter_go::LANGUAGE.into(), prior)
}

/// The Go epoch immediately before argument-independent call gaps stopped
/// contributing to lexical reference coverage.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn go_epoch_before_argument_independent_call_reference_coverage() -> String {
    compute_epoch_before_bump::<Go>(
        &tree_sitter_go::LANGUAGE.into(),
        "go-argument-independent-call-reference-coverage-2026-10",
    )
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
// Salt bumped again (#3501): when a C or C++ parse ends inside constructs it
// never closed, tree-sitter returns an ERROR root, and the walk now records
// every declaration after the outermost open construct as recovered over an
// interval that runs to the end of the file. A warm row holds no such record,
// so the SQLite amalgamation's declarations would read as complete parses.
// Salt bumped again (#3501): such a blob is now persisted with
// `blob_meta.parse_completeness = 'partial'` (migration 0143). A warm row
// written before reads back as the column default, 'complete', so the
// amalgamation would again be reported as a complete parse.
// Salt bumped again (#4343): C++ base rows now retain their access specifier
// in the persisted source-facts publication. Warm rows written before the
// migration have only the `unknown` default, so they must be republished.
// The ABI 15 transition changes the grammar fingerprint, but the 0.24.2
// namespace-constructor repair changes parser tables without changing node
// kinds or fields. Rotate warm rows produced by the 0.24.1 candidate too.
// Grammar 0.24.3 repairs closing-linkage guard ancestry without introducing
// node kinds or fields. Do not reuse facts parsed with the malformed guard.
// #5868: recovered literal namespace heads change persisted qualified names
// and Module provenance for unchanged source bytes; republish both C++ readings.
// Its separate canonical-owner salt also rotates consumers of lexical member
// ownership while preserving the literal-head producer token.
// Grammar 0.24.4 (#6309) moved its node/field fingerprint, but the adapter
// fixes that read its clean macro shapes (a `macro_type_specifier` field that
// absorbed its class terminator, a sentinel `type` whose head became a
// `macro_modifier_declarator` chain, and a `macro_modifier` decorated return
// type) change persisted owners, member units and return identities for
// unchanged bytes under that same fingerprint.
// #6346: under grammar 0.24.4 a macro-decorated constructor with member
// initializers parses as one field declaration whose later initializers are
// function declarators. Those are no longer published as member functions and
// the constructor head is now a definition, so warm rows for unchanged bytes
// hold false callables.
// #3298: under grammar 0.24.4 a class-scope macro invocation that swallowed
// the access label after it now publishes the members under that label and
// gives later members the label's access, for unchanged source bytes.
// #6325: an `#else` that grammar 0.24.4 displaced into a declaration's ERROR
// now opens the alternative branch, and recovered declarations read their
// preprocessor context at the recovered start, so persisted guard
// requirements, exhaustive families and guard-completion bytes change for
// unchanged bytes.
// #6373: under grammar 0.24.4 a type parameter whose default holds an abstract
// declarator (`typename U = T*`) recovers as an unnamed non-type parameter; it
// is now persisted as type parameter `U`, for unchanged source bytes.
// #2928: under grammar 0.24.4 a function-like export-macro class head with no
// base clause (`class API(2, 2) Name final { ... }`) keeps its name inside the
// declarator; that class and its members are published again for unchanged
// source bytes.
// #2184: under grammar 0.24.4 a macro-decorated return type
// (`API static inline T make()`) parses as a leading `macro_modifier` and a
// plain `type`; its same-file alias precedence applies again, so resolved type
// references change for unchanged source bytes.
// #3093: a parsed namespace level that records its name subspan (#4292) again
// carries its source fact (guards, context, dependency names), for unchanged
// source bytes.
// C/C++ salt bumped again (quicksilver round 4 on brokk-bifrost-cpp): base
// access no longer leaks across commas, range-for and const facts read the
// grammar's own fields, exact sizes respect indirection and unions, enum
// fallbacks, brace matching and include paths come from the AST instead of
// source text, line splices join tokens (C phase 2), alloca bounds must
// constrain the loop variable, uppercase class and namespace names are no
// longer vetoed, and recovered aggregates keep every declarator. Old parsed
// blobs hold the earlier declaration, base, structural and include rows.
// #6898 republishes recovered constructors, macro fields, attributed/exported
// classes, template parameter metadata, dependent names/callees, and sentinel
// declaration/source-property facts with exact input origins. Grammar 0.24.6
// parses an unnamed enum's base without recovery; this parse-table-only change
// leaves the grammar fingerprint unchanged (#6902).
// #6902 item 8: an opaque `#if EXPR` guard is now a Boolean atom, so guard
// merging during declaration recovery sees contradictions between opaque
// guards; source-occurrence guard facts can change for unchanged bytes.
// #6902 item 12: namespace aliases are published as typed C++ source facts
// (`source_cpp_namespace_aliases`, migration 0210). Warm blobs parsed before
// carry no alias rows, so namespace-alias qualifiers would stay unbound.
// #7033 (#6902 item 7): class-template owners and callable template heads
// change persisted C/C++ declaration facts for unchanged bytes.
// #6902 item 11: the C++ reading now mints named function-local classes and
// their members under a callable-plus-block identity; warm rows omit them.
// #7082 (#6902 items 1, 3, 5, 6): brokk-tree-sitter-cpp 0.24.8 parses
// semicolon-free macro envelopes, function-like export-class heads, member
// attribute macros and pointer-to-member declarators, and member-pointer
// parameter signatures keep their owning class. Declarations, signatures and
// recovery records change for unchanged bytes.
// #6902 item 7 follow-up: an out-of-line member template under nested heads
// is now indexed, and a specialization member definition keeps its
// specialization owner (`Box<T*>`) instead of the primary's.
lang_epoch!(
    Cpp,
    "cpp",
    "treesitter/cpp/",
    "synthetic-file-scope-code-units-2026-07;recovered-designator-declarations-2026-07;fielded-declarator-routing-2026-07;bare-exported-class-declarators-2026-07;function-like-exported-class-declarators-2026-07;malformed-multiple-base-exported-class-declarators-2026-07;template-alias-declarations-2026-07;structured-return-type-metadata-2026-07;class-owned-alias-identity-2026-07;templated-out-of-line-owner-identity-2026-07;macro-exported-class-field-owner-2026-07;cpp-partial-specialization-ownership-dispatch-2026-07;abstract-parameter-declarator-signatures-2026-07;cpp-template-alias-specialization-dispatch-2026-07;single-base-exported-class-identity-2026-07;callable-linkage-metadata-2026-07;callable-declaration-role-metadata-2026-07;cpp-parameter-type-qualifiers-2026-07;macro-sentinel-region-reparse-2026-07;fragmented-export-class-member-recovery-2026-07;using-directive-owner-namespace-recovery-2026-07;bare-call-global-namespace-lookup-2026-07;nested-class-out-of-line-owner-identity-2026-07;fq-interned-segments-2026-07;recovered-typedef-base-alias-identity-2026-07;inline-classlike-and-macro-prefix-declarations-2026-08;template-parameter-pack-binding-and-qualified-base-initializers-2026-08;recovered-partial-specialization-member-ownership-2026-08;macro-field-terminator-scope-2026-08;complete-sentinel-class-tail-2026-08;sentinel-class-before-member-callable-2026-08;fragmented-class-signature-error-members-2026-08;plain-fragmented-class-constraint-constructor-2026-08;plain-fragmented-class-sibling-ownership-2026-08;fragmented-export-constructor-initializer-2026-08;fragmented-export-constructor-structured-sibling-boundary-2026-08;fragmented-export-sibling-class-parent-scope-2026-08;macro-decorated-template-class-scope-2026-08;conditional-alias-physical-ranges-2026-08;macro-argument-typedef-declarator-2026-08;enum-enumerator-child-ownership-2026-08;sentinel-error-envelope-sibling-recovery-2026-08;cpp-query-assets-in-brokk-bifrost-cpp-2026-08;structural-declarator-qualifier-suffix-and-top-level-parameter-cv-2026-08;macro-fragmented-plain-class-member-signatures-2026-08;namespaced-plain-fragment-boundary-2026-08;templated-plain-fragment-prefix-and-sibling-ownership-2026-08;macro-displaced-scalar-return-callable-name-2026-08;explicit-object-callable-arity-2026-08;structured-callable-parameter-types-2026-08;macro-template-return-free-function-ownership-2026-08;abstract-reference-declarator-identity-2026-08;c-tag-scope-2026-08;c-header-projection-2026-08;temporal-macro-definition-identity-2026-08;nested-include-claims-2026-08;recovered-named-class-member-linkage-2026-09;positional-export-macro-class-names-2026-09;collapsed-namespace-head-scope-2026-09;collapsed-aggregate-definition-ranges-2026-09;lexical-container-partition-2026-09;function-macro-replacement-local-scope-2026-09;canonical-primary-source-ownership-2026-09;canonical-field-activation-and-recovered-context-2026-09;canonical-generated-field-types-and-context-2026-09;canonical-recovered-field-types-and-callable-bodies-2026-09;forward-declared-class-declaration-ranges-2026-09;unterminated-macro-invocation-fields-2026-09;anonymous-aggregate-members-in-both-dialects-2026-09;recovered-namespace-header-ranges-2026-09;unproven-brace-pairing-extents-2026-09;free-function-callee-value-references-2026-09;cpp-callable-modifier-metadata-2026-09;cpp-declared-access-separate-from-linkage-2026-09;cpp-source-member-prototype-units-2026-09;cpp-member-dispatch-extensibility-2026-09;namespace-recovery-ancestry-authority-2026-09;cpp-completed-callable-guard-proof-2771-2026-09-26;raw-quoted-include-header-paths-3806-2026-10;unclosed-construct-recovery-3501-2026-10;unclosed-construct-partial-completeness-3501-2026-10;cpp-recovered-namespace-name-tokens-4292-2026-10-03;cpp-direct-linkage-body-declarations-4414-2026-10-03;c-projection-keeps-tags-nested-in-cpp-classes-4427-2026-10-04;cpp-base-specifier-access-4343-2026-10;brokk-tree-sitter-cpp-0.24.2-abi15-4407-2026-10;structured-callee-spine-5019-2026-10;split-linkage-closing-guard-grammar-0.24.3-4966-2026-10;cpp-alias-declaration-occurrence-role-2430-2026-10;structural-line-numeric-data-admission-5408-2026-10;cpp-recovered-literal-namespace-head-5868-2026-10;cpp-canonical-lexical-owner-5868-2026-10;macro-declaration-grammar-adapter-parity-6309-2026-10;macro-initialized-constructor-field-6346-2026-10;macro-swallowed-access-label-members-3298-2026-10;displaced-else-branch-guards-6325-2026-10;recovered-pointer-default-type-parameter-6373-2026-10;function-like-export-class-no-base-head-2928-2026-10;macro-modifier-return-same-file-alias-2184-2026-10;parsed-namespace-level-source-facts-3093-2026-10;quicksilver-round4-cpp-source-facts-structure-declarations-2026-10;quicksilver-round4-batch2-6898-2026-10;cpp-opaque-guard-implication-6902-2026-10;cpp-namespace-alias-source-facts-6902-2026-10;cpp-class-template-owners-6902-item7-7033-2026-10;cpp-function-local-classes-6902-2026-10;brokk-tree-sitter-cpp-0.24.8-6902-items-1-3-5-6-7082-2026-10;cpp-template-member-owners-6902-item7-2026-10;canonical-overload-discriminator-7505-v1"
);

/// The C and C++ epoch before a parse left inside an unclosed construct was
/// persisted as partial (#3501).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn cpp_epoch_before_partial_parse_completeness() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "unclosed-construct-partial-completeness-3501-2026-10",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

/// The C and C++ epoch before native quoted header paths were parsed correctly.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn cpp_epoch_before_raw_quoted_include_header_paths() -> String {
    let prior = salt_before_bump(Cpp::SALT, "raw-quoted-include-header-paths-3806-2026-10");
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
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn salt_before_bump<'a>(salt: &'a str, bump: &str) -> &'a str {
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub enum TestEpochLanguage {
    Cpp,
    JavaScript,
    TypeScript,
    Kotlin,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn epoch_before_bump(language: TestEpochLanguage, bump: &str) -> String {
    match language {
        TestEpochLanguage::Cpp => {
            compute_epoch_before_bump::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), bump)
        }
        TestEpochLanguage::JavaScript => {
            compute_epoch_before_bump::<JavaScript>(&tree_sitter_javascript::LANGUAGE.into(), bump)
        }
        TestEpochLanguage::TypeScript => compute_epoch_before_bump::<TypeScript>(
            &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            bump,
        ),
        TestEpochLanguage::Kotlin => compute_epoch_before_bump::<Kotlin>(
            &brokk_bifrost_jvm::kotlin::language::LANGUAGE.into(),
            bump,
        ),
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[doc(hidden)]
pub fn compute_epoch_before_bump<L: LanguageEpoch>(ts_language: &TsLanguage, bump: &str) -> String {
    compute_epoch::<L>(ts_language, salt_before_bump(L::SALT, bump))
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn cpp_epoch_before_macro_template_return_free_function_ownership() -> String {
    let prior = salt_before_bump(
        Cpp::SALT,
        "macro-template-return-free-function-ownership-2026-08",
    );
    compute_epoch::<Cpp>(&tree_sitter_cpp::LANGUAGE.into(), prior)
}

#[cfg(test)]
mod query_content_tests {
    use super::normalized_query_contents;

    #[cfg(test)]
    #[test]
    fn normalizes_embedded_query_crlf_for_cross_platform_epochs() {
        assert_eq!(
            normalized_query_contents("(node) @capture\r\n(comment) @comment\r\n"),
            "(node) @capture\n(comment) @comment\n"
        );
    }
}
// The JavaScript salt includes the 0.25.3 JavaScript-grammar ampersand repair
// (#4409): `.js` files with JSX parse with that grammar, and the repair adds no
// node kind or field, so the grammar fingerprint cannot detect it.
// Both language salts include the 0.23.5 TSX ampersand repair. The epoch is
// memoized per language, so its first plain-JS/TS grammar fingerprint cannot
// detect a TSX-only parser change. Rotate both languages to retire old .jsx
// and .tsx rows parsed through ERROR recovery, including trailing-quote cases.
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
// #4385: JS/TS structural facts gain decoded literals, constructor call kinds,
// function binders, object-method properties and positions; warm rows lack them.
// #3843: generic import rows now include source-bearing re-exports. Old
// JS/TS blobs omit these direct dependencies and must be republished.
// Salt bumped again (#3864): the properties of a function-local object
// literal are now scoped to the binding that creates the object.
// #3864: both adapters now scope bound wrapper exports by lexical identity,
// prove UMD export forwarding from direct calls, and share assignment extraction.
// Retire persisted declarations, ownership and source facts under both epochs.
// #4479: TypeScript/TSX now accepts raw NUL in string/comment payloads.
// Lexer/scanner changes keep the same node/field inventory, and JSX shares
// JavaScript's memoized epoch, so both language salts must retire old rows.
// #5295: Shared static object keys and structural strings decode exact JS
// UTF-16 values. Retire raw escaped declaration names and old literal values.
// #5336: the TypeScript grammar now keeps calls to an imported contextual
// `using` identifier out of assignment recovery. TSX and JSX both consume this
// grammar, but its parse-table change is not represented in the node/field
// fingerprint, so both shared language epochs must retire their old rows.
// Salt bumped again: quicksilver round 7 fixes change persisted JS/TS declarations, structural facts, import facts and component props for unchanged bytes.
lang_epoch!(
    JavaScript,
    "javascript",
    "treesitter/javascript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;structured-class-field-properties-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08;js-ts-callable-modifier-metadata-2026-08;js-private-name-assignment-is-not-a-declaration-2026-08;structured-rule-tester-test-detection-2026-08;structured-js-ts-test-classification-2026-08;canonical-primary-source-ownership-2026-09;js-nested-object-literal-property-indexing-2026-09;jsx-dialect-parsed-with-tsx-grammar-2026-09;js-grammar-reserved-word-jsx-names-2026-09;js-ts-augmented-template-operand-flows-3386;js-primary-walk-alias-and-local-object-metadata-2771-2026-09-26;tsx-literal-ampersands-0.23.5;js-ts-codeql-parity-facts-4385-2026-10;js-ts-source-bearing-reexport-file-dependencies-3843-2026-10;js-jsx-literal-ampersands-0.25.3-4409;ts-tsx-raw-nul-content-0.23.6-4479;structured-callee-spine-5019-2026-10;jsts-lexical-owner-code-unit-identity-3864-2026-10;ts-tsx-contextual-using-grammar-0.23.7-5336;js-ts-decoded-static-property-keys-5295;js-ts-var-binding-scopes-5574-2026-10;js-assignment-structural-owners-5589-2026-10;jsts-commonjs-lexical-export-owners-3864-2026-10;jsts-commonjs-lexical-export-owners-3864-landing-2026-10-17;js-ts-quicksilver-round7-survivor-fixes-2026-10"
);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn javascript_epoch_before_private_name_assignment_declarations() -> String {
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
// Salt bumped again (#3502 reopened): array and indexed-access import types
// now retain complete declarations instead of publishing ranges from MISSING
// recovery. Both TypeScript and TSX storage identities must retire old rows.
// #4479: raw NUL lexer/scanner support also retires both TS dialects; the
// node/field fingerprint alone does not identify the changed parser behavior.
// #5336: imported contextual `using(...)` calls now parse as call expressions
// instead of being swallowed by assignment recovery. The parser's changed
// precedence tables leave the node/field fingerprint unchanged, so both TS
// dialect storage keys need a new shared epoch.
// Salt bumped again: quicksilver round 7 fixes change persisted JS/TS declarations, structural facts, import facts and component props for unchanged bytes.
lang_epoch!(
    TypeScript,
    "typescript",
    "treesitter/typescript/",
    "synthetic-file-scope-code-units-2026-07;anonymous-default-export-units-2026-07;fq-interned-segments-2026-07;js-ts-drift-parity-2026-07;js-ts-query-assets-in-brokk-bifrost-js-ts-2026-08;ts-overload-declaration-only-metadata-2026-08;program-scope-plain-value-identities-2026-08;ts-inline-return-type-members-2026-08;js-ts-callable-modifier-metadata-2026-08;structured-rule-tester-test-detection-2026-08;structured-js-ts-test-classification-2026-08;ts-type-alias-type-identity-2026-09;canonical-primary-source-ownership-2026-09;js-ts-augmented-template-operand-flows-3386;ts-grammar-declaration-correctness-3502;ts-import-type-compositions-3502;tsx-literal-ampersands-0.23.5;js-ts-codeql-parity-facts-4385-2026-10;js-ts-source-bearing-reexport-file-dependencies-3843-2026-10;ts-tsx-raw-nul-content-0.23.6-4479;structured-callee-spine-5019-2026-10;ts-tsx-contextual-using-grammar-0.23.7-5336;js-ts-decoded-static-property-keys-5295;js-ts-var-binding-scopes-5574-2026-10;js-assignment-structural-owners-5589-2026-10;jsts-commonjs-lexical-export-owners-3864-2026-10;jsts-commonjs-lexical-export-owners-3864-landing-2026-10-17;js-ts-quicksilver-round7-survivor-fixes-2026-10"
);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn typescript_epoch_before_type_alias_type_identity() -> String {
    compute_epoch_before_bump::<TypeScript>(
        &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "ts-type-alias-type-identity-2026-09",
    )
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
// Salts bumped (#4323, #4332, #4455): Python callable signature metadata
// retains multiline headers, AST-derived parameter identity spans after
// header normalization, and positional arity.
// The origin merge combines those facts with origin's decoded literal and
// string/list structural facts; invalidate workspaces that persisted either
// side's pre-merge fact set. #3851 adds normalized Python await facts.
// #6803: gap-reason provenance now follows minting, including uncovered reasons.
// #6509: retain every module assignment writer's exact source bridge and range.
// #6982: conditional guards select operands past grammar extras.
// Quicksilver round 6: regex facts (verbose comments, quantified group width,
// repeated quantifiers, capture ends, scoped flags), concatenated strings and
// __all__ displays that skip comments, and member_type annotation paths change
// for unchanged bytes.
// #6961: contains_tests is decided from the parsed tree (async tests count;
// string and comment lookalikes do not), so blob_meta.contains_tests changes
// for unchanged bytes.
// #7735: class and def binding targets observe their own binding commit, not an earlier import.
lang_epoch!(
    Python,
    "python",
    "treesitter/python/",
    // #7671: decorator references belong to their decorated declaration, so
    // persisted reference-owner rows must be republished.
    // #7672: method receivers record their own first parameter as the current instance.
    // #7673: qualifiers of type-position attributes publish value roots.
    "python-declaration-commit-points-7735-2026-10;python-type-attribute-roots-7673-2026-10;python-callable-receiver-origins-7672-2026-10;python-decorator-reference-owners-7671-2026-10;python-native-definition-presentation-5658-m2-2026-10-26;python-member-operation-names-7182-2026-10;python-recovered-root-module-scope-5658-2026-10;python-conditional-guard-operands-6982-2026-10;python-module-assignment-occurrences-6509-2026-10;python-gap-reason-mint-provenance-6803-2026-10-24;synthetic-file-scope-code-units-2026-07;structured-python-import-paths-2026-07;fq-interned-segments-2026-07;python-query-assets-in-brokk-bifrost-python-2026-08;python-setuptools-import-roots-2026-08;python-class-rebinding-navigation-ranges-2026-08;python-setup-py-import-roots-2026-09;coordinated-python-source-production-2026-09;canonical-python-declaration-annotations-2026-09;python-source-only-callable-annotations-2026-09;python-subscripted-and-unnameable-bases-2026-09;python-bracketed-unpacking-self-attributes-2026-09;python-chained-assignment-targets-2026-09;python-class-qualified-call-binding-2026-09;python-type-flow-builtin-class-identities-2026-09;python-type-flow-unmodeled-guards-2026-09;python-scoped-dynamic-writes-3129;python-declared-diverging-calls-3135;python-structured-refinement-targets-3196;canonical-python-generic-return-owner-2026-09;python-implicit-resource-release-3410;python-augmented-string-operand-flows-3386;python-callable-modifier-metadata-2026-09;python-replacement-owned-metadata-links-2771-2026-09-26;python-await-structural-kind-3851-2026-10;python-explicit-export-precedence-and-constructor-attribution-3390-4416-4417-2026-10-03;python-binding-parameter-roles-4323-2026-10;python-comparison-binary-structural-facts-4334-2026-10-03;python-structural-literal-collection-facts-2026-10;python-direct-assignment-shapes-2026-10;python-integer-literal-bounded-values-2026-10;python-decoded-duplicate-dictionary-keys-4335-2026-10;python-callable-arity-4332-2026-10-03;python-decoded-string-values-and-list-literals-4342-2026-10;python-origin-merge-facts-2026-10-04;python-crlf-formal-offsets-2026-10-04;python-regex-zero-width-ranges-4454-2026-10;python-empty-regex-sequence-ranges-2026-10-04;python-node-derived-parameter-offsets-4455-2026-10-04;python-exact-factory-and-access-results-4321-2026-10-06;python-exact-call-result-class-flow-4321-2026-10-06;python-codeql-regex-facts-4650-2026-10;structured-callee-spine-5019-2026-10;python-lexical-loop-initializer-proof-5339-2026-10;python-branch-local-hostname-like-separators-5293-2026-10;python-literal-call-pack-arguments-4648-2026-10;python-typed-variadic-parameter-binders-5658-m4-1-2026-10;python-authored-typed-owners-receiver-roles-and-assignment-values-5658-m4-4c-2026-10;quicksilver-round6-python-regex-structural-annotation-facts-2026-10;python-contains-tests-from-tree-6961-2026-10"
);

/// The Python epoch as it stood before the #3451 callable-modifier bump.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn python_epoch_before_callable_modifier_metadata() -> String {
    compute_epoch_before_bump::<Python>(
        &tree_sitter_python::LANGUAGE.into(),
        "python-callable-modifier-metadata-2026-09",
    )
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
// Rust salt bumped again: the Rust walk now
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
// #3851: Rust structural facts publish async callable modifiers and await
// expressions; rebuild rows produced before those AST-backed facts existed.
// Salt bumped (#3828): Rust generic type aliases publish relational formal,
// target-expression, and ordered type-application argument facts.
// Salt bumped (#3828): qualified macro references retain their source-owned
// crate-root route, so old interiors must be republished for macro discovery.
// Salt bumped (#4389): reference and pointer alias transfers use the written
// pointee identity and preserve its structured qualifier deltas.
// Salt bumped again: a non-generic alias such as `type Alias = Box<Item>`
// transfers its applied written identity again instead of the nominal head,
// so Deref payloads behind the alias resolve; only generic aliases transfer
// the nominal head.
// Salt bumped (#4314): Rust call structural facts now publish the written
// generic type arguments of callable and scoped turbofish paths.
// Salt bumped (#4450): malformed cooked and raw string literals can retain
// structural facts with no value instead of aborting source-fact collection.
// Salt bumped (#4448): omit empty recovered inner-attribute names and retain
// source visibility per declaration when signature metadata is deduplicated.
// Salt bumped (#4451): cfg alternatives that share a CodeUnit and signature
// retain separate metadata rows when their source visibility differs.
// Salt bumped (#4457): numeric tuple selectors split from one macro-input token
// remain internal references without claiming separate host token occurrences.
// Salt bumped (#3828): named gap candidates survive nameless Call and
// FieldAccess wrappers instead of persisting an unnecessary wildcard.
// The 0.24.4 grammar accepts attributes on struct-pattern fields without
// changing its node/field names or ABI. Retire interiors parsed under 0.24.3;
// the public grammar fingerprint alone cannot distinguish that parser change.
// Salt bumped (#4310): qualified macro call facts now expose the structured
// root path as receiver evidence for precise RQL selection.
// Salt bumped (#4460): Rust module-self routes and generated attribute
// surfaces change the persisted route and binding facts.
// Salt bumped (#4626): selected macro type and path fragments lower from the
// fragment type, not the synthetic alias declaration used to parse them.
// Salt bumped: macro identifier roles reparse repetition bodies in an impl
// context so value-side `self` inputs are not published as type fragments.
// Salt bumped: macro fragment recovery now keeps lifetime and path bindings in
// their written roles, and a keyword `ident` capture such as `self` or `crate`
// no longer takes a type or value role, changing persisted Rust resolution facts.
// Salt bumped (#4458): effective `cfg_attr` payloads now classify item
// boundaries and derive facts, changing persisted Rust resolution facts.
// Salt bumped (#4458): reference impl receivers keep their reference layers
// while member lookup uses the nominal target owner.
// Salt bumped (#4458): item-level derive-helper names now retain conditional
// binding gaps for the crate-level absence proof.
// #5496: unknown self-call receivers keep positioned member gaps instead of
// synthetic scope gaps; reparse persisted Rust facts with the old gap shape.
// Salt bumped (#5517): only unenumerable macro inputs open reverse inventory;
// guessed reference gaps and additive forward surfaces remain independent.
// #5172: cfg_if arm items retain ordered source cfg guards and module routes.
// #5133 landing: guessed macro references retain one unsupported-expression
// obligation when computed receiver lowering already emitted the same fact.
// #6140: Rust source contexts publish the start bytes of attributes that may
// expand to code; reparse persisted facts with the old context shape.
// BrokkAi/tree-sitter-rust#3: the 0.24.7 parse-table fix changes inclusive
// prefix ranges from assignments to range expressions without changing node
// or field names; reparse old source facts under the new grammar.
// #6393: turbofish type paths now parse without recovery. Reparse unchanged
// blobs so warm stores discard ERROR-derived incomplete structural facts.
// Rust salt bumped again (quicksilver round 3 on brokk-bifrost-rust): a
// closed inner macro no longer hides an outer passthrough's replay bridge,
// macro_rules! signatures come from the AST header instead of a source-line
// scan, test regions read cfg(not(test)) structurally, include! host
// bindings respect function-local import extents, and malformed cfg_attr
// predicates, mutability-strengthening array unsizing and raw format
// argument names no longer produce inert or accepted facts. Old parsed blobs
// hold the earlier declarations, signatures, test regions and include rows.
// #6235: callee provenance follows local value aliases (`let f = init;`).
// Warm structural call facts still hold `unknown` for those calls.
// Rust salt bumped again (#6861): macro replay certifies the selected item
// arm, attribute heads publish Macro-namespace sites, token-tree lookups
// consult certified native replay first, and inline #[path] module routes
// follow the module walk, so parse-time declarations change for unchanged
// bytes.
// #6912: an item macro fragment spans its outer attributes, so attributed
// items inside replayed macros gain declarations, and each derive(...) path
// publishes a Macro-namespace reference site.
// #6844: generic declared-type heads stay nominal and emit a ConditionalPayload
// transfer, and impl subjects keep wrapper-spelled heads, so producer facts
// change for unchanged bytes.
// #7217: trait and impl body children unwrap inert builtin attribute
// wrappers, so attributed members persist their own payload rows.
// #3074: nightly trait aliases and decl_macro items, which the grammar parses
// since brokk-tree-sitter-rust 0.24.3, now declare Trait and Macro code
// units, so unchanged bytes gain declarations.
lang_epoch!(
    Rust,
    "rust",
    "treesitter/rust/",
    "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08;anchored-fq-encoding-2026-08;crate-aware-packages-2026-08;rust-query-assets-in-brokk-bifrost-rust-2026-08;renamed-import-impl-owner-route-2026-08;per-file-usage-facts-2026-08;cargo-route-facts-2026-08;include-edge-facts-2026-08;import-cfg-and-extern-crate-2026-08;enum-variant-named-fields-2026-08;callable-parameter-type-spellings-2026-08;raw-identifier-cargo-module-routes-2026-08;bounded-declaration-labels-2026-08;nested-and-extern-crate-import-facts-2026-08;declaration-type-parameter-arity-2026-09;rust-type-alias-type-identity-2026-09;unnamed-rust-import-binding-facts-2026-09;source-external-module-signatures-2026-09;proc-macro-kind-and-macro-use-extern-facts-2026-09;module-cfg-and-exported-macro-facts-2026-09;native-resolution-first-tranche-2026-09;native-resolution-root-route-halves-2026-09;native-resolution-cfg-fail-closed-2026-09;native-resolution-root-glob-demands-2026-09;native-resolution-type-references-2026-09;native-resolution-item-macros-2026-09;native-resolution-definition-unit-crosswalks-2026-09;native-resolution-point-gap-authority-2026-09;native-resolution-proc-macro-member-boundaries-2026-09;native-resolution-const-static-values-2026-09;native-resolution-extern-crate-routes-2026-09;native-resolution-local-pattern-scopes-2026-09;native-resolution-direct-let-condition-scopes-2026-09;native-resolution-or-pattern-binders-2026-09;native-resolution-foreign-functions-2026-09;native-resolution-union-types-2026-09;native-resolution-unprojectable-item-boundaries-2026-09;native-resolution-bare-condition-assignment-references-2026-09;native-resolution-struct-value-constructors-2026-09;native-resolution-generic-item-interiors-2026-09;native-resolution-const-generic-boundaries-2026-09;native-resolution-declared-rule-authority-2026-09;native-resolution-qualified-reference-boundaries-2026-09;native-resolution-item-macro-surface-boundaries-2026-09;native-resolution-cfg-route-placement-boundaries-2026-09;native-resolution-exact-reference-enumeration-gaps-2026-09;native-resolution-builtin-test-attribute-2026-09;cargo-manifest-default-target-inventory-2026-09;native-resolution-module-cycle-guard-2026-09;native-resolution-include-cycle-guard-2026-09;native-resolution-inline-module-ancestry-2026-09;native-resolution-inline-visibility-and-parent-cfg-2026-09;native-resolution-inline-include-scope-2026-09;native-resolution-inline-module-root-bridge-2026-09;native-resolution-inline-import-scope-2026-09;native-resolution-let-chain-scopes-2026-09;native-resolution-leading-absolute-imports-2026-09;native-resolution-positioned-call-callees-2026-09;native-resolution-member-scope-gaps-2026-09|native-resolution-root-references-2026-09;native-resolution-inherent-callable-bodies-2026-09;canonical-source-facts-2026-09;structured-extern-crate-import-form-2026-09;canonical-import-source-occurrences-2026-09;canonical-import-module-segments-2026-09;canonical-generic-import-spans-2026-09;canonical-import-properties-2026-09;canonical-rust-import-contexts-2026-09;canonical-embedded-declaration-identities-2026-09;canonical-rust-declaration-properties-2026-09;canonical-rust-declaration-classification-2026-09;canonical-rust-declaration-boundaries-2026-09;canonical-primary-module-properties-2026-09;shared-secondary-module-properties-2026-09;canonical-module-source-links-2026-09;ast-signature-header-boundaries-2026-09;source-owned-impl-type-construction-2026-09;shared-embedded-source-occurrences-2026-09;ast-parameter-label-spans-2026-09;primary-item-source-inventory-2026-09;secondary-item-source-inventory-2026-09;embedded-import-source-contexts-2026-09;normalized-item-syntax-2026-09;canonical-item-type-source-publication-2026-09;canonical-recovered-tree-root-contexts-2026-09;canonical-macro-source-position-2026-09;canonical-declaration-annotations-2026-09;canonical-generic-type-contexts-2026-09;canonical-macro-definition-patterns-2026-09;canonical-trait-type-forms-2026-09;canonical-macro-contexts-2026-09;canonical-native-declaration-bridge-publication-2026-09;native-resolution-reference-indirection-provenance-2026-09;native-resolution-let-initialization-2026-09;native-resolution-exact-import-demand-targets-2026-09;native-resolution-generic-argument-type-syntax-2026-09;native-resolution-wrapper-payload-projection-and-unwraps-2026-09;native-resolution-block-local-cfg-route-binders-2026-09;native-resolution-path-prefix-and-field-chain-occurrences-2026-09;native-resolution-qualified-type-projection-references-2026-09;native-resolution-detached-crate-module-trees-2026-09;native-resolution-enum-variant-members-2026-09;canonical-local-field-source-projections-2026-09;native-resolution-qualified-value-projections-2026-09;native-resolution-producer-reference-enumeration-b3-2026-09;native-resolution-census-ch-lexical-import-bindings-2026-09;native-resolution-selected-cfg-activation-2026-09;native-resolution-scoped-single-name-imports-and-serde-helpers-2026-09;native-resolution-trait-impl-bodies-ty-a-2026-09;native-resolution-type-alias-frontiers-ty-b-2026-09;native-resolution-associated-types-ty-c-2026-09;native-resolution-trait-bound-receivers-ty-d-2026-09-r2;native-resolution-macro-matcher-replay-mc-a-2026-09;native-resolution-macro-routes-mc-canonical-inputs-2026-09;native-resolution-include-splice-scopes-and-macros-mc-b-2026-09;transfer-owned-type-identity-observations-2026-09-13;native-resolution-enum-constructor-members-2026-09;native-resolution-terminal-prefix-qualifiers-ec-2026-09;native-resolution-enum-runtime-receivers-ec-2026-09;native-resolution-expression-name-focus-ec-2026-09;native-resolution-explicit-module-anchor-preservation-ec-2026-09;native-resolution-macro-callee-prefix-preservation-ec-2026-09;native-resolution-compound-member-receiver-enumeration-2026-09-13;native-resolution-initializer-field-reference-enumeration-2026-09-13;native-resolution-pattern-path-and-field-enumeration-2026-09-13;native-resolution-compound-type-operand-enumeration-2026-09-13;native-resolution-use-module-prefix-enumeration-2026-09-13;native-resolution-macro-use-module-body-enumeration-2026-09-13;native-resolution-literal-receiver-reference-enumeration-2026-09-13;native-resolution-unified-pending-receivers-reconciliation-2026-09-13;rust-crate-row-schema-cr-r8-1-2026-09;rust-crate-reconcile-cr-r8-2-2026-09;rust-crate-derivation-cr-r8-3-2026-09;rust-single-name-import-binder-cr-2026-09;rust-source-visibility-cr-2026-09;rust-conditional-module-definition-sites-cr-2026-09;rust-signature-source-links-cr-2026-09;rust-crate-target-dependencies-cr-2026-09;rust-canonical-visibility-evidence-cr-2026-09;rust-lexical-macro-access-cr-2026-09;rust-crate-blob-repair-cr-2026-09;rust-crate-held-blob-repair-cr-2026-09;rust-crate-module-sources-and-scoped-imports-cr-2026-09-13;rust-crate-glob-reexport-subtype-cr-2026-09-13;tuple-positional-field-receivers-2026-09-13;tuple-field-empty-name-anchors-2026-09-13;macro-fragment-source-node-identity-2026-09-13;rust-crate-public-use-binders-fw-2026-09-13;rust-crate-reexport-alias-identity-fw-2026-09-13;rust-crate-transitive-import-namespaces-fw-2026-09-13;rust-crate-inline-declaration-names-fw-2026-09-13;rust-crate-open-export-inventory-fw-2026-09-13;rust-crate-file-naming-fw-2026-09-13;rust-crate-local-reexport-inventory-routes-fw-2026-09-13;rust-crate-unknown-export-activation-fw-2026-09-13;rust-crate-2015-explicit-self-routes-fw-2026-09-13;rust-crate-import-placement-keys-fw-2026-09-13;rust-crate-canonical-restricted-visibility-fw-2026-09-13;rust-crate-external-import-gap-classification-fw-2026-09-13;rust-crate-external-bare-import-gap-fw-2026-09-13;rust-enum-export-containers-v1;native-resolution-tier-1-discovery-headers-li3-2026-09-14;native-resolution-root-demand-headers-rv-2026-09;native-resolution-crate-import-reexport-namespaces-rv-2026-09;native-resolution-sparse-reverse-lookup-identities-rv-2026-09;rust-crate-relative-import-roots-rv-2026-09;rust-crate-import-placement-key-rv-2026-09;root-path-route-segments-rv-2026-09;rust-crate-root-reference-routes-rv-2026-09;rust-generic-type-alias-substitution-3828-2026-10-01;rust-generic-type-argument-source-ordinals-3828-2026-10-02;rust-reference-pointer-alias-transfer-input-4389-2026-10-02;rust-non-generic-alias-applied-identity-2026-10-02;rust-plain-extern-crate-import-frontier-3828-2026-10;rust-target-scoped-gap-ast-names-3828-2026-10-05;5522-tuple-callable-field-2026-10;canonical-overload-discriminator-7505-v1",
    ";rust-crate-per-blob-declaration-candidates-rc-2026-09-14;rust-crate-import-head-staging-rc-2026-09-14;native-resolution-dense-rekey-source-identities-dg-2026-09-14;native-resolution-inline-cfg-module-placement-mr-2026-09-14;native-resolution-tier-2-families-not-persisted-li4-2026-09-15;native-resolution-tier-1-root-routes-li5-2026-09-15;native-resolution-definition-less-macro-argument-enumeration-mc2-2026-09-15;native-resolution-self-receiver-value-reference-g6-2026-09-16;native-resolution-struct-literal-let-initializer-dc-2026-09-16;native-resolution-block-local-item-scopes-pr-2026-09-17;native-resolution-member-bodies-and-item-macro-arguments-pm-2026-09-17;m8-batch-one-self-root-routes-anchors-derive-surface-lifetime-args-initializers-root-scopes-2026-09-21;m8-batch-two-conditional-binder-sites-cfg-inline-module-exports-2026-09-22;m8-batch-three-trait-body-self-sites-open-member-surface-type-bindings-item-groups-2026-09-22;m8-batch-four-impl-declaration-rows-decided-macro-decorations-inline-modules-owning-traits-2026-09-24;capital-self-type-references-2026-09;primitive-spelled-impl-owners-2026-09;scoped-generated-rust-model-declarations-2026-09;attributed-impl-member-declarations-2026-09;rust-stack-graph-batch-five-macro-export-context-2771-2026-09-26;rust-method-values-enum-field-visibility-2771-2026-09-27;rust-attributed-member-owner-2771-2026-09-27;rust-self-constructor-binding-2771-2026-09-27;rust-conditional-file-module-exports-2771-2026-09-27;rust-inert-test-attributes-2771-2026-09-27;rust-alias-nominal-identity-2771-2026-09-27;rust-projection-outputs-unsafe-attributes-2771-2026-09-27;rust-import-anchor-occurrences-2771-2026-09-27;rust-function-signature-owners-2771-2026-09-27;rust-trait-signature-owners-2771-2026-09-27;rust-declaration-reference-owners-2771-2026-09-27;rust-shared-unit-type-identity-2771-2026-09-27;rust-impl-bound-and-turbofish-reference-owners-2771-2026-09-27;rust-computed-receiver-members-enumerated-3764-2026-09-29;rust-struct-constructor-root-exports-3746-2026-09;rust-struct-pattern-variant-field-owner-3746-2026-09;rust-unit-self-value-identity-3746-2026-09-29;rust-unwrapped-member-receivers-3746-2026-09-29;rust-u1-3746-producer-2026-09-29;rust-u1-3746-parenthesized-types-2026-09-29;rust-impl-subject-frontier-resolution-gap-3746-2026-09-29;rust-tt-binding-runs-3746-2026-09-29;rust-attributed-inline-module-macros-3746-2026-09-29;rust-tt-static-call-facts-3746-2026-09-29;rust-tt-transcriber-output-proof-3746-2026-09-30;rust-closure-parameter-declared-types-3746-2026-09-30;rust-impl-generic-parameter-owner-c-2026-09-30;rust-macro-scope-f-3746-2026-09-30;rust-u2-bare-transcriber-references-matches-pattern-2026-09-30-a;rust-generic-alias-target-identity-3746-2026-09-30;rust-unindexed-macro-argument-enumeration-restored-2026-09-30-a;rust-unindexed-matches-refutable-patterns-2026-09-30-a;rust-qualified-macro-root-routes-3828-2026-10-02;rust-recovered-syntax-and-type-position-call-lowering-4279-4286-4289-4291-2026-10-03;rust-async-callable-await-structural-facts-3851-2026-10;rust-qualified-task-spawn-structural-facts-3853-2026-10-02;rust-call-type-argument-role-4314-2026-10-02;rust-matched-macro-closed-member-surface-2026-10-04;rust-crate-member-path-identity-4449-2026-10;rust-malformed-string-literal-absence-4450-2026-10-04;rust-struct-pattern-field-attributes-2026-10-05;rust-named-gap-wrapper-candidates-3828-2026-10-05;rust-empty-recovered-inner-attribute-and-source-visibility-4448-2026-10-04;rust-source-declaration-metadata-visibility-alternatives-4451-2026-10;rust-embedded-primary-reference-publication-4451-2026-10;rust-macro-positional-field-token-occurrences-4457-2026-10-05;rust-cq06-log-macro-lowering-2026-10;rust-macro-qualified-call-receivers-4310-2026-10;rust-attribute-source-declaration-bridges-4459-2026-10;rust-import-module-self-route-4460-2026-10-07;rust-cfg-attr-derived-surface-4460-2026-10-07;rust-transforming-attribute-surface-boundary-4460-2026-10-07;rust-selected-macro-type-path-fragment-root-4626-2026-10-08;rust-macro-ident-impl-context-2026-10-08;rust-recovered-macro-fragment-bindings-2026-10-09;rust-interior-path-anchors-4289-2026-10-08;rust-cfg-attr-effective-item-attributes-4458-2026-10;rust-reference-impl-member-owners-4458-2026-10;rust-conditional-derive-helper-attributes-4458-2026-10;rust-summary-import-route-completeness-4955-2026-10;structured-callee-spine-5019-2026-10;rust-generic-formal-defaults-and-impl-subject-arguments-4964-2026-10;rust-impl-argument-applicability-4964-2026-10;generated-surface-bindings-5205-2026-10;receiver-generated-surfaces-and-reverse-inventory-5205-2026-10;rust-additive-helper-bindings-5205-2026-10;native-macro-operand-fragments-5239-2026-10;rust-primitive-shadowing-5235-2026-10;rust-item-macro-guess-scope-5375-2026-10;rust-item-macro-reverse-inventory-5375-2026-10-v2;native-resolution-positioned-unknown-self-call-gap-2026-10-17;rust-composite-primitive-shadowing-5243-2026-10;rust-item-macro-reverse-inventory-5375-2026-10-v3-enumerated-inputs-5517;cfg-if-ordered-native-items-and-imports-5172-2026-10-17;cfg-if-conditional-macro-frontiers-5172-2026-10-17;cfg-if-guessed-item-operands-5172-2026-10-17;local-write-value-joins-5015-2026-10;rust-borrowed-runtime-values-5015-2026-10;unknown-local-incoming-values-5015-2026-10;rust-first-hop-reexports-and-constructor-visibility-5133-2026-10;rust-positional-field-attributes-5133-2026-10;rust-unique-macro-reference-gaps-5133-2026-10;rust-macro-input-invocation-names-5437-2026-10;rust-expanding-attribute-contexts-6140-2026-10;rust-cfg-import-glob-alternatives-6242-2026-10;rust-turbofish-type-path-6393-2026-10;rust-impl-body-metavariables-6389-2026-10;rust-compound-assignment-target-6415-2026-10;rust-exact-producer-facts-6409-m2;rust-inherent-impl-subjects-6394;rust-grammar-0.24.7-range-to-inclusive;quicksilver-round3-rust-macro-scope-signatures-test-cfg-include-extents-2026-10;rust-callee-provenance-local-aliases-6235-2026-10;rust-macro-replay-certified-arms-attribute-heads-6861-2026-10;rust-macro-item-attributes-and-derive-sites-6912-2026-10;rust-wrapper-identity-conditional-payload-6844-2026-10;rust-attributed-trait-member-payloads-7217-2026-10;rust-trait-alias-decl-macro-declarations-3074-2026-10"
);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_type_alias_type_identity() -> String {
    compute_epoch_before_bump::<Rust>(
        &tree_sitter_rust::LANGUAGE.into(),
        "rust-type-alias-type-identity-2026-09",
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_nested_and_extern_crate_import_facts() -> String {
    let prior = salt_before_bump(Rust::SALT, "nested-and-extern-crate-import-facts-2026-08");
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_anchored_fq_encoding() -> String {
    compute_epoch::<Rust>(
        &tree_sitter_rust::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;embedded-macro-rules-code-units-2026-07;ast-test-detection-2026-07;canonical-impl-owner-identities-2026-07;macro-invocation-item-reparse-2026-07;proven-macro-definition-replay-2026-07;per-declaration-test-taint-2026-07;raw-identifier-normalization-2026-07;inline-module-const-static-type-items-2026-07;fq-interned-segments-2026-07;structural-macro-invocation-arguments-2026-08;structural-attributes-and-fields-2026-08",
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_recovered_macro_fragment_bindings() -> String {
    let prior = salt_before_bump(
        Rust::SALT,
        "rust-recovered-macro-fragment-bindings-2026-10-09",
    );
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_cfg_attr_effective_item_attributes() -> String {
    let prior = salt_before_bump(
        Rust::SALT,
        "rust-cfg-attr-effective-item-attributes-4458-2026-10",
    );
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_reference_impl_member_owners() -> String {
    let prior = salt_before_bump(Rust::SALT, "rust-reference-impl-member-owners-4458-2026-10");
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rust_epoch_before_conditional_derive_helper_attributes() -> String {
    let prior = salt_before_bump(
        Rust::SALT,
        "rust-conditional-derive-helper-attributes-4458-2026-10",
    );
    compute_epoch::<Rust>(&tree_sitter_rust::LANGUAGE.into(), prior)
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
// Salt bumped again (#3503): Brokk PHP grammar 0.24.3 accepts asymmetric
// visibility on constructor-promoted properties. Parser-table changes are not
// part of the live grammar fingerprint, so retire rows from the prior parser.
// Salt bumped again (#4408): Brokk PHP grammar 0.24.4 parses clone argument
// lists, and PHP resolves their object operands from structured arguments.
// Salt bumped again: PHP method names are case-insensitive, so a method named
// `__Construct` is the constructor; it now persists a Constructor structural
// kind for unchanged bytes.
// Salt bumped again: quicksilver round 9 fixes change persisted PHP
// signatures, PHPDoc facts, resolved and import identities, field modifiers,
// structural roles, include facts and field-write capture for unchanged bytes.
lang_epoch!(
    Php,
    "php",
    "treesitter/php/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;fq-interned-segments-2026-07;conditional-free-function-declarations-2026-07;php-query-assets-in-brokk-bifrost-php-2026-08;structured-declared-return-identities-2026-08;php-callable-modifier-metadata-2026-09;php-imported-type-names-2026-09;php-per-statement-namespace-scope-2026-09;canonical-primary-source-ownership-2026-09;php-canonical-import-projection-order-4288-2026-10-03;php-trait-relative-names-from-ast-scope-3390-2026-10-03;php-promoted-asymmetric-grammar-0.24.3-3503;php-clone-with-grammar-0.24.4-4408;php-include-edge-facts-3840-2026-10;structured-callee-spine-5019-2026-10;php-case-insensitive-constructor-kinds-2026-10;php-quicksilver-round9-survivor-fixes-2026-10"
);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn php_epoch_before_imported_type_names() -> String {
    let prior = salt_before_bump(Php::SALT, "php-imported-type-names-2026-09");
    compute_epoch::<Php>(&tree_sitter_php::LANGUAGE_PHP.into(), prior)
}

/// The PHP epoch as it stood before the #1420 conditional-free-function bump.
///
/// The literal below is a historical pin and must never be edited: it is what
/// `php_conditional_free_function_epoch_invalidates_prior_parsed_blobs` writes a
/// blob under before asserting the current epoch evicts it. Later salt segments
/// (the 2026-08 asset relocation above) are deliberately absent from it.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn php_epoch_before_conditional_free_function_declarations() -> String {
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
// Salt bumped again: import paths and selectors publish positioned references
// and supported import routes no longer claim an unsupported route gap. Named
// givens publish callable routes, and unsupported anonymous given routes stay
// scoped to their declaration instead of tainting the enclosing type. Warm
// source facts contain none of those distinctions.
// Salt bumped (root import activation): Scala root imports now store the source
// position at which they take effect, and the selected import context consumes
// a blob's imports in that order. Warm rows were written without that column.
// Salt bumped again: Scala qualified terminal paths publish selected
// TypeOrValue member routes, including absolute paths and singleton owners.
// Warm facts predate those root-route facts and cannot close the same paths.
// Salt bumped again: a Scala class's synthetic primary constructor is now a
// source declaration of its own instead of a second unit of the class's
// declaration. Warm rows link both units to the class declaration, which the
// selected unit read and the Java inheritance read reject as duplicates.
// Salt bumped (#5177): operator type names retain their parser units, and
// local companions cannot publish global JVM aliases.
// Quicksilver round 5: classes, objects, traits, enums and extensions nested
// in an anonymous template are now declared, and a recovered type header
// starts at its own keyword instead of the enclosing ERROR node. Warm
// declaration rows for unchanged bytes omit those members or hold the
// earlier ranges.
// Salt bumped (#7577): Scala cast targets enter expression value slots.
lang_epoch!(
    pub Scala,
    "scala",
    "treesitter/scala/",
    "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;tree-sitter-scala-0.26.2-2026-08;scala-anonymous-template-code-units-2026-08;package-object-package-scope-2026-08;same-package-type-identifier-facts-2026-08;top-level-extension-declarations-2026-08;declaration-type-parameter-arity-2026-09;scala-type-alias-type-identity-2026-09;callable-modifiers-parameter-types-and-trait-marker-2026-09;canonical-primary-source-ownership-2026-09;recovered-type-header-one-based-range-2026-09;named-given-declarations-2026-09;abstract-val-var-declarations-export-selector-3499-2026-09;scala-native-root-route-facts-2026-10;scala-trait-source-routes-and-scoped-jvm-aliases-2026-10;scala-case-class-companion-routes-2026-10;scala-positioned-import-references-and-scoped-given-routes-2026-10;scala-package-object-module-aliases-2026-10;scala-unqualified-extractor-type-or-value-2026-10;scala-complete-positioned-import-routes-2026-10;scala-qualified-terminal-type-or-value-member-routes-2026-10;scala-owner-continued-type-or-value-routes-2026-10;scala-same-file-imports-and-deduplicated-package-object-exports-3499-4412-2026-10-03;scala-call-argument-state-with-shared-applicability-2026-10;scala-external-provider-type-identity-frontiers-2026-10;scala-contextual-private-protected-visibility-2026-10;scala-singleton-receiver-without-inferred-gap-2026-10;scala-argument-expression-value-transfers-2026-10;scala-selection-value-is-selected-member-2026-10;scala-singleton-owner-selection-root-reference-2026-10;scala-head-ambiguity-only-without-root-reference-2026-10;scala-selection-argument-uses-projected-member-value-2026-10;scala-root-import-activation-ordinal-2026-10;scala-package-segment-demands-term-namespaces-2026-10;scala-value-slot-producer-facts-2026-10;scala-untyped-initializer-value-slots-2026-10;scala-supertype-edges-in-java-shape-2026-10;scala-contextual-parameters-bind-like-ordinary-ones-2026-10;scala-lexical-declarations-for-unitless-binders-2026-10;scala-implicit-case-class-parents-2026-10;scala-primary-constructor-own-declaration-2026-10;scala-case-class-synthesized-members-2026-10;scala-extractor-role-on-head-reference-2026-10;scala-jvm-reconciliation-merge-3-2026-10;scala-jvm-batch-2-merge-2026-10;scala-import-path-qualified-reference-producers-2026-10;scala-object-term-and-lexical-type-path-head-2026-10;scala-this-current-instance-receiver-2026-10;scala-constructor-and-scoped-extension-facts-2026-10-16;scala-lexical-import-qualifier-reference-2026-10;scala-companion-module-constructor-extension-and-anonymous-owner-facts-2026-10-16;local-write-value-joins-5015-2026-10;isolated-mutation-gaps-5015-2026-10;unknown-local-incoming-values-5015-2026-10;jvm-callable-values-local-write-integration-5015-2026-10;scala-qualified-access-boundaries-2026-10;scala-complete-provider-inventory-absence-above-v78-2026-10;scala-ast-type-names-and-lexical-case-class-companions-5177-2026-10;quicksilver-round5-scala-anonymous-template-members-and-recovered-headers-2026-10;canonical-overload-discriminator-7505-v1;7187-jvm-type-parameter-bindings"
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
// #3851: C# await nodes now share the normalized Await kind.
// #4379: C# source facts record instance-method return types, and C#
// external constructors, properties and indexers resolve to modeled members.
// #6139: the preprocessor scan now reads past a leading byte-order mark, so a
// file that opens with `\u{feff}#if` hides that directive. Warm rows were
// parsed with the `#if` visible and its `#endif` hidden, and hold a MISSING
// `#endif` recovered region that makes every structural selection incomplete.
// Persist generic member-name roles, deconstruction initializer roles,
// event accessor owners, comment-free type-argument arity, parameter label
// spans, headers ending at the body node, and literal signature whitespace.
// #7374: Operator and conversion operator callables now own structural parameter scopes.
// #4379 M3a: C# expression/statement kinds and their grammar-backed roles change persisted rows.
lang_epoch!(
    CSharp,
    "csharp",
    "treesitter/c_sharp/",
    "synthetic-file-scope-code-units-2026-07;ast-test-detection-2026-07;static-using-type-identifiers-2026-07;as-expression-type-identifiers-2026-07;generic-type-identity-2026-07;attribute-type-identifiers-2026-07;callable-arity-and-static-import-metadata-2026-07;generic-method-arity-identity-2026-07;structured-return-type-metadata-2026-07;tuple-element-type-identifiers-2026-07;nameof-type-identifiers-2026-07;callable-dispatch-extensibility-metadata-2026-07;fq-interned-segments-2026-07;csharp-query-assets-in-brokk-bifrost-csharp-2026-08;interop-optional-callable-arity-2026-08;callable-modifier-metadata-2026-08;preprocessor-directive-aware-parsing-2026-08;multiplication-not-pointer-type-reference-2026-08;verbatim-identifier-canonical-declaration-names-2026-08;structured-csharp-runnable-test-classification-2026-08;csharp-inherited-test-classification-2026-08;declaration-type-parameter-arity-2026-09;callable-parameter-types-and-interface-marker-2026-09;callable-override-modifier-2026-09;comment-aware-canonical-using-targets-2026-09;brokk-csharp-grammar-0.23.5-2026-09;static-local-function-grammar-0.23.6-2026-09;generic-attribute-shorthand-identity-2026-09;recovered-type-member-ownership-2026-09;contextual-partial-required-grammar-0.23.7-2026-09;csharp-await-structural-kind-3851-2026-10;csharp-codeql-parity-facts-4379-2026-10;csharp-unsafe-pointer-expressions-0.23.8-4410;structured-callee-spine-5019-2026-10;preprocessor-byte-order-mark-6139-2026-10;csharp-quicksilver-round8-survivor-fixes-2026-10;operator-callable-scopes-7374-2026-10;csharp-structural-kinds-4379-m3a-2026-10;canonical-overload-discriminator-7505-v1;csharp-structural-uninitialized-declarators-4379-m6-2026-10;csharp-structural-role-parens-4379-m6-2026-10;csharp-preprocessor-decisions-8147-m4a-2026-10"
);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn csharp_epoch_before_inherited_test_classification() -> String {
    let prior = salt_before_bump(CSharp::SALT, "csharp-inherited-test-classification-2026-08");
    compute_epoch::<CSharp>(&tree_sitter_c_sharp::LANGUAGE.into(), prior)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn csharp_epoch_before_structured_runnable_test_classification() -> String {
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
// Salt bumped again: Ruby single-quoted escapes and CRLF continuations decode
// into string values, and a bare `for` iterable is a call read, for unchanged
// bytes.
// Salt bumped again: quicksilver round 10 fixes change persisted Ruby
// declaration owners and namespaces, block-defined declarations, dynamic attribute
// names, autoload and Gemfile import facts, and mixin and dispatch facts for
// unchanged bytes.
lang_epoch!(
    Ruby,
    "ruby",
    "treesitter/ruby/",
    "synthetic-file-scope-code-units-2026-07;attr-macro-accessor-identities-2026-07;fq-interned-segments-2026-07;ruby-query-assets-in-brokk-bifrost-ruby-2026-08;ruby-callable-modifier-metadata-2026-09;canonical-ruby-primary-load-runtime-source-2026-09-static-loads;ruby-constant-receiver-value-kind-2026-09;structured-callee-spine-5019-2026-10;ruby-literal-escapes-and-iterable-calls-2026-10;ruby-quicksilver-round10-survivor-fixes-2026-10"
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
// Salt bumped (#3387): scalar Kotlin additive expressions now publish their
// operand-result transfer, and top-level private declarations no longer carry
// an unsupported-visibility gap because file-local lookup is explicit. The
// labeled-this salt records owner-qualified receiver transfers.
// #6603: native loop declarations and their body-only lexical intervals are
// persisted facts; old Kotlin blobs must be produced again.
// #6803: gap-reason provenance now follows minting, including uncovered reasons.
lang_epoch!(
    pub Kotlin,
    "kotlin",
    "treesitter/kotlin/",
    "kotlin-gap-reason-mint-provenance-6803-2026-10-24;brokk-tree-sitter-kotlin-0.4.6-2026-09;kotlin-core-indexing-2026-07;kotlin-class-parameter-default-arity-2026-07;kotlin-backtick-identifier-names-2026-07;kotlin-jvm-realm-imports-supertypes-2026-07;kotlin-signature-returns-receivers-2026-07;kotlin-companion-object-marker-2026-07;kotlin-structured-signature-types-2026-08;jvm-query-assets-in-brokk-bifrost-jvm-2026-08;kotlin-constructor-callable-metadata-2026-08;declaration-type-parameter-arity-2026-09;kotlin-type-alias-type-identity-2026-09;kotlin-coordinated-source-facts-parameter-names-enum-types-2026-09;kotlin-call-binding-constructor-identity-2026-09;kotlin-callable-modifier-metadata-2026-09;kotlin-call-navigation-receiver-facts-2026-10;kotlin-class-type-expression-receiver-2026-10;kotlin-scalar-additive-expression-and-file-private-visibility-2026-10;kotlin-labeled-this-receiver-2026-10;local-write-value-joins-5015-2026-10;unknown-local-incoming-values-5015-2026-10;jvm-callable-values-local-write-integration-5015-2026-10;root-import-kind-facts-5658-2026-10;kotlin-jvm-annotation-identity-facade-2026-10;kotlin-class-literal-smart-cast-evidence-2026-10;kotlin-when-subject-lexical-presentation-2026-10;kotlin-constructor-initialization-scope-header-aliases-2026-10;kotlin-complete-provider-inventory-absence-above-v52-2026-10;kotlin-native-point-default-implicit-receiver-frames-above-v53-2026-10;kotlin-intrinsic-root-hierarchy-above-v54-2026-10;kotlin-dispatch-this-argument-value-above-v55-2026-10;kotlin-anonymous-dispatch-this-above-v56-2026-10;kotlin-absolute-class-literal-reflection-above-v57-2026-10;kotlin-local-constructor-initialization-above-v58-2026-10;kotlin-narrow-nullable-function-invoke-property-callable-namespace-above-v59-2026-10;kotlin-for-loop-lexical-bindings-6603-2026-10;canonical-overload-discriminator-7505-v1;7187-jvm-type-parameter-bindings"
);
