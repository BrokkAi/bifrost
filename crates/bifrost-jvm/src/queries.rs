//! The JVM realm's bundled tree-sitter query assets.
//!
//! The `.scm` files ship inside this crate rather than
//! `brokk-bifrost-analysis/resources/` and are embedded at compile time, so a
//! consumer never resolves them from a runtime path. `brokk-bifrost-analysis`
//! folds [`JVM_QUERY_ASSETS`] into the per-language store epoch exactly as it
//! folds its own `resources/treesitter/<lang>/` files: the entry paths keep the
//! historical `treesitter/java/` and `treesitter/scala/` prefixes so the
//! epoch's per-language filter is one rule rather than two.
//!
//! Kotlin contributes no entry. Its `highlights.scm` is read by
//! `KotlinSupport::highlight_query` and its `tags.scm` is excluded from the
//! published archive; neither has ever been part of the salted content, so
//! `treesitter/kotlin/` selects nothing here and Kotlin's epoch is grammar
//! fingerprint plus salt only.

/// Directory Java's query assets live in, relative to this crate's root.
///
/// Reported by `JavaAdapter::query_directory()`. The relocation from the
/// analysis crate is why the Java store-epoch salt bumped: the salted content
/// now comes from this crate's `resources/`, not analysis's.
pub const JAVA_QUERY_DIRECTORY: &str = "resources/treesitter/java";

/// Directory Scala's query assets live in, relative to this crate's root.
///
/// Reported by `ScalaAdapter::query_directory()`.
pub const SCALA_QUERY_DIRECTORY: &str = "resources/treesitter/scala";

/// Directory Kotlin's query assets live in, relative to this crate's root.
///
/// Reported by `KotlinAdapter::query_directory()`.
pub const KOTLIN_QUERY_DIRECTORY: &str = "resources/treesitter/kotlin";

/// Kotlin's highlight query, embedded for `KotlinSupport::highlight_query`.
///
/// Kotlin is declaration-walk-only, so this is the crate's only Kotlin `.scm`
/// consumer and it is deliberately outside [`JVM_QUERY_ASSETS`].
pub const KOTLIN_HIGHLIGHTS_QUERY: &str =
    include_str!("../resources/treesitter/kotlin/highlights.scm");

/// Scala's highlight query, embedded for `ScalaSupport::highlight_query`.
///
/// Read from the vendored grammar's own `queries/` directory rather than from
/// `resources/`, which is why the manifest's `exclude` list re-includes exactly
/// this one file out of `vendor/tree-sitter-scala/queries/**`.
pub const SCALA_HIGHLIGHTS_QUERY: &str =
    include_str!("../vendor/tree-sitter-scala/queries/highlights.scm");

/// Compile-time embedded `.scm` query files as `(relative_path, contents)`.
pub const JVM_QUERY_ASSETS: &[(&str, &str)] = &[
    (
        "treesitter/java/definitions.scm",
        include_str!("../resources/treesitter/java/definitions.scm"),
    ),
    (
        "treesitter/java/imports.scm",
        include_str!("../resources/treesitter/java/imports.scm"),
    ),
    (
        "treesitter/java/identifiers.scm",
        include_str!("../resources/treesitter/java/identifiers.scm"),
    ),
    (
        "treesitter/scala/definitions.scm",
        include_str!("../resources/treesitter/scala/definitions.scm"),
    ),
    (
        "treesitter/scala/imports.scm",
        include_str!("../resources/treesitter/scala/imports.scm"),
    ),
];
