//! Fixed language universe names consulted after selected source scopes.
//!
//! Universe entries are engine rules, not producer facts. A language's table
//! is fixed and small; identities are interned through the active request only
//! when an entry is actually needed. Go's table holds its predeclared types,
//! values and builtin functions. Kotlin's and Scala's hold the default-imported
//! value types, under the names their literals' intrinsic seeds use.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{IntrinsicTypeKind, ResolutionNamespace};

use super::fact_source::language_identity_domain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UniverseIdentityKind {
    Type(IntrinsicTypeKind),
    Callable,
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoRangeType {
    String,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniverseEntry {
    pub(crate) language: Language,
    /// The name as it is written in source.
    pub(crate) spelling: &'static str,
    /// The name that the identity digest and the intrinsic seeds use. It is
    /// `spelling` unless the written name is a shorthand for a qualified one
    /// (`Int` names `kotlin.Int`, the identity a literal of that type seeds).
    pub(crate) identity_spelling: &'static str,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) identity_kind: UniverseIdentityKind,
    pub(crate) range_type: Option<GoRangeType>,
}

const fn go_primitive_type(
    spelling: &'static str,
    range_type: Option<GoRangeType>,
) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        identity_spelling: spelling,
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::Primitive),
        range_type,
    }
}

const fn go_builtin_type(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        identity_spelling: spelling,
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::LanguageBuiltin),
        range_type: None,
    }
}

const fn go_callable(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        identity_spelling: spelling,
        namespace: ResolutionNamespace::Callable,
        identity_kind: UniverseIdentityKind::Callable,
        range_type: None,
    }
}

const fn go_value(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        identity_spelling: spelling,
        namespace: ResolutionNamespace::Value,
        identity_kind: UniverseIdentityKind::Value,
        range_type: None,
    }
}

const fn jvm_builtin_type(
    language: Language,
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    UniverseEntry {
        language,
        spelling,
        identity_spelling,
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::LanguageBuiltin),
        range_type: None,
    }
}

const fn java_builtin_type(
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    jvm_builtin_type(Language::Java, spelling, identity_spelling)
}

const JAVA_UNIVERSE: &[UniverseEntry] = &[java_builtin_type("String", "java.lang.String")];

const fn kotlin_builtin_type(
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    jvm_builtin_type(Language::Kotlin, spelling, identity_spelling)
}

const fn scala_builtin_type(
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    jvm_builtin_type(Language::Scala, spelling, identity_spelling)
}

const KOTLIN_UNIVERSE: &[UniverseEntry] = &[
    kotlin_builtin_type("Boolean", "kotlin.Boolean"),
    kotlin_builtin_type("Byte", "kotlin.Byte"),
    kotlin_builtin_type("Char", "kotlin.Char"),
    kotlin_builtin_type("Double", "kotlin.Double"),
    kotlin_builtin_type("Float", "kotlin.Float"),
    kotlin_builtin_type("Int", "kotlin.Int"),
    kotlin_builtin_type("Long", "kotlin.Long"),
    kotlin_builtin_type("Short", "kotlin.Short"),
    kotlin_builtin_type("String", "java.lang.String"),
    kotlin_builtin_type("Unit", "kotlin.Unit"),
];

/// The Scala value types that the default `scala` package and `Predef` bring
/// into scope unqualified, under the names a literal's intrinsic seed uses.
/// `String` is `Predef.String`, an alias of `java.lang.String`. A declaration
/// of the same spelling in a selected source scope takes precedence, because
/// the table is consulted only after those scopes are exhausted.
const SCALA_UNIVERSE: &[UniverseEntry] = &[
    scala_builtin_type("Boolean", "scala.Boolean"),
    scala_builtin_type("Byte", "scala.Byte"),
    scala_builtin_type("Char", "scala.Char"),
    scala_builtin_type("Double", "scala.Double"),
    scala_builtin_type("Float", "scala.Float"),
    scala_builtin_type("Int", "scala.Int"),
    scala_builtin_type("Long", "scala.Long"),
    scala_builtin_type("Null", "scala.Null"),
    scala_builtin_type("Short", "scala.Short"),
    scala_builtin_type("String", "java.lang.String"),
    scala_builtin_type("Unit", "scala.Unit"),
];

const GO_UNIVERSE: &[UniverseEntry] = &[
    go_primitive_type("bool", None),
    go_primitive_type("byte", Some(GoRangeType::Integer)),
    go_primitive_type("rune", Some(GoRangeType::Integer)),
    go_primitive_type("int", Some(GoRangeType::Integer)),
    go_primitive_type("int8", Some(GoRangeType::Integer)),
    go_primitive_type("int16", Some(GoRangeType::Integer)),
    go_primitive_type("int32", Some(GoRangeType::Integer)),
    go_primitive_type("int64", Some(GoRangeType::Integer)),
    go_primitive_type("uint", Some(GoRangeType::Integer)),
    go_primitive_type("uint8", Some(GoRangeType::Integer)),
    go_primitive_type("uint16", Some(GoRangeType::Integer)),
    go_primitive_type("uint32", Some(GoRangeType::Integer)),
    go_primitive_type("uint64", Some(GoRangeType::Integer)),
    go_primitive_type("uintptr", Some(GoRangeType::Integer)),
    go_primitive_type("float32", None),
    go_primitive_type("float64", None),
    go_primitive_type("complex64", None),
    go_primitive_type("complex128", None),
    go_primitive_type("string", Some(GoRangeType::String)),
    go_builtin_type("error"),
    go_builtin_type("any"),
    go_builtin_type("comparable"),
    go_value("true"),
    go_value("false"),
    go_value("iota"),
    go_value("nil"),
    go_callable("append"),
    go_callable("cap"),
    go_callable("clear"),
    go_callable("close"),
    go_callable("complex"),
    go_callable("copy"),
    go_callable("delete"),
    go_callable("imag"),
    go_callable("len"),
    go_callable("make"),
    go_callable("max"),
    go_callable("min"),
    go_callable("new"),
    go_callable("panic"),
    go_callable("print"),
    go_callable("println"),
    go_callable("real"),
    go_callable("recover"),
];

fn table(language: Language) -> &'static [UniverseEntry] {
    match language {
        Language::Java => JAVA_UNIVERSE,
        Language::Go => GO_UNIVERSE,
        Language::Kotlin => KOTLIN_UNIVERSE,
        Language::Scala => SCALA_UNIVERSE,
        _ => &[],
    }
}

/// Whether the language has any universe entries to consult.
pub(crate) fn has_table(language: Language) -> bool {
    !table(language).is_empty()
}

pub(crate) fn lookup(
    language: Language,
    namespace: ResolutionNamespace,
    spelling: &str,
) -> Option<UniverseEntry> {
    table(language).iter().copied().find(|entry| {
        entry.spelling == spelling
            && (entry.namespace == namespace
                || (namespace == ResolutionNamespace::TypeOrValue
                    && matches!(
                        entry.namespace,
                        ResolutionNamespace::Type
                            | ResolutionNamespace::Value
                            | ResolutionNamespace::Callable
                    )))
    })
}

pub(crate) fn go_entries() -> impl Iterator<Item = UniverseEntry> {
    table(Language::Go).iter().copied()
}

pub(crate) fn jvm_entries() -> impl Iterator<Item = UniverseEntry> {
    [Language::Java, Language::Kotlin, Language::Scala]
        .into_iter()
        .flat_map(table)
        .copied()
}

pub(crate) fn go_types() -> impl Iterator<Item = UniverseEntry> {
    go_entries().filter(|entry| {
        matches!(entry.identity_kind, UniverseIdentityKind::Type(_))
            && !matches!(entry.spelling, "byte" | "rune")
    })
}

pub(crate) fn identity_digest(entry: UniverseEntry) -> [u8; 32] {
    match entry.identity_kind {
        UniverseIdentityKind::Type(kind) => {
            intrinsic_type_identity_digest(entry.language, kind, entry.identity_spelling)
        }
        UniverseIdentityKind::Callable => intrinsic_non_type_identity_digest(
            b"bifrost-resolution-intrinsic-callable:v1",
            entry.language,
            entry.identity_spelling,
        ),
        UniverseIdentityKind::Value => intrinsic_non_type_identity_digest(
            b"bifrost-resolution-intrinsic-value:v1",
            entry.language,
            entry.identity_spelling,
        ),
    }
}

pub(crate) fn intrinsic_type_identity_digest(
    language: Language,
    kind: IntrinsicTypeKind,
    spelling: &str,
) -> [u8; 32] {
    let spelling = if language == Language::Go && kind == IntrinsicTypeKind::Primitive {
        match spelling {
            "byte" => "uint8",
            "rune" => "int32",
            spelling => spelling,
        }
    } else {
        spelling
    };
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-intrinsic-type:v1");
    hasher.field(
        "language",
        language_identity_domain(language)
            .identity_label()
            .as_bytes(),
    );
    hasher.field("kind", &[intrinsic_kind_rank(kind)]);
    hasher.field("spelling", spelling.as_bytes());
    hasher.finish()
}

fn intrinsic_non_type_identity_digest(
    domain: &'static [u8],
    language: Language,
    spelling: &str,
) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.field("language", language.config_label().as_bytes());
    hasher.field("spelling", spelling.as_bytes());
    hasher.finish()
}

const fn intrinsic_kind_rank(kind: IntrinsicTypeKind) -> u8 {
    match kind {
        IntrinsicTypeKind::Primitive => 0,
        IntrinsicTypeKind::LanguageBuiltin => 1,
        IntrinsicTypeKind::Slice => 2,
        IntrinsicTypeKind::Array => 3,
        IntrinsicTypeKind::Structural => 4,
    }
}
