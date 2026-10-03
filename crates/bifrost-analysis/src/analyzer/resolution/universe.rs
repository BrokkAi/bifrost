//! Fixed language universe names consulted after selected source scopes.
//!
//! Universe entries are engine rules, not producer facts. The table is fixed
//! and small; identities are interned through the active request only when an
//! entry is actually needed.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{IntrinsicTypeKind, ResolutionNamespace};

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
pub(crate) struct UniverseEntry {
    pub(crate) language: Language,
    pub(crate) spelling: &'static str,
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
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::Primitive),
        range_type,
    }
}

const fn go_builtin_type(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::LanguageBuiltin),
        range_type: None,
    }
}

const fn go_callable(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        namespace: ResolutionNamespace::Callable,
        identity_kind: UniverseIdentityKind::Callable,
        range_type: None,
    }
}

const fn go_value(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Go,
        spelling,
        namespace: ResolutionNamespace::Value,
        identity_kind: UniverseIdentityKind::Value,
        range_type: None,
    }
}

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

pub(crate) fn lookup(
    language: Language,
    namespace: ResolutionNamespace,
    spelling: &str,
) -> Option<UniverseEntry> {
    if language != Language::Go {
        return None;
    }
    GO_UNIVERSE.iter().copied().find(|entry| {
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
    GO_UNIVERSE.iter().copied()
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
            intrinsic_type_identity_digest(entry.language, kind, entry.spelling)
        }
        UniverseIdentityKind::Callable => intrinsic_non_type_identity_digest(
            b"bifrost-resolution-intrinsic-callable:v1",
            entry.language,
            entry.spelling,
        ),
        UniverseIdentityKind::Value => intrinsic_non_type_identity_digest(
            b"bifrost-resolution-intrinsic-value:v1",
            entry.language,
            entry.spelling,
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
    hasher.field("language", language.config_label().as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universe_names_are_go_only_and_include_range_types() {
        assert_eq!(
            lookup(Language::Go, ResolutionNamespace::Callable, "len")
                .expect("Go len is predeclared")
                .identity_kind,
            UniverseIdentityKind::Callable
        );
        assert!(lookup(Language::Rust, ResolutionNamespace::Callable, "len").is_none());
        assert_eq!(
            lookup(Language::Go, ResolutionNamespace::TypeOrValue, "len")
                .expect("ambiguous Go references admit builtins")
                .identity_kind,
            UniverseIdentityKind::Callable
        );
        assert!(lookup(Language::Java, ResolutionNamespace::Type, "int").is_none());
        assert_eq!(
            lookup(Language::Go, ResolutionNamespace::Type, "string")
                .expect("Go string is predeclared")
                .range_type,
            Some(GoRangeType::String)
        );
        assert_eq!(
            lookup(Language::Go, ResolutionNamespace::Type, "int")
                .expect("Go int is predeclared")
                .range_type,
            Some(GoRangeType::Integer)
        );
        assert_eq!(
            identity_digest(
                lookup(Language::Go, ResolutionNamespace::Type, "byte")
                    .expect("Go byte is predeclared")
            ),
            identity_digest(
                lookup(Language::Go, ResolutionNamespace::Type, "uint8")
                    .expect("Go uint8 is predeclared")
            )
        );
        assert_eq!(
            identity_digest(
                lookup(Language::Go, ResolutionNamespace::Type, "rune")
                    .expect("Go rune is predeclared")
            ),
            identity_digest(
                lookup(Language::Go, ResolutionNamespace::Type, "int32")
                    .expect("Go int32 is predeclared")
            )
        );
    }
}
