//! Fixed language universe names consulted after selected source scopes.
//!
//! Universe entries are engine rules, not producer facts. A language's table
//! is fixed and small; identities are interned through the active request only
//! when an entry is actually needed. Go's table holds its predeclared types,
//! values and builtin functions. Rust's holds its primitive type fallback.
//! Kotlin's and Scala's hold the default-imported
//! value types, under the names their literals' intrinsic seeds use.

use brokk_bifrost_core::analyzer::Language;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

use super::fact_source::language_identity_domain;

use crate::analyzer::structural::PrecedenceTier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum UniverseIdentityKind {
    Type(IntrinsicTypeKind),
    Callable,
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum GoRangeType {
    String,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniverseEntry {
    #[doc(hidden)]
    pub language: Language,
    /// The name as it is written in source.
    #[doc(hidden)]
    pub spelling: &'static str,
    /// The name that the identity digest and the intrinsic seeds use. It is
    /// `spelling` unless the written name is a shorthand for a qualified one
    /// (`Int` names `kotlin.Int`, the identity a literal of that type seeds).
    #[doc(hidden)]
    pub identity_spelling: &'static str,
    pub(crate) namespace: ResolutionNamespace,
    #[doc(hidden)]
    pub identity_kind: UniverseIdentityKind,
    #[doc(hidden)]
    pub range_type: Option<GoRangeType>,
    /// Source-free definition projection for this language's universe rule.
    /// None retains the existing predeclared or external-boundary surface.
    pub(crate) definition_tier: Option<PrecedenceTier>,
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
        definition_tier: None,
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
        definition_tier: None,
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
        definition_tier: None,
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
        definition_tier: None,
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
        definition_tier: None,
    }
}

const fn java_builtin_type(
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    let mut entry = jvm_builtin_type(Language::Java, spelling, identity_spelling);
    entry.definition_tier = Some(PrecedenceTier::DefaultImport);
    entry
}

#[doc = " Closed JLS bootstrap member inventory. The stable table ordinal distinguishes"]
#[doc = " overloads; the callable projection retains the source-level member name."]
pub(crate) use brokk_bifrost_jvm::intrinsics::IntrinsicMember;

/// Recognize fixed language data by its canonical scalar digest.
pub(crate) fn entry_for_digest(digest: [u8; 32]) -> Option<UniverseEntry> {
    fixed_type_entries()
        .chain(go_entries())
        .chain(python_entries())
        .find(|entry| identity_digest(*entry) == digest)
}

pub(crate) fn intrinsic_member_inventory(owner: &str) -> Option<&'static [IntrinsicMember]> {
    // Keep the existing Java Object ordinals stable. Newly admitted roots use
    // the generated source-name inventory, including inherited members.
    if owner == "java.lang.Object" {
        Some(JAVA_OBJECT_MEMBERS)
    } else {
        brokk_bifrost_jvm::intrinsics::root_member_inventory(owner)
    }
}

/// A closed language-table inventory selected for this request. No workspace data
/// or declaration identities are retained here.
#[derive(Clone, Copy)]
pub enum IntrinsicMemberInventory {
    Jvm(&'static [brokk_bifrost_jvm::intrinsics::ClosedOwnerMember]),
    PythonObject(Option<(u16, u16)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntrinsicMemberPresence {
    Present,
    Absent,
    Unknown,
}

/// One registry for intrinsic inventories. JVM tables ignore the version;
/// Python's table uses only the explicitly selected version.
pub fn closed_intrinsic_member_inventory(
    owner: &str,
    version: Option<(u16, u16)>,
) -> Option<IntrinsicMemberInventory> {
    use brokk_bifrost_python::intrinsics::{self, PythonVersion};
    if owner == "builtins.object" {
        intrinsics::implicit_base(version.map(|(major, minor)| PythonVersion::new(major, minor)))?;
        Some(IntrinsicMemberInventory::PythonObject(version))
    } else {
        brokk_bifrost_jvm::intrinsics::closed_owner_member_inventory(owner)
            .map(IntrinsicMemberInventory::Jvm)
    }
}

impl IntrinsicMemberInventory {
    /// Name presence never proves callable applicability. Unknown versioned
    /// presence likewise cannot certify absence.
    pub fn presence(
        self,
        lookup_digest: [u8; 32],
        namespace: ResolutionNamespace,
    ) -> IntrinsicMemberPresence {
        use IntrinsicMemberPresence::{Absent, Present, Unknown};
        use brokk_bifrost_python::intrinsics::{self, Availability, PythonVersion};
        match self {
            Self::Jvm(members) => {
                if members.iter().any(|member| {
                    super::ResolutionLookupSemanticRecipe::new(
                        Language::Kotlin,
                        namespace,
                        member.name,
                    )
                    .name_digest()
                        == lookup_digest
                }) {
                    Present
                } else {
                    Absent
                }
            }
            Self::PythonObject(version) => {
                let Some(member) = intrinsics::OBJECT_MEMBERS.iter().find(|member| {
                    super::ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        namespace,
                        member.name,
                    )
                    .name_digest()
                        == lookup_digest
                }) else {
                    return Absent;
                };
                match intrinsics::object_member(
                    member.name,
                    version.map(|(major, minor)| PythonVersion::new(major, minor)),
                ) {
                    Availability::Present => Present,
                    Availability::Absent => Absent,
                    Availability::Unknown => Unknown,
                }
            }
        }
    }
}

const JAVA_OBJECT_MEMBERS: &[IntrinsicMember] = &[
    IntrinsicMember {
        name: "getClass",
        visibility: "public",
    },
    IntrinsicMember {
        name: "hashCode",
        visibility: "public",
    },
    IntrinsicMember {
        name: "equals",
        visibility: "public",
    },
    IntrinsicMember {
        name: "clone",
        visibility: "protected",
    },
    IntrinsicMember {
        name: "toString",
        visibility: "public",
    },
    IntrinsicMember {
        name: "notify",
        visibility: "public",
    },
    IntrinsicMember {
        name: "notifyAll",
        visibility: "public",
    },
    IntrinsicMember {
        name: "wait",
        visibility: "public",
    },
    IntrinsicMember {
        name: "wait",
        visibility: "public",
    },
    IntrinsicMember {
        name: "wait",
        visibility: "public",
    },
    IntrinsicMember {
        name: "finalize",
        visibility: "protected",
    },
];

const JAVA_UNIVERSE: &[UniverseEntry] = &[
    java_builtin_type("String", "java.lang.String"),
    java_builtin_type("Object", "java.lang.Object"),
    java_builtin_type("Throwable", "java.lang.Throwable"),
    java_builtin_type("Exception", "java.lang.Exception"),
    java_builtin_type("RuntimeException", "java.lang.RuntimeException"),
    java_builtin_type("Error", "java.lang.Error"),
    java_builtin_type("Boolean", "java.lang.Boolean"),
    java_builtin_type("Byte", "java.lang.Byte"),
    java_builtin_type("Character", "java.lang.Character"),
    java_builtin_type("Double", "java.lang.Double"),
    java_builtin_type("Float", "java.lang.Float"),
    java_builtin_type("Integer", "java.lang.Integer"),
    java_builtin_type("Long", "java.lang.Long"),
    java_builtin_type("Short", "java.lang.Short"),
    java_builtin_type("Void", "java.lang.Void"),
];

const fn kotlin_builtin_type(
    spelling: &'static str,
    identity_spelling: &'static str,
) -> UniverseEntry {
    let mut entry = jvm_builtin_type(Language::Kotlin, spelling, identity_spelling);
    entry.definition_tier = Some(PrecedenceTier::DefaultImport);
    entry
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

const fn rust_primitive_type(spelling: &'static str) -> UniverseEntry {
    UniverseEntry {
        language: Language::Rust,
        spelling,
        identity_spelling: spelling,
        namespace: ResolutionNamespace::Type,
        identity_kind: UniverseIdentityKind::Type(IntrinsicTypeKind::Primitive),
        range_type: None,
        definition_tier: None,
    }
}

const RUST_UNIVERSE: &[UniverseEntry] = &[
    rust_primitive_type("bool"),
    rust_primitive_type("char"),
    rust_primitive_type("str"),
    rust_primitive_type("i8"),
    rust_primitive_type("i16"),
    rust_primitive_type("i32"),
    rust_primitive_type("i64"),
    rust_primitive_type("i128"),
    rust_primitive_type("isize"),
    rust_primitive_type("u8"),
    rust_primitive_type("u16"),
    rust_primitive_type("u32"),
    rust_primitive_type("u64"),
    rust_primitive_type("u128"),
    rust_primitive_type("usize"),
    rust_primitive_type("f32"),
    rust_primitive_type("f64"),
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

/// Canonical JVM identities are shared, but publication follows the caller's
/// universe policy rather than the first table that contains the identity.
#[doc(hidden)]
pub fn projects_intrinsic_definitions(language: Language) -> bool {
    table(language)
        .iter()
        .any(|entry| entry.definition_tier.is_some())
}

// Fixed-size language data, independent of any workspace or selection.
static PYTHON_UNIVERSE: std::sync::LazyLock<Vec<UniverseEntry>> = std::sync::LazyLock::new(|| {
    brokk_bifrost_python::intrinsics::BUILTINS
        .iter()
        .map(|builtin| UniverseEntry {
            language: Language::Python,
            spelling: builtin.name,
            identity_spelling: builtin.qualified_name,
            // Python loads classes and callables through the same value namespace.
            namespace: ResolutionNamespace::Value,
            identity_kind: match builtin.kind {
                brokk_bifrost_python::intrinsics::BuiltinKind::Type => {
                    UniverseIdentityKind::Type(IntrinsicTypeKind::LanguageBuiltin)
                }
                brokk_bifrost_python::intrinsics::BuiltinKind::Callable => {
                    UniverseIdentityKind::Callable
                }
                brokk_bifrost_python::intrinsics::BuiltinKind::Value => UniverseIdentityKind::Value,
            },
            range_type: None,
            definition_tier: None,
        })
        .collect()
});

/// Temporal languages require selected absence, not merely exhausted syntax paths.
pub(crate) fn requires_selected_scope(language: Language) -> bool {
    language == Language::Python
}

fn table(language: Language) -> &'static [UniverseEntry] {
    match language {
        Language::Python => &PYTHON_UNIVERSE,
        Language::Java => JAVA_UNIVERSE,
        Language::Go => GO_UNIVERSE,
        Language::Rust => RUST_UNIVERSE,
        Language::Kotlin => KOTLIN_UNIVERSE,
        Language::Scala => SCALA_UNIVERSE,
        _ => &[],
    }
}

/// Whether the language has any universe entries to consult.
pub(crate) fn has_table(language: Language) -> bool {
    !table(language).is_empty()
}

/// Whether `digest` names one of this language's fixed universe entries.
///
/// A universe entry is a language builtin, not a declaration a selected
/// source scope or a workspace catalog holds: the request interns it as a
/// shared name and no source unit declares it. A name that resolves to one
/// has left the indexed workspace, the way a `std::` or external-crate root
/// has, and it is never a workspace binding that a shadowing declaration
/// could also supply.
pub(crate) fn is_entry_digest(language: Language, digest: [u8; 32]) -> bool {
    table(language)
        .iter()
        .any(|entry| identity_digest(*entry) == digest)
}

#[doc(hidden)]
pub fn lookup(
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

pub(crate) fn python_entries() -> impl Iterator<Item = UniverseEntry> {
    table(Language::Python).iter().copied()
}

pub(crate) fn go_entries() -> impl Iterator<Item = UniverseEntry> {
    table(Language::Go).iter().copied()
}

pub(crate) fn fixed_type_entries() -> impl Iterator<Item = UniverseEntry> {
    [
        Language::Java,
        Language::Kotlin,
        Language::Scala,
        Language::Rust,
    ]
    .into_iter()
    .flat_map(table)
    .copied()
}

/// Intrinsic operand types recognized by Go component selection. Untyped
/// strings are expression types, not predeclared source names.
pub(crate) fn go_component_types() -> impl Iterator<Item = UniverseEntry> {
    go_types().chain([UniverseEntry {
        range_type: Some(GoRangeType::String),
        ..go_builtin_type("untyped string")
    }])
}

pub(crate) fn go_types() -> impl Iterator<Item = UniverseEntry> {
    go_entries().filter(|entry| {
        matches!(entry.identity_kind, UniverseIdentityKind::Type(_))
            && !matches!(entry.spelling, "byte" | "rune")
    })
}

#[doc(hidden)]
pub fn identity_digest(entry: UniverseEntry) -> [u8; 32] {
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn identity_digests(language: Language) -> Vec<(String, [u8; 32])> {
    table(language)
        .iter()
        .map(|entry| (entry.spelling.to_owned(), identity_digest(*entry)))
        .collect()
}
