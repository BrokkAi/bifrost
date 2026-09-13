//! Kotlin `@JvmInline` value-class carrier facts (#2851).
//!
//! Kotlin and the JVM disagree about what a `value class` *is* at run time. A
//! declaration such as
//!
//! ```kotlin
//! @JvmInline
//! value class Money(val amount: Long)
//! ```
//!
//! has two carriers. Its *unboxed* carrier is the underlying value itself --
//! a `long` -- and carries no wrapper object at all. Its *boxed* carrier is a
//! real `Money` instance, and the compiler materializes one exactly where the
//! JVM cannot hold the unboxed form: a nullable slot, a generic (erased) slot,
//! and a supertype slot. Both directions are real operations (`box-impl` and
//! `unbox-impl`), and neither one preserves object identity: two boxings of
//! equal values are not provably the same object, and the wrapper a slot holds
//! is not the value a caller passed.
//!
//! This module answers, from one file's syntax tree, which declarations are
//! JVM inline value classes and which carrier a written type selects. It
//! proves the `@JvmInline` *declaration identity* through Kotlin's own name
//! ladder ([`resolve_kotlin_type_name`]) rather than by matching the spelling:
//! a file that declares or imports its own `JvmInline` binds the name to that
//! declaration, and a value class annotated with it is not a JVM inline class.
//!
//! Everything here is bounded by one file. A destination type the file does
//! not declare, a generic slot whose specialization is written elsewhere, and
//! a wildcard import that could bind the annotation's simple name all produce
//! a typed [`KotlinAdaptationIncomplete`] rather than an optimistic answer.

use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::tree_walk::{
    WalkControl, first_named_child_of_kind, named_children, try_walk_named_tree_preorder,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::kotlin::declarations::{
    KotlinClassLikeKind, kotlin_class_like_kind, kotlin_has_modifier, kotlin_package_name,
};
use crate::kotlin::imports::{kotlin_import_info_from_node, kotlin_import_path};
use crate::kotlin::supertypes::{extract_kotlin_supertype_segments, kotlin_user_type_segments};
use crate::kotlin::syntax::{
    kotlin_binding_type_node, kotlin_declared_type_parameter_names, kotlin_parameter_default,
};
use crate::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};

/// The annotation Kotlin/JVM requires on an inline value class.
const JVM_INLINE_ANNOTATION: &str = "kotlin.jvm.JvmInline";

/// The package a wildcard import of which binds [`JVM_INLINE_ANNOTATION`] to
/// the same declaration the default imports do.
const JVM_INLINE_ANNOTATION_PACKAGE: &str = "kotlin.jvm";

/// Kotlin's universal supertype. Every value class widens to it through the
/// boxed carrier.
const KOTLIN_ANY: &str = "kotlin.Any";

/// The package that owns [`KOTLIN_ANY`].
const KOTLIN_ANY_PACKAGE: &str = "kotlin";

/// How deep a walk out of a written type looks for the declaration whose type
/// parameters are in scope. Real source nests a handful of levels; the cap
/// keeps a recovery-mangled tree from making one lookup unbounded.
const MAX_SCOPE_DEPTH: usize = 64;

/// How deep a written type's arguments are compared. Real carriers nest a
/// level or two; the cap keeps a pathological spelling bounded.
const MAX_TYPE_ARGUMENT_DEPTH: usize = 8;

/// The nodes that hold declarations visible beyond one executable body.
const DECLARATION_SCOPE_KINDS: &[&str] = &["source_file", "class_body", "enum_class_body"];

/// A file-local handle for one declared JVM inline value class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KotlinValueClassId(usize);

impl KotlinValueClassId {
    pub const fn index(self) -> usize {
        self.0
    }
}

/// The exact declaration identity of a Kotlin type declared in one file.
///
/// The source anchor is part of the identity even when two declarations spell
/// the same path: that is how a malformed duplicate stays distinguishable
/// instead of silently overwriting an index entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KotlinDeclarationIdentity {
    package_name: String,
    nesting: Vec<String>,
    name: String,
    declaration_start: usize,
}

impl KotlinDeclarationIdentity {
    pub fn new(
        package_name: impl Into<String>,
        nesting: Vec<String>,
        name: impl Into<String>,
        declaration_start: usize,
    ) -> Self {
        let name = name.into();
        assert!(
            !name.is_empty(),
            "a Kotlin declaration identity needs the name it declares"
        );
        Self {
            package_name: package_name.into(),
            nesting,
            name,
            declaration_start,
        }
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// The enclosing declaration names, outermost first.
    pub fn nesting(&self) -> &[String] {
        &self.nesting
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn declaration_start(&self) -> usize {
        self.declaration_start
    }
}

/// The single `val` primary-constructor property that is a value class's
/// unboxed carrier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KotlinUnderlyingProperty {
    name: String,
    declaration_start: usize,
}

impl KotlinUnderlyingProperty {
    pub fn new(name: impl Into<String>, declaration_start: usize) -> Self {
        let name = name.into();
        assert!(
            !name.is_empty(),
            "an underlying value-class property needs the name it declares"
        );
        Self {
            name,
            declaration_start,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn declaration_start(&self) -> usize {
        self.declaration_start
    }
}

/// One JVM inline value class this file declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KotlinValueClass {
    identity: KotlinDeclarationIdentity,
    underlying: KotlinUnderlyingProperty,
}

impl KotlinValueClass {
    pub fn identity(&self) -> &KotlinDeclarationIdentity {
        &self.identity
    }

    pub fn underlying(&self) -> &KotlinUnderlyingProperty {
        &self.underlying
    }
}

/// Why the JVM cannot hold a value class's unboxed carrier at a boundary.
///
/// This is the adaptation's provenance: it names the language rule that made
/// the compiler emit `box-impl`/`unbox-impl`, not merely that one ran.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KotlinAdaptationBoundary {
    /// A nullable slot. The unboxed carrier has no JVM null when the
    /// underlying type is primitive, and cannot be told apart from an absent
    /// value when it is not.
    Nullable,
    /// A type-parameter slot. Generic code runs against the erased carrier.
    TypeParameter,
    /// A supertype slot: a declared interface, or `kotlin.Any`.
    Supertype,
}

impl KotlinAdaptationBoundary {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nullable => "nullable",
            Self::TypeParameter => "type_parameter",
            Self::Supertype => "supertype",
        }
    }
}

/// One exact representation adaptation of a Kotlin value class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KotlinValueAdaptation {
    /// An underlying value becomes the value class's unboxed carrier. No
    /// wrapper exists, so this creates no object identity.
    Construction,
    /// The underlying value is read back out of a carrier.
    UnderlyingProjection,
    /// The unboxed carrier is wrapped for a boundary that requires a wrapper.
    Boxing(KotlinAdaptationBoundary),
    /// A wrapper is unwrapped back to the unboxed carrier.
    Unboxing(KotlinAdaptationBoundary),
}

impl KotlinValueAdaptation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Construction => "construction",
            Self::UnderlyingProjection => "underlying_projection",
            Self::Boxing(_) => "boxing",
            Self::Unboxing(_) => "unboxing",
        }
    }

    /// The language rule that selected this adaptation, when the adaptation is
    /// one the JVM carrier boundary forced.
    pub const fn boundary(self) -> Option<KotlinAdaptationBoundary> {
        match self {
            Self::Construction | Self::UnderlyingProjection => None,
            Self::Boxing(boundary) | Self::Unboxing(boundary) => Some(boundary),
        }
    }
}

/// The complete witness for one adaptation: which declaration adapts, through
/// which underlying property, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KotlinValueAdaptationFact {
    class: KotlinValueClass,
    adaptation: KotlinValueAdaptation,
}

impl KotlinValueAdaptationFact {
    pub fn new(class: KotlinValueClass, adaptation: KotlinValueAdaptation) -> Self {
        Self { class, adaptation }
    }

    pub fn class(&self) -> &KotlinValueClass {
        &self.class
    }

    pub fn adaptation(&self) -> KotlinValueAdaptation {
        self.adaptation
    }

    /// A stable, length-delimited encoding of the whole witness.
    ///
    /// Everything that decides the adaptation takes part: the adapting
    /// declaration's package, enclosing declarations, name and source anchor,
    /// the property that carries the value, the direction, and the boundary
    /// rule that forced it. Two adaptations that differ in any of those encode
    /// differently, which is what lets a consumer content-address the witness
    /// into an exact operation identity instead of restating its fields.
    pub fn witness_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_field(&mut bytes, WITNESS_DOMAIN);
        let identity = self.class.identity();
        push_field(&mut bytes, identity.package_name().as_bytes());
        push_field(&mut bytes, &(identity.nesting().len() as u64).to_be_bytes());
        for outer in identity.nesting() {
            push_field(&mut bytes, outer.as_bytes());
        }
        push_field(&mut bytes, identity.name().as_bytes());
        push_field(
            &mut bytes,
            &(identity.declaration_start() as u64).to_be_bytes(),
        );
        let underlying = self.class.underlying();
        push_field(&mut bytes, underlying.name().as_bytes());
        push_field(
            &mut bytes,
            &(underlying.declaration_start() as u64).to_be_bytes(),
        );
        push_field(&mut bytes, self.adaptation.label().as_bytes());
        match self.adaptation.boundary() {
            Some(boundary) => push_field(&mut bytes, boundary.label().as_bytes()),
            None => push_field(&mut bytes, b"no_boundary"),
        }
        bytes
    }
}

/// The domain separator that keeps a value-carrier witness from colliding with
/// any other content-addressed payload.
const WITNESS_DOMAIN: &[u8] = b"bifrost.kotlin.value-carrier-adaptation.v1";

fn push_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field);
}

/// Why a value-class carrier question has no proven answer in this file.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KotlinAdaptationIncomplete {
    /// The spelling at a `value class` does not denote `kotlin.jvm.JvmInline`.
    AnnotationIdentity,
    /// A wildcard import could bind the annotation's simple name to a
    /// declaration this file cannot see, and that binding would win over the
    /// default import that would otherwise prove the identity.
    WildcardAnnotationShadow,
    /// More than one declaration in this file spells the same type name.
    AmbiguousDeclaration,
    /// The class does not expose exactly one `val` primary-constructor
    /// property, so it has no proven unboxed carrier.
    UnderlyingProperty,
    /// The destination writes a type this file does not declare. A Java
    /// interop signature reaches this arm, as does any cross-file Kotlin type.
    ForeignDestination,
    /// The destination writes no type at all.
    UnwrittenDestination,
    /// The destination is a generic application whose specialization is not
    /// written here.
    GenericSpecialization,
    /// The destination is declared here but the value class does not widen to
    /// it.
    UnrelatedDestination,
    /// Something other than the primary constructor can answer the callee
    /// spelling: a binding in scope, a same-named declaration, or an import.
    AmbiguousCallee,
    /// The actual argument provably has a type the underlying property does
    /// not accept, so the primary constructor is not what the call selects.
    UnderlyingTypeMismatch,
    /// The actual's type is not known well enough to prove it fits the carrier.
    UnderlyingTypeUnknown,
    /// The class declares another constructor, and this file does not prove
    /// the actual's type well enough to say which one the call selects.
    AmbiguousConstructor,
}

impl KotlinAdaptationIncomplete {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AnnotationIdentity => "annotation_identity",
            Self::WildcardAnnotationShadow => "wildcard_annotation_shadow",
            Self::AmbiguousDeclaration => "ambiguous_declaration",
            Self::UnderlyingProperty => "underlying_property",
            Self::ForeignDestination => "foreign_destination",
            Self::UnwrittenDestination => "unwritten_destination",
            Self::GenericSpecialization => "generic_specialization",
            Self::UnrelatedDestination => "unrelated_destination",
            Self::AmbiguousCallee => "ambiguous_callee",
            Self::UnderlyingTypeMismatch => "underlying_type_mismatch",
            Self::UnderlyingTypeUnknown => "underlying_type_unknown",
            Self::AmbiguousConstructor => "ambiguous_constructor",
        }
    }

    /// A short sentence for the semantic gap a consumer publishes.
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AnnotationIdentity => {
                "the annotation on this value class does not denote kotlin.jvm.JvmInline, so its JVM carrier is not proven"
            }
            Self::WildcardAnnotationShadow => {
                "a wildcard import could bind JvmInline to a declaration outside this file, which would win over the default import"
            }
            Self::AmbiguousDeclaration => {
                "more than one declaration in this file spells this type name"
            }
            Self::UnderlyingProperty => {
                "a JVM inline value class carries exactly one val primary-constructor property, and this declaration does not"
            }
            Self::ForeignDestination => {
                "the destination writes a type this file does not declare, so its JVM carrier is not proven here"
            }
            Self::UnwrittenDestination => {
                "the destination writes no type, so the carrier it selects is not proven here"
            }
            Self::GenericSpecialization => {
                "the destination is a generic slot whose specialization is not written here"
            }
            Self::UnrelatedDestination => {
                "the destination type is declared here but this value class does not widen to it"
            }
            Self::AmbiguousCallee => {
                "a binding in scope, a same-named declaration, or an import can answer this call, so it does not provably select the primary constructor"
            }
            Self::UnderlyingTypeMismatch => {
                "the actual argument has a type the underlying property does not accept, so this call does not select the primary constructor"
            }
            Self::UnderlyingTypeUnknown => {
                "the actual argument's type is not proven to fit the underlying property"
            }
            Self::AmbiguousConstructor => {
                "this value class declares another constructor and the actual's type is not proven here, so which one the call selects is open"
            }
        }
    }
}

/// How a Kotlin value is carried on the JVM.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KotlinCarrier {
    /// The unboxed carrier of a JVM inline value class: the underlying value
    /// itself, with no wrapper object.
    Unboxed(KotlinValueClassId),
    /// The boxed wrapper a boundary forced.
    Boxed(KotlinValueClassId, KotlinAdaptationBoundary),
    /// An ordinary reference, an underlying value, or anything else no value
    /// class this file declares participates in.
    Unrelated,
    /// A value class participates but its carrier is not proven.
    Incomplete(KotlinAdaptationIncomplete),
}

impl KotlinCarrier {
    /// The value class this carrier holds, when one is proven.
    pub const fn value_class(self) -> Option<KotlinValueClassId> {
        match self {
            Self::Unboxed(id) | Self::Boxed(id, _) => Some(id),
            Self::Unrelated | Self::Incomplete(_) => None,
        }
    }
}

/// What one written Kotlin type denotes for carrier purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinWrittenType {
    /// The value class itself.
    ValueClass {
        id: KotlinValueClassId,
        nullable: bool,
    },
    /// A type parameter in scope at the written type.
    TypeParameter,
    /// `kotlin.Any`, Kotlin's universal supertype.
    Any,
    /// A type this file declares that is not a value class, identified by the
    /// declaration start of the declaration it names.
    Declared { declaration_start: usize },
    /// No type is written.
    Absent,
    /// The written type is not proven here.
    Incomplete(KotlinAdaptationIncomplete),
}

/// What carrying a value from one representation into another does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KotlinAdaptationOutcome {
    /// Nothing this file models adapts across this transfer.
    Unrelated,
    /// A value class is carried, but the destination holds the same carrier.
    Unchanged,
    /// The exact adaptation and its complete witness.
    Adapted(KotlinValueAdaptationFact),
    /// A value class is carried but the boundary is not proven.
    Incomplete(KotlinAdaptationIncomplete),
}

/// What a call site's own scope proves about the callee spelling.
///
/// Kotlin resolves `Money(raw)` against everything in scope that can answer
/// it, and a variable with an `invoke` operator in a nearer scope wins over a
/// classifier's constructor. The lowering owns the scope, so it answers this
/// and the index owns what follows from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinCalleeBinding {
    /// No local, parameter, or captured binding in scope spells the callee.
    Free,
    /// A binding in scope spells it and is written with a function type, so
    /// the call invokes that binding and never reaches the constructor.
    Invokable,
    /// A binding in scope spells it, but this file does not prove whether it
    /// is invokable.
    Opaque,
}

/// The type evidence one file has for an actual argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinActualEvidence<'tree> {
    /// The type node the actual's binding writes.
    Written(Node<'tree>),
    /// The literal the actual spells; its node kind is its type.
    Literal(Node<'tree>),
    /// A value class this file declares.
    ValueClass(KotlinValueClassId),
    /// Nothing this file proves.
    Unknown,
}

/// Whether an actual argument provably fits a value class's carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinUnderlyingMatch {
    /// The actual has the underlying property's own type.
    Proven,
    /// The actual provably has a type the underlying property does not accept.
    Mismatched,
    /// This file does not prove the actual's type.
    Unknown,
}

/// Which callable a `Name(...)` spelling provably selects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinConstructorSelection {
    /// Only this value class's primary constructor can answer the spelling.
    Primary(KotlinValueClassId),
    /// A value class is named but the selection is not proven.
    Incomplete(KotlinAdaptationIncomplete),
    /// Nothing about this spelling names a value class this file declares.
    Unrelated,
}

/// A comparable identity for one written Kotlin type.
///
/// Two written types in one file are compared through the same scope, so a
/// name this file does not declare is compared by the spelling the file's own
/// explicit imports normalize it to. That is exactly as much as one file
/// proves, and it is enough to tell `Long` from `String`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KotlinWrittenTypeKey {
    head: KotlinTypeHead,
    nullable: bool,
    arguments: Vec<KotlinWrittenTypeKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KotlinTypeHead {
    /// A type this file declares, by its source anchor.
    Declared(usize),
    /// A type parameter in scope at the written type.
    TypeParameter(String),
    /// A name this file does not declare, normalized through its imports.
    Foreign(String),
}

impl KotlinWrittenTypeKey {
    /// Whether a value of `self`'s type can be passed where `formal` is
    /// written.
    ///
    /// Only the relations one file proves count: the same type, and a non-null
    /// value into a nullable slot. A declared subtype relation is a separate
    /// question this file does not answer.
    fn fits(&self, formal: &Self) -> bool {
        self.head == formal.head
            && self.arguments == formal.arguments
            && (formal.nullable || !self.nullable)
    }

    /// Whether this key names `kotlin.Any`, which accepts every value.
    fn is_any(&self) -> bool {
        matches!(&self.head, KotlinTypeHead::Foreign(name) if name == "Any" || name == KOTLIN_ANY)
            && self.arguments.is_empty()
    }
}

/// The Kotlin types a literal can have.
///
/// An integer literal takes the type its expected type asks for, which is why
/// one literal answers for four widths; `1.0` and `1.0f` share one node kind,
/// so a real literal answers for both floating widths rather than reading the
/// suffix out of the source text.
pub fn literal_type_names(kind: &str) -> &'static [&'static str] {
    match kind {
        "integer_literal" | "hex_literal" | "bin_literal" => &["Byte", "Short", "Int", "Long"],
        "long_literal" => &["Long"],
        "unsigned_literal" => &["UByte", "UShort", "UInt", "ULong"],
        "real_literal" => &["Float", "Double"],
        "string_literal" => &["String"],
        "character_literal" => &["Char"],
        "boolean_literal" => &["Boolean"],
        _ => &[],
    }
}

/// Whether a written type is a function type, which is what makes a binding
/// answer a call directly.
pub fn kotlin_written_type_is_function(written: Node<'_>) -> bool {
    let mut current = written;
    for _ in 0..MAX_SCOPE_DEPTH {
        match current.kind() {
            "function_type" => return true,
            "nullable_type" | "parenthesized_type" | "not_nullable_type" => {
                match named_children(current).into_iter().next() {
                    Some(inner) => current = inner,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    false
}

/// The value classes one Kotlin file declares, and the name bindings that
/// decide which carrier a written type selects.
#[derive(Debug, Default)]
pub struct KotlinValueClassIndex<'tree> {
    package_name: String,
    imports: Vec<ImportInfo>,
    classes: Vec<KotlinValueClass>,
    /// Each value class's spelled supertypes, parallel to `classes`.
    supertypes: Vec<Vec<Vec<String>>>,
    /// The type each value class writes for its underlying property, parallel
    /// to `classes`. A class whose carrier type is not written has none.
    underlying_types: Vec<Option<Node<'tree>>>,
    /// What else could answer a call spelled like each value class, parallel
    /// to `classes`.
    alternatives: Vec<KotlinConstructorAlternatives>,
    /// Simple names the file declares as callables. A function is a callable
    /// wherever it is declared; a property is one only where it is a member or
    /// a top-level declaration, because a local is already a binding in scope.
    callable_names: HashSet<String>,
    /// Simple names an explicit import binds. Such an import can bring in a
    /// factory function that competes with a constructor of the same name.
    imported_names: HashSet<String>,
    /// Every type name the file declares, mapped to what it denotes.
    declarations: HashMap<String, KotlinDeclaredType>,
    /// Fully-qualified names of the declarations in this file, for the name
    /// ladder's existence predicate.
    declared_names: Vec<String>,
    /// The type node each declared class writes for each of its own
    /// properties, keyed by the owner's declaration start.
    members: HashMap<(usize, String), Node<'tree>>,
}

/// What, besides the primary constructor, can answer a call spelled like one
/// value class.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct KotlinConstructorAlternatives {
    /// How many arguments each secondary constructor accepts, as the inclusive
    /// range its required and total parameter counts allow. A secondary
    /// constructor that cannot take the call's argument count is not a
    /// candidate for it at all.
    secondary_arities: Vec<(usize, usize)>,
    /// A companion object declares `operator fun invoke`, which answers the
    /// class's own spelling ahead of the constructor.
    companion_invoke: bool,
}

/// What a simple type name declared in this file denotes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KotlinDeclaredType {
    ValueClass(KotlinValueClassId),
    /// A declaration that is not a proven JVM inline value class.
    Ordinary {
        declaration_start: usize,
    },
    /// A `value class` whose JVM carrier is not proven.
    Incomplete(KotlinAdaptationIncomplete),
    /// More than one declaration spells this name.
    Ambiguous,
}

/// The walk was cancelled before the index was complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KotlinValueClassWalkCancelled;

/// One class-like declaration as the index's first pass reads it.
struct DeclaredClass<'tree> {
    node: Node<'tree>,
    name: String,
    nesting: Vec<String>,
}

impl<'tree> KotlinValueClassIndex<'tree> {
    /// Build the index for one parsed Kotlin file.
    ///
    /// `cancelled` is polled once per visited declaration so a caller that
    /// owns a cancellation token keeps its termination guarantee.
    pub fn build(
        root: Node<'tree>,
        source: &str,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Self, KotlinValueClassWalkCancelled> {
        let package_name = kotlin_package_name(root, source);
        let mut index = Self {
            package_name,
            ..Self::default()
        };
        index.collect_imports(root, source);
        let declared = index.collect_declarations(root, source, cancelled)?;
        index.collect_callable_names(root, source, cancelled)?;
        index.declared_names = declared
            .iter()
            .map(|class| index.qualify(&class.nesting, &class.name))
            .collect();
        index.classify(&declared, source);
        for class in &declared {
            for (name, written) in declared_member_types(class.node, source) {
                index
                    .members
                    .insert((class.node.start_byte(), name), written);
            }
        }
        Ok(index)
    }

    /// The declaration this file gives the type written at `written`, when it
    /// declares one. The answer is the declaration's source anchor, which is
    /// what [`Self::member_written_type`] keys on.
    pub fn declared_type_owner(&self, written: Node<'_>, source: &str) -> Option<usize> {
        let user_type = nominal_user_type(written)?;
        let segments = kotlin_user_type_segments(user_type, source);
        let [head] = segments.as_slice() else {
            return None;
        };
        match self.declarations.get(head.as_str())? {
            KotlinDeclaredType::ValueClass(id) => {
                Some(self.value_class(*id).identity().declaration_start())
            }
            KotlinDeclaredType::Ordinary { declaration_start } => Some(*declaration_start),
            KotlinDeclaredType::Incomplete(_) | KotlinDeclaredType::Ambiguous => None,
        }
    }

    /// The type a declared class writes for one of its own properties.
    pub fn member_written_type(&self, owner: usize, member: &str) -> Option<Node<'tree>> {
        self.members.get(&(owner, member.to_owned())).copied()
    }

    /// The proven value class behind a handle.
    pub fn value_class(&self, id: KotlinValueClassId) -> &KotlinValueClass {
        &self.classes[id.index()]
    }

    /// How many `value class` declarations this file has a proven JVM carrier
    /// for, and how many it reported a typed reason for instead.
    pub fn declaration_census(&self) -> (usize, usize) {
        let unproven = self
            .declarations
            .values()
            .filter(|denotes| matches!(denotes, KotlinDeclaredType::Incomplete(_)))
            .count();
        (self.classes.len(), unproven)
    }

    /// What carrier a type name this file declares stands for.
    ///
    /// This answers a declaration question, not a call one: proving that a
    /// `name(...)` spelling runs that declaration's constructor is
    /// [`Self::constructor_selection`]'s job, and it needs the call site's own
    /// scope as well.
    pub fn declared_value_class(&self, name: &str) -> KotlinCarrier {
        match self.declarations.get(name) {
            Some(KotlinDeclaredType::ValueClass(id)) => KotlinCarrier::Unboxed(*id),
            Some(KotlinDeclaredType::Incomplete(reason)) => KotlinCarrier::Incomplete(*reason),
            Some(KotlinDeclaredType::Ambiguous) => {
                KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::AmbiguousDeclaration)
            }
            Some(KotlinDeclaredType::Ordinary { .. }) | None => KotlinCarrier::Unrelated,
        }
    }

    /// Which callable a `name(...)` spelling selects, given what the call
    /// site's own scope proved about the callee.
    ///
    /// The constructor is selected only when nothing else can answer the
    /// spelling: no binding in scope, no same-named declaration in the file,
    /// no explicit import of the name, and no companion `invoke`.
    pub fn constructor_selection(
        &self,
        name: &str,
        binding: KotlinCalleeBinding,
    ) -> KotlinConstructorSelection {
        let id = match self.declared_value_class(name) {
            KotlinCarrier::Unboxed(id) => id,
            KotlinCarrier::Incomplete(reason) => {
                return KotlinConstructorSelection::Incomplete(reason);
            }
            KotlinCarrier::Boxed(..) | KotlinCarrier::Unrelated => {
                return KotlinConstructorSelection::Unrelated;
            }
        };
        match binding {
            // The binding answers the call itself; no constructor is involved.
            KotlinCalleeBinding::Invokable => return KotlinConstructorSelection::Unrelated,
            KotlinCalleeBinding::Opaque => {
                return KotlinConstructorSelection::Incomplete(
                    KotlinAdaptationIncomplete::AmbiguousCallee,
                );
            }
            KotlinCalleeBinding::Free => {}
        }
        if self.callable_names.contains(name)
            || self.imported_names.contains(name)
            || self.alternatives[id.index()].companion_invoke
        {
            return KotlinConstructorSelection::Incomplete(
                KotlinAdaptationIncomplete::AmbiguousCallee,
            );
        }
        KotlinConstructorSelection::Primary(id)
    }

    /// Whether the class declares another constructor that could take a call
    /// of this argument count, so that an actual whose type this file cannot
    /// prove leaves the selection open.
    ///
    /// A secondary constructor of a different arity answers a different call,
    /// so it cannot compete for this one; only one that accepts the same count
    /// makes the selection depend on the actual's type.
    pub fn competing_constructor(&self, id: KotlinValueClassId, arity: usize) -> bool {
        self.alternatives[id.index()]
            .secondary_arities
            .iter()
            .any(|(required, total)| (*required..=*total).contains(&arity))
    }

    /// Whether an actual argument provably fits the value class's carrier.
    pub fn underlying_match(
        &self,
        id: KotlinValueClassId,
        actual: KotlinActualEvidence<'_>,
        source: &str,
    ) -> KotlinUnderlyingMatch {
        let Some(formal) = self.underlying_types[id.index()] else {
            return KotlinUnderlyingMatch::Unknown;
        };
        let Some(formal) = self.written_type_key(formal, source) else {
            return KotlinUnderlyingMatch::Unknown;
        };
        // A declaration's type parameter does not establish the constructor's
        // call-site specialization. Its actual substitution must be proven.
        if matches!(formal.head, KotlinTypeHead::TypeParameter(_)) {
            return KotlinUnderlyingMatch::Unknown;
        }
        match actual {
            KotlinActualEvidence::Written(written) => {
                match self.written_type_key(written, source) {
                    Some(actual) if matches!(actual.head, KotlinTypeHead::TypeParameter(_)) => {
                        KotlinUnderlyingMatch::Unknown
                    }
                    Some(actual)
                        if actual.fits(&formal)
                            || (formal.is_any() && (formal.nullable || !actual.nullable)) =>
                    {
                        KotlinUnderlyingMatch::Proven
                    }
                    Some(_) => KotlinUnderlyingMatch::Mismatched,
                    None => KotlinUnderlyingMatch::Unknown,
                }
            }
            KotlinActualEvidence::Literal(literal) => {
                if literal.kind() == "null_literal" {
                    return if formal.nullable {
                        KotlinUnderlyingMatch::Proven
                    } else {
                        KotlinUnderlyingMatch::Mismatched
                    };
                }
                if formal.is_any() {
                    return KotlinUnderlyingMatch::Proven;
                }
                let names = literal_type_names(literal.kind());
                if names.is_empty() {
                    return KotlinUnderlyingMatch::Unknown;
                }
                let KotlinTypeHead::Foreign(formal_name) = &formal.head else {
                    return KotlinUnderlyingMatch::Mismatched;
                };
                if !formal.arguments.is_empty() {
                    return KotlinUnderlyingMatch::Mismatched;
                }
                let matched = names.iter().any(|name| {
                    formal_name == name || formal_name == &format!("{KOTLIN_ANY_PACKAGE}.{name}")
                });
                if matched {
                    KotlinUnderlyingMatch::Proven
                } else {
                    KotlinUnderlyingMatch::Mismatched
                }
            }
            KotlinActualEvidence::ValueClass(actual) => {
                if formal.is_any() {
                    return KotlinUnderlyingMatch::Proven;
                }
                let anchor = self.value_class(actual).identity().declaration_start();
                if !formal.arguments.is_empty() {
                    // A generic carrier needs the actual's own arguments, which
                    // a bare class identity does not carry.
                    return KotlinUnderlyingMatch::Unknown;
                }
                if formal.head == KotlinTypeHead::Declared(anchor) {
                    KotlinUnderlyingMatch::Proven
                } else {
                    KotlinUnderlyingMatch::Mismatched
                }
            }
            KotlinActualEvidence::Unknown => KotlinUnderlyingMatch::Unknown,
        }
    }

    /// A comparable identity for one written type, as this file resolves it.
    pub fn written_type_key(
        &self,
        written: Node<'_>,
        source: &str,
    ) -> Option<KotlinWrittenTypeKey> {
        self.written_type_key_at(written, source, 0)
    }

    fn written_type_key_at(
        &self,
        written: Node<'_>,
        source: &str,
        depth: usize,
    ) -> Option<KotlinWrittenTypeKey> {
        if depth >= MAX_TYPE_ARGUMENT_DEPTH {
            return None;
        }
        let nullable = written.kind() == "nullable_type";
        let user_type = nominal_user_type(written)?;
        let segments = kotlin_user_type_segments(user_type, source);
        let [head] = segments.as_slice() else {
            // A dotted spelling names a nested or package-qualified type; this
            // file's own declarations are reached by their simple name, so the
            // spelling is all it proves.
            return (!segments.is_empty()).then(|| KotlinWrittenTypeKey {
                head: KotlinTypeHead::Foreign(segments.join(".")),
                nullable,
                arguments: Vec::new(),
            });
        };
        let arguments = match first_named_child_of_kind(user_type, "type_arguments") {
            Some(arguments) => named_children(arguments)
                .into_iter()
                .map(|argument| self.written_type_key_at(argument, source, depth + 1))
                .collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        let head = if type_parameter_in_scope(head, source, written) {
            KotlinTypeHead::TypeParameter(head.clone())
        } else {
            match self.declarations.get(head.as_str()) {
                Some(KotlinDeclaredType::ValueClass(id)) => {
                    KotlinTypeHead::Declared(self.value_class(*id).identity().declaration_start())
                }
                Some(KotlinDeclaredType::Ordinary { declaration_start }) => {
                    KotlinTypeHead::Declared(*declaration_start)
                }
                // A name this file declares more than once, or declares with an
                // unproven carrier, denotes nothing comparable.
                Some(KotlinDeclaredType::Incomplete(_) | KotlinDeclaredType::Ambiguous) => {
                    return None;
                }
                None => KotlinTypeHead::Foreign(self.normalized_foreign_name(head)),
            }
        };
        Some(KotlinWrittenTypeKey {
            head,
            nullable,
            arguments,
        })
    }

    /// The spelling an explicit import normalizes a foreign simple name to.
    fn normalized_foreign_name(&self, head: &str) -> String {
        self.imports
            .iter()
            .filter(|import| !import.is_wildcard && import.local_name() == Some(head))
            .find_map(kotlin_import_path)
            .unwrap_or_else(|| head.to_owned())
    }

    /// Whether reading `member` off a value-class carrier projects its
    /// underlying value.
    pub fn projects_underlying(&self, id: KotlinValueClassId, member: &str) -> bool {
        self.value_class(id).underlying.name == member
    }

    /// Classify the type written at `written`, which must be a type node.
    ///
    /// `scope` is the node the type is written at; the walk out of it finds
    /// the declarations whose type parameters are in scope.
    pub fn written_type(
        &self,
        written: Node<'_>,
        source: &str,
        scope: Node<'_>,
    ) -> KotlinWrittenType {
        let nullable = written.kind() == "nullable_type";
        let Some(user_type) = nominal_user_type(written) else {
            // A function type, a star projection, or a recovery-mangled node
            // writes no nominal name.
            return KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::ForeignDestination);
        };
        if first_named_child_of_kind(user_type, "type_arguments").is_some() {
            // The applied type is what a slot of this type holds; its argument
            // is a different question, and answering it needs the declaration
            // the argument specializes.
            return KotlinWrittenType::Incomplete(
                KotlinAdaptationIncomplete::GenericSpecialization,
            );
        }
        let segments = kotlin_user_type_segments(user_type, source);
        let [head] = segments.as_slice() else {
            // A dotted spelling names a nested or package-qualified type; this
            // file's own declarations are reached by their simple name.
            return match self.denotes(&segments, KOTLIN_ANY, KOTLIN_ANY_PACKAGE, &[]) {
                Ok(true) => KotlinWrittenType::Any,
                Ok(false) => {
                    KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
                }
                Err(reason) => KotlinWrittenType::Incomplete(reason),
            };
        };
        if type_parameter_in_scope(head, source, scope) {
            return KotlinWrittenType::TypeParameter;
        }
        match self.declarations.get(head.as_str()) {
            Some(KotlinDeclaredType::ValueClass(id)) => {
                KotlinWrittenType::ValueClass { id: *id, nullable }
            }
            Some(KotlinDeclaredType::Ordinary { declaration_start }) => {
                KotlinWrittenType::Declared {
                    declaration_start: *declaration_start,
                }
            }
            Some(KotlinDeclaredType::Incomplete(reason)) => KotlinWrittenType::Incomplete(*reason),
            Some(KotlinDeclaredType::Ambiguous) => {
                KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::AmbiguousDeclaration)
            }
            None => match self.denotes(&segments, KOTLIN_ANY, KOTLIN_ANY_PACKAGE, &[]) {
                Ok(true) => KotlinWrittenType::Any,
                Ok(false) => {
                    KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
                }
                Err(reason) => KotlinWrittenType::Incomplete(reason),
            },
        }
    }

    /// The carrier a slot of this written type holds for a value of class
    /// `carried`.
    pub fn carrier_of(
        &self,
        written: KotlinWrittenType,
        carried: Option<KotlinValueClassId>,
    ) -> KotlinCarrier {
        match written {
            KotlinWrittenType::ValueClass { id, nullable } => {
                if nullable {
                    KotlinCarrier::Boxed(id, KotlinAdaptationBoundary::Nullable)
                } else {
                    KotlinCarrier::Unboxed(id)
                }
            }
            KotlinWrittenType::TypeParameter => match carried {
                Some(id) => KotlinCarrier::Boxed(id, KotlinAdaptationBoundary::TypeParameter),
                None => KotlinCarrier::Unrelated,
            },
            KotlinWrittenType::Any => match carried {
                Some(id) => KotlinCarrier::Boxed(id, KotlinAdaptationBoundary::Supertype),
                None => KotlinCarrier::Unrelated,
            },
            KotlinWrittenType::Declared { declaration_start } => match carried {
                Some(id) if self.widens_to(id, declaration_start) => {
                    KotlinCarrier::Boxed(id, KotlinAdaptationBoundary::Supertype)
                }
                Some(_) => {
                    KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::UnrelatedDestination)
                }
                None => KotlinCarrier::Unrelated,
            },
            KotlinWrittenType::Absent => match carried {
                Some(_) => {
                    KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::UnwrittenDestination)
                }
                None => KotlinCarrier::Unrelated,
            },
            KotlinWrittenType::Incomplete(reason) => match carried {
                Some(_) => KotlinCarrier::Incomplete(reason),
                None => KotlinCarrier::Unrelated,
            },
        }
    }

    /// What carrying a value from `source` into `destination` does.
    pub fn adaptation(
        &self,
        source: KotlinCarrier,
        destination: KotlinCarrier,
    ) -> KotlinAdaptationOutcome {
        match (source, destination) {
            (KotlinCarrier::Unrelated, _) => KotlinAdaptationOutcome::Unrelated,
            (KotlinCarrier::Incomplete(reason), _) | (_, KotlinCarrier::Incomplete(reason)) => {
                KotlinAdaptationOutcome::Incomplete(reason)
            }
            // The destination carries nothing this file models: a value class
            // reaching it is exactly the boundary that is not proven here.
            (_, KotlinCarrier::Unrelated) => {
                KotlinAdaptationOutcome::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
            }
            (KotlinCarrier::Unboxed(from), KotlinCarrier::Unboxed(into))
            | (KotlinCarrier::Boxed(from, _), KotlinCarrier::Boxed(into, _))
                if from == into =>
            {
                KotlinAdaptationOutcome::Unchanged
            }
            (KotlinCarrier::Unboxed(from), KotlinCarrier::Boxed(into, boundary))
                if from == into =>
            {
                self.fact(from, KotlinValueAdaptation::Boxing(boundary))
            }
            (KotlinCarrier::Boxed(from, boundary), KotlinCarrier::Unboxed(into))
                if from == into =>
            {
                self.fact(from, KotlinValueAdaptation::Unboxing(boundary))
            }
            // Two different value classes never convert into one another.
            _ => KotlinAdaptationOutcome::Incomplete(
                KotlinAdaptationIncomplete::UnrelatedDestination,
            ),
        }
    }

    /// The construction of `id` from its underlying value.
    pub fn construction(&self, id: KotlinValueClassId) -> KotlinAdaptationOutcome {
        self.fact(id, KotlinValueAdaptation::Construction)
    }

    /// The projection of `id`'s underlying value out of a carrier.
    pub fn projection(&self, id: KotlinValueClassId) -> KotlinAdaptationOutcome {
        self.fact(id, KotlinValueAdaptation::UnderlyingProjection)
    }

    fn fact(
        &self,
        id: KotlinValueClassId,
        adaptation: KotlinValueAdaptation,
    ) -> KotlinAdaptationOutcome {
        KotlinAdaptationOutcome::Adapted(KotlinValueAdaptationFact::new(
            self.value_class(id).clone(),
            adaptation,
        ))
    }

    /// Whether `id` declares a supertype that is the declaration starting at
    /// `declaration_start`.
    fn widens_to(&self, id: KotlinValueClassId, declaration_start: usize) -> bool {
        self.supertypes[id.index()].iter().any(|spelled| {
            let [head] = spelled.as_slice() else {
                return false;
            };
            matches!(
                self.declarations.get(head.as_str()),
                Some(KotlinDeclaredType::Ordinary { declaration_start: start }) if *start == declaration_start
            )
        })
    }

    fn collect_imports(&mut self, root: Node<'_>, source: &str) {
        for list in named_children(root)
            .into_iter()
            .filter(|child| child.kind() == "import_list")
        {
            for header in named_children(list)
                .into_iter()
                .filter(|child| child.kind() == "import_header")
            {
                if let Some(info) = kotlin_import_info_from_node(header, source) {
                    if !info.is_wildcard
                        && let Some(bound) = info.local_name()
                    {
                        self.imported_names.insert(bound.to_owned());
                    }
                    self.imports.push(info);
                }
            }
        }
    }

    fn collect_declarations(
        &self,
        root: Node<'tree>,
        source: &str,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<DeclaredClass<'tree>>, KotlinValueClassWalkCancelled> {
        let mut declared = Vec::new();
        let mut nesting: Vec<(usize, String)> = Vec::new();
        try_walk_named_tree_preorder(root, true, |node| {
            if cancelled() {
                return Err(KotlinValueClassWalkCancelled);
            }
            while nesting
                .last()
                .is_some_and(|(end, _)| node.start_byte() >= *end)
            {
                nesting.pop();
            }
            if kotlin_class_like_kind(node).is_none() {
                return Ok(WalkControl::Continue);
            }
            let Some(name) = first_named_child_of_kind(node, "type_identifier")
                .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                .filter(|name| !name.is_empty())
            else {
                return Ok(WalkControl::Continue);
            };
            declared.push(DeclaredClass {
                node,
                name: name.to_owned(),
                nesting: nesting.iter().map(|(_, name)| name.clone()).collect(),
            });
            nesting.push((node.end_byte(), name.to_owned()));
            Ok(WalkControl::Continue)
        })?;
        Ok(declared)
    }

    /// Every simple name the file declares as something callable.
    ///
    /// A `Money(raw)` spelling selects a constructor only when nothing else
    /// answers it. A factory function named after its own class is the shape
    /// that matters here, and Kotlin resolves it by overload resolution
    /// against the constructor rather than by preferring either one.
    fn collect_callable_names(
        &mut self,
        root: Node<'tree>,
        source: &str,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<(), KotlinValueClassWalkCancelled> {
        try_walk_named_tree_preorder(root, true, |node| {
            if cancelled() {
                return Err(KotlinValueClassWalkCancelled);
            }
            // A local `fun` and a local `val` are bindings the call site's own
            // scope already sees, and they are in scope only inside their own
            // body. Only a member or top-level declaration is a callable this
            // index has to remember for the whole file.
            if !node
                .parent()
                .is_some_and(|parent| DECLARATION_SCOPE_KINDS.contains(&parent.kind()))
            {
                return Ok(WalkControl::Continue);
            }
            let name = match node.kind() {
                "function_declaration" => first_named_child_of_kind(node, "simple_identifier"),
                "property_declaration" => first_named_child_of_kind(node, "variable_declaration")
                    .and_then(|binding| first_named_child_of_kind(binding, "simple_identifier")),
                _ => None,
            };
            if let Some(name) = name.and_then(|name| name.utf8_text(source.as_bytes()).ok())
                && !name.is_empty()
            {
                self.callable_names.insert(name.to_owned());
            }
            Ok(WalkControl::Continue)
        })
    }

    /// Decide, for each declared name, what it denotes.
    fn classify(&mut self, declared: &[DeclaredClass<'tree>], source: &str) {
        for class in declared {
            let denotes = self.denote_declaration(class, source);
            match self.declarations.entry(class.name.clone()) {
                std::collections::hash_map::Entry::Occupied(mut existing) => {
                    existing.insert(KotlinDeclaredType::Ambiguous);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(denotes);
                }
            }
        }
    }

    fn denote_declaration(
        &mut self,
        class: &DeclaredClass<'tree>,
        source: &str,
    ) -> KotlinDeclaredType {
        let declaration_start = class.node.start_byte();
        if kotlin_class_like_kind(class.node) != Some(KotlinClassLikeKind::Class)
            || !kotlin_has_modifier(class.node, "value")
        {
            return KotlinDeclaredType::Ordinary { declaration_start };
        }
        let scope_owners = self.scope_owners(&class.nesting);
        if let Err(reason) = self.prove_jvm_inline(class.node, source, &scope_owners) {
            return KotlinDeclaredType::Incomplete(reason);
        }
        let Some((underlying, underlying_type)) = underlying_property(class.node, source) else {
            return KotlinDeclaredType::Incomplete(KotlinAdaptationIncomplete::UnderlyingProperty);
        };
        let id = KotlinValueClassId(self.classes.len());
        self.classes.push(KotlinValueClass {
            identity: KotlinDeclarationIdentity::new(
                self.package_name.clone(),
                class.nesting.clone(),
                class.name.clone(),
                declaration_start,
            ),
            underlying,
        });
        self.supertypes
            .push(extract_kotlin_supertype_segments(class.node, source));
        self.underlying_types.push(underlying_type);
        self.alternatives
            .push(constructor_alternatives(class.node, source));
        KotlinDeclaredType::ValueClass(id)
    }

    /// Whether one of this declaration's annotations denotes
    /// `kotlin.jvm.JvmInline`.
    fn prove_jvm_inline(
        &self,
        node: Node<'_>,
        source: &str,
        scope_owners: &[String],
    ) -> Result<(), KotlinAdaptationIncomplete> {
        let Some(modifiers) = first_named_child_of_kind(node, "modifiers") else {
            return Err(KotlinAdaptationIncomplete::AnnotationIdentity);
        };
        let mut shadowed = None;
        for annotation in named_children(modifiers)
            .into_iter()
            .filter(|child| child.kind() == "annotation")
        {
            for user_type in annotation_user_types(annotation) {
                let segments = kotlin_user_type_segments(user_type, source);
                match self.denotes(
                    &segments,
                    JVM_INLINE_ANNOTATION,
                    JVM_INLINE_ANNOTATION_PACKAGE,
                    scope_owners,
                ) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(reason) => shadowed = Some(reason),
                }
            }
        }
        Err(shadowed.unwrap_or(KotlinAdaptationIncomplete::AnnotationIdentity))
    }

    /// Whether a spelled name denotes exactly `expected`.
    ///
    /// The ladder is Kotlin's own. The only tier this file cannot settle is the
    /// one a wildcard import owns: a star import binds a simple name whenever
    /// its package exports it, and that beats the default import that would
    /// otherwise prove `expected`. That case is reported, not guessed.
    fn denotes(
        &self,
        spelled: &[String],
        expected: &str,
        expected_package: &str,
        scope_owners: &[String],
    ) -> Result<bool, KotlinAdaptationIncomplete> {
        let Some(head) = spelled.first() else {
            return Ok(false);
        };
        let rendered = spelled.join(".");
        let scope = KotlinNameScope {
            package_name: &self.package_name,
            imports: &self.imports,
            scope_owners: scope_owners.to_vec(),
        };
        let resolved = resolve_kotlin_type_name(&rendered, &scope, |candidate| {
            candidate == expected || self.declared_names.iter().any(|name| name == candidate)
        });
        match resolved {
            KotlinTypeName::Resolved(fqn) if fqn == expected => {
                if spelled.len() == 1 && self.wildcard_shadow_candidate(head, expected_package) {
                    return Err(KotlinAdaptationIncomplete::WildcardAnnotationShadow);
                }
                Ok(true)
            }
            KotlinTypeName::Resolved(_) | KotlinTypeName::Unresolved => Ok(false),
            KotlinTypeName::Ambiguous => Err(KotlinAdaptationIncomplete::AmbiguousDeclaration),
        }
    }

    /// Whether a wildcard import could bind `head` ahead of the default import
    /// that resolved it.
    ///
    /// An explicit import and a same-package declaration both bind the name at
    /// a tier a wildcard cannot reach, so neither leaves anything open.
    fn wildcard_shadow_candidate(&self, head: &str, expected_package: &str) -> bool {
        if self
            .imports
            .iter()
            .any(|import| !import.is_wildcard && import.local_name() == Some(head))
        {
            return false;
        }
        if self
            .declared_names
            .iter()
            .any(|name| name == &self.qualify(&[], head))
        {
            return false;
        }
        // A wildcard over the package that owns `expected` binds the name at
        // the star-import tier itself, which is the tier a competing wildcard
        // would have to win. Two star imports binding one simple name is a
        // Kotlin ambiguity error rather than a silent shadow, so nothing is
        // left open once the owning package is imported.
        if self.imports.iter().any(|import| {
            import.is_wildcard && kotlin_import_path(import).as_deref() == Some(expected_package)
        }) {
            return false;
        }
        self.imports.iter().any(|import| {
            if !import.is_wildcard {
                return false;
            }
            kotlin_import_path(import).is_some_and(|path| path != expected_package)
        })
    }

    fn scope_owners(&self, nesting: &[String]) -> Vec<String> {
        // Innermost first, matching the ladder's own precedence.
        (0..nesting.len())
            .rev()
            .map(|depth| self.qualify(&nesting[..depth], &nesting[depth]))
            .collect()
    }

    fn qualify(&self, nesting: &[String], name: &str) -> String {
        let mut qualified = String::new();
        if !self.package_name.is_empty() {
            qualified.push_str(&self.package_name);
            qualified.push('.');
        }
        for outer in nesting {
            qualified.push_str(outer);
            qualified.push('.');
        }
        qualified.push_str(name);
        qualified
    }
}

/// The `user_type` a type node names, peeling the wrappers that do not change
/// which nominal type is written.
fn nominal_user_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut frontier = vec![node];
    for _ in 0..MAX_SCOPE_DEPTH {
        let mut next = Vec::new();
        for current in frontier {
            match current.kind() {
                "user_type" => return Some(current),
                "nullable_type" | "not_nullable_type" | "parenthesized_type" | "receiver_type"
                | "type_projection" => next.extend(named_children(current)),
                _ => {}
            }
        }
        if next.is_empty() {
            return None;
        }
        frontier = next;
    }
    None
}

/// The `user_type` nodes one `annotation` node spells. A multi-annotation
/// (`@[A B]`) holds several; the ordinary form holds one, either directly or
/// inside the `constructor_invocation` an annotation with arguments uses.
fn annotation_user_types(annotation: Node<'_>) -> Vec<Node<'_>> {
    named_children(annotation)
        .into_iter()
        .flat_map(|child| match child.kind() {
            "user_type" => vec![child],
            "constructor_invocation" => named_children(child)
                .into_iter()
                .filter(|inner| inner.kind() == "user_type")
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

/// Whether `name` is a type parameter of a declaration enclosing `scope`.
///
/// Iterative and depth-capped: a type written deep inside nested local classes
/// must not turn one lookup into an unbounded walk.
fn type_parameter_in_scope(name: &str, source: &str, scope: Node<'_>) -> bool {
    let mut current = Some(scope);
    for _ in 0..MAX_SCOPE_DEPTH {
        let Some(node) = current else {
            return false;
        };
        if kotlin_declared_type_parameter_names(node, source)
            .iter()
            .any(|parameter| parameter == name)
        {
            return true;
        }
        current = node.parent();
    }
    false
}

/// The single `val` primary-constructor property a JVM inline value class
/// carries, or `None` when the declaration does not expose exactly one.
fn underlying_property<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(KotlinUnderlyingProperty, Option<Node<'tree>>)> {
    let constructor = first_named_child_of_kind(node, "primary_constructor")?;
    let parameters = named_children(constructor)
        .into_iter()
        .filter(|child| child.kind() == "class_parameter")
        .collect::<Vec<_>>();
    let [parameter] = parameters.as_slice() else {
        return None;
    };
    let binding = first_named_child_of_kind(*parameter, "binding_pattern_kind")?;
    if binding.utf8_text(source.as_bytes()).ok()?.trim() != "val" {
        return None;
    }
    let name = first_named_child_of_kind(*parameter, "simple_identifier")?;
    let name = name.utf8_text(source.as_bytes()).ok()?;
    (!name.is_empty()).then(|| {
        (
            KotlinUnderlyingProperty::new(name, parameter.start_byte()),
            kotlin_binding_type_node(*parameter),
        )
    })
}

/// How many arguments one secondary constructor accepts: every parameter is
/// allowed, and one with a default may be omitted.
fn secondary_constructor_arity(constructor: Node<'_>) -> (usize, usize) {
    let parameters = first_named_child_of_kind(constructor, "function_value_parameters")
        .map(named_children)
        .unwrap_or_default();
    let total = parameters
        .iter()
        .filter(|parameter| parameter.kind() == "parameter")
        .count();
    let defaulted = parameters
        .iter()
        .filter(|parameter| parameter.kind() == "parameter")
        .filter(|parameter| kotlin_parameter_default(**parameter).is_some())
        .count();
    (total - defaulted, total)
}

/// What else the class body offers that answers the class's own spelling.
fn constructor_alternatives(node: Node<'_>, source: &str) -> KotlinConstructorAlternatives {
    let Some(body) = first_named_child_of_kind(node, "class_body") else {
        return KotlinConstructorAlternatives::default();
    };
    let members = named_children(body);
    KotlinConstructorAlternatives {
        secondary_arities: members
            .iter()
            .filter(|member| member.kind() == "secondary_constructor")
            .map(|member| secondary_constructor_arity(*member))
            .collect(),
        companion_invoke: members
            .iter()
            .filter(|member| member.kind() == "companion_object")
            .filter_map(|companion| first_named_child_of_kind(*companion, "class_body"))
            .flat_map(named_children)
            .any(|member| {
                member.kind() == "function_declaration"
                    && kotlin_has_modifier(member, "operator")
                    && first_named_child_of_kind(member, "simple_identifier")
                        .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                        == Some("invoke")
            }),
    }
}

/// The properties a class-like declaration writes a type for: its `val`/`var`
/// primary-constructor parameters and its own property declarations.
///
/// A property whose type is inferred writes none, and is therefore absent
/// rather than guessed at.
fn declared_member_types<'tree>(node: Node<'tree>, source: &str) -> Vec<(String, Node<'tree>)> {
    let mut members = Vec::new();
    let mut owners = named_children(node)
        .into_iter()
        .filter(|child| matches!(child.kind(), "primary_constructor" | "class_body"))
        .flat_map(named_children)
        .collect::<Vec<_>>();
    owners.retain(|child| matches!(child.kind(), "class_parameter" | "property_declaration"));
    for owner in owners {
        if first_named_child_of_kind(owner, "binding_pattern_kind").is_none() {
            continue;
        }
        let binding = match owner.kind() {
            "class_parameter" => owner,
            _ => match first_named_child_of_kind(owner, "variable_declaration") {
                Some(binding) => binding,
                None => continue,
            },
        };
        let Some(name) = first_named_child_of_kind(binding, "simple_identifier")
            .and_then(|name| name.utf8_text(source.as_bytes()).ok())
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let Some(written) = kotlin_binding_type_node(binding) else {
            continue;
        };
        members.push((name.to_owned(), written));
    }
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder;
    use tree_sitter::{Parser, Tree};

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        parser.parse(source, None).expect("parse Kotlin source")
    }

    fn index<'tree>(tree: &'tree Tree, source: &str) -> KotlinValueClassIndex<'tree> {
        KotlinValueClassIndex::build(tree.root_node(), source, &mut || false)
            .expect("an uncancelled build completes")
    }

    /// The type node written for the local or parameter named `name`.
    fn written_type_of<'tree>(tree: &'tree Tree, source: &str, name: &str) -> Node<'tree> {
        let mut found = None;
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if matches!(node.kind(), "variable_declaration" | "parameter")
                && first_named_child_of_kind(node, "simple_identifier")
                    .and_then(|identifier| identifier.utf8_text(source.as_bytes()).ok())
                    == Some(name)
            {
                found = kotlin_binding_type_node(node);
            }
            WalkControl::Continue
        });
        found.unwrap_or_else(|| panic!("the fixture writes a type for {name}"))
    }

    const MONEY: &str = "package pay\n\nimport kotlin.jvm.JvmInline\n\n@JvmInline\nvalue class Money(val amount: Long)\n";

    #[test]
    fn an_explicitly_imported_annotation_proves_the_jvm_carrier() {
        let tree = parse(MONEY);
        let index = index(&tree, MONEY);
        let KotlinCarrier::Unboxed(id) = index.declared_value_class("Money") else {
            panic!("Money constructs its unboxed carrier: {:#?}", index);
        };
        let class = index.value_class(id);
        assert_eq!(class.identity().package_name(), "pay");
        assert_eq!(class.identity().name(), "Money");
        assert!(class.identity().nesting().is_empty());
        assert_eq!(class.underlying().name(), "amount");
        assert!(index.projects_underlying(id, "amount"));
        assert!(!index.projects_underlying(id, "other"));
    }

    #[test]
    fn the_default_import_and_the_qualified_spelling_both_prove_the_annotation() {
        for source in [
            "package pay\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
            "package pay\n\n@kotlin.jvm.JvmInline\nvalue class Money(val amount: Long)\n",
            "package pay\n\nimport kotlin.jvm.*\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
        ] {
            let tree = parse(source);
            let index = index(&tree, source);
            assert!(
                matches!(
                    index.declared_value_class("Money"),
                    KotlinCarrier::Unboxed(_)
                ),
                "{source} must prove the JVM inline annotation"
            );
        }
    }

    #[test]
    fn a_same_named_annotation_declaration_or_import_is_not_the_jvm_one() {
        for source in [
            "package pay\n\nannotation class JvmInline\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
            "package pay\n\nimport pay.other.JvmInline\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
            "package pay\n\nvalue class Money(val amount: Long)\n",
        ] {
            let tree = parse(source);
            let index = index(&tree, source);
            assert_eq!(
                index.declared_value_class("Money"),
                KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::AnnotationIdentity),
                "{source} must not claim the JVM inline annotation"
            );
        }
    }

    #[test]
    fn an_unrelated_wildcard_import_leaves_the_annotation_identity_open() {
        let source = "package pay\n\nimport pay.other.*\n\n@JvmInline\nvalue class Money(val amount: Long)\n";
        let tree = parse(source);
        let index = index(&tree, source);
        assert_eq!(
            index.declared_value_class("Money"),
            KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::WildcardAnnotationShadow)
        );
    }

    #[test]
    fn an_explicit_import_or_the_owning_wildcard_survives_a_competing_wildcard() {
        for source in [
            "package pay\n\nimport pay.other.*\nimport kotlin.jvm.JvmInline\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
            // A second wildcard binding `JvmInline` would be a Kotlin
            // ambiguity error, not a silent shadow of the owning package.
            "package pay\n\nimport pay.other.*\nimport kotlin.jvm.*\n\n@JvmInline\nvalue class Money(val amount: Long)\n",
        ] {
            let tree = parse(source);
            let index = index(&tree, source);
            assert!(
                matches!(
                    index.declared_value_class("Money"),
                    KotlinCarrier::Unboxed(_)
                ),
                "{source} binds the annotation at a tier no wildcard can shadow"
            );
        }
    }

    #[test]
    fn a_value_class_without_exactly_one_val_property_has_no_proven_carrier() {
        for source in [
            "package pay\n\n@JvmInline\nvalue class Money(val amount: Long, val currency: String)\n",
            "package pay\n\n@JvmInline\nvalue class Money(var amount: Long)\n",
            "package pay\n\n@JvmInline\nvalue class Money(amount: Long)\n",
        ] {
            let tree = parse(source);
            let index = index(&tree, source);
            assert_eq!(
                index.declared_value_class("Money"),
                KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::UnderlyingProperty),
                "{source} declares no single underlying property"
            );
        }
    }

    #[test]
    fn ordinary_and_data_classes_carry_no_value_class_facts() {
        let source = "package pay\n\nclass Account(val id: Long)\n\ndata class Point(val x: Int, val y: Int)\n";
        let tree = parse(source);
        let index = index(&tree, source);
        assert_eq!(
            index.declared_value_class("Account"),
            KotlinCarrier::Unrelated
        );
        assert_eq!(
            index.declared_value_class("Point"),
            KotlinCarrier::Unrelated
        );
        assert_eq!(
            index.declared_value_class("Missing"),
            KotlinCarrier::Unrelated
        );
    }

    #[test]
    fn two_declarations_of_one_name_stay_ambiguous() {
        let source =
            "package pay\n\n@JvmInline\nvalue class Money(val amount: Long)\n\nclass Money\n";
        let tree = parse(source);
        let index = index(&tree, source);
        assert_eq!(
            index.declared_value_class("Money"),
            KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::AmbiguousDeclaration)
        );
    }

    #[test]
    fn written_types_select_the_carrier_their_boundary_requires() {
        let source = concat!(
            "package pay\n\n",
            "interface Printable\n\n",
            "class Ledger\n\n",
            "@JvmInline\n",
            "value class Money(val amount: Long) : Printable\n\n",
            "class Holder<T> {\n",
            "    fun keep(money: Money) {\n",
            "        val direct: Money = money\n",
            "        val nullable: Money? = money\n",
            "        val generic: T = money as T\n",
            "        val widened: Any = money\n",
            "        val printable: Printable = money\n",
            "        val ledger: Ledger = Ledger()\n",
            "        val foreign: String = \"\"\n",
            "        val applied: List<Money> = listOf(money)\n",
            "    }\n",
            "}\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let KotlinCarrier::Unboxed(money) = index.declared_value_class("Money") else {
            panic!("Money must be a proven value class");
        };
        let classify = |name: &str| {
            let node = written_type_of(&tree, source, name);
            index.written_type(node, source, node)
        };
        assert_eq!(
            classify("direct"),
            KotlinWrittenType::ValueClass {
                id: money,
                nullable: false
            }
        );
        assert_eq!(
            classify("nullable"),
            KotlinWrittenType::ValueClass {
                id: money,
                nullable: true
            }
        );
        assert_eq!(classify("generic"), KotlinWrittenType::TypeParameter);
        assert_eq!(classify("widened"), KotlinWrittenType::Any);
        assert!(matches!(
            classify("printable"),
            KotlinWrittenType::Declared { .. }
        ));
        assert!(matches!(
            classify("ledger"),
            KotlinWrittenType::Declared { .. }
        ));
        assert_eq!(
            classify("foreign"),
            KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
        );
        assert_eq!(
            classify("applied"),
            KotlinWrittenType::Incomplete(KotlinAdaptationIncomplete::GenericSpecialization)
        );

        let carried = Some(money);
        assert_eq!(
            index.carrier_of(classify("nullable"), carried),
            KotlinCarrier::Boxed(money, KotlinAdaptationBoundary::Nullable)
        );
        assert_eq!(
            index.carrier_of(classify("generic"), carried),
            KotlinCarrier::Boxed(money, KotlinAdaptationBoundary::TypeParameter)
        );
        assert_eq!(
            index.carrier_of(classify("widened"), carried),
            KotlinCarrier::Boxed(money, KotlinAdaptationBoundary::Supertype)
        );
        assert_eq!(
            index.carrier_of(classify("printable"), carried),
            KotlinCarrier::Boxed(money, KotlinAdaptationBoundary::Supertype)
        );
        // `Ledger` is declared here, but `Money` does not widen to it.
        assert_eq!(
            index.carrier_of(classify("ledger"), carried),
            KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::UnrelatedDestination)
        );
        // A value that is not a value class adapts nowhere.
        assert_eq!(
            index.carrier_of(classify("ledger"), None),
            KotlinCarrier::Unrelated
        );
    }

    #[test]
    fn adaptations_name_their_exact_class_and_boundary() {
        let source = concat!(
            "package pay\n\n",
            "@JvmInline\n",
            "value class Money(val amount: Long)\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let KotlinCarrier::Unboxed(money) = index.declared_value_class("Money") else {
            panic!("Money must be a proven value class");
        };
        let expected = KotlinValueClass {
            identity: KotlinDeclarationIdentity::new("pay", Vec::new(), "Money", 13),
            underlying: KotlinUnderlyingProperty::new("amount", 42),
        };
        assert_eq!(index.value_class(money), &expected);

        let boxed = KotlinCarrier::Boxed(money, KotlinAdaptationBoundary::Nullable);
        let unboxed = KotlinCarrier::Unboxed(money);
        assert_eq!(
            index.adaptation(unboxed, boxed),
            KotlinAdaptationOutcome::Adapted(KotlinValueAdaptationFact::new(
                expected.clone(),
                KotlinValueAdaptation::Boxing(KotlinAdaptationBoundary::Nullable)
            ))
        );
        assert_eq!(
            index.adaptation(boxed, unboxed),
            KotlinAdaptationOutcome::Adapted(KotlinValueAdaptationFact::new(
                expected.clone(),
                KotlinValueAdaptation::Unboxing(KotlinAdaptationBoundary::Nullable)
            ))
        );
        assert_eq!(
            index.adaptation(unboxed, unboxed),
            KotlinAdaptationOutcome::Unchanged
        );
        assert_eq!(
            index.adaptation(KotlinCarrier::Unrelated, unboxed),
            KotlinAdaptationOutcome::Unrelated
        );
        assert_eq!(
            index.adaptation(
                unboxed,
                KotlinCarrier::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
            ),
            KotlinAdaptationOutcome::Incomplete(KotlinAdaptationIncomplete::ForeignDestination)
        );
        assert_eq!(
            index.construction(money),
            KotlinAdaptationOutcome::Adapted(KotlinValueAdaptationFact::new(
                expected.clone(),
                KotlinValueAdaptation::Construction
            ))
        );
        assert_eq!(
            index.projection(money),
            KotlinAdaptationOutcome::Adapted(KotlinValueAdaptationFact::new(
                expected,
                KotlinValueAdaptation::UnderlyingProjection
            ))
        );
    }

    #[test]
    fn a_nested_value_class_records_its_enclosing_declarations() {
        let source = concat!(
            "package pay\n\n",
            "class Wallet {\n",
            "    @JvmInline\n",
            "    value class Money(val amount: Long)\n",
            "}\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let KotlinCarrier::Unboxed(id) = index.declared_value_class("Money") else {
            panic!("a nested value class is still a value class: {index:#?}");
        };
        assert_eq!(index.value_class(id).identity().nesting(), ["Wallet"]);
    }

    /// The first node of `kind` in the fixture.
    fn first_node_of_kind<'tree>(tree: &'tree Tree, kind: &str) -> Node<'tree> {
        let mut found = None;
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if found.is_none() && node.kind() == kind {
                found = Some(node);
            }
            WalkControl::Continue
        });
        found.unwrap_or_else(|| panic!("the fixture spells a {kind}"))
    }

    /// #2851: a `Name(...)` spelling runs `Name`'s constructor only when
    /// nothing else in the program can answer it. A same-named declaration, an
    /// import of the name, and a companion `invoke` each select something the
    /// class's carrier facts do not describe.
    #[test]
    fn a_constructor_is_selected_only_when_nothing_else_answers_the_spelling() {
        let source = concat!(
            "package pay\n\n",
            "import kotlin.jvm.JvmInline\n",
            "import pay.other.Imported\n\n",
            "@JvmInline\nvalue class Money(val amount: Long)\n\n",
            "@JvmInline\nvalue class Coin(val units: Long)\n\n",
            "@JvmInline\nvalue class Imported(val units: Long)\n\n",
            "@JvmInline\nvalue class Invokable(val units: Long) {\n",
            "    companion object {\n",
            "        operator fun invoke(x: Int): Invokable = Invokable(x.toLong())\n",
            "    }\n",
            "}\n\n",
            "fun Coin(text: String): Coin = Coin(text.toLong())\n\n",
            "fun local() {\n",
            "    fun Money(v: Long): String = \"x\"\n",
            "}\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let KotlinCarrier::Unboxed(money) = index.declared_value_class("Money") else {
            panic!("Money is a proven value class: {index:#?}");
        };
        // A local `fun` of the same name is in scope only inside its own body,
        // which the call site's own scope reports; it must not make every
        // other call in the file ambiguous.
        assert_eq!(
            index.constructor_selection("Money", KotlinCalleeBinding::Free),
            KotlinConstructorSelection::Primary(money)
        );
        for name in ["Coin", "Imported", "Invokable"] {
            assert_eq!(
                index.constructor_selection(name, KotlinCalleeBinding::Free),
                KotlinConstructorSelection::Incomplete(KotlinAdaptationIncomplete::AmbiguousCallee),
                "{name} has a competing callable, import, or companion invoke"
            );
        }
        assert_eq!(
            index.constructor_selection("Missing", KotlinCalleeBinding::Free),
            KotlinConstructorSelection::Unrelated
        );
    }

    /// #2851: a binding in scope that is written with a function type is what
    /// `Money(raw)` invokes, so the call constructs nothing at all; a binding
    /// whose invokability this file cannot read leaves the selection open.
    #[test]
    fn a_binding_in_scope_answers_the_call_before_the_constructor_does() {
        let tree = parse(MONEY);
        let index = index(&tree, MONEY);
        assert_eq!(
            index.constructor_selection("Money", KotlinCalleeBinding::Invokable),
            KotlinConstructorSelection::Unrelated
        );
        assert_eq!(
            index.constructor_selection("Money", KotlinCalleeBinding::Opaque),
            KotlinConstructorSelection::Incomplete(KotlinAdaptationIncomplete::AmbiguousCallee)
        );
    }

    #[test]
    fn a_written_function_type_is_what_makes_a_binding_invokable() {
        let source = concat!(
            "package pay\n\n",
            "fun f(call: (Long) -> String, nullableCall: ((Long) -> String)?, plain: Long) {}\n",
        );
        let tree = parse(source);
        let mut parameters = Vec::new();
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if node.kind() == "parameter" {
                parameters.push(node);
            }
            WalkControl::Continue
        });
        let [call, nullable_call, plain] = parameters.as_slice() else {
            panic!("the fixture writes three parameters");
        };
        for parameter in [call, nullable_call] {
            let written = kotlin_binding_type_node(*parameter).expect("a written type");
            assert!(kotlin_written_type_is_function(written));
        }
        let written = kotlin_binding_type_node(*plain).expect("a written type");
        assert!(!kotlin_written_type_is_function(written));
    }

    /// #2851: an actual argument is matched against the carrier it has to fit,
    /// so a value class is not constructed from a value whose type this file
    /// proves the carrier does not accept.
    #[test]
    fn an_actual_is_matched_against_the_carrier_it_has_to_fit() {
        let source = concat!(
            "package pay\n\n",
            "import kotlin.jvm.JvmInline\n\n",
            "@JvmInline\nvalue class Money(val amount: Long)\n\n",
            "@JvmInline\nvalue class Nick(val text: String)\n\n",
            "@JvmInline\nvalue class Opt(val text: String?)\n\n",
            "@JvmInline\nvalue class Holder<T>(val item: T)\n\n",
            "@JvmInline\nvalue class Anything(val item: Any)\n\n",
            "class Generic<T> {\n",
            "    fun f(generic: T) {\n",
            "        val exact: Long = 0\n",
            "        val other: String = \"\"\n",
            "        val maybe: String? = null\n",
            "    }\n",
            "}\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let class = |name: &str| match index.declared_value_class(name) {
            KotlinCarrier::Unboxed(id) => id,
            other => panic!("{name} is a proven value class, not {other:?}"),
        };
        let (money, nick, opt) = (class("Money"), class("Nick"), class("Opt"));
        let written =
            |name: &str| KotlinActualEvidence::Written(written_type_of(&tree, source, name));
        let integer = KotlinActualEvidence::Literal(first_node_of_kind(&tree, "integer_literal"));
        let text = KotlinActualEvidence::Literal(first_node_of_kind(&tree, "string_literal"));
        let empty = KotlinActualEvidence::Literal(first_node_of_kind(&tree, "null_literal"));

        // The carrier's own type, and an integer literal that takes it.
        assert_eq!(
            index.underlying_match(money, written("exact"), source),
            KotlinUnderlyingMatch::Proven
        );
        assert_eq!(
            index.underlying_match(money, integer, source),
            KotlinUnderlyingMatch::Proven
        );
        // A different type, proved different.
        assert_eq!(
            index.underlying_match(money, written("other"), source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(money, text, source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(money, KotlinActualEvidence::ValueClass(nick), source),
            KotlinUnderlyingMatch::Mismatched
        );
        // Nullability is part of fitting: a nullable value does not fit a
        // non-null carrier, and a non-null value fits a nullable one.
        assert_eq!(
            index.underlying_match(nick, written("maybe"), source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(opt, written("maybe"), source),
            KotlinUnderlyingMatch::Proven
        );
        assert_eq!(
            index.underlying_match(opt, written("other"), source),
            KotlinUnderlyingMatch::Proven
        );
        assert_eq!(
            index.underlying_match(nick, empty, source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(opt, empty, source),
            KotlinUnderlyingMatch::Proven
        );
        // An unresolved generic carrier must not erase the constructor's
        // call-site specialization and accept every actual type.
        assert_eq!(
            index.underlying_match(class("Holder"), written("other"), source),
            KotlinUnderlyingMatch::Unknown
        );
        assert_eq!(
            index.underlying_match(class("Anything"), written("other"), source),
            KotlinUnderlyingMatch::Proven
        );
        assert_eq!(
            index.underlying_match(class("Anything"), empty, source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(class("Anything"), written("maybe"), source),
            KotlinUnderlyingMatch::Mismatched
        );
        assert_eq!(
            index.underlying_match(money, KotlinActualEvidence::Unknown, source),
            KotlinUnderlyingMatch::Unknown
        );
        // A type-parameter actual is instantiated at the call, so its spelling
        // cannot disprove the carrier either.
        assert_eq!(
            index.underlying_match(money, written("generic"), source),
            KotlinUnderlyingMatch::Unknown
        );
    }

    #[test]
    fn a_second_constructor_is_what_makes_an_untyped_actual_ambiguous() {
        let source = concat!(
            "package pay\n\n",
            "import kotlin.jvm.JvmInline\n\n",
            "@JvmInline\nvalue class Money(val amount: Long)\n\n",
            "@JvmInline\nvalue class Token(val text: String) {\n",
            "    constructor(n: Long) : this(n.toString())\n",
            "}\n",
        );
        let tree = parse(source);
        let index = index(&tree, source);
        let KotlinCarrier::Unboxed(money) = index.declared_value_class("Money") else {
            panic!("Money is a proven value class");
        };
        let KotlinCarrier::Unboxed(token) = index.declared_value_class("Token") else {
            panic!("Token is a proven value class");
        };
        assert!(!index.competing_constructor(money, 1));
        // The secondary constructor takes exactly one argument, so it competes
        // for a one-argument call and for nothing else.
        assert!(index.competing_constructor(token, 1));
        assert!(!index.competing_constructor(token, 2));
    }

    #[test]
    fn a_cancelled_walk_reports_cancellation() {
        let tree = parse(MONEY);
        assert!(
            KotlinValueClassIndex::build(tree.root_node(), MONEY, &mut || true)
                .is_err_and(|cancelled| cancelled == KotlinValueClassWalkCancelled)
        );
    }
}
