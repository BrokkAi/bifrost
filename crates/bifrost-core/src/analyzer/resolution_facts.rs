//! Immutable, file-local inputs to compositional name and type resolution.
//!
//! A language walk produces these rows from the syntax tree it is already
//! traversing and carries them in [`ParsedFile`](super::parsed_file::ParsedFile).
//! They deliberately stop before binding a reference to a declaration: that
//! answer depends on the selected workspace revision, while every row here is
//! a function of this file's bytes alone. The analyzer store can therefore
//! persist the rows by blob identity and compose them for any worktree later.
//!
//! IDs are dense only within one file. They make the relations compact and
//! avoid repeating source spans or spellings without creating a Rust-side
//! arena whose lifetime escapes the parse operation.

use super::model::CodeUnit;
use super::structural::occurrences::labelled_enum;
use super::structural::resolution::{DeclaredVisibility, HoistingClass};
use crate::analyzer::dense_id::define_dense_id;
use crate::hash::HashSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;

pub fn dense_ordinal(index: usize, relation: &str) -> u32 {
    u32::try_from(index).unwrap_or_else(|_| panic!("{relation} count exceeds u32"))
}

/// Return the active scope from a producer's nonempty scope stack.
#[inline]
pub fn current_scope_id(scopes: &[ResolutionScopeId], empty_message: &str) -> ResolutionScopeId {
    *scopes.last().expect(empty_message)
}

macro_rules! resolution_id {
    ($name:ident) => {
        define_dense_id! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name {
                new: pub,
                get: pub,
                index: pub,
                try_from_index: pub,
            }
        }
    };
}

resolution_id!(ResolutionNameId);
resolution_id!(ResolutionScopeId);
resolution_id!(ResolutionSiteId);
resolution_id!(ResolutionTypeSlotId);
resolution_id!(ResolutionTypeRelationId);
resolution_id!(ResolutionJvmAliasId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionNameFact {
    pub id: ResolutionNameId,
    pub spelling: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionScopeKind {
    CompilationUnit,
    Package,
    TypeBody,
    Executable,
    Initializer,
    Block,
    /// A file-local import block nested within a language package.
    File,
}

/// Whether a scope continues the lexical chain its parent offers.
///
/// Most scopes do: a block sees the names its enclosing block declared, a
/// method body sees its type's members. Some languages have a scope that is a
/// new root for name lookup even though it is written inside another scope.
/// Rust's module is one: a path's first segment is looked up in the current
/// module's own items and then the preludes, never in an ancestor module, so
/// `mod inner { fn f(_: OuterType) {} }` does not compile without a `use`.
///
/// The property belongs to the scope because only the language that emitted it
/// knows it. The lowering reads the flag and nothing else; it never asks which
/// language produced the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionScopeInheritance {
    /// Names visible in the parent scope are visible here.
    Lexical,
    /// Name lookup stops at this scope. Its own declarations and imports are
    /// visible; the parent's are not.
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionScopeFact {
    pub id: ResolutionScopeId,
    pub parent: Option<ResolutionScopeId>,
    pub owner: Option<ResolutionSiteId>,
    pub kind: ResolutionScopeKind,
    pub inheritance: ResolutionScopeInheritance,
    pub start_byte: usize,
    pub end_byte: usize,
}

labelled_enum! {
    ResolutionSiteKind, ALL_RESOLUTION_SITE_KINDS {
        PackageDeclaration => "package_declaration",
        ImportDeclaration => "import_declaration",
        ModuleDeclaration => "module_declaration",
        MacroDeclaration => "macro_declaration",
        TypeAliasDeclaration => "type_alias_declaration",
        TypeDeclaration => "type_declaration",
        CallableDeclaration => "callable_declaration",
        ConstructorDeclaration => "constructor_declaration",
        ValueDeclaration => "value_declaration",
        Initializer => "initializer",
        TypeReference => "type_reference",
        ValueReference => "value_reference",
        CallableReference => "callable_reference",
        ConstructorReference => "constructor_reference",
        MemberReference => "member_reference",
        ModuleReference => "module_reference",
        MacroReference => "macro_reference",
        Call => "call",
        /// A source pattern that may request an extractor invocation.
        Pattern => "pattern",
        Literal => "literal",
        UnsupportedRoute => "unsupported_route",
        UnsupportedDeclaration => "unsupported_declaration",
        UnsupportedExpression => "unsupported_expression",
        /// A reference the producer writes for its own lowering, not one a
        /// user wrote (a trait's `Self` lower bound names the trait). It is
        /// resolved like any reference but publishes no range, so no point
        /// or usage row stands for it.
        SyntheticReference => "synthetic_reference",
        UnaryExpression => "unary_expression",
        /// An identifier key in an elided Go composite literal. The shared
        /// engine chooses lexical expression lookup for map/sequence owners
        /// and qualified field lookup for a struct owner.
        CompositeLiteralKeyReference => "composite_literal_key_reference",
        BinaryExpression => "binary_expression",
        ConditionalExpression => "conditional_expression",
    }
}

/// One positioned semantic site. Identifier rows point at the site rather
/// than duplicating its range; expression-only sites have no identifier row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionSiteFact {
    pub id: ResolutionSiteId,
    pub scope: ResolutionScopeId,
    pub kind: ResolutionSiteKind,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionIdentifierRole {
    Declaration,
    Reference,
}

labelled_enum! {
    ResolutionNamespace, ALL_RESOLUTION_NAMESPACES {
        Type => "type",
        Value => "value",
        Callable => "callable",
        // Constructor declarations and constructor-call sites. Constructors use
        // the source type name, but they do not participate in ordinary type or
        // method lookup.
        Constructor => "constructor",
        // Macro lookup is independent of Rust's type and value domains.
        Macro => "macro",
        // A declaration that participates only in compile-time constant lookup.
        Constant => "constant",
        // A grammar-level ambiguous name whose classification depends on the
        // selected bindings (for example a Java receiver can be a value or a
        // static type qualifier).
        TypeOrValue => "type_or_value",
        // A file-scoped imported package binding, never a nominal type or value.
        Package => "package",
    }
}

impl ResolutionNamespace {
    /// Stable canonical-hash spelling. This predates the persisted SQL label
    /// for the grammar-ambiguous namespace and therefore remains distinct.
    pub const fn identity_label(self) -> &'static str {
        match self {
            Self::TypeOrValue => "type-or-value",
            _ => self.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PositionedIdentifierFact {
    pub site: ResolutionSiteId,
    pub name: ResolutionNameId,
    pub role: ResolutionIdentifierRole,
    pub namespace: ResolutionNamespace,
    /// Type/value context for a qualified member lookup. `None` means lexical,
    /// package/module, or otherwise unqualified lookup.
    pub qualifier: Option<ResolutionTypeSlotId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionBinderKind {
    Type,
    Callable,
    Constructor,
    Field,
    Local,
    Parameter,
    Pattern,
    Import,
    Macro,
}

/// The lexical interval in which one declaration participates in lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionBinderFact {
    pub declaration: ResolutionSiteId,
    pub scope: ResolutionScopeId,
    pub kind: ResolutionBinderKind,
    pub hoisting: HoistingClass,
    pub activation_start: usize,
    pub activation_end: usize,
}

impl ResolutionBinderFact {
    pub fn scope_wide(
        declaration: ResolutionSiteId,
        kind: ResolutionBinderKind,
        scope: ResolutionScopeFact,
    ) -> Self {
        Self {
            declaration,
            scope: scope.id,
            kind,
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope.start_byte,
            activation_end: scope.end_byte,
        }
    }
}

/// One pattern token that names a declaration before it declares one.
///
/// Rust decides this at name resolution: a bare identifier in a refutable
/// pattern is a path to a unit variant or a constant when one is visible, and
/// a fresh binding otherwise. The producer cannot know which, so it publishes
/// both halves at the same source range: an ordinary Value-namespace
/// reference at `reference`, and an ordinary binder whose declaration is
/// `declaration`.
///
/// This row is the producer's statement that the binder is the weaker of the
/// two. The lowering publishes the binder at a precedence that every enclosing
/// lexical route already beats, so a visible unit variant or constant wins and
/// the binder answers only when the outward lookup proves empty. An outward
/// lookup that proves nothing leaves the answer incomplete, which is the
/// honest report: neither half was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionConditionalBinderFact {
    pub reference: ResolutionSiteId,
    pub declaration: ResolutionSiteId,
}

labelled_enum! {
    ResolutionTypeSlotRole, ALL_RESOLUTION_TYPE_SLOT_ROLES {
        TargetTypeIdentity => "target_type_identity",
        DeclaredValue => "declared_value",
    /// One value observed at a declaration's assignment boundary. This stays
    /// separate from `DeclaredValue`: Java assignments do not change the
    /// declaration's static type.
        AssignmentValue => "assignment_value",
    /// One value observed at a callable's return boundary. This stays
    /// separate from the callable's declared result type.
        ReturnValue => "return_value",
        Receiver => "receiver",
        Argument => "argument",
        CallResult => "call_result",
        ExpressionValue => "expression_value",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionTypeSlotFact {
    pub id: ResolutionTypeSlotId,
    pub site: ResolutionSiteId,
    pub role: ResolutionTypeSlotRole,
}

labelled_enum! {
    DeclarationTypeRole, ALL_DECLARATION_TYPE_ROLES {
        Value => "value",
        Parameter => "parameter",
        Return => "return",
        Identity => "identity",
        // Exact alias owner, before receiver payload projection or dereference.
        NominalIdentity => "nominal_identity",
        // The declared type of a callable's first result. A multi-value callable
        // has no single Return row, so a binder of its first result reads this.
        // Appended last: the persisted role code is this enum's index.
        CallableFirstResult => "callable_first_result",
    }
}

/// The type-bearing slot attached to a declaration. The slot's value is
/// supplied by a projection or transfer row; this relation stores no target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeclarationTypeSlotFact {
    pub declaration: ResolutionSiteId,
    pub slot: ResolutionTypeSlotId,
    pub role: DeclarationTypeRole,
}

labelled_enum! {
    BindingProjectionKind, ALL_BINDING_PROJECTION_KINDS {
        TargetTypeIdentity => "target_type_identity",
        TargetDeclaredValueType => "target_declared_value_type",
        TargetCallableResultType => "target_callable_result_type",
        // Project the owning type of the constructor declaration selected for an
        // object-creation call. This makes construction depend on constructor
        // binding while retaining a separate type reference for navigation.
        TargetConstructorOwnerType => "target_constructor_owner_type",
        // Preserve both structured interpretations of an ambiguous qualifier;
        // the evaluator selects the one whose binding and use context agree.
        TargetTypeOrDeclaredValueType => "target_type_or_declared_value_type",
        // Project the declaration that owns the members a literal names, which
        // is the target itself whenever the target owns a member scope. An enum
        // struct variant is a constructor that owns its own fields, so the
        // constructor rule `TargetTypeIdentity` applies -- answer the enum for
        // `Enum::Variant` -- is exactly wrong for a struct literal's owner.
        TargetMemberOwnerType => "target_member_owner_type",
        // Follow alias owners without substituting a receiver-reachable payload.
        TargetNominalTypeIdentity => "target_nominal_type_identity",
        // A later result of a multi-value callable. It names the callee like the
        // first result does, but no declared type is published for it yet, so it
        // never takes the first result's type. Appended last: the persisted kind
        // code is this enum's index.
        TargetCallableLaterResultType => "target_callable_later_result_type",
    }
}

impl BindingProjectionKind {
    /// A projection from a callable reference to one of its call results. The
    /// first and the later results share this shape; only the first result's
    /// declared type is published as a first-result declaration.
    pub const fn is_callable_result(self) -> bool {
        matches!(
            self,
            Self::TargetCallableResultType | Self::TargetCallableLaterResultType
        )
    }
}

/// Copy a property of whichever declaration the reference eventually binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindingProjectionFact {
    pub reference: ResolutionSiteId,
    pub output: ResolutionTypeSlotId,
    pub kind: BindingProjectionKind,
}

impl BindingProjectionFact {
    pub const fn target_type_identity(
        reference: ResolutionSiteId,
        output: ResolutionTypeSlotId,
    ) -> Self {
        Self {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeIdentity,
        }
    }

    pub const fn target_declared_value_type(
        reference: ResolutionSiteId,
        output: ResolutionTypeSlotId,
    ) -> Self {
        Self {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        }
    }
}

labelled_enum! {
    ResolutionTypeTransferKind, ALL_RESOLUTION_TYPE_TRANSFER_KINDS {
        TypeIdentity => "type_identity",
        /// Independently declared type surfaces form one producer with several
        /// inputs. Its values are their union and completion includes every
        /// input. This does not represent ambiguous lexical alternatives.
        TypeUnion => "type_union",
        /// An alias can retain reference or pointer qualifiers around its
        /// target without turning that type object into a runtime value.
        TypeAlias => "type_alias",
        DeclaredType => "declared_type",
        Initialization => "initialization",
        /// Select one component type from a resolved structural container.
        ComponentElement => "component_element",
        ComponentKey => "component_key",
        ComponentValue => "component_value",
        /// Discharge the one unproven indirection layer that the `Option` and
        /// `Result` payload encoding adds, at a `?`, `.unwrap()` or
        /// `.expect(..)` site. The output is a call result, so the zero-delta
        /// `Initialization` transfer carries it into a binding unchanged.
        Unwrap => "unwrap",
        Assignment => "assignment",
        /// Construct a runtime value from its type. Calls publish CallResult;
        /// literal expressions publish ExpressionValue without inventing a call.
        Construction => "construction",
        Receiver => "receiver",
        Argument => "argument",
        Return => "return",
        UnaryIndirection => "unary_indirection",
        AddressOf => "address_of",
        /// Apply a proven surrounding type to an expression whose language
        /// syntax takes its type from context, such as Go's untyped nil.
        Contextual => "contextual",
        /// Carry an operand's proven type into a unary or binary expression
        /// whose result type is determined by that operand.
        ExpressionResult => "expression_result",
    }
}

impl ResolutionTypeTransferKind {
    pub const fn component_kind(self) -> Option<ResolutionTypeComponentKind> {
        match self {
            Self::ComponentElement => Some(ResolutionTypeComponentKind::Element),
            Self::ComponentKey => Some(ResolutionTypeComponentKind::Key),
            Self::ComponentValue => Some(ResolutionTypeComponentKind::Value),
            _ => None,
        }
    }
}

/// Explicit category/addressability transform for one typed-slot transfer.
///
/// This is producer-owned semantic data. Consumers must not reconstruct it
/// from `ResolutionTypeTransferKind`: language frontends know whether syntax
/// denotes a type object or a runtime value and whether that value is
/// addressable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionTypeTransferValueTransform {
    Preserve,
    ToRuntime {
        addressable: bool,
    },
    /// Produce a complete empty value set. Java `void` return declarations are
    /// the first producer: the type syntax is valid, but no runtime value may
    /// flow from a call.
    ToNoValue,
    /// Retain only type objects, preserving their category.
    TypeObjectOnly,
    /// Retain only runtime values and publish an addressable result.
    AddressableRuntimeOnly,
    /// Admit an addressable runtime operand and produce a non-addressable value.
    AddressableOperandOnly,
    /// Admit any runtime operand and produce a non-addressable value.
    RuntimeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionTypeTransferFact {
    pub input: ResolutionTypeSlotId,
    pub output: ResolutionTypeSlotId,
    pub kind: ResolutionTypeTransferKind,
    /// Signed indirection keeps language-specific pointer/reference syntax out
    /// of the common transfer-kind vocabulary.
    pub indirection_delta: i8,
    /// Signed change to the indirection proven to come from references.
    pub reference_indirection_delta: i8,
    pub value_transform: ResolutionTypeTransferValueTransform,
}

impl ResolutionTypeTransferFact {
    pub const fn new(
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
        indirection_delta: i8,
        reference_indirection_delta: i8,
        value_transform: ResolutionTypeTransferValueTransform,
    ) -> Self {
        Self {
            input,
            output,
            kind,
            indirection_delta,
            reference_indirection_delta,
            value_transform,
        }
    }
}

labelled_enum! {
    ResolutionTypeComponentKind, ALL_RESOLUTION_TYPE_COMPONENT_KINDS {
        Element => "element",
        Key => "key",
        Value => "value",
    }
}

labelled_enum! {
    ResolutionTypeConstructorKind, ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS {
        Sequence => "sequence",
        Map => "map",
        Channel => "channel",
        Slice => "slice",
        Array => "array",
    }
}

/// One edge from a structural type syntax slot to a component type syntax
/// slot. A map has separate key and value rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionTypeComponentFact {
    pub container: ResolutionTypeSlotId,
    pub constructor: ResolutionTypeConstructorKind,
    pub kind: ResolutionTypeComponentKind,
    pub component: ResolutionTypeSlotId,
}

/// One positional type argument written on a declared type syntax node.
///
/// Unlike structural container components, generic arguments are ordered and
/// can have any arity. `owner` is the nominal identity slot for `Box` in
/// `Box<Foo>`; `argument` is the declared identity slot for `Foo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionDeclaredTypeArgumentFact {
    pub owner: ResolutionTypeSlotId,
    pub ordinal: u32,
    pub argument: ResolutionTypeSlotId,
}

/// One ordered type argument in a generic type application. The application
/// slot is the resolved identity of the generic head; the argument slot and
/// written indirection remain structured type-expression facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionTypeArgumentFact {
    pub application: ResolutionTypeSlotId,
    pub ordinal: u32,
    pub argument: ResolutionTypeSlotId,
    pub indirection_delta: i8,
    pub reference_indirection_delta: i8,
}

/// One generic type alias formal and its target type expression. The target
/// slot is repeated per formal, making the alias -> formal -> target relation
/// directly queryable without an opaque payload. Ordered nested target
/// arguments are represented by `ResolutionTypeArgumentFact` rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionGenericTypeAliasParameterFact {
    pub alias: ResolutionSiteId,
    pub ordinal: u32,
    pub parameter: ResolutionSiteId,
    pub target: ResolutionTypeSlotId,
    pub indirection_delta: i8,
    pub reference_indirection_delta: i8,
}

/// One positional formal parameter of a generic type, alias, or callable
/// declaration. Receiver formals are owned by their method and map by
/// position to the generic receiver base's formals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionGenericFormalFact {
    pub owner: ResolutionSiteId,
    pub ordinal: u32,
    pub parameter: ResolutionSiteId,
}

labelled_enum! {
    IntrinsicTypeKind, ALL_INTRINSIC_TYPE_KINDS {
        Primitive => "primitive",
        LanguageBuiltin => "language_builtin",
        /// A slice of a primitive element, such as Rust `[u8]`.
        Slice => "slice",
        /// An array of a primitive element with a literal length, such as
        /// Rust `[u8; 4]`.
        Array => "array",
        /// A structural container whose identity is its type syntax slot.
        Structural => "structural",
    }
}

/// A type known from syntax alone, such as Java `int` or a string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntrinsicTypeSeedFact {
    pub output: ResolutionTypeSlotId,
    pub name: ResolutionNameId,
    pub kind: IntrinsicTypeKind,
    pub indirection: u8,
}

impl IntrinsicTypeSeedFact {
    pub const fn direct(
        output: ResolutionTypeSlotId,
        name: ResolutionNameId,
        kind: IntrinsicTypeKind,
    ) -> Self {
        Self {
            output,
            name,
            kind,
            indirection: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolutionCallFact {
    pub call: ResolutionSiteId,
    pub callee: ResolutionSiteId,
    /// The dispatch receiver for an ordinary member call, or the explicit
    /// enclosing-instance expression for a qualified inner-class construction.
    pub receiver: Option<ResolutionTypeSlotId>,
    pub result: ResolutionTypeSlotId,
    /// Additional result slots for a multi-result call, in result order after
    /// `result` (which is ordinal zero). A producer emits these only when the
    /// syntax consumes more than the first result, such as `a, b := pair()`.
    pub extra_result_slots: Vec<ResolutionTypeSlotId>,
    /// Explicit invocation type arguments written at this call site. Inferred
    /// type arguments are not counted here.
    pub explicit_type_argument_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallArgumentFact {
    pub call: ResolutionSiteId,
    /// Position of this argument list in a curried application.
    pub list_ordinal: u32,
    /// Position within the complete call's arguments. It remains dense across
    /// lists for existing typed-call consumers.
    pub ordinal: u32,
    pub value: ResolutionTypeSlotId,
    /// Source name in a named argument, if this language supports one.
    pub label: Option<ResolutionNameId>,
}

/// One positioned name written as a named-argument label. Resolution uses the
/// call's selected callable and its parameter labels; the producer does not
/// bind the spelling independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionNamedArgumentLabelFact {
    pub call: ResolutionSiteId,
    pub reference: ResolutionSiteId,
    pub label: ResolutionNameId,
}

/// One argument list applied to a call. It is explicit even when empty, so
/// `f()` and `f()(x)` retain their source list boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallArgumentListFact {
    pub call: ResolutionSiteId,
    pub list_ordinal: u32,
}

/// One explicit type or const argument a call writes (Rust's turbofish,
/// `make::<Square>()`), in source order with lifetime arguments skipped, so
/// `ordinal` is the position among the callee's non-lifetime generic
/// parameters. `value` holds a value of the argument's type: a result the
/// callee declares as that type parameter takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallTypeArgumentFact {
    pub call: ResolutionSiteId,
    pub ordinal: u32,
    pub value: ResolutionTypeSlotId,
}

/// The type segment of a call's path that writes `call_owner_type_arguments`
/// (`Wrapper::<Square>` in `Wrapper::<Square>::make()`): `identity` is the
/// identity slot of the segment's type reference. The arguments are the
/// type's own only when the segment names that type directly; through an
/// alias they are the alias's, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallOwnerTypeSegmentFact {
    pub call: ResolutionSiteId,
    pub identity: ResolutionTypeSlotId,
}

/// The type a call's context expects its result to have: a `let` annotation
/// over a call initializer (`let value: Square = make();`). `value` holds a
/// value of that type. Where the callee's result is a type parameter and no
/// argument decides it, the expected type is the result, as Rust infers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallExpectedResultFact {
    pub call: ResolutionSiteId,
    pub value: ResolutionTypeSlotId,
}

labelled_enum! {
    /// The source-syntax route that supplied a callable reference's receiver.
    ///
    /// This intentionally stops before classifying an explicit expression as a
    /// type qualifier or a runtime value. That classification depends on selected
    /// bindings; the producer can only state whether source omitted the receiver,
    /// named the current instance, selected a superclass receiver, or supplied
    /// some other structured expression.
    ResolutionCallableReceiverOrigin, ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS {
        Implicit => "implicit",
        CurrentInstance => "current_instance",
        Super => "super",
        ExplicitExpression => "explicit_expression",
    }
}

impl ResolutionCallableReceiverOrigin {
    /// Whether a source reference's qualification agrees with its receiver
    /// origin. Producers represent a current-instance receiver in either a
    /// separate receiver slot or a qualifier slot.
    pub const fn is_reference_qualification_valid(self, unqualified: bool) -> bool {
        match self {
            Self::Implicit => unqualified,
            Self::CurrentInstance => true,
            Self::Super | Self::ExplicitExpression => !unqualified,
        }
    }
}

/// One receiver-origin row for a positioned callable reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableReceiverOriginFact {
    pub reference: ResolutionSiteId,
    pub origin: ResolutionCallableReceiverOrigin,
}

/// One positional result type in a callable signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableResultTypeFact {
    pub ordinal: u32,
    pub value_type: ResolutionTypeSlotId,
}

/// One callable declaration's signature header.
///
/// This row exists independently of parameter rows so a zero-parameter
/// callable still records whether it declares type parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolutionCallableSignatureFact {
    pub callable: ResolutionSiteId,
    pub type_parameter_count: u32,
    /// The declaration's result type slots, in source result order. This may
    /// also describe a value declaration whose declared type is a function
    /// type; in that case the call reference binds the value declaration and
    /// projects these result slots.
    pub result_types: Vec<ResolutionCallableResultTypeFact>,
}

/// One ordinary parameter of a callable, in declaration order.
///
/// `parameter` is the parameter's value-declaration site. It carries the
/// declaration identifier of the name the parameter binds, and `value_type`
/// its declaration-type property. A wildcard parameter (Rust `_`) binds
/// nothing, so its site carries no identifier and its slot no declaration-type
/// property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableParameterFact {
    pub callable: ResolutionSiteId,
    /// Position of this parameter list in a curried declaration.
    pub list_ordinal: u32,
    /// Position within the complete callable's parameters. It remains dense
    /// across lists for existing typed-call consumers.
    pub ordinal: u32,
    pub parameter: ResolutionSiteId,
    pub value_type: ResolutionTypeSlotId,
    pub repeated: bool,
}

/// One declared parameter list, including an explicitly empty list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableParameterListFact {
    pub callable: ResolutionSiteId,
    pub list_ordinal: u32,
    /// Whether this list is supplied contextually unless source provides it.
    pub contextual: bool,
}

/// A source parameter's label and default availability. These semantics are
/// shared by named-argument and curried-call binding after target selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableParameterSemanticsFact {
    pub callable: ResolutionSiteId,
    pub parameter: ResolutionSiteId,
    pub list_ordinal: u32,
    pub ordinal: u32,
    pub label: ResolutionNameId,
    pub has_default: bool,
}

/// The declared receiver type of an extension callable. This is distinct
/// from a receiver written at a call site and from a member callable's
/// implicit dispatch receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionExtensionReceiverFact {
    pub callable: ResolutionSiteId,
    pub receiver_type: ResolutionTypeSlotId,
}

labelled_enum! {
    /// How a method takes its receiver, where the language writes it and the
    /// form is one of these three. Method-call lookup probes the forms in an
    /// order, so two same-named methods of one type taking their receiver the
    /// same way are probed at the same step.
    ResolutionCallableReceiverForm, ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS {
        Value => "value",
        Reference => "reference",
        MutableReference => "mutable_reference",
    }
}

/// The receiver form of one method that declares its receiver in one of the
/// standard forms. A method with no row takes no receiver, or takes it in a
/// form (`self: Box<Self>`) outside the vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableReceiverFact {
    pub callable: ResolutionSiteId,
    pub form: ResolutionCallableReceiverForm,
}

/// A callable whose result type is one of its own type parameters: the
/// parameter's position among the callable's non-lifetime generic parameters
/// and the result's layers over it. A call's explicit type argument at that
/// position decides the result when no value argument does
/// (`ResolutionCallableResultBindingFact`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableResultTypeParameterFact {
    pub callable: ResolutionSiteId,
    pub position: u32,
    pub indirection_delta: i8,
    pub reference_indirection_delta: i8,
}

/// One ordinary parameter whose argument decides a callable's result type.
///
/// The callable's result type is one of its own type parameters, and this
/// parameter's declared type is that same type parameter behind layers: for
/// `fn pick<T>(value: &T) -> T`, the result is the argument at ordinal 0 with
/// one reference layer removed. The deltas are the result's layers minus the
/// parameter's. A call's argument at `parameter_ordinal` therefore gives the
/// call's result type directly, with no inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableResultBindingFact {
    pub callable: ResolutionSiteId,
    pub parameter_ordinal: u32,
    pub indirection_delta: i8,
    pub reference_indirection_delta: i8,
}

labelled_enum! {
    ResolutionMemberKind, ALL_RESOLUTION_MEMBER_KINDS {
        NestedType => "nested_type",
        Method => "method",
        Constructor => "constructor",
        Field => "field",
        AssociatedType => "associated_type",
    }
}

labelled_enum! {
    ResolutionMemberAccess, ALL_RESOLUTION_MEMBER_ACCESSES {
        Instance => "instance",
        Type => "type",
    }
}

labelled_enum! {
    /// Which qualifier value categories may select a member.
    ///
    /// Declaration access and qualifier compatibility are distinct. Java static
    /// members belong to the type namespace but may also be selected through a
    /// runtime expression, while languages such as Go have different rules.
    ResolutionMemberQualifierCompatibility, ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES {
        RuntimeOnly => "runtime_only",
        TypeOnly => "type_only",
        RuntimeOrType => "runtime_or_type",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionMemberOwnerFact {
    pub member: ResolutionSiteId,
    pub owner: ResolutionSiteId,
    pub kind: ResolutionMemberKind,
    pub access: ResolutionMemberAccess,
    pub qualifier_compatibility: ResolutionMemberQualifierCompatibility,
}

/// Producer authority for a definition to bind one lookup namespace with the
/// declared hoisting behavior.
///
/// Most definitions need no row: their positioned identifier, site kind, and
/// binder kind agree under the language-neutral rules. A producer emits this
/// row for a genuinely additional namespace or when its source language uses
/// a common declaration shape with different namespace or hoisting semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionAdditionalDefinitionNamespaceFact {
    pub declaration: ResolutionSiteId,
    pub namespace: ResolutionNamespace,
    pub hoisting: HoistingClass,
}

/// Preparation-only association between a resolution definition and the
/// parser's exact declaration. Combined blob preparation translates the
/// declaration to its content-local `unit_key`; no mounted identity persists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolutionDefinitionUnitFact {
    pub declaration: ResolutionSiteId,
    pub unit: CodeUnit,
}

/// A member whose owner is a pending type lookup rather than a local type
/// declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionDeferredMemberOwnerFact {
    pub member: ResolutionSiteId,
    pub owner_type: ResolutionTypeSlotId,
    pub kind: ResolutionMemberKind,
    pub access: ResolutionMemberAccess,
    pub qualifier_compatibility: ResolutionMemberQualifierCompatibility,
}

labelled_enum! {
    ResolutionDeclaredTypeRelationKind, ALL_RESOLUTION_DECLARED_TYPE_RELATION_KINDS {
        InherentImplementation => "inherent_implementation",
        TraitImplementation => "trait_implementation",
        TraitBound => "trait_bound",
        Supertrait => "supertrait",
        UnderlyingType => "underlying_type",
    }
}

/// One typed relation. Inherent implementations have no target; underlying
/// type declarations name their typed syntax slot without a positioned name
/// reference. Other relations retain their positioned target reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionDeclaredTypeRelationFact {
    pub id: ResolutionTypeRelationId,
    pub subject: ResolutionTypeSlotId,
    pub kind: ResolutionDeclaredTypeRelationKind,
    pub target_reference: Option<ResolutionSiteId>,
    pub target: Option<ResolutionTypeSlotId>,
}

/// One declaration contributed by a declared type relation, in source order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRelationMemberFact {
    pub relation: ResolutionTypeRelationId,
    pub ordinal: u32,
    pub member: ResolutionSiteId,
    pub kind: ResolutionMemberKind,
}

labelled_enum! {
    ResolutionEngineRuleKind, ALL_RESOLUTION_ENGINE_RULE_KINDS {
        ArgumentIndependentBinding => "argument_independent_binding",
        DefaultConstruction => "default_construction",
        DirectOwnerExactPrimitiveDominance => "direct_owner_exact_primitive_dominance",
        /// This reference's owner does not have a closed member surface, so a
        /// hierarchy walk that reaches no declaring owner has proved nothing.
        ///
        /// Rust sets it for a qualified member lookup: a blanket impl, a trait
        /// bound, a `Deref` chain, or a trait from a crate this workspace does
        /// not index can each supply a member the owner's indexed impls never
        /// mention. A language whose member surface is closed sets nothing and
        /// keeps its proved absences, which is why this is the producer's
        /// statement and not a rule the language-neutral engine applies.
        OpenMemberSurface => "open_member_surface",
        /// The fully replayed, matched item macro cannot introduce members.
        /// Its unexpanded lexical declarations remain a live frontier.
        ClosedMacroMemberSurface => "closed_macro_member_surface",
        /// When lookup leaves this call several candidate declarations, a
        /// candidate whose parameters the call's arguments cannot reach under
        /// Rust's coercions is not the call's target.
        ///
        /// Rust sets it beside `ArgumentIndependentBinding` on a call whose
        /// argument list is exactly represented. A Rust call binds by lookup,
        /// not by overloading, but lookup can leave several impls of one
        /// generic trait for one type, and the argument types choose among
        /// them. The rules compare only intrinsic types -- primitives, and
        /// slices and arrays of them -- because they implement no `Deref` and
        /// unsize only from an array to a slice; a nominal or generic type can
        /// deref or instantiate to anything. The rules are Rust's, which is
        /// why this is the producer's statement.
        ArgumentCoercionFilter => "argument_coercion_filter",
    }
}

/// Producer-owned permission for one site to use a narrow engine theorem.
///
/// The site is a call for the rules that govern call binding and a reference
/// for the rules that govern a lookup. It was a call for every rule until the
/// open-member-surface rule, whose subject -- `Host::ITEM` -- is a constant
/// read and has no call of its own. A closed-macro-member-surface proof
/// names the unexpanded item invocation instead of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionEngineRuleEligibilityFact {
    pub site: ResolutionSiteId,
    pub rule: ResolutionEngineRuleKind,
}

/// The declaration that contains one positioned reference occurrence.
///
/// This is source-containment metadata for usage and graph projection. It is
/// deliberately independent of [`ResolutionSiteFact::scope`]: a declaration
/// header can be looked up in an enclosing lexical scope while still belonging
/// to the declaration whose signature contains it.
/// `owner == None` explicitly states that the reference is not contained by a
/// declaration; absence of this row would instead make ownership unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionReferenceOwnerFact {
    pub reference: ResolutionSiteId,
    pub owner: Option<ResolutionSiteId>,
}

labelled_enum! {
    ResolutionSupertypeKind, ALL_RESOLUTION_SUPERTYPE_KINDS {
        Superclass => "superclass",
        Interface => "interface",
        GoInterfaceElement => "go_interface_element",
        /// The superclass a Java class has without writing one: the absolute
        /// `java.lang.Object` route the producer supplies for every ordinary
        /// class that declares no `extends`. Consumers that know what Object
        /// declares (JLS 4.3.2: methods only) can seal member-type and field
        /// walks across this edge even while the route is unindexed.
        ImplicitSuperclass => "implicit_superclass",
        /// A Scala self-type constraint used for member inheritance inside its
        /// owning template, but not as a nominal subtype relation.
        SelfType => "self_type",
    }
}

/// One declared subtype relation. Both the positioned reference and its type
/// slot are retained so lexical binding and typed hierarchy traversal consume
/// the same source occurrence without resolving its target in the file walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionSupertypeFact {
    pub subtype: ResolutionSiteId,
    /// Written parent order; synthetic implicit parents use zero.
    pub parent_ordinal: u32,
    pub supertype_reference: ResolutionSiteId,
    pub supertype_slot: ResolutionTypeSlotId,
    pub kind: ResolutionSupertypeKind,
}

labelled_enum! {
    ResolutionConstructionRequirementKind, ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS {
        EnclosingInstance => "enclosing_instance",
    }
}

/// A requirement that is specific to constructing a type, rather than to
/// looking up the nested type's name. For example, a non-static Java member
/// class is type-qualified as `Outer.Inner`, but constructing it requires an
/// instance of `Outer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionConstructionRequirementFact {
    pub constructed_type: ResolutionSiteId,
    pub required_owner: ResolutionSiteId,
    pub kind: ResolutionConstructionRequirementKind,
}

/// One source package route attached at `root_scope`. A file may publish
/// several routes for nested or braced package clauses; each route has its own
/// scope, declaration, and ordered segment rows. An unnamed package has no
/// declaration and no segment rows. `placement_gap_site` identifies the
/// source endpoint for an [`ResolutionGapKind::UnsupportedPlacementBoundary`]
/// when the producer reports an unresolved placement boundary; producers that
/// fully model source placement can leave that gap absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageFact {
    pub root_scope: ResolutionScopeId,
    pub declaration: Option<ResolutionSiteId>,
    pub placement_gap_site: ResolutionSiteId,
}

labelled_enum! {
    ResolutionGoPackageImportKind, ALL_GO_PACKAGE_IMPORT_KINDS {
        Named => "named",
        Blank => "blank",
    }
}

/// One source-owned Go package import declaration. Default package spelling
/// remains selected-context authority; an explicit alias stays in source imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionGoPackageImportFact {
    pub import_site: ResolutionSiteId,
    pub file_scope: ResolutionScopeId,
    pub kind: ResolutionGoPackageImportKind,
}

/// One package-name segment in source order. Ordinals are dense within the
/// package route's `root_scope`; names remain target-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageSegmentFact {
    pub root_scope: ResolutionScopeId,
    pub ordinal: u32,
    pub name: ResolutionNameId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionImportRouteKind {
    SingleType,
    TypeOnDemand,
    SingleStatic,
    StaticOnDemand,
    Named,
    Star,
}

/// One supported import route. This records only source-owned route syntax;
/// selecting a declaration target remains a revision-dependent operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionImportRouteFact {
    pub site: ResolutionSiteId,
    pub root_scope: ResolutionScopeId,
    pub kind: ResolutionImportRouteKind,
    /// The one name introduced by a single-name import. On-demand imports bind
    /// names only when a reference demands them, so they have no source-owned
    /// bound name.
    pub bound_name: Option<ResolutionNameId>,
}

/// One import-route segment in source order. Ordinals are dense within the
/// import site. For a single-name route the final segment is the bound type or
/// static member. For an on-demand route the asterisk is not a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionImportRouteSegmentFact {
    pub import_site: ResolutionSiteId,
    pub ordinal: u32,
    pub name: ResolutionNameId,
}

/// One source-owned route that can carry exact lookup demands to the
/// universal root. The route records syntax only; selected workspace context
/// remains responsible for choosing its destination root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionRootImportAnchor {
    /// Resolve the first route segment using the language's contextual import
    /// rules for the selected source unit.
    Lexical,
    /// Resolve a syntactically absolute route using the selected source unit's
    /// language-version rules.
    Absolute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportFact {
    pub site: ResolutionSiteId,
    pub root_scope: ResolutionScopeId,
    pub anchor: ResolutionRootImportAnchor,
    /// The byte from which the import is in effect, through the end of its
    /// root scope. `None` means the import is in effect across the whole
    /// scope, as a Rust `use` or a Java import is. A language whose imports
    /// bind only the names written after them (Scala) gives the position the
    /// import takes effect at; lowering starts the import's route at that
    /// position's checkpoint in the scope timeline.
    pub position: Option<usize>,
}

/// One source-order segment of a root import route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportSegmentFact {
    pub import_site: ResolutionSiteId,
    pub position: u32,
    pub name: ResolutionNameId,
}

/// One direct root-qualified reference. The terminal name and effective
/// namespace come from the positioned identifier at `reference`. A language
/// producer may retain `TypeOrValue` when the route head is grammatically
/// ambiguous. These rows carry the source-owned route that precedes that
/// terminal and whether a head owns a later route continuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootReferenceFact {
    pub reference: ResolutionSiteId,
    pub root_scope: ResolutionScopeId,
    pub anchor: ResolutionRootImportAnchor,
    /// Positioned lexical reference for the first segment. Rust continues
    /// from a Type prefix; Go classifies its package/value prefix; Java uses a
    /// Type prefix to guard package interpretation against lexical shadowing.
    /// The site supplies lexical scope and namespace. Explicit root anchors
    /// leave this absent.
    pub prefix_reference: Option<ResolutionSiteId>,
    /// This reference is an owner whose selected route continues through a
    /// later segment. Producers set this on a TypeOrValue route head or a
    /// projection owner; it is route shape, independent of the language
    /// consuming the path.
    pub owner_continued: bool,
}

/// One source-order segment of a direct root-qualified reference route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootReferenceSegmentFact {
    pub reference: ResolutionSiteId,
    pub position: u32,
    pub name: ResolutionNameId,
}

/// One exact name and effective namespace that a root import may expose.
///
/// Keeping demands explicit lets a producer enforce language visibility rules
/// before an open route reaches the shared root. It also avoids treating a
/// partially supported import form as authority for unobserved names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportDemandFact {
    pub import_site: ResolutionSiteId,
    pub namespace: ResolutionNamespace,
    pub name: ResolutionNameId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionRootImportKind {
    Named,
    Glob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportKindFact {
    pub import_site: ResolutionSiteId,
    pub kind: ResolutionRootImportKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionRootImportDemandTarget {
    NamedReference(ResolutionSiteId),
    SameNameGlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportDemandTargetFact {
    pub import_site: ResolutionSiteId,
    pub namespace: ResolutionNamespace,
    pub name: ResolutionNameId,
    pub target: ResolutionRootImportDemandTarget,
}

labelled_enum! {
    /// Source form of an import selector that changes the local name or
    /// introduces names from a package/object star route.
    ResolutionImportSelectorKind, ALL_RESOLUTION_IMPORT_SELECTOR_KINDS {
        Named => "named",
        Star => "star",
        ReceiverMember => "receiver_member",
    }
}

/// The imported source name and the name visible in the importing file.
/// Either name is absent for a selector form that has no single bound leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionImportSelectorFact {
    pub site: ResolutionSiteId,
    pub kind: ResolutionImportSelectorKind,
    pub source_name: Option<ResolutionNameId>,
    pub local_name: Option<ResolutionNameId>,
}

labelled_enum! {
    /// Relationship that makes an object or companion reachable through its
    /// enclosing declaration. This is source identity metadata, not a
    /// compiler-generated declaration.
    ResolutionSingletonRelationKind, ALL_RESOLUTION_SINGLETON_RELATION_KINDS {
        Object => "object",
        Companion => "companion",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionSingletonRelationFact {
    pub declaration: ResolutionSiteId,
    pub enclosing_type: Option<ResolutionSiteId>,
    pub kind: ResolutionSingletonRelationKind,
}

labelled_enum! {
    /// Whether the parsed source alone proves that a JVM alias is emitted.
    /// Compiler-option-dependent aliases remain explicit but incomplete.
    ResolutionJvmAliasStatus, ALL_RESOLUTION_JVM_ALIAS_STATUSES {
        SourceProven => "source_proven",
        CompilerModeDependent => "compiler_mode_dependent",
    }
}

labelled_enum! {
    /// The JVM member surface reached by one source-derived alias.
    ResolutionJvmAliasKind, ALL_RESOLUTION_JVM_ALIAS_KINDS {
        Field => "field",
        Getter => "getter",
        Setter => "setter",
        Method => "method",
        Constructor => "constructor",
        CompanionObject => "companion_object",
        SingletonInstance => "singleton_instance",
    }
}

/// One JVM spelling projected back to the exact authored declaration.
/// `owner_segments` contains the binary owner components in order, including
/// package segments. It is kept in child rows so SQL can inspect each part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionJvmAliasFact {
    pub id: ResolutionJvmAliasId,
    pub declaration: ResolutionSiteId,
    pub member_name: ResolutionNameId,
    pub kind: ResolutionJvmAliasKind,
    pub is_static: bool,
    pub parameter_count: u32,
    pub status: ResolutionJvmAliasStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionJvmAliasOwnerSegmentFact {
    pub alias: ResolutionJvmAliasId,
    pub ordinal: u32,
    pub name: ResolutionNameId,
}

/// One declaration that may be reached from a selected root attachment.
///
/// The declaration and its lookup namespace are content-owned. The package,
/// module, or include route that makes the root reachable is selected-context
/// authority and is deliberately absent. `root_scope` is the content scope at
/// which selected context attaches the declaration; for Rust this can be an
/// inline-module scope rather than the file's compilation-unit scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootExportFact {
    pub root_scope: ResolutionScopeId,
    pub declaration: ResolutionSiteId,
    pub namespace: ResolutionNamespace,
}

/// A declaration reachable only through selected membership in the same package.
/// This is separate from public root exports: private declarations never acquire
/// external import visibility by appearing here. Namespace is one effective
/// definition namespace, never a grammar union such as TypeOrValue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageMemberFact {
    pub root_scope: ResolutionScopeId,
    pub declaration: ResolutionSiteId,
    pub namespace: ResolutionNamespace,
}

/// An unqualified lookup that may continue from its lexical package scope to
/// sibling source members. The positioned identifier owns its spelling and
/// requested namespace; nearer lexical bindings retain their normal precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageReferenceFact {
    pub reference: ResolutionSiteId,
    pub root_scope: ResolutionScopeId,
}

/// One member that a Scala package object re-exports at its package route.
/// Both declarations retain their source identities; this row only states the
/// selected package route through which the member is also visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageObjectExportFact {
    pub package_object: ResolutionSiteId,
    pub package_scope: ResolutionScopeId,
    pub member: ResolutionSiteId,
}

labelled_enum! {
    /// Source-level operation attached to a call or extractor pattern.
    ResolutionInvocationRole, ALL_RESOLUTION_INVOCATION_ROLES {
        Direct => "direct",
        Apply => "apply",
        Unapply => "unapply",
        UnapplySeq => "unapply_seq",
    }
}

/// One invocation request. `site` is a call node for `Direct`/`Apply` and the
/// head reference of the pattern for `Unapply`/`UnapplySeq` (the reference a
/// reader resolves to the extractor, as a call's callee is resolved); receiver
/// and result slots preserve the typed edges consumed by a shared invocation
/// reader. The row carries no argument count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionInvocationRoleFact {
    pub site: ResolutionSiteId,
    pub role: ResolutionInvocationRole,
    pub receiver: Option<ResolutionTypeSlotId>,
    pub result: Option<ResolutionTypeSlotId>,
}

labelled_enum! {
    ResolutionGapKind, ALL_RESOLUTION_GAP_KINDS {
        UnsupportedTypeSyntax => "unsupported_type_syntax",
        UnsupportedExpression => "unsupported_expression",
        UnsupportedRoute => "unsupported_route",
        UnsupportedScopeOrBinder => "unsupported_scope_or_binder",
        AmbiguousQualifiedType => "ambiguous_qualified_type",
        InferredType => "inferred_type",
        PostfixArrayDimensions => "postfix_array_dimensions",
        AmbiguousNumericLiteral => "ambiguous_numeric_literal",
    /// An ordinary source class has no explicit constructor declaration and is
    /// eligible for the current exact zero-argument direct-construction proof.
    /// This is a conservative proof marker, not a complete inventory of JLS
    /// constructor existence and not an affirmative synthetic declaration.
    /// Abstract classes also receive default constructors, but do not publish
    /// this marker until direct instantiability is represented separately from
    /// superclass-constructor invocation. Records do not publish this marker.
    ///
    /// A Rust unit struct publishes it too: `struct Square;` has no written
    /// constructor, and its value item `Square` is its one zero-argument
    /// construction, so a value read that binds it is an instance of it.
        ImplicitConstructor => "implicit_constructor",
    /// An explicit supertype reference was preserved, or the type has an
    /// implicit language root, but member lookup through that hierarchy is not
    /// yet implemented by the typed evaluator.
        UnsupportedHierarchyTraversal => "unsupported_hierarchy_traversal",
    /// The declaration has a non-public effective visibility whose
    /// accessibility depends on selected package, owner, or hierarchy facts.
    /// This is declaration-local evidence, not a blanket claim that the
    /// owner's member inventory is incomplete.
        UnsupportedVisibility => "unsupported_visibility",
    /// An unqualified value or callable reference occurs where the producer
    /// cannot yet prove that an implicit instance receiver is legal. This is
    /// reference-local evidence; it does not make the surrounding declaration
    /// inventory incomplete.
        UnsupportedImplicitReceiver => "unsupported_implicit_receiver",
    /// A structured call was retained, but arity, conversions, overloads, and
    /// other candidate-applicability rules have not been evaluated. This is
    /// local to the callee reference and does not make symbol inventory
    /// incomplete.
        UnsupportedCallApplicability => "unsupported_call_applicability",
    /// The file-local scope graph has not been attached to its selected
    /// package, module, or default-package placement. The gap belongs to the
    /// actual root scope endpoint and leaves file-local bindings usable.
        UnsupportedPlacementBoundary => "unsupported_placement_boundary",
        MalformedSyntax => "malformed_syntax",
    /// The producer skipped an associated-item or implementation surface.
    /// Such a surface may omit member declarations and references, but it
    /// cannot introduce an ordinary free lexical binder into the surrounding
    /// scope. Lowering therefore keeps broad enumeration and reverse
    /// candidate inventory incomplete without poisoning unrelated lexical
    /// point resolution.
        UnsupportedMemberScope => "unsupported_member_scope",
    /// A retained declaration carries a predicate that selection must decide.
    /// Its source inventory is complete; this is only an activation obligation.
        UnprovenActivation => "unproven_activation",
    /// The item carries an attribute whose expansion this producer does not
    /// model, such as a Rust `derive` or one of its helper attributes.
    ///
    /// Deliberately not a reference-enumeration gap. Nothing authored was
    /// skipped: the item is walked in full and every reference written in it
    /// is enumerated, so the file's authored reference set is still the whole
    /// set. What is missing is the surface the expansion would add, and this
    /// names it, so a reader asking what Bifrost does not cover at this item
    /// is answered by a row positioned on the item instead of by a blanket
    /// claim that the file's references are incomplete.
        GeneratedItemSurface => "generated_item_surface",
    /// A call argument is a macro invocation whose expansion this producer
    /// does not replay as a value, so the argument's type is unknown. Local to
    /// the argument: the call and its callee stay exactly represented, and the
    /// invocation's own gap still covers what it expands to.
        MacroArgument => "macro_argument",
    /// An item-position invocation of a visible `macro_rules!` that is not a
    /// proven passthrough and not proven to declare nothing: its rules write
    /// tokens no row holds (tract's `from_i!` writes impls from a `ty`).
    ///
    /// The expansion can add items to its module and impls to any type the
    /// module declares, and it can shadow a glob or prelude binding or bind an
    /// unbound name. It cannot rebind a name an explicit import or a local
    /// declaration already binds, which would be a duplicate definition. The
    /// lowering reaches exactly those surfaces instead of the whole scope.
        UnexpandedItemMacro => "unexpanded_item_macro",
    /// An item-position invocation of a visible `macro_rules!` whose rules
    /// write nothing but `impl` blocks (tract's `impl_datum_type!`). Its
    /// expansion binds no name in its module, so it leaves the module's
    /// export inventory and bare lookups alone; it can still add members to
    /// the types its scope declares, which is the only surface it opens.
        UnexpandedImplMacro => "unexpanded_impl_macro",
    /// The expression was fully traversed, but its resulting type or value is not modeled.
    /// References and binders below this site are retained, so this is not an enumeration gap.
        UnsupportedExpressionType => "unsupported_expression_type",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionGapFact {
    pub site: ResolutionSiteId,
    pub kind: ResolutionGapKind,
}

/// Producer-owned evidence that positioned reference enumeration is not
/// exhaustive at one semantic site.
///
/// This relation is deliberately separate from [`ResolutionGapFact`]. Most
/// resolution gaps describe binding, typing, applicability, or visibility for
/// occurrences that were already retained. A language producer publishes this
/// row only when it skipped syntax that can contain a reference occurrence or
/// otherwise omitted such an occurrence from [`FileResolutionFacts::identifiers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionReferenceEnumerationGapFact {
    pub site: ResolutionSiteId,
    pub kind: ResolutionGapKind,
}

/// The effective source-language visibility of one supported declaration.
///
/// This remains file-local and target-independent: language defaults such as
/// an implicitly public Java interface member are applied by the producer,
/// while deciding whether a particular reference may access the declaration
/// remains a selected-revision operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionDeclarationVisibilityFact {
    pub declaration: ResolutionSiteId,
    pub visibility: DeclaredVisibility,
}

/// Producer-owned permission for one declaration to carry visibility facts.
///
/// This keeps source-language declaration-kind policy out of common lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionVisibilityEligibilityFact {
    pub declaration: ResolutionSiteId,
}

/// One source file's normalized, target-independent resolution rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileResolutionFacts {
    pub names: Vec<ResolutionNameFact>,
    pub scopes: Vec<ResolutionScopeFact>,
    pub sites: Vec<ResolutionSiteFact>,
    pub packages: Vec<ResolutionPackageFact>,
    pub package_segments: Vec<ResolutionPackageSegmentFact>,
    pub import_routes: Vec<ResolutionImportRouteFact>,
    pub import_route_segments: Vec<ResolutionImportRouteSegmentFact>,
    pub root_imports: Vec<ResolutionRootImportFact>,
    pub root_import_segments: Vec<ResolutionRootImportSegmentFact>,
    pub root_import_demands: Vec<ResolutionRootImportDemandFact>,
    pub root_import_kinds: Vec<ResolutionRootImportKindFact>,
    pub root_import_demand_targets: Vec<ResolutionRootImportDemandTargetFact>,
    pub import_selectors: Vec<ResolutionImportSelectorFact>,
    pub root_references: Vec<ResolutionRootReferenceFact>,
    pub root_reference_segments: Vec<ResolutionRootReferenceSegmentFact>,
    pub root_exports: Vec<ResolutionRootExportFact>,
    pub package_members: Vec<ResolutionPackageMemberFact>,
    pub go_package_imports: Vec<ResolutionGoPackageImportFact>,
    pub package_references: Vec<ResolutionPackageReferenceFact>,
    pub package_object_exports: Vec<ResolutionPackageObjectExportFact>,
    pub invocation_roles: Vec<ResolutionInvocationRoleFact>,
    pub singleton_relations: Vec<ResolutionSingletonRelationFact>,
    pub jvm_aliases: Vec<ResolutionJvmAliasFact>,
    pub jvm_alias_owner_segments: Vec<ResolutionJvmAliasOwnerSegmentFact>,
    pub identifiers: Vec<PositionedIdentifierFact>,
    pub additional_definition_namespaces: Vec<ResolutionAdditionalDefinitionNamespaceFact>,
    pub definition_units: Vec<ResolutionDefinitionUnitFact>,
    pub binders: Vec<ResolutionBinderFact>,
    pub conditional_binders: Vec<ResolutionConditionalBinderFact>,
    pub type_slots: Vec<ResolutionTypeSlotFact>,
    pub declaration_type_slots: Vec<DeclarationTypeSlotFact>,
    pub binding_projections: Vec<BindingProjectionFact>,
    pub type_transfers: Vec<ResolutionTypeTransferFact>,
    pub type_components: Vec<ResolutionTypeComponentFact>,
    pub declared_type_arguments: Vec<ResolutionDeclaredTypeArgumentFact>,
    pub type_arguments: Vec<ResolutionTypeArgumentFact>,
    pub generic_type_alias_parameters: Vec<ResolutionGenericTypeAliasParameterFact>,
    pub generic_formals: Vec<ResolutionGenericFormalFact>,
    pub intrinsic_type_seeds: Vec<IntrinsicTypeSeedFact>,
    pub calls: Vec<ResolutionCallFact>,
    pub call_argument_lists: Vec<ResolutionCallArgumentListFact>,
    pub call_arguments: Vec<ResolutionCallArgumentFact>,
    pub named_argument_labels: Vec<ResolutionNamedArgumentLabelFact>,
    pub call_type_arguments: Vec<ResolutionCallTypeArgumentFact>,
    /// The type arguments a call writes on the type segment of its path
    /// (`Wrapper::<Square>::make()`), in the same shape as
    /// `call_type_arguments`: `ordinal` is the position among the type's
    /// non-lifetime arguments, which an impl's target type names.
    pub call_owner_type_arguments: Vec<ResolutionCallTypeArgumentFact>,
    pub call_owner_type_segments: Vec<ResolutionCallOwnerTypeSegmentFact>,
    pub call_expected_results: Vec<ResolutionCallExpectedResultFact>,
    pub callable_receiver_origins: Vec<ResolutionCallableReceiverOriginFact>,
    pub callable_signatures: Vec<ResolutionCallableSignatureFact>,
    pub callable_parameters: Vec<ResolutionCallableParameterFact>,
    pub callable_parameter_lists: Vec<ResolutionCallableParameterListFact>,
    pub callable_parameter_semantics: Vec<ResolutionCallableParameterSemanticsFact>,
    pub extension_receivers: Vec<ResolutionExtensionReceiverFact>,
    pub callable_result_bindings: Vec<ResolutionCallableResultBindingFact>,
    pub callable_result_type_parameters: Vec<ResolutionCallableResultTypeParameterFact>,
    /// Callables whose result type is a type parameter of the enclosing impl,
    /// in the same shape as `callable_result_type_parameters`: `position` is
    /// where that parameter stands, bare, among the non-lifetime type
    /// arguments of the impl's target type (`impl<W> Wrapper<W>` puts `W` at
    /// 0). A call's type-segment argument at that position decides it.
    pub callable_result_owner_type_parameters: Vec<ResolutionCallableResultTypeParameterFact>,
    pub callable_receivers: Vec<ResolutionCallableReceiverFact>,
    pub member_owners: Vec<ResolutionMemberOwnerFact>,
    pub deferred_member_owners: Vec<ResolutionDeferredMemberOwnerFact>,
    /// Module declarations whose only route is a crate-level module walk, not
    /// a lexical binder: a `mod name;` a Rust macro capsule lowers from an
    /// item-macro invocation's arguments. The crate decides whether the
    /// invocation expands and mounts the module; the capsule only gives the
    /// declaration a definition and a root export, which a crate-row export
    /// lookup reaches when the crate declares the module. No lexical lookup
    /// reaches it, so the missing binder is not a lexical gap.
    pub route_owned_module_declarations: Vec<ResolutionSiteId>,
    /// References that spell a keyword the language binds implicitly rather
    /// than through any lexical scope (Rust's `Self`, bound by the enclosing
    /// `impl` or trait). They take no lexical route: the typed identity the
    /// producer publishes for them is their whole answer, and no binder,
    /// glob, prelude or unexpanded item macro of a scope can supply them.
    pub keyword_references: Vec<ResolutionSiteId>,
    pub declared_type_relations: Vec<ResolutionDeclaredTypeRelationFact>,
    pub relation_members: Vec<ResolutionRelationMemberFact>,
    pub engine_rule_eligibilities: Vec<ResolutionEngineRuleEligibilityFact>,
    pub reference_owners: Vec<ResolutionReferenceOwnerFact>,
    pub visibility_eligibilities: Vec<ResolutionVisibilityEligibilityFact>,
    pub declaration_visibilities: Vec<ResolutionDeclarationVisibilityFact>,
    pub supertypes: Vec<ResolutionSupertypeFact>,
    pub construction_requirements: Vec<ResolutionConstructionRequirementFact>,
    pub reference_enumeration_gaps: Vec<ResolutionReferenceEnumerationGapFact>,
    pub gaps: Vec<ResolutionGapFact>,
}

/// Collect source-owned package lookup requests while leaving scope,
/// namespace, and import rules to the language producer.
///
/// Only unqualified references that are not already owned by an explicit root
/// route can be package lookups. The caller decides which of those references
/// its language permits to search in the source package and supplies that
/// package's scope.
pub fn source_owned_package_references(
    facts: &FileResolutionFacts,
    mut package_scope_for: impl FnMut(
        &PositionedIdentifierFact,
        &ResolutionSiteFact,
    ) -> Option<ResolutionScopeId>,
) -> Vec<ResolutionPackageReferenceFact> {
    let rooted_references = facts
        .root_references
        .iter()
        .map(|reference| reference.reference)
        .collect::<HashSet<_>>();

    facts
        .identifiers
        .iter()
        .filter_map(|identifier| {
            if identifier.role != ResolutionIdentifierRole::Reference
                || identifier.qualifier.is_some()
                || rooted_references.contains(&identifier.site)
            {
                return None;
            }
            let site = &facts.sites[identifier.site.index()];
            package_scope_for(identifier, site).map(|root_scope| ResolutionPackageReferenceFact {
                reference: identifier.site,
                root_scope,
            })
        })
        .collect()
}

impl FileResolutionFacts {
    /// Record one positional type parameter owned by a generic declaration.
    pub fn add_generic_formal(
        &mut self,
        owner: ResolutionSiteId,
        ordinal: u32,
        parameter: ResolutionSiteId,
    ) {
        self.generic_formals.push(ResolutionGenericFormalFact {
            owner,
            ordinal,
            parameter,
        });
    }

    /// Append one site and assign its dense file-local ID.
    pub fn add_site(
        &mut self,
        scope: ResolutionScopeId,
        kind: ResolutionSiteKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionSiteId {
        let id = ResolutionSiteId::try_from_index(self.sites.len())
            .expect("resolution site count exceeds u32");
        self.sites.push(ResolutionSiteFact {
            id,
            scope,
            kind,
            start_byte,
            end_byte,
        });
        id
    }

    /// Append a gap unless this file already contains the same fact.
    pub fn add_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        let gap = ResolutionGapFact { site, kind };
        if !self.gaps.contains(&gap) {
            self.gaps.push(gap);
        }
    }

    /// Append a reference-enumeration gap unless it is already present.
    pub fn add_reference_enumeration_gap(
        &mut self,
        site: ResolutionSiteId,
        kind: ResolutionGapKind,
    ) {
        let gap = ResolutionReferenceEnumerationGapFact { site, kind };
        if !self.reference_enumeration_gaps.contains(&gap) {
            self.reference_enumeration_gaps.push(gap);
        }
    }

    /// Look up one name in this file's dense name table.
    pub fn name(&self, id: ResolutionNameId) -> &str {
        let fact = &self.names[id.index()];
        assert_eq!(fact.id, id, "resolution name index matches its ID");
        &fact.spelling
    }

    /// Find positioned identifiers with one spelling, role, and namespace.
    pub fn identifiers_named<'a>(
        &'a self,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> Vec<&'a PositionedIdentifierFact> {
        self.identifiers
            .iter()
            .filter(|identifier| {
                self.name(identifier.name) == spelling
                    && identifier.role == role
                    && identifier.namespace == namespace
            })
            .collect()
    }

    /// Look up one lexical scope in this file's dense scope table.
    pub fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        let fact = &self.scopes[id.index()];
        assert_eq!(fact.id, id, "resolution scope index matches its ID");
        fact
    }

    /// Look up one type slot in this file's dense type-slot table.
    pub fn type_slot(&self, id: ResolutionTypeSlotId) -> &ResolutionTypeSlotFact {
        let fact = &self.type_slots[id.index()];
        assert_eq!(fact.id, id, "resolution type-slot index matches its ID");
        fact
    }

    /// Intern an already-normalized spelling into this file's name table.
    pub fn intern_name<S: BuildHasher>(
        &mut self,
        known_names: &mut HashMap<String, ResolutionNameId, S>,
        spelling: &str,
    ) -> ResolutionNameId {
        assert!(!spelling.is_empty(), "resolution names need a spelling");
        if let Some(id) = known_names.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.names.len())
            .expect("resolution name count exceeds u32");
        let spelling = spelling.to_owned();
        known_names.insert(spelling.clone(), id);
        self.names.push(ResolutionNameFact { id, spelling });
        id
    }

    /// Append the Cartesian product of root import sites and requested names.
    pub fn extend_root_import_demands(
        &mut self,
        import_sites: &[ResolutionSiteId],
        demands: &[(ResolutionNamespace, ResolutionNameId)],
    ) {
        self.root_import_demands
            .reserve(import_sites.len().saturating_mul(demands.len()));
        for &import_site in import_sites {
            for &(namespace, name) in demands {
                self.root_import_demands
                    .push(ResolutionRootImportDemandFact {
                        import_site,
                        namespace,
                        name,
                    });
            }
        }
    }

    /// Append a call with one result slot and no additional result slots.
    pub fn add_single_result_call(
        &mut self,
        call: ResolutionSiteId,
        callee: ResolutionSiteId,
        receiver: Option<ResolutionTypeSlotId>,
        result: ResolutionTypeSlotId,
        explicit_type_argument_count: u32,
    ) {
        self.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver,
            result,
            extra_result_slots: Vec::new(),
            explicit_type_argument_count,
        });
    }

    /// Append one lexical child scope and assign its dense file-local ID.
    pub fn allocate_lexical_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeId {
        assert!(start_byte <= end_byte, "scope byte range is ordered");
        let id = ResolutionScopeId::try_from_index(self.scopes.len())
            .expect("resolution scope count exceeds u32");
        self.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner,
            kind,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte,
            end_byte,
        });
        id
    }

    /// Append one type slot and assign its dense file-local ID.
    pub fn allocate_type_slot(
        &mut self,
        site: ResolutionSiteId,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        let id = ResolutionTypeSlotId::try_from_index(self.type_slots.len())
            .expect("resolution type slot count exceeds u32");
        self.type_slots
            .push(ResolutionTypeSlotFact { id, site, role });
        id
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.scopes.is_empty()
            && self.sites.is_empty()
            && self.packages.is_empty()
            && self.package_segments.is_empty()
            && self.import_routes.is_empty()
            && self.import_route_segments.is_empty()
            && self.root_imports.is_empty()
            && self.root_import_segments.is_empty()
            && self.root_import_demands.is_empty()
            && self.root_import_kinds.is_empty()
            && self.root_import_demand_targets.is_empty()
            && self.import_selectors.is_empty()
            && self.root_references.is_empty()
            && self.root_reference_segments.is_empty()
            && self.root_exports.is_empty()
            && self.package_members.is_empty()
            && self.go_package_imports.is_empty()
            && self.package_references.is_empty()
            && self.package_object_exports.is_empty()
            && self.invocation_roles.is_empty()
            && self.singleton_relations.is_empty()
            && self.jvm_aliases.is_empty()
            && self.jvm_alias_owner_segments.is_empty()
            && self.identifiers.is_empty()
            && self.additional_definition_namespaces.is_empty()
            && self.definition_units.is_empty()
            && self.binders.is_empty()
            && self.conditional_binders.is_empty()
            && self.type_slots.is_empty()
            && self.declaration_type_slots.is_empty()
            && self.binding_projections.is_empty()
            && self.type_transfers.is_empty()
            && self.type_components.is_empty()
            && self.declared_type_arguments.is_empty()
            && self.type_arguments.is_empty()
            && self.generic_type_alias_parameters.is_empty()
            && self.generic_formals.is_empty()
            && self.intrinsic_type_seeds.is_empty()
            && self.calls.is_empty()
            && self.call_argument_lists.is_empty()
            && self.call_arguments.is_empty()
            && self.named_argument_labels.is_empty()
            && self.call_type_arguments.is_empty()
            && self.call_owner_type_arguments.is_empty()
            && self.call_owner_type_segments.is_empty()
            && self.call_expected_results.is_empty()
            && self.callable_receiver_origins.is_empty()
            && self.callable_signatures.is_empty()
            && self.callable_parameters.is_empty()
            && self.callable_parameter_lists.is_empty()
            && self.callable_parameter_semantics.is_empty()
            && self.extension_receivers.is_empty()
            && self.callable_result_bindings.is_empty()
            && self.callable_result_type_parameters.is_empty()
            && self.callable_result_owner_type_parameters.is_empty()
            && self.callable_receivers.is_empty()
            && self.member_owners.is_empty()
            && self.deferred_member_owners.is_empty()
            && self.route_owned_module_declarations.is_empty()
            && self.keyword_references.is_empty()
            && self.declared_type_relations.is_empty()
            && self.relation_members.is_empty()
            && self.engine_rule_eligibilities.is_empty()
            && self.reference_owners.is_empty()
            && self.visibility_eligibilities.is_empty()
            && self.declaration_visibilities.is_empty()
            && self.supertypes.is_empty()
            && self.construction_requirements.is_empty()
            && self.reference_enumeration_gaps.is_empty()
            && self.gaps.is_empty()
    }

    /// Validate package attachment rows at producer and readback boundaries.
    /// All indexes here live only for this one file's validation.
    pub fn validate_package_relations(&self) {
        use std::collections::{HashMap, HashSet};
        let identifiers = self
            .identifiers
            .iter()
            .map(|identifier| (identifier.site, identifier))
            .collect::<HashMap<_, _>>();
        let mut definitions = self
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .map(|identifier| (identifier.site, identifier.namespace))
            .collect::<HashSet<_>>();
        definitions.extend(
            self.additional_definition_namespaces
                .iter()
                .map(|fact| (fact.declaration, fact.namespace)),
        );
        let binders = self
            .binders
            .iter()
            .map(|binder| (binder.declaration, binder.scope))
            .collect::<HashMap<_, _>>();
        let mut package_imports = HashSet::new();
        for import in &self.go_package_imports {
            assert!(
                package_imports.insert(import.import_site),
                "duplicate Go package import"
            );
            assert_eq!(
                self.scopes[import.file_scope.index()].kind,
                ResolutionScopeKind::File
            );
            let site = self.sites[import.import_site.index()];
            assert_eq!(site.scope, import.file_scope);
            assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
            assert!(
                self.root_imports
                    .iter()
                    .any(|route| route.site == import.import_site
                        && route.root_scope == import.file_scope)
            );
            assert!(
                self.root_import_kinds
                    .iter()
                    .any(|kind| kind.import_site == import.import_site
                        && kind.kind == ResolutionRootImportKind::Named)
            );
        }
        let mut members = HashSet::new();
        for member in &self.package_members {
            assert!(
                self.scopes[member.root_scope.index()].kind == ResolutionScopeKind::Package
                    || (self.scopes[member.root_scope.index()].kind
                        == ResolutionScopeKind::CompilationUnit
                        && self
                            .packages
                            .iter()
                            .any(|package| package.root_scope == member.root_scope)),
                "package relations require a concrete Package scope or an explicitly placed compilation unit"
            );
            assert_eq!(
                self.sites[member.declaration.index()].scope,
                member.root_scope
            );
            assert_eq!(binders.get(&member.declaration), Some(&member.root_scope));
            assert!(matches!(
                member.namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
            ));
            assert!(definitions.contains(&(member.declaration, member.namespace)));
            assert!(identifiers[&member.declaration].qualifier.is_none());
            assert!(
                members.insert((member.declaration, member.namespace)),
                "duplicate package member"
            );
        }
        let qualified = self
            .root_references
            .iter()
            .map(|fact| fact.reference)
            .collect::<HashSet<_>>();
        let explicit_receiver_calls = self
            .callable_receiver_origins
            .iter()
            .filter(|fact| fact.origin == ResolutionCallableReceiverOrigin::ExplicitExpression)
            .map(|fact| fact.reference)
            .collect::<HashSet<_>>();
        let mut references = HashSet::new();
        for reference in &self.package_references {
            assert!(
                self.scopes[reference.root_scope.index()].kind == ResolutionScopeKind::Package
                    || (self.scopes[reference.root_scope.index()].kind
                        == ResolutionScopeKind::CompilationUnit
                        && self
                            .packages
                            .iter()
                            .any(|package| package.root_scope == reference.root_scope)),
                "package relations require a concrete Package scope or an explicitly placed compilation unit"
            );
            let identifier = identifiers[&reference.reference];
            assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
            assert!(
                identifier.qualifier.is_none()
                    || (identifier.namespace == ResolutionNamespace::Callable
                        && explicit_receiver_calls.contains(&reference.reference)),
                "only explicit receiver callable names may have qualified package routes"
            );
            assert!(
                !qualified.contains(&reference.reference),
                "qualified terminal cannot demand a sibling package name"
            );
            assert!(
                references.insert(reference.reference),
                "duplicate package reference"
            );
            let mut scope = self.sites[reference.reference.index()].scope;
            while scope != reference.root_scope {
                let parent = self.scopes[scope.index()]
                    .parent
                    .expect("package reference must descend from its package scope");
                assert!(
                    parent.index() < scope.index(),
                    "scope parents precede descendants"
                );
                scope = parent;
            }
        }
    }

    /// Conservative heap bytes retained by these rows. This mirrors the
    /// analyzer cache's capacity-based accounting: row vectors charge their
    /// spare capacity, and interned spellings additionally charge their owned
    /// string buffers.
    pub fn estimated_retained_bytes(&self) -> usize {
        fn rows<T>(values: &Vec<T>) -> usize {
            values.capacity().saturating_mul(std::mem::size_of::<T>())
        }

        rows(&self.names)
            .saturating_add(
                self.names
                    .iter()
                    .map(|name| name.spelling.capacity())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(rows(&self.scopes))
            .saturating_add(rows(&self.sites))
            .saturating_add(rows(&self.packages))
            .saturating_add(rows(&self.package_segments))
            .saturating_add(rows(&self.import_routes))
            .saturating_add(rows(&self.import_route_segments))
            .saturating_add(rows(&self.root_imports))
            .saturating_add(rows(&self.root_import_segments))
            .saturating_add(rows(&self.root_import_demands))
            .saturating_add(rows(&self.root_import_kinds))
            .saturating_add(rows(&self.root_import_demand_targets))
            .saturating_add(rows(&self.import_selectors))
            .saturating_add(rows(&self.root_references))
            .saturating_add(rows(&self.root_reference_segments))
            .saturating_add(rows(&self.root_exports))
            .saturating_add(rows(&self.package_members))
            .saturating_add(rows(&self.go_package_imports))
            .saturating_add(rows(&self.package_references))
            .saturating_add(rows(&self.package_object_exports))
            .saturating_add(rows(&self.invocation_roles))
            .saturating_add(rows(&self.singleton_relations))
            .saturating_add(rows(&self.jvm_aliases))
            .saturating_add(rows(&self.jvm_alias_owner_segments))
            .saturating_add(rows(&self.identifiers))
            .saturating_add(rows(&self.additional_definition_namespaces))
            .saturating_add(rows(&self.definition_units))
            .saturating_add(rows(&self.binders))
            .saturating_add(rows(&self.conditional_binders))
            .saturating_add(rows(&self.type_slots))
            .saturating_add(rows(&self.declaration_type_slots))
            .saturating_add(rows(&self.binding_projections))
            .saturating_add(rows(&self.type_transfers))
            .saturating_add(rows(&self.type_components))
            .saturating_add(rows(&self.declared_type_arguments))
            .saturating_add(rows(&self.type_arguments))
            .saturating_add(rows(&self.generic_type_alias_parameters))
            .saturating_add(rows(&self.generic_formals))
            .saturating_add(rows(&self.intrinsic_type_seeds))
            .saturating_add(rows(&self.calls))
            .saturating_add(
                self.calls
                    .iter()
                    .map(|call| {
                        call.extra_result_slots
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ResolutionTypeSlotId>())
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(rows(&self.call_argument_lists))
            .saturating_add(rows(&self.call_arguments))
            .saturating_add(rows(&self.named_argument_labels))
            .saturating_add(rows(&self.call_type_arguments))
            .saturating_add(rows(&self.call_owner_type_arguments))
            .saturating_add(rows(&self.call_owner_type_segments))
            .saturating_add(rows(&self.call_expected_results))
            .saturating_add(rows(&self.callable_receiver_origins))
            .saturating_add(rows(&self.callable_signatures))
            .saturating_add(
                self.callable_signatures
                    .iter()
                    .map(|signature| {
                        signature
                            .result_types
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ResolutionCallableResultTypeFact>())
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(rows(&self.callable_parameters))
            .saturating_add(rows(&self.callable_parameter_lists))
            .saturating_add(rows(&self.callable_parameter_semantics))
            .saturating_add(rows(&self.extension_receivers))
            .saturating_add(rows(&self.callable_result_bindings))
            .saturating_add(rows(&self.callable_result_type_parameters))
            .saturating_add(rows(&self.callable_result_owner_type_parameters))
            .saturating_add(rows(&self.callable_receivers))
            .saturating_add(rows(&self.member_owners))
            .saturating_add(rows(&self.deferred_member_owners))
            .saturating_add(rows(&self.declared_type_relations))
            .saturating_add(rows(&self.relation_members))
            .saturating_add(rows(&self.engine_rule_eligibilities))
            .saturating_add(rows(&self.reference_owners))
            .saturating_add(rows(&self.visibility_eligibilities))
            .saturating_add(rows(&self.declaration_visibilities))
            .saturating_add(rows(&self.supertypes))
            .saturating_add(rows(&self.construction_requirements))
            .saturating_add(rows(&self.reference_enumeration_gaps))
            .saturating_add(rows(&self.gaps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::assert_vocabulary_round_trip;

    #[test]
    fn persisted_resolution_fact_vocabularies_are_unique_and_round_trip() {
        assert_vocabulary_round_trip!(ALL_RESOLUTION_SITE_KINDS, ResolutionSiteKind);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_NAMESPACES, ResolutionNamespace);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_IMPORT_SELECTOR_KINDS,
            ResolutionImportSelectorKind
        );
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_SINGLETON_RELATION_KINDS,
            ResolutionSingletonRelationKind
        );
        assert_vocabulary_round_trip!(ALL_RESOLUTION_INVOCATION_ROLES, ResolutionInvocationRole);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_INVOCATION_ROLES, ResolutionInvocationRole);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_JVM_ALIAS_STATUSES, ResolutionJvmAliasStatus);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_JVM_ALIAS_KINDS, ResolutionJvmAliasKind);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_TYPE_SLOT_ROLES, ResolutionTypeSlotRole);
        assert_vocabulary_round_trip!(ALL_DECLARATION_TYPE_ROLES, DeclarationTypeRole);
        assert_vocabulary_round_trip!(ALL_BINDING_PROJECTION_KINDS, BindingProjectionKind);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
            ResolutionTypeTransferKind
        );
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_TYPE_COMPONENT_KINDS,
            ResolutionTypeComponentKind
        );
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS,
            ResolutionTypeConstructorKind
        );
        assert_vocabulary_round_trip!(ALL_INTRINSIC_TYPE_KINDS, IntrinsicTypeKind);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS,
            ResolutionCallableReceiverOrigin
        );
        assert_vocabulary_round_trip!(ALL_RESOLUTION_MEMBER_KINDS, ResolutionMemberKind);
        assert_vocabulary_round_trip!(ALL_RESOLUTION_MEMBER_ACCESSES, ResolutionMemberAccess);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
            ResolutionMemberQualifierCompatibility
        );
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_DECLARED_TYPE_RELATION_KINDS,
            ResolutionDeclaredTypeRelationKind
        );
        assert_vocabulary_round_trip!(ALL_RESOLUTION_ENGINE_RULE_KINDS, ResolutionEngineRuleKind);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS,
            ResolutionCallableReceiverForm
        );
        assert_vocabulary_round_trip!(ALL_RESOLUTION_SUPERTYPE_KINDS, ResolutionSupertypeKind);
        assert_vocabulary_round_trip!(
            ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
            ResolutionConstructionRequirementKind
        );
        assert_vocabulary_round_trip!(ALL_RESOLUTION_GAP_KINDS, ResolutionGapKind);

        assert!(ResolutionNamespace::from_label("not_a_namespace").is_none());
    }

    #[test]
    fn jvm_facts_participate_in_emptiness_and_retained_bytes() {
        let mut facts = FileResolutionFacts::default();
        let name = ResolutionNameId::new(0);
        let declaration = ResolutionSiteId::new(0);
        facts
            .call_argument_lists
            .push(ResolutionCallArgumentListFact {
                call: ResolutionSiteId::new(1),
                list_ordinal: 0,
            });
        facts.call_arguments.push(ResolutionCallArgumentFact {
            call: ResolutionSiteId::new(1),
            list_ordinal: 0,
            ordinal: 0,
            value: ResolutionTypeSlotId::new(1),
            label: Some(name),
        });
        facts
            .named_argument_labels
            .push(ResolutionNamedArgumentLabelFact {
                call: ResolutionSiteId::new(1),
                reference: ResolutionSiteId::new(3),
                label: name,
            });
        facts
            .callable_parameter_semantics
            .push(ResolutionCallableParameterSemanticsFact {
                callable: declaration,
                parameter: ResolutionSiteId::new(2),
                list_ordinal: 0,
                ordinal: 0,
                label: name,
                has_default: true,
            });
        facts
            .callable_parameter_lists
            .push(ResolutionCallableParameterListFact {
                callable: declaration,
                list_ordinal: 0,
                contextual: false,
            });
        facts
            .extension_receivers
            .push(ResolutionExtensionReceiverFact {
                callable: declaration,
                receiver_type: ResolutionTypeSlotId::new(0),
            });
        facts.import_selectors.push(ResolutionImportSelectorFact {
            site: ResolutionSiteId::new(3),
            kind: ResolutionImportSelectorKind::Named,
            source_name: Some(name),
            local_name: Some(ResolutionNameId::new(1)),
        });
        facts
            .singleton_relations
            .push(ResolutionSingletonRelationFact {
                declaration,
                enclosing_type: None,
                kind: ResolutionSingletonRelationKind::Object,
            });
        facts
            .package_object_exports
            .push(ResolutionPackageObjectExportFact {
                package_object: declaration,
                package_scope: ResolutionScopeId::new(0),
                member: ResolutionSiteId::new(4),
            });
        facts.invocation_roles.push(ResolutionInvocationRoleFact {
            site: ResolutionSiteId::new(1),
            role: ResolutionInvocationRole::Direct,
            receiver: None,
            result: Some(ResolutionTypeSlotId::new(2)),
        });
        facts.jvm_aliases.push(ResolutionJvmAliasFact {
            id: ResolutionJvmAliasId::new(0),
            declaration,
            member_name: name,
            kind: ResolutionJvmAliasKind::Field,
            is_static: true,
            parameter_count: 0,
            status: ResolutionJvmAliasStatus::SourceProven,
        });
        facts
            .jvm_alias_owner_segments
            .push(ResolutionJvmAliasOwnerSegmentFact {
                alias: ResolutionJvmAliasId::new(0),
                ordinal: 0,
                name,
            });

        assert!(!facts.is_empty());
        let expected = facts
            .call_argument_lists
            .capacity()
            .saturating_mul(std::mem::size_of::<ResolutionCallArgumentListFact>())
            .saturating_add(
                facts
                    .call_arguments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionCallArgumentFact>()),
            )
            .saturating_add(
                facts
                    .named_argument_labels
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionNamedArgumentLabelFact>()),
            )
            .saturating_add(
                facts
                    .callable_parameter_lists
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionCallableParameterListFact>()),
            )
            .saturating_add(
                facts
                    .callable_parameter_semantics
                    .capacity()
                    .saturating_mul(
                        std::mem::size_of::<ResolutionCallableParameterSemanticsFact>(),
                    ),
            )
            .saturating_add(
                facts
                    .extension_receivers
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionExtensionReceiverFact>()),
            )
            .saturating_add(
                facts
                    .import_selectors
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionImportSelectorFact>()),
            )
            .saturating_add(
                facts
                    .singleton_relations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionSingletonRelationFact>()),
            )
            .saturating_add(
                facts
                    .package_object_exports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionPackageObjectExportFact>()),
            )
            .saturating_add(
                facts
                    .invocation_roles
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionInvocationRoleFact>()),
            )
            .saturating_add(
                facts
                    .jvm_aliases
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionJvmAliasFact>()),
            )
            .saturating_add(
                facts
                    .jvm_alias_owner_segments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionJvmAliasOwnerSegmentFact>()),
            );
        assert_eq!(facts.estimated_retained_bytes(), expected);
    }

    #[test]
    fn root_route_facts_participate_in_emptiness_and_retained_bytes() {
        let mut facts = FileResolutionFacts::default();
        facts.root_imports.push(ResolutionRootImportFact {
            site: ResolutionSiteId::new(0),
            root_scope: ResolutionScopeId::new(0),
            anchor: ResolutionRootImportAnchor::Lexical,
            position: None,
        });
        facts
            .root_import_segments
            .push(ResolutionRootImportSegmentFact {
                import_site: ResolutionSiteId::new(0),
                position: 0,
                name: ResolutionNameId::new(0),
            });
        facts
            .root_import_demands
            .push(ResolutionRootImportDemandFact {
                import_site: ResolutionSiteId::new(0),
                namespace: ResolutionNamespace::Type,
                name: ResolutionNameId::new(1),
            });
        facts.root_exports.push(ResolutionRootExportFact {
            root_scope: ResolutionScopeId::new(0),
            declaration: ResolutionSiteId::new(1),
            namespace: ResolutionNamespace::Type,
        });
        facts.root_references.push(ResolutionRootReferenceFact {
            reference: ResolutionSiteId::new(2),
            root_scope: ResolutionScopeId::new(0),
            anchor: ResolutionRootImportAnchor::Absolute,
            prefix_reference: None,
            owner_continued: false,
        });
        facts
            .root_reference_segments
            .push(ResolutionRootReferenceSegmentFact {
                reference: ResolutionSiteId::new(2),
                position: 0,
                name: ResolutionNameId::new(2),
            });

        assert!(!facts.is_empty());
        let expected = facts
            .root_imports
            .capacity()
            .saturating_mul(std::mem::size_of::<ResolutionRootImportFact>())
            .saturating_add(
                facts
                    .root_import_segments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionRootImportSegmentFact>()),
            )
            .saturating_add(
                facts
                    .root_import_demands
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionRootImportDemandFact>()),
            )
            .saturating_add(
                facts
                    .root_references
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionRootReferenceFact>()),
            )
            .saturating_add(
                facts
                    .root_reference_segments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionRootReferenceSegmentFact>()),
            )
            .saturating_add(
                facts
                    .root_exports
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ResolutionRootExportFact>()),
            );
        assert_eq!(facts.estimated_retained_bytes(), expected);
    }
}
