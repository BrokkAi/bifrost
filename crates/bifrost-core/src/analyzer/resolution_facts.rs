//! Immutable, file-local inputs to compositional name and type resolution.
//!
//! These rows describe the facts a language walk can produce from its syntax
//! tree. This additive model is not yet connected to production parsing.
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
use serde::{Deserialize, Serialize};
use std::fmt;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionScopeFact {
    pub id: ResolutionScopeId,
    pub parent: Option<ResolutionScopeId>,
    pub owner: Option<ResolutionSiteId>,
    pub kind: ResolutionScopeKind,
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
        Literal => "literal",
        UnsupportedRoute => "unsupported_route",
        UnsupportedDeclaration => "unsupported_declaration",
        UnsupportedExpression => "unsupported_expression",
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
    }
}

/// Copy a property of whichever declaration the reference eventually binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindingProjectionFact {
    pub reference: ResolutionSiteId,
    pub output: ResolutionTypeSlotId,
    pub kind: BindingProjectionKind,
}

labelled_enum! {
    ResolutionTypeTransferKind, ALL_RESOLUTION_TYPE_TRANSFER_KINDS {
        DeclaredType => "declared_type",
        Assignment => "assignment",
        Construction => "construction",
        Receiver => "receiver",
        Argument => "argument",
        Return => "return",
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionTypeTransferFact {
    pub input: ResolutionTypeSlotId,
    pub output: ResolutionTypeSlotId,
    pub kind: ResolutionTypeTransferKind,
    /// Signed indirection keeps language-specific pointer/reference syntax out
    /// of the common transfer-kind vocabulary.
    pub indirection_delta: i8,
    pub value_transform: ResolutionTypeTransferValueTransform,
}

labelled_enum! {
    IntrinsicTypeKind, ALL_INTRINSIC_TYPE_KINDS {
        Primitive => "primitive",
        LanguageBuiltin => "language_builtin",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallFact {
    pub call: ResolutionSiteId,
    pub callee: ResolutionSiteId,
    /// The dispatch receiver for an ordinary member call, or the explicit
    /// enclosing-instance expression for a qualified inner-class construction.
    pub receiver: Option<ResolutionTypeSlotId>,
    pub result: ResolutionTypeSlotId,
    /// Explicit invocation type arguments written at this call site. Inferred
    /// type arguments are not counted here.
    pub explicit_type_argument_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallArgumentFact {
    pub call: ResolutionSiteId,
    pub ordinal: u32,
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

/// One receiver-origin row for a positioned callable reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableReceiverOriginFact {
    pub reference: ResolutionSiteId,
    pub origin: ResolutionCallableReceiverOrigin,
}

/// One callable declaration's signature header.
///
/// This row exists independently of parameter rows so a zero-parameter
/// callable still records whether it declares type parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableSignatureFact {
    pub callable: ResolutionSiteId,
    pub type_parameter_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionCallableParameterFact {
    pub callable: ResolutionSiteId,
    pub ordinal: u32,
    pub parameter: ResolutionSiteId,
    pub value_type: ResolutionTypeSlotId,
    pub repeated: bool,
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
    }
}

/// One Rust-like typed relation. Inherent implementations have no target;
/// every other relation retains one positioned target reference and frontier.
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
        DefaultConstruction => "default_construction",
        DirectOwnerExactPrimitiveDominance => "direct_owner_exact_primitive_dominance",
    }
}

/// Producer-owned permission for one call to use a narrow engine theorem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionEngineRuleEligibilityFact {
    pub call: ResolutionSiteId,
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
    }
}

/// One declared subtype relation. Both the positioned reference and its type
/// slot are retained so lexical binding and typed hierarchy traversal consume
/// the same source occurrence without resolving its target in the file walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionSupertypeFact {
    pub subtype: ResolutionSiteId,
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

/// The package placement declared by one compilation-unit root. An unnamed
/// package has no declaration and no segment rows. `placement_gap_site` is the
/// exact root endpoint whose [`ResolutionGapKind::UnsupportedPlacementBoundary`]
/// is discharged when a selected revision attaches this file to a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionPackageFact {
    pub root_scope: ResolutionScopeId,
    pub declaration: Option<ResolutionSiteId>,
    pub placement_gap_site: ResolutionSiteId,
}

/// One package-name segment in source order. Ordinals are dense within the
/// compilation-unit root and names remain target-independent.
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
}

/// One source-order segment of a root import route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootImportSegmentFact {
    pub import_site: ResolutionSiteId,
    pub position: u32,
    pub name: ResolutionNameId,
}

/// One direct root-qualified reference. The terminal name and effective
/// namespace come from the positioned identifier at `reference`; the
/// identifier must not use the grammar-ambiguous `TypeOrValue` namespace.
/// These rows carry only the source-owned root route that precedes that
/// terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionRootReferenceFact {
    pub reference: ResolutionSiteId,
    pub root_scope: ResolutionScopeId,
    pub anchor: ResolutionRootImportAnchor,
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
    pub root_references: Vec<ResolutionRootReferenceFact>,
    pub root_reference_segments: Vec<ResolutionRootReferenceSegmentFact>,
    pub root_exports: Vec<ResolutionRootExportFact>,
    pub identifiers: Vec<PositionedIdentifierFact>,
    pub additional_definition_namespaces: Vec<ResolutionAdditionalDefinitionNamespaceFact>,
    pub definition_units: Vec<ResolutionDefinitionUnitFact>,
    pub binders: Vec<ResolutionBinderFact>,
    pub type_slots: Vec<ResolutionTypeSlotFact>,
    pub declaration_type_slots: Vec<DeclarationTypeSlotFact>,
    pub binding_projections: Vec<BindingProjectionFact>,
    pub type_transfers: Vec<ResolutionTypeTransferFact>,
    pub intrinsic_type_seeds: Vec<IntrinsicTypeSeedFact>,
    pub calls: Vec<ResolutionCallFact>,
    pub call_arguments: Vec<ResolutionCallArgumentFact>,
    pub callable_receiver_origins: Vec<ResolutionCallableReceiverOriginFact>,
    pub callable_signatures: Vec<ResolutionCallableSignatureFact>,
    pub callable_parameters: Vec<ResolutionCallableParameterFact>,
    pub member_owners: Vec<ResolutionMemberOwnerFact>,
    pub deferred_member_owners: Vec<ResolutionDeferredMemberOwnerFact>,
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

impl FileResolutionFacts {
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
            && self.root_references.is_empty()
            && self.root_reference_segments.is_empty()
            && self.root_exports.is_empty()
            && self.identifiers.is_empty()
            && self.additional_definition_namespaces.is_empty()
            && self.definition_units.is_empty()
            && self.binders.is_empty()
            && self.type_slots.is_empty()
            && self.declaration_type_slots.is_empty()
            && self.binding_projections.is_empty()
            && self.type_transfers.is_empty()
            && self.intrinsic_type_seeds.is_empty()
            && self.calls.is_empty()
            && self.call_arguments.is_empty()
            && self.callable_receiver_origins.is_empty()
            && self.callable_signatures.is_empty()
            && self.callable_parameters.is_empty()
            && self.member_owners.is_empty()
            && self.deferred_member_owners.is_empty()
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
            .saturating_add(rows(&self.root_references))
            .saturating_add(rows(&self.root_reference_segments))
            .saturating_add(rows(&self.root_exports))
            .saturating_add(rows(&self.identifiers))
            .saturating_add(rows(&self.additional_definition_namespaces))
            .saturating_add(rows(&self.definition_units))
            .saturating_add(rows(&self.binders))
            .saturating_add(rows(&self.type_slots))
            .saturating_add(rows(&self.declaration_type_slots))
            .saturating_add(rows(&self.binding_projections))
            .saturating_add(rows(&self.type_transfers))
            .saturating_add(rows(&self.intrinsic_type_seeds))
            .saturating_add(rows(&self.calls))
            .saturating_add(rows(&self.call_arguments))
            .saturating_add(rows(&self.callable_receiver_origins))
            .saturating_add(rows(&self.callable_signatures))
            .saturating_add(rows(&self.callable_parameters))
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

    #[test]
    fn persisted_resolution_fact_vocabularies_are_unique_and_round_trip() {
        macro_rules! check {
            ($all:expr, $type:ty) => {{
                let mut labels = std::collections::HashSet::new();
                for &value in $all {
                    assert!(labels.insert(value.label()), "duplicate label {value:?}");
                    assert_eq!(<$type>::from_label(value.label()), Some(value));
                    let json = serde_json::to_value(value).expect("serialize");
                    assert_eq!(json, serde_json::Value::String(value.label().to_owned()));
                    assert_eq!(
                        serde_json::from_value::<$type>(json).expect("deserialize"),
                        value
                    );
                }
                assert_eq!(labels.len(), $all.len());
            }};
        }

        check!(ALL_RESOLUTION_SITE_KINDS, ResolutionSiteKind);
        check!(ALL_RESOLUTION_NAMESPACES, ResolutionNamespace);
        check!(ALL_RESOLUTION_TYPE_SLOT_ROLES, ResolutionTypeSlotRole);
        check!(ALL_DECLARATION_TYPE_ROLES, DeclarationTypeRole);
        check!(ALL_BINDING_PROJECTION_KINDS, BindingProjectionKind);
        check!(
            ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
            ResolutionTypeTransferKind
        );
        check!(ALL_INTRINSIC_TYPE_KINDS, IntrinsicTypeKind);
        check!(
            ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS,
            ResolutionCallableReceiverOrigin
        );
        check!(ALL_RESOLUTION_MEMBER_KINDS, ResolutionMemberKind);
        check!(ALL_RESOLUTION_MEMBER_ACCESSES, ResolutionMemberAccess);
        check!(
            ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
            ResolutionMemberQualifierCompatibility
        );
        check!(
            ALL_RESOLUTION_DECLARED_TYPE_RELATION_KINDS,
            ResolutionDeclaredTypeRelationKind
        );
        check!(ALL_RESOLUTION_ENGINE_RULE_KINDS, ResolutionEngineRuleKind);
        check!(ALL_RESOLUTION_SUPERTYPE_KINDS, ResolutionSupertypeKind);
        check!(
            ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
            ResolutionConstructionRequirementKind
        );
        check!(ALL_RESOLUTION_GAP_KINDS, ResolutionGapKind);

        assert!(ResolutionNamespace::from_label("not_a_namespace").is_none());
    }

    #[test]
    fn reference_enumeration_gaps_participate_in_emptiness_and_retained_bytes() {
        let mut facts = FileResolutionFacts::default();
        assert!(facts.is_empty());
        assert_eq!(facts.estimated_retained_bytes(), 0);

        facts
            .reference_enumeration_gaps
            .push(ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            });

        assert!(!facts.is_empty());
        assert_eq!(
            facts.estimated_retained_bytes(),
            facts
                .reference_enumeration_gaps
                .capacity()
                .saturating_mul(std::mem::size_of::<ResolutionReferenceEnumerationGapFact>())
        );
    }

    #[test]
    fn root_route_facts_participate_in_emptiness_and_retained_bytes() {
        let mut facts = FileResolutionFacts::default();
        facts.root_imports.push(ResolutionRootImportFact {
            site: ResolutionSiteId::new(0),
            root_scope: ResolutionScopeId::new(0),
            anchor: ResolutionRootImportAnchor::Lexical,
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
