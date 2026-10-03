//! Normalized, file-local rows for the Java/Go resolution schema spike.
//!
//! A [`BindingProjectionRow`] means "project a property of whichever
//! declaration this reference resolves to." It does not persist that target,
//! so these rows remain valid when another file changes the definition
//! landscape. The fixtures are hand-authored from external LSP cases rather
//! than parsed by a second source scanner. `SourcePosition` is therefore a
//! fixture-local monotone ordinal; production lowering will use tree-sitter
//! byte spans.
//!
//! The current store already has declaration `CodeUnit`s, declaration-level
//! signature metadata, and generic structural nodes/roles. It lacks lexical
//! activation, expression type slots, binding-to-type projections, and local
//! type-transfer rows. Those are the new relations below. General Java
//! lowering still needs imports/packages, hierarchy, visibility, overload and
//! generic applicability, constructors, casts, and call-result transfer.
//! General Go lowering still needs aliases, multi-value assignment, method
//! sets, embedding/promotion, interfaces, and call-result transfer.
//!
//! These rows intentionally stop before partial-path lowering. The algebra now
//! represents a symbol as `PartialScopedSymbol`, including its optional
//! attached scope-stack pattern. Production language lowering must preserve
//! that attachment when it translates qualifier and owner rows; downgrading
//! them to unscoped semantic IDs would be unsound.

use std::collections::HashSet;

macro_rules! local_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) struct $name(u16);

        impl $name {
            pub(crate) const fn new(value: u16) -> Self {
                Self(value)
            }
        }
    };
}

local_id!(NameId);
local_id!(ScopeId);
local_id!(NodeId);
local_id!(TypeSlotId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SourcePosition(u16);

impl SourcePosition {
    pub(crate) const fn new(value: u16) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpikeLanguage {
    Java,
    Go,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixtureId {
    JavaQualifiedNestedClassReference,
    JavaMethodCallOnTypedLocal,
    GoFieldThroughCompositeLiteralReceiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ScopeKind {
    CompilationUnit,
    Package,
    TypeBody,
    Executable,
    Initializer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NodeKind {
    TypeDeclaration,
    InterfaceDeclaration,
    MethodDeclaration,
    FunctionDeclaration,
    FieldDeclaration,
    ParameterDeclaration,
    LocalDeclaration,
    Initializer,
    TypeReference,
    ValueReference,
    MemberReference,
    CompositeLiteral,
    AddressOf,
    StringLiteral,
    Call,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Namespace {
    Type,
    Value,
    Member,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TypeSlotRole {
    ProjectionOutput,
    DeclaredValue,
    ExpressionValue,
    ParameterValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BindingProjectionKind {
    TargetTypeIdentity,
    TargetDeclaredValueType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TypeTransferKind {
    DeclaredType,
    CompositeLiteral,
    AddressOf,
    ShortDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IntrinsicType {
    JavaLangString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MemberKind {
    NestedType,
    Method,
    Field,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MemberAccess {
    Instance,
    Type,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GapKind {
    UnresolvedTypeReference,
    UnsupportedTypeExpression,
    UnsupportedDispatch,
    ExternalTypeBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NameRow {
    pub id: NameId,
    pub spelling: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ScopeRow {
    pub id: ScopeId,
    pub parent: Option<ScopeId>,
    pub owner: Option<NodeId>,
    pub kind: ScopeKind,
    pub start: SourcePosition,
    pub end: SourcePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NodeRow {
    pub id: NodeId,
    pub scope: ScopeId,
    pub position: SourcePosition,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DeclarationRow {
    pub node: NodeId,
    pub name: NameId,
    pub namespace: Namespace,
    pub visible_from: SourcePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ReferenceRow {
    pub node: NodeId,
    pub name: NameId,
    pub namespace: Namespace,
    pub qualifier: Option<TypeSlotId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TypeSlotRow {
    pub id: TypeSlotId,
    pub node: NodeId,
    pub role: TypeSlotRole,
}

/// The declaration property to copy after the reference is bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BindingProjectionRow {
    pub reference: NodeId,
    pub output: TypeSlotId,
    pub projection: BindingProjectionKind,
}

/// Signed indirection keeps Go `&` out of the common schema vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TypeTransferRow {
    pub input: TypeSlotId,
    pub output: TypeSlotId,
    pub kind: TypeTransferKind,
    pub indirection_delta: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IntrinsicTypeSeedRow {
    pub output: TypeSlotId,
    pub intrinsic: IntrinsicType,
    pub indirection: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CallRow {
    pub node: NodeId,
    pub callee: NodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CallArgumentRow {
    pub call: NodeId,
    pub ordinal: u16,
    pub value: TypeSlotId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CallableParameterRow {
    pub callable: NodeId,
    pub ordinal: u16,
    pub parameter: NodeId,
    pub value_type: TypeSlotId,
    pub repeated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MemberOwnerRow {
    pub member: NodeId,
    pub owner: NodeId,
    pub kind: MemberKind,
    pub access: MemberAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct GapRow {
    pub node: NodeId,
    pub kind: GapKind,
}

/// External ground truth, not a persisted production fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ExpectedTargetRow {
    pub reference: NodeId,
    pub target: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFactRows {
    pub names: Box<[NameRow]>,
    pub scopes: Box<[ScopeRow]>,
    pub nodes: Box<[NodeRow]>,
    pub declarations: Box<[DeclarationRow]>,
    pub references: Box<[ReferenceRow]>,
    pub type_slots: Box<[TypeSlotRow]>,
    pub binding_projections: Box<[BindingProjectionRow]>,
    pub type_transfers: Box<[TypeTransferRow]>,
    pub intrinsic_type_seeds: Box<[IntrinsicTypeSeedRow]>,
    pub calls: Box<[CallRow]>,
    pub call_arguments: Box<[CallArgumentRow]>,
    pub callable_parameters: Box<[CallableParameterRow]>,
    pub member_owners: Box<[MemberOwnerRow]>,
    pub gaps: Box<[GapRow]>,
}

impl NormalizedFactRows {
    fn assert_valid(&self) {
        let names = unique_ids(self.names.iter().map(|row| row.id), "name");
        let scopes = unique_ids(self.scopes.iter().map(|row| row.id), "scope");
        let nodes = unique_ids(self.nodes.iter().map(|row| row.id), "node");
        let declarations = unique_ids(
            self.declarations.iter().map(|row| row.node),
            "declaration node",
        );
        let references = unique_ids(self.references.iter().map(|row| row.node), "reference node");
        let slots = unique_ids(self.type_slots.iter().map(|row| row.id), "type slot");
        assert!(declarations.is_disjoint(&references));

        for row in &self.scopes {
            assert!(row.start < row.end, "empty scope: {row:?}");
            assert!(row.parent.is_none_or(|id| scopes.contains(&id)));
            assert!(row.owner.is_none_or(|id| nodes.contains(&id)));
        }
        for row in &self.nodes {
            assert!(scopes.contains(&row.scope), "unknown node scope: {row:?}");
        }
        for row in &self.declarations {
            assert!(nodes.contains(&row.node) && names.contains(&row.name));
        }
        for row in &self.references {
            assert!(nodes.contains(&row.node) && names.contains(&row.name));
            assert!(row.qualifier.is_none_or(|id| slots.contains(&id)));
        }
        for row in &self.type_slots {
            assert!(nodes.contains(&row.node), "unknown slot node: {row:?}");
        }
        for row in &self.binding_projections {
            assert!(references.contains(&row.reference) && slots.contains(&row.output));
        }
        for row in &self.type_transfers {
            assert!(slots.contains(&row.input) && slots.contains(&row.output));
            assert_ne!(row.input, row.output);
        }
        for row in &self.intrinsic_type_seeds {
            assert!(slots.contains(&row.output));
        }
        for row in &self.calls {
            assert!(nodes.contains(&row.node) && references.contains(&row.callee));
        }
        for row in &self.call_arguments {
            assert!(self.calls.iter().any(|call| call.node == row.call));
            assert!(slots.contains(&row.value));
        }
        for row in &self.callable_parameters {
            assert!(declarations.contains(&row.callable));
            assert!(declarations.contains(&row.parameter));
            assert!(slots.contains(&row.value_type));
        }
        for row in &self.member_owners {
            assert!(declarations.contains(&row.member) && declarations.contains(&row.owner));
        }
        for row in &self.gaps {
            assert!(nodes.contains(&row.node));
        }
    }
}

fn unique_ids<T>(items: impl IntoIterator<Item = T>, label: &str) -> HashSet<T>
where
    T: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    for item in items {
        assert!(seen.insert(item), "duplicate {label}: {item:?}");
    }
    seen
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LanguageSpikeFixture {
    pub id: FixtureId,
    pub language: SpikeLanguage,
    pub provenance: &'static str,
    pub source: &'static str,
    pub rows: NormalizedFactRows,
    pub expected_targets: Box<[ExpectedTargetRow]>,
}

impl LanguageSpikeFixture {
    fn validated(self) -> Self {
        self.rows.assert_valid();
        for expected in &self.expected_targets {
            assert!(
                self.rows
                    .references
                    .iter()
                    .any(|row| row.node == expected.reference)
            );
            assert!(
                self.rows
                    .declarations
                    .iter()
                    .any(|row| row.node == expected.target)
            );
        }
        self
    }
}

const fn name(id: u16, spelling: &'static str) -> NameRow {
    NameRow {
        id: NameId::new(id),
        spelling,
    }
}

const fn scope(
    id: u16,
    parent: Option<u16>,
    owner: Option<u16>,
    kind: ScopeKind,
    start: u16,
    end: u16,
) -> ScopeRow {
    ScopeRow {
        id: ScopeId::new(id),
        parent: match parent {
            Some(id) => Some(ScopeId::new(id)),
            None => None,
        },
        owner: match owner {
            Some(id) => Some(NodeId::new(id)),
            None => None,
        },
        kind,
        start: SourcePosition::new(start),
        end: SourcePosition::new(end),
    }
}

const fn node(id: u16, scope: u16, position: u16, kind: NodeKind) -> NodeRow {
    NodeRow {
        id: NodeId::new(id),
        scope: ScopeId::new(scope),
        position: SourcePosition::new(position),
        kind,
    }
}

const fn declaration(
    node: u16,
    name: u16,
    namespace: Namespace,
    visible_from: u16,
) -> DeclarationRow {
    DeclarationRow {
        node: NodeId::new(node),
        name: NameId::new(name),
        namespace,
        visible_from: SourcePosition::new(visible_from),
    }
}

const fn reference(
    node: u16,
    name: u16,
    namespace: Namespace,
    qualifier: Option<u16>,
) -> ReferenceRow {
    ReferenceRow {
        node: NodeId::new(node),
        name: NameId::new(name),
        namespace,
        qualifier: match qualifier {
            Some(id) => Some(TypeSlotId::new(id)),
            None => None,
        },
    }
}

const fn slot(id: u16, node: u16, role: TypeSlotRole) -> TypeSlotRow {
    TypeSlotRow {
        id: TypeSlotId::new(id),
        node: NodeId::new(node),
        role,
    }
}

const fn projection(
    reference: u16,
    output: u16,
    projection: BindingProjectionKind,
) -> BindingProjectionRow {
    BindingProjectionRow {
        reference: NodeId::new(reference),
        output: TypeSlotId::new(output),
        projection,
    }
}

const fn transfer(
    input: u16,
    output: u16,
    kind: TypeTransferKind,
    indirection_delta: i8,
) -> TypeTransferRow {
    TypeTransferRow {
        input: TypeSlotId::new(input),
        output: TypeSlotId::new(output),
        kind,
        indirection_delta,
    }
}

const fn owner(member: u16, owner: u16, kind: MemberKind, access: MemberAccess) -> MemberOwnerRow {
    MemberOwnerRow {
        member: NodeId::new(member),
        owner: NodeId::new(owner),
        kind,
        access,
    }
}

pub(crate) fn java_qualified_nested_class_reference() -> LanguageSpikeFixture {
    LanguageSpikeFixture {
        id: FixtureId::JavaQualifiedNestedClassReference,
        language: SpikeLanguage::Java,
        provenance: "IntelliJ Community psi/resolve class/ClassExtendsItsInner1",
        source: "class A extends B.Foo implements B{\n}\n\ninterface B{\n  static class Foo{\n  }\n}\n",
        rows: NormalizedFactRows {
            names: Box::new([name(1, "A"), name(2, "B"), name(3, "Foo")]),
            scopes: Box::new([
                scope(1, None, None, ScopeKind::CompilationUnit, 0, 100),
                scope(2, Some(1), Some(1), ScopeKind::TypeBody, 22, 30),
                scope(3, Some(1), Some(4), ScopeKind::TypeBody, 41, 90),
                scope(4, Some(3), Some(5), ScopeKind::TypeBody, 51, 70),
            ]),
            nodes: Box::new([
                node(1, 1, 10, NodeKind::TypeDeclaration),
                node(2, 1, 20, NodeKind::TypeReference),
                node(3, 1, 21, NodeKind::MemberReference),
                node(4, 1, 40, NodeKind::InterfaceDeclaration),
                node(5, 3, 50, NodeKind::TypeDeclaration),
            ]),
            declarations: Box::new([
                declaration(1, 1, Namespace::Type, 0),
                declaration(4, 2, Namespace::Type, 0),
                declaration(5, 3, Namespace::Type, 41),
            ]),
            references: Box::new([
                reference(2, 2, Namespace::Type, None),
                reference(3, 3, Namespace::Member, Some(1)),
            ]),
            type_slots: Box::new([slot(1, 2, TypeSlotRole::ProjectionOutput)]),
            binding_projections: Box::new([projection(
                2,
                1,
                BindingProjectionKind::TargetTypeIdentity,
            )]),
            type_transfers: Box::new([]),
            intrinsic_type_seeds: Box::new([]),
            calls: Box::new([]),
            call_arguments: Box::new([]),
            callable_parameters: Box::new([]),
            member_owners: Box::new([owner(
                5,
                4,
                MemberKind::NestedType,
                MemberAccess::Type,
            )]),
            gaps: Box::new([]),
        },
        expected_targets: Box::new([ExpectedTargetRow {
            reference: NodeId::new(3),
            target: NodeId::new(5),
        }]),
    }
    .validated()
}

pub(crate) fn java_method_call_on_typed_local() -> LanguageSpikeFixture {
    LanguageSpikeFixture {
        id: FixtureId::JavaMethodCallOnTypedLocal,
        language: SpikeLanguage::Java,
        provenance: "IntelliJ Community psi/resolve method/Simple",
        source: "public class Simple {\n    public void method(String s) {\n    }\n\n    static {\n        Simple a = new Simple();\n        a.method(\"blah\");\n    }\n}\n",
        rows: NormalizedFactRows {
            names: Box::new([
                name(1, "Simple"),
                name(2, "method"),
                name(3, "String"),
                name(4, "s"),
                name(5, "a"),
            ]),
            scopes: Box::new([
                scope(1, None, None, ScopeKind::CompilationUnit, 0, 100),
                scope(2, Some(1), Some(1), ScopeKind::TypeBody, 10, 100),
                scope(3, Some(2), Some(2), ScopeKind::Executable, 11, 30),
                scope(4, Some(2), Some(5), ScopeKind::Initializer, 41, 90),
            ]),
            nodes: Box::new([
                node(1, 1, 1, NodeKind::TypeDeclaration),
                node(2, 2, 11, NodeKind::MethodDeclaration),
                node(3, 3, 12, NodeKind::TypeReference),
                node(4, 3, 13, NodeKind::ParameterDeclaration),
                node(5, 2, 40, NodeKind::Initializer),
                node(6, 4, 50, NodeKind::TypeReference),
                node(7, 4, 51, NodeKind::LocalDeclaration),
                node(8, 4, 60, NodeKind::ValueReference),
                node(9, 4, 61, NodeKind::MemberReference),
                node(10, 4, 62, NodeKind::StringLiteral),
                node(11, 4, 63, NodeKind::Call),
            ]),
            declarations: Box::new([
                declaration(1, 1, Namespace::Type, 0),
                declaration(2, 2, Namespace::Member, 10),
                declaration(4, 4, Namespace::Value, 13),
                declaration(7, 5, Namespace::Value, 52),
            ]),
            references: Box::new([
                reference(3, 3, Namespace::Type, None),
                reference(6, 1, Namespace::Type, None),
                reference(8, 5, Namespace::Value, None),
                reference(9, 2, Namespace::Member, Some(5)),
            ]),
            type_slots: Box::new([
                slot(1, 3, TypeSlotRole::ProjectionOutput),
                slot(2, 4, TypeSlotRole::ParameterValue),
                slot(3, 6, TypeSlotRole::ProjectionOutput),
                slot(4, 7, TypeSlotRole::DeclaredValue),
                slot(5, 8, TypeSlotRole::ProjectionOutput),
                slot(6, 10, TypeSlotRole::ExpressionValue),
            ]),
            binding_projections: Box::new([
                projection(3, 1, BindingProjectionKind::TargetTypeIdentity),
                projection(6, 3, BindingProjectionKind::TargetTypeIdentity),
                projection(8, 5, BindingProjectionKind::TargetDeclaredValueType),
            ]),
            type_transfers: Box::new([
                transfer(1, 2, TypeTransferKind::DeclaredType, 0),
                transfer(3, 4, TypeTransferKind::DeclaredType, 0),
            ]),
            intrinsic_type_seeds: Box::new([IntrinsicTypeSeedRow {
                output: TypeSlotId::new(6),
                intrinsic: IntrinsicType::JavaLangString,
                indirection: 0,
            }]),
            calls: Box::new([CallRow {
                node: NodeId::new(11),
                callee: NodeId::new(9),
            }]),
            call_arguments: Box::new([CallArgumentRow {
                call: NodeId::new(11),
                ordinal: 0,
                value: TypeSlotId::new(6),
            }]),
            callable_parameters: Box::new([CallableParameterRow {
                callable: NodeId::new(2),
                ordinal: 0,
                parameter: NodeId::new(4),
                value_type: TypeSlotId::new(2),
                repeated: false,
            }]),
            member_owners: Box::new([owner(
                2,
                1,
                MemberKind::Method,
                MemberAccess::Instance,
            )]),
            gaps: Box::new([]),
        },
        expected_targets: Box::new([ExpectedTargetRow {
            reference: NodeId::new(9),
            target: NodeId::new(2),
        }]),
    }
    .validated()
}

pub(crate) fn go_field_through_composite_literal_receiver() -> LanguageSpikeFixture {
    LanguageSpikeFixture {
        id: FixtureId::GoFieldThroughCompositeLiteralReceiver,
        language: SpikeLanguage::Go,
        provenance: "gopls internal/test/marker/testdata/definition/misc.txt random.go",
        source: "package a\n\ntype Typ struct{ field string }\n\nfunc useField() {\n\tx := &Typ{}\n\t_ = x.field\n}\n",
        rows: NormalizedFactRows {
            names: Box::new([
                name(1, "Typ"),
                name(2, "field"),
                name(3, "useField"),
                name(4, "x"),
            ]),
            scopes: Box::new([
                scope(1, None, None, ScopeKind::Package, 0, 100),
                scope(2, Some(1), Some(1), ScopeKind::TypeBody, 11, 30),
                scope(3, Some(1), Some(3), ScopeKind::Executable, 41, 100),
            ]),
            nodes: Box::new([
                node(1, 1, 10, NodeKind::TypeDeclaration),
                node(2, 2, 20, NodeKind::FieldDeclaration),
                node(3, 1, 40, NodeKind::FunctionDeclaration),
                node(4, 3, 50, NodeKind::TypeReference),
                node(5, 3, 51, NodeKind::CompositeLiteral),
                node(6, 3, 52, NodeKind::AddressOf),
                node(7, 3, 53, NodeKind::LocalDeclaration),
                node(8, 3, 60, NodeKind::ValueReference),
                node(9, 3, 61, NodeKind::MemberReference),
            ]),
            declarations: Box::new([
                declaration(1, 1, Namespace::Type, 0),
                declaration(2, 2, Namespace::Member, 11),
                declaration(3, 3, Namespace::Value, 0),
                declaration(7, 4, Namespace::Value, 54),
            ]),
            references: Box::new([
                reference(4, 1, Namespace::Type, None),
                reference(8, 4, Namespace::Value, None),
                reference(9, 2, Namespace::Member, Some(5)),
            ]),
            type_slots: Box::new([
                slot(1, 4, TypeSlotRole::ProjectionOutput),
                slot(2, 5, TypeSlotRole::ExpressionValue),
                slot(3, 6, TypeSlotRole::ExpressionValue),
                slot(4, 7, TypeSlotRole::DeclaredValue),
                slot(5, 8, TypeSlotRole::ProjectionOutput),
            ]),
            binding_projections: Box::new([
                projection(4, 1, BindingProjectionKind::TargetTypeIdentity),
                projection(8, 5, BindingProjectionKind::TargetDeclaredValueType),
            ]),
            type_transfers: Box::new([
                transfer(1, 2, TypeTransferKind::CompositeLiteral, 0),
                transfer(2, 3, TypeTransferKind::AddressOf, 1),
                transfer(3, 4, TypeTransferKind::ShortDeclaration, 0),
            ]),
            intrinsic_type_seeds: Box::new([]),
            calls: Box::new([]),
            call_arguments: Box::new([]),
            callable_parameters: Box::new([]),
            member_owners: Box::new([owner(
                2,
                1,
                MemberKind::Field,
                MemberAccess::Instance,
            )]),
            gaps: Box::new([]),
        },
        expected_targets: Box::new([ExpectedTargetRow {
            reference: NodeId::new(9),
            target: NodeId::new(2),
        }]),
    }
    .validated()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_nested_type_rows_are_exact_and_target_independent() {
        let fixture = java_qualified_nested_class_reference();
        assert_eq!(
            fixture.rows.scopes.as_ref(),
            [
                scope(1, None, None, ScopeKind::CompilationUnit, 0, 100),
                scope(2, Some(1), Some(1), ScopeKind::TypeBody, 22, 30),
                scope(3, Some(1), Some(4), ScopeKind::TypeBody, 41, 90),
                scope(4, Some(3), Some(5), ScopeKind::TypeBody, 51, 70),
            ]
        );
        assert_eq!(
            fixture.rows.references.as_ref(),
            [
                reference(2, 2, Namespace::Type, None),
                reference(3, 3, Namespace::Member, Some(1)),
            ]
        );
        assert_eq!(
            fixture.rows.binding_projections.as_ref(),
            [projection(2, 1, BindingProjectionKind::TargetTypeIdentity)]
        );
        assert_eq!(
            fixture.rows.member_owners.as_ref(),
            [owner(5, 4, MemberKind::NestedType, MemberAccess::Type)]
        );
        assert_eq!(
            fixture.expected_targets.as_ref(),
            [ExpectedTargetRow {
                reference: NodeId::new(3),
                target: NodeId::new(5),
            }]
        );
        assert!(fixture.rows.gaps.is_empty());
    }

    #[test]
    fn java_typed_local_rows_cover_slots_transfers_and_call_arguments() {
        let fixture = java_method_call_on_typed_local();
        assert_eq!(
            fixture.rows.type_slots.as_ref(),
            [
                slot(1, 3, TypeSlotRole::ProjectionOutput),
                slot(2, 4, TypeSlotRole::ParameterValue),
                slot(3, 6, TypeSlotRole::ProjectionOutput),
                slot(4, 7, TypeSlotRole::DeclaredValue),
                slot(5, 8, TypeSlotRole::ProjectionOutput),
                slot(6, 10, TypeSlotRole::ExpressionValue),
            ]
        );
        assert_eq!(
            fixture.rows.type_transfers.as_ref(),
            [
                transfer(1, 2, TypeTransferKind::DeclaredType, 0),
                transfer(3, 4, TypeTransferKind::DeclaredType, 0),
            ]
        );
        assert_eq!(
            fixture.rows.call_arguments.as_ref(),
            [CallArgumentRow {
                call: NodeId::new(11),
                ordinal: 0,
                value: TypeSlotId::new(6),
            }]
        );
        assert_eq!(
            fixture.rows.callable_parameters.as_ref(),
            [CallableParameterRow {
                callable: NodeId::new(2),
                ordinal: 0,
                parameter: NodeId::new(4),
                value_type: TypeSlotId::new(2),
                repeated: false,
            }]
        );
        assert_eq!(
            fixture.rows.member_owners.as_ref(),
            [owner(2, 1, MemberKind::Method, MemberAccess::Instance)]
        );
        assert!(fixture.rows.gaps.is_empty());
    }

    #[test]
    fn go_rows_preserve_composite_literal_and_pointer_transfer() {
        let fixture = go_field_through_composite_literal_receiver();
        assert_eq!(
            fixture.rows.type_transfers.as_ref(),
            [
                transfer(1, 2, TypeTransferKind::CompositeLiteral, 0),
                transfer(2, 3, TypeTransferKind::AddressOf, 1),
                transfer(3, 4, TypeTransferKind::ShortDeclaration, 0),
            ]
        );
        assert_eq!(
            fixture.rows.binding_projections.as_ref(),
            [
                projection(4, 1, BindingProjectionKind::TargetTypeIdentity),
                projection(8, 5, BindingProjectionKind::TargetDeclaredValueType),
            ]
        );
        assert_eq!(
            fixture.rows.member_owners.as_ref(),
            [owner(2, 1, MemberKind::Field, MemberAccess::Instance)]
        );
        assert_eq!(
            fixture.expected_targets.as_ref(),
            [ExpectedTargetRow {
                reference: NodeId::new(9),
                target: NodeId::new(2),
            }]
        );
        assert!(fixture.rows.gaps.is_empty());
    }
}
