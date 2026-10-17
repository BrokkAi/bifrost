use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionGapFact, ResolutionGapKind, ResolutionIdentifierRole, ResolutionNameFact,
    ResolutionNameId, ResolutionNamespace, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

use super::model::{
    BindingFragmentId, BindingNodeId, EndpointSignature, PartialPath, PrecedenceStep,
    ResolutionCompletion, SemanticId, StackPattern, TypeTransferRule, TypeTransferValueTransform,
    WitnessStep,
};

pub(crate) fn lowered_semantic_at(
    semantics: &[super::fact_lowering::LoweredSemanticSite],
    site: ResolutionSiteId,
    role: super::fact_lowering::LoweredSemanticRole,
) -> SemanticId {
    semantics
        .iter()
        .find(|semantic| semantic.site() == site && semantic.role() == role)
        .unwrap_or_else(|| panic!("lowered semantic {role:?} at {site:?}"))
        .semantic()
}

pub(crate) fn unsupported_expression_gap_facts() -> FileResolutionFacts {
    FileResolutionFacts {
        scopes: vec![ResolutionScopeFact {
            id: ResolutionScopeId::new(0),
            parent: None,
            owner: None,
            kind: ResolutionScopeKind::CompilationUnit,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: 0,
            end_byte: 100,
        }],
        sites: vec![ResolutionSiteFact {
            id: ResolutionSiteId::new(0),
            scope: ResolutionScopeId::new(0),
            kind: ResolutionSiteKind::UnsupportedExpression,
            start_byte: 20,
            end_byte: 21,
        }],
        gaps: vec![ResolutionGapFact {
            site: ResolutionSiteId::new(0),
            kind: ResolutionGapKind::UnsupportedExpression,
        }],
        ..FileResolutionFacts::default()
    }
}

pub(crate) fn semantic(value: &str) -> SemanticId {
    SemanticId::for_test(value.as_bytes())
}

pub(crate) fn fragment(value: &str) -> BindingFragmentId {
    BindingFragmentId::for_test(value.as_bytes())
}

pub(crate) fn node(value: &str) -> BindingNodeId {
    BindingNodeId::for_test(value.as_bytes())
}

pub(crate) fn name(id: u32, spelling: &str) -> ResolutionNameFact {
    ResolutionNameFact {
        id: ResolutionNameId::new(id),
        spelling: spelling.into(),
    }
}

pub(crate) fn scope(
    id: u32,
    parent: Option<u32>,
    owner: Option<u32>,
    kind: ResolutionScopeKind,
    start_byte: usize,
    end_byte: usize,
) -> ResolutionScopeFact {
    ResolutionScopeFact {
        id: ResolutionScopeId::new(id),
        parent: parent.map(ResolutionScopeId::new),
        owner: owner.map(ResolutionSiteId::new),
        kind,
        inheritance: ResolutionScopeInheritance::Lexical,
        start_byte,
        end_byte,
    }
}

pub(crate) fn site(
    id: u32,
    scope: u32,
    kind: ResolutionSiteKind,
    position: usize,
) -> ResolutionSiteFact {
    ResolutionSiteFact {
        id: ResolutionSiteId::new(id),
        scope: ResolutionScopeId::new(scope),
        kind,
        start_byte: position,
        end_byte: position + 1,
    }
}

pub(crate) fn identifier(
    site: u32,
    name: u32,
    role: ResolutionIdentifierRole,
    namespace: ResolutionNamespace,
    qualifier: Option<u32>,
) -> PositionedIdentifierFact {
    PositionedIdentifierFact {
        site: ResolutionSiteId::new(site),
        name: ResolutionNameId::new(name),
        role,
        namespace,
        qualifier: qualifier.map(ResolutionTypeSlotId::new),
    }
}

pub(crate) fn transfer(
    input: u32,
    output: u32,
    kind: ResolutionTypeTransferKind,
    indirection_delta: i8,
    value_transform: ResolutionTypeTransferValueTransform,
) -> ResolutionTypeTransferFact {
    ResolutionTypeTransferFact::new(
        ResolutionTypeSlotId::new(input),
        ResolutionTypeSlotId::new(output),
        kind,
        indirection_delta,
        0,
        value_transform,
    )
}

pub(crate) fn selected_transfer(
    owner: BindingFragmentId,
    semantic: SemanticId,
    source: SemanticId,
    target: SemanticId,
) -> super::fact_source::SelectedTypedRow<super::typed_fact_lowering::LoweredTypeTransfer> {
    selected_transfer_with(
        owner,
        semantic,
        source,
        target,
        0,
        TypeTransferValueTransform::Preserve,
        ResolutionCompletion::Complete,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn selected_transfer_with(
    owner: BindingFragmentId,
    semantic: SemanticId,
    source: SemanticId,
    target: SemanticId,
    indirection_delta: i64,
    value_transform: TypeTransferValueTransform,
    completion: ResolutionCompletion,
) -> super::fact_source::SelectedTypedRow<super::typed_fact_lowering::LoweredTypeTransfer> {
    super::fact_source::SelectedTypedRow::new(
        owner,
        super::typed_fact_lowering::LoweredTypeTransfer::new(
            source,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                semantic,
                target,
                indirection_delta,
                value_transform,
                completion,
            ),
        ),
    )
}

pub(crate) fn binder(
    declaration: u32,
    scope: u32,
    kind: ResolutionBinderKind,
    hoisting: HoistingClass,
    activation_start: usize,
    activation_end: usize,
) -> ResolutionBinderFact {
    ResolutionBinderFact {
        declaration: ResolutionSiteId::new(declaration),
        scope: ResolutionScopeId::new(scope),
        kind,
        hoisting,
        activation_start,
        activation_end,
    }
}

pub(crate) fn slot(id: u32, site: u32, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotFact {
    ResolutionTypeSlotFact {
        id: ResolutionTypeSlotId::new(id),
        site: ResolutionSiteId::new(site),
        role,
    }
}

pub(crate) fn endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
    scopes: impl Into<Box<[BindingNodeId]>>,
) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::closed(symbols),
        StackPattern::closed(scopes),
    )
}

pub(crate) fn partial_path(
    start: BindingNodeId,
    end: BindingNodeId,
    before: impl Into<Box<[SemanticId]>>,
    after: impl Into<Box<[SemanticId]>>,
    precedence: impl Into<Box<[PrecedenceStep]>>,
    completion: ResolutionCompletion,
) -> PartialPath {
    PartialPath::new(
        endpoint(start, before, Vec::new()),
        endpoint(end, after, Vec::new()),
        precedence,
        [WitnessStep::Node(end)],
        completion,
    )
}
