#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeInheritance;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferFact;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferValueTransform;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

#[cfg(any(test, feature = "test-support"))]
use super::model::BindingFragmentId;

#[cfg(any(test, feature = "test-support"))]
use super::model::BindingNodeId;

#[cfg(any(test, feature = "test-support"))]
use super::model::EndpointSignature;

#[cfg(any(test, feature = "test-support"))]
use super::model::PartialPath;

#[cfg(any(test, feature = "test-support"))]
use super::model::PrecedenceStep;

#[cfg(any(test, feature = "test-support"))]
use super::model::ResolutionCompletion;

use super::model::SemanticId;

#[cfg(any(test, feature = "test-support"))]
use super::model::StackPattern;

#[cfg(any(test, feature = "test-support"))]
use super::model::TypeTransferRule;

#[cfg(any(test, feature = "test-support"))]
use super::model::TypeTransferValueTransform;

#[cfg(any(test, feature = "test-support"))]
use super::model::WitnessStep;

#[doc(hidden)]
pub fn lowered_semantic_at(
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

#[cfg(any(test, feature = "test-support"))]
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
        gaps: vec![ResolutionGapFact::new(
            ResolutionSiteId::new(0),
            ResolutionGapKind::UnsupportedExpression,
        )],
        ..FileResolutionFacts::default()
    }
}

#[doc(hidden)]
pub fn semantic(value: &str) -> SemanticId {
    SemanticId::for_test(value.as_bytes())
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn fragment(value: &str) -> BindingFragmentId {
    BindingFragmentId::for_test(value.as_bytes())
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn node(value: &str) -> BindingNodeId {
    BindingNodeId::for_test(value.as_bytes())
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn name(id: u32, spelling: &str) -> ResolutionNameFact {
    ResolutionNameFact {
        id: ResolutionNameId::new(id),
        spelling: spelling.into(),
    }
}

#[doc(hidden)]
pub fn scope(
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

#[doc(hidden)]
pub fn site(id: u32, scope: u32, kind: ResolutionSiteKind, position: usize) -> ResolutionSiteFact {
    ResolutionSiteFact {
        id: ResolutionSiteId::new(id),
        scope: ResolutionScopeId::new(scope),
        kind,
        start_byte: position,
        end_byte: position + 1,
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn identifier(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn transfer(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_transfer(
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

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn selected_transfer_with(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn binder(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn slot(id: u32, site: u32, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotFact {
    ResolutionTypeSlotFact {
        id: ResolutionTypeSlotId::new(id),
        site: ResolutionSiteId::new(site),
        role,
    }
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

/// Synthetic fragment identity for a test fixture.
pub fn fixture_fragment(label: &[u8]) -> BindingFragmentId {
    BindingFragmentId::for_test(label)
}
