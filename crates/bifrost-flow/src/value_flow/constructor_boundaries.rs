//! Exact identity requirements for closing constructor boundaries.

use super::closes_as_resolved_constructor;
use crate::analyzer::Language;
use crate::analyzer::semantic::{
    DeferredInvocationKind, DispatchBoundaryKind, SemanticRole, SourcePosition, SourceSpan,
};

#[test]
fn constructor_closure_requires_an_exact_eager_target() {
    let target = crate::test_support::function_locator(
        "constructor-contract",
        "constructor.ts",
        Language::TypeScript,
        SemanticRole::Procedure,
        "Widget",
        SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(12, 0, 12)).unwrap(),
    );
    for boundary in [
        DispatchBoundaryKind::External(Some(target.clone())),
        DispatchBoundaryKind::Unmaterialized(target.clone()),
    ] {
        assert!(
            closes_as_resolved_constructor(&boundary),
            "exact target: {boundary:?}"
        );
    }
    for boundary in [
        DispatchBoundaryKind::External(None),
        DispatchBoundaryKind::Unresolved,
        DispatchBoundaryKind::Truncated,
        DispatchBoundaryKind::Deferred {
            target,
            kind: DeferredInvocationKind::Async,
        },
    ] {
        assert!(
            !closes_as_resolved_constructor(&boundary),
            "no exact eager constructor: {boundary:?}"
        );
    }
}
