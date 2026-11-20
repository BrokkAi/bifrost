//! Public C# hierarchy routing. The trial path uses selected normalized parents
//! and request-local completeness; the legacy path retains its existing memos.

use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::workspace_authority::{AuthorityInputs, memo_attribution};

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::{
    HierarchyAnswer, HierarchyOpenReason, TypeHierarchyProvider,
};

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_csharp::graph_support::CSharpSource;
use brokk_bifrost_csharp::hierarchy::{classify_unindexed_clauses, logical_direct_ancestors};
use std::sync::Arc;

use crate::analyzer::csharp::CSharpAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn with_hierarchy_query(&self, run: &mut dyn FnMut(&mut dyn HierarchyQuery)) {
        if self.csharp_config.native_trial.is_on() {
            self.native_hierarchy_query(run);
        } else {
            run(&mut LegacyQuery(self));
        }
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        if self.csharp_config.native_trial.is_on() {
            let mut answer = None;
            self.native_hierarchy_query(&mut |query| {
                answer = Some(query.direct_ancestors(code_unit))
            });
            return answer.expect("hierarchy callback runs once");
        }
        self.legacy_direct_ancestors(code_unit)
    }
    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        if self.csharp_config.native_trial.is_on() {
            return unavailable_descendants();
        }
        self.legacy_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&CancellationToken::default()),
        )
        .expect("an uncancelled descendant query cannot be cancelled")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, Cancelled> {
        if self.csharp_config.native_trial.is_on() {
            if scope.cancellation().is_cancelled() {
                return Err(Cancelled);
            }
            return Ok(unavailable_descendants());
        }
        self.legacy_direct_descendants_within(code_unit, scope)
    }
}

impl CSharpAnalyzer {
    fn legacy_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
        let ancestors = self
            .memo_caches
            .direct_ancestors
            .read(&memo_attribution(self), |cache, capture| {
                Ok::<_, std::convert::Infallible>(cache.get(code_unit).unwrap_or_else(|| {
                    let entry = Arc::new(capture.build_weighted(|| {
                        let mut ancestors = logical_direct_ancestors(self, token, code_unit, false);
                        classify_unindexed_clauses(self, token, &mut ancestors);
                        let bytes = super::cache::estimate_direct_ancestors(&ancestors) as usize;
                        (Arc::new(ancestors), bytes)
                    }));
                    if cache_fill.is_complete() {
                        cache.insert(code_unit.clone(), Arc::clone(&entry));
                    }
                    entry
                }))
            })
            .expect("ancestor memo build is infallible");
        ancestors.hierarchy_answer()
    }

    fn legacy_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.memo_caches
            .direct_descendant_index
            .read(
                &memo_attribution(self),
                |direct_descendant_index_memo| {
                    brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                        self,
                        scope,
                        code_unit,
                        direct_descendant_index_memo,
                        || build_direct_descendant_index(self, &LegacyQuery(self), scope),
                        |_| {},
                    )
                },
                |_| {
                    AuthorityInputs::SourceOf(&[
                        brokk_bifrost_core::analyzer::model::Language::CSharp,
                    ])
                },
            )
            .map(|mut answer| {
                if self.pack_open_reason(&code_unit.fq_name(), None).is_some()
                    || answer
                        .edges
                        .iter()
                        .any(|edge| self.pack_open_reason(&edge.fq_name(), None).is_some())
                {
                    answer
                        .open
                        .push(HierarchyOpenReason::DescendantIndexUnavailable);
                }
                answer
            })
    }
}

use brokk_bifrost_analysis::analyzer::native_hierarchy::{
    HierarchyConversionRules, convert, stopped,
};
use brokk_bifrost_analysis::analyzer::native_points::{
    open_native_point_operation_with_services, selected_analyzer_services,
};
use brokk_bifrost_analysis::analyzer::resolution::{
    ClassifiedSupertypeKind as C, NominalSupertypeKind as N,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::direct_supertypes::{
    DirectSupertype, DirectSupertypeAnswer,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
use brokk_bifrost_core::analyzer::capabilities::{
    Cancelled, HierarchyQuery, MemberFamilyAncestors,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

fn unavailable_descendants() -> HierarchyAnswer {
    // Native reverse discovery is tracked in #11897.
    HierarchyAnswer {
        open: vec![HierarchyOpenReason::DescendantIndexUnavailable],
        ..HierarchyAnswer::complete(Vec::new())
    }
}

struct LegacyQuery<'a>(&'a CSharpAnalyzer);
impl HierarchyQuery for LegacyQuery<'_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        self.0.legacy_direct_ancestors(unit)
    }
    fn direct_descendants(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        self.0
            .legacy_direct_descendants_within(
                unit,
                &DescendantIndexScope::whole_workspace(&CancellationToken::default()),
            )
            .expect("uncancelled")
    }
    fn direct_descendants_within(
        &mut self,
        unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, Cancelled> {
        self.0.legacy_direct_descendants_within(unit, scope)
    }
    fn member_family_ancestors(&mut self, unit: &CodeUnit) -> MemberFamilyAncestors {
        // The provider conversion preserves named external clauses from the
        // legacy ancestor memo as unread member-family evidence.
        self.0.member_family_ancestors(unit)
    }
}
struct NativeQuery<'a> {
    ancestors: &'a mut dyn FnMut(&CodeUnit) -> HierarchyAnswer,
}
impl HierarchyQuery for NativeQuery<'_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        (self.ancestors)(unit)
    }
    fn direct_descendants(&mut self, _: &CodeUnit) -> HierarchyAnswer {
        unavailable_descendants()
    }
    fn member_family_ancestors(&mut self, unit: &CodeUnit) -> MemberFamilyAncestors {
        let answer = self.direct_ancestors(unit);
        MemberFamilyAncestors {
            resolved: answer.edges,
            ambiguous: answer.ambiguous,
            unread: answer
                .open
                .into_iter()
                .filter_map(|reason| match reason {
                    HierarchyOpenReason::UnreadAncestor(ancestor) => Some(ancestor),
                    _ => None,
                })
                .collect(),
        }
    }
}
impl CSharpAnalyzer {
    fn native_hierarchy_query(&self, run: &mut dyn FnMut(&mut dyn HierarchyQuery)) {
        let _scope = AnalyzerQueryScope::new(self);
        let cancellation = self.inner.active_query_cancellation().unwrap_or_default();
        let session = ResolutionSession::unbounded();
        let services = selected_analyzer_services(self);
        // Descendant-only queries never open ancestor selection. The selected
        // operation is held by this query once its first ancestor step needs it.
        let operation =
            std::cell::LazyCell::new(|| {
                match open_native_point_operation_with_services(
                    &self.inner,
                    &services,
                    &cancellation,
                ) {
                    Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => Some(operation),
                    Ok(_) => None,
                    Err(error) => {
                        self.inner.record_query_failure(error);
                        None
                    }
                }
            });
        let mut ancestors = |unit: &CodeUnit| {
            let Some(operation) = (*operation).as_ref() else {
                return stopped();
            };
            let resolve = || -> brokk_bifrost_analysis::analyzer::store::Result<HierarchyAnswer> {
                if cancellation.is_cancelled() {
                    return Ok(stopped());
                }
                brokk_bifrost_analysis::CodeUnitIndex::get_declarations(&self.inner, unit.source());
                let SelectedResolutionOperationOutcome::Native(raw) =
                    operation.selected_normalized_direct_parents(unit, &cancellation, &session)?
                else {
                    return Ok(stopped());
                };
                let raw = DirectSupertypeAnswer {
                    completion: raw.completion,
                    parents: raw
                        .parents
                        .into_iter()
                        .map(|parent| DirectSupertype {
                            kind: parent.kind.map(|kind| match kind {
                                N::Superclass => C::Superclass,
                                N::Interface => C::Interface,
                                N::GoInterfaceElement => C::GoInterfaceElement,
                                N::ImplicitSuperclass => C::ImplicitSuperclass,
                                N::SelfType => C::SelfType,
                            }),
                            parent_ordinal: parent.ordinal,
                            reference: parent.reference,
                            applied_arguments: None,
                            targets: parent.targets.into_vec(),
                            completion: parent.completion,
                        })
                        .collect(),
                };
                convert(
                    operation,
                    raw,
                    &cancellation,
                    &session,
                    &HierarchyConversionRules {
                        intrinsic_provider: "csharp",
                        intrinsic_root: |_| None,
                        unread_inventory: |_| None,
                    },
                    |_| {},
                )
            };
            match resolve() {
                Ok(answer) => answer,
                Err(error) => {
                    self.inner.record_query_failure(error);
                    stopped()
                }
            }
        };
        run(&mut NativeQuery {
            ancestors: &mut ancestors,
        });
    }
}

impl TypeHierarchyProvider for LegacyQuery<'_> {
    fn get_direct_ancestors(&self, unit: &CodeUnit) -> HierarchyAnswer {
        self.0.legacy_direct_ancestors(unit)
    }
    fn get_direct_descendants(&self, unit: &CodeUnit) -> HierarchyAnswer {
        self.0
            .legacy_direct_descendants_within(
                unit,
                &DescendantIndexScope::whole_workspace(&CancellationToken::default()),
            )
            .expect("uncancelled")
    }
    fn get_direct_descendants_within(
        &self,
        unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, Cancelled> {
        self.0.legacy_direct_descendants_within(unit, scope)
    }
}
