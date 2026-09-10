//! Java's `TypeHierarchyProvider` impl and the two cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant walk moved to
//! [`brokk_bifrost_jvm::java::hierarchy`]. What stays is the moka ancestor
//! cache, the `OnceLock` descendant index, the persisted hierarchy row type the
//! walk reads through [`JavaHierarchyFact`], and the query-count test hooks.

use super::*;
use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey, declaration_set_digest};
use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::usages::{
    ExternalMemberFamilyAnswer, ExternalMemberFamilyIncompleteReason, ExternalMemberFamilyStatus,
    JvmExternalMemberIdentity, JvmReceiverSemantics, MemberFacts,
};
use crate::analyzer::{
    CodeUnitType, DescendantIndexScope, DirectDescendantIndex, ImportInfo, Range,
    descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use brokk_bifrost_jvm::java::hierarchy::{
    JavaExternalRootHierarchyAnswer, JavaExternalRootHierarchyIncompleteReason,
    JavaExternalRootHierarchyStatus, JavaHierarchyFact, build_java_direct_descendant_index,
    build_java_external_root_hierarchy, java_direct_ancestors,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

impl JavaHierarchyFact for HierarchyDeclarationFacts {
    fn declaration(&self) -> &CodeUnit {
        &self.declaration
    }

    fn primary_range(&self) -> Option<&Range> {
        self.primary_range.as_ref()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.raw_supertypes
    }
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = java_direct_ancestors(self, token, code_unit);
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let descendants = descendants_from_variant_index(
            &self.memo_caches.direct_descendant_index,
            scope,
            code_unit,
            || self.build_direct_descendant_index(scope),
        );
        if !scope.cancellation().is_cancelled()
            && let Some(descendants) = descendants.as_ref()
        {
            self.inner.record_read_key(ReadKey::lookup(
                LookupKind::Descendants,
                LookupQuestion::declaration(code_unit),
                declaration_set_digest(descendants),
            ));
        }
        descendants
    }
}

impl JavaAnalyzer {
    /// Resolve workspace implementations of a Java member whose owner is an
    /// external root. The Java analyzer owns the persisted hierarchy facts;
    /// `analyzer` supplies the realm-wide declarations for a MultiAnalyzer.
    pub(crate) fn resolve_external_member_family(
        &self,
        analyzer: &dyn IAnalyzer,
        identity: &JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        if identity.language() != Language::Java {
            return ExternalMemberFamilyAnswer::unsupported();
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return ExternalMemberFamilyAnswer::stopped(ExternalMemberFamilyStatus::Cancelled, 0);
        }
        if identity.receiver() == JvmReceiverSemantics::Static {
            return ExternalMemberFamilyAnswer {
                status: ExternalMemberFamilyStatus::Complete,
                candidates: Vec::new(),
                visited: 0,
            };
        }

        let hierarchy =
            self.external_root_hierarchy(identity.owner_fqn(), max_visits, cancellation);
        let status = match hierarchy.status {
            JavaExternalRootHierarchyStatus::Complete => None,
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
            ) => Some(ExternalMemberFamilyStatus::Incomplete(
                ExternalMemberFamilyIncompleteReason::HierarchyFactsUnavailable,
            )),
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
            ) => Some(ExternalMemberFamilyStatus::Incomplete(
                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
            )),
            JavaExternalRootHierarchyStatus::Cancelled => {
                Some(ExternalMemberFamilyStatus::Cancelled)
            }
            JavaExternalRootHierarchyStatus::BudgetExhausted => {
                Some(ExternalMemberFamilyStatus::BudgetExhausted)
            }
        };
        if let Some(status) = status {
            return ExternalMemberFamilyAnswer::stopped(status, hierarchy.visited);
        }

        let mut visited = hierarchy.visited;
        let mut candidates = Vec::new();
        for descendant in hierarchy.descendants {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::Cancelled,
                    visited,
                );
            }
            let children = analyzer.direct_children(&descendant);
            if children.len() > max_visits.saturating_sub(visited) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::BudgetExhausted,
                    visited,
                );
            }
            visited += children.len();
            let mut matching = Vec::new();
            for candidate in children {
                if !candidate.is_function() || candidate.identifier() != identity.member() {
                    continue;
                }
                let Some(facts) = MemberFacts::read(analyzer, &candidate) else {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::MemberFactsUnavailable,
                        visited,
                    );
                };
                if facts.universal_exclusion().is_some() || facts.is_static() {
                    continue;
                }
                let Some(arity) = facts.arity() else {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::MemberFactsUnavailable,
                        visited,
                    );
                };
                if arity.accepts(identity.arity()) {
                    matching.push(candidate);
                }
            }
            match matching.as_slice() {
                [] => {}
                [candidate] => candidates.push(candidate.clone()),
                _ => {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::OverloadIdentityUnproven,
                        visited,
                    );
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        ExternalMemberFamilyAnswer {
            status: ExternalMemberFamilyStatus::Complete,
            candidates,
            visited,
        }
    }

    pub(crate) fn external_root_hierarchy(
        &self,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> JavaExternalRootHierarchyAnswer {
        let Some(candidates) = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
        else {
            return JavaExternalRootHierarchyAnswer {
                status: brokk_bifrost_jvm::java::hierarchy::JavaExternalRootHierarchyStatus::Incomplete(
                    brokk_bifrost_jvm::java::hierarchy::JavaExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
                ),
                descendants: Vec::new(),
                visited: 0,
            };
        };
        build_java_external_root_hierarchy(
            candidates,
            |batch| {
                self.inner
                    .hydrate_hierarchy_declaration_facts(batch)
                    .is_some()
            },
            external_root_fqn,
            max_visits,
            cancellation,
        )
    }

    fn build_direct_descendant_index(
        &self,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<DirectDescendantIndex> {
        let _scope = crate::profiling::scope("JavaAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind_for_descendant_lookup(CodeUnitType::Class)?;
        let hydration_complete = AtomicBool::new(true);
        let index = build_java_direct_descendant_index(
            candidates,
            |batch| {
                let complete = self
                    .inner
                    .hydrate_hierarchy_declaration_facts_for_descendant_lookup(batch)
                    .is_some();
                if !complete {
                    hydration_complete.store(false, Ordering::Relaxed);
                }
                complete
            },
            scope,
        );
        if !hydration_complete.load(Ordering::Relaxed) || scope.cancellation().is_cancelled() {
            None
        } else {
            index
        }
    }

    #[doc(hidden)]
    pub fn reset_hierarchy_query_counts_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn hierarchy_definition_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }

    #[doc(hidden)]
    pub fn hierarchy_full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn hierarchy_bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn reset_definition_query_count_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
    }

    #[doc(hidden)]
    pub fn definition_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }
}
