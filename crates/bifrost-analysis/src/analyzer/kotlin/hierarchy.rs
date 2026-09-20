//! `KotlinAnalyzer`'s `TypeHierarchyProvider` impl and the four realm-keyed
//! cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant inversion moved
//! to [`brokk_bifrost_jvm::kotlin::hierarchy`]. What stays is the two moka
//! ancestor caches, the two memoized descendant indexes, and the persisted
//! hierarchy row type the walk reads through [`KotlinHierarchyFact`]. Each pair
//! is realm-keyed because the realm-aware and realm-less answers are different
//! questions, and a Kotlin-only entry must never be served to a caller that can
//! see Java and Scala declarations too.

use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::usages::{
    ExternalMemberFamilyAnswer, ExternalMemberFamilyIncompleteReason, ExternalMemberFamilyStatus,
    JvmExternalMemberIdentity, JvmReceiverSemantics, MemberFacts,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, DescendantIndexScope, DirectDescendantIndex, IAnalyzer, ImportInfo,
    Language, TypeHierarchyProvider, descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::kotlin::hierarchy::{
    KotlinExternalRootHierarchyAnswer, KotlinExternalRootHierarchyIncompleteReason,
    KotlinExternalRootHierarchyStatus, KotlinHierarchyFact, build_kotlin_direct_descendant_index,
    build_kotlin_external_root_hierarchy, kotlin_resolve_direct_ancestors,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

impl KotlinHierarchyFact for HierarchyDeclarationFacts {
    fn declaration(&self) -> &CodeUnit {
        &self.declaration
    }

    fn primary_range(&self) -> Option<crate::analyzer::Range> {
        self.primary_range
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.raw_supertypes
    }
}

impl TypeHierarchyProvider for KotlinAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        self.direct_ancestors_in_realm(token, code_unit, None)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let uncancelled = CancellationToken::default();
        self.direct_descendants_in_realm(
            token,
            code_unit,
            None,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        self.direct_descendants_in_realm(token, code_unit, None, scope)
    }
}

impl KotlinAnalyzer {
    /// Resolve workspace implementations of a Kotlin member whose owner is an
    /// external root. This is the Kotlin arm of the JVM external member-family
    /// seam (#2580); the Java analyzer owns the Java arm, and each answers only
    /// for its own call-site language.
    pub(crate) fn resolve_external_member_family(
        &self,
        analyzer: &dyn IAnalyzer,
        identity: &JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        assert_eq!(
            identity.language(),
            Language::Kotlin,
            "the Kotlin analyzer answers only Kotlin call sites; the composite routes the rest"
        );
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
            KotlinExternalRootHierarchyStatus::Complete => None,
            KotlinExternalRootHierarchyStatus::Incomplete(
                KotlinExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
            ) => Some(ExternalMemberFamilyStatus::Incomplete(
                ExternalMemberFamilyIncompleteReason::HierarchyFactsUnavailable,
            )),
            KotlinExternalRootHierarchyStatus::Incomplete(
                KotlinExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
            ) => Some(ExternalMemberFamilyStatus::Incomplete(
                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
            )),
            KotlinExternalRootHierarchyStatus::Cancelled => {
                Some(ExternalMemberFamilyStatus::Cancelled)
            }
            KotlinExternalRootHierarchyStatus::BudgetExhausted => {
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

    fn external_root_hierarchy(
        &self,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> KotlinExternalRootHierarchyAnswer {
        let Some(candidates) = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
        else {
            return KotlinExternalRootHierarchyAnswer {
                status: KotlinExternalRootHierarchyStatus::Incomplete(
                    KotlinExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
                ),
                descendants: Vec::new(),
                visited: 0,
            };
        };
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        build_kotlin_external_root_hierarchy(
            candidates,
            |batch| {
                self.inner
                    .hydrate_hierarchy_declaration_facts(batch)
                    .is_some()
            },
            self,
            token,
            external_root_fqn,
            max_visits,
            cancellation,
        )
    }

    /// Direct ancestors of a Kotlin declaration, widened to the whole JVM
    /// source realm when a realm view is supplied.
    pub(crate) fn direct_ancestors_in_realm(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Vec<CodeUnit> {
        let cache = match realm {
            Some(_) => &self.realm_direct_ancestors,
            None => &self.direct_ancestors,
        };
        if let Some(cached) = cache.get(code_unit) {
            return (*cached).clone();
        }
        let ancestors = kotlin_resolve_direct_ancestors(self, token, code_unit, realm);
        cache.insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    pub(crate) fn direct_descendants_in_realm(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let index = match realm {
            Some(_) => &self.realm_direct_descendant_index,
            None => &self.direct_descendant_index,
        };
        descendants_from_variant_index(index, scope, code_unit, || {
            self.build_direct_descendant_index(token, realm, scope)
        })
    }

    fn build_direct_descendant_index(
        &self,
        token: QueryToken<'_>,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<DirectDescendantIndex> {
        let _scope = crate::profiling::scope("KotlinAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        build_kotlin_direct_descendant_index(
            candidates,
            |batch| {
                self.inner
                    .hydrate_hierarchy_declaration_facts(batch)
                    .is_some()
            },
            self,
            realm,
            scope,
            token,
        )
    }
}

/// Kotlin's half of the #1477 member-family capability.
///
/// The workspace member's own family stays `unsupported` for the reason the
/// total support table states: Kotlin's ancestor walk does not distinguish an
/// interface edge from a superclass edge, so an edge's relation would be
/// unstatable. What Kotlin does answer is the *external-root* question (#2580):
/// the workspace declarations that implement one exact JDK member, enumerated
/// from the JVM realm's own supertype facts. Publishing the provider with that
/// one answered half is what lets the composite route the external identity to
/// this analyzer instead of refusing the whole JVM realm.
impl crate::analyzer::usages::MemberFamilyProvider for KotlinAnalyzer {
    fn member_family_capability(
        &self,
        _member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        crate::analyzer::structural::resolution::MemberFamilyCapability::Unsupported
    }

    fn member_family(
        &self,
        _member: &CodeUnit,
        _cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::MemberFamilyAnswer::unsupported_answer()
    }

    fn external_member_family(
        &self,
        identity: &JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        self.resolve_external_member_family(self, identity, max_visits, cancellation)
    }
}
