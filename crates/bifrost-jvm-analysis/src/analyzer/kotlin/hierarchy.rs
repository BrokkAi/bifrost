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

use crate::analyzer::jvm::hierarchy::JvmHierarchyFact;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyStatus;

use brokk_bifrost_jvm::realm::JvmExternalMemberIdentity;

use brokk_bifrost_jvm::realm::JvmReceiverSemantics;

use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFacts;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::kotlin::hierarchy::{
    KotlinExternalRootHierarchyAnswer, KotlinExternalRootHierarchyIncompleteReason,
    KotlinExternalRootHierarchyStatus, build_kotlin_direct_descendant_index,
    build_kotlin_external_root_hierarchy, kotlin_resolve_direct_ancestors,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;

use crate::analyzer::kotlin::KotlinAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

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

        MemberFacts::external_descendant_family(
            analyzer,
            hierarchy.descendants,
            hierarchy.visited,
            identity.member(),
            identity.arity(),
            max_visits,
            cancellation,
        )
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
            candidates.into_iter().map(JvmHierarchyFact).collect(),
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
        crate::analyzer::jvm::hierarchy::memoized_ancestors(cache, self, code_unit, || {
            kotlin_resolve_direct_ancestors(self, token, code_unit, realm)
        })
    }

    pub(crate) fn direct_descendants_in_realm(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        crate::analyzer::jvm::authority::source_read(self, match realm {
            Some(_) => brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::KotlinRealmDescendantIndex,
            None => brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::KotlinDescendantIndex,
        });
        let index = match realm {
            Some(_) => &self.realm_direct_descendant_index,
            None => &self.direct_descendant_index,
        };
        descendants_from_variant_index(index, scope, code_unit, || {
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                self.build_direct_descendant_index(token, realm, scope)
            })
            .ok()
            .flatten()
        })
    }

    fn build_direct_descendant_index(
        &self,
        token: QueryToken<'_>,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<DirectDescendantIndex> {
        let _scope =
            brokk_bifrost_core::profiling::scope("KotlinAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        build_kotlin_direct_descendant_index(
            candidates.into_iter().map(JvmHierarchyFact).collect(),
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
impl brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider
    for KotlinAnalyzer
{
    fn member_family_capability(
        &self,
        _member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability::Unsupported
    }

    fn member_family(
        &self,
        _member: &CodeUnit,
        _cancellation: Option<&CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer::unsupported_answer()
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
