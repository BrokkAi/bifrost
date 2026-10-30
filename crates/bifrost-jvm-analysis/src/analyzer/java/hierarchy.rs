//! Java's `TypeHierarchyProvider` impl and the two cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant walk moved to
//! [`brokk_bifrost_jvm::java::hierarchy`]. What stays is the moka ancestor
//! cache, the `OnceLock` descendant index, the persisted hierarchy row type the
//! walk reads through [`JavaHierarchyFact`], and the query-count test hooks.

use crate::analyzer::jvm::hierarchy::JvmHierarchyFact;

use crate::analyzer::java::*;

use brokk_bifrost_analysis::analyzer::read_ledger::LookupKind;

use brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion;

use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;

use brokk_bifrost_analysis::analyzer::read_ledger::declaration_set_digest;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyStatus;

use brokk_bifrost_jvm::realm::JvmExternalMemberIdentity;

use brokk_bifrost_jvm::realm::JvmReceiverSemantics;

use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFacts;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_jvm::java::hierarchy::{
    JavaExternalRootHierarchyAnswer, JavaExternalRootHierarchyIncompleteReason,
    JavaExternalRootHierarchyStatus, build_java_direct_descendant_index,
    build_java_external_root_hierarchy, java_direct_ancestors,
};
use std::sync::atomic::{AtomicBool, Ordering};

use brokk_bifrost_core::analyzer::capabilities::{
    MemberFamilyAncestors, PlatformInventoryMethod, UnreadMemberFamilyAncestor,
};
use brokk_bifrost_jvm::intrinsics::{implicit_interface_members, overridable_method_inventory};
use brokk_bifrost_jvm::java::graph_support::{
    java_type_name_candidate_fqns, resolve_java_lexical_type_name,
};

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        crate::analyzer::jvm::hierarchy::memoized_ancestors(
            &self.memo_caches.direct_ancestors,
            self,
            code_unit,
            || java_direct_ancestors(self, token, code_unit),
        )
    }

    fn member_family_ancestors(&self, owner: &CodeUnit) -> MemberFamilyAncestors {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let mut unread = Vec::new();
        for name in self.raw_supertypes_of(owner) {
            if resolve_java_lexical_type_name(self, owner, &name)
                .or_else(|| self.resolve_imported_type_name(token, owner.source(), &name))
                .is_none()
            {
                unread.push(UnreadMemberFamilyAncestor {
                    name,
                    inventory: None,
                });
            }
        }
        // Every class ultimately inherits Object. Inventory matching and name
        // deduplication avoid reparsing each frontier owner for its superclass.
        let interface = self
            .signature_metadata(owner)
            .iter()
            .any(|entry| entry.class_like_is_interface());
        let root = match self.declaration_syntax_kind(owner) {
            Some("enum_declaration") => Some("java.lang.Enum"),
            Some("record_declaration") => Some("java.lang.Record"),
            Some("interface_declaration" | "annotation_type_declaration") => {
                Some("java.lang.Object")
            }
            _ if interface => Some("java.lang.Object"),
            _ => Some("java.lang.Object"),
        };
        if let Some(name) = root {
            let inventory = if interface {
                implicit_interface_members(Language::Java).map(|root| root.methods)
            } else {
                overridable_method_inventory(name)
            };
            unread.push(UnreadMemberFamilyAncestor {
                name: name.into(),
                inventory,
            });
        }
        MemberFamilyAncestors {
            resolved: self.get_direct_ancestors(owner),
            unread,
        }
    }

    fn member_family_inventory_matches(
        &self,
        member: &CodeUnit,
        inventory: &[PlatformInventoryMethod],
    ) -> bool {
        let methods: Vec<_> = inventory
            .iter()
            .filter(|method| method.name == member.identifier())
            .collect();
        if methods.is_empty() {
            return false;
        }
        let metadata = self.signature_metadata(member);
        let Some(parameter_types) = metadata
            .first()
            .and_then(|entry| entry.callable_parameter_types())
        else {
            return true;
        };
        let methods: Vec<_> = methods
            .into_iter()
            .filter(|method| method.parameters.len() == parameter_types.len())
            .collect();
        if methods.is_empty() {
            return false;
        }
        if methods.iter().any(|method| method.parameters.is_empty()) {
            return true;
        }
        let Some(parameters) = self.java_erased_member_parameters(member) else {
            return true;
        };
        methods.iter().any(|method| {
            parameters
                .iter()
                .map(String::as_str)
                .eq(method.parameters.iter().copied())
        })
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
        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaDescendantIndex,
        );

        let descendants = descendants_from_variant_index(
            &self.memo_caches.direct_descendant_index,
            scope,
            code_unit,
            || {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                    self.build_direct_descendant_index(scope)
                })
                .ok()
                .flatten()
            },
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
    /// Erase the grammar's type nodes, then resolve nominal identities using
    /// Java's lexical/import tiers. No signature spelling is parsed here.
    fn java_erased_member_parameters(&self, member: &CodeUnit) -> Option<Vec<String>> {
        use crate::analyzer::java::imports::JavaTypeResolution;
        use brokk_bifrost_jvm::java::declarations::spread_parameter_type_node;
        use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
        use brokk_bifrost_jvm::java::graph_support::{
            java_type_parameter_bounds, java_type_parameter_in_scope,
        };
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let source = self.inner.project().read_source(member.source()).ok()?;
        let tree = parse_tree(&source)?;
        let ranges = self.ranges(member);
        let range = ranges.first()?;
        let mut callable = tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        while !matches!(
            callable.kind(),
            "method_declaration" | "constructor_declaration"
        ) {
            callable = callable.parent()?;
        }
        let parameters = callable.child_by_field_name("parameters")?;
        let mut erased = Vec::new();
        for parameter in parameters.named_children(&mut parameters.walk()) {
            if !matches!(parameter.kind(), "formal_parameter" | "spread_parameter") {
                continue;
            }
            let mut ty = parameter
                .child_by_field_name("type")
                .or_else(|| spread_parameter_type_node(parameter))?;
            // These fixed platform inventories contain no array parameters,
            // so an array or varargs parameter cannot match them.
            if parameter.kind() == "spread_parameter"
                || parameter.child_by_field_name("dimensions").is_some()
            {
                erased.push("<array>".into());
                continue;
            }
            let mut seen = Vec::new();
            let identity = loop {
                if seen.contains(&ty.id()) {
                    return None;
                }
                seen.push(ty.id());
                match ty.kind() {
                    "array_type" => break "<array>".into(),
                    "generic_type" | "annotated_type" => {
                        ty = ty.named_children(&mut ty.walk()).find(|child| {
                            brokk_bifrost_jvm::java::graph::return_type::is_java_nominal_type_node(
                                child.kind(),
                            )
                        })?;
                    }
                    "integral_type" | "floating_point_type" | "boolean_type" => {
                        break node_text(ty, &source).to_owned();
                    }
                    _ => {
                        let components = java_type_name_components(ty, &source)?;
                        let name = components.join(".");
                        if let Some(bound) = java_type_parameter_in_scope(ty, &source, &name) {
                            if let Some(first) = java_type_parameter_bounds(bound).first() {
                                ty = *first;
                                continue;
                            }
                            break "java.lang.Object".into();
                        }
                        if let Some(resolved) = resolve_java_lexical_type_name(self, member, &name)
                        {
                            break resolved.fq_name().to_string();
                        }
                        if let Some(resolved) = self.resolve_type_name_with_external(
                            token,
                            None,
                            member.source(),
                            &name,
                        ) {
                            break match resolved {
                                JavaTypeResolution::Source(unit) => unit.fq_name().to_string(),
                                JavaTypeResolution::External(ty) => ty.fqn().to_owned(),
                            };
                        }
                        // The fixed intrinsic inventory supplies the Object
                        // nominal declaration even without an indexed JDK. Use
                        // the resolver's import tiers, including shadowing.
                        let candidates =
                            java_type_name_candidate_fqns(self, token, member.source(), &name);
                        if candidates
                            .iter()
                            .any(|candidate| candidate == "java.lang.Object")
                        {
                            break "java.lang.Object".into();
                        }
                        return None;
                    }
                }
            };
            erased.push(identity);
        }
        Some(erased)
    }

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
            candidates.into_iter().map(JvmHierarchyFact).collect(),
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
        let _scope =
            brokk_bifrost_core::profiling::scope("JavaAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind_for_descendant_lookup(CodeUnitType::Class)?;
        let hydration_complete = AtomicBool::new(true);
        let index = build_java_direct_descendant_index(
            candidates.into_iter().map(JvmHierarchyFact).collect(),
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
