//! Java's `TypeHierarchyProvider` impl and the two cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant walk moved to
//! [`brokk_bifrost_jvm::java::hierarchy`]. What stays is the moka ancestor
//! cache, the `OnceLock` descendant index, the persisted hierarchy row type the
//! walk reads through [`JavaHierarchyFact`], and the query-count test hooks.

use crate::analyzer::jvm::hierarchy::JvmHierarchyFact;
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;

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

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_jvm::java::hierarchy::{
    JavaExternalRootHierarchyAnswer, JavaExternalRootHierarchyIncompleteReason,
    JavaExternalRootHierarchyIndex, JavaExternalRootHierarchyStatus,
    build_java_direct_descendant_index, java_direct_ancestors,
};
use std::sync::atomic::{AtomicBool, Ordering};

use brokk_bifrost_core::analyzer::capabilities::{
    MemberFamilyAncestors, MemberFamilyParameterType, MemberFamilySupertypeArguments,
    UnreadMemberFamilyAncestor,
};
use brokk_bifrost_jvm::intrinsics::{implicit_interface_members, overridable_method_inventory};
use brokk_bifrost_jvm::java::graph_support::{
    java_type_name_candidate_fqns, resolve_java_lexical_type_name,
};

impl JavaAnalyzer {
    pub(crate) fn legacy_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        HierarchyAnswer::complete(crate::analyzer::jvm::hierarchy::memoized_ancestors(
            &self.memo_caches.direct_ancestors,
            self,
            code_unit,
            || java_direct_ancestors(self, token, code_unit),
        ))
    }
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn with_hierarchy_query(
        &self,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
            self.native_hierarchy_query(None, run);
            return;
        }
        run(&mut brokk_bifrost_core::analyzer::capabilities::ForwardingHierarchyQuery(self));
    }

    fn with_hierarchy_query_for(
        &self,
        _root: &CodeUnit,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
            self.native_hierarchy_query(Some(_root), run);
            return;
        }
        run(&mut brokk_bifrost_core::analyzer::capabilities::ForwardingHierarchyQuery(self));
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
            let mut answer = None;
            self.with_hierarchy_query_for(code_unit, &mut |query| {
                answer = Some(query.direct_ancestors(code_unit))
            });
            return answer.expect("hierarchy query runs once");
        }
        self.legacy_direct_ancestors(code_unit)
    }

    fn member_family_ancestors(&self, owner: &CodeUnit) -> MemberFamilyAncestors {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
            let mut answer = None;
            self.with_hierarchy_query_for(owner, &mut |query| {
                answer = Some(query.member_family_ancestors(owner))
            });
            return answer.expect("hierarchy query runs once");
        }
        self.legacy_member_family_ancestors(owner)
    }

    fn member_family_parameter_arity(&self, member: &CodeUnit) -> Option<usize> {
        self.signature_metadata(member)
            .first()
            .and_then(|entry| entry.callable_parameter_types())
            .map(<[String]>::len)
    }

    fn member_family_erased_parameters(&self, member: &CodeUnit) -> Option<Vec<String>> {
        self.java_erased_member_parameters(member)
    }

    fn member_family_parameter_types(
        &self,
        member: &CodeUnit,
    ) -> Option<Vec<MemberFamilyParameterType>> {
        self.java_member_family_parameter_types(member)
    }

    fn member_family_supertype_arguments(
        &self,
        subtype: &CodeUnit,
        supertype: &CodeUnit,
    ) -> MemberFamilySupertypeArguments {
        self.java_member_family_supertype_arguments(subtype, supertype)
            .unwrap_or(MemberFamilySupertypeArguments::Unknown)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("an uncancelled descendant query cannot be cancelled")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA").is_some() {
            if scope.cancellation().is_cancelled() {
                return Err(brokk_bifrost_core::analyzer::capabilities::Cancelled);
            }
            let mut answer = None;
            self.with_hierarchy_query_for(code_unit, &mut |query| {
                answer = Some(query.direct_descendants_within(code_unit, scope));
            });
            return answer.expect("hierarchy query runs once");
        }

        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaDescendantIndex,
        );
        brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
            self,
            scope,
            code_unit,
            &self.memo_caches.direct_descendant_index,
            || self.build_direct_descendant_index(scope),
            |descendants| {
                self.inner.record_read_key(ReadKey::lookup(
                    LookupKind::Descendants,
                    LookupQuestion::declaration(code_unit),
                    declaration_set_digest(descendants),
                ));
            },
        )
    }
}

/// The workspace descendants of each external root, per active model set,
/// root and visit budget, with the certificate that names the answer. Every
/// virtual call on an external owner asks this; the walk visits every
/// workspace type.
pub(crate) type ExternalRootDescendantsMemo = crate::analyzer::jvm::hierarchy::DerivedMemo<
    (
        Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest>,
        Box<str>,
        usize,
    ),
    ExternalRootDescendants,
>;

pub(crate) fn fresh_external_root_descendants(
    memo_budget: u64,
) -> Arc<ExternalRootDescendantsMemo> {
    Arc::new(crate::analyzer::jvm::hierarchy::derived_memo(
        memo_budget / 16,
    ))
}

/// One external root's workspace descendants with the reason a workspace
/// supertype nothing resolves keeps its families open, retained per snapshot,
/// model set, root and visit budget.
pub(crate) struct ExternalRootDescendants {
    /// The walk's answer without its unmatched supertypes, which only the
    /// unresolved-supertype report reads.
    pub(crate) hierarchy: JavaExternalRootHierarchyAnswer,
    unresolved_supertype: Option<Box<str>>,
}

impl ExternalRootDescendants {
    /// The answer a `JavaExternalRootDescendants` certificate names: every
    /// field a member family reads, and the reported gap.
    pub(super) fn digest(&self) -> brokk_bifrost_analysis::analyzer::semantic::StableDigest {
        let mut digest = brokk_bifrost_analysis::analyzer::semantic::LengthDelimitedDigest::new(
            b"java-external-root-descendants/v1",
        );
        match &self.hierarchy.status {
            JavaExternalRootHierarchyStatus::Complete => digest.push(b"complete"),
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
            ) => digest.push(b"hierarchy_facts_unavailable"),
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
            ) => digest.push(b"ambiguous_supertype"),
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(name),
            ) => {
                digest.push(b"unresolved_supertype");
                digest.push(name.as_bytes());
            }
            JavaExternalRootHierarchyStatus::Cancelled => digest.push(b"cancelled"),
            JavaExternalRootHierarchyStatus::BudgetExhausted => digest.push(b"budget_exhausted"),
        }
        digest.push(
            &u64::try_from(self.hierarchy.visited)
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        let mut descendants = self
            .hierarchy
            .descendants
            .iter()
            .map(|unit| {
                (
                    brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(
                        unit.source().rel_path(),
                    ),
                    unit.fq_name(),
                )
            })
            .collect::<Vec<_>>();
        descendants.sort();
        for (path, name) in descendants {
            digest.push(path.as_bytes());
            digest.push(name.as_bytes());
        }
        match &self.unresolved_supertype {
            Some(gap) => {
                digest.push(b"gap");
                digest.push(gap.as_bytes());
            }
            None => digest.push(b"no_gap"),
        }
        digest.finish()
    }
}

impl JavaAnalyzer {
    /// The platform-inventory spelling of the member's erased parameters: a
    /// primitive keyword, a fully qualified name, or `<array>` for any array.
    /// The fixed platform inventories contain no array parameters, so an array
    /// cannot match them whatever its element type.
    fn java_erased_member_parameters(&self, member: &CodeUnit) -> Option<Vec<String>> {
        fn inventory_spelling(ty: &MemberFamilyParameterType) -> Option<String> {
            match ty {
                MemberFamilyParameterType::Primitive(name)
                | MemberFamilyParameterType::Nominal(name) => Some(name.clone()),
                MemberFamilyParameterType::Array(_) => Some("<array>".into()),
                MemberFamilyParameterType::OwnerTypeParameter { erasure, .. } => {
                    inventory_spelling(erasure)
                }
                MemberFamilyParameterType::Unresolved(_) => None,
            }
        }
        self.java_member_family_parameter_types(member)?
            .iter()
            .map(inventory_spelling)
            .collect()
    }

    /// Erase the grammar's type nodes, then resolve nominal identities using
    /// Java's lexical/import tiers. No signature spelling is parsed here.
    fn java_member_family_parameter_types(
        &self,
        member: &CodeUnit,
    ) -> Option<Vec<MemberFamilyParameterType>> {
        use brokk_bifrost_jvm::java::declarations::spread_parameter_type_node;
        let source = self.inner.project().read_source(member.source()).ok()?;
        let tree = parse_tree(&source)?;
        let callable = self.java_declaration_node(
            &tree,
            member,
            &["method_declaration", "constructor_declaration"],
        )?;
        let owner = java_owner_declaration(callable);
        let parameters = callable.child_by_field_name("parameters")?;
        let reader = JavaMemberFamilyTypeReader {
            java: self,
            scope: member,
            source: &source,
            owner,
        };
        let mut types = Vec::new();
        for parameter in parameters.named_children(&mut parameters.walk()) {
            if !matches!(parameter.kind(), "formal_parameter" | "spread_parameter") {
                continue;
            }
            let ty = parameter
                .child_by_field_name("type")
                .or_else(|| spread_parameter_type_node(parameter))?;
            let mut ty = reader.read(ty);
            // `int x[]` writes its dimensions on the parameter, and `T... x`
            // is an array of `T`.
            for _ in 0..parameter
                .child_by_field_name("dimensions")
                .map_or(0, java_dimension_count)
                + usize::from(parameter.kind() == "spread_parameter")
            {
                ty = MemberFamilyParameterType::Array(Box::new(ty));
            }
            types.push(ty);
        }
        Some(types)
    }

    /// The type arguments `subtype`'s declaration passes to `supertype`.
    fn java_member_family_supertype_arguments(
        &self,
        subtype: &CodeUnit,
        supertype: &CodeUnit,
    ) -> Option<MemberFamilySupertypeArguments> {
        use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
        use brokk_bifrost_jvm::java::graph_support::java_type_argument_nodes;
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let source = self.inner.project().read_source(subtype.source()).ok()?;
        let tree = parse_tree(&source)?;
        let declaration =
            self.java_declaration_node(&tree, subtype, JAVA_TYPE_DECLARATION_KINDS)?;
        let mut clauses = Vec::new();
        for field in ["superclass", "interfaces"] {
            clauses.extend(declaration.child_by_field_name(field));
        }
        clauses.extend(
            declaration
                .named_children(&mut declaration.walk())
                .filter(|child| child.kind() == "extends_interfaces"),
        );
        let mut named = Vec::new();
        for clause in clauses {
            // `superclass` holds the type itself; the interface clauses hold a
            // `type_list` of them.
            let mut types: Vec<_> = clause.named_children(&mut clause.walk()).collect();
            if let [list] = types.as_slice()
                && list.kind() == "type_list"
            {
                types = list.named_children(&mut list.walk()).collect();
            }
            for ty in types {
                let name = java_type_name_components(ty, &source)?.join(".");
                let resolved = resolve_java_lexical_type_name(self, subtype, &name)
                    .or_else(|| self.resolve_imported_type_name(token, subtype.source(), &name));
                if resolved.as_ref() == Some(supertype) {
                    named.push(ty);
                }
            }
        }
        let [ty] = named.as_slice() else {
            return None;
        };
        let arguments = java_type_argument_nodes(*ty);
        if arguments.is_empty() {
            return Some(MemberFamilySupertypeArguments::Raw);
        }
        let reader = JavaMemberFamilyTypeReader {
            java: self,
            scope: subtype,
            source: &source,
            owner: Some(declaration),
        };
        Some(MemberFamilySupertypeArguments::Arguments(
            arguments
                .into_iter()
                .map(|argument| reader.read(argument))
                .collect(),
        ))
    }

    /// The declaration node of `unit`, of one of `kinds`.
    fn java_declaration_node<'tree>(
        &self,
        tree: &'tree tree_sitter::Tree,
        unit: &CodeUnit,
        kinds: &[&str],
    ) -> Option<tree_sitter::Node<'tree>> {
        let ranges = self.ranges(unit);
        let range = ranges.first()?;
        let mut node = tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        while !kinds.contains(&node.kind()) {
            node = node.parent()?;
        }
        Some(node)
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

        // The set of methods a virtual call can run is a different question from
        // which declaration a name denotes, and a missing jar can change it: a
        // workspace class can extend `dep.Base`, which extends this owner, and
        // override the member. The family therefore keeps every gap. The walk
        // below follows artifact intermediates, but an unresolved workspace
        // supertype still records the independent semantic evidence gap as well
        // as the hierarchy's typed incomplete status.
        let external =
            self.external_declarations(analyzer.semantic_model_overlay_read().published());
        external.record_all_gaps(&crate::analyzer::jvm::external::QueryGapRecorder::new(self));
        let descendants = self.external_root_descendants(
            analyzer,
            identity.owner_fqn(),
            max_visits,
            cancellation,
        );
        let hierarchy = &descendants.hierarchy;
        let status = match &hierarchy.status {
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
            // The proven descendants still answer; the family stays open below.
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(_),
            ) => None,
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
        let open = matches!(
            hierarchy.status,
            JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(_)
            )
        );
        let mut family = MemberFacts::external_descendant_family(
            analyzer,
            hierarchy.descendants.clone(),
            hierarchy.visited,
            identity.member(),
            identity.arity(),
            max_visits,
            cancellation,
        );
        // A supertype nothing resolves may hide another overrider: keep the
        // proven candidates as targets, but never claim the family complete.
        if open && family.status == ExternalMemberFamilyStatus::Complete {
            family.status = ExternalMemberFamilyStatus::Incomplete(
                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
            );
        }
        family
    }

    /// The workspace descendants of one external root, shared by every member
    /// and every call that asks about that root. The walk visits every
    /// workspace type and resolves each supertype that names neither a
    /// workspace type nor the root, and the unresolved-supertype report
    /// resolves them again; per call that cost grew as calls x workspace
    /// types. The answer depends on the snapshot, the active model set, the
    /// root and the visit budget, never on the member.
    ///
    /// The walk reads every workspace type, so its named reads are a
    /// workspace-sized set; retaining and replaying that set per root is what
    /// made each dispatch receipt large. The build instead records one
    /// [`WorkspaceFactFamily::JavaExternalRootDescendants`] certificate whose
    /// answer digest verification recomputes on the head, so a hit replays
    /// one key and the incompleteness reasons of the walk. A walk stopped by
    /// cancellation names no certificate, answers its own caller and is not
    /// retained.
    pub(super) fn external_root_descendants(
        &self,
        analyzer: &dyn IAnalyzer,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<ExternalRootDescendants> {
        use brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit;
        use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
        use brokk_bifrost_analysis::analyzer::workspace_authority::{
            AuthorityInputs, memo_attribution,
        };
        use brokk_bifrost_analysis::analyzer::{
            FactSubject, WorkspaceAuthorityMemo, WorkspaceFactFamily,
        };
        let key = (
            analyzer
                .semantic_model_overlay()
                .as_ref()
                .map(|overlay| StableDigest::sha256(overlay.active_model_set_hash())),
            Box::<str>::from(external_root_fqn),
            max_visits,
        );
        crate::analyzer::jvm::hierarchy::derived_read_retaining(
            &self.external_root_descendants,
            self,
            &key,
            || {
                let answer = WorkspaceAuthorityMemo::new(
                    WorkspaceFactFamily::JavaExternalRootDescendants,
                    (),
                )
                .read(
                    &memo_attribution(self),
                    |_| {
                        let mut hierarchy = self.external_root_hierarchy_with_external(
                            analyzer,
                            external_root_fqn,
                            max_visits,
                            cancellation,
                        );
                        // The scan runs whether or not a JDK pack is active.
                        // Skipping it without a pack would let a family over a
                        // library owner look complete while a workspace type
                        // extends a supertype nothing can resolve, and the
                        // analyzer path has no query obligation that would say
                        // otherwise. With no pack a JDK supertype is reported
                        // as unresolved, which fails closed.
                        let unresolved_supertype = self.unresolved_supertype_gap(
                            analyzer,
                            external_root_fqn,
                            &hierarchy,
                        );
                        if let Some(gap) = &unresolved_supertype {
                            analyzer.record_query_incomplete(
                                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                                    gap.clone(),
                                ),
                            );
                        }
                        // Only the report reads the unmatched supertypes.
                        hierarchy.unmatched_supertypes = Vec::new();
                        ExternalRootDescendants {
                            hierarchy,
                            unresolved_supertype,
                        }
                    },
                    |answer| {
                        if answer.hierarchy.status == JavaExternalRootHierarchyStatus::Cancelled {
                            AuthorityInputs::Unnamed
                        } else {
                            AuthorityInputs::Fact {
                                language: Language::Java,
                                subject: FactSubject::Named {
                                    name: external_root_fqn.into(),
                                },
                                answer: answer.digest(),
                            }
                        }
                    },
                );
                let retain = answer.hierarchy.status != JavaExternalRootHierarchyStatus::Cancelled;
                let bytes = std::mem::size_of_val(&key)
                    + external_root_fqn.len()
                    + std::mem::size_of::<ExternalRootDescendants>()
                    + answer
                        .unresolved_supertype
                        .as_ref()
                        .map_or(0, |gap| gap.len())
                    + answer
                        .hierarchy
                        .descendants
                        .iter()
                        .map(|unit| usize::try_from(estimate_code_unit(unit)).unwrap_or(usize::MAX))
                        .sum::<usize>();
                (Arc::new(answer), bytes, retain)
            },
        )
    }

    /// The independent incompleteness reason when a workspace type has a
    /// supertype that is neither a workspace type, nor the root, nor a type the
    /// external surface resolves: that type might be an overrider of a member of
    /// the root, and the walk cannot see through it.
    fn unresolved_supertype_gap(
        &self,
        analyzer: &dyn IAnalyzer,
        external_root_fqn: &str,
        hierarchy: &JavaExternalRootHierarchyAnswer,
    ) -> Option<Box<str>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let packs = analyzer.semantic_model_overlay_read().published();
        let mut seen = brokk_bifrost_core::hash::HashSet::default();
        hierarchy
            .unmatched_supertypes
            .iter()
            .filter(|(descendant, raw)| seen.insert((descendant.source().clone(), raw.as_str())))
            .find(|(descendant, raw)| {
                self.supertype_identity(token, &packs, descendant, raw)
                    .is_none()
            })
            .map(|(descendant, raw)| {
                format!(
                    "jvm.dispatch.unresolved_supertype: {raw} of {} may override a member of {external_root_fqn}",
                    descendant.fq_name()
                )
                .into_boxed_str()
            })
    }

    /// The type a workspace declaration's written supertype names: a lexically
    /// visible or imported workspace type, or else what Java's type-name ladder
    /// binds against the external surface.
    ///
    /// The answer depends on the declaration's file, the snapshot and the
    /// active model set, never on the root a hierarchy query asks about, so it
    /// is memoized across queries with the reads of its resolution. Each
    /// external-owner family query used to resolve every unmatched supertype
    /// of every workspace type again through SQL, once for the closure walk
    /// and once for the unresolved-supertype report (#11517).
    fn supertype_identity(
        &self,
        token: QueryToken<'_>,
        packs: &Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        descendant: &CodeUnit,
        raw: &str,
    ) -> Option<String> {
        use crate::analyzer::java::imports::{JavaTypeResolution, TypeNameOutcome};
        use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
        use brokk_bifrost_jvm::java::graph_support::JavaTypeName;
        let key = (
            packs
                .as_ref()
                .map(|overlay| StableDigest::sha256(overlay.active_model_set_hash())),
            descendant.clone(),
            raw.to_owned(),
        );
        let identity = crate::analyzer::jvm::hierarchy::derived_read(
            &self.memo_caches.supertype_identities,
            self,
            &key,
            || {
                let identity = resolve_java_lexical_type_name(self, descendant, raw)
                    .or_else(|| self.resolve_imported_type_name(token, descendant.source(), raw))
                    .map(|unit| unit.fq_name())
                    .or_else(|| {
                        let name = JavaTypeName::from_normalized_spelling(raw)?;
                        match self.resolve_type_name_outcome_at(
                            token,
                            packs.clone(),
                            descendant.source(),
                            &name,
                            None,
                            None,
                        ) {
                            TypeNameOutcome::Resolved(JavaTypeResolution::External(hit)) => {
                                Some(hit.fqn().to_owned())
                            }
                            TypeNameOutcome::Resolved(JavaTypeResolution::Source(unit)) => {
                                Some(unit.fq_name())
                            }
                            _ => None,
                        }
                    });
                let bytes = std::mem::size_of_val(&key)
                    + usize::try_from(
                        brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit(
                            descendant,
                        ),
                    )
                    .unwrap_or(usize::MAX)
                    + raw.len()
                    + identity.as_ref().map_or(0, String::len);
                (Arc::new(identity), bytes)
            },
        );
        (*identity).clone()
    }

    fn external_root_hierarchy_with_external(
        &self,
        analyzer: &dyn IAnalyzer,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> JavaExternalRootHierarchyAnswer {
        let index = match self.external_root_hierarchy_index(cancellation) {
            Ok(index) => index,
            Err(status) => {
                return JavaExternalRootHierarchyAnswer {
                    status,
                    descendants: Vec::new(),
                    visited: 0,
                    unmatched_supertypes: Vec::new(),
                };
            }
        };
        let packs = analyzer.semantic_model_overlay_read().published();
        let external = self.external_declarations(packs.clone());
        let recorder = crate::analyzer::jvm::external::QueryGapRecorder::new(self);
        let scope = AnalyzerQueryScope::new(self);
        let mut closure = brokk_bifrost_jvm::ExternalSupertypeClosure::default();
        index.descendants_of_with_external(
            external_root_fqn,
            max_visits,
            cancellation,
            |descendant, raw, visited| {
                closure.reaches_root(
                    raw,
                    external_root_fqn,
                    visited,
                    max_visits,
                    cancellation,
                    |raw| self.supertype_identity(scope.token(), &packs, descendant, raw),
                    |identity| external.hierarchy_supertypes(&recorder, identity),
                )
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn external_root_hierarchy(
        &self,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> JavaExternalRootHierarchyAnswer {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return JavaExternalRootHierarchyAnswer {
                status: JavaExternalRootHierarchyStatus::Cancelled,
                descendants: Vec::new(),
                visited: 0,
                unmatched_supertypes: Vec::new(),
            };
        }
        match self.external_root_hierarchy_index(cancellation) {
            Ok(index) => index.descendants_of(external_root_fqn, max_visits, cancellation),
            Err(status) => JavaExternalRootHierarchyAnswer {
                status,
                descendants: Vec::new(),
                visited: 0,
                unmatched_supertypes: Vec::new(),
            },
        }
    }

    /// The hydrated hierarchy of every workspace class, shared by every
    /// external root of this snapshot (#10428). Each virtual call on an
    /// external owner used to re-read all of it from SQL. The index depends on
    /// no root, budget or cancellation, so one retained build per snapshot
    /// serves every call. A hit replays the build's read receipt, so a
    /// consumer records the same whole-workspace hierarchy read as a cold
    /// build. Only a complete index is retained; a refused or cancelled build
    /// answers its own caller and the next caller builds again.
    fn external_root_hierarchy_index(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::java::cache::ExternalRootHierarchyIndexOutcome {
        use brokk_bifrost_analysis::analyzer::common::{
            read_replayable_query_cache, replayable_query_cache_value,
        };
        let entry = read_replayable_query_cache(
            &self.memo_caches.external_root_hierarchy_index,
            &(),
            || {
                let prepared = std::cell::Cell::new(false);
                let fill = replayable_query_cache_value(self, || {
                    let outcome = self.prepare_external_root_hierarchy_index(cancellation);
                    prepared.set(outcome.is_ok());
                    outcome
                });
                match fill {
                    Ok(entry) if prepared.get() => Ok(entry),
                    Ok(entry) | Err(entry) => Err(entry),
                }
            },
        );
        entry.replay().clone()
    }

    fn prepare_external_root_hierarchy_index(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::java::cache::ExternalRootHierarchyIndexOutcome {
        let _scope = brokk_bifrost_core::profiling::scope(
            "JavaAnalyzer::prepare_external_root_hierarchy_index",
        );
        let Some(candidates) = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
        else {
            return Err(JavaExternalRootHierarchyStatus::Incomplete(
                JavaExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
            ));
        };
        JavaExternalRootHierarchyIndex::prepare(
            candidates.into_iter().map(JvmHierarchyFact).collect(),
            |batch| {
                self.inner
                    .hydrate_hierarchy_declaration_facts(batch)
                    .is_some()
            },
            cancellation,
        )
        .map(Arc::new)
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

impl JavaAnalyzer {
    fn legacy_member_family_ancestors(&self, owner: &CodeUnit) -> MemberFamilyAncestors {
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
                implicit_interface_members(Language::Java).map(|root| {
                    root.methods
                        .expect("Java has a fixed implicit Object method inventory")
                })
            } else {
                overridable_method_inventory(name)
            };
            unread.push(UnreadMemberFamilyAncestor {
                name: name.into(),
                inventory,
            });
        }
        let answer = self.get_direct_ancestors(owner);
        MemberFamilyAncestors {
            resolved: answer.edges,
            ambiguous: answer.ambiguous,
            unread,
        }
    }
}

impl JavaAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn native_hierarchy_query(
        &self,
        root: Option<&CodeUnit>,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        use brokk_bifrost_analysis::analyzer::resolution::ClassifiedSupertypeKind;
        let _scope = AnalyzerQueryScope::new(self);
        crate::analyzer::jvm::native_hierarchy::with_native_query(
            self.inner(),
            root,
            &mut |_, _| {},
            &mut |owner, parents| {
                for parent in parents.iter_mut() {
                    if let Some(root) = &parent.intrinsic_root
                        && root.owner_fqn.as_ref() == "java.lang.Object"
                    {
                        parent.unread.push(UnreadMemberFamilyAncestor {
                            name: root.owner_fqn.to_string(),
                            inventory: overridable_method_inventory(&root.owner_fqn),
                        });
                    }
                }
                let syntax_kind = self.declaration_syntax_kind(owner);
                let interface = matches!(
                    syntax_kind,
                    Some("interface_declaration" | "annotation_type_declaration")
                ) || self
                    .signature_metadata(owner)
                    .iter()
                    .any(|entry| entry.class_like_is_interface());
                // The root is an ancestor here only when no resolved parent of the
                // kind that leads to it continues the chain (JLS 8.1.4, 9.2). A
                // resolved superclass or superinterface reaches the root through
                // its own hierarchy, where a nearer redeclaration closes the route.
                let continuing: &[ClassifiedSupertypeKind] = if interface {
                    &[ClassifiedSupertypeKind::Interface]
                } else {
                    &[
                        ClassifiedSupertypeKind::Superclass,
                        ClassifiedSupertypeKind::ImplicitSuperclass,
                    ]
                };
                if parents.iter().any(|parent| {
                    !parent.targets.is_empty()
                        && parent.kind.is_some_and(|kind| continuing.contains(&kind))
                }) {
                    return;
                }
                let (root, inventory) = match syntax_kind {
                    Some("enum_declaration") => (
                        "java.lang.Enum",
                        overridable_method_inventory("java.lang.Enum"),
                    ),
                    Some("record_declaration") => (
                        "java.lang.Record",
                        overridable_method_inventory("java.lang.Record"),
                    ),
                    _ if interface => (
                        "java.lang.Object",
                        implicit_interface_members(Language::Java).map(|root| {
                            root.methods
                                .expect("Java has a fixed implicit Object method inventory")
                        }),
                    ),
                    _ => (
                        "java.lang.Object",
                        overridable_method_inventory("java.lang.Object"),
                    ),
                };
                if !parents
                    .iter()
                    .any(|parent| parent.unread.iter().any(|unread| unread.name == root))
                {
                    parents.push(crate::analyzer::jvm::native_hierarchy::MappedParent {
                        kind: Some(ClassifiedSupertypeKind::ImplicitSuperclass),
                        ordinal: u32::MAX,
                        targets: Vec::new(),
                        unread: vec![UnreadMemberFamilyAncestor {
                            name: root.into(),
                            inventory,
                        }],
                        intrinsic_root: None,
                        alternatives: 0,
                        complete: true,
                    });
                }
            },
            run,
        );
    }
}

const JAVA_TYPE_DECLARATION_KINDS: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
];

/// The type declaration whose body declares `callable`, or `None` for an
/// anonymous class body, which declares no type parameters.
fn java_owner_declaration(callable: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut node = callable.parent()?;
    loop {
        if JAVA_TYPE_DECLARATION_KINDS.contains(&node.kind()) {
            return Some(node);
        }
        if node.kind() == "object_creation_expression" {
            return None;
        }
        node = node.parent()?;
    }
}

/// The number of `[]` pairs a `dimensions` node writes.
fn java_dimension_count(dimensions: tree_sitter::Node<'_>) -> usize {
    dimensions
        .children(&mut dimensions.walk())
        .filter(|child| child.kind() == "[")
        .count()
}

/// Reads one written Java type as a [`MemberFamilyParameterType`] in the scope
/// of `scope`, whose enclosing type declaration is `owner`.
struct JavaMemberFamilyTypeReader<'a, 'tree> {
    java: &'a JavaAnalyzer,
    /// The unit the type is written on: its lexical scope starts at its parent.
    scope: &'a CodeUnit,
    source: &'a str,
    /// The declaration whose type parameters stay substitutable.
    owner: Option<tree_sitter::Node<'tree>>,
}

impl JavaMemberFamilyTypeReader<'_, '_> {
    fn read(&self, ty: tree_sitter::Node<'_>) -> MemberFamilyParameterType {
        self.read_bounded(ty, 0)
    }

    /// `depth` counts array elements and type-variable bounds followed so far.
    /// Javac rejects a cyclic bound, but a file being edited can write one.
    fn read_bounded(&self, ty: tree_sitter::Node<'_>, depth: usize) -> MemberFamilyParameterType {
        use crate::analyzer::java::imports::JavaTypeResolution;
        use brokk_bifrost_jvm::java::graph::return_type::{
            is_java_nominal_type_node, java_type_name_components,
        };
        use brokk_bifrost_jvm::java::graph_support::{
            java_declared_type_parameters, java_type_parameter_bounds, java_type_parameter_in_scope,
        };
        const MAX_DEPTH: usize = 32;
        let unknown = MemberFamilyParameterType::Unresolved(Vec::new());
        if depth > MAX_DEPTH {
            return unknown;
        }
        let mut ty = ty;
        while matches!(ty.kind(), "generic_type" | "annotated_type") {
            let Some(nominal) = ty
                .named_children(&mut ty.walk())
                .find(|child| is_java_nominal_type_node(child.kind()))
            else {
                return unknown;
            };
            ty = nominal;
        }
        match ty.kind() {
            "array_type" => {
                let Some(element) = ty.child_by_field_name("element") else {
                    return unknown;
                };
                let mut result = self.read_bounded(element, depth + 1);
                for _ in 0..ty
                    .child_by_field_name("dimensions")
                    .map_or(1, java_dimension_count)
                {
                    result = MemberFamilyParameterType::Array(Box::new(result));
                }
                result
            }
            "integral_type" | "floating_point_type" | "boolean_type" => {
                MemberFamilyParameterType::Primitive(node_text(ty, self.source).to_owned())
            }
            _ => {
                let Some(components) = java_type_name_components(ty, self.source) else {
                    return unknown;
                };
                let name = components.join(".");
                if let Some(parameter) = java_type_parameter_in_scope(ty, self.source, &name) {
                    let erasure = match java_type_parameter_bounds(parameter).first() {
                        Some(bound) => erase(self.read_bounded(*bound, depth + 1)),
                        None => MemberFamilyParameterType::Nominal("java.lang.Object".into()),
                    };
                    let declaration = parameter.parent().and_then(|list| list.parent());
                    let index = self
                        .owner
                        .filter(|owner| Some(owner.id()) == declaration.map(|node| node.id()))
                        .and_then(|owner| {
                            java_declared_type_parameters(owner)
                                .iter()
                                .position(|declared| declared.id() == parameter.id())
                        });
                    return match index {
                        Some(index) => MemberFamilyParameterType::OwnerTypeParameter {
                            index,
                            erasure: Box::new(erasure),
                        },
                        None => erasure,
                    };
                }
                let java = self.java;
                if let Some(resolved) = resolve_java_lexical_type_name(java, self.scope, &name) {
                    return MemberFamilyParameterType::Nominal(resolved.fq_name().to_string());
                }
                let scope = AnalyzerQueryScope::new(java);
                let token = scope.token();
                let file = self.scope.source();
                // A single-type import names the type structurally: the import
                // path is the canonical name whether or not any index holds the
                // target, so no external lookup (and no gap) is needed to read it.
                if components.len() == 1
                    && let Some(imported) = java.explicit_imported_type_fqn(token, file, &name)
                {
                    return MemberFamilyParameterType::Nominal(imported);
                }
                if let Some(resolved) =
                    java.resolve_type_name_with_external(token, None, file, &name)
                {
                    return MemberFamilyParameterType::Nominal(match resolved {
                        JavaTypeResolution::Source(unit) => unit.fq_name().to_string(),
                        JavaTypeResolution::External(ty) => ty.fqn().to_owned(),
                    });
                }
                let candidates = java_type_name_candidate_fqns(java, token, file, &name);
                // A single-type import claims the spelling whether or not its
                // target is indexed, which leaves one candidate. The fixed
                // intrinsic inventory supplies `Object` even without an
                // indexed JDK.
                match candidates.as_slice() {
                    [only] => MemberFamilyParameterType::Nominal(only.clone()),
                    _ if candidates
                        .iter()
                        .any(|candidate| candidate == "java.lang.Object") =>
                    {
                        MemberFamilyParameterType::Nominal("java.lang.Object".into())
                    }
                    _ => MemberFamilyParameterType::Unresolved(candidates),
                }
            }
        }
    }
}

/// The erasure of a type already read: an owner type parameter erases to its
/// bound's erasure.
fn erase(ty: MemberFamilyParameterType) -> MemberFamilyParameterType {
    match ty {
        MemberFamilyParameterType::OwnerTypeParameter { erasure, .. } => *erasure,
        MemberFamilyParameterType::Array(element) => {
            MemberFamilyParameterType::Array(Box::new(erase(*element)))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::capture_query_reads;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::atomic::AtomicUsize;

    #[test]
    #[hardwon("#10497: an unrelated unresolved supertype erased known Java and Kotlin overrides")]
    fn unresolved_supertype_keeps_proven_external_family_candidates() {
        use crate::analyzer::KotlinAnalyzer;
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };

        for (language, extension, known, missing) in [
            (
                Language::Java,
                "java",
                "package app; class Direct extends java.io.InputStream { public void close() {} } class Indirect extends org.example.Base { public void close() {} }",
                "package app; class Missing extends com.missing.Gone {}",
            ),
            (
                Language::Kotlin,
                "kt",
                "package app\nclass Direct : java.io.InputStream() { override fun close() {} }\nclass Indirect : org.example.Base() { override fun close() {} }",
                "package app\nclass Missing : com.missing.Gone()",
            ),
        ] {
            for source_jar in [false, true] {
                for missing_first in [None, Some(true), Some(false)] {
                    let (first, second) = match missing_first {
                        Some(true) => (missing, known),
                        Some(false) => (known, missing),
                        None => (known, ""),
                    };
                    let project = InlineTestProject::with_language(language)
                        .file(format!("app/First.{extension}"), first)
                        .file(format!("app/Second.{extension}"), second)
                        .build();
                    let dir = tempfile::tempdir().unwrap();
                    let jar = dir.path().join(if source_jar {
                        "dependency-sources.jar"
                    } else {
                        "dependency.jar"
                    });
                    if source_jar {
                        brokk_bifrost_analysis::test_support::write_zip(
                            &jar,
                            &[(
                                "org/example/Base.java",
                                "package org.example; public class Base extends java.io.InputStream {}",
                            )],
                        );
                    } else {
                        write_test_class_jar(
                            &jar,
                            &[TestClassFile {
                                internal_name: "org/example/Base",
                                super_internal_name: "java/io/InputStream",
                                methods: &[],
                                private_nested: false,
                            }],
                        );
                    }
                    let config = AnalyzerConfig {
                        jvm: JvmAnalyzerConfig {
                            external_dependencies: JvmExternalDependencies {
                                artifact_paths: vec![JvmExternalArtifact {
                                    artifact_path: jar,
                                    ..Default::default()
                                }],
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let analyzer: Box<dyn IAnalyzer> = match language {
                        Language::Java => {
                            Box::new(JavaAnalyzer::new_with_config(project.project_dyn(), config))
                        }
                        Language::Kotlin => Box::new(KotlinAnalyzer::new_with_config(
                            project.project_dyn(),
                            config,
                        )),
                        _ => unreachable!(),
                    };
                    let answer = analyzer
                        .member_family_provider()
                        .unwrap()
                        .external_member_family(
                            &JvmExternalMemberIdentity::new(
                                language,
                                "java.io.InputStream",
                                "close",
                                0,
                                JvmReceiverSemantics::Instance,
                            ),
                            usize::MAX,
                            None,
                        );
                    assert_eq!(
                        answer.status,
                        if source_jar || missing_first.is_some() {
                            ExternalMemberFamilyStatus::Incomplete(
                                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                            )
                        } else {
                            ExternalMemberFamilyStatus::Complete
                        },
                        "{language:?}, missing_first={missing_first:?}, source_jar={source_jar}: {answer:?}"
                    );
                    let mut names = answer
                        .candidates
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<Vec<_>>();
                    names.sort();
                    assert_eq!(
                        names,
                        ["app.Direct.close", "app.Indirect.close"],
                        "{language:?}, missing_first={missing_first:?}, source_jar={source_jar}: {answer:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon("#10497: pack hierarchy changes must reopen warm external dispatch families")]
    fn external_intermediate_pack_swap() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate;
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };

        use brokk_bifrost_analysis::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::CompilerOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest;

        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelResolutionOutcome;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelRuntimeLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::semantic_model::SessionPackSource;

        use brokk_bifrost_analysis::analyzer::semantic_model::SessionPackSourceKind;

        use brokk_bifrost_semantic::analyzer::semantic_model::source::SourceFormat;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_source;

        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::resolve_active_semantic_models;
        use brokk_bifrost_semantic::analyzer::semantic_model::model::TypeRef;
        for (source, root, kind) in [
            (
                "package app; class Foo extends org.example.Base { public void close() {} }",
                "java.io.InputStream",
                "class",
            ),
            (
                "package app; class Foo implements org.example.Base { public void close() {} }",
                "dep.Root",
                "interface",
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Java)
                .file("app/Foo.java", source)
                .build();
            let default_java = JavaAnalyzer::new(project.project_dyn());
            use crate::analyzer::KotlinAnalyzer;
            use brokk_bifrost_analysis::analyzer::multi_analyzer::{
                AnalyzerDelegate, MultiAnalyzer, resolve_analyzer,
            };
            let kotlin_source = if kind == "interface" {
                "package app\nclass Foo : org.example.Base { override fun close() {} }"
            } else {
                "package app\nclass Foo : org.example.Base() { override fun close() {} }"
            };
            let kotlin_project = InlineTestProject::with_language(Language::Kotlin)
                .file("app/Foo.kt", kotlin_source)
                .build();
            let default_workspace = MultiAnalyzer::new(std::collections::BTreeMap::from([(
                Language::Kotlin,
                AnalyzerDelegate::new(KotlinAnalyzer::new(kotlin_project.project_dyn())),
            )]));
            for (present, parents, artifact_parent, reaches_root) in [
                (true, vec![root], None, true),
                (false, vec![root], None, true),
                (true, vec![root, "dep.Missing"], None, true),
                (true, vec!["dep.Missing", root], None, true),
                (true, vec![root], Some("dep.Other"), true),
                (true, vec!["dep.Other"], Some(root), true),
                (true, vec!["dep.Other"], Some("dep.Other"), false),
                (false, vec!["dep.Other"], Some("dep.Other"), false),
            ]
            .into_iter()
            .filter(|(_, _, artifact, _)| kind == "class" || artifact.is_none())
            {
                let complete = present
                    && parents.len() == 1
                    && artifact_parent.is_none_or(|parent| parent == parents[0]);
                let artifact_directory = tempfile::tempdir().unwrap();
                let artifact_config = artifact_parent.map(|parent| {
                    let jar = artifact_directory.path().join("dependency.jar");
                    write_test_class_jar(
                        &jar,
                        &[
                            TestClassFile {
                                internal_name: "org/example/Base",
                                super_internal_name: &parent.replace('.', "/"),
                                methods: &[],
                                private_nested: false,
                            },
                            TestClassFile {
                                internal_name: "dep/Other",
                                super_internal_name: "java/lang/Object",
                                methods: &[],
                                private_nested: false,
                            },
                            TestClassFile {
                                internal_name: "java/lang/Object",
                                super_internal_name: "java/lang/Object",
                                methods: &[],
                                private_nested: false,
                            },
                        ],
                    );
                    AnalyzerConfig {
                        jvm: JvmAnalyzerConfig {
                            external_dependencies: JvmExternalDependencies {
                                artifact_paths: vec![JvmExternalArtifact {
                                    artifact_path: jar,
                                    ..Default::default()
                                }],
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                });
                let artifact_java = artifact_config.as_ref().map(|config| {
                    JavaAnalyzer::new_with_config(project.project_dyn(), config.clone())
                });
                let java = artifact_java.as_ref().unwrap_or(&default_java);
                let artifact_workspace = artifact_config.map(|config| {
                    MultiAnalyzer::new(std::collections::BTreeMap::from([(
                        Language::Kotlin,
                        AnalyzerDelegate::new(KotlinAnalyzer::new_with_config(
                            kotlin_project.project_dyn(),
                            config,
                        )),
                    )]))
                });
                let workspace = artifact_workspace.as_ref().unwrap_or(&default_workspace);
                let hierarchy = parents.iter().map(|parent| serde_json::json!({"hierarchy_kind": "extends", "target": TypeRef::named(*parent)})).collect::<Vec<_>>();
                let inventory = if present {
                    serde_json::json!({
                        "callables_complete": true, "values_complete": true, "types_complete": true,
                        "supertypes_complete": true, "supertypes": hierarchy,
                        "nested_types": [], "additional_members": []
                    })
                } else {
                    serde_json::Value::Null
                };
                let document = serde_json::json!({
                    "schema_version": 2, "pack_id": "test.10497", "version": "1.0.0",
                    "producer": {"name": "bifrost-test", "version": "1.0.0"},
                    "language": "java", "ecosystem": "jdk",
                    "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": [{"name": "jdk", "requirement": ">=17.0.0"}]},
                    "provenance": {"source": "test:inline", "revision": "10497"},
                    "license": "Apache-2.0", "completeness": "complete",
                    "safety": {"generated_code_only": false, "review_required": false},
                    "shards": [{"id": "decls", "activation": [{"toolchain": {"name": "jdk", "version": ">=17.0.0"}, "targets": ["jvm"], "configurations": []}],
                    "payload": {"kind": "declaration_facts", "types": [{
                        "id": "type.base", "name": "org.example.Base", "type_kind": kind, "visibility": "public",
                        "is_abstract": false, "is_sealed": false, "has_explicit_type_terms": false,
                        "type_parameters": [], "type_parameter_constraints": [], "embedded_types": [],
                        "hierarchy": hierarchy, "aliases": [], "extension_surfaces": [],
                    "jvm_inventory": inventory,
                    "locator": {"kind": "artifact", "path": "org/example/Base.class", "symbol": "org.example.Base"}
                    }], "members": [], "relations": []}}]
                });
                let pack = compile_source(
                    SourceFormat::Json,
                    &serde_json::to_vec(&document).expect("fixture JSON"),
                    &CompilerOptions::default(),
                )
                .expect("compile test-only declarations");
                let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
                    .expect("fixture catalog");
                catalog
                    .register_session_pack(
                        &pack,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: "test:private-overload".into(),
                        },
                    )
                    .expect("register declarations");
                let request = SemanticModelActivationRequest {
                    host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                    approximate_standard_libraries: Vec::new(),
                    bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                        .expect("crate version"),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "java".into(),
                        ecosystem: "jdk".into(),
                        package: None,
                        module: None,
                        toolchain: Some(CatalogCoordinate {
                            name: "jdk".into(),
                            version: Some(semver::Version::new(21, 0, 0)),
                        }),
                        target: Some("jvm".into()),
                        configuration: None,
                        production_input_digest: None,
                        verified_raw_artifacts: Vec::new(),
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                };
                let cancellation = CancellationToken::default();
                let active = match resolve_active_semantic_models(&catalog, &request, &cancellation)
                {
                    SemanticModelResolutionOutcome::Ready(active) => active,
                    other => panic!("fixture activation must be ready: {other:#?}"),
                };
                let active = Arc::new(active);
                let overlay = Arc::new(
                    SemanticModelOverlay::build(
                        java,
                        &active,
                        &cancellation,
                        64 << 20,
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    )
                    .expect("fixture overlay"),
                );

                let _scope =
                    AnalyzerQueryScope::with_semantic_model_overlay(java, Some(overlay.clone()));
                let answer =
                    java.external_root_hierarchy_with_external(java, root, usize::MAX, None);
                if complete {
                    assert_eq!(answer.status, JavaExternalRootHierarchyStatus::Complete);
                } else {
                    assert!(
                        matches!(
                            answer.status,
                            JavaExternalRootHierarchyStatus::Incomplete(_)
                        ),
                        "{answer:?}"
                    );
                }
                assert_eq!(
                    answer
                        .descendants
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<Vec<_>>(),
                    if reaches_root {
                        vec!["app.Foo"]
                    } else {
                        Vec::new()
                    }
                );
                let identity = JvmExternalMemberIdentity::new(
                    Language::Java,
                    root,
                    "close",
                    0,
                    JvmReceiverSemantics::Instance,
                );
                let family = java.resolve_external_member_family(java, &identity, usize::MAX, None);
                let expected_status = if complete {
                    ExternalMemberFamilyStatus::Complete
                } else {
                    ExternalMemberFamilyStatus::Incomplete(
                        ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                    )
                };
                assert_eq!(family.status, expected_status, "{family:?}");
                assert_eq!(
                    family
                        .candidates
                        .iter()
                        .any(|unit| unit.fq_name() == "app.Foo.close"),
                    reaches_root,
                    "{family:?}"
                );
                let _workspace_scope =
                    AnalyzerQueryScope::with_semantic_model_overlay(workspace, Some(overlay));
                let kotlin = resolve_analyzer::<KotlinAnalyzer>(workspace).unwrap();
                let identity = JvmExternalMemberIdentity::new(
                    Language::Kotlin,
                    root,
                    "close",
                    0,
                    JvmReceiverSemantics::Instance,
                );
                let family =
                    kotlin.resolve_external_member_family(workspace, &identity, usize::MAX, None);
                assert_eq!(family.status, expected_status, "{family:?}");
                assert_eq!(
                    family
                        .candidates
                        .iter()
                        .any(|unit| unit.fq_name() == "app.Foo.close"),
                    reaches_root,
                    "{family:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "c50bb6cb12b7: classes sharing an external base re-charged its chain and exhausted the visit budget"
    )]
    fn shared_external_ancestry_is_charged_once() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };
        const CLASSES: usize = 40;
        let source = std::iter::once("package app;".to_owned())
            .chain((0..CLASSES).map(|i| format!(" class C{i} extends org.example.Base {{}}")))
            .collect::<String>();
        let project = InlineTestProject::with_language(Language::Java)
            .file("app/C.java", source.as_str())
            .build();
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("dependency.jar");
        write_test_class_jar(
            &jar,
            &[
                TestClassFile {
                    internal_name: "org/example/Base",
                    super_internal_name: "org/example/Mid",
                    methods: &[],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "org/example/Mid",
                    super_internal_name: "java/io/InputStream",
                    methods: &[],
                    private_nested: false,
                },
            ],
        );
        let java = JavaAnalyzer::new_with_config(
            project.project_dyn(),
            AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        artifact_paths: vec![JvmExternalArtifact {
                            artifact_path: jar,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let unbounded = java.external_root_hierarchy_with_external(
            &java,
            "java.io.InputStream",
            usize::MAX,
            None,
        );
        assert_eq!(
            unbounded.status,
            JavaExternalRootHierarchyStatus::Complete,
            "{unbounded:?}"
        );
        assert_eq!(unbounded.descendants.len(), CLASSES, "{unbounded:?}");
        // The three external identities are charged once, not once per class.
        assert!(unbounded.visited < CLASSES + 3 * 2, "{unbounded:?}");
        let bounded = java.external_root_hierarchy_with_external(
            &java,
            "java.io.InputStream",
            unbounded.visited,
            None,
        );
        assert_eq!(
            bounded.status,
            JavaExternalRootHierarchyStatus::Complete,
            "{bounded:?}"
        );
        assert_eq!(bounded.descendants, unbounded.descendants);
    }

    #[test]
    #[hardwon(
        "389cd6be068e: an incomplete external closure stopped the scan before a later unresolved supertype"
    )]
    fn incomplete_external_closure_keeps_collecting_unmatched_supertypes() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };
        // Foo's supertype resolves to a jar type whose own parent is absent, so
        // its closure is incomplete; Bar's supertype resolves to nothing. Both
        // spellings must still reach the independent unresolved report.
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "app/Foo.java",
                "package app; class Foo extends org.example.Base {} class Bar extends com.missing.Gone {}",
            )
            .build();
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("dependency.jar");
        write_test_class_jar(
            &jar,
            &[TestClassFile {
                internal_name: "org/example/Base",
                super_internal_name: "org/example/Mid",
                methods: &[],
                private_nested: false,
            }],
        );
        let java = JavaAnalyzer::new_with_config(
            project.project_dyn(),
            AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        artifact_paths: vec![JvmExternalArtifact {
                            artifact_path: jar,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let answer = java.external_root_hierarchy_with_external(
            &java,
            "java.io.InputStream",
            usize::MAX,
            None,
        );
        assert!(
            matches!(
                answer.status,
                JavaExternalRootHierarchyStatus::Incomplete(
                    JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(_)
                )
            ),
            "{answer:?}"
        );
        let mut unmatched = answer
            .unmatched_supertypes
            .iter()
            .map(|(_, raw)| raw.as_str())
            .collect::<Vec<_>>();
        unmatched.sort_unstable();
        assert_eq!(
            unmatched,
            ["com.missing.Gone", "org.example.Base"],
            "{answer:?}"
        );
    }

    #[test]
    #[hardwon("#10497: external jar intermediates hid workspace overrides and reported complete")]
    fn external_intermediate_jar_closure() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };
        for (name, parents, present, expected) in [
            (
                "one",
                vec![("org/example/Base", "java/io/InputStream")],
                true,
                vec!["app.Child", "app.Foo"],
            ),
            (
                "object",
                vec![("org/example/Base", "java/lang/Object")],
                true,
                vec!["app.Child", "app.Foo"],
            ),
            (
                "two",
                vec![
                    ("org/example/Base", "org/example/Mid"),
                    ("org/example/Mid", "java/io/InputStream"),
                ],
                true,
                vec!["app.Child", "app.Foo"],
            ),
            ("missing", vec![], false, vec![]),
            (
                "unrelated",
                vec![
                    ("org/example/Base", "java/io/OutputStream"),
                    ("java/io/OutputStream", "java/lang/Object"),
                    ("java/lang/Object", "java/lang/Object"),
                ],
                true,
                vec![],
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Java)
                .file("app/Foo.java", "package app; class Foo extends org.example.Base { public void close() {} } class Child extends Foo {}")
                .build();
            let dir = tempfile::tempdir().unwrap();
            let jar = dir.path().join("dependency.jar");
            if present {
                let classes = parents
                    .iter()
                    .map(|(owner, parent)| TestClassFile {
                        internal_name: owner,
                        super_internal_name: parent,
                        methods: &[],
                        private_nested: false,
                    })
                    .collect::<Vec<_>>();
                write_test_class_jar(&jar, &classes);
            }
            let java = JavaAnalyzer::new_with_config(
                project.project_dyn(),
                AnalyzerConfig {
                    jvm: JvmAnalyzerConfig {
                        external_dependencies: JvmExternalDependencies {
                            artifact_paths: vec![JvmExternalArtifact {
                                artifact_path: jar,
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            let root = if name == "object" {
                "java.lang.Object"
            } else {
                "java.io.InputStream"
            };
            let answer = java.external_root_hierarchy_with_external(&java, root, usize::MAX, None);
            if present {
                assert_eq!(
                    answer.status,
                    JavaExternalRootHierarchyStatus::Complete,
                    "{name}"
                );
                assert_eq!(
                    answer
                        .descendants
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<Vec<_>>(),
                    expected,
                    "{name}"
                );
            } else {
                assert!(
                    matches!(
                        answer.status,
                        JavaExternalRootHierarchyStatus::Incomplete(
                            JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(_)
                        )
                    ),
                    "{answer:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#10428: every external-owner dispatch re-read all workspace hierarchy facts from SQL, so OWASP taint compilation timed out"
    )]
    fn external_roots_share_one_hierarchy_read_and_replay_its_receipt() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "app/Families.java",
                "package app;\n\
                 import com.example.Ext;\n\
                 class Good implements Ext {}\n\
                 class GoodChild extends Good {}\n\
                 class Other implements com.example.Other {}\n",
            )
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let statements = Arc::new(AtomicUsize::new(0));
        let probe = rusqlite::Connection::open_in_memory().unwrap();
        let counter = Arc::clone(&statements);
        let _subscription = brokk_bifrost_core::cache_db::sql_profile::subscribe_test_statements(
            &probe,
            Arc::new(move |_| {
                counter.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let fq_names = |answer: &JavaExternalRootHierarchyAnswer| {
            assert_eq!(answer.status, JavaExternalRootHierarchyStatus::Complete);
            answer
                .descendants
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>()
        };

        let (cold, cold_reads) = capture_query_reads(&java, || {
            java.external_root_hierarchy("com.example.Ext", usize::MAX, None)
        });
        assert_eq!(fq_names(&cold), ["app.Good", "app.GoodChild"]);
        assert!(
            statements.load(Ordering::Relaxed) > 0,
            "the cold build reads hierarchy facts on this thread"
        );

        statements.store(0, Ordering::Relaxed);
        let (warm, warm_reads) = capture_query_reads(&java, || {
            java.external_root_hierarchy("com.example.Other", usize::MAX, None)
        });
        assert_eq!(fq_names(&warm), ["app.Other"]);
        assert_eq!(statements.load(Ordering::Relaxed), 0);
        assert_eq!(warm_reads.keys(), cold_reads.keys());

        let exhausted = java.external_root_hierarchy("com.example.Ext", 1, None);
        assert_eq!(
            exhausted.status,
            JavaExternalRootHierarchyStatus::BudgetExhausted
        );
    }

    #[test]
    #[hardwon(
        "#11517: every external-owner family query re-resolved each workspace class's external supertype through SQL, doubling OWASP taint compile CPU"
    )]
    fn external_member_families_resolve_each_supertype_once_per_snapshot() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };
        const CLASSES: usize = 8;
        let mut project = InlineTestProject::with_language(Language::Java);
        for index in 0..CLASSES {
            project = project.file(
                format!("app/Servlet{index}.java"),
                format!(
                    "package app;\nimport dep.Base;\nclass Servlet{index} extends Base {{ public void close() {{}} }}\n"
                ),
            );
        }
        let project = project.build();
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("dependency.jar");
        let class = |internal_name, super_internal_name| TestClassFile {
            internal_name,
            super_internal_name,
            methods: &[],
            private_nested: false,
        };
        write_test_class_jar(
            &jar,
            &[
                class("dep/Base", "dep/Middle"),
                class("dep/Middle", "java/lang/Object"),
                class("dep/Unrelated", "java/lang/Object"),
                class("java/lang/Object", "java/lang/Object"),
            ],
        );
        let java = JavaAnalyzer::new_with_config(
            project.project_dyn(),
            AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        artifact_paths: vec![JvmExternalArtifact {
                            artifact_path: jar,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        const HEADS_SQL: &str = "SELECT heads.lang, heads.generation, heads.revision\n             FROM workspace_heads AS heads\n             LEFT JOIN analysis_epochs AS epochs ON epochs.lang = heads.lang\n             WHERE heads.workspace_id = ?1\n               AND heads.generation = COALESCE(epochs.generation, 0)";
        // #10828 inventory freshness check on checkout.
        const INVENTORY_SQL: &str =
            "SELECT generation FROM jvm_external_inventory_generation WHERE id=0";
        // Test-mode checkout validation. This workspace has no Rust snapshot,
        // and #13857 issues no Rust selection stamp for one: no scoped epoch
        // SELECT and no main/temp schema PRAGMAs. They remain allowed here as
        // checkout validation in case the selection shape changes, but only
        // the Java-owned reads below prove that the checkout happened.
        const VALIDATION_SQL: [&str; 5] = [
            HEADS_SQL,
            "PRAGMA main.schema_version",
            "PRAGMA temp.schema_version",
            INVENTORY_SQL,
            // #13416 selection freshness check when the selection has Rust.
            "SELECT epoch FROM main.workspace_selection_epochs\n      WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND revision=?3",
        ];
        let statements = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let probe = rusqlite::Connection::open_in_memory().unwrap();
        let counter = Arc::clone(&statements);
        let _subscription = brokk_bifrost_core::cache_db::sql_profile::subscribe_test_statements(
            &probe,
            Arc::new(move |sql| {
                counter.lock().unwrap().push(sql.to_owned());
            }),
        );
        let family = |root: &str| {
            let answer = java.resolve_external_member_family(
                &java,
                &JvmExternalMemberIdentity::new(
                    Language::Java,
                    root,
                    "close",
                    0,
                    JvmReceiverSemantics::Instance,
                ),
                usize::MAX,
                None,
            );
            assert_eq!(
                answer.status,
                ExternalMemberFamilyStatus::Complete,
                "{answer:?}"
            );
            answer.candidates.len()
        };

        let (cold, cold_reads) = capture_query_reads(&java, || family("dep.Middle"));
        assert_eq!(cold, CLASSES, "every servlet overrides through dep.Base");

        // The supertype `Base` of each servlet names the same external type
        // whatever root a query asks about, so another root resolves nothing.
        let assert_validation_only = || {
            let mut statements = statements.lock().unwrap();
            // After the first resolution in a snapshot, class, member and
            // supertype resolution statements must remain zero. The issue for
            // carrying generation on the request-pinned snapshot will remove
            // these validation reads. Whether the external index is already
            // warm makes the checkout count one or two; neither count changes
            // the contract that no resolution statement reruns.
            let unexpected: Vec<_> = statements
                .iter()
                .filter(|sql| !VALIDATION_SQL.contains(&sql.as_str()))
                .collect();
            assert!(unexpected.is_empty(), "unexpected SQL: {unexpected:?}");
            for sql in [HEADS_SQL, INVENTORY_SQL] {
                let count = statements
                    .iter()
                    .filter(|actual| actual.as_str() == sql)
                    .count();
                assert!(
                    (1..=2).contains(&count),
                    "checkout validation must occur once or twice: {sql}: {count}"
                );
            }
            statements.clear();
        };
        statements.lock().unwrap().clear();
        assert_eq!(family("dep.Unrelated"), 0);
        assert_validation_only();

        let (warm, warm_reads) = capture_query_reads(&java, || family("dep.Middle"));
        assert_eq!(warm, cold);
        assert_eq!(warm_reads.keys(), cold_reads.keys());
        assert_validation_only();
    }

    #[test]
    #[hardwon(
        "#12888: every external-owner dispatch replayed a workspace-sized supertype read set"
    )]
    fn a_retained_external_root_walk_names_one_certificate_and_replays_its_gaps() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use brokk_bifrost_analysis::analyzer::common::capture_query_cache_build;
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "app/Servlet.java",
                "package app;\nimport dep.Base;\nclass Servlet extends Base { public void close() {} public void open() {} }\n",
            )
            .file(
                "app/Missing.java",
                "package app;\nclass Missing extends com.missing.Gone {}\n",
            )
            .build();
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("dependency.jar");
        write_test_class_jar(
            &jar,
            &[
                TestClassFile {
                    internal_name: "dep/Base",
                    super_internal_name: "java/lang/Object",
                    methods: &[],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "java/lang/Object",
                    super_internal_name: "java/lang/Object",
                    methods: &[],
                    private_nested: false,
                },
            ],
        );
        let java = JavaAnalyzer::new_with_config(
            project.project_dyn(),
            AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        artifact_paths: vec![JvmExternalArtifact {
                            artifact_path: jar,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let family = |member: &str| {
            let ((answer, receipt), reads) = capture_query_reads(&java, || {
                capture_query_cache_build(&java, || {
                    java.resolve_external_member_family(
                        &java,
                        &JvmExternalMemberIdentity::new(
                            Language::Java,
                            "dep.Base",
                            member,
                            0,
                            JvmReceiverSemantics::Instance,
                        ),
                        usize::MAX,
                        None,
                    )
                })
            });
            assert_eq!(
                answer.status,
                ExternalMemberFamilyStatus::Incomplete(
                    ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                ),
                "{answer:?}"
            );
            let names = answer
                .candidates
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>();
            let mut reasons = receipt
                .stable_reasons()
                .iter()
                .map(|reason| reason.stable_replay_reason().unwrap())
                .collect::<Vec<_>>();
            reasons.sort();
            (names, reads.keys(), reasons)
        };

        let (cold_names, cold_keys, cold_reasons) = family("close");
        assert_eq!(cold_names, ["app.Servlet.close"]);
        // The walk reads every workspace type; the caller sees one certificate
        // for it instead. Only the walk reads `app/Missing.java`.
        let subject = brokk_bifrost_analysis::analyzer::FactSubject::Named {
            name: "dep.Base".into(),
        };
        let certificates = cold_keys
            .iter()
            .filter_map(|key| match key {
                ReadKey::Lookup {
                    question:
                        LookupQuestion::WorkspaceFact {
                            family:
                                brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalRootDescendants,
                            language: Language::Java,
                            subject: recorded,
                        },
                    digest,
                    ..
                } if *recorded == subject => Some(*digest),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(certificates.len(), 1, "{cold_keys:?}");
        assert!(
            !format!("{cold_keys:?}").contains("app/Missing.java"),
            "{cold_keys:?}"
        );
        // Verification recomputes the same answer on an unchanged head.
        assert_eq!(
            crate::analyzer::java::workspace_facts::answer(
                &java,
                brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalRootDescendants,
                Language::Java,
                &subject,
            ),
            Some(certificates[0])
        );
        assert!(
            cold_reasons
                .iter()
                .any(|reason| reason.contains("unresolved_supertype: com.missing.Gone")),
            "{cold_reasons:?}"
        );
        // Another member of the same root reuses the retained walk, and its
        // report of the unresolved supertype still reaches the caller.
        let (open_names, _, open_reasons) = family("open");
        assert_eq!(open_names, ["app.Servlet.open"]);
        assert_eq!(open_reasons, cold_reasons);
        let (warm_names, warm_keys, warm_reasons) = family("close");
        assert_eq!(warm_names, cold_names);
        assert_eq!(warm_keys, cold_keys);
        assert_eq!(warm_reasons, cold_reasons);
    }
}
