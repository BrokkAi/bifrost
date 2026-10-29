use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalDefinition;
use brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
use brokk_bifrost_analysis::analyzer::{
    CodeUnit, DeclarationKind, IAnalyzer, Language, ProjectFile, Range, resolve_analyzer,
};
use brokk_bifrost_analysis::cancellation::CancellationToken;
use brokk_bifrost_analysis::hash::{HashMap, HashSet};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::usages::inverted_edges::first_precise;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

use crate::analyzer::CSharpAnalyzer;

use brokk_bifrost_csharp::graph::resolver::CSharpInitializerOwnerLookups;

use brokk_bifrost_csharp::graph::resolver::CSharpInitializerOwnerTarget;

use brokk_bifrost_csharp::graph::resolver::argument_count as csharp_argument_count;

use brokk_bifrost_csharp::graph::resolver::collection_target_element_type_node as csharp_collection_target_element_type_node;

use crate::analyzer::usages::csharp_graph::csharp_extension_invocation_return_type_fq_name;

use brokk_bifrost_csharp::graph::resolver::first_type_child as csharp_first_type_child;

use brokk_bifrost_csharp::graph::extractor::is_declaration_name as csharp_is_declaration_name;

use brokk_bifrost_csharp::graph::resolver::is_type_reference_node as csharp_is_type_reference_node;

use brokk_bifrost_csharp::graph::resolver::member_declared_collection_element_type_fq_name as csharp_member_declared_collection_element_type_fq_name;

use brokk_bifrost_csharp::graph::resolver::member_declared_collection_element_type_fq_name_in_session as csharp_member_declared_collection_element_type_fq_name_in_session;

use brokk_bifrost_csharp::graph::resolver::member_declared_type_fq_name as csharp_member_declared_type_fq_name;

use brokk_bifrost_csharp::graph::resolver::method_return_type_fq_name_for_arity as csharp_method_return_type_fq_name_for_arity;

use brokk_bifrost_csharp::graph::resolver::node_text as csharp_node_text;

use brokk_bifrost_csharp::graph::resolver::object_created_type as csharp_object_created_type;

use brokk_bifrost_csharp::graph::resolver::object_initializer_for_label as csharp_object_initializer_for_label;

use brokk_bifrost_csharp::graph::resolver::object_initializer_owners as csharp_object_initializer_owners;

use brokk_bifrost_csharp::graph::resolver::reference_type_text as csharp_reference_type_text;

use brokk_bifrost_csharp::graph::resolver::type_parameter_shadows_reference as csharp_type_parameter_shadows_reference;

use crate::analyzer::usages::csharp_graph::csharp_visible_extension_method_candidates;

use brokk_bifrost_csharp::graph::extractor::member_access_name as csharp_member_access_name;

use brokk_bifrost_csharp::graph::extractor::member_access_receiver as csharp_member_access_receiver;

use brokk_bifrost_csharp::graph::resolver::seed_bindings_before as seed_csharp_bindings_before;

use brokk_bifrost_csharp::graph_support;

use brokk_bifrost_csharp::hierarchy;

use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

use brokk_bifrost_core::analyzer::structural::resolution::RejectionReason;

use brokk_bifrost_analysis::analyzer::usages::applicability::ApplicabilityOutcome;

use brokk_bifrost_analysis::analyzer::usages::applicability::CandidateApplicability;

use brokk_bifrost_analysis::analyzer::usages::applicability::arity_verdict;

use brokk_bifrost_core::analyzer::usages::common::same_node;

use brokk_bifrost_csharp::graph::resolver::CSharpDeclaredType;

use crate::analyzer::usages::csharp_graph::csharp_extension_invocation_return_type_fq_name_in_session;

use brokk_bifrost_csharp::graph::resolver::member_declared_type_fq_name_in_session as csharp_member_declared_type_fq_name_in_session;

use brokk_bifrost_csharp::graph::resolver::method_return_type_fq_name_for_arity_in_session as csharp_method_return_type_fq_name_for_arity_in_session;

use crate::analyzer::usages::csharp_graph::csharp_visible_extension_method_candidates_in_session;

use brokk_bifrost_csharp::graph::resolver::seed_bindings_before_in_session as seed_csharp_bindings_before_in_session;

use brokk_bifrost_core::analyzer::usages::reference_site::node_range;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_csharp::syntax::csharp_attribute_name_node;

use brokk_bifrost_csharp::syntax::csharp_attribute_type_names;

use brokk_bifrost_csharp::syntax::csharp_conditional_member_access;

use brokk_bifrost_csharp::syntax::csharp_member_name;

use brokk_bifrost_csharp::syntax::csharp_normalize_full_name;

use brokk_bifrost_core::analyzer::model::ClassLikeKind;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason,
};
use brokk_bifrost_csharp::graph::extractor::is_statement_label as csharp_is_statement_label;
use brokk_bifrost_csharp::graph::resolver::{
    CSharpCallArgumentOwners, call_argument_node, call_argument_parameter_index,
    canonical_builtin_type_identity as csharp_canonical_builtin_type_identity,
    csharp_invocation_member, filter_call_argument_method_candidates_with_metadata,
    resolve_call_argument_owners, with_callable_parameter_type_nodes,
};
use brokk_bifrost_csharp::graph_support::CSharpSource;
use brokk_bifrost_csharp::syntax::csharp_source_identifier;
use brokk_bifrost_csharp::syntax::{
    CSharpNamedArgumentLabel, csharp_arity_preserving_full_name,
    csharp_constant_pattern_type_candidate, csharp_implicit_accessor_value,
    csharp_is_member_variable_owner_kind, csharp_local_binder_name, csharp_named_argument_label,
    csharp_nameof_type_candidates, csharp_parameter_name_and_type, csharp_type_node_identity,
    csharp_using_directive_is_static, csharp_using_directive_target_node,
};
use std::cell::RefCell;

pub(crate) struct CSharpDefinitionProvider<'a> {
    csharp: &'a CSharpAnalyzer,
    session: Option<&'a ResolutionSession>,
    // Complete demand answers die with this resolution request. In bounded
    // sessions, the existing summary allowance bounds retained owners.
    direct_ancestor_answers: RefCell<HashMap<CodeUnit, Vec<CodeUnit>>>,
    parent_answers: RefCell<HashMap<CodeUnit, Option<CodeUnit>>>,
    /// Declarations this request admitted although their compilation
    /// membership is unproven. An answer reached with one is not proven.
    unproven_types: RefCell<Vec<CodeUnit>>,
    /// The analyzer viewed through the compilation membership of the file
    /// holding the reference being resolved. Every declaration this provider
    /// returns, and every lookup of the shared usage resolver it calls, is
    /// held to that one rule.
    scoped: brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource<'a>,
}

impl<'a> CSharpDefinitionProvider<'a> {
    pub(crate) fn new(csharp: &'a CSharpAnalyzer, reference: &ProjectFile) -> Self {
        Self {
            csharp,
            session: None,
            direct_ancestor_answers: RefCell::default(),
            parent_answers: RefCell::default(),
            unproven_types: RefCell::default(),
            scoped: brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource::new(
                csharp, reference,
            ),
        }
    }

    fn bounded(
        csharp: &'a CSharpAnalyzer,
        session: &'a ResolutionSession,
        reference: &ProjectFile,
    ) -> Self {
        Self {
            csharp,
            session: Some(session),
            direct_ancestor_answers: RefCell::default(),
            parent_answers: RefCell::default(),
            unproven_types: RefCell::default(),
            scoped: brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource::new(
                csharp, reference,
            ),
        }
    }

    /// The analyzer source for the shared usage resolver, held to the
    /// reference's compilation membership.
    fn source(&self) -> &dyn graph_support::CSharpSource {
        &self.scoped
    }

    /// The declarations among `units` the reference's compilation may see.
    /// Every lookup this provider makes passes through here, under the one
    /// rule [`MembershipScopedSource::admit_all`] states for the shared
    /// resolver too: invisible declarations are dropped, unproven parts are
    /// kept, and a member identity without a visible declaration is doubt.
    fn admit_units(&self, units: impl IntoIterator<Item = CodeUnit>) -> Vec<CodeUnit> {
        self.scoped.admit_all(units)
    }

    /// The declarations of `types`, remembering the unproven ones so the
    /// answer they reach is held to its proof.
    fn admit_visible_types(&self, types: graph_support::VisibleTypes) -> Vec<CodeUnit> {
        self.unproven_types
            .borrow_mut()
            .extend(types.unproven.iter().cloned());
        types.declarations
    }

    fn scope_step(&self) -> bool {
        brokk_bifrost_analysis::analyzer::usages::get_definition::session_scope_step(self.session)
    }

    fn summary_step(&self) -> bool {
        brokk_bifrost_analysis::analyzer::usages::get_definition::summary_step(self.session)
    }

    fn observe_cancellation(&self) -> bool {
        self.session
            .is_none_or(ResolutionSession::observe_cancellation)
    }

    fn query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        ResolutionSession::query_with_optional_session(self.session, query)
    }

    fn query_optional<T>(&self, query: impl FnOnce() -> Option<T>) -> Option<T> {
        match self.session {
            Some(session) => session.query_optional(query),
            None => query(),
        }
    }

    fn signature_metadata(
        &self,
        unit: &CodeUnit,
    ) -> Vec<brokk_bifrost_core::analyzer::model::SignatureMetadata> {
        ResolutionSession::query_limited_rows_with_optional_session(
            self.session,
            |limit| self.csharp.signature_metadata_limited(unit, limit),
            || self.csharp.signature_metadata(unit),
        )
    }

    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let found = self.unadmitted_fqn(fqn);
        self.admit_units(found)
    }

    fn unadmitted_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let exact = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::declaration_candidates_by_fqn_limited(
                    self.csharp,
                    fqn,
                    false,
                    limit,
                    || session.observe_cancellation(),
                )
            }),
            None => graph_support::declaration_candidates_by_fqn(self.csharp, fqn, false)
                .into_iter()
                .collect(),
        };
        if !exact.is_empty() {
            return exact;
        }
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::declaration_candidates_by_fqn_limited(
                    self.csharp,
                    fqn,
                    true,
                    limit,
                    || session.observe_cancellation(),
                )
            }),
            None => graph_support::declaration_candidates_by_fqn(self.csharp, fqn, true)
                .into_iter()
                .collect(),
        }
    }

    fn arity_free_types_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let found = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::arity_free_declaration_type_candidates_by_fqn_limited(
                    self.csharp,
                    fqn,
                    limit,
                    || session.observe_cancellation(),
                )
            }),
            None => graph_support::arity_free_declaration_type_candidates_by_fqn(self.csharp, fqn),
        };
        self.admit_units(found)
    }

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let found: Vec<CodeUnit> = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self
                .csharp
                .member_candidates_for_owner(owner_fqn, name)
                .into_iter()
                .collect(),
        };
        self.admit_units(found)
    }

    fn package_exists(&self, package: &str) -> bool {
        self.query(|| self.csharp.workspace_namespace_exists(package))
            .unwrap_or(false)
    }

    fn type_exists(&self, fqn: &str) -> bool {
        self.fqn(fqn).into_iter().any(|unit| unit.is_class())
    }

    fn visible_type_candidates(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.visible_type_candidates_with_lookup(token, file, name, &mut |fqn| self.fqn(fqn))
    }

    fn visible_type_candidates_at(
        &self,
        file: &ProjectFile,
        name: &str,
        source: &str,
        node: Node<'_>,
    ) -> Vec<CodeUnit> {
        let Some(context) =
            graph_support::CSharpLookupContext::at(source, node, &mut || self.scope_step())
        else {
            return Vec::new();
        };
        graph_support::visible_type_candidates_at_with_lookups(
            name,
            &context,
            &mut |name| self.global_alias_target_at(name),
            &mut || self.global_using_namespaces_at(),
            &mut |namespace| self.query(|| self.csharp.workspace_namespace_exists(namespace)),
            &mut |fqn| self.type_declarations_by_fqn(fqn),
            &mut |candidate: &CodeUnit| {
                self.csharp.compilation_visibility(file, candidate.source())
            },
            &mut || self.scope_step(),
        )
        .map(|types| self.admit_visible_types(types))
        .unwrap_or_default()
    }

    fn visible_type_declarations_at(
        &self,
        file: &ProjectFile,
        name: &str,
        source: &str,
        node: Node<'_>,
    ) -> Vec<CodeUnit> {
        let Some(context) =
            graph_support::CSharpLookupContext::at(source, node, &mut || self.scope_step())
        else {
            return Vec::new();
        };
        graph_support::visible_type_declarations_at_with_lookups(
            name,
            &context,
            &mut |name| self.global_alias_target_at(name),
            &mut || self.global_using_namespaces_at(),
            &mut |namespace| self.query(|| self.csharp.workspace_namespace_exists(namespace)),
            &mut |fqn| self.type_declarations_by_fqn(fqn),
            &mut |candidate: &CodeUnit| {
                self.csharp.compilation_visibility(file, candidate.source())
            },
            &mut || self.scope_step(),
        )
        .map(|types| self.admit_visible_types(types))
        .unwrap_or_default()
    }

    fn global_alias_target_at(&self, name: &str) -> Option<Option<String>> {
        let target = match self.session {
            Some(session) => session
                .query_limited_rows(|limit| {
                    self.csharp
                        .global_using_aliases_limited(limit, || session.observe_cancellation())
                })
                .into_iter()
                .find_map(|(alias, target)| (alias == name).then_some(target)),
            None => CSharpSource::global_using_aliases(self.csharp)
                .get(name)
                .cloned(),
        };
        self.observe_cancellation().then_some(target)
    }

    fn global_using_namespaces_at(&self) -> Option<Vec<String>> {
        let mut namespaces = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .global_using_namespaces_limited(limit, || session.observe_cancellation())
            }),
            None => CSharpSource::sorted_global_using_namespaces(self.csharp),
        };
        namespaces.sort();
        self.observe_cancellation().then_some(namespaces)
    }

    fn type_declarations_by_fqn(&self, fqn: &str) -> Option<Vec<CodeUnit>> {
        let candidates = self
            .fqn(fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
        self.observe_cancellation().then_some(candidates)
    }

    fn arity_free_visible_type_candidates(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.visible_type_candidates_with_lookup(token, file, name, &mut |fqn| {
            self.arity_free_types_by_fqn(fqn)
        })
    }

    fn visible_type_candidates_with_lookup<Candidates>(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
        type_candidates: &mut Candidates,
    ) -> Vec<CodeUnit>
    where
        Candidates: FnMut(&str) -> Vec<CodeUnit>,
    {
        let mut using_aliases = || {
            let aliases = self.using_aliases(token, file);
            self.observe_cancellation().then_some(aliases)
        };
        let mut namespace_of_file = || self.namespace_of_file(file);
        let mut file_using_namespaces = || {
            let namespaces = match self.session {
                Some(session) => session.query_limited_rows(|limit| {
                    graph_support::file_using_namespaces_limited(self.csharp, token, file, limit)
                }),
                None => self.csharp.file_using_namespaces_of(token, file),
            };
            self.observe_cancellation().then_some(namespaces)
        };
        let mut global_using_namespaces = || {
            let mut namespaces: Vec<_> = match self.session {
                Some(session) => session.query_limited_rows(|limit| {
                    self.csharp
                        .global_using_namespaces_limited(limit, || session.observe_cancellation())
                }),
                None => self
                    .csharp
                    .global_using_namespaces(token)
                    .iter()
                    .cloned()
                    .collect(),
            };
            namespaces.sort();
            self.observe_cancellation().then_some(namespaces)
        };
        // Not `package_exists`: that answers `false` for a namespace the budget
        // could not check, and a `false` here drops a probe. The gate must
        // answer `true` when it does not know.
        let mut namespace_exists = |namespace: &str| {
            self.query(|| self.csharp.workspace_namespace_exists(namespace))
                .unwrap_or(true)
        };
        let mut type_candidates_by_fqn = |fqn: &str| {
            let candidates = type_candidates(fqn)
                .into_iter()
                .filter(CodeUnit::is_class)
                .collect();
            self.observe_cancellation().then_some(candidates)
        };
        graph_support::visible_type_candidates_with_lookups(
            name,
            true,
            &mut using_aliases,
            &mut namespace_of_file,
            &mut file_using_namespaces,
            &mut global_using_namespaces,
            &mut namespace_exists,
            &mut type_candidates_by_fqn,
        )
    }

    /// Every declaration a base-type spelling on `part` can name. C# looks in
    /// the declaring type's enclosing type chain before the file's namespace
    /// and `using` scopes, which is the only way a nested base spelled by its
    /// simple name is reachable (#1801).
    fn supertype_candidates(
        &self,
        token: QueryToken<'_>,
        part: &CodeUnit,
        raw: &str,
    ) -> Vec<CodeUnit> {
        graph_support::supertype_candidates_with_lookups(
            &part.fq_name(),
            raw,
            &mut |fqn| {
                let candidates = self
                    .fqn(fqn)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect();
                self.observe_cancellation().then_some(candidates)
            },
            &mut |name| self.visible_type_candidates(token, part.source(), name),
        )
    }

    fn partial_type_parts(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        let parts = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::partial_type_parts_limited(self.csharp, owner, limit, || {
                    session.observe_cancellation()
                })
            }),
            None => graph_support::partial_type_parts(self.csharp, owner),
        };
        self.admit_units(parts)
    }

    fn using_namespaces(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .using_namespaces_of_limited(token, file, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.csharp.using_namespaces_of(token, file),
        }
    }

    fn global_using_namespaces(&self, token: QueryToken<'_>) -> Vec<String> {
        let mut namespaces = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .global_using_namespaces_limited(limit, || session.observe_cancellation())
            }),
            None => self
                .csharp
                .global_using_namespaces(token)
                .iter()
                .cloned()
                .collect(),
        };
        namespaces.sort();
        namespaces
    }

    fn using_aliases(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<HashMap<String, String>> {
        match self.session {
            Some(session) => Arc::new(
                session
                    .query_limited_rows(|limit| {
                        self.csharp
                            .using_aliases_of_limited(token, file, limit, || {
                                session.observe_cancellation()
                            })
                    })
                    .into_iter()
                    .collect(),
            ),
            // The analyzer's own memo cell already holds this map behind an
            // `Arc`, so the unbudgeted path hands it straight back.
            None => self.csharp.using_aliases_of(token, file),
        }
    }

    fn import_infos(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        ResolutionSession::query_limited_rows_with_optional_session(
            self.session,
            |limit| self.csharp.import_info_of_limited(token, file, limit),
            || self.csharp.import_info_of(token, file).to_vec(),
        )
    }

    fn namespace_of_file(&self, file: &ProjectFile) -> Option<String> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.csharp.namespace_of_file_limited(file, limit))
                .into_iter()
                .next(),
            None => Some(self.csharp.namespace_of_file(file)),
        }
    }

    /// The indexed attribute classes an attribute name can denote, and whether
    /// more than one of its spellings resolved.
    ///
    /// An attribute name is a type reference the grammar spells outside the
    /// type roles, so each spelling takes the same lookup ladder an ordinary
    /// C# type reference at `byte` takes: the enclosing type chain, then the
    /// enclosing namespace scopes and their lexically visible `using`
    /// directives. File-wide namespace/import hints cannot establish a site's
    /// context when sibling namespaces declare same-name types (#5198).
    /// Only the file-wide stage originally ran here, which is why `[Mark]`
    /// could not name a `MarkAttribute` nested in the very class that writes
    /// it, and why any attribute name failed in a file whose recorded
    /// namespace is not the one enclosing the reference (#3300).
    fn attribute_type_candidates(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        names: &[String],
        source: &str,
        node: Node<'_>,
    ) -> (Vec<CodeUnit>, bool) {
        let byte = node.start_byte();
        let mut type_candidates = |name: &str| {
            if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
                analyzer, token, self, file, name, byte,
            ) {
                return Some(vec![unit]);
            }
            let candidates = self.visible_type_declarations_at(file, name, source, node);
            self.observe_cancellation().then_some(candidates)
        };
        let mut attribute_class_is_applicable = |candidate: &CodeUnit| match self.session {
            Some(_) => self.attribute_class_is_applicable(token, candidate),
            // Through the membership view, so a base list counts by its
            // part's membership and its doubt reaches the answer.
            None => Some(hierarchy::attribute_class_is_applicable(
                self.source(),
                token,
                candidate,
            )),
        };
        hierarchy::attribute_type_candidates_with_lookups(
            names,
            &mut type_candidates,
            &mut attribute_class_is_applicable,
        )
        .unwrap_or((Vec::new(), false))
    }

    fn attribute_class_is_applicable(
        &self,
        token: QueryToken<'_>,
        candidate: &CodeUnit,
    ) -> Option<bool> {
        const ATTRIBUTE_FQN: &str = "System.Attribute";

        let session = self.session?;
        let mut stack = vec![candidate.clone()];
        let mut seen = HashSet::default();
        let mut unresolved_ancestry = false;
        while let Some(current) = stack.pop() {
            if !self.scope_step() {
                return None;
            }
            let current_fqn = current.fq_name();
            if !seen.insert(current_fqn.clone()) {
                continue;
            }
            if csharp_normalize_full_name(&current_fqn) == ATTRIBUTE_FQN {
                return Some(true);
            }

            let mut parts = self.partial_type_parts(&current);
            if !self.observe_cancellation() {
                return None;
            }
            if parts.is_empty() {
                parts.push(current);
            }
            for part in parts {
                if !self.scope_step() {
                    return None;
                }
                // Held to the part's membership, as in `raw_supertypes`.
                let raw_supertypes = self.raw_supertypes(&part);
                if !self.observe_cancellation() {
                    return None;
                }
                for raw in raw_supertypes {
                    let normalized_raw = csharp_normalize_full_name(&raw);
                    if normalized_raw == ATTRIBUTE_FQN {
                        return Some(true);
                    }
                    if matches!(normalized_raw.as_str(), "object" | "System.Object") {
                        continue;
                    }
                    let ancestors = self.supertype_candidates(token, &part, &raw);
                    if !self.observe_cancellation() {
                        return None;
                    }
                    if ancestors.is_empty() || graph_support::logical_type_count(&ancestors) > 1 {
                        unresolved_ancestry = true;
                    } else {
                        stack.extend(ancestors);
                    }
                }
            }
        }

        if unresolved_ancestry {
            session.mark_scope_incomplete();
            None
        } else {
            Some(false)
        }
    }

    /// The base-type spellings `part` declares, exactly as written.
    ///
    /// Unlike [`Self::direct_ancestors`] this keeps a spelling the workspace
    /// cannot resolve, which is what tells a complete hierarchy apart from one
    /// that leaves the indexed workspace (#1797).
    /// The base list of a physical part, held to membership: an unproven
    /// part's bases are doubt and an invisible part has none.
    fn raw_supertypes(&self, part: &CodeUnit) -> Vec<String> {
        let source = self.source();
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| source.raw_supertypes_limited(part, limit))
            }
            None => source.raw_supertypes_of(part),
        }
    }

    /// The direct ancestors of `owner` read from its admitted physical parts'
    /// base lists, each base admitted too: a part outside the reference's
    /// compilation contributes no base, and an unproven one contributes its
    /// bases as doubt.
    fn direct_ancestors(&self, token: QueryToken<'_>, owner: &CodeUnit) -> Vec<CodeUnit> {
        if !self.observe_cancellation() {
            return Vec::new();
        }
        if let Some(ancestors) = self.direct_ancestor_answers.borrow().get(owner) {
            return if self
                .session
                .is_none_or(|session| session.scope_steps(ancestors.len()))
            {
                ancestors.clone()
            } else {
                Vec::new()
            };
        }
        if !self.summary_step() {
            return Vec::new();
        }

        let mut parts = self.partial_type_parts(owner);
        if !self.observe_cancellation() {
            return Vec::new();
        }
        if parts.is_empty() {
            parts.push(owner.clone());
        }
        let ancestors = graph_support::logical_direct_ancestors(
            parts,
            |part| {
                if !self.scope_step() {
                    return None;
                }
                let raw = self.raw_supertypes(part);
                self.observe_cancellation().then_some(raw)
            },
            |part, raw| {
                let candidates = self.supertype_candidates(token, part, raw);
                self.observe_cancellation().then_some(candidates)
            },
            |_| Some(()),
        );
        let Some(ancestors) = ancestors.filter(|_| self.observe_cancellation()) else {
            return Vec::new();
        };
        self.direct_ancestor_answers
            .borrow_mut()
            .insert(owner.clone(), ancestors.clone());
        ancestors
    }

    fn parent_of(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
        let Some(session) = self.session else {
            return analyzer.parent_of(unit);
        };
        if !session.observe_cancellation() {
            return None;
        }
        if let Some(parent) = self.parent_answers.borrow().get(unit) {
            if parent.is_some() && !self.scope_step() {
                return None;
            }
            return parent.clone();
        }
        if !self.summary_step() {
            return None;
        }
        let parent = analyzer.parent_of(unit);
        if !self.observe_cancellation() {
            return None;
        }
        if parent.is_some() && !self.scope_step() {
            return None;
        }
        self.parent_answers
            .borrow_mut()
            .insert(unit.clone(), parent.clone());
        parent
    }

    fn session(&self) -> Option<&ResolutionSession> {
        self.session
    }
}

fn csharp_smallest_named_node_covering<'tree>(
    definitions: &CSharpDefinitionProvider<'_>,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !definitions.scope_step() || node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.children(&mut cursor) {
            if !definitions.scope_step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing_child = Some(child);
                break;
            }
        }
        match containing_child {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

pub(crate) enum CSharpTypeLookupResolution {
    Type {
        fqn: String,
        candidates: Vec<CodeUnit>,
        target_kind: TypeLookupTargetKind,
        ambiguous: bool,
    },
    External {
        names: Vec<String>,
        target_kind: TypeLookupTargetKind,
    },
    Dynamic {
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

/// CLR metadata names the property behind a C# indexer `Item`.
use brokk_bifrost_csharp::syntax::CSHARP_INDEXER_MEMBER_NAME;

pub(crate) fn csharp_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    session: &ResolutionSession,
) -> Option<CSharpTypeLookupResolution> {
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
    let definitions = CSharpDefinitionProvider::bounded(csharp, session, file);
    let node = csharp_smallest_named_node_covering(
        &definitions,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    csharp_type_lookup_node_resolution(
        analyzer,
        token,
        csharp,
        &definitions,
        file,
        source,
        root,
        node,
    )
}

fn csharp_using_alias_definition(
    root: Node<'_>,
    source: &str,
    reference: &str,
) -> Option<LexicalDefinition> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "using_directive"
            && let Some(name) = node.child_by_field_name("name")
            && csharp_node_text(name, source).trim() == reference
        {
            let range = |node: Node<'_>| Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
            };
            return Some(LexicalDefinition {
                source_file: None,
                identifier: reference.to_string(),
                kind: DeclarationKind::ImportAlias,
                name_range: range(name),
                declaration_range: range(node),
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

/// The written `using` binder navigation should land on for `reference`, or
/// `None` when the reference is not an alias or the alias leaves the workspace.
///
/// Commit 9a9c6dedf made navigation on a C# using alias reach the alias binder
/// rather than the canonical type, matching what Roslyn's go-to-definition does.
/// That binder is only a useful destination while the alias target is indexed:
/// the caller lands on the `using` line and can keep navigating from it. When
/// the target is outside the workspace the binder is a dead end, and answering
/// `resolved` there would replace the `unresolvable_import_boundary` status with
/// a location that never tells the caller navigation left the indexed
/// workspace. The alias-target-not-indexed predicate below is the same one the
/// type path uses to raise that boundary, so declining here hands the reference
/// back to it.
#[allow(clippy::too_many_arguments)]
fn csharp_navigable_using_alias_binding(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    source: &str,
    reference: &str,
) -> Option<LexicalDefinition> {
    if !definitions
        .using_aliases(token, file)
        .contains_key(reference)
        || csharp_alias_using_boundary_for_type(csharp, token, definitions, file, reference)
    {
        return None;
    }
    csharp_using_alias_definition(root, source, reference)
}

pub(crate) struct CSharpDefinitionResolution {
    pub(crate) outcome: DefinitionLookupOutcome,
    pub(crate) evidence: CallEvidence,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    preserve_using_alias: bool,
) -> CSharpDefinitionResolution {
    let outcome = resolve_csharp_in_session(
        analyzer,
        token,
        definitions,
        file,
        source,
        tree,
        site,
        preserve_using_alias,
    );
    let constructor_evidence = csharp_external_constructor_evidence(
        analyzer,
        token,
        definitions,
        file,
        source,
        tree,
        site,
        &outcome,
    );
    let evidence = if constructor_evidence.exact_external_call.is_some() {
        constructor_evidence
    } else {
        csharp_external_member_evidence(
            analyzer,
            definitions.csharp,
            definitions,
            source,
            tree,
            site,
            &outcome,
        )
    };
    CSharpDefinitionResolution { outcome, evidence }
}

#[allow(clippy::too_many_arguments)]
fn csharp_external_member_evidence(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    outcome: &DefinitionLookupOutcome,
) -> CallEvidence {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !outcome.definitions.is_empty()
        || !outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "csharp_receiver_type_unindexed")
    {
        return CallEvidence::default();
    }
    let Some(canonical) = outcome
        .reference
        .as_ref()
        .map(|reference| reference.text.as_str())
    else {
        return CallEvidence::default();
    };
    let Some((owner, member)) =
        brokk_bifrost_analysis::analyzer::semantic::split_canonical_qualified_callee(
            canonical,
            Language::CSharp,
        )
    else {
        return CallEvidence::default();
    };
    let staticness =
        csharp.external_member_is_static(analyzer.semantic_model_overlay(), &owner, &member);
    let Some(is_static) = staticness else {
        return CallEvidence::default();
    };
    let Some(tree) = tree else {
        return CallEvidence::default();
    };
    let Some(node) = csharp_smallest_named_node_covering(
        definitions,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return CallEvidence::default();
    };
    let Some(CSharpReferenceNode::Member { name, .. }) = csharp_reference_node(node, definitions)
    else {
        return CallEvidence::default();
    };
    let Some(parameter_count) = csharp_invocation_arity(name, source, definitions)
        .and_then(|count| u32::try_from(count).ok())
    else {
        return CallEvidence::default();
    };
    let proof = if is_static {
        ExactExternalCallProof::csharp_static_external_member(&owner, &member, parameter_count)
    } else {
        ExactExternalCallProof::csharp_bound_external_member(&owner, &member, parameter_count)
    };
    CallEvidence {
        call_application: proof.call_application(),
        dispatch_extensibility: proof.dispatch_extensibility(),
        exact_external_call: Some(proof),
        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
            Language::CSharp,
            owner,
            member,
        )),
        authority: DefinitionResolutionAuthority::Incumbent,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_csharp_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    ResolutionSession::run_bounded(budget, cancellation, |session| {
        let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
            return no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable");
        };
        let definitions = CSharpDefinitionProvider::bounded(csharp, session, file);
        resolve_csharp_in_session(
            analyzer,
            token,
            &definitions,
            file,
            source,
            tree,
            site,
            false,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_csharp_in_session(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    preserve_using_alias: bool,
) -> DefinitionLookupOutcome {
    let outcome = resolve_csharp_reference(
        analyzer,
        token,
        definitions,
        file,
        source,
        tree,
        site,
        preserve_using_alias,
    );
    hold_to_compilation_membership(analyzer, definitions, file, outcome)
}

/// Hold an answer to compilation membership.
///
/// A definition is proven only where the reference's compilation sees its
/// identity (some physical declaration of it): one only an invisible copy
/// declares is dropped, and one only an unproven copy declares leaves the
/// answer `Incomplete`. A type of unproven membership that took part in this
/// resolution (as a receiver, base, constructed or named type) also leaves a
/// resolved or decided-negative answer `Incomplete`: the derivation through
/// it is not proven even when the definition reached is. That is tracked for
/// the whole request, which over-approximates the derivation rather than
/// losing doubt. Definitions found still arrive under `Incomplete`.
fn hold_to_compilation_membership(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    let mut doubt = Vec::new();
    let root = analyzer.project().root();
    let mut removed = Vec::new();
    let mut unproven_definitions = Vec::new();
    let mut failed = false;
    outcome.definitions.retain(|definition| {
        // Declarations outside the workspace carry their own provenance.
        if definition.source().root() != root {
            return true;
        }
        match graph_support::identity_visibility(
            definitions.csharp,
            file,
            &definition.fq_name(),
            Some(definition),
            |candidate| {
                candidate.kind() == definition.kind()
                    && candidate.signature() == definition.signature()
            },
        ) {
            Some(graph_support::CSharpCompilationVisibility::Visible) => true,
            Some(graph_support::CSharpCompilationVisibility::NotVisible) => {
                removed.push(definition.fq_name());
                false
            }
            Some(graph_support::CSharpCompilationVisibility::Unresolved) => {
                unproven_definitions.push(definition.fq_name());
                true
            }
            None => {
                failed = true;
                true
            }
        }
    });
    if !removed.is_empty() {
        doubt.push(format!(
            "definitions {removed:?} are declared only where this compilation cannot see them"
        ));
    }
    if !unproven_definitions.is_empty() {
        doubt.push(format!(
            "definitions {unproven_definitions:?} are declared only where compilation membership is unproven"
        ));
    }
    if failed {
        doubt.push("compilation membership could not be read".to_owned());
    }
    if definitions.scoped.doubt() > 0 {
        doubt.push(format!(
            "{} shared-resolver lookups admitted declarations of unproven compilation membership",
            definitions.scoped.doubt()
        ));
    }
    let unproven = definitions.unproven_types.borrow();
    if !unproven.is_empty() {
        doubt.push(format!(
            "visible types {:?} depend on compilation membership the configuration does not prove",
            unproven.iter().map(CodeUnit::fq_name).collect::<Vec<_>>()
        ));
    }
    // Only an answer that claims something is downgraded; an ambiguity or a
    // stop already makes no claim.
    if !doubt.is_empty()
        && matches!(
            outcome.status,
            DefinitionLookupStatus::Resolved
                | DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::NotFound
        )
    {
        outcome.status = DefinitionLookupStatus::Incomplete;
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "csharp_compilation_membership_unproven".to_owned(),
            message: doubt.join("; "),
        });
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn resolve_csharp_reference(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    preserve_using_alias: bool,
) -> DefinitionLookupOutcome {
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("csharp_parse_failed", "C# source could not be parsed");
    };
    let Some(node) = csharp_smallest_named_node_covering(
        definitions,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C# definition",
                site.text
            ),
        );
    };
    if csharp_is_declaration_name(node) || csharp_is_namespace_using_target(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a C# reference site", site.text),
        );
    }
    if csharp_is_statement_label(node) {
        return no_definition(
            "statement_label_site",
            format!("`{}` is a C# statement label, not a reference", site.text),
        );
    }
    // Two C# roles introduce a binding at the occurrence itself, and no
    // declaration index publishes either, so the lexical pre-pass that runs
    // ahead of this resolver cannot answer them and the enclosing-class member
    // walk below must never see them. Both were already read off the grammar for
    // the #2059 census taxonomy; forward lookup now consults the same helpers
    // rather than a parallel spelling test (#2164).
    //
    // `value` is the implicit parameter of a `set`, `init`, `add` or `remove`
    // accessor. SteamKit's generated `public uint value { ... set => __pbn__value
    // = value; }` bound the read to the property that encloses it; the language
    // forbids anything else called `value` in that scope (CS0136), so the read is
    // the parameter and the answer is a local binding.
    if csharp_implicit_accessor_value(node, source) {
        return no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            format!(
                "`{}` is the implicit parameter of a C# write accessor",
                site.text
            ),
        );
    }
    // A binder name is the grammar's own `name` field of a tuple element,
    // pattern, `catch`, `out var`, deconstruction, type-parameter or LINQ
    // range-variable declaration. `(string Name, object Value)` in StockSharp's
    // `ReportSource` bound `Name` to the class property of that spelling; the
    // element's `type` field is the only reference the node carries, and it is
    // classified as a type before the walk below.
    if csharp_local_binder_name(node) {
        return no_definition(
            DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND,
            format!("`{}` is not a C# reference site", site.text),
        );
    }

    match csharp_reference_node(node, definitions) {
        Some(CSharpReferenceNode::Attribute(name)) => {
            csharp_attribute_outcome(analyzer, token, csharp, definitions, file, name, source)
        }
        Some(CSharpReferenceNode::Type(type_reference)) => {
            let (type_node, reference) = match type_reference {
                CSharpTypeReference::Complete(type_node) => {
                    (type_node, csharp_reference_type_text(type_node, source))
                }
                CSharpTypeReference::FocusedSegment(type_node) => {
                    (type_node, csharp_type_node_identity(type_node, source))
                }
            };
            if csharp_type_parameter_shadows_reference(type_node, source, &reference) {
                return no_definition(
                    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                    format!("`{reference}` is a lexical C# type parameter"),
                );
            }
            if preserve_using_alias
                && let Some(alias) = csharp_navigable_using_alias_binding(
                    csharp,
                    token,
                    definitions,
                    file,
                    tree.root_node(),
                    source,
                    &reference,
                )
            {
                return lexical_definition_outcome(alias);
            }
            if csharp_alias_qualified_boundary(definitions, token, file, type_node, source) {
                // gated upstream: the alias target names neither an indexed
                // type nor an indexed namespace, so the qualifier itself is
                // structured evidence that this reference leaves the workspace.
                return boundary_unchecked(
                    format!(
                        "`{reference}` appears to cross a C# using-alias boundary not indexed in this workspace"
                    ),
                    UnindexedClaim::external_boundary(reference, ClaimSubjectRole::Type),
                );
            }
            if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
                analyzer,
                token,
                definitions,
                file,
                &reference,
                type_node.start_byte(),
            ) {
                return candidates_outcome(vec![unit]);
            }
            // Prefer a type in the lexically enclosing scope (namespace/class) over
            // the scope-blind type resolver, so a bare `Config` inside `namespace B`
            // resolves to `B.Config` rather than a same-named sibling namespace's
            // (#431).
            if let Some(unit) = resolve_csharp_in_enclosing_scopes(
                analyzer,
                definitions,
                file,
                &reference,
                type_node.start_byte(),
                CodeUnit::is_class,
            ) {
                return candidates_outcome(vec![unit]);
            }
            csharp_type_outcome(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                type_node,
                &reference,
            )
        }
        Some(CSharpReferenceNode::Constructor(creation)) => {
            if preserve_using_alias
                && let Some(type_node) = creation
                    .child_by_field_name("type")
                    .or_else(|| csharp_first_type_child(creation))
            {
                let reference = csharp_reference_type_text(type_node, source);
                if let Some(alias) = csharp_navigable_using_alias_binding(
                    csharp,
                    token,
                    definitions,
                    file,
                    tree.root_node(),
                    source,
                    &reference,
                ) {
                    return lexical_definition_outcome(alias);
                }
            }
            resolve_csharp_constructor(analyzer, token, csharp, definitions, file, source, creation)
        }
        Some(CSharpReferenceNode::Indexer { receiver }) => csharp_indexer_outcome(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            tree.root_node(),
            site,
            receiver,
        ),
        Some(CSharpReferenceNode::Member { receiver, name }) => {
            let Some((member, explicit_generic_arity)) = csharp_member_name_parts(name, source)
            else {
                return no_definition("no_member_name", "C# member reference is blank");
            };
            if member.is_empty() {
                return no_definition("no_member_name", "C# member reference is blank");
            }
            let member_name_node = csharp_member_name(name)
                .map(|name| name.identifier)
                .unwrap_or(name);
            let receiver_types = csharp_receiver_types(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            let owners = receiver_types.units;
            let mut receiver_type_names = receiver_types.fq_names;
            let structured_receiver_type_names = csharp_structured_receiver_type_names(
                csharp,
                token,
                definitions,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            if receiver_type_names.is_empty() {
                receiver_type_names = structured_receiver_type_names.clone();
            } else if !structured_receiver_type_names.is_empty() {
                receiver_type_names.extend(structured_receiver_type_names.iter().cloned());
                receiver_type_names.sort();
                receiver_type_names.dedup();
            }
            if owners.is_empty() && receiver_type_names.is_empty() {
                receiver_type_names = csharp_unindexed_type_qualifier_names(
                    analyzer,
                    token,
                    csharp,
                    definitions,
                    file,
                    source,
                    tree.root_node(),
                    receiver,
                );
            }
            let arity = csharp_invocation_arity(name, source, definitions);
            let external_member_identity = csharp.external_member_identity(
                analyzer.semantic_model_overlay(),
                &receiver_type_names,
                member,
            );
            // C# instance-member lookup wins over extension methods. When the
            // declaration surface proves that the receiver is a sealed type,
            // an exact external instance member therefore excludes an
            // applicable workspace extension rather than leaving an ambiguity
            // boundary. This is especially important for BCL types whose
            // ordinary members are supplied by the activated reference model.
            let exact_sealed_external_instance = external_member_identity
                .as_deref()
                .and_then(|identity| {
                    let owner = identity.strip_suffix(member)?.strip_suffix('.')?;
                    (csharp.external_member_is_static(
                        analyzer.semantic_model_overlay(),
                        owner,
                        member,
                    ) == Some(false)
                        && csharp.external_type_is_sealed(analyzer.semantic_model_overlay(), owner)
                            == Some(true))
                    .then_some(())
                })
                .is_some();
            // Indexed ordinary members retain precedence. For external types,
            // invocation syntax and a precise receiver identity admit the same
            // structured extension applicability checks, including builtins.
            // A property read or an untyped receiver cannot prove an extension
            // invocation (#1266, #3182).
            let should_try_extensions = !exact_sealed_external_instance
                && (!owners.is_empty() || (!receiver_type_names.is_empty() && arity.is_some()));
            let mut outcome = csharp_member_outcome(
                analyzer,
                token,
                definitions,
                owners.clone(),
                member,
                arity,
                explicit_generic_arity,
            );
            // #1477: an extension candidate stays unattributed. The seam below
            // admits a method by matching its declared receiver spelling
            // against a *set* of compatible receiver type names -- the
            // receiver's own type and its supertypes, plus names the workspace
            // never indexed -- and returns only the declarations. It reports
            // neither which name matched nor the type it matched, so this side
            // holds no owner and no hop distance for the find. Attributing the
            // receiver's own type at depth zero would claim the extension was
            // declared on it, which an extension of a base type contradicts.
            // The member walk binds nothing both when it never saw the name and
            // when every declaration it saw was arity-inapplicable (#1797, which
            // reports a boundary rather than no_definition when the receiver's
            // bases leave the workspace). An extension method is a candidate for
            // either, so the escalation is gated on "bound nothing", not on one
            // particular unresolved status.
            if outcome.definitions.is_empty() && should_try_extensions {
                let extensions = match definitions.session() {
                    Some(session) => csharp_visible_extension_method_candidates_in_session(
                        definitions.source(),
                        analyzer,
                        token,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                        session,
                    ),
                    None => csharp_visible_extension_method_candidates(
                        definitions.source(),
                        analyzer,
                        token,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                    ),
                };
                if !extensions.is_empty() {
                    outcome = candidates_outcome(extensions);
                }
            }
            outcome = refine_csharp_invocation_overload(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                name,
                outcome,
            );
            if owners.is_empty() && !receiver_type_names.is_empty() {
                // The authored extension identity can be known while ordinary
                // member lookup remains incomplete. Keep that frontier even
                // for a positive result: an unindexed instance member might
                // take precedence over the applicable workspace extension.
                // An empty answer here is a boundary, not an exact negative.
                if outcome.definitions.is_empty() {
                    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
                    outcome
                        .diagnostics
                        .retain(|diagnostic| diagnostic.kind != "unsupported_csharp_receiver");
                }
                if !exact_sealed_external_instance {
                    outcome.diagnostics.push(DefinitionLookupDiagnostic {
                        kind: "csharp_receiver_type_unindexed".to_owned(),
                        message: format!(
                            "receiver types {receiver_type_names:?} for C# member `{member}` are not indexed; applicable workspace extensions do not complete ordinary member lookup"
                        ),
                        claim: Some(UnindexedClaim::external_boundary(
                            receiver_type_names.join(", "),
                            ClaimSubjectRole::Type,
                        )),
                    });
                }
                // The boundary is published under the canonical external
                // identity rather than the receiver *variable* spelling, so a
                // reviewed model can bind the exact member the call reaches
                // (#3461). This is the C# half of the publication Java adopted
                // in #3466. It is gated on the external declaration surface
                // itself -- an indexed assembly or an activated declaration-fact
                // pack declared the owner type *and* the member -- and
                // workspace member lookup has already answered nothing above,
                // so the route is external by construction. A surface that
                // names no candidate owner, or several, keeps the receiver
                // spelling and publishes no identity.
                if outcome.definitions.is_empty()
                    && let Some(canonical) = external_member_identity
                {
                    outcome.reference = Some(ResolvedReferenceSite {
                        text: canonical,
                        // The site is unchanged: only what it is *called*
                        // changes, so its own coordinates are carried through
                        // rather than rebuilt from a node.
                        ..site.clone()
                    });
                }
            }
            outcome
        }
        Some(CSharpReferenceNode::UnqualifiedMember(name)) => {
            let Some((member, explicit_generic_arity)) = csharp_member_name_parts(name, source)
            else {
                return no_definition("no_member_name", "C# member reference is blank");
            };
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                token,
                definitions,
                file,
                source,
                tree.root_node(),
                name.start_byte(),
            );
            if bindings.is_shadowed(member) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{member}` is a local C# value or local function"),
                );
            }
            let owners =
                csharp_enclosing_class_chain(analyzer, definitions, file, name.start_byte());
            let arity = csharp_invocation_arity(name, source, definitions);
            let outcome = csharp_member_outcome_in_enclosing_chain(
                analyzer,
                token,
                definitions,
                owners,
                member,
                arity,
                explicit_generic_arity,
            );
            let outcome = refine_csharp_invocation_overload(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                name,
                outcome,
            );
            if outcome.status == DefinitionLookupStatus::NoDefinition
                && csharp_static_using_boundary_for_member(csharp, token, definitions, file)
            {
                // The unindexed-static-using signal is member-blind (any
                // unresolved `using static` trips it). Tie the confident claim to
                // this member: if a static-using target the workspace *does*
                // index declares `member`, the missing resolution is a
                // workspace-internal gap, never an external boundary (#1158).
                return gated_boundary(
                    || {
                        csharp_member_declared_by_indexed_static_using(
                            definitions,
                            token,
                            file,
                            member,
                        )
                    },
                    format!(
                        "`{member}` appears to cross a C# static using boundary not indexed in this workspace"
                    ),
                    UnindexedClaim::external_boundary(member, ClaimSubjectRole::Member),
                    "no_indexed_definition",
                    format!("`{member}` did not resolve to an indexed C# member"),
                );
            }
            outcome
        }
        Some(CSharpReferenceNode::NamedArgumentLabel { label, shape }) => {
            csharp_named_argument_label_outcome(
                analyzer,
                token,
                definitions,
                file,
                source,
                label,
                shape,
            )
        }
        Some(CSharpReferenceNode::Identifier(identifier)) => {
            let text = csharp_node_text(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C# identifier is blank");
            }
            if let Some(outcome) = csharp_object_initializer_label_outcome(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                identifier,
            ) {
                return outcome;
            }
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                token,
                definitions,
                file,
                source,
                tree.root_node(),
                identifier.start_byte(),
            );
            if csharp_is_type_reference_node(identifier) {
                let reference = csharp_reference_type_text(identifier, source);
                return csharp_type_outcome(
                    analyzer,
                    token,
                    csharp,
                    definitions,
                    file,
                    source,
                    identifier,
                    &reference,
                );
            }
            if !bindings.is_shadowed(text) {
                if csharp_is_unqualified_member_reference(identifier) {
                    let owners = csharp_enclosing_class_chain(
                        analyzer,
                        definitions,
                        file,
                        identifier.start_byte(),
                    );
                    if !owners.is_empty() {
                        let outcome = csharp_member_outcome_in_enclosing_chain(
                            analyzer,
                            token,
                            definitions,
                            owners,
                            text,
                            None,
                            None,
                        );
                        if outcome.status != DefinitionLookupStatus::NoDefinition {
                            return outcome;
                        }
                    }
                    if !csharp_identifier_allows_type_fallback(identifier, source) {
                        return no_definition(
                            "no_indexed_definition",
                            format!("`{text}` did not resolve to an indexed C# member"),
                        );
                    }
                }
                if csharp_identifier_is_arity_free_type_name(identifier, source)
                    && let Some(outcome) = csharp_arity_free_type_outcome(
                        analyzer,
                        token,
                        definitions,
                        file,
                        text,
                        identifier.start_byte(),
                    )
                {
                    return outcome;
                }
                let outcome = csharp_type_outcome(
                    analyzer,
                    token,
                    csharp,
                    definitions,
                    file,
                    source,
                    identifier,
                    text,
                );
                if outcome.status != DefinitionLookupStatus::NoDefinition {
                    return outcome;
                }
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C# definition"),
            )
        }
        None => no_definition(
            "unsupported_csharp_reference_shape",
            format!(
                "`{}` is a C# `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn csharp_is_namespace_using_target(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "using_directive" {
            if csharp_using_directive_is_static(candidate)
                || candidate.child_by_field_name("name").is_some()
            {
                return false;
            }
            return csharp_using_directive_target_node(candidate).is_some_and(|target| {
                target.start_byte() <= node.start_byte() && target.end_byte() >= node.end_byte()
            });
        }
        current = candidate.parent();
    }
    false
}

fn csharp_structured_receiver_type_names(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    mut receiver: Node<'_>,
) -> Vec<String> {
    if !definitions.scope_step() {
        return Vec::new();
    }
    while matches!(
        receiver.kind(),
        "parenthesized_expression" | "checked_expression"
    ) {
        if !definitions.scope_step() {
            return Vec::new();
        }
        let Some(inner) = receiver.named_child(0) else {
            return Vec::new();
        };
        receiver = inner;
    }
    if receiver.kind() == "identifier" {
        let name = csharp_node_text(receiver, source);
        let typed_bindings = csharp_type_bindings_before_scoped(
            csharp,
            token,
            definitions,
            file,
            source,
            root,
            receiver.start_byte(),
        );
        if let Some(types) = typed_bindings.resolve_symbol(name).as_precise() {
            let mut names = types.iter().map(CodeUnit::fq_name).collect::<Vec<_>>();
            names.sort();
            names.dedup();
            if !names.is_empty() {
                return names;
            }
        }

        let bindings = csharp_legacy_bindings_before_scoped(
            csharp,
            token,
            definitions,
            file,
            source,
            root,
            receiver.start_byte(),
        );
        let mut names = Vec::new();
        if let Some(types) = bindings.resolve_symbol(name).as_precise() {
            for declared in types {
                match declared {
                    // The seeder already proved this identity against the same
                    // workspace generation, so it is taken as the answer rather
                    // than re-fed to the visible-name lookup ladder (#1842).
                    CSharpDeclaredType::Resolved { fqn } => names.push(fqn.clone()),
                    // The binding was declared earlier in this body, inside
                    // the receiver's namespace scopes.
                    CSharpDeclaredType::Spelling(spelling) => {
                        names.extend(csharp_structured_receiver_reference_type_names(
                            token,
                            definitions,
                            file,
                            source,
                            receiver,
                            spelling,
                        ));
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        return names;
    }
    let type_node = match receiver.kind() {
        "cast_expression" => receiver.child_by_field_name("type"),
        "as_expression" => receiver.child_by_field_name("right"),
        _ => None,
    };
    let Some(type_node) = type_node else {
        return Vec::new();
    };
    csharp_structured_receiver_reference_type_names(
        token,
        definitions,
        file,
        source,
        type_node,
        &csharp_reference_type_text(type_node, source),
    )
}

/// The type identities `reference`, written at `site`, can name: the one
/// visible declaration when the site's lookup proves it, otherwise the
/// spellings an external surface may answer.
fn csharp_structured_receiver_reference_type_names(
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    reference: &str,
) -> Vec<String> {
    let reference = csharp_arity_preserving_full_name(reference);
    if reference.is_empty() {
        return Vec::new();
    }
    if let Some(canonical) = csharp_canonical_builtin_type_identity(&reference) {
        return vec![canonical.to_string()];
    }
    let mut candidates =
        csharp_logical_visible_type_candidates(definitions, file, source, site, &reference);
    if candidates.len() == 1 {
        return vec![candidates.remove(0).fq_name()];
    }

    let aliases = definitions.using_aliases(token, file);
    let alias = aliases
        .get(&reference)
        .or_else(|| aliases.get(&csharp_normalize_full_name(&reference)))
        .cloned();
    let mut names = vec![alias.unwrap_or_else(|| reference.clone())];
    if !reference.contains('.') && !aliases.contains_key(&reference) {
        let namespaces = definitions.using_namespaces(token, file);
        for namespace in namespaces {
            if !definitions.scope_step() {
                return Vec::new();
            }
            names.push(format!("{namespace}.{reference}"));
        }
    }
    names.sort();
    names.dedup();
    names
}

#[allow(clippy::too_many_arguments)]
fn csharp_type_lookup_node_resolution(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    mut node: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    // Contextual identifiers can retain their anonymous keyword token beneath
    // the public `identifier` node. A reference range covers both exactly, and
    // the smallest-node lookup selects the token; resolution must operate on
    // the structured identifier wrapper that carries its AST role.
    if !node.is_named()
        && let Some(parent) = node.parent()
        && parent.kind() == "identifier"
        && parent.start_byte() == node.start_byte()
        && parent.end_byte() == node.end_byte()
    {
        node = parent;
    }
    if !definitions.scope_step() {
        return None;
    }
    // #3118's per-segment contract reaches the type-of question too: only the
    // segment the focus lands on is being asked about. The whole attribute
    // name takes the attribute-specific resolution; a shorter prefix is an
    // ordinary focused type segment and must answer for itself, never for the
    // attribute class spelled after the dot (#3289 on the definition surface,
    // #3300 here).
    if let Some(name) = csharp_attribute_name_node(node) {
        if csharp_node_spells_whole_attribute_name(node, name) {
            let names = csharp_attribute_type_names(name, source);
            let (candidates, ambiguous) =
                definitions.attribute_type_candidates(analyzer, token, file, &names, source, name);
            return csharp_type_candidates_resolution_with_kind(
                names.first().map(String::as_str).unwrap_or_default(),
                candidates,
                TypeLookupTargetKind::TypeReference,
                ambiguous,
            );
        }
        let reference = csharp_type_node_identity(node, source);
        return csharp_type_candidates_resolution_with_kind(
            &reference,
            csharp_visible_type_output_candidates(definitions, file, source, node, &reference),
            TypeLookupTargetKind::TypeReference,
            false,
        );
    }

    if matches!(
        node.kind(),
        "invocation_expression"
            | "object_creation_expression"
            | "member_access_expression"
            | "conditional_access_expression"
    ) {
        if csharp_expression_is_dynamic(csharp, definitions, file, source, root, node) {
            return Some(CSharpTypeLookupResolution::Dynamic {
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
        let candidates = csharp_receiver_types(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            node,
        )
        .units;
        return csharp_type_candidates_resolution(csharp_node_text(node, source), candidates);
    }

    if csharp_is_type_reference_node(node) {
        let reference = csharp_reference_type_text(node, source);
        if csharp_is_dynamic_type_reference(&reference) {
            return Some(CSharpTypeLookupResolution::Dynamic {
                target_kind: TypeLookupTargetKind::TypeReference,
            });
        }
        let candidates =
            csharp_visible_type_output_candidates(definitions, file, source, node, &reference);
        return csharp_type_candidates_resolution_with_kind(
            &reference,
            candidates,
            TypeLookupTargetKind::TypeReference,
            false,
        )
        .or_else(|| {
            csharp_external_type_resolution(
                csharp_structured_receiver_reference_type_names(
                    token,
                    definitions,
                    file,
                    source,
                    node,
                    &reference,
                ),
                TypeLookupTargetKind::TypeReference,
            )
        });
    }

    if definitions.scope_step()
        && let Some(parent) = node.parent()
    {
        if parent.kind() == "member_access_expression"
            && csharp_member_access_receiver(parent) == Some(node)
        {
            if csharp_expression_is_dynamic(csharp, definitions, file, source, root, node) {
                return Some(CSharpTypeLookupResolution::Dynamic {
                    target_kind: TypeLookupTargetKind::ValueExpression,
                });
            }
            let (candidates, target_kind) = csharp_receiver_type_lookup_units(
                csharp,
                token,
                definitions,
                file,
                source,
                root,
                node,
            );
            let candidates = csharp_type_candidates_resolution_with_kind(
                csharp_node_text(node, source),
                candidates,
                target_kind.clone(),
                false,
            );
            return candidates.or_else(|| {
                csharp_external_type_resolution(
                    csharp_structured_receiver_type_names(
                        csharp,
                        token,
                        definitions,
                        file,
                        source,
                        root,
                        node,
                    ),
                    target_kind,
                )
            });
        }
        if csharp_is_callable_declaration_name(parent, node) {
            return Some(CSharpTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(resolution) = csharp_declaration_name_type_resolution(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            parent,
            node,
        ) {
            return Some(resolution);
        }
    }

    if node.kind() != "identifier" {
        return None;
    }

    let name = csharp_node_text(node, source);
    if csharp_expression_is_dynamic(csharp, definitions, file, source, root, node) {
        return Some(CSharpTypeLookupResolution::Dynamic {
            target_kind: TypeLookupTargetKind::ValueExpression,
        });
    }
    let bindings = csharp_type_bindings_before_scoped(
        csharp,
        token,
        definitions,
        file,
        source,
        root,
        node.start_byte(),
    );
    let candidates = bindings
        .resolve_symbol(name)
        .as_precise()
        .map(|targets| targets.iter().cloned().collect())
        .unwrap_or_default();
    csharp_type_candidates_resolution(name, candidates).or_else(|| {
        csharp_external_type_resolution(
            csharp_structured_receiver_type_names(
                csharp,
                token,
                definitions,
                file,
                source,
                root,
                node,
            ),
            TypeLookupTargetKind::ValueExpression,
        )
    })
}

fn csharp_receiver_type_lookup_units(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> (Vec<CodeUnit>, TypeLookupTargetKind) {
    if receiver.kind() == "identifier" {
        let name = csharp_node_text(receiver, source);
        let bindings = csharp_type_bindings_before_scoped(
            csharp,
            token,
            definitions,
            file,
            source,
            root,
            receiver.start_byte(),
        );
        if let Some(targets) = bindings.resolve_symbol(name).as_precise() {
            return (
                targets.iter().cloned().collect(),
                TypeLookupTargetKind::ValueExpression,
            );
        }
        if bindings.is_shadowed(name) {
            return (Vec::new(), TypeLookupTargetKind::ValueExpression);
        }
        let member_candidates = csharp_enclosing_member_type_units(
            csharp,
            token,
            csharp,
            definitions,
            file,
            receiver,
            name,
        );
        if !member_candidates.is_empty() {
            return (member_candidates, TypeLookupTargetKind::ValueExpression);
        }
        return (
            csharp_logical_visible_type_candidates(definitions, file, source, receiver, name),
            TypeLookupTargetKind::TypeReference,
        );
    }
    (
        csharp_receiver_types(
            csharp as &dyn IAnalyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            receiver,
        )
        .units,
        if matches!(
            receiver.kind(),
            "qualified_name" | "alias_qualified_name" | "generic_name" | "predefined_type"
        ) {
            TypeLookupTargetKind::TypeReference
        } else {
            TypeLookupTargetKind::ValueExpression
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn csharp_declaration_name_type_resolution(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    match parent.kind() {
        "parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                csharp_type_node_resolution(definitions, file, source, type_node)
            })
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(name) => {
            parent.parent().and_then(|declaration| {
                (declaration.kind() == "variable_declaration")
                    .then(|| declaration.child_by_field_name("type"))
                    .flatten()
                    .and_then(|type_node| {
                        csharp_type_node_resolution(definitions, file, source, type_node)
                    })
            })
        }
        _ if matches!(parent.kind(), "property_declaration" | "field_declaration")
            && parent.child_by_field_name("name") == Some(name) =>
        {
            let owner = csharp_enclosing_class(analyzer, definitions, file, name.start_byte())?;
            let member_name = csharp_node_text(name, source);
            let fqn = match definitions.session() {
                Some(session) => csharp_member_declared_type_fq_name_in_session(
                    definitions.source(),
                    token,
                    file,
                    &owner,
                    member_name,
                    session,
                ),
                None => csharp_member_declared_type_fq_name(
                    definitions.source(),
                    token,
                    file,
                    &owner,
                    member_name,
                ),
            }?;
            csharp_type_candidates_resolution(csharp_node_text(name, source), definitions.fqn(&fqn))
        }
        _ => {
            let name_text = csharp_node_text(name, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                token,
                definitions,
                file,
                source,
                root,
                name.end_byte(),
            );
            let candidates = bindings
                .resolve_symbol(name_text)
                .as_precise()
                .map(|targets| targets.iter().cloned().collect())
                .unwrap_or_default();
            csharp_type_candidates_resolution(name_text, candidates)
        }
    }
}

fn csharp_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(
            parent.kind(),
            "method_declaration" | "local_function_statement" | "constructor_declaration"
        )
}

fn csharp_type_node_resolution(
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    let reference = csharp_reference_type_text(type_node, source);
    if csharp_is_dynamic_type_reference(&reference) {
        return Some(CSharpTypeLookupResolution::Dynamic {
            target_kind: TypeLookupTargetKind::ValueExpression,
        });
    }
    let candidates =
        csharp_visible_type_output_candidates(definitions, file, source, type_node, &reference);
    csharp_type_candidates_resolution(&reference, candidates)
}

fn csharp_type_candidates_resolution(
    reference: &str,
    candidates: Vec<CodeUnit>,
) -> Option<CSharpTypeLookupResolution> {
    csharp_type_candidates_resolution_with_kind(
        reference,
        candidates,
        TypeLookupTargetKind::ValueExpression,
        false,
    )
}

fn csharp_type_candidates_resolution_with_kind(
    reference: &str,
    candidates: Vec<CodeUnit>,
    target_kind: TypeLookupTargetKind,
    ambiguous: bool,
) -> Option<CSharpTypeLookupResolution> {
    if candidates.is_empty() {
        return None;
    }
    let fqn = if candidates.len() == 1 {
        candidates[0].fq_name().to_string()
    } else {
        reference.to_string()
    };
    Some(CSharpTypeLookupResolution::Type {
        fqn,
        candidates,
        target_kind,
        ambiguous,
    })
}

fn csharp_external_type_resolution(
    mut names: Vec<String>,
    target_kind: TypeLookupTargetKind,
) -> Option<CSharpTypeLookupResolution> {
    names.sort();
    names.dedup();
    (!names.is_empty()).then_some(CSharpTypeLookupResolution::External { names, target_kind })
}

fn csharp_type_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_type_active_path(
        csharp,
        token,
        definitions,
        file,
        source,
        root,
        cutoff_start,
        &mut bindings,
    );
    bindings
}

fn csharp_is_dynamic_type_reference(reference: &str) -> bool {
    csharp_normalize_full_name(reference) == "dynamic"
}

fn csharp_expression_is_dynamic(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> bool {
    let mut stack = vec![expression];
    while let Some(current) = stack.pop() {
        if !definitions.scope_step() {
            return false;
        }
        match current.kind() {
            "identifier" => {
                if csharp_dynamic_binding_is_visible(
                    csharp,
                    definitions,
                    file,
                    source,
                    root,
                    current,
                ) {
                    return true;
                }
            }
            "member_access_expression" => {
                if let Some(receiver) = csharp_member_access_receiver(current) {
                    stack.push(receiver);
                }
            }
            "conditional_access_expression" => {
                if let Some(access) = csharp_conditional_member_access(current) {
                    stack.push(access.receiver);
                }
            }
            "invocation_expression" => {
                if let Some(function) = current.child_by_field_name("function") {
                    stack.push(function);
                }
            }
            "parenthesized_expression" | "checked_expression" => {
                if let Some(inner) = current.named_child(0) {
                    stack.push(inner);
                }
            }
            "cast_expression" | "as_expression" => {
                let field = if current.kind() == "cast_expression" {
                    "type"
                } else {
                    "right"
                };
                if current
                    .child_by_field_name(field)
                    .map(|type_node| csharp_reference_type_text(type_node, source))
                    .is_some_and(|reference| csharp_is_dynamic_type_reference(&reference))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn csharp_dynamic_binding_is_visible(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    identifier: Node<'_>,
) -> bool {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_dynamic_active_path(
        definitions,
        source,
        root,
        identifier.start_byte(),
        &mut bindings,
    );
    let name = csharp_node_text(identifier, source);
    if bindings.resolve_symbol(name).as_precise().is_some() {
        return true;
    }
    if bindings.is_shadowed(name) {
        return false;
    }

    // A bare identifier can name a member of any enclosing type, not just the
    // innermost one (#1802). Missing that member here reports a `dynamic`
    // binding as statically typed.
    let owners = csharp_enclosing_class_chain(
        csharp as &dyn IAnalyzer,
        definitions,
        file,
        identifier.start_byte(),
    );
    for owner in owners {
        for candidate in definitions.members_for_owner_name(&owner.fq_name(), name) {
            if !definitions.scope_step() {
                return false;
            }
            let metadata = definitions.signature_metadata(&candidate);
            let is_dynamic = if let Some(session) = definitions.session() {
                metadata.iter().any(|metadata| {
                    metadata
                        .return_type_identity()
                        .and_then(|identity| identity.nominal_name_with(|| session.scope_step()))
                        .is_some_and(|name| {
                            !name.is_absolute()
                                && matches!(name.path(), [name] if name == "dynamic")
                        })
                })
            } else {
                metadata.iter().any(|metadata| {
                    metadata
                        .return_type_text()
                        .is_some_and(csharp_is_dynamic_type_reference)
                })
            };
            if is_dynamic {
                return true;
            }
        }
    }
    false
}

fn csharp_seed_dynamic_active_path(
    definitions: &CSharpDefinitionProvider<'_>,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<()>,
) {
    csharp_visit_bounded_active_path(definitions, root, cutoff_start, |node| {
        if node.kind() == "local_function_statement"
            && let Some(name) = node.child_by_field_name("name")
            && name.start_byte() < cutoff_start
        {
            bindings.declare_shadow(csharp_node_text(name, source));
        }

        let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            return false;
        }
        if enters_scope {
            bindings.enter_scope();
        }

        if (node.kind() == "parameter" || csharp_is_local_variable_declaration(node))
            && node.end_byte() <= cutoff_start
        {
            csharp_seed_dynamic_binding(definitions, source, node, bindings);
        }

        true
    });
}

fn csharp_seed_dynamic_binding(
    definitions: &CSharpDefinitionProvider<'_>,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<()>,
) {
    if !definitions.scope_step() {
        return;
    }
    match node.kind() {
        "parameter" => {
            let Some((name, type_node)) = csharp_parameter_name_and_type(node) else {
                return;
            };
            let is_dynamic =
                csharp_is_dynamic_type_reference(&csharp_reference_type_text(type_node, source));
            if is_dynamic {
                bindings.seed_symbol(csharp_node_text(name, source), ());
            } else {
                bindings.declare_shadow(csharp_node_text(name, source));
            }
        }
        "variable_declaration" => {
            let Some(type_node) = node.child_by_field_name("type") else {
                return;
            };
            let is_dynamic =
                csharp_is_dynamic_type_reference(&csharp_reference_type_text(type_node, source));
            let mut cursor = node.walk();
            for declarator in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "variable_declarator")
            {
                if !definitions.scope_step() {
                    return;
                }
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                if is_dynamic {
                    bindings.seed_symbol(csharp_node_text(name, source), ());
                } else {
                    bindings.declare_shadow(csharp_node_text(name, source));
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn csharp_seed_type_active_path(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    csharp_visit_bounded_active_path(definitions, root, cutoff_start, |node| {
        if node.kind() == "local_function_statement"
            && let Some(name) = node.child_by_field_name("name")
            && name.start_byte() < cutoff_start
        {
            bindings.declare_shadow(csharp_node_text(name, source));
        }

        let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            return false;
        }
        if enters_scope {
            bindings.enter_scope();
        }

        if (node.kind() == "parameter" || csharp_is_local_variable_declaration(node))
            && node.end_byte() <= cutoff_start
        {
            csharp_seed_type_binding(node, token, csharp, definitions, file, source, bindings);
        }

        true
    });
}

fn csharp_visit_bounded_active_path<'tree>(
    definitions: &CSharpDefinitionProvider<'_>,
    root: Node<'tree>,
    cutoff_start: usize,
    mut visit: impl FnMut(Node<'tree>) -> bool,
) {
    if !definitions.scope_step() {
        return;
    }

    let mut pending = Some(root);
    let mut parents = Vec::<(Node<'tree>, usize)>::new();
    loop {
        if let Some(node) = pending.take()
            && node.start_byte() < cutoff_start
            && visit(node)
        {
            parents.push((node, 0));
        }

        let child = loop {
            let Some((parent, next_child)) = parents.last_mut() else {
                return;
            };
            let Some(child) = parent.named_child(*next_child) else {
                parents.pop();
                continue;
            };
            *next_child += 1;
            if child.start_byte() >= cutoff_start {
                parents.pop();
                continue;
            }
            break child;
        };

        if !definitions.scope_step() {
            return;
        }
        pending = Some(child);
    }
}

fn csharp_seed_type_binding(
    node: Node<'_>,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    if !definitions.scope_step() {
        return;
    }
    match node.kind() {
        "parameter" => {
            let Some((name, type_node)) = csharp_parameter_name_and_type(node) else {
                return;
            };
            csharp_seed_symbol_for_type(
                name,
                token,
                type_node,
                csharp,
                definitions,
                file,
                source,
                bindings,
            );
        }
        "variable_declaration" => {
            let Some(type_node) = node.child_by_field_name("type") else {
                return;
            };
            let inferred = csharp_node_text(type_node, source) == "var";
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !definitions.scope_step() {
                    return;
                }
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                if inferred {
                    let candidates = csharp_object_created_type(child)
                        .map(|type_node| {
                            csharp_type_candidates_at(
                                csharp,
                                token,
                                definitions,
                                file,
                                source,
                                type_node,
                            )
                        })
                        .unwrap_or_default();
                    if candidates.is_empty() {
                        bindings.declare_shadow(csharp_node_text(name, source));
                    } else {
                        bindings.seed_symbol_many(csharp_node_text(name, source), candidates);
                    }
                    continue;
                }
                csharp_seed_symbol_for_type(
                    name,
                    token,
                    type_node,
                    csharp,
                    definitions,
                    file,
                    source,
                    bindings,
                );
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn csharp_seed_symbol_for_type(
    name: Node<'_>,
    token: QueryToken<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let binding_name = csharp_node_text(name, source);
    let candidates = csharp_type_candidates_at(csharp, token, definitions, file, source, type_node);
    if candidates.is_empty() {
        bindings.declare_shadow(binding_name);
    } else {
        bindings.seed_symbol_many(binding_name, candidates);
    }
}

fn csharp_type_candidates_at(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Vec<CodeUnit> {
    let reference = csharp_reference_type_text(type_node, source);
    if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
        csharp,
        token,
        definitions,
        file,
        &reference,
        type_node.start_byte(),
    ) {
        return vec![unit];
    }
    let mut candidates =
        definitions.visible_type_candidates_at(file, &reference, source, type_node);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

/// What the written type of one callable parameter names.
enum CSharpParameterType {
    /// A predefined type such as `int`, by its canonical identity.
    Predefined(&'static str),
    /// The workspace classes the name resolves to where the callee wrote it.
    Classes(Vec<CodeUnit>),
}

/// The type a callable's parameter spells at `type_node`, in the file `method`
/// is declared in.
///
/// The callee wrote the name in its own scope, so it is resolved there and not
/// in the scope of the call: through the ladder a receiver typed by that
/// parameter takes, in which a global type outranks a compilation-unit `using`
/// and a type of unproven compilation membership leaves the answer unproven
/// (#6472). A lexical type parameter names no workspace type.
fn csharp_parameter_type(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    method: &CodeUnit,
    source: &str,
    type_node: Node<'_>,
) -> Option<CSharpParameterType> {
    let reference = csharp_reference_type_text(type_node, source);
    if csharp_type_parameter_shadows_reference(type_node, source, &reference) {
        return None;
    }
    if let Some(canonical) = csharp_canonical_builtin_type_identity(&reference) {
        return Some(CSharpParameterType::Predefined(canonical));
    }
    Some(CSharpParameterType::Classes(csharp_type_candidates_at(
        csharp,
        token,
        definitions,
        method.source(),
        source,
        type_node,
    )))
}

/// The classes that parameter `parameter_index` of `method` constructs when an
/// argument is a target-typed `new()`.
fn csharp_callable_parameter_type_owners(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    method: &CodeUnit,
    parameter_index: usize,
) -> Vec<CodeUnit> {
    // Reading and parsing the declaring file is one step of the request's
    // scope budget; the lookups inside charge their own.
    if !definitions.scope_step() {
        return Vec::new();
    }
    let parameter_type =
        with_callable_parameter_type_nodes(csharp, method, |source, type_nodes| {
            let type_node = type_nodes.get(parameter_index).copied().flatten()?;
            csharp_parameter_type(csharp, token, definitions, method, source, type_node)
        })
        .flatten();
    match parameter_type {
        Some(CSharpParameterType::Classes(owners)) => owners,
        Some(CSharpParameterType::Predefined(_)) | None => Vec::new(),
    }
}

/// Whether each argument type in `argument_types` names the type of the
/// parameter it is passed to, `parameter_indices[i]` for argument `i`. A
/// parameter whose type does not resolve to exactly one type matches nothing.
fn csharp_callable_parameter_types_match(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    method: &CodeUnit,
    parameter_indices: &[usize],
    argument_types: &[String],
) -> bool {
    if parameter_indices.is_empty() {
        return true;
    }
    if !definitions.scope_step() {
        return false;
    }
    with_callable_parameter_type_nodes(csharp, method, |source, type_nodes| {
        parameter_indices
            .iter()
            .zip(argument_types)
            .all(|(&parameter_index, actual_type)| {
                let Some(type_node) = type_nodes.get(parameter_index).copied().flatten() else {
                    return false;
                };
                let parameter_type = match csharp_parameter_type(
                    csharp,
                    token,
                    definitions,
                    method,
                    source,
                    type_node,
                ) {
                    Some(CSharpParameterType::Predefined(canonical)) => canonical.to_owned(),
                    Some(CSharpParameterType::Classes(classes))
                        if graph_support::logical_type_count(&classes) == 1 =>
                    {
                        match graph_support::first_logical_type_fqn(&classes) {
                            Some(fqn) => fqn,
                            None => return false,
                        }
                    }
                    Some(CSharpParameterType::Classes(_)) | None => return false,
                };
                csharp_comparable_type_name(&parameter_type) == *actual_type
            })
    })
    .unwrap_or(false)
}

#[cfg(test)]
fn parse_csharp_tree(source: &str) -> Option<Tree> {
    brokk_bifrost_csharp::preprocessor::parse_csharp(source)
}

enum CSharpReferenceNode<'tree> {
    Attribute(Node<'tree>),
    Type(CSharpTypeReference<'tree>),
    Constructor(Node<'tree>),
    Member {
        receiver: Node<'tree>,
        name: Node<'tree>,
    },
    Indexer {
        receiver: Node<'tree>,
    },
    UnqualifiedMember(Node<'tree>),
    NamedArgumentLabel {
        label: Node<'tree>,
        shape: CSharpNamedArgumentLabel<'tree>,
    },
    Identifier(Node<'tree>),
}

enum CSharpTypeReference<'tree> {
    Complete(Node<'tree>),
    FocusedSegment(Node<'tree>),
}

fn csharp_reference_node<'tree>(
    node: Node<'tree>,
    definitions: &CSharpDefinitionProvider<'_>,
) -> Option<CSharpReferenceNode<'tree>> {
    if !definitions.scope_step() {
        return None;
    }
    // A named-argument label is a leaf in its argument's `name` field, so the
    // walk below never reaches it, and every shape it could otherwise fall
    // through to -- type reference, unqualified member, bare identifier --
    // answers with something the label does not name (#1796).
    if let Some(shape) = csharp_named_argument_label(node) {
        return Some(CSharpReferenceNode::NamedArgumentLabel { label: node, shape });
    }

    let original = node;
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !definitions.scope_step() {
            return None;
        }
        if (matches!(
            parent.kind(),
            "generic_name" | "qualified_name" | "alias_qualified_name"
        ) && parent
            .child_by_field_name("name")
            .or_else(|| {
                if parent.kind() == "generic_name" {
                    parent.named_child(0)
                } else {
                    None
                }
            })
            .is_some_and(|name| same_node(name, current) || same_node(name, original)))
            || (parent.kind() == "member_access_expression"
                && !csharp_member_access_receiver(parent)
                    .is_some_and(|receiver| same_node(receiver, current))
                && !csharp_member_access_receiver(parent)
                    .is_some_and(|receiver| same_node(receiver, original))
                && (csharp_member_access_name(parent).is_some_and(|name| same_node(name, current))
                    || csharp_member_access_name(parent)
                        .is_some_and(|name| same_node(name, original))))
            || (parent.kind() == "member_binding_expression"
                && parent
                    .child_by_field_name("name")
                    .is_some_and(|name| same_node(name, current) || same_node(name, original)))
            || (parent.kind() == "conditional_access_expression"
                && csharp_conditional_member_access(parent)
                    .is_some_and(|access| same_node(access.binding, current)))
            || (parent.kind() == "element_access_expression"
                && (parent
                    .child_by_field_name("expression")
                    .is_some_and(|expression| {
                        same_node(expression, current) || same_node(expression, original)
                    })
                    || parent
                        .child_by_field_name("subscript")
                        .is_some_and(|subscript| same_node(subscript, current))))
            || (matches!(
                parent.kind(),
                "string_literal" | "character_literal" | "argument" | "bracketed_argument_list"
            ) && csharp_element_access_ancestor(parent))
            || (parent.kind() == "object_creation_expression"
                && (parent.child_by_field_name("type") == Some(current)
                    || csharp_first_type_child(parent) == Some(current)))
        {
            current = parent;
        } else {
            break;
        }
    }

    // An attribute name is a type reference the grammar spells outside the
    // type roles, so the per-segment contract that #3118 gave qualified type
    // names has to reach it too: only the segment the climb stopped on is
    // being asked about. The whole `name` node is the attribute type and takes
    // the attribute-specific resolution (shorthand `Attribute` suffix,
    // attribute-applicability); a shorter prefix is an ordinary focused type
    // segment, which must answer for itself and never for the attribute class
    // spelled after the dot (#3289).
    if let Some(name) = csharp_attribute_name_node(current) {
        return Some(if same_node(name, current) {
            CSharpReferenceNode::Attribute(name)
        } else {
            CSharpReferenceNode::Type(CSharpTypeReference::FocusedSegment(current))
        });
    }

    match current.kind() {
        "member_access_expression" => Some(CSharpReferenceNode::Member {
            receiver: csharp_member_access_receiver(current)?,
            name: csharp_member_access_name(current)?,
        }),
        "element_access_expression" => Some(CSharpReferenceNode::Indexer {
            receiver: current.child_by_field_name("expression")?,
        }),
        "conditional_access_expression" => {
            let access = csharp_conditional_member_access(current)?;
            Some(CSharpReferenceNode::Member {
                receiver: access.receiver,
                name: access.name,
            })
        }
        "object_creation_expression" => Some(CSharpReferenceNode::Constructor(current)),
        "identifier" | "type" => {
            if csharp_is_unqualified_invocation_target(current) {
                return Some(CSharpReferenceNode::UnqualifiedMember(current));
            }
            if csharp_is_type_reference_node(current) {
                return Some(CSharpReferenceNode::Type(
                    CSharpTypeReference::FocusedSegment(current),
                ));
            }
            if csharp_is_unqualified_member_reference(current) {
                return Some(CSharpReferenceNode::Identifier(current));
            }
            Some(CSharpReferenceNode::Identifier(current))
        }
        "generic_name" if csharp_is_unqualified_invocation_target(current) => {
            Some(CSharpReferenceNode::UnqualifiedMember(current))
        }
        "qualified_name"
        | "alias_qualified_name"
        | "generic_name"
        | "nullable_type"
        | "array_type" => Some(CSharpReferenceNode::Type(CSharpTypeReference::Complete(
            current,
        ))),
        _ => None,
    }
}

fn csharp_element_access_ancestor(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "element_access_expression"
            && parent
                .child_by_field_name("subscript")
                .is_some_and(|subscript| same_node(subscript, current))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "string_literal" | "character_literal" | "argument" | "bracketed_argument_list"
        ) {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

/// Whether `node` spells the whole of the attribute name node `name`.
///
/// [`csharp_reference_node`] answers this question by climbing before it asks;
/// the type-of resolver is handed the smallest node covering the focus range
/// and has to climb here instead. A node occupying the `name` field of its
/// enclosing qualified or generic name spells that enclosing name too, so
/// `Cache` in `[Cache<Payload>]` reaches the attribute's whole `generic_name`
/// while `SqlSugar` in `[SqlSugar.SugarColumn]` stops at the qualifier.
fn csharp_node_spells_whole_attribute_name(node: Node<'_>, name: Node<'_>) -> bool {
    let mut current = node;
    while !same_node(current, name) {
        let Some(parent) = current.parent() else {
            return false;
        };
        let terminal = match parent.kind() {
            "qualified_name" | "alias_qualified_name" => parent.child_by_field_name("name"),
            "generic_name" => parent
                .child_by_field_name("name")
                .or_else(|| parent.named_child(0)),
            _ => return false,
        };
        if !terminal.is_some_and(|terminal| same_node(terminal, current)) {
            return false;
        }
        current = parent;
    }
    true
}

fn csharp_is_unqualified_invocation_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(node)
    })
}

fn csharp_invocation_arity(
    node: Node<'_>,
    source: &str,
    definitions: &CSharpDefinitionProvider<'_>,
) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !definitions.scope_step() {
            return None;
        }
        if matches!(
            parent.kind(),
            "member_access_expression"
                | "qualified_name"
                | "member_binding_expression"
                | "conditional_access_expression"
        ) {
            current = parent;
            continue;
        }
        if parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            return Some(csharp_argument_count_in_session(
                parent,
                source,
                definitions,
            ));
        }
        break;
    }
    None
}

fn csharp_invocation_node<'tree>(
    node: Node<'tree>,
    definitions: &CSharpDefinitionProvider<'_>,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !definitions.scope_step() {
            return None;
        }
        if parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "member_access_expression"
                | "qualified_name"
                | "alias_qualified_name"
                | "generic_name"
                | "member_binding_expression"
                | "conditional_access_expression"
        ) {
            current = parent;
            continue;
        }
        break;
    }
    None
}

fn csharp_argument_expression(argument: Node<'_>) -> Option<Node<'_>> {
    let label = argument.child_by_field_name("name");
    (0..argument.named_child_count())
        .filter_map(|index| argument.named_child(index))
        .find(|child| label.is_none_or(|label| child.id() != label.id()))
}

fn csharp_comparable_type_name(name: &str) -> String {
    let normalized = csharp_normalize_full_name(name);
    canonical_csharp_predefined_type(&normalized).map_or(normalized.clone(), str::to_owned)
}

#[allow(clippy::too_many_arguments)]
fn refine_csharp_invocation_overload(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: Node<'_>,
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    if outcome.definitions.len() < 2 {
        return outcome;
    }
    let Some(invocation) = csharp_invocation_node(name, definitions) else {
        return outcome;
    };
    let argument_count = csharp_argument_count_in_session(invocation, source, definitions);
    let mut argument_types = Vec::with_capacity(argument_count);
    for index in 0..argument_count {
        let Some(argument) =
            call_argument_node(invocation, index).and_then(csharp_argument_expression)
        else {
            return outcome;
        };
        let receiver_types = csharp_receiver_types(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            argument,
        );
        let mut names = receiver_types
            .fq_names
            .iter()
            .map(|name| csharp_comparable_type_name(name))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        if names.len() != 1 {
            // A dynamic, unknown, or multiply-typed argument cannot select an
            // overload safely. The caller retains the original ambiguous
            // outcome, which the call relation reports as incomplete.
            return outcome;
        }
        argument_types.push(names.remove(0));
    }

    let mut selected = Vec::new();
    for candidate in &outcome.definitions {
        let metadata = definitions
            .signature_metadata(candidate)
            .into_iter()
            .find(|metadata| metadata.callable_parameter_types().is_some());
        let Some(metadata) = metadata else {
            continue;
        };
        let parameter_indices = (0..argument_types.len())
            .map(|index| call_argument_parameter_index(invocation, index, &metadata, source))
            .collect::<Option<Vec<_>>>();
        let matches = parameter_indices.is_some_and(|parameter_indices| {
            csharp_callable_parameter_types_match(
                csharp,
                token,
                definitions,
                candidate,
                &parameter_indices,
                &argument_types,
            )
        });
        if matches {
            selected.push(candidate.clone());
        }
    }

    if selected.len() == 1 {
        outcome = candidates_outcome(selected);
    }
    outcome
}

fn csharp_argument_count_in_session(
    node: Node<'_>,
    source: &str,
    definitions: &CSharpDefinitionProvider<'_>,
) -> usize {
    if !definitions.scope_step() {
        return 0;
    }
    let count = csharp_argument_count(node, source);
    for _ in 0..count {
        if !definitions.scope_step() {
            return 0;
        }
    }
    count
}

fn csharp_member_name_parts<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<(&'a str, Option<usize>)> {
    let name = csharp_member_name(node)?;
    let identifier = csharp_node_text(name.identifier, source).trim();
    (!identifier.is_empty()).then_some((identifier, name.explicit_generic_arity))
}

#[allow(clippy::too_many_arguments)]
fn csharp_external_constructor_target(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    creation: Node<'_>,
) -> Option<(String, String, u32)> {
    let type_node = creation
        .child_by_field_name("type")
        .or_else(|| csharp_first_type_child(creation))?;
    let reference = csharp_reference_type_text(type_node, source);
    let candidate_owners = csharp_external_constructor_owner_names(
        analyzer,
        token,
        definitions,
        file,
        source,
        type_node,
        &reference,
    );
    if candidate_owners.is_empty() {
        return None;
    }
    let parameter_count = u32::try_from(csharp_argument_count(creation, source)).ok()?;
    let (owner, member) = csharp.external_constructor_identity(
        analyzer.semantic_model_overlay(),
        &candidate_owners,
        parameter_count,
    )?;
    Some((owner, member, parameter_count))
}

/// Candidate owner identities for an object-creation type that the workspace
/// does not materialize. The ordinary visible-type index is intentionally not
/// used as the external answer: its final unqualified-name probe can return a
/// same-terminal-name source declaration even when C#'s actual using scope
/// selects an external type. Lexical source scopes still win; after they miss,
/// the aliases and using namespaces are the structured owner ladder that can
/// reach an activated declaration model.
#[allow(clippy::too_many_arguments)]
fn csharp_external_constructor_owner_names(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    reference: &str,
) -> Vec<String> {
    let byte = site.start_byte();
    let reference = csharp_normalize_full_name(reference);
    if reference.is_empty() {
        return Vec::new();
    }
    if !reference.contains('.') {
        if resolve_csharp_nested_type_in_enclosing_classes(
            analyzer,
            token,
            definitions,
            file,
            &reference,
            byte,
        )
        .is_some()
            || resolve_csharp_in_enclosing_scopes(
                analyzer,
                definitions,
                file,
                &reference,
                byte,
                CodeUnit::is_class,
            )
            .is_some()
        {
            return Vec::new();
        }
    } else if !csharp_logical_visible_type_candidates(definitions, file, source, site, &reference)
        .is_empty()
    {
        return Vec::new();
    }

    let aliases = definitions.using_aliases(token, file);
    let mut owners = aliases
        .get(&reference)
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();
    if !reference.contains('.') && aliases.get(&reference).is_none() {
        owners.extend(
            definitions
                .using_namespaces(token, file)
                .into_iter()
                .map(|namespace| format!("{namespace}.{reference}")),
        );
        owners.extend(
            definitions
                .global_using_namespaces(token)
                .into_iter()
                .map(|namespace| format!("{namespace}.{reference}")),
        );
    } else if aliases.get(&reference).is_none() {
        owners.push(reference);
    }
    owners.sort();
    owners.dedup();
    owners
}

fn csharp_external_constructor_outcome(
    file: &ProjectFile,
    creation: Node<'_>,
    owner: String,
    member: String,
) -> DefinitionLookupOutcome {
    let type_node = creation
        .child_by_field_name("type")
        .or_else(|| csharp_first_type_child(creation))
        .expect("an external constructor target has a type node");
    let canonical = format!("{owner}.{member}");
    external_member_boundary_outcome(
        canonical.clone(),
        format!("`{canonical}` names an external C# constructor declaration"),
        Some(ResolvedReferenceSite {
            path: file.to_string(),
            text: canonical,
            range: node_range(creation),
            focus_start_byte: type_node.start_byte(),
            focus_end_byte: type_node.end_byte(),
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn csharp_external_constructor_evidence(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    outcome: &DefinitionLookupOutcome,
) -> CallEvidence {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
    {
        return CallEvidence::default();
    }
    let Some(tree) = tree else {
        return CallEvidence::default();
    };
    let Some(node) = csharp_smallest_named_node_covering(
        definitions,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return CallEvidence::default();
    };
    let Some(CSharpReferenceNode::Constructor(creation)) = csharp_reference_node(node, definitions)
    else {
        return CallEvidence::default();
    };
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return CallEvidence::default();
    };
    let Some((owner, member, parameter_count)) = csharp_external_constructor_target(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        creation,
    ) else {
        return CallEvidence::default();
    };
    let canonical = format!("{owner}.{member}");
    if outcome
        .reference
        .as_ref()
        .is_none_or(|reference| reference.text != canonical)
    {
        return CallEvidence::default();
    }
    let proof =
        ExactExternalCallProof::csharp_external_constructor(&owner, &member, parameter_count);
    CallEvidence {
        call_application: proof.call_application(),
        dispatch_extensibility: proof.dispatch_extensibility(),
        exact_external_call: Some(proof),
        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
            Language::CSharp,
            owner,
            member,
        )),
        authority: DefinitionResolutionAuthority::Incumbent,
    }
}

fn resolve_csharp_constructor(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    creation: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = creation
        .child_by_field_name("type")
        .or_else(|| csharp_first_type_child(creation))
    else {
        return no_definition("no_reference_text", "C# constructor call has no type");
    };
    let reference = csharp_reference_type_text(type_node, source);
    // A nested type declared by a sibling partial declaration is visible
    // through its enclosing partial type. Keep this lookup within classes:
    // walking out to a namespace would resolve an ordinary constructor call to
    // its owner type before the constructor-overload lookup below runs.
    if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
        analyzer,
        token,
        definitions,
        file,
        &reference,
        type_node.start_byte(),
    ) {
        return candidates_outcome(vec![unit]);
    }
    if definitions
        .using_aliases(token, file)
        .contains_key(&reference)
    {
        if let Some((owner, member, _parameter_count)) = csharp_external_constructor_target(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            creation,
        ) {
            return csharp_external_constructor_outcome(file, creation, owner, member);
        }
        return csharp_type_outcome(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            type_node,
            &reference,
        );
    }
    if let Some((owner, member, _parameter_count)) = csharp_external_constructor_target(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        creation,
    ) {
        return csharp_external_constructor_outcome(file, creation, owner, member);
    }
    let owners =
        csharp_logical_visible_type_candidates(definitions, file, source, type_node, &reference);
    let call_arity = csharp_argument_count(creation, source);
    let mut constructors = Vec::new();
    let mut applicable = Vec::new();
    let mut implicit_parameterless_owners = Vec::new();
    for owner in &owners {
        let owner_constructors = definitions
            .members_for_owner_name(
                &owner.fq_name(),
                brokk_bifrost_csharp::syntax::csharp_source_identifier(owner),
            )
            .into_iter()
            // The member index also tries the generic-arity-stripped owner
            // name. Keep only constructors whose parent is the exact owner;
            // otherwise `Item`2 can receive `Item`'s constructor.
            .filter(|candidate| candidate.fq().parent().as_ref() == Some(owner.fq()))
            .collect::<Vec<_>>();
        let owner_applicable = csharp_filter_candidates_by_arity(
            csharp,
            definitions,
            &owner_constructors,
            Some(call_arity),
        );
        if !owner_applicable.is_empty() {
            applicable.extend(owner_applicable);
        } else if call_arity == 0
            && (owner_constructors.is_empty()
                || csharp_uses_implicit_parameterless_value_constructor(definitions, owner))
        {
            implicit_parameterless_owners.push(owner.clone());
        }
        constructors.extend(owner_constructors);
    }
    sort_units(&mut constructors);
    constructors.dedup();
    sort_units(&mut applicable);
    applicable.dedup();
    if !applicable.is_empty() {
        return candidates_outcome(applicable);
    }
    sort_units(&mut implicit_parameterless_owners);
    implicit_parameterless_owners.dedup();
    if !implicit_parameterless_owners.is_empty() {
        return candidates_outcome(implicit_parameterless_owners);
    }
    if !constructors.is_empty() {
        // Every indexed constructor of every candidate owner was rejected by
        // the argument count, and a constructor is never inherited, so no base
        // type can supply the accepting one either. Binding one anyway was the
        // forward side's #1797 defect: the inverse scan refuses the site
        // (`scan_constructor_reference` applies the same `CallableArity`), so
        // the pair disagreed about it.
        return no_definition(
            "no_applicable_overload",
            format!("no `{reference}` constructor overload accepts this call"),
        );
    }
    if let Some((owner, member, _parameter_count)) = csharp_external_constructor_target(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        creation,
    ) {
        return csharp_external_constructor_outcome(file, creation, owner, member);
    }
    csharp_type_outcome(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        type_node,
        &reference,
    )
}

fn csharp_uses_implicit_parameterless_value_constructor(
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
) -> bool {
    let metadata = definitions.signature_metadata(owner);
    !metadata.is_empty()
        && metadata
            .iter()
            .all(|metadata| metadata.class_like_kind() == Some(ClassLikeKind::Struct))
}

fn csharp_indexed_non_type_outcome(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
    subject: &str,
) -> Option<DefinitionLookupOutcome> {
    let candidate =
        csharp_indexed_non_type_candidate(analyzer, definitions, file, reference, byte, |unit| {
            !unit.is_class()
        })?;
    Some(no_definition(
        "indexed_declaration_wrong_kind",
        csharp_indexed_candidate_honesty_message(reference, subject, &candidate),
    ))
}

#[allow(clippy::too_many_arguments)]
fn csharp_type_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    reference: &str,
) -> DefinitionLookupOutcome {
    let byte = site.start_byte();
    let mut candidates =
        csharp_visible_type_output_candidates(definitions, file, source, site, reference);
    if candidates.is_empty() {
        candidates = definitions.fqn(reference);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    // A type nested in an enclosing class is visible from member type
    // positions inside sibling nested types. The namespace-style walks above
    // miss it because C# nested-type fq segments join with `$`, which their
    // `.`-joined candidate keys never try — and the miss then drew a
    // dishonest using-boundary claim for a type indexed in the very same
    // file (#1105). Runs after the scope-blind resolvers so currently
    // resolving lookups are unaffected.
    if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
        analyzer,
        token,
        definitions,
        file,
        reference,
        byte,
    ) {
        return candidates_outcome(vec![unit]);
    }
    if let Some(reason) =
        csharp.type_forward_boundary(analyzer.semantic_model_overlay(), token, file, reference)
    {
        return boundary_unchecked(
            reason,
            UnindexedClaim::external_boundary(reference, ClaimSubjectRole::Type),
        );
    }
    // `csharp_import_boundary_for_type` fuses the unresolved-using signal with
    // the workspace type/namespace check; its negation is the workspace gate.
    if csharp_import_boundary_for_type(csharp, token, definitions, file, reference)
        && let Some(outcome) =
            csharp_indexed_non_type_outcome(analyzer, definitions, file, reference, byte, "type")
    {
        // #1218: every type-shaped resolver above has already failed to find
        // `reference` as a type, and this retry excludes classes explicitly
        // (rather than trusting that exhaustion), so a hit here is
        // guaranteed to be a different-kind declaration (property/field/
        // method/...) that merely shares the failed type reference's
        // spelling. The boundary claim would call it "not indexed" while
        // the index plainly contains it.
        return outcome;
    }
    gated_boundary(
        || !csharp_import_boundary_for_type(csharp, token, definitions, file, reference),
        format!("`{reference}` appears to cross a C# using boundary not indexed in this workspace"),
        UnindexedClaim::external_boundary(reference, ClaimSubjectRole::Type),
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# type"),
    )
}

/// Resolve a type name only in a grammar role that permits its generic arity
/// to be omitted. Ordinary C# identifiers never enter this path: a bare `Box`
/// in a declared type position continues to mean arity zero, while
/// `nameof(Box)` may widen to `Box<T>` after the exact declaration misses
/// (#2209).
fn csharp_arity_free_type_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
) -> Option<DefinitionLookupOutcome> {
    if let Some(unit) = resolve_csharp_arity_free_nested_type_in_enclosing_classes(
        analyzer,
        token,
        definitions,
        file,
        reference,
        byte,
    ) {
        return Some(candidates_outcome(vec![unit]));
    }
    let mut candidates = definitions.arity_free_visible_type_candidates(token, file, reference);
    if candidates.is_empty() {
        candidates = definitions.arity_free_types_by_fqn(reference);
    }
    if !candidates.is_empty() {
        graph_support::sort_type_candidates(&mut candidates);
        candidates.dedup();
        return Some(candidates_outcome(candidates));
    }
    None
}

fn csharp_attribute_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let names = csharp_attribute_type_names(name, source);
    let (candidates, ambiguous_spelling) =
        definitions.attribute_type_candidates(analyzer, token, file, &names, source, name);
    if !candidates.is_empty() {
        let mut outcome = candidates_outcome(candidates);
        if ambiguous_spelling {
            outcome.status = DefinitionLookupStatus::Ambiguous;
            outcome.diagnostics = vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: "ambiguous_definition".to_string(),
                message: "C# attribute name has multiple successful type-name spellings"
                    .to_string(),
            }];
        }
        return outcome;
    }
    let reference = names.first().map(String::as_str).unwrap_or_default();
    let boundary = csharp_alias_qualified_boundary(definitions, token, file, name, source)
        || names
            .iter()
            .any(|name| csharp_import_boundary_for_type(csharp, token, definitions, file, name));
    // #1218: same honesty check as `csharp_type_outcome` — an attribute name
    // that fails every type-shaped resolver above but is indexed as some
    // other kind of declaration reachable from this reference's enclosing
    // scope must not be called "not indexed". Classes are excluded: unlike
    // the plain type path, `attribute_type_candidates` above already
    // considered every same-spelled *class* and rejected the ones that are
    // not attribute-applicable (don't derive `System.Attribute`) — that
    // rejection is deliberate and must not be second-guessed here, so a
    // class match is not "different-kind" evidence (Generated/ExportProxyCmdlet's
    // `internal class Parameter` vs the external `ParameterAttribute`
    // shorthand: the boundary claim there is the honest answer).
    if boundary
        && let Some(outcome) = csharp_indexed_non_type_outcome(
            analyzer,
            definitions,
            file,
            reference,
            name.start_byte(),
            "attribute type",
        )
    {
        return outcome;
    }
    // Both disjuncts are workspace-fused boundary predicates (alias target /
    // using target the workspace does not index); their negation is the gate.
    gated_boundary(
        || !boundary,
        format!("`{reference}` appears to cross a C# using boundary not indexed in this workspace"),
        UnindexedClaim::external_boundary(reference, ClaimSubjectRole::Type),
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# attribute type"),
    )
}

fn csharp_alias_qualified_boundary(
    definitions: &CSharpDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: Node<'_>,
    source: &str,
) -> bool {
    let mut stack = vec![name];
    while let Some(current) = stack.pop() {
        if current.kind() == "alias_qualified_name" {
            let Some(alias) = current
                .child_by_field_name("alias")
                .or_else(|| current.child_by_field_name("qualifier"))
                .or_else(|| current.named_child(0))
            else {
                return false;
            };
            let alias = csharp_node_text(alias, source);
            let suffix = current
                .child_by_field_name("name")
                .map(|name| csharp_reference_type_text(name, source))
                .unwrap_or_default();
            return definitions
                .using_aliases(token, file)
                .get(alias)
                .is_some_and(|target| {
                    let qualified = if suffix.is_empty() {
                        target.clone()
                    } else {
                        format!("{target}.{suffix}")
                    };
                    !definitions.type_exists(target)
                        && !definitions.package_exists(target)
                        && !definitions.type_exists(&qualified)
                });
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn csharp_indexer_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    receiver: Node<'_>,
) -> DefinitionLookupOutcome {
    let receiver_types = csharp_receiver_types(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        root,
        receiver,
    );
    let owners = receiver_types.units;
    let mut receiver_type_names = receiver_types.fq_names;
    let structured_receiver_type_names = csharp_structured_receiver_type_names(
        csharp,
        token,
        definitions,
        file,
        source,
        root,
        receiver,
    );
    if receiver_type_names.is_empty() {
        receiver_type_names = structured_receiver_type_names;
    } else {
        receiver_type_names.extend(structured_receiver_type_names);
        receiver_type_names.sort();
        receiver_type_names.dedup();
    }

    if !owners.is_empty() {
        let outcome = csharp_member_outcome(
            analyzer,
            token,
            definitions,
            owners,
            CSHARP_INDEXER_MEMBER_NAME,
            None,
            None,
        );
        return outcome;
    }
    if receiver_type_names.is_empty() {
        return no_definition(
            "unsupported_csharp_receiver",
            "receiver for C# indexer is not resolved",
        );
    }

    let mut outcome = no_definition(
        "unsupported_csharp_receiver",
        format!("receiver types {receiver_type_names:?} for C# indexer are not indexed"),
    );
    outcome.status = DefinitionLookupStatus::UnresolvableImportBoundary;
    outcome
        .diagnostics
        .retain(|diagnostic| diagnostic.kind != "unsupported_csharp_receiver");
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "csharp_receiver_type_unindexed".to_owned(),
        message: format!(
            "receiver types {receiver_type_names:?} for C# indexer are not indexed; ordinary member lookup remains incomplete"
        ),
        claim: Some(UnindexedClaim::external_boundary(
            receiver_type_names.join(", "),
            ClaimSubjectRole::Type,
        )),
    });
    if let Some(canonical) = csharp.external_member_identity(
        analyzer.semantic_model_overlay(),
        &receiver_type_names,
        CSHARP_INDEXER_MEMBER_NAME,
    ) {
        outcome.reference = Some(ResolvedReferenceSite {
            text: canonical,
            ..site.clone()
        });
    }
    outcome
}

fn csharp_member_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
) -> DefinitionLookupOutcome {
    if !definitions.scope_step() {
        return no_definition(
            "csharp_resolution_stopped",
            "C# member resolution stopped before completion",
        );
    }
    if owners.is_empty() {
        return no_definition(
            "unsupported_csharp_receiver",
            format!("receiver for C# member `{member}` is not resolved"),
        );
    };

    // Attribution is built only while a trace records (#1477); the walk itself
    // reads nothing back from it and decides nothing with it.
    let mut member_trace = trace::recording().then(CSharpMemberTrace::default);

    let mut direct_candidates = Vec::new();
    let mut seen_owner_fqns = HashSet::default();
    for owner in &owners {
        if !definitions.scope_step() {
            break;
        }
        if let Some(state) = member_trace.as_mut() {
            state.record_root(owner);
        }
        let mut parts = definitions.partial_type_parts(owner);
        if parts.is_empty() {
            parts.push(owner.clone());
        }
        for part in parts {
            if !definitions.scope_step() {
                break;
            }
            let owner_fqn = part.fq_name();
            if seen_owner_fqns.insert(owner_fqn.clone()) {
                let found =
                    csharp_non_constructor_member_candidates(analyzer, definitions, &part, member);
                if let Some(state) = member_trace.as_mut() {
                    state.record_root(&part);
                    state.record_found(&found, &part, 0);
                }
                direct_candidates.extend(found);
            }
        }
    }
    sort_units(&mut direct_candidates);
    direct_candidates.dedup();
    // One applicability computation decides what the walk binds and what it
    // reports (#1478 M3): `winners` is the production filter, `verdicts` is the
    // evidence, and neither can drift from the other. C# refuses on two axes,
    // so the two checks are chained rather than run independently -- a
    // candidate the explicit type-argument check discarded keeps that reason
    // instead of reaching the trace unattributed.
    let generic =
        csharp_generic_arity_applicability(definitions, &direct_candidates, explicit_generic_arity);
    let direct_candidates = generic.winners.clone();
    let applicability = generic.then(csharp_candidate_applicability(
        analyzer,
        definitions,
        &direct_candidates,
        arity,
    ));
    if !applicability.winners.is_empty() {
        if let Some(state) = member_trace.as_ref() {
            state.stage_selection(&applicability, &applicability.winners);
        }
        return candidates_outcome(applicability.winners);
    }
    let mut fallback_candidates = direct_candidates;

    if analyzer.type_hierarchy_provider().is_some() {
        let mut seen = HashSet::default();
        let mut level = Vec::new();
        let mut depth = 0usize;
        for owner in &owners {
            if !definitions.scope_step() {
                break;
            }
            seen.insert(owner.clone());
            let expanded = definitions.direct_ancestors(token, owner);
            if let Some(state) = member_trace.as_mut() {
                brokk_bifrost_analysis::analyzer::usages::get_definition::record_hierarchy_parents(
                    &mut state.parents,
                    owner,
                    &expanded,
                );
            }
            level.extend(expanded);
        }
        while !level.is_empty() {
            if !definitions.scope_step() {
                break;
            }
            depth += 1;
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !definitions.scope_step() {
                    break;
                }
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                let found = csharp_non_constructor_member_candidates(
                    analyzer,
                    definitions,
                    &ancestor,
                    member,
                );
                if let Some(state) = member_trace.as_mut() {
                    state.record_found(&found, &ancestor, depth);
                }
                level_candidates.extend(found);
                let expanded = definitions.direct_ancestors(token, &ancestor);
                if let Some(state) = member_trace.as_mut() {
                    brokk_bifrost_analysis::analyzer::usages::get_definition::record_hierarchy_parents(&mut state.parents, &ancestor, &expanded);
                }
                next_level.extend(expanded);
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let level_generic = csharp_generic_arity_applicability(
                definitions,
                &level_candidates,
                explicit_generic_arity,
            );
            let level_candidates = level_generic.winners.clone();
            let level_applicability = level_generic.then(csharp_candidate_applicability(
                analyzer,
                definitions,
                &level_candidates,
                arity,
            ));
            if !level_applicability.winners.is_empty() {
                if let Some(state) = member_trace.as_ref() {
                    state.stage_selection(&level_applicability, &level_applicability.winners);
                }
                return candidates_outcome(level_applicability.winners);
            }
            if fallback_candidates.is_empty() && !level_candidates.is_empty() {
                fallback_candidates = level_candidates;
            }
            level = next_level;
        }
    }
    if !fallback_candidates.is_empty() {
        debug_assert!(
            arity.is_some(),
            "an unknown arity accepts every candidate, so a rejected set is unreachable"
        );
        if let Some(state) = member_trace.as_ref() {
            // Discarded, never bound: the arity filter accepted none of them,
            // and the inverse usage scan refuses such a site for exactly the
            // same reason (#1797). Record the discard while the walk still
            // knows the rows, with the reason the filter itself produced.
            let discarded =
                csharp_candidate_applicability(analyzer, definitions, &fallback_candidates, arity);
            state.stage_selection(&discarded, &[]);
        }
        // An overload whose parameter list cannot accept this argument list is
        // not the target. When the receiver's own hierarchy leaves the indexed
        // workspace, the accepting declaration is on the far side of that
        // boundary -- `Writer.WriteLine()` against a type deriving from the
        // unindexed `System.IO.TextWriter` -- which is what the site reports.
        // The implicit `object` base is such a departure too, but only for the
        // members `object` itself declares (#1810).
        return gated_boundary(
            || {
                !csharp_hierarchy_crosses_unindexed_supertype(definitions, token, &owners)
                    && !csharp_object_declares_overload(member, arity)
            },
            format!("`{member}` is inherited from a C# base type not indexed in this workspace"),
            UnindexedClaim::unindexed_owner(member, ClaimSubjectRole::Member),
            "no_applicable_overload",
            format!("no C# member `{member}` overload accepts this call"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("C# member `{member}` is not indexed as a definition"),
    )
}

/// Whether the receiver's own supertype closure names a type this workspace
/// does not index.
///
/// [`CSharpDefinitionProvider::direct_ancestors`] drops a base-type spelling it
/// cannot resolve, so the resolved ancestors alone cannot tell a complete
/// hierarchy from a truncated one. The raw `: Base, IFace` spellings can, put
/// through the very same supertype resolution that dropped them (#1797, the C#
/// face of Java's #1755).
fn csharp_hierarchy_crosses_unindexed_supertype(
    definitions: &CSharpDefinitionProvider<'_>,
    token: QueryToken<'_>,
    owners: &[CodeUnit],
) -> bool {
    let mut seen: HashSet<CodeUnit> = owners.iter().cloned().collect();
    let mut queue = owners.to_vec();
    while let Some(unit) = queue.pop() {
        if !definitions.scope_step() {
            return false;
        }
        let mut parts = definitions.partial_type_parts(&unit);
        if parts.is_empty() {
            parts.push(unit);
        }
        for part in parts {
            if !definitions.scope_step() {
                return false;
            }
            for raw in definitions.raw_supertypes(&part) {
                // Every C# type derives from `object`, which no workspace
                // indexes; naming it is not evidence of a truncated hierarchy.
                if matches!(
                    csharp_normalize_full_name(&raw).as_str(),
                    "object" | "System.Object"
                ) {
                    continue;
                }
                let candidates = definitions.supertype_candidates(token, &part, &raw);
                if candidates.is_empty() {
                    return true;
                }
                for candidate in candidates {
                    if seen.insert(candidate.clone()) {
                        queue.push(candidate);
                    }
                }
            }
        }
    }
    false
}

/// Whether `System.Object` itself declares a `member` overload this call's
/// argument count could reach.
///
/// [`csharp_hierarchy_crosses_unindexed_supertype`] skips `object` because
/// naming it says nothing about a truncated hierarchy -- every C# type derives
/// from it. That is right for resolution, and it is right for the boundary
/// verdict on *most* names: an unconditional "the implicit object base is
/// unindexed" rule would turn every arity-rejected call into a boundary claim,
/// including calls whose owner chain this workspace indexes completely, which
/// #1797's `LocalWriter.WriteLine()` face answers `no_definition` on purpose.
///
/// `object`'s own declared members are the exception (#1810). neo's
/// `WitnessCondition` declares only the one-argument `Equals` override, and the
/// bare `Equals(left, right)` beside it binds the external static
/// `object.Equals(object, object)` -- a declaration that exists, that the
/// workspace genuinely does not index, and that no explicit base type leads to.
/// Matching the identifier against the members `object` declares is what makes
/// that claim specific to this call rather than a blanket one.
///
/// The arity is part of the entry because the name alone would over-claim:
/// `object` has no three-argument `Equals`, so an `Equals(a, b, c)` call is not
/// reaching across this boundary either.
fn csharp_object_declares_overload(member: &str, arity: Option<usize>) -> bool {
    /// `System.Object`'s declared members, with the parameter counts each name
    /// offers. `Finalize` is omitted: C# forbids calling it by name.
    const OBJECT_MEMBERS: &[(&str, &[usize])] = &[
        ("Equals", &[1, 2]),
        ("GetHashCode", &[0]),
        ("GetType", &[0]),
        ("MemberwiseClone", &[0]),
        ("ReferenceEquals", &[2]),
        ("ToString", &[0]),
    ];
    let Some(arity) = arity else {
        return false;
    };
    OBJECT_MEMBERS
        .iter()
        .any(|(name, arities)| *name == member && arities.contains(&arity))
}

/// Where the C# member walk found one candidate: the exact type it read the
/// declaration out of, and how many hierarchy hops that type is from the
/// receiver's own type.
struct CSharpMemberFind {
    owner: CodeUnit,
    depth: usize,
}

/// The per-candidate attribution the C# member walk records while it runs
/// (#1477), built only when a trace is being recorded.
///
/// It is an emission of facts the walk already holds -- which type each
/// candidate was read out of, at which breadth-first depth, and through which
/// first-discovery edges that type was reached. The walk decides nothing from
/// it, so an untraced lookup allocates none of these maps and takes no extra
/// step.
///
/// Two limits are stated here rather than guessed around.
///
/// - Every hop is [`HierarchyRelation::Supertype`]. Both ancestor sources the
///   walk uses report one undifferentiated supertype list: the unbudgeted path
///   asks [`TypeHierarchyProvider::get_direct_ancestors`], and the bounded path
///   resolves the declaration's raw `: A, IB` list. Neither says which entry was
///   a base class and which an interface, so a C# interface member is
///   `inherited_or_promoted` at its true depth rather than `trait_or_interface`:
///   claiming the interface bucket would assert a distinction no layer here
///   made.
/// - Nothing claims [`MemberDispatchTier::StaticOrCompanion`]. C# spells a
///   static access exactly like an instance one (`Type.Member`), so the
///   reference site cannot state the bucket, and the C# adapter records no
///   `callable_is_static` signature metadata, so the declaration cannot either.
#[derive(Default)]
struct CSharpMemberTrace {
    /// The types the walk started from: each resolved receiver type and each
    /// part of a partial one. A route terminates when it reaches one.
    roots: HashSet<CodeUnit>,
    /// First-discovery parent of every ancestor the walk expanded, which makes
    /// the route a bounded walk back to a root.
    parents: HashMap<CodeUnit, CodeUnit>,
    found: HashMap<CodeUnit, CSharpMemberFind>,
    /// Every candidate the walk computed, in discovery order, so a candidate it
    /// discarded can be reported beside the one it bound.
    considered: Vec<CodeUnit>,
}

impl CSharpMemberTrace {
    fn record_root(&mut self, root: &CodeUnit) {
        self.roots.insert(root.clone());
    }

    fn record_found(&mut self, candidates: &[CodeUnit], owner: &CodeUnit, depth: usize) {
        for candidate in candidates {
            if self.found.contains_key(candidate) {
                continue;
            }
            self.found.insert(
                candidate.clone(),
                CSharpMemberFind {
                    owner: owner.clone(),
                    depth,
                },
            );
            self.considered.push(candidate.clone());
        }
    }

    /// The exact route from the root the walk descended through to the type
    /// `candidate` was found on, as the first-discovery edges the walk took.
    fn route(&self, candidate: &CodeUnit) -> Vec<trace::HierarchyHopRecord> {
        use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

        let Some(find) = self.found.get(candidate) else {
            return Vec::new();
        };
        let (route, _) = trace::hierarchy_route_from_predecessors(
            &find.owner,
            find.depth,
            |current, _| self.roots.contains(current),
            |current| {
                self.parents
                    .get(current)
                    .cloned()
                    .map(|parent| (parent, HierarchyRelation::Supertype))
            },
            |unit| Some(unit.clone()),
        )
        .expect("C# hierarchy route nodes always have declaration identities");
        debug_assert_eq!(
            route.len(),
            find.depth,
            "the first-discovery chain must be exactly the walk's hop distance"
        );
        route
    }

    fn enrichment(
        &self,
        candidate: &CodeUnit,
        applicability: ApplicabilityVerdict,
    ) -> Option<trace::MemberEnrichment> {
        let find = self.found.get(candidate)?;
        Some(trace::member_enrichment(
            find.owner.clone(),
            find.depth,
            applicability,
            self.route(candidate),
        ))
    }

    fn precedence_tier(&self, candidate: &CodeUnit) -> Option<PrecedenceTier> {
        self.found.get(candidate).map(|find| {
            brokk_bifrost_analysis::analyzer::usages::get_definition::member_precedence_tier(
                find.depth,
            )
        })
    }

    /// Stage attribution for the candidates the walk is about to bind, and
    /// record every other candidate it computed as rejected.
    ///
    /// A C# member loser here always lost on the call's shape alone -- the
    /// explicit type-argument count or the argument count -- whose structured
    /// story belongs to the callable axis (#1478), so the reason defers to it.
    ///
    /// `applicability` is the *same* value the caller used to decide what to
    /// bind (#1478 M3), so a loser's reason is the reason the filter acted on.
    /// `winners` is what the seam actually returns: the bound candidates on a
    /// return that constructs an outcome, and empty where the walk discarded a
    /// whole level. An empty `winners` therefore stages no attribution, only
    /// the rejected rows, because the reference's real answer may still come
    /// from a different seam entirely.
    fn stage_selection(&self, applicability: &ApplicabilityOutcome, winners: &[CodeUnit]) {
        let verdict_of = |unit: &CodeUnit| {
            applicability
                .verdicts
                .iter()
                .find(|verdict| verdict.candidate == *unit)
        };
        for loser in self
            .considered
            .iter()
            .filter(|unit| !winners.contains(unit))
        {
            trace::record_rejected_unit(
                loser,
                self.precedence_tier(loser),
                RejectionReason::CallableApplicabilityDeferred,
                verdict_of(loser).map(trace::CallableApplicabilityRecord::from),
                self.enrichment(loser, ApplicabilityVerdict::Inapplicable),
            );
        }
        trace::stage_winner_tier(
            winners,
            winners.iter().filter_map(|unit| self.precedence_tier(unit)),
        );
        trace::stage_applicability_context(winners, applicability, |unit, verdict| {
            self.enrichment(unit, verdict)
        });
    }
}

fn csharp_non_constructor_member_candidates(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
    name: &str,
) -> Vec<CodeUnit> {
    if !definitions.scope_step() {
        return Vec::new();
    }
    let constructor_name = csharp_source_identifier(owner);
    definitions
        .members_for_owner_name(&owner.fq_name(), name)
        .into_iter()
        .filter(|candidate| {
            if !definitions.scope_step() {
                return false;
            }
            definitions
                .parent_of(analyzer, candidate)
                .is_some_and(|parent| parent.fq_name() == owner.fq_name())
                && !(candidate.is_function() && candidate.identifier() == constructor_name)
        })
        .collect()
}

/// The member an object-initializer label names, which is always a member of
/// the constructed type and never of the enclosing class.
///
/// The constructed type is resolved through the same ladder the constructor
/// call directly above the initializer already uses. That matters most for a
/// type nested in an enclosing class: C# makes it visible by its simple name
/// from a sibling nested type, but the namespace-style walk joins candidate
/// keys with `.` against a `$`-nested fq segment and never finds it (#1105,
/// #1801). Resolving the owner with `csharp_logical_visible_type_candidates`
/// alone therefore found ZERO declarations for StockSharp's `new Actions {
/// Items = ... }` and ILSpy's `new CheckedUncheckedAnnotation { IsChecked =
/// ... }`, and then reported that as an ambiguity -- an answer that lists
/// nothing gives a caller nothing to choose between (#1811).
///
/// The two refusals below are now distinct facts. A target type that resolves
/// to no indexed declaration is unresolved, and the message says which type;
/// a target type that resolves to several is ambiguous, and the message names
/// every candidate with its file, the way `csharp_indexed_candidate_honesty_message`
/// names what it found while declining to pick.
///
/// Which target the owner comes from is decided by
/// `csharp_object_initializer_owners`, the ladder the inverse usage scan runs
/// too, so the two directions answer the same construct the same way (#2173).
/// Only the index probes below are forward-specific.
#[allow(clippy::too_many_arguments)]
fn csharp_object_initializer_label_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    label: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let initializer = csharp_object_initializer_for_label(label)?;
    let member = csharp_node_text(label, source);
    let mut lookups = CSharpForwardInitializerOwnerLookups {
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        root,
    };
    let Some(resolved) = csharp_object_initializer_owners(initializer, source, &mut lookups) else {
        return Some(no_definition(
            "unknown_object_initializer_owner",
            "C# object initializer target type could not be inferred",
        ));
    };
    if !resolved.ambiguous_call_candidates.is_empty() {
        let candidates = resolved
            .ambiguous_call_candidates
            .iter()
            .map(|candidate| {
                let signature = candidate
                    .signature()
                    .map(str::to_string)
                    .or_else(|| {
                        definitions
                            .signature_metadata(candidate)
                            .into_iter()
                            .next()
                            .map(|metadata| metadata.label().to_string())
                    })
                    .unwrap_or_default();
                if signature.is_empty() {
                    format!("`{}`", candidate.fq_name())
                } else {
                    format!("`{}` ({signature})", candidate.fq_name())
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Some(no_definition(
            "ambiguous_object_initializer_owner",
            format!(
                "C# object initializer call argument target is not uniquely typed; candidates: {candidates}"
            ),
        ));
    }
    Some(
        csharp_initializer_member_outcome(
            analyzer,
            token,
            definitions,
            resolved.owners,
            member,
            resolved.target.text(),
        )
        .unwrap_or_else(|| match &resolved.target {
            CSharpInitializerOwnerTarget::WrittenType(type_name) => no_definition(
                "unresolved_object_initializer_owner",
                format!(
                    "C# object initializer target type `{type_name}` did not resolve to an indexed C# type"
                ),
            ),
            CSharpInitializerOwnerTarget::CallArgument(target) => no_definition(
                "unknown_object_initializer_owner",
                format!(
                    "C# object initializer target type could not be inferred from call argument `{target}`"
                ),
            ),
            CSharpInitializerOwnerTarget::CollectionTarget(target) => no_definition(
                "unknown_object_initializer_owner",
                format!(
                    "C# object initializer element type could not be inferred from collection target `{target}`"
                ),
            ),
            CSharpInitializerOwnerTarget::AssignmentTarget(target) => no_definition(
                "unknown_object_initializer_owner",
                format!(
                    "C# object initializer target type could not be inferred from assignment target `{target}`"
                ),
            ),
            CSharpInitializerOwnerTarget::InitializerMember(member) => no_definition(
                "unknown_object_initializer_owner",
                format!(
                    "C# object initializer target type could not be inferred from initializer member `{member}`"
                ),
            ),
        }),
    )
}

/// The forward side of the shared object-initializer owner ladder: the same
/// probes the inverse scan supplies, reached through the definition
/// provider's budgeted session instead of the usage index.
struct CSharpForwardInitializerOwnerLookups<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'a>,
    csharp: &'a CSharpAnalyzer,
    definitions: &'a CSharpDefinitionProvider<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
}

impl CSharpInitializerOwnerLookups for CSharpForwardInitializerOwnerLookups<'_, '_> {
    fn written_type_owners(&mut self, reference: &str, type_node: Node<'_>) -> Vec<CodeUnit> {
        csharp_constructed_type_candidates(
            self.analyzer,
            self.token,
            self.definitions,
            self.file,
            self.source,
            type_node,
            reference,
        )
    }

    fn call_argument_owners(&mut self, call: Node<'_>, index: usize) -> CSharpCallArgumentOwners {
        let candidates = csharp_forward_call_argument_method_candidates(
            self.analyzer,
            self.token,
            self.csharp,
            self.definitions,
            self.file,
            self.source,
            self.root,
            call,
        );
        resolve_call_argument_owners(
            call,
            index,
            self.source,
            candidates,
            |method| self.definitions.signature_metadata(method),
            |method, parameter_index| {
                csharp_callable_parameter_type_owners(
                    self.csharp,
                    self.token,
                    self.definitions,
                    method,
                    parameter_index,
                )
            },
        )
    }

    fn collection_target_owners(&mut self, target: Node<'_>) -> Vec<CodeUnit> {
        csharp_collection_element_owner_types(
            self.analyzer,
            self.token,
            self.csharp,
            self.definitions,
            self.file,
            self.source,
            target,
        )
    }

    fn expression_owners(&mut self, target: Node<'_>) -> Vec<CodeUnit> {
        // The type of `x` in `x = new() { ... }` is the type of `x` in
        // `x.Member`, so an assignment target types exactly like a receiver.
        csharp_receiver_types(
            self.analyzer,
            self.token,
            self.csharp,
            self.definitions,
            self.file,
            self.source,
            self.root,
            target,
        )
        .units
    }

    fn member_type_owners(&mut self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let mut types = CSharpReceiverTypes::default();
        csharp_collect_member_types(
            self.csharp,
            self.token,
            self.definitions,
            self.file,
            owner,
            member,
            &mut types,
        );
        types.normalized().units
    }

    fn member_element_type_owners(&mut self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        csharp_member_element_type_owners(self.token, self.csharp, self.definitions, owner, member)
    }
}

fn csharp_member_element_type_owners(
    token: QueryToken<'_>,
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    let element = match definitions.session() {
        Some(session) => csharp_member_declared_collection_element_type_fq_name_in_session(
            definitions.source(),
            token,
            owner,
            member,
            session,
        ),
        None => csharp_member_declared_collection_element_type_fq_name(
            definitions.source(),
            token,
            owner,
            member,
        ),
    };
    element
        .into_iter()
        .flat_map(|fqn| definitions.fqn(&fqn))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn csharp_forward_call_argument_method_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Vec<CodeUnit> {
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some(invocation) = csharp_invocation_member(function, source) else {
        return Vec::new();
    };
    let method_name = csharp_node_text(invocation.name.identifier, source);
    if method_name.is_empty() {
        return Vec::new();
    }
    let call_arity = csharp_argument_count_in_session(call, source, definitions);
    let mut candidates = Vec::new();
    if let Some(receiver) = invocation.receiver {
        let owners = csharp_receiver_types(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            receiver,
        )
        .units;
        for owner in owners {
            let raw = csharp_forward_call_methods_for_owner(
                analyzer,
                token,
                definitions,
                &owner,
                method_name,
            );
            if raw.is_empty() {
                continue;
            }
            candidates.extend(filter_call_argument_method_candidates_with_metadata(
                raw,
                call_arity,
                invocation.name.explicit_generic_arity,
                |candidate| definitions.signature_metadata(candidate),
            ));
        }
    } else {
        // A simple-name invocation is resolved in lexical scope order. Once a
        // declaring scope has a member of this name, an arity mismatch there
        // cannot be rescued by an outer class's same-name method.
        for owner in csharp_enclosing_class_chain(analyzer, definitions, file, call.start_byte()) {
            let raw = csharp_forward_call_methods_for_owner(
                analyzer,
                token,
                definitions,
                &owner,
                method_name,
            );
            if raw.is_empty() {
                continue;
            }
            candidates = filter_call_argument_method_candidates_with_metadata(
                raw,
                call_arity,
                invocation.name.explicit_generic_arity,
                |candidate| definitions.signature_metadata(candidate),
            );
            break;
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_forward_call_methods_for_owner(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
    name: &str,
) -> Vec<CodeUnit> {
    if analyzer.type_hierarchy_provider().is_none() {
        return csharp_non_constructor_member_candidates(analyzer, definitions, owner, name);
    }
    let mut seen = HashSet::default();
    let mut level = vec![owner.clone()];
    while !level.is_empty() {
        let mut candidates = Vec::new();
        let mut next_level = Vec::new();
        for current in level {
            if !definitions.scope_step() || !seen.insert(current.clone()) {
                continue;
            }
            let mut parts = definitions.partial_type_parts(&current);
            if parts.is_empty() {
                parts.push(current.clone());
            }
            for part in parts {
                candidates.extend(csharp_non_constructor_member_candidates(
                    analyzer,
                    definitions,
                    &part,
                    name,
                ));
            }
            next_level.extend(definitions.direct_ancestors(token, &current));
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if !candidates.is_empty() {
            return candidates;
        }
        level = next_level;
    }
    Vec::new()
}

#[allow(clippy::too_many_arguments)]
fn csharp_collection_element_owner_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    target: Node<'_>,
) -> Vec<CodeUnit> {
    if target.kind() != "identifier" {
        return Vec::new();
    }
    let name = csharp_node_text(target, source);
    if let Some(type_node) = csharp_collection_target_element_type_node(target, source) {
        let type_name = csharp_reference_type_text(type_node, source);
        let mut owners = csharp_constructed_type_candidates(
            analyzer,
            token,
            definitions,
            file,
            source,
            type_node,
            &type_name,
        );
        sort_units(&mut owners);
        owners.dedup();
        return owners;
    }

    let owners = csharp_enclosing_class_chain(analyzer, definitions, file, target.start_byte());
    for owner in owners {
        let mut seen = HashSet::default();
        let mut level = vec![owner];
        while !level.is_empty() {
            let mut next_level = Vec::new();
            for current in level {
                if !definitions.scope_step() {
                    return Vec::new();
                }
                if !seen.insert(current.clone()) {
                    continue;
                }
                let members = definitions.members_for_owner_name(&current.fq_name(), name);
                if !members.is_empty() {
                    return csharp_member_element_type_owners(
                        token,
                        csharp,
                        definitions,
                        &current,
                        name,
                    );
                }
                if analyzer.type_hierarchy_provider().is_some() {
                    next_level.extend(definitions.direct_ancestors(token, &current));
                }
            }
            level = next_level;
        }
    }
    Vec::new()
}

/// Every declaration the constructed type of an object creation can name.
///
/// This is the constructor call's own ladder (`resolve_csharp_constructor`,
/// and the `Type` reference branch above it): a type nested in an enclosing
/// class first, because C# looks there before the namespace and `using`
/// scopes, then the lexically enclosing scopes, then the scope-blind visible
/// walk at the site, and finally the reference read as a fully qualified name.
fn csharp_constructed_type_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    reference: &str,
) -> Vec<CodeUnit> {
    let byte = site.start_byte();
    if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
        analyzer,
        token,
        definitions,
        file,
        reference,
        byte,
    ) {
        return vec![unit];
    }
    if let Some(unit) = resolve_csharp_in_enclosing_scopes(
        analyzer,
        definitions,
        file,
        reference,
        byte,
        CodeUnit::is_class,
    ) {
        return vec![unit];
    }
    let candidates =
        csharp_logical_visible_type_candidates(definitions, file, source, site, reference);
    if !candidates.is_empty() {
        return candidates;
    }
    definitions
        .fqn(reference)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect()
}

/// The label's member on the one constructed type, the ambiguity that names
/// every candidate, or `None` when the target proved no type at all.
///
/// The caller owns the `None` refusal because the two callers cannot prove the
/// same thing: one has a written type name that resolved to nothing, the other
/// has an assignment target whose type it could not infer.
fn csharp_initializer_member_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    mut owners: Vec<CodeUnit>,
    member: &str,
    target: &str,
) -> Option<DefinitionLookupOutcome> {
    match owners.len() {
        0 => None,
        1 => Some(csharp_member_outcome(
            analyzer,
            token,
            definitions,
            vec![owners.remove(0)],
            member,
            None,
            None,
        )),
        _ => Some(no_definition(
            "ambiguous_object_initializer_owner",
            format!(
                "C# object initializer target type `{target}` is not uniquely resolved; candidates: {}",
                owners
                    .iter()
                    .map(|owner| format!(
                        "`{}` ({})",
                        owner.fq_name(),
                        rel_path_string(owner.source())
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Resolve a named-argument label the same way the object-initializer label
/// above resolves: through the owner the label writes into, never through the
/// label's own spelling as a type (#1796).
///
/// An attribute label's owner is the attribute type, so `[Svc(Lifetime = ...)]`
/// answers `SvcAttribute.Lifetime` and reaches an inherited property through the
/// member walk's base chain. A label the attribute type does not declare has no
/// definition at all -- neither the same-named type nor a using-boundary claim
/// about a property name. A plain `Name:` label names a parameter, which C#
/// analysis does not index as a declaration.
fn csharp_named_argument_label_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    label: Node<'_>,
    shape: CSharpNamedArgumentLabel<'_>,
) -> DefinitionLookupOutcome {
    let name = csharp_node_text(label, source);
    let CSharpNamedArgumentLabel::AttributeMember { attribute_name } = shape else {
        return no_definition(
            "named_argument_parameter_label",
            format!(
                "`{name}` is a C# named-argument label naming a parameter, which is not an indexed declaration"
            ),
        );
    };
    let attribute_names = csharp_attribute_type_names(attribute_name, source);
    let (owners, _ambiguous_spelling) = definitions.attribute_type_candidates(
        analyzer,
        token,
        file,
        &attribute_names,
        source,
        attribute_name,
    );
    if owners.is_empty() {
        let attribute = attribute_names
            .first()
            .map(String::as_str)
            .unwrap_or_default();
        return no_definition(
            "unresolved_attribute_named_argument_owner",
            format!(
                "C# attribute type `{attribute}` owning named argument `{name}` did not resolve to an indexed definition"
            ),
        );
    }
    csharp_member_outcome(analyzer, token, definitions, owners, name, None, None)
}

fn csharp_is_unqualified_member_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "parameter" {
        // A parameter owns both its declaration name and its default-value
        // expression. The former is filtered as a declaration before this
        // helper runs; the latter is an ordinary value reference and can name
        // an enclosing constant or field (#2061).
        return parent.child_by_field_name("name") != Some(node);
    }
    if parent.kind() == "member_access_expression" {
        return csharp_member_access_receiver(parent)
            .is_some_and(|receiver| same_node(receiver, node));
    }
    if parent.kind() == "member_binding_expression" {
        return false;
    }
    if matches!(parent.kind(), "argument" | "attribute_argument")
        && parent.child_by_field_name("name") == Some(node)
    {
        return false;
    }
    if parent.kind() == "variable_declarator" {
        // Only the declarator's own name is a declaration site; the
        // initializer value is an ordinary reference and must reach the
        // enclosing-class member lookup (CsvHelper's
        // `var i = delimiterPosition` drew a dishonest using-boundary
        // claim for a field declared in the same class).
        return parent.child_by_field_name("name") != Some(node);
    }
    if parent.kind() == "property_declaration" {
        // A property owns its declaration name, its declared type, and the
        // `value` field that holds its initializer. The name is filtered as a
        // declaration and the type is classified as a type reference before
        // this helper runs; the initializer is an ordinary value reference and
        // routinely names an enclosing constant
        // (`public int CardinalityLimit { get; set; } = DefaultCardinalityLimit;`,
        // #2061).
        return parent.child_by_field_name("value") == Some(node);
    }
    !matches!(
        parent.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "local_function_statement"
            | "constructor_declaration"
            | "using_directive"
    )
}

/// Whether an unqualified identifier that bound no value may be reinterpreted
/// as a type name.
///
/// Every arm here is a syntactic role that C# lets a *type* fill even though
/// the grammar parses it as an ordinary expression, so the value-first lookup
/// running ahead of this check can legitimately come up empty. Roles that admit
/// only values are absent on purpose: an identifier that reaches this point in
/// one of them stays unresolved rather than picking up a same-named type
/// (#2061).
fn csharp_identifier_allows_type_fallback(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "member_access_expression"
        && csharp_member_access_receiver(parent).is_some_and(|receiver| same_node(receiver, node))
    {
        return true;
    }
    // `x is Structure` parses as a constant pattern because the grammar cannot
    // tell a type pattern from a constant one; the declaration index decides.
    // `x is not Structure` nests the same constant pattern under
    // `negated_pattern`, so the operand's parent is the pattern either way.
    if csharp_constant_pattern_type_candidate(parent)
        .is_some_and(|candidate| same_node(candidate, node))
    {
        return true;
    }
    // `nameof(Structure)` names a type through expression syntax.
    csharp_identifier_is_arity_free_type_name(node, source)
}

fn csharp_identifier_is_arity_free_type_name(node: Node<'_>, source: &str) -> bool {
    csharp_nameof_invocation_for_operand(node)
        .and_then(|invocation| csharp_nameof_type_candidates(invocation, source))
        .is_some_and(|(operand, _)| same_node(operand, node))
}

/// The `nameof(...)` invocation whose sole operand is `node`, if any.
///
/// The grammar wraps the operand in `argument_list > argument`, and an operand
/// that is itself parenthesized or a member access is handled by
/// [`csharp_nameof_type_candidates`], which the caller applies to the
/// invocation this returns.
fn csharp_nameof_invocation_for_operand(node: Node<'_>) -> Option<Node<'_>> {
    let argument = node.parent()?;
    if argument.kind() != "argument" {
        return None;
    }
    let argument_list = argument.parent()?;
    if argument_list.kind() != "argument_list" {
        return None;
    }
    let invocation = argument_list.parent()?;
    (invocation.kind() == "invocation_expression").then_some(invocation)
}

/// The one C# call-shape applicability check (#1478 M3): the candidates the
/// resolver's arity filter admits and the typed verdict for every candidate it
/// considered.
///
/// Three states are distinct here, and each is preserved exactly as the filter
/// has always treated it.
///
/// A non-callable member declares no parameter list: a delegate-valued property
/// or field is invoked through its own type's signature, which this side does
/// not read. The inverse scan gates such a target on nothing but its name
/// (`TargetSpec::callable_arity` is `None` for a field), so neither does this
/// side -- otherwise the two disagree about every `configuration.Select(1)`
/// site. It is admitted, and its verdict is `unknown` because no parameter list
/// was measured.
///
/// A candidate the scope budget stopped on is not a verdict about its parameter
/// list at all. It is not admitted, exactly as before, and records `unknown`
/// rather than a rejection nobody computed.
///
/// Missing or conflicting primary parameter metadata is unknown; it cannot
/// prove a zero-argument callable or a parameter-count mismatch.
fn csharp_candidate_applicability(
    _analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> ApplicabilityOutcome {
    let Some(expected) = arity else {
        return ApplicabilityOutcome::undecidable(candidates);
    };
    let mut winners = Vec::new();
    let mut verdicts = Vec::new();
    for unit in candidates {
        if !definitions.scope_step() {
            verdicts.push(CandidateApplicability::unknown(unit.clone()));
            continue;
        }
        if !unit.is_function() {
            winners.push(unit.clone());
            verdicts.push(CandidateApplicability::unknown(unit.clone()));
            continue;
        }
        let declared = brokk_bifrost_csharp::syntax::csharp_callable_arity_from_metadata(
            &definitions.signature_metadata(unit),
        );
        let verdict = arity_verdict(unit, declared.as_ref().map(std::slice::from_ref), expected);
        if verdict.verdict != ApplicabilityVerdict::Inapplicable {
            winners.push(unit.clone());
        }
        verdicts.push(verdict);
    }
    ApplicabilityOutcome { winners, verdicts }
}

fn csharp_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    csharp_candidate_applicability(analyzer, definitions, candidates, arity).winners
}

/// The explicit type-argument check, on the same one-pass shape.
///
/// A method reference written `Convert<int>` names a generic arity, and a
/// candidate whose declared type-parameter count differs is not that method.
/// The verdict says exactly that, which is what separates this refusal from a
/// value-argument mismatch in a row a policy reads.
fn csharp_generic_arity_applicability(
    definitions: &CSharpDefinitionProvider<'_>,
    candidates: &[CodeUnit],
    explicit_generic_arity: Option<usize>,
) -> ApplicabilityOutcome {
    let Some(expected) = explicit_generic_arity else {
        return ApplicabilityOutcome::undecidable(candidates);
    };
    let mut winners = Vec::new();
    let mut verdicts = Vec::new();
    for unit in candidates {
        if !definitions.scope_step() {
            verdicts.push(CandidateApplicability::unknown(unit.clone()));
            continue;
        }
        let metadata = definitions.signature_metadata(unit);
        if !definitions.observe_cancellation() {
            verdicts.push(CandidateApplicability::unknown(unit.clone()));
            continue;
        }
        if unit.is_function()
            && (metadata.is_empty()
                || metadata
                    .iter()
                    .any(|row| row.type_parameters().len() != metadata[0].type_parameters().len()))
        {
            winners.push(unit.clone());
            verdicts.push(CandidateApplicability::unknown(unit.clone()));
        } else if unit.is_function() && metadata[0].type_parameters().len() == expected {
            winners.push(unit.clone());
            verdicts.push(CandidateApplicability::applicable(unit.clone()));
        } else {
            verdicts.push(CandidateApplicability::inapplicable(
                unit.clone(),
                CallableRejectionReason::TypeArgumentArityMismatch,
            ));
        }
    }
    ApplicabilityOutcome { winners, verdicts }
}

#[derive(Clone, Copy)]
enum CSharpReceiverBase<'tree> {
    Expression(Node<'tree>),
    EnclosingType { byte: usize },
}

#[derive(Clone, Copy)]
enum CSharpReceiverTransition<'tree> {
    Member {
        expression: Node<'tree>,
        name: Node<'tree>,
    },
    Invocation {
        invocation: Node<'tree>,
        name: Node<'tree>,
    },
}

struct CSharpReceiverProgram<'tree> {
    base: CSharpReceiverBase<'tree>,
    transitions: Vec<CSharpReceiverTransition<'tree>>,
}

/// Receiver evidence for forward member resolution. `units` are the indexed
/// declarations that ordinary member lookup can traverse; `fq_names` also keeps
/// precise declared types that are not indexed in the workspace, such as
/// `System.String`, for extension-method applicability.
#[derive(Default)]
struct CSharpReceiverTypes {
    units: Vec<CodeUnit>,
    fq_names: Vec<String>,
}

impl CSharpReceiverTypes {
    fn from_units(units: Vec<CodeUnit>) -> Self {
        let fq_names = units.iter().map(CodeUnit::fq_name).collect();
        Self { units, fq_names }.normalized()
    }

    fn push_fq_name(&mut self, definitions: &CSharpDefinitionProvider<'_>, fqn: String) {
        self.units.extend(definitions.fqn(&fqn));
        self.fq_names.push(fqn);
    }

    fn normalized(mut self) -> Self {
        sort_units(&mut self.units);
        self.units.dedup();
        self.fq_names.sort();
        self.fq_names.dedup();
        self
    }
}

fn csharp_receiver_program<'tree>(
    definitions: &CSharpDefinitionProvider<'_>,
    mut expression: Node<'tree>,
) -> Option<CSharpReceiverProgram<'tree>> {
    let mut transitions = Vec::new();
    let base = loop {
        if !definitions.scope_step() {
            return None;
        }
        match expression.kind() {
            "parenthesized_expression" | "checked_expression" => {
                expression = expression
                    .child_by_field_name("expression")
                    .or_else(|| expression.named_child(0))?;
            }
            "member_access_expression" => {
                let receiver = csharp_member_access_receiver(expression)?;
                let name = csharp_member_access_name(expression)?;
                transitions.push(CSharpReceiverTransition::Member { expression, name });
                expression = receiver;
            }
            "conditional_access_expression" => {
                let access = csharp_conditional_member_access(expression)?;
                transitions.push(CSharpReceiverTransition::Member {
                    expression,
                    name: access.name,
                });
                expression = access.receiver;
            }
            "invocation_expression" => {
                let function = expression.child_by_field_name("function")?;
                match function.kind() {
                    "member_access_expression" => {
                        let receiver = csharp_member_access_receiver(function)?;
                        let name = csharp_member_access_name(function)?;
                        transitions.push(CSharpReceiverTransition::Invocation {
                            invocation: expression,
                            name,
                        });
                        expression = receiver;
                    }
                    "conditional_access_expression" => {
                        let access = csharp_conditional_member_access(function)?;
                        transitions.push(CSharpReceiverTransition::Invocation {
                            invocation: expression,
                            name: access.name,
                        });
                        expression = access.receiver;
                    }
                    "identifier" | "generic_name" => {
                        transitions.push(CSharpReceiverTransition::Invocation {
                            invocation: expression,
                            name: function,
                        });
                        break CSharpReceiverBase::EnclosingType {
                            byte: function.start_byte(),
                        };
                    }
                    _ => return None,
                }
            }
            _ => break CSharpReceiverBase::Expression(expression),
        }
    };
    transitions.reverse();
    Some(CSharpReceiverProgram { base, transitions })
}

#[allow(clippy::too_many_arguments)]
fn csharp_receiver_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> CSharpReceiverTypes {
    let Some(program) = csharp_receiver_program(definitions, receiver) else {
        return CSharpReceiverTypes::default();
    };
    if !definitions.observe_cancellation() {
        return CSharpReceiverTypes::default();
    }

    if let CSharpReceiverBase::EnclosingType { byte } = program.base {
        for owner in csharp_enclosing_class_chain(analyzer, definitions, file, byte) {
            let receiver_types = csharp_apply_receiver_transitions(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                CSharpReceiverTypes::from_units(vec![owner]),
                &program.transitions,
            );
            if !receiver_types.units.is_empty() || !receiver_types.fq_names.is_empty() {
                return receiver_types.normalized();
            }
        }
        return CSharpReceiverTypes::default();
    }

    let CSharpReceiverBase::Expression(base) = program.base else {
        unreachable!("enclosing receiver bases returned above")
    };
    let mut receiver_types = csharp_receiver_base_types(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        root,
        base,
    );
    if !definitions.observe_cancellation() {
        return CSharpReceiverTypes::default();
    }

    let mut first_transition = 0usize;
    if receiver_types.units.is_empty()
        && !csharp_receiver_base_is_shadowed(csharp, token, definitions, file, source, root, base)
    {
        if !definitions.scope_step() {
            return CSharpReceiverTypes::default();
        }
        let expression_type = csharp_reference_type_text(receiver, source);
        let direct_types = csharp_logical_visible_type_candidates(
            definitions,
            file,
            source,
            receiver,
            &expression_type,
        );
        if !direct_types.is_empty() {
            return CSharpReceiverTypes::from_units(direct_types);
        }

        for (index, transition) in program.transitions.iter().enumerate() {
            if !definitions.scope_step() {
                return CSharpReceiverTypes::default();
            }
            let CSharpReceiverTransition::Member { expression, .. } = transition else {
                continue;
            };
            let type_name = csharp_reference_type_text(*expression, source);
            let candidates = csharp_logical_visible_type_candidates(
                definitions,
                file,
                source,
                *expression,
                &type_name,
            );
            if !candidates.is_empty() {
                receiver_types = CSharpReceiverTypes::from_units(candidates);
                first_transition = index + 1;
                break;
            }
        }
    }

    csharp_apply_receiver_transitions(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        source,
        receiver_types,
        &program.transitions[first_transition..],
    )
    .normalized()
}

#[allow(clippy::too_many_arguments)]
fn csharp_apply_receiver_transitions(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    mut receiver_types: CSharpReceiverTypes,
    transitions: &[CSharpReceiverTransition<'_>],
) -> CSharpReceiverTypes {
    for transition in transitions {
        if receiver_types.fq_names.is_empty() || !definitions.scope_step() {
            return CSharpReceiverTypes::default();
        }
        receiver_types = match *transition {
            CSharpReceiverTransition::Member { name, .. } => {
                let Some(name) = csharp_member_name(name) else {
                    return CSharpReceiverTypes::default();
                };
                csharp_nearest_member_types(
                    analyzer,
                    token,
                    csharp,
                    definitions,
                    file,
                    receiver_types.units,
                    csharp_node_text(name.identifier, source),
                )
            }
            CSharpReceiverTransition::Invocation { invocation, name } => {
                csharp_invocation_return_types(
                    analyzer,
                    token,
                    definitions,
                    file,
                    source,
                    invocation,
                    name,
                    receiver_types,
                )
            }
        };
        if !definitions.observe_cancellation() {
            return CSharpReceiverTypes::default();
        }
    }
    receiver_types
}

#[allow(clippy::too_many_arguments)]
fn csharp_receiver_base_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> CSharpReceiverTypes {
    if !definitions.scope_step() {
        return CSharpReceiverTypes::default();
    }
    match receiver.kind() {
        "identifier" => {
            let name = csharp_node_text(receiver, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
                token,
                definitions,
                file,
                source,
                root,
                receiver.start_byte(),
            );
            if let Some(targets) = bindings.resolve_symbol(name).as_precise() {
                return CSharpReceiverTypes::from_units(targets.iter().cloned().collect());
            }
            if bindings.is_shadowed(name) {
                let legacy = csharp_legacy_bindings_before_scoped(
                    csharp,
                    token,
                    definitions,
                    file,
                    source,
                    root,
                    receiver.start_byte(),
                );
                let mut receiver_types = CSharpReceiverTypes::default();
                // Both forms are pushed as the fq name they carry, which is
                // what this shadowed-binding fallback already did; only the
                // resolved form is now typed as one.
                if let Some(declared) = first_precise(&legacy, name) {
                    receiver_types.push_fq_name(definitions, declared.as_type_name().to_string());
                }
                receiver_types
            } else {
                let mut receiver_types = csharp_enclosing_member_types(
                    analyzer,
                    token,
                    csharp,
                    definitions,
                    file,
                    receiver,
                    name,
                );
                if receiver_types.units.is_empty() && receiver_types.fq_names.is_empty() {
                    receiver_types =
                        CSharpReceiverTypes::from_units(csharp_logical_visible_type_candidates(
                            definitions,
                            file,
                            source,
                            receiver,
                            name,
                        ));
                }
                receiver_types
            }
        }
        "this" => CSharpReceiverTypes::from_units(
            csharp_enclosing_class(analyzer, definitions, file, receiver.start_byte())
                .into_iter()
                .collect(),
        ),
        "base" => CSharpReceiverTypes::from_units(
            csharp_enclosing_class(analyzer, definitions, file, receiver.start_byte())
                .and_then(|owner| {
                    crate::analyzer::usages::csharp_graph::csharp_usage_direct_base(
                        analyzer,
                        token,
                        definitions.source(),
                        &owner,
                    )
                })
                .into_iter()
                .collect(),
        ),
        "qualified_name" | "alias_qualified_name" | "generic_name" => {
            CSharpReceiverTypes::from_units(csharp_logical_visible_type_candidates(
                definitions,
                file,
                source,
                receiver,
                &csharp_reference_type_text(receiver, source),
            ))
        }
        "predefined_type" => {
            let reference = csharp_reference_type_text(receiver, source);
            let Some(fqn) = canonical_csharp_predefined_type(&reference) else {
                return CSharpReceiverTypes::default();
            };
            let mut receiver_types = CSharpReceiverTypes::default();
            receiver_types.push_fq_name(definitions, fqn.to_string());
            receiver_types
        }
        // These are flattened into explicit transitions by
        // `csharp_receiver_program`; seeing one here means an unsupported shape
        // interrupted program construction.
        "member_access_expression"
        | "conditional_access_expression"
        | "invocation_expression"
        | "parenthesized_expression"
        | "checked_expression" => CSharpReceiverTypes::default(),
        "object_creation_expression" => CSharpReceiverTypes::from_units(
            receiver
                .child_by_field_name("type")
                .map(|type_node| {
                    csharp_logical_visible_type_candidates(
                        definitions,
                        file,
                        source,
                        type_node,
                        &csharp_reference_type_text(type_node, source),
                    )
                })
                .unwrap_or_default(),
        ),
        "cast_expression" | "as_expression" => CSharpReceiverTypes::from_units(
            receiver
                .child_by_field_name(if receiver.kind() == "cast_expression" {
                    "type"
                } else {
                    "right"
                })
                .map(|type_node| {
                    csharp_logical_visible_type_candidates(
                        definitions,
                        file,
                        source,
                        type_node,
                        &csharp_reference_type_text(type_node, source),
                    )
                })
                .unwrap_or_default(),
        ),
        _ => CSharpReceiverTypes::default(),
    }
}

fn csharp_receiver_base_is_shadowed(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    base: Node<'_>,
) -> bool {
    if base.kind() == "identifier" {
        let name = csharp_node_text(base, source);
        csharp_type_bindings_before_scoped(
            csharp,
            token,
            definitions,
            file,
            source,
            root,
            base.start_byte(),
        )
        .is_shadowed(name)
    } else {
        false
    }
}

/// The type names a member access's bare receiver leaves behind when the
/// workspace indexes neither the receiver nor the type it names.
///
/// `Environment.GetEnvironmentVariable` is a static member access whose
/// receiver is a type, but nothing about the identifier says so: it is also
/// exactly the shape of a value receiver whose declaration the workspace
/// failed to index. The two are told apart structurally. A visible local,
/// parameter, or enclosing member of that name is a value, and the missing
/// fact is then its type -- `unsupported_csharp_receiver`, never an external
/// type boundary. Only after every value channel answers nothing does the
/// name itself become the one structured fact left: the receiver names a type
/// the workspace does not index, which is the same frontier
/// `csharp_receiver_type_unindexed` publishes for receivers whose type was
/// read but not indexed (#3466).
#[allow(clippy::too_many_arguments)]
fn csharp_unindexed_type_qualifier_names(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<String> {
    if receiver.kind() != "identifier" || !definitions.scope_step() {
        return Vec::new();
    }
    let name = csharp_node_text(receiver, source);
    if name.is_empty() {
        return Vec::new();
    }
    let bindings = csharp_type_bindings_before_scoped(
        csharp,
        token,
        definitions,
        file,
        source,
        root,
        receiver.start_byte(),
    );
    if bindings.is_shadowed(name) {
        return Vec::new();
    }
    for owner in csharp_enclosing_class_chain(analyzer, definitions, file, receiver.start_byte()) {
        if !definitions
            .members_for_owner_name(&owner.fq_name(), name)
            .is_empty()
        {
            return Vec::new();
        }
    }
    csharp_structured_receiver_reference_type_names(
        token,
        definitions,
        file,
        source,
        receiver,
        name,
    )
}

fn canonical_csharp_predefined_type(reference: &str) -> Option<&'static str> {
    match reference {
        "bool" => Some("System.Boolean"),
        "byte" => Some("System.Byte"),
        "sbyte" => Some("System.SByte"),
        "char" => Some("System.Char"),
        "decimal" => Some("System.Decimal"),
        "double" => Some("System.Double"),
        "float" => Some("System.Single"),
        "int" => Some("System.Int32"),
        "uint" => Some("System.UInt32"),
        "nint" => Some("System.IntPtr"),
        "nuint" => Some("System.UIntPtr"),
        "long" => Some("System.Int64"),
        "ulong" => Some("System.UInt64"),
        "short" => Some("System.Int16"),
        "ushort" => Some("System.UInt16"),
        "string" => Some("System.String"),
        "object" => Some("System.Object"),
        _ => None,
    }
}

fn csharp_nearest_member_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    owners: Vec<CodeUnit>,
    name: &str,
) -> CSharpReceiverTypes {
    let provider = analyzer.type_hierarchy_provider();
    let mut result = CSharpReceiverTypes::default();
    for owner in owners {
        if !definitions.scope_step() {
            return CSharpReceiverTypes::default();
        }
        let mut seen = HashSet::default();
        let mut level = vec![owner];
        while !level.is_empty() {
            if !definitions.scope_step() {
                return CSharpReceiverTypes::default();
            }
            let mut level_types = CSharpReceiverTypes::default();
            let mut level_declares_member = false;
            let mut next_level = Vec::new();
            for current in level {
                if !definitions.scope_step() {
                    return CSharpReceiverTypes::default();
                }
                if !seen.insert(current.clone()) {
                    continue;
                }
                level_declares_member |= !definitions
                    .members_for_owner_name(&current.fq_name(), name)
                    .is_empty();
                csharp_collect_member_types(
                    csharp,
                    token,
                    definitions,
                    file,
                    &current,
                    name,
                    &mut level_types,
                );
                if provider.is_some() {
                    next_level.extend(definitions.direct_ancestors(token, &current));
                }
            }
            if level_declares_member {
                result.units.extend(level_types.units);
                result.fq_names.extend(level_types.fq_names);
                break;
            }
            level = next_level;
        }
    }
    result.normalized()
}

/// Fold one invocation transition over already-resolved owners. Keeping owner
/// evaluation outside this helper prevents alternating call/member syntax from
/// recursing through the Rust stack.
#[allow(clippy::too_many_arguments)]
fn csharp_invocation_return_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    invocation: Node<'_>,
    name_node: Node<'_>,
    receiver_types: CSharpReceiverTypes,
) -> CSharpReceiverTypes {
    if !definitions.scope_step() {
        return CSharpReceiverTypes::default();
    }
    let Some(name) = csharp_member_name(name_node) else {
        return CSharpReceiverTypes::default();
    };
    let method = csharp_node_text(name.identifier, source);
    if receiver_types.fq_names.is_empty() || method.is_empty() {
        return CSharpReceiverTypes::default();
    }
    let explicit_type_arguments =
        csharp_resolved_type_arguments(definitions, file, source, name.type_arguments);
    let extension_site =
        (!csharp_is_unqualified_invocation_target(name_node)).then_some(name.identifier);

    let receiver_type_names = receiver_types.fq_names;
    let mut return_types = CSharpReceiverTypes::default();
    let value_arity = csharp_argument_count_in_session(invocation, source, definitions);
    for owner in &receiver_types.units {
        if !definitions.scope_step() {
            return CSharpReceiverTypes::default();
        }
        let type_fqn = match definitions.session() {
            Some(session) => csharp_method_return_type_fq_name_for_arity_in_session(
                definitions.source(),
                token,
                file,
                owner,
                method,
                Some(value_arity),
                name.explicit_generic_arity,
                explicit_type_arguments.as_deref(),
                session,
            ),
            None => csharp_method_return_type_fq_name_for_arity(
                definitions.source(),
                token,
                file,
                owner,
                method,
                Some(value_arity),
                name.explicit_generic_arity,
                explicit_type_arguments.as_deref(),
            ),
        };
        if let Some(type_fqn) = type_fqn {
            return_types.push_fq_name(definitions, type_fqn);
        }
    }
    // The invoked name was not an ordinary member of the receiver type; the callee
    // may itself be an extension method (`handler.Handle("Ada")` where `Handle` is
    // `this Handler`). Type the invocation by that extension's declared return type
    // so a chained extension call on the result (`…​.Tag()`) can still resolve. Uses
    // the shared extension matcher + return-type derivation — no duplicated typing.
    if return_types.fq_names.is_empty()
        && let Some(site) = extension_site
    {
        let type_fqn = match definitions.session() {
            Some(session) => csharp_extension_invocation_return_type_fq_name_in_session(
                definitions.source(),
                analyzer,
                token,
                source,
                site,
                &receiver_type_names,
                method,
                Some(value_arity),
                name.explicit_generic_arity,
                explicit_type_arguments.as_deref(),
                false,
                session,
            ),
            None => csharp_extension_invocation_return_type_fq_name(
                definitions.source(),
                analyzer,
                token,
                source,
                site,
                &receiver_type_names,
                method,
                Some(value_arity),
                name.explicit_generic_arity,
                explicit_type_arguments.as_deref(),
                false,
            ),
        };
        if let Some(type_fqn) = type_fqn {
            return_types.push_fq_name(definitions, type_fqn);
        }
    }
    return_types.normalized()
}

fn csharp_resolved_type_arguments(
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    type_arguments: Option<Node<'_>>,
) -> Option<Vec<String>> {
    brokk_bifrost_csharp::syntax::map_csharp_type_arguments(type_arguments, |argument| {
        if !definitions.scope_step() {
            return None;
        }
        let reference = csharp_reference_type_text(argument, source);
        let mut candidates =
            csharp_logical_visible_type_candidates(definitions, file, source, argument, &reference);
        (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
    })
}

fn csharp_enclosing_member_type_units(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    csharp_enclosing_member_types(analyzer, token, csharp, definitions, file, receiver, name).units
}

fn csharp_enclosing_member_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> CSharpReceiverTypes {
    if !definitions.scope_step() {
        return CSharpReceiverTypes::default();
    }
    // Same lexical scope chain as the member walk (#1802): a bare receiver may
    // name a field or property of an enclosing type. One enclosing type and its
    // whole base chain are searched before the next one outward, so a nearer
    // base class's member still supplies the type.
    for owner in csharp_enclosing_class_chain(analyzer, definitions, file, receiver.start_byte()) {
        let mut candidates = CSharpReceiverTypes::default();
        csharp_collect_member_types(
            csharp,
            token,
            definitions,
            file,
            &owner,
            name,
            &mut candidates,
        );
        if analyzer.type_hierarchy_provider().is_some() {
            let mut seen = HashSet::default();
            let mut stack = definitions.direct_ancestors(token, &owner);
            while let Some(ancestor) = stack.pop() {
                if !definitions.scope_step() {
                    return CSharpReceiverTypes::default();
                }
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                csharp_collect_member_types(
                    csharp,
                    token,
                    definitions,
                    file,
                    &ancestor,
                    name,
                    &mut candidates,
                );
                stack.extend(definitions.direct_ancestors(token, &ancestor));
            }
        }
        let candidates = candidates.normalized();
        if !candidates.units.is_empty() || !candidates.fq_names.is_empty() {
            return candidates;
        }
    }
    CSharpReceiverTypes::default()
}

fn csharp_collect_member_types(
    _csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    name: &str,
    candidates: &mut CSharpReceiverTypes,
) {
    if !definitions.scope_step() {
        return;
    }
    let type_fqn = match definitions.session() {
        Some(session) => csharp_member_declared_type_fq_name_in_session(
            definitions.source(),
            token,
            file,
            owner,
            name,
            session,
        ),
        None => csharp_member_declared_type_fq_name(definitions.source(), token, file, owner, name),
    };
    if let Some(type_fqn) = type_fqn {
        candidates.push_fq_name(definitions, type_fqn);
    }
}

// Both lookups take the reference's site. A file can hold several namespace
// bodies, and a file-wide namespace hint made a global-namespace reference see
// a sibling namespace's members unqualified (#7569).
fn csharp_visible_type_output_candidates(
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = definitions.visible_type_candidates_at(file, name, source, site);
    graph_support::sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_logical_visible_type_candidates(
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = definitions.visible_type_candidates_at(file, name, source, site);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn csharp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: 0,
        end_line: 0,
    };
    if definitions.session().is_some() {
        let start = definitions.query_optional(|| analyzer.enclosing_code_unit(file, &range))?;
        return brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(
            start,
            |unit| definitions.parent_of(analyzer, unit),
        )
        .find(CodeUnit::is_class);
    }
    if let Some(unit) = analyzer.class_range_index(file).enclosing_unit(byte) {
        return Some(unit.clone());
    }

    let start = analyzer.enclosing_code_unit(file, &range)?;
    brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
        analyzer.parent_of(unit)
    })
    .find(CodeUnit::is_class)
}

/// Every class that lexically encloses `byte`, innermost first: the type the
/// reference is written in, then the type that declares it, and so on out to
/// the outermost type declaration.
///
/// C# simple-name lookup does not stop at the innermost type (#1802). After
/// that type, its partial parts and its whole base chain are exhausted, the
/// search continues in the type that encloses it, on the same terms.
///
/// Consume this in order through `csharp_member_outcome_in_enclosing_chain`.
/// Never hand the whole chain to `csharp_member_outcome` as one owners vector:
/// that walk sweeps every owner level by level, so an enclosing type's member
/// would beat a nearer base class's member and invert C# lookup order.
fn csharp_enclosing_class_chain(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    byte: usize,
) -> Vec<CodeUnit> {
    let Some(innermost) = csharp_enclosing_class(analyzer, definitions, file, byte) else {
        return Vec::new();
    };
    brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(innermost, |unit| {
        definitions
            .parent_of(analyzer, unit)
            .filter(CodeUnit::is_class)
    })
    .map_while(|owner| definitions.scope_step().then_some(owner))
    .collect()
}

/// The C# simple-name member walk over a lexical scope chain: run the full
/// `csharp_member_outcome` walk -- the type, its partial parts, its whole base
/// chain -- for one enclosing type before moving outward to the next, and
/// answer with the first type that resolves the name (#1802).
///
/// A failure reports the innermost type's verdict, which is the scope the
/// reference is actually written in.
fn csharp_member_outcome_in_enclosing_chain(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
) -> DefinitionLookupOutcome {
    if owners.is_empty() {
        return csharp_member_outcome(
            analyzer,
            token,
            definitions,
            owners,
            member,
            arity,
            explicit_generic_arity,
        );
    }
    let mut innermost_failure = None;
    for owner in owners {
        if !definitions.scope_step() {
            return no_definition(
                "csharp_resolution_stopped",
                "C# member resolution stopped before completion",
            );
        }
        let outcome = csharp_member_outcome(
            analyzer,
            token,
            definitions,
            vec![owner],
            member,
            arity,
            explicit_generic_arity,
        );
        if outcome.status != DefinitionLookupStatus::NoDefinition {
            return outcome;
        }
        innermost_failure.get_or_insert(outcome);
    }
    innermost_failure.expect("a non-empty owner chain records the innermost type's verdict")
}

fn resolve_csharp_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }
    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: 0,
        end_line: 0,
    };
    let scope = definitions
        .query_optional(|| analyzer.enclosing_code_unit(file, &range))?
        .fq_name();
    resolve_qualified_name_in_shrinking_scopes(
        &scope,
        name,
        || definitions.scope_step(),
        |fqn| definitions.fqn(fqn),
        accept,
    )
}

/// The #1218 shape: a reference fails C# type resolution and looks like it
/// crosses an unindexed `using` boundary, but the exact identifier is
/// nonetheless indexed as *some other kind* of declaration reachable from the
/// reference's enclosing scope chain (e.g. a property that merely shares its
/// spelling with an unrelated, genuinely-external BCL type — Newtonsoft.Json's
/// deprecated `Binder` property is declared `SerializationBinder Binder`,
/// where the type `SerializationBinder` is `System.Runtime.Serialization`'s
/// abstract class, not this workspace's own `JsonSerializer.SerializationBinder`
/// property, but both share the bare spelling `SerializationBinder`).
///
/// `resolve_csharp_in_enclosing_scopes` and
/// `resolve_csharp_nested_type_in_enclosing_classes` already walk this same
/// scope chain, filtered to `CodeUnit::is_class` so they only ever *resolve*
/// to a real type. Retrying the identical walk with `accept` explicitly
/// excluding the kinds those earlier resolvers already vetted, purely to
/// decide whether the boundary message is honest, cannot substitute a
/// wrong-kind declaration as the answer (it is never returned as a
/// definition) — it only downgrades a dishonest "not indexed" claim to an
/// accurate "not a type here; a `{kind}` of that name is indexed at
/// `{path}`" message. Same invariant as #1126/#1089/#1174, applied along the
/// declaration-kind axis instead of shadowing/naming/language.
fn csharp_indexed_non_type_candidate(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    resolve_csharp_in_enclosing_scopes(analyzer, definitions, file, reference, byte, accept)
}

fn csharp_indexed_candidate_honesty_message(
    reference: &str,
    subject: &str,
    candidate: &CodeUnit,
) -> String {
    format!(
        "`{reference}` does not resolve to an indexed C# {subject} here; `{reference}` is indexed as `{}` ({})",
        candidate.fq_name(),
        rel_path_string(candidate.source()),
    )
}

fn resolve_csharp_nested_type_in_enclosing_classes(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    resolve_csharp_nested_type_in_enclosing_classes_with(
        analyzer,
        token,
        definitions,
        file,
        name,
        byte,
        &mut |fqn| definitions.fqn(fqn),
    )
}

fn resolve_csharp_arity_free_nested_type_in_enclosing_classes(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    resolve_csharp_nested_type_in_enclosing_classes_with(
        analyzer,
        token,
        definitions,
        file,
        name,
        byte,
        &mut |fqn| definitions.arity_free_types_by_fqn(fqn),
    )
}

/// The class `name` names inside `owner`: one `owner` declares itself, or one
/// it inherits from a base type.
///
/// C# looks a simple type name up among the members of the enclosing type, and
/// a type nested in a base class is one of those members, so `new Options { .. }`
/// written inside `class Derived : Base` names `Base`'s nested `Options`
/// (#2173). A type `owner` declares itself hides the inherited one, so the base
/// walk runs only after the owner's own probe misses, and it is breadth first
/// so the nearest base answers. Ancestors are read as the hierarchy states
/// them, interfaces included, the same way the member walks here read them.
fn csharp_nested_type_declared_or_inherited<Candidates>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
    name: &str,
    type_candidates_by_fqn: &mut Candidates,
) -> Option<CodeUnit>
where
    Candidates: FnMut(&str) -> Vec<CodeUnit>,
{
    let mut nested_class = |owner: &CodeUnit| {
        type_candidates_by_fqn(&format!("{}.{}", owner.fq_name(), name))
            .into_iter()
            .find(CodeUnit::is_class)
    };
    if let Some(unit) = nested_class(owner) {
        return Some(unit);
    }
    analyzer.type_hierarchy_provider()?;
    let mut seen = HashSet::default();
    seen.insert(owner.clone());
    let mut pending: std::collections::VecDeque<CodeUnit> = definitions
        .direct_ancestors(token, owner)
        .into_iter()
        .filter(|ancestor| seen.insert(ancestor.clone()))
        .collect();
    while let Some(ancestor) = pending.pop_front() {
        if !definitions.scope_step() {
            return None;
        }
        if let Some(unit) = nested_class(&ancestor) {
            return Some(unit);
        }
        pending.extend(
            definitions
                .direct_ancestors(token, &ancestor)
                .into_iter()
                .filter(|next| seen.insert(next.clone())),
        );
    }
    None
}

fn resolve_csharp_nested_type_in_enclosing_classes_with<Candidates>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
    type_candidates_by_fqn: &mut Candidates,
) -> Option<CodeUnit>
where
    Candidates: FnMut(&str) -> Vec<CodeUnit>,
{
    if name.is_empty() {
        return None;
    }
    // A qualified spelling (`ResultDialogDemo2.FooContext`, #2232) resolves the
    // way C# reads it: the first segment is an ordinary simple name found on
    // this same enclosing-class walk, and every later segment is a nested type
    // of the type the previous segment named. The `.`-joined probe keys below
    // match the index's `$`-joined nested fq names through the provider's
    // normalized-fqn fallback, the same way the simple-name probe always has.
    let (prefix, suffix) = match name.split_once('.') {
        Some((prefix, suffix)) if !prefix.is_empty() && !suffix.is_empty() => {
            (prefix, Some(suffix))
        }
        Some(_) => return None,
        None => (name, None),
    };
    let enclosing = csharp_enclosing_class(analyzer, definitions, file, byte)?;
    let owners =
        brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(enclosing, |unit| {
            definitions
                .parent_of(analyzer, unit)
                .filter(CodeUnit::is_class)
        })
        .map_while(|owner| definitions.scope_step().then_some(owner));
    for owner in owners {
        // An enclosing type declaration is in scope under its own name, so
        // `Outer.Mark` written inside `Outer` names `Outer`'s nested `Mark`
        // (#3300). A type `owner` declares or inherits wins, because a member
        // of the enclosing type hides the enclosing type's own spelling.
        let prefix_unit = csharp_nested_type_declared_or_inherited(
            analyzer,
            token,
            definitions,
            &owner,
            prefix,
            type_candidates_by_fqn,
        )
        .or_else(|| (owner.identifier() == prefix).then(|| owner.clone()));
        let Some(prefix_unit) = prefix_unit else {
            continue;
        };
        // The first enclosing class that binds the prefix decides: C# simple-name
        // lookup stops there, so a missing nested suffix is unresolved rather
        // than an invitation to bind a further-out type of the same spelling.
        return match suffix {
            None => Some(prefix_unit),
            Some(suffix) => {
                type_candidates_by_fqn(&format!("{}.{}", prefix_unit.fq_name(), suffix))
                    .into_iter()
                    .find(CodeUnit::is_class)
            }
        };
    }
    None
}

fn csharp_import_boundary_for_type(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if csharp_alias_using_boundary_for_type(csharp, token, definitions, file, reference) {
        return true;
    }
    // `reference` is source-written C# reference text (dot-qualified, never
    // `$`-nested at the syntax level — that spelling is an internal
    // short_name storage convention, not source syntax); re-tokenizing with
    // the shared structured splitter and taking the last segment reproduces
    // `rsplit('.').next()`'s terminal split exactly.
    let simple =
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(Language::CSharp, reference)
            .pop()
            .unwrap_or_else(|| reference.to_string());
    definitions
        .using_namespaces(token, file)
        .into_iter()
        .any(|namespace| {
            !definitions.package_exists(&namespace)
                && (reference == simple || reference.starts_with(&format!("{namespace}.")))
        })
}

fn csharp_alias_using_boundary_for_type(
    _csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    definitions
        .using_aliases(token, file)
        .get(reference)
        .is_some_and(|target| !definitions.type_exists(target))
}

fn csharp_static_using_boundary_for_member(
    _csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
) -> bool {
    csharp_static_using_targets(definitions, token, file)
        .any(|target| !definitions.type_exists(&target))
}

/// True when `member` is declared by a `using static` target the workspace
/// actually indexes — e.g. `using static Workspace.MathUtils;` where `MathUtils`
/// exists and declares the member. The unindexed-static-using signal above is
/// member-blind (it trips on any unresolved static using), so this ties the
/// confident boundary to the specific member: a member a workspace static-using
/// provides is workspace-internal, never an external boundary (#1158).
fn csharp_member_declared_by_indexed_static_using(
    definitions: &CSharpDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    member: &str,
) -> bool {
    csharp_static_using_targets(definitions, token, file).any(|target| {
        definitions.type_exists(&target)
            && !definitions
                .members_for_owner_name(&target, member)
                .is_empty()
    })
}

/// The `using static <target>;` targets declared in `file`, one per static-using
/// directive (global or file-scoped). Shared by the static-using boundary
/// predicates so the member-blind and member-specific checks agree on which
/// directives count.
fn csharp_static_using_targets(
    definitions: &CSharpDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> impl Iterator<Item = String> {
    definitions
        .import_infos(token, file)
        .into_iter()
        .filter_map(|import| {
            brokk_bifrost_csharp::imports::csharp_static_using_from_import(&import)
                .map(str::to_owned)
        })
}

const CSHARP_SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn csharp_legacy_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CSharpDeclaredType> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_legacy_active_path(
        root,
        token,
        cutoff_start,
        csharp,
        definitions,
        file,
        source,
        &mut bindings,
    );
    bindings
}

#[allow(clippy::too_many_arguments)]
fn csharp_seed_legacy_active_path(
    root: Node<'_>,
    token: QueryToken<'_>,
    cutoff_start: usize,
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    let mut stack = vec![(root, 0usize)];
    while let Some((node, next_child)) = stack.pop() {
        if next_child == 0 {
            if node.start_byte() >= cutoff_start || !definitions.scope_step() {
                continue;
            }
            let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
            if enters_scope
                && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte())
            {
                continue;
            }
            if enters_scope {
                bindings.enter_scope();
            }
            if (node.kind() == "parameter" || csharp_is_local_variable_declaration(node))
                && node.end_byte() <= cutoff_start
            {
                match definitions.session() {
                    Some(session) => seed_csharp_bindings_before_in_session(
                        node,
                        cutoff_start,
                        definitions.source(),
                        token,
                        file,
                        source,
                        bindings,
                        session,
                    ),
                    None => {
                        seed_csharp_bindings_before(
                            node,
                            cutoff_start,
                            definitions.source(),
                            token,
                            file,
                            source,
                            bindings,
                        );
                    }
                }
            }
        }
        let Some(child) = node.named_child(next_child) else {
            continue;
        };
        if child.start_byte() >= cutoff_start {
            continue;
        }
        stack.push((node, next_child + 1));
        stack.push((child, 0));
    }
}

fn csharp_is_local_variable_declaration(node: Node<'_>) -> bool {
    node.kind() == "variable_declaration"
        && node
            .parent()
            .is_none_or(|parent| !csharp_is_member_variable_owner_kind(parent.kind()))
}

pub(crate) fn csharp_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if (parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(current))
            || (parent.kind() == "object_creation_expression"
                && parent.child_by_field_name("type") == Some(current))
        {
            return true;
        }
        // Only the member name dispatches a C# member-access call. The
        // receiver is also nested under this node, but it is a value/type
        // reference and resolving it as a call candidate creates a spurious
        // unresolved outgoing relation.
        if parent.kind() == "member_access_expression"
            && parent.child_by_field_name("name") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "qualified_name" && parent.child_by_field_name("name") == Some(current)
        {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_definition_dispatch<'a>(
    analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    _context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<
        'a,
        '_,
    >,
    request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
    source: &std::sync::Arc<str>,
    tree: &Option<tree_sitter::Tree>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
    _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    _go_session: Option<
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    >,
) -> std::ops::ControlFlow<
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
> {
    let mut evidence = CallEvidence::default();
    let outcome = resolve_analyzer::<CSharpAnalyzer>(analyzer).map_or_else(
        || no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable"),
        |csharp_analyzer| {
            let definitions = CSharpDefinitionProvider::new(csharp_analyzer, &request.file);
            let resolution = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &request.file,
                source,
                tree.as_ref(),
                site,
                operation.is_some(),
            );
            evidence = resolution.evidence;
            resolution.outcome
        },
    );
    std::ops::ControlFlow::Continue(DefinitionResolution { outcome, evidence })
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};

    use crate::analyzer::usages::get_definition::csharp::*;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_analysis::analyzer::usages::test_support::assert_scope_budget_exceeded;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::WorkspaceAnalyzer;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;
    use brokk_bifrost_test_macros::hardwon;
    use std::fmt::Write as _;

    /// Some analyzed file, as the reference of a provider whose test needs
    /// no particular one: these fixtures are one implicit compilation.
    fn any_reference(analyzer: &dyn IAnalyzer) -> ProjectFile {
        analyzer
            .get_analyzed_files()
            .into_iter()
            .next()
            .expect("an analyzed file")
    }

    #[test]
    #[hardwon("#5198: a later block-scoped namespace rebound earlier global bindings")]
    fn reference_context_preserves_namespace_and_import_boundaries() {
        const LIBRARY: &str = r#"
namespace System { public class Attribute {} }
namespace Tools {
    public class MarkerAttribute : System.Attribute {}
    public class Service { public void Work() {} }
}
namespace Other {
    public class MarkerAttribute : System.Attribute {}
    public class Service { public void Work() {} }
}
"#;
        let cases = [
            (
                r#"
using Tools;
using Mark = Tools.MarkerAttribute;
[Mark] class Service {
    public void Work() {}
    void Call(Service obj) { obj.Work(); }
}
namespace Custom {
    using Other;
    using Mark = Other.MarkerAttribute;
    class Service { public void Work() {} }
}
"#,
                "Service.Work",
                "Tools.MarkerAttribute",
            ),
            (
                r#"
namespace Left {
    using Tools;
    using Mark = Tools.MarkerAttribute;
    [Mark] class Consumer { void Call(Service obj) { obj.Work(); } }
}
namespace Right {
    using Other;
    using Mark = Other.MarkerAttribute;
    class Consumer { void Call(Service obj) { obj.Work(); } }
}
"#,
                "Tools.Service.Work",
                "Tools.MarkerAttribute",
            ),
            (
                r#"
namespace Outer {
    using Other;
    namespace Inner {
        using Tools;
        using Mark = Tools.MarkerAttribute;
        [Mark] class Consumer { void Call(Service obj) { obj.Work(); } }
    }
}
"#,
                "Tools.Service.Work",
                "Tools.MarkerAttribute",
            ),
            (
                r#"
using Tools;
namespace FileScoped;
using Mark = Tools.MarkerAttribute;
[Mark] class Consumer { void Call(Service obj) { obj.Work(); } }
"#,
                "Tools.Service.Work",
                "Tools.MarkerAttribute",
            ),
        ];
        for (source, method_target, attribute_target) in cases {
            let fixture = AnalyzerFixture::new_for_language(
                Language::CSharp,
                // One explicit compilation holds both files, so the global
                // namespace's precedence applies within it.
                &[
                    ("App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                    ("References.cs", source),
                    ("Library.cs", LIBRARY),
                ],
            );
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
            let file = ProjectFile::new(fixture.project_root(), "References.cs");
            let tree = parse_csharp_tree(source).expect("C# reference tree");
            let scope = AnalyzerQueryScope::new(analyzer);
            let token = scope.token();
            for (fragment, prefix, name, expected) in [
                ("obj.Work();", "obj.", "Work", method_target),
                ("[Mark]", "[", "Mark", attribute_target),
            ] {
                let start_byte = source.find(fragment).expect("reference fixture") + prefix.len();
                let end_byte = start_byte + name.len();
                let line = source[..start_byte]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count();
                let site = ResolvedReferenceSite {
                    path: rel_path_string(&file),
                    text: name.to_owned(),
                    range: Range {
                        start_byte,
                        end_byte,
                        start_line: line,
                        end_line: line,
                    },
                    focus_start_byte: start_byte,
                    focus_end_byte: end_byte,
                };
                let definitions = CSharpDefinitionProvider::new(csharp, &file);
                let unbounded = resolve_csharp(
                    analyzer,
                    token,
                    &definitions,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    false,
                )
                .outcome;
                let bounded = resolve_csharp_bounded(
                    analyzer,
                    token,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    ReceiverAnalysisBudget::default(),
                    None,
                );
                let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                    panic!("reference lookup must complete: {bounded:#?}");
                };
                for outcome in [unbounded, bounded] {
                    assert_eq!(
                        outcome.status,
                        DefinitionLookupStatus::Resolved,
                        "{source}\n{outcome:#?}"
                    );
                    assert_eq!(
                        outcome
                            .definitions
                            .iter()
                            .map(CodeUnit::fq_name)
                            .collect::<Vec<_>>(),
                        vec![expected.to_owned()],
                        "{source}\n{outcome:#?}",
                    );
                }
            }
            let target = analyzer
                .get_definitions(method_target)
                .into_iter()
                .find(CodeUnit::is_function)
                .expect("exact method declaration");
            let roots = HashSet::from_iter([file.clone()]);
            let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
                analyzer, token, &roots,
            )
            .expect("C# authoritative usage batch");
            let result = batch
                .find_usages(std::slice::from_ref(&target), &roots, 100)
                .into_fuzzy_result();
            let FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                ..
            } = result
            else {
                panic!("inverse reference lookup must complete: {result:#?}");
            };
            let start = source.find("obj.Work();").expect("method reference") + "obj.".len();
            let actual = hits_by_overload
                .get(&target)
                .into_iter()
                .flatten()
                .map(|hit| {
                    (
                        hit.file.rel_path().to_string_lossy().into_owned(),
                        hit.start_offset,
                        hit.end_offset,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                vec![("References.cs".to_owned(), start, start + 4)],
                "{source}"
            );
            assert!(
                unproven_by_overload.values().all(|hits| hits.is_empty()),
                "exact receiver identity must be proven: {source}\n{unproven_by_overload:#?}",
            );
        }
    }

    #[test]
    #[hardwon(
        "#6296: a global-namespace type in an unreferenced project shadowed an imported receiver type"
    )]
    fn global_namespace_precedence_follows_compilation_membership() {
        const REFERENCES: &str = r#"
using Tools;
class Consumer {
    void UseService(Service service) { service.Work(); }
    void UseHelper(Helper helper) { helper.Run(); }
    void UseWidget(Widget widget) { widget.Spin(); }
    void UseGadget(Gadget gadget) { gadget.Go(); }
    void UseLonely(Lonely lonely) { lonely.Hum(); }
    void UseTwin(Twin twin) { twin.Beat(); }
}
"#;
        let sdk = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[
                (
                    "App/App.csproj",
                    r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../Tools/Tools.csproj" /><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup></Project>"#,
                ),
                ("App/References.cs", REFERENCES),
                // Same compilation, another file: precedes the import.
                (
                    "App/Shadow.cs",
                    "public class Service { public void Work() {} }",
                ),
                ("Tools/Tools.csproj", sdk),
                (
                    "Tools/Tools.cs",
                    r#"
namespace Tools {
    public class Service { public void Work() {} }
    public class Helper { public void Run() {} }
    public class Widget { public void Spin() {} }
    public class Gadget { public void Go() {} }
}
"#,
                ),
                // A referenced project's global namespace precedes the import.
                ("Lib/Lib.csproj", sdk),
                (
                    "Lib/Helper.cs",
                    "public class Helper { public void Run() {} }",
                ),
                // An unreferenced project's global namespace is not visible.
                ("Tests/Tests.csproj", sdk),
                (
                    "Tests/Widget.cs",
                    "public class Widget { public void Spin() {} }",
                ),
                // No project claims these sources: their membership is
                // unproven. `Lonely` has no competitor at all; `Twin` has a
                // proven same-name twin in the reference's compilation.
                (
                    "Loose/Gadget.cs",
                    "public class Gadget { public void Go() {} }",
                ),
                (
                    "Loose/Lonely.cs",
                    "public class Lonely { public void Hum() {} }",
                ),
                ("App/Twin.cs", "public class Twin { public void Beat() {} }"),
                (
                    "Loose/Twin.cs",
                    "public class Twin { public void Beat() {} }",
                ),
            ],
        );
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let file = ProjectFile::new(fixture.project_root(), "App/References.cs");
        let source = REFERENCES;
        let tree = parse_csharp_tree(source).expect("C# reference tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes_at = |fragment: &str, name: &str| {
            let start_byte = source.find(fragment).expect("reference fixture") + fragment.len()
                - name.len()
                - "();".len();
            let end_byte = start_byte + name.len();
            assert_eq!(&source[start_byte..end_byte], name);
            let line = source[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: name.to_owned(),
                range: Range {
                    start_byte,
                    end_byte,
                    start_line: line,
                    end_line: line,
                },
                focus_start_byte: start_byte,
                focus_end_byte: end_byte,
            };
            let definitions = CSharpDefinitionProvider::new(csharp, &file);
            let unbounded = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &file,
                source,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let bounded = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                panic!("reference lookup must complete: {bounded:#?}");
            };
            [unbounded, bounded]
        };
        for (fragment, name, expected) in [
            ("service.Work();", "Work", "Service.Work"),
            ("helper.Run();", "Run", "Helper.Run"),
            ("widget.Spin();", "Spin", "Tools.Widget.Spin"),
        ] {
            for outcome in outcomes_at(fragment, name) {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{fragment}\n{outcome:#?}"
                );
                assert_eq!(
                    outcome
                        .definitions
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<Vec<_>>(),
                    vec![expected.to_owned()],
                    "{fragment}\n{outcome:#?}",
                );
            }
        }
        for outcome in outcomes_at("gadget.Go();", "Go") {
            assert!(
                outcome.status != DefinitionLookupStatus::Resolved
                    || outcome.definitions.len() != 1,
                "unproven membership must not resolve to one declaration: {outcome:#?}"
            );
        }

        // The proven twin names the type, so the name is resolved. Members
        // are found by the type's fully qualified name, so the unproven
        // twin's same-name member is the same identity (as duplicate
        // physical declarations are everywhere else).
        for outcome in outcomes_at("twin.Beat();", "Beat") {
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outcome:#?}"
            );
            let mut names = outcome
                .definitions
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>();
            names.dedup();
            assert_eq!(names, vec!["Twin.Beat".to_owned()], "{outcome:#?}");
        }
        for outcome in outcomes_at("lonely.Hum();", "Hum") {
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Incomplete,
                "a lone candidate of unproven membership is doubt, not a resolution: {outcome:#?}"
            );
            assert_eq!(
                outcome
                    .definitions
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<Vec<_>>(),
                vec!["Lonely.Hum".to_owned()],
                "Incomplete still carries what it found: {outcome:#?}"
            );
            assert!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.kind == "csharp_compilation_membership_unproven"),
                "{outcome:#?}"
            );
        }

        let roots = HashSet::from_iter([file.clone()]);
        let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
            analyzer, token, &roots,
        )
        .expect("C# authoritative usage batch");
        let method = |fq_name: &str| {
            analyzer
                .get_definitions(fq_name)
                .into_iter()
                .find(CodeUnit::is_function)
                .unwrap_or_else(|| panic!("exact method declaration {fq_name}"))
        };
        let usages = |target: &CodeUnit| {
            batch
                .find_usages(std::slice::from_ref(target), &roots, 100)
                .into_fuzzy_result()
        };
        for (fq_name, hits) in [
            ("Service.Work", 1),
            ("Tools.Service.Work", 0),
            ("Helper.Run", 1),
            ("Tools.Helper.Run", 0),
            ("Widget.Spin", 0),
            ("Tools.Widget.Spin", 1),
        ] {
            let target = method(fq_name);
            let result = usages(&target);
            let FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                ..
            } = &result
            else {
                panic!("{fq_name}: proven membership must complete: {result:#?}");
            };
            assert_eq!(
                hits_by_overload.get(&target).map_or(0, |hits| hits.len()),
                hits,
                "{fq_name}: {result:#?}"
            );
            assert!(
                unproven_by_overload.values().all(|hits| hits.is_empty()),
                "{fq_name}: {result:#?}"
            );
        }
        // The proven twin's member has its one proven use.
        let twin = analyzer
            .get_definitions("Twin.Beat")
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && unit.source().rel_path() == std::path::Path::new("App/Twin.cs")
            })
            .expect("proven twin method");
        let result = usages(&twin);
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = &result
        else {
            panic!("the proven twin's usages complete: {result:#?}");
        };
        assert_eq!(
            hits_by_overload.get(&twin).map_or(0, |hits| hits.len()),
            1,
            "{result:#?}"
        );
        for fq_name in ["Gadget.Go", "Tools.Gadget.Go", "Lonely.Hum"] {
            let target = method(fq_name);
            let result = usages(&target);
            let proven_empty = matches!(
                &result,
                FuzzyResult::Success { hits_by_overload, unproven_by_overload, .. }
                    if hits_by_overload.values().all(|hits| hits.is_empty())
                        && unproven_by_overload.values().all(|hits| hits.is_empty())
            );
            assert!(
                !proven_empty,
                "{fq_name}: an unproven membership must not prove the gadget call absent: {result:#?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#6296: a member found only on an unproven or invisible physical twin resolved through the proven twin's name"
    )]
    fn members_of_an_unproven_physical_twin_are_not_proven_by_the_named_type() {
        const USE: &str = r#"
class Consumer {
    void Use(Twin twin) { twin.OnlyOutside(); }
    void Known(Twin twin) { twin.Known(); }
}
"#;
        let sdk = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        for (outside_path, extra) in [
            // Outside every project: membership unproven.
            ("Loose/Twin.cs", None),
            // In an SDK project App does not reference: provably invisible.
            ("Other/Twin.cs", Some(("Other/Other.csproj", sdk))),
        ] {
            let mut files = vec![
                ("App/App.csproj", sdk),
                ("App/Use.cs", USE),
                (
                    "App/Twin.cs",
                    "public class Twin { public void Known() {} }",
                ),
                (
                    outside_path,
                    "public class Twin { public void OnlyOutside() {} }",
                ),
            ];
            files.extend(extra);
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
            let file = ProjectFile::new(fixture.project_root(), "App/Use.cs");
            let tree = parse_csharp_tree(USE).expect("C# reference tree");
            let scope = AnalyzerQueryScope::new(analyzer);
            let token = scope.token();
            let outcomes_at = |fragment: &str, name: &str| {
                let start_byte = USE.find(fragment).expect("reference fixture") + fragment.len()
                    - name.len()
                    - "();".len();
                let end_byte = start_byte + name.len();
                let line = USE[..start_byte]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count();
                let site = ResolvedReferenceSite {
                    path: rel_path_string(&file),
                    text: name.to_owned(),
                    range: Range {
                        start_byte,
                        end_byte,
                        start_line: line,
                        end_line: line,
                    },
                    focus_start_byte: start_byte,
                    focus_end_byte: end_byte,
                };
                let definitions = CSharpDefinitionProvider::new(csharp, &file);
                let unbounded = resolve_csharp(
                    analyzer,
                    token,
                    &definitions,
                    &file,
                    USE,
                    Some(&tree),
                    &site,
                    false,
                )
                .outcome;
                let bounded = resolve_csharp_bounded(
                    analyzer,
                    token,
                    &file,
                    USE,
                    Some(&tree),
                    &site,
                    ReceiverAnalysisBudget::default(),
                    None,
                );
                let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                    panic!("reference lookup must complete: {bounded:#?}");
                };
                [unbounded, bounded]
            };
            for outcome in outcomes_at("twin.Known();", "Known") {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{outside_path}: {outcome:#?}"
                );
            }
            for outcome in outcomes_at("twin.OnlyOutside();", "OnlyOutside") {
                // An unproven copy leaves doubt; a provably invisible copy is
                // simply not part of the compilation, so no definition exists.
                assert_eq!(
                    outcome.status,
                    if extra.is_some() {
                        DefinitionLookupStatus::NoDefinition
                    } else {
                        DefinitionLookupStatus::Incomplete
                    },
                    "{outside_path}: a member only the excluded twin declares is not a proven definition: {outcome:#?}"
                );
                let paths = outcome
                    .definitions
                    .iter()
                    .map(|unit| rel_path_string(unit.source()))
                    .collect::<Vec<_>>();
                if extra.is_some() {
                    assert!(
                        paths.is_empty(),
                        "{outside_path}: a provably invisible declaration is no definition: {outcome:#?}"
                    );
                } else {
                    assert_eq!(
                        paths,
                        vec![outside_path.to_owned()],
                        "{outside_path}: Incomplete still carries the unproven declaration: {outcome:#?}"
                    );
                }
            }

            let roots = HashSet::from_iter([file.clone()]);
            let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
                analyzer, token, &roots,
            )
            .expect("C# authoritative usage batch");
            let target = analyzer
                .get_definitions("Twin.OnlyOutside")
                .into_iter()
                .find(CodeUnit::is_function)
                .expect("outside twin method");
            let result = batch
                .find_usages(std::slice::from_ref(&target), &roots, 100)
                .into_fuzzy_result();
            let FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                ..
            } = &result
            else {
                panic!("{outside_path}: usages complete: {result:#?}");
            };
            assert!(
                hits_by_overload.values().all(|hits| hits.is_empty()),
                "{outside_path}: a call on the proven Twin cannot prove a use of the excluded twin's member: {result:#?}"
            );
            assert_eq!(
                unproven_by_overload.values().any(|hits| !hits.is_empty()),
                extra.is_none(),
                "{outside_path}: an unproven copy's member use stays unproven; an invisible copy's is none: {result:#?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#6296: an inherited member reached through a receiver of unproven membership resolved as proven"
    )]
    fn inherited_members_through_an_unproven_receiver_stay_unproven() {
        const RUN: &str = r#"
class Runner {
    void Run(Lonely x) { x.Hum(); }
    void Qualified(global::Lonely y) { y.Hum(); }
    void Proven(Base z) { z.Hum(); }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Run.cs", RUN),
                ("App/Base.cs", "public class Base { public void Hum() {} }"),
                // No project claims this source.
                ("Loose/Lonely.cs", "public class Lonely : Base {}"),
            ],
        );
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let file = ProjectFile::new(fixture.project_root(), "App/Run.cs");
        let tree = parse_csharp_tree(RUN).expect("C# reference tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes_at = |fragment: &str| {
            let start_byte = RUN.find(fragment).expect("reference fixture") + 2;
            let end_byte = start_byte + "Hum".len();
            assert_eq!(&RUN[start_byte..end_byte], "Hum");
            let line = RUN[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: "Hum".to_owned(),
                range: Range {
                    start_byte,
                    end_byte,
                    start_line: line,
                    end_line: line,
                },
                focus_start_byte: start_byte,
                focus_end_byte: end_byte,
            };
            let definitions = CSharpDefinitionProvider::new(csharp, &file);
            let unbounded = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &file,
                RUN,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let bounded = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                RUN,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                panic!("reference lookup must complete: {bounded:#?}");
            };
            [unbounded, bounded]
        };
        for outcome in outcomes_at("z.Hum();") {
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outcome:#?}"
            );
        }
        for fragment in ["x.Hum();", "y.Hum();"] {
            for outcome in outcomes_at(fragment) {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Incomplete,
                    "{fragment}: the receiver's membership is unproven: {outcome:#?}"
                );
                assert_eq!(
                    outcome
                        .definitions
                        .iter()
                        .map(CodeUnit::fq_name)
                        .collect::<Vec<_>>(),
                    vec!["Base.Hum".to_owned()],
                    "{fragment}: {outcome:#?}"
                );
            }
        }

        let roots = HashSet::from_iter([file.clone()]);
        let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
            analyzer, token, &roots,
        )
        .expect("C# authoritative usage batch");
        let target = analyzer
            .get_definitions("Base.Hum")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("Base.Hum");
        let result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } = &result
        else {
            panic!("usages complete: {result:#?}");
        };
        let lines = |hits: &std::collections::BTreeSet<
            brokk_bifrost_core::analyzer::usages::model::UsageHit,
        >| {
            hits.iter()
                .map(|hit| {
                    RUN[..hit.start_offset]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hits_by_overload.get(&target).map(lines).unwrap_or_default(),
            vec![4],
            "only the Base-typed receiver is a proven use: {result:#?}"
        );
        assert_eq!(
            unproven_by_overload
                .get(&target)
                .map(lines)
                .unwrap_or_default(),
            vec![2, 3],
            "receivers of unproven membership are unproven uses: {result:#?}"
        );
    }

    /// The definition outcome at `fragment`'s `name` in `use_path`, and the
    /// proven and unproven usage hit counts of the method `target_fqn`
    /// declared in `target_path`, both from one fixture.
    fn membership_outcome(
        files: &[(&str, &str)],
        use_path: &str,
        source: &str,
        fragment: &str,
        name: &str,
        target_fqn: &str,
        target_path: &str,
    ) -> (DefinitionLookupOutcome, usize, usize) {
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, files);
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let file = ProjectFile::new(fixture.project_root(), use_path);
        let tree = parse_csharp_tree(source).expect("C# reference tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let start_byte = source.find(fragment).expect("reference fixture")
            + fragment.find(name).expect("name in fragment");
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: name.to_owned(),
            range: Range {
                start_byte,
                end_byte: start_byte + name.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + name.len(),
        };
        let definitions = CSharpDefinitionProvider::new(csharp, &file);
        let outcome = resolve_csharp(
            analyzer,
            token,
            &definitions,
            &file,
            source,
            Some(&tree),
            &site,
            false,
        )
        .outcome;
        let bounded = resolve_csharp_bounded(
            analyzer,
            token,
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value: bounded, .. } = bounded else {
            panic!("reference lookup must complete: {bounded:#?}");
        };
        assert_eq!(outcome.status, bounded.status, "{outcome:#?}\n{bounded:#?}");
        let roots = HashSet::from_iter([file.clone()]);
        let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
            analyzer, token, &roots,
        )
        .expect("C# authoritative usage batch");
        let target = analyzer
            .get_definitions(target_fqn)
            .into_iter()
            .find(|unit| {
                unit.is_function() && unit.source().rel_path() == std::path::Path::new(target_path)
            })
            .unwrap_or_else(|| panic!("target {target_fqn} in {target_path}"));
        let result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } = &result
        else {
            panic!("usages complete: {result:#?}");
        };
        let count = |hits: &HashMap<CodeUnit, std::collections::BTreeSet<_>>| {
            hits.values().map(|hits| hits.len()).sum::<usize>()
        };
        (
            outcome,
            count(hits_by_overload),
            count(unproven_by_overload),
        )
    }

    #[test]
    #[hardwon(
        "#6296: a static receiver of unproven or invisible membership resolved an inherited member"
    )]
    fn static_receivers_through_an_outside_type_are_not_proven() {
        let sdk = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        let source = "class Use {\n void A() { global::Lonely.Hum(); }\n void B() { Lonely.Hum(); }\n void C() { Base.Hum(); }\n}\n";
        for (outside, extra) in [
            ("Loose", None),
            ("Other", Some(("Other/Other.csproj", sdk))),
        ] {
            let lonely = format!("{outside}/Lonely.cs");
            let mut files = vec![
                ("App/App.csproj", sdk),
                (
                    "App/Base.cs",
                    "public class Base { public static void Hum() {} }",
                ),
                (lonely.as_str(), "public class Lonely : Base {}"),
                ("App/Use.cs", source),
            ];
            files.extend(extra);
            for fragment in ["global::Lonely.Hum()", "{ Lonely.Hum()"] {
                let (outcome, proven, _) = membership_outcome(
                    &files,
                    "App/Use.cs",
                    source,
                    fragment,
                    "Hum",
                    "Base.Hum",
                    "App/Base.cs",
                );
                assert_ne!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{outside} {fragment}: {outcome:#?}"
                );
                if extra.is_none() {
                    assert_eq!(
                        outcome.status,
                        DefinitionLookupStatus::Incomplete,
                        "{outside} {fragment}: {outcome:#?}"
                    );
                }
                assert_eq!(proven, 1, "{outside}: only `Base.Hum()` is a proven use");
            }
            let (outcome, _, _) = membership_outcome(
                &files,
                "App/Use.cs",
                source,
                "{ Base.Hum()",
                "Hum",
                "Base.Hum",
                "App/Base.cs",
            );
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outcome:#?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#6296: a base list on an unproven or invisible physical twin gave the proven type an inherited member"
    )]
    fn an_outside_physical_twin_contributes_no_proven_base() {
        let sdk = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        let source = "class Use { void Run(Twin x) { x.Hum(); } }\n";
        for (outside, extra) in [
            ("Loose", None),
            ("Other", Some(("Other/Other.csproj", sdk))),
        ] {
            let twin = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", sdk),
                ("App/Twin.cs", "public class Twin {}"),
                ("App/Base.cs", "public class Base { public void Hum() {} }"),
                (twin.as_str(), "public class Twin : Base {}"),
                ("App/Use.cs", source),
            ];
            files.extend(extra);
            let (outcome, proven, unproven) = membership_outcome(
                &files,
                "App/Use.cs",
                source,
                "x.Hum()",
                "Hum",
                "Base.Hum",
                "App/Base.cs",
            );
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outside}: {outcome:#?}"
            );
            assert_eq!(
                proven, 0,
                "{outside}: the base is not proven for App's Twin"
            );
            if extra.is_none() {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Incomplete,
                    "{outcome:#?}"
                );
                assert_eq!(
                    unproven, 1,
                    "an unproven twin's base leaves an unproven use"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#6296: an inverted edge to an overload only an outside copy declares was proven by a visible same-name overload"
    )]
    fn inverted_edges_keep_the_selected_overloads_membership() {
        let sdk = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        let source =
            "class Use { void Run(Twin x) { x.Work(1); } void Plain(Twin y) { y.Work(); } }\n";
        let mut baseline = None;
        for (outside, extra) in [
            ("Absent", Some(("Absent/Absent.csproj", sdk))),
            ("Loose", None),
            ("Other", Some(("Other/Other.csproj", sdk))),
        ] {
            let twin = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", sdk),
                ("App/Twin.cs", "public class Twin { public void Work() {} }"),
                (
                    twin.as_str(),
                    "public class Twin { public void Work(int n) {} }",
                ),
                ("App/Use.cs", source),
            ];
            files.extend(extra);
            if outside == "Absent" {
                files.retain(|(path, _)| !path.starts_with("Absent/Twin"));
            }
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let scope = AnalyzerQueryScope::new(analyzer);
            let edges = match crate::analyzer::usages::csharp_graph::build_inbound_csharp_usage_edges_with_completeness(
                analyzer,
                scope.token(),
                &HashSet::from_iter(["Twin.Work".to_owned()]),
            )
            .expect("C# edges")
            {
                brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult::Complete(edges) => edges,
                other => {
                    let brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult::Uncacheable {
                        output,
                        omitted_files,
                    } = other
                    else {
                        unreachable!()
                    };
                    assert!(omitted_files.is_empty(), "{omitted_files:?}");
                    output
                }
            };
            let sites = edges
                .edges
                .iter()
                .filter(|((_, callee), _)| callee == "Twin.Work")
                .map(|((caller, _), sites)| (caller.clone(), sites.len()))
                .collect::<Vec<_>>();
            // `Run` calls the overload only the outside copy declares. With an
            // unproven copy, every `Twin.Work` lookup admits that overload as
            // doubt, so neither call is a proven edge (a conservative answer
            // for `Plain`). With an invisible copy the edges are exactly those
            // of a workspace without the copy ("Absent"): membership adds no
            // claim. That baseline also records `Run`, because the inverted
            // graph keeps a name-only edge when no overload is applicable,
            // which predates compilation membership.
            let unproven = edges
                .unproven_inbound
                .get("Twin.Work")
                .copied()
                .unwrap_or(0);
            match outside {
                "Absent" => baseline = Some(sites),
                "Other" => assert_eq!(
                    Some(sites),
                    baseline.clone(),
                    "an invisible copy changes no edge"
                ),
                _ => {
                    assert!(
                        sites.is_empty(),
                        "{outside}: no call is a proven edge: {sites:?}"
                    );
                    assert_eq!(
                        unproven, 2,
                        "both calls are unproven inbound: {:?}",
                        edges.unproven_inbound
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon("#6296: local inference must carry unproven factory membership")]
    fn inferred_locals_keep_the_membership_doubt_of_their_initializer() {
        // The second source names the doubted local like a visible type: a
        // shadowed local is still the receiver, not that type.
        for source in [
            "class Use { void Run(Twin t) { var x = t.Make(); x.Hum(); } }",
            "class Use { void Run(Twin t) { var Target = t.Make(); Target.Hum(); } }",
        ] {
            let edges = inbound_edges(
                &[
                    ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                    ("App/Twin.cs", "public partial class Twin {}"),
                    (
                        "Loose/Twin.cs",
                        "public partial class Twin { public Target Make() { return null; } }",
                    ),
                    (
                        "App/Target.cs",
                        "public class Target { public void Hum() {} }",
                    ),
                    ("App/Use.cs", source),
                ],
                "Target.Hum",
            );
            assert!(
                edges
                    .edges
                    .iter()
                    .all(|((_, callee), _)| callee != "Target.Hum"),
                "{source}: unproven factory cannot prove an edge: {:?}, unproven={:?}",
                edges.edges,
                edges.unproven_inbound
            );
        }
    }

    /// The inbound C# usage edges of `callee` over `files`.
    fn inbound_edges(
        files: &[(&str, &str)],
        callee: &str,
    ) -> brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges {
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, files);
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let result = crate::analyzer::usages::csharp_graph::build_inbound_csharp_usage_edges_with_completeness(
            analyzer, scope.token(), &HashSet::from_iter([callee.to_owned()]),
        ).expect("C# edges");
        match result {
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult::Complete(edges) => edges,
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult::Uncacheable { output, .. } => output,
        }
    }

    #[test]
    #[hardwon(
        "#6296: an unproven partial part's unrelated nested class made a visible nested type's uses unproven"
    )]
    fn an_unproven_parts_unrelated_nested_class_leaves_a_visible_nested_type_proven() {
        let source = "public partial class Outer { public class Inner { public void Hum() {} } void Run() { new Inner().Hum(); } }";
        // Forward usage hits only: this definition lookup answers
        // NoDefinition with or without the unproven part.
        let (_, proven, unproven) = membership_outcome(
            &[
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Outer.cs", source),
                (
                    "Loose/Outer.Part.cs",
                    "public partial class Outer { public class Other {} }",
                ),
            ],
            "App/Outer.cs",
            source,
            "new Inner().Hum()",
            "Hum",
            "Outer$Inner.Hum",
            "App/Outer.cs",
        );
        assert_eq!((proven, unproven), (1, 0));
    }

    #[test]
    #[hardwon("#6296: extension receiver construction must carry membership doubt")]
    fn an_unproven_constructed_receiver_cannot_prove_an_extension() {
        let source = "class Use { void Run() { new Lonely().Hum(); } }";
        let files = [
            ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
            ("Loose/Lonely.cs", "public class Lonely {}"),
            (
                "App/Extensions.cs",
                "public static class Extensions { public static void Hum<T>(this T value) {} }",
            ),
            ("App/Use.cs", source),
        ];
        let (outcome, _, _) = membership_outcome(
            &files,
            "App/Use.cs",
            source,
            "new Lonely().Hum()",
            "Hum",
            "Extensions.Hum",
            "App/Extensions.cs",
        );
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "unproven constructed receiver cannot resolve uniquely: {outcome:#?}"
        );
    }

    fn review_chained_receiver_case(outside: &str, extra: Option<(&str, &str)>) {
        let source = "class Use { void Run(Twin t) { t.Make().Hum(); } }";
        let twin = format!("{outside}/Twin.cs");
        let mut files = vec![
            ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
            ("App/Twin.cs", "public partial class Twin {}"),
            (twin.as_str(), "public partial class Twin : Base {}"),
            (
                "App/Base.cs",
                "public class Base { public Target Make() { return null; } }",
            ),
            (
                "App/Target.cs",
                "public class Target { public void Hum() {} }",
            ),
            ("App/Use.cs", source),
        ];
        files.extend(extra);
        let (outcome, _, _) = membership_outcome(
            &files,
            "App/Use.cs",
            source,
            "t.Make().Hum()",
            "Hum",
            "Target.Hum",
            "App/Target.cs",
        );
        assert_ne!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "outside base cannot prove a chained receiver: {outcome:#?}"
        );
    }

    #[test]
    #[hardwon("#6296: chained return-type inference must filter unproven physical bases")]
    fn review_chained_receiver_through_unproven_base() {
        review_chained_receiver_case("Loose", None);
    }

    #[test]
    #[hardwon("#6296: chained return-type inference must filter invisible physical bases")]
    fn review_chained_receiver_through_invisible_base() {
        review_chained_receiver_case(
            "Other",
            Some((
                "Other/Other.csproj",
                r#"<Project Sdk="Microsoft.NET.Sdk" />"#,
            )),
        );
    }

    #[test]
    fn a_visible_parts_base_list_still_types_a_chained_receiver() {
        // The visible part writes the base; the outside part adds nothing.
        for (outside, extra) in [
            ("Loose", None),
            (
                "Other",
                Some((
                    "Other/Other.csproj",
                    r#"<Project Sdk="Microsoft.NET.Sdk" />"#,
                )),
            ),
        ] {
            let source = "class Use { void Run(Twin t) { t.Make().Hum(); } }";
            let twin = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Twin.cs", "public partial class Twin : Base {}"),
                (twin.as_str(), "public partial class Twin {}"),
                (
                    "App/Base.cs",
                    "public class Base { public Target Make() { return null; } }",
                ),
                (
                    "App/Target.cs",
                    "public class Target { public void Hum() {} }",
                ),
                ("App/Use.cs", source),
            ];
            files.extend(extra);
            let (outcome, proven, unproven) = membership_outcome(
                &files,
                "App/Use.cs",
                source,
                "t.Make().Hum()",
                "Hum",
                "Target.Hum",
                "App/Target.cs",
            );
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outside}: {outcome:#?}"
            );
            assert_eq!((proven, unproven), (1, 0), "{outside}");
        }
    }

    #[test]
    #[hardwon("#6296: the membership view's hierarchy merged every physical part's base list")]
    fn the_membership_view_derives_hierarchy_from_each_parts_membership() {
        use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
        for (outside, extra, expected_descendants, expected_doubt) in [
            ("Loose", None, 1, true),
            (
                "Other",
                Some((
                    "Other/Other.csproj",
                    r#"<Project Sdk="Microsoft.NET.Sdk" />"#,
                )),
                0,
                false,
            ),
        ] {
            let twin = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Twin.cs", "public partial class Twin {}"),
                (twin.as_str(), "public partial class Twin : Base {}"),
                ("App/Base.cs", "public class Base {}"),
                ("App/Use.cs", "class Use {}"),
            ];
            files.extend(extra);
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
            let reference = ProjectFile::new(fixture.project_root(), "App/Use.cs");
            let view = brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource::new(
                csharp, &reference,
            );
            let base = analyzer
                .get_definitions("Base")
                .into_iter()
                .find(CodeUnit::is_class)
                .expect("Base");
            let twin = analyzer
                .get_definitions("Twin")
                .into_iter()
                .find(|unit| unit.source().rel_path() == std::path::Path::new("App/Twin.cs"))
                .expect("visible Twin part");
            let ancestors = view.get_direct_ancestors(&twin);
            let descendants = view.get_direct_descendants(&base);
            assert_eq!(
                ancestors.iter().any(|unit| unit.fq_name() == "Base"),
                expected_doubt,
                "{outside}: {ancestors:?}"
            );
            let descendant_types = descendants
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                descendant_types.len(),
                expected_descendants,
                "{outside}: {descendants:?}"
            );
            assert_eq!(view.doubt() > 0, expected_doubt, "{outside}");
        }
    }

    #[test]
    #[hardwon("#6296: generic nested alias and cast receiver identities carry doubt")]
    fn review_receiver_forms_keep_membership_doubt() {
        for source in [
            "class Use { void Run() { new Lonely<int>().Hum(); } }",
            "using Alias = Lonely; class Use { void Run() { new Alias().Hum(); } }",
            "class Use { void Run() { ((Lonely)null).Hum(); } }",
            "class Use { void Run() { new Outer.Inner().Hum(); } }",
        ] {
            let files = [
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                (
                    "Loose/Lonely.cs",
                    "public class Lonely {} public class Lonely<T> {} public class Outer { public class Inner {} }",
                ),
                (
                    "App/Extensions.cs",
                    "public static class Extensions { public static void Hum<T>(this T value) {} }",
                ),
                ("App/Use.cs", source),
            ];
            let (outcome, proven, _) = membership_outcome(
                &files,
                "App/Use.cs",
                source,
                ".Hum()",
                "Hum",
                "Extensions.Hum",
                "App/Extensions.cs",
            );
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{source}: {outcome:#?}"
            );
            assert_eq!(proven, 0, "{source}");
        }
    }

    fn review_warm_membership_outcome(
        files: &[(&str, &str)],
        use_path: &str,
        source: &str,
        fragment: &str,
        name: &str,
        target_fqn: &str,
        target_path: &str,
    ) -> (DefinitionLookupOutcome, usize, usize) {
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, files);
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let file = ProjectFile::new(fixture.project_root(), use_path);
        let tree = parse_csharp_tree(source).expect("C# reference tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let start_byte = source.find(fragment).expect("reference fixture")
            + fragment.find(name).expect("name in fragment");
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: name.to_owned(),
            range: Range {
                start_byte,
                end_byte: start_byte + name.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + name.len(),
        };
        let definitions = CSharpDefinitionProvider::new(csharp, &file);
        let outcome = resolve_csharp(
            analyzer,
            token,
            &definitions,
            &file,
            source,
            Some(&tree),
            &site,
            false,
        )
        .outcome;
        let bounded = resolve_csharp_bounded(
            analyzer,
            token,
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value: bounded, .. } = bounded else {
            panic!("reference lookup must complete: {bounded:#?}");
        };
        assert_eq!(outcome.status, bounded.status, "{outcome:#?}\n{bounded:#?}");
        use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
        // Prime the unscoped memo after the cold query, then start fresh requests.
        for unit in analyzer
            .get_all_declarations()
            .into_iter()
            .filter(CodeUnit::is_class)
        {
            csharp.get_ancestors(&unit);
        }
        for _ in 0..2 {
            let warm_definitions = CSharpDefinitionProvider::new(csharp, &file);
            let warm = resolve_csharp(
                analyzer,
                token,
                &warm_definitions,
                &file,
                source,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let warm_bounded = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete {
                value: warm_bounded,
                ..
            } = warm_bounded
            else {
                panic!("warm budget: {warm_bounded:#?}");
            };
            assert_eq!(
                outcome.status, warm.status,
                "cold={outcome:#?}, warm={warm:#?}"
            );
            assert_eq!(
                outcome.status, warm_bounded.status,
                "cold={outcome:#?}, warm bounded={warm_bounded:#?}"
            );
        }
        let roots = HashSet::from_iter([file.clone()]);
        let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
            analyzer, token, &roots,
        )
        .expect("C# authoritative usage batch");
        let target = analyzer
            .get_definitions(target_fqn)
            .into_iter()
            .find(|unit| {
                unit.is_function() && unit.source().rel_path() == std::path::Path::new(target_path)
            })
            .unwrap_or_else(|| panic!("target {target_fqn} in {target_path}"));
        let result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } = &result
        else {
            panic!("usages complete: {result:#?}");
        };
        let count = |hits: &HashMap<CodeUnit, std::collections::BTreeSet<_>>| {
            hits.values().map(|hits| hits.len()).sum::<usize>()
        };
        let cold_counts = (count(hits_by_overload), count(unproven_by_overload));
        let warm_result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } = &warm_result
        else {
            panic!("warm usages: {warm_result:#?}");
        };
        assert_eq!(
            cold_counts,
            (count(hits_by_overload), count(unproven_by_overload)),
            "usage parity"
        );
        (outcome, cold_counts.0, cold_counts.1)
    }

    #[test]
    #[hardwon("#6296: ancestor membership must survive cold and warm chained lookups")]
    fn review_ancestor_routes_cold_warm() {
        let cases = [
            (
                "direct",
                "public partial class Twin {}",
                "public partial class Twin : Base {}",
                "public class Base { public Target Make() { return null; } }",
                "class Use { void Run(Twin t) { t.Make().Hum(); } }",
            ),
            (
                "transitive",
                "public partial class Twin {}",
                "public partial class Twin : Middle {}",
                "public class Middle : Base {} public class Base { public Target Make() { return null; } }",
                "class Use { void Run(Twin t) { t.Make().Hum(); } }",
            ),
            (
                "interface",
                "public partial interface Twin {}",
                "public partial interface Twin : IBase {}",
                "public interface IBase { Target Make(); }",
                "class Use { void Run(Twin t) { t.Make().Hum(); } }",
            ),
            (
                "generic",
                "public partial class Twin {}",
                "public partial class Twin : Base<Target> {}",
                "public class Base<T> { public Target Make() { return null; } }",
                "class Use { void Run(Twin t) { t.Make().Hum(); } }",
            ),
            (
                "nested",
                "public partial class Twin {} public class Outer { public class Inner : Twin {} }",
                "public partial class Twin : Base {}",
                "public class Base { public Target Make() { return null; } }",
                "class Use { void Run(Outer.Inner t) { t.Make().Hum(); } }",
            ),
        ];
        for (kind, visible, outside_source, base, source) in cases {
            for outside in ["Loose", "Other"] {
                let path = format!("{outside}/Twin.cs");
                let mut files = vec![
                    ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                    ("App/Twin.cs", visible),
                    (path.as_str(), outside_source),
                    ("App/Base.cs", base),
                    (
                        "App/Target.cs",
                        "public class Target { public void Hum() {} }",
                    ),
                    ("App/Use.cs", source),
                ];
                if outside == "Other" {
                    files.push((
                        "Other/Other.csproj",
                        r#"<Project Sdk="Microsoft.NET.Sdk" />"#,
                    ));
                }
                let (outcome, proven, unproven) = review_warm_membership_outcome(
                    &files,
                    "App/Use.cs",
                    source,
                    ".Hum()",
                    "Hum",
                    "Target.Hum",
                    "App/Target.cs",
                );
                eprintln!(
                    "{kind} {outside}: {:?}, proven={proven}, unproven={unproven}",
                    outcome.status
                );
                assert_ne!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{kind} {outside}: {outcome:#?}"
                );
                assert_eq!(proven, 0, "{kind} {outside}");
            }
        }
    }

    #[test]
    #[hardwon("#6296: scoped direct transitive and descendant accessors must replay base doubt")]
    fn review_all_hierarchy_accessors_replay_doubt() {
        use brokk_bifrost_core::analyzer::capabilities::{
            DescendantIndexScope, TypeHierarchyProvider,
        };
        for outside in ["Loose", "Other"] {
            let path = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                (
                    "App/Twin.cs",
                    "public partial class Twin {} public class Child : Twin {}",
                ),
                (path.as_str(), "public partial class Twin : Middle {}"),
                (
                    "App/Base.cs",
                    "public class Middle : Base {} public class Base {}",
                ),
                ("App/Use.cs", "class Use {}"),
            ];
            if outside == "Other" {
                files.push((
                    "Other/Other.csproj",
                    r#"<Project Sdk="Microsoft.NET.Sdk" />"#,
                ));
            }
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C#");
            let get = |name: &str| {
                analyzer
                    .get_definitions(name)
                    .into_iter()
                    .find(|u| u.source().rel_path() == std::path::Path::new("App/Twin.cs"))
                    .expect("visible type")
            };
            let twin = get("Twin");
            let child = get("Child");
            let base = analyzer
                .get_definitions("Base")
                .into_iter()
                .next()
                .expect("Base");
            csharp.get_ancestors(&child); // A populated inner memo must not affect the view.
            let reference = ProjectFile::new(fixture.project_root(), "App/Use.cs");
            let view = brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource::new(
                csharp, &reference,
            );
            let cancellation = CancellationToken::new();
            let scope = DescendantIndexScope::whole_workspace(&cancellation);
            for _ in 0..2 {
                let before = view.doubt();
                let direct = view.get_direct_ancestors(&twin);
                assert_eq!(
                    direct.iter().any(|u| u.fq_name() == "Middle"),
                    outside == "Loose"
                );
                assert_eq!(view.doubt() > before, outside == "Loose");
                let before = view.doubt();
                let scoped = view
                    .get_direct_ancestors_within(&twin, &scope)
                    .expect("scope");
                assert_eq!(direct, scoped);
                assert_eq!(view.doubt() > before, outside == "Loose");
                let before = view.doubt();
                let ancestors = view.get_ancestors(&child);
                assert_eq!(
                    ancestors.iter().any(|u| u.fq_name() == "Base"),
                    outside == "Loose"
                );
                assert_eq!(view.doubt() > before, outside == "Loose");
                let before = view.doubt();
                let descendants = view.get_descendants(&base);
                assert_eq!(
                    descendants.iter().any(|u| u.fq_name() == "Child"),
                    outside == "Loose"
                );
                assert_eq!(view.doubt() > before, outside == "Loose");
                let before = view.doubt();
                let scoped_descendants = view.get_descendants_within(&base, &scope).expect("scope");
                assert_eq!(
                    scoped_descendants.iter().any(|u| u.fq_name() == "Child"),
                    outside == "Loose"
                );
                assert_eq!(view.doubt() > before, outside == "Loose");
            }
        }
    }

    #[test]
    #[hardwon("#6296: supported unknown local receivers must remain unproven")]
    fn review_supported_local_bindings_remain_unproven() {
        for source in [
            "class Use { void Run() { using (Lonely Target = new Lonely()) { Target.Hum(); } } }",
            "class Use { void Run() { using var Target = new Lonely(); Target.Hum(); } }",
            "delegate void D(Lonely x); class Use { void Run() { D a = (Lonely Target) => Target.Hum(); } }",
        ] {
            let edges = inbound_edges(
                &[
                    ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                    (
                        "App/Target.cs",
                        "public class Target { public static void Hum() {} }",
                    ),
                    (
                        "Loose/Lonely.cs",
                        "public class Lonely { public void Hum() {} }",
                    ),
                    ("App/Use.cs", source),
                ],
                "Target.Hum",
            );
            assert!(
                edges
                    .edges
                    .iter()
                    .all(|((_, callee), _)| callee != "Target.Hum"),
                "{source}: {:?}",
                edges.edges
            );
            assert_eq!(edges.unproven_inbound.get("Target.Hum"), Some(&1));
        }
    }

    #[test]
    #[hardwon("#6296: extension applicability must not use an invisible partial base")]
    fn review_extension_compatibility_uses_only_visible_bases() {
        let source = "class Use { void Run(Twin t) { t.Hum(); } }";
        let files = [
            ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
            (
                "Other/Other.csproj",
                r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../App/App.csproj" /></ItemGroup></Project>"#,
            ),
            ("App/Twin.cs", "public partial class Twin {}"),
            ("Other/Twin.cs", "public partial class Twin : Base {}"),
            ("App/Base.cs", "public class Base {}"),
            (
                "App/Extensions.cs",
                "public static class Extensions { public static void Hum(this Base value) {} }",
            ),
            ("App/Use.cs", source),
        ];
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C#");
        let file = ProjectFile::new(fixture.project_root(), "App/Use.cs");
        assert_eq!(
            csharp.compilation_visibility(
                &file,
                &ProjectFile::new(fixture.project_root(), "Other/Twin.cs")
            ),
            Some(graph_support::CSharpCompilationVisibility::NotVisible)
        );
        let tree = parse_csharp_tree(source).expect("tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let start_byte = source.find("Hum()").expect("Hum");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "Hum".to_owned(),
            range: Range {
                start_byte,
                end_byte: start_byte + 3,
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + 3,
        };
        let mut results = Vec::new();
        for pass in 0..2 {
            let definitions = CSharpDefinitionProvider::new(csharp, &file);
            let unbounded = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &file,
                source,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let bounded = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                panic!("budget: {bounded:#?}");
            };
            eprintln!("pass={pass}, unbounded={unbounded:#?}, bounded={bounded:#?}");
            results.push((unbounded.status, bounded.status));
        }
        assert!(
            results
                .iter()
                .all(|(u, b)| *u != DefinitionLookupStatus::Resolved
                    && *b != DefinitionLookupStatus::Resolved),
            "invisible base cannot prove an extension, cold/warm={results:?}"
        );
    }

    #[test]
    #[hardwon("#6296: extension applicability must not use an invisible partial base")]
    fn extension_applicability_reads_bases_through_the_reference_membership() {
        use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
        let source = "class Use { void Run(Twin t) { t.Hum(); } }";
        for (outside, base_on, expected) in [
            ("Other", "outside", DefinitionLookupStatus::NoDefinition),
            ("Loose", "outside", DefinitionLookupStatus::Incomplete),
            ("Other", "visible", DefinitionLookupStatus::Resolved),
            ("Loose", "visible", DefinitionLookupStatus::Resolved),
        ] {
            let other_project = r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../App/App.csproj" /></ItemGroup></Project>"#;
            let outside_twin = format!("{outside}/Twin.cs");
            let (visible_twin, outside_body) = if base_on == "visible" {
                (
                    "public partial class Twin : Base {}",
                    "public partial class Twin {}",
                )
            } else {
                (
                    "public partial class Twin {}",
                    "public partial class Twin : Base {}",
                )
            };
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Twin.cs", visible_twin),
                (outside_twin.as_str(), outside_body),
                ("App/Base.cs", "public class Base {}"),
                (
                    "App/Extensions.cs",
                    "public static class Extensions { public static void Hum(this Base value) {} }",
                ),
                ("App/Use.cs", source),
            ];
            if outside == "Other" {
                files.push(("Other/Other.csproj", other_project));
            }
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C#");
            let file = ProjectFile::new(fixture.project_root(), "App/Use.cs");
            // Prime the analyzer's merged ancestor memo for every Twin part.
            for twin in analyzer.get_definitions("Twin") {
                csharp.get_direct_ancestors(&twin);
            }
            let tree = parse_csharp_tree(source).expect("tree");
            let scope = AnalyzerQueryScope::new(analyzer);
            let token = scope.token();
            let start_byte = source.find("Hum()").expect("Hum");
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: "Hum".to_owned(),
                range: Range {
                    start_byte,
                    end_byte: start_byte + 3,
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start_byte,
                focus_end_byte: start_byte + 3,
            };
            for pass in ["cold", "warm"] {
                let definitions = CSharpDefinitionProvider::new(csharp, &file);
                let unbounded = resolve_csharp(
                    analyzer,
                    token,
                    &definitions,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    false,
                )
                .outcome;
                let BoundedResolution::Complete { value: bounded, .. } = resolve_csharp_bounded(
                    analyzer,
                    token,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    ReceiverAnalysisBudget::default(),
                    None,
                ) else {
                    panic!("{outside} {base_on} {pass}: bounded lookup did not complete");
                };
                assert_eq!(
                    (unbounded.status, bounded.status),
                    (expected, expected),
                    "{outside} {base_on} {pass}: {unbounded:#?}"
                );
            }
        }
    }

    fn review_definition_statuses(
        files: &[(&str, &str)],
        source: &str,
        fragment: &str,
        name: &str,
    ) -> Vec<(DefinitionLookupStatus, DefinitionLookupStatus)> {
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, files);
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C#");
        let file = ProjectFile::new(fixture.project_root(), "App/Use.cs");
        let tree = parse_csharp_tree(source).expect("tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let start_byte =
            source.find(fragment).expect("fragment") + fragment.find(name).expect("name");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: name.to_owned(),
            range: Range {
                start_byte,
                end_byte: start_byte + name.len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + name.len(),
        };
        let mut results = Vec::new();
        for pass in 0..2 {
            let definitions = CSharpDefinitionProvider::new(csharp, &file);
            let u = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &file,
                source,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let b = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value: b, .. } = b else {
                panic!("budget: {b:#?}");
            };
            eprintln!("pass={pass}, unbounded={u:#?}, bounded={b:#?}");
            results.push((u.status, b.status));
        }
        results
    }

    fn review_attribute_base_case(outside: &str) {
        let source = "[Mark] class Use {}";
        let twin = format!("{outside}/Twin.cs");
        let mut files = vec![
            ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
            ("App/Twin.cs", "public partial class Twin {}"),
            (
                twin.as_str(),
                "public partial class Twin : System.Attribute {}",
            ),
            ("App/Mark.cs", "public class MarkAttribute : Twin {}"),
            ("App/Use.cs", source),
        ];
        if outside == "Other" {
            files.push(("Other/Other.csproj", r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../App/App.csproj" /></ItemGroup></Project>"#));
        }
        let results = review_definition_statuses(&files, source, "[Mark]", "Mark");
        assert!(
            results
                .iter()
                .all(|(u, b)| *u != DefinitionLookupStatus::Resolved
                    && *b != DefinitionLookupStatus::Resolved),
            "{outside}: attribute ancestry is not proven: {results:?}"
        );
    }

    #[test]
    #[hardwon("#6296: attribute evidence must filter an unproven partial ancestor")]
    fn review_attribute_base_membership_unresolved() {
        review_attribute_base_case("Loose");
    }

    #[test]
    #[hardwon("#6296: attribute evidence must filter an invisible partial ancestor")]
    fn review_attribute_base_membership_invisible() {
        review_attribute_base_case("Other");
    }

    fn review_extension_variant(
        visible: &str,
        outside_source: &str,
        base: &str,
        extension: &str,
        source: &str,
    ) {
        for outside in ["Loose", "Other"] {
            let path = format!("{outside}/Twin.cs");
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Twin.cs", visible),
                (path.as_str(), outside_source),
                ("App/Base.cs", base),
                ("App/Extensions.cs", extension),
                ("App/Use.cs", source),
            ];
            if outside == "Other" {
                files.push(("Other/Other.csproj", r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../App/App.csproj" /></ItemGroup></Project>"#));
            }
            let (outcome, proven, _) = review_warm_membership_outcome(
                &files,
                "App/Use.cs",
                source,
                ".Hum()",
                "Hum",
                "Extensions.Hum",
                "App/Extensions.cs",
            );
            eprintln!("{outside}: {:?}, proven={proven}", outcome.status);
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outside}: {outcome:#?}"
            );
            assert_eq!(proven, 0);
        }
    }

    #[test]
    #[hardwon("#6296: extension class base applicability carries membership doubt")]
    fn review_extension_variant_class() {
        review_extension_variant(
            "public partial class Twin {}",
            "public partial class Twin : Base {}",
            "public class Base {}",
            "public static class Extensions { public static void Hum(this Base v) {} }",
            "class Use { void Run(Twin t) { t.Hum(); } }",
        );
    }
    #[test]
    #[hardwon("#6296: extension interface base applicability carries membership doubt")]
    fn review_extension_variant_interface() {
        review_extension_variant(
            "public partial class Twin {}",
            "public partial class Twin : IBase {}",
            "public interface IBase {}",
            "public static class Extensions { public static void Hum(this IBase v) {} }",
            "class Use { void Run(Twin t) { t.Hum(); } }",
        );
    }
    #[test]
    #[hardwon("#6296: constrained extension applicability carries membership doubt")]
    fn review_extension_variant_constraint() {
        review_extension_variant(
            "public partial class Twin {}",
            "public partial class Twin : Base {}",
            "public class Base {}",
            "public static class Extensions { public static void Hum<T>(this T v) where T : Base {} }",
            "class Use { void Run(Twin t) { t.Hum(); } }",
        );
    }
    #[test]
    #[hardwon("#6296: nested receiver extension applicability carries membership doubt")]
    fn review_extension_variant_nested() {
        review_extension_variant(
            "public partial class Twin {} public class Outer { public class Inner : Twin {} }",
            "public partial class Twin : Base {}",
            "public class Base {}",
            "public static class Extensions { public static void Hum(this Base v) {} }",
            "class Use { void Run(Outer.Inner t) { t.Hum(); } }",
        );
    }
    #[test]
    #[hardwon("#6296: generic receiver extension applicability carries membership doubt")]
    fn review_extension_variant_generic() {
        review_extension_variant(
            "public partial class Twin<T> {}",
            "public partial class Twin<T> : Base {}",
            "public class Base {}",
            "public static class Extensions { public static void Hum(this Base v) {} }",
            "class Use { void Run(Twin<int> t) { t.Hum(); } }",
        );
    }

    #[test]
    #[hardwon("#6296: attribute evidence must filter an unproven or invisible partial ancestor")]
    fn attribute_ancestry_reads_bases_through_the_reference_membership() {
        use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
        let source = "[Mark] class Use {}";
        for (outside, base_on, expected) in [
            ("Loose", "outside", DefinitionLookupStatus::Incomplete),
            ("Other", "outside", DefinitionLookupStatus::NoDefinition),
            ("Loose", "visible", DefinitionLookupStatus::Resolved),
            ("Other", "visible", DefinitionLookupStatus::Resolved),
            ("Loose", "direct", DefinitionLookupStatus::Resolved),
        ] {
            let outside_twin = format!("{outside}/Twin.cs");
            let (visible_twin, outside_body, mark) = match base_on {
                "outside" => (
                    "public partial class Twin {}",
                    "public partial class Twin : System.Attribute {}",
                    "public class MarkAttribute : Twin {}",
                ),
                "visible" => (
                    "public partial class Twin : System.Attribute {}",
                    "public partial class Twin {}",
                    "public class MarkAttribute : Twin {}",
                ),
                _ => (
                    "public partial class Twin {}",
                    "public partial class Twin : System.Attribute {}",
                    "public class MarkAttribute : System.Attribute {}",
                ),
            };
            let mut files = vec![
                ("App/App.csproj", r#"<Project Sdk="Microsoft.NET.Sdk" />"#),
                ("App/Twin.cs", visible_twin),
                (outside_twin.as_str(), outside_body),
                ("App/Mark.cs", mark),
                ("App/Use.cs", source),
            ];
            if outside == "Other" {
                files.push((
                    "Other/Other.csproj",
                    r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../App/App.csproj" /></ItemGroup></Project>"#,
                ));
            }
            let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &files);
            let analyzer = fixture.analyzer.analyzer();
            let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C#");
            let file = ProjectFile::new(fixture.project_root(), "App/Use.cs");
            // Prime the analyzer's merged ancestor memo.
            for unit in analyzer
                .get_definitions("Twin")
                .into_iter()
                .chain(analyzer.get_definitions("MarkAttribute"))
            {
                csharp.get_direct_ancestors(&unit);
            }
            let tree = parse_csharp_tree(source).expect("tree");
            let scope = AnalyzerQueryScope::new(analyzer);
            let token = scope.token();
            let start_byte = source.find("Mark").expect("Mark");
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: "Mark".to_owned(),
                range: Range {
                    start_byte,
                    end_byte: start_byte + 4,
                    start_line: 0,
                    end_line: 0,
                },
                focus_start_byte: start_byte,
                focus_end_byte: start_byte + 4,
            };
            for pass in ["cold", "warm"] {
                let definitions = CSharpDefinitionProvider::new(csharp, &file);
                let unbounded = resolve_csharp(
                    analyzer,
                    token,
                    &definitions,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    false,
                )
                .outcome;
                let BoundedResolution::Complete { value: bounded, .. } = resolve_csharp_bounded(
                    analyzer,
                    token,
                    &file,
                    source,
                    Some(&tree),
                    &site,
                    ReceiverAnalysisBudget::default(),
                    None,
                ) else {
                    panic!("{outside} {base_on} {pass}: bounded lookup did not complete");
                };
                assert_eq!(
                    (unbounded.status, bounded.status),
                    (expected, expected),
                    "{outside} {base_on} {pass}: {unbounded:#?}"
                );
            }
        }
    }

    #[test]
    fn event_field_variable_declaration_is_not_a_local_binding() {
        let source = r#"
using System;
class EventOwner
{
    event EventHandler Changed;
    void Run() { Changed.Invoke(this, EventArgs.Empty); }
}
"#;
        let tree = parse_csharp_tree(source).expect("C# tree");
        let changed_start = source.find("Changed;").expect("event declaration");
        let name = tree
            .root_node()
            .named_descendant_for_byte_range(changed_start, changed_start + "Changed".len())
            .expect("event name node");
        let declaration = name
            .parent()
            .and_then(|declarator| declarator.parent())
            .expect("event variable declaration");

        assert_eq!(declaration.kind(), "variable_declaration");
        assert_eq!(
            declaration.parent().map(|parent| parent.kind()),
            Some("event_field_declaration")
        );
        assert!(!csharp_is_local_variable_declaration(declaration));
    }

    fn member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let source = r#"
namespace Demo;
public class Product { public void Work() {} }
public class Consumer
{
    public void Run(Product product) { product.Work(); }
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[("BoundedDefinition.cs", &source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "BoundedDefinition.cs");
        let tree = parse_csharp_tree(&source).expect("C# tree");
        let call_start = source.rfind("product.Work()").expect("member call");
        let start_byte = call_start + "product.".len();
        let end_byte = start_byte + "Work".len();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "Work".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line: 6,
                end_line: 6,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        (fixture, file, source, tree, site)
    }

    #[test]
    fn repeated_ancestor_queries_reuse_complete_answers_and_keep_request_limits() {
        let project = InlineTestProject::with_language(Language::CSharp)
            .file(
                "Ancestors.cs",
                "namespace Demo { class Base {} class First : Base {} class Second : Base {} }",
            )
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("C# ancestor workspace");
        let analyzer = workspace.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let unbounded = CSharpDefinitionProvider::new(csharp, &any_reference(csharp));
        let first = unbounded.fqn("Demo.First").pop().expect("first owner");
        let second = unbounded.fqn("Demo.Second").pop().expect("second owner");
        let base = unbounded.fqn("Demo.Base").pop().expect("base class");
        analyzer.type_hierarchy_provider().expect("C# hierarchy");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 1,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(
            definitions.direct_ancestors(token, &first),
            vec![base.clone()]
        );
        let first_work = session.finish(()).work();
        assert_eq!(
            definitions.direct_ancestors(token, &first),
            vec![base.clone()]
        );
        let mut cached_work = first_work;
        cached_work.scope_nodes += 1;
        assert!(
            matches!(session.finish(()), BoundedResolution::Complete { work, .. }
            if work == cached_work && work.summary_expansions == 1)
        );
        assert!(definitions.direct_ancestors(token, &second).is_empty());
        assert!(matches!(session.finish(()), BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::SummaryExpansions, work,
        } if work.summary_expansions == 1));

        let cancellation = CancellationToken::new();
        let session = ResolutionSession::bounded(budget, Some(&cancellation));
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(definitions.direct_ancestors(token, &first), vec![base]);
        cancellation.cancel();
        assert!(definitions.direct_ancestors(token, &first).is_empty());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn repeated_parent_queries_preserve_present_absent_and_cancelled_answers() {
        let project = InlineTestProject::with_language(Language::CSharp)
            .file("Parents.cs", "class Root { void Work() {} } class Other {}")
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("C# parent workspace");
        let analyzer = workspace.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let unbounded = CSharpDefinitionProvider::new(csharp, &any_reference(csharp));
        let root = unbounded.fqn("Root").pop().expect("root class");
        let work = unbounded.fqn("Root.Work").pop().expect("method");
        let other = unbounded.fqn("Other").pop().expect("other class");
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 1,
            ..ReceiverAnalysisBudget::default()
        };

        let session = ResolutionSession::bounded(budget, None);
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(definitions.parent_of(analyzer, &work), Some(root.clone()));
        let first_work = session.finish(()).work();
        assert_eq!(definitions.parent_of(analyzer, &work), Some(root.clone()));
        let mut cached_work = first_work;
        cached_work.scope_nodes += 1;
        assert!(
            matches!(session.finish(()), BoundedResolution::Complete { work, .. }
            if work == cached_work && work.summary_expansions == 1)
        );
        assert_eq!(definitions.parent_of(analyzer, &root), None);
        assert!(matches!(session.finish(()), BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::SummaryExpansions, work,
        } if work.summary_expansions == 1));

        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                ..budget
            },
            None,
        );
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(definitions.parent_of(analyzer, &work), Some(root.clone()));
        assert_eq!(definitions.parent_of(analyzer, &work), None);
        assert!(matches!(session.finish(()), BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes, work,
        } if work.scope_nodes == 1 && work.summary_expansions == 1));

        let session = ResolutionSession::bounded(budget, None);
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(definitions.parent_of(analyzer, &root), None);
        let first_work = session.finish(()).work();
        assert_eq!(definitions.parent_of(analyzer, &root), None);
        assert!(
            matches!(session.finish(()), BoundedResolution::Complete { work, .. }
            if work == first_work && work.summary_expansions == 1)
        );
        assert_eq!(definitions.parent_of(analyzer, &other), None);
        assert!(matches!(session.finish(()), BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::SummaryExpansions, work,
        } if work.summary_expansions == 1));

        let cancellation = CancellationToken::new();
        let session = ResolutionSession::bounded(budget, Some(&cancellation));
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert_eq!(definitions.parent_of(analyzer, &work), Some(root));
        cancellation.cancel();
        assert_eq!(definitions.parent_of(analyzer, &work), None);
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn bounded_definition_lookup_stops_at_scope_budget() {
        let (fixture, file, source, tree, site) = member_fixture();
        let budget = ReceiverAnalysisBudget::tiny();
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let outcome = resolve_csharp_bounded(
            fixture.analyzer.analyzer(),
            token,
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );

        assert_scope_budget_exceeded(&outcome, budget);
    }

    #[test]
    fn very_wide_active_path_stops_before_materializing_siblings() {
        const SIBLING_COUNT: usize = 25_000;

        let mut statements = String::new();
        for index in 0..SIBLING_COUNT {
            writeln!(statements, "Call{index}();").expect("write wide C# statement");
        }
        let source = format!("class Wide {{ void Run() {{\n{statements}_ = target;\n}} }}",);
        let cutoff_start = source.find("_ = target").expect("target expression");
        let tree = parse_csharp_tree(&source).expect("wide C# tree");
        let mut block = tree
            .root_node()
            .named_descendant_for_byte_range(cutoff_start, cutoff_start + 1)
            .expect("target node");
        while block.kind() != "block" {
            block = block.parent().expect("target must be inside a block");
        }
        assert_eq!(
            block.named_child_count(),
            SIBLING_COUNT + 1,
            "fixture must retain the deliberately wide sibling set"
        );

        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("Provider.cs", "class P {}")]);
        let csharp =
            resolve_analyzer::<CSharpAnalyzer>(fixture.analyzer.analyzer()).expect("C# analyzer");

        let budget = ReceiverAnalysisBudget::tiny();
        let budget_session = ResolutionSession::bounded(budget, None);
        let budget_definitions =
            CSharpDefinitionProvider::bounded(csharp, &budget_session, &any_reference(csharp));
        let mut budget_visits = 0usize;
        csharp_visit_bounded_active_path(&budget_definitions, block, cutoff_start, |_| {
            budget_visits += 1;
            true
        });
        assert_eq!(budget_visits, 1, "only the charged root may be visited");
        assert!(matches!(
            budget_session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));

        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        let cancel_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let cancel_definitions =
            CSharpDefinitionProvider::bounded(csharp, &cancel_session, &any_reference(csharp));
        let mut cancel_visits = 0usize;
        csharp_visit_bounded_active_path(&cancel_definitions, block, cutoff_start, |_| {
            cancel_visits += 1;
            true
        });
        assert_eq!(
            cancel_visits, 1,
            "cancellation must stop before another sibling is pushed"
        );
        assert!(matches!(
            cancel_session.finish(()),
            BoundedResolution::Cancelled { work } if work.scope_nodes == 1
        ));
    }

    #[test]
    fn bounded_member_lookup_caps_overload_materialization() {
        let source = r#"
namespace Demo;
public class Product
{
    public void Work() {}
    public void Work(int first) {}
    public void Work(int first, int second) {}
    public void Work(string first) {}
    public void Work(string first, string second) {}
    public void Work(long first) {}
    public void Work(double first) {}
    public void Work(decimal first) {}
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("BoundedOverloads.cs", source)]);
        let csharp =
            resolve_analyzer::<CSharpAnalyzer>(fixture.analyzer.analyzer()).expect("C# analyzer");
        assert!(
            csharp
                .member_candidates_for_owner("Demo.Product", "Work")
                .len()
                > 3,
            "fixture must contain more overloads than the bounded lookahead"
        );

        let provider_batch =
            csharp.member_candidates_for_owner_limited("Demo.Product", "Work", 3, || true);
        assert!(!provider_batch.complete);
        assert_eq!(provider_batch.inspected, 3);
        assert!(provider_batch.rows.is_empty());

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 3,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        assert!(
            definitions
                .members_for_owner_name("Demo.Product", "Work")
                .is_empty()
        );
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_global_using_scan_stops_cold_without_hydration() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[
                (
                    "GlobalA.cs",
                    "global using Alpha.One; namespace Demo; public class A {}",
                ),
                (
                    "GlobalB.cs",
                    "global using Beta.Two; namespace Demo; public class B {}",
                ),
                (
                    "GlobalC.cs",
                    "global using Gamma.Three; namespace Demo; public class C {}",
                ),
                (
                    "GlobalD.cs",
                    "global using Delta.Four; namespace Demo; public class D {}",
                ),
            ],
        );
        let csharp =
            resolve_analyzer::<CSharpAnalyzer>(fixture.analyzer.analyzer()).expect("C# analyzer");
        csharp.reset_full_hydration_count_for_test();

        let direct = csharp.global_using_namespaces_limited(3, || true);
        assert!(!direct.complete);
        assert_eq!(direct.inspected, 3);
        assert_eq!(csharp.full_hydration_count_for_test(), 0);

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 4,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let definitions =
            CSharpDefinitionProvider::bounded(csharp, &session, &any_reference(csharp));
        let file = ProjectFile::new(fixture.project_root(), "GlobalA.cs");
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        assert!(definitions.using_namespaces(token, &file).is_empty());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert_eq!(csharp.full_hydration_count_for_test(), 0);
    }

    #[test]
    fn bounded_attribute_evidence_rejects_unresolved_ancestry_as_incomplete() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[(
                "Attributes.cs",
                r#"
namespace System { public class Attribute {} }
namespace Demo
{
    public class ProvenAttribute : System.Attribute {}
    public class UnknownAttribute : External.AttributeBase {}
}
"#,
            )],
        );
        let csharp =
            resolve_analyzer::<CSharpAnalyzer>(fixture.analyzer.analyzer()).expect("C# analyzer");
        let proven =
            graph_support::declaration_candidates_by_fqn(csharp, "Demo.ProvenAttribute", false)
                .into_iter()
                .find(CodeUnit::is_class)
                .expect("proven attribute");
        let unknown =
            graph_support::declaration_candidates_by_fqn(csharp, "Demo.UnknownAttribute", false)
                .into_iter()
                .find(CodeUnit::is_class)
                .expect("unknown attribute");

        let proven_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let proven_definitions =
            CSharpDefinitionProvider::bounded(csharp, &proven_session, &any_reference(csharp));
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        assert_eq!(
            proven_definitions.attribute_class_is_applicable(token, &proven),
            Some(true)
        );
        assert!(matches!(
            proven_session.finish(()),
            BoundedResolution::Complete { .. }
        ));

        let unknown_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let unknown_definitions =
            CSharpDefinitionProvider::bounded(csharp, &unknown_session, &any_reference(csharp));
        assert_eq!(
            unknown_definitions.attribute_class_is_applicable(token, &unknown),
            None
        );
        assert!(matches!(
            unknown_session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    /// The definition answers for the reference `name` inside the first
    /// `needle` of `source`, the text of `use_path`: the unbounded and the
    /// bounded API, on the first requests and again once the analyzer's
    /// hierarchy memos are warm, followed by the proven and unproven inverse
    /// hits of each field in `targets`.
    fn definition_answers(
        files: &[(&str, &str)],
        use_path: &str,
        source: &str,
        needle: &str,
        name: &str,
        targets: &[&str],
    ) -> (Vec<DefinitionLookupOutcome>, Vec<(usize, usize)>) {
        use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, files);
        let analyzer = fixture.analyzer.analyzer();
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).expect("C# analyzer");
        let file = ProjectFile::new(fixture.project_root(), use_path);
        let tree = parse_csharp_tree(source).expect("C# reference tree");
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let start_byte = source.find(needle).expect("reference fixture")
            + needle.find(name).expect("name in fragment");
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: name.to_owned(),
            range: Range {
                start_byte,
                end_byte: start_byte + name.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + name.len(),
        };
        let answers = || {
            let definitions = CSharpDefinitionProvider::new(csharp, &file);
            let unbounded = resolve_csharp(
                analyzer,
                token,
                &definitions,
                &file,
                source,
                Some(&tree),
                &site,
                false,
            )
            .outcome;
            let bounded = resolve_csharp_bounded(
                analyzer,
                token,
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value: bounded, .. } = bounded else {
                panic!("reference lookup must complete: {bounded:#?}");
            };
            [unbounded, bounded]
        };
        let mut outcomes = Vec::from(answers());
        for unit in analyzer
            .get_all_declarations()
            .into_iter()
            .filter(CodeUnit::is_class)
        {
            csharp.get_ancestors(&unit);
        }
        outcomes.extend(answers());
        outcomes.extend(answers());

        let roots = HashSet::from_iter([file.clone()]);
        let batch = crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch::new(
            analyzer, token, &roots,
        )
        .expect("C# authoritative usage batch");
        let count = |hits: &HashMap<CodeUnit, std::collections::BTreeSet<_>>| {
            hits.values().map(|hits| hits.len()).sum::<usize>()
        };
        let inverse = targets
            .iter()
            .map(|target_fqn| {
                let target = analyzer
                    .get_definitions(target_fqn)
                    .into_iter()
                    .find(CodeUnit::is_field)
                    .unwrap_or_else(|| panic!("field {target_fqn}"));
                let result = batch
                    .find_usages(std::slice::from_ref(&target), &roots, 100)
                    .into_fuzzy_result();
                let FuzzyResult::Success {
                    hits_by_overload,
                    unproven_by_overload,
                    ..
                } = &result
                else {
                    panic!("usages of {target_fqn} complete: {result:#?}");
                };
                (count(hits_by_overload), count(unproven_by_overload))
            })
            .collect();
        (outcomes, inverse)
    }

    fn fq_names(outcome: &DefinitionLookupOutcome) -> Vec<String> {
        outcome.definitions.iter().map(CodeUnit::fq_name).collect()
    }

    #[test]
    #[hardwon(
        "#6472: a call-argument initializer took its owner from an imported type that a visible global parameter type outranks"
    )]
    fn call_argument_initializer_owner_follows_parameter_type_precedence() {
        const MODEL: &str = "namespace Ns { public class Foo { public int Flag; } }";
        const USE: &str = "using Ns; class Use { void Take(Foo arg) {} void Run() { Take(new() { Flag = 1 }); } }";
        const NESTED_USE: &str = "namespace Outer { using Ns; class Use { void Take(Foo arg) {} void Run() { Take(new() { Flag = 1 }); } } }";
        const SDK: &str = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        // The callee's file imports `Ns`; the caller's imports `Other`. The
        // parameter type is written in the callee's file, so only its scope
        // decides what `Foo` names.
        const API: &str = "using Ns; public class Api { public void Take(Foo arg) {} }";
        const CALLER: &str =
            "using Other; class Use { void Run(Api api) { api.Take(new() { Flag = 1 }); } }";
        const OTHER: &str = "namespace Other { public class Foo { public int Flag; } }";
        // Attributes, a doc comment and a generic method put the parameter
        // after the callee's own type parameter.
        const GENERIC_API: &str = "using Ns;\npublic class Api {\n    /// <summary>Takes it.</summary>\n    [System.Obsolete] public static void Take<T>(T tag, Foo arg) {}\n}";
        const GENERIC_CALLER: &str =
            "class Use { void Run() { Api.Take(1, new() { Flag = 1 }); } }";

        // A global `Foo` precedes every compilation-unit `using`, so the
        // imported `Ns.Foo` is never the owner.
        // Case name, fixture files, the file with the call, its source, and the
        // fully qualified names a proven answer resolves to.
        type InitializerCase<'a> = (
            &'a str,
            Vec<(&'a str, &'a str)>,
            &'a str,
            &'a str,
            &'a [&'a str],
        );
        let cases: [InitializerCase<'_>; 10] = [
            (
                "a visible global type without the member",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Foo.cs", "public class Foo {}"),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", USE),
                ],
                "App/Use.cs",
                USE,
                &[],
            ),
            (
                "a visible global type with the member",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Foo.cs", "public class Foo { public int Flag; }"),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", USE),
                ],
                "App/Use.cs",
                USE,
                &["Foo.Flag"],
            ),
            (
                "an imported type no global type outranks",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", USE),
                ],
                "App/Use.cs",
                USE,
                &["Ns.Foo.Flag"],
            ),
            (
                "an import inside the enclosing namespace precedes the global namespace",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Foo.cs", "public class Foo {}"),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", NESTED_USE),
                ],
                "App/Use.cs",
                NESTED_USE,
                &["Ns.Foo.Flag"],
            ),
            (
                "a callee in another file resolves its parameter in its own scope",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Model.cs", MODEL),
                    ("App/Other.cs", OTHER),
                    ("App/Api.cs", API),
                    ("App/Use.cs", CALLER),
                ],
                "App/Use.cs",
                CALLER,
                &["Ns.Foo.Flag"],
            ),
            (
                "a visible global type in the callee's file scope",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Foo.cs", "public class Foo {}"),
                    ("App/Model.cs", MODEL),
                    ("App/Other.cs", OTHER),
                    ("App/Api.cs", API),
                    ("App/Use.cs", CALLER),
                ],
                "App/Use.cs",
                CALLER,
                &[],
            ),
            (
                "an attributed generic callee, imported type",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Model.cs", MODEL),
                    ("App/Api.cs", GENERIC_API),
                    ("App/Use.cs", GENERIC_CALLER),
                ],
                "App/Use.cs",
                GENERIC_CALLER,
                &["Ns.Foo.Flag"],
            ),
            (
                "an attributed generic callee, visible global type",
                vec![
                    ("App/App.csproj", SDK),
                    ("App/Foo.cs", "public class Foo {}"),
                    ("App/Model.cs", MODEL),
                    ("App/Api.cs", GENERIC_API),
                    ("App/Use.cs", GENERIC_CALLER),
                ],
                "App/Use.cs",
                GENERIC_CALLER,
                &[],
            ),
            (
                "a global type of unproven membership",
                vec![
                    ("App/App.csproj", SDK),
                    ("Loose/Foo.cs", "public class Foo {}"),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", USE),
                ],
                "App/Use.cs",
                USE,
                &[],
            ),
            (
                "a global type of unproven membership with the member",
                vec![
                    ("App/App.csproj", SDK),
                    ("Loose/Foo.cs", "public class Foo { public int Flag; }"),
                    ("App/Model.cs", MODEL),
                    ("App/Use.cs", USE),
                ],
                "App/Use.cs",
                USE,
                &["Foo.Flag"],
            ),
        ];
        for (name, files, use_path, source, expected) in cases {
            let unproven_global = name.contains("unproven");
            let global_target =
                expected == ["Foo.Flag"] || (unproven_global && name.contains("with the member"));
            let mut targets = vec!["Ns.Foo.Flag"];
            if global_target {
                targets.push("Foo.Flag");
            }
            let (outcomes, inverse) =
                definition_answers(&files, use_path, source, "Flag = 1", "Flag", &targets);
            for outcome in &outcomes {
                if unproven_global {
                    // Either type could be the owner; no resolution is proven.
                    assert_eq!(
                        outcome.status,
                        DefinitionLookupStatus::Incomplete,
                        "{name}: {outcome:#?}"
                    );
                    assert!(
                        outcome.diagnostics.iter().any(|diagnostic| diagnostic.kind
                            == "csharp_compilation_membership_unproven"),
                        "{name}: {outcome:#?}"
                    );
                    assert!(
                        !fq_names(outcome).contains(&"Ns.Foo.Flag".to_owned()),
                        "{name}: {outcome:#?}"
                    );
                } else if expected.is_empty() {
                    assert_ne!(
                        outcome.status,
                        DefinitionLookupStatus::Resolved,
                        "{name}: {outcome:#?}"
                    );
                    assert!(fq_names(outcome).is_empty(), "{name}: {outcome:#?}");
                } else {
                    assert_eq!(
                        outcome.status,
                        DefinitionLookupStatus::Resolved,
                        "{name}: {outcome:#?}"
                    );
                    assert_eq!(fq_names(outcome), expected, "{name}: {outcome:#?}");
                }
            }
            // The inverse scan agrees: the imported field is a proven use only
            // when the forward answer names it. An owner that lacks the member
            // leaves the use unproven rather than absent, as it always has.
            let (imported_proven, imported_unproven) = inverse[0];
            assert_eq!(
                imported_proven,
                usize::from(expected == ["Ns.Foo.Flag"]),
                "{name}: inverse proven hits of Ns.Foo.Flag"
            );
            if unproven_global {
                assert!(
                    imported_unproven > 0,
                    "{name}: an unproven global type leaves the imported field unproven, not absent"
                );
            }
            if !unproven_global && expected == ["Foo.Flag"] {
                assert_eq!(
                    imported_unproven, 0,
                    "{name}: the visible global field is a different member"
                );
                assert_eq!(inverse[1], (1, 0), "{name}: inverse hits of Foo.Flag");
            }
            if unproven_global && global_target {
                assert_eq!(inverse[1].0, 0, "{name}: inverse proven hits of Foo.Flag");
                assert!(
                    inverse[1].1 > 0,
                    "{name}: inverse unproven hits of Foo.Flag"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#6472: overload refinement compared an argument with an imported parameter type that a visible global type outranks"
    )]
    fn overload_refinement_follows_parameter_type_precedence() {
        const SDK: &str = r#"<Project Sdk="Microsoft.NET.Sdk" />"#;
        const USE: &str = "using Ns; class Use { void Take(Foo arg) {} void Take(int count) {} void Run(Foo foo) { Take(foo); } }";
        const IMPORTED_ARGUMENT: &str = "using Ns; class Use { void Take(Foo arg) {} void Take(int count) {} void Run(Ns.Foo foo) { Take(foo); } }";
        let files = |use_source| {
            vec![
                ("App/App.csproj", SDK),
                ("App/Foo.cs", "public class Foo {}"),
                ("App/Model.cs", "namespace Ns { public class Foo {} }"),
                ("App/Use.cs", use_source),
            ]
        };
        // `Foo` names the global type at the declaration, so a global `Foo`
        // argument selects `Take(Foo)` and an `Ns.Foo` argument does not: the
        // overload set stays as the call found it.
        for (name, source, narrowed) in [
            ("a global argument", USE, true),
            ("an imported argument", IMPORTED_ARGUMENT, false),
        ] {
            let (outcomes, _) = definition_answers(
                &files(source),
                "App/Use.cs",
                source,
                "Take(foo)",
                "Take",
                &[],
            );
            for outcome in &outcomes {
                let signatures = outcome
                    .definitions
                    .iter()
                    .map(|definition| definition.signature().unwrap_or_default().to_owned())
                    .collect::<Vec<_>>();
                let foo_overload_only =
                    matches!(signatures.as_slice(), [signature] if signature.contains("Foo"));
                assert_eq!(foo_overload_only, narrowed, "{name}: {outcome:#?}");
                if narrowed {
                    assert_eq!(
                        outcome.status,
                        DefinitionLookupStatus::Resolved,
                        "{name}: {outcome:#?}"
                    );
                } else {
                    assert_eq!(signatures.len(), 2, "{name}: {signatures:?}");
                }
            }
        }
    }

    #[test]
    fn bounded_definition_lookup_stops_on_cancellation() {
        let (fixture, file, source, tree, site) = member_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let token = scope.token();
        let outcome = resolve_csharp_bounded(
            fixture.analyzer.analyzer(),
            token,
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }
}
