use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::csharp::{graph_support, hierarchy};
use crate::analyzer::structural::{PrecedenceTier, RejectionReason};
use crate::analyzer::tree_walk::node_for_exact_range;
use crate::analyzer::usages::applicability::{
    ApplicabilityOutcome, CandidateApplicability, arity_verdict,
};
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::csharp_graph::{
    CSharpDeclaredType, canonical_builtin_type_identity,
    csharp_extension_invocation_return_type_fq_name_in_session,
    csharp_member_declared_type_fq_name_in_session,
    csharp_method_return_type_fq_name_for_arity_in_session, csharp_resolve_type_fq_name,
    csharp_usage_direct_base, csharp_visible_extension_method_candidates_in_session,
    seed_csharp_bindings_before_in_session,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{
    TypeHierarchyProvider, csharp_attribute_name_node, csharp_attribute_type_names,
    csharp_conditional_member_access, csharp_member_name, csharp_method_generic_arity,
    csharp_normalize_full_name, csharp_source_identifier,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason,
};
use brokk_bifrost_csharp::graph::extractor::is_statement_label as csharp_is_statement_label;
use brokk_bifrost_csharp::graph_support::CSharpSource;
use brokk_bifrost_csharp::syntax::{
    CSharpNamedArgumentLabel, csharp_constant_pattern_type_candidate,
    csharp_implicit_accessor_value, csharp_local_binder_name, csharp_named_argument_label,
    csharp_nameof_type_candidates, csharp_using_directive_is_static,
    csharp_using_directive_target_node,
};

pub(super) struct CSharpDefinitionProvider<'a> {
    csharp: &'a CSharpAnalyzer,
    session: Option<&'a ResolutionSession>,
}

impl<'a> CSharpDefinitionProvider<'a> {
    pub(super) fn new(csharp: &'a CSharpAnalyzer) -> Self {
        Self {
            csharp,
            session: None,
        }
    }

    fn bounded(csharp: &'a CSharpAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            csharp,
            session: Some(session),
        }
    }

    fn scope_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::scope_step)
    }

    fn summary_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::summary_step)
    }

    fn observe_cancellation(&self) -> bool {
        self.session
            .is_none_or(ResolutionSession::observe_cancellation)
    }

    fn query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        match self.session {
            Some(session) => session.query(query),
            None => Some(query()),
        }
    }

    fn query_optional<T>(&self, query: impl FnOnce() -> Option<T>) -> Option<T> {
        match self.session {
            Some(session) => session.query_optional(query),
            None => query(),
        }
    }

    fn signature_metadata(&self, unit: &CodeUnit) -> Vec<crate::analyzer::SignatureMetadata> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.csharp.signature_metadata_limited(unit, limit)),
            None => self.csharp.signature_metadata(unit),
        }
    }

    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
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
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::arity_free_declaration_type_candidates_by_fqn_limited(
                    self.csharp,
                    fqn,
                    limit,
                    || session.observe_cancellation(),
                )
            }),
            None => graph_support::arity_free_declaration_type_candidates_by_fqn(self.csharp, fqn),
        }
    }

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        match self.session {
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
        }
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
        if self.session.is_none() {
            return graph_support::visible_type_candidates(self.csharp, token, file, name);
        }
        self.visible_type_candidates_with_lookup(token, file, name, &mut |fqn| self.fqn(fqn))
    }

    fn arity_free_visible_type_candidates(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<CodeUnit> {
        if self.session.is_none() {
            return graph_support::arity_free_visible_type_candidates(
                self.csharp,
                token,
                file,
                name,
            );
        }
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
        debug_assert!(self.session.is_some());
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
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::partial_type_parts_limited(self.csharp, owner, limit, || {
                    session.observe_cancellation()
                })
            }),
            None => graph_support::partial_type_parts(self.csharp, owner),
        }
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

    fn import_statements(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                graph_support::import_statements_limited(self.csharp, token, file, limit)
            }),
            None => self.csharp.import_statements(file),
        }
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

    fn attribute_type_candidates(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        names: &[String],
    ) -> (Vec<CodeUnit>, bool) {
        if self.session.is_none() {
            return hierarchy::attribute_type_candidates_with_ambiguity(
                self.csharp,
                token,
                file,
                names,
            );
        }
        let mut visible_type_candidates = |name: &str| {
            let candidates = self.visible_type_candidates(token, file, name);
            self.observe_cancellation().then_some(candidates)
        };
        let mut attribute_class_is_applicable =
            |candidate: &CodeUnit| self.attribute_class_is_applicable(token, candidate);
        hierarchy::attribute_type_candidates_with_lookups(
            names,
            &mut visible_type_candidates,
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
                let raw_supertypes = session
                    .query_limited_rows(|limit| self.csharp.raw_supertypes_limited(&part, limit));
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
    fn raw_supertypes(&self, part: &CodeUnit) -> Vec<String> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| self.csharp.raw_supertypes_limited(part, limit))
            }
            None => self.csharp.raw_supertypes_of(part),
        }
    }

    fn direct_ancestors(
        &self,
        provider: &dyn TypeHierarchyProvider,
        token: QueryToken<'_>,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let Some(session) = self.session else {
            return provider.get_direct_ancestors(owner);
        };
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
        let mut ancestors = Vec::new();
        for part in parts {
            if !self.scope_step() {
                return Vec::new();
            }
            let raw_supertypes = session
                .query_limited_rows(|limit| self.csharp.raw_supertypes_limited(&part, limit));
            if !self.observe_cancellation() {
                return Vec::new();
            }
            for raw in raw_supertypes {
                let candidates = self.supertype_candidates(token, &part, &raw);
                if !self.observe_cancellation() {
                    return Vec::new();
                }
                ancestors.extend(graph_support::unique_logical_type(candidates));
            }
        }
        graph_support::sort_dedup_type_candidates(&mut ancestors);
        ancestors
    }

    fn parent_of(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.summary_step() {
            return None;
        }
        let parent = analyzer.parent_of(unit);
        if !self.observe_cancellation() {
            return None;
        }
        let parent = parent?;
        self.scope_step().then_some(parent)
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
    Dynamic {
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

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
    let definitions = CSharpDefinitionProvider::bounded(csharp, session);
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

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    preserve_using_alias: bool,
) -> DefinitionLookupOutcome {
    resolve_csharp_in_session(
        analyzer,
        token,
        definitions,
        file,
        source,
        tree,
        site,
        preserve_using_alias,
    )
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
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "csharp_analyzer_unavailable",
            "C# analyzer is unavailable",
        ));
    };
    let definitions = CSharpDefinitionProvider::bounded(csharp, &session);
    let outcome = resolve_csharp_in_session(
        analyzer,
        token,
        &definitions,
        file,
        source,
        tree,
        site,
        false,
    );
    session.finish(outcome)
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
        Some(CSharpReferenceNode::Type(type_node)) => {
            let reference = csharp_reference_type_text(type_node, source);
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
                return boundary_unchecked(format!(
                    "`{reference}` appears to cross a C# using-alias boundary not indexed in this workspace"
                ));
            }
            if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
                analyzer,
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
                &reference,
                type_node.start_byte(),
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
            let unindexed_builtin_receiver = owners.is_empty()
                && structured_receiver_type_names
                    .iter()
                    .any(|name| canonical_builtin_type_identity(name).is_some());
            let arity = csharp_invocation_arity(name, source, definitions);
            // What an extension candidate is allowed to answer depends on what
            // this site can prove about it (#1266).
            //
            // When the receiver's own type IS indexed, `csharp_member_outcome`
            // below searches every ordinary member of it and of its supertypes.
            // An empty result there IS C#'s extension-precedence rule
            // discharged: no applicable instance member exists, so an extension
            // may answer, in a call position or as a method group.
            //
            // When the receiver's type is NOT indexed -- `System.Type`,
            // `JsonSerializerOptions`, a BCL `IEnumerable<T>` -- that proof does
            // not exist and cannot be obtained. An ordinary instance member of
            // the same spelling may well be the binding, and a workspace
            // extension that merely shares the name is a possibility rather than
            // the answer. The site itself can still supply the OTHER half of
            // applicability, so an external receiver is admitted only for an
            // actual invocation, whose argument count the candidate's parameter
            // list must accept. A bare member access over an external receiver
            // proves nothing: BootstrapBlazor's `innerType.IsEnum` and
            // YamlDotNet's `t.IsGenericType` read a `System.Type` PROPERTY, and
            // answering them with the same-spelled workspace extension METHOD
            // was a claim the inverse scan -- which has always required a call
            // arity here -- never made.
            let should_try_extensions = if owners.is_empty() {
                !structured_receiver_type_names.is_empty()
                    && !unindexed_builtin_receiver
                    && arity.is_some()
            } else {
                true
            };
            let outcome = csharp_member_outcome(
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
                        csharp,
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
                        csharp,
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
                    return candidates_outcome(extensions);
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
                    &reference,
                    identifier.start_byte(),
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
                    text,
                    identifier.start_byte(),
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
                    CSharpDeclaredType::Spelling(spelling) => {
                        names.extend(csharp_structured_receiver_reference_type_names(
                            csharp,
                            token,
                            definitions,
                            file,
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
        csharp,
        token,
        definitions,
        file,
        &csharp_reference_type_text(type_node, source),
    )
}

fn csharp_structured_receiver_reference_type_names(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Vec<String> {
    let reference = csharp_normalize_full_name(reference);
    if reference.is_empty() {
        return Vec::new();
    }
    if definitions.session().is_some() {
        let mut candidates =
            csharp_logical_visible_type_candidates(csharp, token, definitions, file, &reference);
        if candidates.len() == 1 {
            return vec![candidates.remove(0).fq_name()];
        }
    } else if let Some(resolved) = csharp_resolve_type_fq_name(csharp, token, file, &reference) {
        return vec![resolved];
    }

    let aliases = definitions.using_aliases(token, file);
    let mut names = vec![
        aliases
            .get(&reference)
            .cloned()
            .unwrap_or_else(|| reference.clone()),
    ];
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
    node: Node<'_>,
) -> Option<CSharpTypeLookupResolution> {
    if !definitions.scope_step() {
        return None;
    }
    if let Some(name) = csharp_attribute_name_node(node) {
        let names = csharp_attribute_type_names(name, source);
        let (candidates, ambiguous) = definitions.attribute_type_candidates(token, file, &names);
        return csharp_type_candidates_resolution_with_kind(
            names.first().map(String::as_str).unwrap_or_default(),
            candidates,
            TypeLookupTargetKind::TypeReference,
            ambiguous,
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
        return csharp_type_candidates_resolution_with_kind(
            &reference,
            csharp_visible_type_output_candidates(csharp, token, definitions, file, &reference),
            TypeLookupTargetKind::TypeReference,
            false,
        );
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
            return csharp_type_candidates_resolution_with_kind(
                csharp_node_text(node, source),
                candidates,
                target_kind,
                false,
            );
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
    csharp_type_candidates_resolution(name, candidates)
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
            csharp_logical_visible_type_candidates(csharp, token, definitions, file, name),
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
                csharp_type_node_resolution(
                    csharp,
                    token,
                    definitions,
                    file,
                    &csharp_reference_type_text(type_node, source),
                )
            })
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(name) => {
            parent.parent().and_then(|declaration| {
                (declaration.kind() == "variable_declaration")
                    .then(|| declaration.child_by_field_name("type"))
                    .flatten()
                    .and_then(|type_node| {
                        csharp_type_node_resolution(
                            csharp,
                            token,
                            definitions,
                            file,
                            &csharp_reference_type_text(type_node, source),
                        )
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
                    csharp,
                    token,
                    file,
                    &owner,
                    member_name,
                    session,
                ),
                None => {
                    csharp_member_declared_type_fq_name(csharp, token, file, &owner, member_name)
                }
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
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<CSharpTypeLookupResolution> {
    if csharp_is_dynamic_type_reference(reference) {
        return Some(CSharpTypeLookupResolution::Dynamic {
            target_kind: TypeLookupTargetKind::ValueExpression,
        });
    }
    csharp_type_candidates_resolution_with_kind(
        reference,
        csharp_visible_type_output_candidates(csharp, token, definitions, file, reference),
        TypeLookupTargetKind::ValueExpression,
        false,
    )
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
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let is_dynamic =
        csharp_is_dynamic_type_reference(&csharp_reference_type_text(type_node, source));
    match node.kind() {
        "parameter" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            if is_dynamic {
                bindings.seed_symbol(csharp_node_text(name, source), ());
            } else {
                bindings.declare_shadow(csharp_node_text(name, source));
            }
        }
        "variable_declaration" => {
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
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            let Some(type_node) = node.child_by_field_name("type") else {
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
                        .map(|type_node| csharp_reference_type_text(type_node, source))
                        .map(|reference| {
                            csharp_logical_visible_type_candidates(
                                csharp,
                                token,
                                definitions,
                                file,
                                &reference,
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
    let reference = csharp_reference_type_text(type_node, source);
    let candidates =
        csharp_logical_visible_type_candidates(csharp, token, definitions, file, &reference);
    if candidates.is_empty() {
        bindings.declare_shadow(binding_name);
    } else {
        bindings.seed_symbol_many(binding_name, candidates);
    }
}

pub(super) fn parse_csharp_tree(source: &str) -> Option<Tree> {
    brokk_bifrost_csharp::preprocessor::parse_csharp(source)
}

enum CSharpReferenceNode<'tree> {
    Attribute(Node<'tree>),
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Member {
        receiver: Node<'tree>,
        name: Node<'tree>,
    },
    UnqualifiedMember(Node<'tree>),
    NamedArgumentLabel {
        label: Node<'tree>,
        shape: CSharpNamedArgumentLabel<'tree>,
    },
    Identifier(Node<'tree>),
}

fn csharp_reference_node<'tree>(
    node: Node<'tree>,
    definitions: &CSharpDefinitionProvider<'_>,
) -> Option<CSharpReferenceNode<'tree>> {
    if !definitions.scope_step() {
        return None;
    }
    if let Some(name) = csharp_attribute_name_node(node) {
        return Some(CSharpReferenceNode::Attribute(name));
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
        ) && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte())
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
            || (parent.kind() == "object_creation_expression"
                && (parent.child_by_field_name("type") == Some(current)
                    || csharp_first_type_child(parent) == Some(current)))
        {
            current = parent;
        } else {
            break;
        }
    }

    match current.kind() {
        "member_access_expression" => Some(CSharpReferenceNode::Member {
            receiver: csharp_member_access_receiver(current)?,
            name: csharp_member_access_name(current)?,
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
                return Some(CSharpReferenceNode::Type(current));
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
        | "array_type" => Some(CSharpReferenceNode::Type(current)),
        _ => None,
    }
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
        return csharp_type_outcome(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            &reference,
            type_node.start_byte(),
        );
    }
    let owners =
        csharp_logical_visible_type_candidates(csharp, token, definitions, file, &reference);
    let call_arity = csharp_argument_count(creation, source);
    let mut constructors = Vec::new();
    let mut applicable = Vec::new();
    let mut implicit_parameterless_owners = Vec::new();
    for owner in &owners {
        let owner_constructors = definitions
            .members_for_owner_name(
                &owner.fq_name(),
                crate::analyzer::csharp_source_identifier(owner),
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
                || csharp_uses_implicit_parameterless_value_constructor(
                    analyzer,
                    definitions,
                    owner,
                ))
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
    csharp_type_outcome(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        &reference,
        type_node.start_byte(),
    )
}

fn csharp_uses_implicit_parameterless_value_constructor(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(source) = definitions.query_optional(|| owner.source().read_to_string().ok()) else {
        return false;
    };
    let Some(tree) = parse_csharp_tree(&source) else {
        return false;
    };
    let ranges = definitions
        .query(|| analyzer.ranges(owner).to_vec())
        .unwrap_or_default();
    let root = tree.root_node();
    ranges.into_iter().any(|range| {
        let Some(declaration) = node_for_exact_range(root, &range) else {
            return false;
        };
        matches!(
            declaration.kind(),
            "struct_declaration" | "record_struct_declaration"
        )
    })
}

fn csharp_type_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
) -> DefinitionLookupOutcome {
    let mut candidates =
        csharp_visible_type_output_candidates(csharp, token, definitions, file, reference);
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
        definitions,
        file,
        reference,
        byte,
    ) {
        return candidates_outcome(vec![unit]);
    }
    // `csharp_import_boundary_for_type` fuses the unresolved-using signal with
    // the workspace type/namespace check; its negation is the workspace gate.
    if csharp_import_boundary_for_type(csharp, token, definitions, file, reference)
        && let Some(candidate) = csharp_indexed_non_type_candidate(
            analyzer,
            definitions,
            file,
            reference,
            byte,
            |unit| !unit.is_class(),
        )
    {
        // #1218: every type-shaped resolver above has already failed to find
        // `reference` as a type, and this retry excludes classes explicitly
        // (rather than trusting that exhaustion), so a hit here is
        // guaranteed to be a different-kind declaration (property/field/
        // method/...) that merely shares the failed type reference's
        // spelling. The boundary claim would call it "not indexed" while
        // the index plainly contains it.
        return no_definition(
            "indexed_declaration_wrong_kind",
            csharp_indexed_candidate_honesty_message(reference, "type", &candidate),
        );
    }
    gated_boundary(
        || !csharp_import_boundary_for_type(csharp, token, definitions, file, reference),
        format!("`{reference}` appears to cross a C# using boundary not indexed in this workspace"),
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
        definitions.attribute_type_candidates(token, file, &names);
    if !candidates.is_empty() {
        let mut outcome = candidates_outcome(candidates);
        if ambiguous_spelling {
            outcome.status = DefinitionLookupStatus::Ambiguous;
            outcome.diagnostics = vec![DefinitionLookupDiagnostic {
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
        && let Some(candidate) = csharp_indexed_non_type_candidate(
            analyzer,
            definitions,
            file,
            reference,
            name.start_byte(),
            |unit| !unit.is_class(),
        )
    {
        return no_definition(
            "indexed_declaration_wrong_kind",
            csharp_indexed_candidate_honesty_message(reference, "attribute type", &candidate),
        );
    }
    // Both disjuncts are workspace-fused boundary predicates (alias target /
    // using target the workspace does not index); their negation is the gate.
    gated_boundary(
        || !boundary,
        format!("`{reference}` appears to cross a C# using boundary not indexed in this workspace"),
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

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = Vec::new();
        let mut depth = 0usize;
        for owner in &owners {
            if !definitions.scope_step() {
                break;
            }
            seen.insert(owner.clone());
            let expanded = definitions.direct_ancestors(provider, token, owner);
            if let Some(state) = member_trace.as_mut() {
                state.record_expansion(owner, &expanded);
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
                let expanded = definitions.direct_ancestors(provider, token, &ancestor);
                if let Some(state) = member_trace.as_mut() {
                    state.record_expansion(&ancestor, &expanded);
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

    fn record_expansion(&mut self, owner: &CodeUnit, ancestors: &[CodeUnit]) {
        for ancestor in ancestors {
            self.parents
                .entry(ancestor.clone())
                .or_insert_with(|| owner.clone());
        }
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
        use crate::analyzer::structural::HierarchyRelation;

        let Some(find) = self.found.get(candidate) else {
            return Vec::new();
        };
        let mut chain = vec![find.owner.clone()];
        while !self
            .roots
            .contains(chain.last().expect("chain is never empty"))
        {
            let Some(parent) = self
                .parents
                .get(chain.last().expect("chain is never empty"))
            else {
                break;
            };
            chain.push(parent.clone());
        }
        chain.reverse();
        debug_assert_eq!(
            chain.len(),
            find.depth + 1,
            "the first-discovery chain must be exactly the walk's hop distance"
        );
        chain
            .windows(2)
            .enumerate()
            .map(|(hop, pair)| trace::HierarchyHopRecord {
                hop,
                from: pair[0].clone(),
                to: pair[1].clone(),
                relation: HierarchyRelation::Supertype,
            })
            .collect()
    }

    fn enrichment(
        &self,
        candidate: &CodeUnit,
        applicability: ApplicabilityVerdict,
    ) -> Option<trace::MemberEnrichment> {
        use crate::analyzer::structural::MemberDispatchTier;

        let find = self.found.get(candidate)?;
        let dispatch_tier = if find.depth == 0 {
            MemberDispatchTier::InherentOrDirect
        } else {
            MemberDispatchTier::InheritedOrPromoted
        };
        Some(trace::MemberEnrichment {
            owner: find.owner.clone(),
            hierarchy_depth: find.depth,
            dispatch_tier,
            applicability,
            route: self.route(candidate),
        })
    }

    fn precedence_tier(&self, candidate: &CodeUnit) -> Option<PrecedenceTier> {
        self.found.get(candidate).map(|find| {
            if find.depth == 0 {
                PrecedenceTier::OwnMember
            } else {
                PrecedenceTier::InheritedMember
            }
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
            let mut row = trace::TraceCandidate::rejected(
                trace::TraceCandidateRef::Unit(loser.clone()),
                self.precedence_tier(loser),
                RejectionReason::CallableApplicabilityDeferred,
            );
            if let Some(verdict) = verdict_of(loser) {
                row = row.with_callable(trace::CallableApplicabilityRecord {
                    verdict: verdict.verdict,
                    reason: verdict.reason,
                });
            }
            if let Some(enrichment) = self.enrichment(loser, ApplicabilityVerdict::Inapplicable) {
                row = row.with_member(enrichment);
            }
            trace::record(row);
        }
        if let Some(tier) = winners
            .iter()
            .filter_map(|unit| self.precedence_tier(unit))
            .min()
        {
            trace::stage_tier(tier, winners.iter().map(CodeUnit::fq_name).collect());
        }
        trace::stage_member_context(
            winners
                .iter()
                .filter_map(|unit| {
                    let applicability = verdict_of(unit)
                        .map(|verdict| verdict.verdict)
                        .unwrap_or(ApplicabilityVerdict::Unknown);
                    self.enrichment(unit, applicability)
                        .map(|enrichment| (unit.fq_name(), enrichment))
                })
                .collect(),
        );
        trace::stage_callable_context(
            winners
                .iter()
                .filter_map(|unit| {
                    verdict_of(unit).map(|verdict| {
                        (
                            unit.fq_name(),
                            trace::CallableApplicabilityRecord {
                                verdict: verdict.verdict,
                                reason: verdict.reason,
                            },
                        )
                    })
                })
                .collect(),
        );
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
    let Some(type_node) = csharp_object_initializer_owner_type_node(initializer) else {
        if let Some(collection_target) = csharp_object_creation_collection_target(initializer) {
            let owners = csharp_collection_element_owner_types(
                analyzer,
                token,
                csharp,
                definitions,
                file,
                source,
                collection_target,
            );
            let target_text = csharp_node_text(collection_target, source);
            return Some(
                csharp_initializer_member_outcome(
                    analyzer,
                    token,
                    definitions,
                    owners,
                    member,
                    target_text,
                )
                .unwrap_or_else(|| {
                    no_definition(
                        "unknown_object_initializer_owner",
                        format!(
                            "C# object initializer element type could not be inferred from collection target `{target_text}`"
                        ),
                    )
                }),
            );
        }
        // A target-typed `new()` whose target type the tree does not write.
        // The one such target the index can still prove is an assignment's
        // left side: it types exactly like a receiver, because the type of
        // `x` in `x = new() { ... }` is the type of `x` in `x.Member`.
        let Some(target) = csharp_object_creation_assignment_target(initializer) else {
            return Some(no_definition(
                "unknown_object_initializer_owner",
                "C# object initializer target type could not be inferred",
            ));
        };
        let owners = csharp_receiver_types(
            analyzer,
            token,
            csharp,
            definitions,
            file,
            source,
            root,
            target,
        )
        .units;
        let target_text = csharp_node_text(target, source);
        return Some(
            csharp_initializer_member_outcome(analyzer, token, definitions, owners, member, target_text)
                .unwrap_or_else(|| {
                    no_definition(
                        "unknown_object_initializer_owner",
                        format!(
                            "C# object initializer target type could not be inferred from assignment target `{target_text}`"
                        ),
                    )
                }),
        );
    };
    let type_name = csharp_reference_type_text(type_node, source);
    let owners = csharp_constructed_type_candidates(
        analyzer,
        token,
        csharp,
        definitions,
        file,
        &type_name,
        type_node.start_byte(),
    );
    Some(
        csharp_initializer_member_outcome(analyzer, token, definitions, owners, member, &type_name)
            .unwrap_or_else(|| {
                no_definition(
                    "unresolved_object_initializer_owner",
                    format!(
                        "C# object initializer target type `{type_name}` did not resolve to an indexed C# type"
                    ),
                )
            }),
    )
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
            csharp,
            definitions,
            file,
            &type_name,
            type_node.start_byte(),
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
                    let element = match definitions.session() {
                        Some(session) => {
                            csharp_member_declared_collection_element_type_fq_name_in_session(
                                csharp, token, &current, name, session,
                            )
                        }
                        None => csharp_member_declared_collection_element_type_fq_name(
                            csharp, token, &current, name,
                        ),
                    };
                    return element
                        .into_iter()
                        .flat_map(|fqn| definitions.fqn(&fqn))
                        .collect();
                }
                if let Some(provider) = analyzer.type_hierarchy_provider() {
                    next_level.extend(definitions.direct_ancestors(provider, token, &current));
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
/// walk, and finally the reference read as a fully qualified name.
fn csharp_constructed_type_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
) -> Vec<CodeUnit> {
    if let Some(unit) = resolve_csharp_nested_type_in_enclosing_classes(
        analyzer,
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
        csharp_logical_visible_type_candidates(csharp, token, definitions, file, reference);
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
    let (owners, _ambiguous_spelling) =
        definitions.attribute_type_candidates(token, file, &attribute_names);
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
/// A callable whose parameter list C# never recorded is compared against a
/// defaulted zero arity, which is a language-side choice this factoring
/// preserves rather than changes: the row states the refusal the resolver acted
/// on. See the plan's Surprises entry.
fn csharp_candidate_applicability(
    analyzer: &dyn IAnalyzer,
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
        let declared = definitions
            .query(|| csharp_callable_arity(analyzer, unit))
            .unwrap_or_else(|| crate::analyzer::CallableArity::exact(0));
        let verdict = arity_verdict(unit, Some(&[declared]), expected);
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
        if unit.is_function() && csharp_method_generic_arity(unit.signature()) == expected {
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
            csharp,
            token,
            definitions,
            file,
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
                csharp,
                token,
                definitions,
                file,
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
                    csharp,
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
                            csharp,
                            token,
                            definitions,
                            file,
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
                .and_then(|owner| csharp_usage_direct_base(analyzer, token, csharp, &owner))
                .into_iter()
                .collect(),
        ),
        "qualified_name" | "alias_qualified_name" | "generic_name" => {
            CSharpReceiverTypes::from_units(csharp_logical_visible_type_candidates(
                csharp,
                token,
                definitions,
                file,
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
                        csharp,
                        token,
                        definitions,
                        file,
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
                        csharp,
                        token,
                        definitions,
                        file,
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
                if let Some(provider) = provider {
                    next_level.extend(definitions.direct_ancestors(provider, token, &current));
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
    csharp: &CSharpAnalyzer,
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
    let explicit_type_arguments = csharp_resolved_type_arguments(
        csharp,
        token,
        definitions,
        file,
        source,
        name.type_arguments,
    );
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
                csharp,
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
                csharp,
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
                csharp,
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
                csharp,
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
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    type_arguments: Option<Node<'_>>,
) -> Option<Vec<String>> {
    let type_arguments = type_arguments?;
    let mut cursor = type_arguments.walk();
    type_arguments
        .named_children(&mut cursor)
        .map(|argument| {
            if !definitions.scope_step() {
                return None;
            }
            let reference = csharp_reference_type_text(argument, source);
            let mut candidates = csharp_logical_visible_type_candidates(
                csharp,
                token,
                definitions,
                file,
                &reference,
            );
            (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
        })
        .collect()
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
        if let Some(provider) = analyzer.type_hierarchy_provider() {
            let mut seen = HashSet::default();
            let mut stack = definitions.direct_ancestors(provider, token, &owner);
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
                stack.extend(definitions.direct_ancestors(provider, token, &ancestor));
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
    csharp: &CSharpAnalyzer,
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
            csharp, token, file, owner, name, session,
        ),
        None => csharp_member_declared_type_fq_name(csharp, token, file, owner, name),
    };
    if let Some(type_fqn) = type_fqn {
        candidates.push_fq_name(definitions, type_fqn);
    }
}

fn csharp_visible_type_output_candidates(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, token, definitions, file, name);
    graph_support::sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_logical_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, token, definitions, file, name);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn csharp_visible_type_candidates(
    _csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    definitions.visible_type_candidates(token, file, name)
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
        return crate::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
            definitions.parent_of(analyzer, unit)
        })
        .find(CodeUnit::is_class);
    }
    if let Some(unit) = analyzer.class_range_index(file).enclosing_unit(byte) {
        return Some(unit.clone());
    }

    let start = analyzer.enclosing_code_unit(file, &range)?;
    crate::analyzer::usages::common::enclosing_owner_chain(start, |unit| analyzer.parent_of(unit))
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
    crate::analyzer::usages::common::enclosing_owner_chain(innermost, |unit| {
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
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    resolve_csharp_nested_type_in_enclosing_classes_with(
        analyzer,
        definitions,
        file,
        name,
        byte,
        &mut |fqn| definitions.fqn(fqn),
    )
}

fn resolve_csharp_arity_free_nested_type_in_enclosing_classes(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    resolve_csharp_nested_type_in_enclosing_classes_with(
        analyzer,
        definitions,
        file,
        name,
        byte,
        &mut |fqn| definitions.arity_free_types_by_fqn(fqn),
    )
}

fn resolve_csharp_nested_type_in_enclosing_classes_with<Candidates>(
    analyzer: &dyn IAnalyzer,
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
    let owners = crate::analyzer::usages::common::enclosing_owner_chain(enclosing, |unit| {
        definitions
            .parent_of(analyzer, unit)
            .filter(CodeUnit::is_class)
    })
    .map_while(|owner| definitions.scope_step().then_some(owner));
    for owner in owners {
        let child_fqn = format!("{}.{}", owner.fq_name(), prefix);
        let Some(prefix_unit) = type_candidates_by_fqn(&child_fqn)
            .into_iter()
            .find(CodeUnit::is_class)
        else {
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
    let simple = crate::analyzer::symbol_lookup::parse_symbol_path(Language::CSharp, reference)
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
        .import_statements(token, file)
        .into_iter()
        .filter_map(|raw| {
            raw.trim()
                .trim_start_matches("global ")
                .trim_start_matches("using ")
                .trim_end_matches(';')
                .trim()
                .strip_prefix("static ")
                .map(|target| target.trim().to_string())
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
    csharp: &CSharpAnalyzer,
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
                        csharp,
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
                            csharp,
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
            .is_none_or(|parent| parent.kind() != "field_declaration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;
    use std::fmt::Write as _;

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
    fn bounded_definition_lookup_completes_with_accounted_work() {
        let (fixture, file, source, tree, site) = member_fixture();
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
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("member lookup should complete");
        };
        assert!(work.scope_nodes > 0);
        assert_eq!(value.status, DefinitionLookupStatus::Resolved);
        assert!(
            value
                .definitions
                .iter()
                .any(|unit| { unit.fq_name() == "Demo.Product.Work" })
        );
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

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
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
        let budget_definitions = CSharpDefinitionProvider::bounded(csharp, &budget_session);
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
        let cancel_definitions = CSharpDefinitionProvider::bounded(csharp, &cancel_session);
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
        let definitions = CSharpDefinitionProvider::bounded(csharp, &session);
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
        let definitions = CSharpDefinitionProvider::bounded(csharp, &session);
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
        let proven_definitions = CSharpDefinitionProvider::bounded(csharp, &proven_session);
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
        let unknown_definitions = CSharpDefinitionProvider::bounded(csharp, &unknown_session);
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
