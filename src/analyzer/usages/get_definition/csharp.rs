use super::*;
use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::csharp_graph::{
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
                self.csharp
                    .declaration_candidates_by_fqn_limited(fqn, false, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self
                .csharp
                .declaration_candidates_by_fqn(fqn, false)
                .into_iter()
                .collect(),
        };
        if !exact.is_empty() {
            return exact;
        }
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .declaration_candidates_by_fqn_limited(fqn, true, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self
                .csharp
                .declaration_candidates_by_fqn(fqn, true)
                .into_iter()
                .collect(),
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

    fn visible_type_candidates(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        if self.session.is_none() {
            return self.csharp.visible_type_candidates(file, name);
        }
        let mut using_aliases = || {
            let aliases = self.using_aliases(file);
            self.observe_cancellation().then_some(aliases)
        };
        let mut namespace_of_file = || self.namespace_of_file(file);
        let mut using_namespaces = || {
            let namespaces = self.using_namespaces(file);
            self.observe_cancellation().then_some(namespaces)
        };
        let mut type_candidates_by_fqn = |fqn: &str| {
            let candidates = self
                .fqn(fqn)
                .into_iter()
                .filter(CodeUnit::is_class)
                .collect();
            self.observe_cancellation().then_some(candidates)
        };
        self.csharp.visible_type_candidates_with_lookups(
            name,
            true,
            &mut using_aliases,
            &mut namespace_of_file,
            &mut using_namespaces,
            &mut type_candidates_by_fqn,
        )
    }

    fn partial_type_parts(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .partial_type_parts_limited(owner, limit, || session.observe_cancellation())
            }),
            None => self.csharp.partial_type_parts(owner),
        }
    }

    fn using_namespaces(&self, file: &ProjectFile) -> Vec<String> {
        match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .using_namespaces_of_limited(file, limit, || session.observe_cancellation())
            }),
            None => self.csharp.using_namespaces_of(file),
        }
    }

    fn using_aliases(&self, file: &ProjectFile) -> HashMap<String, String> {
        let aliases = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.csharp
                    .using_aliases_of_limited(file, limit, || session.observe_cancellation())
            }),
            None => self.csharp.using_aliases_of(file).into_iter().collect(),
        };
        aliases.into_iter().collect()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.csharp.import_statements_limited(file, limit)),
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
        file: &ProjectFile,
        names: &[String],
    ) -> (Vec<CodeUnit>, bool) {
        if self.session.is_none() {
            return self
                .csharp
                .attribute_type_candidates_with_ambiguity(file, names);
        }
        let mut visible_type_candidates = |name: &str| {
            let candidates = self.visible_type_candidates(file, name);
            self.observe_cancellation().then_some(candidates)
        };
        let mut attribute_class_is_applicable =
            |candidate: &CodeUnit| self.attribute_class_is_applicable(candidate);
        self.csharp
            .attribute_type_candidates_with_lookups(
                names,
                &mut visible_type_candidates,
                &mut attribute_class_is_applicable,
            )
            .unwrap_or((Vec::new(), false))
    }

    fn attribute_class_is_applicable(&self, candidate: &CodeUnit) -> Option<bool> {
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
                    let ancestors = self.visible_type_candidates(part.source(), &raw);
                    if !self.observe_cancellation() {
                        return None;
                    }
                    if ancestors.is_empty() || self.csharp.logical_type_count(&ancestors) > 1 {
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

    fn direct_ancestors(
        &self,
        provider: &dyn TypeHierarchyProvider,
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
                let mut candidates = self.visible_type_candidates(part.source(), &raw);
                if !self.observe_cancellation() {
                    return Vec::new();
                }
                if self.csharp.logical_type_count(&candidates) == 1 {
                    self.csharp.sort_type_candidates(&mut candidates);
                    if let Some(ancestor) = candidates.into_iter().next() {
                        ancestors.push(ancestor);
                    }
                }
            }
        }
        self.csharp.sort_dedup_type_candidates(&mut ancestors);
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

pub(crate) fn csharp_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<CSharpTypeLookupResolution> {
    let session = ResolutionSession::unbounded();
    csharp_type_lookup_resolution_in_session(analyzer, file, source, root, site, &session)
}

pub(crate) fn csharp_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
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
    csharp_type_lookup_node_resolution(analyzer, csharp, &definitions, file, source, root, node)
}

pub(super) fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    resolve_csharp_in_session(analyzer, definitions, file, source, tree, site)
}

pub(crate) fn resolve_csharp_bounded(
    analyzer: &dyn IAnalyzer,
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
    let outcome = resolve_csharp_in_session(analyzer, &definitions, file, source, tree, site);
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
fn resolve_csharp_in_session(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
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
    if csharp_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a C# reference site", site.text),
        );
    }

    match csharp_reference_node(node, definitions) {
        Some(CSharpReferenceNode::Attribute(name)) => {
            csharp_attribute_outcome(csharp, definitions, file, name, source)
        }
        Some(CSharpReferenceNode::Type(type_node)) => {
            let reference = csharp_reference_type_text(type_node, source);
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
            ) {
                return candidates_outcome(vec![unit]);
            }
            csharp_type_outcome(
                analyzer,
                csharp,
                definitions,
                file,
                &reference,
                type_node.start_byte(),
            )
        }
        Some(CSharpReferenceNode::Constructor(creation)) => {
            resolve_csharp_constructor(analyzer, csharp, definitions, file, source, creation)
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
                csharp,
                definitions,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            let owners = receiver_types.units;
            let mut receiver_type_names = receiver_types.fq_names;
            if receiver_type_names.is_empty() {
                receiver_type_names = csharp_structured_receiver_type_names(
                    csharp,
                    definitions,
                    file,
                    source,
                    tree.root_node(),
                    receiver,
                );
            }
            let arity = csharp_invocation_arity(name, source, definitions);
            let outcome = csharp_member_outcome(
                analyzer,
                definitions,
                owners.clone(),
                member,
                arity,
                explicit_generic_arity,
                false,
            );
            if outcome.status == DefinitionLookupStatus::NoDefinition {
                let extensions = match definitions.session() {
                    Some(session) => csharp_visible_extension_method_candidates_in_session(
                        csharp,
                        analyzer,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                        false,
                        session,
                    ),
                    None => csharp_visible_extension_method_candidates(
                        csharp,
                        analyzer,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                        false,
                    ),
                };
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
                let fallback = csharp_member_outcome(
                    analyzer,
                    definitions,
                    owners.clone(),
                    member,
                    arity,
                    explicit_generic_arity,
                    true,
                );
                if fallback.status != DefinitionLookupStatus::NoDefinition {
                    return fallback;
                }
                let extensions = match definitions.session() {
                    Some(session) => csharp_visible_extension_method_candidates_in_session(
                        csharp,
                        analyzer,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                        true,
                        session,
                    ),
                    None => csharp_visible_extension_method_candidates(
                        csharp,
                        analyzer,
                        file,
                        source,
                        member_name_node,
                        &receiver_type_names,
                        member,
                        arity,
                        explicit_generic_arity,
                        true,
                    ),
                };
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
                return fallback;
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
            let owners = csharp_enclosing_class(analyzer, definitions, file, name.start_byte())
                .into_iter()
                .collect();
            let arity = csharp_invocation_arity(name, source, definitions);
            let outcome = csharp_member_outcome(
                analyzer,
                definitions,
                owners,
                member,
                arity,
                explicit_generic_arity,
                true,
            );
            if outcome.status == DefinitionLookupStatus::NoDefinition
                && csharp_static_using_boundary_for_member(csharp, definitions, file)
            {
                return boundary(format!(
                    "`{member}` appears to cross a C# static using boundary not indexed in this workspace"
                ));
            }
            outcome
        }
        Some(CSharpReferenceNode::Identifier(identifier)) => {
            let text = csharp_node_text(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C# identifier is blank");
            }
            if let Some(outcome) = csharp_object_initializer_label_outcome(
                analyzer,
                csharp,
                definitions,
                file,
                source,
                identifier,
            ) {
                return outcome;
            }
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
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
                    csharp,
                    definitions,
                    file,
                    &reference,
                    identifier.start_byte(),
                );
            }
            if !bindings.is_shadowed(text) {
                if csharp_is_unqualified_member_reference(identifier)
                    && let Some(owner) =
                        csharp_enclosing_class(analyzer, definitions, file, identifier.start_byte())
                {
                    let outcome = csharp_member_outcome(
                        analyzer,
                        definitions,
                        vec![owner],
                        text,
                        None,
                        None,
                        true,
                    );
                    if outcome.status != DefinitionLookupStatus::NoDefinition {
                        return outcome;
                    }
                }
                let outcome = csharp_type_outcome(
                    analyzer,
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

fn csharp_structured_receiver_type_names(
    csharp: &CSharpAnalyzer,
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
        let bindings = csharp_legacy_bindings_before_scoped(
            csharp,
            definitions,
            file,
            source,
            root,
            receiver.start_byte(),
        );
        return bindings
            .resolve_symbol(name)
            .as_precise()
            .map(|types| types.iter().cloned().collect())
            .unwrap_or_default();
    }
    let type_node = match receiver.kind() {
        "cast_expression" => receiver.child_by_field_name("type"),
        "as_expression" => receiver.child_by_field_name("right"),
        _ => None,
    };
    let Some(type_node) = type_node else {
        return Vec::new();
    };
    let reference = csharp_normalize_full_name(&csharp_reference_type_text(type_node, source));
    if reference.is_empty() {
        return Vec::new();
    }
    if definitions.session().is_some() {
        let mut candidates =
            csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
        if candidates.len() == 1 {
            return vec![candidates.remove(0).fq_name()];
        }
    } else if let Some(resolved) = csharp_resolve_type_fq_name(csharp, file, &reference) {
        return vec![resolved];
    }

    let aliases = definitions.using_aliases(file);
    let mut names = vec![
        aliases
            .get(&reference)
            .cloned()
            .unwrap_or_else(|| reference.clone()),
    ];
    if !reference.contains('.') && !aliases.contains_key(&reference) {
        let namespaces = definitions.using_namespaces(file);
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

fn csharp_type_lookup_node_resolution(
    analyzer: &dyn IAnalyzer,
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
        let (candidates, ambiguous) = definitions.attribute_type_candidates(file, &names);
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
        let candidates =
            csharp_receiver_types(analyzer, csharp, definitions, file, source, root, node).units;
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
            csharp_visible_type_output_candidates(csharp, definitions, file, &reference),
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
            let (candidates, target_kind) =
                csharp_receiver_type_lookup_units(csharp, definitions, file, source, root, node);
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
        let member_candidates =
            csharp_enclosing_member_type_units(csharp, csharp, definitions, file, receiver, name);
        if !member_candidates.is_empty() {
            return (member_candidates, TypeLookupTargetKind::ValueExpression);
        }
        return (
            csharp_logical_visible_type_candidates(csharp, definitions, file, name),
            TypeLookupTargetKind::TypeReference,
        );
    }
    (
        csharp_receiver_types(
            csharp as &dyn IAnalyzer,
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
                    file,
                    &owner,
                    member_name,
                    session,
                ),
                None => csharp_member_declared_type_fq_name(csharp, file, &owner, member_name),
            }?;
            csharp_type_candidates_resolution(csharp_node_text(name, source), definitions.fqn(&fqn))
        }
        _ => {
            let name_text = csharp_node_text(name, source);
            let bindings = csharp_type_bindings_before_scoped(
                csharp,
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
        csharp_visible_type_output_candidates(csharp, definitions, file, reference),
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
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_type_active_path(
        csharp,
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

    let Some(owner) = csharp_enclosing_class(
        csharp as &dyn IAnalyzer,
        definitions,
        file,
        identifier.start_byte(),
    ) else {
        return false;
    };
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
                        !name.is_absolute() && matches!(name.path(), [name] if name == "dynamic")
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

fn csharp_seed_type_active_path(
    csharp: &CSharpAnalyzer,
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
            csharp_seed_type_binding(node, csharp, definitions, file, source, bindings);
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

fn csharp_seed_symbol_for_type(
    name: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let binding_name = csharp_node_text(name, source);
    let reference = csharp_reference_type_text(type_node, source);
    let candidates = csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
    if candidates.is_empty() {
        bindings.declare_shadow(binding_name);
    } else {
        bindings.seed_symbol_many(binding_name, candidates);
    }
}

pub(super) fn parse_csharp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
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

    let original = node;
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !definitions.scope_step() {
            return None;
        }
        if (matches!(parent.kind(), "generic_name" | "qualified_name")
            && parent.start_byte() <= current.start_byte()
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
        "qualified_name" | "generic_name" | "nullable_type" | "array_type" => {
            Some(CSharpReferenceNode::Type(current))
        }
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
    if definitions.using_aliases(file).contains_key(&reference) {
        return csharp_type_outcome(
            analyzer,
            csharp,
            definitions,
            file,
            &reference,
            type_node.start_byte(),
        );
    }
    let owners = csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
    let mut constructors = Vec::new();
    for owner in &owners {
        constructors.extend(definitions.members_for_owner_name(
            &owner.fq_name(),
            crate::analyzer::csharp_source_identifier(owner),
        ));
    }
    sort_units(&mut constructors);
    constructors.dedup();
    let applicable = csharp_filter_candidates_by_arity(
        csharp,
        definitions,
        &constructors,
        Some(csharp_argument_count(creation, source)),
    );
    if !applicable.is_empty() {
        return candidates_outcome(applicable);
    }
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    csharp_type_outcome(
        analyzer,
        csharp,
        definitions,
        file,
        &reference,
        type_node.start_byte(),
    )
}

fn csharp_type_outcome(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
) -> DefinitionLookupOutcome {
    let mut candidates =
        csharp_visible_type_output_candidates(csharp, definitions, file, reference);
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
    if csharp_import_boundary_for_type(csharp, definitions, file, reference) {
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# type"),
    )
}

fn csharp_attribute_outcome(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let names = csharp_attribute_type_names(name, source);
    let (candidates, ambiguous_spelling) = definitions.attribute_type_candidates(file, &names);
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
    if csharp_attribute_alias_boundary(csharp, definitions, file, name, source)
        || names
            .iter()
            .any(|name| csharp_import_boundary_for_type(csharp, definitions, file, name))
    {
        let reference = names.first().map(String::as_str).unwrap_or_default();
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    let reference = names.first().map(String::as_str).unwrap_or_default();
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# attribute type"),
    )
}

fn csharp_attribute_alias_boundary(
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
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
            return definitions
                .using_aliases(file)
                .get(alias)
                .is_some_and(|target| {
                    !definitions.type_exists(target) && !definitions.package_exists(target)
                });
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn csharp_member_outcome(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
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

    let mut direct_candidates = Vec::new();
    let mut seen_owner_fqns = HashSet::default();
    for owner in &owners {
        if !definitions.scope_step() {
            break;
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
                direct_candidates.extend(csharp_non_constructor_member_candidates(
                    analyzer,
                    definitions,
                    &part,
                    member,
                ));
            }
        }
    }
    sort_units(&mut direct_candidates);
    direct_candidates.dedup();
    let direct_candidates = csharp_filter_candidates_by_generic_arity(
        definitions,
        &direct_candidates,
        explicit_generic_arity,
    );
    let applicable =
        csharp_filter_candidates_by_arity(analyzer, definitions, &direct_candidates, arity);
    if !applicable.is_empty() {
        return candidates_outcome(applicable);
    }
    let mut fallback_candidates = direct_candidates;

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = Vec::new();
        for owner in owners {
            if !definitions.scope_step() {
                break;
            }
            seen.insert(owner.clone());
            level.extend(definitions.direct_ancestors(provider, &owner));
        }
        while !level.is_empty() {
            if !definitions.scope_step() {
                break;
            }
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !definitions.scope_step() {
                    break;
                }
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates.extend(csharp_non_constructor_member_candidates(
                    analyzer,
                    definitions,
                    &ancestor,
                    member,
                ));
                next_level.extend(definitions.direct_ancestors(provider, &ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let level_candidates = csharp_filter_candidates_by_generic_arity(
                definitions,
                &level_candidates,
                explicit_generic_arity,
            );
            let applicable =
                csharp_filter_candidates_by_arity(analyzer, definitions, &level_candidates, arity);
            if !applicable.is_empty() {
                return candidates_outcome(applicable);
            }
            if fallback_candidates.is_empty() && !level_candidates.is_empty() {
                fallback_candidates = level_candidates;
            }
            level = next_level;
        }
    }
    if !fallback_candidates.is_empty() {
        return if fallback_when_inapplicable {
            candidates_outcome(fallback_candidates)
        } else {
            no_definition(
                "no_applicable_overload",
                format!("no C# member `{member}` overload accepts this call"),
            )
        };
    }
    no_definition(
        "no_indexed_definition",
        format!("C# member `{member}` is not indexed as a definition"),
    )
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

fn csharp_object_initializer_label_outcome(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    label: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let initializer = csharp_object_initializer_for_label(label)?;
    let Some(type_node) = csharp_object_initializer_owner_type_node(initializer) else {
        return Some(no_definition(
            "unknown_object_initializer_owner",
            "C# object initializer target type could not be inferred",
        ));
    };
    let type_name = csharp_reference_type_text(type_node, source);
    let mut owners = csharp_logical_visible_type_candidates(csharp, definitions, file, &type_name);
    if owners.len() != 1 {
        return Some(no_definition(
            "ambiguous_object_initializer_owner",
            format!("C# object initializer target type `{type_name}` is not uniquely resolved"),
        ));
    }
    let owner = owners.remove(0);
    Some(csharp_member_outcome(
        analyzer,
        definitions,
        vec![owner],
        csharp_node_text(label, source),
        None,
        None,
        true,
    ))
}

fn csharp_is_unqualified_member_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
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
            | "property_declaration"
            | "parameter"
            | "using_directive"
    )
}

fn csharp_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates.to_vec();
    };
    let applicable: Vec<_> = candidates
        .iter()
        .filter_map(|unit| {
            if !definitions.scope_step() {
                return None;
            }
            if !unit.is_function() {
                return None;
            }
            let callable_arity = definitions
                .query(|| csharp_callable_arity(analyzer, unit))
                .unwrap_or_else(|| crate::analyzer::CallableArity::exact(0));
            callable_arity
                .accepts(expected)
                .then(|| (unit.clone(), callable_arity))
        })
        .collect();
    applicable.into_iter().map(|(unit, _)| unit).collect()
}

fn csharp_filter_candidates_by_generic_arity(
    definitions: &CSharpDefinitionProvider<'_>,
    candidates: &[CodeUnit],
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    candidates
        .iter()
        .filter(|unit| {
            if !definitions.scope_step() {
                return false;
            }
            explicit_generic_arity.is_none_or(|arity| {
                unit.is_function() && csharp_method_generic_arity(unit.signature()) == arity
            })
        })
        .cloned()
        .collect()
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

fn csharp_receiver_types(
    analyzer: &dyn IAnalyzer,
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

    let mut receiver_types = match program.base {
        CSharpReceiverBase::Expression(base) => {
            csharp_receiver_base_types(analyzer, csharp, definitions, file, source, root, base)
        }
        CSharpReceiverBase::EnclosingType { byte } => CSharpReceiverTypes::from_units(
            csharp_enclosing_class(analyzer, definitions, file, byte)
                .into_iter()
                .collect(),
        ),
    };
    if !definitions.observe_cancellation() {
        return CSharpReceiverTypes::default();
    }

    let mut first_transition = 0usize;
    if receiver_types.units.is_empty()
        && let CSharpReceiverBase::Expression(base) = program.base
        && !csharp_receiver_base_is_shadowed(csharp, definitions, file, source, root, base)
    {
        if !definitions.scope_step() {
            return CSharpReceiverTypes::default();
        }
        let expression_type = csharp_reference_type_text(receiver, source);
        let direct_types =
            csharp_logical_visible_type_candidates(csharp, definitions, file, &expression_type);
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
            let candidates =
                csharp_logical_visible_type_candidates(csharp, definitions, file, &type_name);
            if !candidates.is_empty() {
                receiver_types = CSharpReceiverTypes::from_units(candidates);
                first_transition = index + 1;
                break;
            }
        }
    }

    for transition in &program.transitions[first_transition..] {
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
    receiver_types.normalized()
}

#[allow(clippy::too_many_arguments)]
fn csharp_receiver_base_types(
    analyzer: &dyn IAnalyzer,
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
                    definitions,
                    file,
                    source,
                    root,
                    receiver.start_byte(),
                );
                let mut receiver_types = CSharpReceiverTypes::default();
                if let Some(fqn) = first_precise(&legacy, name) {
                    receiver_types.push_fq_name(definitions, fqn);
                }
                receiver_types
            } else {
                let mut receiver_types = csharp_enclosing_member_types(
                    analyzer,
                    csharp,
                    definitions,
                    file,
                    receiver,
                    name,
                );
                if receiver_types.units.is_empty() && receiver_types.fq_names.is_empty() {
                    receiver_types = CSharpReceiverTypes::from_units(
                        csharp_logical_visible_type_candidates(csharp, definitions, file, name),
                    );
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
                .and_then(|owner| csharp_usage_direct_base(analyzer, csharp, &owner))
                .into_iter()
                .collect(),
        ),
        "qualified_name" | "alias_qualified_name" | "generic_name" => {
            CSharpReceiverTypes::from_units(csharp_logical_visible_type_candidates(
                csharp,
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
                    definitions,
                    file,
                    &current,
                    name,
                    &mut level_types,
                );
                if let Some(provider) = provider {
                    next_level.extend(definitions.direct_ancestors(provider, &current));
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
    let explicit_type_arguments =
        csharp_resolved_type_arguments(csharp, definitions, file, source, name.type_arguments);
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
            let mut candidates =
                csharp_logical_visible_type_candidates(csharp, definitions, file, &reference);
            (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
        })
        .collect()
}

fn csharp_enclosing_member_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    csharp_enclosing_member_types(analyzer, csharp, definitions, file, receiver, name).units
}

fn csharp_enclosing_member_types(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> CSharpReceiverTypes {
    if !definitions.scope_step() {
        return CSharpReceiverTypes::default();
    }
    let Some(owner) = csharp_enclosing_class(analyzer, definitions, file, receiver.start_byte())
    else {
        return CSharpReceiverTypes::default();
    };
    let mut candidates = CSharpReceiverTypes::default();
    csharp_collect_member_types(csharp, definitions, file, &owner, name, &mut candidates);
    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut stack = definitions.direct_ancestors(provider, &owner);
        while let Some(ancestor) = stack.pop() {
            if !definitions.scope_step() {
                return CSharpReceiverTypes::default();
            }
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            csharp_collect_member_types(
                csharp,
                definitions,
                file,
                &ancestor,
                name,
                &mut candidates,
            );
            stack.extend(definitions.direct_ancestors(provider, &ancestor));
        }
    }
    candidates.normalized()
}

fn csharp_collect_member_types(
    csharp: &CSharpAnalyzer,
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
        Some(session) => {
            csharp_member_declared_type_fq_name_in_session(csharp, file, owner, name, session)
        }
        None => csharp_member_declared_type_fq_name(csharp, file, owner, name),
    };
    if let Some(type_fqn) = type_fqn {
        candidates.push_fq_name(definitions, type_fqn);
    }
}

fn csharp_visible_type_output_candidates(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, definitions, file, name);
    csharp.sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_logical_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp_visible_type_candidates(csharp, definitions, file, name);
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn csharp_visible_type_candidates(
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    definitions.visible_type_candidates(file, name)
}

fn csharp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    if definitions.session().is_some() {
        let range = Range {
            start_byte: byte,
            end_byte: byte.saturating_add(1),
            start_line: 0,
            end_line: 0,
        };
        let mut current =
            definitions.query_optional(|| analyzer.enclosing_code_unit(file, &range))?;
        while !current.is_class() {
            current = definitions.parent_of(analyzer, &current)?;
        }
        return Some(current);
    }
    if let Some(unit) = ClassRangeIndex::build(analyzer, file).enclosing_unit(byte) {
        return Some(unit.clone());
    }

    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: 0,
        end_line: 0,
    };
    let mut current = analyzer.enclosing_code_unit(file, &range)?;
    loop {
        if current.is_class() {
            return Some(current);
        }
        current = analyzer.parent_of(&current)?;
    }
}

fn resolve_csharp_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
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
    let mut scope = definitions
        .query_optional(|| analyzer.enclosing_code_unit(file, &range))?
        .fq_name();
    loop {
        if scope.is_empty() || !definitions.scope_step() {
            return None;
        }
        let child_fqn = format!("{scope}.{name}");
        if let Some(child) = definitions
            .fqn(&child_fqn)
            .into_iter()
            .find(CodeUnit::is_class)
        {
            return Some(child);
        }
        match scope.rfind('.') {
            Some(index) => scope.truncate(index),
            None => return None,
        }
    }
}

fn resolve_csharp_nested_type_in_enclosing_classes(
    analyzer: &dyn IAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }
    let mut enclosing = csharp_enclosing_class(analyzer, definitions, file, byte)?;
    loop {
        if !definitions.scope_step() {
            return None;
        }
        let child_fqn = format!("{}.{}", enclosing.fq_name(), name);
        if let Some(child) = definitions
            .fqn(&child_fqn)
            .into_iter()
            .find(CodeUnit::is_class)
        {
            return Some(child);
        }
        let parent = definitions.parent_of(analyzer, &enclosing)?;
        if !parent.is_class() {
            return None;
        }
        enclosing = parent;
    }
}

fn csharp_import_boundary_for_type(
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if csharp_alias_using_boundary_for_type(csharp, definitions, file, reference) {
        return true;
    }
    let simple = reference.rsplit('.').next().unwrap_or(reference);
    definitions
        .using_namespaces(file)
        .into_iter()
        .any(|namespace| {
            !definitions.package_exists(&namespace)
                && (reference == simple || reference.starts_with(&format!("{namespace}.")))
        })
}

fn csharp_alias_using_boundary_for_type(
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    definitions
        .using_aliases(file)
        .get(reference)
        .is_some_and(|target| !definitions.type_exists(target))
}

fn csharp_static_using_boundary_for_member(
    _csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
) -> bool {
    definitions.import_statements(file).iter().any(|raw| {
        raw.trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_end_matches(';')
            .trim()
            .strip_prefix("static ")
            .is_some_and(|target| !definitions.type_exists(target.trim()))
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
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_legacy_active_path(
        root,
        cutoff_start,
        csharp,
        definitions,
        file,
        source,
        &mut bindings,
    );
    bindings
}

fn csharp_seed_legacy_active_path(
    root: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    definitions: &CSharpDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
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
        let outcome = resolve_csharp_bounded(
            fixture.analyzer.analyzer(),
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
        let outcome = resolve_csharp_bounded(
            fixture.analyzer.analyzer(),
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
        assert!(definitions.using_namespaces(&file).is_empty());
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
        let proven = csharp
            .declaration_candidates_by_fqn("Demo.ProvenAttribute", false)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("proven attribute");
        let unknown = csharp
            .declaration_candidates_by_fqn("Demo.UnknownAttribute", false)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("unknown attribute");

        let proven_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let proven_definitions = CSharpDefinitionProvider::bounded(csharp, &proven_session);
        assert_eq!(
            proven_definitions.attribute_class_is_applicable(&proven),
            Some(true)
        );
        assert!(matches!(
            proven_session.finish(()),
            BoundedResolution::Complete { .. }
        ));

        let unknown_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let unknown_definitions = CSharpDefinitionProvider::bounded(csharp, &unknown_session);
        assert_eq!(
            unknown_definitions.attribute_class_is_applicable(&unknown),
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
        let outcome = resolve_csharp_bounded(
            fixture.analyzer.analyzer(),
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
