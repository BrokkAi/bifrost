use super::*;
use crate::analyzer::{GlobalUsageDefinitionIndex, SignatureMetadata, StructuredTypeIdentity};
use tree_sitter::Tree;

pub(crate) trait GoDefinitionProvider {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_prefix_exists(&self, prefix: &str) -> bool;
    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        self.fqn(&format!("{owner_fqn}.{name}"))
    }
    fn import_infos(&self, go: &GoAnalyzer, file: &ProjectFile) -> Vec<ImportInfo> {
        go.import_info_of(file)
    }
    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        analyzer.signature_metadata(unit)
    }
    fn raw_supertypes(&self, go: &GoAnalyzer, unit: &CodeUnit) -> Vec<String> {
        go.raw_supertypes(unit)
    }
    fn scope_step(&self) -> bool {
        true
    }
    fn summary_step(&self) -> bool {
        true
    }
    fn session(&self) -> Option<&ResolutionSession> {
        None
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }
}

impl GoDefinitionProvider for GlobalUsageDefinitionIndex {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        GlobalUsageDefinitionIndex::fqn(self, fqn)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        GlobalUsageDefinitionIndex::fqn_prefix_exists(self, prefix)
    }
}

pub(crate) struct AnalyzerGoDefinitionProvider<'a> {
    analyzer: &'a GoAnalyzer,
    session: Option<&'a ResolutionSession>,
}

impl<'a> AnalyzerGoDefinitionProvider<'a> {
    pub(crate) fn new(analyzer: &'a GoAnalyzer) -> Self {
        Self {
            analyzer,
            session: None,
        }
    }

    pub(crate) fn bounded(analyzer: &'a GoAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            analyzer,
            session: Some(session),
        }
    }
}

impl GoDefinitionProvider for AnalyzerGoDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units: Vec<_> = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.analyzer
                    .declaration_candidates_by_fqn_limited(fqn, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.analyzer.definitions(fqn).collect(),
        };
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.session.is_none()
            && self
                .analyzer
                .workspace_path_index()
                .package_prefix_exists(prefix)
    }

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let mut units = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.analyzer
                    .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.fqn(&format!("{owner_fqn}.{name}")),
        };
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn import_infos(&self, go: &GoAnalyzer, file: &ProjectFile) -> Vec<ImportInfo> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| go.import_info_limited(file, limit))
            }
            None => go.import_info_of(file),
        }
    }

    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.analyzer.signature_metadata_limited(unit, limit)),
            None => analyzer.signature_metadata(unit),
        }
    }

    fn raw_supertypes(&self, go: &GoAnalyzer, unit: &CodeUnit) -> Vec<String> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| go.raw_supertypes_limited(unit, limit))
            }
            None => go.raw_supertypes(unit),
        }
    }

    fn scope_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::scope_step)
    }

    fn summary_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::summary_step)
    }

    fn session(&self) -> Option<&ResolutionSession> {
        self.session
    }
}

fn go_smallest_named_node_covering<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !support.scope_step() || node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.named_children(&mut cursor) {
            if !support.scope_step() {
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

fn go_fqn_candidates(
    support: &dyn GoDefinitionProvider,
    fqns: impl IntoIterator<Item = String>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for fqn in fqns {
        candidates.extend(support.fqn(&fqn));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

pub(super) fn parse_go_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    parser.parse(source, None)
}

pub(crate) fn resolve_go_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "go_analyzer_unavailable",
            "Go analyzer is unavailable",
        ));
    };
    let definitions = AnalyzerGoDefinitionProvider::bounded(go, &session);
    let selector = tree.and_then(|tree| {
        go_selector_descriptor_with_scope(tree.root_node(), site, || definitions.scope_step())
    });
    let outcome = resolve_go(
        analyzer,
        &definitions,
        file,
        source,
        tree,
        site,
        selector.as_ref(),
        None,
    );
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_go(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    selector: Option<&GoSelectorDescriptor<'_>>,
    resolution: Option<GoReferenceResolution>,
) -> DefinitionLookupOutcome {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return no_definition("go_analyzer_unavailable", "Go analyzer is unavailable");
    };
    let reference = selector
        .map(GoSelectorDescriptor::focused_node)
        .map(|node| go_node_text(node, source))
        .unwrap_or(site.text.as_str());
    if let Some(outcome) = tree.and_then(|tree| {
        go_keyed_composite_label_outcome(analyzer, support, file, source, tree.root_node(), site)
    }) {
        return outcome;
    }
    if let Some(selector) = selector
        && selector.focus_segment > 0
        && selector.base_identifier(source).is_none()
    {
        return tree
            .and_then(|tree| {
                resolve_go_local_selector_chain(
                    analyzer,
                    support,
                    file,
                    source,
                    tree.root_node(),
                    site,
                    selector,
                )
            })
            .unwrap_or_else(|| {
                no_definition(
                    "no_indexed_definition",
                    format!("`{reference}` did not resolve to an indexed Go definition"),
                )
            });
    }
    if let Some(resolution) = resolution {
        let candidates = go_fqn_candidates(support, resolution.fqn_candidates);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if resolution.shadowed {
            if let Some(outcome) = tree.and_then(|tree| {
                selector.and_then(|selector| {
                    resolve_go_local_selector_chain(
                        analyzer,
                        support,
                        file,
                        source,
                        tree.root_node(),
                        site,
                        selector,
                    )
                })
            }) {
                return outcome;
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` is shadowed by a local Go binding"),
            );
        }
        if let Some(package) = resolution.resolved_import_packages.first()
            && let Some(selector) = selector
        {
            if selector.focus_segment == 0 {
                return boundary(format!(
                    "`{reference}` is a Go import namespace rather than an indexed declaration"
                ));
            }
            if let Some(outcome) =
                go_package_selector_chain_outcome(support, package, source, selector)
            {
                return outcome;
            }
            if !go_import_path_is_workspace(support, package) {
                return boundary(format!(
                    "`{package}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` is not indexed in Go package `{package}`"),
            );
        }
        if let Some(package) = resolution
            .resolved_import_packages
            .iter()
            .find(|package| !go_import_path_is_workspace(support, package))
        {
            return boundary(format!(
                "`{package}` is outside this partial Go workspace analysis"
            ));
        }
    }

    let package =
        go_package_name(support, file, source, tree.map(Tree::root_node)).unwrap_or_default();
    if let Some(selector) = selector
        && selector.focus_segment > 0
        && let Some(qualifier) = selector.base_identifier(source)
    {
        let name = go_node_text(selector.focused_node(), source);
        let imports = go_import_paths(support, go, file);
        if let Some(import_path) = imports.get(qualifier) {
            if let Some(outcome) =
                go_package_selector_chain_outcome(support, import_path, source, selector)
            {
                return outcome;
            }
            if !go_import_path_is_workspace(support, import_path) {
                return boundary(format!(
                    "`{import_path}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{import_path}`"),
            );
        }
        if let Some(outcome) = tree.and_then(|tree| {
            resolve_go_local_selector_chain(
                analyzer,
                support,
                file,
                source,
                tree.root_node(),
                site,
                selector,
            )
        }) {
            return outcome;
        }
        let candidates = if selector.focus_segment == 1 {
            go_fqn_candidates(support, [format!("{package}.{qualifier}.{name}")])
        } else {
            Vec::new()
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = go_package_member_candidates(support, &package, reference);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let dot_imports = go_dot_import_paths(go, support, file);
    let mut dot_candidates = Vec::new();
    for import_path in &dot_imports {
        if !support.scope_step() {
            break;
        }
        dot_candidates.extend(go_package_member_candidates(
            support,
            import_path,
            reference,
        ));
    }
    sort_units(&mut dot_candidates);
    dot_candidates.dedup();
    if !dot_candidates.is_empty() {
        return candidates_outcome(dot_candidates);
    }
    if let Some(import_path) = dot_imports
        .into_iter()
        .find(|import_path| !go_import_path_is_workspace(support, import_path))
    {
        return boundary(format!(
            "`{import_path}` is outside this partial Go workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Go definition"),
    )
}

/// Resolve a keyed struct-composite label from the literal's structured owner.
///
/// The same `keyed_element` node represents struct labels, map keys, and
/// array/slice indexes in Go. A direct map/array/slice key remains an ordinary
/// expression; only a named literal owner, or a named element/value reached
/// through an elided literal boundary, owns a struct-field label.
fn go_keyed_composite_label_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let selected =
        go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)?;
    let keyed = go_keyed_element_containing_key(support, selected)?;
    let key = keyed.child_by_field_name("key")?;
    let label_node = go_simple_composite_key_identifier(support, key, selected)?;

    let owner_type = go_composite_label_owner_type(support, keyed)?;
    if matches!(owner_type.kind(), "map_type" | "array_type" | "slice_type") {
        return None;
    }

    let label = go_node_text(label_node, source);
    let Some(owner_fqn) = go_resolve_type_fqn(analyzer, support, file, source, owner_type) else {
        return Some(no_definition(
            "go_literal_owner_unresolved",
            format!(
                "could not resolve the exact Go composite-literal owner for field label `{label}`"
            ),
        ));
    };
    let candidates: Vec<_> = support
        .members_for_owner_name(&owner_fqn, label)
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if candidates.is_empty() {
        return Some(no_definition(
            "no_indexed_definition",
            format!("`{label}` is not a direct field of Go literal owner `{owner_fqn}`"),
        ));
    }
    Some(candidates_outcome(candidates))
}

fn go_keyed_element_containing_key<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    let selected_start = node.start_byte();
    let selected_end = node.end_byte();
    loop {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "keyed_element" {
            let key = node.child_by_field_name("key")?;
            return (key.start_byte() <= selected_start && selected_end <= key.end_byte())
                .then_some(node);
        }
        node = node.parent()?;
    }
}

fn go_simple_composite_key_identifier<'tree>(
    support: &dyn GoDefinitionProvider,
    key: Node<'tree>,
    selected: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let identifier = if matches!(key.kind(), "identifier" | "field_identifier") {
        key
    } else if key.kind() == "literal_element" {
        let mut cursor = key.walk();
        let mut children = key.named_children(&mut cursor);
        let child = children.next()?;
        if !support.scope_step() {
            return None;
        }
        if let Some(_extra) = children.next() {
            let _ = support.scope_step();
            return None;
        }
        if !matches!(child.kind(), "identifier" | "field_identifier") {
            return None;
        }
        child
    } else {
        return None;
    };
    (identifier.start_byte() <= selected.start_byte()
        && selected.end_byte() <= identifier.end_byte())
    .then_some(identifier)
}

fn go_composite_label_owner_type<'tree>(
    support: &dyn GoDefinitionProvider,
    keyed: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let mut literal = keyed
        .parent()
        .filter(|parent| parent.kind() == "literal_value")?;
    if !support.scope_step() {
        return None;
    }
    let mut elided_depth = 0usize;
    loop {
        if !support.scope_step() {
            return None;
        }
        let parent = literal.parent()?;
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "composite_literal" => {
                let mut owner = parent.child_by_field_name("type")?;
                for _ in 0..elided_depth {
                    owner = go_composite_container_element_or_value_type(support, owner)?;
                }
                return Some(owner);
            }
            "keyed_element" => {
                let value = parent.child_by_field_name("value")?;
                if value.id() != literal.id() {
                    return None;
                }
                literal = parent
                    .parent()
                    .filter(|ancestor| ancestor.kind() == "literal_value")?;
                if !support.scope_step() {
                    return None;
                }
                elided_depth += 1;
            }
            "literal_value" => {
                literal = parent;
                elided_depth += 1;
            }
            "literal_element" => {
                let container = parent.parent()?;
                if !support.scope_step() {
                    return None;
                }
                literal = match container.kind() {
                    "keyed_element" => {
                        let value = container.child_by_field_name("value")?;
                        if value.id() != parent.id() {
                            return None;
                        }
                        container
                            .parent()
                            .filter(|ancestor| ancestor.kind() == "literal_value")?
                    }
                    "literal_value" => container,
                    _ => return None,
                };
                if !support.scope_step() {
                    return None;
                }
                elided_depth += 1;
            }
            _ => return None,
        }
    }
}

fn go_composite_container_element_or_value_type<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        match node.kind() {
            "array_type" => return node.child_by_field_name("element"),
            "slice_type" => return node.named_child(0),
            "map_type" => return node.child_by_field_name("value"),
            "pointer_type" | "parenthesized_type" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoTypeLookupResolutionKind {
    Expression,
    InterfaceMethodOwner,
}

#[derive(Debug, Clone)]
pub(crate) struct GoTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) kind: GoTypeLookupResolutionKind,
    pub(crate) member_name: Option<String>,
}

pub(crate) fn go_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<GoTypeLookupResolution> {
    let node =
        go_smallest_named_node_covering(support, root, site.focus_start_byte, site.focus_end_byte)?;
    if let Some((fqn, member_name)) =
        go_interface_method_owner_type_fqn(support, file, source, root, node)
    {
        return Some(GoTypeLookupResolution {
            fqn,
            kind: GoTypeLookupResolutionKind::InterfaceMethodOwner,
            member_name: Some(member_name),
        });
    }

    let expression = go_type_lookup_expression(support, node)?;
    let fqn = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        site.range.start_byte,
    )?;
    Some(GoTypeLookupResolution {
        fqn,
        kind: GoTypeLookupResolutionKind::Expression,
        member_name: None,
    })
}

fn go_package_name(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
) -> Option<String> {
    let declared = match root {
        Some(root) => go_declared_package_name(support, root, source)?,
        None if support.session().is_none() => parse_go_tree(source)
            .map(|tree| crate::analyzer::go::determine_go_package_name(tree.root_node(), source))
            .unwrap_or_default(),
        None => return None,
    };
    Some(crate::analyzer::go::packages::canonical_go_package_name(
        file, &declared,
    ))
}

fn go_declared_package_name(
    support: &dyn GoDefinitionProvider,
    root: Node<'_>,
    source: &str,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if !support.scope_step() {
                return None;
            }
            if matches!(package_child.kind(), "package_identifier" | "identifier") {
                return Some(go_node_text(package_child, source).to_string());
            }
        }
    }
    Some(String::new())
}

fn go_import_paths(
    support: &dyn GoDefinitionProvider,
    go: &crate::analyzer::GoAnalyzer,
    file: &ProjectFile,
) -> HashMap<String, String> {
    if support.session().is_none() {
        return go
            .definition_import_namespaces(file)
            .0
            .into_iter()
            .filter_map(|(local, packages)| {
                packages.into_iter().next().map(|package| (local, package))
            })
            .collect();
    }
    support
        .import_infos(go, file)
        .into_iter()
        .filter_map(|import| {
            let local = import.alias.clone().or_else(|| import.identifier.clone())?;
            if local == "_" {
                return None;
            }
            let path = go_structured_import_path(support, &import)?;
            Some((local, path))
        })
        .collect()
}

fn go_structured_import_path(
    support: &dyn GoDefinitionProvider,
    import: &ImportInfo,
) -> Option<String> {
    let path = import.path.as_ref()?;
    if path.kind != Some(crate::analyzer::StructuredImportPathKind::Namespace)
        || path.segments.is_empty()
    {
        return None;
    }
    let mut rendered = String::new();
    for segment in &path.segments {
        if !support.scope_step() || segment.is_empty() {
            return None;
        }
        if !rendered.is_empty() {
            rendered.push('/');
        }
        rendered.push_str(segment);
    }
    Some(rendered)
}

fn go_import_path_is_workspace(support: &dyn GoDefinitionProvider, import_path: &str) -> bool {
    support.fqn_prefix_exists(import_path)
}

fn go_package_member_candidates(
    support: &dyn GoDefinitionProvider,
    package: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.fqn(&format!("{package}.{name}"));
    candidates.extend(support.fqn(&format!(
        "{package}.{}.{name}",
        crate::analyzer::GO_MODULE_SCOPE_SEGMENT
    )));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn go_package_selector_chain_outcome(
    support: &dyn GoDefinitionProvider,
    package: &str,
    source: &str,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment != 1 {
        return None;
    }
    let member = selector.member_name(source, 0)?;
    let candidates = go_package_member_candidates(support, package, member);
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

fn go_dot_import_paths(
    go: &crate::analyzer::GoAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
) -> Vec<String> {
    if support.session().is_none() {
        return go.definition_import_namespaces(file).1;
    }
    support
        .import_infos(go, file)
        .into_iter()
        .filter_map(|import| {
            (import.alias.as_deref() == Some("."))
                .then(|| go_structured_import_path(support, &import))
                .flatten()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_go_local_selector_chain(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    selector: &GoSelectorDescriptor<'_>,
) -> Option<DefinitionLookupOutcome> {
    if selector.focus_segment == 0 {
        return None;
    }

    // Type the chain's structured base node directly. This supports both plain
    // identifiers and expression receivers such as `T{}` or `f()` without
    // reconstructing selector syntax from expanded source text.
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let mut owner_inferred = go_expression_inferred_type(
        analyzer,
        support,
        file,
        source,
        root,
        selector.base,
        site.focus_start_byte,
    );
    let mut owner_fqn = owner_inferred
        .as_ref()
        .and_then(|owner| go_resolve_inferred_type_fqn(support, go, owner))
        .or_else(|| {
            selector.base_identifier(source).and_then(|base| {
                go_binding_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    base,
                    site.focus_start_byte,
                )
            })
        })?;
    let mut deepest_workspace_field = None;
    for (index, member) in selector
        .members
        .iter()
        .take(selector.focus_segment)
        .enumerate()
    {
        if !support.scope_step() {
            return None;
        }
        let member = go_node_text(*member, source);
        let lookup = match owner_inferred.as_ref() {
            Some(owner) => go_indexed_field_lookup_with_method_set(
                analyzer,
                support,
                &owner_fqn,
                member,
                Some(owner),
            ),
            None => go_indexed_field_lookup(analyzer, support, &owner_fqn, member),
        };
        if let GoDefinitionMemberLookup::Ambiguous(candidates) = &lookup {
            return Some(go_ambiguous_selector_outcome(member, candidates.clone()));
        }
        if let GoDefinitionMemberLookup::Unique(candidate) = &lookup {
            deepest_workspace_field = Some(vec![candidate.clone()]);
        }
        if index + 1 == selector.focus_segment {
            return match lookup {
                GoDefinitionMemberLookup::Unique(candidate) => {
                    Some(candidates_outcome(vec![candidate]))
                }
                GoDefinitionMemberLookup::Ambiguous(_) => unreachable!("handled above"),
                GoDefinitionMemberLookup::Missing => deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member)),
            };
        }
        if let Some(owner) = owner_inferred.take() {
            let Some(next_owner) =
                go_field_inferred_type_for_receiver(analyzer, support, &owner, &owner_fqn, member)
            else {
                return deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member));
            };
            let Some(next_owner_fqn) = go_resolve_inferred_type_fqn(support, go, &next_owner)
            else {
                return deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member));
            };
            owner_fqn = next_owner_fqn;
            owner_inferred = Some(next_owner);
        } else {
            let Some(next_owner) = go_indexed_field_type_fqn(analyzer, support, &owner_fqn, member)
            else {
                return deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member));
            };
            owner_fqn = next_owner;
        }
    }
    None
}

fn go_ambiguous_selector_outcome(
    member: &str,
    mut candidates: Vec<CodeUnit>,
) -> DefinitionLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    let mut outcome = ambiguous_definition(format!(
        "`{member}` resolves to multiple Go embedded members at the nearest promotion depth"
    ));
    outcome.definitions = candidates;
    outcome
}

fn go_partial_selector_chain_outcome(
    candidates: Vec<CodeUnit>,
    missing_member: &str,
) -> DefinitionLookupOutcome {
    let mut outcome = candidates_outcome(candidates);
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: PARTIAL_SELECTOR_CHAIN_DIAGNOSTIC_KIND.to_string(),
        message: format!(
            "resolved the deepest indexed Go workspace field before `{missing_member}`"
        ),
    });
    outcome
}

fn go_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    go_receiver_binding_type_fqn(analyzer, support, file, source, root, name, byte)
        .or_else(|| go_local_binding_type_fqn(analyzer, support, file, source, root, name, byte))
}

fn go_receiver_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let type_node = go_receiver_binding_type_node(support, root, source, name, byte)?;
    go_resolve_type_fqn(analyzer, support, file, source, type_node)
}

fn go_receiver_binding_type_node<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<Node<'tree>> {
    let mut current = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if current.kind() == "method_declaration"
            && let Some(receiver) = current.child_by_field_name("receiver")
            && let Some(type_node) = go_parameter_type_for_name(support, receiver, source, name)
        {
            return Some(type_node);
        }
        current = current.parent()?;
    }
}

/// The type a local `name` is bound to, resolved by walking the parsed AST
/// outward from `byte`. Each enclosing scope is searched for the nearest
/// preceding `:=` or `var` declaration of `name`; the innermost match wins, so
/// shadowing is respected. An `if`/`for` initializer is a named child of the
/// statement node we walk through, so those bindings are covered too.
fn go_local_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut scope = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if let Some(binding) = go_nearest_binding_in_scope(support, scope, source, name, byte) {
            return match binding {
                GoLocalBinding::Type(type_node) => {
                    go_resolve_type_fqn(analyzer, support, file, source, type_node)
                }
                GoLocalBinding::Value(value_node) => {
                    go_value_type_fqn(analyzer, support, file, source, root, value_node, byte)
                }
                GoLocalBinding::RangeElement(range_node) => {
                    go_range_binding_type_fqn(analyzer, support, file, source, root, range_node)
                }
            };
        }
        scope = scope.parent()?;
    }
}

/// How a local binding names its type: an explicit `var x T` annotation, or the
/// value expression of an inferred `x := value` binding to derive it from.
enum GoLocalBinding<'tree> {
    Type(Node<'tree>),
    Value(Node<'tree>),
    RangeElement(Node<'tree>),
}

fn go_nearest_binding_in_scope<'tree>(
    support: &dyn GoDefinitionProvider,
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = scope.walk();
    let mut nearest: Option<(usize, GoLocalBinding<'tree>)> = None;
    for child in scope.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.end_byte() > byte {
            continue;
        }
        let binding = match child.kind() {
            "parameter_list" => go_parameter_list_binding(support, child, source, name),
            "short_var_declaration" => go_short_var_binding(support, child, source, name),
            "var_declaration" => go_var_declaration_binding(support, child, source, name),
            "range_clause" => go_range_binding(support, child, source, name),
            _ => None,
        };
        if let Some(binding) = binding
            && nearest
                .as_ref()
                .is_none_or(|(start, _)| child.start_byte() > *start)
        {
            nearest = Some((child.start_byte(), binding));
        }
    }
    nearest.map(|(_, binding)| binding)
}

fn go_parameter_list_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for parameter in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let Some(type_node) = go_parameter_type_for_name(support, parameter, source, name) else {
            continue;
        };
        return Some(GoLocalBinding::Type(type_node));
    }
    None
}

fn go_range_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(support, left, source, name)?;
    (index == 1).then_some(GoLocalBinding::RangeElement(node))
}

fn go_short_var_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(support, left, source, name)?;
    let right = node.child_by_field_name("right")?;
    go_expression_list_item(support, right, index).map(GoLocalBinding::Value)
}

fn go_var_declaration_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        // `var x T` holds a `var_spec` directly; `var ( ... )` wraps each spec.
        let found = if child.kind() == "var_spec" {
            go_var_spec_binding(support, child, source, name)
        } else {
            let mut inner = child.walk();
            let mut found = None;
            for spec in child.named_children(&mut inner) {
                if !support.scope_step() {
                    return None;
                }
                if spec.kind() == "var_spec"
                    && let Some(binding) = go_var_spec_binding(support, spec, source, name)
                {
                    found = Some(binding);
                    break;
                }
            }
            found
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn go_var_spec_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    spec: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let index = go_named_identifier_index(support, spec, source, name)?;
    if let Some(type_node) = spec.child_by_field_name("type") {
        return Some(GoLocalBinding::Type(type_node));
    }
    let value_list = spec.child_by_field_name("value")?;
    go_expression_list_item(support, value_list, index).map(GoLocalBinding::Value)
}

fn go_named_identifier_index(
    support: &dyn GoDefinitionProvider,
    spec: Node<'_>,
    source: &str,
    name: &str,
) -> Option<usize> {
    let mut cursor = spec.walk();
    let mut position = 0usize;
    for child in spec.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if child.kind() != "identifier" {
            continue;
        }
        if go_node_text(child, source).trim() == name {
            return Some(position);
        }
        position += 1;
    }
    None
}

fn go_expression_list_index(
    support: &dyn GoDefinitionProvider,
    list: Node<'_>,
    source: &str,
    name: &str,
) -> Option<usize> {
    let mut cursor = list.walk();
    for (index, child) in list.named_children(&mut cursor).enumerate() {
        if !support.scope_step() {
            return None;
        }
        if go_node_text(child, source).trim() == name {
            return Some(index);
        }
    }
    None
}

fn go_expression_list_item<'tree>(
    support: &dyn GoDefinitionProvider,
    list: Node<'tree>,
    index: usize,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    if list.kind() == "expression_list" {
        let mut cursor = list.walk();
        for (position, child) in list.named_children(&mut cursor).enumerate() {
            if !support.scope_step() {
                return None;
            }
            if position == index {
                return Some(child);
            }
        }
        None
    } else {
        (index == 0).then_some(list)
    }
}

fn go_first_named_child<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).next()?;
    support.scope_step().then_some(child)
}

fn go_last_named_child<'tree>(
    support: &dyn GoDefinitionProvider,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    let mut cursor = node.walk();
    let mut last = None;
    for child in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        last = Some(child);
    }
    last
}

struct GoInferredType {
    identity: StructuredTypeIdentity,
    file: ProjectFile,
    package: String,
    addressable: bool,
}

enum GoTypeInferenceFrame<'tree> {
    Expression {
        node: Node<'tree>,
        reference_byte: usize,
    },
    Field(String),
    Method(String),
    Element,
    MakeAddressable,
    AddressOf,
    Dereference,
    MakeNonAddressable,
}

#[allow(clippy::too_many_arguments)]
fn go_expression_inferred_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<GoInferredType> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let package = go_package_name(support, file, source, Some(root))?;
    let mut frames = vec![GoTypeInferenceFrame::Expression {
        node: expression,
        reference_byte: byte,
    }];
    let mut values = Vec::new();
    let mut active_expressions = HashSet::default();

    while let Some(frame) = frames.pop() {
        if !support.scope_step() {
            return None;
        }
        match frame {
            GoTypeInferenceFrame::Expression {
                node,
                reference_byte,
            } => {
                if !active_expressions.insert((node.id(), reference_byte)) {
                    return None;
                }
                match node.kind() {
                    "identifier" => {
                        let name = go_node_text(node, source);
                        if let Some(type_node) = go_receiver_binding_type_node(
                            support,
                            root,
                            source,
                            name,
                            reference_byte,
                        ) {
                            let mut inferred = go_inferred_type_from_node(
                                support, type_node, file, source, &package,
                            )?;
                            inferred.addressable = true;
                            values.push(inferred);
                            continue;
                        }
                        let binding = go_nearest_visible_binding(
                            support,
                            root,
                            source,
                            name,
                            reference_byte,
                        )?;
                        match binding {
                            GoLocalBinding::Type(type_node) => {
                                let mut inferred = go_inferred_type_from_node(
                                    support, type_node, file, source, &package,
                                )?;
                                inferred.addressable = true;
                                values.push(inferred);
                            }
                            GoLocalBinding::Value(value_node) => {
                                frames.push(GoTypeInferenceFrame::MakeAddressable);
                                frames.push(GoTypeInferenceFrame::Expression {
                                    node: value_node,
                                    reference_byte: value_node.start_byte(),
                                });
                            }
                            GoLocalBinding::RangeElement(range_node) => {
                                let iterable = range_node
                                    .child_by_field_name("right")
                                    .or_else(|| go_last_named_child(support, range_node))?;
                                frames.push(GoTypeInferenceFrame::MakeAddressable);
                                frames.push(GoTypeInferenceFrame::Element);
                                frames.push(GoTypeInferenceFrame::Expression {
                                    node: iterable,
                                    reference_byte: iterable.start_byte(),
                                });
                            }
                        }
                    }
                    "selector_expression" => {
                        let qualifier = go_first_named_child(support, node)?;
                        let field = go_last_named_child(support, node)?;
                        frames.push(GoTypeInferenceFrame::Field(
                            go_node_text(field, source).to_string(),
                        ));
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: qualifier,
                            reference_byte: reference_byte.min(node.start_byte()),
                        });
                    }
                    "call_expression" => {
                        let function = node
                            .child_by_field_name("function")
                            .or_else(|| go_first_named_child(support, node))?;
                        match function.kind() {
                            "identifier" => {
                                let name = go_node_text(function, source);
                                if name == "new"
                                    && let Some(inferred) = go_builtin_new_inferred_type(
                                        support,
                                        file,
                                        source,
                                        root,
                                        node,
                                        reference_byte,
                                        &package,
                                    )
                                {
                                    values.push(inferred);
                                } else {
                                    values.push(go_callable_return_inferred_type(
                                        analyzer,
                                        support,
                                        go_package_member_candidates(support, &package, name),
                                    )?);
                                }
                            }
                            "selector_expression" => {
                                let qualifier = go_first_named_child(support, function)?;
                                let method = go_last_named_child(support, function)?;
                                let method_name = go_node_text(method, source);
                                let imported = (qualifier.kind() == "identifier")
                                    .then(|| {
                                        go_import_paths(support, go, file)
                                            .remove(go_node_text(qualifier, source))
                                    })
                                    .flatten()
                                    .and_then(|import_path| {
                                        go_callable_return_inferred_type(
                                            analyzer,
                                            support,
                                            go_package_member_candidates(
                                                support,
                                                &import_path,
                                                method_name,
                                            ),
                                        )
                                    });
                                if let Some(imported) = imported {
                                    values.push(imported);
                                } else {
                                    frames.push(GoTypeInferenceFrame::Method(
                                        method_name.to_string(),
                                    ));
                                    frames.push(GoTypeInferenceFrame::Expression {
                                        node: qualifier,
                                        reference_byte: reference_byte.min(node.start_byte()),
                                    });
                                }
                            }
                            _ => return None,
                        }
                    }
                    "composite_literal" => {
                        let type_node = node.child_by_field_name("type")?;
                        values.push(go_inferred_type_from_node(
                            support, type_node, file, source, &package,
                        )?);
                    }
                    "index_expression" => {
                        let operand = node
                            .child_by_field_name("operand")
                            .or_else(|| go_first_named_child(support, node))?;
                        frames.push(GoTypeInferenceFrame::Element);
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: operand,
                            reference_byte,
                        });
                    }
                    "parenthesized_expression" => {
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: go_first_named_child(support, node)?,
                            reference_byte,
                        });
                    }
                    "unary_expression" => {
                        let operator = node.child_by_field_name("operator")?.kind();
                        let operand = node
                            .child_by_field_name("operand")
                            .or_else(|| go_first_named_child(support, node))?;
                        frames.push(match operator {
                            "&" => GoTypeInferenceFrame::AddressOf,
                            "*" => GoTypeInferenceFrame::Dereference,
                            _ => GoTypeInferenceFrame::MakeNonAddressable,
                        });
                        frames.push(GoTypeInferenceFrame::Expression {
                            node: operand,
                            reference_byte,
                        });
                    }
                    _ => return None,
                }
            }
            GoTypeInferenceFrame::Field(field) => {
                let owner = values.pop()?;
                let owner_fqn = go_resolve_inferred_type_fqn(support, go, &owner)?;
                values.push(go_field_inferred_type_for_receiver(
                    analyzer, support, &owner, &owner_fqn, &field,
                )?);
            }
            GoTypeInferenceFrame::Method(method) => {
                let owner = values.pop()?;
                let owner_fqn = go_resolve_inferred_type_fqn(support, go, &owner)?;
                values.push(go_callable_return_inferred_type(
                    analyzer,
                    support,
                    go_indexed_member_candidates_for_receiver(
                        analyzer, support, &owner_fqn, &method, &owner,
                    )?,
                )?);
            }
            GoTypeInferenceFrame::Element => {
                let mut iterable = values.pop()?;
                let addressable = iterable.identity.is_slice()
                    || (iterable.identity.is_array() && iterable.addressable);
                iterable.identity = iterable
                    .identity
                    .into_container_element_with(|| support.scope_step())?;
                iterable.addressable = addressable;
                values.push(iterable);
            }
            GoTypeInferenceFrame::MakeAddressable => {
                let mut inferred = values.pop()?;
                inferred.addressable = true;
                values.push(inferred);
            }
            GoTypeInferenceFrame::AddressOf => {
                let mut inferred = values.pop()?;
                inferred.identity = inferred.identity.wrap_pointer()?;
                inferred.addressable = false;
                values.push(inferred);
            }
            GoTypeInferenceFrame::Dereference => {
                let mut inferred = values.pop()?;
                if !inferred.identity.is_pointer() {
                    return None;
                }
                // A dereferenced pointer expression is addressable. Keeping
                // the pointer wrapper is sufficient for nominal-owner and
                // method-set selection; both resolve through the same named
                // type and admit the pointer receiver's method set.
                inferred.addressable = true;
                values.push(inferred);
            }
            GoTypeInferenceFrame::MakeNonAddressable => {
                let mut inferred = values.pop()?;
                inferred.addressable = false;
                values.push(inferred);
            }
        }
    }

    (values.len() == 1).then(|| values.pop()).flatten()
}

fn go_inferred_type_from_node(
    support: &dyn GoDefinitionProvider,
    node: Node<'_>,
    file: &ProjectFile,
    source: &str,
    package: &str,
) -> Option<GoInferredType> {
    Some(GoInferredType {
        identity: crate::analyzer::go::go_structured_type_identity_bounded(node, source, || {
            support.scope_step()
        })?,
        file: file.clone(),
        package: package.to_string(),
        addressable: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn go_builtin_new_inferred_type(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    reference_byte: usize,
    package: &str,
) -> Option<GoInferredType> {
    if go_nearest_visible_binding(support, root, source, "new", reference_byte).is_some()
        || !go_package_member_candidates(support, package, "new").is_empty()
    {
        return None;
    }
    if !support.scope_step() {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut argument = None;
    for child in arguments.named_children(&mut cursor) {
        if !support.scope_step() || argument.replace(child).is_some() {
            return None;
        }
    }
    let type_node = argument?;
    let mut inferred = go_inferred_type_from_node(support, type_node, file, source, package)?;
    inferred.identity = inferred.identity.wrap_pointer()?;
    inferred.addressable = false;
    Some(inferred)
}

fn go_callable_return_inferred_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    candidates: Vec<CodeUnit>,
) -> Option<GoInferredType> {
    let mut inferred = Vec::new();
    for candidate in candidates {
        if !support.scope_step() {
            return None;
        }
        for metadata in support.signature_metadata(analyzer, &candidate) {
            if !support.scope_step() {
                return None;
            }
            let Some(identity) = metadata.into_return_type_identity() else {
                continue;
            };
            let candidate_type = GoInferredType {
                identity,
                file: candidate.source().clone(),
                package: candidate.package_name().to_string(),
                addressable: false,
            };
            let mut duplicate = false;
            for existing in &inferred {
                if go_inferred_types_equal(support, existing, &candidate_type)? {
                    duplicate = true;
                    break;
                }
            }
            if !duplicate {
                inferred.push(candidate_type);
            }
        }
    }
    (inferred.len() == 1).then(|| inferred.pop()).flatten()
}

fn go_inferred_types_equal(
    support: &dyn GoDefinitionProvider,
    left: &GoInferredType,
    right: &GoInferredType,
) -> Option<bool> {
    if left.file != right.file || left.package != right.package {
        return Some(false);
    }
    left.identity
        .structurally_eq_with(&right.identity, || support.scope_step())
}

fn go_field_inferred_type_for_receiver(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner: &GoInferredType,
    owner_fqn: &str,
    field: &str,
) -> Option<GoInferredType> {
    let candidate =
        go_indexed_member_candidate_for_receiver(analyzer, support, owner_fqn, field, owner)?;
    let identity = go_field_unit_type_identity(analyzer, support, &candidate)?;
    Some(GoInferredType {
        identity,
        file: candidate.source().clone(),
        package: candidate.package_name().to_string(),
        addressable: !candidate.is_function() && (owner.addressable || owner.identity.is_pointer()),
    })
}

fn go_resolve_inferred_type_fqn(
    support: &dyn GoDefinitionProvider,
    go: &GoAnalyzer,
    inferred: &GoInferredType,
) -> Option<String> {
    go_resolve_structured_type_fqn(
        support,
        go,
        &inferred.file,
        &inferred.package,
        &inferred.identity,
    )
}

fn go_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    go_expression_type_fqn(analyzer, support, file, source, root, value_node, byte)
}

fn go_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let inferred =
        go_expression_inferred_type(analyzer, support, file, source, root, expression, byte)?;
    go_resolve_inferred_type_fqn(support, go, &inferred)
}

fn go_type_lookup_expression<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        let Some(parent) = node.parent() else {
            return Some(node);
        };
        let node_id = node.id();
        let parent_is_semantic_expression = match parent.kind() {
            "selector_expression" => parent
                .child_by_field_name("field")
                .or_else(|| go_last_named_child(support, parent))
                .is_some_and(|field| field.id() == node_id),
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "composite_literal" => parent
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.id() == node_id),
            "parenthesized_expression" | "unary_expression" => true,
            _ => false,
        };
        if !parent_is_semantic_expression {
            return Some(node);
        }
        node = parent;
    }
}

fn go_interface_method_owner_type_fqn(
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    mut node: Node<'_>,
) -> Option<(String, String)> {
    let selected = node;
    loop {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "method_elem" {
            let method_name = node
                .child_by_field_name("name")
                .or_else(|| go_first_named_child(support, node))?;
            if selected.start_byte() < method_name.start_byte()
                || selected.end_byte() > method_name.end_byte()
            {
                return None;
            }
            let interface = node.parent()?;
            if !support.scope_step() || interface.kind() != "interface_type" {
                return None;
            }
            let type_spec = interface.parent()?;
            if !support.scope_step() || type_spec.kind() != "type_spec" {
                return None;
            }
            let name = type_spec.child_by_field_name("name")?;
            let owner_fqn = go_resolve_type_name_in_package(
                support,
                &go_package_name(support, file, source, Some(root))?,
                go_node_text(name, source),
            )?;
            return Some((owner_fqn, go_node_text(method_name, source).to_string()));
        }
        node = node.parent()?;
    }
}

fn go_range_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    range_node: Node<'_>,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    let right = range_node
        .child_by_field_name("right")
        .or_else(|| go_last_named_child(support, range_node))?;
    // Go's range variables enter scope only after the range expression has
    // been evaluated. Resolve the iterable at its own source position so a
    // same-named range variable cannot resolve the RHS back to itself and
    // create an unbounded type-inference cycle.
    let mut iterable_type = go_expression_inferred_type(
        analyzer,
        support,
        file,
        source,
        root,
        right,
        right.start_byte(),
    )?;
    iterable_type.identity = iterable_type
        .identity
        .into_container_element_with(|| support.scope_step())?;
    go_resolve_inferred_type_fqn(
        support,
        resolve_analyzer::<GoAnalyzer>(analyzer)?,
        &iterable_type,
    )
}

fn go_nearest_visible_binding<'tree>(
    support: &dyn GoDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut scope = go_smallest_named_node_covering(support, root, byte, byte)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if let Some(binding) =
            go_nearest_binding_in_scope(support, scope, source, name.trim(), byte)
        {
            return Some(binding);
        }
        scope = scope.parent()?;
    }
}

fn go_parameter_type_for_name<'tree>(
    support: &dyn GoDefinitionProvider,
    parameter_list: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    if !support.scope_step() {
        return None;
    }
    if parameter_list.kind() == "parameter_declaration" {
        return go_parameter_declaration_type_for_name(support, parameter_list, source, name);
    }
    let mut cursor = parameter_list.walk();
    for parameter in parameter_list.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let type_node = go_parameter_declaration_type_for_name(support, parameter, source, name);
        if type_node.is_some() {
            return type_node;
        }
    }
    None
}

fn go_parameter_declaration_type_for_name<'tree>(
    support: &dyn GoDefinitionProvider,
    parameter: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut names = Vec::new();
    let mut type_node = None;
    let mut inner = parameter.walk();
    for child in parameter.named_children(&mut inner) {
        if !support.scope_step() {
            return None;
        }
        match child.kind() {
            "identifier" => names.push(go_node_text(child, source)),
            _ => type_node = Some(child),
        }
    }
    names.contains(&name).then_some(type_node).flatten()
}

fn go_indexed_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    if let Some((field_unit, identity)) =
        go_indexed_field_type_identity(analyzer, support, owner_fqn, field)
    {
        return go_resolve_structured_type_fqn(
            support,
            go,
            field_unit.source(),
            field_unit.package_name(),
            &identity,
        );
    }
    if support.session().is_some() {
        return None;
    }
    let (field_file, type_text) = go_indexed_field_type(analyzer, support, owner_fqn, field)?;
    go_resolve_go_field_type_fqn(analyzer, support, owner_fqn, &field_file, &type_text)
}

fn go_indexed_field_type_identity(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<(CodeUnit, StructuredTypeIdentity)> {
    let GoDefinitionMemberLookup::Unique(field_unit) =
        go_indexed_field_lookup(analyzer, support, owner_fqn, field)
    else {
        return None;
    };
    go_field_unit_type_identity(analyzer, support, &field_unit)
        .map(|identity| (field_unit, identity))
}

fn go_indexed_field_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> Option<(ProjectFile, String)> {
    if support.session().is_some() {
        return None;
    }
    match go_indexed_field_lookup(analyzer, support, owner_fqn, field) {
        GoDefinitionMemberLookup::Unique(field_unit) => {
            go_field_unit_type_text(analyzer, support, &field_unit, field)
                .map(|type_text| (field_unit.source().clone(), type_text))
        }
        GoDefinitionMemberLookup::Missing | GoDefinitionMemberLookup::Ambiguous(_) => None,
    }
}

enum GoDefinitionMemberLookup {
    Missing,
    Unique(CodeUnit),
    Ambiguous(Vec<CodeUnit>),
}

fn go_indexed_field_lookup(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
) -> GoDefinitionMemberLookup {
    go_indexed_field_lookup_with_method_set(analyzer, support, owner_fqn, field, None)
}

fn go_indexed_member_candidate_for_receiver(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    member: &str,
    receiver: &GoInferredType,
) -> Option<CodeUnit> {
    let GoDefinitionMemberLookup::Unique(candidate) = go_indexed_field_lookup_with_method_set(
        analyzer,
        support,
        owner_fqn,
        member,
        Some(receiver),
    ) else {
        return None;
    };
    Some(candidate)
}

fn go_indexed_member_candidates_for_receiver(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    member: &str,
    receiver: &GoInferredType,
) -> Option<Vec<CodeUnit>> {
    go_indexed_member_candidate_for_receiver(analyzer, support, owner_fqn, member, receiver)
        .map(|candidate| vec![candidate])
}

fn go_indexed_field_lookup_with_method_set(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field: &str,
    receiver: Option<&GoInferredType>,
) -> GoDefinitionMemberLookup {
    struct PromotionPath {
        owner: String,
        pointer_receivers: Option<bool>,
        parent: Option<usize>,
    }

    let root_pointer_receivers =
        receiver.map(|receiver| receiver.identity.is_pointer() || receiver.addressable);
    let mut paths = vec![PromotionPath {
        owner: owner_fqn.to_string(),
        pointer_receivers: root_pointer_receivers,
        parent: None,
    }];
    let mut frontier = vec![0];
    while !frontier.is_empty() {
        let mut candidates = Vec::new();
        for &path_index in &frontier {
            if !support.scope_step() {
                return GoDefinitionMemberLookup::Missing;
            }
            let path = &paths[path_index];
            candidates.extend(
                support
                    .members_for_owner_name(&path.owner, field)
                    .into_iter()
                    .filter(|candidate| {
                        path.pointer_receivers.is_none_or(|pointer_receivers| {
                            go_member_in_method_set(analyzer, support, candidate, pointer_receivers)
                        })
                    }),
            );
        }
        sort_units(&mut candidates);
        match candidates.len() {
            0 => {}
            1 => {
                return GoDefinitionMemberLookup::Unique(
                    candidates
                        .pop()
                        .expect("single Go member candidate was checked"),
                );
            }
            _ => return GoDefinitionMemberLookup::Ambiguous(candidates),
        }
        let mut next = Vec::new();
        for path_index in frontier {
            if !support.summary_step() {
                return GoDefinitionMemberLookup::Missing;
            }
            let owner = paths[path_index].owner.clone();
            let pointer_receivers = paths[path_index].pointer_receivers;
            let embedded: Vec<(String, Option<bool>)> =
                if let Some(pointer_receivers) = pointer_receivers {
                    go_embedded_method_set_types(analyzer, support, &owner, pointer_receivers)
                        .into_iter()
                        .map(|(owner, pointer_receivers)| (owner, Some(pointer_receivers)))
                        .collect()
                } else {
                    go_embedded_field_types(analyzer, support, &owner)
                        .into_iter()
                        .map(|owner| (owner, None))
                        .collect()
                };
            for (embedded_owner, embedded_pointer_receivers) in embedded {
                let mut ancestor = Some(path_index);
                let mut cycle = false;
                while let Some(ancestor_index) = ancestor {
                    if !support.scope_step() {
                        return GoDefinitionMemberLookup::Missing;
                    }
                    let ancestor_path = &paths[ancestor_index];
                    if ancestor_path.owner == embedded_owner {
                        cycle = true;
                        break;
                    }
                    ancestor = ancestor_path.parent;
                }
                if cycle {
                    continue;
                }
                let embedded_index = paths.len();
                paths.push(PromotionPath {
                    owner: embedded_owner,
                    pointer_receivers: embedded_pointer_receivers,
                    parent: Some(path_index),
                });
                next.push(embedded_index);
            }
        }
        frontier = next;
    }
    GoDefinitionMemberLookup::Missing
}

fn go_member_in_method_set(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    candidate: &CodeUnit,
    pointer_receivers: bool,
) -> bool {
    if !candidate.is_function() {
        return true;
    }
    let mut saw_receiver = false;
    for metadata in support.signature_metadata(analyzer, candidate) {
        if !support.scope_step() {
            return false;
        }
        let Some(receiver) = metadata.extension_receiver_type_identity() else {
            continue;
        };
        saw_receiver = true;
        if !receiver.is_pointer() || pointer_receivers {
            return true;
        }
    }
    // Interface methods have no concrete receiver declaration. Their open
    // dispatch remains visible rather than being mistaken for a pointer-only
    // concrete method.
    !saw_receiver
}

fn go_embedded_method_set_types(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    inherited_pointer_receivers: bool,
) -> Vec<(String, bool)> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut embedded = Vec::new();
    for owner in support.fqn(owner_fqn) {
        if !support.scope_step() {
            return Vec::new();
        }
        let mut saw_structured_identity = false;
        for metadata in support.signature_metadata(analyzer, &owner) {
            if !support.scope_step() {
                return Vec::new();
            }
            let Some(identity) = metadata.into_return_type_identity() else {
                continue;
            };
            saw_structured_identity = true;
            let pointer_receivers = inherited_pointer_receivers || identity.is_pointer();
            if let Some(fqn) = go_resolve_structured_type_fqn(
                support,
                go,
                owner.source(),
                owner.package_name(),
                &identity,
            ) {
                embedded.push((fqn, pointer_receivers));
            }
        }
        if saw_structured_identity || support.session().is_some() {
            continue;
        }
        embedded.extend(
            go_embedded_field_types(analyzer, support, owner_fqn)
                .into_iter()
                .map(|fqn| (fqn, inherited_pointer_receivers)),
        );
    }
    embedded.sort();
    embedded.dedup();
    embedded
}

fn go_embedded_field_types(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
) -> Vec<String> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let mut embedded = Vec::new();
    for owner in support.fqn(owner_fqn) {
        if !support.scope_step() {
            return Vec::new();
        }
        if support.session().is_some() {
            for metadata in support.signature_metadata(analyzer, &owner) {
                if !support.scope_step() {
                    return Vec::new();
                }
                let Some(identity) = metadata.into_return_type_identity() else {
                    continue;
                };
                if let Some(fqn) = go_resolve_structured_type_fqn(
                    support,
                    go,
                    owner.source(),
                    owner.package_name(),
                    &identity,
                ) {
                    embedded.push(fqn);
                }
            }
            continue;
        }
        for type_text in support.raw_supertypes(go, &owner) {
            if !support.scope_step() {
                return Vec::new();
            }
            if let Some(fqn) = go_resolve_go_field_type_fqn(
                analyzer,
                support,
                owner_fqn,
                owner.source(),
                &type_text,
            ) {
                embedded.push(fqn);
            }
        }
    }
    embedded.sort();
    embedded.dedup();
    embedded
}

fn go_field_unit_type_identity(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    field_unit: &CodeUnit,
) -> Option<StructuredTypeIdentity> {
    let mut identities: Vec<StructuredTypeIdentity> = Vec::new();
    for metadata in support.signature_metadata(analyzer, field_unit) {
        let Some(identity) = metadata.into_return_type_identity() else {
            continue;
        };
        let mut duplicate = false;
        for existing in &identities {
            if existing.structurally_eq_with(&identity, || support.scope_step())? {
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            identities.push(identity);
        }
    }
    (identities.len() == 1).then(|| identities.pop()).flatten()
}

fn go_field_unit_type_text(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    field_unit: &CodeUnit,
    field: &str,
) -> Option<String> {
    let mut type_texts = support
        .signature_metadata(analyzer, field_unit)
        .into_iter()
        .filter_map(|metadata| metadata.return_type_text().map(str::to_string))
        .collect::<Vec<_>>();
    type_texts.sort();
    type_texts.dedup();
    if type_texts.len() == 1 {
        return type_texts.pop();
    }
    if support.session().is_some() {
        return None;
    }
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(field_unit).first().cloned())?;
    let trimmed = signature.trim();
    if let Some(type_text) = trimmed
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(type_text.to_string());
    }
    let simple = go_simple_type_name(trimmed)?;
    (simple == field).then(|| trimmed.to_string())
}

fn go_resolve_go_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    owner_fqn: &str,
    field_file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if support.session().is_some() {
        return None;
    }
    let (qualifier, name) = go_type_name_parts(type_text)?;
    if qualifier.is_some() {
        return go_resolve_qualified_type_from_file(analyzer, support, field_file, type_text);
    }
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    go_resolve_type_name_in_package(support, package, name)
}

fn go_resolve_structured_type_fqn(
    support: &dyn GoDefinitionProvider,
    go: &GoAnalyzer,
    file: &ProjectFile,
    default_package: &str,
    identity: &StructuredTypeIdentity,
) -> Option<String> {
    let name = identity.nominal_name_with(|| support.scope_step())?;
    match name.path() {
        [name] => go_resolve_exact_type_name_in_package(support, default_package, name),
        [qualifier, name] => {
            let import_path = go_import_paths(support, go, file).remove(qualifier)?;
            let fqn = format!("{import_path}.{name}");
            support.fqn_exists(&fqn).then_some(fqn)
        }
        _ => None,
    }
}

fn go_resolve_qualified_type_from_file(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if support.session().is_some() {
        return None;
    }
    let (Some(qualifier), name) = go_type_name_parts(type_text)? else {
        return None;
    };
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let import_path = go_import_paths(support, go, file).remove(qualifier)?;
    let fqn = format!("{import_path}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_resolve_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<String> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let root = go_syntax_root(support, type_node)?;
    let package = go_package_name(support, file, source, Some(root))?;
    let identity =
        crate::analyzer::go::go_structured_type_identity_bounded(type_node, source, || {
            support.scope_step()
        })?;
    go_resolve_structured_type_fqn(support, go, file, &package, &identity)
}

fn go_syntax_root<'tree>(
    support: &dyn GoDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        let Some(parent) = node.parent() else {
            return Some(node);
        };
        node = parent;
    }
}

fn go_resolve_type_name_in_package(
    support: &dyn GoDefinitionProvider,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let name = go_simple_type_name(type_text)?;
    go_resolve_exact_type_name_in_package(support, package, name)
}

fn go_resolve_exact_type_name_in_package(
    support: &dyn GoDefinitionProvider,
    package: &str,
    name: &str,
) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let fqn = format!("{package}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::model::StructuredTypeIdentityBuilder;
    use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisWork, ReceiverBudgetLimit};
    use crate::analyzer::{Language, Range, StructuredTypeName};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn site_for(
        file: &ProjectFile,
        source: &str,
        expression: &str,
        focus: &str,
    ) -> ResolvedReferenceSite {
        let expression_start = source.rfind(expression).expect("Go expression");
        let relative_focus = expression.find(focus).expect("Go focus");
        let start_byte = expression_start + relative_focus;
        let end_byte = start_byte + focus.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: focus.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn imported_type_fixture(
        import: &str,
        expression: &str,
    ) -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let source =
            format!("package main\n\nimport {import}\n\nfunc use() {{\n    _ = {expression}\n}}\n");
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                (
                    "service/service.go",
                    "package service\n\ntype Service struct{}\n",
                ),
                ("main.go", &source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(&source).expect("Go tree");
        let site = site_for(&file, &source, expression, "Service");
        (fixture, file, source, tree, site)
    }

    #[test]
    fn go_import_declarations_persist_structured_paths() {
        let source = r#"
package main
import (
    svc "example.com/app/service"
    . `example.com/app/model`
)
"#;
        let tree = parse_go_tree(source).expect("Go tree");
        let imports = crate::analyzer::go::collect_go_import_infos(tree.root_node(), source);

        assert_eq!(imports.len(), 2);
        assert_eq!(
            imports[0]
                .path
                .as_ref()
                .map(|path| path.segments.as_slice()),
            Some(["example.com/app/service".to_string()].as_slice())
        );
        assert_eq!(
            imports[1]
                .path
                .as_ref()
                .map(|path| path.segments.as_slice()),
            Some(["example.com/app/model".to_string()].as_slice())
        );
    }

    #[test]
    fn bounded_go_import_alias_and_dot_import_use_structured_paths() {
        for (import, expression) in [
            ("svc \"example.com/app/service\"", "svc.Service{}"),
            (". \"example.com/app/service\"", "Service{}"),
        ] {
            let (fixture, file, source, tree, site) = imported_type_fixture(import, expression);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("bounded Go import lookup should complete: {outcome:#?}");
            };
            assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
            assert!(
                value
                    .definitions
                    .iter()
                    .any(|definition| definition.fq_name() == "example.com/app/service.Service"),
                "{value:#?}"
            );
        }
    }

    fn wide_deep_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    value{index} := {index}\n    _ = value{index}\n"))
            .collect::<String>();
        let expression = format!("{}service{}.Run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "package main\n\ntype Service struct{{}}\nfunc (Service) Run() {{}}\n\nfunc use(service Service) {{\n{statements}    {expression}\n}}\n"
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(&source).expect("Go tree");
        let site = site_for(&file, &source, &expression, "Run");
        (fixture, file, source, tree, site)
    }

    #[test]
    fn bounded_go_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_fixture();
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[test]
    fn bounded_go_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_go_bounded(
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

    #[test]
    fn bounded_go_deep_receiver_wrappers_use_an_explicit_work_stack() {
        let expression = format!("{}service{}.Run()", "(".repeat(512), ")".repeat(512));
        let source = format!(
            "package main\n\ntype Service struct{{}}\nfunc (Service) Run() {{}}\nfunc use(service Service) {{\n    {expression}\n}}\n"
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(&source).expect("Go tree");
        let site = site_for(&file, &source, &expression, "Run");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget {
                context_depth: 8,
                max_targets: 16,
                max_summary_expansions: 4_096,
                max_scope_nodes: 100_000,
            },
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("deep Go receiver lookup should complete: {outcome:#?}");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name() == "main.Service.Run"),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_go_structured_type_walk_charges_each_flat_wrapper() {
        let source = "package main\n\ntype Service struct{}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let go = resolve_analyzer::<GoAnalyzer>(fixture.analyzer.analyzer())
            .expect("fixture Go analyzer");
        let file = ProjectFile::new(fixture.project_root(), "main.go");

        let mut builder = StructuredTypeIdentityBuilder::default();
        let name = StructuredTypeName::new(vec!["Service".to_string()], Vec::new(), false).unwrap();
        let mut root = builder.named(name).unwrap();
        for _ in 0..8 {
            root = builder.pointer(root).unwrap();
        }
        let identity = builder.finish(root).unwrap();

        let complete_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let complete_provider = AnalyzerGoDefinitionProvider::bounded(go, &complete_session);
        let resolved =
            go_resolve_structured_type_fqn(&complete_provider, go, &file, "main", &identity);
        assert!(matches!(
            complete_session.finish(resolved),
            BoundedResolution::Complete {
                value: Some(ref fqn),
                ..
            } if fqn == "main.Service"
        ));

        let tiny_session = ResolutionSession::bounded(ReceiverAnalysisBudget::tiny(), None);
        let tiny_provider = AnalyzerGoDefinitionProvider::bounded(go, &tiny_session);
        let unresolved =
            go_resolve_structured_type_fqn(&tiny_provider, go, &file, "main", &identity);
        assert!(matches!(
            tiny_session.finish(unresolved),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork { scope_nodes: 1, .. },
            }
        ));
    }

    #[test]
    fn bounded_go_uses_structured_return_field_and_container_shapes() {
        let source = r#"package main

import svc "example.com/app/service"

type Holder struct {
    Next *svc.Service
    Items []svc.Service
    ByName map[string]svc.Service
}

func Make() *svc.Service { return nil }
func Similar() string { return "svc.Service" }

func use(holder Holder) {
    holder.Next.Run()
    Make().Run()
    svc.Make().Run()
    holder.Items[0].Run()
    holder.ByName["chosen"].Run()
    for _, service := range holder.Items {
        service.Run()
    }
    Similar().Run()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                (
                    "service/service.go",
                    "package service\n\ntype Service struct{}\nfunc (*Service) Run() {}\nfunc Make() *Service { return nil }\n",
                ),
                ("main.go", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");

        for expression in [
            "holder.Next.Run()",
            "Make().Run()",
            "svc.Make().Run()",
            "holder.Items[0].Run()",
            "service.Run()",
        ] {
            let site = site_for(&file, source, expression, "Run");
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status,
                DefinitionLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert!(
                value.definitions.iter().any(|definition| {
                    definition.fq_name() == "example.com/app/service.Service.Run"
                }),
                "{expression}: {value:#?}"
            );
        }

        let non_addressable_map_element =
            site_for(&file, source, "holder.ByName[\"chosen\"].Run()", "Run");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &non_addressable_map_element,
            ReceiverAnalysisBudget::default(),
            None,
        );
        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "a map element is not addressable and must not claim a pointer-only method: {outcome:#?}"
        );

        let negative = site_for(&file, source, "Similar().Run()", "Run");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &negative,
            ReceiverAnalysisBudget::default(),
            None,
        );
        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "textually similar string return must not become a receiver type: {outcome:#?}"
        );
    }

    #[test]
    fn bounded_go_builtin_new_and_method_sets_respect_addressability() {
        let source = r#"package main

type Service struct{}
func (Service) ValueOnly() {}
func (*Service) PointerOnly() {}

type Embedded struct{}
func (*Embedded) Promoted() {}
type Outer struct{ Embedded }
type OuterPointer struct{ *Embedded }

func MakeValue() Service { return Service{} }
func MakePointer() *Service { return nil }
func MakeOuter() Outer { return Outer{} }
func MakeOuterPointer() OuterPointer { return OuterPointer{} }

func use() {
    var addressable Service
    addressable.PointerOnly()
    new(Service).PointerOnly()
    new(Service).ValueOnly()
    MakePointer().PointerOnly()
    MakeValue().ValueOnly()
    MakeValue().PointerOnly()

    var outer Outer
    outer.Promoted()
    MakeOuter().Promoted()
    MakeOuterPointer().Promoted()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");

        for (expression, member, target) in [
            (
                "addressable.PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "new(Service).PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "new(Service).ValueOnly()",
                "ValueOnly",
                "main.Service.ValueOnly",
            ),
            (
                "MakePointer().PointerOnly()",
                "PointerOnly",
                "main.Service.PointerOnly",
            ),
            (
                "MakeValue().ValueOnly()",
                "ValueOnly",
                "main.Service.ValueOnly",
            ),
            ("outer.Promoted()", "Promoted", "main.Embedded.Promoted"),
            (
                "MakeOuterPointer().Promoted()",
                "Promoted",
                "main.Embedded.Promoted",
            ),
        ] {
            let site = site_for(&file, source, expression, member);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status,
                DefinitionLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert!(
                matches!(value.definitions.as_slice(), [definition] if definition.fq_name() == target),
                "{expression}: {value:#?}"
            );
        }

        for (expression, member) in [
            ("MakeValue().PointerOnly()", "PointerOnly"),
            ("MakeOuter().Promoted()", "Promoted"),
        ] {
            let site = site_for(&file, source, expression, member);
            let outcome = resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            assert!(
                !matches!(
                    outcome,
                    BoundedResolution::Complete {
                        value: DefinitionLookupOutcome {
                            status: DefinitionLookupStatus::Resolved,
                            ..
                        },
                        ..
                    }
                ),
                "non-addressable value receiver must not claim a pointer-only method: {expression}: {outcome:#?}"
            );
        }
    }

    #[test]
    fn bounded_go_shadowed_new_is_not_treated_as_builtin_allocation() {
        let source = r#"package main

type Service struct{}
func (*Service) PointerOnly() {}
func new(value Service) Service { return value }

func use() {
    new(Service{}).PointerOnly()
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let tree = parse_go_tree(source).expect("Go tree");
        let site = site_for(&file, source, "new(Service{}).PointerOnly()", "PointerOnly");
        let outcome = resolve_go_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        assert!(
            !matches!(
                outcome,
                BoundedResolution::Complete {
                    value: DefinitionLookupOutcome {
                        status: DefinitionLookupStatus::Resolved,
                        ..
                    },
                    ..
                }
            ),
            "a package binding named new must shadow the builtin: {outcome:#?}"
        );
    }
}
