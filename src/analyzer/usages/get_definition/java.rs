use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub(crate) enum BoundedJavaResolution<T> {
    Complete {
        value: T,
        work: ReceiverAnalysisWork,
    },
    Exceeded {
        work: ReceiverAnalysisWork,
        limit: ReceiverBudgetLimit,
    },
    Cancelled {
        work: ReceiverAnalysisWork,
    },
}

impl<T> BoundedJavaResolution<T> {
    pub(crate) fn work(&self) -> ReceiverAnalysisWork {
        match self {
            Self::Complete { work, .. }
            | Self::Exceeded { work, .. }
            | Self::Cancelled { work } => *work,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum JavaResolutionStop {
    Exceeded(ReceiverBudgetLimit),
    Cancelled,
}

#[derive(Debug, Clone, Copy, Default)]
struct JavaResolutionState {
    work: ReceiverAnalysisWork,
    stop: Option<JavaResolutionStop>,
}

/// A single bounded lookup view shared by every structured Java resolver
/// expansion in one receiver-compatibility request.
pub(crate) struct JavaResolutionSession<'a> {
    support: &'a dyn BoundedDefinitionLookup,
    budget: Option<ReceiverAnalysisBudget>,
    cancellation: Option<CancellationToken>,
    state: RefCell<JavaResolutionState>,
}

impl<'a> JavaResolutionSession<'a> {
    fn unbounded(support: &'a dyn BoundedDefinitionLookup) -> Self {
        Self {
            support,
            budget: None,
            cancellation: None,
            state: RefCell::new(JavaResolutionState::default()),
        }
    }

    pub(crate) fn bounded(
        support: &'a dyn BoundedDefinitionLookup,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self {
            support,
            budget: Some(budget),
            cancellation: cancellation.cloned(),
            state: RefCell::new(JavaResolutionState::default()),
        }
    }

    pub(crate) fn finish<T>(&self, value: T) -> BoundedJavaResolution<T> {
        self.observe_cancellation();
        let state = *self.state.borrow();
        match state.stop {
            Some(JavaResolutionStop::Exceeded(limit)) => BoundedJavaResolution::Exceeded {
                work: state.work,
                limit,
            },
            Some(JavaResolutionStop::Cancelled) => {
                BoundedJavaResolution::Cancelled { work: state.work }
            }
            None => BoundedJavaResolution::Complete {
                value,
                work: state.work,
            },
        }
    }

    fn observe_cancellation(&self) -> bool {
        if self.budget.is_none() && self.cancellation.is_none() {
            return true;
        }
        let mut state = self.state.borrow_mut();
        if state.stop.is_none()
            && self
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
        {
            state.stop = Some(JavaResolutionStop::Cancelled);
        }
        state.stop.is_none()
    }

    fn charge_scope_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::ScopeNodes)
    }

    fn charge_hierarchy_expansion(&self) -> bool {
        self.charge(ReceiverBudgetLimit::SummaryExpansions)
    }

    fn enclosing_unit(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        byte: usize,
    ) -> Option<CodeUnit> {
        let mut unit = self.query_optional_row(|| {
            analyzer.enclosing_code_unit(
                file,
                &Range {
                    start_byte: byte,
                    end_byte: byte.saturating_add(1),
                    start_line: 0,
                    end_line: 0,
                },
            )
        })?;
        while !unit.is_class() {
            unit = self.parent_of(analyzer, &unit)?;
        }
        Some(unit)
    }

    fn structured_query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        if !self.charge_scope_step() {
            return None;
        }
        let value = query();
        self.observe_cancellation().then_some(value)
    }

    fn query_optional_row<T>(&self, query: impl FnOnce() -> Option<T>) -> Option<T> {
        let row = self.structured_query(query)??;
        self.charge_scope_step().then_some(row)
    }

    fn query_rows<T>(&self, query: impl FnOnce() -> Vec<T>) -> Vec<T> {
        let Some(rows) = self.structured_query(query) else {
            return Vec::new();
        };
        self.track_rows(rows)
    }

    fn track_rows<T>(&self, rows: Vec<T>) -> Vec<T> {
        if self.budget.is_none() && self.cancellation.is_none() {
            return rows;
        }
        for _ in &rows {
            if !self.charge_scope_step() {
                return Vec::new();
            }
        }
        rows
    }

    fn resolve_type_name_in_file(
        &self,
        java: &JavaAnalyzer,
        file: &ProjectFile,
        name: &str,
    ) -> Option<CodeUnit> {
        self.query_optional_row(|| java.resolve_type_name_in_file(file, name))
    }

    fn type_name_resolves_with_external(
        &self,
        java: &JavaAnalyzer,
        file: &ProjectFile,
        name: &str,
    ) -> bool {
        self.query_optional_row(|| java.resolve_type_name_with_external(file, name))
            .is_some()
    }

    fn import_statements(&self, analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<String> {
        self.query_rows(|| analyzer.import_statements(file))
    }

    fn ranges(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<Range> {
        self.query_rows(|| analyzer.ranges(unit))
    }

    fn signatures(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<String> {
        self.query_rows(|| analyzer.signatures(unit))
    }

    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<crate::analyzer::SignatureMetadata> {
        self.query_rows(|| analyzer.signature_metadata(unit))
    }

    fn source(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<String> {
        self.query_optional_row(|| analyzer.get_source(unit, false))
    }

    fn read_source(&self, file: &ProjectFile) -> Option<String> {
        self.query_optional_row(|| file.read_to_string().ok())
    }

    fn parse_java_source(&self, source: &str) -> Option<Tree> {
        self.structured_query(|| parse_java_tree(source)).flatten()
    }

    fn smallest_named_node_covering<'tree>(
        &self,
        mut node: Node<'tree>,
        start: usize,
        end: usize,
    ) -> Option<Node<'tree>> {
        if !self.charge_scope_step() || node.end_byte() < end || node.start_byte() > start {
            return None;
        }
        loop {
            let mut cursor = node.walk();
            let mut containing_child = None;
            for child in node.named_children(&mut cursor) {
                if !self.charge_scope_step() {
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

    fn parent_of(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.charge_hierarchy_expansion() {
            return None;
        }
        let parent = analyzer.parent_of(unit);
        if !self.observe_cancellation() {
            return None;
        }
        let parent = parent?;
        self.charge_scope_step().then_some(parent)
    }

    fn direct_ancestors(
        &self,
        provider: &dyn crate::analyzer::TypeHierarchyProvider,
        unit: &CodeUnit,
    ) -> Vec<CodeUnit> {
        if !self.charge_hierarchy_expansion() {
            return Vec::new();
        }
        let ancestors = provider.get_direct_ancestors(unit);
        if !self.observe_cancellation() {
            return Vec::new();
        }
        self.track_rows(ancestors)
    }

    fn charge(&self, limit: ReceiverBudgetLimit) -> bool {
        if self.budget.is_none() && self.cancellation.is_none() {
            return true;
        }
        if !self.observe_cancellation() {
            return false;
        }
        let Some(budget) = self.budget else {
            return true;
        };
        let mut state = self.state.borrow_mut();
        let (used, maximum) = match limit {
            ReceiverBudgetLimit::ScopeNodes => {
                (&mut state.work.scope_nodes, budget.max_scope_nodes)
            }
            ReceiverBudgetLimit::SummaryExpansions => (
                &mut state.work.summary_expansions,
                budget.max_summary_expansions,
            ),
        };
        if *used == maximum {
            state.stop = Some(JavaResolutionStop::Exceeded(limit));
            false
        } else {
            *used += 1;
            true
        }
    }

    fn bool_query(&self, query: impl FnOnce() -> bool) -> bool {
        self.structured_query(query).unwrap_or(false)
    }
}

impl BoundedDefinitionLookup for JavaResolutionSession<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.query_rows(|| self.support.fqn(fqn))
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        self.query_rows(|| self.support.fqn_in_language(fqn, language))
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.query_rows(|| self.support.file_identifier(file, ident))
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        self.query_rows(|| self.support.fqn_direct_children(fqn))
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        self.bool_query(|| self.support.fqn_exists(fqn))
    }

    fn package_exists(&self, package: &str) -> bool {
        self.bool_query(|| self.support.package_exists(package))
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        self.bool_query(|| self.support.package_exists_in_language(package, language))
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.bool_query(|| self.support.fqn_prefix_exists(prefix))
    }
}

pub(crate) enum JavaTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaMemberLookupKind {
    Field,
    Method,
}

pub(crate) fn java_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<JavaTypeLookupResolution> {
    let session = JavaResolutionSession::unbounded(support);
    java_type_lookup_resolution_in_session(analyzer, &session, file, source, root, site)
}

pub(crate) fn java_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<JavaTypeLookupResolution> {
    if !session.observe_cancellation() {
        return None;
    }
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    let node =
        session.smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    java_type_lookup_node_fqn(analyzer, java, session, file, source, root, node)
}

pub(crate) fn resolve_java(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let session = JavaResolutionSession::unbounded(support);
    match resolve_java_in_session(analyzer, &session, file, source, tree, site) {
        BoundedJavaResolution::Complete { value, .. } => value,
        BoundedJavaResolution::Exceeded { .. } | BoundedJavaResolution::Cancelled { .. } => {
            unreachable!("unbounded Java resolution cannot be interrupted")
        }
    }
}

pub(crate) fn resolve_java_bounded(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedJavaResolution<DefinitionLookupOutcome> {
    let session = JavaResolutionSession::bounded(support, budget, cancellation);
    resolve_java_in_session(analyzer, &session, file, source, tree, site)
}

fn resolve_java_in_session(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> BoundedJavaResolution<DefinitionLookupOutcome> {
    if !session.observe_cancellation() {
        return session.finish(no_definition(
            "java_resolution_cancelled",
            "Java resolution was cancelled",
        ));
    }
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "java_analyzer_unavailable",
            "Java analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_definition(
            "java_parse_failed",
            "Java source could not be parsed",
        ));
    };

    let root = tree.root_node();
    let Some(node) =
        session.smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return session.finish(no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Java definition",
                site.text
            ),
        ));
    };

    if is_java_declaration_or_import_name(node) {
        return session.finish(no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Java reference site", site.text),
        ));
    }

    let outcome = match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            if let Some(creation) = java_enclosing_object_creation(session, node)
                && java_object_creation_focus_is_terminal_type(session, creation, node)
            {
                return session.finish(resolve_java_constructor_call(
                    analyzer, java, session, file, source, creation,
                ));
            }
            resolve_java_type_reference(analyzer, java, session, file, source, node)
        }
        "object_creation_expression" => {
            resolve_java_constructor_call(analyzer, java, session, file, source, node)
        }
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, session, file, source, root, node)
        }
        "method_reference" => {
            resolve_java_method_reference(analyzer, java, session, file, source, root, node)
        }
        "field_access" => resolve_java_field_access(analyzer, session, file, source, root, node),
        "identifier" => {
            if let Some(parent) = node.parent() {
                match parent.kind() {
                    "method_invocation" => {
                        return session.finish(
                            match qualified_access_focus(node, parent, &["object"], &["name"]) {
                                Some(QualifiedAccessFocus::Qualifier) => {
                                    resolve_java_bare_identifier(
                                        analyzer, java, session, file, source, root, node,
                                    )
                                }
                                Some(QualifiedAccessFocus::Member) => {
                                    resolve_java_method_invocation(
                                        analyzer, session, file, source, root, parent,
                                    )
                                }
                                None => resolve_java_bare_identifier(
                                    analyzer, java, session, file, source, root, node,
                                ),
                            },
                        );
                    }
                    "field_access" => {
                        return session.finish(match qualified_access_focus(
                            node,
                            parent,
                            &["object"],
                            &["field"],
                        ) {
                            Some(QualifiedAccessFocus::Qualifier) => resolve_java_bare_identifier(
                                analyzer, java, session, file, source, root, node,
                            ),
                            Some(QualifiedAccessFocus::Member) => resolve_java_field_access(
                                analyzer, session, file, source, root, parent,
                            ),
                            None => no_definition(
                                "unsupported_java_reference_shape",
                                format!(
                                    "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                                    site.text,
                                    node.kind()
                                ),
                            ),
                        });
                    }
                    "method_reference" => {
                        return session.finish(
                            if java_method_reference_receiver_contains_focus(parent, node) {
                                resolve_java_bare_identifier(
                                    analyzer, java, session, file, source, root, node,
                                )
                            } else {
                                resolve_java_method_reference(
                                    analyzer, java, session, file, source, root, parent,
                                )
                            },
                        );
                    }
                    _ => {}
                }
            }
            resolve_java_bare_identifier(analyzer, java, session, file, source, root, node)
        }
        _ => no_definition(
            "unsupported_java_reference_shape",
            format!(
                "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    };
    session.finish(outcome)
}

fn java_type_lookup_node_fqn(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<JavaTypeLookupResolution> {
    if matches!(
        node.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        return java_type_from_node_with_context(analyzer, java, session, file, source, node).map(
            |unit| JavaTypeLookupResolution::Type {
                fqn: unit.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::TypeReference,
            },
        );
    }

    if node.kind() != "identifier" {
        return None;
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "field_access"
            && parent.child_by_field_name("object") == Some(node)
            && let Some(receiver) = java_receiver_type(analyzer, session, file, source, root, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: receiver.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
        if parent.kind() == "method_invocation"
            && parent.child_by_field_name("object") == Some(node)
            && let Some(receiver) = java_receiver_type(analyzer, session, file, source, root, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: receiver.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
        if java_is_callable_declaration_name(parent, node) {
            return Some(JavaTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(declared) =
            java_declaration_name_type(analyzer, java, session, file, source, root, parent, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: declared.fq_name().to_string(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
    }

    let name = java_node_text(node, source);
    java_type_of_identifier_before(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        name,
        node.start_byte(),
    )
    .map(|unit| JavaTypeLookupResolution::Type {
        fqn: unit.fq_name().to_string(),
        target_kind: TypeLookupTargetKind::ValueExpression,
    })
}

fn java_declaration_name_type(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<CodeUnit> {
    match parent.kind() {
        "formal_parameter" | "resource" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(analyzer, java, session, file, source, type_node)
            })
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(name) => {
            let declaration = parent.parent()?;
            if !matches!(
                declaration.kind(),
                "local_variable_declaration" | "field_declaration"
            ) {
                return None;
            }
            declaration
                .child_by_field_name("type")
                .and_then(|type_node| {
                    java_type_from_node_with_context(
                        analyzer, java, session, file, source, type_node,
                    )
                })
        }
        _ => java_type_of_identifier_before(
            analyzer,
            java,
            session,
            file,
            source,
            root,
            java_node_text(name, source),
            name.end_byte(),
        ),
    }
}

pub(super) fn parse_java_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn java_next_named_preorder<'tree>(
    root: Node<'tree>,
    current: Node<'tree>,
    descend: bool,
) -> Option<Node<'tree>> {
    if descend && let Some(child) = current.named_child(0) {
        return Some(child);
    }
    let mut cursor = current;
    loop {
        if cursor.id() == root.id() {
            return None;
        }
        if let Some(sibling) = cursor.next_named_sibling() {
            return Some(sibling);
        }
        cursor = cursor.parent()?;
    }
}

fn is_java_declaration_or_import_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "import_declaration" || parent.kind() == "package_declaration" {
        return true;
    }
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "compact_constructor_declaration"
                | "field_declaration"
                | "variable_declarator"
                | "formal_parameter"
        )
}

fn resolve_java_type_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let raw = java_node_text(node, source);
    let normalized = normalize_java_type_text(raw);
    if normalized.is_empty() {
        return no_definition("no_reference_text", "Java type reference is blank");
    }
    if let Some(outcome) =
        java_explicit_scoped_type_reference(analyzer, java, session, file, source, node)
    {
        return outcome;
    }
    if let Some(unit) =
        java_nested_type_from_context(analyzer, session, file, normalized, node.start_byte())
    {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = session.resolve_type_name_in_file(java, file, normalized) {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = java_qualified_nested_type(analyzer, java, session, file, source, node) {
        return candidates_outcome(vec![unit]);
    }
    if java_import_boundary_for_type(java, session, file, normalized) {
        return boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    )
}

fn java_explicit_scoped_type_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let support: &dyn BoundedDefinitionLookup = session;
    let scoped = java_enclosing_scoped_type_identifier(session, node)?;
    let focused_prefix = source.get(scoped.start_byte()..node.end_byte())?;
    let normalized = normalize_java_type_text(focused_prefix);
    let terminal = normalize_java_type_text(java_node_text(node, source));
    if normalized.is_empty() || normalized == terminal {
        return None;
    }

    if let Some(unit) = session.resolve_type_name_in_file(java, file, normalized) {
        return Some(candidates_outcome(vec![unit]));
    }
    if let Some(unit) = java_qualified_nested_type(analyzer, java, session, file, source, node) {
        return Some(candidates_outcome(vec![unit]));
    }
    if session.type_name_resolves_with_external(java, file, normalized) {
        return Some(boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        )));
    }
    if java_scoped_type_qualifier_resolves_in_source(session, java, file, source, scoped) {
        return Some(no_definition(
            "no_indexed_definition",
            format!("`{normalized}` did not resolve to an indexed Java type"),
        ));
    }
    let qualifier_is_in_workspace = java_scoped_type_qualifier_text(session, scoped, source)
        .is_some_and(|qualifier| java_workspace_package_exists(support, qualifier));
    if java_import_boundary_for_type(java, session, file, normalized) || !qualifier_is_in_workspace
    {
        return Some(boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        )));
    }
    Some(no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    ))
}

fn resolve_java_method_invocation(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = node.child_by_field_name("name") else {
        return no_definition("no_method_name", "Java method invocation has no name");
    };
    let name = java_node_text(name_node, source);
    if name.is_empty() {
        return no_definition("no_method_name", "Java method invocation has a blank name");
    }
    let arity = java_argument_count(node);

    if let Some(object) = node.child_by_field_name("object") {
        if let Some(owner) = java_receiver_type(analyzer, session, file, source, root, object) {
            return java_member_candidates(
                analyzer,
                session,
                &owner,
                name,
                JavaMemberLookupKind::Method,
                true,
                Some(arity),
            );
        }
        return no_definition(
            "unsupported_java_receiver",
            format!("receiver for Java method `{name}` is not resolved"),
        );
    }

    let static_import = java_static_import_candidates(
        analyzer,
        session,
        file,
        name,
        JavaMemberLookupKind::Method,
        Some(arity),
    );
    if static_import.status != DefinitionLookupStatus::NoDefinition
        && static_import
            .definitions
            .iter()
            .any(|unit| java_callable_accepts_arity(analyzer, Some(session), unit, arity))
    {
        return static_import;
    }

    if let Some(owner) = session.enclosing_unit(analyzer, file, name_node.start_byte()) {
        let outcome = java_member_candidates(
            analyzer,
            session,
            &owner,
            name,
            JavaMemberLookupKind::Method,
            true,
            Some(arity),
        );
        if outcome
            .definitions
            .iter()
            .any(|unit| java_callable_accepts_arity(analyzer, Some(session), unit, arity))
        {
            return outcome;
        }
    }

    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    )
}

fn resolve_java_method_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(receiver_node) = java_method_reference_receiver_node(node) else {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has no receiver",
        );
    };
    let receiver_text = java_node_text(receiver_node, source);
    if receiver_text.is_empty() {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has a blank receiver",
        );
    }
    let owner =
        java_receiver_type(analyzer, session, file, source, root, receiver_node).or_else(|| {
            java_type_text_with_context(
                analyzer,
                java,
                session,
                file,
                normalize_java_type_text(receiver_text),
                receiver_node.start_byte(),
            )
        });
    if java_method_reference_is_constructor(session, node) {
        if let Some(owner) = owner {
            return java_constructor_outcome(analyzer, session, owner, None);
        }
        return no_definition(
            "unsupported_java_receiver",
            "receiver for Java constructor reference is not resolved",
        );
    }

    let Some(member_node) = java_method_reference_member_node(session, node) else {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has no member",
        );
    };
    let member = java_node_text(member_node, source);
    if member.is_empty() {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has a blank member",
        );
    }
    if let Some(owner) = owner {
        return java_member_candidates(
            analyzer,
            session,
            &owner,
            member,
            JavaMemberLookupKind::Method,
            true,
            None,
        );
    }

    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java method reference `{member}` is not resolved"),
    )
}

fn java_method_reference_receiver_node(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "method_reference")
        .then(|| node.named_child(0))
        .flatten()
}

fn java_method_reference_member_node<'tree>(
    session: &JavaResolutionSession<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let receiver = java_method_reference_receiver_node(node)?;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor).skip(1) {
        if !session.charge_scope_step() {
            return None;
        }
        if child.id() != receiver.id() && child.kind() == "identifier" {
            return Some(child);
        }
    }
    None
}

fn java_method_reference_is_constructor(
    session: &JavaResolutionSession<'_>,
    node: Node<'_>,
) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !session.charge_scope_step() {
            return false;
        }
        if child.kind() == "new" {
            return true;
        }
    }
    false
}

fn resolve_java_constructor_call(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = node.child_by_field_name("type") else {
        return no_definition("no_indexed_definition", "Java constructor call has no type");
    };
    let owner = java_type_from_node_with_context(analyzer, java, session, file, source, type_node)
        .or_else(|| {
            let raw = java_node_text(type_node, source);
            java_type_text_with_context(
                analyzer,
                java,
                session,
                file,
                normalize_java_type_text(raw),
                type_node.start_byte(),
            )
        });
    if let Some(owner) = owner {
        return java_constructor_outcome(analyzer, session, owner, Some(java_argument_count(node)));
    }
    resolve_java_type_reference(analyzer, java, session, file, source, type_node)
}

fn java_constructor_outcome(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: CodeUnit,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let support: &dyn BoundedDefinitionLookup = session;
    let mut constructors = support.fqn(&format!("{}.{}", owner.fq_name(), owner.identifier()));
    constructors.retain(|unit| unit.is_function() && !unit.is_synthetic());
    constructors = java_filter_candidates_by_arity(analyzer, session, constructors, arity);
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }

    let indexed_owner = support.fqn(&owner.fq_name());
    if indexed_owner.is_empty() {
        candidates_outcome(vec![owner])
    } else {
        candidates_outcome(indexed_owner)
    }
}

fn java_enclosing_object_creation<'tree>(
    session: &JavaResolutionSession<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !session.charge_scope_step() {
            return None;
        }
        if matches!(
            parent.kind(),
            "type_identifier" | "scoped_type_identifier" | "generic_type"
        ) {
            current = parent;
            continue;
        }
        if parent.kind() == "object_creation_expression"
            && parent.child_by_field_name("type") == Some(current)
        {
            return Some(parent);
        }
        return None;
    }
    None
}

fn java_object_creation_focus_is_terminal_type(
    session: &JavaResolutionSession<'_>,
    creation: Node<'_>,
    focus: Node<'_>,
) -> bool {
    let Some(mut terminal) = creation.child_by_field_name("type") else {
        return false;
    };
    loop {
        let next = match terminal.kind() {
            "scoped_type_identifier" => {
                let mut cursor = terminal.walk();
                let mut last = None;
                for child in terminal.named_children(&mut cursor) {
                    if !session.charge_scope_step() {
                        return false;
                    }
                    if !matches!(child.kind(), "annotation" | "marker_annotation") {
                        last = Some(child);
                    }
                }
                last
            }
            "generic_type" => {
                let mut cursor = terminal.walk();
                let mut found = None;
                for child in terminal.named_children(&mut cursor) {
                    if !session.charge_scope_step() {
                        return false;
                    }
                    if child.kind() != "type_arguments" {
                        found = Some(child);
                        break;
                    }
                }
                found
            }
            "annotated_type" => {
                let mut cursor = terminal.walk();
                let mut found = None;
                for child in terminal.named_children(&mut cursor) {
                    if !session.charge_scope_step() {
                        return false;
                    }
                    if !matches!(child.kind(), "annotation" | "marker_annotation") {
                        found = Some(child);
                        break;
                    }
                }
                found
            }
            _ => None,
        };
        let Some(next) = next else {
            break;
        };
        terminal = next;
    }
    node_contains_focus(terminal, focus)
}

fn java_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| java_callable_accepts_arity(analyzer, Some(session), unit, expected))
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn java_arity_candidates(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> Option<Vec<CodeUnit>> {
    let expected = arity?;
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| java_callable_accepts_arity(analyzer, Some(session), unit, expected))
        .cloned()
        .collect();
    (!filtered.is_empty()).then_some(filtered)
}

fn java_callable_accepts_arity(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    unit: &CodeUnit,
    actual: usize,
) -> bool {
    java_signature_metadata(analyzer, session, unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| {
            crate::analyzer::CallableArity::exact(java_signature_arity(unit.signature()))
        })
        .accepts(actual)
}

fn java_argument_count(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .map(|arguments| arguments.named_child_count())
        .unwrap_or(0)
}

fn java_method_reference_receiver_contains_focus(reference: Node<'_>, focus: Node<'_>) -> bool {
    java_method_reference_receiver_node(reference)
        .is_some_and(|receiver| node_contains_focus(receiver, focus))
}

fn resolve_java_field_access(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let support: &dyn BoundedDefinitionLookup = session;
    let Some(field_node) = node.child_by_field_name("field") else {
        return no_definition("no_field_name", "Java field access has no field name");
    };
    let field = java_node_text(field_node, source);
    let Some(object) = node.child_by_field_name("object") else {
        return no_definition("no_field_receiver", "Java field access has no receiver");
    };
    if let Some(owner) = java_receiver_type(analyzer, session, file, source, root, object) {
        let qualified_name = format!("{}.{}", owner.fq_name(), field);
        let has_indexed_field = support.fqn(&qualified_name).iter().any(CodeUnit::is_field);
        if !has_indexed_field && java_field_access_is_selector_receiver(node) {
            let nested_types = support
                .fqn(&qualified_name)
                .into_iter()
                .filter(CodeUnit::is_class)
                .collect::<Vec<_>>();
            if !nested_types.is_empty() {
                return candidates_outcome(nested_types);
            }
        }
        return java_member_candidates(
            analyzer,
            session,
            &owner,
            field,
            JavaMemberLookupKind::Field,
            false,
            None,
        );
    }
    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java field `{field}` is not resolved"),
    )
}

fn java_field_access_is_selector_receiver(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| match parent.kind() {
        "field_access" | "method_invocation" => parent.child_by_field_name("object") == Some(node),
        "method_reference" => true,
        _ => false,
    })
}

fn resolve_java_bare_identifier(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    if let Some(unit) = session.resolve_type_name_in_file(java, file, name) {
        return candidates_outcome(vec![unit]);
    }
    // A bare identifier can be an unqualified field access — resolve it to a
    // field of the enclosing class (or an inherited one), unless the name is
    // bound in the active lexical path. Java resolves these members before
    // considering static imports, including on-demand imports with the same
    // simple name.
    let locally_bound = java_local_binding_before(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        name,
        node.start_byte(),
    );
    if !locally_bound {
        if let Some(owner) = session.enclosing_unit(analyzer, file, node.start_byte()) {
            let outcome = java_member_candidates(
                analyzer,
                session,
                &owner,
                name,
                JavaMemberLookupKind::Field,
                false,
                None,
            );
            if outcome.status != DefinitionLookupStatus::NoDefinition {
                return outcome;
            }
        }
    }
    if locally_bound {
        return no_definition(
            "local_binding",
            format!("`{name}` resolves to a local Java binding"),
        );
    }
    let static_import = java_static_import_candidates(
        analyzer,
        session,
        file,
        name,
        JavaMemberLookupKind::Field,
        None,
    );
    if static_import.status != DefinitionLookupStatus::NoDefinition {
        return static_import;
    }
    if java_import_boundary_for_type(java, session, file, name) {
        return boundary(format!(
            "`{name}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java definition"),
    )
}

fn java_receiver_type(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    java_receiver_type_for_java(analyzer, java, session, file, source, root, object).or_else(|| {
        matches!(object.kind(), "this" | "super")
            .then(|| session.enclosing_unit(analyzer, file, object.start_byte()))
            .flatten()
    })
}

fn java_receiver_type_for_java(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "object_creation_expression" => object.child_by_field_name("type").and_then(|type_node| {
            java_type_from_node_with_context(analyzer, java, session, file, source, type_node)
        }),
        "type_identifier" | "scoped_type_identifier" | "generic_type" | "annotated_type" => {
            let raw = java_node_text(object, source);
            java_type_text_with_context(
                analyzer,
                java,
                session,
                file,
                normalize_java_type_text(raw),
                object.start_byte(),
            )
        }
        "identifier" => {
            let name = java_node_text(object, source);
            java_type_of_identifier_before(
                analyzer,
                java,
                session,
                file,
                source,
                root,
                name,
                object.start_byte(),
            )
            .or_else(|| {
                java_lambda_parameter_type_before(
                    analyzer,
                    java,
                    session,
                    file,
                    source,
                    root,
                    name,
                    object.start_byte(),
                )
            })
            .or_else(|| {
                (!java_identifier_binding_before(session, source, root, name, object.start_byte()))
                    .then(|| session.resolve_type_name_in_file(java, file, name))
                    .flatten()
            })
        }
        // A method-call receiver (`getABC().i`) is typed by the called method's
        // declared return type.
        "method_invocation" => {
            let outcome =
                resolve_java_method_invocation(analyzer, session, file, source, root, object);
            let method_unit = outcome.definitions.into_iter().next()?;
            java_method_return_type_unit(analyzer, java, session, file, source, root, &method_unit)
        }
        "field_access" => {
            let field_node = object.child_by_field_name("field")?;
            let field = java_node_text(field_node, source);
            let receiver = object.child_by_field_name("object")?;
            let owner = java_receiver_type(analyzer, session, file, source, root, receiver)?;
            let qualified_name = format!("{}.{}", owner.fq_name(), field);
            let candidates = session.fqn(&qualified_name);
            if let Some(field_unit) = candidates.iter().find(|unit| unit.is_field()) {
                let type_text =
                    java_field_type_text_from_source(analyzer, Some(session), field_unit)?;
                return session
                    .fqn(&format!("{}.{}", owner.fq_name(), type_text))
                    .into_iter()
                    .find(CodeUnit::is_class)
                    .or_else(|| {
                        java_type_text_with_context(
                            analyzer,
                            java,
                            session,
                            file,
                            normalize_java_type_text(&type_text),
                            object.start_byte(),
                        )
                    });
            }
            candidates.into_iter().find(CodeUnit::is_class)
        }
        _ => None,
    }
}

/// Resolve the class named by a method's declared return type. The return type
/// lives on the method's declaration AST node (the stored signature keeps only
/// the parameter list), so read the `type` field from the declaration — using
/// the current tree when the method is in this file, otherwise re-parsing the
/// method's own file.
fn java_method_return_type_unit(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    method_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let method_range = session.ranges(analyzer, method_unit).first().copied()?;
    let method_file = method_unit.source();
    if method_file == file {
        let type_node = java_return_type_node_covering(session, root, &method_range)?;
        return java_type_from_node_with_context(analyzer, java, session, file, source, type_node);
    }
    let method_source = session.read_source(method_file)?;
    let tree = session.parse_java_source(&method_source)?;
    let type_node = java_return_type_node_covering(session, tree.root_node(), &method_range)?;
    java_type_from_node_with_context(
        analyzer,
        java,
        session,
        method_file,
        &method_source,
        type_node,
    )
}

/// The `type` (return-type) node of the innermost `method_declaration` whose
/// span covers `range`.
fn java_return_type_node_covering<'tree>(
    session: &JavaResolutionSession<'_>,
    root: Node<'tree>,
    range: &Range,
) -> Option<Node<'tree>> {
    let mut result = None;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return None;
        }
        let contains = node.start_byte() <= range.start_byte && node.end_byte() >= range.end_byte;
        if contains
            && node.kind() == "method_declaration"
            && let Some(type_node) = node.child_by_field_name("type")
        {
            result = Some(type_node);
        }
        next = java_next_named_preorder(root, node, contains);
    }
    result
}

fn java_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(
            parent.kind(),
            "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        )
}

/// Resolve the name of a `scoped_type_identifier` (`B.Foo`) by resolving the
/// qualifier (`B`) and finding the nested type `Foo` in it — directly or via a
/// superclass/interface. Handles cases the from-context nested lookup misses,
/// like `class A extends B.Foo`.
fn java_qualified_nested_type(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let parent = node.parent()?;
    if parent.kind() != "scoped_type_identifier" {
        return None;
    }
    let mut cursor = parent.walk();
    let mut qualifier = None;
    for child in parent.named_children(&mut cursor) {
        if !session.charge_scope_step() {
            return None;
        }
        if child.id() != node.id() && child.end_byte() <= node.start_byte() {
            qualifier = Some(child);
            break;
        }
    }
    let qualifier = qualifier?;
    let qualifier_type =
        java_type_from_node_with_context(analyzer, java, session, file, source, qualifier)?;
    let name = java_node_text(node, source);

    let nested = |owner: &CodeUnit| {
        session
            .fqn(&format!("{}.{}", owner.fq_name(), name))
            .into_iter()
            .find(|unit| unit.is_class())
    };
    if let Some(unit) = nested(&qualifier_type) {
        return Some(unit);
    }
    let provider = analyzer.type_hierarchy_provider()?;
    let mut queue = VecDeque::from(session.direct_ancestors(provider, &qualifier_type));
    let mut seen = HashSet::default();
    seen.insert(qualifier_type);
    while let Some(ancestor) = queue.pop_front() {
        if !session.observe_cancellation() {
            return None;
        }
        if !seen.insert(ancestor.clone()) {
            continue;
        }
        if let Some(unit) = nested(&ancestor) {
            return Some(unit);
        }
        queue.extend(session.direct_ancestors(provider, &ancestor));
    }
    None
}

fn java_enclosing_scoped_type_identifier<'tree>(
    session: &JavaResolutionSession<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut current = node;
    loop {
        if !session.charge_scope_step() {
            return None;
        }
        if current.kind() == "scoped_type_identifier" {
            return Some(current);
        }
        let parent = current.parent()?;
        if !matches!(
            parent.kind(),
            "annotated_type" | "generic_type" | "scoped_type_identifier"
        ) {
            return None;
        }
        current = parent;
    }
}

fn java_scoped_type_qualifier_resolves_in_source(
    session: &JavaResolutionSession<'_>,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    scoped: Node<'_>,
) -> bool {
    java_scoped_type_qualifier_text(session, scoped, source)
        .and_then(|qualifier| session.resolve_type_name_in_file(java, file, qualifier))
        .is_some()
}

fn java_scoped_type_qualifier_text<'a>(
    session: &JavaResolutionSession<'_>,
    scoped: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let mut cursor = scoped.walk();
    for child in scoped.named_children(&mut cursor) {
        if !session.charge_scope_step() {
            return None;
        }
        if child.end_byte() < scoped.end_byte() {
            let qualifier = java_node_text(child, source);
            return (!qualifier.is_empty()).then_some(qualifier);
        }
    }
    None
}

fn java_type_from_node_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java_type_text_with_context(
        analyzer,
        java,
        session,
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
        type_node.start_byte(),
    )
}

fn java_type_text_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if normalized.is_empty() {
        return None;
    }
    if !normalized.contains('.')
        && let Some(unit) = java_nested_type_from_context(analyzer, session, file, normalized, byte)
    {
        return Some(unit);
    }
    session.resolve_type_name_in_file(java, file, normalized)
}

fn java_nested_type_from_context(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if normalized.contains('.') || normalized.is_empty() {
        return None;
    }
    let mut owner = session.enclosing_unit(analyzer, file, byte);
    while let Some(current) = owner {
        let child_fqn = format!("{}.{}", current.fq_name(), normalized);
        if let Some(child) = session.fqn(&child_fqn).into_iter().find(CodeUnit::is_class) {
            return Some(child);
        }
        // Packages are module parents in the analyzer graph, not lexical type scopes.
        owner = session
            .parent_of(analyzer, &current)
            .filter(CodeUnit::is_class);
    }
    None
}

fn java_type_of_identifier_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let bindings =
        java_bindings_before_scoped(analyzer, java, session, file, source, root, before_byte);
    first_precise(&bindings, name)
}

const JAVA_TYPE_LOOKUP_SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "compact_constructor_declaration",
    "block",
    "lambda_expression",
    "catch_clause",
    "enhanced_for_statement",
    "for_statement",
    "try_with_resources_statement",
];

fn java_bindings_before_scoped(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    java_bindings_before_scoped_inner(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        cutoff_start,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn java_local_binding_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    cutoff_start: usize,
) -> bool {
    java_bindings_before_scoped_inner(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        cutoff_start,
        false,
    )
    .is_shadowed(name)
}

#[allow(clippy::too_many_arguments)]
fn java_bindings_before_scoped_inner(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
    include_fields: bool,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    java_seed_active_path(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        cutoff_start,
        include_fields,
        &mut bindings,
    );
    bindings
}

#[allow(clippy::too_many_arguments)]
fn java_seed_active_path(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    include_fields: bool,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let root = node;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return;
        }
        if node.start_byte() >= cutoff_start {
            next = java_next_named_preorder(root, node, false);
            continue;
        }
        let enters_scope = JAVA_TYPE_LOOKUP_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            next = java_next_named_preorder(root, node, false);
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
            java_seed_scope_declarations(
                analyzer,
                java,
                session,
                file,
                source,
                node,
                cutoff_start,
                bindings,
            );
        } else {
            java_seed_inline_typed_binding_inner(
                analyzer,
                java,
                session,
                file,
                source,
                node,
                include_fields,
                bindings,
            );
        }

        next = java_next_named_preorder(root, node, true);
    }
}

fn java_seed_scope_declarations(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for parameter in parameters.named_children(&mut cursor) {
                    if !session.charge_scope_step() {
                        return;
                    }
                    if parameter.kind() == "formal_parameter" {
                        java_seed_inline_typed_binding(
                            analyzer, java, session, file, source, parameter, bindings,
                        );
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                java_seed_inline_typed_binding(
                    analyzer, java, session, file, source, parameter, bindings,
                );
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                bindings.declare_shadow(java_node_text(name, source));
            }
        }
        "try_with_resources_statement" => {
            let Some(resources) = node.child_by_field_name("resources") else {
                return;
            };
            let cutoff_in_resources =
                resources.start_byte() <= cutoff_start && cutoff_start < resources.end_byte();
            let cutoff_in_body = node.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= cutoff_start && cutoff_start < body.end_byte()
            });
            if !cutoff_in_resources && !cutoff_in_body {
                return;
            }
            let mut cursor = resources.walk();
            for resource in resources.named_children(&mut cursor) {
                if !session.charge_scope_step() {
                    return;
                }
                if resource.kind() == "resource"
                    && (cutoff_in_body || resource.end_byte() <= cutoff_start)
                {
                    java_seed_typed_name_binding(
                        analyzer, java, session, file, source, resource, bindings,
                    );
                }
            }
        }
        _ => {}
    }
}

fn java_seed_inline_typed_binding(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    java_seed_inline_typed_binding_inner(
        analyzer, java, session, file, source, node, true, bindings,
    );
}

#[allow(clippy::too_many_arguments)]
fn java_seed_inline_typed_binding_inner(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    include_fields: bool,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration"
            if include_fields || node.kind() == "local_variable_declaration" =>
        {
            let resolved = node.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(analyzer, java, session, file, source, type_node)
            });
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !session.charge_scope_step() {
                    return;
                }
                if child.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                let binding_name = java_node_text(name, source);
                if let Some(unit) = resolved.as_ref() {
                    bindings.seed_symbol(binding_name, unit.clone());
                } else {
                    bindings.declare_shadow(binding_name);
                }
            }
        }
        "formal_parameter" => {
            java_seed_typed_name_binding(analyzer, java, session, file, source, node, bindings)
        }
        _ => {}
    }
}

fn java_seed_typed_name_binding(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = java_node_text(name, source);
    if let Some(unit) = node.child_by_field_name("type").and_then(|type_node| {
        java_type_from_node_with_context(analyzer, java, session, file, source, type_node)
    }) {
        bindings.seed_symbol(binding_name, unit);
    } else {
        bindings.declare_shadow(binding_name);
    }
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let type_text = java_lambda_parameter_type_text_before(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        name,
        before_byte,
    )?;
    java_type_text_with_context(
        analyzer,
        java,
        session,
        file,
        normalize_java_type_text(&type_text),
        before_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_text_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let lambda = java_matching_lambda_parameter(session, root, source, name, before_byte)?;
    let invocation = java_ancestor_method_invocation(session, lambda)?;
    let method = invocation
        .child_by_field_name("name")
        .map(|node| java_node_text(node, source))?;
    let object = invocation.child_by_field_name("object")?;
    match method {
        "filter" => {
            if object.kind() == "method_invocation"
                && object
                    .child_by_field_name("name")
                    .is_some_and(|node| java_node_text(node, source) == "stream")
                && let Some(collection) = object.child_by_field_name("object")
            {
                return java_collection_element_type_text(
                    analyzer,
                    java,
                    session,
                    file,
                    source,
                    root,
                    collection,
                    lambda.start_byte(),
                );
            }
            java_collection_element_type_text(
                analyzer,
                java,
                session,
                file,
                source,
                root,
                object,
                lambda.start_byte(),
            )
        }
        "forEach" => java_collection_element_type_text(
            analyzer,
            java,
            session,
            file,
            source,
            root,
            object,
            lambda.start_byte(),
        ),
        _ => None,
    }
}

fn java_matching_lambda_parameter<'tree>(
    session: &JavaResolutionSession<'_>,
    root: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<Node<'tree>> {
    let mut best = None;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return None;
        }
        let contains = node.start_byte() <= before_byte && node.end_byte() >= before_byte;
        if contains
            && node.kind() == "lambda_expression"
            && java_lambda_has_parameter(session, node, source, name, before_byte)
        {
            let span = node.end_byte() - node.start_byte();
            if best
                .map(|current: Node<'_>| span < current.end_byte() - current.start_byte())
                .unwrap_or(true)
            {
                best = Some(node);
            }
        }
        next = java_next_named_preorder(root, node, contains);
    }
    best
}

fn java_lambda_has_parameter(
    session: &JavaResolutionSession<'_>,
    lambda: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut cursor = lambda.walk();
    for child in lambda.named_children(&mut cursor) {
        if !session.charge_scope_step() {
            return false;
        }
        if child.start_byte() >= before_byte {
            continue;
        }
        if child.kind() == "identifier" && java_node_text(child, source) == name {
            return true;
        }
        if matches!(child.kind(), "formal_parameters" | "inferred_parameters") {
            let mut inner = child.walk();
            for parameter in child.named_children(&mut inner) {
                if !session.charge_scope_step() {
                    return false;
                }
                if parameter.kind() == "identifier" && java_node_text(parameter, source) == name {
                    return true;
                }
            }
        }
    }
    false
}

fn java_ancestor_method_invocation<'tree>(
    session: &JavaResolutionSession<'_>,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if !session.charge_scope_step() {
            return None;
        }
        if parent.kind() == "method_invocation" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn java_collection_element_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    if expression.kind() == "method_invocation"
        && expression
            .child_by_field_name("name")
            .is_some_and(|node| java_node_text(node, source) == "values")
        && let Some(object) = expression.child_by_field_name("object")
    {
        let type_text = java_expression_type_text(
            analyzer,
            java,
            session,
            file,
            source,
            root,
            object,
            before_byte,
        )?;
        if !java_is_map_type(&type_text) {
            return None;
        }
        return java_generic_arg(&type_text, 1);
    }
    let type_text = java_expression_type_text(
        analyzer,
        java,
        session,
        file,
        source,
        root,
        expression,
        before_byte,
    )?;
    if !java_is_collection_type(&type_text) {
        return None;
    }
    java_generic_arg(&type_text, 0)
}

#[allow(clippy::too_many_arguments)]
fn java_expression_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = java_node_text(expression, source);
            java_identifier_type_text_before(session, java, file, source, root, name, before_byte)
                .or_else(|| {
                    java_lambda_parameter_type_text_before(
                        analyzer,
                        java,
                        session,
                        file,
                        source,
                        root,
                        name,
                        before_byte,
                    )
                })
        }
        "field_access" => {
            let field_node = expression.child_by_field_name("field")?;
            let field = java_node_text(field_node, source);
            let object = expression.child_by_field_name("object")?;
            let owner = java_receiver_type(analyzer, session, file, source, root, object)?;
            let unit = session
                .fqn(&format!("{}.{}", owner.fq_name(), field))
                .into_iter()
                .next()?;
            let signature = unit
                .signature()
                .map(str::to_string)
                .or_else(|| session.signatures(analyzer, &unit).first().cloned())?;
            java_field_type_text_from_signature(&signature, field)
        }
        "method_invocation" => {
            if expression
                .child_by_field_name("name")
                .is_some_and(|node| java_node_text(node, source) == "values")
                && let Some(object) = expression.child_by_field_name("object")
            {
                let type_text = java_expression_type_text(
                    analyzer,
                    java,
                    session,
                    file,
                    source,
                    root,
                    object,
                    before_byte,
                )?;
                if !java_is_map_type(&type_text) {
                    return None;
                }
                return java_generic_arg(&type_text, 1);
            }
            None
        }
        _ => None,
    }
}

fn java_identifier_type_text_before(
    session: &JavaResolutionSession<'_>,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    collect_java_type_text_binding_before(
        session,
        java,
        file,
        source,
        root,
        name,
        before_byte,
        &mut found,
    );
    found
}

fn collect_java_type_text_binding_before(
    session: &JavaResolutionSession<'_>,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut Option<String>,
) {
    let root = node;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return;
        }
        if node.start_byte() >= before_byte {
            next = java_next_named_preorder(root, node, false);
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = normalize_java_type_text(java_node_text(type_node, source));
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if !session.charge_scope_step() {
                            return;
                        }
                        if child.kind() == "variable_declarator"
                            && let Some(name_node) = child.child_by_field_name("name")
                            && name_node.start_byte() < before_byte
                            && java_node_text(name_node, source) == name
                        {
                            *found = Some(type_text.to_string());
                        }
                    }
                }
            }
            "formal_parameter" | "resource" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                    && let Some(type_node) = node.child_by_field_name("type")
                {
                    *found = Some(
                        normalize_java_type_text(java_node_text(type_node, source)).to_string(),
                    );
                }
            }
            _ => {}
        }
        next = java_next_named_preorder(root, node, true);
    }
    if found.is_none()
        && session
            .resolve_type_name_in_file(java, file, name)
            .is_some()
    {
        *found = Some(name.to_string());
    }
}

fn java_field_type_text_from_signature(signature: &str, field: &str) -> Option<String> {
    let before_initializer = signature.split('=').next().unwrap_or(signature);
    let field_start = before_initializer.rfind(field)?;
    let mut type_text = before_initializer[..field_start].trim();
    for modifier in [
        "public",
        "protected",
        "private",
        "static",
        "final",
        "transient",
        "volatile",
    ] {
        type_text = type_text
            .strip_prefix(modifier)
            .unwrap_or(type_text)
            .trim_start();
    }
    (!type_text.is_empty()).then(|| type_text.to_string())
}

fn java_generic_arg(type_text: &str, index: usize) -> Option<String> {
    let start = type_text.find('<')?;
    let end = type_text.rfind('>')?;
    if end <= start {
        return None;
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut arg_start = start + 1;
    let inner = &type_text[start + 1..end];
    for (offset, ch) in inner.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(inner[arg_start - start - 1..offset].trim().to_string());
                arg_start = start + 1 + offset + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(type_text[arg_start..end].trim().to_string());
    args.get(index).filter(|arg| !arg.is_empty()).cloned()
}

fn java_is_map_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Map")
            | Some("HashMap")
            | Some("LinkedHashMap")
            | Some("NavigableMap")
            | Some("SortedMap")
            | Some("TreeMap")
            | Some("ConcurrentMap")
            | Some("ConcurrentHashMap")
    )
}

fn java_is_collection_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Iterable")
            | Some("Collection")
            | Some("List")
            | Some("ArrayList")
            | Some("LinkedList")
            | Some("Set")
            | Some("HashSet")
            | Some("LinkedHashSet")
            | Some("SortedSet")
            | Some("NavigableSet")
            | Some("Stream")
    )
}

fn java_raw_type_name(type_text: &str) -> Option<String> {
    let raw = type_text
        .trim()
        .split('<')
        .next()
        .unwrap_or(type_text)
        .trim();
    let name = raw.rsplit('.').next().unwrap_or(raw).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn java_identifier_binding_before(
    session: &JavaResolutionSession<'_>,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut found = false;
    collect_java_identifier_binding_before(
        session,
        source,
        root,
        name,
        before_byte,
        true,
        &mut found,
    );
    found
}

fn collect_java_identifier_binding_before(
    session: &JavaResolutionSession<'_>,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    include_fields: bool,
    found: &mut bool,
) {
    if *found {
        return;
    }
    let root = node;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return;
        }
        if node.start_byte() >= before_byte {
            next = java_next_named_preorder(root, node, false);
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration"
                if include_fields || node.kind() == "local_variable_declaration" =>
            {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !session.charge_scope_step() {
                        return;
                    }
                    if child.kind() == "variable_declarator"
                        && let Some(name_node) = child.child_by_field_name("name")
                        && name_node.start_byte() < before_byte
                        && java_node_text(name_node, source) == name
                    {
                        *found = true;
                        return;
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                {
                    *found = true;
                    return;
                }
            }
            _ => {}
        }
        next = java_next_named_preorder(root, node, true);
    }
}

fn java_member_candidates(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
    member: &str,
    kind: JavaMemberLookupKind,
    allow_generated_accessors: bool,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let support: &dyn BoundedDefinitionLookup = session;
    let owner_fqn = owner.fq_name();
    let mut candidates =
        java_filter_member_candidates(support.fqn(&format!("{owner_fqn}.{member}")), kind);
    sort_units(&mut candidates);
    candidates.dedup();
    if let Some(filtered_candidates) = java_arity_candidates(analyzer, session, &candidates, arity)
    {
        return candidates_outcome(filtered_candidates);
    }
    if !candidates.is_empty() && arity.is_none() {
        return candidates_outcome(candidates);
    }
    let mut fallback_candidates = (!candidates.is_empty()).then_some(candidates);

    if allow_generated_accessors {
        let generated_accessor_candidates = java_lombok_accessor_field_candidates_for_arity(
            analyzer,
            support,
            Some(session),
            owner,
            member,
            arity,
        );
        if !generated_accessor_candidates.is_empty() {
            return candidates_outcome(generated_accessor_candidates);
        }
    }

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = session.direct_ancestors(provider, owner);
        seen.insert(owner.clone());
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !session.observe_cancellation() {
                    return no_definition(
                        "java_resolution_interrupted",
                        "Java member hierarchy resolution was interrupted",
                    );
                }
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates.extend(java_filter_member_candidates(
                    support.fqn(&format!("{}.{}", ancestor.fq_name(), member)),
                    kind,
                ));
                next_level.extend(session.direct_ancestors(provider, &ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            if let Some(filtered_level_candidates) =
                java_arity_candidates(analyzer, session, &level_candidates, arity)
            {
                return candidates_outcome(filtered_level_candidates);
            }
            if !level_candidates.is_empty() {
                if arity.is_none() {
                    return candidates_outcome(level_candidates);
                }
                fallback_candidates.get_or_insert(level_candidates);
            }
            level = next_level;
        }
    }
    if let Some(candidates) = fallback_candidates {
        return candidates_outcome(candidates);
    }
    no_definition(
        "no_indexed_definition",
        format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
    )
}

fn java_filter_member_candidates(
    candidates: Vec<CodeUnit>,
    kind: JavaMemberLookupKind,
) -> Vec<CodeUnit> {
    candidates
        .into_iter()
        .filter(|unit| match kind {
            JavaMemberLookupKind::Field => unit.is_field(),
            JavaMemberLookupKind::Method => unit.is_function(),
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaAccessorKind {
    Getter,
    Setter,
}

struct JavaAccessorProperty {
    kind: JavaAccessorKind,
    field_name: String,
    requires_boolean_field: bool,
    arity: usize,
}

pub(crate) fn java_lombok_accessor_field_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    java_lombok_accessor_field_candidates_for_arity(analyzer, support, None, owner, member, None)
}

pub(crate) fn java_lombok_generated_accessor_field_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    member: &str,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    if java_accessor_property(member).is_none() {
        return Vec::new();
    }
    let declared_methods = java_filter_member_candidates(
        support.fqn(&format!("{}.{}", owner.fq_name(), member)),
        JavaMemberLookupKind::Method,
    );
    let declared_method_wins = match arity {
        Some(arity) => declared_methods
            .iter()
            .any(|method| java_callable_accepts_arity(analyzer, None, method, arity)),
        None => !declared_methods.is_empty(),
    };
    if declared_method_wins {
        return Vec::new();
    }
    java_lombok_accessor_field_candidates_for_arity(analyzer, support, None, owner, member, arity)
}

fn java_lombok_accessor_field_candidates_for_arity(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    session: Option<&JavaResolutionSession<'_>>,
    owner: &CodeUnit,
    member: &str,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(accessor) = java_accessor_property(member) else {
        return Vec::new();
    };
    if arity.is_some_and(|arity| arity != accessor.arity) {
        return Vec::new();
    }
    let mut fields: Vec<_> = support
        .fqn(&format!("{}.{}", owner.fq_name(), accessor.field_name))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    sort_units(&mut fields);
    fields.dedup();
    if accessor.requires_boolean_field {
        fields.retain(|field| java_field_is_boolean(analyzer, session, field));
    }
    if fields.is_empty() {
        return Vec::new();
    }

    let owner_has_accessor_annotation =
        java_source(analyzer, session, owner).is_some_and(|source| {
            java_class_source_has_lombok_accessor_annotation(session, &source, accessor.kind)
        });
    if owner_has_accessor_annotation {
        return fields;
    }

    fields
        .into_iter()
        .filter(|field| {
            java_source(analyzer, session, field).is_some_and(|source| {
                java_field_source_has_lombok_accessor_annotation(session, &source, accessor.kind)
            })
        })
        .collect()
}

fn java_accessor_property(member: &str) -> Option<JavaAccessorProperty> {
    let (kind, suffix, requires_boolean_field) = if let Some(suffix) = member.strip_prefix("get") {
        (JavaAccessorKind::Getter, suffix, false)
    } else if let Some(suffix) = member.strip_prefix("is") {
        (JavaAccessorKind::Getter, suffix, true)
    } else if let Some(suffix) = member.strip_prefix("set") {
        (JavaAccessorKind::Setter, suffix, false)
    } else {
        return None;
    };
    if suffix.is_empty()
        || !suffix
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_uppercase())
    {
        return None;
    }
    Some(JavaAccessorProperty {
        kind,
        field_name: java_bean_decapitalize(suffix),
        requires_boolean_field,
        arity: usize::from(kind == JavaAccessorKind::Setter),
    })
}

fn java_field_is_boolean(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    field: &CodeUnit,
) -> bool {
    let signature = field
        .signature()
        .map(str::to_string)
        .or_else(|| java_signatures(analyzer, session, field).first().cloned());
    let type_text = java_field_type_text_from_source(analyzer, session, field).or_else(|| {
        signature.as_deref().and_then(|signature| {
            java_field_type_text_from_signature(signature, field.identifier())
        })
    });
    type_text
        .as_deref()
        .and_then(java_raw_type_name)
        .is_some_and(|raw| matches!(raw.as_str(), "boolean" | "Boolean"))
}

fn java_field_type_text_from_source(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    field: &CodeUnit,
) -> Option<String> {
    let source = java_source(analyzer, session, field)?;
    let wrapped = format!("class __BifrostLombokField {{\n{source}\n}}");
    let tree = java_parse_source(session, &wrapped)?;
    let root = tree.root_node();
    let mut next = Some(root);
    while let Some(node) = next {
        if !java_charge_resolution_scope(session) {
            return None;
        }
        if node.kind() == "field_declaration"
            && let Some(type_node) = node.child_by_field_name("type")
        {
            return Some(java_node_text(type_node, &wrapped).trim().to_string());
        }
        next = java_next_named_preorder(root, node, true);
    }
    None
}

fn java_bean_decapitalize(name: &str) -> String {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    if first.is_ascii_uppercase()
        && chars
            .clone()
            .next()
            .is_some_and(|second| second.is_ascii_uppercase())
    {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len());
    out.push(first.to_ascii_lowercase());
    out.extend(chars);
    out
}

fn java_class_source_has_lombok_accessor_annotation(
    session: Option<&JavaResolutionSession<'_>>,
    source: &str,
    kind: JavaAccessorKind,
) -> bool {
    java_source_declaration_has_lombok_accessor_annotation(
        session,
        source,
        &[
            "class_declaration",
            "record_declaration",
            "enum_declaration",
            "interface_declaration",
        ],
        kind,
    )
}

fn java_field_source_has_lombok_accessor_annotation(
    session: Option<&JavaResolutionSession<'_>>,
    source: &str,
    kind: JavaAccessorKind,
) -> bool {
    if java_source_declaration_has_lombok_accessor_annotation(
        session,
        source,
        &["field_declaration"],
        kind,
    ) {
        return true;
    }
    let wrapped = format!("class __BifrostLombokAccessor {{\n{source}\n}}");
    java_source_declaration_has_lombok_accessor_annotation(
        session,
        &wrapped,
        &["field_declaration"],
        kind,
    )
}

fn java_source_declaration_has_lombok_accessor_annotation(
    session: Option<&JavaResolutionSession<'_>>,
    source: &str,
    declaration_kinds: &[&str],
    kind: JavaAccessorKind,
) -> bool {
    let Some(tree) = java_parse_source(session, source) else {
        return false;
    };
    let root = tree.root_node();
    let mut next = Some(root);
    while let Some(node) = next {
        if !java_charge_resolution_scope(session) {
            return false;
        }
        if declaration_kinds.contains(&node.kind())
            && java_modifiers_have_lombok_accessor_annotation(session, node, source, kind)
        {
            return true;
        }
        next = java_next_named_preorder(root, node, true);
    }
    false
}

fn java_source(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    unit: &CodeUnit,
) -> Option<String> {
    match session {
        Some(session) => session.source(analyzer, unit),
        None => analyzer.get_source(unit, false),
    }
}

fn java_signatures(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    unit: &CodeUnit,
) -> Vec<String> {
    match session {
        Some(session) => session.signatures(analyzer, unit),
        None => analyzer.signatures(unit),
    }
}

fn java_signature_metadata(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    unit: &CodeUnit,
) -> Vec<crate::analyzer::SignatureMetadata> {
    match session {
        Some(session) => session.signature_metadata(analyzer, unit),
        None => analyzer.signature_metadata(unit),
    }
}

fn java_parse_source(session: Option<&JavaResolutionSession<'_>>, source: &str) -> Option<Tree> {
    match session {
        Some(session) => session.parse_java_source(source),
        None => parse_java_tree(source),
    }
}

fn java_charge_resolution_scope(session: Option<&JavaResolutionSession<'_>>) -> bool {
    session.is_none_or(JavaResolutionSession::charge_scope_step)
}

fn java_modifiers_have_lombok_accessor_annotation(
    session: Option<&JavaResolutionSession<'_>>,
    declaration: Node<'_>,
    source: &str,
    kind: JavaAccessorKind,
) -> bool {
    let Some(modifiers) = java_named_child_by_kind(session, declaration, "modifiers") else {
        return false;
    };
    let mut cursor = modifiers.walk();
    for child in modifiers.named_children(&mut cursor) {
        if !java_charge_resolution_scope(session) {
            return false;
        }
        if matches!(child.kind(), "annotation" | "marker_annotation")
            && java_annotation_short_name(child, source)
                .is_some_and(|name| java_lombok_annotation_generates_accessor(&name, kind))
        {
            return true;
        }
    }
    false
}

fn java_named_child_by_kind<'tree>(
    session: Option<&JavaResolutionSession<'_>>,
    node: Node<'tree>,
    kind: &str,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !java_charge_resolution_scope(session) {
            return None;
        }
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

fn java_annotation_short_name(annotation: Node<'_>, source: &str) -> Option<String> {
    let raw = if let Some(name_node) = annotation.child_by_field_name("name") {
        java_node_text(name_node, source)
    } else {
        java_node_text(annotation, source)
    };
    let trimmed = raw.trim().trim_start_matches('@');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    (!short.is_empty()).then(|| short.to_string())
}

fn java_lombok_annotation_generates_accessor(name: &str, kind: JavaAccessorKind) -> bool {
    match name {
        "Data" | "Value" => kind == JavaAccessorKind::Getter,
        "Getter" => kind == JavaAccessorKind::Getter,
        "Setter" => kind == JavaAccessorKind::Setter,
        _ => false,
    }
}

fn java_static_import_candidates(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let support: &dyn BoundedDefinitionLookup = session;
    let mut candidates = Vec::new();
    let mut saw_external = false;
    for import in session.import_statements(analyzer, file) {
        let Some(path) = java_static_import_path(&import) else {
            continue;
        };
        if let Some(owner) = path.strip_suffix(".*") {
            let owner_candidates =
                java_filter_member_candidates(support.fqn(&format!("{owner}.{member}")), kind);
            if owner_candidates.is_empty() && !java_workspace_fqn_exists(support, owner) {
                saw_external = true;
            }
            candidates.extend(owner_candidates);
            continue;
        }
        let Some((owner, imported_member)) = path.rsplit_once('.') else {
            continue;
        };
        if imported_member != member {
            continue;
        }
        let imported = java_filter_member_candidates(support.fqn(path), kind);
        if imported.is_empty() && !java_workspace_fqn_exists(support, owner) {
            saw_external = true;
        }
        candidates.extend(imported);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if let Some(filtered_candidates) = java_arity_candidates(analyzer, session, &candidates, arity)
    {
        return candidates_outcome(filtered_candidates);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if saw_external {
        return boundary(format!(
            "`{member}` appears to cross a Java static import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_static_import_match",
        format!("`{member}` did not match an indexed Java static import"),
    )
}

fn java_import_boundary_for_type(
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let support: &dyn BoundedDefinitionLookup = session;
    for import in session.import_statements(java, file) {
        let trimmed = import.trim();
        if trimmed.starts_with("import static ") {
            continue;
        }
        let Some(path) = trimmed
            .strip_prefix("import ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
        else {
            continue;
        };
        if let Some(package) = path.strip_suffix(".*") {
            if !package.is_empty() && !java_workspace_package_exists(support, package) {
                return true;
            }
            continue;
        }
        if path.rsplit('.').next() == Some(name) {
            let package = path
                .rsplit_once('.')
                .map(|(package, _)| package)
                .unwrap_or("");
            return !java_workspace_package_exists(support, package);
        }
    }
    false
}

fn java_static_import_path(import: &str) -> Option<&str> {
    import
        .trim()
        .strip_prefix("import static ")
        .and_then(|rest| rest.strip_suffix(';'))
        .map(str::trim)
}

fn java_workspace_fqn_exists(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    support.fqn_exists(fqn)
}

fn java_workspace_package_exists(support: &dyn BoundedDefinitionLookup, package: &str) -> bool {
    support.package_exists(package) || support.fqn_prefix_exists(package)
}

fn java_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn normalize_java_type_text(raw: &str) -> &str {
    raw.split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim()
}
