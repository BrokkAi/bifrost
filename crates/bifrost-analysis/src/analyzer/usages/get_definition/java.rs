use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::structural::resolution::RejectionReason;
use crate::analyzer::usages::applicability::{ApplicabilityOutcome, arity_applicability};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use crate::analyzer::usages::reference_site::node_range;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
use brokk_bifrost_jvm::java::graph::resolver::argument_list_arity;
use brokk_bifrost_jvm::java::graph::return_type::{
    is_java_local_type_scope_node, java_local_type_scope_contains,
};
use brokk_bifrost_jvm::java::graph_support::{JavaSource, normalize_java_type_text};
use brokk_bifrost_jvm::java::hierarchy::java_preferred_declaring_owners;
use std::cell::RefCell;
use std::collections::VecDeque;

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
    /// What each type parameter this request has already expanded denotes for
    /// member lookup, keyed by its `type_parameter` declaration site. `None`
    /// marks an expansion still in progress, which is the cycle a bound that
    /// names its own parameter would otherwise re-enter forever (#2048).
    type_parameter_bounds: RefCell<HashMap<JavaTypeSpelling, Option<Vec<JavaReceiverType>>>>,
}

impl<'a> JavaResolutionSession<'a> {
    fn unbounded(support: &'a dyn BoundedDefinitionLookup) -> Self {
        Self {
            support,
            budget: None,
            cancellation: None,
            state: RefCell::new(JavaResolutionState::default()),
            type_parameter_bounds: RefCell::new(HashMap::default()),
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
            type_parameter_bounds: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn finish<T>(&self, value: T) -> BoundedResolution<T> {
        self.observe_cancellation();
        let state = *self.state.borrow();
        match state.stop {
            Some(JavaResolutionStop::Exceeded(limit)) => BoundedResolution::Exceeded {
                work: state.work,
                limit,
            },
            Some(JavaResolutionStop::Cancelled) => {
                BoundedResolution::Cancelled { work: state.work }
            }
            None => BoundedResolution::Complete {
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

    fn is_stopped(&self) -> bool {
        self.state.borrow().stop.is_some()
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
        self.enclosing_units(analyzer, file, byte)
            .into_iter()
            .next()
    }

    /// The innermost declaration containing `byte`, before Java member lookup
    /// filters the owner chain to classes. A method-local class is indexed as
    /// a child of its method, so type lookup needs this unfiltered seed even
    /// though implicit-this member lookup does not (#2271).
    fn enclosing_owner(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        byte: usize,
    ) -> Option<CodeUnit> {
        self.query_optional_row(|| {
            analyzer.enclosing_code_unit(
                file,
                &Range {
                    start_byte: byte,
                    end_byte: byte.saturating_add(1),
                    start_line: 0,
                    end_line: 0,
                },
            )
        })
    }

    /// Every class that lexically encloses `byte`, from the innermost class
    /// outward. Java simple-name lookup must exhaust each class's own and
    /// inherited members before it checks the next enclosing class (#1905).
    fn enclosing_units(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        byte: usize,
    ) -> Vec<CodeUnit> {
        let start = self.enclosing_owner(analyzer, file, byte);
        let Some(start) = start else {
            return Vec::new();
        };
        crate::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
            self.parent_of(analyzer, unit)
        })
        .filter(CodeUnit::is_class)
        .collect()
    }

    fn enclosing_static_context(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        node: Node<'_>,
    ) -> (bool, bool) {
        let byte = node.start_byte();
        let start = self.query_optional_row(|| {
            analyzer.enclosing_code_unit(
                file,
                &Range {
                    start_byte: byte,
                    end_byte: byte.saturating_add(1),
                    start_line: 0,
                    end_line: 0,
                },
            )
        });
        let Some(start) = start else {
            return (false, false);
        };
        let mut saw_class = false;
        let mut ancestor = Some(node);
        let mut current_static = false;
        while let Some(current) = ancestor {
            if current.kind() == "static_initializer" {
                current_static = true;
                break;
            }
            ancestor = current.parent();
        }
        let mut outer_static = false;
        for unit in crate::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
            self.parent_of(analyzer, unit)
        }) {
            if unit.is_class() {
                saw_class = true;
                continue;
            }
            if (unit.is_function() || unit.is_field())
                && self
                    .signature_metadata(analyzer, &unit)
                    .iter()
                    .any(|metadata| {
                        if unit.is_function() {
                            metadata.callable_is_static()
                        } else {
                            metadata.field_is_static()
                        }
                    })
            {
                if saw_class {
                    outer_static = true;
                } else {
                    current_static = true;
                }
            }
        }
        (current_static, outer_static)
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
        token: QueryToken<'_>,
        java: &JavaAnalyzer,
        file: &ProjectFile,
        name: &str,
    ) -> Option<CodeUnit> {
        self.query_optional_row(|| java.resolve_type_name_in_file(token, file, name))
    }

    /// The full candidate set for a type name, ambiguous wildcard peers
    /// included. Reference sites use this so colliding on-demand imports
    /// become an `Ambiguous` outcome; receiver and qualifier lookups keep
    /// [`Self::resolve_type_name_in_file`], which demands a unique answer.
    fn resolve_type_name_candidates_in_file(
        &self,
        token: QueryToken<'_>,
        java: &JavaAnalyzer,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<CodeUnit> {
        self.query_rows(|| java.resolve_type_name_candidates_in_file(token, file, name))
    }

    /// Whether `name` resolves once the external surface is consulted. The
    /// activated packs come from the dispatching analyzer, which is the only
    /// one activation publishes onto (#1893).
    fn type_name_resolves_with_external(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        java: &JavaAnalyzer,
        file: &ProjectFile,
        name: &str,
    ) -> bool {
        self.query_optional_row(|| {
            java.resolve_type_name_with_external(
                token,
                analyzer.semantic_model_overlay(),
                file,
                name,
            )
        })
        .is_some()
    }

    fn import_infos(
        &self,
        token: QueryToken<'_>,
        java: &JavaAnalyzer,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::ImportInfo> {
        self.query_rows(|| java.import_info_of(token, file))
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

    fn direct_children(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.query_rows(|| analyzer.direct_children(unit))
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

    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        self.query_rows(|| self.support.fqn_in_any_language(fqn))
    }

    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.bool_query(|| self.support.package_exists_in_any_language(package))
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
    Type,
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
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
            unreachable!("unbounded Java resolution cannot be interrupted")
        }
    }
}

pub(crate) fn resolve_java_bounded(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> BoundedResolution<DefinitionLookupOutcome> {
    resolve_java_in_session(analyzer, session, file, source, tree, site)
}

fn resolve_java_in_session(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    // Java's tier ladder resolves the reference this site names, so the deep
    // scope covers the whole dispatch: the type-name tiers in
    // `java::imports::resolve_type_name_with`, the member tier, the
    // static-import tier and the boundary gate. A nested lookup for another
    // name -- a receiver type, an owner -- falls outside it and therefore
    // attributes nothing to this reference.
    let _deep = trace::DeepScope::enter(&site.text);
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
                    analyzer, token, java, session, file, source, creation,
                ));
            }
            resolve_java_type_reference(analyzer, java, session, file, source, node)
        }
        "object_creation_expression" => {
            resolve_java_constructor_call(analyzer, token, java, session, file, source, node)
        }
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, token, session, file, source, root, node)
        }
        "method_reference" => {
            resolve_java_method_reference(analyzer, token, java, session, file, source, root, node)
        }
        "field_access" => {
            resolve_java_field_access(analyzer, token, session, file, source, root, node)
        }
        "identifier" => {
            if let Some(parent) = node.parent() {
                match parent.kind() {
                    "method_invocation" => {
                        return session.finish(
                            match qualified_access_focus(node, parent, &["object"], &["name"]) {
                                Some(QualifiedAccessFocus::Qualifier) => {
                                    resolve_java_bare_identifier(
                                        analyzer, token, java, session, file, source, root, node,
                                    )
                                }
                                Some(QualifiedAccessFocus::Member) => {
                                    resolve_java_method_invocation(
                                        analyzer, token, session, file, source, root, parent,
                                    )
                                }
                                None => resolve_java_bare_identifier(
                                    analyzer, token, java, session, file, source, root, node,
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
                                analyzer, token, java, session, file, source, root, node,
                            ),
                            Some(QualifiedAccessFocus::Member) => resolve_java_field_access(
                                analyzer, token, session, file, source, root, parent,
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
                    "switch_label" => {
                        return session.finish(resolve_java_switch_label(
                            analyzer, token, java, session, file, source, root, node,
                        ));
                    }
                    "method_reference" => {
                        return session.finish(
                            if java_method_reference_receiver_contains_focus(parent, node) {
                                resolve_java_bare_identifier(
                                    analyzer, token, java, session, file, source, root, node,
                                )
                            } else {
                                resolve_java_method_reference(
                                    analyzer, token, java, session, file, source, root, parent,
                                )
                            },
                        );
                    }
                    _ => {}
                }
            }
            resolve_java_bare_identifier(analyzer, token, java, session, file, source, root, node)
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
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    if matches!(
        node.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        return java_type_from_node_with_context(
            analyzer, token, java, session, file, source, node,
        )
        .map(|unit| JavaTypeLookupResolution::Type {
            fqn: unit.fq_name().to_string(),
            target_kind: TypeLookupTargetKind::TypeReference,
        });
    }

    if node.kind() != "identifier" {
        return None;
    }

    if let Some(parent) = node.parent() {
        if matches!(parent.kind(), "field_access" | "method_invocation")
            && parent.child_by_field_name("object") == Some(node)
            && let Some(receiver) =
                java_sole_receiver_type(analyzer, token, session, file, source, root, node)
        {
            return Some(JavaTypeLookupResolution::Type {
                fqn: receiver.unit.fq_name().to_string(),
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
        token,
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

#[allow(clippy::too_many_arguments)]
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
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    match parent.kind() {
        "formal_parameter" | "resource" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                java_type_from_node_with_context(
                    analyzer, token, java, session, file, source, type_node,
                )
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
                        analyzer, token, java, session, file, source, type_node,
                    )
                })
        }
        _ => java_type_of_identifier_before(
            analyzer,
            token,
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

/// Memoized on exact source bytes (#2679): the resolver re-parses the file it
/// is resolving in once per local-type candidate, and its cross-file receiver
/// and return-type probes re-parse the same declaring files once per
/// occurrence.
static JAVA_TREES: super::TreeParseMemo = super::TreeParseMemo::new();

pub(super) fn parse_java_tree(source: &str) -> Option<Tree> {
    JAVA_TREES.parse(source, |source| {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .ok()?;
        parser.parse(source, None)
    })
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
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
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
    if !normalized.contains('.')
        && let Some(unit) =
            java_local_type_in_scope(analyzer, session, file, normalized, node.start_byte())
    {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = java_nested_type_in_scope(
        analyzer,
        session,
        session.enclosing_unit(analyzer, file, node.start_byte()),
        normalized,
    ) {
        return candidates_outcome(vec![unit]);
    }
    let candidates = session.resolve_type_name_candidates_in_file(token, java, file, normalized);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if let Some(unit) =
        java_qualified_nested_type(analyzer, token, java, session, file, source, node)
    {
        return candidates_outcome(vec![unit]);
    }
    // `java_import_boundary_for_type` fuses the unresolved-import signal with the
    // workspace-type check; its negation is the workspace-internal gate.
    gated_boundary(
        || !java_import_boundary_for_type(java, token, session, file, normalized),
        format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ),
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
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let support: &dyn BoundedDefinitionLookup = session;
    let scoped = java_enclosing_scoped_type_identifier(session, node)?;
    let focused_prefix = source.get(scoped.start_byte()..node.end_byte())?;
    let normalized = normalize_java_type_text(focused_prefix);
    let terminal = normalize_java_type_text(java_node_text(node, source));
    if normalized.is_empty() || normalized == terminal {
        return None;
    }

    let candidates = session.resolve_type_name_candidates_in_file(token, java, file, normalized);
    if !candidates.is_empty() {
        return Some(candidates_outcome(candidates));
    }
    if let Some(unit) =
        java_qualified_nested_type(analyzer, token, java, session, file, source, node)
    {
        return Some(candidates_outcome(vec![unit]));
    }
    if session.type_name_resolves_with_external(analyzer, token, java, file, normalized) {
        // gated upstream: `resolve_type_name_in_file` and `java_qualified_nested_type`
        // above return early for any workspace-internal type; reaching here means
        // the name only resolves once external imports are considered.
        return Some(boundary_unchecked(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        )));
    }
    if java_scoped_type_qualifier_resolves_in_source(session, token, java, file, source, scoped) {
        return Some(no_definition(
            "no_indexed_definition",
            format!("`{normalized}` did not resolve to an indexed Java type"),
        ));
    }
    let qualifier_is_in_workspace = java_scoped_type_qualifier_text(session, scoped, source)
        .is_some_and(|qualifier| java_workspace_package_exists(support, qualifier));
    // The `!qualifier_is_in_workspace` disjunct is the #1089 workspace-namespace
    // check, so the negation of the whole condition is the workspace gate.
    Some(gated_boundary(
        || {
            !java_import_boundary_for_type(java, token, session, file, normalized)
                && qualifier_is_in_workspace
        },
        format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ),
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    ))
}

/// What a Java method invocation binds to, with the receiver types the binding
/// ran against. A chained call needs both: the definition to read a return type
/// from, and the receiver's type arguments to substitute into it (#2048).
struct JavaInvocationBinding {
    outcome: DefinitionLookupOutcome,
    receiver: Vec<JavaReceiverType>,
}

/// The workspace candidates and external owner evidence produced by one
/// structured static-import lookup. An external owner is retained only when
/// the import lookup found no workspace candidate and all external imports
/// name the same owner; callers can then publish the owner/member identity
/// without guessing from the call's source spelling.
struct JavaStaticImportResolution {
    outcome: DefinitionLookupOutcome,
    external_owner: Option<String>,
}

/// The enclosing-member ladder's outcome and whether it completed without a
/// declaration claim, leaving static imports as the next lookup tier.
struct JavaEnclosingMemberResolution {
    outcome: DefinitionLookupOutcome,
    static_import_fallback_allowed: bool,
}

impl JavaInvocationBinding {
    fn without_receiver(outcome: DefinitionLookupOutcome) -> Self {
        Self {
            outcome,
            receiver: Vec::new(),
        }
    }
}

fn resolve_java_method_invocation(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    java_method_invocation_binding(analyzer, token, session, file, source, root, node).outcome
}

fn java_method_invocation_binding(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> JavaInvocationBinding {
    let Some(name_node) = node.child_by_field_name("name") else {
        return JavaInvocationBinding::without_receiver(no_definition(
            "no_method_name",
            "Java method invocation has no name",
        ));
    };
    let name = java_node_text(name_node, source);
    if name.is_empty() {
        return JavaInvocationBinding::without_receiver(no_definition(
            "no_method_name",
            "Java method invocation has a blank name",
        ));
    }
    // The one Java argument count. tree-sitter spells a comment as an `extra`
    // named node, so a comment written between two arguments used to be
    // counted as an argument here and no overload accepted the call. The
    // inverse usage scan has always excluded extras, so the two surfaces
    // disagreed about the same call (#2046).
    let arity = argument_list_arity(node);

    if let Some(object) = node.child_by_field_name("object") {
        let receiver = java_receiver_types(analyzer, token, session, file, source, root, object);
        if !receiver.is_empty() {
            let outcome = java_member_candidates_across(
                analyzer,
                token,
                session,
                &receiver,
                name,
                JavaMemberLookupKind::Method,
                Some(arity),
            );
            return JavaInvocationBinding { outcome, receiver };
        }
        let mut outcome = java_unresolved_receiver_outcome(
            analyzer,
            token,
            session,
            file,
            source,
            root,
            object,
            name,
            format!("receiver for Java method `{name}` is not resolved"),
        );
        // #2354: workspace receiver typing answered nothing, so the receiver's
        // written declared type names no indexed class. When the external
        // declaration surface (classpath artifacts plus activated
        // declaration-fact packs) does name it, publish the call's canonical
        // external identity -- `<owner FQN>.<member>` -- as the resolved
        // reference text. That is the one identity an unmaterialized external
        // callee leaves behind, and #1978's boundary reads exactly this field.
        // Without it an instance call on an external interface
        // (`request.getParameter(...)`) carries only its syntactic receiver
        // *variable* name, which no summary can ever match.
        if let Some(owner_fqn) = resolve_analyzer::<JavaAnalyzer>(analyzer).and_then(|java| {
            java_external_receiver_owner_fqn(
                analyzer,
                token,
                java,
                session,
                file,
                source,
                root,
                object,
                name,
                JAVA_CHAINED_RECEIVER_LIMIT,
            )
        }) {
            outcome.reference = Some(ResolvedReferenceSite {
                path: file.to_string(),
                text: format!("{owner_fqn}.{name}"),
                range: node_range(node),
                focus_start_byte: name_node.start_byte(),
                focus_end_byte: name_node.end_byte(),
            });
        }
        return JavaInvocationBinding::without_receiver(outcome);
    }

    let (initial_static_context, outer_static_context) =
        session.enclosing_static_context(analyzer, file, name_node);
    let enclosing = java_member_candidates_in_enclosing_chain(
        analyzer,
        token,
        session,
        session.enclosing_units(analyzer, file, name_node.start_byte()),
        initial_static_context,
        outer_static_context,
        name,
        JavaMemberLookupKind::Method,
        Some(arity),
    );
    // Java's implicit-this member ladder shadows static imports. A failed
    // overload or static-context check is still an adjudicated member name,
    // not permission to bind a same-named imported method.
    if !enclosing.static_import_fallback_allowed {
        return JavaInvocationBinding::without_receiver(enclosing.outcome);
    }

    let static_import = java_static_import_candidates(
        analyzer,
        token,
        session,
        file,
        name,
        JavaMemberLookupKind::Method,
        Some(arity),
    );
    // The tier took the call's arity, so anything it names already accepts the
    // argument list. A static-import boundary claim carries its structured
    // owner through `reference` so downstream summary lookup can use the full
    // owner/member/arity identity (#2736).
    if static_import.outcome.status != DefinitionLookupStatus::NoDefinition {
        let JavaStaticImportResolution {
            mut outcome,
            external_owner,
        } = static_import;
        if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && let Some(owner) = external_owner
        {
            outcome.reference = Some(ResolvedReferenceSite {
                path: file.to_string(),
                text: format!("{owner}.{name}"),
                range: node_range(node),
                focus_start_byte: name_node.start_byte(),
                focus_end_byte: name_node.end_byte(),
            });
        }
        return JavaInvocationBinding::without_receiver(outcome);
    }

    JavaInvocationBinding::without_receiver(no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    ))
}

/// Member lookup against every type a receiver can have.
///
/// One type is the ordinary case and keeps its own outcome exactly. Several
/// types are an intersection bound (JLS 4.9): the receiver names every bound's
/// members at once, so the answer is their union, and a member more than one
/// bound declares is honestly ambiguous rather than resolved to whichever bound
/// was written first.
fn java_member_candidates_across(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    receiver: &[JavaReceiverType],
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let mut outcomes = receiver
        .iter()
        .map(|candidate| {
            java_member_candidates(
                analyzer,
                token,
                session,
                &candidate.unit,
                member,
                kind,
                arity,
            )
        })
        .collect::<Vec<_>>();
    if outcomes.len() == 1 {
        return outcomes.remove(0);
    }
    let union = outcomes
        .iter()
        .flat_map(|outcome| outcome.definitions.iter().cloned())
        .collect::<Vec<_>>();
    if !union.is_empty() {
        return candidates_outcome(union);
    }
    // No bound declares the member. A bound whose own hierarchy leaves the
    // workspace is the strongest report available, so it wins over a plain
    // miss on another bound.
    let boundary = outcomes
        .iter()
        .position(|outcome| outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary);
    match boundary {
        Some(index) => outcomes.remove(index),
        None => outcomes.into_iter().next().unwrap_or_else(|| {
            no_definition(
                "no_indexed_definition",
                format!("`{member}` did not resolve to an indexed Java member"),
            )
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_java_method_reference(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    let mut owner =
        java_receiver_types(analyzer, token, session, file, source, root, receiver_node);
    if owner.is_empty() {
        owner = java_type_text_with_context(
            analyzer,
            token,
            java,
            session,
            file,
            normalize_java_type_text(receiver_text),
            receiver_node.start_byte(),
        )
        .map(JavaReceiverType::plain)
        .into_iter()
        .collect();
    }
    if java_method_reference_is_constructor(session, node) {
        // A constructor reference names one type. An intersection bound has no
        // constructor of its own, so several owners are not a target.
        if let [only] = owner.as_slice() {
            return java_constructor_outcome(analyzer, session, only.unit.clone(), None);
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
    if !owner.is_empty() {
        return java_member_candidates_across(
            analyzer,
            token,
            session,
            &owner,
            member,
            JavaMemberLookupKind::Method,
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
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = node.child_by_field_name("type") else {
        return no_definition("no_indexed_definition", "Java constructor call has no type");
    };
    let owner =
        java_type_from_node_with_context(analyzer, token, java, session, file, source, type_node)
            .or_else(|| {
                let raw = java_node_text(type_node, source);
                java_type_text_with_context(
                    analyzer,
                    token,
                    java,
                    session,
                    file,
                    normalize_java_type_text(raw),
                    type_node.start_byte(),
                )
            });
    if let Some(owner) = owner {
        return java_constructor_outcome(analyzer, session, owner, Some(argument_list_arity(node)));
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
    constructors.retain(|unit| {
        unit.is_function() && !unit.is_synthetic() && unit.source() == owner.source()
    });
    constructors = java_filter_candidates_by_arity(analyzer, session, constructors, arity);
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }

    if java_modeled_constructor_exists(analyzer, session, &owner, arity) {
        return no_definition(
            "modeled_java_constructor",
            format!(
                "`{}.{}` is supplied by an active Java semantic model",
                owner.fq_name(),
                owner.identifier()
            ),
        );
    }

    let indexed_owner = support
        .fqn(&owner.fq_name())
        .into_iter()
        .filter(|candidate| candidate.source() == owner.source())
        .collect::<Vec<_>>();
    if indexed_owner.is_empty() {
        candidates_outcome(vec![owner])
    } else {
        candidates_outcome(indexed_owner)
    }
}

fn java_modeled_constructor_exists(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
    arity: Option<usize>,
) -> bool {
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return false;
    };
    session
        .query_rows(|| overlay.members_of(&owner.fq_name()).records)
        .into_iter()
        .any(|symbol| {
            symbol.language == "java"
                && symbol.kind
                    == crate::analyzer::semantic_model::SemanticModelSymbolKind::Constructor
                && symbol.name == owner.identifier()
                && arity.is_none_or(|arity| {
                    symbol
                        .structured_signature
                        .as_ref()
                        .is_some_and(|signature| signature.parameters.len() == arity)
                })
        })
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

/// The one Java applicability check (#1478 M3).
///
/// Every Java seam that discriminates overloads calls this, and it returns both
/// halves of the answer in one value: the candidates the resolver binds
/// (`winners`) and the per-candidate verdict with its typed rejection reason
/// (`verdicts`). Before this factoring the same check ran twice in spirit --
/// once as a `filter` that produced the binding and once as a trace loop that
/// re-derived who had lost -- and only the survivors escaped. There is now one
/// computation, so the rows a policy reads and the declaration the resolver
/// bound cannot drift apart.
fn java_candidate_applicability(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    candidates: &[CodeUnit],
    arity: Option<usize>,
) -> ApplicabilityOutcome {
    arity_applicability(candidates, arity, |unit| {
        Some(java_declared_arity(analyzer, Some(session), unit))
    })
}

/// The parameter list a Java callable declares, as the resolver has always read
/// it: the persisted arity when the extractor recorded one, and otherwise the
/// count the indexed signature states. Java therefore always has a declared
/// arity, which is why a Java candidate is never an undecided verdict once the
/// call's argument count is known.
fn java_declared_arity(
    analyzer: &dyn IAnalyzer,
    session: Option<&JavaResolutionSession<'_>>,
    unit: &CodeUnit,
) -> crate::analyzer::CallableArity {
    java_signature_metadata(analyzer, session, unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| {
            crate::analyzer::CallableArity::exact(java_signature_arity(unit.signature()))
        })
}

/// Narrow `candidates` to the overloads that accept the call, binding nothing
/// when none does.
///
/// An earlier form of this filter kept the whole candidate set when no overload
/// accepted the call. `e9033e203` removed that fallback so a constructor a
/// semantic model supplies -- a Lombok `@NoArgsConstructor`, for example -- can
/// be reported instead of an authored constructor the call cannot reach, and the
/// same answer is what #1478's rule contract states: zero applicable candidates
/// stay unresolved. Every refused candidate therefore becomes a rejected
/// applicability row carrying its typed reason, and the site's selection summary
/// reports `unresolved` rather than a bound set nobody accepted.
fn java_filter_candidates_by_arity(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    if arity.is_none() {
        return candidates;
    }
    let applicability = java_candidate_applicability(analyzer, session, &candidates, arity);
    java_record_callable_applicability(&applicability, &applicability.winners);
    applicability.winners
}

/// Emit the callable-applicability trace for a seam with no member walk behind
/// it, such as a constructor call or a static import.
///
/// A refused candidate the seam did **not** bind becomes a rejected row
/// carrying its typed reason; a candidate the seam bound gets its verdict
/// staged for the outcome constructor. Since `e9033e203` removed the
/// no-accept fallback, every Java seam binds `ApplicabilityOutcome::winners`
/// or nothing, so a bound candidate is never `inapplicable`: a site no overload
/// accepts binds nothing, and its rows are the rejected ones. The one bound
/// verdict that is not `applicable` is `unknown`, which the static-import seam
/// stages when the call's argument count is unreadable and no candidate was
/// measured at all.
fn java_record_callable_applicability(applicability: &ApplicabilityOutcome, bound: &[CodeUnit]) {
    if !trace::recording() {
        return;
    }
    for verdict in &applicability.verdicts {
        if verdict.verdict != ApplicabilityVerdict::Inapplicable
            || bound.contains(&verdict.candidate)
        {
            continue;
        }
        trace::record(
            trace::TraceCandidate::rejected(
                trace::TraceCandidateRef::Unit(verdict.candidate.clone()),
                None,
                RejectionReason::CallableApplicabilityDeferred,
            )
            .with_callable(trace::CallableApplicabilityRecord {
                verdict: verdict.verdict,
                reason: verdict.reason,
            }),
        );
    }
    trace::stage_callable_context(
        applicability
            .verdicts
            .iter()
            .filter(|verdict| bound.contains(&verdict.candidate))
            .map(|verdict| {
                (
                    verdict.candidate.fq_name(),
                    trace::CallableApplicabilityRecord {
                        verdict: verdict.verdict,
                        reason: verdict.reason,
                    },
                )
            })
            .collect(),
    );
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

fn java_method_reference_receiver_contains_focus(reference: Node<'_>, focus: Node<'_>) -> bool {
    java_method_reference_receiver_node(reference)
        .is_some_and(|receiver| node_contains_focus(receiver, focus))
}

fn resolve_java_field_access(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    let owner = java_receiver_types(analyzer, token, session, file, source, root, object);
    if !owner.is_empty() {
        let mut nested_types = Vec::new();
        for candidate in &owner {
            let qualified_name = format!("{}.{}", candidate.unit.fq_name(), field);
            let members = support.fqn(&qualified_name);
            if members.iter().any(CodeUnit::is_field) {
                nested_types.clear();
                break;
            }
            nested_types.extend(members.into_iter().filter(CodeUnit::is_class));
        }
        if !nested_types.is_empty() && java_field_access_is_selector_receiver(node) {
            return candidates_outcome(nested_types);
        }
        return java_member_candidates_across(
            analyzer,
            token,
            session,
            &owner,
            field,
            JavaMemberLookupKind::Field,
            None,
        );
    }
    java_unresolved_receiver_outcome(
        analyzer,
        token,
        session,
        file,
        source,
        root,
        object,
        field,
        format!("receiver for Java field `{field}` is not resolved"),
    )
}

/// What a member reference reports when its receiver is not a type this
/// workspace indexes.
///
/// A receiver whose written spelling resolves to an *external* type, on which
/// the external declaration surface declares `member`, is a reference the
/// workspace cannot index rather than one nothing declares. That is the import
/// boundary the resolver actually crossed, and reporting it is what lets the
/// trace name the external declaration the reference landed on (#1900).
/// Anything else keeps the plain unresolved-receiver miss, so a receiver of
/// unknown type and a member no surface declares are both unchanged.
///
/// A receiver typed by a type parameter whose written bound is imported from
/// outside the workspace is the same kind of claim, made one step earlier: the
/// member surface is on the far side of that import, so the report names the
/// bound the walk stopped at instead of claiming nothing declares the member
/// (#2048).
#[allow(clippy::too_many_arguments)]
fn java_unresolved_receiver_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
    member: &str,
    unresolved_message: String,
) -> DefinitionLookupOutcome {
    let spelling = format!("{}.{}", java_node_text(object, source), member);
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer);
    let imported_bound = java.and_then(|java| {
        java_imported_receiver_bound(java, token, session, file, source, root, object)
    });
    let boundary_message = match &imported_bound {
        Some(bound) => format!(
            "`{spelling}` reads a receiver bounded by `{bound}`, a Java type imported from outside the indexed workspace"
        ),
        None => format!(
            "`{spelling}` appears to cross a Java import boundary not indexed in this workspace"
        ),
    };
    gated_boundary(
        || {
            imported_bound.is_none()
                && java.is_none_or(|java| {
                    session
                        .query_optional_row(|| {
                            java.resolve_member_name_with_external(
                                token,
                                analyzer.semantic_model_overlay(),
                                file,
                                &spelling,
                            )
                        })
                        .is_none()
                })
        },
        boundary_message,
        "unsupported_java_receiver",
        unresolved_message,
    )
}

/// How many chained calls the receiver ladder walks inward before it refuses
/// (#2454).
///
/// `response.getWriter().println(...)`, the shape 2668 of the 2740 OWASP
/// Benchmark case files are written in, is one rung; `a().b().c()` is two. The
/// bound makes a chain cost a fixed number of external declaration lookups
/// rather than one per written call, and a chain longer than it answers nothing
/// rather than a partial identity.
const JAVA_CHAINED_RECEIVER_LIMIT: usize = 8;

/// The fully-qualified name of the external type a receiver's written declared
/// type spells, or `None` when no external declaration names it.
///
/// Called only after workspace receiver typing produced nothing, so the
/// spelling here is by construction one that resolved to no indexed class. The
/// answer is the owner half of the canonical external-callee identity
/// `(language, owner FQN, member, arity, has_receiver)` that an activated
/// procedure summary binds by (#1978). A type-parameter spelling names no
/// class and a workspace-source resolution is not external, so both answer
/// `None` and the call keeps the identity-free boundary it had before.
///
/// `chain_budget` is spent only by the #2454 chained-call rung below, which
/// re-enters this function for the inner call's own receiver.
#[allow(clippy::too_many_arguments)]
fn java_external_receiver_owner_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
    member_name: &str,
    chain_budget: usize,
) -> Option<String> {
    if let Some(type_node) = java_receiver_type_node(session, file, source, root, object) {
        let normalized = normalize_java_type_text(java_node_text(type_node, source));
        if !normalized.is_empty()
            && brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
                type_node, source, normalized,
            )
            .is_none()
            && let Some(fqn) = java_resolved_type_owner_fqn(
                analyzer,
                token,
                java,
                session,
                file,
                normalized,
                member_name,
            )
        {
            return Some(fqn);
        }
    }
    // #2454: a receiver that is itself a call writes its type nowhere in the
    // reading file, so the written-type tier above answers nothing for it. Its
    // static type is the callee's *declared return type*, which the same
    // external declaration surface writes down --
    // `javax.servlet.ServletResponse.getWriter` returns `java.io.PrintWriter`
    // in the servlet artifact -- so the ladder simply continues from there.
    if object.kind() == "method_invocation" {
        let returned = java_external_call_return_type_fqn(
            analyzer,
            token,
            java,
            session,
            file,
            source,
            root,
            object,
            chain_budget,
        )?;
        return java_resolved_type_owner_fqn(
            analyzer,
            token,
            java,
            session,
            file,
            &returned,
            member_name,
        );
    }
    // #2364: a method qualifier with no variable or field in scope is a
    // TypeName (JLS 6.5.2). Resolve the written spelling through imports and
    // the activated overlay so `URLDecoder.decode` carries the same owner FQN
    // as `java.net.URLDecoder.decode`.
    let spelling = match object.kind() {
        "identifier" => {
            let name = java_node_text(object, source);
            if java_bindings_before_scoped_inner(
                session,
                file,
                source,
                root,
                object.start_byte(),
                true,
            )
            .is_shadowed(name)
            {
                return None;
            }
            name
        }
        "field_access" | "scoped_type_identifier" | "type_identifier" => {
            java_node_text(object, source)
        }
        _ => return None,
    };
    let normalized = normalize_java_type_text(spelling);
    if normalized.is_empty() {
        return None;
    }
    java_resolved_type_owner_fqn(
        analyzer,
        token,
        java,
        session,
        file,
        normalized,
        member_name,
    )
}

/// The fully-qualified name of the class an external call's declaration says it
/// returns (#2454), which is the static type of that call used as a receiver.
///
/// The call's own receiver is typed by the same ladder this feeds, so a chain
/// walks inward one call at a time until a rung grounds it in a written type or
/// a type name. Every step fails closed, and a step that fails ends the chain:
/// a call whose receiver names no external owner, a member no activated pack or
/// classpath artifact declares, and a declaration that writes no usable return
/// type all answer `None`, and the outer call keeps the identity-free boundary
/// it had.
///
/// The one call this cannot type is an unqualified one (`getWriter().println()`
/// inside the servlet itself): it has no receiver to resolve, so there is no
/// external owner to read a declaration from.
#[allow(clippy::too_many_arguments)]
fn java_external_call_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    chain_budget: usize,
) -> Option<String> {
    let remaining = chain_budget.checked_sub(1)?;
    let member_name = java_node_text(call.child_by_field_name("name")?, source);
    if member_name.is_empty() {
        return None;
    }
    let object = call.child_by_field_name("object")?;
    let owner_fqn = java_external_receiver_owner_fqn(
        analyzer,
        token,
        java,
        session,
        file,
        source,
        root,
        object,
        member_name,
        remaining,
    )?;
    let member = session.query_optional_row(|| {
        java.resolve_member_name_with_external(
            token,
            analyzer.semantic_model_overlay(),
            file,
            &format!("{owner_fqn}.{member_name}"),
        )
    })?;
    member.declared_return_type_fqn().map(str::to_owned)
}

fn java_resolved_type_owner_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    normalized: &str,
    member_name: &str,
) -> Option<String> {
    if let Some(resolution) = session.query_optional_row(|| {
        java.resolve_type_name_with_external(
            token,
            analyzer.semantic_model_overlay(),
            file,
            normalized,
        )
    }) {
        let JavaTypeResolution::External(external_type) = resolution else {
            return None;
        };
        // #2371: an inherited member's canonical identity must name the type
        // that *declares* it, not the (sub)type the receiver was written as.
        // `HttpServletRequest.getParameter` is declared on `ServletRequest`.
        if let Some(member) = session.query_optional_row(|| {
            java.resolve_member_name_with_external(
                token,
                analyzer.semantic_model_overlay(),
                file,
                &format!("{}.{member_name}", external_type.fqn()),
            )
        }) {
            return Some(
                member
                    .fqn()
                    .rsplit_once('.')
                    .map_or_else(|| member.fqn().to_owned(), |(owner, _)| owner.to_owned()),
            );
        }
        return Some(external_type.fqn().to_owned());
    }
    // The overlay and jar index can both be empty in an inline fixture. An
    // explicit single-type import is still file-local structured evidence of
    // the owner FQN (#2364).
    if let Some(imported) =
        session.query_optional_row(|| java.explicit_imported_type_fqn(token, file, normalized))
    {
        return Some(imported);
    }

    // java.lang is implicitly imported into every compilation unit. A golden
    // summary pack can be the only active external surface in a small fixture,
    // so no declaration fact exists for the ordinary type ladder to return.
    // The caller has already rejected value shadowing, and the runtime lookup
    // below asks the canonical summary index for an exact receiverless member;
    // it does not infer an owner from source text or a member-name match.
    if normalized.contains('.') {
        return None;
    }
    let owner = format!("java.lang.{normalized}");
    analyzer
        .active_semantic_models()
        .filter(|models| {
            models.has_receiverless_procedure_summary_member("java", &owner, member_name)
        })
        .map(|_| owner)
}

/// The written bound of a type-parameter receiver whose bound this file imports
/// from a package the workspace does not index.
///
/// Called only when receiver typing already produced nothing, so a bound named
/// here is by construction one that resolved to no indexed class. The import
/// tier is what separates a boundary from a misspelling: a bound with no import
/// behind it stays a plain miss.
fn java_imported_receiver_bound(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<String> {
    let type_node = java_receiver_type_node(session, file, source, root, object)?;
    let normalized = normalize_java_type_text(java_node_text(type_node, source));
    let parameter = brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
        type_node, source, normalized,
    )?;
    brokk_bifrost_jvm::java::graph_support::java_type_parameter_bounds(parameter)
        .into_iter()
        .map(|bound| normalize_java_type_text(java_node_text(bound, source)))
        .find(|bound| java_import_boundary_for_type(java, token, session, file, bound))
        .map(str::to_owned)
}

fn java_field_access_is_selector_receiver(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| match parent.kind() {
        "field_access" | "method_invocation" => parent.child_by_field_name("object") == Some(node),
        "method_reference" => true,
        _ => false,
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_java_bare_identifier(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    if java_identifier_is_annotation_name(node) {
        if let Some(unit) = java_type_text_with_context(
            analyzer,
            token,
            java,
            session,
            file,
            name,
            node.start_byte(),
        ) {
            return candidates_outcome(vec![unit]);
        }
        return java_bare_name_static_import_or_boundary(
            analyzer, token, java, session, file, name,
        );
    }
    // JLS 6.4.2 (obscuring) and 6.5.2 (ambiguous names): outside a type context
    // a simple name denotes a variable whenever one is in scope -- a local, a
    // parameter, or a field of the enclosing class, inherited ones included --
    // and the same-named type only when none is. A qualifier head
    // (`Widget.CONST`, `Widget.of()`, `Widget::run`) is an ambiguous name and
    // takes the same order. The inverse usage scan already refuses such a site
    // as a type reference, so resolving the type first made the two surfaces
    // disagree (#1754).
    let locally_bound =
        java_local_binding_before(session, file, source, root, name, node.start_byte());
    if !locally_bound {
        let (initial_static_context, outer_static_context) =
            session.enclosing_static_context(analyzer, file, node);
        let outcome = java_member_candidates_in_enclosing_chain(
            analyzer,
            token,
            session,
            session.enclosing_units(analyzer, file, node.start_byte()),
            initial_static_context,
            outer_static_context,
            name,
            JavaMemberLookupKind::Field,
            None,
        )
        .outcome;
        if outcome.status != DefinitionLookupStatus::NoDefinition {
            return outcome;
        }
    }
    if locally_bound {
        return no_definition(
            "local_binding",
            format!("`{name}` resolves to a local Java binding"),
        );
    }
    if let Some(unit) = java_type_text_with_context(
        analyzer,
        token,
        java,
        session,
        file,
        name,
        node.start_byte(),
    ) {
        return candidates_outcome(vec![unit]);
    }
    java_bare_name_static_import_or_boundary(analyzer, token, java, session, file, name)
}

/// tree-sitter-java spells every Java type reference as `type_identifier`,
/// `scoped_type_identifier` or `generic_type` -- except an annotation name,
/// which is a plain `identifier`. So this is the complete set of type contexts
/// a bare-identifier reference site can sit in; everything else that reaches
/// [`resolve_java_bare_identifier`] is an expression name or an ambiguous-name
/// qualifier, where a variable in scope wins over a same-named type.
fn java_identifier_is_annotation_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "annotation" | "marker_annotation")
            && parent.child_by_field_name("name") == Some(node)
    })
}

/// The last two tiers a bare Java name falls through to once neither a
/// variable, a member of the enclosing class, nor a type name claimed it:
/// static imports, then the import-boundary gate.
fn java_bare_name_static_import_or_boundary(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    name: &str,
) -> DefinitionLookupOutcome {
    let static_import = java_static_import_candidates(
        analyzer,
        token,
        session,
        file,
        name,
        JavaMemberLookupKind::Field,
        None,
    );
    if static_import.outcome.status != DefinitionLookupStatus::NoDefinition {
        return static_import.outcome;
    }
    // Workspace gate is the negation of the fused import-boundary predicate.
    gated_boundary(
        || !java_import_boundary_for_type(java, token, session, file, name),
        format!("`{name}` appears to cross a Java import boundary not indexed in this workspace"),
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java definition"),
    )
}

/// Resolve a case label written as a simple name.
///
/// JLS 14.11: when the switch selector has enum type, a case label spelled as a
/// simple name denotes a constant of *that* enum type, and the name is resolved
/// in the enum's member scope. The ordinary lexical scope is never consulted, so
/// an import, a field or a local of the same spelling cannot claim the label.
///
/// Resolving a label as an ordinary expression name is exactly what the rank-31+
/// census caught at 63a1912a: 18 Java label defects, 16 of them returning no
/// definition for a constant the selector's enum plainly declares, and 2 binding
/// to an imported class the label merely shares a spelling with (#2043). The
/// ordinary path is therefore not a fallback once the selector's type is known:
/// a constant the enum does not declare is a miss, not an invitation to look
/// somewhere else.
#[allow(clippy::too_many_arguments)]
fn resolve_java_switch_label(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    match java_switch_selector_type(analyzer, token, java, session, file, source, root, node) {
        JavaSwitchSelectorType::Indexed(owner) => java_member_candidates(
            analyzer,
            token,
            session,
            &owner,
            name,
            JavaMemberLookupKind::Field,
            None,
        ),
        JavaSwitchSelectorType::ConstantVariable => {
            resolve_java_bare_identifier(analyzer, token, java, session, file, source, root, node)
        }
        JavaSwitchSelectorType::Unknown => no_definition(
            "unresolved_switch_selector_type",
            format!(
                "`{name}` is a Java case label whose switch selector type did not resolve, so the enum scope that binds it is unknown"
            ),
        ),
    }
}

/// What the static type of a switch selector says about how a case label
/// written as a simple name binds.
enum JavaSwitchSelectorType {
    /// The selector's type is a type this workspace indexes. JLS 14.11 admits
    /// four selector families: an enum, `String`, an integral primitive or its
    /// box, and, in a pattern switch, any reference type. Only the enum both
    /// names a workspace declaration and admits a simple-name label -- a
    /// pattern switch spells its labels as `pattern` nodes, which never reach
    /// here -- so the label binds in this type's member scope.
    Indexed(CodeUnit),
    /// The selector's type is one of the JLS 14.11 non-enum selector types. A
    /// simple-name label on such a switch is a constant variable, which the
    /// ordinary lexical scope resolves.
    ConstantVariable,
    /// The selector's static type was not determined, so no scope is known to
    /// bind the label.
    Unknown,
}

/// The JLS 14.11 selector types on which a simple-name case label denotes a
/// constant variable rather than an enum constant. `long`, `float`, `double`
/// and `boolean` are absent because a switch may not select on them at all.
const JAVA_CONSTANT_VARIABLE_SELECTOR_TYPES: &[&str] = &[
    "char",
    "byte",
    "short",
    "int",
    "Character",
    "Byte",
    "Short",
    "Integer",
    "String",
];

#[allow(clippy::too_many_arguments)]
fn java_switch_selector_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    label: Node<'_>,
) -> JavaSwitchSelectorType {
    if !session.charge_scope_step() {
        return JavaSwitchSelectorType::Unknown;
    }
    let Some(selector) =
        brokk_bifrost_jvm::java::graph_support::java_switch_selector_expression(label)
    else {
        return JavaSwitchSelectorType::Unknown;
    };
    if let Some(owner) =
        java_sole_receiver_type(analyzer, token, session, file, source, root, selector)
    {
        return JavaSwitchSelectorType::Indexed(owner.unit);
    }
    if let Some(type_text) = java_expression_type_text(
        analyzer,
        token,
        java,
        session,
        file,
        source,
        root,
        selector,
        selector.start_byte(),
    ) {
        return match java_raw_type_name(&type_text) {
            Some(raw) if JAVA_CONSTANT_VARIABLE_SELECTOR_TYPES.contains(&raw.as_str()) => {
                JavaSwitchSelectorType::ConstantVariable
            }
            // A named reference type this workspace does not index. It could be
            // an enum whose constants live outside the workspace, so nothing
            // here proves the label is a constant variable.
            _ => JavaSwitchSelectorType::Unknown,
        };
    }
    // No declaration names this selector's type, so the only remaining evidence
    // is the operator the selector applies. Java has no operator overloading:
    // an arithmetic, bitwise or shift result and a primitive cast are numeric
    // or `String`, never an enum. Every other shape -- an array access, a
    // conditional, an unresolved call -- can be enum-typed and stays unknown.
    match selector.kind() {
        "binary_expression" | "unary_expression" => JavaSwitchSelectorType::ConstantVariable,
        "cast_expression" => match selector.child_by_field_name("type") {
            Some(type_node)
                if matches!(type_node.kind(), "integral_type" | "floating_point_type") =>
            {
                JavaSwitchSelectorType::ConstantVariable
            }
            _ => JavaSwitchSelectorType::Unknown,
        },
        _ => JavaSwitchSelectorType::Unknown,
    }
}

/// Where a Java type spelling is written.
///
/// The scope that resolves a spelling travels with it: a simple name means
/// whatever its own compilation unit's nesting, imports and package say, and a
/// type parameter is in scope only inside the declaration that writes it. The
/// byte range addresses the spelling's node in that file's tree, so a spelling
/// that outlives the tree it came from can be resolved again later (#2048).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JavaTypeSpelling {
    file: ProjectFile,
    start_byte: usize,
    end_byte: usize,
}

impl JavaTypeSpelling {
    fn new(file: &ProjectFile, node: Node<'_>) -> Self {
        Self {
            file: file.clone(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        }
    }
}

/// A class a Java receiver's static type gives member lookup, with the type
/// arguments the receiver's spelling supplied.
///
/// Member lookup runs against `unit`. `arguments` keeps the spelling's type
/// arguments in declaration order so a member whose declared return type names
/// one of `unit`'s own type parameters can be substituted (JLS 4.5.2) instead
/// of stopping at a spelling no class carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JavaReceiverType {
    unit: CodeUnit,
    arguments: Vec<JavaTypeSpelling>,
}

impl JavaReceiverType {
    /// A receiver whose type supplies no type arguments this walk can read.
    fn plain(unit: CodeUnit) -> Self {
        Self {
            unit,
            arguments: Vec::new(),
        }
    }
}

fn java_push_receiver_type(types: &mut Vec<JavaReceiverType>, candidate: JavaReceiverType) {
    if !types.contains(&candidate) {
        types.push(candidate);
    }
}

/// Every class a Java receiver expression's static type gives member lookup.
///
/// Empty is "nothing structural typed this receiver". Exactly one entry is the
/// ordinary case. More than one is a type parameter with an intersection bound
/// (`T extends A & B`), whose member surface is every bound's at once.
fn java_receiver_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Vec<JavaReceiverType> {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let types =
        java_receiver_types_for_java(analyzer, token, java, session, file, source, root, object);
    if !types.is_empty() {
        return types;
    }
    if matches!(object.kind(), "this" | "super") {
        return java_enclosing_receiver_type(analyzer, session, file, root, object.start_byte())
            .into_iter()
            .collect();
    }
    Vec::new()
}

/// The receiver type an unqualified member reference reads: the class that
/// lexically encloses it.
///
/// Inside its own body a generic class's type arguments are its own type
/// parameters (JLS 8.1.2), so a member that returns one of them substitutes
/// back to that parameter, whose bound then carries the member surface. Census
/// sibling `AbstractFieldMatrix.walkInRowOrder` is exactly this shape:
/// `getEntry(i, col).multiply(...)` calls an abstract `T getEntry(...)` on the
/// implicit `this`.
fn java_enclosing_receiver_type(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    byte: usize,
) -> Option<JavaReceiverType> {
    let unit = session.enclosing_unit(analyzer, file, byte)?;
    let arguments = session
        .smallest_named_node_covering(root, byte, byte.saturating_add(1))
        .and_then(|node| java_enclosing_type_declaration(session, node))
        .map(|declaration| {
            brokk_bifrost_jvm::java::graph_support::java_declared_type_parameters(declaration)
                .into_iter()
                .filter_map(brokk_bifrost_jvm::java::graph_support::java_type_parameter_name_node)
                .map(|name| JavaTypeSpelling::new(file, name))
                .collect()
        })
        .unwrap_or_default();
    Some(JavaReceiverType { unit, arguments })
}

/// The one class a Java receiver's static type names.
///
/// A surface that must report a single type -- `get_type`, a switch selector --
/// cannot choose between the bounds of an intersection bound, so several types
/// answer nothing rather than the first one written.
fn java_sole_receiver_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<JavaReceiverType> {
    let mut types = java_receiver_types(analyzer, token, session, file, source, root, object);
    (types.len() == 1).then(|| types.remove(0))
}

#[allow(clippy::too_many_arguments)]
fn java_receiver_types_for_java(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Vec<JavaReceiverType> {
    match object.kind() {
        "object_creation_expression"
        | "type_identifier"
        | "scoped_type_identifier"
        | "generic_type"
        | "annotated_type" => java_receiver_type_node(session, file, source, root, object)
            .map(|type_node| {
                java_receiver_types_in_tree(analyzer, token, java, session, file, source, type_node)
            })
            .unwrap_or_default(),
        "identifier" => {
            let name = java_node_text(object, source);
            // One scope-aware seeding pass answers both questions: which type
            // the identifier is declared with on the active lexical path, and
            // whether any binding on that path shadows the spelling. A binding
            // in a sibling scope must not block resolving the name as a type
            // (#1569).
            let bindings =
                java_bindings_before_scoped(session, file, source, root, object.start_byte());
            if let Some(declared) = first_precise(&bindings, name) {
                let types = java_receiver_types_of_spelling(
                    analyzer, token, java, session, file, source, root, &declared,
                );
                if !types.is_empty() {
                    return types;
                }
            }
            if let Some(unit) = java_lambda_parameter_type_before(
                analyzer,
                token,
                java,
                session,
                file,
                source,
                root,
                name,
                object.start_byte(),
            ) {
                return vec![JavaReceiverType::plain(unit)];
            }
            if bindings.is_shadowed(name) {
                return Vec::new();
            }
            java_type_text_with_context(
                analyzer,
                token,
                java,
                session,
                file,
                name,
                object.start_byte(),
            )
            .map(JavaReceiverType::plain)
            .into_iter()
            .collect()
        }
        // A method-call receiver (`getABC().i`) is typed by the called method's
        // declared return type, which the call's own receiver may have to
        // supply a type argument for.
        "method_invocation" => {
            let binding = java_method_invocation_binding(
                analyzer, token, session, file, source, root, object,
            );
            let Some(method_unit) = binding.outcome.definitions.into_iter().next() else {
                return Vec::new();
            };
            let mut receiver = binding.receiver;
            if object.child_by_field_name("object").is_none() {
                // An unqualified call reads the enclosing class. Its receiver is
                // only computed here, where a chained type actually needs it.
                receiver.extend(java_enclosing_receiver_type(
                    analyzer,
                    session,
                    file,
                    root,
                    object.start_byte(),
                ));
            }
            java_method_return_types(
                analyzer,
                token,
                java,
                session,
                file,
                source,
                root,
                &receiver,
                &method_unit,
            )
        }
        "field_access" => {
            let Some(field_node) = object.child_by_field_name("field") else {
                return Vec::new();
            };
            let field = java_node_text(field_node, source);
            let Some(receiver) = object.child_by_field_name("object") else {
                return Vec::new();
            };
            let mut types = Vec::new();
            for owner in java_receiver_types(analyzer, token, session, file, source, root, receiver)
            {
                if let Some(unit) =
                    java_field_access_type(analyzer, token, java, session, &owner.unit, field)
                {
                    java_push_receiver_type(&mut types, JavaReceiverType::plain(unit));
                }
            }
            types
        }
        _ => Vec::new(),
    }
}

/// The class a field access denotes: the declared type of the field its owner
/// declares, or a nested type of the owner when the spelling names one.
fn java_field_access_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
    field: &str,
) -> Option<CodeUnit> {
    let qualified_name = format!("{}.{}", owner.fq_name(), field);
    let candidates = session.fqn(&qualified_name);
    if let Some(field_unit) = candidates.iter().find(|unit| unit.is_field()) {
        let type_text = java_signature_metadata(analyzer, Some(session), field_unit)
            .into_iter()
            .find_map(|metadata| metadata.return_type_text().map(str::to_owned))?;
        // A field's declared type is written in the field's own compilation
        // unit, so its simple name resolves through that file's nesting,
        // imports and package -- never through the imports of whatever file
        // happens to read the field. Census witness 3e6b7efe is exactly this:
        // `configuration.command` is declared `CCommand`, a type in the owner's
        // package that the reading file never imports, so typing the receiver
        // against the reading file left the switch selector unknown (#2043).
        let normalized = normalize_java_type_text(&type_text);
        return java_nested_type_in_scope(analyzer, session, Some(owner.clone()), normalized)
            .or_else(|| {
                session.resolve_type_name_in_file(token, java, field_unit.source(), normalized)
            });
    }
    candidates.into_iter().find(CodeUnit::is_class)
}

/// The type node a Java receiver expression's static type is written at, when
/// the receiver names one. A call or a field read has no written type, so this
/// answers nothing for those shapes.
fn java_receiver_type_node<'tree>(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'tree>,
    object: Node<'tree>,
) -> Option<Node<'tree>> {
    match object.kind() {
        "object_creation_expression" => object.child_by_field_name("type"),
        "type_identifier" | "scoped_type_identifier" | "generic_type" | "annotated_type" => {
            Some(object)
        }
        "identifier" => {
            let bindings =
                java_bindings_before_scoped(session, file, source, root, object.start_byte());
            let declared = first_precise(&bindings, java_node_text(object, source))?;
            session.smallest_named_node_covering(root, declared.start_byte, declared.end_byte)
        }
        _ => None,
    }
}

/// Every class the type spelled at `type_node` gives member lookup.
///
/// A spelling that names a class denotes that class. A spelling that names a
/// type parameter denotes the parameter's written upper bounds (JLS 4.4), which
/// is where that parameter's member surface actually is; an intersection bound
/// denotes every bound at once. A parameter with no `extends` clause is bounded
/// only by `java.lang.Object`, which no workspace indexes, so it denotes
/// nothing and the receiver stays fail-closed.
///
/// The type-parameter question is asked first because a type parameter shadows
/// any class of the same spelling (JLS 6.4), and asking it costs one walk up
/// the spelling's own ancestors.
fn java_receiver_types_in_tree(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Vec<JavaReceiverType> {
    if !session.charge_scope_step() {
        return Vec::new();
    }
    let normalized = normalize_java_type_text(java_node_text(type_node, source));
    if normalized.is_empty() {
        return Vec::new();
    }
    if let Some(parameter) = brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
        type_node, source, normalized,
    ) {
        return java_type_parameter_types(analyzer, token, java, session, file, source, parameter);
    }
    java_type_text_with_context(
        analyzer,
        token,
        java,
        session,
        file,
        normalized,
        type_node.start_byte(),
    )
    .map(|unit| JavaReceiverType {
        unit,
        arguments: brokk_bifrost_jvm::java::graph_support::java_type_argument_nodes(type_node)
            .into_iter()
            .map(|argument| JavaTypeSpelling::new(file, argument))
            .collect(),
    })
    .into_iter()
    .collect()
}

/// What a type parameter denotes for member lookup: the classes its written
/// bounds name.
///
/// A bound may name the parameter it bounds -- `T extends FieldElement<T>` is
/// the shape the census witness is written in -- so the request records an
/// expansion before it starts one and reuses a finished expansion instead of
/// repeating it. The recorded-but-unfinished state is the only genuine cycle: a
/// bound that resolves to a class stores its arguments unresolved, so ordinary
/// self-reference never re-enters this function at all.
fn java_type_parameter_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    parameter: Node<'_>,
) -> Vec<JavaReceiverType> {
    let key = JavaTypeSpelling::new(file, parameter);
    let recorded = session
        .type_parameter_bounds
        .borrow()
        .get(&key)
        .cloned()
        .map(|expanded| expanded.unwrap_or_default());
    if let Some(expanded) = recorded {
        return expanded;
    }
    session
        .type_parameter_bounds
        .borrow_mut()
        .insert(key.clone(), None);
    let mut expanded = Vec::new();
    for bound in brokk_bifrost_jvm::java::graph_support::java_type_parameter_bounds(parameter) {
        for candidate in
            java_receiver_types_in_tree(analyzer, token, java, session, file, source, bound)
        {
            java_push_receiver_type(&mut expanded, candidate);
        }
    }
    session
        .type_parameter_bounds
        .borrow_mut()
        .insert(key, Some(expanded.clone()));
    expanded
}

/// Every class the type written at `spelling` gives member lookup. The caller's
/// tree serves when the spelling is written in the caller's own file; any other
/// file is read and parsed, because a simple name resolves through the
/// compilation unit that writes it.
#[allow(clippy::too_many_arguments)]
fn java_receiver_types_of_spelling(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    spelling: &JavaTypeSpelling,
) -> Vec<JavaReceiverType> {
    if &spelling.file == file {
        return session
            .smallest_named_node_covering(root, spelling.start_byte, spelling.end_byte)
            .map(|node| {
                java_receiver_types_in_tree(analyzer, token, java, session, file, source, node)
            })
            .unwrap_or_default();
    }
    let Some(other_source) = session.read_source(&spelling.file) else {
        return Vec::new();
    };
    let Some(tree) = session.parse_java_source(&other_source) else {
        return Vec::new();
    };
    session
        .smallest_named_node_covering(tree.root_node(), spelling.start_byte, spelling.end_byte)
        .map(|node| {
            java_receiver_types_in_tree(
                analyzer,
                token,
                java,
                session,
                &spelling.file,
                &other_source,
                node,
            )
        })
        .unwrap_or_default()
}

/// What a method's declared return type resolves to on its own.
enum JavaReturnType {
    /// The classes the spelling names, already resolved in the method's file.
    Types(Vec<JavaReceiverType>),
    /// The spelling names the declaring class's own type parameter at this
    /// position. The receiver's type argument fills it exactly; `bounds` is what
    /// the parameter names without one, which is still a true upper bound.
    OwnerTypeParameter {
        index: usize,
        bounds: Vec<JavaReceiverType>,
    },
}

/// The classes a method's declared return type gives the next member lookup in
/// a chain.
///
/// The return type lives on the method's declaration AST node (the stored
/// signature keeps only the parameter list) and is written in the method's own
/// file, so that file's scope resolves it.
///
/// A return type that names one of the *declaring class's* type parameters is
/// the type argument the receiver supplied at that position (JLS 4.5.2).
/// Without that substitution the census witness stops after one hop:
/// `FieldElement<T>.add` returns `FieldElement`'s own unbounded `T`, which
/// names no class at all.
#[allow(clippy::too_many_arguments)]
fn java_method_return_types(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: &[JavaReceiverType],
    method_unit: &CodeUnit,
) -> Vec<JavaReceiverType> {
    let Some(method_range) = session.ranges(analyzer, method_unit).first().copied() else {
        return Vec::new();
    };
    let method_file = method_unit.source();
    let returned = if method_file == file {
        java_return_type_of(
            analyzer,
            token,
            java,
            session,
            file,
            source,
            root,
            &method_range,
        )
    } else {
        let Some(method_source) = session.read_source(method_file) else {
            return Vec::new();
        };
        let Some(tree) = session.parse_java_source(&method_source) else {
            return Vec::new();
        };
        java_return_type_of(
            analyzer,
            token,
            java,
            session,
            method_file,
            &method_source,
            tree.root_node(),
            &method_range,
        )
    };
    let (index, bounds) = match returned {
        JavaReturnType::Types(types) => return types,
        JavaReturnType::OwnerTypeParameter { index, bounds } => (index, bounds),
    };
    // Only a receiver typed as the declaring class itself carries the arguments
    // this method's own type parameters stand for. A member reached through a
    // supertype would need that supertype's arguments, which the spelling this
    // walk read never supplied, so it falls back to the parameter's own bounds.
    let owner = session.parent_of(analyzer, method_unit);
    let mut types = Vec::new();
    for candidate in receiver {
        if owner.as_ref() != Some(&candidate.unit) {
            continue;
        }
        let Some(argument) = candidate.arguments.get(index) else {
            continue;
        };
        for resolved in java_receiver_types_of_spelling(
            analyzer, token, java, session, file, source, root, argument,
        ) {
            java_push_receiver_type(&mut types, resolved);
        }
    }
    if types.is_empty() { bounds } else { types }
}

#[allow(clippy::too_many_arguments)]
fn java_return_type_of(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    method_range: &Range,
) -> JavaReturnType {
    let Some(declaration) = java_method_declaration_covering(session, root, method_range) else {
        return JavaReturnType::Types(Vec::new());
    };
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return JavaReturnType::Types(Vec::new());
    };
    let normalized = normalize_java_type_text(java_node_text(type_node, source));
    if let Some(parameter) = brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
        type_node, source, normalized,
    ) && let Some(owner) = java_enclosing_type_declaration(session, declaration)
        && let Some(index) =
            brokk_bifrost_jvm::java::graph_support::java_declared_type_parameters(owner)
                .into_iter()
                .position(|declared| declared == parameter)
    {
        // A parameter the method itself writes is not in the owner's list, so
        // it falls through to the ordinary bound expansion below.
        return JavaReturnType::OwnerTypeParameter {
            index,
            bounds: java_type_parameter_types(
                analyzer, token, java, session, file, source, parameter,
            ),
        };
    }
    JavaReturnType::Types(java_receiver_types_in_tree(
        analyzer, token, java, session, file, source, type_node,
    ))
}

/// The innermost `method_declaration` whose span covers `range`.
fn java_method_declaration_covering<'tree>(
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
        if contains && node.kind() == "method_declaration" {
            result = Some(node);
        }
        next = java_next_named_preorder(root, node, contains);
    }
    result
}

/// The class-like declaration that lexically encloses `node`.
fn java_enclosing_type_declaration<'tree>(
    session: &JavaResolutionSession<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if !session.charge_scope_step() {
            return None;
        }
        if matches!(
            candidate.kind(),
            "class_declaration" | "interface_declaration" | "record_declaration"
        ) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
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
    token: QueryToken<'_>,
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
        java_type_from_node_with_context(analyzer, token, java, session, file, source, qualifier)?;
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
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    scoped: Node<'_>,
) -> bool {
    java_scoped_type_qualifier_text(session, scoped, source)
        .and_then(|qualifier| session.resolve_type_name_in_file(token, java, file, qualifier))
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
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java_type_text_with_context(
        analyzer,
        token,
        java,
        session,
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
        type_node.start_byte(),
    )
}

fn java_type_text_with_context(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
        && let Some(unit) = java_local_type_in_scope(analyzer, session, file, normalized, byte)
    {
        return Some(unit);
    }
    if !normalized.contains('.')
        && let Some(unit) = java_nested_type_in_scope(
            analyzer,
            session,
            session.enclosing_unit(analyzer, file, byte),
            normalized,
        )
    {
        return Some(unit);
    }
    session.resolve_type_name_in_file(token, java, file, normalized)
}

/// Find a method- or lambda-local class visible at `byte`.
///
/// Local classes are indexed below the executable declaration that contains
/// them, rather than below the enclosing class. Their scope begins at the
/// declaration and ends with the nearest Java lexical scope node containing
/// that declaration. The AST range check prevents a sibling block or a later
/// declaration from shadowing an ordinary package or member type (#2271).
fn java_local_type_in_scope(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    let mut owner = session.enclosing_owner(analyzer, file, byte);
    while let Some(current) = owner {
        if current.is_module() {
            break;
        }
        if !current.is_class() {
            let candidates = session
                .direct_children(analyzer, &current)
                .into_iter()
                .filter(|candidate| {
                    candidate.is_class()
                        && candidate.identifier() == normalized
                        && candidate.source() == file
                        && java_local_type_candidate_visible(
                            analyzer, session, file, candidate, byte,
                        )
                })
                .collect::<Vec<_>>();
            if candidates.len() == 1 {
                return candidates.into_iter().next();
            }
            if candidates.len() > 1 {
                return None;
            }
        }
        owner = session.parent_of(analyzer, &current);
    }
    None
}

fn java_local_type_candidate_visible(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    candidate: &CodeUnit,
    byte: usize,
) -> bool {
    if candidate.source() != file {
        return false;
    }
    let Some(source) = session.read_source(file) else {
        return false;
    };
    let Some(tree) = session.parse_java_source(&source) else {
        return false;
    };
    session
        .ranges(analyzer, candidate)
        .into_iter()
        .any(|range| {
            if range.start_byte >= byte {
                return false;
            }
            let Some(declaration) = session.smallest_named_node_covering(
                tree.root_node(),
                range.start_byte,
                range.end_byte,
            ) else {
                return false;
            };
            java_local_type_scope_contains(declaration, byte)
        })
}

/// Find `normalized` as a nested type of `scope` or of one of its enclosing
/// types. The seed is a declaration rather than a position because the scope a
/// simple type name is written in is not always the position that reads it: a
/// field's declared type is written in the field's own class (#2043).
fn java_nested_type_in_scope(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    scope: Option<CodeUnit>,
    normalized: &str,
) -> Option<CodeUnit> {
    if normalized.contains('.') || normalized.is_empty() {
        return None;
    }
    let mut owner = scope;
    while let Some(current) = owner {
        let child_fqn = format!("{}.{}", current.fq_name(), normalized);
        if let Some(child) = session.fqn(&child_fqn).into_iter().find(CodeUnit::is_class) {
            return Some(child);
        }
        // A Java lexical type scope is not broken by the callable, lambda, or
        // anonymous body a scope is written in: a name written inside an
        // anonymous class body still sees the enclosing class's nested types,
        // and a class local to a method body is itself indexed under that
        // method (#2045), so every owner on the chain is asked. Only a package
        // ends the chain: packages are module parents in the analyzer graph,
        // not lexical type scopes.
        owner = session
            .parent_of(analyzer, &current)
            .filter(|parent| !parent.is_module());
    }
    None
}

/// The class an identifier's declared type names at `before_byte`.
///
/// This is the declared type itself, not the member surface a receiver of that
/// type reads: a variable declared `T` has the type parameter `T`, and saying
/// it has the parameter's bound would misreport what the declaration writes.
/// Receiver typing asks the other question through [`java_receiver_types`].
#[allow(clippy::too_many_arguments)]
fn java_type_of_identifier_before(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let bindings = java_bindings_before_scoped(session, file, source, root, before_byte);
    let declared = first_precise(&bindings, name)?;
    let type_node =
        session.smallest_named_node_covering(root, declared.start_byte, declared.end_byte)?;
    java_type_from_node_with_context(analyzer, token, java, session, file, source, type_node)
}

/// Every local binding visible at `cutoff_start`, recorded as the type spelling
/// each one is declared with.
///
/// A spelling rather than a resolved class, because what a spelling denotes
/// depends on the question: a declaration's written type is a type parameter
/// itself, while a receiver of that type reads the parameter's bound (#2048).
/// Deferring resolution to the read also keeps the walk from resolving a type
/// for every binding it passes when one of them is asked about.
fn java_bindings_before_scoped(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<JavaTypeSpelling> {
    java_bindings_before_scoped_inner(session, file, source, root, cutoff_start, true)
}

fn java_local_binding_before(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    cutoff_start: usize,
) -> bool {
    java_bindings_before_scoped_inner(session, file, source, root, cutoff_start, false)
        .is_shadowed(name)
}

fn java_bindings_before_scoped_inner(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
    include_fields: bool,
) -> LocalInferenceEngine<JavaTypeSpelling> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    java_seed_active_path(
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
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    include_fields: bool,
    bindings: &mut LocalInferenceEngine<JavaTypeSpelling>,
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
        let enters_scope = is_java_local_type_scope_node(node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            next = java_next_named_preorder(root, node, false);
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
            java_seed_scope_declarations(session, file, source, node, cutoff_start, bindings);
        } else {
            java_seed_inline_typed_binding_inner(
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
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<JavaTypeSpelling>,
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
                        java_seed_inline_typed_binding(session, file, source, parameter, bindings);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                java_seed_inline_typed_binding(session, file, source, parameter, bindings);
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
                    java_seed_typed_name_binding(file, source, resource, bindings);
                }
            }
        }
        _ => {}
    }
}

fn java_seed_inline_typed_binding(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<JavaTypeSpelling>,
) {
    java_seed_inline_typed_binding_inner(session, file, source, node, true, bindings);
}

fn java_seed_inline_typed_binding_inner(
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    include_fields: bool,
    bindings: &mut LocalInferenceEngine<JavaTypeSpelling>,
) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration"
            if include_fields || node.kind() == "local_variable_declaration" =>
        {
            let declared = node
                .child_by_field_name("type")
                .map(|type_node| JavaTypeSpelling::new(file, type_node));
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
                match declared.as_ref() {
                    Some(spelling) => bindings.seed_symbol(binding_name, spelling.clone()),
                    None => bindings.declare_shadow(binding_name),
                }
            }
        }
        "formal_parameter" => java_seed_typed_name_binding(file, source, node, bindings),
        _ => {}
    }
}

fn java_seed_typed_name_binding(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<JavaTypeSpelling>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = java_node_text(name, source);
    match node.child_by_field_name("type") {
        Some(type_node) => {
            bindings.seed_symbol(binding_name, JavaTypeSpelling::new(file, type_node))
        }
        None => bindings.declare_shadow(binding_name),
    }
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_before(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
        token,
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
        token,
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
    token: QueryToken<'_>,
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
                    token,
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
                token,
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
            token,
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
    token: QueryToken<'_>,
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
            token,
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
        token,
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
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "assignment_expression" => {
            let left = expression.child_by_field_name("left")?;
            java_expression_type_text(
                analyzer,
                token,
                java,
                session,
                file,
                source,
                root,
                left,
                before_byte,
            )
        }
        "identifier" => {
            let name = java_node_text(expression, source);
            java_identifier_type_text_before(
                session,
                token,
                java,
                file,
                source,
                root,
                name,
                before_byte,
            )
            .or_else(|| {
                java_lambda_parameter_type_text_before(
                    analyzer,
                    token,
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
            let owner =
                java_sole_receiver_type(analyzer, token, session, file, source, root, object)?.unit;
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
                    token,
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

#[allow(clippy::too_many_arguments)]
fn java_identifier_type_text_before(
    session: &JavaResolutionSession<'_>,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    let mut next = Some(root);
    while let Some(node) = next {
        if !session.charge_scope_step() {
            return found;
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
                            return found;
                        }
                        if child.kind() == "variable_declarator"
                            && let Some(name_node) = child.child_by_field_name("name")
                            && name_node.start_byte() < before_byte
                            && java_node_text(name_node, source) == name
                        {
                            found = Some(type_text.to_string());
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
                    found = Some(
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
            .resolve_type_name_in_file(token, java, file, name)
            .is_some()
    {
        found = Some(name.to_string());
    }
    found
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
    java_terminal_segment(raw)
}

/// The final `.`-joined segment of a Java-spelled qualified name (an import
/// path or type reference, with any generic argument list already stripped by
/// the caller). Java identifiers never contain a literal `.`, so re-tokenizing
/// with the shared structured splitter and taking the last segment reproduces
/// `rsplit('.').next()`'s terminal split exactly.
fn java_terminal_segment(path: &str) -> Option<String> {
    crate::analyzer::symbol_lookup::parse_symbol_path(Language::Java, path)
        .pop()
        .filter(|segment| !segment.is_empty())
}

/// The per-candidate attribution the Java member walk records while it runs,
/// built only when a trace is being recorded (#1477). The walk itself decides
/// nothing from it; it is an emission of facts the walk already holds: which
/// hierarchy type each candidate was found on, at which BFS depth, and through
/// which first-discovery parent chain.
#[derive(Default)]
struct JavaMemberTrace {
    /// First-discovery parent of each ancestor the walk expanded, which makes
    /// the route reconstruction a bounded walk back to the receiver's owner.
    parents: HashMap<CodeUnit, CodeUnit>,
    /// Candidate declaration -> (hierarchy type it was found on, BFS depth).
    found: HashMap<CodeUnit, (CodeUnit, usize)>,
}

impl JavaMemberTrace {
    fn record_found(&mut self, candidates: &[CodeUnit], found_on: &CodeUnit, depth: usize) {
        for candidate in candidates {
            self.found
                .entry(candidate.clone())
                .or_insert_with(|| (found_on.clone(), depth));
        }
    }

    /// The exact hierarchy route from `base` to the type `candidate` was found
    /// on, as first-discovery hops. The provider reports undifferentiated
    /// ancestors, so every hop is [`HierarchyRelation::Supertype`].
    fn route(&self, base: &CodeUnit, candidate: &CodeUnit) -> Vec<trace::HierarchyHopRecord> {
        use crate::analyzer::structural::HierarchyRelation;

        let Some((found_on, depth)) = self.found.get(candidate) else {
            return Vec::new();
        };
        let mut chain = vec![found_on.clone()];
        while chain.last() != Some(base) {
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
            depth + 1,
            "the first-discovery chain must be exactly the BFS depth"
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
        base: &CodeUnit,
        candidate: &CodeUnit,
        applicability: brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict,
    ) -> Option<trace::MemberEnrichment> {
        use crate::analyzer::structural::MemberDispatchTier;

        let (found_on, depth) = self.found.get(candidate)?;
        let dispatch_tier = if *depth == 0 {
            MemberDispatchTier::InherentOrDirect
        } else {
            MemberDispatchTier::InheritedOrPromoted
        };
        Some(trace::MemberEnrichment {
            owner: found_on.clone(),
            hierarchy_depth: *depth,
            dispatch_tier,
            applicability,
            route: self.route(base, candidate),
        })
    }

    /// Stage attribution for the candidates this lookup is about to bind, and
    /// record every refused candidate it discarded as a rejected row.
    ///
    /// `applicability` is the *same* value the caller used to decide what to
    /// bind (#1478 M3): the winners here are the winners the resolver bound,
    /// and each row's verdict and typed reason are the ones the check produced.
    /// `bound` is what the seam actually returns, which is `winners` where the
    /// call's argument count is known, the whole considered set where it is not
    /// (every verdict is then `unknown`), and empty where nothing accepted the
    /// call. A bound candidate is never reported as rejected.
    ///
    /// On the resolution axis a refused candidate keeps
    /// [`RejectionReason::CallableApplicabilityDeferred`]: that reason now
    /// points at real evidence rather than standing in for it, because the
    /// candidate's applicability row carries the exact callable reason.
    fn stage_selection(
        &self,
        base: &CodeUnit,
        applicability: &ApplicabilityOutcome,
        bound: &[CodeUnit],
    ) {
        use crate::analyzer::structural::PrecedenceTier;

        let tier_of = |unit: &CodeUnit| {
            self.found.get(unit).map(|(_, depth)| {
                if *depth == 0 {
                    PrecedenceTier::OwnMember
                } else {
                    PrecedenceTier::InheritedMember
                }
            })
        };
        for verdict in &applicability.verdicts {
            if verdict.verdict != ApplicabilityVerdict::Inapplicable
                || bound.contains(&verdict.candidate)
            {
                continue;
            }
            let mut row = trace::TraceCandidate::rejected(
                trace::TraceCandidateRef::Unit(verdict.candidate.clone()),
                tier_of(&verdict.candidate),
                RejectionReason::CallableApplicabilityDeferred,
            )
            .with_callable(trace::CallableApplicabilityRecord {
                verdict: verdict.verdict,
                reason: verdict.reason,
            });
            if let Some(enrichment) =
                self.enrichment(base, &verdict.candidate, ApplicabilityVerdict::Inapplicable)
            {
                row = row.with_member(enrichment);
            }
            trace::record(row);
        }
        let winner_tier = bound
            .iter()
            .filter_map(|unit| self.found.get(unit))
            .map(|(_, depth)| *depth)
            .min()
            .map(|depth| {
                if depth == 0 {
                    PrecedenceTier::OwnMember
                } else {
                    PrecedenceTier::InheritedMember
                }
            });
        if let Some(tier) = winner_tier {
            trace::stage_tier(tier, bound.iter().map(|unit| unit.fq_name()).collect());
        }
        let verdict_of = |unit: &CodeUnit| {
            applicability
                .verdicts
                .iter()
                .find(|verdict| verdict.candidate == *unit)
        };
        trace::stage_member_context(
            bound
                .iter()
                .filter_map(|unit| {
                    let applicability = verdict_of(unit)
                        .map(|verdict| verdict.verdict)
                        .unwrap_or(ApplicabilityVerdict::Unknown);
                    self.enrichment(base, unit, applicability)
                        .map(|enrichment| (unit.fq_name(), enrichment))
                })
                .collect(),
        );
        trace::stage_callable_context(
            bound
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

/// Resolve a bare Java member through each lexical class scope, from the
/// innermost class outward. Each scope runs its complete member and ancestor
/// walk before the next scope starts (#1905).
#[allow(clippy::too_many_arguments)]
fn java_member_candidates_in_enclosing_chain(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    owners: Vec<CodeUnit>,
    initial_static_context: bool,
    outer_static_context: bool,
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> JavaEnclosingMemberResolution {
    let mut innermost_failure = None;
    let mut walk_incomplete = false;
    let mut static_context = initial_static_context;
    for (owner_index, owner) in owners.into_iter().enumerate() {
        if owner_index > 0 {
            static_context |= outer_static_context;
        }
        if !session.charge_scope_step() {
            return JavaEnclosingMemberResolution {
                outcome: no_definition(
                    "java_resolution_stopped",
                    "Java member resolution stopped before completion",
                ),
                static_import_fallback_allowed: false,
            };
        }
        let outcome = java_member_candidates(analyzer, token, session, &owner, member, kind, arity);
        if session.is_stopped() {
            return JavaEnclosingMemberResolution {
                outcome,
                static_import_fallback_allowed: false,
            };
        }
        let outcome = if static_context {
            java_static_context_member_outcome(analyzer, session, outcome, kind, member)
        } else {
            outcome
        };
        // A scope whose own hierarchy leaves the indexed workspace has not
        // answered the lookup: an anonymous body written against `Runnable`,
        // or a local class implementing an interface this workspace does not
        // index, reaches that gate for every name it does not itself declare.
        // Java stops the simple-name walk only at the scope that declares the
        // name, so the boundary claim must not stop it either -- it is kept as
        // the reported failure instead, so a site nothing else resolves still
        // reports the boundary it crossed (#1126's invariant, applied to the
        // lexical chain, #2046).
        let crossed_boundary = outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary;
        if outcome.status != DefinitionLookupStatus::NoDefinition && !crossed_boundary {
            return JavaEnclosingMemberResolution {
                outcome,
                static_import_fallback_allowed: false,
            };
        }
        if !crossed_boundary {
            match java_member_declared_in_hierarchy(analyzer, session, &owner, member, kind) {
                JavaMemberHierarchyResolution::Declared
                | JavaMemberHierarchyResolution::Incomplete => {
                    return JavaEnclosingMemberResolution {
                        outcome,
                        static_import_fallback_allowed: false,
                    };
                }
                JavaMemberHierarchyResolution::NoDeclaration => {}
            }
        }
        walk_incomplete |= crossed_boundary;
        innermost_failure.get_or_insert(outcome);
        static_context |= java_class_is_static(analyzer, session, &owner);
    }
    let outcome = innermost_failure.unwrap_or_else(|| {
        no_definition(
            "no_enclosing_class",
            format!("`{member}` has no enclosing indexed Java class"),
        )
    });
    JavaEnclosingMemberResolution {
        static_import_fallback_allowed: !walk_incomplete
            && outcome.status == DefinitionLookupStatus::NoDefinition,
        outcome,
    }
}

fn java_class_is_static(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
) -> bool {
    session
        .signature_metadata(analyzer, owner)
        .iter()
        .any(|metadata| metadata.class_like_is_static())
}

fn java_member_is_static(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    member: &CodeUnit,
    kind: JavaMemberLookupKind,
) -> bool {
    session
        .signature_metadata(analyzer, member)
        .iter()
        .any(|metadata| match kind {
            JavaMemberLookupKind::Field => metadata.field_is_static(),
            JavaMemberLookupKind::Method => metadata.callable_is_static(),
            JavaMemberLookupKind::Type => false,
        })
}

fn java_static_context_member_outcome(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    outcome: DefinitionLookupOutcome,
    kind: JavaMemberLookupKind,
    member: &str,
) -> DefinitionLookupOutcome {
    if outcome.definitions.is_empty() {
        return outcome;
    }
    let definitions: Vec<_> = outcome
        .definitions
        .iter()
        .filter(|candidate| java_member_is_static(analyzer, session, candidate, kind))
        .cloned()
        .collect();
    if definitions.is_empty() {
        return no_definition(
            "java_static_context",
            format!("`{member}` is an instance Java member outside a static context"),
        );
    }
    if definitions.len() == outcome.definitions.len() {
        outcome
    } else {
        candidates_outcome(definitions)
    }
}

enum JavaMemberHierarchyResolution {
    Declared,
    NoDeclaration,
    Incomplete,
}

fn java_member_declared_in_hierarchy(
    analyzer: &dyn IAnalyzer,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
    member: &str,
    kind: JavaMemberLookupKind,
) -> JavaMemberHierarchyResolution {
    let direct = java_owned_member_candidates(
        session.fqn(&format!("{}.{}", owner.fq_name(), member)),
        kind,
        owner,
    );
    if session.is_stopped() {
        return JavaMemberHierarchyResolution::Incomplete;
    }
    if !direct.is_empty() {
        return JavaMemberHierarchyResolution::Declared;
    }
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return JavaMemberHierarchyResolution::Incomplete;
    };
    let mut seen = HashSet::default();
    seen.insert(owner.clone());
    let mut level = session.direct_ancestors(provider, owner);
    if session.is_stopped() {
        return JavaMemberHierarchyResolution::Incomplete;
    }
    while !level.is_empty() {
        let mut next = Vec::new();
        for current in level {
            if !seen.insert(current.clone()) {
                continue;
            }
            if !java_owned_member_candidates(
                session.fqn(&format!("{}.{}", current.fq_name(), member)),
                kind,
                &current,
            )
            .is_empty()
            {
                return JavaMemberHierarchyResolution::Declared;
            }
            if session.is_stopped() {
                return JavaMemberHierarchyResolution::Incomplete;
            }
            next.extend(session.direct_ancestors(provider, &current));
            if session.is_stopped() {
                return JavaMemberHierarchyResolution::Incomplete;
            }
        }
        level = next;
    }
    JavaMemberHierarchyResolution::NoDeclaration
}

fn java_member_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let support: &dyn BoundedDefinitionLookup = session;
    let owner_fqn = owner.fq_name();
    let mut member_trace = trace::recording().then(JavaMemberTrace::default);
    let mut candidates =
        java_owned_member_candidates(support.fqn(&format!("{owner_fqn}.{member}")), kind, owner);
    sort_units(&mut candidates);
    candidates.dedup();
    if let Some(state) = member_trace.as_mut() {
        state.record_found(&candidates, owner, 0);
    }
    // One applicability computation decides what to bind and what to report
    // (#1478 M3): `winners` is the production filter, `verdicts` is the
    // evidence, and neither can drift from the other.
    let applicability = java_candidate_applicability(analyzer, session, &candidates, arity);
    if arity.is_some() && !applicability.winners.is_empty() {
        if let Some(state) = member_trace.as_ref() {
            state.stage_selection(owner, &applicability, &applicability.winners);
        }
        return candidates_outcome(applicability.winners);
    }
    if !candidates.is_empty() && arity.is_none() {
        if let Some(state) = member_trace.as_ref() {
            state.stage_selection(owner, &applicability, &candidates);
        }
        return candidates_outcome(candidates);
    }
    if !candidates.is_empty() {
        // Arity is known and nothing accepted (#1755): the direct set is
        // discarded, never bound. Record the discard as rejected rows.
        if let Some(state) = member_trace.as_ref() {
            state.stage_selection(owner, &applicability, &[]);
        }
    }

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = session.direct_ancestors(provider, owner);
        if let Some(state) = member_trace.as_mut() {
            for ancestor in &level {
                state
                    .parents
                    .entry(ancestor.clone())
                    .or_insert_with(|| owner.clone());
            }
        }
        seen.insert(owner.clone());
        let mut depth = 0usize;
        while !level.is_empty() {
            depth += 1;
            let mut level_candidates = Vec::new();
            let mut declaring_owner_by_candidate = HashMap::default();
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
                let found = java_owned_member_candidates(
                    support.fqn(&format!("{}.{}", ancestor.fq_name(), member)),
                    kind,
                    &ancestor,
                );
                if let Some(state) = member_trace.as_mut() {
                    state.record_found(&found, &ancestor, depth);
                }
                for candidate in &found {
                    declaring_owner_by_candidate.insert(candidate.clone(), ancestor.clone());
                }
                level_candidates.extend(found);
                let expanded = session.direct_ancestors(provider, &ancestor);
                if let Some(state) = member_trace.as_mut() {
                    for next in &expanded {
                        state
                            .parents
                            .entry(next.clone())
                            .or_insert_with(|| ancestor.clone());
                    }
                }
                next_level.extend(expanded);
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let level_applicability =
                java_candidate_applicability(analyzer, session, &level_candidates, arity);
            if arity.is_some() && !level_applicability.winners.is_empty() {
                let winners = java_prefer_class_method_candidates(
                    analyzer,
                    kind,
                    level_applicability.winners.clone(),
                    &declaring_owner_by_candidate,
                );
                if let Some(state) = member_trace.as_ref() {
                    state.stage_selection(owner, &level_applicability, &winners);
                }
                return candidates_outcome(winners);
            }
            if !level_candidates.is_empty() {
                if arity.is_none() {
                    let candidates = java_prefer_class_method_candidates(
                        analyzer,
                        kind,
                        level_candidates,
                        &declaring_owner_by_candidate,
                    );
                    if let Some(state) = member_trace.as_ref() {
                        state.stage_selection(owner, &level_applicability, &candidates);
                    }
                    return candidates_outcome(candidates);
                }
                // JLS 15.12.2 applicability (#1755): a level set with no
                // accepting overload is discarded, never bound. Record the
                // discard as rejected rows while the walk still knows them.
                if let Some(state) = member_trace.as_ref() {
                    state.stage_selection(owner, &level_applicability, &[]);
                }
            }
            level = next_level;
        }
    }
    let Some(expected) = arity else {
        return no_definition(
            "no_indexed_definition",
            format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
        );
    };
    // JLS 15.12.2 applicability: an overload whose parameter list cannot accept
    // this argument list is not the target, and the inverse usage scan already
    // refuses such a site (`callable_arity_matches_target`). Binding it anyway
    // was the forward side's #1755 defect. When the owner's hierarchy leaves the
    // indexed workspace, the accepting declaration is on the far side of that
    // boundary, which is what the site must report.
    gated_boundary(
        || !java_hierarchy_crosses_unindexed_supertype(analyzer, token, session, owner),
        format!(
            "`{owner_fqn}.{member}` is inherited from a Java supertype not indexed in this workspace"
        ),
        "no_accepting_overload",
        format!("no indexed `{owner_fqn}.{member}` overload accepts {expected} arguments"),
    )
}

fn java_prefer_class_method_candidates(
    analyzer: &dyn IAnalyzer,
    kind: JavaMemberLookupKind,
    candidates: Vec<CodeUnit>,
    declaring_owner_by_candidate: &HashMap<CodeUnit, CodeUnit>,
) -> Vec<CodeUnit> {
    if kind != JavaMemberLookupKind::Method || candidates.len() < 2 {
        return candidates;
    }
    let mut owners = candidates
        .iter()
        .map(|candidate| {
            declaring_owner_by_candidate
                .get(candidate)
                .expect("hierarchy candidate has its declaring owner")
                .clone()
        })
        .collect::<Vec<_>>();
    sort_units(&mut owners);
    owners.dedup();
    let preferred = java_preferred_declaring_owners(analyzer, &owners);
    candidates
        .into_iter()
        .filter(|candidate| {
            preferred.contains(
                declaring_owner_by_candidate
                    .get(candidate)
                    .expect("hierarchy candidate has its declaring owner"),
            )
        })
        .collect()
}

/// Whether `owner`'s supertype closure names a type this workspace does not
/// index.
///
/// `java_direct_ancestors` drops a supertype spelling it cannot resolve, so the
/// resolved ancestors alone cannot tell a complete hierarchy from a truncated
/// one. The raw `extends`/`implements` spellings can, put through the very same
/// forward type-name tiers that dropped them.
///
/// A spelling is written in the declaration's own lexical scope, so the
/// enclosing-scope tier runs first: `new SetView() { ... }` inside
/// `Sets.union()` extends the workspace's own `Sets.SetView`, which the
/// file-level tier alone cannot see (#2161). Reporting that indexed supertype
/// as an unindexed one excused a genuine forward gap as an import boundary.
fn java_hierarchy_crosses_unindexed_supertype(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return false;
    };
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return false;
    };
    let mut seen = HashSet::default();
    seen.insert(owner.clone());
    let mut queue = VecDeque::from([owner.clone()]);
    while let Some(unit) = queue.pop_front() {
        if !session.observe_cancellation() {
            return false;
        }
        for raw in java.raw_supertypes_of(&unit) {
            let normalized = normalize_java_type_text(&raw);
            if java_nested_type_in_scope(analyzer, session, Some(unit.clone()), normalized)
                .is_none()
                && session
                    .resolve_type_name_in_file(token, java, unit.source(), normalized)
                    .is_none()
            {
                return true;
            }
        }
        for ancestor in session.direct_ancestors(provider, &unit) {
            if seen.insert(ancestor.clone()) {
                queue.push_back(ancestor);
            }
        }
    }
    false
}

/// The members `owner` itself declares, out of everything the workspace
/// indexes under `owner`'s fully qualified name.
///
/// Two filters apply. The kind filter keeps a field lookup off a method of the
/// same name. The physical-owner filter keeps a mirrored source tree from
/// turning one declaration into a pair of peers: a Java class body lives in
/// exactly one compilation unit, so a member indexed under this owner's name
/// but written in another file belongs to another copy of the owner, not to
/// this one (#2045). When no candidate shares the owner's file the set is
/// returned untouched, which leaves a cross-file collision honestly ambiguous.
fn java_owned_member_candidates(
    candidates: Vec<CodeUnit>,
    kind: JavaMemberLookupKind,
    owner: &CodeUnit,
) -> Vec<CodeUnit> {
    brokk_bifrost_jvm::java::graph_support::java_same_file_candidates(
        java_filter_member_candidates(candidates, kind),
        owner.source(),
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
            JavaMemberLookupKind::Type => unit.is_class(),
        })
        .collect()
}

fn java_static_import_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    member: &str,
    kind: JavaMemberLookupKind,
    arity: Option<usize>,
) -> JavaStaticImportResolution {
    let support: &dyn BoundedDefinitionLookup = session;
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return JavaStaticImportResolution {
            outcome: no_definition(
                "no_java_analyzer",
                "no Java analyzer is available for static import resolution",
            ),
            external_owner: None,
        };
    };
    let mut candidates = Vec::new();
    let mut external_owners = HashSet::default();
    for import in session.import_infos(token, java, file) {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        if path.kind != Some(crate::analyzer::StructuredImportPathKind::StaticMember) {
            continue;
        }
        if import.is_wildcard {
            let owner = path.render_segments(".");
            let mut owner_candidates =
                java_filter_member_candidates(support.fqn(&format!("{owner}.{member}")), kind);
            if owner_candidates.is_empty() {
                // Static imports may also name nested types.
                owner_candidates = java_filter_member_candidates(
                    support.fqn(&format!("{owner}.{member}")),
                    JavaMemberLookupKind::Type,
                );
            }
            if owner_candidates.is_empty()
                && let Some((leaf, outer_segments)) = path.segments.split_last()
                && !outer_segments.is_empty()
            {
                // On-demand static imports may land on nested types too.
                owner_candidates = java_filter_member_candidates(
                    support.fqn(&format!("{}${leaf}.{member}", outer_segments.join("."))),
                    kind,
                );
            }
            if owner_candidates.is_empty() && !java_workspace_fqn_exists(support, &owner) {
                external_owners.insert(owner);
            }
            candidates.extend(owner_candidates);
            continue;
        }
        let Some((imported_member, owner_segments)) = path.segments.split_last() else {
            continue;
        };
        if owner_segments.is_empty() || imported_member != member {
            continue;
        }
        let owner = owner_segments.join(".");
        let path_fqn = path.render_segments(".");
        let mut imported = java_filter_member_candidates(support.fqn(&path_fqn), kind);
        if imported.is_empty() {
            // Static imports may also name nested types
            // (`import static com.x.Tacos.Burritos`).
            imported =
                java_filter_member_candidates(support.fqn(&path_fqn), JavaMemberLookupKind::Type);
        }
        if imported.is_empty() {
            // The index keys nested types with `$`, not `.` (tier-4
            // spoon/mockito static-import claims).
            imported = java_filter_member_candidates(
                support.fqn(&format!("{owner}${imported_member}")),
                kind,
            );
        }
        if imported.is_empty() && !java_workspace_fqn_exists(support, &owner) {
            external_owners.insert(owner);
        }
        candidates.extend(imported);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    // An external identity is safe only for one unambiguous external route.
    // Workspace candidates and competing owners remain a typed boundary; they
    // must not be converted into a name-only summary binding.
    let saw_external = !external_owners.is_empty();
    let external_owner = (candidates.is_empty() && external_owners.len() == 1)
        .then(|| external_owners.into_iter().next())
        .flatten();
    let applicability = java_candidate_applicability(analyzer, session, &candidates, arity);
    if arity.is_some() && !saw_external && !applicability.winners.is_empty() {
        java_record_callable_applicability(&applicability, &applicability.winners);
        return JavaStaticImportResolution {
            outcome: candidates_outcome(applicability.winners),
            external_owner: None,
        };
    }
    // A statically imported overload that cannot accept the call's argument list
    // is not the target (#1755), so it never stands in for one that can.
    if !candidates.is_empty() && !saw_external && arity.is_none() {
        java_record_callable_applicability(&applicability, &candidates);
        return JavaStaticImportResolution {
            outcome: candidates_outcome(candidates),
            external_owner: None,
        };
    }
    if !candidates.is_empty() {
        java_record_callable_applicability(&applicability, &[]);
    }
    // `saw_external` is set only when an import target is both unindexed and
    // `!java_workspace_fqn_exists(owner)`, so `!saw_external` is the workspace
    // gate (no double work — the flag already carries the check).
    JavaStaticImportResolution {
        outcome: gated_boundary(
            || !saw_external,
            format!(
                "`{member}` appears to cross a Java static import boundary not indexed in this workspace"
            ),
            "no_static_import_match",
            format!("`{member}` did not match an indexed Java static import"),
        ),
        external_owner,
    }
}

fn java_import_boundary_for_type(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let support: &dyn BoundedDefinitionLookup = session;
    for import in session.import_infos(token, java, file) {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        if path.kind == Some(crate::analyzer::StructuredImportPathKind::StaticMember) {
            continue;
        }
        if import.is_wildcard {
            let package = path.render_segments(".");
            if !package.is_empty() && !java_workspace_package_exists(support, &package) {
                return true;
            }
            continue;
        }
        if path.segments.last().map(String::as_str) == Some(name) {
            let package = path.segments[..path.segments.len() - 1].join(".");
            return !java_workspace_package_exists(support, &package);
        }
    }
    false
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
