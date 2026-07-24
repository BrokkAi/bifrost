use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::lexical_definitions::{
    PythonMethodBinding, formal_parameter_slots_for_owner_bounded,
};
use crate::analyzer::python::bindings::{
    PythonLexicalNameResolution, PythonLexicalScopeInventory,
    python_unambiguous_module_class_binding_bounded,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const PYTHON_RECEIVER_TYPE_CACHE_LIMIT: usize = 512;

pub(crate) struct PythonDefinitionProvider<'a> {
    python: &'a PythonAnalyzer,
    session: &'a ResolutionSession,
}

impl<'a> PythonDefinitionProvider<'a> {
    pub(crate) fn new(python: &'a PythonAnalyzer, session: &'a ResolutionSession) -> Self {
        Self { python, session }
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    pub(crate) fn identifier(&self, identifier: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_identifier_limited(identifier, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.identifier(identifier)
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect()
    }

    pub(crate) fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.python
                .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    pub(crate) fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.python.ranges_limited(unit, limit))
    }

    fn scope_step(&self) -> bool {
        self.session.scope_step()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PythonTypeLookupResolution {
    pub(crate) unit: CodeUnit,
    pub(crate) target_kind: TypeLookupTargetKind,
}

pub(crate) fn resolve_python_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_definition(
            "python_parse_failed",
            "Python source could not be parsed",
        ));
    };
    let support = PythonDefinitionProvider::new(python, &session);
    let Some(node) = python_smallest_named_node_covering_bounded(
        &support,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return session.finish(no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        ));
    };
    let outcome = match python_reference_node_bounded(&support, node) {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let member = python_slice(attribute, source);
            let receiver = python_type_for_expression_bounded(
                &support,
                file,
                source,
                tree.root_node(),
                object,
                0,
            );
            match receiver {
                Some(receiver) if !member.is_empty() => {
                    let candidates = support.members_for_owner_name(&receiver.fq_name(), member);
                    if candidates.is_empty() {
                        no_definition(
                            "no_indexed_definition",
                            format!(
                                "`{}.{member}` is not indexed as a Python definition",
                                receiver.fq_name()
                            ),
                        )
                    } else {
                        candidates_outcome(candidates)
                    }
                }
                _ => no_definition(
                    "python_dynamic_receiver",
                    format!(
                        "`{}` has no structurally proven Python receiver type",
                        site.text
                    ),
                ),
            }
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let name = python_slice(identifier, source);
            let candidates = support.file_identifier(file, name);
            if candidates.is_empty() {
                no_definition(
                    "no_indexed_definition",
                    format!("`{name}` did not resolve to an indexed Python definition"),
                )
            } else {
                candidates_outcome(candidates)
            }
        }
        Some(PythonReferenceNode::KeywordArgument { .. }) | None => no_definition(
            "python_reference_shape_unsupported",
            format!(
                "`{}` is not a supported bounded Python reference shape",
                site.text
            ),
        ),
    };
    session.finish(outcome)
}

pub(crate) fn python_type_lookup_resolution_bounded(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<PythonTypeLookupResolution> {
    let node = python_smallest_named_node_covering_bounded(
        support,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let target_kind = if node.kind() == "identifier"
        && !python_has_lexical_binding_bounded(support, node, source)
        && python_class_candidate_for_name(support, file, source, node, python_slice(node, source))
            .is_some()
    {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    let unit = python_type_for_expression_bounded(support, file, source, root, node, 0)?;
    Some(PythonTypeLookupResolution { unit, target_kind })
}

fn python_smallest_named_node_covering_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !support.scope_step() || node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing = None;
        for child in node.named_children(&mut cursor) {
            if !support.scope_step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing = Some(child);
                break;
            }
        }
        match containing {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn python_named_children_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Vec<Node<'tree>>> {
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !support.scope_step() {
            return None;
        }
        children.push(child);
    }
    Some(children)
}

fn python_keyword_argument_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<PythonReferenceNode<'tree>> {
    if !support.scope_step() || node.kind() != "identifier" {
        return None;
    }
    let kwarg = node.parent()?;
    if !support.scope_step()
        || kwarg.kind() != "keyword_argument"
        || kwarg.child_by_field_name("name") != Some(node)
    {
        return None;
    }
    let arguments = kwarg.parent()?;
    if !support.scope_step() || arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if !support.scope_step() || call.kind() != "call" {
        return None;
    }
    Some(PythonReferenceNode::KeywordArgument { call, name: node })
}

fn python_reference_node_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<PythonReferenceNode<'tree>> {
    if let Some(keyword) = python_keyword_argument_bounded(support, node) {
        return Some(keyword);
    }
    if !support.scope_step() {
        return None;
    }
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if !support.scope_step() {
            return None;
        }
        if parent.kind() != "attribute" {
            break;
        }
        if parent.child_by_field_name("attribute") == Some(node)
            || parent.child_by_field_name("attribute") == Some(original)
        {
            node = parent;
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            Some(PythonReferenceNode::Attribute { object, attribute })
        }
        "identifier" => Some(PythonReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn python_type_for_expression_bounded(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match node.kind() {
        "identifier" => {
            let name = python_slice(node, source);
            if let Some(receiver) = python_current_receiver_class(support, file, source, node, name)
            {
                Some(receiver)
            } else if python_has_lexical_binding_bounded(support, node, source) {
                python_bound_type_for_identifier(support, file, source, root, node, name, depth + 1)
            } else {
                python_class_candidate_for_name(support, file, source, node, name)
            }
        }
        "call" => {
            let function = node.child_by_field_name("function")?;
            let callable = match function.kind() {
                "identifier" => {
                    let name = python_slice(function, source);
                    let lexical_binding = python_lexical_binding_bounded(support, function, source);
                    match lexical_binding {
                        PythonLexicalBinding::Other => return None,
                        PythonLexicalBinding::LocalFunction(declaration) => {
                            return python_function_return_type_from_node_bounded(
                                support,
                                file,
                                source,
                                root,
                                declaration,
                                depth + 1,
                            );
                        }
                        PythonLexicalBinding::UnboundOrGlobal => {
                            if let Some(class) = python_class_candidate_for_name(
                                support, file, source, function, name,
                            ) {
                                return Some(class);
                            }
                        }
                    }
                    unique_python_candidate(
                        support
                            .file_identifier(file, name)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .filter(|candidate| {
                                python_same_file_function_visible_at(
                                    support, source, function, candidate,
                                )
                                .unwrap_or(false)
                            })
                            .collect(),
                    )
                }
                "attribute" => {
                    let object = function.child_by_field_name("object")?;
                    let member = python_slice(function.child_by_field_name("attribute")?, source);
                    let receiver = python_type_for_expression_bounded(
                        support,
                        file,
                        source,
                        root,
                        object,
                        depth + 1,
                    )?;
                    unique_python_candidate(
                        support
                            .members_for_owner_name(&receiver.fq_name(), member)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .collect(),
                    )
                }
                _ => None,
            }?;
            python_callable_return_type_in_tree(support, file, source, root, &callable, depth + 1)
        }
        "parenthesized_expression" => {
            let child = node.named_child(0)?;
            python_type_for_expression_bounded(support, file, source, root, child, depth + 1)
        }
        _ => None,
    }
}

fn python_class_candidate_for_name(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if name.is_empty() {
        return None;
    }
    let mut file_candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    file_candidates.retain(|candidate| {
        python_same_file_class_visible_at(support, source, site, candidate).unwrap_or(false)
    });
    if let Some(candidate) = unique_python_candidate(file_candidates) {
        return Some(candidate);
    }
    if !name.contains('.') {
        return None;
    }
    let exact_candidates = support
        .fqn(name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    unique_python_candidate(exact_candidates)
}

#[derive(Clone, Copy)]
struct PythonReferenceVisibility<'tree> {
    class_scope: Option<Node<'tree>>,
    deferred_body: bool,
}

#[derive(Clone, Copy)]
enum PythonClassDeclarationScope<'tree> {
    Module,
    Class(Node<'tree>),
    Other,
}

#[derive(Clone, Copy)]
enum PythonFunctionDeclarationScope<'tree> {
    Module,
    Function(Node<'tree>),
    Other,
}

fn python_same_file_class_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let visibility = python_reference_visibility_bounded(support, site)?;
    let declaration = python_class_node_for_candidate_bounded(support, source, site, candidate)?;
    if !visibility.deferred_body && declaration.start_byte() > site.start_byte() {
        return Some(false);
    }
    let declaration_scope = python_class_declaration_scope_bounded(support, declaration)?;
    let visible = match declaration_scope {
        PythonClassDeclarationScope::Module => {
            let mut root = site;
            while let Some(parent) = root.parent() {
                if !support.scope_step() {
                    return None;
                }
                root = parent;
            }
            python_unambiguous_module_class_binding_bounded(
                root,
                source,
                candidate.identifier(),
                || support.scope_step(),
            )?
        }
        PythonClassDeclarationScope::Class(scope) => visibility
            .class_scope
            .is_some_and(|visible| visible == scope),
        PythonClassDeclarationScope::Other => false,
    };
    Some(visible)
}

fn python_reference_visibility_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    site: Node<'tree>,
) -> Option<PythonReferenceVisibility<'tree>> {
    let site_start = site.start_byte();
    let site_end = site.end_byte();
    let mut class_scope = None;
    let mut current = site;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return Some(PythonReferenceVisibility {
                class_scope: None,
                deferred_body: true,
            });
        }
        if class_scope.is_none() && parent.kind() == "class_definition" {
            class_scope = Some(parent);
        }
        current = parent;
    }
    Some(PythonReferenceVisibility {
        class_scope,
        deferred_body: false,
    })
}

fn python_class_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    for range in support.ranges(candidate) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if node.kind() == "class_definition"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == candidate.identifier())
            {
                return Some(node);
            }
            if node.kind() == "decorated_definition" {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !support.scope_step() {
                        return None;
                    }
                    if child.kind() == "class_definition"
                        && child.child_by_field_name("name").is_some_and(|name| {
                            python_slice(name, source) == candidate.identifier()
                        })
                    {
                        return Some(child);
                    }
                }
            }
            let Some(parent) = node.parent() else {
                break;
            };
            if !support.scope_step() {
                return None;
            }
            node = parent;
        }
    }
    None
}

fn python_class_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonClassDeclarationScope<'tree>> {
    let mut current = declaration;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "module" => return Some(PythonClassDeclarationScope::Module),
            "class_definition" => return Some(PythonClassDeclarationScope::Class(parent)),
            "decorated_definition" => current = parent,
            "function_definition" | "lambda" => {
                return Some(PythonClassDeclarationScope::Other);
            }
            "if_statement" | "for_statement" | "while_statement" | "try_statement"
            | "with_statement" | "match_statement" | "case_clause" => {
                return Some(PythonClassDeclarationScope::Other);
            }
            _ => current = parent,
        }
    }
    Some(PythonClassDeclarationScope::Other)
}

fn python_same_file_function_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let declaration = python_function_node_for_candidate_bounded(support, source, site, candidate)?;
    let visibility = python_reference_visibility_bounded(support, site)?;
    match python_function_declaration_scope_bounded(support, declaration)? {
        PythonFunctionDeclarationScope::Module => {
            Some(visibility.deferred_body || declaration.start_byte() <= site.start_byte())
        }
        PythonFunctionDeclarationScope::Function(owner) => {
            let nearest = python_enclosing_callable_bounded(support, site)?;
            let mut inside_owner = false;
            let mut current = Some(site);
            while let Some(node) = current {
                if !support.scope_step() {
                    return None;
                }
                if node == owner {
                    inside_owner = true;
                    break;
                }
                current = node.parent();
            }
            Some(
                inside_owner && (nearest != owner || declaration.start_byte() <= site.start_byte()),
            )
        }
        PythonFunctionDeclarationScope::Other => Some(false),
    }
}

fn python_function_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    for range in support.ranges(candidate) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if node.kind() == "function_definition"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == candidate.identifier())
            {
                return Some(node);
            }
            if node.kind() == "decorated_definition" {
                for child in python_named_children_bounded(support, node)? {
                    if child.kind() == "function_definition"
                        && child.child_by_field_name("name").is_some_and(|name| {
                            python_slice(name, source) == candidate.identifier()
                        })
                    {
                        return Some(child);
                    }
                }
            }
            let Some(parent) = node.parent() else {
                break;
            };
            if !support.scope_step() {
                return None;
            }
            node = parent;
        }
    }
    None
}

fn python_function_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonFunctionDeclarationScope<'tree>> {
    let mut current = declaration;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "module" => return Some(PythonFunctionDeclarationScope::Module),
            "function_definition" | "lambda" => {
                return Some(PythonFunctionDeclarationScope::Function(parent));
            }
            "decorated_definition" => current = parent,
            "class_definition" | "if_statement" | "for_statement" | "while_statement"
            | "try_statement" | "with_statement" | "match_statement" | "case_clause" => {
                return Some(PythonFunctionDeclarationScope::Other);
            }
            _ => current = parent,
        }
    }
    Some(PythonFunctionDeclarationScope::Other)
}

fn unique_python_candidate(mut candidates: Vec<CodeUnit>) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn python_current_receiver_class(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if !matches!(name, "self" | "cls") {
        return None;
    }
    let function = python_enclosing_callable_bounded(support, node)?;
    let layout = formal_parameter_slots_for_owner_bounded(
        Language::Python,
        function,
        source,
        &node_range(function),
        || support.scope_step(),
    )?;
    if matches!(layout.python_binding, Some(PythonMethodBinding::Static))
        || layout
            .slots
            .first()
            .is_none_or(|slot| !slot.names.iter().any(|candidate| candidate == name))
    {
        return None;
    }
    let mut parent = function.parent();
    while let Some(candidate) = parent {
        if !support.scope_step() {
            return None;
        }
        if candidate.kind() == "class_definition" {
            let class_name = candidate.child_by_field_name("name")?;
            return python_class_candidate_for_name(
                support,
                file,
                source,
                node,
                python_slice(class_name, source),
            );
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") {
            return None;
        }
        parent = candidate.parent();
    }
    None
}

fn python_bound_type_for_identifier(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    identifier: Node<'_>,
    name: &str,
    depth: usize,
) -> Option<CodeUnit> {
    let function = python_enclosing_callable_bounded(support, identifier)?;
    if let Some(parameters) = function.child_by_field_name("parameters")
        && let Some(annotation) =
            python_parameter_annotation_bounded(support, parameters, source, name)
    {
        return python_type_from_annotation_bounded(support, file, source, annotation, depth + 1);
    }

    let body = function.child_by_field_name("body")?;
    let mut best: Option<Node<'_>> = None;
    let mut stack = vec![body];
    while let Some(candidate) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if candidate.start_byte() >= identifier.start_byte() {
            continue;
        }
        if candidate != body
            && matches!(
                candidate.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if candidate.kind() == "assignment"
            && let Some(left) = candidate.child_by_field_name("left")
            && left.kind() == "identifier"
            && python_slice(left, source) == name
            && best.is_none_or(|previous| previous.start_byte() < candidate.start_byte())
        {
            best = Some(candidate);
        }
        let children = python_named_children_bounded(support, candidate)?;
        stack.extend(children.into_iter().rev());
    }
    let assignment = best?;
    if let Some(annotation) = assignment.child_by_field_name("type") {
        return python_type_from_annotation_bounded(support, file, source, annotation, depth + 1);
    }
    let value = assignment.child_by_field_name("right")?;
    python_type_for_expression_bounded(support, file, source, root, value, depth + 1)
}

fn python_parameter_annotation_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    parameters: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if matches!(node.kind(), "typed_parameter" | "typed_default_parameter") {
            let binding = node.child_by_field_name("name").or_else(|| {
                node.named_child(0)
                    .filter(|candidate| candidate.kind() == "identifier")
            });
            if binding.is_some_and(|binding| python_slice(binding, source) == name) {
                if let Some(annotation) = node.child_by_field_name("type") {
                    return Some(annotation);
                }
                for candidate in python_named_children_bounded(support, node)? {
                    if candidate.kind() != "identifier" {
                        return Some(candidate);
                    }
                }
                return None;
            }
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    None
}

fn python_type_from_annotation_bounded(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    annotation: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match annotation.kind() {
        "identifier" | "string_content" => python_class_candidate_for_name(
            support,
            file,
            source,
            annotation,
            python_slice(annotation, source),
        ),
        "attribute" => {
            let exact = python_slice(annotation, source);
            unique_python_candidate(
                support
                    .fqn(exact)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect(),
            )
        }
        "string" => {
            let content = python_named_children_bounded(support, annotation)?
                .into_iter()
                .find(|child| child.kind() == "string_content")?;
            python_type_from_annotation_bounded(support, file, source, content, depth + 1)
        }
        _ => {
            let mut candidates = Vec::new();
            let mut stack = vec![annotation];
            while let Some(node) = stack.pop() {
                if !support.scope_step() {
                    return None;
                }
                if node != annotation
                    && matches!(node.kind(), "identifier" | "attribute" | "string")
                    && let Some(candidate) =
                        python_type_from_annotation_bounded(support, file, source, node, depth + 1)
                {
                    candidates.push(candidate);
                    continue;
                }
                let children = python_named_children_bounded(support, node)?;
                stack.extend(children.into_iter().rev());
            }
            unique_python_candidate(candidates)
        }
    }
}

fn python_callable_return_type_in_tree(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callable: &CodeUnit,
    depth: usize,
) -> Option<CodeUnit> {
    if callable.source() != file || depth >= 12 {
        return None;
    }
    let ranges = support.ranges(callable);
    let mut functions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "function_definition"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| python_slice(name, source) == callable.identifier())
            && ranges.iter().any(|range| {
                range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte
            })
        {
            functions.push(node);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    let function = (functions.len() == 1).then(|| functions.remove(0))?;
    python_function_return_type_from_node_bounded(support, file, source, root, function, depth)
}

fn python_function_return_type_from_node_bounded(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if let Some(annotation) = function.child_by_field_name("return_type") {
        return python_type_from_annotation_bounded(support, file, source, annotation, depth + 1);
    }

    let body = function.child_by_field_name("body")?;
    let mut returns = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
            && let Some(candidate) =
                python_type_for_expression_bounded(support, file, source, root, value, depth + 1)
        {
            returns.push(candidate);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    unique_python_candidate(returns)
}

fn python_enclosing_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if !support.scope_step() {
            return None;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

fn python_has_lexical_binding_bounded(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'_>,
    source: &str,
) -> bool {
    !matches!(
        python_lexical_binding_bounded(support, identifier, source),
        PythonLexicalBinding::UnboundOrGlobal
    )
}

#[derive(Clone, Copy, Debug)]
enum PythonLexicalBinding<'tree> {
    UnboundOrGlobal,
    LocalFunction(Node<'tree>),
    Other,
}

fn python_lexical_binding_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'tree>,
    source: &str,
) -> PythonLexicalBinding<'tree> {
    let name = python_slice(identifier, source);
    let reference_start = identifier.start_byte();
    let reference_end = identifier.end_byte();
    let mut current = identifier;
    let mut unresolved_nonlocal = false;
    while let Some(candidate) = current.parent() {
        if !support.scope_step() {
            // Exhausted or cancelled binding discovery must never reopen the
            // module-level class fallback.
            return PythonLexicalBinding::Other;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda")
            && candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        {
            let Some(inventory) =
                PythonLexicalScopeInventory::collect_bounded(candidate, source, || {
                    support.scope_step()
                })
            else {
                return PythonLexicalBinding::Other;
            };
            match inventory.name_resolution_at(name, identifier) {
                PythonLexicalNameResolution::Local => {
                    let Some(declaration) = inventory.local_function_declaration(name, identifier)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(PythonFunctionDeclarationScope::Function(owner)) =
                        python_function_declaration_scope_bounded(support, declaration)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(nearest) = python_enclosing_body_callable_bounded(support, identifier)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    return if owner == candidate
                        && (nearest != owner || declaration.start_byte() <= identifier.start_byte())
                    {
                        PythonLexicalBinding::LocalFunction(declaration)
                    } else {
                        PythonLexicalBinding::Other
                    };
                }
                PythonLexicalNameResolution::Nonlocal => unresolved_nonlocal = true,
                PythonLexicalNameResolution::Global => {
                    return PythonLexicalBinding::UnboundOrGlobal;
                }
                PythonLexicalNameResolution::Unbound => {}
            }
        }
        current = candidate;
    }
    if unresolved_nonlocal {
        PythonLexicalBinding::Other
    } else {
        PythonLexicalBinding::UnboundOrGlobal
    }
}

fn python_enclosing_body_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let reference_start = node.start_byte();
    let reference_end = node.end_byte();
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if !support.scope_step() {
            return None;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda")
            && candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

pub(super) fn resolve_python(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("python_parse_failed", "Python source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        );
    };
    if python_is_non_reference_context(node) || python_is_declaration_identifier(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Python reference site", site.text),
        );
    }

    let ctx = context.python_context(py, file);
    let support = context.bounded_support();
    let reference = python_reference_node(node);
    match reference {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let object_text = python_slice(object, source);
            let attribute_text = python_slice(attribute, source);
            if object_text.is_empty() || attribute_text.is_empty() {
                return no_definition("no_reference_text", "Python attribute reference is blank");
            }
            let object_shadowed = python_name_shadowed_at(
                object_text,
                tree.root_node(),
                site.range.start_byte,
                source,
            );
            if !object_shadowed && let Some(module) = ctx.namespace_module_for_node(object, source)
            {
                return python_fqn_outcome(
                    py,
                    support,
                    &format!("{module}.{attribute_text}"),
                    site.text.as_str(),
                );
            }
            if !object_shadowed
                && let Some(receiver_type) = ctx.receiver_type_for_object(py, support, object_text)
            {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                object,
            ) {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if object_shadowed {
                return no_definition(
                    "local_variable_reference",
                    format!("`{object_text}` is a local Python value"),
                );
            }
            if python_unresolved_import_boundary(file, analyzer, object_text, Some(attribute_text))
            {
                return boundary(format!(
                    "`{object_text}.{attribute_text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "`{}` did not resolve to an indexed Python definition",
                    site.text
                ),
            )
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let text = python_slice(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "Python identifier is blank");
            }
            if python_name_shadowed_at(text, tree.root_node(), site.range.start_byte, source) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Python value"),
                );
            }
            if let Some(candidates) = python_visible_module_binding_candidates(
                analyzer,
                py,
                support,
                &ctx,
                source,
                tree.root_node(),
                identifier,
                text,
            ) {
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
                if let Some(module) = ctx.namespace.get(text) {
                    return python_module_outcome(py, support, module, text);
                }
                return no_definition(
                    "no_indexed_definition",
                    format!("`{text}` is bound locally but has no indexed Python definition"),
                );
            }
            if let Some(module) = ctx.namespace.get(text) {
                return python_module_outcome(py, support, module, text);
            }
            if let Some(fqn) = ctx.named.get(text) {
                return python_fqn_outcome(py, support, fqn, text);
            }
            if let Some(candidates) = ctx.same_file.get(text)
                && !candidates.is_empty()
            {
                let candidates =
                    python_visible_same_file_candidates(analyzer, file, identifier, candidates);
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if python_unresolved_import_boundary(file, analyzer, text, None) {
                return boundary(format!(
                    "`{text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Python definition"),
            )
        }
        Some(PythonReferenceNode::KeywordArgument { call, name }) => {
            let name_text = python_slice(name, source);
            if name_text.is_empty() {
                return no_definition("no_reference_text", "Python keyword argument is blank");
            }
            let Some(function) = call.child_by_field_name("function") else {
                return no_definition("no_function_name", "Python call has no callee");
            };
            // `Foo(a=..)` -> `a` is a member/parameter of the callee's type (e.g. a
            // dataclass field `Foo.a`). Type the callee and look the name up as a
            // member.
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                function,
            ) {
                return python_member_outcome(analyzer, support, receiver_type, name_text);
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "keyword argument `{name_text}` did not resolve to an indexed Python member"
                ),
            )
        }
        None => no_definition(
            "unsupported_python_reference_shape",
            format!(
                "`{}` is a Python `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn python_visible_module_binding_candidates(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<Vec<CodeUnit>> {
    let timeline = context.module_bindings(source, root);
    let events = timeline.get(name)?;
    let cutoff = if python_reference_is_deferred_function_body(node) {
        usize::MAX
    } else {
        node.start_byte()
    };
    let visible: Vec<_> = events
        .iter()
        .filter(|event| event.visible_from <= cutoff)
        .collect();
    if visible.is_empty() {
        return Some(Vec::new());
    }
    let start = visible
        .iter()
        .rposition(|event| !event.conditional)
        .unwrap_or(0);
    let mut candidates = Vec::new();
    for event in &visible[start..] {
        match &event.kind {
            ModuleBindingEventKind::FromImport {
                module,
                imported_name,
            } => {
                let mut resolved = false;
                for module_file in py.usage_resolve_module_files(&context.file, module) {
                    let Some(module_fqn) = analyzer
                        .declarations(&module_file)
                        .into_iter()
                        .find(CodeUnit::is_module)
                        .map(|unit| unit.fq_name())
                    else {
                        continue;
                    };
                    resolved = true;
                    let fqn = format!("{module_fqn}.{imported_name}");
                    candidates.extend(
                        py.resolve_fqn_candidates(&fqn, |candidate| support.fqn(candidate)),
                    );
                }
                if !resolved {
                    let fqn = if module.ends_with('.') {
                        format!("{module}{imported_name}")
                    } else {
                        format!("{module}.{imported_name}")
                    };
                    candidates.extend(
                        py.resolve_fqn_candidates(&fqn, |candidate| support.fqn(candidate)),
                    );
                }
            }
            ModuleBindingEventKind::ImportModule(module) => {
                let bound_module = context
                    .namespace
                    .get(name)
                    .map(String::as_str)
                    .unwrap_or(module);
                candidates.extend(py.resolve_module_code_unit(bound_module));
            }
            ModuleBindingEventKind::Other => {
                if let Some(local) = context.same_file.get(name) {
                    candidates.extend(python_visible_same_file_candidates(
                        analyzer,
                        &context.file,
                        node,
                        local,
                    ));
                }
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates)
}

fn python_visible_same_file_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing_class = analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|mut scope| {
            if scope.is_function() && !python_function_declaration_expression_is_class_scoped(node)
            {
                return None;
            }
            loop {
                if scope.is_class() {
                    break Some(scope);
                }
                if scope.is_module() {
                    break None;
                }
                scope = analyzer.parent_of(&scope)?;
            }
        });
    candidates
        .iter()
        .filter(|candidate| {
            analyzer.parent_of(candidate).is_some_and(|parent| {
                parent.is_module()
                    || enclosing_class
                        .as_ref()
                        .is_some_and(|scope| scope == &parent)
            })
        })
        .cloned()
        .collect()
}

fn python_function_declaration_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            return parent.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= site_start && site_end <= body.end_byte())
            });
        }
        if parent.kind() == "decorated_definition" {
            return current.kind() == "decorator";
        }
        if parent.kind() == "class_definition" {
            break;
        }
        current = parent;
    }
    false
}

fn python_reference_is_deferred_function_body(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return true;
        }
        current = parent;
    }
    false
}

pub(super) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

pub(super) struct PythonDefinitionContext {
    file: ProjectFile,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
    scope_facts: OnceLock<Arc<HashMap<CodeUnit, LocalBindingsSnapshot<String>>>>,
    module_bindings: OnceLock<Arc<ModuleBindingTimeline>>,
    receiver_types: Mutex<PythonReceiverTypeCache>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

struct PythonReceiverTypeCache {
    limit: usize,
    values: HashMap<(String, bool), Option<CodeUnit>>,
}

impl PythonReceiverTypeCache {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            values: HashMap::default(),
        }
    }
}

impl PythonDefinitionContext {
    pub(super) fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        #[cfg(test)] build_counters: Arc<PythonDefinitionBuildCounters>,
    ) -> Self {
        let binder = py.import_binder_of(file);
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        named.insert(
                            local.clone(),
                            format!("{}.{}", binding.module_specifier, imported),
                        );
                    }
                }
                ImportKind::Namespace => {
                    namespace.insert(local.clone(), binding.module_specifier.clone());
                }
                ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
            }
        }
        let mut same_file: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in same_file.values_mut() {
            sort_units(units);
        }
        Self {
            file: file.clone(),
            named,
            namespace,
            same_file,
            scope_facts: OnceLock::new(),
            module_bindings: OnceLock::new(),
            receiver_types: Mutex::new(PythonReceiverTypeCache::new(
                PYTHON_RECEIVER_TYPE_CACHE_LIMIT,
            )),
            #[cfg(test)]
            build_counters,
        }
    }

    fn namespace_module_for_node(&self, object: Node<'_>, source: &str) -> Option<String> {
        let mut attributes = Vec::new();
        let mut current = object;
        while current.kind() == "attribute" {
            let attribute = current.child_by_field_name("attribute")?;
            let text = python_slice(attribute, source);
            if text.is_empty() {
                return None;
            }
            attributes.push(text);
            current = current.child_by_field_name("object")?;
        }
        if current.kind() != "identifier" {
            return None;
        }
        let root = python_slice(current, source);
        let mut module = self.namespace.get(root)?.clone();
        for attribute in attributes.into_iter().rev() {
            module.push('.');
            module.push_str(attribute);
        }
        Some(module)
    }

    fn receiver_type_for_object(
        &self,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        object: &str,
    ) -> Option<CodeUnit> {
        if let Some(fqn) = self.named.get(object) {
            return python_class_for_fqn(py, support, fqn);
        }
        self.same_file
            .get(object)?
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    }

    fn receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        let raw_type = raw_type.trim();
        if &self.file != file {
            return self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file);
        }

        let key = (raw_type.to_string(), target_self_file);
        if let Some(cached) = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .get(&key)
        {
            return cached.clone();
        }

        #[cfg(test)]
        self.build_counters
            .receiver_type_cache_misses
            .fetch_add(1, Ordering::Relaxed);

        let resolved = self
            .receiver_type_for_object(py, support, raw_type)
            .or_else(|| self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file));

        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        if cache.values.len() < cache.limit {
            cache.values.insert(key, resolved.clone());
        }
        resolved
    }

    fn generic_receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        #[cfg(test)]
        self.build_counters
            .generic_receiver_type_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        resolve_python_receiver_type(analyzer, py, file, raw_type, target_self_file)
    }

    #[cfg(test)]
    pub(super) fn set_receiver_type_cache_limit(&self, limit: usize) {
        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        cache.limit = limit;
        cache.values.clear();
    }

    #[cfg(test)]
    pub(super) fn receiver_type_cache_len(&self) -> usize {
        self.receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .len()
    }

    fn scope_facts(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        source: &str,
        root: Node<'_>,
    ) -> Arc<HashMap<CodeUnit, LocalBindingsSnapshot<String>>> {
        self.scope_facts
            .get_or_init(|| {
                let _scope = crate::profiling::scope("get_definition::python::scope_facts");
                #[cfg(test)]
                self.build_counters
                    .scope_fact_builds
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(collect_scope_facts_from_parsed_source(
                    analyzer, py, file, source, root,
                ))
            })
            .clone()
    }

    fn module_bindings(&self, source: &str, root: Node<'_>) -> Arc<ModuleBindingTimeline> {
        self.module_bindings
            .get_or_init(|| Arc::new(collect_module_binding_timeline(root, source)))
            .clone()
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct PythonDefinitionBuildCounters {
    pub(super) context_builds: AtomicUsize,
    pub(super) scope_fact_builds: AtomicUsize,
    pub(super) receiver_type_cache_misses: AtomicUsize,
    pub(super) generic_receiver_type_fallbacks: AtomicUsize,
}

enum PythonReferenceNode<'tree> {
    Identifier(Node<'tree>),
    Attribute {
        object: Node<'tree>,
        attribute: Node<'tree>,
    },
    /// A keyword argument `name=value` in a call `Callee(name=..)`: `name` resolves
    /// to the callee type's member/parameter (e.g. a dataclass field `Foo.a`), not
    /// a name in scope.
    KeywordArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A keyword-argument identifier (`a` in `Foo(a=3)`): the `name` of a
/// `keyword_argument` inside a call's `argument_list`.
fn python_keyword_argument(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    if node.kind() != "identifier" {
        return None;
    }
    let kwarg = node
        .parent()
        .filter(|parent| parent.kind() == "keyword_argument")?;
    if kwarg.child_by_field_name("name") != Some(node) {
        return None;
    }
    let call = kwarg
        .parent()
        .filter(|parent| parent.kind() == "argument_list")?
        .parent()
        .filter(|parent| parent.kind() == "call")?;
    Some(PythonReferenceNode::KeywordArgument { call, name: node })
}

fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    if let Some(keyword) = python_keyword_argument(node) {
        return Some(keyword);
    }
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if parent.kind() == "attribute" {
            if parent.child_by_field_name("attribute") == Some(node)
                || parent.child_by_field_name("attribute") == Some(original)
            {
                node = parent;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            Some(PythonReferenceNode::Attribute { object, attribute })
        }
        "identifier" => Some(PythonReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn python_fqn_outcome(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    let candidates = py.resolve_fqn_candidates(fqn, |name| support.fqn(name));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if python_crosses_unindexed_boundary(support, fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial Python workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed Python definition was found"),
    )
}

fn python_module_outcome(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    module_fq: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    if let Some(module) = py.resolve_module_code_unit(module_fq) {
        return candidates_outcome(vec![module]);
    }
    if python_crosses_unindexed_boundary(support, module_fq) {
        return boundary(format!(
            "`{raw}` resolves to module `{module_fq}`, which is outside this partial Python workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to module `{module_fq}`, but no indexed Python module was found"),
    )
}

fn python_class_for_fqn(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Option<CodeUnit> {
    py.resolve_fqn_candidates(fqn, |name| support.fqn(name))
        .into_iter()
        .find(|unit| unit.is_class())
}

fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    receiver_type: CodeUnit,
    member: &str,
) -> DefinitionLookupOutcome {
    // Members use a `.` separator; a nested class is indexed with `$`
    // (`Outer$Inner`), so try both.
    let member_candidates = |owner: &str| {
        let mut units = support.fqn(&format!("{owner}.{member}"));
        if units.is_empty() {
            units = support.fqn(&format!("{owner}${member}"));
        }
        units
    };
    let mut candidates = member_candidates(&receiver_type.fq_name());
    if candidates.is_empty()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        for ancestor in provider.get_ancestors(&receiver_type) {
            candidates.extend(member_candidates(&ancestor.fq_name()));
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "`{}.{member}` is not indexed as a Python definition",
                receiver_type.fq_name()
            ),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn python_crosses_unindexed_boundary(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    let Some((module, _)) = fqn.rsplit_once('.') else {
        return !python_workspace_module_exists(support, "");
    };
    !python_workspace_module_exists(support, module)
}

fn python_workspace_module_exists(support: &dyn BoundedDefinitionLookup, module: &str) -> bool {
    if module.is_empty() {
        return false;
    }
    support.package_exists(module) || support.fqn_exists(module)
}

#[allow(clippy::too_many_arguments)]
fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "identifier" => {
            let receiver = python_slice(object, source);
            if let Some(unit) =
                python_self_receiver_type(analyzer, py, file, root, object, receiver)
            {
                return Some(unit);
            }
            // A typed-variable receiver: use the local/parameter's inferred type.
            let facts_by_scope = context.scope_facts(analyzer, py, file, source, root);
            if let Some(facts) = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)
                && let Some(raw_type) = facts
                    .resolution_for(receiver)
                    .as_precise()
                    .and_then(|targets| targets.iter().next().cloned())
                && let Some(unit) =
                    context.receiver_type(analyzer, py, support, file, &raw_type, false)
            {
                return Some(unit);
            }
            // A class-name receiver: `ClassName.Nested` / `ClassName.member`
            // accesses a member on the class itself.
            let class = context.receiver_type(analyzer, py, support, file, receiver, false);
            if class.is_some() {
                return class;
            }
            let binder = py.import_binder_of(file);
            let binding = binder.bindings.get(receiver)?;
            let imported = binding.imported_name.as_ref()?;
            let fqn = format!("{}.{}", binding.module_specifier, imported);
            python_class_for_fqn(py, support, &fqn)
        }
        // A call receiver: `Foo().bar` (construction) or `make().bar` (the
        // called function/method's return type).
        "call" => {
            python_call_result_type(analyzer, py, support, context, file, source, root, object)
        }
        _ => None,
    }
}

/// The type produced by a call expression: the class for a construction
/// (`Foo()`), or the resolved return type of the called function/method
/// (`make()`, `obj.make()`).
#[allow(clippy::too_many_arguments)]
fn python_call_result_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<CodeUnit> {
    let function = call.child_by_field_name("function")?;
    let callee =
        python_resolve_callable(analyzer, py, support, context, file, source, root, function)?;
    if callee.is_class() {
        return Some(callee);
    }
    python_callable_return_type(analyzer, py, support, context, &callee)
}

/// Resolve a call's callee expression to the class or function/method being
/// called.
#[allow(clippy::too_many_arguments)]
fn python_resolve_callable(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
) -> Option<CodeUnit> {
    match function.kind() {
        "identifier" => {
            let name = python_slice(function, source);
            if let Some(class) = context.receiver_type(analyzer, py, support, file, name, false) {
                return Some(class);
            }
            analyzer
                .declarations(file)
                .into_iter()
                .find(|unit| unit.identifier() == name && unit.is_function())
        }
        "attribute" => {
            let receiver = function.child_by_field_name("object")?;
            let method = python_slice(function.child_by_field_name("attribute")?, source);
            let receiver_type = python_receiver_type_unit(
                analyzer, py, support, context, file, source, root, receiver,
            )?;
            analyzer
                .definitions(&format!("{}.{}", receiver_type.fq_name(), method))
                .next()
        }
        _ => None,
    }
}

/// The declared or inferred return type of a Python function/method: read a
/// `-> T` annotation, else infer from a `return T(...)` / `return T` in the
/// body. Resolved in the callable's own file.
fn python_callable_return_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    callable: &CodeUnit,
) -> Option<CodeUnit> {
    let file = callable.source();
    let source = analyzer.get_source(callable, false)?;
    let tree = parse_python_tree(&source)?;
    let function = python_first_function_definition(tree.root_node())?;

    if let Some(return_type) = function.child_by_field_name("return_type") {
        let text = python_slice(return_type, &source).trim();
        if let Some(class) = context.receiver_type(analyzer, py, support, file, text, true) {
            return Some(class);
        }
    }

    let body = function.child_by_field_name("body")?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        // Don't descend into nested functions/classes — their returns are theirs.
        if matches!(node.kind(), "function_definition" | "class_definition") {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
        {
            let name = match value.kind() {
                "call" => value
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|f| python_slice(f, &source)),
                "identifier" => Some(python_slice(value, &source)),
                _ => None,
            };
            let class = name
                .and_then(|name| context.receiver_type(analyzer, py, support, file, name, true));
            if let Some(class) = class {
                return Some(class);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_first_function_definition(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_self_receiver_type(
    analyzer: &dyn IAnalyzer,
    _py: &PythonAnalyzer,
    file: &ProjectFile,
    _root: Node<'_>,
    object: Node<'_>,
    receiver: &str,
) -> Option<CodeUnit> {
    if receiver != "self" && receiver != "cls" {
        return None;
    }
    let range = Range {
        start_byte: object.start_byte(),
        end_byte: object.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .filter(|unit| unit.is_class())
}

fn python_unresolved_import_boundary(
    file: &ProjectFile,
    analyzer: &dyn IAnalyzer,
    local: &str,
    attribute: Option<&str>,
) -> bool {
    let Some(provider) = analyzer.import_analysis_provider() else {
        return false;
    };
    for import in provider.import_info_of(file) {
        let alias_or_identifier = import.alias.as_deref().or(import.identifier.as_deref());
        if alias_or_identifier == Some(local) {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != local);
        }
        if let Some(attribute) = attribute
            && import.identifier.as_deref() == Some(attribute)
            && import.alias.as_deref().unwrap_or(attribute) == attribute
        {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != attribute);
        }
    }
    false
}

fn python_name_shadowed_at(name: &str, root: Node<'_>, byte: usize, source: &str) -> bool {
    let Some(scope) = python_enclosing_function(root, byte) else {
        return false;
    };
    let mut locals = HashSet::default();
    if let Some(parameters) = scope.child_by_field_name("parameters") {
        python_collect_parameter_names(parameters, source, &mut locals);
    }
    if let Some(body) = scope.child_by_field_name("body") {
        python_collect_bound_targets(body, source, &mut locals);
    }
    locals.contains(name)
}

fn python_enclosing_function<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if matches!(node.kind(), "function_definition" | "lambda") {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn python_collect_parameter_names(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let name = match child.kind() {
            "identifier" => Some(child),
            _ => child.child_by_field_name("name").or_else(|| {
                child
                    .named_child(0)
                    .filter(|node| node.kind() == "identifier")
            }),
        };
        if let Some(name) = name {
            let text = python_slice(name, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
        }
    }
}

fn python_collect_bound_targets(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = python_slice(name, source).trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
                continue;
            }
            "lambda" => continue,
            "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                if let Some(left) = node.child_by_field_name("left") {
                    collect_assigned_identifiers(left, source, out);
                }
            }
            "named_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    collect_assigned_identifiers(name, source, out);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn python_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "import_statement"
                | "import_from_statement"
                | "comment"
                | "string"
                | "string_content"
                | "module"
        ) && current.kind() != "module"
        {
            return true;
        }
        parent = current.parent();
    }
    false
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    value{index} = {index}\n"))
            .collect::<String>();
        let expression = format!("{}service{}.run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "class Service:\n    def run(self) -> None:\n        pass\n\n\
             def use(service: Service) -> None:\n{statements}    {expression}\n"
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("receiver.py", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "receiver.py");
        let tree = parse_python_tree(&source).expect("Python tree");
        let expression_start = source.rfind(&expression).expect("Python member call");
        let start_byte = expression_start + expression.rfind("run").expect("member name");
        let end_byte = start_byte + "run".len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        (fixture, file, source, tree, site)
    }

    #[test]
    fn bounded_python_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let outcome = resolve_python_bounded(
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
    fn bounded_python_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_python_bounded(
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
    fn bounded_python_local_function_call_retains_its_return_type() {
        let source = r#"class Product:
    def run(self) -> None:
        pass

def caller() -> None:
    def make() -> Product:
        return Product()

    value = make()
    value.run()
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("local_factory.py", source)]);
        let file = ProjectFile::new(fixture.project_root(), "local_factory.py");
        let tree = parse_python_tree(source).expect("Python tree");
        let start_byte = source.rfind("run").expect("member name");
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + "run".len(),
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "run".len(),
        };
        let outcome = resolve_python_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("local factory lookup did not complete: {outcome:#?}");
        };
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name().ends_with("Product.run")),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_python_local_function_requires_definite_visibility() {
        for (path, source) in [
            (
                "forward_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def caller() -> None:
    value = make()
    value.run()

    def make() -> Product:
        return Product()
"#,
            ),
            (
                "conditional_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def caller(flag) -> None:
    if flag:
        def make() -> Product:
            return Product()

    value = make()
    value.run()
"#,
            ),
            (
                "header_forward_local_factory.py",
                r#"class Product:
    def run(self) -> None:
        pass

def outer() -> None:
    def nested(argument=make().run()) -> None:
        pass

    def make() -> Product:
        return Product()
"#,
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(Language::Python, &[(path, source)]);
            let file = ProjectFile::new(fixture.project_root(), path);
            let tree = parse_python_tree(source).expect("Python tree");
            let start_byte = source.rfind("run").expect("member name");
            let start_line = source[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let site = ResolvedReferenceSite {
                path: rel_path_string(&file),
                text: "run".to_string(),
                range: Range {
                    start_byte,
                    end_byte: start_byte + "run".len(),
                    start_line,
                    end_line: start_line,
                },
                focus_start_byte: start_byte,
                focus_end_byte: start_byte + "run".len(),
            };
            let outcome = resolve_python_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{path} lookup did not complete: {outcome:#?}");
            };
            assert!(
                value
                    .definitions
                    .iter()
                    .all(|definition| !definition.fq_name().ends_with("Product.run")),
                "{path}: {value:#?}"
            );
        }
    }
}
