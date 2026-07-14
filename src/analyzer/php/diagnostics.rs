use crate::analyzer::semantic_diagnostics::{node_range, node_text};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::usages::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::{
    GlobalUsageDefinitionIndex, IAnalyzer, PhpAnalyzer, PhpFileContext, ProjectFile, Range,
    SemanticDiagnostic, resolve_analyzer, resolve_php_constant, resolve_php_function,
    resolve_php_type,
};
use crate::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub(crate) const PHP_UNRECOGNIZED_SYMBOL: &str = "php_unrecognized_symbol";
pub(crate) const PHP_UNRECOGNIZED_MEMBER: &str = "php_unrecognized_member";
pub(crate) const PHP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-php";
const MAX_PHP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_PHP_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhpSemanticDiagnostic {
    pub(crate) range: Range,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

impl From<PhpSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: PhpSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: PHP_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Conservative PHP unresolved-reference diagnostics.
///
/// This pass intentionally stays inside Bifrost's indexed PHP model. It reports
/// only references whose namespace/member owner is already known to the
/// analyzer, and it suppresses dynamic PHP behavior such as variable class
/// names, variable function names, variable member names, magic members, and
/// external Composer/vendor symbols that are not indexed by this workspace.
pub(crate) fn collect_php_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<PhpSemanticDiagnostic> {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return Vec::new();
    };
    if source.len() > MAX_PHP_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = parse_php_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let support = analyzer.global_usage_definition_index();
    let line_starts = compute_line_starts(source);
    let ctx = php.file_context_from_source(file, source);
    let mut collector = PhpDiagnosticCollector {
        php,
        analyzer,
        support,
        file,
        source,
        line_starts: &line_starts,
        ctx,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

struct PhpDiagnosticCollector<'a> {
    php: &'a PhpAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a GlobalUsageDefinitionIndex,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    ctx: PhpFileContext,
    diagnostics: Vec<PhpSemanticDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    Type,
    Function,
    Constant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberAccessKind {
    InstanceCall,
    InstanceProperty,
    StaticCall,
    StaticProperty,
    ClassConstant,
}

impl PhpDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = vec![root];
        while let Some(scope) = scopes.pop() {
            if self.diagnostics.len() >= MAX_PHP_SEMANTIC_DIAGNOSTICS {
                break;
            }
            let mut bindings = LocalInferenceEngine::default();
            if is_local_scope(scope) {
                seed_parameter_types(scope, self.source, &self.ctx, &mut bindings);
            }
            self.scan_scope(scope, &mut bindings, &mut scopes);
        }
    }

    fn scan_scope<'tree>(
        &mut self,
        root: Node<'tree>,
        bindings: &mut LocalInferenceEngine<String>,
        scopes: &mut Vec<Node<'tree>>,
    ) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.diagnostics.len() >= MAX_PHP_SEMANTIC_DIAGNOSTICS {
                break;
            }
            if node != root && is_local_scope(node) {
                scopes.push(node);
                continue;
            }
            self.scan_node(node, bindings, &mut stack);
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        bindings: &mut LocalInferenceEngine<String>,
        stack: &mut Vec<Node<'tree>>,
    ) {
        if is_non_reference_container(node) {
            return;
        }
        self.seed_assignment(node, bindings);
        self.check_reference(node, bindings);
        push_named_children(stack, node);
    }

    fn seed_assignment(&self, node: Node<'_>, bindings: &mut LocalInferenceEngine<String>) {
        let Some((left, right)) = assignment_parts(node) else {
            return;
        };
        if left.kind() != "variable_name" {
            return;
        }
        let name = variable_identifier(left, self.source);
        if name.is_empty() {
            return;
        }
        match receiver_type_from_expression(right, self.source, &self.ctx, bindings) {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => {
                if right.kind() == "variable_name" {
                    let rhs = variable_identifier(right, self.source);
                    if !rhs.is_empty() {
                        bindings.alias_symbol(name.to_string(), rhs);
                        return;
                    }
                }
                bindings.declare_shadow(name.to_string());
            }
        }
    }

    fn check_reference(&mut self, node: Node<'_>, bindings: &LocalInferenceEngine<String>) {
        match node.kind() {
            "object_creation_expression" => {
                if let Some(type_node) = object_creation_type(node) {
                    self.check_symbol(type_node, SymbolKind::Type);
                }
            }
            "named_type" => {
                let raw = qualified_candidate_text(node, self.source);
                if !is_builtin_php_type(&raw) && !is_in_object_creation(node) {
                    self.check_symbol(node, SymbolKind::Type);
                }
            }
            "function_call_expression" => {
                if let Some(function) = node.child_by_field_name("function")
                    && matches!(function.kind(), "name" | "qualified_name")
                {
                    self.check_symbol(function, SymbolKind::Function);
                }
            }
            "class_constant_access_expression"
            | "scoped_call_expression"
            | "scoped_property_access_expression" => {
                self.check_static_member(node);
            }
            "member_call_expression" | "member_access_expression" => {
                self.check_instance_member(node, bindings);
            }
            "name" | "qualified_name" => {
                if is_instanceof_type_name(node) {
                    self.check_symbol(node, SymbolKind::Type);
                } else if is_bare_constant_reference(node) {
                    self.check_symbol(node, SymbolKind::Constant);
                }
            }
            _ => {}
        }
    }

    fn check_symbol(&mut self, node: Node<'_>, kind: SymbolKind) {
        if is_declaration_name(node) || is_non_reference_context(node) {
            return;
        }
        let raw = qualified_candidate_text(node, self.source);
        if raw.is_empty() {
            return;
        }
        if is_dynamic_php_name(&raw) {
            return;
        }
        if matches!(kind, SymbolKind::Type) && is_builtin_php_type(&raw) {
            return;
        }
        if matches!(kind, SymbolKind::Function) && is_builtin_php_function(&raw) {
            return;
        }
        if matches!(kind, SymbolKind::Constant) && is_builtin_php_constant(&raw) {
            return;
        }
        if matches!(kind, SymbolKind::Function | SymbolKind::Constant)
            && is_unqualified_php_name(&raw)
        {
            return;
        }
        let fqn = match kind {
            SymbolKind::Type => resolve_php_type(&raw, &self.ctx),
            SymbolKind::Function => resolve_php_function(&raw, &self.ctx),
            SymbolKind::Constant => resolve_php_constant(&raw, &self.ctx),
        };
        let Some(fqn) = fqn else {
            return;
        };
        if !self.support.fqn(&fqn).is_empty() {
            return;
        }
        if !self.fqn_is_workspace_bounded(&fqn) {
            return;
        }
        let label = match kind {
            SymbolKind::Type => "type",
            SymbolKind::Function => "function",
            SymbolKind::Constant => "constant",
        };
        self.push_diagnostic(
            node,
            PHP_UNRECOGNIZED_SYMBOL,
            format!("Unrecognized PHP {label} `{raw}`"),
        );
    }

    fn check_static_member(&mut self, node: Node<'_>) {
        let Some((scope, member)) = static_member_parts(node) else {
            return;
        };
        let Some(member_name) = static_member_identifier(node, member, self.source) else {
            return;
        };
        if member_name.is_empty() {
            return;
        }
        let owner = self.static_scope_fqn(scope);
        if owner
            .as_deref()
            .is_none_or(|owner| !self.support.fqn_exists(owner))
        {
            self.check_symbol(scope, SymbolKind::Type);
            return;
        }
        let kind = match node.kind() {
            "scoped_call_expression" => MemberAccessKind::StaticCall,
            "scoped_property_access_expression" => MemberAccessKind::StaticProperty,
            "class_constant_access_expression" => MemberAccessKind::ClassConstant,
            _ => return,
        };
        self.check_member(member, owner, member_name, kind);
    }

    fn check_instance_member(&mut self, node: Node<'_>, bindings: &LocalInferenceEngine<String>) {
        let (Some(object), Some(member)) = (
            node.child_by_field_name("object"),
            node.child_by_field_name("name"),
        ) else {
            return;
        };
        let Some(member_name) = literal_member_identifier(member, self.source) else {
            return;
        };
        if member_name.is_empty() {
            return;
        }
        let owner = if object.kind() == "variable_name"
            && variable_identifier(object, self.source) == "this"
        {
            self.enclosing_owner_fqn(object)
        } else {
            receiver_type_from_expression(object, self.source, &self.ctx, bindings)
        };
        let kind = match node.kind() {
            "member_call_expression" => MemberAccessKind::InstanceCall,
            "member_access_expression" => MemberAccessKind::InstanceProperty,
            _ => return,
        };
        self.check_member(member, owner, member_name, kind);
    }

    fn check_member(
        &mut self,
        member_node: Node<'_>,
        owner: Option<String>,
        member_name: &str,
        kind: MemberAccessKind,
    ) {
        let Some(owner) = owner else {
            return;
        };
        if !self.support.fqn_exists(&owner) {
            return;
        }
        if self.class_has_trait_use(&owner) || self.has_magic_member_boundary(&owner, kind) {
            return;
        }
        let fqn = format!("{owner}.{member_name}");
        if !self.support.fqn(&fqn).is_empty()
            || !self
                .inherited_member_candidates(&owner, member_name)
                .is_empty()
        {
            return;
        }
        if !self.fqn_is_workspace_bounded(&owner) {
            return;
        }
        self.push_diagnostic(
            member_node,
            PHP_UNRECOGNIZED_MEMBER,
            format!("Unrecognized PHP member `{member_name}` on `{owner}`"),
        );
    }

    fn inherited_member_candidates(&self, owner_fqn: &str, member: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = crate::hash::HashSet::default();
        let mut level = self.direct_parent_fqns(owner_fqn);
        seen.insert(owner_fqn.to_string());
        while !level.is_empty() {
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                let candidate = format!("{ancestor}.{member}");
                if self.support.fqn_exists(&candidate) {
                    out.push(candidate);
                }
                next_level.extend(self.direct_parent_fqns(&ancestor));
            }
            if !out.is_empty() {
                return out;
            }
            level = next_level;
        }
        out
    }

    fn direct_parent_fqns(&self, owner_fqn: &str) -> Vec<String> {
        self.support
            .fqn(owner_fqn)
            .into_iter()
            .filter_map(|child| self.php.direct_declared_class_parent(&child))
            .map(|parent| parent.fq_name())
            .filter(|parent| self.support.fqn_exists(parent))
            .collect()
    }

    fn static_scope_fqn(&self, scope: Node<'_>) -> Option<String> {
        let text = node_text(scope, self.source);
        match text {
            "self" | "static" => self.enclosing_owner_fqn(scope),
            "parent" => {
                let owner = self.enclosing_owner_fqn(scope)?;
                let child = self.support.fqn(&owner).into_iter().next()?;
                self.php
                    .direct_declared_class_parent(&child)
                    .map(|parent| parent.fq_name())
            }
            _ => resolve_php_type(text, &self.ctx),
        }
    }

    fn has_magic_member_boundary(&self, owner_fqn: &str, kind: MemberAccessKind) -> bool {
        let magic = match kind {
            MemberAccessKind::InstanceCall => Some("__call"),
            MemberAccessKind::InstanceProperty => Some("__get"),
            MemberAccessKind::StaticCall => Some("__callStatic"),
            MemberAccessKind::StaticProperty | MemberAccessKind::ClassConstant => None,
        };
        magic.is_some_and(|name| self.owner_or_ancestor_has_member(owner_fqn, name))
    }

    fn owner_or_ancestor_has_member(&self, owner_fqn: &str, member: &str) -> bool {
        let mut seen = crate::hash::HashSet::default();
        let mut level = vec![owner_fqn.to_string()];
        while !level.is_empty() {
            let mut next_level = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                if self.support.fqn_exists(&format!("{owner}.{member}")) {
                    return true;
                }
                next_level.extend(self.direct_parent_fqns(&owner));
            }
            level = next_level;
        }
        false
    }

    fn class_has_trait_use(&self, owner_fqn: &str) -> bool {
        self.support
            .fqn(owner_fqn)
            .into_iter()
            .any(|unit| self.class_unit_has_trait_use(&unit))
    }

    fn class_unit_has_trait_use(&self, unit: &crate::analyzer::CodeUnit) -> bool {
        let source_storage;
        let source = if unit.source() == self.file {
            self.source
        } else {
            let Ok(source) = unit.source().read_to_string() else {
                return true;
            };
            source_storage = source;
            &source_storage
        };
        let Some(tree) = parse_php_tree(source) else {
            return true;
        };
        let ranges = self.analyzer.ranges(unit);
        let Some(start) = ranges.iter().map(|range| range.start_byte).min() else {
            return true;
        };
        let Some(end) = ranges.iter().map(|range| range.end_byte).max() else {
            return true;
        };
        declaration_range_has_trait_use(tree.root_node(), start, end)
    }

    fn enclosing_owner_fqn(&self, node: Node<'_>) -> Option<String> {
        let range = node_range(node, self.line_starts);
        self.analyzer
            .enclosing_code_unit(self.file, &range)
            .and_then(|enclosing| self.analyzer.parent_of(&enclosing).or(Some(enclosing)))
            .filter(|owner| owner.is_class())
            .map(|owner| owner.fq_name())
    }

    fn fqn_is_workspace_bounded(&self, fqn: &str) -> bool {
        let namespace = diagnostic_namespace(fqn);
        self.support.package_exists(&namespace)
    }

    fn push_diagnostic(&mut self, node: Node<'_>, kind: &'static str, message: String) {
        if self.diagnostics.len() >= MAX_PHP_SEMANTIC_DIAGNOSTICS {
            return;
        }
        self.diagnostics.push(PhpSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind,
            message,
        });
    }
}

fn diagnostic_namespace(fqn: &str) -> String {
    let public = fqn.replace("._module_.", ".");
    let Some((namespace, _)) = public.rsplit_once('.') else {
        return String::new();
    };
    namespace.to_string()
}

fn is_unqualified_php_name(raw: &str) -> bool {
    !raw.starts_with('\\') && !raw.contains('\\')
}

fn is_dynamic_php_name(raw: &str) -> bool {
    raw.starts_with('$')
}

fn declaration_range_has_trait_use(root: Node<'_>, start: usize, end: usize) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.end_byte() < start || node.start_byte() > end {
            continue;
        }
        if node.kind() == "use_declaration" {
            return true;
        }
        push_named_children(&mut stack, node);
    }
    false
}

fn push_named_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}

fn is_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "anonymous_function_creation"
            | "arrow_function"
    )
}

fn is_non_reference_container(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "namespace_use_declaration"
            | "namespace_use_clause"
            | "comment"
            | "string"
            | "encapsed_string"
            | "string_value"
            | "heredoc"
            | "nowdoc"
    )
}

fn is_non_reference_context(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if is_non_reference_container(candidate) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn seed_parameter_types(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "assignment_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn static_member_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

fn variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

fn literal_member_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "name").then(|| node_text(node, source))
}

fn static_property_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name").then(|| variable_identifier(node, source))
}

fn static_member_identifier<'a>(
    parent: Node<'_>,
    member: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    if parent.kind() == "scoped_property_access_expression" {
        static_property_identifier(member, source)
    } else {
        literal_member_identifier(member, source)
    }
}

fn receiver_type_from_expression(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match node.kind() {
        "variable_name" => {
            let name = variable_identifier(node, source);
            first_precise(bindings, name)
        }
        "object_creation_expression" => object_creation_type(node)
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx)),
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|inner| receiver_type_from_expression(inner, source, ctx, bindings)),
        _ => None,
    }
}

fn first_precise(bindings: &LocalInferenceEngine<String>, symbol: &str) -> Option<String> {
    match bindings.resolve_symbol(symbol) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
    }
}

fn qualified_candidate_text(node: Node<'_>, source: &str) -> String {
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if matches!(ancestor.kind(), "namespace_name" | "qualified_name") {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    node_text(candidate, source).trim().to_string()
}

fn is_instanceof_type_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "binary_expression"
        && parent
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "instanceof")
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
        })
}

fn is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

fn is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if has_ancestor_kind(
        node,
        &[
            "variable_name",
            "namespace_name",
            "namespace_definition",
            "property_element",
            "simple_parameter",
            "property_promotion_parameter",
        ],
    ) {
        return false;
    }
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "namespace_name"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "variable_name"
            | "base_clause"
            | "class_interface_clause"
    )
}

fn has_ancestor_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if kinds.contains(&candidate.kind()) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "function_definition"
                | "method_declaration"
                | "enum_declaration"
                | "enum_case"
                | "const_element"
                | "property_element"
                | "simple_parameter"
                | "property_promotion_parameter"
        )
}

fn is_builtin_php_type(raw: &str) -> bool {
    raw.split('|').all(|part| {
        matches!(
            part.trim().trim_start_matches('?'),
            "array"
                | "bool"
                | "callable"
                | "false"
                | "float"
                | "int"
                | "iterable"
                | "mixed"
                | "never"
                | "null"
                | "object"
                | "self"
                | "static"
                | "parent"
                | "string"
                | "true"
                | "void"
        )
    })
}

fn is_builtin_php_function(raw: &str) -> bool {
    !raw.contains('\\')
        && matches!(
            raw,
            "array_key_exists"
                | "count"
                | "defined"
                | "empty"
                | "in_array"
                | "is_array"
                | "is_bool"
                | "is_float"
                | "is_int"
                | "is_null"
                | "is_object"
                | "is_string"
                | "isset"
                | "json_decode"
                | "json_encode"
                | "printf"
                | "sprintf"
                | "strlen"
                | "substr"
                | "trim"
                | "var_dump"
        )
}

fn is_builtin_php_constant(raw: &str) -> bool {
    !raw.contains('\\')
        && matches!(
            raw,
            "DIRECTORY_SEPARATOR"
                | "PHP_EOL"
                | "PHP_VERSION"
                | "STDERR"
                | "STDIN"
                | "STDOUT"
                | "__CLASS__"
                | "__DIR__"
                | "__FILE__"
                | "__FUNCTION__"
                | "__LINE__"
                | "__METHOD__"
                | "__NAMESPACE__"
                | "__TRAIT__"
        )
}

#[cfg(test)]
mod tests {
    use super::{
        PHP_UNRECOGNIZED_MEMBER, PHP_UNRECOGNIZED_SYMBOL, collect_php_semantic_diagnostics,
    };
    use crate::analyzer::{Language, PhpAnalyzer, ProjectFile, TestProject};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: PhpAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<super::PhpSemanticDiagnostic> {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_php_semantic_diagnostics(&self.analyzer, &file, &source)
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Php);
        let analyzer = PhpAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn php_semantic_diagnostics_report_unknown_namespaced_type_function_and_constant() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

class Service {
    private MissingType $value;

    public function run(): void {
        \App\missing_function();
        \App\MISSING_CONSTANT;
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(3, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == PHP_UNRECOGNIZED_SYMBOL),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType")),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_function")),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MISSING_CONSTANT")),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn php_semantic_diagnostics_suppress_imported_aliases_and_builtins() {
        let fixture = fixture(&[
            (
                "src/Service.php",
                r#"<?php
namespace App;

class Service {}
function render_view(): void {}
const READY = 1;
"#,
            ),
            (
                "src/Controller.php",
                r#"<?php
namespace App\Http;

use App\Service as S;
use function App\render_view as rv;
use const App\READY as READY_FLAG;

class Controller {
    public function handle(S $service): void {
        rv();
        READY_FLAG;
        strlen("ok");
    }
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("src/Controller.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_unqualified_functions_and_constants() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

function run(): void {
    str_replace("old", "new", "old");
    may_fallback_to_global();
    MAY_FALLBACK_TO_GLOBAL;
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_composer_psr4_project_classes() {
        let fixture = fixture(&[
            (
                "composer.json",
                r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "src/Domain/Service.php",
                "<?php\nnamespace App\\Domain;\nclass Service {}\n",
            ),
            (
                "src/Http/Controller.php",
                r#"<?php
namespace App\Http;

use App\Domain\Service;

class Controller {
    public function handle(Service $service): void {}
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("src/Http/Controller.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_dynamic_constructs_and_malformed_files() {
        let fixture = fixture(&[
            (
                "src/Dynamic.php",
                r#"<?php
namespace App;

class Anchor {}

function run($target, $method, $className): void {
    $target->$method();
    $className::factory();
    $callable();
    new $className();
}
"#,
            ),
            (
                "src/Broken.php",
                "<?php\nnamespace App;\nclass Broken { public function run(: void { MissingType; }\n",
            ),
        ]);

        let dynamic_diagnostics = fixture.diagnostics_for("src/Dynamic.php");
        assert!(dynamic_diagnostics.is_empty(), "{dynamic_diagnostics:#?}");
        let broken_diagnostics = fixture.diagnostics_for("src/Broken.php");
        assert!(broken_diagnostics.is_empty(), "{broken_diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_report_only_known_receiver_missing_members() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Base {
    public function inherited(): void {}
}

class Service extends Base {
    public function present(): void {}

    public function run(Service $service): void {
        $this->present();
        self::present();
        static::present();
        parent::inherited();
        $service->missing();
        $unknown->missing();
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PHP_UNRECOGNIZED_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missing"));
    }

    #[test]
    fn php_semantic_diagnostics_suppress_magic_and_trait_members() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

trait SharedMethods {
    public function shared(): void {}
}

class DynamicService {
    public function __call(string $name, array $args): mixed {}
    public function __get(string $name): mixed {}
    public static function __callStatic(string $name, array $args): mixed {}
}

class TraitService {
    use SharedMethods;

    public function run(): void {
        $this->shared();
    }
}

function run(DynamicService $service): void {
    $service->dynamicCall();
    $service->dynamicProperty;
    DynamicService::dynamicStaticCall();
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_do_not_leak_bindings_into_nested_functions() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Service {}

function run(Service $service): void {
    function inner(): void {
        $service->missing();
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_report_missing_static_receiver_type() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

function run(): void {
    MissingStatic::run();
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PHP_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingStatic"));
    }

    #[test]
    fn php_semantic_diagnostics_suppress_external_vendor_boundaries() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Service {
    private \Vendor\Package\MissingType $value;
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }
}
