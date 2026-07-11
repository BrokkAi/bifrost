use super::imports::parse_python_import_infos;
use super::syntax::{PythonOverloadDecoratorBindings, expression_name_node};
use super::*;
use crate::analyzer::ParameterMetadata;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

pub(super) fn python_is_decorated_function_boundary(node: Node<'_>) -> bool {
    if node.kind() != "decorated_definition" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "function_definition")
}

#[derive(Clone)]
pub(super) struct Scope {
    kind: ScopeKind,
    path: String,
    code_unit: Option<CodeUnit>,
    method_receiver: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Class,
    Function,
}

pub(super) struct PythonVisitor<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) package_name: &'a str,
    pub(super) parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    pub(super) module: Option<CodeUnit>,
    pub(super) overload_decorators: &'a PythonOverloadDecoratorBindings,
}

struct PythonContainer<'tree> {
    node: Node<'tree>,
    scope: Vec<Scope>,
    module_control_depth: usize,
}

enum PythonWork<'tree> {
    Container(PythonContainer<'tree>),
    Statement {
        node: Node<'tree>,
        scope: Vec<Scope>,
        module_control_depth: usize,
    },
}

impl<'a> PythonVisitor<'a> {
    pub(super) fn visit_container(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let mut stack = vec![PythonWork::Container(PythonContainer {
            node,
            scope: scope.to_vec(),
            module_control_depth,
        })];
        while let Some(work) = stack.pop() {
            match work {
                PythonWork::Container(container) => {
                    let mut cursor = container.node.walk();
                    let children = container
                        .node
                        .named_children(&mut cursor)
                        .collect::<Vec<_>>();
                    for child in children.into_iter().rev() {
                        stack.push(PythonWork::Statement {
                            node: child,
                            scope: container.scope.clone(),
                            module_control_depth: container.module_control_depth,
                        });
                    }
                }
                PythonWork::Statement {
                    node,
                    scope,
                    module_control_depth,
                } => self.visit_statement(node, &scope, module_control_depth, &mut stack),
            }
        }
    }

    fn visit_statement<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        match node.kind() {
            "decorated_definition" => {
                if let Some(definition) = node.child_by_field_name("definition") {
                    self.visit_definition(
                        definition,
                        Some(node),
                        scope,
                        module_control_depth,
                        stack,
                    );
                }
            }
            "class_definition" | "function_definition" => {
                self.visit_definition(node, None, scope, module_control_depth, stack)
            }
            "expression_statement" => {
                self.visit_expression_statement(node, scope, module_control_depth)
            }
            "import_statement" | "import_from_statement" => self.visit_import_statement(node),
            "if_statement" | "try_statement" | "with_statement" | "for_statement"
            | "while_statement" => {
                let next_depth = if scope.is_empty() {
                    module_control_depth + 1
                } else {
                    module_control_depth
                };
                stack.push(PythonWork::Container(PythonContainer {
                    node,
                    scope: scope.to_vec(),
                    module_control_depth: next_depth,
                }));
            }
            "elif_clause" | "else_clause" | "except_clause" | "finally_clause" => {
                stack.push(PythonWork::Container(PythonContainer {
                    node,
                    scope: scope.to_vec(),
                    module_control_depth,
                }));
            }
            "block" | "module" => stack.push(PythonWork::Container(PythonContainer {
                node,
                scope: scope.to_vec(),
                module_control_depth,
            })),
            _ => {}
        }
    }

    fn visit_definition<'tree>(
        &mut self,
        definition: Node<'tree>,
        wrapper: Option<Node<'tree>>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        match definition.kind() {
            "class_definition" => self.visit_class_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
                stack,
            ),
            "function_definition" => self.visit_function_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
                stack,
            ),
            _ => {}
        }
    }

    fn visit_class_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !scope.is_empty() || module_control_depth <= 1;

        let short_name = scope
            .last()
            .map(|parent| format!("{}${name}", parent.path))
            .unwrap_or_else(|| name.to_string());
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.to_string(),
            short_name.clone(),
        );
        if capture {
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                python_class_signature(range_node, self.source),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            self.parsed.set_raw_supertypes(
                code_unit.clone(),
                extract_python_supertypes(node, self.source),
            );
        }

        let mut next_scope = scope.to_vec();
        if capture {
            next_scope.push(Scope {
                kind: ScopeKind::Class,
                path: short_name,
                code_unit: Some(code_unit),
                method_receiver: None,
            });
        }
        if let Some(body) = node.child_by_field_name("body") {
            stack.push(PythonWork::Container(PythonContainer {
                node: body,
                scope: next_scope,
                module_control_depth,
            }));
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !python_is_property_mutator(range_node, self.source)
            && ((scope.is_empty() && module_control_depth <= 1)
                || scope
                    .last()
                    .is_some_and(|parent| parent.kind == ScopeKind::Class));
        let short_name = if let Some(parent) = scope.last() {
            match parent.kind {
                ScopeKind::Class => format!("{}.{}", parent.path, name),
                ScopeKind::Function => format!("{}${name}", parent.path),
            }
        } else {
            name.to_string()
        };

        if capture {
            let code_unit_type = if python_function_has_decorator(node, self.source, "property") {
                CodeUnitType::Field
            } else {
                CodeUnitType::Function
            };
            let signature = node
                .child_by_field_name("parameters")
                .map(|parameters| py_node_text(parameters, self.source).trim().to_string());
            let code_unit = CodeUnit::with_signature(
                self.file.clone(),
                code_unit_type,
                self.package_name.to_string(),
                short_name.clone(),
                signature,
                false,
            );
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            let signature = python_function_signature(range_node, self.source);
            self.parsed.add_signature_with_metadata(
                code_unit.clone(),
                python_signature_metadata(signature, node, self.source).with_declaration_only(
                    self.overload_decorators
                        .decorates_as_overload(node, self.source),
                ),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            let scope_code_unit = Some(code_unit);
            let mut next_scope = scope.to_vec();
            next_scope.push(Scope {
                kind: ScopeKind::Function,
                path: short_name,
                code_unit: scope_code_unit,
                method_receiver: scope
                    .last()
                    .is_some_and(|parent| parent.kind == ScopeKind::Class)
                    .then(|| python_instance_method_receiver_name(node, self.source))
                    .flatten(),
            });
            if let Some(body) = node.child_by_field_name("body") {
                stack.push(PythonWork::Container(PythonContainer {
                    node: body,
                    scope: next_scope,
                    module_control_depth,
                }));
            }
            return;
        }

        let mut next_scope = scope.to_vec();
        next_scope.push(Scope {
            kind: ScopeKind::Function,
            path: short_name,
            code_unit: None,
            method_receiver: None,
        });
        if let Some(body) = node.child_by_field_name("body") {
            stack.push(PythonWork::Container(PythonContainer {
                node: body,
                scope: next_scope,
                module_control_depth,
            }));
        }
    }

    fn visit_expression_statement(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let Some(assignment) = node.named_child(0) else {
            return;
        };
        if assignment.kind() != "assignment" {
            return;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            return;
        };
        self.visit_instance_attribute_assignment(left, scope);
        let names = collect_assigned_names(left, self.source);
        for name in names {
            let short_name = if let Some(parent) = scope.last() {
                if parent.kind != ScopeKind::Class {
                    continue;
                }
                format!("{}.{}", parent.path, name)
            } else if module_control_depth <= 1 {
                name.clone()
            } else {
                continue;
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                short_name,
            );
            self.parsed
                .replace_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(node, self.source).trim().to_string(),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit);
            }
        }
    }

    fn visit_instance_attribute_assignment(&mut self, left: Node<'_>, scope: &[Scope]) {
        let Some(function) = scope
            .last()
            .filter(|scope| scope.kind == ScopeKind::Function)
        else {
            return;
        };
        let Some(receiver) = function.method_receiver.as_deref() else {
            return;
        };
        let Some(parent) = scope
            .get(scope.len().saturating_sub(2))
            .filter(|scope| scope.kind == ScopeKind::Class)
        else {
            return;
        };
        let Some(parent_cu) = parent.code_unit.clone() else {
            return;
        };
        for (name, node) in collect_self_assigned_attributes(left, self.source, receiver) {
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                format!("{}.{}", parent.path, name),
            );
            if !self.parsed.declarations.contains(&code_unit) {
                self.parsed.replace_code_unit(
                    code_unit.clone(),
                    node,
                    self.source,
                    Some(parent_cu.clone()),
                    Some(parent_cu.clone()),
                );
            }
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(left, self.source).trim().to_string(),
            );
        }
    }

    fn visit_import_statement(&mut self, node: Node<'_>) {
        let raw = py_node_text(node, self.source).trim();
        for info in parse_python_import_infos(raw) {
            self.parsed.import_statements.push(info.raw_snippet.clone());
            self.parsed.imports.push(info);
        }
    }
}

pub(super) fn py_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

struct PythonModuleInfo {
    package_name: String,
    module_name: String,
}

impl PythonModuleInfo {
    fn module_qualified_package(&self) -> String {
        if self.package_name.is_empty() {
            self.module_name.clone()
        } else {
            format!("{}.{}", self.package_name, self.module_name)
        }
    }
}

pub(super) fn python_module_name(file: &ProjectFile) -> String {
    python_module_info(file).module_qualified_package()
}

pub(super) fn build_python_module_code_units(
    inner: &TreeSitterAnalyzer<PythonAdapter>,
) -> HashMap<String, CodeUnit> {
    inner
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let module_fq = python_module_name(&file);
            module_code_unit(&file, &module_fq).map(|code_unit| (module_fq, code_unit))
        })
        .collect()
}

fn python_module_info(file: &ProjectFile) -> PythonModuleInfo {
    let raw_package = python_package_name_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string();

    if module_name == "__init__" && !raw_package.is_empty() {
        if let Some((package_name, last_segment)) = raw_package.rsplit_once('.') {
            return PythonModuleInfo {
                package_name: package_name.to_string(),
                module_name: last_segment.to_string(),
            };
        }
        return PythonModuleInfo {
            package_name: String::new(),
            module_name: raw_package,
        };
    }

    PythonModuleInfo {
        package_name: raw_package,
        module_name,
    }
}

fn python_package_name_for_file(file: &ProjectFile) -> String {
    let Some(parent_rel) = file.rel_path().parent() else {
        return String::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return String::new();
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let Some(package_root_rel) = effective_package_root_rel else {
        return dotted_path(parent_rel);
    };

    let Some(import_root_rel) = package_root_rel.parent() else {
        return dotted_path(parent_rel);
    };

    dotted_path(
        import_root_rel
            .strip_prefix("")
            .ok()
            .and_then(|_| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
    )
}

fn dotted_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

pub(super) fn module_code_unit(file: &ProjectFile, module_fq: &str) -> Option<CodeUnit> {
    if module_fq.is_empty() {
        return None;
    }
    let mut parts = module_fq.rsplitn(2, '.');
    let short_name = parts.next().unwrap_or(module_fq);
    let package_name = parts.next().unwrap_or_default();
    Some(CodeUnit::new(
        file.clone(),
        CodeUnitType::Module,
        package_name.to_string(),
        short_name.to_string(),
    ))
}

fn python_class_signature(node: Node<'_>, source: &str) -> String {
    python_header_with_decorators(node, source)
}

fn python_function_signature(node: Node<'_>, source: &str) -> String {
    let header = python_header_with_decorators(node, source);
    if let Some((head, tail)) = header.rsplit_once('\n') {
        format!("{head}\n{tail} ...")
    } else {
        format!("{header} ...")
    }
}

fn python_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameter_text = py_node_text(parameters_node, source).trim();
    let Some(parameters_start) = signature.find(parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = python_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = py_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
}

fn python_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.named_children(&mut cursor) {
        if let Some(label_node) = python_parameter_label_node(child) {
            labels.push(label_node);
        }
    }
    labels
}

fn python_parameter_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "typed_parameter"
        | "typed_default_parameter"
        | "default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "keyword_separator" => node.child_by_field_name("name").or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(python_parameter_label_node)
        }),
        _ => None,
    }
}

fn python_is_property_mutator(node: Node<'_>, source: &str) -> bool {
    python_header_with_decorators(node, source)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('@'))
        .any(|decorator| decorator.ends_with(".setter") || decorator.ends_with(".deleter"))
}

pub(super) fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = compute_line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            comment_start = line_start;
            continue;
        }

        break;
    }

    comment_start
}

fn python_header_with_decorators(node: Node<'_>, source: &str) -> String {
    let raw = py_node_text(node, source);
    let lines: Vec<_> = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    let mut relevant = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('@')
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("class ")
        {
            relevant.push(trimmed.to_string());
            if trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ")
            {
                break;
            }
        }
    }
    relevant.join("\n")
}

fn extract_python_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(superclasses) = node.child_by_field_name("superclasses") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = superclasses.walk();
    for child in superclasses.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "attribute" => {
                let text = py_node_text(child, source).trim();
                if !text.is_empty() {
                    result.push(text.to_string());
                }
            }
            _ => {}
        }
    }
    result
}

fn collect_assigned_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            // An attribute or subscript target (`foo.bar = …`, `foo[i] = …`)
            // mutates an existing object; it declares neither the receiver nor
            // the member as a name, so do not descend into it.
            "attribute" | "subscript" => WalkControl::SkipChildren,
            "identifier" => {
                let text = py_node_text(node, source).trim();
                if !text.is_empty() {
                    names.push(text.to_string());
                }
                WalkControl::Continue
            }
            _ => WalkControl::Continue,
        }
    });
    names
}

fn collect_self_assigned_attributes<'tree>(
    node: Node<'tree>,
    source: &str,
    receiver_name: &str,
) -> Vec<(String, Node<'tree>)> {
    let mut attributes = Vec::new();
    collect_direct_self_assigned_attributes(node, source, receiver_name, &mut attributes);
    attributes
}

fn collect_direct_self_assigned_attributes<'tree>(
    node: Node<'tree>,
    source: &str,
    receiver_name: &str,
    attributes: &mut Vec<(String, Node<'tree>)>,
) {
    match node.kind() {
        "attribute" => {
            let Some(object) = node.child_by_field_name("object") else {
                return;
            };
            if object.kind() != "identifier" || py_node_text(object, source).trim() != receiver_name
            {
                return;
            }
            let Some(attribute) = node.child_by_field_name("attribute") else {
                return;
            };
            let name = py_node_text(attribute, source).trim();
            if !name.is_empty() {
                attributes.push((name.to_string(), attribute));
            }
        }
        "pattern_list" | "tuple" | "list" | "parenthesized_expression" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_direct_self_assigned_attributes(child, source, receiver_name, attributes);
            }
        }
        _ => {}
    }
}

fn python_instance_method_receiver_name(node: Node<'_>, source: &str) -> Option<String> {
    if python_function_has_decorator(node, source, "staticmethod")
        || python_function_has_decorator(node, source, "classmethod")
    {
        return None;
    }
    python_first_parameter_name(node, source)
}

fn python_function_has_decorator(node: Node<'_>, source: &str, decorator_name: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "decorated_definition" {
        return false;
    }
    let mut cursor = parent.walk();
    parent
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| decorator.named_child(0))
        .filter_map(expression_name_node)
        .any(|name| py_node_text(name, source).trim() == decorator_name)
}

fn python_first_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .find_map(|child| python_parameter_name(child, source))
}

fn python_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(py_node_text(node, source).trim().to_string()),
        "typed_parameter"
        | "default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern" => node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "identifier")
            })
            .and_then(|name| python_parameter_name(name, source)),
        _ => None,
    }
    .filter(|name| !name.is_empty())
}

pub(super) fn collect_python_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "identifier" {
            let text = py_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        WalkControl::Continue
    });
}

pub(super) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load python parser");
    parser.parse(source, None)
}
