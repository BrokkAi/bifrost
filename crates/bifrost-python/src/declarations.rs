use crate::imports::python_import_infos_from_node;
use crate::syntax::{PythonOverloadDecoratorBindings, expression_name_node};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DispatchExtensibility, ParameterMetadata, SignatureMetadata,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

/// Intern one qualified-name segment in the process-global interner.
fn py_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Build the structured module-path prefix for a Python declaration.
///
/// Ordinary modules render as a dotted path such as `mypkg.subpkg.mymodule`,
/// with each original path component represented by one
/// [`SegmentKind::Package`] segment. Hidden directories such as `.agent` and
/// `.github` are also legal components in the analyzer's path-derived Python
/// convention, but their leading dot is ambiguous after a rendered name has
/// been joined.
///
/// Build the structured name from the file path's original components so
/// hidden-directory segments stay intact in cold extraction, synthesized module
/// units, and persisted reconstruction.
pub fn python_module_fq(file: &ProjectFile) -> FqName {
    let mut fq = FqName::new();
    for component in python_module_components(file) {
        fq.push(py_segment(&component, SegmentKind::Package));
    }
    fq
}

fn python_module_components(file: &ProjectFile) -> Vec<String> {
    let mut components = python_package_components_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if module_name != "__init__" || components.is_empty() {
        components.push(module_name.to_string());
    }
    components
}

fn python_package_components_for_file(file: &ProjectFile) -> Vec<String> {
    let Some(parent_rel) = file.rel_path().parent() else {
        return Vec::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return Vec::new();
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let relative_package = match effective_package_root_rel {
        Some(package_root_rel) => package_root_rel
            .parent()
            .and_then(|import_root_rel| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
        None => parent_rel,
    };
    path_components(relative_package)
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect()
}

pub fn python_is_decorated_function_boundary(node: Node<'_>) -> bool {
    if node.kind() != "decorated_definition" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "function_definition")
}

#[derive(Clone)]
pub struct Scope {
    kind: ScopeKind,
    path: String,
    /// The structured qualified name matching `path` (M1 dual representation;
    /// see `.agents/plans/fqname-interned-segments.md`). Tracked independent of
    /// whether this scope level was actually `capture`d as a `CodeUnit`, so a
    /// nested class/function that IS captured can always extend an ancestor's
    /// `fq` even when an intermediate scope level (e.g. a non-captured nested
    /// function) has no `code_unit` of its own to read `.fq()` from.
    fq: FqName,
    code_unit: Option<CodeUnit>,
    method_receiver: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Class,
    Function,
}

pub struct PythonVisitor<'a> {
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub package_name: &'a str,
    pub parsed: &'a mut ParsedFile,
    pub module: Option<CodeUnit>,
    pub overload_decorators: &'a PythonOverloadDecoratorBindings,
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
    pub fn visit_container(
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
        // A nested class (any parent scope, Class or Function) is always joined
        // with a literal `$` in the legacy convention above, which is exactly
        // what `SegmentKind::Nested` renders regardless of the preceding
        // segment's kind; a top-level class has no parent and is a plain `Type`
        // hanging off the module-path `Package` chain.
        let fq = match scope.last() {
            Some(parent) => parent
                .fq
                .clone()
                .with_pushed(py_segment(name, SegmentKind::Nested)),
            None => python_module_fq(self.file).with_pushed(py_segment(name, SegmentKind::Type)),
        };
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.to_string(),
            short_name.clone(),
            fq.clone(),
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
                fq,
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
        // Mirrors `short_name` above segment-for-segment: a method owned
        // directly by a class joins with `.` (`Member`), while a function
        // nested under another function is a local/closure and joins with the
        // literal `$` that `SegmentKind::Nested` renders.
        let fq = if let Some(parent) = scope.last() {
            match parent.kind {
                ScopeKind::Class => parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(name, SegmentKind::Member)),
                ScopeKind::Function => parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(name, SegmentKind::Nested)),
            }
        } else {
            python_module_fq(self.file).with_pushed(py_segment(name, SegmentKind::Member))
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
            let code_unit = CodeUnit::with_signature_and_fq(
                self.file.clone(),
                code_unit_type,
                self.package_name.to_string(),
                short_name.clone(),
                signature,
                false,
                fq.clone(),
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
                fq,
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
            fq,
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
            let (short_name, fq) = if let Some(parent) = scope.last() {
                if parent.kind != ScopeKind::Class {
                    continue;
                }
                (
                    format!("{}.{}", parent.path, name),
                    parent
                        .fq
                        .clone()
                        .with_pushed(py_segment(&name, SegmentKind::Member)),
                )
            } else if module_control_depth <= 1 {
                (
                    name.clone(),
                    python_module_fq(self.file).with_pushed(py_segment(&name, SegmentKind::Member)),
                )
            } else {
                continue;
            };
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                short_name,
                fq,
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
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                format!("{}.{}", parent.path, name),
                parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(&name, SegmentKind::Member)),
            );
            if !self.parsed.contains_declaration(&code_unit) {
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
        for info in python_import_infos_from_node(node, self.source) {
            self.parsed.import_statements.push(info.raw_snippet.clone());
            self.parsed.imports.push(info);
        }
    }
}

/// Build the [`ParsedFile`] for one Python source file: module unit, type
/// identifiers, and the declaration walk. `analyzer/python/adapter.rs`'s
/// `LanguageAdapter::parse_file` is the only caller.
pub fn parse_python_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let module_fq = python_module_name(file);
    let mut parsed = ParsedFile::new(module_fq.clone());
    let root = tree.root_node();

    collect_python_identifiers(root, source, &mut parsed.type_identifiers);

    let module_code_unit = module_code_unit(file, &module_fq);
    if let Some(module) = module_code_unit.clone() {
        parsed.add_code_unit(module, root, source, None, None);
    }

    let overload_decorators = PythonOverloadDecoratorBindings::collect(root, source);
    let mut visitor = PythonVisitor {
        file,
        source,
        package_name: &module_fq,
        parsed: &mut parsed,
        module: module_code_unit,
        overload_decorators: &overload_decorators,
    };
    visitor.visit_container(root, &[], 0);

    parsed
}

pub fn py_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

pub fn python_module_name(file: &ProjectFile) -> String {
    python_module_components(file).join(".")
}

pub fn module_code_unit(file: &ProjectFile, module_fq: &str) -> Option<CodeUnit> {
    if module_fq.is_empty() {
        return None;
    }
    let mut components = python_module_components(file);
    debug_assert_eq!(
        module_fq,
        components.join("."),
        "module_code_unit must be built from the file's path-derived Python module name"
    );
    let short_name = components.pop()?;
    let package_name = components.join(".");
    Some(CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Module,
        package_name,
        short_name,
        python_module_fq(file),
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
        return SignatureMetadata::new(signature, Vec::new())
            .with_dispatch_extensibility(DispatchExtensibility::Open);
    };
    let parameter_text = py_node_text(parameters_node, source).trim();
    let Some(parameters_start) = signature.find(parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_dispatch_extensibility(DispatchExtensibility::Open);
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
        .with_dispatch_extensibility(DispatchExtensibility::Open)
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

pub fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
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

pub fn collect_python_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
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

pub fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load python parser");
    parser.parse(source, None)
}
