use crate::analyzer::go::packages::canonical_go_package_name;
use crate::analyzer::semantic_diagnostics::{
    ScopeStack, contains_node, node_range, node_text, same_node,
};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::usages::go_graph::resolve_go_import_namespaces;
use crate::analyzer::{
    DefinitionLookupIndex, GoAnalyzer, IAnalyzer, ProjectFile, Range, SemanticDiagnostic,
    resolve_analyzer,
};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub(crate) const GO_UNRECOGNIZED_SYMBOL: &str = "go_unrecognized_symbol";
pub(crate) const GO_UNRECOGNIZED_PACKAGE_MEMBER: &str = "go_unrecognized_package_member";
pub(crate) const GO_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-go";
const MAX_GO_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_GO_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoSemanticDiagnostic {
    pub(crate) range: Range,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

impl From<GoSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: GoSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: GO_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

pub(crate) fn collect_go_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<GoSemanticDiagnostic> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return Vec::new();
    };
    if source.len() > MAX_GO_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = parse_go_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let support = analyzer.definition_lookup_index();
    let line_starts = compute_line_starts(source);
    let imports = GoImportNamespaces::new(go, file);
    let package_name = declared_package_name(tree.root_node(), source)
        .map(|declared| canonical_go_package_name(file, &declared))
        .unwrap_or_default();
    let mut collector = GoDiagnosticCollector {
        support,
        source,
        line_starts: &line_starts,
        package_name,
        imports,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
}

fn parse_go_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    parser.parse(source, None)
}

struct GoDiagnosticCollector<'a> {
    support: &'a DefinitionLookupIndex,
    source: &'a str,
    line_starts: &'a [usize],
    package_name: String,
    imports: GoImportNamespaces,
    diagnostics: Vec<GoSemanticDiagnostic>,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    SeedShortVar(Node<'tree>),
    SeedRange(Node<'tree>),
}

impl GoDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = ScopeStack::default();
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostics.len() >= MAX_GO_SEMANTIC_DIAGNOSTICS {
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut scopes, &mut stack),
                ScanFrame::ExitScope => scopes.exit(),
                ScanFrame::SeedShortVar(node) => self.seed_short_var_declaration(node, &mut scopes),
                ScanFrame::SeedRange(node) => self.seed_range_clause(node, &mut scopes),
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scopes: &mut ScopeStack,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        match node.kind() {
            "source_file" => push_named_children(stack, node),
            "block" | "block_statement" => {
                scopes.enter();
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "function_declaration" | "method_declaration" => {
                scopes.enter();
                self.seed_function_scope(node, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "type_spec" | "type_alias" => {
                if node.child_by_field_name("type_parameters").is_some() {
                    scopes.enter();
                    self.seed_type_parameters_from_owner(node, scopes);
                    stack.push(ScanFrame::ExitScope);
                }
                push_named_children(stack, node);
            }
            "import_declaration" | "package_clause" => {}
            "parameter_declaration" | "variadic_parameter_declaration" => {
                self.seed_parameter_declaration(node, scopes);
                push_named_children(stack, node);
            }
            "type_parameter_declaration" => {
                self.seed_type_parameter_declaration(node, scopes);
                push_named_children(stack, node);
            }
            "var_declaration" | "const_declaration" => {
                self.seed_value_declaration(node, scopes);
                push_named_children(stack, node);
            }
            "short_var_declaration" => {
                stack.push(ScanFrame::SeedShortVar(node));
                push_field_if_present(stack, node, "right");
            }
            "assignment_statement" => {
                push_field_if_present(stack, node, "right");
                push_field_if_present(stack, node, "left");
            }
            "range_clause" => {
                stack.push(ScanFrame::SeedRange(node));
                push_field_if_present(stack, node, "right");
            }
            "selector_expression" | "qualified_type" => {
                self.check_selector(node, scopes);
                push_named_children(stack, node);
            }
            "identifier" | "type_identifier" | "field_identifier" | "package_identifier" => {
                self.check_identifier(node, scopes);
            }
            _ => push_named_children(stack, node),
        }
    }

    fn seed_range_clause(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(left) = node.child_by_field_name("left") {
            for name in identifier_texts(left, self.source) {
                scopes.declare(name);
            }
        }
    }

    fn seed_function_scope(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        if node.kind() == "method_declaration"
            && let Some(receiver) = node.child_by_field_name("receiver")
        {
            self.seed_parameter_list(receiver, scopes);
        }
        self.seed_type_parameters_from_owner(node, scopes);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "parameter_list" {
                self.seed_parameter_list(child, scopes);
            }
        }
    }

    fn seed_parameter_list(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            ) {
                self.seed_parameter_declaration(child, scopes);
            }
        }
    }

    fn seed_parameter_declaration(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        for name in parameter_names(node, self.source) {
            scopes.declare(name);
        }
    }

    fn seed_value_declaration(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "var_spec" | "const_spec") {
                self.seed_spec_names(child, scopes);
            } else {
                let mut nested = child.walk();
                for spec in child.named_children(&mut nested) {
                    if matches!(spec.kind(), "var_spec" | "const_spec") {
                        self.seed_spec_names(spec, scopes);
                    }
                }
            }
        }
    }

    fn seed_spec_names(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut cursor = node.walk();
        for child in node.children_by_field_name("name", &mut cursor) {
            let name = node_text(child, self.source);
            if name != "_" {
                scopes.declare(name.to_string());
            }
        }
    }

    fn seed_type_parameters_from_owner(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(type_parameters) = node.child_by_field_name("type_parameters") {
            self.seed_type_parameter_list(type_parameters, scopes);
        }
    }

    fn seed_type_parameter_list(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "type_parameter_declaration" {
                self.seed_type_parameter_declaration(child, scopes);
            }
        }
    }

    fn seed_type_parameter_declaration(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut cursor = node.walk();
        for child in node.children_by_field_name("name", &mut cursor) {
            let name = node_text(child, self.source);
            if name != "_" {
                scopes.declare(name.to_string());
            }
        }
    }

    fn seed_short_var_declaration(&mut self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(left) = node.child_by_field_name("left") {
            for name in identifier_texts(left, self.source) {
                scopes.declare(name);
            }
        }
    }

    fn check_identifier(&mut self, node: Node<'_>, scopes: &ScopeStack) {
        if !self.is_standalone_reference(node) {
            return;
        }
        let name = node_text(node, self.source);
        if self.name_is_known(name, scopes) {
            return;
        }
        self.push_diagnostic(
            node,
            GO_UNRECOGNIZED_SYMBOL,
            format!("unrecognized Go symbol `{name}`"),
        );
    }

    fn check_selector(&mut self, node: Node<'_>, scopes: &ScopeStack) {
        let Some((qualifier, _qualifier_node, field, field_node)) =
            selector_parts(node, self.source)
        else {
            return;
        };
        if field == "_" || is_predeclared_go_name(&field) {
            return;
        }
        if scopes.contains(&qualifier) {
            return;
        }
        if let Some(packages) = self.imports.alias_packages.get(&qualifier) {
            if packages
                .iter()
                .any(|package| self.package_has_member(package, &field))
            {
                return;
            }
            let Some(package) = packages.first().filter(|_| packages.len() == 1) else {
                return;
            };
            self.push_diagnostic(
                field_node,
                GO_UNRECOGNIZED_PACKAGE_MEMBER,
                format!("Go package `{package}` has no indexed member `{field}`"),
            );
        }
    }

    fn is_standalone_reference(&self, node: Node<'_>) -> bool {
        let name = node_text(node, self.source);
        if name == "_" || name.is_empty() || is_predeclared_go_name(name) {
            return false;
        }
        if is_declaration_identifier(node) || is_package_clause_identifier(node) {
            return false;
        }
        if is_keyed_element_key(node) {
            return false;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        !matches!(
            parent.kind(),
            "selector_expression"
                | "qualified_type"
                | "import_spec"
                | "label_name"
                | "labeled_statement"
                | "goto_statement"
                | "break_statement"
                | "continue_statement"
                | "keyed_element"
        )
    }

    fn name_is_known(&self, name: &str, scopes: &ScopeStack) -> bool {
        scopes.contains(name)
            || self.imports.alias_packages.contains_key(name)
            || self.imports.has_dot_member(name, self.support)
            || self.package_has_member(&self.package_name, name)
    }

    fn package_has_member(&self, package: &str, name: &str) -> bool {
        !self.support.fqn(&format!("{package}.{name}")).is_empty()
            || !self
                .support
                .fqn(&format!(
                    "{package}.{}.{name}",
                    crate::analyzer::GO_MODULE_SCOPE_SEGMENT
                ))
                .is_empty()
    }

    fn push_diagnostic(&mut self, node: Node<'_>, kind: &'static str, message: String) {
        self.diagnostics.push(GoSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind,
            message,
        });
    }
}

struct GoImportNamespaces {
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
}

impl GoImportNamespaces {
    fn new(go: &GoAnalyzer, file: &ProjectFile) -> Self {
        let (alias_packages, dot_packages) =
            resolve_go_import_namespaces(go, file, go.package_clause_names());
        Self {
            alias_packages,
            dot_packages,
        }
    }

    fn has_dot_member(&self, name: &str, support: &DefinitionLookupIndex) -> bool {
        self.dot_packages.iter().any(|package| {
            !support.fqn(&format!("{package}.{name}")).is_empty()
                || !support
                    .fqn(&format!(
                        "{package}.{}.{name}",
                        crate::analyzer::GO_MODULE_SCOPE_SEGMENT
                    ))
                    .is_empty()
        })
    }
}

fn declared_package_name(root: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if matches!(package_child.kind(), "package_identifier" | "identifier") {
                return Some(node_text(package_child, source).trim().to_string());
            }
        }
    }
    None
}

fn selector_parts<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>, String, Node<'tree>)> {
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor);
    let qualifier = children.next()?;
    let field = children.next()?;
    Some((
        node_text(qualifier, source).to_string(),
        qualifier,
        node_text(field, source).to_string(),
        field,
    ))
}

fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            let name = node_text(child, source);
            if name != "_" {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn identifier_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "field_identifier" | "package_identifier"
    ) {
        let name = node_text(node, source);
        if name != "_" {
            out.push(name.to_string());
        }
        return out;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "identifier" | "type_identifier" | "field_identifier" | "package_identifier"
            ) {
                let name = node_text(child, source);
                if name != "_" {
                    out.push(name.to_string());
                }
            } else {
                stack.push(child);
            }
        }
    }
    out
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

fn push_field_if_present<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    field_name: &str,
) {
    if let Some(child) = node.child_by_field_name(field_name) {
        stack.push(ScanFrame::Node(child));
    }
}

fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "function_declaration"
        | "method_declaration"
        | "type_spec"
        | "type_alias"
        | "method_elem" => parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, node)),
        "parameter_declaration" | "variadic_parameter_declaration" => {
            node.kind() == "identifier" && parent.child_by_field_name("type").is_some()
        }
        "field_declaration" => {
            let mut cursor = parent.walk();
            parent
                .children_by_field_name("name", &mut cursor)
                .any(|name| same_node(name, node))
        }
        "type_parameter_declaration" => {
            let mut cursor = parent.walk();
            parent
                .children_by_field_name("name", &mut cursor)
                .any(|name| same_node(name, node))
        }
        "var_spec" | "const_spec" => {
            let mut cursor = parent.walk();
            parent
                .children_by_field_name("name", &mut cursor)
                .any(|name| same_node(name, node))
        }
        "short_var_declaration" | "range_clause" => {
            parent.child_by_field_name("left").is_some_and(|left| {
                left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
            })
        }
        _ => false,
    }
}

fn is_package_clause_identifier(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "package_clause" {
            return true;
        }
        current = parent;
    }
    false
}

fn is_keyed_element_key(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "keyed_element" {
            if parent
                .child_by_field_name("value")
                .is_some_and(|value| contains_node(value, node))
            {
                return false;
            }
            if parent
                .child_by_field_name("key")
                .is_some_and(|key| contains_node(key, node))
            {
                return true;
            }
            return false;
        }
        current = parent;
    }
    false
}

fn is_predeclared_go_name(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "bool"
            | "byte"
            | "comparable"
            | "complex64"
            | "complex128"
            | "error"
            | "float32"
            | "float64"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "rune"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
            | "true"
            | "false"
            | "iota"
            | "nil"
            | "append"
            | "cap"
            | "clear"
            | "close"
            | "complex"
            | "copy"
            | "delete"
            | "imag"
            | "len"
            | "make"
            | "max"
            | "min"
            | "new"
            | "panic"
            | "print"
            | "println"
            | "real"
            | "recover"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        GO_UNRECOGNIZED_PACKAGE_MEMBER, GO_UNRECOGNIZED_SYMBOL, MAX_GO_SEMANTIC_DIAGNOSTICS,
        collect_go_semantic_diagnostics,
    };
    use crate::analyzer::{GoAnalyzer, Language, ProjectFile, TestProject};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: GoAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<super::GoSemanticDiagnostic> {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_go_semantic_diagnostics(&self.analyzer, &file, &source)
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        fixture_with_go_mod(files, true)
    }

    fn fixture_without_go_mod(files: &[(&str, &str)]) -> Fixture {
        fixture_with_go_mod(files, false)
    }

    fn fixture_with_go_mod(files: &[(&str, &str)], write_go_mod: bool) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        if write_go_mod {
            ProjectFile::new(root.clone(), "go.mod")
                .write("module example.com/app\n\ngo 1.22\n")
                .expect("write go.mod");
        }
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Go);
        let analyzer = GoAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn go_semantic_diagnostics_report_unknown_local_identifier() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func Run() {
    missingValue
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
    }

    #[test]
    fn go_semantic_diagnostics_report_unknown_workspace_package_member() {
        let fixture = fixture(&[
            (
                "store/store.go",
                r#"
package store

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "example.com/app/store"

func Run() {
    store.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    #[test]
    fn go_semantic_diagnostics_report_nested_unknown_workspace_package_member() {
        let fixture = fixture(&[
            (
                "store/store.go",
                r#"
package store

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "example.com/app/store"

func Run() {
    store.Missing.Nested()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    #[test]
    fn go_semantic_diagnostics_resolve_relative_workspace_imports() {
        let fixture = fixture_without_go_mod(&[
            (
                "store/store.go",
                r#"
package store

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "./store"

func Run() {
    store.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    #[test]
    fn go_semantic_diagnostics_suppress_known_names_and_import_forms() {
        let fixture = fixture(&[
            (
                "store/store.go",
                r#"
package store

type Client struct {
    Name string
}

func Present() {}
func (Client) Run() {}
"#,
            ),
            (
                "dot/dot.go",
                r#"
package dot

func DotFunc() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import (
    s "example.com/app/store"
    . "example.com/app/dot"
    _ "example.com/app/store"
)

type Local struct{}

func Present() {}

func Run(client s.Client) {
Start:
    local := Local{}
    _ = local
    _ = client.Name
    client.Run()
    Present()
    s.Present()
    DotFunc()
    println(len([]int{1}))
    goto Start
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn go_semantic_diagnostics_suppress_generic_and_variadic_declarations() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Box[T any] struct {
    value T
}

func Identity[T any](x T) T {
    var y T = x
    return y
}

func Log(xs ...string) {
    println(xs)
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn go_semantic_diagnostics_respect_function_local_scopes() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func A() {
    ctx := 1
    _ = ctx
}

func B() {
    _ = ctx
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("ctx"));
    }

    #[test]
    fn go_semantic_diagnostics_scan_assignment_lhs_references() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

func Run() {
    missingValue = 1
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
    }

    #[test]
    fn go_semantic_diagnostics_suppress_keyed_literal_keys_but_scan_values() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    _ = Client{Name: missingValue}
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missingValue"));
    }

    #[test]
    fn go_semantic_diagnostics_do_not_treat_struct_fields_as_bare_names() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    _ = Name
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Name"));
    }

    #[test]
    fn go_semantic_diagnostics_scan_struct_field_types() {
        let fixture = fixture(&[(
            "main.go",
            r#"
package main

type Client struct {
    Store MissingType
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingType"));
    }

    #[test]
    fn go_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("package main\n\nfunc Run() {\n");
        for index in 0..(MAX_GO_SEMANTIC_DIAGNOSTICS + 25) {
            source.push_str(&format!("    missing{index}\n"));
        }
        source.push_str("}\n");
        let fixture = fixture(&[("main.go", &source)]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(MAX_GO_SEMANTIC_DIAGNOSTICS, diagnostics.len());
    }

    #[test]
    fn go_semantic_diagnostics_use_imported_package_clause_for_unaliased_imports() {
        let fixture = fixture(&[
            (
                "postgres/postgres.go",
                r#"
package pg

func Present() {}
"#,
            ),
            (
                "main.go",
                r#"
package main

import "example.com/app/postgres"

func Run() {
    pg.Present()
    pg.Missing()
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("main.go");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(GO_UNRECOGNIZED_PACKAGE_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("Missing"));
    }

    #[test]
    fn go_semantic_diagnostics_suppress_external_and_malformed_files() {
        let fixture = fixture(&[
            (
                "external.go",
                r#"
package main

import "fmt"

func Run() {
    fmt.Println("ok")
}
"#,
            ),
            (
                "broken.go",
                r#"
package main

func Run( {
    missingValue
}
"#,
            ),
        ]);

        assert!(
            fixture.diagnostics_for("external.go").is_empty(),
            "external package selectors should not be diagnosed"
        );
        assert!(
            fixture.diagnostics_for("broken.go").is_empty(),
            "semantic diagnostics should suppress malformed files"
        );
    }
}
