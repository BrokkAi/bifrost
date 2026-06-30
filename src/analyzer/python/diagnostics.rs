use crate::analyzer::semantic_diagnostics::{
    ScopeStack, contains_node, node_range, node_text, same_node,
};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::{
    DefinitionLookupIndex, IAnalyzer, ImportAnalysisProvider, ProjectFile, PythonAnalyzer, Range,
    SemanticDiagnostic, resolve_analyzer,
};
use crate::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub(crate) const PYTHON_UNRECOGNIZED_SYMBOL: &str = "python_unrecognized_symbol";
pub(crate) const PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-python";
const MAX_PYTHON_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_PYTHON_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonSemanticDiagnostic {
    pub(crate) range: Range,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

impl From<PythonSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: PythonSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Collect conservative Python unresolved-name diagnostics.
///
/// This pass intentionally emits only for bare-name references. It suppresses
/// files that use dynamic namespace features or unresolved wildcard imports,
/// and it never diagnoses attribute/member names. Python programs commonly use
/// optional imports, `sys.path` mutation, module `__getattr__`, monkey-patched
/// attributes, and dynamic imports; those cases make absence unknowable without
/// a fuller Python runtime model.
pub(crate) fn collect_python_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<PythonSemanticDiagnostic> {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return Vec::new();
    };
    if source.len() > MAX_PYTHON_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = parse_python_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() || file_has_dynamic_unknowns(py, file, source, tree.root_node()) {
        return Vec::new();
    }

    let support = analyzer.definition_lookup_index();
    let line_starts = compute_line_starts(source);
    let module_name = super::python_module_name(file);
    let mut collector = PythonDiagnosticCollector {
        py,
        analyzer,
        support,
        file,
        source,
        line_starts: &line_starts,
        module_name,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
}

fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

struct PythonDiagnosticCollector<'a> {
    py: &'a PythonAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    module_name: String,
    diagnostics: Vec<PythonSemanticDiagnostic>,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    SeedTargets(Node<'tree>),
}

impl PythonDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = ScopeStack::default();
        scopes.enter();
        self.seed_module_scope(&mut scopes);
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostics.len() >= MAX_PYTHON_SEMANTIC_DIAGNOSTICS {
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut scopes, &mut stack),
                ScanFrame::ExitScope => scopes.exit(),
                ScanFrame::SeedTargets(node) => self.seed_assignment_targets(node, &mut scopes),
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
            "module" => push_named_children(stack, node),
            "function_definition" | "lambda" => {
                self.seed_named_declaration(node, scopes);
                scopes.enter();
                self.seed_parameters(node, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children_except(stack, node, node.child_by_field_name("name"));
            }
            "class_definition" => {
                self.seed_named_declaration(node, scopes);
                self.push_field_if_present(stack, node, "superclasses");
                scopes.enter();
                stack.push(ScanFrame::ExitScope);
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(ScanFrame::Node(body));
                }
            }
            "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression" => {
                scopes.enter();
                self.seed_comprehension_targets(node, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "match_statement" => {}
            "import_statement" | "import_from_statement" => {}
            "assignment" | "augmented_assignment" | "named_expression" => {
                stack.push(ScanFrame::SeedTargets(node));
                self.push_field_if_present(stack, node, "right");
                self.push_field_if_present(stack, node, "value");
            }
            "for_statement" | "for_in_clause" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(ScanFrame::Node(body));
                }
                stack.push(ScanFrame::SeedTargets(node));
                self.push_field_if_present(stack, node, "right");
            }
            "with_statement" | "with_item" => {
                stack.push(ScanFrame::SeedTargets(node));
                push_named_children(stack, node);
            }
            "except_clause" => {
                self.seed_except_alias(node, scopes);
                push_named_children(stack, node);
            }
            "identifier" => self.check_identifier(node, scopes),
            "attribute" => {
                if let Some(object) = node.child_by_field_name("object") {
                    stack.push(ScanFrame::Node(object));
                }
            }
            "string" | "string_content" | "comment" => {}
            _ => push_named_children(stack, node),
        }
    }

    fn seed_module_scope(&self, scopes: &mut ScopeStack) {
        for import in self.py.import_info_of(self.file) {
            if let Some(local_name) = import.alias.as_ref().or(import.identifier.as_ref()) {
                scopes.declare(local_name.clone());
            }
        }
        for (binding, _) in self.py.resolve_import_bindings(self.file) {
            scopes.declare(binding);
        }
        for unit in self.analyzer.declarations(self.file) {
            if !unit.identifier().is_empty() {
                scopes.declare(unit.identifier().to_string());
            }
        }
    }

    fn seed_named_declaration(&self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(name) = node.child_by_field_name("name") {
            let text = node_text(name, self.source).trim();
            if !text.is_empty() {
                scopes.declare(text.to_string());
            }
        }
    }

    fn seed_parameters(&self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(parameters) = node.child_by_field_name("parameters") {
            collect_parameter_names(parameters, self.source, scopes);
        }
    }

    fn seed_assignment_targets(&self, node: Node<'_>, scopes: &mut ScopeStack) {
        for field in ["left", "name", "alias"] {
            if let Some(target) = node.child_by_field_name(field) {
                collect_bound_identifiers(target, self.source, scopes);
            }
        }
        if node.kind() == "with_item" || node.kind() == "with_statement" {
            collect_alias_children(node, self.source, scopes);
        }
    }

    fn seed_except_alias(&self, node: Node<'_>, scopes: &mut ScopeStack) {
        if let Some(alias) = node.child_by_field_name("alias") {
            collect_bound_identifiers(alias, self.source, scopes);
            return;
        }
        let mut identifiers = Vec::new();
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == "identifier" {
                let text = node_text(current, self.source).trim();
                if !text.is_empty() {
                    identifiers.push(text.to_string());
                }
                continue;
            }
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        if identifiers.len() >= 2
            && let Some(alias) = identifiers.into_iter().next()
        {
            scopes.declare(alias);
        }
    }

    fn seed_comprehension_targets(&self, node: Node<'_>, scopes: &mut ScopeStack) {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if matches!(current.kind(), "for_statement" | "for_in_clause")
                && let Some(left) = current.child_by_field_name("left")
            {
                collect_bound_identifiers(left, self.source, scopes);
            }
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }

    fn check_identifier(&mut self, node: Node<'_>, scopes: &ScopeStack) {
        if !self.is_reference_identifier(node) {
            return;
        }
        let name = node_text(node, self.source);
        if name.is_empty() || name == "_" || is_python_builtin_or_constant(name) {
            return;
        }
        if scopes.contains(name) || self.name_resolves_project_locally(name) {
            return;
        }
        self.diagnostics.push(PythonSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: PYTHON_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Python symbol `{name}`"),
        });
    }

    fn is_reference_identifier(&self, node: Node<'_>) -> bool {
        if is_declaration_identifier(node)
            || is_import_identifier(node)
            || is_attribute_identifier(node)
            || is_pattern_identifier(node)
        {
            return false;
        }
        let mut current = node;
        while let Some(parent) = current.parent() {
            if matches!(parent.kind(), "string" | "string_content" | "comment") {
                return false;
            }
            current = parent;
        }
        true
    }

    fn name_resolves_project_locally(&self, name: &str) -> bool {
        if !self.support.file_identifier(self.file, name).is_empty() {
            return true;
        }
        if !self
            .support
            .fqn(&format!("{}.{}", self.module_name, name))
            .is_empty()
        {
            return true;
        }
        let bindings = self.py.resolve_import_bindings(self.file);
        if bindings.contains_key(name) {
            return true;
        }
        false
    }

    fn push_field_if_present<'tree>(
        &self,
        stack: &mut Vec<ScanFrame<'tree>>,
        node: Node<'tree>,
        field_name: &str,
    ) {
        if let Some(child) = node.child_by_field_name(field_name) {
            stack.push(ScanFrame::Node(child));
        }
    }
}

fn file_has_dynamic_unknowns(
    py: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> bool {
    has_unresolved_wildcard_import(py, file)
        || has_module_getattr(source, root)
        || has_dynamic_namespace_call(source, root)
}

fn has_unresolved_wildcard_import(py: &PythonAnalyzer, file: &ProjectFile) -> bool {
    py.import_info_of(file)
        .iter()
        .filter(|import| import.is_wildcard)
        .any(|import| py.resolve_import(file, import).is_empty())
}

fn has_module_getattr(source: &str, root: Node<'_>) -> bool {
    let mut cursor = root.walk();
    root.named_children(&mut cursor).any(|child| {
        child.kind() == "function_definition"
            && child
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "__getattr__")
    })
}

fn has_dynamic_namespace_call(source: &str, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && is_dynamic_function(function, source)
        {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn is_dynamic_function(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "identifier" => matches!(node_text(node, source), "globals" | "locals" | "__import__"),
        "attribute" => node_text(node, source) == "importlib.import_module",
        _ => false,
    }
}

fn collect_bound_identifiers(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" => {
                let text = node_text(current, source).trim();
                if !text.is_empty() {
                    scopes.declare(text.to_string());
                }
            }
            "attribute" | "call" => {}
            _ => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

fn collect_parameter_names(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(name) = python_parameter_name(child, source) {
            scopes.declare(name);
        }
    }
}

fn python_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(node_text(node, source).trim().to_string()),
        "typed_parameter"
        | "typed_default_parameter"
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

fn collect_alias_children(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let mut cursor = node.walk();
    for alias in node.children_by_field_name("alias", &mut cursor) {
        collect_bound_identifiers(alias, source, scopes);
    }
    let mut cursor = node.walk();
    for item in node.named_children(&mut cursor) {
        let mut item_cursor = item.walk();
        for alias in item.children_by_field_name("alias", &mut item_cursor) {
            collect_bound_identifiers(alias, source, scopes);
        }
    }
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

fn push_named_children_except<'tree>(
    stack: &mut Vec<ScanFrame<'tree>>,
    node: Node<'tree>,
    excluded: Option<Node<'tree>>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| excluded.is_none_or(|excluded| !same_node(*child, excluded)))
        .collect();
    for child in children.into_iter().rev() {
        stack.push(ScanFrame::Node(child));
    }
}

fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "function_definition" | "class_definition" => parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, node)),
        "parameters" | "list_splat_pattern" | "dictionary_splat_pattern" => true,
        "default_parameter" | "typed_parameter" | "typed_default_parameter" => parent
            .child_by_field_name("name")
            .is_some_and(|name| contains_node(name, node)),
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => parent
            .child_by_field_name("left")
            .is_some_and(|left| contains_node(left, node)),
        "named_expression" => parent
            .child_by_field_name("name")
            .is_some_and(|name| contains_node(name, node)),
        _ => false,
    }
}

fn is_import_identifier(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "import_statement" | "import_from_statement") {
            return true;
        }
        current = parent;
    }
    false
}

fn is_attribute_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "attribute"
        && parent
            .child_by_field_name("attribute")
            .is_some_and(|attribute| same_node(attribute, node))
}

fn is_pattern_identifier(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind().contains("pattern") {
            return true;
        }
        current = parent;
    }
    false
}

fn is_python_builtin_or_constant(name: &str) -> bool {
    matches!(
        name,
        "None"
            | "True"
            | "False"
            | "NotImplemented"
            | "Ellipsis"
            | "__annotations__"
            | "__builtins__"
            | "__debug__"
            | "__doc__"
            | "__file__"
            | "__loader__"
            | "__name__"
            | "__package__"
            | "__spec__"
            | "ArithmeticError"
            | "AssertionError"
            | "AttributeError"
            | "BaseException"
            | "BaseExceptionGroup"
            | "BlockingIOError"
            | "BrokenPipeError"
            | "BufferError"
            | "BytesWarning"
            | "ChildProcessError"
            | "ConnectionAbortedError"
            | "ConnectionError"
            | "ConnectionRefusedError"
            | "ConnectionResetError"
            | "DeprecationWarning"
            | "EOFError"
            | "EncodingWarning"
            | "EnvironmentError"
            | "Exception"
            | "ExceptionGroup"
            | "FileExistsError"
            | "FileNotFoundError"
            | "FloatingPointError"
            | "FutureWarning"
            | "GeneratorExit"
            | "IOError"
            | "ImportError"
            | "ImportWarning"
            | "IndentationError"
            | "IndexError"
            | "InterruptedError"
            | "IsADirectoryError"
            | "KeyError"
            | "KeyboardInterrupt"
            | "LookupError"
            | "MemoryError"
            | "ModuleNotFoundError"
            | "NameError"
            | "NotADirectoryError"
            | "NotImplementedError"
            | "OSError"
            | "OverflowError"
            | "PendingDeprecationWarning"
            | "PermissionError"
            | "ProcessLookupError"
            | "RecursionError"
            | "ReferenceError"
            | "ResourceWarning"
            | "RuntimeError"
            | "RuntimeWarning"
            | "StopAsyncIteration"
            | "StopIteration"
            | "SyntaxError"
            | "SyntaxWarning"
            | "SystemError"
            | "SystemExit"
            | "TabError"
            | "TimeoutError"
            | "TypeError"
            | "UnboundLocalError"
            | "UnicodeDecodeError"
            | "UnicodeEncodeError"
            | "UnicodeError"
            | "UnicodeTranslateError"
            | "UnicodeWarning"
            | "UserWarning"
            | "ValueError"
            | "Warning"
            | "ZeroDivisionError"
            | "abs"
            | "aiter"
            | "all"
            | "anext"
            | "any"
            | "ascii"
            | "bin"
            | "bool"
            | "breakpoint"
            | "bytearray"
            | "bytes"
            | "callable"
            | "chr"
            | "classmethod"
            | "compile"
            | "complex"
            | "copyright"
            | "credits"
            | "delattr"
            | "dict"
            | "dir"
            | "divmod"
            | "enumerate"
            | "eval"
            | "exec"
            | "exit"
            | "filter"
            | "float"
            | "format"
            | "frozenset"
            | "getattr"
            | "hasattr"
            | "hash"
            | "help"
            | "hex"
            | "id"
            | "input"
            | "int"
            | "isinstance"
            | "issubclass"
            | "iter"
            | "len"
            | "license"
            | "list"
            | "locals"
            | "map"
            | "max"
            | "memoryview"
            | "min"
            | "next"
            | "object"
            | "oct"
            | "open"
            | "ord"
            | "pow"
            | "print"
            | "property"
            | "quit"
            | "range"
            | "repr"
            | "reversed"
            | "round"
            | "set"
            | "setattr"
            | "slice"
            | "sorted"
            | "staticmethod"
            | "str"
            | "sum"
            | "super"
            | "tuple"
            | "type"
            | "vars"
            | "zip"
            | "__import__"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PYTHON_SEMANTIC_DIAGNOSTICS, PYTHON_UNRECOGNIZED_SYMBOL,
        collect_python_semantic_diagnostics,
    };
    use crate::analyzer::{Language, ProjectFile, PythonAnalyzer, TestProject};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: PythonAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn diagnostics_for(&self, rel_path: &str) -> Vec<super::PythonSemanticDiagnostic> {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_python_semantic_diagnostics(&self.analyzer, &file, &source)
        }

        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
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
        let project = TestProject::new(root.clone(), Language::Python);
        let analyzer = PythonAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_local_identifier() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    missing_value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missing_value"));
    }

    #[test]
    fn python_semantic_diagnostics_suppress_known_names_and_imports() {
        let fixture = fixture(&[
            (
                "pkg/service.py",
                r#"
class Service:
    pass

def build():
    return Service()
"#,
            ),
            (
                "app.py",
                r#"
from pkg.service import Service, build

LOCAL = 1

class Runner:
    pass

def run(param):
    value = LOCAL
    for item in range(1):
        alias = item
    with open(__file__) as handle:
        data = handle
    try:
        build()
    except Exception as exc:
        print(exc)
    return Service(), Runner(), value, alias, data, param, True, None
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_relative_imports_and_reexports() {
        let fixture = fixture(&[
            (
                "pkg/core.py",
                r#"
class Service:
    pass
"#,
            ),
            (
                "pkg/__init__.py",
                r#"
from .core import Service
"#,
            ),
            (
                "app.py",
                r#"
from pkg import Service

def run():
    return Service()
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_type_references() {
        let fixture = fixture(&[(
            "app.py",
            r#"
class Known:
    pass

def run(value: Known) -> MissingType:
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PYTHON_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingType"));
    }

    #[test]
    fn python_semantic_diagnostics_report_unknown_parameter_annotations_and_defaults() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value: MissingType = missing_default):
    return value
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_default"))
        );
    }

    #[test]
    fn python_semantic_diagnostics_check_attribute_receiver_but_not_member() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    return missing_client.fetch()
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("missing_client"));
        assert!(!diagnostics[0].message.contains("fetch"));
    }

    #[test]
    fn python_semantic_diagnostics_handle_comprehension_scopes() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(rows):
    values = [item for item in rows if item]
    return item
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].message.contains("item"));
    }

    #[test]
    fn python_semantic_diagnostics_suppress_match_pattern_uncertainty() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run(value):
    match value:
        case {"id": ident}:
            return ident
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_builtin_exceptions() {
        let fixture = fixture(&[(
            "app.py",
            r#"
def run():
    try:
        raise RuntimeError("boom")
    except ValueError as exc:
        return exc
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn python_semantic_diagnostics_suppress_unresolved_import_boundaries() {
        let fixture = fixture(&[
            (
                "external.py",
                r#"
from missing_package import *

def run():
    missing_name
"#,
            ),
            (
                "named.py",
                r#"
from missing_package import maybe

def run():
    maybe
"#,
            ),
        ]);

        assert!(fixture.diagnostics_for("external.py").is_empty());
        assert!(fixture.diagnostics_for("named.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_suppress_dynamic_constructs_and_attributes() {
        let fixture = fixture(&[
            (
                "dynamic.py",
                r#"
def run():
    globals()
    missing_name
"#,
            ),
            (
                "module_getattr.py",
                r#"
def __getattr__(name):
    return 1

def run():
    missing_name
"#,
            ),
            (
                "attribute.py",
                r#"
def run(obj):
    obj.missing_name
"#,
            ),
        ]);

        assert!(fixture.diagnostics_for("dynamic.py").is_empty());
        assert!(fixture.diagnostics_for("module_getattr.py").is_empty());
        assert!(fixture.diagnostics_for("attribute.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_suppress_malformed_files() {
        let fixture = fixture(&[(
            "broken.py",
            r#"
def run(
    missing_name
"#,
        )]);

        assert!(fixture.diagnostics_for("broken.py").is_empty());
    }

    #[test]
    fn python_semantic_diagnostics_cap_reported_items() {
        let mut source = String::from("def run():\n");
        for index in 0..(MAX_PYTHON_SEMANTIC_DIAGNOSTICS + 25) {
            source.push_str(&format!("    missing_{index}\n"));
        }
        let fixture = fixture(&[("app.py", &source)]);

        let diagnostics = fixture.diagnostics_for("app.py");
        assert_eq!(MAX_PYTHON_SEMANTIC_DIAGNOSTICS, diagnostics.len());
    }
}
