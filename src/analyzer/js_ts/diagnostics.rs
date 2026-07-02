use crate::analyzer::js_ts::syntax::{
    compute_import_binder, is_declaration_identifier, is_object_in_member_expression,
    is_property_key_in_member, slice,
};
use crate::analyzer::js_ts::{AliasResolver, resolve_js_ts_module_specifier};
use crate::analyzer::semantic_diagnostics::{ScopeStack, node_range};
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::usages::parsed_tree::js_ts_tree_sitter_language_for_file;
use crate::analyzer::{
    IAnalyzer, Language, ProjectFile, Range, SemanticDiagnostic, resolve_analyzer,
};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser};

pub(crate) const JS_TS_UNRECOGNIZED_SYMBOL: &str = "js_ts_unrecognized_symbol";
pub(crate) const JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-javascript";
pub(crate) const TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-typescript";
const MAX_JS_TS_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_JS_TS_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsTsSemanticDiagnostic {
    pub(crate) range: Range,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    source: &'static str,
}

impl From<JsTsSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: JsTsSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: diagnostic.source,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

pub(crate) fn collect_javascript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    aliases: &AliasResolver,
) -> Vec<JsTsSemanticDiagnostic> {
    if resolve_analyzer::<crate::analyzer::JavascriptAnalyzer>(analyzer).is_none() {
        return Vec::new();
    }
    collect_js_ts_semantic_diagnostics(
        analyzer,
        file,
        source,
        Language::JavaScript,
        JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        aliases,
    )
}

pub(crate) fn collect_typescript_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    aliases: &AliasResolver,
) -> Vec<JsTsSemanticDiagnostic> {
    if resolve_analyzer::<crate::analyzer::TypescriptAnalyzer>(analyzer).is_none() {
        return Vec::new();
    }
    collect_js_ts_semantic_diagnostics(
        analyzer,
        file,
        source,
        Language::TypeScript,
        TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE,
        aliases,
    )
}

fn collect_js_ts_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    language: Language,
    diagnostic_source: &'static str,
    aliases: &AliasResolver,
) -> Vec<JsTsSemanticDiagnostic> {
    if source.len() > MAX_JS_TS_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(parser_language) = js_ts_tree_sitter_language_for_file(file, language) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&parser_language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let line_starts = compute_line_starts(source);
    let root = tree.root_node();
    let import_binder = compute_import_binder(source, &tree);
    let known_imports = import_binder
        .bindings
        .keys()
        .filter(|name| !name.is_empty())
        .cloned()
        .collect();
    let unresolved_external_imports = import_binder
        .bindings
        .iter()
        .filter_map(|(local, binding)| {
            let module = binding.module_specifier.as_str();
            let resolved = resolve_js_ts_module_specifier(file, module, language, Some(aliases));
            (!module.starts_with('.') && resolved.is_empty()).then(|| local.clone())
        })
        .collect();
    let same_file_declarations = analyzer
        .top_level_declarations(file)
        .map(|unit| unit.identifier().to_string())
        .filter(|name| !name.is_empty())
        .collect();

    let mut collector = JsTsDiagnosticCollector {
        source,
        diagnostic_source,
        line_starts: &line_starts,
        known_imports,
        unresolved_external_imports,
        same_file_declarations,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(root);
    collector.diagnostics
}

struct JsTsDiagnosticCollector<'a> {
    source: &'a str,
    diagnostic_source: &'static str,
    line_starts: &'a [usize],
    known_imports: HashSet<String>,
    unresolved_external_imports: HashSet<String>,
    same_file_declarations: HashSet<String>,
    diagnostics: Vec<JsTsSemanticDiagnostic>,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    DeclarePattern(Node<'tree>),
}

impl JsTsDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = ScopeStack::default();
        scopes.enter();
        for name in self
            .known_imports
            .iter()
            .chain(self.same_file_declarations.iter())
        {
            scopes.declare(name.clone());
        }
        declare_function_scoped_bindings(root, self.source, &mut scopes);

        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostics.len() >= MAX_JS_TS_SEMANTIC_DIAGNOSTICS {
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut scopes, &mut stack),
                ScanFrame::ExitScope => scopes.exit(),
                ScanFrame::DeclarePattern(node) => {
                    declare_binding_pattern(node, self.source, &mut scopes)
                }
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scopes: &mut ScopeStack,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        let kind = node.kind();
        if is_suppressed_subtree(kind) {
            return;
        }

        declare_declaration_name_in_current_scope(node, self.source, scopes);
        let introduces_scope = introduces_js_ts_scope(kind);
        if introduces_scope {
            scopes.enter();
            if let Some(parameters) = node.child_by_field_name("parameters") {
                declare_parameter_bindings(parameters, self.source, scopes);
            }
            declare_declaration_name_in_current_scope(node, self.source, scopes);
            declare_function_scoped_bindings(node, self.source, scopes);
            if kind == "catch_clause"
                && let Some(parameter) = node.child_by_field_name("parameter")
            {
                declare_binding_pattern(parameter, self.source, scopes);
            }
            stack.push(ScanFrame::ExitScope);
        }

        match kind {
            "variable_declarator" => {
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(ScanFrame::DeclarePattern(
                        node.child_by_field_name("name").unwrap_or(value),
                    ));
                    stack.push(ScanFrame::Node(value));
                } else if let Some(name) = node.child_by_field_name("name") {
                    declare_binding_pattern(name, self.source, scopes);
                }
                return;
            }
            "identifier" | "type_identifier" | "shorthand_property_identifier" => {
                self.handle_identifier(node, scopes);
            }
            _ => {}
        }

        push_named_children(stack, node);
    }

    fn handle_identifier(&mut self, node: Node<'_>, scopes: &ScopeStack) {
        let text = slice(node, self.source);
        if text.is_empty()
            || scopes.contains(text)
            || self.unresolved_external_imports.contains(text)
            || is_known_js_ts_global(text)
            || is_unsafe_reference_context(node, self.source)
        {
            return;
        }
        self.diagnostics.push(JsTsSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            source: self.diagnostic_source,
            kind: JS_TS_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized JS/TS symbol `{text}`"),
        });
    }
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(ScanFrame::Node(child));
        }
    }
}

fn declare_declaration_name_in_current_scope(
    node: Node<'_>,
    source: &str,
    scopes: &mut ScopeStack,
) {
    if !matches!(
        node.kind(),
        "function_declaration" | "class_declaration" | "abstract_class_declaration"
    ) {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        scopes.declare(slice(name, source).to_string());
    }
}

fn declare_function_scoped_bindings(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let root_id = node.id();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_declaration" if node.id() != root_id => {
                if let Some(name) = node.child_by_field_name("name") {
                    scopes.declare(slice(name, source).to_string());
                }
                continue;
            }
            "function_expression"
            | "arrow_function"
            | "generator_function"
            | "class_declaration"
            | "abstract_class_declaration"
                if node.id() != root_id =>
            {
                continue;
            }
            "variable_declarator" if is_var_declarator(node) => {
                if let Some(name) = node.child_by_field_name("name") {
                    declare_binding_pattern(name, source, scopes);
                }
                continue;
            }
            _ => {}
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn declare_parameter_bindings(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        declare_parameter_binding(child, source, scopes);
    }
}

fn declare_parameter_binding(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    match node.kind() {
        "identifier" | "object_pattern" | "array_pattern" | "assignment_pattern" => {
            declare_binding_pattern(node, source, scopes);
        }
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node
                .child_by_field_name("pattern")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.named_child(0))
            {
                declare_binding_pattern(pattern, source, scopes);
            }
        }
        "rest_pattern" => {
            if let Some(pattern) = node.named_child(0) {
                declare_binding_pattern(pattern, source, scopes);
            }
        }
        _ => {}
    }
}

fn declare_binding_pattern(node: Node<'_>, source: &str, scopes: &mut ScopeStack) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) {
            scopes.declare(slice(node, source).to_string());
            continue;
        }
        if node.kind() == "assignment_pattern" {
            if let Some(pattern) = node.named_child(0) {
                stack.push(pattern);
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn is_var_declarator(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "variable_declaration" {
        return false;
    }
    let Some(grandparent) = parent.parent() else {
        return false;
    };
    grandparent.kind() != "lexical_declaration"
}

fn introduces_js_ts_scope(kind: &str) -> bool {
    matches!(
        kind,
        "statement_block"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "function_declaration"
            | "method_definition"
            | "catch_clause"
    )
}

fn is_suppressed_subtree(kind: &str) -> bool {
    matches!(
        kind,
        "import_statement"
            | "import_clause"
            | "import_specifier"
            | "namespace_import"
            | "export_clause"
            | "export_specifier"
            | "jsx_opening_element"
            | "jsx_closing_element"
            | "jsx_self_closing_element"
            | "jsx_fragment"
    )
}

fn is_unsafe_reference_context(node: Node<'_>, source: &str) -> bool {
    if is_declaration_identifier(node)
        || is_property_key_in_member(node)
        || is_object_in_member_expression(node)
    {
        return true;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "labeled_statement"
        | "break_statement"
        | "continue_statement"
        | "pair_pattern"
        | "object_pattern"
        | "array_pattern"
        | "required_parameter"
        | "optional_parameter"
        | "rest_pattern"
        | "property_signature"
        | "public_field_definition"
        | "field_definition"
        | "method_signature"
        | "abstract_method_signature"
        | "ambient_declaration"
        | "internal_module"
        | "namespace_import"
        | "import_specifier"
        | "import_clause" => true,
        "pair" => parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id()),
        "member_expression" | "subscript_expression" => true,
        _ => {
            let text = slice(node, source);
            text.starts_with('_') || text == "arguments"
        }
    }
}

fn is_known_js_ts_global(name: &str) -> bool {
    matches!(
        name,
        "Array"
            | "ArrayBuffer"
            | "BigInt"
            | "Boolean"
            | "Date"
            | "Error"
            | "EvalError"
            | "Function"
            | "Infinity"
            | "Intl"
            | "JSON"
            | "Map"
            | "Math"
            | "NaN"
            | "Number"
            | "Object"
            | "Promise"
            | "Proxy"
            | "RangeError"
            | "ReferenceError"
            | "Reflect"
            | "RegExp"
            | "Set"
            | "String"
            | "Symbol"
            | "SyntaxError"
            | "TypeError"
            | "URIError"
            | "WeakMap"
            | "WeakSet"
            | "console"
            | "document"
            | "window"
            | "global"
            | "globalThis"
            | "process"
            | "module"
            | "exports"
            | "require"
            | "React"
            | "JSX"
            | "undefined"
            | "null"
            | "true"
            | "false"
            | "any"
            | "unknown"
            | "never"
            | "void"
            | "object"
            | "string"
            | "number"
            | "boolean"
            | "bigint"
            | "symbol"
            | "describe"
            | "it"
            | "test"
            | "expect"
            | "beforeEach"
            | "afterEach"
            | "beforeAll"
            | "afterAll"
            | "jest"
            | "vi"
            | "setTimeout"
            | "clearTimeout"
            | "setInterval"
            | "clearInterval"
            | "fetch"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        JS_TS_UNRECOGNIZED_SYMBOL, collect_javascript_semantic_diagnostics,
        collect_typescript_semantic_diagnostics,
    };
    use crate::analyzer::{
        AliasResolver, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TestProject,
        TypescriptAnalyzer,
    };
    use std::path::PathBuf;
    use std::sync::Arc;

    struct JsTsFixture<A> {
        _temp: tempfile::TempDir,
        analyzer: A,
        root: PathBuf,
        aliases: AliasResolver,
    }

    fn javascript_project(files: &[(&str, &str)]) -> JsTsFixture<JavascriptAnalyzer> {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (path, source) in files {
            ProjectFile::new(root.clone(), *path).write(source).unwrap();
        }
        let analyzer =
            JavascriptAnalyzer::from_project(TestProject::new(root.clone(), Language::JavaScript));
        let aliases = AliasResolver::new(root.clone());
        JsTsFixture {
            _temp: temp,
            analyzer,
            root,
            aliases,
        }
    }

    fn typescript_project(files: &[(&str, &str)]) -> JsTsFixture<TypescriptAnalyzer> {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for (path, source) in files {
            ProjectFile::new(root.clone(), *path).write(source).unwrap();
        }
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let aliases = AliasResolver::new(root.clone());
        JsTsFixture {
            _temp: temp,
            analyzer,
            root,
            aliases,
        }
    }

    fn js_diagnostics(fixture: &JsTsFixture<JavascriptAnalyzer>, rel_path: &str) -> Vec<String> {
        let file = ProjectFile::new(fixture.root.clone(), rel_path);
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        collect_javascript_semantic_diagnostics(&fixture.analyzer, &file, &source, &fixture.aliases)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect()
    }

    fn ts_diagnostics(fixture: &JsTsFixture<TypescriptAnalyzer>, rel_path: &str) -> Vec<String> {
        let file = ProjectFile::new(fixture.root.clone(), rel_path);
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        collect_typescript_semantic_diagnostics(&fixture.analyzer, &file, &source, &fixture.aliases)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect()
    }

    #[test]
    fn js_ts_semantic_diagnostics_report_unknown_local_identifiers() {
        let fixture = javascript_project(&[(
            "app.js",
            "function run(known) {\n  const local = known;\n  missingValue;\n  local;\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("missingValue"));

        let fixture = typescript_project(&[(
            "app.ts",
            "type Present = string;\nfunction run(value: Present): MissingType {\n  return missingValue;\n}\n",
        )]);
        let diagnostics = ts_diagnostics(&fixture, "app.ts");
        assert_eq!(2, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("MissingType"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("missingValue"))
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_imports_and_aliases() {
        let fixture = typescript_project(&[
            (
                "tsconfig.json",
                r#"{"compilerOptions":{"baseUrl":".","paths":{"@lib/*":["src/lib/*"]}}}"#,
            ),
            ("src/lib/util.ts", "export const helper = 1;\n"),
            (
                "src/app.ts",
                "import { helper } from '@lib/util';\nimport pkgDefault from 'external-package';\nimport { externalThing } from 'external-package';\nimport { localThing } from './local';\nhelper;\npkgDefault;\nexternalThing;\nlocalThing;\n",
            ),
            ("src/local.ts", "export const localThing = 2;\n"),
        ]);
        let diagnostics = ts_diagnostics(&fixture, "src/app.ts");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_properties_jsx_globals_and_malformed_files() {
        let fixture = javascript_project(&[
            (
                "component.jsx",
                "function View(props) {\n  const options = { missingKey: props.value, shorthand };\n  console.log(options.missingMember);\n  return <div className=\"x\"><span /></div>;\n}\n",
            ),
            ("broken.js", "function run( {\n  missingValue;\n}\n"),
        ]);
        let diagnostics = js_diagnostics(&fixture, "component.jsx");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("shorthand"));

        let broken = js_diagnostics(&fixture, "broken.js");
        assert!(broken.is_empty(), "{broken:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_suppress_type_only_import_uncertainty() {
        let fixture = typescript_project(&[(
            "app.ts",
            "import type { ExternalType } from 'external-package';\nconst value = ExternalType;\n",
        )]);
        let diagnostics = ts_diagnostics(&fixture, "app.ts");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_report_missing_imports_across_modules() {
        let fixture = typescript_project(&[
            ("src/a.ts", "export const config = 1;\n"),
            ("src/b.ts", "function run() {\n  return config;\n}\n"),
        ]);
        let diagnostics = ts_diagnostics(&fixture, "src/b.ts");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(diagnostics[0].contains("config"));
    }

    #[test]
    fn js_ts_semantic_diagnostics_handle_var_and_nested_function_scope() {
        let fixture = javascript_project(&[(
            "app.js",
            "function outer(ok) {\n  if (ok) { var value = 1; }\n  function inner() { return value; }\n  return inner();\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn js_ts_semantic_diagnostics_scan_parameter_default_values() {
        let fixture = javascript_project(&[(
            "app.js",
            "function run(value = missingDefault) {\n  return value;\n}\n",
        )]);
        let diagnostics = js_diagnostics(&fixture, "app.js");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("missingDefault"))
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_cap_reported_items() {
        let source = (0..250)
            .map(|index| format!("missing{index};"))
            .collect::<Vec<_>>()
            .join("\n");
        let fixture = javascript_project(&[("app.js", &source)]);
        let file = ProjectFile::new(fixture.root.clone(), "app.js");
        let source = fixture.analyzer.project().read_source(&file).unwrap();
        let diagnostics = collect_javascript_semantic_diagnostics(
            &fixture.analyzer,
            &file,
            &source,
            &fixture.aliases,
        );
        assert_eq!(200, diagnostics.len());
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == JS_TS_UNRECOGNIZED_SYMBOL)
        );
    }

    #[test]
    fn js_ts_semantic_diagnostics_multi_analyzer_routes_to_language_delegate() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "app.js")
            .write("missingValue;\n")
            .unwrap();
        let project = Arc::new(TestProject::new(root.clone(), Language::JavaScript));
        let analyzer = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let file = ProjectFile::new(root.clone(), "app.js");
        let source = analyzer.analyzer().project().read_source(&file).unwrap();
        let diagnostics = analyzer.analyzer().semantic_diagnostics(&file, &source);
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(JS_TS_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
    }
}
