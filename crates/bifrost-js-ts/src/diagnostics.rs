//! JS/TS semantic diagnostics: the unrecognized-symbol scope/binding walk, plus
//! the classification of every binding an external module specifier introduces.
//!
//! One collector for both dialects. `brokk-bifrost-analysis` keeps the two
//! entry points that guard on the concrete analyzer being present
//! (`analyzer/js_ts/diagnostics.rs`), the retained-npm-surface evidence the two
//! entry points supply, and the analyzer-bound tests; everything the walk
//! itself does is syntax and core types.
//!
//! The collector builds a [`SemanticDiagnosticReport`] directly, so every
//! candidate it looked at leaves a typed outcome. Two populations reach it:
//!
//! - Names the file spells. A name the lexical surface binds is resolved
//!   against a complete workspace-local surface; a name it does not bind is
//!   absent from that same complete surface.
//! - Bindings an external module specifier introduces. `brokk-bifrost-js-ts`
//!   cannot name a semantic-model overlay, so the retained npm surface answers
//!   for those through [`JsTsExternalSurfaceEvidence`].

use crate::imports::{
    npm_package_of_module_specifier, require_call_module_specifier, resolve_js_ts_module_specifier,
};
use crate::parse::js_ts_tree_sitter_language_for_file;
use crate::syntax::{
    compute_import_binder, is_declaration_identifier, is_object_in_member_expression,
    is_property_key_in_member, slice,
};
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{ScopeStack, node_range};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use std::path::Path;
use tree_sitter::{Node, Parser};

pub const JS_TS_UNRECOGNIZED_SYMBOL: &str = "js_ts_unrecognized_symbol";
pub const JS_TS_MISSING_MODULE_EXPORT: &str = "js_ts_missing_module_export";
pub const JAVASCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-javascript";
pub const TYPESCRIPT_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-typescript";
const MAX_JS_TS_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_JS_TS_SEMANTIC_DIAGNOSTICS: usize = 200;

/// What the retained external surface can prove about one imported name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsExportedNameEvidence {
    /// An activated pack surface for the module declares the name.
    Indexed,
    /// Every pack that contributes the module's surface is complete, and none
    /// of them declares the name.
    AbsentFromCompleteSurface,
    /// Nothing retained can decide the name. The reasons say why.
    Undecided(Vec<SemanticDiagnosticIncompleteReason>),
}

/// What the retained external surface can prove about a whole module.
///
/// A default, namespace, side-effect, or CommonJS binding names no single
/// export, so this deliberately has no absence arm: the surface records a
/// default export under its own declaration name rather than as `default`, and
/// `esModuleInterop` lets a default binding stand for a CommonJS module
/// object. Neither fact can be checked from a declaration surface, so a
/// module-shaped binding is never proof of absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsTsModuleEvidence {
    /// An activated pack surface declares the module.
    Indexed,
    /// Nothing retained declares the module. The reasons say why.
    Undecided(Vec<SemanticDiagnosticIncompleteReason>),
}

/// The retained external evidence a JS/TS diagnostic request may consult.
///
/// `brokk-bifrost-js-ts` depends only on `brokk-bifrost-core` and cannot name a
/// `SemanticModelOverlay` or retained dependency-discovery evidence, so the
/// analysis side implements this and the collector asks structured questions
/// through it. This mirrors Java's `external_boundary_evidence` split.
///
/// Every implementation reads retained state only. A diagnostic request must
/// never walk `node_modules`, read a lockfile, or start dependency discovery;
/// state that has not been retained is a typed incomplete outcome, never an
/// error and never a reason to go and look.
pub trait JsTsExternalSurfaceEvidence {
    /// Whether the retained surface of `module_specifier` exports `name`.
    fn classify_exported_name(
        &self,
        module_specifier: &str,
        name: &str,
    ) -> JsTsExportedNameEvidence;

    /// Whether `module_specifier` has a retained surface at all.
    fn classify_module(&self, module_specifier: &str) -> JsTsModuleEvidence;
}

#[allow(clippy::too_many_arguments)]
pub fn collect_js_ts_semantic_diagnostics(
    analyzer: &dyn CodeUnitIndex,
    evidence: &dyn JsTsExternalSurfaceEvidence,
    file: &ProjectFile,
    source: &str,
    language: Language,
    diagnostic_source: &'static str,
    aliases: &AliasResolver,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_JS_TS_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(parser_language) = js_ts_tree_sitter_language_for_file(file, language) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("no JS/TS grammar serves {}", file.rel_path().display()),
            }],
        );
        return report;
    };
    let mut parser = Parser::new();
    if parser.set_language(&parser_language).is_err() {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "JS/TS parser is unavailable".to_string(),
            }],
        );
        return report;
    }
    let Some(tree) = parser.parse(source, None) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "JS/TS source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // A malformed file's scope surface is not the one the author meant.
        // Parse errors travel the separate LSP path; the semantic report stays
        // complete and empty rather than claiming anything about the wreckage.
        return report;
    }

    let line_starts = compute_line_starts(source);
    let root = tree.root_node();
    let import_binder = compute_import_binder(source, &tree);
    let known_imports = import_binder
        .names()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    let same_file_declarations = analyzer
        .top_level_declarations(file)
        .into_iter()
        .map(|unit| unit.identifier().to_string())
        .filter(|name| !name.is_empty())
        .collect();

    ExternalModuleClassifier {
        source,
        file,
        language,
        aliases,
        evidence,
        line_starts: &line_starts,
        diagnostic_source,
        locally_declared_modules: locally_declared_modules(root, source),
    }
    .classify(root, &mut report);

    let mut collector = JsTsDiagnosticCollector {
        source,
        diagnostic_source,
        file_rel_path: file.rel_path(),
        line_starts: &line_starts,
        known_imports,
        same_file_declarations,
        report,
        errors: 0,
    };
    collector.scan_tree(root);
    collector.report
}

/// The bindings an external module specifier introduces, classified against the
/// retained npm surface.
///
/// Nothing here re-reads the file system. A specifier that resolves to a
/// workspace file is the export graph's business and is left alone; a bare
/// specifier the workspace itself declares with `declare module '...'` is
/// workspace-local; everything else is an external boundary the retained
/// surface must answer for.
struct ExternalModuleClassifier<'a> {
    source: &'a str,
    file: &'a ProjectFile,
    language: Language,
    aliases: &'a AliasResolver,
    evidence: &'a dyn JsTsExternalSurfaceEvidence,
    line_starts: &'a [usize],
    diagnostic_source: &'static str,
    locally_declared_modules: HashSet<String>,
}

impl ExternalModuleClassifier<'_> {
    fn classify(&self, root: Node<'_>, report: &mut SemanticDiagnosticReport) {
        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };
            match child.kind() {
                "import_statement" => self.classify_import_statement(child, report),
                // `export { name } from 'pkg'` and `export * from 'pkg'` read
                // the same module surface an import does.
                "export_statement" => self.classify_export_statement(child, report),
                "lexical_declaration" | "variable_declaration" => {
                    self.classify_require_declaration(child, report)
                }
                _ => {}
            }
        }
    }

    fn classify_import_statement(&self, node: Node<'_>, report: &mut SemanticDiagnosticReport) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        let Some(specifier) = module_specifier_text(source_node, self.source) else {
            return;
        };
        let Some(specifier) = self.external_specifier(specifier) else {
            return;
        };
        let mut clauses = 0;
        let mut cursor = node.walk();
        for clause in node.named_children(&mut cursor) {
            if clause.kind() != "import_clause" {
                continue;
            }
            clauses += 1;
            let mut clause_cursor = clause.walk();
            for clause_child in clause.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    // `import local from 'pkg'`.
                    "identifier" => self.push_module(specifier, clause_child, report),
                    // `import * as ns from 'pkg'`.
                    "namespace_import" => self.push_module(specifier, clause_child, report),
                    "named_imports" => {
                        let mut spec_cursor = clause_child.walk();
                        for spec in clause_child.named_children(&mut spec_cursor) {
                            if spec.kind() != "import_specifier" {
                                continue;
                            }
                            if let Some(name) = spec.child_by_field_name("name") {
                                self.push_exported_name(specifier, name, report);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if clauses == 0 {
            // `import 'pkg'`: a side effect, so the module itself is the
            // whole question.
            self.push_module(specifier, source_node, report);
        }
    }

    fn classify_export_statement(&self, node: Node<'_>, report: &mut SemanticDiagnosticReport) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        let Some(specifier) = module_specifier_text(source_node, self.source) else {
            return;
        };
        let Some(specifier) = self.external_specifier(specifier) else {
            return;
        };
        let mut named = 0;
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == "export_specifier" {
                if let Some(name) = current.child_by_field_name("name") {
                    named += 1;
                    self.push_exported_name(specifier, name, report);
                }
                continue;
            }
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
        if named == 0 {
            // `export * from 'pkg'` re-exports the whole surface.
            self.push_module(specifier, source_node, report);
        }
    }

    fn classify_require_declaration(&self, node: Node<'_>, report: &mut SemanticDiagnosticReport) {
        let mut cursor = node.walk();
        for declarator in node.named_children(&mut cursor) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            let Some(value) = declarator.child_by_field_name("value") else {
                continue;
            };
            let Some(specifier) = require_call_module_specifier(value, self.source) else {
                continue;
            };
            let Some(specifier) = self.external_specifier(&specifier) else {
                continue;
            };
            let anchor = declarator.child_by_field_name("name").unwrap_or(declarator);
            // A `require` binding reads a CommonJS module object, whose shape a
            // TypeScript declaration surface describes only indirectly. Judge
            // the module, never one name destructured off it.
            self.push_module(specifier, anchor, report);
        }
    }

    /// The specifier as an external npm boundary, or `None` when this request
    /// has no external question to ask about it.
    fn external_specifier<'s>(&self, specifier: &'s str) -> Option<&'s str> {
        npm_package_of_module_specifier(specifier)?;
        if !resolve_js_ts_module_specifier(self.file, specifier, self.language, Some(self.aliases))
            .is_empty()
        {
            return None;
        }
        Some(specifier)
    }

    fn push_exported_name(
        &self,
        specifier: &str,
        name_node: Node<'_>,
        report: &mut SemanticDiagnosticReport,
    ) {
        let name = slice(name_node, self.source);
        if name.is_empty() {
            return;
        }
        let range = node_range(name_node, self.line_starts);
        if self.locally_declared_modules.contains(specifier) {
            report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        match self.evidence.classify_exported_name(specifier, name) {
            JsTsExportedNameEvidence::Indexed => {
                report.push_resolved(range, BoundaryStatus::ExternalIndexed)
            }
            JsTsExportedNameEvidence::AbsentFromCompleteSurface => report.push_absent(
                SemanticAbsenceProof {
                    range,
                    domain: SemanticDiagnosticDomain::Module {
                        name: specifier.to_string(),
                    },
                    boundary: BoundaryStatus::ExternalIndexed,
                },
                SemanticDiagnostic {
                    range,
                    source: self.diagnostic_source,
                    kind: JS_TS_MISSING_MODULE_EXPORT,
                    message: format!("Module `{specifier}` has no exported member `{name}`"),
                },
            ),
            JsTsExportedNameEvidence::Undecided(reasons) => {
                report.push_incomplete(Some(range), reasons)
            }
        }
    }

    fn push_module(
        &self,
        specifier: &str,
        anchor: Node<'_>,
        report: &mut SemanticDiagnosticReport,
    ) {
        let range = node_range(anchor, self.line_starts);
        if self.locally_declared_modules.contains(specifier) {
            report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        match self.evidence.classify_module(specifier) {
            JsTsModuleEvidence::Indexed => {
                report.push_resolved(range, BoundaryStatus::ExternalIndexed)
            }
            JsTsModuleEvidence::Undecided(reasons) => report.push_incomplete(Some(range), reasons),
        }
    }
}

/// The bare module specifiers this file itself declares with
/// `declare module 'name' { ... }`.
///
/// An ambient module declaration is the workspace's own surface for that
/// specifier, so an import from it resolves workspace-locally and no retained
/// external surface can contradict it. Only this file's declarations are
/// visible here; a sibling file's ambient declaration is a wider question that
/// the analyzer's declaration index would have to answer.
fn locally_declared_modules(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut declared = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        // The TypeScript grammar spells `declare module 'x'` as `module` and
        // `namespace x` as `internal_module`, and older trees reuse
        // `internal_module` for both. A quoted name is what distinguishes a
        // module-specifier declaration from a namespace either way.
        if matches!(node.kind(), "module" | "internal_module")
            && let Some(name) = node.child_by_field_name("name")
            && let Some(text) = module_specifier_text(name, source)
        {
            declared.insert(text.to_string());
            continue;
        }
        // Ambient module declarations sit at the top level, directly or under
        // an `ambient_declaration`. Nothing deeper needs walking.
        if matches!(node.kind(), "program" | "ambient_declaration") {
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }
    declared
}

/// A `string` node's own text carries its quotes; its `string_fragment` child
/// is the specifier. Read the child rather than trimming delimiters off the
/// parent's text.
fn module_specifier_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "string" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "string_fragment")
        .map(|fragment| slice(fragment, source))
        .filter(|text| !text.is_empty())
}

struct JsTsDiagnosticCollector<'a> {
    source: &'a str,
    diagnostic_source: &'static str,
    /// The workspace-relative path that names the lexical surface each absence
    /// proof was checked against.
    file_rel_path: &'a Path,
    line_starts: &'a [usize],
    known_imports: HashSet<String>,
    same_file_declarations: HashSet<String>,
    report: SemanticDiagnosticReport,
    errors: usize,
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
            if self.errors >= MAX_JS_TS_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
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
        if is_dynamic_require_call(node, self.source) {
            self.report.push_incomplete(
                Some(node_range(node, self.line_starts)),
                vec![SemanticDiagnosticIncompleteReason::DynamicBehavior {
                    detail: "require() argument is not a literal module specifier".to_string(),
                }],
            );
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
            || is_known_js_ts_global(text)
            || is_unsafe_reference_context(node, self.source)
        {
            // Not a checked lookup: the name is a language global, or it sits
            // where JS/TS gives an identifier a meaning the lexical surface
            // does not decide (a member name off an unknown receiver, a
            // property key, a label). These stay suppressed without an
            // outcome because no lookup was attempted, not because one failed.
            return;
        }
        let range = node_range(node, self.line_starts);
        if scopes.contains(text) {
            // The file's own lexical surface binds the name. An imported name
            // is bound here too: the binding is workspace-local even when what
            // it routes to is not, and the import's own boundary outcome
            // already stands for the module.
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain: SemanticDiagnosticDomain::LexicalScope {
                    file: self.file_rel_path.to_path_buf(),
                    range,
                },
                boundary: BoundaryStatus::WorkspaceLocal,
            },
            SemanticDiagnostic {
                range,
                source: self.diagnostic_source,
                kind: JS_TS_UNRECOGNIZED_SYMBOL,
                message: format!("Unrecognized JS/TS symbol `{text}`"),
            },
        );
        self.errors += 1;
    }
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(ScanFrame::Node(child));
        }
    }
}

/// A `require(...)` call whose argument is not a literal module specifier. The
/// module it loads is chosen at run time, so no retained surface answers for it.
fn is_dynamic_require_call(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    function.kind() == "identifier"
        && slice(function, source) == "require"
        && require_call_module_specifier(node, source).is_none()
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
        // A member name is looked up on a receiver whose type the lexical
        // surface does not carry, and JS lets any object gain a property at
        // run time. Neither is a lexical-scope question, so neither is one
        // this walk can answer.
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
