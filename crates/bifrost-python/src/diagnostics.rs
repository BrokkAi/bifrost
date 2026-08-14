//! Python's semantic diagnostics: proof-gated unresolved-name reporting.
//!
//! Every candidate this pass reaches leaves one typed outcome in the
//! [`SemanticDiagnosticReport`]: a resolution, a complete absence proof, or a
//! typed reason why absence could not be proven. A candidate is never dropped
//! in silence, and an error is only ever published behind a
//! [`SemanticAbsenceProof`] over a surface that was complete.
//!
//! The analyzer facts this needs are the [`PythonSource`] the import resolver
//! already takes, a [`BoundedDefinitionLookup`] for "is this fqn indexed", and
//! a [`PythonEnvironmentSurface`] for "what do the activated environment packs
//! prove about this imported module". `analyzer/python/diagnostics.rs` in
//! `brokk-bifrost-analysis` keeps the downcast that produces all three: this
//! crate cannot name the semantic-model overlay those answers come from.
//!
//! What this pass judges:
//!
//! - every bare-name reference, against the file's lexical surface and the
//!   workspace index, which are both complete and workspace-local;
//! - every import declaration, against the retained environment surface;
//! - an attribute read through a module binder (`os.path.join`), which is the
//!   one receiver whose owner Python's syntax proves without type inference.
//!
//! An attribute on any other receiver is not a candidate here: proving that
//! `value.method` is absent needs a proven receiver type, which this pass does
//! not have.

use crate::graph_support::PythonSource;
use crate::imports::resolve_imports_batched;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport, StructuredImportPathKind,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{
    ScopeStack, contains_node, node_range, node_text, same_node,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::{
    WalkControl, collect_parse_errors, walk_tree_preorder,
};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use tree_sitter::{Node, Parser};

pub const PYTHON_UNRECOGNIZED_SYMBOL: &str = "python_unrecognized_symbol";
pub const PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-python";
const MAX_PYTHON_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
pub const MAX_PYTHON_SEMANTIC_DIAGNOSTICS: usize = 200;

/// What the analyzer's retained environment evidence proves about one name a
/// Python file reaches across an import boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonEnvironmentBoundary {
    /// An activated pack surface contains the name.
    Indexed,
    /// A complete activated module surface does not contain the name. The
    /// absence is therefore proven at [`BoundaryStatus::ExternalIndexed`].
    Absent,
    /// Retained state cannot decide, for this typed reason.
    Incomplete(SemanticDiagnosticIncompleteReason),
}

/// The retained Python environment surface a diagnostic request may read.
///
/// Every method answers only from state the analyzer already holds. An
/// implementation must never start dependency discovery, read a distribution,
/// or execute Python: a missing answer is
/// [`PythonEnvironmentBoundary::Incomplete`], never a blocking call.
pub trait PythonEnvironmentSurface {
    /// Classify the module a namespace import names (`import a.b`).
    fn module_boundary(&self, module_path: &str) -> PythonEnvironmentBoundary;

    /// Classify `member` on the environment declaration `owner_path` names.
    /// This is one question asked from two places: `from a.b import member`,
    /// and an attribute read through a module binder (`a.b.member`).
    ///
    /// The owner is a module for an import, and either a module or a type for
    /// an attribute read: `theta.Klass.method` reaches here with the owner
    /// `theta.Klass`. An implementation that answers
    /// [`PythonEnvironmentBoundary::Absent`] for a type owner is claiming to
    /// have seen that type's whole inherited surface.
    fn attribute_boundary(&self, owner_path: &str, member: &str) -> PythonEnvironmentBoundary;
}

/// An environment that has acquired nothing. Every boundary is unknown, which
/// is the honest answer for an analyzer no host has activated packs on.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnacquiredPythonEnvironment;

impl PythonEnvironmentSurface for UnacquiredPythonEnvironment {
    fn module_boundary(&self, _module_path: &str) -> PythonEnvironmentBoundary {
        unknown_boundary()
    }

    fn attribute_boundary(&self, _owner_path: &str, _member: &str) -> PythonEnvironmentBoundary {
        unknown_boundary()
    }
}

fn unknown_boundary() -> PythonEnvironmentBoundary {
    PythonEnvironmentBoundary::Incomplete(
        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
            boundary: BoundaryStatus::ExternalUnknown,
        },
    )
}

/// Collect Python semantic diagnostics and the proof behind each one.
pub fn collect_python_semantic_diagnostics(
    py: &dyn PythonSource,
    support: &dyn BoundedDefinitionLookup,
    environment: &dyn PythonEnvironmentSurface,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_PYTHON_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Python parser is unavailable".to_string(),
            }],
        );
        return report;
    }
    let Some(tree) = parser.parse(source, None) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Python source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // The parse errors themselves reach the host through the analyzer's
        // parse-diagnostic path. What the semantic report records is that the
        // tree this pass would have judged is not trustworthy, so no name in
        // the file was checked at all.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Python source has parse errors".to_string(),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let imports = py.import_info_of(file);
    let resolved_imports = resolve_imports_batched(py, file, &imports);
    let dynamic = dynamic_surface_reasons(&imports, &resolved_imports, source, tree.root_node());
    if !dynamic.is_empty() {
        // A dynamic namespace makes every name in the file unjudgeable: the
        // set of bindings is decided at run time. The file is reported once,
        // with each reason that made it so.
        report.push_incomplete(None, dynamic);
        return report;
    }

    let mut collector = PythonDiagnosticCollector {
        py,
        support,
        environment,
        file,
        source,
        line_starts: &line_starts,
        module_name: crate::declarations::python_module_name(file),
        module_binders: HashMap::default(),
        report,
    };
    collector.classify_imports(&imports, &resolved_imports);
    collector.scan_tree(tree.root_node(), &imports, &resolved_imports);
    collector.report
}

struct PythonDiagnosticCollector<'a> {
    py: &'a dyn PythonSource,
    support: &'a dyn BoundedDefinitionLookup,
    environment: &'a dyn PythonEnvironmentSurface,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    module_name: String,
    /// Local name -> the module path it is bound to by a namespace import.
    /// This is the one receiver whose owner Python's syntax fixes without type
    /// inference, so it is the only owner this pass judges attributes against.
    module_binders: HashMap<String, String>,
    report: SemanticDiagnosticReport,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    SeedTargets(Node<'tree>),
}

impl PythonDiagnosticCollector<'_> {
    /// Ask the environment about every import the file declares, once per
    /// declaration. Later references to an imported name resolve in the file's
    /// own lexical scope; the boundary question belongs to the import that
    /// created the binding, which is also where a host can act on the answer.
    fn classify_imports(&mut self, imports: &[ImportInfo], resolved: &[Vec<(String, CodeUnit)>]) {
        debug_assert_eq!(imports.len(), resolved.len());
        for (import, resolved) in imports.iter().zip(resolved) {
            let range = import
                .binder_span
                .map(|span| span_range(span, self.line_starts));
            let Some(path) = import.path.as_ref() else {
                self.report.push_incomplete(
                    range,
                    vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "import `{}` records no parser-derived path",
                            import.raw_snippet
                        ),
                    }],
                );
                continue;
            };
            let namespace_import = path.kind != Some(StructuredImportPathKind::ImportFrom);
            if namespace_import && let Some(name) = import.local_name() {
                // `import a.b` binds `a` and `import a.b as ab` binds `a.b`:
                // the split `python_namespace_binding_module` makes for import
                // resolution, over the same parser-derived segments.
                let bound = if import.alias.is_some() {
                    path.render_segments(".")
                } else {
                    path.segments.first().cloned().unwrap_or_default()
                };
                if !bound.is_empty() {
                    self.module_binders.insert(name.to_string(), bound);
                }
            }
            if !resolved.is_empty() {
                // The import resolved inside the workspace, whose file set is
                // complete. A wildcard resolves to every public declaration of
                // the target module, so the seeded scope stays complete too.
                if let Some(range) = range {
                    self.report
                        .push_resolved(range, BoundaryStatus::WorkspaceLocal);
                }
                continue;
            }
            let (owner, boundary) = if namespace_import {
                let module = path.render_segments(".");
                let boundary = self.environment.module_boundary(&module);
                (SemanticDiagnosticDomain::Module { name: module }, boundary)
            } else if let Some((member, module)) = path.segments.split_last() {
                // A `from a.b import c` path records the module segments and
                // the imported name in one list.
                let module = module.join(".");
                let boundary = self.environment.attribute_boundary(&module, member);
                (SemanticDiagnosticDomain::Module { name: module }, boundary)
            } else {
                self.report.push_incomplete(
                    range,
                    vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!("import `{}` records no path segments", import.raw_snippet),
                    }],
                );
                continue;
            };
            let Some(range) = range else {
                // Nothing points at one name: a wildcard, or a form whose
                // bound name is spelled only inside a compound token.
                self.report.push_incomplete(
                    None,
                    vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "import `{}` binds no single name token",
                            import.raw_snippet
                        ),
                    }],
                );
                continue;
            };
            self.record_boundary(range, owner, import.raw_snippet.as_str(), boundary);
        }
    }

    /// Place one environment verdict in the report at `range`.
    fn record_boundary(
        &mut self,
        range: Range,
        domain: SemanticDiagnosticDomain,
        subject: &str,
        boundary: PythonEnvironmentBoundary,
    ) {
        match boundary {
            PythonEnvironmentBoundary::Indexed => self
                .report
                .push_resolved(range, BoundaryStatus::ExternalIndexed),
            PythonEnvironmentBoundary::Absent => {
                let message = match &domain {
                    // The owner is a module for an import and either a module
                    // or an indexed type for an attribute read, so the message
                    // names it without claiming which.
                    SemanticDiagnosticDomain::MemberSurface { owner, member } => {
                        format!("Unrecognized Python attribute `{member}` on `{owner}`")
                    }
                    _ => format!("Unrecognized Python import `{subject}`"),
                };
                self.report.push_absent(
                    SemanticAbsenceProof {
                        range,
                        domain,
                        boundary: BoundaryStatus::ExternalIndexed,
                    },
                    SemanticDiagnostic {
                        range,
                        source: PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE,
                        kind: PYTHON_UNRECOGNIZED_SYMBOL,
                        message,
                    },
                );
            }
            PythonEnvironmentBoundary::Incomplete(reason) => {
                self.report.push_incomplete(Some(range), vec![reason])
            }
        }
    }

    fn scan_tree(
        &mut self,
        root: Node<'_>,
        imports: &[ImportInfo],
        resolved: &[Vec<(String, CodeUnit)>],
    ) {
        let mut scopes = ScopeStack::default();
        scopes.enter();
        self.seed_module_scope(&mut scopes, imports, resolved);
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.report.diagnostics().len() >= MAX_PYTHON_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                return;
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
            "match_statement" => {
                // A capture pattern binds names this pass does not model, so
                // no name inside the statement can be judged. Say so once,
                // with the statement's own range, instead of scanning it.
                self.report.push_incomplete(
                    Some(node_range(node, self.line_starts)),
                    vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: "match statement pattern bindings are not modeled".to_string(),
                    }],
                );
            }
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
                self.check_attribute(node);
                if let Some(object) = node.child_by_field_name("object") {
                    stack.push(ScanFrame::Node(object));
                }
            }
            "string" | "string_content" | "comment" => {}
            _ => push_named_children(stack, node),
        }
    }

    fn seed_module_scope(
        &self,
        scopes: &mut ScopeStack,
        imports: &[ImportInfo],
        resolved: &[Vec<(String, CodeUnit)>],
    ) {
        for import in imports {
            if let Some(local_name) = import.alias.as_ref().or(import.identifier.as_ref()) {
                scopes.declare(local_name.clone());
            }
        }
        for binding in resolved.iter().flatten() {
            scopes.declare(binding.0.clone());
        }
        for unit in self.py.declarations(self.file) {
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
        // `_` is the conventional throwaway target; a read of it names no
        // declaration this pass can check either way.
        if name.is_empty() || name == "_" {
            return;
        }
        let range = node_range(node, self.line_starts);
        if is_python_builtin_or_constant(name) {
            // The builtin surface is a complete table compiled into this
            // analyzer, so it is an indexed external surface.
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if scopes.contains(name) || self.name_resolves_project_locally(name) {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        // The file's lexical surface and the workspace index are both complete
        // and workspace-local, and every import in the file seeded a binding
        // into that surface, so this name is absent from it.
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain: SemanticDiagnosticDomain::LexicalScope {
                    file: self.file.rel_path().to_path_buf(),
                    range,
                },
                boundary: BoundaryStatus::WorkspaceLocal,
            },
            SemanticDiagnostic {
                range,
                source: PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE,
                kind: PYTHON_UNRECOGNIZED_SYMBOL,
                message: format!("Unrecognized Python symbol `{name}`"),
            },
        );
    }

    /// Judge an attribute whose receiver chain starts at a module binder.
    fn check_attribute(&mut self, node: Node<'_>) {
        let Some((owner, member)) = self.module_attribute_target(node) else {
            return;
        };
        let Some(attribute) = node.child_by_field_name("attribute") else {
            return;
        };
        let range = node_range(attribute, self.line_starts);
        let boundary = self.environment.attribute_boundary(&owner, &member);
        self.record_boundary(
            range,
            SemanticDiagnosticDomain::MemberSurface {
                owner,
                member: member.clone(),
            },
            &member,
            boundary,
        );
    }

    /// The owning module path and member name of an attribute read whose
    /// receiver is a chain of plain names rooted at a module binder, e.g.
    /// `os.path.join` -> (`os.path`, `join`). `None` when the receiver is
    /// anything else, because then this pass cannot prove what owns the
    /// member.
    ///
    /// A local rebinding of an imported module name would defeat this, which
    /// no working program does: rebinding `os` to a non-module makes every
    /// later `os.*` read fail at run time.
    fn module_attribute_target(&self, node: Node<'_>) -> Option<(String, String)> {
        let member = node_text(node.child_by_field_name("attribute")?, self.source);
        if member.is_empty() {
            return None;
        }
        let mut intermediate = Vec::new();
        let mut current = node.child_by_field_name("object")?;
        while current.kind() == "attribute" {
            intermediate.push(node_text(
                current.child_by_field_name("attribute")?,
                self.source,
            ));
            current = current.child_by_field_name("object")?;
        }
        if current.kind() != "identifier" {
            return None;
        }
        let mut owner = self
            .module_binders
            .get(node_text(current, self.source))?
            .clone();
        for segment in intermediate.iter().rev() {
            owner.push('.');
            owner.push_str(segment);
        }
        Some((owner, member.to_string()))
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

fn span_range(span: Span, line_starts: &[usize]) -> Range {
    Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: find_line_index_for_offset(line_starts, span.start_byte) + 1,
        end_line: find_line_index_for_offset(line_starts, span.end_byte.saturating_sub(1)) + 1,
    }
}

/// Every dynamic-namespace feature the file uses, each as the typed reason it
/// makes the file's binding set unknowable. An empty result means the file's
/// namespace is static and every name in it can be judged.
fn dynamic_surface_reasons(
    imports: &[ImportInfo],
    resolved: &[Vec<(String, CodeUnit)>],
    source: &str,
    root: Node<'_>,
) -> Vec<SemanticDiagnosticIncompleteReason> {
    debug_assert_eq!(imports.len(), resolved.len());
    let mut reasons = Vec::new();
    for (import, resolved) in imports.iter().zip(resolved) {
        if import.is_wildcard && resolved.is_empty() {
            reasons.push(SemanticDiagnosticIncompleteReason::DynamicBehavior {
                detail: format!(
                    "`{}` binds an unknown set of names",
                    import.raw_snippet.trim()
                ),
            });
        }
    }
    if has_module_getattr(source, root) {
        reasons.push(SemanticDiagnosticIncompleteReason::DynamicBehavior {
            detail: "the module defines `__getattr__`".to_string(),
        });
    }
    for call in dynamic_namespace_calls(source, root) {
        reasons.push(SemanticDiagnosticIncompleteReason::DynamicBehavior {
            detail: format!("the module calls `{call}`"),
        });
    }
    reasons
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

/// The distinct namespace-mutating calls the file makes, in first-seen order.
fn dynamic_namespace_calls(source: &str, root: Node<'_>) -> Vec<String> {
    let mut calls: Vec<String> = Vec::new();
    walk_tree_preorder(root, true, |node| {
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && let Some(name) = dynamic_function_name(function, source)
            && !calls.iter().any(|seen| seen == name)
        {
            calls.push(name.to_string());
        }
        WalkControl::Continue
    });
    calls
}

fn dynamic_function_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(node, source);
    match node.kind() {
        "identifier" => matches!(text, "globals" | "locals" | "__import__").then_some(text),
        "attribute" => (text == "importlib.import_module").then_some(text),
        _ => None,
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
