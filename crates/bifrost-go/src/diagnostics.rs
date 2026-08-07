//! Go's semantic diagnostics: every name a Go file spells, classified as
//! resolved, absent with a complete proof, or suppressed with a typed reason.
//!
//! The analyzer facts this needs are a [`BoundedDefinitionLookup`] for "is this
//! fqn indexed in the workspace", the file's resolved [`GoImportBindings`], and
//! a [`GoExternalEvidence`] view of the activated exact API packs and the
//! retained module graph. `analyzer/go/diagnostics.rs` in
//! `brokk-bifrost-analysis` keeps the downcast that produces them, because this
//! crate cannot name `SemanticModelOverlay`.
//!
//! No path here may run the Go toolchain, walk a module cache, or start
//! dependency discovery. State a request cannot read is a typed
//! [`SemanticDiagnosticIncompleteReason`], never a guess and never an error.

use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{
    ScopeStack, contains_node, node_range, node_text, same_node,
};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, ProjectFile, Range};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

use crate::graph::resolver::GoImportBindings;
use crate::packages::{GO_MODULE_SCOPE_SEGMENT, canonical_go_package_name};

pub const GO_UNRECOGNIZED_SYMBOL: &str = "go_unrecognized_symbol";
pub const GO_UNRECOGNIZED_PACKAGE_MEMBER: &str = "go_unrecognized_package_member";
pub const GO_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-go";
const MAX_GO_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
pub const MAX_GO_SEMANTIC_DIAGNOSTICS: usize = 200;

/// What the activated exact API packs prove about one Go package's exported
/// surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoPackageSurface {
    /// No activated pack publishes this import path at all.
    Unpublished,
    /// A pack publishes it and records its exported surface as complete, so a
    /// member miss against it is proof of absence.
    Complete,
    /// A pack publishes it but recorded its surface as explicitly partial: the
    /// producer could not model generated sources, cgo files, or files a build
    /// constraint excluded. A member miss against it proves nothing.
    Partial,
}

/// The external Go evidence one diagnostic request may read.
///
/// Every method answers from state the analyzer already retains. None of them
/// may run `go`, read a module cache, or trigger dependency discovery: a
/// request that cannot see the answer reports incompleteness instead.
pub trait GoExternalEvidence {
    /// How completely the activated packs describe `import_path`.
    fn package_surface(&self, import_path: &str) -> GoPackageSurface;

    /// Whether the packs publish `member` as a visible, public declaration of
    /// `import_path`.
    fn publishes_member(&self, import_path: &str, member: &str) -> bool;

    /// How far a lookup for an import path no pack published could see: the
    /// retained module graph declares it ([`BoundaryStatus::ExternalDeclaredUnindexed`])
    /// or nothing is known ([`BoundaryStatus::ExternalUnknown`]).
    fn unindexed_boundary(&self, import_path: &str) -> BoundaryStatus;
}

pub fn collect_go_semantic_diagnostics(
    bindings: &GoImportBindings,
    support: &dyn BoundedDefinitionLookup,
    external: &dyn GoExternalEvidence,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_GO_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(tree) = parse_go_tree(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Go parser is unavailable".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // A malformed file is a parse problem, reported through the LSP parse
        // path. Its name lookups are meaningless, so this request checked
        // nothing and claims nothing.
        return report;
    }

    let line_starts = compute_line_starts(source);
    let package_name = declared_package_name(tree.root_node(), source)
        .map(|declared| canonical_go_package_name(file, &declared))
        .unwrap_or_default();
    let mut collector = GoDiagnosticCollector {
        support,
        external,
        source,
        rel_path: file.rel_path().to_path_buf(),
        line_starts: &line_starts,
        package_name,
        imports: bindings,
        report,
        diagnostic_count: 0,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

fn parse_go_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    parser.parse(source, None)
}

struct GoDiagnosticCollector<'a> {
    support: &'a dyn BoundedDefinitionLookup,
    external: &'a dyn GoExternalEvidence,
    source: &'a str,
    rel_path: std::path::PathBuf,
    line_starts: &'a [usize],
    package_name: String,
    imports: &'a GoImportBindings,
    report: SemanticDiagnosticReport,
    diagnostic_count: usize,
}

/// What the external evidence says about one reference, decided before the
/// report is touched so the decision reads only immutable state.
enum ExternalOutcome {
    /// A pack publishes this name.
    Published,
    /// Every checked package surface is complete and none publishes it.
    ProvenAbsent { owner: String },
    /// At least one checked surface cannot support a claim.
    Suppressed(Vec<SemanticDiagnosticIncompleteReason>),
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
            if self.diagnostic_count >= MAX_GO_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
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
            self.push_resolved(node, BoundaryStatus::WorkspaceLocal);
            return;
        }
        // A dot-imported external package can supply this bare name, and only
        // the activated packs can say so.
        match self.external_dot_outcome(name) {
            ExternalOutcome::Published => {
                self.push_resolved(node, BoundaryStatus::ExternalIndexed);
            }
            ExternalOutcome::Suppressed(reasons) => self.push_incomplete(node, reasons),
            ExternalOutcome::ProvenAbsent { .. } => {
                let range = node_range(node, self.line_starts);
                self.push_absent(
                    range,
                    SemanticDiagnosticDomain::LexicalScope {
                        file: self.rel_path.clone(),
                        range,
                    },
                    BoundaryStatus::WorkspaceLocal,
                    GO_UNRECOGNIZED_SYMBOL,
                    format!("unrecognized Go symbol `{name}`"),
                );
            }
        }
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
            // The qualifier is a value, not a package. This request checked no
            // package surface, so it claims nothing: member resolution through
            // an embedded struct's promoted fields and methods is
            // `get_definition`'s structured job, not a name-absence proof.
            return;
        }
        if let Some(packages) = self.imports.workspace.get(&qualifier) {
            if packages
                .iter()
                .any(|package| self.package_has_member(package, &field))
            {
                self.push_resolved(field_node, BoundaryStatus::WorkspaceLocal);
                return;
            }
            let Some(package) = packages.first().filter(|_| packages.len() == 1) else {
                // The same local name binds several workspace packages, so no
                // single package surface answers this member.
                self.push_ambiguous(field_node, packages.len());
                return;
            };
            let range = node_range(field_node, self.line_starts);
            let owner = package.clone();
            self.push_absent(
                range,
                SemanticDiagnosticDomain::MemberSurface {
                    owner: owner.clone(),
                    member: field.clone(),
                },
                BoundaryStatus::WorkspaceLocal,
                GO_UNRECOGNIZED_PACKAGE_MEMBER,
                format!("Go package `{owner}` has no indexed member `{field}`"),
            );
            return;
        }
        let Some(paths) = self.imports.external.get(&qualifier) else {
            return;
        };
        let Some(import_path) = paths.first().filter(|_| paths.len() == 1) else {
            // One local name for several external import paths cannot identify
            // a package, and an arbitrary winner would be a false claim.
            self.push_ambiguous(field_node, paths.len());
            return;
        };
        match self.external_member_outcome(import_path, &field) {
            ExternalOutcome::Published => {
                self.push_resolved(field_node, BoundaryStatus::ExternalIndexed);
            }
            ExternalOutcome::Suppressed(reasons) => self.push_incomplete(field_node, reasons),
            ExternalOutcome::ProvenAbsent { owner } => {
                let range = node_range(field_node, self.line_starts);
                self.push_absent(
                    range,
                    SemanticDiagnosticDomain::MemberSurface {
                        owner: owner.clone(),
                        member: field.clone(),
                    },
                    BoundaryStatus::ExternalIndexed,
                    GO_UNRECOGNIZED_PACKAGE_MEMBER,
                    format!("Go package `{owner}` has no exported member `{field}`"),
                );
            }
        }
    }

    /// Classify `member` of one external `import_path` against the activated
    /// packs and the retained module graph. Reads immutable state only.
    fn external_member_outcome(&self, import_path: &str, member: &str) -> ExternalOutcome {
        if self.external.publishes_member(import_path, member) {
            return ExternalOutcome::Published;
        }
        match self.external.package_surface(import_path) {
            GoPackageSurface::Complete => ExternalOutcome::ProvenAbsent {
                owner: import_path.to_string(),
            },
            GoPackageSurface::Partial => {
                ExternalOutcome::Suppressed(vec![partial_surface_reason(import_path)])
            }
            GoPackageSurface::Unpublished => ExternalOutcome::Suppressed(vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: self.external.unindexed_boundary(import_path),
                },
            ]),
        }
    }

    /// Classify a bare `name` against every dot-imported external package.
    /// With no external dot import the workspace lexical surface stands on its
    /// own, which is the `ProvenAbsent` answer for an empty check.
    fn external_dot_outcome(&self, name: &str) -> ExternalOutcome {
        let mut reasons = Vec::new();
        for import_path in &self.imports.dot_external {
            if self.external.publishes_member(import_path, name) {
                return ExternalOutcome::Published;
            }
            match self.external.package_surface(import_path) {
                GoPackageSurface::Complete => {}
                GoPackageSurface::Partial => reasons.push(partial_surface_reason(import_path)),
                GoPackageSurface::Unpublished => reasons.push(
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                        boundary: self.external.unindexed_boundary(import_path),
                    },
                ),
            }
        }
        if reasons.is_empty() {
            return ExternalOutcome::ProvenAbsent {
                owner: self.package_name.clone(),
            };
        }
        ExternalOutcome::Suppressed(reasons)
    }

    fn push_resolved(&mut self, node: Node<'_>, boundary: BoundaryStatus) {
        let range = node_range(node, self.line_starts);
        self.report.push_resolved(range, boundary);
    }

    fn push_ambiguous(&mut self, node: Node<'_>, count: usize) {
        let range = node_range(node, self.line_starts);
        self.report
            .push_ambiguous(range, vec![BoundaryStatus::WorkspaceLocal; count]);
    }

    fn push_incomplete(
        &mut self,
        node: Node<'_>,
        reasons: Vec<SemanticDiagnosticIncompleteReason>,
    ) {
        let range = node_range(node, self.line_starts);
        self.report.push_incomplete(Some(range), reasons);
    }

    fn push_absent(
        &mut self,
        range: Range,
        domain: SemanticDiagnosticDomain,
        boundary: BoundaryStatus,
        kind: &'static str,
        message: String,
    ) {
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain,
                boundary,
            },
            SemanticDiagnostic {
                range,
                source: GO_SEMANTIC_DIAGNOSTIC_SOURCE,
                kind,
                message,
            },
        );
        self.diagnostic_count += 1;
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
            || self.imports.workspace.contains_key(name)
            || self.imports.external.contains_key(name)
            || self
                .imports
                .dot_workspace
                .iter()
                .any(|package| self.package_has_member(package, name))
            || self.package_has_member(&self.package_name, name)
    }

    fn package_has_member(&self, package: &str, name: &str) -> bool {
        !self.support.fqn(&format!("{package}.{name}")).is_empty()
            || !self
                .support
                .fqn(&format!("{package}.{}.{name}", GO_MODULE_SCOPE_SEGMENT))
                .is_empty()
    }
}

/// A pack that recorded its own surface as partial cannot support an absence
/// claim about it. The Go producer marks a package partial when it could not
/// model a generated source, a cgo file, or a file a build constraint
/// excluded, so the honest report names that surface rather than the member.
fn partial_surface_reason(import_path: &str) -> SemanticDiagnosticIncompleteReason {
    SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
        detail: format!(
            "the exact API pack for Go package `{import_path}` records an explicitly partial exported surface (generated, cgo, or build-constrained sources)"
        ),
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
