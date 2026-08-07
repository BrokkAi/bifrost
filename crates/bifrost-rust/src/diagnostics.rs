//! Rust's unrecognized-symbol semantic diagnostics.
//!
//! The scan resolves names through the same per-file
//! [`crate::graph_support::RustReferenceContext`] the usage graph uses, and
//! confirms survivors against a core
//! [`brokk_bifrost_core::analyzer::BoundedDefinitionLookup`]. Neither needs an
//! analyzer handle, so all of it lives here; `analyzer/rust/diagnostics.rs` in
//! `brokk-bifrost-analysis` keeps only the downcast that produces those
//! arguments, and the tests that need a live analyzer to produce them.
//!
//! Every lookup produces an outcome (#1625). A reference that resolves is
//! recorded as resolved against the surface that explained it, a reference no
//! complete surface explains becomes an error carrying its
//! [`brokk_bifrost_core::analyzer::model::SemanticAbsenceProof`], and a
//! reference the scan declined to judge states the typed reason why. The
//! previous pass returned only the errors, so a suppression and a clean
//! resolution were indistinguishable, and every error it did return claimed a
//! complete workspace-local lexical proof that it had not actually made.
//!
//! Nothing here runs `cargo` or `rustdoc`, reads `target/doc`, or triggers pack
//! production. External facts arrive through [`RustExternalEvidence`], whose
//! implementations read retained analyzer state only.

use crate::graph_support::RustUsageSource;
use crate::proof::{RustNameProof, RustProofGap, record_rust_name_proof};
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{
    contains_node, node_range, node_text, same_node,
};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::Node;

/// The upper bound on source a diagnostics scan will look at, and on the number
/// of diagnostics one file may report.
pub const MAX_RUST_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
pub const MAX_RUST_SEMANTIC_DIAGNOSTICS: usize = 200;

pub const RUST_UNRECOGNIZED_SYMBOL: &str = "rust_unrecognized_symbol";
pub const RUST_UNRECOGNIZED_CRATE_ITEM: &str = "rust_unrecognized_crate_item";
pub const RUST_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-rust";

/// What the activated Cargo API packs prove about one dependency crate's
/// exported surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustCrateSurface {
    /// No activated pack publishes this crate at all.
    Unpublished,
    /// A pack publishes it and records a complete API surface, so a miss
    /// against it is proof of absence.
    Complete,
    /// A pack publishes it but cannot support an absence claim, for the reason
    /// `detail` names: an explicitly partial surface, a re-export or glob the
    /// producer could not follow, or a pack whose feature set is not the one
    /// the workspace resolves.
    Uncertain { detail: String },
}

/// The external Rust evidence one diagnostic request may read.
///
/// Every method answers from state the analyzer already retains. None of them
/// may run `cargo` or `rustdoc`, read `target/doc`, or trigger pack production:
/// a request that cannot see the answer reports incompleteness instead.
///
/// `crate_name` is always spelled as the *source* spells it. A dependency that
/// Cargo renames is published under that spelling as a pack alias, so a renamed
/// crate needs no separate mapping here, and two same-named crates at different
/// versions collide into an overlay conflict that answers nothing rather than
/// picking a winner.
pub trait RustExternalEvidence {
    /// How completely the activated packs describe the crate `crate_name`
    /// names.
    fn crate_surface(&self, crate_name: &str) -> RustCrateSurface;

    /// Whether the packs publish the item that `segments` names. `segments`
    /// includes the leading crate name.
    fn publishes_path(&self, segments: &[String]) -> bool;

    /// Whether the packs publish `segments` as a *module* surface.
    ///
    /// A module is the only owner whose membership a pack enumerates
    /// completely. A type's associated items are not enumerable that way: a
    /// trait bound or a `Deref` chain puts methods on a type that its own
    /// `impl` blocks never mention, so a miss under a type owner proves
    /// nothing even when the crate surface is complete.
    fn is_module_surface(&self, segments: &[String]) -> bool;

    /// How far a lookup for a crate no pack published could see: the retained
    /// Cargo dependency evidence declares it
    /// ([`BoundaryStatus::ExternalDeclaredUnindexed`]) or nothing is known
    /// ([`BoundaryStatus::ExternalUnknown`]).
    fn unindexed_boundary(&self, crate_name: &str) -> BoundaryStatus;
}

/// Evidence that has acquired nothing. Every crate is unknown, which is the
/// honest answer for an analyzer no host has activated packs on.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnindexedRustDependencies;

impl RustExternalEvidence for UnindexedRustDependencies {
    fn crate_surface(&self, _crate_name: &str) -> RustCrateSurface {
        RustCrateSurface::Unpublished
    }

    fn publishes_path(&self, _segments: &[String]) -> bool {
        false
    }

    fn is_module_surface(&self, _segments: &[String]) -> bool {
        false
    }

    fn unindexed_boundary(&self, _crate_name: &str) -> BoundaryStatus {
        BoundaryStatus::ExternalUnknown
    }
}

/// Scan `source` for names no surface explains, recording what each lookup
/// proved.
///
/// `rust` supplies the per-file reference context and type-alias predicate;
/// `support` is the declaration lookup survivors are confirmed against;
/// `external` answers for crates outside the workspace. The caller produces all
/// three -- see the analysis-side entry point of the same name.
pub fn collect_rust_semantic_diagnostics(
    rust: &dyn RustUsageSource,
    support: &dyn BoundedDefinitionLookup,
    external: &dyn RustExternalEvidence,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_RUST_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(tree) = crate::lexical_scope::parse_rust_tree(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Rust source did not parse".to_string(),
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
                detail: "Rust source has parse errors".to_string(),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let root = tree.root_node();
    let visible_uses = collect_rust_use_bindings(root, source);
    let mut collector = RustDiagnosticCollector {
        rust,
        support,
        external,
        file,
        source,
        line_starts: &line_starts,
        root,
        visible_uses,
        report,
        diagnostic_count: 0,
    };
    collector.scan_tree(root);
    collector.report
}

struct RustDiagnosticCollector<'a, 'tree> {
    rust: &'a dyn RustUsageSource,
    support: &'a dyn BoundedDefinitionLookup,
    external: &'a dyn RustExternalEvidence,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    root: Node<'tree>,
    visible_uses: Vec<RustUseBinding>,
    report: SemanticDiagnosticReport,
    diagnostic_count: usize,
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitScope,
    SeedPattern(Node<'tree>),
}

impl RustDiagnosticCollector<'_, '_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = RustScopeStack::default();
        scopes.enter();
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostic_count >= MAX_RUST_SEMANTIC_DIAGNOSTICS {
                // The scan stopped early, so every name it never reached is
                // unjudged rather than absent.
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut scopes, &mut stack),
                ScanFrame::ExitScope => scopes.exit(),
                ScanFrame::SeedPattern(pattern) => {
                    seed_pattern_bindings(pattern, self.source, &mut scopes)
                }
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scopes: &mut RustScopeStack,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
        if let Some(gap) = subtree_suppression(node, self.source) {
            // The whole subtree goes unjudged, so one typed outcome stands for
            // it rather than one per name inside it.
            let range = node_range(node, self.line_starts);
            self.report
                .push_incomplete(Some(range), vec![gap.into_reason()]);
            return;
        }
        match node.kind() {
            "source_file" => push_named_children(stack, node),
            "block" => {
                scopes.enter();
                seed_block_item_bindings(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "function_item" | "function_signature_item" => {
                scopes.enter_isolated();
                seed_item_name(node, self.source, scopes);
                seed_function_like_bindings(node, self.source, scopes);
                seed_type_parameters(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "closure_expression" => {
                scopes.enter();
                seed_function_like_bindings(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "struct_item" | "enum_item" | "trait_item" | "type_item" | "impl_item" => {
                scopes.enter();
                seed_type_parameters(node, self.source, scopes);
                stack.push(ScanFrame::ExitScope);
                push_named_children(stack, node);
            }
            "let_declaration" => {
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(ScanFrame::SeedPattern(
                        node.child_by_field_name("pattern").unwrap_or(value),
                    ));
                    stack.push(ScanFrame::Node(value));
                } else if let Some(pattern) = node.child_by_field_name("pattern") {
                    seed_pattern_bindings(pattern, self.source, scopes);
                }
                if let Some(type_node) = node.child_by_field_name("type") {
                    stack.push(ScanFrame::Node(type_node));
                }
            }
            "for_expression" => {
                if let Some(body) = node.child_by_field_name("body") {
                    scopes.enter();
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        seed_pattern_bindings(pattern, self.source, scopes);
                    }
                    stack.push(ScanFrame::ExitScope);
                    stack.push(ScanFrame::Node(body));
                }
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(ScanFrame::Node(value));
                }
            }
            "match_arm" => {
                scopes.enter();
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    seed_pattern_bindings(pattern, self.source, scopes);
                }
                stack.push(ScanFrame::ExitScope);
                push_named_children_except(stack, node, &["pattern"]);
            }
            "parameter" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    stack.push(ScanFrame::Node(type_node));
                }
            }
            "self_parameter" | "use_declaration" | "attribute_item" => {}
            "type_identifier" => {
                self.check_type_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "scoped_type_identifier" => {
                self.check_scoped_type_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "identifier" => {
                self.check_value_identifier(node, scopes);
                push_named_children(stack, node);
            }
            "scoped_identifier" => {
                self.check_scoped_identifier(node, scopes);
                push_named_children(stack, node);
            }
            _ => push_named_children(stack, node),
        }
    }

    fn check_type_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_type_reference_identifier(node) {
            return;
        }
        let name = node_text(node, self.source).trim();
        self.record_bare_name(node, name, scopes, SymbolKind::Type);
    }

    fn check_value_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        if !is_value_reference_identifier(node) {
            return;
        }
        let name = node_text(node, self.source).trim();
        self.record_bare_name(node, name, scopes, SymbolKind::Value);
    }

    fn check_scoped_type_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        self.check_scoped_path(node, scopes, SymbolKind::Type);
    }

    fn check_scoped_identifier(&mut self, node: Node<'_>, scopes: &RustScopeStack) {
        self.check_scoped_path(node, scopes, SymbolKind::Value);
    }

    /// Judge one bare written name and record what the lookup proved.
    fn record_bare_name(
        &mut self,
        node: Node<'_>,
        name: &str,
        scopes: &RustScopeStack,
        kind: SymbolKind,
    ) {
        let Some(proof) = self.bare_name_proof(name, node, scopes, kind) else {
            return;
        };
        let rel_path = self.file.rel_path().to_path_buf();
        let owned = name.to_string();
        self.record(node, proof, RUST_UNRECOGNIZED_SYMBOL, move |range| {
            (
                SemanticDiagnosticDomain::LexicalScope {
                    file: rel_path,
                    range,
                },
                format!("Unrecognized Rust symbol `{owned}`"),
            )
        });
    }

    /// Judge one `a::b::Name` path and record what the lookup proved.
    fn check_scoped_path(&mut self, node: Node<'_>, scopes: &RustScopeStack, kind: SymbolKind) {
        if !is_scoped_reference(node) {
            return;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let Some(path_node) = node.child_by_field_name("path") else {
            self.record_bare_name(name_node, name, scopes, kind);
            return;
        };
        // Crate-local roots stay on the workspace surface the reference
        // context already resolves; everything else may leave the workspace.
        if is_crate_local_path(path_node, self.source) {
            let path = node_text(path_node, self.source).trim();
            let refs = self.rust.reference_context_of(self.file);
            let resolved = refs
                .resolve_scoped(path, name)
                .is_some_and(|resolved| self.fqn_has_matching_declaration(&resolved, kind));
            let proof = if resolved {
                RustNameProof::Workspace
            } else {
                RustNameProof::Absent {
                    boundary: BoundaryStatus::WorkspaceLocal,
                }
            };
            let owner = path.to_string();
            let owned = name.to_string();
            self.record(name_node, proof, RUST_UNRECOGNIZED_SYMBOL, move |_| {
                (
                    SemanticDiagnosticDomain::Module {
                        name: owner.clone(),
                    },
                    format!("Rust module `{owner}` has no item `{owned}`"),
                )
            });
            return;
        }
        // A workspace sibling may still answer the path before any dependency
        // pack is consulted.
        let path = node_text(path_node, self.source).trim();
        let refs = self.rust.reference_context_of(self.file);
        if refs
            .resolve_scoped(path, name)
            .is_some_and(|resolved| self.fqn_has_matching_declaration(&resolved, kind))
        {
            self.record_resolved(name_node, BoundaryStatus::WorkspaceLocal);
            return;
        }
        let segments = self.dependency_path_segments(node, node.start_byte());
        let proof = self.external_path_proof(&segments);
        let owner = segments
            .split_last()
            .map(|(_, owner)| owner.join("::"))
            .unwrap_or_default();
        let owned = name.to_string();
        self.record(name_node, proof, RUST_UNRECOGNIZED_CRATE_ITEM, move |_| {
            (
                SemanticDiagnosticDomain::Module {
                    name: owner.clone(),
                },
                format!("Rust crate path `{owner}` has no exported item `{owned}`"),
            )
        });
    }

    /// What every retained surface proves about one bare written name.
    ///
    /// `None` means the name is not a judgeable reference at all (a placeholder
    /// or an empty token), so no outcome is recorded for it.
    fn bare_name_proof(
        &self,
        name: &str,
        node: Node<'_>,
        scopes: &RustScopeStack,
        kind: SymbolKind,
    ) -> Option<RustNameProof> {
        if name.is_empty() || name == "_" {
            return None;
        }
        if scopes.contains(name, kind) {
            return Some(RustNameProof::Workspace);
        }
        if is_rust_builtin_name(name) {
            // The prelude and the primitive types are compiled into the
            // language itself, so the table that answers them is complete.
            return Some(RustNameProof::ExternalIndexed);
        }
        let binder = self.visible_import_binder_at(node.start_byte());
        if binder
            .bindings
            .values()
            .any(|binding| binding.kind == ImportKind::Glob)
        {
            // `use foo::*` puts an unknown set of names in scope. Which names
            // it supplies is exactly what this surface cannot enumerate.
            return Some(RustNameProof::Incomplete(RustProofGap::Unsupported {
                detail: format!(
                    "a glob import in scope could supply `{name}`, and its bound names are not enumerated"
                ),
            }));
        }
        if binder.bindings.contains_key(name) {
            // A `use` binds the name. Whether its target exists is a question
            // about the crate the import enters, so ask the same ladder a
            // written path would take.
            if let Some(segments) = self.imported_path_segments(node.start_byte(), name)
                && !is_crate_local_root(&segments)
            {
                return Some(self.external_path_proof(&segments));
            }
            return Some(RustNameProof::Workspace);
        }
        let refs = self.rust.reference_context_of(self.file);
        if let Some(resolved) = refs.resolve_bare(name)
            && self.fqn_has_matching_declaration(resolved, kind)
        {
            return Some(RustNameProof::Workspace);
        }
        if self
            .support
            .file_identifier(self.file, name)
            .into_iter()
            .any(|unit| self.symbol_kind_matches(&unit, kind))
        {
            return Some(RustNameProof::Workspace);
        }
        Some(RustNameProof::Absent {
            boundary: BoundaryStatus::WorkspaceLocal,
        })
    }

    /// The classification ladder for a path that leaves the workspace.
    ///
    /// `segments` starts with the crate name as the source spells it, which is
    /// also the spelling a Cargo rename publishes as a pack alias.
    fn external_path_proof(&self, segments: &[String]) -> RustNameProof {
        let Some(crate_name) = segments.first() else {
            return RustNameProof::Incomplete(RustProofGap::ExternalBoundary {
                boundary: BoundaryStatus::ExternalUnknown,
            });
        };
        if self.external.publishes_path(segments) {
            return RustNameProof::ExternalIndexed;
        }
        match self.external.crate_surface(crate_name) {
            // The pack states a complete API surface for this exact crate and
            // does not publish the item. That is proof only when the owner is
            // a surface whose membership the pack actually enumerates.
            RustCrateSurface::Complete => {
                let (_, owner) = segments
                    .split_last()
                    .expect("a non-empty path has a trailing name");
                // The crate root is itself a module, so a bare `krate::Item`
                // has an enumerable owner with no owner segments to check.
                if owner.len() <= 1 || self.external.is_module_surface(owner) {
                    return RustNameProof::Absent {
                        boundary: BoundaryStatus::ExternalIndexed,
                    };
                }
                RustNameProof::Incomplete(RustProofGap::Unsupported {
                    detail: format!(
                        "`{}` is an indexed Rust type rather than a module, and a trait bound or `Deref` chain can supply an associated item its own impls do not declare",
                        owner.join("::")
                    ),
                })
            }
            RustCrateSurface::Uncertain { detail } => {
                RustNameProof::Incomplete(RustProofGap::Unsupported { detail })
            }
            RustCrateSurface::Unpublished => {
                RustNameProof::Incomplete(RustProofGap::ExternalBoundary {
                    boundary: self.external.unindexed_boundary(crate_name),
                })
            }
        }
    }

    fn fqn_has_matching_declaration(&self, fqn: &str, kind: SymbolKind) -> bool {
        self.support
            .fqn(fqn)
            .into_iter()
            .any(|unit| self.symbol_kind_matches(&unit, kind))
    }

    fn symbol_kind_matches(&self, unit: &CodeUnit, kind: SymbolKind) -> bool {
        match kind {
            SymbolKind::Type => unit.is_class() || self.rust.is_type_alias(unit),
            SymbolKind::Value => unit.is_function() || unit.is_field() || unit.is_module(),
        }
    }

    fn visible_import_binder_at(&self, reference_byte: usize) -> ImportBinder {
        let reference_mod =
            crate::lexical_scope::enclosing_mod_item_range_at(self.root, reference_byte);
        let mut binder = ImportBinder::empty();
        for visible_use in &self.visible_uses {
            if visible_use.mod_range != reference_mod {
                continue;
            }
            if visible_use
                .scope_range
                .is_some_and(|(start, end)| !(start <= reference_byte && reference_byte < end))
            {
                continue;
            }
            for import in &visible_use.imports {
                crate::lexical_scope::insert_rust_import_binding(&mut binder, import);
            }
        }
        binder
    }

    /// The dotted-lookup segments for a written path, with its leading name
    /// rebased onto whatever a visible `use` binds it to, so `use serde_json as
    /// json; json::Value` asks the pack about `serde_json::Value`.
    fn dependency_path_segments(&self, node: Node<'_>, reference_byte: usize) -> Vec<String> {
        let written = path_segments(node, self.source);
        let Some((root, rest)) = written.split_first() else {
            return Vec::new();
        };
        let mut segments = self
            .imported_path_segments(reference_byte, root)
            .unwrap_or_else(|| vec![root.clone()]);
        segments.extend_from_slice(rest);
        segments
    }

    /// The structured path segments of the visible `use` that binds `name`.
    ///
    /// Read from the parser's recorded import path, never by splitting the
    /// import's source text.
    fn imported_path_segments(&self, reference_byte: usize, name: &str) -> Option<Vec<String>> {
        let reference_mod =
            crate::lexical_scope::enclosing_mod_item_range_at(self.root, reference_byte);
        for visible_use in &self.visible_uses {
            if visible_use.mod_range != reference_mod {
                continue;
            }
            if visible_use
                .scope_range
                .is_some_and(|(start, end)| !(start <= reference_byte && reference_byte < end))
            {
                continue;
            }
            for import in &visible_use.imports {
                if import.local_name() != Some(name) {
                    continue;
                }
                if let Some(path) = import.path.as_ref()
                    && !path.segments.is_empty()
                {
                    return Some(path.segments.clone());
                }
            }
        }
        None
    }

    /// Place one proof in the report, minting the diagnostic only on the arm
    /// that can carry one.
    fn record(
        &mut self,
        node: Node<'_>,
        proof: RustNameProof,
        kind: &'static str,
        absence: impl FnOnce(Range) -> (SemanticDiagnosticDomain, String),
    ) {
        let range = node_range(node, self.line_starts);
        let emitted = record_rust_name_proof(&mut self.report, range, proof, || {
            let (domain, message) = absence(range);
            (
                domain,
                SemanticDiagnostic {
                    range,
                    source: RUST_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind,
                    message,
                },
            )
        });
        if emitted {
            self.diagnostic_count += 1;
        }
    }

    fn record_resolved(&mut self, node: Node<'_>, boundary: BoundaryStatus) {
        let range = node_range(node, self.line_starts);
        self.report.push_resolved(range, boundary);
    }
}

/// The `::`-separated segments of a structured path node, read from the
/// parser's `path` and `name` fields rather than from the source text.
fn path_segments(node: Node<'_>, source: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = Some(node);
    while let Some(candidate) = current {
        match candidate.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(name) = candidate.child_by_field_name("name") {
                    segments.push(node_text(name, source).trim().to_string());
                }
                current = candidate.child_by_field_name("path");
            }
            "identifier" | "type_identifier" | "crate" | "self" | "super" => {
                segments.push(node_text(candidate, source).trim().to_string());
                current = None;
            }
            _ => current = None,
        }
    }
    segments.reverse();
    segments
}

/// Whether a path stays inside the crate that spells it.
fn is_crate_local_root(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| matches!(root.as_str(), "crate" | "self" | "super"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SymbolKind {
    Type,
    Value,
}

#[derive(Default)]
struct RustScopeStack {
    scopes: Vec<RustScope>,
}

#[derive(Default)]
struct RustScope {
    names: HashSet<(String, SymbolKind)>,
    isolated: bool,
}

impl RustScopeStack {
    fn enter(&mut self) {
        self.scopes.push(RustScope::default());
    }

    fn enter_isolated(&mut self) {
        self.scopes.push(RustScope {
            isolated: true,
            ..RustScope::default()
        });
    }

    fn exit(&mut self) {
        self.scopes.pop();
    }

    fn declare(&mut self, name: String, kind: SymbolKind) {
        if name == "_" {
            return;
        }
        if self.scopes.is_empty() {
            self.enter();
        }
        let scope = self.scopes.last_mut().expect("scope exists after enter");
        scope.names.insert((name, kind));
    }

    fn contains(&self, name: &str, kind: SymbolKind) -> bool {
        let key = (name.to_string(), kind);
        for scope in self.scopes.iter().rev() {
            if scope.names.contains(&key) {
                return true;
            }
            if scope.isolated {
                return false;
            }
        }
        false
    }
}

struct RustUseBinding {
    imports: Vec<ImportInfo>,
    mod_range: Option<(usize, usize)>,
    scope_range: Option<(usize, usize)>,
}

fn collect_rust_use_bindings(root: Node<'_>, source: &str) -> Vec<RustUseBinding> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "use_declaration" {
            let imports = crate::imports::rust_imports_from_use_declaration(node, source);
            if !imports.is_empty() {
                bindings.push(RustUseBinding {
                    imports,
                    mod_range: enclosing_mod_item_range(node),
                    scope_range: enclosing_visibility_scope_range(node),
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    bindings
}

fn enclosing_mod_item_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item" {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn enclosing_visibility_scope_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if lexical_scope_kind(parent.kind()) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn lexical_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block" | "function_item" | "impl_item" | "trait_item" | "mod_item"
    )
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
    excluded_fields: &[&str],
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        if excluded_fields.iter().any(|field| {
            node.child_by_field_name(field)
                .is_some_and(|field_node| same_node(field_node, child))
        }) {
            continue;
        }
        stack.push(ScanFrame::Node(child));
    }
}

fn seed_function_like_bindings(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut cursor = params.walk();
        for child in params.named_children(&mut cursor) {
            if let Some(pattern) = child.child_by_field_name("pattern") {
                seed_pattern_bindings(pattern, source, scopes);
            }
        }
    }
}

fn seed_block_item_bindings(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        seed_item_name(child, source, scopes);
    }
}

fn seed_item_name(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let kind = match node.kind() {
        "function_item" | "const_item" | "static_item" => SymbolKind::Value,
        "struct_item" | "enum_item" | "trait_item" | "type_item" => SymbolKind::Type,
        "mod_item" => SymbolKind::Value,
        _ => return,
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, source).trim();
    if !name.is_empty() {
        scopes.declare(name.to_string(), kind);
    }
}

fn seed_type_parameters(node: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut stack = Vec::new();
    if let Some(params) = node.child_by_field_name("type_parameters") {
        stack.push(params);
    }
    while let Some(current) = stack.pop() {
        if current.kind() == "type_identifier" {
            let name = node_text(current, source).trim();
            if !name.is_empty() {
                scopes.declare(name.to_string(), SymbolKind::Type);
            }
            continue;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn seed_pattern_bindings(pattern: Node<'_>, source: &str, scopes: &mut RustScopeStack) {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" => {
                let name = node_text(node, source).trim();
                if !name.is_empty() {
                    scopes.declare(name.to_string(), SymbolKind::Value);
                }
            }
            "scoped_identifier" | "field_identifier" | "type_identifier" => {}
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

/// Why the scan declines to judge any name inside `node`, if it declines.
///
/// Each arm is a real limit on what a surface can prove, not a convenience:
/// a macro synthesizes names no surface declares, an attribute names a
/// derive whose expansion is likewise generated, and a `cfg` attribute
/// selects an item set by a configuration this pass does not evaluate.
/// Comments contain no references, so they are skipped without an outcome.
fn subtree_suppression(node: Node<'_>, source: &str) -> Option<RustProofGap> {
    if matches!(node.kind(), "line_comment" | "block_comment") {
        return None;
    }
    if matches!(node.kind(), "macro_invocation" | "macro_definition") {
        return Some(RustProofGap::Generated {
            detail: format!(
                "names inside the Rust {} are produced by macro expansion, which no surface declares",
                node.kind().replace('_', " ")
            ),
        });
    }
    if node.kind() == "attribute_item" {
        return Some(RustProofGap::Generated {
            detail: "names inside a Rust attribute name a derive or attribute macro whose expansion no surface declares".to_string(),
        });
    }
    if let Some(condition) = enclosing_cfg_condition(node, source) {
        return Some(RustProofGap::Unsupported {
            detail: format!(
                "the item is gated by `{condition}`, and this pass does not evaluate Cargo configuration"
            ),
        });
    }
    None
}

fn is_type_reference_identifier(node: Node<'_>) -> bool {
    if node.kind() != "type_identifier" || is_declaration_name(node) || is_inside_use(node) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "type_parameters"
            | "type_parameter"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
    )
}

fn is_scoped_reference(node: Node<'_>) -> bool {
    !is_declaration_name(node)
        && !is_inside_use(node)
        && !is_inside_macro_invocation(node)
        && node.child_by_field_name("name").is_some()
}

fn is_value_reference_identifier(node: Node<'_>) -> bool {
    if node.kind() != "identifier"
        || is_declaration_name(node)
        || is_inside_use(node)
        || is_pattern_identifier(node)
    {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "call_expression" => parent
            .child_by_field_name("function")
            .is_some_and(|function| same_node(function, node)),
        "scoped_identifier" | "scoped_type_identifier" => false,
        "field_expression" | "field_initializer" | "field_declaration" => false,
        "macro_invocation" | "macro_definition" | "attribute_item" => false,
        "let_declaration" | "parameter" | "self_parameter" => false,
        _ => true,
    }
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "trait_item"
            | "type_item"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "field_declaration"
            | "enum_variant"
            | "function_signature_item"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
}

fn is_pattern_identifier(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "let_declaration" | "parameter" | "match_arm" | "for_expression"
        ) && parent
            .child_by_field_name("pattern")
            .is_some_and(|pattern| contains_node(pattern, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "closure_expression"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn is_inside_use(node: Node<'_>) -> bool {
    has_ancestor(node, |ancestor| ancestor.kind() == "use_declaration")
}

fn is_inside_macro_invocation(node: Node<'_>) -> bool {
    has_ancestor(node, |ancestor| {
        matches!(ancestor.kind(), "macro_invocation" | "macro_definition")
    })
}

/// The `cfg` attribute gating `node`, named exactly so a suppression reason can
/// say which configuration it could not evaluate.
fn enclosing_cfg_condition(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        let mut sibling = candidate.prev_named_sibling();
        while let Some(prev) = sibling {
            if prev.kind() != "attribute_item" {
                break;
            }
            let text = node_text(prev, source).trim();
            if text.starts_with("#[cfg") || text.starts_with("#![cfg") {
                return Some(text.to_string());
            }
            sibling = prev.prev_named_sibling();
        }
        current = candidate.parent();
    }
    None
}

fn has_ancestor(node: Node<'_>, predicate: impl Fn(Node<'_>) -> bool) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if predicate(parent) {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_crate_local_path(path_node: Node<'_>, source: &str) -> bool {
    let Some(root) = path_root(path_node) else {
        return false;
    };
    matches!(node_text(root, source).trim(), "crate" | "self" | "super")
}

fn path_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                node = node.child_by_field_name("path")?;
            }
            "identifier" | "type_identifier" | "crate" | "self" | "super" => return Some(node),
            _ => return None,
        }
    }
}

fn is_rust_builtin_name(name: &str) -> bool {
    matches!(
        name,
        "Self"
            | "self"
            | "super"
            | "crate"
            | "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "Option"
            | "Result"
            | "Some"
            | "None"
            | "Ok"
            | "Err"
            | "Vec"
            | "String"
            | "Box"
            | "Default"
            | "Debug"
            | "Clone"
            | "Copy"
            | "Send"
            | "Sync"
            | "Sized"
            | "Drop"
            | "Iterator"
            | "IntoIterator"
            | "From"
            | "Into"
            | "AsRef"
            | "AsMut"
            | "ToString"
            | "ToOwned"
            | "println"
            | "format"
            | "vec"
            | "drop"
            | "panic"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "assert"
            | "assert_eq"
            | "assert_ne"
    )
}
