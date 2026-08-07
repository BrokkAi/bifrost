//! C#'s semantic diagnostics: every name this pass checks, classified as
//! resolved, absent with a complete proof, or suppressed with a typed reason.
//!
//! The analyzer facts this needs are a [`CSharpSource`] for the workspace half
//! and a [`CSharpExternalEvidence`] view of the retained assembly index for the
//! other half. `analyzer/csharp/diagnostics.rs` in `brokk-bifrost-analysis`
//! keeps the downcast that produces them, because this crate cannot name
//! `CSharpExternalDeclarationIndex`.
//!
//! No path here may read an assembly, `project.assets.json`, or a NuGet cache,
//! and none may build an index. State a request cannot read is a typed
//! [`SemanticDiagnosticIncompleteReason`], never a guess and never an error.
//! That makes this pass's evidence a strict subset of the resolver's, so a
//! diagnostic can only ever fall further toward incompleteness than a
//! `get_definition` for the same reference, never past it into a false error.
//!
//! # What this pass checks
//!
//! `using` directives (namespace, alias and static forms), type references in
//! the positions the grammar reserves for one, and member accesses whose owner
//! this pass can prove. Everything else -- a bare identifier, a receiver whose
//! type is not proven, a `dynamic` value -- is left unchecked rather than
//! guessed at, because an outcome is a claim about a lookup that happened.

use std::collections::BTreeSet;

use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text, same_node};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

use crate::graph_support::{
    CSharpSource, first_logical_type_fqn, logical_type_count, visible_type_candidates,
};
use crate::imports::{csharp_using_alias_from_node, csharp_using_namespace};
use crate::syntax::{
    csharp_type_node_identity, csharp_using_directive_is_static, normalize_csharp_type_fragment,
};
use brokk_bifrost_core::hash::HashSet;

pub const CSHARP_UNRECOGNIZED_SYMBOL: &str = "csharp_unrecognized_symbol";
pub const CSHARP_UNRECOGNIZED_MEMBER: &str = "csharp_unrecognized_member";
pub const CSHARP_UNRECOGNIZED_NAMESPACE: &str = "csharp_unrecognized_namespace";
pub const CSHARP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-csharp";

/// Past this size the pass reports one `Truncated` outcome instead of walking
/// the file. A generated or vendored C# file that large is not what a
/// diagnostic request is for.
const MAX_CSHARP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;

/// The most diagnostics one file may publish before the rest is `Truncated`.
pub const MAX_CSHARP_SEMANTIC_DIAGNOSTICS: usize = 200;

/// How many externally visible types the retained index resolves one reference
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpExternalTypes {
    /// The index publishes nothing this reference could name.
    None,
    /// Exactly one indexed type, at this metadata identity.
    One { fqn: String },
    /// More than one, so the reference is ambiguous rather than resolved.
    Many { count: usize },
}

/// What the retained index proves about one member on an external owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpMemberSurface {
    /// The owner's surface publishes the member.
    Published,
    /// The owner's whole surface, base chain included, lacks it.
    Absent,
    /// A link in the owner's base chain is not resolvable from retained state,
    /// so the remainder of its surface is unknown and a miss proves nothing.
    IncompleteOwner { detail: String },
}

/// The retained C# external surface a diagnostic request may read.
///
/// Every method answers from state the analyzer already holds. None may read an
/// assembly, `project.assets.json`, or a NuGet cache, and none may trigger an
/// index build: an answer a request cannot see is an incompleteness, never a
/// reason to go and produce it.
pub trait CSharpExternalEvidence {
    /// Why the retained index cannot prove any name absent, or `None` when it
    /// is built and read every one of its inputs whole.
    ///
    /// The collector asks once per request and reuses the answer, so the other
    /// methods are only ever called against a readable index.
    fn unreadable(&self) -> Option<SemanticDiagnosticIncompleteReason>;

    /// Whether the retained index describes the compilation's external surface
    /// well enough for a miss against it to be a proof.
    ///
    /// A readable index built from *no* dependency inputs -- no configured
    /// assembly path and no `project.assets.json` -- is not that. Discovery
    /// over an empty input set completes vacuously, and reading that as "the
    /// compilation references nothing" would make every `using System;` in a
    /// loose `.cs` file an error.
    fn surface_is_known(&self) -> bool;

    /// Whether the index publishes an externally visible type in `namespace`.
    fn declares_namespace(&self, namespace: &str) -> bool;

    /// The externally visible types the index resolves `identity` to, as
    /// `file`'s own namespace, `using` namespaces and aliases spell it.
    fn resolve_type(&self, file: &ProjectFile, identity: &str) -> CSharpExternalTypes;

    /// Whether the index publishes `member` anywhere on the complete surface of
    /// the external type `owner_fqn`, its base chain included.
    fn resolve_member(&self, owner_fqn: &str, member: &str) -> CSharpMemberSurface;

    /// Whether an indexed static method named `name` sits in one of
    /// `namespaces`.
    ///
    /// An extension method is a static method, and assembly metadata carries no
    /// marker this index decodes, so a hit means an instance-member miss might
    /// be an extension call and is therefore not proof of absence.
    fn could_supply_extension_method(&self, namespaces: &[String], name: &str) -> bool;
}

/// Collect C# semantic diagnostics and the proof behind each one.
pub fn collect_csharp_semantic_diagnostics(
    csharp: &dyn CSharpSource,
    external: &dyn CSharpExternalEvidence,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_CSHARP_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .is_err()
    {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "C# parser is unavailable".to_string(),
            }],
        );
        return report;
    }
    let Some(tree) = parser.parse(source, None) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "C# source did not parse".to_string(),
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
                detail: "C# source has parse errors".to_string(),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let mut collector = CSharpDiagnosticCollector {
        csharp,
        external,
        unreadable_external: external.unreadable(),
        file,
        source,
        line_starts: &line_starts,
        file_namespace: csharp.namespace_of_file(file),
        usings: file_using_namespaces(csharp, file),
        scope_is_visible: true,
        type_parameters: Vec::new(),
        partial_declarations: HashSet::default(),
        report,
        diagnostic_count: 0,
    };
    // The `using` directives are checked first and in one pass: whether the
    // namespaces a file opens are all visible decides whether an unqualified
    // reference that misses everywhere was checked against a complete surface.
    collector.check_using_directives(&tree);
    collector.collect_partial_declarations(&tree);
    collector.scan_tree(tree.root_node());
    collector.report
}

/// Every namespace a file opens: its own `using` directives plus the workspace's
/// `global using` ones, which C# applies to every file in the compilation.
fn file_using_namespaces(csharp: &dyn CSharpSource, file: &ProjectFile) -> Vec<String> {
    let mut usings: BTreeSet<String> = csharp.using_namespaces_of(file).into_iter().collect();
    usings.extend(csharp.global_using_namespaces().iter().cloned());
    usings.into_iter().collect()
}

struct CSharpDiagnosticCollector<'a> {
    csharp: &'a dyn CSharpSource,
    external: &'a dyn CSharpExternalEvidence,
    /// Cached once per request: the reason no external claim can be made, when
    /// there is one.
    unreadable_external: Option<SemanticDiagnosticIncompleteReason>,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    file_namespace: String,
    usings: Vec<String>,
    /// Whether every namespace this file opens is one the pass can see whole.
    /// A `using` of a namespace neither the workspace nor the index publishes
    /// leaves an unqualified miss unprovable: the name could live there.
    scope_is_visible: bool,
    /// Generic parameter names in scope, innermost frame last. A reference to
    /// one names no declaration and is not a lookup.
    type_parameters: Vec<HashSet<String>>,
    /// Short names this file declares `partial`, whose member surface a
    /// generated half may extend.
    partial_declarations: HashSet<String>,
    report: SemanticDiagnosticReport,
    diagnostic_count: usize,
}

/// What the workspace alone says about one type reference.
enum WorkspaceTypes {
    /// No workspace declaration matches.
    None,
    /// Exactly one logical type, counting a partial type's parts as one.
    One,
    /// More than one logical type is visible under this name.
    Many { count: usize },
}

/// The owner a member access reads through, once this pass has proven it.
enum MemberOwner {
    /// A workspace declaration, at this fully qualified name.
    Workspace { fqn: String },
    /// An indexed assembly type, at this metadata identity.
    External { fqn: String },
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitTypeParameters,
}

impl CSharpDiagnosticCollector<'_> {
    // -- using directives ---------------------------------------------------

    fn check_using_directives(&mut self, tree: &Tree) {
        let mut cursor = tree.root_node().walk();
        let mut stack = vec![tree.root_node()];
        let mut directives = Vec::new();
        // `using` directives sit at the top of a file or inside a namespace
        // body, so the walk is shallow, but it is still an explicit stack: a
        // file-scoped namespace nests every declaration under one node.
        while let Some(node) = stack.pop() {
            if node.kind() == "using_directive" {
                directives.push(node);
                continue;
            }
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "using_directive"
                    | "namespace_declaration"
                    | "file_scoped_namespace_declaration"
                    | "declaration_list" => stack.push(child),
                    _ => {}
                }
            }
        }
        directives.sort_by_key(Node::start_byte);
        for directive in directives {
            self.check_using_directive(directive);
        }
    }

    fn check_using_directive(&mut self, node: Node<'_>) {
        let range = self.range_of(node);
        let raw = node_text(node, self.source).to_string();
        if let Some(namespace) = csharp_using_namespace(&raw) {
            self.check_using_namespace(range, &namespace);
            return;
        }
        if csharp_using_directive_is_static(node) {
            // `using static X;` names a type whose static members the file
            // opens, so it is a type reference like any other.
            let Some(target) = csharp_using_directive_target_identity(node, self.source) else {
                return;
            };
            self.check_type_identity(range, &target);
            return;
        }
        let Some((_, target)) = csharp_using_alias_from_node(node, self.source) else {
            return;
        };
        // An alias target is either a namespace or a type, and C# accepts both
        // spellings. A namespace hit settles it; otherwise the type ladder does.
        if self.namespace_is_visible(&target) {
            self.report
                .push_resolved(range, self.namespace_boundary(&target));
            return;
        }
        self.check_type_identity(range, &target);
    }

    fn check_using_namespace(&mut self, range: Range, namespace: &str) {
        if self.csharp.workspace_namespace_exists(namespace) {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        if let Some(reason) = self.unreadable_external.clone() {
            // The namespace may well be in the part of the dependency set this
            // request cannot see, and every unqualified name in the file could
            // resolve through it.
            self.scope_is_visible = false;
            self.report.push_incomplete(Some(range), vec![reason]);
            return;
        }
        if self.external.declares_namespace(namespace) {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if !self.external.surface_is_known() {
            // The index read every input it was given, but it was given none.
            // The namespace may be in a reference nothing here can see, and so
            // may any unqualified name the file spells.
            self.scope_is_visible = false;
            self.report.push_incomplete(
                Some(range),
                vec![
                    SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                        boundary: BoundaryStatus::ExternalUnknown,
                    },
                ],
            );
            return;
        }
        // The workspace does not declare it and a complete index built from the
        // project's own dependency inputs does not publish it, so the directive
        // opens nothing. That is a proven absence, and it leaves the rest of
        // the file's scope intact.
        self.publish_absence(
            range,
            SemanticDiagnosticDomain::Package {
                name: namespace.to_string(),
            },
            BoundaryStatus::ExternalIndexed,
            CSHARP_UNRECOGNIZED_NAMESPACE,
            format!("unrecognized namespace `{namespace}`"),
        );
    }

    fn namespace_is_visible(&self, namespace: &str) -> bool {
        self.csharp.workspace_namespace_exists(namespace)
            || (self.unreadable_external.is_none() && self.external.declares_namespace(namespace))
    }

    fn namespace_boundary(&self, namespace: &str) -> BoundaryStatus {
        if self.csharp.workspace_namespace_exists(namespace) {
            BoundaryStatus::WorkspaceLocal
        } else {
            BoundaryStatus::ExternalIndexed
        }
    }

    // -- partial declarations -----------------------------------------------

    /// The short names of types this file declares `partial`.
    ///
    /// A `partial` type may be completed by a half this workspace never sees --
    /// a source generator writes into the build's intermediate output, which is
    /// not analyzed. Its own declarations are therefore only part of its member
    /// surface, so a member miss against one proves nothing.
    ///
    /// The scan is of this file only, because it is the tree the request
    /// already holds. A `partial` half declared in *another* file is not
    /// detected, which leaves a known gap; the multi-file case that gap covers
    /// is the benign one, since every part the workspace holds contributes its
    /// members to the owner's fq-name lookup already.
    fn collect_partial_declarations(&mut self, tree: &Tree) {
        let mut cursor = tree.root_node().walk();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "class_declaration"
                    | "struct_declaration"
                    | "record_declaration"
                    | "record_struct_declaration"
                    | "interface_declaration"
            ) && declares_partial(node, self.source)
                && let Some(name) = node.child_by_field_name("name")
            {
                self.partial_declarations
                    .insert(node_text(name, self.source).trim().to_string());
            }
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }

    // -- the tree walk ------------------------------------------------------

    fn scan_tree(&mut self, root: Node<'_>) {
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostic_count >= MAX_CSHARP_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(node, &mut stack),
                ScanFrame::ExitTypeParameters => {
                    self.type_parameters.pop();
                }
            }
        }
    }

    fn scan_node<'tree>(&mut self, node: Node<'tree>, stack: &mut Vec<ScanFrame<'tree>>) {
        // A `using` directive was already checked in its own pass; descending
        // into one here would check its target a second time.
        if node.kind() == "using_directive" {
            return;
        }
        if let Some(names) = declared_type_parameters(node, self.source) {
            self.type_parameters.push(names);
            stack.push(ScanFrame::ExitTypeParameters);
        }
        if node.kind() == "member_access_expression" {
            self.check_member_access(node);
        } else if is_type_reference_position(node) {
            self.check_type_reference(node);
        }
        push_named_children(stack, node);
    }

    // -- type references ----------------------------------------------------

    fn check_type_reference(&mut self, node: Node<'_>) {
        let identity = csharp_type_node_identity(node, self.source);
        if self.is_uncheckable_type_identity(&identity) {
            return;
        }
        self.check_type_identity(self.range_of(node), &identity);
    }

    /// Names that are not lookups: a predefined keyword type, the inferred
    /// `var`, the `dynamic` escape hatch, and a generic parameter in scope.
    fn is_uncheckable_type_identity(&self, identity: &str) -> bool {
        if identity.is_empty() {
            return true;
        }
        let head = normalize_csharp_type_fragment(identity);
        if head.is_empty() || is_csharp_keyword_type(&head) {
            return true;
        }
        self.type_parameters
            .iter()
            .any(|frame| frame.contains(head.as_str()))
    }

    fn check_type_identity(&mut self, range: Range, identity: &str) {
        match self.workspace_types(identity) {
            WorkspaceTypes::One => {
                self.report
                    .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            }
            WorkspaceTypes::Many { count } => {
                self.report
                    .push_ambiguous(range, vec![BoundaryStatus::WorkspaceLocal; count]);
            }
            WorkspaceTypes::None => self.check_external_type(range, identity),
        }
    }

    fn workspace_types(&self, identity: &str) -> WorkspaceTypes {
        // The same helper `get_definition` resolves a C# type reference with,
        // so a name this pass calls absent is one the definition route also
        // fails to find.
        let candidates = visible_type_candidates(self.csharp, self.file, identity);
        match logical_type_count(&candidates) {
            0 => WorkspaceTypes::None,
            1 => WorkspaceTypes::One,
            count => WorkspaceTypes::Many { count },
        }
    }

    fn check_external_type(&mut self, range: Range, identity: &str) {
        if self.workspace_bounded() {
            // Nothing this file can name lives outside the workspace, so the
            // workspace was the whole surface and the miss is already proven.
            // No external state is read at all on this path.
            self.publish_absence(
                range,
                SemanticDiagnosticDomain::Type {
                    name: identity.to_string(),
                },
                BoundaryStatus::WorkspaceLocal,
                CSHARP_UNRECOGNIZED_SYMBOL,
                format!("unrecognized type `{identity}`"),
            );
            return;
        }
        if let Some(reason) = self.unreadable_external.clone() {
            self.report.push_incomplete(Some(range), vec![reason]);
            return;
        }
        match self.external.resolve_type(self.file, identity) {
            CSharpExternalTypes::One { .. } => {
                self.report
                    .push_resolved(range, BoundaryStatus::ExternalIndexed);
            }
            CSharpExternalTypes::Many { count } => {
                self.report
                    .push_ambiguous(range, vec![BoundaryStatus::ExternalIndexed; count]);
            }
            CSharpExternalTypes::None => {
                if !self.external_miss_is_proof() {
                    self.report.push_incomplete(
                        Some(range),
                        vec![
                            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                boundary: BoundaryStatus::ExternalUnknown,
                            },
                        ],
                    );
                    return;
                }
                self.publish_absence(
                    range,
                    SemanticDiagnosticDomain::Type {
                        name: identity.to_string(),
                    },
                    BoundaryStatus::ExternalIndexed,
                    CSHARP_UNRECOGNIZED_SYMBOL,
                    format!("unrecognized type `{identity}`"),
                );
            }
        }
    }

    /// Whether a name lookup from this file cannot leave the workspace.
    ///
    /// True when every namespace the file opens is one the workspace declares,
    /// and a readable index publishes nothing in the global namespace that an
    /// unqualified name could reach. The index must be *readable* for that last
    /// clause to mean anything, which is why an unbuilt one answers false: this
    /// pass does not know what it has not read.
    ///
    /// This is what lets a workspace with no dependencies at all report a
    /// missing local type, and it is the same rule C# scoping uses -- a name,
    /// and an extension method, is reachable only through a namespace the file
    /// actually opens.
    fn workspace_bounded(&self) -> bool {
        self.scope_is_visible
            && self.unreadable_external.is_none()
            && !self.external.declares_namespace("")
            && self
                .usings
                .iter()
                .all(|namespace| self.csharp.workspace_namespace_exists(namespace))
    }

    /// Whether a miss against the indexed external surface is a proof.
    fn external_miss_is_proof(&self) -> bool {
        self.scope_is_visible
            && self.unreadable_external.is_none()
            && self.external.surface_is_known()
    }

    // -- member accesses ----------------------------------------------------

    fn check_member_access(&mut self, node: Node<'_>) {
        let (Some(receiver), Some(name_node)) = (
            node.child_by_field_name("expression"),
            node.child_by_field_name("name"),
        ) else {
            return;
        };
        let member = node_text(name_node, self.source).trim().to_string();
        if member.is_empty() {
            return;
        }
        let range = self.range_of(name_node);
        // A qualified type or namespace spelling reaches here too --
        // `System.Console` is a `member_access_expression` in expression
        // position. Those are settled by the type ladder, not the member one.
        let receiver_identity = csharp_type_node_identity(receiver, self.source);
        if !receiver_identity.is_empty() && self.namespace_is_visible(&receiver_identity) {
            return;
        }
        match self.member_owner(receiver, &receiver_identity) {
            Ok(MemberOwner::Workspace { fqn }) => self.check_workspace_member(range, &fqn, &member),
            Ok(MemberOwner::External { fqn }) => self.check_external_member(range, &fqn, &member),
            Err(reason) => self.report.push_incomplete(Some(range), vec![reason]),
        }
    }

    /// Prove what a member access reads through, or say why this pass cannot.
    fn member_owner(
        &self,
        receiver: Node<'_>,
        receiver_identity: &str,
    ) -> Result<MemberOwner, SemanticDiagnosticIncompleteReason> {
        // `this` names the enclosing type, which is the one receiver whose type
        // needs no inference at all. The grammar spells it as the bare keyword
        // token inside a member access, and as `this_expression` elsewhere.
        if matches!(receiver.kind(), "this" | "this_expression") {
            let Some(enclosing) = enclosing_type_name(receiver, self.source) else {
                return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: "`this` appears outside a type declaration".to_string(),
                });
            };
            return self.type_owner(&enclosing).ok_or_else(|| {
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!("enclosing type `{enclosing}` does not resolve uniquely"),
                }
            });
        }
        // A plain identifier is looked up as a value before it is looked up as
        // a type. That is C#'s own order for `E.I` -- the "Color Color" rule --
        // and getting it backwards would read `widget.Missing` against the type
        // named `widget` whenever a local shadows one, and report a member the
        // value does have as absent.
        if receiver.kind() == "identifier" {
            let symbol = node_text(receiver, self.source).trim();
            match self.declared_type_of_binding(receiver, symbol) {
                Ok(declared) => {
                    if is_csharp_dynamic(&declared) {
                        return Err(SemanticDiagnosticIncompleteReason::DynamicBehavior {
                            detail: format!("`{symbol}` is declared `dynamic`"),
                        });
                    }
                    return self.type_owner(&declared).ok_or_else(|| {
                        SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                            detail: format!("receiver `{symbol}` has no uniquely resolved type"),
                        }
                    });
                }
                // Nothing binds the name as a value, so it may name a type and
                // this is a static access.
                Err(unbound) => {
                    return self
                        .type_owner(symbol)
                        .filter(|_| !self.is_uncheckable_type_identity(symbol))
                        .ok_or(unbound);
                }
            }
        }
        // A qualified receiver can only be a type or namespace path; the
        // namespace case was settled before this call.
        if receiver_identity.is_empty() || self.is_uncheckable_type_identity(receiver_identity) {
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!(
                    "receiver expression of kind `{}` has no proven C# type",
                    receiver.kind()
                ),
            });
        }
        self.type_owner(receiver_identity).ok_or_else(|| {
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{receiver_identity}` has no uniquely resolved type"),
            }
        })
    }

    /// The declared type name of a local, parameter or field the receiver
    /// identifier binds.
    ///
    /// Seeded from the file root with the receiver's own start byte as the
    /// cutoff, which is what `get_definition`'s
    /// `csharp_structured_receiver_type_names` does. Seeding from the enclosing
    /// body instead would miss a field declared after the method that reads it.
    fn declared_type_of_binding(
        &self,
        receiver: Node<'_>,
        symbol: &str,
    ) -> Result<String, SemanticDiagnosticIncompleteReason> {
        let mut bindings = LocalInferenceEngine::<String>::default();
        crate::graph::resolver::seed_bindings_before(
            file_root(receiver),
            receiver.start_byte(),
            self.csharp,
            self.file,
            self.source,
            &mut bindings,
        );
        let resolution = bindings.resolve_symbol(symbol);
        let Some(targets) = resolution.as_precise() else {
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{symbol}` has no uniquely inferred declared type"),
            });
        };
        let mut declared = targets.iter();
        match (declared.next(), declared.next()) {
            (Some(only), None) => Ok(only.clone()),
            _ => Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{symbol}` binds more than one declared type"),
            }),
        }
    }

    /// The unique declaration a type name identifies, workspace first.
    fn type_owner(&self, identity: &str) -> Option<MemberOwner> {
        let candidates = visible_type_candidates(self.csharp, self.file, identity);
        if logical_type_count(&candidates) == 1 {
            return first_logical_type_fqn(&candidates).map(|fqn| MemberOwner::Workspace { fqn });
        }
        if !candidates.is_empty() || self.unreadable_external.is_some() {
            return None;
        }
        match self.external.resolve_type(self.file, identity) {
            CSharpExternalTypes::One { fqn } => Some(MemberOwner::External { fqn }),
            CSharpExternalTypes::None | CSharpExternalTypes::Many { .. } => None,
        }
    }

    fn check_workspace_member(&mut self, range: Range, owner_fqn: &str, member: &str) {
        if !self
            .csharp
            .member_candidates_for_owner(owner_fqn, member)
            .is_empty()
        {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        // The owner's own declarations are only part of its surface. Walking
        // its ancestors is what makes a miss a proof rather than a guess, and
        // an ancestor this pass cannot resolve leaves the rest unknown (#1789).
        match self.inherited_member(owner_fqn, member) {
            InheritedMember::Found { boundary } => self.report.push_resolved(range, boundary),
            InheritedMember::IncompleteSurface { detail } => self.report.push_incomplete(
                Some(range),
                vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }],
            ),
            InheritedMember::Absent => {
                self.publish_member_absence(
                    range,
                    owner_fqn,
                    member,
                    BoundaryStatus::WorkspaceLocal,
                );
            }
        }
    }

    fn check_external_member(&mut self, range: Range, owner_fqn: &str, member: &str) {
        match self.external.resolve_member(owner_fqn, member) {
            CSharpMemberSurface::Published => {
                self.report
                    .push_resolved(range, BoundaryStatus::ExternalIndexed);
            }
            CSharpMemberSurface::IncompleteOwner { detail } => self.report.push_incomplete(
                Some(range),
                vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }],
            ),
            CSharpMemberSurface::Absent => {
                if !self.external_miss_is_proof() {
                    self.report.push_incomplete(
                        Some(range),
                        vec![
                            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                boundary: BoundaryStatus::ExternalUnknown,
                            },
                        ],
                    );
                    return;
                }
                self.publish_member_absence(
                    range,
                    owner_fqn,
                    member,
                    BoundaryStatus::ExternalIndexed,
                );
            }
        }
    }

    /// Publish a member absence, unless an extension method could explain it.
    fn publish_member_absence(
        &mut self,
        range: Range,
        owner_fqn: &str,
        member: &str,
        boundary: BoundaryStatus,
    ) {
        if self.owner_may_be_generated(owner_fqn) {
            self.report.push_incomplete(
                Some(range),
                vec![
                    SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                        detail: format!(
                            "`{owner_fqn}` is declared partial, so a generated half may declare `{member}`"
                        ),
                    },
                ],
            );
            return;
        }
        if self.extension_method_could_apply(member) {
            self.report.push_incomplete(
                Some(range),
                vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!(
                        "`{member}` may be an extension method in a namespace this file opens"
                    ),
                }],
            );
            return;
        }
        self.publish_absence(
            range,
            SemanticDiagnosticDomain::MemberSurface {
                owner: owner_fqn.to_string(),
                member: member.to_string(),
            },
            boundary,
            CSHARP_UNRECOGNIZED_MEMBER,
            format!("unrecognized member `{member}` on `{owner_fqn}`"),
        );
    }

    /// Whether the owner is a `partial` type this file declares, so a half the
    /// workspace never sees may declare the member.
    ///
    /// Matched on the short name: a file that declares `partial class Widget`
    /// and reads a member off some other namespace's `Widget` suppresses one
    /// claim it could have made, which is the safe direction to be wrong in.
    fn owner_may_be_generated(&self, owner_fqn: &str) -> bool {
        let short_name = owner_fqn.rsplit('.').next().unwrap_or(owner_fqn);
        self.partial_declarations.contains(short_name)
    }

    /// Whether a static method named `member` is visible from this file, which
    /// would make the miss an extension call rather than an error.
    ///
    /// C# brings an extension method into scope only through the namespace that
    /// declares it, so a file whose lookups cannot leave the workspace can only
    /// reach a workspace one -- and then no external state is read at all.
    /// Otherwise an index this pass cannot read has to be assumed to hold one.
    fn extension_method_could_apply(&self, member: &str) -> bool {
        if !self.workspace_bounded()
            && (self.unreadable_external.is_some()
                || self
                    .external
                    .could_supply_extension_method(&self.usings, member))
        {
            return true;
        }
        let mut namespaces: Vec<&str> = self.usings.iter().map(String::as_str).collect();
        namespaces.push(self.file_namespace.as_str());
        self.csharp
            .declaration_candidates_by_identifier(member)
            .iter()
            .any(|candidate| {
                candidate.is_function()
                    && namespaces
                        .iter()
                        .any(|namespace| candidate.package_name() == *namespace)
            })
    }

    /// Walk the owner's ancestors for `member`.
    fn inherited_member(&self, owner_fqn: &str, member: &str) -> InheritedMember {
        let mut seen: HashSet<String> = HashSet::default();
        seen.insert(owner_fqn.to_string());
        let mut queue: Vec<String> = vec![owner_fqn.to_string()];
        while let Some(current) = queue.pop() {
            let Some(unit) = self.workspace_type_unit(&current) else {
                // The chain leaves the workspace. Only the index can say what
                // the rest of the surface holds.
                if let Some(reason) = &self.unreadable_external {
                    return InheritedMember::IncompleteSurface {
                        detail: format!(
                            "ancestor `{current}` of `{owner_fqn}` is outside the workspace and {}",
                            describe_reason(reason)
                        ),
                    };
                }
                match self.external.resolve_member(&current, member) {
                    CSharpMemberSurface::Published => {
                        return InheritedMember::Found {
                            boundary: BoundaryStatus::ExternalIndexed,
                        };
                    }
                    CSharpMemberSurface::IncompleteOwner { detail } => {
                        return InheritedMember::IncompleteSurface { detail };
                    }
                    CSharpMemberSurface::Absent => continue,
                }
            };
            for raw in self.csharp.raw_supertypes_of(&unit) {
                let candidates = visible_type_candidates(self.csharp, self.file, &raw);
                match logical_type_count(&candidates) {
                    1 => {
                        let Some(fqn) = first_logical_type_fqn(&candidates) else {
                            continue;
                        };
                        if !self
                            .csharp
                            .member_candidates_for_owner(&fqn, member)
                            .is_empty()
                        {
                            return InheritedMember::Found {
                                boundary: BoundaryStatus::WorkspaceLocal,
                            };
                        }
                        if seen.insert(fqn.clone()) {
                            queue.push(fqn);
                        }
                    }
                    0 => {
                        // A supertype that resolves nowhere in the workspace is
                        // either an indexed assembly type or an unknown one.
                        // Either way the chain continues outside, so hand the
                        // raw name to the next turn of the loop.
                        if seen.insert(raw.clone()) {
                            queue.push(raw);
                        }
                    }
                    count => {
                        return InheritedMember::IncompleteSurface {
                            detail: format!(
                                "supertype `{raw}` of `{owner_fqn}` names {count} visible types"
                            ),
                        };
                    }
                }
            }
        }
        InheritedMember::Absent
    }

    fn workspace_type_unit(&self, fqn: &str) -> Option<CodeUnit> {
        let candidates = visible_type_candidates(self.csharp, self.file, fqn);
        (logical_type_count(&candidates) == 1)
            .then(|| {
                candidates
                    .into_iter()
                    .find(|candidate| candidate.fq_name() == fqn)
            })
            .flatten()
    }

    // -- report plumbing ----------------------------------------------------

    fn publish_absence(
        &mut self,
        range: Range,
        domain: SemanticDiagnosticDomain,
        boundary: BoundaryStatus,
        kind: &'static str,
        message: String,
    ) {
        self.diagnostic_count += 1;
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain,
                boundary,
            },
            SemanticDiagnostic {
                range,
                source: CSHARP_SEMANTIC_DIAGNOSTIC_SOURCE,
                kind,
                message,
            },
        );
    }

    fn range_of(&self, node: Node<'_>) -> Range {
        node_range(node, self.line_starts)
    }
}

/// What the owner's inherited surface says about one member.
enum InheritedMember {
    Found { boundary: BoundaryStatus },
    Absent,
    IncompleteSurface { detail: String },
}

fn describe_reason(reason: &SemanticDiagnosticIncompleteReason) -> String {
    match reason {
        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary } => {
            format!("the assembly index is unreadable at {boundary:?}")
        }
        other => format!("the assembly index is unreadable: {other:?}"),
    }
}

/// The identity a `using static X;` directive names.
fn csharp_using_directive_target_identity(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let target = node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"
        )
    })?;
    let identity = csharp_type_node_identity(target, source);
    (!identity.is_empty()).then_some(identity)
}

/// The generic parameter names a declaration introduces, when it has any.
///
/// The list is found by kind rather than by field: a `method_declaration`
/// labels it `type_parameters`, but a `class_declaration` carries it as an
/// unlabelled child.
fn declared_type_parameters(node: Node<'_>, source: &str) -> Option<HashSet<String>> {
    let mut children = node.walk();
    let list = node
        .named_children(&mut children)
        .find(|child| child.kind() == "type_parameter_list")?;
    let mut cursor = list.walk();
    let names: HashSet<String> = list
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter")
        .filter_map(|child| {
            let name = child
                .child_by_field_name("name")
                .unwrap_or_else(|| child.named_child(0).unwrap_or(child));
            let text = node_text(name, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        })
        .collect();
    (!names.is_empty()).then_some(names)
}

/// Whether `node` names a type in a position the C# grammar reserves for one.
///
/// The test is structural rather than lexical: the node fills its parent's
/// `type` or `returns` field, or is a generic argument or a base-list entry.
/// Those are the positions where a name can only be a type, so a miss there is
/// a real lookup failure and not a constant, label or member spelled the same
/// way. `x is Pat` and `x as Conv` are deliberately left out: the grammar
/// parses the first as a `constant_pattern`, which an enum member also
/// produces, so neither can be judged here without claiming more than the
/// syntax proves.
///
/// A wrapper's inner type answers `false` because the wrapper itself already
/// covers it -- [`csharp_type_node_identity`] unwraps arrays, nullables and
/// pointers to the type they decorate.
fn is_type_reference_position(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "array_type"
            | "nullable_type"
            | "pointer_type"
            | "simple_base_type"
            | "primary_constructor_base_type"
    ) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "array_type" | "nullable_type" | "pointer_type" | "ref_type" => false,
        "type_argument_list" | "base_list" => true,
        _ => ["type", "returns"].iter().any(|field| {
            parent
                .child_by_field_name(field)
                .is_some_and(|typed| same_node(typed, node))
        }),
    }
}

/// The name of the type declaration `node` sits in.
fn enclosing_type_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "interface_declaration"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            let name = node_text(name, source).trim();
            return (!name.is_empty()).then(|| name.to_string());
        }
        current = parent;
    }
    None
}

/// The file's root node, which bounds the local-binding seeding.
fn file_root(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        current = parent;
    }
    current
}

/// Whether a type declaration carries the `partial` modifier.
fn declares_partial(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "modifier")
        .any(|child| node_text(child, source).trim() == "partial")
}

fn is_csharp_dynamic(declared: &str) -> bool {
    normalize_csharp_type_fragment(declared) == "dynamic"
}

/// Keyword types and inference placeholders, which name no declaration.
fn is_csharp_keyword_type(name: &str) -> bool {
    matches!(
        name,
        "var"
            | "void"
            | "dynamic"
            | "object"
            | "string"
            | "bool"
            | "byte"
            | "sbyte"
            | "char"
            | "decimal"
            | "double"
            | "float"
            | "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "nint"
            | "nuint"
    )
}

fn push_named_children<'tree>(stack: &mut Vec<ScanFrame<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        stack.push(ScanFrame::Node(child));
    }
}
