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

use brokk_bifrost_core::analyzer::memo_attribution::CaptureScopedMemo;

use std::cell::RefCell;
use std::collections::BTreeSet;

use brokk_bifrost_core::analyzer::model::{
    ClassLikeKind, SemanticAbsenceProof, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport, push_absent_diagnostic,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text, same_node};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::{
    collect_parse_errors, node_for_exact_range, push_named_children_reversed_as,
    single_named_child_matching,
};
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Tree};

use crate::graph::CSharpGraphSource;
use crate::graph::resolver::{
    CSharpDeclaredType, member_declared_type_fq_name_in_session,
    nearest_member_candidates_for_owner_inner, resolve_type_fq_name_of_node,
    type_parameter_shadows_reference, visible_declared_type_node,
};
use crate::graph_support::{
    CSharpLookupContext, CSharpSource, first_logical_type_fqn, logical_type_count,
    visible_type_candidates,
};
use crate::imports::csharp_using_alias_from_node;
use crate::syntax::{
    csharp_arity_preserving_full_name, csharp_identifier_text, csharp_member_access_receiver,
    csharp_type_node_identity, csharp_using_directive_is_static, csharp_using_directive_namespace,
    csharp_using_directive_target_node, normalize_csharp_type_fragment,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};

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
    /// The retained facts cannot close the lookup, for this explicit reason.
    Unknown(SemanticDiagnosticIncompleteReason),
}

/// The retained evidence for one external namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpExternalNamespace {
    /// A retained TypeDef declares this namespace.
    Declared,
    /// Complete provider evidence has neither a declaration nor a forward here.
    Absent,
    /// A forward or unreadable provider prevents proving the namespace absent.
    Unknown(SemanticDiagnosticIncompleteReason),
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
/// A miss proves absence only when every possible provider was read and none
/// declares or forwards a candidate name. Missing readers, unreadable forward
/// tables and unbuilt indexes are Unknown. Native answers map onto the same
/// declared/resolved, absent, and unknown states.
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
    fn declares_namespace(&self, namespace: &str) -> CSharpExternalNamespace;

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
    token: QueryToken<'_>,
    external: &dyn CSharpExternalEvidence,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_CSHARP_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some((tree, scan)) = crate::preprocessor::parse_csharp_scanned(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "C# source did not parse".to_string(),
            }],
        );
        return report;
    };
    if scan
        .conditional_regions(source)
        .has_uncertain_omission(0..source.len())
    {
        // An undecided omitted branch can contain declarations this reading
        // never saw. Decided exclusions carry no such obligation.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: crate::preprocessor::CSHARP_INACTIVE_BRANCHES_DETAIL.to_string(),
            }],
        );
    }
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
        usings: file_using_namespaces(csharp, file),
        scope_is_visible: true,
        type_parameters: Vec::new(),
        partial_declarations: HashSet::default(),
        visible_types: CaptureScopedMemo::default(),
        report,
        diagnostic_count: 0,
    };
    // The `using` directives are checked first and in one pass: whether the
    // namespaces a file opens are all visible decides whether an unqualified
    // reference that misses everywhere was checked against a complete surface.
    collector.check_using_directives(token, &tree);
    collector.collect_partial_declarations(&tree);
    collector.scan_tree(token, tree.root_node());
    collector.report
}

/// Every namespace a file opens: its own `using` directives plus the workspace's
/// `global using` ones, which C# applies to every file in the compilation.
fn file_using_namespaces(csharp: &dyn CSharpSource, file: &ProjectFile) -> Vec<String> {
    // The source contract already includes global using namespaces.
    let usings: BTreeSet<String> = csharp.using_namespaces_of(file).into_iter().collect();
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
    /// The visible-type search's answer for each spelling this request has
    /// already looked up.
    ///
    /// [`visible_type_candidates`] is a function of the analyzer generation, the
    /// file and the spelling, and a diagnostic request reads one fixed
    /// generation and one file, so the first answer is the only answer. The
    /// four ladders below -- type references, member owners, the enclosing-type
    /// lookup and the supertype walk -- each asked independently, so a file that
    /// names one type in ten positions searched the workspace ten times. That
    /// search costs a store query per candidate spelling per namespace it
    /// probes, which is what made repetition expensive rather than merely
    /// redundant (#1806).
    visible_types: CaptureScopedMemo<RefCell<HashMap<String, Vec<CodeUnit>>>>,
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
    /// A namespace qualifier has no value member surface to check.
    Namespace,
    /// A workspace declaration, at this fully qualified name.
    Workspace { fqn: String },
    /// An indexed assembly type, at this metadata identity.
    External { fqn: String },
}

fn unique_workspace_member_owner(candidates: &[CodeUnit]) -> Option<MemberOwner> {
    (logical_type_count(candidates) == 1)
        .then(|| first_logical_type_fqn(candidates))
        .flatten()
        .map(|fqn| MemberOwner::Workspace { fqn })
}

enum ScanFrame<'tree> {
    Node(Node<'tree>),
    ExitTypeParameters,
}

impl CSharpDiagnosticCollector<'_> {
    // -- using directives ---------------------------------------------------

    fn check_using_directives(&mut self, token: QueryToken<'_>, tree: &Tree) {
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
            if self.diagnostic_count >= MAX_CSHARP_SEMANTIC_DIAGNOSTICS {
                break;
            }
            self.check_using_directive(token, directive);
        }
    }

    fn check_using_directive(&mut self, token: QueryToken<'_>, node: Node<'_>) {
        let range = self.range_of(node);
        // The namespace form is read off the directive node, not off its text:
        // the parser already tells a plain `using` apart from `using static`
        // and `using A = X`.
        if let Some(namespace) = csharp_using_directive_namespace(node, self.source) {
            self.check_using_namespace(range, &namespace);
            return;
        }
        if csharp_using_directive_is_static(node) {
            // `using static X;` names a type whose static members the file
            // opens, so it is a type reference like any other.
            let Some(target) = csharp_using_directive_target_node(node) else {
                return;
            };
            self.check_type_identity(token, range, target);
            return;
        }
        let Some((_, target)) = csharp_using_alias_from_node(node, self.source) else {
            return;
        };
        // An alias target is either a namespace or a type, and C# accepts both
        // spellings. A namespace hit settles it; otherwise the type ladder does.
        let namespace_visible = match self.namespace_is_visible(&target) {
            Ok(visible) => visible,
            Err(reason) => {
                self.report.push_incomplete(Some(range), vec![reason]);
                return;
            }
        };
        if namespace_visible {
            self.report
                .push_resolved(range, self.namespace_boundary(&target));
            return;
        }
        if let Some(target) = csharp_using_directive_target_node(node) {
            self.check_type_identity(token, range, target);
        }
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
        match self.external.declares_namespace(namespace) {
            CSharpExternalNamespace::Declared => {
                self.report
                    .push_resolved(range, BoundaryStatus::ExternalIndexed);
                return;
            }
            CSharpExternalNamespace::Unknown(reason) => {
                self.scope_is_visible = false;
                self.report.push_incomplete(Some(range), vec![reason]);
                return;
            }
            CSharpExternalNamespace::Absent => {}
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

    fn namespace_is_visible(
        &self,
        namespace: &str,
    ) -> Result<bool, SemanticDiagnosticIncompleteReason> {
        if self.csharp.workspace_namespace_exists(namespace) {
            return Ok(true);
        }
        if self.unreadable_external.is_some() {
            // This is a namespace probe on a type-or-namespace spelling.
            // Leave the workspace type ladder available; it can still prove
            // an alias/static owner without any external evidence.
            return Ok(false);
        }
        match self.external.declares_namespace(namespace) {
            CSharpExternalNamespace::Declared => Ok(true),
            CSharpExternalNamespace::Absent => Ok(false),
            CSharpExternalNamespace::Unknown(reason) => Err(reason),
        }
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

    fn scan_tree(&mut self, token: QueryToken<'_>, root: Node<'_>) {
        let mut stack = vec![ScanFrame::Node(root)];
        while let Some(frame) = stack.pop() {
            if self.diagnostic_count >= MAX_CSHARP_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                break;
            }
            match frame {
                ScanFrame::Node(node) => self.scan_node(token, node, &mut stack),
                ScanFrame::ExitTypeParameters => {
                    self.type_parameters.pop();
                }
            }
        }
    }

    fn scan_node<'tree>(
        &mut self,
        token: QueryToken<'_>,
        node: Node<'tree>,
        stack: &mut Vec<ScanFrame<'tree>>,
    ) {
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
            self.check_member_access(token, node);
        } else if is_type_reference_position(node) {
            self.check_type_reference(token, node);
        }
        push_named_children_reversed_as(node, stack, ScanFrame::Node);
    }

    // -- type references ----------------------------------------------------

    fn check_type_reference(&mut self, token: QueryToken<'_>, node: Node<'_>) {
        self.check_type_identity(token, self.range_of(node), node);
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

    fn check_type_identity(&mut self, token: QueryToken<'_>, range: Range, node: Node<'_>) {
        let identity = csharp_type_node_identity(node, self.source);
        if self.is_uncheckable_type_identity(&identity) {
            return;
        }
        match self.workspace_types(token, &identity) {
            WorkspaceTypes::One => {
                self.report
                    .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            }
            WorkspaceTypes::Many { count } => {
                self.report
                    .push_ambiguous(range, vec![BoundaryStatus::WorkspaceLocal; count]);
            }
            WorkspaceTypes::None => self.check_external_type(range, &identity, node),
        }
    }

    /// The visible-type search for `identity`, answered once per request.
    ///
    /// The same helper `get_definition` resolves a C# type reference with, so a
    /// name this pass calls absent is one the definition route also fails to
    /// find.
    fn visible_types(&self, token: QueryToken<'_>, identity: &str) -> Vec<CodeUnit> {
        self.visible_types.read(
            &self.csharp.read_capability().memo_attribution(),
            |visible_types| {
                if let Some(known) = visible_types.borrow().get(identity) {
                    return known.clone();
                }
                let candidates = visible_type_candidates(self.csharp, token, self.file, identity);
                visible_types
                    .borrow_mut()
                    .insert(identity.to_string(), candidates.clone());
                candidates
            },
        )
    }

    fn workspace_types(&self, token: QueryToken<'_>, identity: &str) -> WorkspaceTypes {
        let candidates = self.visible_types(token, identity);
        match logical_type_count(&candidates) {
            0 => WorkspaceTypes::None,
            1 => WorkspaceTypes::One,
            count => WorkspaceTypes::Many { count },
        }
    }

    fn check_external_type(&mut self, range: Range, identity: &str, mut node: Node<'_>) {
        // Qualification belongs to this reference, not to the file's imports.
        // Wrapper nodes keep their referent's lookup scope.
        while matches!(
            node.kind(),
            "array_type"
                | "nullable_type"
                | "pointer_type"
                | "simple_base_type"
                | "primary_constructor_base_type"
        ) {
            node = node
                .child_by_field_name("type")
                .or_else(|| node.named_child(0))
                .expect("type wrapper referent");
        }
        let unqualified = matches!(node.kind(), "identifier" | "generic_name");
        if let Some(reason) = self.unreadable_external.clone() {
            self.report.push_incomplete(Some(range), vec![reason]);
            return;
        }
        match self.external.resolve_type(self.file, identity) {
            CSharpExternalTypes::Unknown(reason) => {
                self.report.push_incomplete(Some(range), vec![reason]);
            }
            CSharpExternalTypes::One { .. } => {
                self.report
                    .push_resolved(range, BoundaryStatus::ExternalIndexed);
            }
            CSharpExternalTypes::Many { count } => {
                self.report
                    .push_ambiguous(range, vec![BoundaryStatus::ExternalIndexed; count]);
            }
            CSharpExternalTypes::None => {
                let workspace_bounded = if unqualified {
                    match self.workspace_bounded() {
                        Ok(bounded) => bounded,
                        Err(reason) => {
                            self.report.push_incomplete(Some(range), vec![reason]);
                            return;
                        }
                    }
                } else {
                    false
                };
                if workspace_bounded {
                    // This identity also misses against retained external evidence.
                    // A fully local unqualified lookup scope can prove its absence.
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
    fn workspace_bounded(&self) -> Result<bool, SemanticDiagnosticIncompleteReason> {
        if !self.scope_is_visible || self.unreadable_external.is_some() {
            return Ok(false);
        }
        match self.external.declares_namespace("") {
            CSharpExternalNamespace::Declared => Ok(false),
            CSharpExternalNamespace::Absent => Ok(self
                .usings
                .iter()
                .all(|namespace| self.csharp.workspace_namespace_exists(namespace))),
            CSharpExternalNamespace::Unknown(reason) => Err(reason),
        }
    }

    /// Whether a miss against the indexed external surface is a proof.
    fn external_miss_is_proof(&self) -> bool {
        self.scope_is_visible
            && self.unreadable_external.is_none()
            && self.external.surface_is_known()
    }

    // -- member accesses ----------------------------------------------------

    fn check_member_access(&mut self, token: QueryToken<'_>, node: Node<'_>) {
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
        match self.member_owner(token, receiver, &receiver_identity) {
            Ok(MemberOwner::Namespace) => {}
            Ok(MemberOwner::Workspace { fqn }) => {
                self.check_workspace_member(token, node, range, &fqn, &member)
            }
            Ok(MemberOwner::External { fqn }) => {
                self.check_external_member(node, range, &fqn, &member)
            }
            Err(reason) => self.report.push_incomplete(Some(range), vec![reason]),
        }
    }

    /// Prove what a member access reads through, or say why this pass cannot.
    fn member_owner(
        &self,
        token: QueryToken<'_>,
        receiver: Node<'_>,
        receiver_identity: &str,
    ) -> Result<MemberOwner, SemanticDiagnosticIncompleteReason> {
        if matches!(
            receiver.kind(),
            "member_access_expression" | "parenthesized_expression"
        ) {
            // Follow the expression spine, not its dotted spelling. A value at
            // the root shadows a namespace or type with the same name for the
            // entire chain, even when a later field's type is unknown.
            let mut root = receiver;
            let mut members = Vec::new();
            loop {
                match root.kind() {
                    "member_access_expression" => {
                        let (Some(expression), Some(name)) = (
                            csharp_member_access_receiver(root),
                            root.child_by_field_name("name"),
                        ) else {
                            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                detail: "receiver member access has no complete C# structure"
                                    .to_string(),
                            });
                        };
                        members.push(name);
                        root = expression;
                    }
                    "parenthesized_expression" => {
                        let Some(inner) =
                            single_named_child_matching(root, |child| !child.is_extra())
                        else {
                            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                detail: "parenthesized receiver has no proven C# expression"
                                    .to_string(),
                            });
                        };
                        root = inner;
                    }
                    _ => break,
                }
            }
            let root_owner = match root.kind() {
                "identifier" => {
                    let symbol = csharp_identifier_text(root, self.source);
                    self.declared_type_of_binding(token, root, symbol)?
                        .map(|declared| self.declared_type_owner(token, root, symbol, declared))
                        .transpose()?
                }
                "this" | "this_expression" => Some(self.this_owner(token, root)?),
                _ => None,
            };
            if let Some(mut owner) = root_owner {
                for name in members.into_iter().rev() {
                    if name.kind() != "identifier" {
                        return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                            detail: format!(
                                "receiver member of kind `{}` has no proven C# type",
                                name.kind()
                            ),
                        });
                    }
                    let member = csharp_identifier_text(name, self.source);
                    owner = match owner {
                        MemberOwner::Workspace { fqn } => {
                            let unit = self.proved_workspace_type_unit(token, &fqn).ok_or_else(
                                || SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                    detail: format!(
                                        "receiver type `{fqn}` is unavailable for member `{member}`"
                                    ),
                                },
                            )?;
                            let declared = self.workspace_value_member_type(token, &unit, member, name)?
                                .ok_or_else(|| SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                    detail: format!("receiver member `{member}` on `{fqn}` has no proven declared type"),
                                })?;
                            self.declared_type_owner(token, name, member, declared)?
                        }
                        MemberOwner::External { fqn } => {
                            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                detail: format!(
                                    "receiver member `{member}` on external type `{fqn}` has no proven declared type"
                                ),
                            });
                        }
                        MemberOwner::Namespace => unreachable!("a value has a type owner"),
                    };
                }
                return Ok(owner);
            }
        }
        // `this` names the enclosing type, which is the one receiver whose type
        // needs no inference at all. The grammar spells it as the bare keyword
        // token inside a member access, and as `this_expression` elsewhere.
        if matches!(receiver.kind(), "this" | "this_expression") {
            return self.this_owner(token, receiver);
        }
        // A plain identifier is looked up as a value before it is looked up as
        // a type. That is C#'s own order for `E.I` -- the "Color Color" rule --
        // and getting it backwards would read `widget.Missing` against the type
        // named `widget` whenever a local shadows one, and report a member the
        // value does have as absent.
        if receiver.kind() == "identifier" {
            let symbol = receiver_identity;
            match self.declared_type_of_binding(token, receiver, symbol)? {
                // The seeder proved this identity against the workspace, so it
                // is looked up as an identity rather than re-read as a written
                // name.
                Some(declared) => {
                    return self.declared_type_owner(token, receiver, symbol, declared);
                }
                // Nothing binds the name as a value, so it may name a type and
                // this is a static access.
                None => {
                    if self.namespace_is_visible(symbol)? {
                        return Ok(MemberOwner::Namespace);
                    }
                    return self
                        .type_owner(token, symbol)?
                        .filter(|_| !self.is_uncheckable_type_identity(symbol))
                        .ok_or_else(
                            || SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                                detail: format!(
                                    "receiver `{symbol}` has no uniquely inferred declared type"
                                ),
                            },
                        );
                }
            }
        }
        // A qualified receiver can name either a type or a namespace.
        if !receiver_identity.is_empty() && self.namespace_is_visible(receiver_identity)? {
            return Ok(MemberOwner::Namespace);
        }
        if receiver_identity.is_empty() || self.is_uncheckable_type_identity(receiver_identity) {
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!(
                    "receiver expression of kind `{}` has no proven C# type",
                    receiver.kind()
                ),
            });
        }
        self.type_owner(token, receiver_identity)?.ok_or_else(|| {
            SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{receiver_identity}` has no uniquely resolved type"),
            }
        })
    }

    fn this_owner(
        &self,
        token: QueryToken<'_>,
        receiver: Node<'_>,
    ) -> Result<MemberOwner, SemanticDiagnosticIncompleteReason> {
        let classes = self.csharp.class_range_index(self.file);
        let Some(enclosing) = classes.enclosing_unit(receiver.start_byte()) else {
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "`this` has no proven enclosing type declaration".to_string(),
            });
        };
        self.resolved_type_owner(token, &enclosing.fq_name(), "this")
    }

    fn declared_type_owner(
        &self,
        token: QueryToken<'_>,
        receiver: Node<'_>,
        symbol: &str,
        declared: CSharpDeclaredType,
    ) -> Result<MemberOwner, SemanticDiagnosticIncompleteReason> {
        match declared {
            CSharpDeclaredType::Resolved { fqn } => self.resolved_type_owner(token, &fqn, symbol),
            CSharpDeclaredType::Spelling(spelling) => {
                if is_csharp_dynamic(&spelling) {
                    return Err(SemanticDiagnosticIncompleteReason::DynamicBehavior {
                        detail: format!("`{symbol}` is declared `dynamic`"),
                    });
                }
                if type_parameter_shadows_reference(receiver, self.source, &spelling) {
                    return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!("receiver `{symbol}` has type parameter `{spelling}`"),
                    });
                }
                self.type_owner(token, &spelling)?.ok_or_else(|| {
                    SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!("receiver `{symbol}` has no uniquely resolved type"),
                    }
                })
            }
        }
    }

    /// The declared type name of a local, parameter or field the receiver
    /// identifier binds.
    ///
    /// The seeder supplies only visible locals and parameters. If none binds
    /// the name, resolve a member through its indexed enclosing owner, which
    /// also sees fields declared after the method that reads them.
    fn declared_type_of_binding(
        &self,
        token: QueryToken<'_>,
        receiver: Node<'_>,
        symbol: &str,
    ) -> Result<Option<CSharpDeclaredType>, SemanticDiagnosticIncompleteReason> {
        let mut bindings = LocalInferenceEngine::<CSharpDeclaredType>::default();
        crate::graph::resolver::seed_bindings_before(
            file_root(receiver),
            receiver.start_byte(),
            self.csharp,
            token,
            self.file,
            self.source,
            &mut bindings,
        );
        if !bindings.is_shadowed(symbol) {
            let classes = self.csharp.class_range_index(self.file);
            return match classes.enclosing_unit(receiver.start_byte()) {
                Some(owner) => self.workspace_value_member_type(token, owner, symbol, receiver),
                None => Ok(None),
            };
        }
        let resolution = bindings.resolve_symbol(symbol);
        let Some(targets) = resolution.as_precise() else {
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{symbol}` has no uniquely inferred declared type"),
            });
        };
        let mut declared = targets.iter();
        match (declared.next(), declared.next()) {
            (Some(only), None) => {
                let written = visible_declared_type_node(receiver, self.source, symbol);
                if written
                    .is_none_or(|node| matches!(node.kind(), "nullable_type" | "implicit_type"))
                    && !self.is_proven_reference_type(token, only)
                {
                    return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "receiver `{symbol}` has no proven non-nullable value type"
                        ),
                    });
                }
                Ok(Some(only.clone()))
            }
            _ => Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("receiver `{symbol}` binds more than one declared type"),
            }),
        }
    }

    fn is_proven_reference_type(
        &self,
        token: QueryToken<'_>,
        declared: &CSharpDeclaredType,
    ) -> bool {
        let CSharpDeclaredType::Resolved { fqn } = declared else {
            return false;
        };
        let Some(unit) = self.proved_workspace_type_unit(token, fqn) else {
            return false;
        };
        let signatures = self.csharp.signature_metadata(&unit);
        !signatures.is_empty()
            && signatures.iter().all(|signature| {
                matches!(
                    signature.class_like_kind(),
                    Some(ClassLikeKind::Class | ClassLikeKind::Interface)
                )
            })
    }

    /// A uniquely declared field or property can carry a value through one
    /// receiver step. A missing or ambiguous type remains incomplete, rather
    /// than allowing the caller to reinterpret that value as a namespace.
    fn workspace_value_member_type(
        &self,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        member: &str,
        site: Node<'_>,
    ) -> Result<Option<CSharpDeclaredType>, SemanticDiagnosticIncompleteReason> {
        let owner_fqn = owner.fq_name();
        let unproved = || SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: format!(
                "receiver member `{member}` on `{owner_fqn}` has no uniquely proven declared type"
            ),
        };
        let graph = CSharpGraphSource::from_source(self.csharp);
        let candidates = nearest_member_candidates_for_owner_inner(
            &graph,
            self.csharp,
            token,
            owner,
            member,
            None,
            None,
            false,
            None,
        );
        if candidates.is_empty() {
            return match self.inherited_member(token, &owner_fqn, member) {
                InheritedMember::Absent => Ok(None),
                InheritedMember::Found { .. } | InheritedMember::IncompleteSurface { .. } => {
                    Err(unproved())
                }
            };
        }
        let [candidate] = candidates.as_slice() else {
            return Err(unproved());
        };
        if !candidate.is_field() {
            return Err(unproved());
        }
        let declaring = self
            .csharp
            .parent_of(candidate)
            .expect("a nearest C# member has a declaring owner");
        if declaring.fq_name() != owner_fqn {
            let declaring_signatures = self.csharp.signature_metadata(&declaring);
            if declaring_signatures.is_empty()
                || declaring_signatures
                    .iter()
                    .any(|signature| signature.class_like_kind().is_none())
            {
                return Err(unproved());
            }
            if declaring_signatures
                .iter()
                .any(|signature| signature.class_like_kind() == Some(ClassLikeKind::Interface))
            {
                let owner_signatures = self.csharp.signature_metadata(owner);
                if owner_signatures.is_empty()
                    || owner_signatures.iter().any(|signature| {
                        signature.class_like_kind() != Some(ClassLikeKind::Interface)
                    })
                {
                    // A default interface member is not a member of the class
                    // that implements it. It can type a receiver only when the
                    // receiver itself has an interface type.
                    return Err(unproved());
                }
                // An external interface at the same or a nearer level could
                // declare a competing property. A single direct workspace
                // base is the inherited-interface case this view can prove.
                let bases = self.csharp.raw_supertypes_of(owner);
                let direct = self.csharp.direct_ancestors_through(self.csharp, owner);
                if bases.len() != 1
                    || logical_type_count(&direct) != 1
                    || !direct
                        .iter()
                        .any(|base| base.fq_name() == declaring.fq_name())
                {
                    return Err(unproved());
                }
            }
            // An empty identifier cannot match a member. This existing surface
            // walk must therefore finish every base before an inherited member
            // can supply a type; an unknown base might hide that member.
            match self.inherited_member(token, &owner_fqn, "") {
                InheritedMember::Absent => {}
                InheritedMember::IncompleteSurface { .. } => return Err(unproved()),
                InheritedMember::Found { .. } => unreachable!("C# member names are nonempty"),
            }
        }
        let metadata = self.csharp.signature_metadata(candidate);
        if metadata.is_empty() {
            return Err(unproved());
        }
        for row in &metadata {
            let Some(identity) = row.return_type_identity() else {
                return Err(unproved());
            };
            if identity.is_array() || identity.is_pointer() || identity.is_reference() {
                return Err(unproved());
            }
            let Some(name) = identity.nominal_name() else {
                return Err(unproved());
            };
            if let [identifier] = name.path()
                && !name.is_absolute()
            {
                let mut enclosing = Some(declaring.clone());
                while let Some(unit) = enclosing {
                    if unit.is_class() {
                        let signatures = self.csharp.signature_metadata(&unit);
                        if signatures.is_empty()
                            || signatures.iter().any(|signature| {
                                !signature.type_parameters_recorded()
                                    || signature.type_parameters().contains(identifier)
                            })
                        {
                            return Err(unproved());
                        }
                    }
                    enclosing = self.csharp.parent_of(&unit);
                }
            }
        }
        if candidate.source() == self.file {
            let ranges = self.csharp.ranges(candidate);
            if ranges.is_empty() {
                return Err(unproved());
            }
            let mut resolved = None;
            for range in ranges {
                let mut node =
                    node_for_exact_range(file_root(site), &range).ok_or_else(unproved)?;
                let type_node = loop {
                    if matches!(node.kind(), "variable_declaration" | "property_declaration") {
                        break node.child_by_field_name("type").ok_or_else(unproved)?;
                    }
                    if matches!(
                        node.kind(),
                        "class_declaration" | "struct_declaration" | "interface_declaration"
                    ) {
                        return Err(unproved());
                    }
                    node = node.parent().ok_or_else(unproved)?;
                };
                let fqn =
                    resolve_type_fq_name_of_node(self.csharp, self.file, self.source, type_node)
                        .ok_or_else(unproved)?;
                if type_node.kind() == "nullable_type"
                    && !self
                        .is_proven_reference_type(token, &CSharpDeclaredType::resolved(fqn.clone()))
                {
                    return Err(unproved());
                }
                if resolved.as_ref().is_some_and(|previous| previous != &fqn) {
                    return Err(unproved());
                }
                resolved = Some(fqn);
            }
            return Ok(resolved.map(CSharpDeclaredType::resolved));
        }

        let session = ResolutionSession::unbounded();
        let resolved = member_declared_type_fq_name_in_session(
            self.csharp,
            token,
            self.file,
            owner,
            member,
            &session,
        );
        let BoundedResolution::Complete {
            value: Some(fqn), ..
        } = session.finish(resolved)
        else {
            return Err(unproved());
        };
        let declared = CSharpDeclaredType::resolved(fqn);
        // The persisted nominal identity drops `?`, so a cross-file value type
        // does not prove whether the field is nullable.
        if !self.is_proven_reference_type(token, &declared) {
            return Err(unproved());
        }
        if let CSharpDeclaredType::Resolved { fqn } = &declared {
            let target = self
                .proved_workspace_type_unit(token, fqn)
                .ok_or_else(unproved)?;
            let namespace = target.package_name();
            let declaration_namespace = declaring.package_name();
            if !namespace.is_empty()
                && namespace != declaration_namespace
                && !declaration_namespace
                    .strip_prefix(namespace)
                    .is_some_and(|suffix| suffix.starts_with('.'))
                && !metadata.iter().all(|row| {
                    row.return_type_identity()
                        .and_then(|identity| identity.nominal_name())
                        .is_some_and(|name| {
                            name.is_absolute()
                                || name.path().join(".") == csharp_arity_preserving_full_name(fqn)
                        })
                })
            {
                return Err(unproved());
            }
        }
        Ok(Some(declared))
    }

    /// The declaration a receiver's already-resolved type identity names.
    ///
    /// Looked up absolutely, through the ladder's own `global::` branch and the
    /// request-scoped memo behind it. The seeder proved this identity in this
    /// same request and analyzer generation, so re-running the relative
    /// visible-name ladder over it could bind a *different* type -- a file in
    /// namespace `A.B` re-qualifies `A.B.Widget` into `A.B.A.B.Widget` -- and
    /// re-paid an ancestor-namespace probe walk per member access (#1842).
    ///
    /// A proved identity never reaches external resolution: the workspace holds
    /// the declaration it names, or this request cannot say what it names.
    fn resolved_type_owner(
        &self,
        token: QueryToken<'_>,
        fqn: &str,
        symbol: &str,
    ) -> Result<MemberOwner, SemanticDiagnosticIncompleteReason> {
        let candidates = self.visible_types(token, &format!("global::{fqn}"));
        // The seeder resolved this fq name against the same generation this
        // lookup reads, so it names exactly one logical declaration.
        debug_assert_eq!(
            logical_type_count(&candidates),
            1,
            "resolved receiver type `{fqn}` looked up as {candidates:?}"
        );
        if let Some(owner) = unique_workspace_member_owner(&candidates) {
            return Ok(owner);
        }
        Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: format!("receiver `{symbol}` has no uniquely resolved type"),
        })
    }

    /// The unique declaration a type name identifies, workspace first.
    fn type_owner(
        &self,
        token: QueryToken<'_>,
        identity: &str,
    ) -> Result<Option<MemberOwner>, SemanticDiagnosticIncompleteReason> {
        let candidates = self.visible_types(token, identity);
        if let Some(owner) = unique_workspace_member_owner(&candidates) {
            return Ok(Some(owner));
        }
        if !candidates.is_empty() {
            return Ok(None);
        }
        if let Some(reason) = &self.unreadable_external {
            return Err(reason.clone());
        }
        match self.external.resolve_type(self.file, identity) {
            CSharpExternalTypes::One { fqn } => Ok(Some(MemberOwner::External { fqn })),
            CSharpExternalTypes::None | CSharpExternalTypes::Many { .. } => Ok(None),
            CSharpExternalTypes::Unknown(reason) => Err(reason),
        }
    }

    fn check_workspace_member(
        &mut self,
        token: QueryToken<'_>,
        node: Node<'_>,
        range: Range,
        owner_fqn: &str,
        member: &str,
    ) {
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
        match self.inherited_member(token, owner_fqn, member) {
            InheritedMember::Found { boundary } => self.report.push_resolved(range, boundary),
            InheritedMember::IncompleteSurface { detail } => self.report.push_incomplete(
                Some(range),
                vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }],
            ),
            InheritedMember::Absent => {
                self.publish_member_absence(
                    node,
                    range,
                    owner_fqn,
                    member,
                    BoundaryStatus::WorkspaceLocal,
                );
            }
        }
    }

    fn check_external_member(
        &mut self,
        node: Node<'_>,
        range: Range,
        owner_fqn: &str,
        member: &str,
    ) {
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
                    node,
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
        node: Node<'_>,
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
        let extension_possible = match self.extension_method_could_apply(node, member) {
            Ok(possible) => possible,
            Err(reason) => {
                self.report.push_incomplete(Some(range), vec![reason]);
                return;
            }
        };
        if extension_possible {
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
    fn extension_method_could_apply(
        &self,
        node: Node<'_>,
        member: &str,
    ) -> Result<bool, SemanticDiagnosticIncompleteReason> {
        let context = CSharpLookupContext::at(self.source, node, || true)
            .expect("an unbounded C# lexical lookup completes");
        let mut namespaces = self.usings.clone();
        namespaces.extend(context.namespaces().map(str::to_string));
        if !self.workspace_bounded()?
            && (self.unreadable_external.is_some()
                || self
                    .external
                    .could_supply_extension_method(&namespaces, member))
        {
            return Ok(true);
        }
        Ok(self
            .csharp
            .declaration_candidates_by_identifier(member)
            .iter()
            .any(|candidate| {
                candidate.is_function()
                    && namespaces
                        .iter()
                        .any(|namespace| candidate.package_name() == namespace.as_str())
            }))
    }

    /// Walk the owner's ancestors for `member`.
    fn inherited_member(
        &self,
        token: QueryToken<'_>,
        owner_fqn: &str,
        member: &str,
    ) -> InheritedMember {
        let owner = InheritedTypeName::Proved(owner_fqn.to_string());
        let mut seen = HashSet::from_iter([owner.clone()]);
        let mut queue = vec![owner];
        while let Some(current) = queue.pop() {
            let unit = match &current {
                InheritedTypeName::Proved(fqn) => {
                    let Some(unit) = self.proved_workspace_type_unit(token, fqn) else {
                        // This identity was resolved in the same analyzer
                        // generation. Losing it is an internal inconsistency,
                        // never evidence that the chain left the workspace.
                        return InheritedMember::IncompleteSurface {
                            detail: format!(
                                "proved ancestor `{fqn}` of `{owner_fqn}` is unavailable in the current workspace generation"
                            ),
                        };
                    };
                    unit
                }
                InheritedTypeName::Spelled(raw) => {
                    // This spelling was already searched relative to the
                    // declaring workspace type and proved absent there. Only
                    // the retained external surface can continue the chain.
                    if let Some(reason) = &self.unreadable_external {
                        return InheritedMember::IncompleteSurface {
                            detail: format!(
                                "ancestor `{raw}` of `{owner_fqn}` is outside the workspace and {}",
                                describe_reason(reason)
                            ),
                        };
                    }
                    match self.external.resolve_member(raw, member) {
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
                }
            };
            for raw in self.csharp.raw_supertypes_of(&unit) {
                let candidates = self.visible_types(token, &raw);
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
                        let proved = InheritedTypeName::Proved(fqn);
                        if seen.insert(proved.clone()) {
                            queue.push(proved);
                        }
                    }
                    0 => {
                        // A supertype that resolves nowhere in the workspace is
                        // either an indexed assembly type or an unknown one.
                        // Either way the chain continues outside, so hand the
                        // raw name to the next turn of the loop.
                        let spelled = InheritedTypeName::Spelled(raw);
                        if seen.insert(spelled.clone()) {
                            queue.push(spelled);
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

    fn proved_workspace_type_unit(&self, token: QueryToken<'_>, fqn: &str) -> Option<CodeUnit> {
        let candidates = self.visible_types(token, &format!("global::{fqn}"));
        debug_assert_eq!(
            logical_type_count(&candidates),
            1,
            "proved inherited type `{fqn}` looked up as {candidates:?}"
        );
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
        push_absent_diagnostic(
            &mut self.report,
            &mut self.diagnostic_count,
            SemanticAbsenceProof {
                range,
                domain,
                boundary,
            },
            CSHARP_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind,
            message,
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

/// A type identity already proved in the workspace is not interchangeable
/// with an unresolved source spelling. Only spellings may cross into the
/// retained external surface; proved identities always round-trip absolutely.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum InheritedTypeName {
    Proved(String),
    Spelled(String),
}

fn describe_reason(reason: &SemanticDiagnosticIncompleteReason) -> String {
    match reason {
        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary } => {
            format!("the assembly index is unreadable at {boundary:?}")
        }
        other => format!("the assembly index is unreadable: {other:?}"),
    }
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
/// pointers to the type they decorate. A `ref_type` has no dotted identity;
/// its `type` child supplies the one reference site instead.
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
        "array_type" | "nullable_type" | "pointer_type" => false,
        "ref_type" | "type_argument_list" | "base_list" => true,
        _ => ["type", "returns"].iter().any(|field| {
            parent
                .child_by_field_name(field)
                .is_some_and(|typed| same_node(typed, node))
        }),
    }
}

/// The name of the type declaration `node` sits in.
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

#[cfg(test)]
mod type_position_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: ref return referents had no diagnostic type position"
    )]
    fn grammar_type_positions_cover_wrappers_arguments_and_bases_once() {
        let source = "class C : MissingBase { Missing[] a; Missing? b; Missing* c; ref Missing M() { throw null; } Box<Missing> d; }";
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut positions = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if is_type_reference_position(node) {
                positions.push((node.kind(), node_text(node, source)));
            }
            for i in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(i).unwrap());
            }
        }
        assert_eq!(
            positions,
            [
                ("identifier", "MissingBase"),
                ("array_type", "Missing[]"),
                ("nullable_type", "Missing?"),
                ("pointer_type", "Missing*"),
                ("identifier", "Missing"),
                ("generic_name", "Box<Missing>"),
                ("identifier", "Missing")
            ]
        );
    }
}
