//! PHP's semantic diagnostics: conservative unresolved-reference reporting.
//!
//! The analyzer facts this needs are the [`PhpSource`] the rest of the
//! crate already takes, the dispatching analyzer's `CodeUnitIndex`, and a
//! [`BoundedDefinitionLookup`] for "is this fqn indexed".
//! `analyzer/php/diagnostics.rs` in `brokk-bifrost-analysis` keeps the downcast
//! that produces them, and the analyzer-bound fixture suite that exercises them.

use crate::aliases::{
    PhpFileContext, resolve_php_constant, resolve_php_function, resolve_php_type,
};
use crate::external_surface::{PhpExternalMember, PhpExternalSurface, PhpExternalSymbol};
use crate::graph_support::{
    PhpSource, php_direct_declared_class_parent, php_file_context_from_source,
};
use brokk_bifrost_core::analyzer::model::{Range, SemanticDiagnostic};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile, SemanticAbsenceProof,
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

pub const PHP_UNRECOGNIZED_SYMBOL: &str = "php_unrecognized_symbol";
pub const PHP_UNRECOGNIZED_MEMBER: &str = "php_unrecognized_member";
pub const PHP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-php";
const MAX_PHP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_PHP_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpSemanticDiagnostic {
    pub range: Range,
    pub kind: &'static str,
    pub message: String,
}

impl From<PhpSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: PhpSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: PHP_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Proof-gated PHP unresolved-reference diagnostics.
///
/// Every reference this pass visits produces a typed outcome. A name resolves
/// in the workspace or in an indexed Composer pack, it is proved absent from a
/// surface that was complete enough to prove it, or the lookup reports the
/// typed reason it could not finish. Dynamic PHP behavior -- a variable class
/// name, a variable function or member name, a magic `__call` or `__get` owner
/// -- is recorded as incomplete rather than passed over in silence.
///
/// This function reads only retained analyzer state. It never starts dependency
/// discovery and never touches a vendor tree.
pub fn collect_php_semantic_diagnostics(
    php: &dyn PhpSource,
    index: &dyn CodeUnitIndex,
    support: &dyn BoundedDefinitionLookup,
    external: &dyn PhpExternalSurface,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_PHP_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "PHP parser is unavailable".to_owned(),
            }],
        );
        return report;
    }
    let Some(tree) = parser.parse(source, None) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "PHP source did not parse".to_owned(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // A malformed file belongs to the parse-diagnostic path. The semantic
        // report records that this file could not be judged, so an empty
        // result is not mistaken for clean.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "PHP source has parse errors".to_string(),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let ctx = php_file_context_from_source(php, file, source);
    let mut collector = PhpDiagnosticCollector {
        php,
        index,
        support,
        external,
        file,
        source,
        line_starts: &line_starts,
        ctx,
        report,
        published: 0,
        truncated: false,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

struct PhpDiagnosticCollector<'a> {
    php: &'a dyn PhpSource,
    index: &'a dyn CodeUnitIndex,
    support: &'a dyn BoundedDefinitionLookup,
    external: &'a dyn PhpExternalSurface,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    ctx: PhpFileContext,
    report: SemanticDiagnosticReport,
    /// Published errors, which is what the cap bounds. Resolved and incomplete
    /// outcomes are cheap and are not limited.
    published: usize,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    Type,
    Function,
    Constant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberAccessKind {
    InstanceCall,
    InstanceProperty,
    StaticCall,
    StaticProperty,
    ClassConstant,
}

impl PhpDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut scopes = vec![root];
        while let Some(scope) = scopes.pop() {
            if self.at_capacity() {
                break;
            }
            let mut bindings = LocalInferenceEngine::default();
            if is_local_scope(scope) {
                seed_parameter_types(scope, self.source, &self.ctx, &mut bindings);
            }
            self.scan_scope(scope, &mut bindings, &mut scopes);
        }
    }

    fn scan_scope<'tree>(
        &mut self,
        root: Node<'tree>,
        bindings: &mut LocalInferenceEngine<String>,
        scopes: &mut Vec<Node<'tree>>,
    ) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.at_capacity() {
                break;
            }
            if node != root && is_local_scope(node) {
                scopes.push(node);
                continue;
            }
            self.scan_node(node, bindings, &mut stack);
        }
    }

    fn scan_node<'tree>(
        &mut self,
        node: Node<'tree>,
        bindings: &mut LocalInferenceEngine<String>,
        stack: &mut Vec<Node<'tree>>,
    ) {
        if is_non_reference_container(node) {
            return;
        }
        self.seed_assignment(node, bindings);
        self.check_reference(node, bindings);
        push_named_children(stack, node);
    }

    fn seed_assignment(&self, node: Node<'_>, bindings: &mut LocalInferenceEngine<String>) {
        let Some((left, right)) = assignment_parts(node) else {
            return;
        };
        if left.kind() != "variable_name" {
            return;
        }
        let name = variable_identifier(left, self.source);
        if name.is_empty() {
            return;
        }
        match receiver_type_from_expression(right, self.source, &self.ctx, bindings) {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => {
                if right.kind() == "variable_name" {
                    let rhs = variable_identifier(right, self.source);
                    if !rhs.is_empty() {
                        bindings.alias_symbol(name.to_string(), rhs);
                        return;
                    }
                }
                bindings.declare_shadow(name.to_string());
            }
        }
    }

    fn check_reference(&mut self, node: Node<'_>, bindings: &LocalInferenceEngine<String>) {
        match node.kind() {
            "object_creation_expression" => match object_creation_type(node) {
                Some(type_node) => self.check_symbol(type_node, SymbolKind::Type),
                // `new $className()` names its class at run time.
                None => self.push_dynamic(node, "PHP object creation names its class at run time"),
            },
            "named_type" => {
                let raw = qualified_candidate_text(node, self.source);
                if !is_builtin_php_type(&raw) && !is_in_object_creation(node) {
                    self.check_symbol(node, SymbolKind::Type);
                }
            }
            "function_call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    if matches!(function.kind(), "name" | "qualified_name") {
                        self.check_symbol(function, SymbolKind::Function);
                    } else if function.kind() == "variable_name" {
                        // `$callable()` names its callee at run time.
                        self.push_dynamic(function, "PHP call names its callable at run time");
                    }
                }
            }
            "class_constant_access_expression"
            | "scoped_call_expression"
            | "scoped_property_access_expression" => {
                self.check_static_member(node);
            }
            "member_call_expression" | "member_access_expression" => {
                self.check_instance_member(node, bindings);
            }
            "name" | "qualified_name" => {
                if is_instanceof_type_name(node) {
                    self.check_symbol(node, SymbolKind::Type);
                } else if is_bare_constant_reference(node) {
                    self.check_symbol(node, SymbolKind::Constant);
                }
            }
            _ => {}
        }
    }

    fn check_symbol(&mut self, node: Node<'_>, kind: SymbolKind) {
        if is_declaration_name(node) || is_non_reference_context(node) {
            return;
        }
        let raw = qualified_candidate_text(node, self.source);
        if raw.is_empty() {
            return;
        }
        let range = node_range(node, self.line_starts);
        if is_dynamic_php_name(&raw) {
            self.push_dynamic_range(range, &format!("PHP name `{raw}` is chosen at run time"));
            return;
        }
        // A built-in language type, function, or constant is part of the PHP
        // runtime surface rather than any indexed package.
        if matches!(kind, SymbolKind::Type) && is_builtin_php_type(&raw) {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if matches!(kind, SymbolKind::Function) && is_builtin_php_function(&raw) {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if matches!(kind, SymbolKind::Constant) && is_builtin_php_constant(&raw) {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if matches!(kind, SymbolKind::Function | SymbolKind::Constant)
            && is_unqualified_php_name(&raw)
        {
            // PHP falls back to the global namespace for an unqualified
            // function or constant. Bifrost does not index the whole built-in
            // global surface, so this lookup is unfinished, not absent.
            self.push_missing_discovery(range, BoundaryStatus::ExternalUnknown);
            return;
        }
        let fqn = match kind {
            SymbolKind::Type => resolve_php_type(&raw, &self.ctx),
            SymbolKind::Function => resolve_php_function(&raw, &self.ctx),
            SymbolKind::Constant => resolve_php_constant(&raw, &self.ctx),
        };
        let Some(fqn) = fqn else {
            return;
        };
        if !self.support.fqn(&fqn).is_empty() {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        match self.external.lookup_type(&fqn) {
            PhpExternalSymbol::Indexed { .. } => {
                self.report
                    .push_resolved(range, BoundaryStatus::ExternalIndexed);
                return;
            }
            // Two Composer packages can install the same class name. Naming the
            // conflict is honest; picking a winner would not be.
            PhpExternalSymbol::Ambiguous => {
                self.report.push_ambiguous(
                    range,
                    vec![
                        BoundaryStatus::ExternalIndexed,
                        BoundaryStatus::ExternalIndexed,
                    ],
                );
                return;
            }
            PhpExternalSymbol::Absent => {}
        }
        let label = match kind {
            SymbolKind::Type => "type",
            SymbolKind::Function => "function",
            SymbolKind::Constant => "constant",
        };
        let diagnostic = SemanticDiagnostic {
            range,
            source: PHP_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: PHP_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized PHP {label} `{raw}`"),
        };
        let namespace = diagnostic_namespace(&fqn);
        let domain = match kind {
            SymbolKind::Type => SemanticDiagnosticDomain::Type { name: fqn.clone() },
            // A namespaced function or constant is a member of its namespace,
            // and the namespace surface is what the lookup checked.
            SymbolKind::Function | SymbolKind::Constant => SemanticDiagnosticDomain::Module {
                name: namespace.clone(),
            },
        };
        if self.fqn_is_workspace_bounded(&fqn) {
            self.publish_absence(range, domain, BoundaryStatus::WorkspaceLocal, diagnostic);
            return;
        }
        // Completeness is checked before declaration, because the two are not
        // exclusive: the build declares an indexed package too. Asking
        // "declared?" first would let every fully indexed package fall into
        // `ExternalDeclaredUnindexed` and never prove anything absent.
        if self.external.namespace_surface_is_complete(&namespace) {
            self.publish_absence(range, domain, BoundaryStatus::ExternalIndexed, diagnostic);
            return;
        }
        if self.external.declares_unindexed(&fqn) {
            self.push_missing_discovery(range, BoundaryStatus::ExternalDeclaredUnindexed);
            return;
        }
        self.push_unknown_boundary(range);
    }

    fn check_static_member(&mut self, node: Node<'_>) {
        let Some((scope, member)) = static_member_parts(node) else {
            return;
        };
        let Some(member_name) = static_member_identifier(node, member, self.source) else {
            // `Owner::$$name` and `Owner::{$name}` choose the member at run time.
            self.push_dynamic(member, "PHP static member is named at run time");
            return;
        };
        if member_name.is_empty() {
            return;
        }
        let owner = self.static_scope_fqn(scope);
        // An owner the workspace does not declare may still be an indexed
        // Composer type, in which case the member check can continue against
        // the external surface.
        let owner_is_known = owner.as_deref().is_some_and(|owner| {
            self.support.fqn_exists(owner)
                || !matches!(self.external.lookup_type(owner), PhpExternalSymbol::Absent)
        });
        if !owner_is_known {
            self.check_symbol(scope, SymbolKind::Type);
            return;
        }
        let kind = match node.kind() {
            "scoped_call_expression" => MemberAccessKind::StaticCall,
            "scoped_property_access_expression" => MemberAccessKind::StaticProperty,
            "class_constant_access_expression" => MemberAccessKind::ClassConstant,
            _ => return,
        };
        self.check_member(member, owner, member_name, kind);
    }

    fn check_instance_member(&mut self, node: Node<'_>, bindings: &LocalInferenceEngine<String>) {
        let (Some(object), Some(member)) = (
            node.child_by_field_name("object"),
            node.child_by_field_name("name"),
        ) else {
            return;
        };
        let Some(member_name) = literal_member_identifier(member, self.source) else {
            // `$object->$name()` chooses the member at run time.
            self.push_dynamic(member, "PHP instance member is named at run time");
            return;
        };
        if member_name.is_empty() {
            return;
        }
        let owner = if object.kind() == "variable_name"
            && variable_identifier(object, self.source) == "this"
        {
            self.enclosing_owner_fqn(object)
        } else {
            receiver_type_from_expression(object, self.source, &self.ctx, bindings)
        };
        let kind = match node.kind() {
            "member_call_expression" => MemberAccessKind::InstanceCall,
            "member_access_expression" => MemberAccessKind::InstanceProperty,
            _ => return,
        };
        self.check_member(member, owner, member_name, kind);
    }

    fn check_member(
        &mut self,
        member_node: Node<'_>,
        owner: Option<String>,
        member_name: &str,
        kind: MemberAccessKind,
    ) {
        let range = node_range(member_node, self.line_starts);
        let Some(owner) = owner else {
            // The receiver's type is not statically known, so there is no owner
            // surface to check the member against.
            self.push_dynamic_range(range, "PHP receiver type is not statically known");
            return;
        };
        let diagnostic = SemanticDiagnostic {
            range,
            source: PHP_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: PHP_UNRECOGNIZED_MEMBER,
            message: format!("Unrecognized PHP member `{member_name}` on `{owner}`"),
        };
        let domain = SemanticDiagnosticDomain::MemberSurface {
            owner: owner.clone(),
            member: member_name.to_owned(),
        };

        if self.support.fqn_exists(&owner) {
            if self.class_has_trait_use(&owner) || self.has_magic_member_boundary(&owner, kind) {
                self.push_dynamic_range(
                    range,
                    &format!("PHP owner `{owner}` resolves members at run time"),
                );
                return;
            }
            let fqn = format!("{owner}.{member_name}");
            if !self.support.fqn(&fqn).is_empty()
                || !self
                    .inherited_member_candidates(&owner, member_name)
                    .is_empty()
            {
                self.report
                    .push_resolved(range, BoundaryStatus::WorkspaceLocal);
                return;
            }
            if self.fqn_is_workspace_bounded(&owner) {
                self.publish_absence(range, domain, BoundaryStatus::WorkspaceLocal, diagnostic);
            } else {
                self.push_unknown_boundary(range);
            }
            return;
        }

        // An external owner. A member is provable only when the owner resolved
        // uniquely and the packs published its whole inherited surface.
        match self.external.lookup_type(&owner) {
            PhpExternalSymbol::Indexed { id } => {
                match self.external.lookup_member(&id, member_name) {
                    PhpExternalMember::Indexed => {
                        self.report
                            .push_resolved(range, BoundaryStatus::ExternalIndexed);
                    }
                    PhpExternalMember::Ambiguous => {
                        self.report.push_ambiguous(
                            range,
                            vec![
                                BoundaryStatus::ExternalIndexed,
                                BoundaryStatus::ExternalIndexed,
                            ],
                        );
                    }
                    PhpExternalMember::Absent => {
                        self.publish_absence(
                            range,
                            domain,
                            BoundaryStatus::ExternalIndexed,
                            diagnostic,
                        );
                    }
                    PhpExternalMember::Unproven { detail } => self.push_unproven(range, detail),
                }
            }
            PhpExternalSymbol::Ambiguous => {
                self.report.push_ambiguous(
                    range,
                    vec![
                        BoundaryStatus::ExternalIndexed,
                        BoundaryStatus::ExternalIndexed,
                    ],
                );
            }
            PhpExternalSymbol::Absent => {
                if self.external.declares_unindexed(&owner) {
                    self.push_missing_discovery(range, BoundaryStatus::ExternalDeclaredUnindexed);
                } else {
                    self.push_unknown_boundary(range);
                }
            }
        }
    }

    fn inherited_member_candidates(&self, owner_fqn: &str, member: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        let mut level = self.direct_parent_fqns(owner_fqn);
        seen.insert(owner_fqn.to_string());
        while !level.is_empty() {
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                let candidate = format!("{ancestor}.{member}");
                if self.support.fqn_exists(&candidate) {
                    out.push(candidate);
                }
                next_level.extend(self.direct_parent_fqns(&ancestor));
            }
            if !out.is_empty() {
                return out;
            }
            level = next_level;
        }
        out
    }

    fn direct_parent_fqns(&self, owner_fqn: &str) -> Vec<String> {
        self.support
            .fqn(owner_fqn)
            .into_iter()
            .filter_map(|child| php_direct_declared_class_parent(self.php, &child))
            .map(|parent| parent.fq_name())
            .filter(|parent| self.support.fqn_exists(parent))
            .collect()
    }

    fn static_scope_fqn(&self, scope: Node<'_>) -> Option<String> {
        let text = node_text(scope, self.source);
        match text {
            "self" | "static" => self.enclosing_owner_fqn(scope),
            "parent" => {
                let owner = self.enclosing_owner_fqn(scope)?;
                let child = self.support.fqn(&owner).into_iter().next()?;
                php_direct_declared_class_parent(self.php, &child).map(|parent| parent.fq_name())
            }
            _ => resolve_php_type(text, &self.ctx),
        }
    }

    fn has_magic_member_boundary(&self, owner_fqn: &str, kind: MemberAccessKind) -> bool {
        let magic = match kind {
            MemberAccessKind::InstanceCall => Some("__call"),
            MemberAccessKind::InstanceProperty => Some("__get"),
            MemberAccessKind::StaticCall => Some("__callStatic"),
            MemberAccessKind::StaticProperty | MemberAccessKind::ClassConstant => None,
        };
        magic.is_some_and(|name| self.owner_or_ancestor_has_member(owner_fqn, name))
    }

    fn owner_or_ancestor_has_member(&self, owner_fqn: &str, member: &str) -> bool {
        let mut seen = HashSet::default();
        let mut level = vec![owner_fqn.to_string()];
        while !level.is_empty() {
            let mut next_level = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                if self.support.fqn_exists(&format!("{owner}.{member}")) {
                    return true;
                }
                next_level.extend(self.direct_parent_fqns(&owner));
            }
            level = next_level;
        }
        false
    }

    fn class_has_trait_use(&self, owner_fqn: &str) -> bool {
        self.support
            .fqn(owner_fqn)
            .into_iter()
            .any(|unit| self.class_unit_has_trait_use(&unit))
    }

    fn class_unit_has_trait_use(&self, unit: &CodeUnit) -> bool {
        let source_storage;
        let source = if unit.source() == self.file {
            self.source
        } else {
            let Ok(source) = unit.source().read_to_string() else {
                return true;
            };
            source_storage = source;
            &source_storage
        };
        let Some(tree) = parse_php_tree(source) else {
            return true;
        };
        let ranges = self.index.ranges(unit);
        let Some(start) = ranges.iter().map(|range| range.start_byte).min() else {
            return true;
        };
        let Some(end) = ranges.iter().map(|range| range.end_byte).max() else {
            return true;
        };
        declaration_range_has_trait_use(tree.root_node(), start, end)
    }

    fn enclosing_owner_fqn(&self, node: Node<'_>) -> Option<String> {
        let range = node_range(node, self.line_starts);
        self.index
            .enclosing_code_unit(self.file, &range)
            .and_then(|enclosing| self.index.parent_of(&enclosing).or(Some(enclosing)))
            .filter(|owner| owner.is_class())
            .map(|owner| owner.fq_name())
    }

    fn fqn_is_workspace_bounded(&self, fqn: &str) -> bool {
        let namespace = diagnostic_namespace(fqn);
        self.support.package_exists(&namespace)
    }

    /// Publish an error together with the proof that licenses it.
    fn publish_absence(
        &mut self,
        range: Range,
        domain: SemanticDiagnosticDomain,
        boundary: BoundaryStatus,
        diagnostic: SemanticDiagnostic,
    ) {
        if self.at_capacity() {
            return;
        }
        self.report.push_absent(
            SemanticAbsenceProof {
                range,
                domain,
                boundary,
            },
            diagnostic,
        );
        self.published = self.published.saturating_add(1);
    }

    fn push_dynamic(&mut self, node: Node<'_>, detail: &str) {
        let range = node_range(node, self.line_starts);
        self.push_dynamic_range(range, detail);
    }

    fn push_dynamic_range(&mut self, range: Range, detail: &str) {
        self.report.push_incomplete(
            Some(range),
            vec![SemanticDiagnosticIncompleteReason::DynamicBehavior {
                detail: detail.to_owned(),
            }],
        );
    }

    /// The lookup reached a published surface that cannot carry a proof, and
    /// `detail` names the part of it that is missing.
    fn push_unproven(&mut self, range: Range, detail: String) {
        self.report.push_incomplete(
            Some(range),
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }],
        );
    }

    fn push_missing_discovery(&mut self, range: Range, boundary: BoundaryStatus) {
        self.report.push_incomplete(
            Some(range),
            vec![SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }],
        );
    }

    /// Nothing indexed the name and the build does not declare an owner for it.
    /// Retained discovery evidence explains why, when a host retained any.
    fn push_unknown_boundary(&mut self, range: Range) {
        let mut reasons = self.external.discovery_incomplete_reasons();
        if reasons.is_empty() {
            reasons.push(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
            );
        }
        self.report.push_incomplete(Some(range), reasons);
    }

    /// Whether the published-error cap is reached, recording the truncation the
    /// first time it is.
    fn at_capacity(&mut self) -> bool {
        if self.published < MAX_PHP_SEMANTIC_DIAGNOSTICS {
            return false;
        }
        if !self.truncated {
            self.truncated = true;
            self.report
                .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        }
        true
    }
}

fn diagnostic_namespace(fqn: &str) -> String {
    let public = fqn.replace("._module_.", ".");
    let Some((namespace, _)) = public.rsplit_once('.') else {
        return String::new();
    };
    namespace.to_string()
}

fn is_unqualified_php_name(raw: &str) -> bool {
    !raw.starts_with('\\') && !raw.contains('\\')
}

fn is_dynamic_php_name(raw: &str) -> bool {
    raw.starts_with('$')
}

fn declaration_range_has_trait_use(root: Node<'_>, start: usize, end: usize) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.end_byte() < start || node.start_byte() > end {
            continue;
        }
        if node.kind() == "use_declaration" {
            return true;
        }
        push_named_children(&mut stack, node);
    }
    false
}

fn push_named_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}

fn is_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "anonymous_function_creation"
            | "arrow_function"
    )
}

fn is_non_reference_container(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "namespace_use_declaration"
            | "namespace_use_clause"
            | "comment"
            | "string"
            | "encapsed_string"
            | "string_value"
            | "heredoc"
            | "nowdoc"
    )
}

fn is_non_reference_context(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if is_non_reference_container(candidate) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn seed_parameter_types(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "assignment_expression")
        .then(|| {
            node.child_by_field_name("left")
                .zip(node.child_by_field_name("right"))
        })
        .flatten()
}

fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn static_member_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

fn variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_text(node, source).trim_start_matches('$')
}

fn literal_member_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "name").then(|| node_text(node, source))
}

fn static_property_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name").then(|| variable_identifier(node, source))
}

fn static_member_identifier<'a>(
    parent: Node<'_>,
    member: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    if parent.kind() == "scoped_property_access_expression" {
        static_property_identifier(member, source)
    } else {
        literal_member_identifier(member, source)
    }
}

fn receiver_type_from_expression(
    node: Node<'_>,
    source: &str,
    ctx: &PhpFileContext,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match node.kind() {
        "variable_name" => {
            let name = variable_identifier(node, source);
            first_precise(bindings, name)
        }
        "object_creation_expression" => object_creation_type(node)
            .and_then(|type_node| resolve_php_type(node_text(type_node, source), ctx)),
        "parenthesized_expression" => node
            .named_child(0)
            .and_then(|inner| receiver_type_from_expression(inner, source, ctx, bindings)),
        _ => None,
    }
}

fn first_precise(bindings: &LocalInferenceEngine<String>, symbol: &str) -> Option<String> {
    match bindings.resolve_symbol(symbol) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
    }
}

fn qualified_candidate_text(node: Node<'_>, source: &str) -> String {
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if matches!(ancestor.kind(), "namespace_name" | "qualified_name") {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    node_text(candidate, source).trim().to_string()
}

fn is_instanceof_type_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "binary_expression"
        && parent
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "instanceof")
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
        })
}

fn is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

fn is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if has_ancestor_kind(
        node,
        &[
            "variable_name",
            "namespace_name",
            "namespace_definition",
            "property_element",
            "simple_parameter",
            "property_promotion_parameter",
        ],
    ) {
        return false;
    }
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "namespace_name"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "variable_name"
            | "base_clause"
            | "class_interface_clause"
    )
}

fn has_ancestor_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if kinds.contains(&candidate.kind()) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "function_definition"
                | "method_declaration"
                | "enum_declaration"
                | "enum_case"
                | "const_element"
                | "property_element"
                | "simple_parameter"
                | "property_promotion_parameter"
        )
}

fn is_builtin_php_type(raw: &str) -> bool {
    raw.split('|').all(|part| {
        matches!(
            part.trim().trim_start_matches('?'),
            "array"
                | "bool"
                | "callable"
                | "false"
                | "float"
                | "int"
                | "iterable"
                | "mixed"
                | "never"
                | "null"
                | "object"
                | "self"
                | "static"
                | "parent"
                | "string"
                | "true"
                | "void"
        )
    })
}

fn is_builtin_php_function(raw: &str) -> bool {
    !raw.contains('\\')
        && matches!(
            raw,
            "array_key_exists"
                | "count"
                | "defined"
                | "empty"
                | "in_array"
                | "is_array"
                | "is_bool"
                | "is_float"
                | "is_int"
                | "is_null"
                | "is_object"
                | "is_string"
                | "isset"
                | "json_decode"
                | "json_encode"
                | "printf"
                | "sprintf"
                | "strlen"
                | "substr"
                | "trim"
                | "var_dump"
        )
}

fn is_builtin_php_constant(raw: &str) -> bool {
    !raw.contains('\\')
        && matches!(
            raw,
            "DIRECTORY_SEPARATOR"
                | "PHP_EOL"
                | "PHP_VERSION"
                | "STDERR"
                | "STDIN"
                | "STDOUT"
                | "__CLASS__"
                | "__DIR__"
                | "__FILE__"
                | "__FUNCTION__"
                | "__LINE__"
                | "__METHOD__"
                | "__NAMESPACE__"
                | "__TRAIT__"
        )
}
