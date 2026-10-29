//! PHP's semantic diagnostics: conservative unresolved-reference reporting.
//!
//! The analyzer facts this needs are the [`PhpSource`] the rest of the
//! crate already takes, the dispatching analyzer's `CodeUnitIndex`, and a
//! [`BoundedDefinitionLookup`] for "is this fqn indexed".
//! `analyzer/php/diagnostics.rs` in `brokk-bifrost-analysis` keeps the downcast
//! that produces them, and the analyzer-bound fixture suite that exercises them.

use crate::aliases::{
    PhpFileContextIndex, resolve_php_constant, resolve_php_function, resolve_php_type,
    resolve_php_type_arms,
};
use crate::external_surface::{PhpExternalMember, PhpExternalSurface, PhpExternalSymbol};
use crate::graph::extractor::static_member_identifier;
use crate::graph::resolver::{
    is_bare_constant_reference, is_object_creation_type_name, qualified_candidate_text,
};
use crate::graph::syntax::{
    PhpMagicSurface, instance_receiver_type_fq_name, instanceof_type_node, is_local_scope,
    literal_member_identifier, magic_member_names, seed_assignment_binding, seed_parameter_types,
    static_member_parts, static_scope_type_fq_name,
};
use crate::graph::{PhpCallableFacts, PhpGraphSource};
use crate::graph_support::{PhpSource, php_direct_declared_class_parent};
use brokk_bifrost_core::analyzer::model::{Range, SemanticDiagnostic};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::{collect_parse_errors, find_node_or_ancestor};
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile, SemanticAbsenceProof,
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use tree_sitter::{Node, Parser};

pub const PHP_UNRECOGNIZED_SYMBOL: &str = "php_unrecognized_symbol";
pub const PHP_UNRECOGNIZED_MEMBER: &str = "php_unrecognized_member";
pub const PHP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-php";
const MAX_PHP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_PHP_SEMANTIC_DIAGNOSTICS: usize = 200;

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
    let Some(contexts) = PhpFileContextIndex::from_tree(tree.root_node(), source, || true) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "PHP namespace/import indexing failed".to_owned(),
            }],
        );
        return report;
    };
    let mut collector = PhpDiagnosticCollector {
        php,
        index,
        support,
        external,
        file,
        source,
        line_starts: &line_starts,
        contexts,
        report,
        published: 0,
        truncated: false,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

struct PhpDiagnosticCollector<'a> {
    php: &'a dyn PhpSource,
    index: &'a dyn CodeUnitIndex,
    support: &'a dyn BoundedDefinitionLookup,
    external: &'a dyn PhpExternalSurface,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    contexts: PhpFileContextIndex,
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

/// The callable-return facts a semantic-diagnostics pass can honestly supply.
///
/// The usage-facts index is analysis-owned and this pass never builds one, so
/// both answers are absent and the shared receiver evaluator falls back to the
/// declaration's canonical source facts. Answering anything else here would claim a fact
/// this pass did not compute.
struct PhpDiagnosticCallableFacts;

impl PhpCallableFacts for PhpDiagnosticCallableFacts {
    fn declaration_return_type_fqn(&self, _unit: &CodeUnit) -> Option<String> {
        None
    }

    fn callable_return_type_fqn(&self, _callable_fqn: &str) -> Option<String> {
        None
    }
}

static PHP_DIAGNOSTIC_CALLABLE_FACTS: PhpDiagnosticCallableFacts = PhpDiagnosticCallableFacts;

/// The shared magic-member surface this pass's access kind addresses, so the
/// magic-method table itself lives in one place for both this pass and forward
/// definition lookup (#2030).
fn magic_surface(kind: MemberAccessKind) -> PhpMagicSurface {
    match kind {
        MemberAccessKind::InstanceCall => PhpMagicSurface::InstanceCall,
        MemberAccessKind::InstanceProperty => PhpMagicSurface::InstanceProperty,
        MemberAccessKind::StaticCall => PhpMagicSurface::StaticCall,
        MemberAccessKind::StaticProperty | MemberAccessKind::ClassConstant => {
            PhpMagicSurface::StaticData
        }
    }
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
                seed_parameter_types(scope, self.source, &mut bindings, |_name, raw| {
                    resolve_php_type_arms(raw, self.contexts.context_at(scope.start_byte()))
                });
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
        brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed(node, stack);
    }

    fn seed_assignment(&self, node: Node<'_>, bindings: &mut LocalInferenceEngine<String>) {
        seed_assignment_binding(node, self.source, bindings, |right, bindings| {
            self.receiver_type_from_expression(right, bindings)
        });
    }

    /// The declared type of one receiver expression, evaluated by the shared
    /// PHP receiver evaluator so diagnostics judge member chains, factory
    /// results, and nullsafe receivers exactly as usage analysis does.
    fn receiver_type_from_expression(
        &self,
        node: Node<'_>,
        bindings: &LocalInferenceEngine<String>,
    ) -> Option<String> {
        instance_receiver_type_fq_name(
            self.php,
            PhpGraphSource {
                index: self.index,
                facts: &PHP_DIAGNOSTIC_CALLABLE_FACTS,
            },
            node,
            self.source,
            self.contexts.context_at(node.start_byte()),
            bindings,
            |start, end| self.enclosing_owner_fqn_at(start, end),
        )
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
                if !is_builtin_php_type(&raw) && !is_object_creation_type_name(node) {
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
            "member_call_expression"
            | "member_access_expression"
            | "nullsafe_member_call_expression"
            | "nullsafe_member_access_expression" => {
                self.check_instance_member(node, bindings);
            }
            "name" | "qualified_name" => {
                if is_instanceof_type_name(node) {
                    self.check_symbol(node, SymbolKind::Type);
                } else if is_bare_constant_reference(node)
                    && !has_ancestor_kind(node, &["variable_name", "namespace_name"])
                {
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
        // A built-in language type, function, or constant is part of the PHP
        // runtime surface rather than any indexed package.
        if matches!(kind, SymbolKind::Type) && is_builtin_php_type(&raw) {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        // PHP falls back to the global namespace for an unqualified function or
        // constant. The resolver now models that fallback (#1866), so the
        // workspace gets the first answer; only when no candidate is indexed is
        // the lookup unfinished -- Bifrost does not index the whole built-in
        // global surface, so an unqualified name that reaches neither namespace
        // is undiscovered rather than absent.
        let unqualified_callable = matches!(kind, SymbolKind::Function | SymbolKind::Constant)
            && is_unqualified_php_name(&raw);
        let indexed = |candidate: &str| !self.support.fqn(candidate).is_empty();
        let mut runtime_builtin = false;
        let fqn = match kind {
            SymbolKind::Type => resolve_php_type(&raw, self.contexts.context_at(node.start_byte())),
            SymbolKind::Function => {
                resolve_php_function(&raw, self.contexts.context_at(node.start_byte())).map(
                    |candidates| {
                        runtime_builtin = candidates.iter().any(is_builtin_php_function);
                        candidates.first_indexed(indexed).to_string()
                    },
                )
            }
            SymbolKind::Constant => {
                resolve_php_constant(&raw, self.contexts.context_at(node.start_byte())).map(
                    |candidates| {
                        runtime_builtin = candidates.iter().any(|candidate| {
                            is_builtin_php_constant(
                                candidate.strip_prefix("_module_.").unwrap_or(candidate),
                            )
                        });
                        candidates.first_indexed(indexed).to_string()
                    },
                )
            }
        };
        let Some(fqn) = fqn else {
            return;
        };
        if !self.support.fqn(&fqn).is_empty() {
            self.report
                .push_resolved(range, BoundaryStatus::WorkspaceLocal);
            return;
        }
        if runtime_builtin {
            self.report
                .push_resolved(range, BoundaryStatus::ExternalIndexed);
            return;
        }
        if unqualified_callable {
            self.push_missing_discovery(range, BoundaryStatus::ExternalUnknown);
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
        if !matches!(scope.kind(), "name" | "qualified_name" | "relative_scope") {
            self.push_dynamic(scope, "PHP static scope is chosen at run time");
            return;
        }
        let owner = self.static_scope_fqn(scope);
        if owner.is_none() && matches!(node_text(scope, self.source), "self" | "static" | "parent")
        {
            return;
        }
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
        let owner = self.receiver_type_from_expression(object, bindings);
        let kind = match node.kind() {
            "member_call_expression" | "nullsafe_member_call_expression" => {
                MemberAccessKind::InstanceCall
            }
            "member_access_expression" | "nullsafe_member_access_expression" => {
                MemberAccessKind::InstanceProperty
            }
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
                if let Some(magic) = magic_member_names(magic_surface(kind))
                    .iter()
                    .find(|magic| {
                        matches!(
                            self.external.lookup_member(&id, magic),
                            PhpExternalMember::Indexed | PhpExternalMember::Ambiguous
                        )
                    })
                {
                    self.push_dynamic_range(
                        range,
                        &format!(
                            "PHP owner `{owner}` resolves members at run time through `{magic}`"
                        ),
                    );
                    return;
                }
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
        let enclosing_owner = self.enclosing_owner_fqn(scope);
        static_scope_type_fq_name(
            self.php,
            PhpGraphSource {
                index: self.index,
                facts: &PHP_DIAGNOSTIC_CALLABLE_FACTS,
            },
            text,
            self.contexts.context_at(scope.start_byte()),
            enclosing_owner.as_deref(),
        )
    }

    fn has_magic_member_boundary(&self, owner_fqn: &str, kind: MemberAccessKind) -> bool {
        magic_member_names(magic_surface(kind))
            .iter()
            .any(|name| self.owner_or_ancestor_has_member(owner_fqn, name))
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
        let Some(source) = self.php.php_source_facts(unit.source()) else {
            return true;
        };
        let mut declarations = source.declarations_for(unit).peekable();
        declarations.peek().is_none() || declarations.any(|declaration| declaration.has_trait_use)
    }

    fn enclosing_owner_fqn(&self, node: Node<'_>) -> Option<String> {
        self.enclosing_owner_fqn_at(node.start_byte(), node.end_byte())
    }

    /// The class that lexically owns `start..end`, which is what `$this`,
    /// `self`, and `static` name. Byte offsets rather than a node, because the
    /// shared receiver evaluator reports the position it needs an owner for.
    fn enclosing_owner_fqn_at(&self, start: usize, end: usize) -> Option<String> {
        let range = Range {
            start_byte: start,
            end_byte: end,
            start_line: find_line_index_for_offset(self.line_starts, start),
            end_line: find_line_index_for_offset(self.line_starts, end),
        };
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

fn object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn is_instanceof_type_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(instanceof_type_node)
        .is_some_and(|right| {
            right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
        })
}

fn has_ancestor_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    find_node_or_ancestor(node, |candidate| kinds.contains(&candidate.kind())).is_some()
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    brokk_bifrost_core::analyzer::structural::adapter_helpers::is_field_of(parent, node, "name")
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
    matches!(
        raw.to_ascii_lowercase().as_str(),
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
}

fn is_builtin_php_function(raw: &str) -> bool {
    !raw.contains('\\')
        && matches!(
            raw.to_ascii_lowercase().as_str(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_facts::{PhpFileSourceFacts, PhpSourceFactProvider};
    use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
    use brokk_bifrost_core::analyzer::model::{Language, SemanticDiagnosticOutcome};
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::project::Project;
    use brokk_bifrost_test_macros::hardwon;
    use std::{collections::BTreeSet, sync::Arc};

    // A query-local index over real producer output. No discovery or storage is
    // simulated: the collector consumes the same parsed rows the store mounts.
    struct Fixture {
        file: ProjectFile,
        parsed: ParsedFile,
        facts: Arc<PhpFileSourceFacts>,
        alternatives: Vec<Fixture>,
    }
    impl Fixture {
        fn new(source: &str) -> Self {
            Self::in_file(source, "diagnostic.php")
        }
        fn in_file(source: &str, name: &str) -> Self {
            let file = ProjectFile::new(std::env::temp_dir(), name);
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let parsed = crate::declarations::parse_php_file(&file, source, &tree);
            let source_facts = parsed.source_facts.as_ref().unwrap();
            let mut declaration_units = brokk_bifrost_core::hash::HashMap::<_, Vec<_>>::default();
            for (id, unit) in &parsed.source_declaration_units {
                declaration_units.entry(*id).or_default().push(unit.clone());
            }
            let facts = Arc::new(PhpFileSourceFacts {
                source: source_facts.occurrences.clone(),
                imports: source_facts.imports.clone(),
                facts: source_facts.php.clone().unwrap(),
                declaration_units,
            });
            Self {
                file,
                parsed,
                facts,
                alternatives: vec![],
            }
        }
        fn report(&self, source: &str) -> SemanticDiagnosticReport {
            collect_php_semantic_diagnostics(self, self, self, self, &self.file, source)
        }
    }
    impl TypeHierarchyProvider for Fixture {
        fn get_direct_ancestors(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
            self.parsed
                .raw_supertypes
                .get(unit)
                .into_iter()
                .flatten()
                .flat_map(|name| {
                    self.parsed
                        .declarations()
                        .iter()
                        .filter(move |candidate| candidate.identifier() == name)
                        .cloned()
                })
                .collect()
        }
        fn get_direct_descendants(&self, _: &CodeUnit) -> HashSet<CodeUnit> {
            HashSet::default()
        }
    }
    impl PhpSourceFactProvider for Fixture {
        fn php_source_facts_while(
            &self,
            file: &ProjectFile,
            keep: &dyn Fn() -> bool,
        ) -> Option<Arc<PhpFileSourceFacts>> {
            if *file == self.file {
                keep().then(|| self.facts.clone())
            } else {
                self.alternatives
                    .iter()
                    .find_map(|fixture| fixture.php_source_facts_while(file, keep))
            }
        }
    }
    impl CodeUnitIndex for Fixture {
        fn project(&self) -> &dyn Project {
            unimplemented!("collector never reads project")
        }
        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Php])
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.parsed.declarations().iter().cloned())
        }
        fn definitions(&self, fqn: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            let fqn = fqn.to_owned();
            Box::new(
                std::iter::once(self)
                    .chain(self.alternatives.iter())
                    .flat_map(|fixture| fixture.parsed.declarations().iter())
                    .filter(move |unit| unit.fq_name() == fqn)
                    .cloned(),
            )
        }
        fn parent_of(&self, unit: &CodeUnit) -> Option<CodeUnit> {
            self.parsed
                .children
                .iter()
                .find(|(_, children)| children.contains(unit))
                .map(|(parent, _)| parent.clone())
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _: &ProjectFile, range: &Range) -> Option<CodeUnit> {
            self.parsed
                .ranges
                .iter()
                .flat_map(|(unit, ranges)| ranges.iter().map(move |range| (unit, range)))
                .filter(|(_, r)| r.start_byte <= range.start_byte && range.end_byte <= r.end_byte)
                .min_by_key(|(_, r)| r.end_byte - r.start_byte)
                .map(|(unit, _)| unit.clone())
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }
    impl BoundedDefinitionLookup for Fixture {
        fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.definitions(fqn).collect()
        }
        fn fqn_in_language(&self, fqn: &str, _: Language) -> Vec<CodeUnit> {
            self.fqn(fqn)
        }
        fn file_identifier(&self, _: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
            self.parsed
                .declarations()
                .iter()
                .filter(|unit| unit.identifier() == ident)
                .cloned()
                .collect()
        }
        fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
            self.fqn(fqn)
                .iter()
                .flat_map(|unit| {
                    self.parsed
                        .children
                        .get(unit)
                        .into_iter()
                        .flatten()
                        .cloned()
                })
                .collect()
        }
        fn package_exists(&self, package: &str) -> bool {
            self.parsed
                .declarations()
                .iter()
                .any(|unit| unit.package_name() == package)
        }
        fn package_exists_in_language(&self, package: &str, _: Language) -> bool {
            self.package_exists(package)
        }
        fn fqn_prefix_exists(&self, prefix: &str) -> bool {
            self.parsed
                .declarations()
                .iter()
                .any(|unit| unit.fq_name().starts_with(prefix))
        }
    }
    impl PhpExternalSurface for Fixture {
        fn lookup_type(&self, _: &str) -> PhpExternalSymbol {
            PhpExternalSymbol::Absent
        }
        fn lookup_member(&self, _: &str, _: &str) -> PhpExternalMember {
            unimplemented!()
        }
        fn namespace_surface_is_complete(&self, _: &str) -> bool {
            false
        }
        fn declares_unindexed(&self, _: &str) -> bool {
            false
        }
        fn discovery_incomplete_reasons(&self) -> Vec<SemanticDiagnosticIncompleteReason> {
            vec![]
        }
    }

    #[test]
    #[hardwon("#7228: review: named argument labels produced constant outcomes")]
    fn named_argument_labels_are_not_constants() {
        let source = "<?php class C { function __construct($size) {} } function g($size) {} function f($x = new C(size: Missing)) { g(size: Missing); }";
        let report = Fixture::new(source).report(source);
        let incomplete: Vec<_> = report
            .outcomes()
            .iter()
            .filter_map(|outcome| match outcome {
                SemanticDiagnosticOutcome::Incomplete {
                    range: Some(range), ..
                } => Some(&source[range.start_byte..range.end_byte]),
                _ => None,
            })
            .collect();
        assert_eq!(incomplete, ["Missing", "Missing"], "{report:?}");
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: expression static scopes fabricated nominal names or disappeared"
    )]
    fn expression_static_scopes_always_report_dynamic_evidence() {
        for scope in [
            "$owner",
            "($owner)",
            "($owner ?? 'A|B')",
            "($owner ?? 'A|string|B')",
            "choose($owner)",
        ] {
            let source = format!(
                "<?php namespace App; class Anchor {{}} function f($owner) {{ {scope}::run(); }}"
            );
            let fixture = Fixture::new(&source);
            let report = fixture.report(&source);
            assert!(report.diagnostics().is_empty(), "{scope}: {report:?}");
            assert!(report.outcomes().iter().any(|outcome| matches!(outcome,
                SemanticDiagnosticOutcome::Incomplete { range: Some(_), reasons }
                if reasons.iter().any(|reason| matches!(reason, SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }))
            )), "{scope}: {report:?}");
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: bracketed namespaces and default constants lost reference outcomes"
    )]
    fn constant_outcomes_do_not_depend_on_namespace_braces_or_default_position() {
        for body in ["return Missing;", "$x = Missing; return $x;"] {
            for (open, close) in [("namespace App;", ""), ("namespace App {", "}")] {
                let source = format!(
                    "<?php {open} class Anchor {{ public $p = Missing; }} function f($p = Missing) {{ {body} }} {close}"
                );
                let report = Fixture::new(&source).report(&source);
                let missing: Vec<_> = report
                    .outcomes()
                    .iter()
                    .filter(|outcome| match outcome {
                        SemanticDiagnosticOutcome::Incomplete {
                            range: Some(range), ..
                        } => &source[range.start_byte..range.end_byte] == "Missing",
                        _ => false,
                    })
                    .collect();
                assert_eq!(missing.len(), 3, "{source}: {report:?}");
            }
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: runtime builtins hid workspace shadows"
    )]
    fn runtime_builtin_outcomes_follow_namespace_precedence() {
        for (declaration, expected) in [
            ("", BoundaryStatus::ExternalIndexed),
            (
                "function strlen($x) { return 42; }",
                BoundaryStatus::WorkspaceLocal,
            ),
        ] {
            let source = format!(
                "<?php namespace App; {declaration} function f() {{ strlen('x'); count([]); unknown(); }}"
            );
            let report = Fixture::new(&source).report(&source);
            let resolved: Vec<_> = report
                .outcomes()
                .iter()
                .filter_map(|outcome| match outcome {
                    SemanticDiagnosticOutcome::Resolved { range, boundary } => {
                        Some((&source[range.start_byte..range.end_byte], *boundary))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                resolved,
                [
                    ("strlen", expected),
                    ("count", BoundaryStatus::ExternalIndexed)
                ],
                "{report:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: builtin recognition must follow imported targets"
    )]
    fn builtin_aliases_and_case_use_resolved_candidates() {
        for (prefix, call, resolved) in [
            ("", "STRLEN", true),
            ("", "\\strlen", true),
            ("use function strlen as length;", "length", true),
            ("use function Vendor\\length as strlen;", "strlen", false),
        ] {
            let source = format!("<?php namespace App; {prefix} function f() {{ {call}('x'); }}");
            let report = Fixture::new(&source).report(&source);
            assert_eq!(
                report.outcomes().iter().any(|outcome| matches!(
                    outcome,
                    SemanticDiagnosticOutcome::Resolved {
                        boundary: BoundaryStatus::ExternalIndexed,
                        ..
                    }
                )),
                resolved,
                "{report:?}"
            );
        }
    }

    #[test]
    fn diagnostic_reference_domains_ranges_and_boundaries() {
        let source = r"<?php namespace App; class K {} const Missing = 1; function f(Missing $arg, K $known) { new \App\K(); new \App\Missing(); new Z(); $arg instanceof Missing; Missing\call(); unknown(); } namespace App\Missing; class Nested {}";
        let report = Fixture::new(source).report(source);
        let types: Vec<_> = report
            .outcomes()
            .iter()
            .filter_map(|outcome| match outcome {
                SemanticDiagnosticOutcome::Absent(proof)
                    if matches!(proof.domain, SemanticDiagnosticDomain::Type { .. }) =>
                {
                    Some(&source[proof.range.start_byte..proof.range.end_byte])
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            types,
            ["Missing", r"\App\Missing", "Z", "Missing"],
            "{report:?}"
        );
        assert!(report.outcomes().iter().any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Absent(proof) if &source[proof.range.start_byte..proof.range.end_byte] == r"Missing\call")), "{report:?}");
    }

    #[test]
    fn diagnostic_byte_and_error_budgets_include_exact_limits() {
        for length in [512 * 1024 - 1, 512 * 1024, 512 * 1024 + 1] {
            let mut source = "<?php strlen('x');".to_owned();
            source.extend(std::iter::repeat_n(' ', length - source.len()));
            let fixture = Fixture::new(&source);
            let report = fixture.report(&source);
            assert_eq!(
                report
                    .outcomes()
                    .iter()
                    .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { .. })),
                length <= 512 * 1024
            );
        }
        for count in [199, 200, 201] {
            let mut source = "<?php namespace App; class Anchor {} function f() {".to_owned();
            for n in 0..count {
                source.push_str(&format!("new Missing{n}();"));
            }
            source.push('}');
            let report = Fixture::new(&source).report(&source);
            assert_eq!(report.diagnostics().len(), count.min(200), "{report:?}");
            assert_eq!(report.outcomes().iter().any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Incomplete {range: None, reasons} if reasons.contains(&SemanticDiagnosticIncompleteReason::Truncated))), count >= 200);
        }
    }

    #[test]
    fn alternative_trait_owners_prevent_false_member_absence() {
        let source = "<?php namespace App; class Owner {} function f(Owner $o) { $o->run(); }";
        let mut fixture = Fixture::new(source);
        fixture.alternatives.push(Fixture::in_file(
            "<?php namespace App; trait T { function run() {} } class Owner { use T; }",
            "alternative.php",
        ));
        let report = fixture.report(source);
        assert!(report.diagnostics().is_empty(), "{report:?}");
        assert!(report.outcomes().iter().any(|outcome| matches!(outcome,
            SemanticDiagnosticOutcome::Incomplete {range: Some(range), reasons}
            if &source[range.start_byte..range.end_byte] == "run" && reasons.iter().any(|reason| matches!(reason, SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }))
        )), "{report:?}");
    }

    #[test]
    fn inherited_members_and_relative_owners_have_typed_outcomes() {
        let source = "<?php namespace App; class Grand { public static function inherited() {} } class Base extends Grand {} class Child extends Base { public function run() { self::missing(); static::missing(); parent::inherited(); $this->inherited(); $this->missing(); } } function f(Child $c) { $c->inherited(); }";
        let report = Fixture::new(source).report(source);
        let mut resolved = 0;
        let mut missing = 0;
        for outcome in report.outcomes() {
            match outcome {
                SemanticDiagnosticOutcome::Resolved {
                    range,
                    boundary: BoundaryStatus::WorkspaceLocal,
                } if &source[range.start_byte..range.end_byte] == "inherited" => resolved += 1,
                SemanticDiagnosticOutcome::Absent(proof)
                    if &source[proof.range.start_byte..proof.range.end_byte] == "missing" =>
                {
                    assert_eq!(
                        proof.domain,
                        SemanticDiagnosticDomain::MemberSurface {
                            owner: "App.Child".to_owned(),
                            member: "missing".to_owned()
                        }
                    );
                    missing += 1;
                }
                _ => {}
            }
        }
        assert_eq!((resolved, missing), (3, 3), "{report:?}");
    }
}
