use crate::analyzer::rust::lexical_scope::{self, RustLexicalScopeIndex};
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{
    CodeUnit, GlobalUsageDefinitionIndex, IAnalyzer, ProjectFile, RustAnalyzer,
    RustReferenceContext, TypeHierarchyProvider,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

/// Owned, query-shaped declaration access used by Rust forward resolution.
///
/// The legacy [`GlobalUsageDefinitionIndex`] implementation keeps usage-graph callers
/// working, while point lookups can answer these operations from persisted,
/// bounded analyzer queries without materializing every workspace declaration.
pub(crate) trait RustDefinitionProvider {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit>;

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        self.fqn(&format!("{owner_fqn}.{name}"))
    }
}

impl RustDefinitionProvider for GlobalUsageDefinitionIndex {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        GlobalUsageDefinitionIndex::fqn(self, fqn)
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        GlobalUsageDefinitionIndex::file_identifier(self, file, identifier)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RustGraphSeedKind {
    Export,
    LocalDeclaration,
}

pub(super) struct RustGraphSeeds {
    pub(super) roots: BTreeSet<CodeUnit>,
    pub(super) kind: RustGraphSeedKind,
}

pub(crate) fn resolve_rust_path_fqn(
    rust: &RustAnalyzer,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    full_path: &str,
) -> Option<String> {
    refs.resolve_bare(full_path)
        .map(str::to_string)
        .or_else(|| refs.resolve_scoped_owner(full_path))
        .or_else(|| rust.resolve_module_package(file, full_path))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustTokenPathRole {
    Prefix,
    Value,
    Call,
}

pub(crate) struct ResolvedRustTokenPathSegment<'tree> {
    pub(crate) node: Node<'tree>,
    pub(crate) path: Vec<Node<'tree>>,
    pub(crate) fqn: String,
    pub(crate) role: RustTokenPathRole,
}

/// Resolve every segment of each qualified Rust path represented directly by a
/// macro `token_tree`. Tree-sitter does not wrap these tokens in
/// `scoped_identifier` nodes, so use the sibling `segment :: segment` structure
/// and source ranges between those nodes. This deliberately does not interpret
/// delimiters or split source text.
pub(crate) fn resolve_rust_token_tree_paths<'tree>(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    source: &str,
    token_tree: Node<'tree>,
) -> Vec<ResolvedRustTokenPathSegment<'tree>> {
    if token_tree.kind() != "token_tree" {
        return Vec::new();
    }

    let mut cursor = token_tree.walk();
    let children: Vec<_> = token_tree.children(&mut cursor).collect();
    let mut resolved = Vec::new();
    let mut index = 0;
    while index + 2 < children.len() {
        if !rust_token_path_segment(children[index])
            || children[index + 1].kind() != "::"
            || !rust_token_path_segment(children[index + 2])
            || (index >= 2
                && children[index - 1].kind() == "::"
                && rust_token_path_segment(children[index - 2]))
        {
            index += 1;
            continue;
        }

        let root = children[index];
        let dollar_crate_root = rust_token_is_dollar_crate(root, source);
        let mut dollar_crate_owner = if dollar_crate_root {
            rust.resolve_module_package(file, "crate")
        } else {
            None
        };
        let mut segment_index = index;
        let mut path = Vec::new();
        loop {
            let segment = children[segment_index];
            path.push(segment);
            let continues = children
                .get(segment_index + 1..=segment_index + 2)
                .is_some_and(|next| next[0].kind() == "::" && rust_token_path_segment(next[1]));
            let role = if continues {
                RustTokenPathRole::Prefix
            } else if children
                .get(segment_index + 1)
                .is_some_and(rust_token_call_arguments)
            {
                RustTokenPathRole::Call
            } else {
                RustTokenPathRole::Value
            };

            let macro_call = !continues
                && children
                    .get(segment_index + 1)
                    .is_some_and(|bang| bang.kind() == "!")
                && children
                    .get(segment_index + 2)
                    .is_some_and(|arguments| arguments.kind() == "token_tree");
            let fqn = if dollar_crate_root && macro_call {
                None
            } else if dollar_crate_root {
                if segment_index == index {
                    None
                } else {
                    dollar_crate_owner.as_deref().and_then(|owner| {
                        resolve_direct_token_path_child(support, source, owner, segment)
                    })
                }
            } else {
                resolve_token_path_segment_fqn(
                    rust,
                    support,
                    refs,
                    file,
                    source,
                    root,
                    segment,
                    (segment_index > index).then(|| children[segment_index - 2]),
                )
            };
            if dollar_crate_root && segment_index > index {
                dollar_crate_owner.clone_from(&fqn);
            }
            if let Some(fqn) = fqn {
                resolved.push(ResolvedRustTokenPathSegment {
                    node: segment,
                    path: path.clone(),
                    fqn,
                    role,
                });
            }

            if !continues {
                index = segment_index + 1;
                break;
            }
            segment_index += 2;
        }
    }
    resolved
}

fn resolve_direct_token_path_child(
    support: &dyn RustDefinitionProvider,
    source: &str,
    owner_fqn: &str,
    segment: Node<'_>,
) -> Option<String> {
    let name = source.get(segment.start_byte()..segment.end_byte())?;
    let candidates: BTreeSet<_> = if owner_fqn.is_empty() {
        support.fqn(name)
    } else {
        support.members_for_owner_name(owner_fqn, name)
    }
    .into_iter()
    .collect();
    if candidates.len() == 1 {
        candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.fq_name())
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_token_path_segment_fqn(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    segment: Node<'_>,
    owner_terminal: Option<Node<'_>>,
) -> Option<String> {
    let Some(owner_terminal) = owner_terminal else {
        let path = source.get(root.start_byte()..segment.end_byte())?.trim();
        return lexical_import_fqn(rust, support, file, source, root).or_else(|| {
            resolve_rust_path_fqn(rust, refs, file, path).filter(|fqn| !support.fqn(fqn).is_empty())
        });
    };
    let owner = source
        .get(root.start_byte()..owner_terminal.end_byte())?
        .trim();
    let name = source.get(segment.start_byte()..segment.end_byte())?.trim();
    if owner_terminal.start_byte() == root.start_byte()
        && owner_terminal.end_byte() == root.end_byte()
        && let Some(owner_fqn) = lexical_import_fqn(rust, support, file, source, root)
    {
        let fqns: BTreeSet<_> = support
            .members_for_owner_name(&owner_fqn, name)
            .into_iter()
            .map(|candidate| candidate.fq_name())
            .collect();
        if fqns.len() == 1 {
            return fqns.into_iter().next();
        }
    }
    let full_path = source.get(root.start_byte()..segment.end_byte())?.trim();
    if let Some(fqn) = resolve_rust_path_fqn(rust, refs, file, full_path)
        && !support.fqn(&fqn).is_empty()
    {
        return Some(fqn);
    }
    match resolve_scoped_associated_item(
        rust,
        support,
        refs,
        file,
        owner,
        name,
        segment.start_byte(),
    ) {
        ReceiverAnalysisOutcome::Precise(candidates) => {
            let mut fqns = candidates.into_iter().map(|candidate| candidate.fq_name());
            let fqn = fqns.next()?;
            fqns.all(|candidate| candidate == fqn).then_some(fqn)
        }
        ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unknown
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => None,
    }
}

fn lexical_import_fqn(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    segment: Node<'_>,
) -> Option<String> {
    let name = source.get(segment.start_byte()..segment.end_byte())?.trim();
    let mut root = segment;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let binder = lexical_scope::visible_import_binder_in_tree(root, source, segment.start_byte());
    let fqns: BTreeSet<_> = rust
        .resolve_imported_export_from_binder_forward(file, &binder, name)
        .into_iter()
        .flat_map(|(target_file, target_name)| support.file_identifier(&target_file, &target_name))
        .map(|candidate| candidate.fq_name())
        .collect();
    if fqns.len() == 1 {
        fqns.into_iter().next()
    } else {
        None
    }
}

fn rust_token_path_segment(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "crate" | "self" | "super" | "default" | "metavariable"
    )
}

fn rust_token_is_dollar_crate(node: Node<'_>, source: &str) -> bool {
    node.kind() == "metavariable"
        && source.get(node.start_byte()..node.end_byte()) == Some("$crate")
}

pub(crate) fn rust_token_path_segment_is_qualified(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "token_tree"
            && ((node
                .prev_sibling()
                .is_some_and(|separator| separator.kind() == "::")
                && node
                    .prev_sibling()
                    .and_then(|separator| separator.prev_sibling())
                    .is_some_and(rust_token_path_segment))
                || (node
                    .next_sibling()
                    .is_some_and(|separator| separator.kind() == "::")
                    && node
                        .next_sibling()
                        .and_then(|separator| separator.next_sibling())
                        .is_some_and(rust_token_path_segment)))
    })
}

fn rust_token_call_arguments(node: &Node<'_>) -> bool {
    node.kind() == "token_tree" && node.child(0).is_some_and(|open| open.kind() == "(")
}

pub(super) fn is_member_target(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    // A member is referenced through a value of its owning type (`receiver.member`).
    // Free items belong on the top-level scan path even if a same-FQN module/macro
    // collision gives one a non-module hierarchy parent.
    (target.is_function() || target.is_field())
        && analyzer.parent_of(target).is_some_and(|parent| {
            // Rust members are owned by structs, enums, traits, or impl target
            // types. A same-FQN module/macro collision can otherwise attach a
            // free item to a macro CodeUnit and incorrectly route it through
            // receiver-based member scanning.
            parent.is_class()
        })
}

pub(super) fn is_trait_owner(rust: &RustAnalyzer, owner: &CodeUnit) -> bool {
    rust.is_rust_trait_declaration(owner)
}

fn is_public_like_declaration(rust: &RustAnalyzer, code_unit: &CodeUnit) -> bool {
    rust.is_rust_public_like_declaration(code_unit)
}

fn is_export_visible_declaration(rust: &RustAnalyzer, code_unit: &CodeUnit) -> bool {
    rust.is_rust_export_visible_declaration(code_unit)
}

pub(super) fn is_graph_visible_member_target(rust: &RustAnalyzer, target: &CodeUnit) -> bool {
    if is_public_like_declaration(rust, target) {
        return true;
    }

    let Some(owner) = rust.parent_of(target) else {
        return false;
    };
    if !is_public_like_declaration(rust, &owner) {
        return false;
    }

    (rust.is_rust_trait_declaration(&owner) && (target.is_function() || target.is_field()))
        || (rust.is_rust_enum_declaration(&owner) && target.is_field())
        || is_trait_impl_member_target(rust, target, &owner)
}

pub(super) fn trait_member_for_impl_member(
    rust: &RustAnalyzer,
    target: &CodeUnit,
) -> Option<CodeUnit> {
    let owner = rust.parent_of(target)?;
    if !is_trait_impl_member_target(rust, target, &owner) {
        return None;
    }
    rust.get_direct_ancestors(&owner)
        .into_iter()
        .filter(|trait_unit| rust.is_rust_trait_declaration(trait_unit))
        .find_map(|trait_unit| trait_member(rust, &trait_unit, target))
}

fn is_trait_impl_member_target(rust: &RustAnalyzer, target: &CodeUnit, owner: &CodeUnit) -> bool {
    if !(target.is_function() || target.is_field()) || rust.is_rust_trait_declaration(owner) {
        return false;
    }
    rust.is_rust_trait_impl_member_declaration(target)
}

fn trait_member(
    rust: &RustAnalyzer,
    trait_unit: &CodeUnit,
    impl_member: &CodeUnit,
) -> Option<CodeUnit> {
    let has_parameters = impl_member.is_function();
    rust.exact_member(
        trait_unit.source(),
        trait_unit.identifier(),
        impl_member.identifier(),
        has_parameters,
    )
    .filter(|trait_member| rust_member_roles_match(rust, impl_member, trait_member))
}

fn rust_member_roles_match(
    rust: &RustAnalyzer,
    impl_member: &CodeUnit,
    trait_member: &CodeUnit,
) -> bool {
    (impl_member.is_function() && trait_member.is_function())
        || (impl_member.is_field()
            && trait_member.is_field()
            && rust.is_type_alias(impl_member) == rust.is_type_alias(trait_member))
}

pub(crate) fn resolve_scoped_associated_item(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    path: &str,
    method_name: &str,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    resolve_scoped_associated_item_matching(
        rust,
        support,
        refs,
        file,
        path,
        method_name,
        CodeUnit::is_function,
        reference_byte,
    )
}

pub(crate) fn resolve_scoped_associated_item_matching(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    path: &str,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    if let Some(direct) = refs.resolve_scoped(path, item_name) {
        let candidates: Vec<_> = support
            .fqn(&direct)
            .into_iter()
            .filter(|candidate| item_matches(candidate) && candidate.identifier() == item_name)
            .collect();
        if !candidates.is_empty() {
            return ReceiverAnalysisOutcome::Precise(candidates);
        }
    }

    let Some(owner_fqn) = refs.resolve_scoped_owner(path) else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    resolve_owner_associated_item_matching(
        rust,
        support,
        refs,
        file,
        &owner_fqn,
        item_name,
        item_matches,
        reference_byte,
    )
}

pub(crate) fn resolve_owner_associated_item_matching(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner_fqn: &str,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let direct = if owner_fqn.is_empty() {
        item_name.to_string()
    } else {
        format!("{owner_fqn}.{item_name}")
    };
    let candidates: Vec<_> = support
        .fqn(&direct)
        .into_iter()
        .filter(|candidate| item_matches(candidate) && candidate.identifier() == item_name)
        .collect();
    if !candidates.is_empty() {
        return ReceiverAnalysisOutcome::Precise(candidates);
    }

    resolve_trait_associated_item_matching(
        rust,
        support,
        refs,
        file,
        owner_fqn,
        item_name,
        item_matches,
        reference_byte,
    )
}

pub(crate) fn resolve_exact_owner_associated_item_matching(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner: &CodeUnit,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let canonical_owner = rust
        .canonical_rust_hierarchy_type(owner.clone())
        .unwrap_or_else(|| owner.clone());
    let candidates: Vec<_> = support
        .members_for_owner_name(&canonical_owner.fq_name(), item_name)
        .into_iter()
        .filter(|candidate| item_matches(candidate) && candidate.identifier() == item_name)
        .filter(|candidate| {
            rust.structural_parent_of(candidate)
                .or_else(|| rust.parent_of(candidate))
                .and_then(|parent| rust.canonical_rust_hierarchy_type(parent))
                .is_some_and(|parent| parent == canonical_owner)
        })
        .collect();
    if !candidates.is_empty() {
        return ReceiverAnalysisOutcome::Precise(candidates);
    }

    resolve_trait_associated_item_for_owner_matching(
        rust,
        support,
        refs,
        file,
        &canonical_owner,
        item_name,
        item_matches,
        reference_byte,
    )
}

/// Compiler-style trait-candidate step for an owner type already resolved to
/// `owner_fqn`: enumerate traits implemented for the owner and visible at the
/// call site, and resolve iff exactly one declares `method_name`. Split out of
/// [`resolve_scoped_associated_item`] so `Self::assoc` (where the owner fqn
/// comes from the enclosing impl, not from a scoped path) shares one resolver.
pub(crate) fn resolve_trait_associated_item(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner_fqn: &str,
    method_name: &str,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    resolve_trait_associated_item_matching(
        rust,
        support,
        refs,
        file,
        owner_fqn,
        method_name,
        CodeUnit::is_function,
        reference_byte,
    )
}

pub(crate) fn resolve_trait_associated_item_matching(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner_fqn: &str,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let owner = match ReceiverAnalysisOutcome::single_precise_or_ambiguous(
        support
            .fqn(owner_fqn)
            .into_iter()
            .filter(|unit| rust.supports_type_hierarchy(unit))
            .filter(|unit| !rust.is_rust_trait_declaration(unit)),
        ReceiverAnalysisBudget::default(),
    ) {
        ReceiverAnalysisOutcome::Precise(mut owners) if owners.len() == 1 => owners.remove(0),
        ReceiverAnalysisOutcome::Ambiguous(owners) => {
            return ReceiverAnalysisOutcome::Ambiguous(owners);
        }
        ReceiverAnalysisOutcome::Precise(_)
        | ReceiverAnalysisOutcome::Unknown
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => {
            return ReceiverAnalysisOutcome::Unknown;
        }
    };

    resolve_trait_associated_item_for_owner_matching(
        rust,
        support,
        refs,
        file,
        &owner,
        item_name,
        item_matches,
        reference_byte,
    )
}

pub(crate) fn resolve_trait_associated_item_for_owner_matching(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    _refs: &RustReferenceContext,
    file: &ProjectFile,
    owner: &CodeUnit,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
    reference_byte: usize,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    ReceiverAnalysisOutcome::single_precise_or_ambiguous(
        rust.get_direct_ancestors(owner)
            .into_iter()
            .filter(|trait_unit| trait_visible_at_call_site(rust, file, trait_unit, reference_byte))
            .flat_map(|trait_unit| {
                support
                    .members_for_owner_name(&trait_unit.fq_name(), item_name)
                    .into_iter()
                    .filter(move |candidate| {
                        item_matches(candidate)
                            && candidate.identifier() == item_name
                            && rust
                                .structural_parent_of(candidate)
                                .or_else(|| rust.parent_of(candidate))
                                .as_ref()
                                .is_some_and(|parent| parent == &trait_unit)
                    })
            }),
        ReceiverAnalysisBudget::default(),
    )
}

fn trait_visible_at_call_site(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    trait_unit: &CodeUnit,
    reference_byte: usize,
) -> bool {
    let roots = [trait_unit.clone()].into_iter().collect::<BTreeSet<_>>();
    let seeds = rust.usage_binding_seeds(&roots);
    let mut names = rust.usage_binding_local_names(file, &seeds);
    names.insert(trait_unit.identifier().to_string());
    let Some(prepared) = rust.prepared_syntax(file) else {
        return false;
    };
    let lexical_scope = RustLexicalScopeIndex::new(prepared.tree().root_node(), prepared.source());
    names.into_iter().any(|name| {
        let root_shadowed = lexical_scope.name_bound_at(&name, reference_byte)
            || (lexical_scope.item_bound_at(&name, reference_byte)
                && !rust.usage_root_declaration_matches_at(file, &seeds, &name, reference_byte)
                && !rust.usage_local_module_prefix_visible_at(file, &seeds, &name, reference_byte));
        let resolution = rust.usage_reference_at(
            file,
            &seeds,
            &[name.as_str()],
            reference_byte,
            crate::analyzer::rust::RustReferenceNamespace::Type,
            root_shadowed,
        );
        rust.usage_exact_root_for_resolution(&resolution, &seeds)
            .is_some_and(|resolved| resolved == *trait_unit)
    })
}

pub(super) fn canonical_usage_target(rust: &RustAnalyzer, target: &CodeUnit) -> CodeUnit {
    canonical_imported_impl_target(rust, target).unwrap_or_else(|| target.clone())
}

pub(super) fn local_impl_target_importer_files(
    rust: &RustAnalyzer,
    target: &CodeUnit,
) -> HashSet<ProjectFile> {
    let Some(resolved_fqn) = imported_impl_target_fqn(rust, target) else {
        return HashSet::default();
    };
    if rust.definitions(&resolved_fqn).next().is_some() {
        return HashSet::default();
    }

    rust.get_analyzed_files()
        .into_iter()
        .filter(|file| {
            rust.reference_context_of(file)
                .bare_names_resolving_to(&resolved_fqn)
                .contains(target.identifier())
        })
        .collect()
}

pub(super) fn infer_graph_seeds(analyzer: &RustAnalyzer, target: &CodeUnit) -> RustGraphSeeds {
    let roots = infer_export_graph_seeds(analyzer, target);
    if !roots.is_empty() {
        return RustGraphSeeds {
            roots,
            kind: RustGraphSeedKind::Export,
        };
    }

    RustGraphSeeds {
        roots: local_declaration_graph_seeds(analyzer, target),
        kind: RustGraphSeedKind::LocalDeclaration,
    }
}

fn infer_export_graph_seeds(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<CodeUnit> {
    let Some(seed_target) = graph_seed_target(analyzer, target) else {
        return BTreeSet::new();
    };
    let roots = BTreeSet::from([seed_target]);
    // A module-scope constant is represented as a parentless field. Its own
    // declaration remains a valid import origin even when a public-like
    // visibility produces additional export seeds through the crate graph.
    // Retain that structured origin so `use crate::module::CONST` bindings are
    // matched without treating the constant as a type member.
    if target.is_field()
        && analyzer.parent_of(target).is_none()
        && is_local_declaration(analyzer, target)
    {
        return roots;
    }
    if !infer_export_names(analyzer, target).is_empty() {
        return roots;
    }

    if let Some(parent) = analyzer.parent_of(target)
        && parent.is_module()
        && parent.source() != target.source()
        && is_public_like_declaration(analyzer, target)
    {
        let parent_index = analyzer.export_index_of(parent.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            return roots;
        }
    }

    // Last resort: resolve an export-visible item that reaches the public API only
    // through a `pub use` re-export of a private module. These names are tried only
    // via real re-export chains, so a private, never-re-exported item stays unseeded.
    if !reexport_fallback_export_names(analyzer, target).is_empty()
        && analyzer.usage_binding_seeds(&roots).has_import_edges()
    {
        return roots;
    }

    BTreeSet::new()
}

fn local_declaration_graph_seeds(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<CodeUnit> {
    let member_target = is_member_target(analyzer, target);
    let seed_target = graph_seed_target(analyzer, target);
    let Some(seed_target) = seed_target else {
        return BTreeSet::new();
    };
    // Macro-generated and imported impl target types may not have their own
    // declaration in this file. Their impl members do, and the parser retains
    // the exact structural owner for those members. Seed that owner identity so
    // associated references inside the impl remain graph-addressable.
    if !(is_local_declaration(analyzer, &seed_target)
        || member_target && is_local_declaration(analyzer, target))
    {
        return BTreeSet::new();
    }
    [seed_target].into_iter().collect()
}

fn graph_seed_target(analyzer: &RustAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    let seed_target = if is_member_target(analyzer, target) {
        analyzer.parent_of(target)?
    } else {
        target.clone()
    };
    Some(canonical_imported_impl_target(analyzer, &seed_target).unwrap_or(seed_target))
}

fn is_local_declaration(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    analyzer
        .declarations(target.source())
        .into_iter()
        .any(|declaration| &declaration == target)
}

fn canonical_imported_impl_target(rust: &RustAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    let resolved_fqn = imported_impl_target_fqn(rust, target)?;
    let mut definitions = rust
        .definitions(&resolved_fqn)
        .filter(|definition| definition != target);
    let first = definitions.next()?;
    definitions.next().is_none().then_some(first)
}

fn imported_impl_target_fqn(rust: &RustAnalyzer, target: &CodeUnit) -> Option<String> {
    if !target.is_class() || rust.parent_of(target).is_some() || !is_impl_target_unit(rust, target)
    {
        return None;
    }
    let refs = rust.reference_context_of(target.source());
    let resolved = refs.resolve_bare(target.identifier())?;
    (resolved != target.fq_name()).then(|| resolved.to_string())
}

fn is_impl_target_unit(rust: &RustAnalyzer, target: &CodeUnit) -> bool {
    let Ok(source) = target.source().read_to_string() else {
        return false;
    };
    let Some(range) = rust.ranges(target).into_iter().next() else {
        return false;
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return false;
    };
    tree.root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)
        .is_some_and(|node| node.kind() == "impl_item")
}

fn infer_export_names(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner) = analyzer.parent_of(target)
    {
        let owner_exports =
            infer_export_names_for_local(analyzer, owner.source(), owner.identifier());
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    let mut export_names =
        infer_export_names_for_local(analyzer, target.source(), target.identifier());
    if !export_names.is_empty() {
        return export_names;
    }

    if let Some(owner) = analyzer.parent_of(target)
        && owner.is_module()
        && owner.source() != target.source()
    {
        let parent_index = analyzer.export_index_of(owner.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            export_names.insert(target.identifier().to_string());
        }
    }

    if target.is_function() && analyzer.parent_of(target).is_none() {
        return [target.identifier().to_string()].into_iter().collect();
    }

    BTreeSet::new()
}

/// Export names to try only through actual re-export chains, after the primary
/// inference yields no seeds. An export-visible item can live in a private `mod`
/// whose own file exports nothing, reaching the crate's public API solely through a
/// `pub use` re-export elsewhere. Seed by the export identifier — the owner's, for a
/// member referenced through a value of the owner type. Unlike the primary names,
/// these are never force-seeded onto the definition file: reachability is decided by
/// whether the re-export chain exists, so an export-visible-but-never-re-exported
/// item still resolves to no seeds.
fn reexport_fallback_export_names(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if !is_export_visible_declaration(analyzer, target) {
        return BTreeSet::new();
    }
    if (target.is_function() || target.is_field())
        && let Some(owner) = analyzer.parent_of(target)
        && !owner.is_module()
        && is_export_visible_declaration(analyzer, &owner)
    {
        return [owner.identifier().to_string()].into_iter().collect();
    }
    [target.identifier().to_string()].into_iter().collect()
}

fn infer_export_names_for_local(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    local_name: &str,
) -> BTreeSet<String> {
    let index = analyzer.export_index_of(file);
    let mut export_names = BTreeSet::new();
    if index.exports_by_name.contains_key(local_name) {
        export_names.insert(local_name.to_string());
    }
    for (export_name, entry) in index.exports_by_name {
        if matches!(entry, crate::analyzer::usages::ExportEntry::Local { local_name: ref name } if name == local_name)
        {
            export_names.insert(export_name);
        }
    }
    export_names
}

pub(super) fn unresolved_external_frontier_specifiers(
    analyzer: &RustAnalyzer,
    defining_file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<String> {
    let mut frontier = BTreeSet::new();
    let index = analyzer.export_index_of(defining_file);

    if let Some(crate::analyzer::usages::ExportEntry::ReexportedNamed {
        module_specifier, ..
    }) = index.exports_by_name.get(export_name)
        && analyzer
            .resolve_module_files(defining_file, module_specifier)
            .is_empty()
        && let Some(external) = external_frontier_specifier(module_specifier)
    {
        frontier.insert(external);
    }

    for star in &index.reexport_stars {
        if analyzer
            .resolve_module_files(defining_file, &star.module_specifier)
            .is_empty()
            && let Some(external) = external_frontier_specifier(&star.module_specifier)
        {
            frontier.insert(external);
        }
    }

    frontier
}

fn external_frontier_specifier(module_specifier: &str) -> Option<String> {
    let root = module_specifier
        .split("::")
        .find(|segment| !segment.is_empty())?
        .trim();
    (!matches!(root, "crate" | "self" | "super") && !root.is_empty()).then(|| root.to_string())
}
