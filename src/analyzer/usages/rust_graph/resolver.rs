use crate::analyzer::rust::lexical_scope::{self, RustLexicalScopeIndex};
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{
    CodeUnit, GlobalUsageDefinitionIndex, IAnalyzer, ProjectFile, RustAnalyzer,
    RustReferenceContext, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use tree_sitter::Node;

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
    Macro,
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
                .is_some_and(|bang| bang.kind() == "!")
            {
                RustTokenPathRole::Macro
            } else if children
                .get(segment_index + 1)
                .is_some_and(rust_token_call_arguments)
            {
                RustTokenPathRole::Call
            } else {
                RustTokenPathRole::Value
            };

            let fqn = if dollar_crate_root {
                if segment_index == index {
                    None
                } else {
                    let normalized_path = path
                        .iter()
                        .filter_map(|node| {
                            if rust_token_is_dollar_crate(*node, source) {
                                Some("crate")
                            } else {
                                source
                                    .get(node.start_byte()..node.end_byte())
                                    .map(str::trim)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("::");
                    resolve_rust_path_fqn(rust, refs, file, &normalized_path)
                        .filter(|fqn| !support.fqn(fqn).is_empty())
                        .or_else(|| {
                            (path.len() == 2).then(|| {
                                resolve_crate_exported_token_path_child(
                                    rust, support, file, source, segment,
                                )
                            })?
                        })
                        .or_else(|| {
                            dollar_crate_owner.as_deref().and_then(|owner| {
                                resolve_direct_token_path_child(support, source, owner, segment)
                            })
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

fn resolve_crate_exported_token_path_child(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    segment: Node<'_>,
) -> Option<String> {
    let name = source.get(segment.start_byte()..segment.end_byte())?;
    let fqns = rust
        .usage_crate_export_targets(file, name)
        .into_iter()
        .flat_map(|(target_file, target_name)| support.file_identifier(&target_file, &target_name))
        .map(|candidate| candidate.fq_name())
        .collect::<BTreeSet<_>>();
    (fqns.len() == 1).then(|| fqns.into_iter().next()).flatten()
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
    // Resolve the written owner first, then select its written child. This keeps
    // aliases as their own declaration identity instead of allowing the full
    // type path resolver to canonicalize `module::Alias` to the aliased type.
    if let Some(owner_fqn) = resolve_rust_path_fqn(rust, refs, file, owner) {
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

pub(crate) fn lexical_import_fqn(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    segment: Node<'_>,
) -> Option<String> {
    let name = source.get(segment.start_byte()..segment.end_byte())?.trim();
    lexical_explicit_import_fqn(rust, support, file, source, segment).or_else(|| {
        let forward = rust.forward_reference_context_of(file);
        forward
            .resolve_bare(name)
            .filter(|fqn| !support.fqn(fqn).is_empty())
            .map(str::to_string)
    })
}

pub(crate) fn lexical_explicit_import_fqn(
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
        .filter(|candidate| {
            candidate.is_module() || candidate.is_class() || rust.is_type_alias(candidate)
        })
        .map(|candidate| candidate.fq_name())
        .collect();
    if fqns.len() == 1 {
        return fqns.into_iter().next();
    }
    let mut pending = rust.resolve_visible_import_targets_forward(file, &binder, name);
    let mut visited = HashSet::default();
    let mut imported_fqns = BTreeSet::new();
    while let Some((target_file, target_name)) = pending.pop() {
        if !visited.insert((target_file.clone(), target_name.clone())) {
            continue;
        }
        let direct = support
            .file_identifier(&target_file, &target_name)
            .into_iter()
            .filter(|candidate| {
                candidate.is_module() || candidate.is_class() || rust.is_type_alias(candidate)
            })
            .collect::<Vec<_>>();
        if !direct.is_empty() {
            imported_fqns.extend(direct.into_iter().map(|candidate| candidate.fq_name()));
            continue;
        }
        let Ok(target_source) = target_file.read_to_string() else {
            continue;
        };
        let target_binder =
            lexical_scope::visible_import_binder_at(&target_source, target_source.len());
        pending.extend(rust.resolve_visible_import_targets_forward(
            &target_file,
            &target_binder,
            &target_name,
        ));
    }
    if imported_fqns.len() == 1 {
        return imported_fqns.into_iter().next();
    }
    None
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustBareTokenTreeRole {
    Reference,
    TypeReference,
    Pattern,
    Binding,
    Declaration,
}

impl RustBareTokenTreeRole {
    pub(crate) fn is_reference_candidate(self) -> bool {
        matches!(self, Self::Reference | Self::TypeReference)
    }
}

/// Per-file cache of roles projected from reparsed macro token trees.
///
/// The inverse and forward usage scans can visit every raw identifier in a
/// token tree. Cache the complete projection on the first visit so each nearest
/// or enclosing token tree is parsed at most once per scan rather than once per
/// identifier. Enclosing groups supply context such as `match { pattern => }`,
/// while a nested macro's nearest group supplies its closure-parameter roles.
#[derive(Default)]
pub(crate) struct RustTokenTreeRoleCache {
    roles: HashMap<(usize, usize), HashMap<(usize, usize), RustBareTokenTreeRole>>,
}

impl RustTokenTreeRoleCache {
    pub(crate) fn role(&mut self, node: Node<'_>, source: &str) -> RustBareTokenTreeRole {
        if !rust_bare_token_tree_identifier(node) {
            return RustBareTokenTreeRole::Reference;
        }
        let Some(mut token_tree) = direct_token_tree(node) else {
            return RustBareTokenTreeRole::Reference;
        };
        loop {
            let tree_key = (token_tree.start_byte(), token_tree.end_byte());
            self.roles
                .entry(tree_key)
                .or_insert_with(|| parse_token_tree_roles(token_tree, source).unwrap_or_default());
            if let Some(role) = self
                .roles
                .get(&tree_key)
                .and_then(|roles| roles.get(&(node.start_byte(), node.end_byte())))
                .copied()
                && role != RustBareTokenTreeRole::Reference
            {
                return role;
            }
            let Some(enclosing) = enclosing_token_tree(token_tree) else {
                break;
            };
            token_tree = enclosing;
        }
        direct_token_tree_role(node)
    }
}

/// Classify a bare identifier represented directly by a macro token tree.
///
/// Tree-sitter intentionally leaves macro input as raw tokens. For the few
/// spellings whose sibling punctuation is ambiguous (`as`, `=>`, and `|`),
/// parse the enclosing token-tree fragment with the Rust grammar and project
/// the original byte range into that tree. This distinguishes cast types from
/// import aliases, unit variants from match bindings, closure parameters from
/// bitwise operands, and declaration names from their referenced types without
/// a source-text mini-parser or delimiter scan.
pub(crate) fn rust_bare_token_tree_role(node: Node<'_>, source: &str) -> RustBareTokenTreeRole {
    RustTokenTreeRoleCache::default().role(node, source)
}

fn direct_token_tree_role(node: Node<'_>) -> RustBareTokenTreeRole {
    let previous = node.prev_sibling();
    let next = node.next_sibling();
    if previous.is_some_and(|token| {
        matches!(
            token.kind(),
            "$" | "'"
                | "label"
                | "struct"
                | "enum"
                | "union"
                | "trait"
                | "type"
                | "fn"
                | "mod"
                | "const"
                | "static"
                | "let"
        )
    }) {
        return RustBareTokenTreeRole::Declaration;
    }
    if next.is_some_and(|token| matches!(token.kind(), ":" | "label")) {
        return RustBareTokenTreeRole::Binding;
    }
    RustBareTokenTreeRole::Reference
}

pub(crate) fn rust_bare_token_tree_non_reference_role(node: Node<'_>, source: &str) -> bool {
    matches!(
        rust_bare_token_tree_role(node, source),
        RustBareTokenTreeRole::Binding | RustBareTokenTreeRole::Declaration
    )
}

fn rust_bare_token_tree_identifier(node: Node<'_>) -> bool {
    matches!(node.kind(), "identifier" | "type_identifier")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "token_tree")
        && !rust_token_path_segment_is_qualified(node)
}

fn direct_token_tree(node: Node<'_>) -> Option<Node<'_>> {
    node.parent().filter(|parent| parent.kind() == "token_tree")
}

fn enclosing_token_tree(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "token_tree" {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn parse_token_tree_roles(
    token_tree: Node<'_>,
    source: &str,
) -> Option<HashMap<(usize, usize), RustBareTokenTreeRole>> {
    let open = token_tree.child(0)?;
    let close = token_tree.child(token_tree.child_count().checked_sub(1)?)?;
    if !matches!(open.kind(), "(" | "[" | "{") || !matches!(close.kind(), ")" | "]" | "}") {
        return None;
    }
    let fragment = source.get(open.end_byte()..close.start_byte())?;
    let tree = lexical_scope::parse_rust_tree(fragment)?;
    let lexical_scope = RustLexicalScopeIndex::new(tree.root_node(), fragment);
    let mut roles = HashMap::default();
    let mut stack = vec![tree.root_node()];
    while let Some(parsed) = stack.pop() {
        if matches!(parsed.kind(), "identifier" | "type_identifier") {
            let role = parsed_identifier_role(parsed, fragment, &lexical_scope);
            roles.insert(
                (
                    open.end_byte() + parsed.start_byte(),
                    open.end_byte() + parsed.end_byte(),
                ),
                role,
            );
        }
        for index in (0..parsed.named_child_count()).rev() {
            if let Some(child) = parsed.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(roles)
}

fn parsed_identifier_role(
    parsed: Node<'_>,
    fragment: &str,
    lexical_scope: &RustLexicalScopeIndex,
) -> RustBareTokenTreeRole {
    if parsed_identifier_is_declaration(parsed) {
        return RustBareTokenTreeRole::Declaration;
    }
    if parsed_identifier_is_direct_pattern(parsed) {
        return RustBareTokenTreeRole::Pattern;
    }
    if lexical_scope::is_pattern_binding_identifier(parsed) {
        return RustBareTokenTreeRole::Binding;
    }
    if parsed_identifier_is_shadowed_by_closure_binding(parsed, fragment) {
        return RustBareTokenTreeRole::Binding;
    }
    if parsed.kind() == "type_identifier" {
        return RustBareTokenTreeRole::TypeReference;
    }
    let name = fragment
        .get(parsed.start_byte()..parsed.end_byte())
        .unwrap_or_default();
    if lexical_scope.name_bound_at(name, parsed.start_byte()) {
        return RustBareTokenTreeRole::Binding;
    }
    RustBareTokenTreeRole::Reference
}

fn parsed_identifier_is_declaration(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "use_as_clause"
        && parent
            .child_by_field_name("alias")
            .is_some_and(|alias| alias.id() == node.id())
    {
        return true;
    }
    matches!(
        parent.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "type_item"
            | "mod_item"
            | "const_item"
            | "static_item"
            | "field_declaration"
            | "enum_variant"
            | "macro_definition"
            | "type_parameter"
            | "const_parameter"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| name.id() == node.id())
}

fn parsed_identifier_is_shadowed_by_closure_binding(node: Node<'_>, source: &str) -> bool {
    let Some(name) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    let mut current = node.parent();
    while let Some(parent) = current {
        // A token-tree fragment containing only a closure can recover as an
        // ERROR node whose structured children are `closure_parameters` plus
        // the body expression. Preserve that AST relationship as well as the
        // ordinary `closure_expression` shape.
        if matches!(parent.kind(), "closure_expression" | "ERROR")
            && (0..parent.named_child_count())
                .filter_map(|index| parent.named_child(index))
                .find(|child| child.kind() == "closure_parameters")
                .is_some_and(|parameters| closure_parameters_bind_name(parameters, source, name))
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn closure_parameters_bind_name(parameters: Node<'_>, source: &str, name: &str) -> bool {
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && lexical_scope::is_pattern_binding_identifier(node)
            && source.get(node.start_byte()..node.end_byte()) == Some(name)
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn parsed_identifier_is_direct_pattern(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "match_pattern"
            || (parent.kind() == "let_condition"
                && parent
                    .child_by_field_name("pattern")
                    .is_some_and(|pattern| pattern.id() == node.id()))
    })
}

pub(crate) fn rust_unique_nominal_reference_namespace(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    fqn: &str,
) -> Option<crate::analyzer::rust::RustReferenceNamespace> {
    use crate::analyzer::rust::RustReferenceNamespace;

    let declarations = support.fqn(fqn);
    let has_type = declarations
        .iter()
        .any(|declaration| declaration.is_class() || rust.is_type_alias(declaration));
    let has_value = declarations.iter().any(|declaration| {
        !rust.is_type_alias(declaration) && (declaration.is_function() || declaration.is_field())
    });
    let has_macro = declarations.iter().any(CodeUnit::is_macro);
    let has_module = declarations.iter().any(CodeUnit::is_module);
    let namespace_count = [has_type, has_value, has_macro, has_module]
        .into_iter()
        .filter(|present| *present)
        .count();
    if namespace_count != 1 {
        return None;
    }
    if has_type {
        Some(RustReferenceNamespace::Type)
    } else if has_value {
        Some(RustReferenceNamespace::Value)
    } else if has_macro {
        Some(RustReferenceNamespace::Macro)
    } else {
        Some(RustReferenceNamespace::PathPrefix)
    }
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
            parent.is_class() || analyzer.is_type_alias(&parent)
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
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
            false,
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

pub(super) fn canonical_imported_impl_target(
    rust: &RustAnalyzer,
    target: &CodeUnit,
) -> Option<CodeUnit> {
    let resolved_fqn = imported_impl_target_fqn(rust, target)?;
    let mut definitions = rust
        .definitions(&resolved_fqn)
        .filter(|definition| definition != target);
    let first = definitions.next()?;
    definitions.next().is_none().then_some(first)
}

fn imported_impl_target_fqn(rust: &RustAnalyzer, target: &CodeUnit) -> Option<String> {
    if !target.is_class()
        || rust
            .definitions(&target.fq_name())
            .any(|definition| definition == *target)
    {
        return None;
    }
    let refs = rust.reference_context_of(target.source());
    let resolved = refs.resolve_bare(target.identifier())?;
    Some(resolved.to_string())
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
