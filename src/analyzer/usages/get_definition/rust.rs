use super::*;
use crate::analyzer::RustReferenceContext;
use crate::analyzer::rust::field_roles::{
    RustFieldNameRole, RustStructFieldContainer, classify_rust_field_name,
};
use crate::analyzer::rust::lexical_scope;
use crate::analyzer::rust::rust_focused_use_path;
use crate::analyzer::usages::rust_graph::RustDefinitionProvider;
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;

pub(crate) struct AnalyzerRustDefinitionProvider<'a> {
    rust: &'a RustAnalyzer,
    cache_lookups: bool,
    fqns: RefCell<HashMap<String, Vec<CodeUnit>>>,
    file_identifiers: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
}

impl<'a> AnalyzerRustDefinitionProvider<'a> {
    pub(crate) fn new(rust: &'a RustAnalyzer, cache_lookups: bool) -> Self {
        Self {
            rust,
            cache_lookups,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }
}

impl RustDefinitionProvider for AnalyzerRustDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        if self.cache_lookups
            && let Some(units) = self.fqns.borrow().get(fqn)
        {
            return units.clone();
        }
        let mut units: Vec<_> = self.rust.definitions(fqn).collect();
        sort_units(&mut units);
        units.dedup();
        if self.cache_lookups {
            self.fqns
                .borrow_mut()
                .insert(fqn.to_string(), units.clone());
        }
        units
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        if self.cache_lookups {
            let key = (file.clone(), identifier.to_string());
            if let Some(units) = self.file_identifiers.borrow().get(&key) {
                return units.clone();
            }
        }
        let mut units: Vec<_> = self
            .rust
            .declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == identifier)
            .collect();
        sort_units(&mut units);
        units.dedup();
        if self.cache_lookups {
            self.file_identifiers
                .borrow_mut()
                .insert((file.clone(), identifier.to_string()), units.clone());
        }
        units
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_rust(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
    operation: Option<NavigationOperation>,
) -> DefinitionLookupOutcome {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let reference = site.text.as_str();
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_struct_field_name_outcome(analyzer, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && !reference.contains(['.', ':'])
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && node.kind() == "identifier"
        && (lexical_scope::is_pattern_binding_identifier(node)
            || lexical_scope::name_shadowed_in_tree(
                tree.root_node(),
                source,
                reference,
                site.focus_start_byte,
            ))
    {
        return no_definition(
            "local_binding",
            format!("`{reference}` is a local Rust binding, which is not indexed"),
        );
    }
    if let Some(tree) = tree
        && let Some(operation) = operation
        && let Some(outcome) = rust_qualified_associated_type_navigation_outcome(
            rust, analyzer, support, file, source, tree, site, operation,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_impl_associated_type_declaration_outcome(
            rust, support, file, source, tree, site, operation,
        )
    {
        return outcome;
    }
    if reference.contains('.')
        && let Some(tree) = tree
        && let Some(outcome) =
            resolve_rust_field(analyzer, support, file, source, tree, site, cache)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) =
            rust_self_scoped_associated_type_candidates(analyzer, file, source, tree, site)
        && !candidates.is_empty()
    {
        return candidates_outcome(candidates);
    }
    // `Self` (as a type) denotes the lexically enclosing impl's type — the Rust
    // form of the `LexicalEnclosingType` receiver origin. Name-based resolution
    // (`resolve_bare` / `resolve_scoped`) has no notion of `Self`, so resolve it
    // here where the cursor node is available: bare `Self` / `Self { .. }` goes
    // to the type declaration, and `Self::assoc` to the associated item.
    if let Some(tree) = tree
        && (reference == "Self" || reference.starts_with("Self::"))
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && let Some(self_type) = rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
    {
        let focused_segment = reference_segments(site, "::", 2)
            .and_then(|segments| focus_segment_index(site, &segments));
        let candidates = match reference.split_once("::") {
            Some(_) if focused_segment == Some(0) => support.fqn(&self_type),
            Some((_, name)) => {
                let mut candidates = rust_member_candidates(
                    support.fqn(&format!("{self_type}.{name}")),
                    RustMemberKind::Function,
                );
                if candidates.is_empty() {
                    // The enclosing impl's type may get the associated item from an
                    // implemented trait; the owner fqn is already resolved, so this
                    // enters the shared resolver past its scoped-path step.
                    let refs = rust.forward_reference_context_of(file);
                    candidates =
                        match crate::analyzer::usages::rust_graph::resolve_trait_associated_item(
                            rust, support, &refs, file, &self_type, name,
                        ) {
                            ReceiverAnalysisOutcome::Precise(resolved) => {
                                rust_member_candidates(resolved, RustMemberKind::Function)
                            }
                            ReceiverAnalysisOutcome::Ambiguous(_)
                            | ReceiverAnalysisOutcome::Unknown
                            | ReceiverAnalysisOutcome::Unsupported { .. }
                            | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                        };
                }
                if candidates.is_empty() {
                    let refs = rust.forward_reference_context_of(file);
                    candidates = match crate::analyzer::usages::rust_graph::resolve_trait_associated_item_matching(
                        rust,
                        support,
                        &refs,
                        file,
                        &self_type,
                        name,
                        CodeUnit::is_field,
                    ) {
                        ReceiverAnalysisOutcome::Precise(resolved) => {
                            rust_member_candidates(resolved, RustMemberKind::Field)
                        }
                        ReceiverAnalysisOutcome::Ambiguous(_)
                        | ReceiverAnalysisOutcome::Unknown
                        | ReceiverAnalysisOutcome::Unsupported { .. }
                        | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                    };
                }
                candidates
            }
            None => support.fqn(&self_type),
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    let refs = rust.forward_reference_context_of(file);
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_use_path_outcome(rust, support, file, source, tree, site, &refs)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_scoped_prefix_outcome(rust, support, file, source, tree, site, &refs)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_token_tree_prefix_outcome(rust, support, file, source, tree, site, &refs)
    {
        return outcome;
    }
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let resolved = match crate::analyzer::usages::rust_graph::resolve_scoped_associated_item(
            rust, support, &refs, file, path, name,
        ) {
            ReceiverAnalysisOutcome::Precise(candidates) => candidates,
            ReceiverAnalysisOutcome::Ambiguous(_)
            | ReceiverAnalysisOutcome::Unknown
            | ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
        };
        (resolved, true)
    } else {
        // Prefer a type declared in the lexically enclosing scope (module) over the
        // flat same-file name map, so a bare `Config` inside `mod b` resolves to
        // `b::Config` rather than a same-named sibling module's `Config` (#431). The
        // `is_class` filter keeps this to type references — a bare function call is
        // left to the name map below, so free-function resolution is unchanged.
        if let Some(unit) = resolve_in_enclosing_scopes(
            analyzer,
            file,
            reference,
            site.focus_start_byte,
            CodeUnit::is_class,
        ) {
            return candidates_outcome(vec![unit]);
        }
        let resolved = if let Some(tree) = tree
            && let Some(role) = rust_bare_reference_role(tree, site)
        {
            if role == RustBareReferenceRole::Type
                && lexical_scope::local_item_name_shadowed_in_tree(
                    tree.root_node(),
                    source,
                    reference,
                    site.focus_start_byte,
                )
            {
                return no_definition(
                    "local_binding",
                    format!("`{reference}` is a local Rust item, which is not indexed"),
                );
            }
            match rust_visible_import_resolution(
                rust,
                support,
                file,
                source,
                site.focus_start_byte,
                reference,
                role,
            ) {
                RustVisibleImportResolution::Resolved(candidates) => candidates,
                RustVisibleImportResolution::GlobResolved(candidates) => {
                    let local = rust_current_module_candidates(
                        analyzer, rust, support, file, tree, site, reference, role, &refs,
                    );
                    if local.is_empty() { candidates } else { local }
                }
                RustVisibleImportResolution::BoundButUnindexed => {
                    return boundary(format!(
                        "`{reference}` is explicitly imported across a Rust crate/module boundary that is not indexed"
                    ));
                }
                RustVisibleImportResolution::Unbound => rust_current_module_candidates(
                    analyzer, rust, support, file, tree, site, reference, role, &refs,
                ),
            }
        } else {
            refs.resolve_bare(reference)
                .map(|fqn| support.fqn(fqn))
                .unwrap_or_default()
        };
        (resolved, false)
    };
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if rust_reference_looks_external(reference) {
        return boundary(format!(
            "`{reference}` appears to cross a Rust crate/module boundary not indexed in this workspace"
        ));
    }
    if scoped_lookup_failed {
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve through its Rust module path"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Rust definition"),
    )
}

fn rust_struct_field_name_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    match classify_rust_field_name(focused) {
        RustFieldNameRole::Declaration { name }
            if name.start_byte() == site.focus_start_byte
                && name.end_byte() == site.focus_end_byte =>
        {
            Some(no_definition(
                "declaration_site",
                "Rust field declaration names do not reference another definition",
            ))
        }
        RustFieldNameRole::Reference {
            owner_type,
            name,
            container: RustStructFieldContainer::Literal,
        } if name.start_byte() == site.focus_start_byte
            && name.end_byte() == site.focus_end_byte =>
        {
            let Some(owner) = rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                owner_type,
                Some(owner_type.start_byte()),
            ) else {
                return Some(no_definition(
                    "unresolved_struct_owner",
                    "Rust struct literal owner could not be resolved",
                ));
            };
            let name = &source[name.byte_range()];
            let candidates = support
                .fqn(&format!("{owner}.{name}"))
                .into_iter()
                .filter(CodeUnit::is_field)
                .collect();
            Some(candidates_outcome(candidates))
        }
        RustFieldNameRole::Reference {
            container: RustStructFieldContainer::Pattern,
            ..
        }
        | RustFieldNameRole::Other
        | RustFieldNameRole::Declaration { .. }
        | RustFieldNameRole::Reference { .. } => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustBareReferenceRole {
    Type,
    // Rust struct and enum constructors occupy the value namespace too.
    Value,
}

enum RustVisibleImportResolution {
    Resolved(Vec<CodeUnit>),
    GlobResolved(Vec<CodeUnit>),
    BoundButUnindexed,
    Unbound,
}

fn rust_bare_reference_role(
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<RustBareReferenceRole> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    match node.kind() {
        "type_identifier" => Some(RustBareReferenceRole::Type),
        "identifier" => Some(RustBareReferenceRole::Value),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_visible_import_resolution(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    reference_byte: usize,
    reference: &str,
    role: RustBareReferenceRole,
) -> RustVisibleImportResolution {
    let binder = lexical_scope::visible_import_binder_at(source, reference_byte);
    let explicitly_bound = rust_binder_has_external_binding(&binder, reference);
    let mut expected_fqns = HashSet::default();
    if explicitly_bound {
        for (local_name, binding) in &binder.bindings {
            if local_name != reference || binding.kind != ImportKind::Named {
                continue;
            }
            let imported = binding.imported_name.as_deref().unwrap_or(reference);
            if let Some(package) = rust.resolve_module_package(file, &binding.module_specifier) {
                expected_fqns.insert(format!("{package}.{imported}"));
            }
        }
    }
    let targets = rust.resolve_imported_export_from_binder_forward(file, &binder, reference);
    let mut candidates = Vec::new();
    for (target_file, target_name) in targets {
        candidates.extend(
            support
                .file_identifier(&target_file, &target_name)
                .into_iter()
                .filter(|candidate| rust_role_accepts_imported(rust, role, candidate)),
        );
    }
    if explicitly_bound && !expected_fqns.is_empty() {
        let exact: Vec<_> = candidates
            .iter()
            .filter(|candidate| expected_fqns.contains(&candidate.fq_name()))
            .cloned()
            .collect();
        if !exact.is_empty() {
            candidates = exact;
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        if explicitly_bound {
            RustVisibleImportResolution::Resolved(candidates)
        } else {
            RustVisibleImportResolution::GlobResolved(candidates)
        }
    } else if explicitly_bound {
        RustVisibleImportResolution::BoundButUnindexed
    } else {
        RustVisibleImportResolution::Unbound
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_current_module_candidates(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    reference: &str,
    role: RustBareReferenceRole,
    refs: &RustReferenceContext,
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: site.focus_start_byte,
        end_byte: site.focus_end_byte,
        start_line: 0,
        end_line: 0,
    };
    let mut enclosing = Vec::new();
    let mut current = analyzer.enclosing_code_unit(file, &range);
    while let Some(unit) = current {
        enclosing.push(unit.clone());
        current = analyzer.parent_of(&unit);
    }
    let package = enclosing
        .first()
        .map(CodeUnit::package_name)
        .unwrap_or_else(|| refs.package_name());
    let reference_module =
        lexical_scope::enclosing_mod_item_range_at(tree.root_node(), site.focus_start_byte);
    let mut candidates: Vec<_> = support
        .file_identifier(file, reference)
        .into_iter()
        .filter(|candidate| candidate.package_name() == package)
        .filter(|candidate| rust_role_accepts_current_module(analyzer, rust, role, candidate))
        .filter(|candidate| {
            analyzer
                .ranges(candidate)
                .first()
                .map(|range| {
                    lexical_scope::enclosing_mod_item_range_at(tree.root_node(), range.start_byte)
                        == reference_module
                })
                .unwrap_or(reference_module.is_none())
        })
        .filter(|candidate| {
            analyzer.parent_of(candidate).is_none_or(|parent| {
                parent.is_module() || enclosing.iter().any(|scope| scope == &parent)
            })
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_role_accepts_imported(
    rust: &RustAnalyzer,
    role: RustBareReferenceRole,
    candidate: &CodeUnit,
) -> bool {
    match role {
        RustBareReferenceRole::Type => candidate.is_class() || rust.is_type_alias(candidate),
        RustBareReferenceRole::Value => !candidate.is_module(),
    }
}

fn rust_role_accepts_current_module(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    role: RustBareReferenceRole,
    candidate: &CodeUnit,
) -> bool {
    match role {
        RustBareReferenceRole::Type => candidate.is_class() || rust.is_type_alias(candidate),
        RustBareReferenceRole::Value => {
            candidate.is_class()
                || candidate.is_function()
                || (candidate.is_field()
                    && analyzer
                        .parent_of(candidate)
                        .is_none_or(|parent| !parent.is_class()))
        }
    }
}

fn rust_impl_associated_type_declaration_outcome(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    operation: Option<NavigationOperation>,
) -> Option<DefinitionLookupOutcome> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let type_item =
        rust_enclosing_named_associated_type(node, site.focus_start_byte, site.focus_end_byte)?;
    let name = type_item.child_by_field_name("name")?;
    let associated_type = rust_node_text(name, source).trim();
    if associated_type.is_empty() {
        return None;
    }
    let impl_item = rust_enclosing_ancestor(type_item, "impl_item")?;
    if operation == Some(NavigationOperation::Definition) {
        let candidate =
            rust.rust_associated_type_declaration_for_exact_node(file, type_item, associated_type)?;
        return Some(candidates_outcome(vec![candidate]));
    }
    let trait_type = impl_item.child_by_field_name("trait")?;
    let trait_fqn = rust_resolve_type_node_fqn(
        rust,
        support,
        file,
        source,
        trait_type,
        Some(trait_type.start_byte()),
    )?;
    let mut candidates: Vec<_> = support
        .fqn(&format!("{trait_fqn}.{associated_type}"))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates_outcome(candidates))
}

#[allow(clippy::too_many_arguments)]
fn rust_qualified_associated_type_navigation_outcome(
    rust: &RustAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    operation: NavigationOperation,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_ancestor(focused, "scoped_type_identifier")?;
    let name = scoped.child_by_field_name("name")?;
    if name.start_byte() > site.focus_start_byte || name.end_byte() < site.focus_end_byte {
        return None;
    }
    let mut qualified = scoped.child_by_field_name("path")?;
    while qualified.kind() == "bracketed_type" {
        qualified = qualified.named_child(0)?;
    }
    if qualified.kind() != "qualified_type" {
        return None;
    }
    let owner_type = qualified.child_by_field_name("type")?;
    let trait_type = qualified.child_by_field_name("alias")?;
    let owner_fqn = rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        source,
        owner_type,
        Some(owner_type.start_byte()),
    )?;
    let trait_fqn = rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        source,
        trait_type,
        Some(trait_type.start_byte()),
    )?;
    let member_name = rust_node_text(name, source).trim();
    let trait_members: Vec<_> = support
        .fqn(&format!("{trait_fqn}.{member_name}"))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if trait_members.is_empty() {
        return None;
    }
    if operation == NavigationOperation::Declaration {
        return Some(candidates_outcome(trait_members));
    }
    let mut implementations = Vec::new();
    for trait_member in trait_members {
        implementations.extend(
            rust.rust_trait_member_implementations(&trait_member)
                .unwrap_or_default()
                .into_iter()
                .filter(|candidate| {
                    analyzer
                        .parent_of(candidate)
                        .is_some_and(|parent| parent.fq_name() == owner_fqn)
                }),
        );
    }
    sort_units(&mut implementations);
    implementations.dedup();
    Some(if implementations.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "qualified Rust associated type `{member_name}` has no indexed implementation for `{owner_fqn}`"
            ),
        )
    } else {
        candidates_outcome(implementations)
    })
}

fn rust_enclosing_named_associated_type(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(candidate.kind(), "associated_type" | "type_item")
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_self_scoped_associated_type_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_scoped_type_identifier_name(
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let path = scoped.child_by_field_name("path")?;
    if rust_node_text(path, source).trim() != "Self" {
        return None;
    }
    let name = scoped.child_by_field_name("name")?;
    let name = rust_node_text(name, source).trim();
    let associated_type = resolve_in_enclosing_scopes(
        analyzer,
        file,
        name,
        site.focus_start_byte,
        CodeUnit::is_field,
    )?;
    Some(vec![associated_type])
}

fn rust_enclosing_scoped_type_identifier_name(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "scoped_type_identifier"
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_enclosing_ancestor<'tree>(mut node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn rust_focused_use_path_outcome(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let focused_path = rust_focused_use_path(focused, source)?;
    let focused_text = rust_node_text(focused, source).trim();
    let resolved_fqn = crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(
        rust,
        refs,
        file,
        &focused_path.full_path,
    );
    Some(rust_focused_prefix_resolution_outcome(
        rust,
        support,
        file,
        source,
        site,
        refs,
        focused_path.root,
        focused_text,
        resolved_fqn.as_deref(),
    ))
}

fn node_within(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn rust_focused_scoped_prefix_outcome(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let prefix = rust_focused_nonterminal_prefix(focused)?;
    let focused_text = rust_node_text(focused, source).trim();
    let prefix_text = rust_node_text(prefix, source).trim();
    if focused_text.is_empty() || prefix_text.is_empty() {
        return Some(no_definition(
            "invalid_scoped_segment",
            "the focused Rust path segment is empty",
        ));
    }

    let resolved_fqn = rust_scoped_prefix_fqn(rust, file, refs, prefix, source);
    let root = rust_scoped_path_root(prefix);
    Some(rust_focused_prefix_resolution_outcome(
        rust,
        support,
        file,
        source,
        site,
        refs,
        root,
        focused_text,
        resolved_fqn.as_deref(),
    ))
}

fn rust_focused_token_tree_prefix_outcome(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if !rust_path_segment_node(focused) || focused.parent()?.kind() != "token_tree" {
        return None;
    }
    let separator = focused.next_sibling()?;
    if separator.kind() != "::" || !separator.next_sibling().is_some_and(rust_path_segment_node) {
        return None;
    }

    let mut root = focused;
    while let Some(previous_separator) = root.prev_sibling() {
        if previous_separator.kind() != "::" {
            break;
        }
        let Some(previous_segment) = previous_separator.prev_sibling() else {
            break;
        };
        if !rust_path_segment_node(previous_segment) {
            break;
        }
        root = previous_segment;
    }

    let prefix = source.get(root.start_byte()..focused.end_byte())?.trim();
    let focused_text = rust_node_text(focused, source).trim();
    if prefix.is_empty() || focused_text.is_empty() {
        return Some(no_definition(
            "invalid_scoped_segment",
            "the focused Rust path segment is empty",
        ));
    }
    let resolved_fqn =
        crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(rust, refs, file, prefix);
    Some(rust_focused_prefix_resolution_outcome(
        rust,
        support,
        file,
        source,
        site,
        refs,
        root,
        focused_text,
        resolved_fqn.as_deref(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_prefix_resolution_outcome(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
    root: Node<'_>,
    focused_text: &str,
    resolved_fqn: Option<&str>,
) -> DefinitionLookupOutcome {
    if let Some(fqn) = resolved_fqn {
        let candidates: Vec<_> = support
            .fqn(fqn)
            .into_iter()
            .filter(|candidate| language_for_file(candidate.source()) == Language::Rust)
            .collect();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    let root_name = rust_node_text(root, source).trim();
    let binder = lexical_scope::visible_import_binder_at(source, site.focus_start_byte);
    if rust_binder_has_external_binding(&binder, root_name)
        || rust_extern_prelude_root(rust, file, refs, root, root_name)
    {
        return boundary(format!(
            "focused Rust path segment `{focused_text}` crosses a crate/module boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!(
            "focused Rust path segment `{focused_text}` did not resolve to an indexed definition"
        ),
    )
}

fn rust_path_segment_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "crate" | "self" | "super"
    )
}

fn rust_extern_prelude_root(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    refs: &RustReferenceContext,
    root: Node<'_>,
    root_name: &str,
) -> bool {
    matches!(root.kind(), "identifier" | "type_identifier")
        && refs.resolve_bare(root_name).is_none()
        && rust.resolve_module_files(file, root_name).is_empty()
}

fn rust_focused_nonterminal_prefix<'tree>(focused: Node<'tree>) -> Option<Node<'tree>> {
    let mut prefix = focused;
    while let Some(parent) = prefix.parent() {
        if !matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            break;
        }
        if parent
            .child_by_field_name("name")
            .is_some_and(|name| node_within(name, focused))
        {
            prefix = parent;
            continue;
        }
        break;
    }
    let parent = prefix.parent()?;
    if !matches!(
        parent.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        return None;
    }
    parent
        .child_by_field_name("path")
        .filter(|path| node_within(*path, prefix))
        .map(|_| prefix)
}

fn rust_scoped_prefix_fqn(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    refs: &RustReferenceContext,
    prefix: Node<'_>,
    source: &str,
) -> Option<String> {
    match prefix.kind() {
        "scoped_identifier" | "scoped_type_identifier" => {
            let path = prefix.child_by_field_name("path")?;
            let name = prefix.child_by_field_name("name")?;
            let path = rust_node_text(path, source).trim();
            let name = rust_node_text(name, source).trim();
            refs.resolve_scoped(path, name).or_else(|| {
                rust.resolve_module_package(file, rust_node_text(prefix, source).trim())
            })
        }
        "identifier" | "type_identifier" => {
            let name = rust_node_text(prefix, source).trim();
            refs.resolve_bare(name)
                .map(str::to_string)
                .or_else(|| rust.resolve_module_package(file, name))
        }
        "crate" | "self" | "super" => {
            rust.resolve_module_package(file, rust_node_text(prefix, source).trim())
        }
        _ => None,
    }
}

fn rust_scoped_path_root(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    node
}

fn resolve_rust_field(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    if let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
        && let Some(field_expression) = rust_enclosing_field_expression(node)
    {
        let field = field_expression.child_by_field_name("field")?;
        let receiver = field_expression.child_by_field_name("value")?;
        if receiver.start_byte() <= site.focus_start_byte
            && site.focus_end_byte <= receiver.end_byte()
        {
            if rust_node_text(receiver, source).trim() == "self"
                && let Some(owner) =
                    rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
            {
                let candidates = support.fqn(&owner);
                if !candidates.is_empty() {
                    return Some(candidates_outcome(candidates));
                }
            }
            return Some(no_definition(
                "local_receiver",
                "the focused Rust receiver is a local expression, which is not indexed",
            ));
        }
        if !(field.start_byte() <= site.focus_start_byte && site.focus_end_byte <= field.end_byte())
        {
            return None;
        }
        let member = rust_node_text(field, source).trim();
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            receiver,
            field_expression.start_byte(),
            cache,
        )?;
        let candidates = rust_member_candidates(
            support.fqn(&format!("{owner}.{member}")),
            rust_field_expression_member_kind(field_expression),
        );
        if candidates.is_empty()
            && rust_field_expression_member_kind(field_expression) == RustMemberKind::Function
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            let refs = rust.forward_reference_context_of(file);
            let trait_candidates =
                match crate::analyzer::usages::rust_graph::resolve_trait_associated_item(
                    rust, support, &refs, file, &owner, member,
                ) {
                    ReceiverAnalysisOutcome::Precise(resolved) => {
                        rust_member_candidates(resolved, RustMemberKind::Function)
                    }
                    ReceiverAnalysisOutcome::Ambiguous(_)
                    | ReceiverAnalysisOutcome::Unknown
                    | ReceiverAnalysisOutcome::Unsupported { .. }
                    | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                };
            if !trait_candidates.is_empty() {
                return Some(candidates_outcome(trait_candidates));
            }
        }
        return if candidates.is_empty() {
            Some(no_definition(
                "no_indexed_definition",
                format!("`{owner}.{member}` is not indexed as a Rust definition"),
            ))
        } else {
            Some(candidates_outcome(candidates))
        };
    }
    rust_resolve_dotted_reference_text(analyzer, support, file, source, tree, site, cache)
}

fn rust_resolve_dotted_reference_text(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    let segments = reference_segments(site, ".", 1)?;
    if segments.len() < 2 {
        return None;
    }
    let focus_index = focus_segment_index(site, &segments)?;
    if focus_index == 0 {
        return None;
    }
    let base = &segments[0].0;
    let mut owner = if base == "self" {
        let node = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )?;
        rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)?
    } else {
        rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            tree.root_node(),
            base,
            site.range.start_byte,
            RustTypeMode::Direct,
            cache,
        )?
    };
    for (index, (member, _, _)) in segments.iter().enumerate().skip(1) {
        let candidates = rust_member_candidates(
            support.fqn(&format!("{owner}.{member}")),
            RustMemberKind::Field,
        );
        if index == focus_index {
            return if candidates.is_empty() {
                Some(no_definition(
                    "no_indexed_definition",
                    format!("`{owner}.{member}` is not indexed as a Rust definition"),
                ))
            } else {
                Some(candidates_outcome(candidates))
            };
        }
        if candidates.is_empty() {
            return None;
        }
        owner = rust_field_type_fqn(
            analyzer,
            support,
            file,
            source,
            &owner,
            member,
            RustTypeMode::Direct,
            cache,
        )?;
    }
    None
}

fn reference_segments(
    site: &ResolvedReferenceSite,
    delimiter: &str,
    delimiter_width: usize,
) -> Option<Vec<(String, usize, usize)>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for part in site.text.split(delimiter) {
        if part.is_empty()
            || !part
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        let start = offset;
        let end = start + part.len();
        segments.push((part.to_string(), start, end));
        offset = end + delimiter_width;
    }
    Some(segments)
}

fn focus_segment_index(
    site: &ResolvedReferenceSite,
    segments: &[(String, usize, usize)],
) -> Option<usize> {
    let focus = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    segments
        .iter()
        .position(|(_, start, end)| *start <= focus && focus < *end)
}

fn rust_enclosing_field_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "field_expression" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustMemberKind {
    Field,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustTypeMode {
    Direct,
    UnwrapContainer,
}

#[derive(Default)]
pub(crate) struct RustTypeLookupCache {
    declarations: HashMap<ProjectFile, Option<RustParsedDeclarationSource>>,
}

struct RustParsedDeclarationSource {
    source: String,
    tree: Tree,
}

impl RustTypeLookupCache {
    fn parsed(&mut self, file: &ProjectFile) -> Option<&RustParsedDeclarationSource> {
        self.declarations
            .entry(file.clone())
            .or_insert_with(|| {
                let source = file.read_to_string().ok()?;
                let tree = lexical_scope::parse_rust_tree(&source)?;
                Some(RustParsedDeclarationSource { source, tree })
            })
            .as_ref()
    }

    #[cfg(test)]
    pub(crate) fn parsed_declaration_source_count_for_test(&self) -> usize {
        self.declarations.len()
    }
}

fn rust_field_expression_member_kind(field_expression: Node<'_>) -> RustMemberKind {
    let mut function = field_expression;
    while let Some(parent) = function.parent()
        && parent.kind() == "generic_function"
        && parent.child_by_field_name("function") == Some(function)
    {
        function = parent;
    }
    if let Some(parent) = function.parent()
        && parent.kind() == "call_expression"
        && parent
            .child_by_field_name("function")
            .is_some_and(|callee| callee.id() == function.id())
    {
        RustMemberKind::Function
    } else {
        RustMemberKind::Field
    }
}

fn rust_member_candidates(candidates: Vec<CodeUnit>, kind: RustMemberKind) -> Vec<CodeUnit> {
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| match kind {
            RustMemberKind::Field => unit.is_field(),
            RustMemberKind::Function => unit.is_function(),
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn_mode(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        RustTypeMode::Direct,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_expression_type_definition_fqn_cached(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn_mode(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    match expression.kind() {
        "self" if mode == RustTypeMode::Direct => {
            rust_enclosing_impl_type_fqn(analyzer, support, file, source, expression)
        }
        "identifier" => rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            rust_node_text(expression, source).trim(),
            before_byte,
            mode,
            cache,
        ),
        "field_expression" => {
            let receiver = expression.child_by_field_name("value")?;
            let field = expression.child_by_field_name("field")?;
            let owner = rust_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                before_byte,
                cache,
            )?;
            let member = rust_node_text(field, source).trim();
            rust_field_type_fqn(analyzer, support, file, source, &owner, member, mode, cache)
        }
        "call_expression" => rust_call_expression_type_fqn(
            analyzer, support, file, source, root, expression, mode, cache,
        ),
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    RustTypeMode::UnwrapContainer,
                    cache,
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    mode,
                    cache,
                )
            })
        }
        "struct_expression" if mode == RustTypeMode::Direct => {
            let name = expression.child_by_field_name("name")?;
            rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                name,
                Some(name.start_byte()),
            )
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let mut found = None;
    let mut ctx = RustBindingLookupCtx {
        analyzer,
        support,
        file,
        source,
        root,
        name,
        before_byte,
        mode,
        cache,
    };
    rust_collect_binding_type_fqn(&mut ctx, root, &mut found);
    found
}

struct RustBindingLookupCtx<'a, 'tree, 'cache> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn RustDefinitionProvider,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    name: &'a str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &'cache mut RustTypeLookupCache,
}

fn rust_collect_binding_type_fqn(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    root: Node<'_>,
    found: &mut Option<String>,
) {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.start_byte() >= ctx.before_byte {
            continue;
        }
        match node.kind() {
            "parameter" => {
                if let Some((binding, type_node)) = rust_typed_binding(node, ctx.source)
                    && binding == ctx.name
                    && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                        ctx,
                        type_node,
                        Some(type_node.start_byte()),
                    )
                {
                    *found = Some(fqn);
                }
            }
            "let_declaration" if node.end_byte() <= ctx.before_byte => {
                if let Some(binding) = node
                    .child_by_field_name("pattern")
                    .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                    && binding == ctx.name
                {
                    if let Some(type_node) = node.child_by_field_name("type")
                        && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                            ctx,
                            type_node,
                            Some(type_node.start_byte()),
                        )
                    {
                        *found = Some(fqn);
                    } else if let Some(value) = node.child_by_field_name("value")
                        && let Some(fqn) = rust_expression_type_fqn_mode(
                            ctx.analyzer,
                            ctx.support,
                            ctx.file,
                            ctx.source,
                            ctx.root,
                            value,
                            value.start_byte(),
                            ctx.mode,
                            ctx.cache,
                        )
                    {
                        *found = Some(fqn);
                    }
                }
            }
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if child.start_byte() < ctx.before_byte
                && !rust_scope_boundary_excludes_reference(child, ctx.before_byte)
            {
                pending.push(child);
            }
        }
    }
}

fn rust_resolve_type_node_fqn_mode(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let target_node = match ctx.mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => rust_unwrap_container_type_node(type_node, ctx.source)?,
    };
    rust_resolve_type_node_fqn(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.source,
        target_node,
        reference_byte,
    )
}

fn rust_scope_boundary_excludes_reference(node: Node<'_>, reference_byte: usize) -> bool {
    rust_is_scope_boundary(node.kind())
        && !(node.start_byte() <= reference_byte && reference_byte <= node.end_byte())
}

fn rust_is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "block_expression"
            | "closure_expression"
            | "const_item"
            | "enum_item"
            | "function_item"
            | "impl_item"
            | "macro_definition"
            | "mod_item"
            | "static_item"
            | "trait_item"
    )
}

fn rust_typed_binding<'tree>(node: Node<'tree>, source: &str) -> Option<(String, Node<'tree>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = rust_simple_identifier_text(pattern, source)?;
    let type_node = node.child_by_field_name("type")?;
    Some((name, type_node))
}

#[allow(clippy::too_many_arguments)]
fn rust_call_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    if function.kind() == "field_expression"
        && let Some(method) = function.child_by_field_name("field")
        && let Some(receiver) = function.child_by_field_name("value")
    {
        let method_name = rust_node_text(method, source).trim();
        if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
            return rust_expression_type_fqn_mode(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                call.start_byte(),
                RustTypeMode::UnwrapContainer,
                cache,
            );
        }
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            receiver,
            call.start_byte(),
            cache,
        )?;
        return rust_callable_return_type_fqn(
            analyzer,
            support,
            file,
            support.fqn(&format!("{owner}.{method_name}")),
            mode,
            cache,
        );
    }
    let name = rust_callable_name(function, source)?;
    rust_callable_return_type_fqn(
        analyzer,
        support,
        file,
        rust_callable_candidates(analyzer, support, file, &name, function.start_byte()),
        mode,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    _source: &str,
    owner_fqn: &str,
    member: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let field = support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .next()?;
    rust_field_code_unit_type_fqn(analyzer, support, file, &field, mode, cache)
}

fn rust_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    candidates: Vec<CodeUnit>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        rust_function_code_unit_return_type_fqn(analyzer, support, file, &candidate, mode, cache)
    })
}

fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    field: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(analyzer, support, file, field, "type", mode, cache)
}

fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    function: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        support,
        file,
        function,
        "return_type",
        mode,
        cache,
    )
}

fn rust_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    _file: &ProjectFile,
    code_unit: &CodeUnit,
    field_name: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let parsed = cache.parsed(code_unit.source())?;
    let declaration =
        rust_code_unit_declaration_node(analyzer, code_unit, parsed.tree.root_node())?;
    let type_node = declaration.child_by_field_name(field_name)?;
    let target_node = match mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => {
            rust_unwrap_container_type_node(type_node, &parsed.source)?
        }
    };
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        code_unit.source(),
        &parsed.source,
        target_node,
        Some(target_node.start_byte()),
    )
}

fn rust_code_unit_declaration_node<'tree>(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    root: Node<'tree>,
) -> Option<Node<'tree>> {
    analyzer
        .ranges(code_unit)
        .iter()
        .filter_map(|range| root.descendant_for_byte_range(range.start_byte, range.end_byte))
        .find(|node| node.child_by_field_name("name").is_some())
}

pub(crate) fn rust_resolve_type_node_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let type_ref = rust_type_ref(type_node, source)?;
    let name = type_ref.name.as_str();
    if type_ref.path.is_none() && name == "Self" {
        return rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node);
    }
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = rust.forward_reference_context_of(file);
        if let Some(path) = type_ref.path.as_deref()
            && let Some(resolved) = refs.resolve_scoped(path, name)
            && support
                .fqn(&resolved)
                .into_iter()
                .any(|unit| rust_is_type_definition(analyzer, &unit))
        {
            return Some(resolved);
        }
        if let Some(reference_byte) = reference_byte {
            if let Some(local) =
                rust_local_type_fqn_visible_at(analyzer, support, file, name, reference_byte)
            {
                return Some(local);
            }
        } else if let Some(resolved) = refs.resolve_bare(name)
            && support
                .fqn(resolved)
                .into_iter()
                .any(|unit| rust_is_type_definition(analyzer, &unit))
            && rust_type_fqn_visible_from_file(file, resolved)
        {
            return Some(resolved.to_string());
        }
        if let Some(imported) = rust_import_type_fqn(rust, support, file, name, reference_byte) {
            return Some(imported);
        }
    }
    support
        .fqn(name)
        .into_iter()
        .find(|unit| rust_is_type_definition(analyzer, unit))
        .map(|unit| unit.fq_name().to_string())
}

pub(crate) fn rust_is_type_definition(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
}

#[derive(Debug)]
struct RustTypeRef {
    path: Option<String>,
    name: String,
}

fn rust_type_ref(type_node: Node<'_>, source: &str) -> Option<RustTypeRef> {
    let node = rust_named_type_node(type_node)?;
    match node.kind() {
        "type_identifier" | "identifier" | "self" | "super" | "crate" => {
            let name = rust_node_text(node, source).trim();
            (!name.is_empty()).then(|| RustTypeRef {
                path: None,
                name: name.to_string(),
            })
        }
        "scoped_type_identifier" => {
            let name = node.child_by_field_name("name")?;
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            Some(RustTypeRef {
                path: node
                    .child_by_field_name("path")
                    .and_then(|path| rust_type_path_text(path, source)),
                name: name.to_string(),
            })
        }
        "generic_type" => {
            let base = node.child_by_field_name("type")?;
            rust_type_ref(base, source)
        }
        "qualified_type" => {
            let inner = node.child_by_field_name("type")?;
            rust_type_ref(inner, source)
        }
        _ => None,
    }
}

fn rust_named_type_node(type_node: Node<'_>) -> Option<Node<'_>> {
    match type_node.kind() {
        "reference_type" | "pointer_type" | "array_type" | "bracketed_type" => type_node
            .child_by_field_name("type")
            .and_then(rust_named_type_node),
        "generic_type" | "qualified_type" => Some(type_node),
        "scoped_type_identifier"
        | "type_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => Some(type_node),
        _ => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(rust_named_type_node)
        }
    }
}

fn rust_type_path_text(path: Node<'_>, source: &str) -> Option<String> {
    match path.kind() {
        "generic_type" => path
            .child_by_field_name("type")
            .and_then(|base| rust_type_path_text(base, source)),
        "scoped_type_identifier"
        | "scoped_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
    }
}

fn rust_unwrap_container_type_node<'tree>(
    type_node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let node = rust_named_type_node(type_node)?;
    let type_ref = rust_type_ref(node, source)?;
    let is_container = matches!(
        (type_ref.path.as_deref(), type_ref.name.as_str()),
        (None, "Result")
            | (Some("std::result"), "Result")
            | (Some("anyhow"), "Result")
            | (None, "Option")
            | (Some("std::option"), "Option")
    );
    if !is_container {
        return None;
    }
    let type_arguments = node.child_by_field_name("type_arguments")?;
    let mut cursor = type_arguments.walk();
    type_arguments
        .named_children(&mut cursor)
        .next()
        .and_then(rust_named_type_node)
}

fn rust_import_type_fqn(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: Option<usize>,
) -> Option<String> {
    let mut candidates: Vec<_> =
        rust_imported_export_candidates(rust, support, file, name, reference_byte)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_type_fqn_visible_from_file(file: &ProjectFile, fqn: &str) -> bool {
    rust_fqn_package(fqn) == rust_local_package_name(file)
}

fn rust_local_type_fqn_visible_at(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Option<String> {
    let source = file.read_to_string().ok()?;
    let tree = lexical_scope::parse_rust_tree(&source)?;
    let reference_mod =
        lexical_scope::enclosing_mod_item_range_at(tree.root_node(), reference_byte);
    let mut candidates: Vec<_> = support
        .file_identifier(file, name)
        .into_iter()
        .filter(|unit| unit.is_class())
        .filter(|unit| {
            analyzer.ranges(unit).iter().any(|range| {
                rust_definition_scope_visible_at(tree.root_node(), range.start_byte, reference_byte)
                    && lexical_scope::enclosing_mod_item_range_at(
                        tree.root_node(),
                        range.start_byte,
                    ) == reference_mod
            })
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_definition_scope_visible_at(
    root: Node<'_>,
    definition_byte: usize,
    reference_byte: usize,
) -> bool {
    let Some(definition_node) =
        smallest_named_node_covering(root, definition_byte, definition_byte)
    else {
        return false;
    };
    lexical_scope::enclosing_visibility_scope_range(definition_node)
        .is_none_or(|(start, end)| start <= reference_byte && reference_byte < end)
}

fn rust_fqn_package(fqn: &str) -> &str {
    fqn.rsplit_once('.')
        .map(|(package, _)| package)
        .unwrap_or("")
}

fn rust_local_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    if components.first().map(|component| component.as_str()) == Some("src") {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = std::path::Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if rel.starts_with("src") {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn rust_enclosing_impl_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<String> {
    let mut current = node.parent()?;
    loop {
        if current.kind() == "impl_item"
            && let Some(type_node) = current.child_by_field_name("type")
        {
            return rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            );
        }
        current = current.parent()?;
    }
}

fn rust_named_candidates(
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.file_identifier(file, name);
    candidates.extend(support.fqn(name));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_callable_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let mut candidates = rust_named_candidates(support, file, name);
    if candidates.is_empty()
        && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
    {
        candidates =
            rust_imported_export_candidates(rust, support, file, name, Some(reference_byte));
    }
    candidates
}

fn rust_callable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|name| rust_node_text(name, source).trim().to_string()),
        _ => None,
    }
}

fn rust_simple_identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        _ => None,
    }
}

fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
}

fn rust_imported_export_candidates(
    rust: &crate::analyzer::RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    reference: &str,
    reference_byte: Option<usize>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    let targets = if let Some(reference_byte) = reference_byte
        && let Ok(source) = file.read_to_string()
    {
        if lexical_scope::name_shadowed_at(&source, reference, reference_byte) {
            Vec::new()
        } else {
            let binder = lexical_scope::visible_import_binder_at(&source, reference_byte);
            let targets =
                rust.resolve_imported_export_from_binder_forward(file, &binder, reference);
            if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
                return Vec::new();
            }
            targets
        }
    } else {
        let binder = rust.import_binder_of(file);
        let targets = rust.resolve_imported_export_from_binder_forward(file, &binder, reference);
        if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
            return Vec::new();
        }
        targets
    };
    for (target_file, target_name) in targets {
        candidates.extend(support.file_identifier(&target_file, &target_name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_binder_has_external_binding(binder: &ImportBinder, reference: &str) -> bool {
    binder
        .bindings
        .iter()
        .any(|(local_name, binding)| match binding.kind {
            ImportKind::Named | ImportKind::Namespace if local_name == reference => true,
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => false,
            ImportKind::Named | ImportKind::Namespace => false,
        })
}

fn rust_reference_looks_external(reference: &str) -> bool {
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
}

pub(super) fn parse_rust_tree(source: &str) -> Option<Tree> {
    lexical_scope::parse_rust_tree(source)
}
