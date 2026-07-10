use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{
    CodeUnit, DefinitionLookupIndex, IAnalyzer, ProjectFile, RustAnalyzer, RustReferenceContext,
    TypeHierarchyProvider,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::Parser;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RustGraphSeedKind {
    Export,
    LocalDeclaration,
}

pub(super) struct RustGraphSeeds {
    pub(super) seeds: BTreeSet<(ProjectFile, String)>,
    pub(super) kind: RustGraphSeedKind,
}

pub(super) fn supports_same_file_local_scan(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    target.is_function()
        && analyzer
            .parent_of(target)
            .is_none_or(|parent| parent.is_module())
        && (!is_public_like_declaration(analyzer, target)
            || analyzer.is_rust_cfg_test_declaration(target))
}

pub(super) fn is_member_target(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    // A member is referenced through a value of its owning type (`receiver.member`).
    // A function or field whose parent is a module is a free item referenced by name,
    // so it belongs on the top-level scan path, not the member-receiver path.
    (target.is_function() || target.is_field())
        && analyzer
            .parent_of(target)
            .is_some_and(|parent| !parent.is_module())
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

    (rust.is_rust_trait_declaration(&owner) && target.is_function())
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
        .find_map(|trait_unit| trait_member(rust, &trait_unit, target.identifier()))
}

fn is_trait_impl_member_target(rust: &RustAnalyzer, target: &CodeUnit, owner: &CodeUnit) -> bool {
    if !target.is_function() || rust.is_rust_trait_declaration(owner) {
        return false;
    }
    if rust.is_rust_trait_impl_member_declaration(target) {
        return true;
    }
    rust.get_direct_ancestors(owner)
        .into_iter()
        .filter(|trait_unit| rust.is_rust_trait_declaration(trait_unit))
        .any(|trait_unit| trait_member(rust, &trait_unit, target.identifier()).is_some())
}

fn trait_member(rust: &RustAnalyzer, trait_unit: &CodeUnit, member_name: &str) -> Option<CodeUnit> {
    rust.exact_member(
        trait_unit.source(),
        trait_unit.identifier(),
        member_name,
        true,
    )
    .or_else(|| {
        rust.exact_member(
            trait_unit.source(),
            trait_unit.identifier(),
            member_name,
            false,
        )
    })
}

pub(crate) fn resolve_scoped_associated_item(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    path: &str,
    method_name: &str,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    if let Some(direct) = refs.resolve_scoped(path, method_name) {
        let candidates = support.fqn(&direct);
        if !candidates.is_empty() {
            return ReceiverAnalysisOutcome::Precise(candidates);
        }
    }

    let Some(owner_fqn) = refs.resolve_scoped_owner(path) else {
        return ReceiverAnalysisOutcome::Unknown;
    };

    resolve_trait_associated_item(rust, support, refs, file, &owner_fqn, method_name)
}

/// Compiler-style trait-candidate step for an owner type already resolved to
/// `owner_fqn`: enumerate traits implemented for the owner and visible at the
/// call site, and resolve iff exactly one declares `method_name`. Split out of
/// [`resolve_scoped_associated_item`] so `Self::assoc` (where the owner fqn
/// comes from the enclosing impl, not from a scoped path) shares one resolver.
pub(crate) fn resolve_trait_associated_item(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner_fqn: &str,
    method_name: &str,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    resolve_trait_associated_item_matching(
        rust,
        support,
        refs,
        file,
        owner_fqn,
        method_name,
        CodeUnit::is_function,
    )
}

pub(crate) fn resolve_trait_associated_item_matching(
    rust: &RustAnalyzer,
    support: &DefinitionLookupIndex,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    owner_fqn: &str,
    item_name: &str,
    item_matches: fn(&CodeUnit) -> bool,
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

    ReceiverAnalysisOutcome::single_precise_or_ambiguous(
        rust.get_direct_ancestors(&owner)
            .into_iter()
            .filter(|trait_unit| trait_visible_at_call_site(rust, refs, file, trait_unit))
            .flat_map(|trait_unit| {
                support
                    .fqn_direct_children(&trait_unit.fq_name())
                    .into_iter()
                    .filter(move |candidate| {
                        item_matches(candidate)
                            && candidate.identifier() == item_name
                            && rust
                                .parent_of(candidate)
                                .as_ref()
                                .is_some_and(|parent| parent == &trait_unit)
                    })
            }),
        ReceiverAnalysisBudget::default(),
    )
}

fn trait_visible_at_call_site(
    rust: &RustAnalyzer,
    refs: &RustReferenceContext,
    file: &ProjectFile,
    trait_unit: &CodeUnit,
) -> bool {
    if !refs
        .bare_names_resolving_to(&trait_unit.fq_name())
        .is_empty()
    {
        return true;
    }
    // Glob imports (`use module::*;`) never land in the reference context's name
    // maps, so a trait pulled in through a glob/prelude is only reachable via the
    // import-export resolver.
    rust.resolve_imported_export(file, trait_unit.identifier())
        .contains(&(
            trait_unit.source().clone(),
            trait_unit.identifier().to_string(),
        ))
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
    let seeds = infer_export_graph_seeds(analyzer, target);
    if !seeds.is_empty() {
        return RustGraphSeeds {
            seeds,
            kind: RustGraphSeedKind::Export,
        };
    }

    RustGraphSeeds {
        seeds: local_declaration_graph_seeds(analyzer, target),
        kind: RustGraphSeedKind::LocalDeclaration,
    }
}

fn infer_export_graph_seeds(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    let nested_module_target = analyzer
        .parent_of(target)
        .is_some_and(|parent| parent.is_module());
    for seed_name in infer_export_names(analyzer, target) {
        let resolved = analyzer.usage_seeds(target.source(), &seed_name);
        if resolved.is_empty() && nested_module_target {
            seeds.insert((target.source().clone(), seed_name));
        } else {
            seeds.extend(resolved);
        }
    }

    if seeds.is_empty()
        && let Some(parent) = analyzer.parent_of(target)
        && parent.is_module()
        && parent.source() != target.source()
        && is_public_like_declaration(analyzer, target)
    {
        let parent_index = analyzer.export_index_of(parent.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            seeds.insert((parent.source().clone(), target.identifier().to_string()));
        }
    }

    // Last resort: resolve an export-visible item that reaches the public API only
    // through a `pub use` re-export of a private module. These names are tried only
    // via real re-export chains, so a private, never-re-exported item stays unseeded.
    if seeds.is_empty() {
        for seed_name in reexport_fallback_export_names(analyzer, target) {
            seeds.extend(analyzer.usage_seeds(target.source(), &seed_name));
        }
    }

    seeds
}

fn local_declaration_graph_seeds(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
) -> BTreeSet<(ProjectFile, String)> {
    let seed_target = if is_member_target(analyzer, target) {
        analyzer.parent_of(target)
    } else {
        Some(target.clone())
    };
    let Some(seed_target) = seed_target else {
        return BTreeSet::new();
    };
    if !is_local_declaration(analyzer, &seed_target) {
        return BTreeSet::new();
    }
    [(
        seed_target.source().clone(),
        seed_target.identifier().to_string(),
    )]
    .into_iter()
    .collect()
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
