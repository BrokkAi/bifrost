//! The language half of C#'s type-resolution logic: namespace and `using`
//! resolution, visible-type lookup, partial-type grouping and the bounded
//! declaration queries built on top of them, written as free functions over a
//! source trait instead of as methods on [`CSharpAnalyzer`].
//!
//! [`CSharpAnalyzer`] owns the lazy cells (six moka caches, six `OnceLock`s and
//! two `PoolSafeMemo`s) and implements [`CSharpAnalysisSource`] out of its own
//! accessors, so the functions below reach back for the memoized products they
//! need without naming the analyzer type.
//!
//! One tier is enough here, unlike Rust's `RustAnalysisSource`/`RustUsageSource`
//! split: no `OnceLock` in the C# memo web re-enters the cell it is filling.
//! The deepest recursion, `visible_type_candidates_with_lookups`, was already
//! written as a function of four injected lookups and stays that way -- it
//! needs no source at all.
//!
//! [`CSharpAnalyzer`]: super::CSharpAnalyzer

use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, CodeUnitType, ImportAnalysisProvider,
    ImportInfo, ProjectFile, build_reverse_file_index,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use super::imports::{
    csharp_static_using_from_import, csharp_using_alias_from_import, csharp_using_namespace,
};
use super::{
    csharp_arity_preserving_full_name, csharp_normalize_full_name, normalize_csharp_type_fragment,
};

/// The analyzer-resident products C#'s language logic resolves through, on top
/// of the two core capability traits it reads declarations and imports with.
/// The analyzer is the only implementor and every method forwards to one of its
/// own accessors or memo cells, so the cells stay where they are and no free
/// function below can reach past this surface.
pub(crate) trait CSharpAnalysisSource: CodeUnitIndex + ImportAnalysisProvider {
    // --- bounded declaration lookups ---

    fn persisted_declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit>;

    fn persisted_declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit>;

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// The workspace's usage-definition index, as the bounded lookup contract.
    /// Every `usage_*` spelling below answers from here rather than from the
    /// persisted store.
    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup;

    // --- indexed file facts ---

    fn all_files(&self) -> Vec<ProjectFile>;

    fn package_name_of(&self, file: &ProjectFile) -> Option<String>;

    fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String>;

    fn import_info_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<ImportInfo>;

    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<ImportInfo>;

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>>;

    // --- memoized products the analyzer owns ---

    fn namespace_of_file(&self, file: &ProjectFile) -> String;

    fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String>;

    fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String>;

    fn global_using_namespaces(&self) -> &HashSet<String>;

    fn global_using_namespaces_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String>;

    fn global_using_aliases(&self) -> &HashMap<String, String>;

    fn global_using_aliases_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)>;
}

// ---------------------------------------------------------------------------
// Declaration lookups
// ---------------------------------------------------------------------------

pub(crate) fn usage_declaration_candidates_by_identifier(
    source: &dyn CSharpAnalysisSource,
    identifier: &str,
) -> Vec<CodeUnit> {
    source.usage_definitions().identifier(identifier)
}

pub(crate) fn declaration_candidates_by_fqn(
    source: &dyn CSharpAnalysisSource,
    fqn: &str,
    normalized: bool,
) -> BTreeSet<CodeUnit> {
    let candidates = source.persisted_declaration_candidates_by_fqn(fqn, normalized);
    if !normalized {
        return candidates;
    }
    let arity_key = csharp_arity_preserving_full_name(fqn);
    candidates
        .into_iter()
        .filter(|candidate| csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key)
        .collect()
}

pub(crate) fn declaration_candidates_by_fqn_limited(
    source: &dyn CSharpAnalysisSource,
    fqn: &str,
    normalized: bool,
    limit: usize,
    mut continue_query: impl FnMut() -> bool,
) -> LimitedQueryRows<CodeUnit> {
    let mut batch = source.persisted_declaration_candidates_by_fqn_limited(
        fqn,
        normalized,
        limit,
        &mut continue_query,
    );
    if normalized {
        let arity_key = csharp_arity_preserving_full_name(fqn);
        batch.rows.retain(|candidate| {
            csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key
        });
    }
    batch
}

pub(crate) fn usage_member_candidates_for_owner(
    source: &dyn CSharpAnalysisSource,
    owner_fqn: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let normalized = csharp_normalize_full_name(owner_fqn);
    source
        .usage_definitions()
        .members_for_owner_name(owner_fqn, &normalized, name)
}

pub(crate) fn usage_workspace_namespace_exists(
    source: &dyn CSharpAnalysisSource,
    namespace: &str,
) -> bool {
    source.usage_definitions().package_exists(namespace)
}

pub(crate) fn usage_type_candidates_by_fqn(
    source: &dyn CSharpAnalysisSource,
    fqn: &str,
) -> Vec<CodeUnit> {
    let lookup = source.usage_definitions();
    let exact = lookup
        .fqn(fqn)
        .iter()
        .filter(|unit| unit.is_class())
        .cloned()
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }
    let arity_key = csharp_arity_preserving_full_name(fqn);
    lookup
        .by_normalized_fqn(&csharp_normalize_full_name(fqn))
        .iter()
        .filter(|unit| {
            unit.is_class() && csharp_arity_preserving_full_name(&unit.fq_name()) == arity_key
        })
        .cloned()
        .collect()
}

pub(crate) fn usage_definition_candidates_by_fqn(
    source: &dyn CSharpAnalysisSource,
    fqn: &str,
) -> Vec<CodeUnit> {
    let lookup = source.usage_definitions();
    let exact = lookup.fqn(fqn);
    if !exact.is_empty() {
        return exact.to_vec();
    }
    let arity_key = csharp_arity_preserving_full_name(fqn);
    lookup
        .by_normalized_fqn(&csharp_normalize_full_name(fqn))
        .iter()
        .filter(|unit| csharp_arity_preserving_full_name(&unit.fq_name()) == arity_key)
        .cloned()
        .collect()
}

pub(crate) fn type_candidates_by_fqn(
    source: &dyn CSharpAnalysisSource,
    fqn: &str,
    usage: bool,
) -> Vec<CodeUnit> {
    if usage {
        return usage_type_candidates_by_fqn(source, fqn);
    }
    source
        .forward_definition_fqn(fqn)
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect()
}

// ---------------------------------------------------------------------------
// Namespaces and `using` directives
// ---------------------------------------------------------------------------

/// The uncached half of the analyzer's `namespace_of_file`.
pub(super) fn compute_namespace_of_file(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
) -> String {
    let package = source.package_name_of(file).unwrap_or_default();
    if package.is_empty() {
        source
            .declarations(file)
            .into_iter()
            .map(|unit| unit.package_name().to_string())
            .find(|package| !package.is_empty())
            .unwrap_or_default()
    } else {
        package
    }
}

/// The uncached half of the analyzer's `namespace_of_file_limited`. A complete
/// batch is what the analyzer memoizes; an incomplete one is passed straight
/// through.
pub(super) fn compute_namespace_of_file_limited(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    limit: usize,
) -> LimitedQueryRows<String> {
    let package = source.file_namespace_hint_limited(file, limit);
    if !package.complete {
        return package;
    }
    let namespace = package.rows.into_iter().next().unwrap_or_default();
    LimitedQueryRows::complete(vec![namespace], package.inspected)
}

pub(crate) fn import_statements_limited(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    limit: usize,
) -> LimitedQueryRows<String> {
    let imports = source.import_info_of_limited(file, limit);
    let statements = imports
        .rows
        .into_iter()
        .map(|import| import.raw_snippet)
        .collect();
    if imports.complete {
        LimitedQueryRows::complete(statements, imports.inspected)
    } else {
        LimitedQueryRows::incomplete(statements, imports.inspected)
    }
}

/// The uncached half of the analyzer's `using_namespaces_of`.
pub(super) fn compute_using_namespaces_of(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
) -> Vec<String> {
    let mut namespaces: Vec<String> = source
        .import_info_of(file)
        .iter()
        .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
        .collect();
    for namespace in source.global_using_namespaces() {
        if !namespaces.contains(namespace) {
            namespaces.push(namespace.clone());
        }
    }
    namespaces
}

/// The uncached half of the analyzer's `using_namespaces_of_limited`.
pub(super) fn compute_using_namespaces_of_limited(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    if limit == 0 || !continue_query() {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }

    let imports = source.import_info_of_limited(file, limit);
    let mut namespaces: Vec<_> = imports
        .rows
        .into_iter()
        .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(namespaces, imports.inspected);
    }

    let globals = source
        .global_using_namespaces_limited(limit.saturating_sub(imports.inspected), continue_query);
    for namespace in globals.rows {
        if !namespaces.contains(&namespace) {
            namespaces.push(namespace);
        }
    }
    let inspected = imports.inspected.saturating_add(globals.inspected);
    if !globals.complete {
        return LimitedQueryRows::incomplete(namespaces, inspected);
    }
    LimitedQueryRows::complete(namespaces, inspected)
}

/// The uncached half of the analyzer's `using_aliases_of`.
pub(super) fn compute_using_aliases_of(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
) -> HashMap<String, String> {
    let mut aliases: HashMap<String, String> = source
        .import_info_of(file)
        .iter()
        .filter_map(csharp_using_alias_from_import)
        .collect();
    for (alias, target) in source.global_using_aliases() {
        aliases
            .entry(alias.clone())
            .or_insert_with(|| target.clone());
    }
    aliases
}

/// The uncached half of the analyzer's `using_aliases_of_limited`.
pub(super) fn compute_using_aliases_of_limited(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<(String, String)> {
    if limit == 0 || !continue_query() {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }

    let imports = source.import_info_of_limited(file, limit);
    let mut aliases: HashMap<String, String> = imports
        .rows
        .iter()
        .filter_map(csharp_using_alias_from_import)
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(aliases.into_iter().collect(), imports.inspected);
    }

    let globals = source
        .global_using_aliases_limited(limit.saturating_sub(imports.inspected), continue_query);
    for (alias, target) in globals.rows {
        aliases.entry(alias).or_insert(target);
    }
    let inspected = imports.inspected.saturating_add(globals.inspected);
    if !globals.complete {
        return LimitedQueryRows::incomplete(aliases.into_iter().collect(), inspected);
    }
    LimitedQueryRows::complete(aliases.into_iter().collect(), inspected)
}

/// The uncached half of the analyzer's `global_using_namespaces`.
pub(super) fn compute_global_using_namespaces(
    source: &dyn CSharpAnalysisSource,
) -> HashSet<String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(&file).into_iter())
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
        .map(|namespace| {
            normalize_csharp_type_fragment(namespace.strip_prefix("global::").unwrap_or(&namespace))
        })
        .filter(|namespace| !namespace.is_empty())
        .collect()
}

/// The uncached half of the analyzer's `global_using_namespaces_limited`.
pub(super) fn compute_global_using_namespaces_limited(
    source: &dyn CSharpAnalysisSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let namespaces: HashSet<_> = imports
        .rows
        .into_iter()
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
        .map(|namespace| {
            normalize_csharp_type_fragment(namespace.strip_prefix("global::").unwrap_or(&namespace))
        })
        .filter(|namespace| !namespace.is_empty())
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(namespaces.into_iter().collect(), imports.inspected);
    }
    LimitedQueryRows::complete(namespaces.into_iter().collect(), imports.inspected)
}

/// The uncached half of the analyzer's `global_using_aliases`.
pub(super) fn compute_global_using_aliases(
    source: &dyn CSharpAnalysisSource,
) -> HashMap<String, String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(&file).into_iter())
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(|import| csharp_using_alias_from_import(&import))
        .collect()
}

/// The uncached half of the analyzer's `global_using_aliases_limited`.
pub(super) fn compute_global_using_aliases_limited(
    source: &dyn CSharpAnalysisSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<(String, String)> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let aliases: HashMap<_, _> = imports
        .rows
        .iter()
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(csharp_using_alias_from_import)
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(aliases.into_iter().collect(), imports.inspected);
    }
    LimitedQueryRows::complete(aliases.into_iter().collect(), imports.inspected)
}

/// The uncached half of the analyzer's `global_static_using_type_names_limited`.
pub(super) fn compute_global_static_using_type_names_limited(
    source: &dyn CSharpAnalysisSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let mut type_names: Vec<_> = imports
        .rows
        .iter()
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(csharp_static_using_from_import)
        .map(|target| {
            normalize_csharp_type_fragment(target.strip_prefix("global::").unwrap_or(target))
        })
        .filter(|target| !target.is_empty())
        .collect();
    type_names.sort();
    type_names.dedup();
    if !imports.complete {
        return LimitedQueryRows::incomplete(type_names, imports.inspected);
    }
    LimitedQueryRows::complete(type_names, imports.inspected)
}

/// The uncached half of the analyzer's two `global_static_using_types` cells;
/// `usage` selects the usage-definition index over the persisted store.
pub(super) fn compute_global_static_using_types(
    source: &dyn CSharpAnalysisSource,
) -> Vec<CodeUnit> {
    let mut types = Vec::new();
    for file in source.all_files() {
        for target in source
            .import_info_of(&file)
            .iter()
            .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
            .filter_map(csharp_static_using_from_import)
        {
            let target =
                normalize_csharp_type_fragment(target.strip_prefix("global::").unwrap_or(target));
            types.extend(type_candidates_by_fqn(source, &target, false));
        }
    }
    types.sort();
    types.dedup();
    types
}

/// [`compute_global_static_using_types`] answered from the usage-definition
/// index instead of the persisted store. Two cells, two walks: the difference
/// is which index resolves each target, and a `usage` flag threaded through one
/// body would hide that behind a mode parameter.
pub(super) fn compute_usage_global_static_using_types(
    source: &dyn CSharpAnalysisSource,
) -> Vec<CodeUnit> {
    let mut types = Vec::new();
    for file in source.all_files() {
        for target in source
            .import_info_of(&file)
            .iter()
            .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
            .filter_map(csharp_static_using_from_import)
        {
            let target =
                normalize_csharp_type_fragment(target.strip_prefix("global::").unwrap_or(target));
            types.extend(type_candidates_by_fqn(source, &target, true));
        }
    }
    types.sort();
    types.dedup();
    types
}

// ---------------------------------------------------------------------------
// Visible types
// ---------------------------------------------------------------------------

pub(crate) fn visible_type_candidates(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    visible_type_candidates_inner(source, file, name, true, false)
}

pub(crate) fn usage_visible_type_candidates(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    visible_type_candidates_inner(source, file, name, true, true)
}

fn visible_type_candidates_inner(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
    resolve_aliases: bool,
    usage: bool,
) -> Vec<CodeUnit> {
    let mut using_aliases = || Some(source.using_aliases_of(file));
    let mut namespace_of_file = || Some(source.namespace_of_file(file));
    let mut using_namespaces = || Some(source.using_namespaces_of(file));
    let mut type_candidates = |fqn: &str| Some(type_candidates_by_fqn(source, fqn, usage));
    visible_type_candidates_with_lookups(
        name,
        resolve_aliases,
        &mut using_aliases,
        &mut namespace_of_file,
        &mut using_namespaces,
        &mut type_candidates,
    )
}

/// C#'s visible-type search, as a function of the four lookups it needs. Each
/// returns `None` when its own bounded budget ran out, which aborts the search
/// rather than reporting a miss.
pub(crate) fn visible_type_candidates_with_lookups<Aliases, Namespace, Usings, Candidates>(
    name: &str,
    resolve_aliases: bool,
    using_aliases: &mut Aliases,
    namespace_of_file: &mut Namespace,
    using_namespaces: &mut Usings,
    type_candidates_by_fqn: &mut Candidates,
) -> Vec<CodeUnit>
where
    Aliases: FnMut() -> Option<HashMap<String, String>>,
    Namespace: FnMut() -> Option<String>,
    Usings: FnMut() -> Option<Vec<String>>,
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
{
    let mut normalized = normalize_csharp_type_fragment(name);
    if normalized.is_empty() {
        return Vec::new();
    }
    let mut global_qualified = false;
    if let Some((alias, suffix)) = normalized.split_once("::") {
        normalized = if alias == "global" {
            global_qualified = true;
            suffix.to_string()
        } else if let Some(target) = using_aliases().and_then(|mut aliases| aliases.remove(alias)) {
            if suffix.is_empty() {
                target
            } else {
                format!("{target}.{suffix}")
            }
        } else {
            return Vec::new();
        };
    }
    if global_qualified {
        return type_candidates_by_fqn(&normalized).unwrap_or_default();
    }
    if resolve_aliases
        && let Some(target) = using_aliases().and_then(|aliases| aliases.get(&normalized).cloned())
        && target != normalized
    {
        return visible_type_candidates_with_lookups(
            &target,
            false,
            using_aliases,
            namespace_of_file,
            using_namespaces,
            type_candidates_by_fqn,
        );
    }

    let Some(mut namespace) = namespace_of_file() else {
        return Vec::new();
    };
    if !namespace.is_empty() {
        let Some(candidates) = type_candidates_by_fqn(&format!("{namespace}.{normalized}")) else {
            return Vec::new();
        };
        if !candidates.is_empty() {
            return candidates;
        }
    }

    let mut visible = Vec::new();
    let Some(namespaces) = using_namespaces() else {
        return Vec::new();
    };
    for using_namespace in namespaces {
        let Some(candidates) = type_candidates_by_fqn(&format!("{using_namespace}.{normalized}"))
        else {
            return Vec::new();
        };
        visible.extend(
            candidates
                .into_iter()
                .filter(|candidate| candidate.package_name() == using_namespace),
        );
    }
    if !visible.is_empty() {
        return visible;
    }

    while let Some(separator) = namespace.rfind('.') {
        namespace.truncate(separator);
        let Some(candidates) = type_candidates_by_fqn(&format!("{namespace}.{normalized}")) else {
            return Vec::new();
        };
        if !candidates.is_empty() {
            return candidates;
        }
    }

    type_candidates_by_fqn(&normalized).unwrap_or_default()
}

pub(crate) fn resolve_visible_type(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    let candidates = visible_type_candidates(source, file, name);
    (logical_type_count(&candidates) == 1)
        .then(|| {
            let mut candidates = candidates;
            sort_type_candidates(&mut candidates);
            candidates.into_iter().next()
        })
        .flatten()
}

pub(crate) fn resolve_usage_visible_type(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    let candidates = usage_visible_type_candidates(source, file, name);
    (logical_type_count(&candidates) == 1)
        .then(|| {
            let mut candidates = candidates;
            sort_type_candidates(&mut candidates);
            candidates.into_iter().next()
        })
        .flatten()
}

// ---------------------------------------------------------------------------
// Partial types
// ---------------------------------------------------------------------------

pub(crate) fn partial_type_parts(
    source: &dyn CSharpAnalysisSource,
    owner: &CodeUnit,
) -> Vec<CodeUnit> {
    if !owner.is_class() {
        return Vec::new();
    }
    let owner_key = type_declaration_key(owner);
    let mut parts: Vec<_> = source
        .get_definitions(&owner.fq_name())
        .into_iter()
        .filter(|unit| unit.is_class() && type_declaration_key(unit) == owner_key)
        .collect();
    sort_type_candidates(&mut parts);
    parts.dedup();
    parts
}

pub(crate) fn partial_type_parts_limited(
    source: &dyn CSharpAnalysisSource,
    owner: &CodeUnit,
    limit: usize,
    continue_query: impl FnMut() -> bool,
) -> LimitedQueryRows<CodeUnit> {
    if !owner.is_class() {
        return LimitedQueryRows::complete(Vec::new(), 0);
    }
    let batch = declaration_candidates_by_fqn_limited(
        source,
        &owner.fq_name(),
        false,
        limit,
        continue_query,
    );
    if !batch.complete {
        return LimitedQueryRows::incomplete(Vec::new(), batch.inspected);
    }
    let owner_key = type_declaration_key(owner);
    let mut parts: Vec<_> = batch
        .rows
        .into_iter()
        .filter(|unit| unit.is_class() && type_declaration_key(unit) == owner_key)
        .collect();
    sort_type_candidates(&mut parts);
    parts.dedup();
    LimitedQueryRows::complete(parts, batch.inspected)
}

pub(crate) fn usage_partial_type_parts(
    source: &dyn CSharpAnalysisSource,
    owner: &CodeUnit,
) -> Vec<CodeUnit> {
    if !owner.is_class() {
        return Vec::new();
    }
    let owner_key = type_declaration_key(owner);
    let mut parts: Vec<_> = usage_definition_candidates_by_fqn(source, &owner.fq_name())
        .into_iter()
        .filter(|unit| unit.is_class() && type_declaration_key(unit) == owner_key)
        .collect();
    sort_type_candidates(&mut parts);
    parts.dedup();
    parts
}

// ---------------------------------------------------------------------------
// Candidate ordering. A "logical type" is one partial declaration group, so
// these are pure functions of the fq names involved.
// ---------------------------------------------------------------------------

pub(crate) fn sort_dedup_type_candidates(candidates: &mut Vec<CodeUnit>) {
    let mut keyed: Vec<_> = candidates
        .drain(..)
        .map(|unit| {
            let key = type_declaration_key(&unit);
            let source = crate::path_utils::rel_path_string(unit.source());
            (unit, key, source)
        })
        .collect();
    keyed.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
    keyed.dedup_by(|left, right| left.1 == right.1);
    candidates.extend(keyed.into_iter().map(|(unit, _, _)| unit));
}

pub(crate) fn sort_type_candidates(candidates: &mut [CodeUnit]) {
    candidates.sort_by_cached_key(|unit| {
        (
            type_declaration_key(unit),
            crate::path_utils::rel_path_string(unit.source()),
        )
    });
}

pub(crate) fn logical_type_count(candidates: &[CodeUnit]) -> usize {
    candidates
        .iter()
        .map(type_declaration_key)
        .collect::<HashSet<_>>()
        .len()
}

pub(crate) fn first_logical_type_fqn(candidates: &[CodeUnit]) -> Option<String> {
    let mut sorted = candidates.to_vec();
    sort_type_candidates(&mut sorted);
    sorted.first().map(CodeUnit::fq_name)
}

fn type_declaration_key(unit: &CodeUnit) -> String {
    unit.fq_name()
}

// ---------------------------------------------------------------------------
// Implicit references
// ---------------------------------------------------------------------------

/// The uncached half of the analyzer's `implicit_reference_index`: which files
/// name a type declared in another file without importing it, which in C# is
/// every same-namespace reference.
pub(super) fn compute_implicit_reference_index(
    source: &dyn CSharpAnalysisSource,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
    let mut by_namespace_and_name: HashMap<String, HashMap<String, Vec<ProjectFile>>> =
        HashMap::default();
    let mut by_fq_name: HashMap<String, Vec<ProjectFile>> = HashMap::default();
    let mut namespaces_by_file: HashMap<ProjectFile, Vec<String>> = HashMap::default();
    let files: Vec<_> = source.all_files();
    for target in &files {
        let top_level = source.top_level_declarations(target);
        let mut namespaces = HashSet::default();
        for unit in &top_level {
            namespaces.insert(unit.package_name().to_string());
        }
        if namespaces.is_empty() {
            namespaces.insert(String::new());
        }
        namespaces_by_file.insert(target.clone(), namespaces.into_iter().collect());

        for unit in top_level
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
        {
            by_namespace_and_name
                .entry(unit.package_name().to_string())
                .or_default()
                .entry(unit.identifier().to_string())
                .or_default()
                .push(target.clone());
            by_fq_name
                .entry(unit.fq_name())
                .or_default()
                .push(target.clone());
            by_fq_name
                .entry(unit.fq_name().replace('$', "."))
                .or_default()
                .push(target.clone());
        }
    }

    build_reverse_file_index(
        &files,
        |candidate| {
            let Some(identifiers) = source.type_identifiers_of(candidate) else {
                return Vec::new();
            };
            let candidate_namespaces = namespaces_by_file
                .get(candidate)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut resolved_targets = Vec::new();
            for identifier in identifiers {
                for candidate_namespace in candidate_namespaces {
                    if let Some(namespace_targets) = by_namespace_and_name
                        .get(candidate_namespace)
                        .and_then(|by_name| by_name.get(&identifier))
                    {
                        resolved_targets.extend(namespace_targets.iter().cloned());
                    }
                }
                if let Some(fq_targets) = by_fq_name.get(&identifier) {
                    resolved_targets.extend(fq_targets.iter().cloned());
                }
                // Attribute names can be structurally alias-qualified or
                // `global::` qualified. Resolve only those uncommon persisted
                // identities through the normal C# visible-type resolver so
                // default candidate routing agrees with authoritative scanning.
                if identifier.contains("::") {
                    resolved_targets.extend(
                        visible_type_candidates(source, candidate, &identifier)
                            .into_iter()
                            .map(|unit| unit.source().clone()),
                    );
                }
            }
            resolved_targets
        },
        parallel,
    )
}
