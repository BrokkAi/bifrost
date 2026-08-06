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
//! `CSharpAnalyzer` lives in `brokk-bifrost-analysis`; this crate never names it.

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeHierarchyProvider, build_reverse_file_index,
};
use brokk_bifrost_core::analyzer::code_unit_index::file_namespace_from_top_level_declarations;
use brokk_bifrost_core::analyzer::model::{CodeUnitType, ImportInfo, SignatureMetadata};
use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::imports::{
    csharp_static_using_from_import, csharp_using_alias_from_import, csharp_using_namespace,
};
use crate::syntax::{
    csharp_arity_preserving_full_name, csharp_normalize_full_name, normalize_csharp_type_fragment,
};

/// The analyzer-resident products C#'s language logic resolves through, on top
/// of the two core capability traits it reads declarations and imports with.
/// The analyzer is the only implementor and every method forwards to one of its
/// own accessors or memo cells, so the cells stay where they are and no free
/// function below can reach past this surface.
///
/// `TypeHierarchyProvider` is a supertrait because the analyzer answers
/// `Some(self)` to `IAnalyzer::type_hierarchy_provider`, and the resolution
/// paths that hold only the concrete C# analyzer used it in both roles.
///
/// Several names below appear twice, plain and `_limited`. The two spellings
/// are two different queries, not one query and a capped view of it: the plain
/// one answers from the hydrating in-memory path, while the `_limited` one
/// answers from a single bounded store query whose row-byte budget is fixed
/// independently of `limit`. A `_limited` call can therefore report
/// `complete = false` at any budget, `usize::MAX` included, so no plain method
/// here can be redefined as a default over its twin without silently turning a
/// truncated batch into an authoritative answer. The per-pair divergences --
/// different filtering, ordering, fallback or index -- are recorded on the
/// methods themselves.
pub trait CSharpAnalysisSource:
    CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider
{
    // --- bounded declaration lookups ---

    /// Declarations the persisted store records under `fqn`, keyed exactly or,
    /// when `normalized` is set, by the generic-arity-stripped name. The
    /// normalized index over-matches, so callers re-apply the arity test.
    fn persisted_declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit>;

    /// [`Self::persisted_declaration_candidates_by_fqn`] under a budget.
    /// `limit` caps the store rows inspected and `continue_query` is polled for
    /// cancellation; either one exhausted leaves `complete` false, which a
    /// caller must not read as an empty result.
    fn persisted_declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit>;

    /// Declarations whose short identifier is `identifier`, from the persisted
    /// store and the definition-lookup units. Resolution enters here when it
    /// holds a bare name with no namespace to qualify it with.
    fn declaration_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit>;

    /// [`Self::declaration_candidates_by_identifier`] under a budget. The plain
    /// spelling also drops hydrated units whose identifier no longer equals
    /// `identifier`; this one filters in the store query alone and so admits
    /// rows the plain spelling rejects.
    fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit>;

    /// Members named `name` declared on the type `owner_fqn`, matched on the
    /// exact owner name first and on the normalized owner name only when that
    /// misses.
    fn member_candidates_for_owner(&self, owner_fqn: &str, name: &str) -> BTreeSet<CodeUnit>;

    /// [`Self::member_candidates_for_owner`] under a budget shared by both
    /// phases. An exhausted exact phase returns without consulting the
    /// normalized-owner phase that the plain spelling always reaches.
    fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit>;

    /// Whether any persisted declaration sits in `namespace`. Resolution reads
    /// it to tell a namespace-qualified prefix from a type name spelled the
    /// same way.
    fn workspace_namespace_exists(&self, namespace: &str) -> bool;

    /// Definitions of `fqn` after the store forwards renamed or relocated units
    /// to their current identity. The persisted counterpart of the `usage_*`
    /// fq-name lookups, which answer from the usage-definition index instead.
    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// The workspace's usage-definition index, as the bounded lookup contract.
    /// Every `usage_*` spelling below answers from here rather than from the
    /// persisted store.
    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup;

    // --- indexed file facts ---

    /// Every analyzed C# file in the workspace. The `global using` cells and
    /// the implicit-reference index walk this rather than the store's own file
    /// table.
    fn all_files(&self) -> Vec<ProjectFile>;

    /// The namespace the store recorded for `file`: `None` when the file has no
    /// recorded state at all, empty when it has state but no namespace. The
    /// first input to [`Self::namespace_of_file`]. C#'s extractor never records
    /// one -- the namespace lives on each declaration -- so in practice the
    /// declaration fallback is what answers.
    fn package_name_of(&self, file: &ProjectFile) -> Option<String>;

    /// The recorded namespace of `file` as at most one row, falling back to the
    /// first top-level declaration in source order that carries one. `limit`
    /// caps the declarations inspected. [`Self::namespace_of_file`] applies the
    /// same rule at an unbounded budget but reads the hydrating in-memory path,
    /// so it stays a distinct method rather than a default over this one.
    fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String>;

    /// [`ImportAnalysisProvider::import_info_of`] under a budget: the import
    /// records of `file`, whose `raw_snippet` still holds the `using` directive
    /// verbatim for the C# spellings to parse. `limit` caps rows.
    fn import_info_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<ImportInfo>;

    /// Every file's import records in one store walk, so the `global using`
    /// cells need not iterate [`Self::all_files`] themselves. `limit` caps rows
    /// and `continue_query` is polled for cancellation.
    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<ImportInfo>;

    /// Base-type and interface names as written at the declaration of
    /// `code_unit`, unresolved and in declaration order.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// [`Self::raw_supertypes_of`] under a budget, answered from the store's
    /// supertype rows in stored ordinal order and matched on signature and
    /// syntheticness as well as name. A predicate miss is reported as an empty
    /// complete batch, so it does not distinguish itself from a real absence.
    fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String>;

    /// The stored signature metadata of `code_unit` -- parameters, return type
    /// and modifiers -- under a budget. `limit` caps the rows inspected.
    fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata>;

    /// Every type-name token `file` mentions, `None` when the file has no
    /// recorded identifier set. [`compute_implicit_reference_index`] resolves
    /// these against the declaring files to build the reverse index.
    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>>;

    // --- memoized products the analyzer owns ---

    /// The namespace `file`'s declarations sit in, empty when it declares
    /// nothing. When the store recorded no namespace this falls back to the
    /// namespace of the file's first top-level declaration in source order.
    /// Memoized per file.
    ///
    /// A file may open more than one namespace; this names the one it opens
    /// with. Callers that need every namespace of the file must read the
    /// declarations themselves.
    fn namespace_of_file(&self, file: &ProjectFile) -> String;

    /// [`Self::namespace_of_file`] under a budget, answering the same rule from
    /// the same memo cell. This is the one pair on this trait whose two
    /// spellings are required to agree: they share
    /// `memo_caches.namespace_by_file`, so a divergence would make the
    /// memoized answer depend on which spelling ran first (#1726).
    fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String>;

    /// The namespaces `file` can name unqualified: its own `using` directives
    /// in source order, then the workspace `global using` namespaces it does
    /// not already repeat. Memoized per file.
    fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String>;

    /// [`Self::using_namespaces_of`] under one budget shared between the file's
    /// own imports and the global ones, with `continue_query` polled before
    /// each phase. The globals arrive from a store-wide import walk rather than
    /// from [`Self::global_using_namespaces`].
    fn using_namespaces_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String>;

    /// Alias to target for every `using X = Y;` in `file`, with workspace
    /// `global using` aliases filling only the names the file does not bind
    /// itself. Memoized per file.
    fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String>;

    /// [`Self::using_aliases_of`] under one budget shared between both phases,
    /// as pairs rather than as a map. File-local bindings still win over global
    /// ones.
    fn using_aliases_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)>;

    /// The normalized type names named by the workspace's `global using static`
    /// directives, sorted and deduplicated, under a budget. Names only;
    /// [`Self::global_static_using_types`] is the resolved form.
    fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String>;

    /// Those `global using static` targets resolved against the persisted
    /// store, memoized whole. Borrowed out of the memo cell, so it has no
    /// budgeted form: there is nothing to cap once the cell is filled.
    fn global_static_using_types(&self) -> &[CodeUnit];

    /// [`Self::global_static_using_types`] resolved against the
    /// usage-definition index instead of the persisted store. Two cells because
    /// the index differs, not the walk.
    fn usage_global_static_using_types(&self) -> &[CodeUnit];

    /// The normalized namespaces of every `global using` directive in the
    /// workspace, memoized whole. Borrowed out of the memo cell, so it cannot
    /// be expressed as a default over the budgeted spelling below.
    fn global_using_namespaces(&self) -> &HashSet<String>;

    /// [`Self::global_using_namespaces`] under a budget, from one store-wide
    /// import walk. It fills the same memo cell when the batch completes.
    fn global_using_namespaces_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String>;

    /// Alias to target for every `global using X = Y;` in the workspace,
    /// memoized whole. Borrowed out of the memo cell, so it cannot be expressed
    /// as a default over the budgeted spelling below.
    fn global_using_aliases(&self) -> &HashMap<String, String>;

    /// [`Self::global_using_aliases`] under a budget, as pairs, from one
    /// store-wide import walk. It fills the same memo cell when the batch
    /// completes.
    fn global_using_aliases_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)>;
}

// ---------------------------------------------------------------------------
// Declaration lookups
// ---------------------------------------------------------------------------

pub fn usage_declaration_candidates_by_identifier(
    source: &dyn CSharpAnalysisSource,
    identifier: &str,
) -> Vec<CodeUnit> {
    source.usage_definitions().identifier(identifier)
}

pub fn declaration_candidates_by_fqn(
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

pub fn declaration_candidates_by_fqn_limited(
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

pub fn usage_member_candidates_for_owner(
    source: &dyn CSharpAnalysisSource,
    owner_fqn: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let normalized = csharp_normalize_full_name(owner_fqn);
    source
        .usage_definitions()
        .members_for_owner_name(owner_fqn, &normalized, name)
}

pub fn usage_workspace_namespace_exists(
    source: &dyn CSharpAnalysisSource,
    namespace: &str,
) -> bool {
    source.usage_definitions().package_exists(namespace)
}

pub fn usage_type_candidates_by_fqn(source: &dyn CSharpAnalysisSource, fqn: &str) -> Vec<CodeUnit> {
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

pub fn usage_definition_candidates_by_fqn(
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

pub fn type_candidates_by_fqn(
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
///
/// Answers the same rule as `namespace_of_file_limited` below, at an unbounded
/// budget, so the memo cell the two spellings share cannot serve one spelling's
/// answer to the other (#1726). The earlier fallback scanned every declaration
/// of the file out of a `BTreeSet`, which named whichever namespace sorted
/// first rather than whichever one the file opens with.
pub fn compute_namespace_of_file(source: &dyn CSharpAnalysisSource, file: &ProjectFile) -> String {
    let recorded = source.package_name_of(file).unwrap_or_default();
    file_namespace_from_top_level_declarations(
        &recorded,
        &source.top_level_declarations(file),
        usize::MAX,
    )
    .rows
    .into_iter()
    .next()
    .unwrap_or_default()
}

/// The uncached half of the analyzer's `namespace_of_file_limited`. A complete
/// batch is what the analyzer memoizes; an incomplete one is passed straight
/// through.
pub fn compute_namespace_of_file_limited(
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

pub fn import_statements_limited(
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
pub fn compute_using_namespaces_of(
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
pub fn compute_using_namespaces_of_limited(
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
pub fn compute_using_aliases_of(
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
pub fn compute_using_aliases_of_limited(
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
pub fn compute_global_using_namespaces(source: &dyn CSharpAnalysisSource) -> HashSet<String> {
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
pub fn compute_global_using_namespaces_limited(
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
pub fn compute_global_using_aliases(source: &dyn CSharpAnalysisSource) -> HashMap<String, String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(&file).into_iter())
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(|import| csharp_using_alias_from_import(&import))
        .collect()
}

/// The uncached half of the analyzer's `global_using_aliases_limited`.
pub fn compute_global_using_aliases_limited(
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
pub fn compute_global_static_using_type_names_limited(
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
pub fn compute_global_static_using_types(source: &dyn CSharpAnalysisSource) -> Vec<CodeUnit> {
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
pub fn compute_usage_global_static_using_types(source: &dyn CSharpAnalysisSource) -> Vec<CodeUnit> {
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

pub fn visible_type_candidates(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    visible_type_candidates_inner(source, file, name, true, false)
}

pub fn usage_visible_type_candidates(
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
pub fn visible_type_candidates_with_lookups<Aliases, Namespace, Usings, Candidates>(
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

pub fn resolve_visible_type(
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

pub fn resolve_usage_visible_type(
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

pub fn partial_type_parts(source: &dyn CSharpAnalysisSource, owner: &CodeUnit) -> Vec<CodeUnit> {
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

pub fn partial_type_parts_limited(
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

pub fn usage_partial_type_parts(
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

pub fn sort_dedup_type_candidates(candidates: &mut Vec<CodeUnit>) {
    let mut keyed: Vec<_> = candidates
        .drain(..)
        .map(|unit| {
            let key = type_declaration_key(&unit);
            let source = brokk_bifrost_core::path_utils::rel_path_string(unit.source());
            (unit, key, source)
        })
        .collect();
    keyed.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
    keyed.dedup_by(|left, right| left.1 == right.1);
    candidates.extend(keyed.into_iter().map(|(unit, _, _)| unit));
}

pub fn sort_type_candidates(candidates: &mut [CodeUnit]) {
    candidates.sort_by_cached_key(|unit| {
        (
            type_declaration_key(unit),
            brokk_bifrost_core::path_utils::rel_path_string(unit.source()),
        )
    });
}

pub fn logical_type_count(candidates: &[CodeUnit]) -> usize {
    candidates
        .iter()
        .map(type_declaration_key)
        .collect::<HashSet<_>>()
        .len()
}

pub fn first_logical_type_fqn(candidates: &[CodeUnit]) -> Option<String> {
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
pub fn compute_implicit_reference_index(
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
