//! The language half of C#'s type-resolution logic: namespace and `using`
//! resolution, visible-type lookup, partial-type grouping and the bounded
//! declaration queries built on top of them, written as free functions over a
//! source trait instead of as methods on [`CSharpAnalyzer`].
//!
//! [`CSharpAnalyzer`] owns the generation caches and lazy cells and implements
//! [`CSharpSource`] out of its own
//! accessors, so the functions below reach back for the memoized products they
//! need without naming the analyzer type.
//!
//! One tier is enough here, unlike Rust's `RustSource`/`RustFactSource`
//! split: no `OnceLock` in the C# memo web re-enters the cell it is filling.
//! The deepest recursion, `visible_type_candidates_with_lookups`, was already
//! written as a function of its injected lookups and stays that way -- it needs
//! no source at all.
//!
//! `CSharpAnalyzer` lives in `brokk-bifrost-analysis`; this crate never names it.

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, ImportReachability, TypeHierarchyProvider, build_reverse_file_index,
};
use brokk_bifrost_core::analyzer::code_unit_index::file_namespace_from_top_level_declarations;
use brokk_bifrost_core::analyzer::model::{CodeUnitType, ImportInfo, SignatureMetadata};
use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::imports::{
    csharp_static_using_from_import, csharp_using_alias_from_import, csharp_using_alias_from_node,
    csharp_using_namespace,
};
use crate::syntax::{
    csharp_arity_preserving_full_name, csharp_normalize_full_name, csharp_type_node_segments,
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace, normalize_csharp_type_fragment, strip_csharp_generic_arity,
};
use tree_sitter::Node;

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
pub trait CSharpSource: CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider {
    /// Read attribution tied to this source's exact generation and query registry.
    fn read_capability(&self) -> brokk_bifrost_core::analyzer::project_reads::ReadCapability;

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

    /// Where `candidate`'s source sits relative to the compilation that holds
    /// `reference`, from the revision's recorded compilation membership.
    /// `None` when the membership read failed; a lookup treats it as aborted.
    fn compilation_visibility(
        &self,
        reference: &ProjectFile,
        candidate: &ProjectFile,
    ) -> Option<CSharpCompilationVisibility>;

    /// `code_unit`'s direct logical ancestors with every input read through
    /// `view`: its partial parts, each part's base list and the candidates
    /// of the base names. A view that filters declarations then decides each
    /// base-list contribution by the membership of the part that wrote it.
    fn direct_ancestors_through(
        &self,
        view: &dyn CSharpSource,
        code_unit: &CodeUnit,
    ) -> Vec<CodeUnit>;

    /// The direct children of `parent` that `keep` selects. A view that
    /// admits declarations admits only the selected ones, so a lookup by
    /// name does not count its unrelated siblings as doubt.
    fn direct_children_where(
        &self,
        parent: &CodeUnit,
        keep: &dyn Fn(&CodeUnit) -> bool,
    ) -> Vec<CodeUnit> {
        self.direct_children(parent)
            .into_iter()
            .filter(|child| keep(child))
            .collect()
    }

    /// Run one synchronous usage-resolution step against a request-local
    /// bounded definition lookup. The callback boundary lets the analysis
    /// implementation borrow its analyzer without publishing lookup state as
    /// analyzer-generation state.
    fn with_usage_definitions(
        &self,
        token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
    );

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

    /// [`ImportAnalysisProvider::import_info_of`] under a budget: canonical
    /// import records of `file`, including structured paths and global flags.
    /// `limit` caps rows.
    fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
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
    ///
    /// Shared, not owned: `visible_type_candidates_with_lookups` asks for this
    /// map up to twice per type-name reference and reads one entry each time,
    /// so an owned return made the whole map's worth of `String` allocations
    /// the per-reference cost of a single alias lookup.
    fn using_aliases_of(&self, file: &ProjectFile) -> Arc<HashMap<String, String>>;

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
    /// directives, sorted and deduplicated, memoized whole. Names rather than
    /// resolved units: a reachability proof cannot treat an unresolvable name
    /// as an absent one.
    fn global_static_using_type_names(&self) -> std::sync::Arc<Vec<String>>;

    /// [`Self::global_static_using_type_names`] under a budget. It fills the
    /// same memo cell when the batch completes.
    fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String>;

    /// Those `global using static` targets resolved against the persisted
    /// store, memoized whole. Completed values share an owned handle; a failed
    /// build returns its local handle without populating the memo.
    fn global_static_using_types(&self) -> std::sync::Arc<Vec<CodeUnit>>;

    /// [`Self::global_static_using_types`] resolved against the
    /// usage-definition index instead of the persisted store. Two cells because
    /// the index differs, not the walk.
    fn usage_global_static_using_types(&self) -> std::sync::Arc<Vec<CodeUnit>>;

    /// The normalized namespaces of every `global using` directive in the
    /// workspace, memoized whole. Completed values share an owned handle; a
    /// failed build remains local to the caller.
    fn global_using_namespaces(&self) -> std::sync::Arc<HashSet<String>>;

    /// [`file_using_namespaces`] with whatever per-file memo the
    /// implementation keeps (#2679). The visible-type search asks this once
    /// per probed name, and the bulk reference engine probes several names per
    /// occurrence, so the unmemoized default re-reads and re-filters the
    /// file's import records once per probe.
    fn file_using_namespaces_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        file_using_namespaces(self, token, file)
    }

    /// [`Self::global_using_namespaces`] as a sorted list (#2679). The
    /// visible-type search wants deterministic candidate order, and cloning
    /// and sorting the whole workspace set once per probed name is what this
    /// default does; implementations memoize the sorted list.
    fn sorted_global_using_namespaces(&self) -> Vec<String> {
        let mut namespaces: Vec<_> = self.global_using_namespaces().iter().cloned().collect();
        namespaces.sort();
        namespaces
    }

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
    fn global_using_aliases(&self) -> std::sync::Arc<HashMap<String, String>>;

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

fn with_usage_definitions<R>(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    read: impl FnOnce(&dyn BoundedDefinitionLookup) -> R,
) -> R {
    brokk_bifrost_core::analyzer::definition_lookup::with_usage_definitions_once(
        |consumer| source.with_usage_definitions(token, consumer),
        read,
    )
}

pub fn usage_declaration_candidates_by_identifier(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    identifier: &str,
) -> Vec<CodeUnit> {
    with_usage_definitions(source, token, |lookup| lookup.identifier(identifier))
}

pub fn declaration_candidates_by_fqn(
    source: &dyn CSharpSource,
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
        .filter(|candidate| has_csharp_arity_key(candidate, &arity_key))
        .collect()
}

/// Whether the compilation holding `reference` sees the identity that
/// `matches` selects among the physical declarations of `fqn`.
///
/// Physical declarations that share a fully qualified name are one identity
/// only where each is visible: a proven declaration proves its own members,
/// never a member that only an unproven or invisible copy declares. So the
/// identity is visible when some matching declaration is, unresolved when the
/// best is unresolved, and not visible when every one is provably invisible.
/// A name with no workspace declaration (an external or intrinsic member)
/// is outside compilation membership and answers `Visible`, as before.
/// `None` when a membership read failed.
pub fn identity_visibility(
    source: &dyn CSharpSource,
    reference: &ProjectFile,
    fqn: &str,
    known: Option<&CodeUnit>,
    matches: impl Fn(&CodeUnit) -> bool,
) -> Option<CSharpCompilationVisibility> {
    // A declaration the caller already holds is one of the identity's
    // physical declarations even if the name lookup spells it differently.
    let mut physical = declaration_candidates_by_fqn(source, fqn, true)
        .into_iter()
        .chain(known.cloned())
        .filter(|candidate| matches(candidate))
        .peekable();
    if physical.peek().is_none() {
        return Some(CSharpCompilationVisibility::Visible);
    }
    let mut answer = CSharpCompilationVisibility::NotVisible;
    for candidate in physical {
        match source.compilation_visibility(reference, candidate.source())? {
            CSharpCompilationVisibility::Visible => {
                return Some(CSharpCompilationVisibility::Visible);
            }
            CSharpCompilationVisibility::Unresolved => {
                answer = CSharpCompilationVisibility::Unresolved
            }
            CSharpCompilationVisibility::NotVisible => {}
        }
    }
    Some(answer)
}

pub fn declaration_candidates_by_fqn_limited(
    source: &dyn CSharpSource,
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
        batch
            .rows
            .retain(|candidate| has_csharp_arity_key(candidate, &arity_key));
    }
    batch
}

fn has_csharp_arity_key(candidate: &CodeUnit, arity_key: &str) -> bool {
    csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key
}

pub fn usage_member_candidates_for_owner(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner_fqn: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let normalized = csharp_normalize_full_name(owner_fqn);
    with_usage_definitions(source, token, |lookup| {
        lookup.members_for_owner_name(owner_fqn, &normalized, name)
    })
}

pub fn usage_workspace_namespace_exists(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    namespace: &str,
) -> bool {
    with_usage_definitions(source, token, |lookup| lookup.package_exists(namespace))
}

fn usage_type_candidates_by_fqn_in(
    lookup: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Vec<CodeUnit> {
    usage_definition_candidates_by_fqn_in_filter(lookup, fqn, CodeUnit::is_class)
}

pub fn usage_type_candidates_by_fqn(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
) -> Vec<CodeUnit> {
    with_usage_definitions(source, token, |lookup| {
        usage_type_candidates_by_fqn_in(lookup, fqn)
    })
}

fn usage_definition_candidates_by_fqn_in(
    lookup: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Vec<CodeUnit> {
    usage_definition_candidates_by_fqn_in_filter(lookup, fqn, |_| true)
}

fn usage_definition_candidates_by_fqn_in_filter(
    lookup: &dyn BoundedDefinitionLookup,
    fqn: &str,
    mut include: impl FnMut(&CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    let exact = lookup
        .fqn(fqn)
        .into_iter()
        .filter(|unit| include(unit))
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }
    let arity_key = csharp_arity_preserving_full_name(fqn);
    lookup
        .by_normalized_fqn(&csharp_normalize_full_name(fqn))
        .iter()
        .filter(|unit| {
            include(unit) && csharp_arity_preserving_full_name(&unit.fq_name()) == arity_key
        })
        .cloned()
        .collect()
}

pub fn usage_definition_candidates_by_fqn(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
) -> Vec<CodeUnit> {
    with_usage_definitions(source, token, |lookup| {
        usage_definition_candidates_by_fqn_in(lookup, fqn)
    })
}

pub fn type_candidates_by_fqn(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
    usage: bool,
) -> Vec<CodeUnit> {
    if usage {
        return usage_type_candidates_by_fqn(source, token, fqn);
    }
    // One normalized-fqn probe covers both persisted nested separators and
    // generic identities. The declaration helper re-applies the spelling's
    // arity before returning, so this does not spend a second store query on
    // an exact miss (#1806/#2209).
    declaration_candidates_by_fqn(source, fqn, true)
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect()
}

/// Type candidates for a syntax role that permits an arity-free type name.
///
/// C# normally treats a bare `Box` as arity zero. A small set of grammar-proven
/// forms, notably `nameof(Box)`, may still name `Box<T>` (#2209). Those callers
/// opt into this lookup rather than weakening ordinary type lookup globally.
/// Exact arity-zero declarations retain precedence over normalized generics.
pub fn usage_arity_free_type_candidates_by_fqn(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
) -> Vec<CodeUnit> {
    with_usage_definitions(source, token, |lookup| {
        usage_arity_free_type_candidates_by_fqn_in(lookup, fqn)
    })
}

fn usage_arity_free_type_candidates_by_fqn_in(
    lookup: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Vec<CodeUnit> {
    let exact = lookup
        .fqn(fqn)
        .iter()
        .filter(|unit| unit.is_class())
        .cloned()
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }
    lookup
        .by_normalized_fqn(&csharp_normalize_full_name(fqn))
        .iter()
        .filter(|unit| unit.is_class())
        .cloned()
        .collect()
}

pub fn arity_free_declaration_type_candidates_by_fqn(
    source: &dyn CSharpSource,
    fqn: &str,
) -> Vec<CodeUnit> {
    let candidates = source
        .persisted_declaration_candidates_by_fqn(fqn, true)
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    let mut candidates = candidates;
    retain_exact_arity_candidates(&mut candidates, fqn);
    candidates
}

/// The persisted, budgeted counterpart of
/// [`arity_free_declaration_type_candidates_by_fqn`]. It issues one indexed
/// normalized-fqn probe, then gives exact arity-zero declarations precedence
/// over generic candidates in memory (#1806/#2209).
pub fn arity_free_declaration_type_candidates_by_fqn_limited(
    source: &dyn CSharpSource,
    fqn: &str,
    limit: usize,
    mut continue_query: impl FnMut() -> bool,
) -> LimitedQueryRows<CodeUnit> {
    let mut normalized = source.persisted_declaration_candidates_by_fqn_limited(
        fqn,
        true,
        limit,
        &mut continue_query,
    );
    normalized.rows.retain(CodeUnit::is_class);
    if !retain_exact_arity_candidates(&mut normalized.rows, fqn) && !normalized.complete {
        // A later row may still be an exact arity-zero declaration, which has
        // precedence over every generic candidate already observed.
        normalized.rows.clear();
    }
    normalized
}

fn retain_exact_arity_candidates(candidates: &mut Vec<CodeUnit>, fqn: &str) -> bool {
    let arity_key = csharp_arity_preserving_full_name(fqn);
    let has_exact_arity = candidates
        .iter()
        .any(|candidate| has_csharp_arity_key(candidate, &arity_key));
    if has_exact_arity {
        candidates.retain(|candidate| has_csharp_arity_key(candidate, &arity_key));
    }
    has_exact_arity
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
pub fn compute_namespace_of_file(source: &dyn CSharpSource, file: &ProjectFile) -> String {
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
    source: &dyn CSharpSource,
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

/// The uncached half of the analyzer's `using_namespaces_of`.
pub fn compute_using_namespaces_of(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Vec<String> {
    let mut namespaces: Vec<String> = source
        .import_info_of(token, file)
        .iter()
        .filter_map(csharp_using_namespace)
        .collect();
    for namespace in source.global_using_namespaces().iter() {
        if !namespaces.contains(namespace) {
            namespaces.push(namespace.clone());
        }
    }
    namespaces
}

/// The ordinary namespace `using` directives written in `file`, excluding
/// workspace `global using` directives. Visible-type lookup keeps this set as
/// a distinct precedence tier so a global directive from another compilation
/// cannot make a file-local import ambiguous (#2060).
pub fn file_using_namespaces<S: CSharpSource + ?Sized>(
    source: &S,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Vec<String> {
    source
        .import_info_of(token, file)
        .iter()
        .filter(|import| !import.is_global)
        .filter_map(csharp_using_namespace)
        .collect()
}

/// [`file_using_namespaces`] under a store-row budget.
pub fn file_using_namespaces_limited(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    limit: usize,
) -> LimitedQueryRows<String> {
    let imports = source.import_info_of_limited(token, file, limit);
    let namespaces = imports
        .rows
        .into_iter()
        .filter(|import| !import.is_global)
        .filter_map(|import| csharp_using_namespace(&import))
        .collect();
    if imports.complete {
        LimitedQueryRows::complete(namespaces, imports.inspected)
    } else {
        LimitedQueryRows::incomplete(namespaces, imports.inspected)
    }
}

/// The uncached half of the analyzer's `using_namespaces_of_limited`.
pub fn compute_using_namespaces_of_limited(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    if limit == 0 || !continue_query() {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }

    let imports = source.import_info_of_limited(token, file, limit);
    combine_limited_local_global_imports(
        imports,
        limit,
        continue_query,
        |imports| {
            imports
                .into_iter()
                .filter_map(|import| csharp_using_namespace(&import))
                .collect()
        },
        |remaining, continue_query| {
            source.global_using_namespaces_limited(remaining, continue_query)
        },
        |mut namespaces, globals| {
            for namespace in globals {
                if !namespaces.contains(&namespace) {
                    namespaces.push(namespace);
                }
            }
            namespaces
        },
    )
}

fn combine_limited_local_global_imports<T>(
    imports: LimitedQueryRows<ImportInfo>,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
    local_values: impl FnOnce(Vec<ImportInfo>) -> Vec<T>,
    global_values: impl FnOnce(usize, &mut dyn FnMut() -> bool) -> LimitedQueryRows<T>,
    merge: impl FnOnce(Vec<T>, Vec<T>) -> Vec<T>,
) -> LimitedQueryRows<T> {
    let local_rows = local_values(imports.rows);
    if !imports.complete {
        return LimitedQueryRows::incomplete(local_rows, imports.inspected);
    }

    let globals = global_values(limit.saturating_sub(imports.inspected), continue_query);
    let rows = merge(local_rows, globals.rows);
    let inspected = imports.inspected.saturating_add(globals.inspected);
    if globals.complete {
        LimitedQueryRows::complete(rows, inspected)
    } else {
        LimitedQueryRows::incomplete(rows, inspected)
    }
}

// ---------------------------------------------------------------------------
// Import reachability
// ---------------------------------------------------------------------------

/// Query-independent reachability inputs for one file in an analyzer generation.
///
/// C# has no named imports: a `using` directive names a namespace, so asking
/// the framework's generic question "which declarations does this file import"
/// materializes every top-level type of every used namespace. Candidate
/// discovery then reduces that whole set to one boolean. Answering the boolean
/// directly is cheap; answering it *authoritatively* is what lets the caller
/// skip the expansion (#1730, after the #1194 incident).
///
/// [`ImportReachability::Reaches`] is the historical `could_import_file`
/// answer, unchanged. [`ImportReachability::DoesNotReach`] is returned only
/// from the indexed name and namespace proof. Everything else stays
/// [`ImportReachability::Unknown`], which is exactly the old behavior.
///
/// Proven, each with a behavior test and a near miss:
///
/// - plain `using N;`, including `global using N;` from another file, via the
///   workspace-level global-using cells rather than per-file import facts
/// - same-namespace visibility with no `using` at all, read from every
///   namespace the file declares into rather than from `namespace_of_file`,
///   which names only the first of them (#1726)
/// - nested-namespace implicit visibility (`namespace A.B` sees `A.*`)
/// - fully qualified references, `global::`-qualified references, and
///   alias-qualified (`A::N.T`) references, from the file's type-identifier set
/// - `using` aliases and namespace aliases, file-local and global
/// - `using static`, file-local and global
/// - generic arity spellings: compared with the arity stripped from both
///   sides, so ``Foo`1`` and ``Foo`2`` are treated as possible references to
///   each other rather than as a proof of difference
/// - partial classes split across files, which fall under same-namespace
///   visibility because both parts declare into the namespace
///
/// NOT proven, and therefore always `Unknown` for that file pair:
///
/// - a file whose extractor recorded no type-identifier set at all
///   (`type_identifiers_of` is `None`): an absent set is not an empty one
/// - a target with no class declarations, where there is nothing to prove
///   against
///
/// One class of reference is invisible to this proof and to the expansion it
/// replaces, so neither loses to the other: a reference whose type is only
/// inferred (`var x = Factory.Create(); x.Method();`) names no target type and
/// needs no `using`, so it appears neither in the file's identifier set nor in
/// its imported declarations. The import-graph candidate walk never found
/// those; it is not a regression to keep not finding them.
///
/// Identifier spans are reduced to names once, rather than rescanned per target.
pub struct CSharpReachabilityFacts {
    namespace: String,
    classes: Vec<CodeUnit>,
    target_names: HashSet<String>,
    target_segments: HashSet<String>,
    target_namespaces: HashSet<String>,
    arity_sensitive: bool,
    identifiers: Option<HashSet<String>>,
    identifier_segments: HashSet<String>,
    alias_candidates: HashSet<CodeUnit>,
    using_namespaces: HashSet<String>,
    visible_namespaces: HashSet<String>,
}

impl CSharpReachabilityFacts {
    pub fn build(
        source: &dyn CSharpSource,
        token: QueryToken<'_>,
        file: &ProjectFile,
        declarations: Vec<CodeUnit>,
        identifiers: Option<HashSet<String>>,
        imports: &[ImportInfo],
    ) -> Self {
        // The bounded spelling implements the same namespace rule using
        // relational metadata. With no row limit it also warms the shared
        // namespace memo before alias resolution, without hydrating file state.
        let namespace = source
            .namespace_of_file_limited(file, usize::MAX)
            .rows
            .into_iter()
            .next()
            .unwrap_or_default();
        let mut aliases: HashMap<String, String> = imports
            .iter()
            .filter_map(csharp_using_alias_from_import)
            .collect();
        for (alias, target) in source.global_using_aliases().iter() {
            aliases
                .entry(alias.clone())
                .or_insert_with(|| target.clone());
        }
        let using_namespaces: HashSet<String> = imports
            .iter()
            .filter_map(csharp_using_namespace)
            .chain(source.global_using_namespaces().iter().cloned())
            .collect();
        let mut visible_namespaces = HashSet::default();
        visible_namespaces.insert(String::new());
        for path in declarations
            .iter()
            .map(|unit| unit.package_name())
            .chain(using_namespaces.iter().map(String::as_str))
            .chain(aliases.values().map(String::as_str))
            .chain(imports.iter().filter_map(csharp_static_using_from_import))
            .chain(
                source
                    .global_static_using_type_names()
                    .iter()
                    .map(String::as_str),
            )
        {
            insert_namespace_prefixes(path, &mut visible_namespaces);
        }
        let mut alias_candidates = HashSet::default();
        for target in aliases.values() {
            alias_candidates.extend(visible_type_candidates(source, token, file, target));
        }
        let mut identifier_segments = HashSet::default();
        if let Some(identifiers) = &identifiers {
            for identifier in identifiers {
                identifier_segments
                    .extend(csharp_reference_name_segments(identifier).map(str::to_owned));
                if aliases.keys().any(|alias| {
                    identifier
                        .strip_prefix(alias)
                        .is_some_and(|suffix| suffix.starts_with("::"))
                }) {
                    alias_candidates
                        .extend(visible_type_candidates(source, token, file, identifier));
                }
            }
        }
        let classes: Vec<_> = declarations
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .collect();
        Self {
            namespace,
            target_names: classes
                .iter()
                .flat_map(|unit| {
                    let fq_name = unit.fq_name();
                    [
                        unit.identifier().to_string(),
                        fq_name.clone(),
                        fq_name.replace('$', "."),
                    ]
                })
                .collect(),
            target_segments: classes
                .iter()
                .flat_map(csharp_target_name_segments)
                .map(str::to_owned)
                .collect(),
            target_namespaces: classes
                .iter()
                .map(|unit| unit.package_name().to_string())
                .collect(),
            arity_sensitive: classes.iter().any(|unit| unit.identifier().contains('`')),
            classes,
            // Extraction can include declaration spans as well as names. A
            // span cannot equal a target type name; do not retain its source
            // body in this workspace index.
            identifiers: identifiers.map(|identifiers| {
                identifiers
                    .into_iter()
                    .filter(|identifier| {
                        csharp_reference_name_segments(identifier).next().is_some()
                    })
                    .map(|identifier| {
                        identifier
                            .strip_prefix("global::")
                            .map(str::to_owned)
                            .unwrap_or(identifier)
                    })
                    .collect()
            }),
            identifier_segments,
            alias_candidates,
            using_namespaces,
            visible_namespaces,
        }
    }
}

pub fn csharp_import_reachability(
    source: &CSharpReachabilityFacts,
    imports: &[ImportInfo],
    target: &CSharpReachabilityFacts,
) -> ImportReachability {
    if (source.namespace == target.namespace && !target.arity_sensitive)
        || source
            .identifiers
            .as_ref()
            .is_some_and(|identifiers| !identifiers.is_disjoint(&target.target_names))
        || !source
            .using_namespaces
            .is_disjoint(&target.target_namespaces)
        || imports
            .iter()
            .filter_map(csharp_using_namespace)
            .any(|namespace| target.target_namespaces.contains(&namespace))
        || target
            .classes
            .iter()
            .any(|unit| source.alias_candidates.contains(unit))
    {
        return ImportReachability::Reaches;
    }
    if target.classes.is_empty()
        || source.identifiers.is_none()
        || !source
            .identifier_segments
            .is_disjoint(&target.target_segments)
        || !source
            .visible_namespaces
            .is_disjoint(&target.target_namespaces)
    {
        return ImportReachability::Unknown;
    }
    // Caller-supplied imports remain authoritative even when they differ from
    // the generation's stored directives.
    let mut visible = HashSet::default();
    for import in imports {
        if let Some(namespace) = csharp_using_namespace(import) {
            insert_namespace_prefixes(&namespace, &mut visible);
        }
        if let Some(target) = csharp_static_using_from_import(import) {
            insert_namespace_prefixes(target, &mut visible);
        }
    }
    if visible.is_disjoint(&target.target_namespaces) {
        ImportReachability::DoesNotReach
    } else {
        ImportReachability::Unknown
    }
}

/// Every short name a reference could use to name `unit`: its own identifier,
/// the leaf of its fully-qualified name and the leaf of its short name, each
/// with the generic arity stripped so ``Foo`1`` and ``Foo`2`` are not treated
/// as different types. A nested type is reachable as `Outer.Inner`, so `Inner`
/// has to be one of them.
fn csharp_target_name_segments(unit: &CodeUnit) -> impl Iterator<Item = &str> {
    [unit.identifier(), unit.short_name()]
        .into_iter()
        .flat_map(|spelling| spelling.split(['.', '$', '+']))
        .map(strip_csharp_generic_arity)
        .filter(|segment| !segment.is_empty())
}

/// The identifier segments a C# type spelling can name a type with.
///
/// `N.C.Nested` can name `N`, `C` or `Nested`, so a proof that a file names
/// none of the target's types has to test every segment rather than the last.
/// The extractor's identifier set also holds raw declaration spans -- a class
/// body arrives as one entry -- and a span is not a name, so a spelling
/// carrying whitespace or a brace contributes nothing.
fn csharp_reference_name_segments(identifier: &str) -> impl Iterator<Item = &str> {
    let is_name = !identifier
        .chars()
        .any(|character| character.is_whitespace() || character == '{' || character == '(');
    is_name
        .then_some(identifier)
        .into_iter()
        .flat_map(|identifier| identifier.split(['.', ':', '$', '+']))
        .map(strip_csharp_generic_arity)
        .filter(|segment| !segment.is_empty())
}

/// Insert `path` and every dotted prefix of it, `global::`-stripped.
fn insert_namespace_prefixes(path: &str, visible: &mut HashSet<String>) {
    let path = path.strip_prefix("global::").unwrap_or(path);
    let mut prefix = String::new();
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(strip_csharp_generic_arity(segment));
        visible.insert(prefix.clone());
    }
}

/// The uncached half of the analyzer's `using_aliases_of`.
pub fn compute_using_aliases_of(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> HashMap<String, String> {
    let mut aliases: HashMap<String, String> = source
        .import_info_of(token, file)
        .iter()
        .filter_map(csharp_using_alias_from_import)
        .collect();
    for (alias, target) in source.global_using_aliases().iter() {
        aliases
            .entry(alias.clone())
            .or_insert_with(|| target.clone());
    }
    aliases
}

/// The uncached half of the analyzer's `using_aliases_of_limited`.
pub fn compute_using_aliases_of_limited(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<(String, String)> {
    if limit == 0 || !continue_query() {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }

    let imports = source.import_info_of_limited(token, file, limit);
    combine_limited_local_global_imports(
        imports,
        limit,
        continue_query,
        |imports| {
            imports
                .iter()
                .filter_map(csharp_using_alias_from_import)
                .collect::<HashMap<String, String>>()
                .into_iter()
                .collect()
        },
        |remaining, continue_query| source.global_using_aliases_limited(remaining, continue_query),
        |mut aliases, globals| {
            let mut aliases: HashMap<String, String> = aliases.drain(..).collect();
            for (alias, target) in globals {
                aliases.entry(alias).or_insert(target);
            }
            aliases.into_iter().collect()
        },
    )
}

/// The uncached half of the analyzer's `global_using_namespaces`.
pub fn compute_global_using_namespaces(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> HashSet<String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(token, &file).into_iter())
        .filter(|import| import.is_global)
        .filter_map(|import| csharp_using_namespace(&import))
        .filter_map(|namespace| normalize_global_using_target(&namespace))
        .collect()
}

/// The uncached half of the analyzer's `global_using_namespaces_limited`.
pub fn compute_global_using_namespaces_limited(
    source: &dyn CSharpSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let namespaces: HashSet<_> = imports
        .rows
        .into_iter()
        .filter(|import| import.is_global)
        .filter_map(|import| csharp_using_namespace(&import))
        .filter_map(|namespace| normalize_global_using_target(&namespace))
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(namespaces.into_iter().collect(), imports.inspected);
    }
    LimitedQueryRows::complete(namespaces.into_iter().collect(), imports.inspected)
}

/// The uncached half of the analyzer's `global_using_aliases`.
pub fn compute_global_using_aliases(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> HashMap<String, String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(token, &file).into_iter())
        .filter(|import| import.is_global)
        .filter_map(|import| csharp_using_alias_from_import(&import))
        .collect()
}

/// The uncached half of the analyzer's `global_using_aliases_limited`.
pub fn compute_global_using_aliases_limited(
    source: &dyn CSharpSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<(String, String)> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let aliases: HashMap<_, _> = imports
        .rows
        .iter()
        .filter(|import| import.is_global)
        .filter_map(csharp_using_alias_from_import)
        .collect();
    if !imports.complete {
        return LimitedQueryRows::incomplete(aliases.into_iter().collect(), imports.inspected);
    }
    LimitedQueryRows::complete(aliases.into_iter().collect(), imports.inspected)
}

/// The uncached half of the analyzer's `global_static_using_type_names_limited`.
/// The uncached half of the analyzer's `global_static_using_type_names`.
pub fn compute_global_static_using_type_names(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> Vec<String> {
    let mut names = compute_global_static_using_targets(source, token)
        .into_iter()
        .filter(|target| !target.is_empty())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn compute_global_static_using_targets(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> Vec<String> {
    source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(token, &file).into_iter())
        .filter(|import| import.is_global)
        .filter_map(|import| normalized_static_using_target(&import))
        .collect()
}

pub fn compute_global_static_using_type_names_limited(
    source: &dyn CSharpSource,
    limit: usize,
    continue_query: &mut dyn FnMut() -> bool,
) -> LimitedQueryRows<String> {
    let imports = source.workspace_import_info_limited(limit, continue_query);
    let mut type_names: Vec<_> = imports
        .rows
        .iter()
        .filter(|import| import.is_global)
        .filter_map(normalized_static_using_target)
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
pub fn compute_global_static_using_types(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> Vec<CodeUnit> {
    let mut types = Vec::new();
    for target in compute_global_static_using_targets(source, token) {
        types.extend(type_candidates_by_fqn(source, token, &target, false));
    }
    types.sort();
    types.dedup();
    types
}

/// [`compute_global_static_using_types`] answered from the usage-definition
/// index instead of the persisted store. Two cells, two walks: the difference
/// is which index resolves each target, and a `usage` flag threaded through one
/// body would hide that behind a mode parameter.
pub fn compute_usage_global_static_using_types(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> Vec<CodeUnit> {
    let mut types = Vec::new();
    for target in compute_global_static_using_targets(source, token) {
        types.extend(type_candidates_by_fqn(source, token, &target, true));
    }
    types.sort();
    types.dedup();
    types
}

fn normalize_global_using_target(target: &str) -> Option<String> {
    let target = target.strip_prefix("global::").unwrap_or(target);
    let normalized = normalize_csharp_type_fragment(target);
    (!normalized.is_empty()).then_some(normalized)
}

fn normalized_static_using_target(import: &ImportInfo) -> Option<String> {
    let target = csharp_static_using_from_import(import)?;
    let target = target.strip_prefix("global::").unwrap_or(target);
    Some(normalize_csharp_type_fragment(target))
}

// ---------------------------------------------------------------------------
// Visible types
// ---------------------------------------------------------------------------

pub fn visible_type_candidates(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut type_candidates = |fqn: &str| type_candidates_by_fqn(source, token, fqn, false);
    visible_type_candidates_inner(source, token, file, name, &mut type_candidates)
}

pub fn usage_visible_type_candidates(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut type_candidates = |fqn: &str| type_candidates_by_fqn(source, token, fqn, true);
    visible_type_candidates_inner(source, token, file, name, &mut type_candidates)
}

fn visible_type_candidates_inner<Candidates>(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
    type_candidates: &mut Candidates,
) -> Vec<CodeUnit>
where
    Candidates: FnMut(&str) -> Vec<CodeUnit>,
{
    let mut using_aliases = || Some(source.using_aliases_of(file));
    let mut namespace_of_file = || Some(source.namespace_of_file(file));
    let mut file_using_namespaces = || Some(source.file_using_namespaces_of(token, file));
    let mut global_using_namespaces = || Some(source.sorted_global_using_namespaces());
    let mut namespace_exists = |namespace: &str| source.workspace_namespace_exists(namespace);
    let mut type_candidates_by_fqn = |fqn: &str| Some(type_candidates(fqn));
    visible_type_candidates_with_lookups(
        name,
        true,
        &mut using_aliases,
        &mut namespace_of_file,
        &mut file_using_namespaces,
        &mut global_using_namespaces,
        &mut namespace_exists,
        &mut type_candidates_by_fqn,
    )
}

/// The syntax-local namespace and import scopes visible at one C# source node.
///
/// A context is a query-local value built from the current syntax tree. It does
/// not cache workspace facts: namespace existence and declaration candidates
/// are still resolved through the bounded callbacks in
/// [`visible_type_candidates_at_with_lookups`]. Scopes are ordered from the
/// nearest namespace outward. A namespace declaration's directives stay with
/// the declaration that introduced them, so a relative import in one sibling
/// namespace cannot leak into another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSharpLookupContext {
    scopes: Vec<CSharpLookupScope>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CSharpLookupScope {
    namespace: String,
    using_namespaces: Vec<CSharpScopedName>,
    using_aliases: Vec<(String, CSharpScopedName)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CSharpScopedName {
    target: String,
    declared_in: Vec<String>,
}

impl CSharpLookupContext {
    /// Build the ordered namespace scopes enclosing `node` and their direct
    /// plain `using` and alias directives. `continue_lookup` is polled during
    /// both ancestry and directive walks; `None` means the caller's bounded
    /// query stopped before the context was complete.
    pub fn at(
        source: &str,
        node: Node<'_>,
        mut continue_lookup: impl FnMut() -> bool,
    ) -> Option<Self> {
        let mut namespace_nodes = Vec::new();
        let mut current = node;
        while let Some(parent) = current.parent() {
            if !continue_lookup() {
                return None;
            }
            if parent.kind() == "namespace_declaration" {
                namespace_nodes.push(parent);
            }
            current = parent;
        }
        let root = current;
        namespace_nodes.reverse();

        // File-scoped namespaces are compilation-unit siblings, not ancestors.
        // Record one only when the requested node lies within its namespace
        // body, including when that body contains a nested block namespace.
        let mut root_cursor = root.walk();
        let mut file_scoped = None;
        for child in root.named_children(&mut root_cursor) {
            if !continue_lookup() {
                return None;
            }
            if child.kind() == "file_scoped_namespace_declaration"
                && child.end_byte() <= node.start_byte()
            {
                file_scoped = Some(child);
                break;
            }
        }
        let file_namespace_segments = file_scoped
            .and_then(|declaration| declaration.child_by_field_name("name"))
            .map(|name| csharp_type_node_segments(name, source))
            .filter(|segments| !segments.is_empty())
            .unwrap_or_default();

        let mut declarations = Vec::with_capacity(namespace_nodes.len());
        let mut namespace_segments = file_namespace_segments.clone();
        for declaration in namespace_nodes {
            if !continue_lookup() {
                return None;
            }
            let Some(name) = declaration.child_by_field_name("name") else {
                continue;
            };
            let segments = csharp_type_node_segments(name, source);
            if segments.is_empty() {
                continue;
            }
            let parent_segments = namespace_segments.clone();
            namespace_segments.extend(segments);
            declarations.push((declaration, parent_segments, namespace_segments.clone()));
        }

        let mut scopes = Vec::new();
        for (declaration, parent_segments, declaration_segments) in declarations.iter().rev() {
            let namespace = declaration_segments.join(".");
            let mut scope = CSharpLookupScope {
                namespace,
                ..CSharpLookupScope::default()
            };
            if let Some(body) = declaration.child_by_field_name("body") {
                collect_context_usings(
                    source,
                    body,
                    0,
                    usize::MAX,
                    declaration_segments,
                    &mut scope,
                    &mut continue_lookup,
                )?;
            }
            scopes.push(scope);

            // A dotted namespace declaration introduces each containing
            // namespace for lookup, but its imports belong only to the exact
            // namespace declaration above.
            for end in (parent_segments.len() + 1..declaration_segments.len()).rev() {
                if !continue_lookup() {
                    return None;
                }
                scopes.push(CSharpLookupScope {
                    namespace: declaration_segments[..end].join("."),
                    ..CSharpLookupScope::default()
                });
            }
        }

        // A file-scoped namespace is a direct compilation-unit child rather
        // than an AST ancestor of its declarations. Its root-level usings
        // after the declaration belong to that namespace; preceding root
        // usings remain compilation-unit imports.
        if let Some(declaration) = file_scoped {
            let file_namespace = &file_namespace_segments;
            if !file_namespace.is_empty() {
                let mut scope = CSharpLookupScope {
                    namespace: file_namespace.join("."),
                    ..CSharpLookupScope::default()
                };
                collect_context_usings(
                    source,
                    root,
                    declaration.end_byte(),
                    usize::MAX,
                    file_namespace,
                    &mut scope,
                    &mut continue_lookup,
                )?;
                scopes.push(scope);
                for end in (1..file_namespace.len()).rev() {
                    if !continue_lookup() {
                        return None;
                    }
                    scopes.push(CSharpLookupScope {
                        namespace: file_namespace[..end].join("."),
                        ..CSharpLookupScope::default()
                    });
                }
            }
        }

        // Compilation-unit directives are a distinct outer scope. In a
        // file-scoped source only directives preceding that declaration are
        // compilation-unit imports; later directives were collected above.
        let mut compilation_scope = CSharpLookupScope::default();
        let compilation_using_end =
            file_scoped.map_or(usize::MAX, |declaration| declaration.start_byte());
        collect_context_usings(
            source,
            root,
            0,
            compilation_using_end,
            &[],
            &mut compilation_scope,
            &mut continue_lookup,
        )?;
        scopes.push(compilation_scope);

        Some(Self { scopes })
    }

    /// The namespace declared nearest the node; empty in the global namespace.
    pub fn namespace(&self) -> &str {
        &self.scopes[0].namespace
    }
}

fn collect_context_usings(
    source: &str,
    scope_node: Node<'_>,
    using_start: usize,
    using_end: usize,
    namespace_segments: &[String],
    scope: &mut CSharpLookupScope,
    continue_lookup: &mut impl FnMut() -> bool,
) -> Option<()> {
    let mut cursor = scope_node.walk();
    for directive in scope_node.named_children(&mut cursor) {
        if !continue_lookup() {
            return None;
        }
        if directive.kind() != "using_directive"
            || directive.start_byte() < using_start
            || directive.end_byte() > using_end
            || csharp_using_directive_is_global(directive)
            || csharp_using_directive_is_static(directive)
        {
            continue;
        }
        let declared_in = namespace_segments.to_vec();
        if let Some(target) = csharp_using_directive_namespace(directive, source) {
            scope.using_namespaces.push(CSharpScopedName {
                target,
                declared_in,
            });
        } else if let Some((alias, target)) = csharp_using_alias_from_node(directive, source) {
            scope.using_aliases.push((
                alias,
                CSharpScopedName {
                    target,
                    declared_in,
                },
            ));
        }
    }
    Some(())
}

/// Where a candidate declaration's source sits relative to the compilation
/// that contains the reference being resolved.
///
/// C# merges the global namespace across a compilation and the assemblies it
/// references, and that merged namespace precedes every `using` directive. An
/// analyzed workspace can hold many compilations, so a source file's identity
/// alone does not say whether a global-namespace declaration in another file
/// takes part in that precedence: only compilation membership does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CSharpCompilationVisibility {
    /// The candidate belongs to the reference's compilation or to one that it
    /// references.
    Visible,
    /// Membership proves that the reference's compilation cannot see the
    /// candidate.
    NotVisible,
    /// The membership of the reference or of the candidate is not proven.
    Unresolved,
}

/// C# visible-type lookup for an AST-site context. Every external/workspace
/// lookup is injectable and abortable: outer `None` from any callback, or a
/// false continuation poll, returns `None` rather than a false clean miss.
/// `compilation_visibility` places each global-namespace candidate relative to
/// the reference's compilation (see [`CSharpCompilationVisibility`]).
#[allow(clippy::too_many_arguments)]
pub fn visible_type_candidates_at_with_lookups<
    GlobalAliasTarget,
    GlobalUsings,
    NamespaceExists,
    Candidates,
    Visibility,
    Continue,
>(
    name: &str,
    context: &CSharpLookupContext,
    global_alias_target: &mut GlobalAliasTarget,
    global_using_namespaces: &mut GlobalUsings,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
    compilation_visibility: &mut Visibility,
    continue_lookup: &mut Continue,
) -> Option<VisibleTypes>
where
    GlobalAliasTarget: FnMut(&str) -> Option<Option<String>>,
    GlobalUsings: FnMut() -> Option<Vec<String>>,
    NamespaceExists: FnMut(&str) -> Option<bool>,
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Visibility: FnMut(&CodeUnit) -> Option<CSharpCompilationVisibility>,
    Continue: FnMut() -> bool,
{
    let result = visible_type_lookup_result_at_with_lookups(
        name,
        context,
        global_alias_target,
        global_using_namespaces,
        namespace_exists,
        type_candidates_by_fqn,
        compilation_visibility,
        continue_lookup,
    )?;
    // This view names types, so an unproven declaration that shares its
    // fully qualified name with a proven one leaves the named type proven
    // and is dropped: it adds no name, and its own members are not proven
    // by the proven twin. Any other unproven declaration is doubt.
    let proven_name = |unresolved: &CodeUnit| {
        result.declarations.iter().any(|declaration| {
            declaration.fq_name() == unresolved.fq_name()
                && !result.unresolved.contains(declaration)
        })
    };
    let (covered, unproven): (Vec<_>, Vec<_>) = result
        .unresolved
        .iter()
        .cloned()
        .partition(|unresolved| proven_name(unresolved));
    let mut declarations = result.declarations;
    declarations.retain(|declaration| !covered.contains(declaration));
    if result.imported_scope {
        sort_dedup_type_candidates(&mut declarations);
    }
    Some(VisibleTypes {
        declarations,
        unproven,
    })
}

/// C# visible declaration lookup for an AST-site context. Unlike
/// [`visible_type_candidates_at_with_lookups`], this preserves path-distinct
/// declarations with the same fully qualified name; it removes only repeated
/// identical `CodeUnit`s. Attribute lookup uses this physical declaration view
/// because each declaration carries its own syntax-site identity.
#[allow(clippy::too_many_arguments)]
pub fn visible_type_declarations_at_with_lookups<
    GlobalAliasTarget,
    GlobalUsings,
    NamespaceExists,
    Candidates,
    Visibility,
    Continue,
>(
    name: &str,
    context: &CSharpLookupContext,
    global_alias_target: &mut GlobalAliasTarget,
    global_using_namespaces: &mut GlobalUsings,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
    compilation_visibility: &mut Visibility,
    continue_lookup: &mut Continue,
) -> Option<VisibleTypes>
where
    GlobalAliasTarget: FnMut(&str) -> Option<Option<String>>,
    GlobalUsings: FnMut() -> Option<Vec<String>>,
    NamespaceExists: FnMut(&str) -> Option<bool>,
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Visibility: FnMut(&CodeUnit) -> Option<CSharpCompilationVisibility>,
    Continue: FnMut() -> bool,
{
    let result = visible_type_lookup_result_at_with_lookups(
        name,
        context,
        global_alias_target,
        global_using_namespaces,
        namespace_exists,
        type_candidates_by_fqn,
        compilation_visibility,
        continue_lookup,
    )?;
    // This view keeps physical declarations, so every unproven one is doubt.
    let mut declarations = result.declarations;
    let mut seen = HashSet::default();
    declarations.retain(|declaration| seen.insert(declaration.clone()));
    sort_type_candidates(&mut declarations);
    Some(VisibleTypes {
        declarations,
        unproven: result.unresolved,
    })
}

#[derive(Debug)]
struct VisibleTypeLookupResult {
    declarations: Vec<CodeUnit>,
    imported_scope: bool,
    /// Global-namespace declarations in `declarations` whose compilation
    /// membership is unproven.
    unresolved: Vec<CodeUnit>,
}

/// The types a name denotes at one site.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VisibleTypes {
    pub declarations: Vec<CodeUnit>,
    /// Declarations in `declarations` that are there only because their
    /// compilation membership is unproven. When non-empty the answer is not a
    /// proven resolution, even if it names one type: a caller reports the
    /// doubt instead of resolving.
    pub unproven: Vec<CodeUnit>,
}

impl VisibleTypes {
    /// The declarations, if compilation membership proves all of them.
    pub fn proven(self) -> Option<Vec<CodeUnit>> {
        self.unproven.is_empty().then_some(self.declarations)
    }
}

#[allow(clippy::too_many_arguments)]
fn visible_type_lookup_result_at_with_lookups<
    GlobalAliasTarget,
    GlobalUsings,
    NamespaceExists,
    Candidates,
    Visibility,
    Continue,
>(
    name: &str,
    context: &CSharpLookupContext,
    global_alias_target: &mut GlobalAliasTarget,
    global_using_namespaces: &mut GlobalUsings,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
    compilation_visibility: &mut Visibility,
    continue_lookup: &mut Continue,
) -> Option<VisibleTypeLookupResult>
where
    GlobalAliasTarget: FnMut(&str) -> Option<Option<String>>,
    GlobalUsings: FnMut() -> Option<Vec<String>>,
    NamespaceExists: FnMut(&str) -> Option<bool>,
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Visibility: FnMut(&CodeUnit) -> Option<CSharpCompilationVisibility>,
    Continue: FnMut() -> bool,
{
    let normalized = normalize_csharp_type_fragment(name);
    if normalized.is_empty() {
        return Some(VisibleTypeLookupResult {
            declarations: Vec::new(),
            imported_scope: false,
            unresolved: Vec::new(),
        });
    }

    // Every tier, qualified or not, sees only declarations its compilation
    // can see: a candidate the reference's compilation provably cannot see
    // is not a member of the namespace there, and one of unproven membership
    // is set aside as doubt. Set-aside candidates of an inner tier would
    // take precedence if visible, so they travel with whatever an outer tier
    // finds.
    let unresolved = RefCell::new(Vec::new());
    let mut visible_candidates = |fqn: &str| -> Option<Vec<CodeUnit>> {
        let mut visible = Vec::new();
        for candidate in type_candidates_by_fqn(fqn)? {
            match compilation_visibility(&candidate)? {
                CSharpCompilationVisibility::Visible => visible.push(candidate),
                CSharpCompilationVisibility::Unresolved => unresolved.borrow_mut().push(candidate),
                CSharpCompilationVisibility::NotVisible => {}
            }
        }
        Some(visible)
    };
    let found = |mut declarations: Vec<CodeUnit>, imported_scope: bool| {
        let unresolved = unresolved.take();
        declarations.extend(unresolved.iter().cloned());
        VisibleTypeLookupResult {
            declarations,
            imported_scope,
            unresolved,
        }
    };

    if let Some((alias, suffix)) = normalized.split_once("::") {
        if alias == "global" {
            let declarations =
                lookup_exact_type_candidates(suffix, &mut visible_candidates, continue_lookup)?;
            return Some(found(declarations, false));
        }
        let Some(target) =
            lookup_alias_target(alias, context, global_alias_target, continue_lookup)?
        else {
            return Some(found(Vec::new(), false));
        };
        let declarations = lookup_scoped_alias_target(
            &target.target,
            suffix,
            &target.declared_in,
            &mut visible_candidates,
            continue_lookup,
        )?;
        return Some(found(declarations, false));
    }

    let bare_name = !normalized.contains(['.', '$', '+']);
    for scope in &context.scopes {
        if !continue_lookup() {
            return None;
        }
        if bare_name
            && let Some((_, target)) = scope
                .using_aliases
                .iter()
                .find(|(alias, _)| alias == &normalized)
        {
            let declarations = lookup_scoped_alias_target(
                &target.target,
                "",
                &target.declared_in,
                &mut visible_candidates,
                continue_lookup,
            )?;
            return Some(found(declarations, false));
        }

        // The global namespace is the containing namespace of the
        // compilation-unit scope. Probe it before either ordinary or global
        // `using` namespaces so an import cannot redirect a type that the
        // reference's compilation sees in the global namespace.
        let fqn = if scope.namespace.is_empty() {
            normalized.clone()
        } else {
            format!("{}.{}", scope.namespace, normalized)
        };
        let candidates =
            lookup_exact_type_candidates(&fqn, &mut visible_candidates, continue_lookup)?;
        if !candidates.is_empty() {
            return Some(found(candidates, false));
        }
        if scope.namespace.is_empty() && bare_name {
            if !continue_lookup() {
                return None;
            }
            if let Some(target) = global_alias_target(&normalized)? {
                let declarations = lookup_scoped_alias_target(
                    &target,
                    "",
                    &[],
                    &mut visible_candidates,
                    continue_lookup,
                )?;
                return Some(found(declarations, false));
            }
        }

        let mut visible = Vec::new();
        for import in &scope.using_namespaces {
            if !continue_lookup() {
                return None;
            }
            let Some(namespace) =
                resolve_scoped_namespace(import, namespace_exists, continue_lookup)?
            else {
                continue;
            };
            let candidates = lookup_exact_type_candidates(
                &format!("{namespace}.{normalized}"),
                &mut visible_candidates,
                continue_lookup,
            )?;
            visible.extend(
                candidates
                    .into_iter()
                    .filter(|candidate| candidate.package_name() == namespace),
            );
        }

        if scope.namespace.is_empty() && visible.is_empty() {
            // Global usings come from the whole workspace, not from the
            // reference's compilation, so they may not apply here. A
            // compilation-unit import that names the type therefore wins
            // rather than being made ambiguous by them (#2060).
            if !continue_lookup() {
                return None;
            }
            for namespace in global_using_namespaces()? {
                if !continue_lookup() {
                    return None;
                }
                let exists = namespace_exists(&namespace)?;
                if !exists {
                    continue;
                }
                let candidates = lookup_exact_type_candidates(
                    &format!("{namespace}.{normalized}"),
                    &mut visible_candidates,
                    continue_lookup,
                )?;
                visible.extend(
                    candidates
                        .into_iter()
                        .filter(|candidate| candidate.package_name() == namespace),
                );
            }
        }
        if !visible.is_empty() {
            return Some(found(visible, true));
        }
    }

    // `CSharpLookupContext::at` always appends a compilation-unit scope. Set
    // aside candidates are all that remains, and all are doubt.
    Some(found(Vec::new(), false))
}

fn lookup_alias_target(
    alias: &str,
    context: &CSharpLookupContext,
    global_alias_target: &mut impl FnMut(&str) -> Option<Option<String>>,
    continue_lookup: &mut impl FnMut() -> bool,
) -> Option<Option<CSharpScopedName>> {
    for scope in &context.scopes {
        if !continue_lookup() {
            return None;
        }
        if let Some((_, target)) = scope
            .using_aliases
            .iter()
            .find(|(candidate, _)| candidate == alias)
        {
            return Some(Some(target.clone()));
        }
    }
    if !continue_lookup() {
        return None;
    }
    global_alias_target(alias).map(|target| {
        target.map(|target| CSharpScopedName {
            target,
            declared_in: Vec::new(),
        })
    })
}

fn lookup_scoped_alias_target(
    target: &str,
    suffix: &str,
    declared_in: &[String],
    type_candidates_by_fqn: &mut impl FnMut(&str) -> Option<Vec<CodeUnit>>,
    continue_lookup: &mut impl FnMut() -> bool,
) -> Option<Vec<CodeUnit>> {
    let mut target = normalize_csharp_type_fragment(target);
    let explicitly_global = if let Some(absolute) = target.strip_prefix("global::") {
        target = absolute.to_string();
        true
    } else {
        false
    };
    let target = if suffix.is_empty() {
        target
    } else {
        format!("{target}.{suffix}")
    };
    let target = normalize_csharp_type_fragment(&target);

    if explicitly_global {
        return lookup_exact_type_candidates(&target, type_candidates_by_fqn, continue_lookup);
    }

    for prefix_len in (0..=declared_in.len()).rev() {
        if !continue_lookup() {
            return None;
        }
        let prefix = declared_in[..prefix_len].join(".");
        let candidate = if prefix.is_empty() {
            target.clone()
        } else {
            format!("{prefix}.{target}")
        };
        let candidates =
            lookup_exact_type_candidates(&candidate, type_candidates_by_fqn, continue_lookup)?;
        if !candidates.is_empty() {
            return Some(candidates);
        }
    }
    Some(Vec::new())
}

fn resolve_scoped_namespace(
    import: &CSharpScopedName,
    namespace_exists: &mut impl FnMut(&str) -> Option<bool>,
    continue_lookup: &mut impl FnMut() -> bool,
) -> Option<Option<String>> {
    let target = normalize_csharp_type_fragment(&import.target);
    if let Some(absolute) = target.strip_prefix("global::") {
        if !continue_lookup() {
            return None;
        }
        return namespace_exists(absolute).map(|exists| exists.then(|| absolute.to_string()));
    }
    for prefix_len in (0..=import.declared_in.len()).rev() {
        if !continue_lookup() {
            return None;
        }
        let prefix = import.declared_in[..prefix_len].join(".");
        let candidate = if prefix.is_empty() {
            target.clone()
        } else {
            format!("{prefix}.{target}")
        };
        let exists = namespace_exists(&candidate)?;
        if exists {
            return Some(Some(candidate));
        }
    }
    Some(None)
}

fn lookup_exact_type_candidates(
    fqn: &str,
    type_candidates_by_fqn: &mut impl FnMut(&str) -> Option<Vec<CodeUnit>>,
    continue_lookup: &mut impl FnMut() -> bool,
) -> Option<Vec<CodeUnit>> {
    if !continue_lookup() {
        return None;
    }
    type_candidates_by_fqn(fqn)
}

/// C#'s visible-type search, as a function of the lookups it needs. Each
/// `Option`-returning one answers `None` when its own bounded budget ran out,
/// which aborts the search rather than reporting a miss.
///
/// `namespace_exists` is the exception: it has no `None`, and a caller that
/// cannot determine an answer must say `true`. It only ever *skips* a probe, so
/// a wrong `false` would silently lose a candidate while a wrong `true` costs
/// nothing but the probe that would have run anyway.
#[allow(clippy::too_many_arguments)]
pub fn visible_type_candidates_with_lookups<
    Aliases,
    Namespace,
    FileUsings,
    GlobalUsings,
    NamespaceExists,
    Candidates,
>(
    name: &str,
    resolve_aliases: bool,
    using_aliases: &mut Aliases,
    namespace_of_file: &mut Namespace,
    file_using_namespaces: &mut FileUsings,
    global_using_namespaces: &mut GlobalUsings,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
) -> Vec<CodeUnit>
where
    Aliases: FnMut() -> Option<Arc<HashMap<String, String>>>,
    Namespace: FnMut() -> Option<String>,
    FileUsings: FnMut() -> Option<Vec<String>>,
    GlobalUsings: FnMut() -> Option<Vec<String>>,
    NamespaceExists: FnMut(&str) -> bool,
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
        } else if let Some(target) = using_aliases().and_then(|aliases| aliases.get(alias).cloned())
        {
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
            file_using_namespaces,
            global_using_namespaces,
            namespace_exists,
            type_candidates_by_fqn,
        );
    }

    // A `{qualifier}.{normalized}` probe only ever matches a class whose own
    // namespace is exactly `qualifier`, as long as `normalized` names a single
    // type: `csharp_normalize_full_name` turns the whole fq name into
    // `{namespace}.{type chain}`, so one trailing segment leaves the namespace
    // equal to the qualifier. A qualifier the workspace declares nothing in can
    // therefore be skipped rather than probed, which is what stops a file with
    // a deep namespace from paying a store query per candidate spelling per
    // ancestor namespace for a name that is plainly external (#1806).
    //
    // A `normalized` that carries its own separators is not gated: it can put
    // any number of segments between the qualifier and the type, so the
    // namespace that would hold the match is not the qualifier.
    let qualifier_decides_namespace = !normalized.contains(['.', '$', '+']);
    let Some(mut namespace) = namespace_of_file() else {
        return Vec::new();
    };
    if !namespace.is_empty() && (!qualifier_decides_namespace || namespace_exists(&namespace)) {
        let Some(candidates) = type_candidates_by_fqn(&format!("{namespace}.{normalized}")) else {
            return Vec::new();
        };
        if !candidates.is_empty() {
            return candidates;
        }
    }

    let Some(namespaces) = file_using_namespaces() else {
        return Vec::new();
    };
    let Some(visible) = visible_types_from_using_namespaces(
        namespaces,
        &normalized,
        namespace_exists,
        type_candidates_by_fqn,
    ) else {
        return Vec::new();
    };
    if !visible.is_empty() {
        return visible;
    }

    let Some(namespaces) = global_using_namespaces() else {
        return Vec::new();
    };
    let Some(visible) = visible_types_from_using_namespaces(
        namespaces,
        &normalized,
        namespace_exists,
        type_candidates_by_fqn,
    ) else {
        return Vec::new();
    };
    if !visible.is_empty() {
        return visible;
    }

    while let Some(separator) = namespace.rfind('.') {
        namespace.truncate(separator);
        if qualifier_decides_namespace && !namespace_exists(&namespace) {
            continue;
        }
        let Some(candidates) = type_candidates_by_fqn(&format!("{namespace}.{normalized}")) else {
            return Vec::new();
        };
        if !candidates.is_empty() {
            return candidates;
        }
    }

    type_candidates_by_fqn(&normalized).unwrap_or_default()
}

fn visible_types_from_using_namespaces<NamespaceExists, Candidates>(
    namespaces: Vec<String>,
    normalized: &str,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
) -> Option<Vec<CodeUnit>>
where
    NamespaceExists: FnMut(&str) -> bool,
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
{
    let mut visible = Vec::new();
    for using_namespace in namespaces {
        // This one is gated whatever `normalized` looks like: the filter below
        // already keeps only candidates whose namespace is the `using` itself.
        if !namespace_exists(&using_namespace) {
            continue;
        }
        let candidates = type_candidates_by_fqn(&format!("{using_namespace}.{normalized}"))?;
        visible.extend(
            candidates
                .into_iter()
                .filter(|candidate| candidate.package_name() == using_namespace),
        );
    }
    Some(visible)
}

pub fn resolve_visible_type(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    unique_logical_type(visible_type_candidates(source, token, file, name))
}

pub fn resolve_usage_visible_type(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    unique_logical_type(usage_visible_type_candidates(source, token, file, name))
}

/// The one declaration `candidates` names, or `None` when the spelling is
/// ambiguous. Partial declarations of the same type count once, so a type
/// split over several files still resolves.
pub fn unique_logical_type(mut candidates: Vec<CodeUnit>) -> Option<CodeUnit> {
    if logical_type_count(&candidates) != 1 {
        return None;
    }
    sort_type_candidates(&mut candidates);
    candidates.into_iter().next()
}

/// Resolve the unique logical bases of each partial type part, then sort and
/// deduplicate the resulting hierarchy edges. The callbacks retain each
/// caller's query and cancellation policy; returning `None` stops the walk.
pub fn logical_direct_ancestors(
    parts: Vec<CodeUnit>,
    mut raw_supertypes: impl FnMut(&CodeUnit) -> Option<Vec<String>>,
    mut resolve_candidates: impl FnMut(&CodeUnit, &str) -> Option<Vec<CodeUnit>>,
    mut accept_ancestor: impl FnMut(&CodeUnit) -> Option<()>,
) -> Option<Vec<CodeUnit>> {
    let mut ancestors = Vec::new();
    for part in parts {
        for raw in raw_supertypes(&part)? {
            let candidates = resolve_candidates(&part, &raw)?;
            let Some(ancestor) = unique_logical_type(candidates) else {
                continue;
            };
            accept_ancestor(&ancestor)?;
            ancestors.push(ancestor);
        }
    }
    sort_dedup_type_candidates(&mut ancestors);
    Some(ancestors)
}

// ---------------------------------------------------------------------------
// Enclosing-type scopes
// ---------------------------------------------------------------------------

/// The type scopes a spelling written inside `declaring_type_fqn` can name a
/// type through, innermost first: the declaring type itself and then each type
/// it is nested in. Namespace prefixes are deliberately excluded -- those are
/// what [`visible_type_candidates_with_lookups`] already searches -- so the
/// walk stops at the outermost nesting boundary.
///
/// C# writes a nesting boundary as `$` in a `CodeUnit` fq name and as `+` in
/// reflection-style spellings, so both cut the scope.
fn enclosing_type_scopes(declaring_type_fqn: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(
        (!declaring_type_fqn.is_empty()).then_some(declaring_type_fqn),
        |scope| scope.rfind(['$', '+']).map(|cut| &scope[..cut]),
    )
}

/// C#'s enclosing-type stage of type lookup, missing from
/// [`visible_type_candidates_with_lookups`] because that search is keyed on a
/// `ProjectFile` and so only ever offers alias, namespace and `using` scopes.
///
/// A spelling written inside a type declaration -- including its base-type
/// list -- first names a type nested in that type or in any type enclosing it,
/// and that scope wins over every namespace scope. Supertype resolution had no
/// such stage, so `class Derived : Base` where `Base` is a sibling nested type
/// resolved to nothing at all and the derived type reported no ancestors
/// (#1801).
///
/// `type_candidates_by_fqn` returns `None` when its own bounded budget ran out,
/// which aborts the search rather than reporting a miss, exactly as the
/// file-keyed search does. A `global::`- or alias-qualified spelling names an
/// absolute scope and never reaches this stage.
pub fn enclosing_type_candidates_with_lookups<Candidates>(
    declaring_type_fqn: &str,
    name: &str,
    type_candidates_by_fqn: &mut Candidates,
) -> Option<Vec<CodeUnit>>
where
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
{
    let normalized = normalize_csharp_type_fragment(name);
    if normalized.is_empty() || normalized.contains("::") {
        return Some(Vec::new());
    }
    for scope in enclosing_type_scopes(declaring_type_fqn) {
        let candidates = type_candidates_by_fqn(&format!("{scope}.{normalized}"))?;
        if !candidates.is_empty() {
            return Some(candidates);
        }
    }
    Some(Vec::new())
}

/// Every declaration a base-type spelling on `declaring_type_fqn` can name:
/// the enclosing type chain first, then whatever the file-keyed search offers.
///
/// The four C# supertype walks -- the analyzer's `direct_ancestors`, its
/// bounded session fork, and the two attribute-class evidence walks -- all
/// resolve a raw supertype spelling this way, so the two stages are composed
/// here once rather than at each of them.
pub fn supertype_candidates_with_lookups<Candidates, Visible>(
    declaring_type_fqn: &str,
    raw: &str,
    type_candidates_by_fqn: &mut Candidates,
    visible_type_candidates: &mut Visible,
) -> Vec<CodeUnit>
where
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Visible: FnMut(&str) -> Vec<CodeUnit>,
{
    let nested =
        enclosing_type_candidates_with_lookups(declaring_type_fqn, raw, type_candidates_by_fqn)
            .unwrap_or_default();
    if !nested.is_empty() {
        return nested;
    }
    visible_type_candidates(raw)
}

/// [`supertype_candidates_with_lookups`] over an unbounded [`CSharpSource`].
pub fn supertype_candidates(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    part: &CodeUnit,
    raw: &str,
    usage: bool,
) -> Vec<CodeUnit> {
    supertype_candidates_with_lookups(
        &part.fq_name(),
        raw,
        &mut |fqn| Some(type_candidates_by_fqn(source, token, fqn, usage)),
        &mut |name| {
            if usage {
                usage_visible_type_candidates(source, token, part.source(), name)
            } else {
                visible_type_candidates(source, token, part.source(), name)
            }
        },
    )
}

// ---------------------------------------------------------------------------
// Partial types
// ---------------------------------------------------------------------------

pub fn partial_type_parts(source: &dyn CSharpSource, owner: &CodeUnit) -> Vec<CodeUnit> {
    if !owner.is_class() {
        return Vec::new();
    }
    partial_type_parts_for_owner(owner, source.get_definitions(&owner.fq_name()))
}

pub fn partial_type_parts_limited(
    source: &dyn CSharpSource,
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
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
) -> Vec<CodeUnit> {
    if !owner.is_class() {
        return Vec::new();
    }
    partial_type_parts_for_owner(
        owner,
        usage_definition_candidates_by_fqn(source, token, &owner.fq_name()),
    )
}

fn partial_type_parts_for_owner(
    owner: &CodeUnit,
    candidates: impl IntoIterator<Item = CodeUnit>,
) -> Vec<CodeUnit> {
    let mut candidates = candidates.into_iter().collect::<Vec<_>>();
    let owner_key = type_declaration_key(owner);
    candidates.retain(|unit| unit.is_class() && type_declaration_key(unit) == owner_key);
    sort_type_candidates(&mut candidates);
    candidates.dedup();
    candidates
}

// ---------------------------------------------------------------------------
// Candidate ordering. A "logical type" is one partial declaration group, so
// these are pure functions of the fq names involved.
// ---------------------------------------------------------------------------

pub fn sort_dedup_type_candidates(candidates: &mut Vec<CodeUnit>) {
    sort_type_candidates(candidates);
    candidates.dedup_by(|left, right| type_declaration_key(left) == type_declaration_key(right));
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
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
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
                        visible_type_candidates(source, token, candidate, &identifier)
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

#[cfg(test)]
mod lookup_context_tests {
    use super::{
        CSharpCompilationVisibility, CSharpLookupContext, visible_type_candidates_at_with_lookups,
        visible_type_declarations_at_with_lookups,
    };
    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
    use brokk_bifrost_core::hash::HashMap;
    use tree_sitter::{Parser, Tree};

    /// Every candidate shares the reference's compilation.
    fn single_compilation_visibility(_: &CodeUnit) -> Option<CSharpCompilationVisibility> {
        Some(CSharpCompilationVisibility::Visible)
    }

    fn parsed_tree(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar loads");
        parser.parse(source, None).expect("C# source parses")
    }

    fn context_at(source: &str, marker: &str, occurrence: usize) -> CSharpLookupContext {
        let tree = parsed_tree(source);
        let start = source
            .match_indices(marker)
            .nth(occurrence)
            .map(|(start, _)| start)
            .expect("source marker exists");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + marker.len())
            .expect("marker has a syntax node");
        CSharpLookupContext::at(source, node, || true).expect("lookup context completes")
    }

    fn unit(path: &str, namespace: &str, name: &str) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(
                std::env::temp_dir().join("csharp-lookup-context-test"),
                path,
            ),
            CodeUnitType::Class,
            namespace,
            name,
        )
    }

    fn lookup(
        context: &CSharpLookupContext,
        name: &str,
        by_fqn: &HashMap<String, Vec<CodeUnit>>,
        namespaces: &[&str],
    ) -> Option<Vec<CodeUnit>> {
        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || Some(Vec::new());
        let mut namespace_exists = |namespace: &str| Some(namespaces.contains(&namespace));
        let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
        let mut continue_lookup = || true;
        visible_type_candidates_at_with_lookups(
            name,
            context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
    }

    fn lookup_declarations(
        context: &CSharpLookupContext,
        name: &str,
        by_fqn: &HashMap<String, Vec<CodeUnit>>,
        namespaces: &[&str],
    ) -> Option<Vec<CodeUnit>> {
        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || Some(Vec::new());
        let mut namespace_exists = |namespace: &str| Some(namespaces.contains(&namespace));
        let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
        let mut continue_lookup = || true;
        visible_type_declarations_at_with_lookups(
            name,
            context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
    }

    #[test]
    fn namespace_grammar_boundaries_preserve_relative_and_global_imports() {
        // The reference node is the class itself: a file namespace can end
        // exactly at its start, and a compilation using can end at the
        // namespace's start. Whitespace has no semantic significance.
        let inventory = "namespace Lib { class T {} } namespace App.Lib { class T {} } namespace App { class T {} }";
        let file = ProjectFile::new(std::env::temp_dir(), "Types.cs");
        let tree = parsed_tree(inventory);
        let declarations = crate::declarations::parse_csharp_file(&file, inventory, &tree);
        let mut by_fqn: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for declaration in declarations.declarations() {
            by_fqn
                .entry(declaration.fq_name())
                .or_default()
                .push(declaration.clone());
        }
        let namespaces = ["Lib", "App.Lib", "App"];
        for (source, spelling, expected) in [
            ("namespace App;class C{T field;}", "T", "App.T"),
            ("using Lib;namespace Other;class C{T field;}", "T", "Lib.T"),
            (
                "namespace App{using Lib;class C{T field;}}",
                "T",
                "App.Lib.T",
            ),
            (
                "namespace App{using A=Lib.T;class C{A field;}}",
                "A",
                "App.Lib.T",
            ),
            (
                "namespace App{using A=global::Lib.T;class C{A field;}}",
                "A",
                "Lib.T",
            ),
        ] {
            for separator in ["", "\n "] {
                let source = source.replace(';', &format!(";{separator}"));
                let tree = parsed_tree(&source);
                assert!(!tree.root_node().has_error(), "{source}");
                let mut pending = vec![tree.root_node()];
                let class = loop {
                    let node = pending.pop().expect("class declaration exists");
                    if node.kind() == "class_declaration" {
                        break node;
                    }
                    pending.extend(node.named_children(&mut node.walk()));
                };
                let context =
                    CSharpLookupContext::at(&source, class, || true).expect("context completes");
                let mut candidates = by_fqn.clone();
                if expected != "App.T" {
                    candidates.remove("App.T");
                }
                let actual =
                    lookup(&context, spelling, &candidates, &namespaces).expect("lookup completes");
                assert_eq!(
                    actual.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                    vec![expected],
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn context_keeps_nested_and_sibling_using_scopes_separate() {
        let source = r#"
namespace Outer {
    using OuterScope;
    namespace Inner {
        using InnerScope;
        using InnerOther;
        using Svc = global::Targets.Service;
        class Current { InnerOnly inner; OuterOnly outer; Svc alias; }
    }
}
namespace InnerScope { class InnerOnly {} }
namespace InnerOther { class InnerOnly {} }
namespace OuterScope { class OuterOnly {} }
namespace Targets { class Service {} }
namespace Sibling { class Current { InnerOnly missing; Svc missingAlias; } }
"#;
        let inner_context = context_at(source, "InnerOnly", 0);
        assert!(
            inner_context
                .scopes
                .iter()
                .any(|scope| scope.namespace == "Outer.Inner")
        );
        assert!(
            inner_context
                .scopes
                .iter()
                .any(|scope| scope.namespace == "Outer")
        );

        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "InnerScope.InnerOnly".to_string(),
            vec![unit("one.cs", "InnerScope", "InnerOnly")],
        );
        by_fqn.insert(
            "InnerOther.InnerOnly".to_string(),
            vec![unit("two.cs", "InnerOther", "InnerOnly")],
        );
        by_fqn.insert(
            "OuterScope.OuterOnly".to_string(),
            vec![unit("outer.cs", "OuterScope", "OuterOnly")],
        );
        by_fqn.insert(
            "Targets.Service".to_string(),
            vec![unit("service.cs", "Targets", "Service")],
        );
        let namespaces = ["InnerScope", "InnerOther", "OuterScope", "Targets"];
        let inner =
            lookup(&inner_context, "InnerOnly", &by_fqn, &namespaces).expect("lookup completes");
        assert_eq!(inner.len(), 2, "ambiguous candidate sets stay intact");

        let outer_context = context_at(source, "OuterOnly", 0);
        let outer =
            lookup(&outer_context, "OuterOnly", &by_fqn, &namespaces).expect("lookup completes");
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].package_name(), "OuterScope");

        let alias_context = context_at(source, "Svc", 1);
        let alias = lookup(&alias_context, "Svc", &by_fqn, &namespaces).expect("lookup completes");
        assert_eq!(alias.len(), 1);
        assert_eq!(alias[0].package_name(), "Targets");

        let sibling_context = context_at(source, "Svc", 2);
        assert!(
            lookup(&sibling_context, "Svc", &by_fqn, &namespaces)
                .expect("sibling miss completes")
                .is_empty()
        );
        assert!(
            lookup(&sibling_context, "InnerOnly", &by_fqn, &namespaces)
                .expect("sibling miss completes")
                .is_empty()
        );
    }

    #[test]
    fn file_scoped_namespace_separates_compilation_and_namespace_imports() {
        let source = r#"
using Before;
namespace Scoped.Path;
using After;
using Alias = global::Targets.Service;
class Current { BeforeType before; AfterType after; Alias service; }
namespace Nested {
    using NestedAfter;
    class NestedCurrent { NestedType nested; }
}
"#;
        let before_context = context_at(source, "BeforeType", 0);
        let after_context = context_at(source, "AfterType", 0);
        let nested_context = context_at(source, "NestedType", 0);
        assert!(
            after_context
                .scopes
                .iter()
                .any(|scope| scope.namespace == "Scoped.Path")
        );
        assert!(
            nested_context
                .scopes
                .iter()
                .any(|scope| scope.namespace == "Scoped.Path.Nested")
        );

        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "Before.BeforeType".to_string(),
            vec![unit("before.cs", "Before", "BeforeType")],
        );
        by_fqn.insert(
            "After.AfterType".to_string(),
            vec![unit("after.cs", "After", "AfterType")],
        );
        by_fqn.insert(
            "Targets.Service".to_string(),
            vec![unit("service.cs", "Targets", "Service")],
        );
        by_fqn.insert(
            "NestedAfter.NestedType".to_string(),
            vec![unit("nested.cs", "NestedAfter", "NestedType")],
        );
        let namespaces = ["Before", "After", "NestedAfter", "Targets"];
        assert_eq!(
            lookup(&before_context, "BeforeType", &by_fqn, &namespaces).expect("lookup completes")
                [0]
            .package_name(),
            "Before"
        );
        assert_eq!(
            lookup(&after_context, "AfterType", &by_fqn, &namespaces).expect("lookup completes")[0]
                .package_name(),
            "After"
        );
        assert_eq!(
            lookup(&nested_context, "NestedType", &by_fqn, &namespaces).expect("lookup completes")
                [0]
            .package_name(),
            "NestedAfter"
        );
        let alias_context = context_at(source, "Alias", 1);
        assert_eq!(
            lookup(&alias_context, "Alias", &by_fqn, &namespaces).expect("lookup completes")[0]
                .package_name(),
            "Targets"
        );
    }

    #[test]
    fn compilation_imports_precede_global_usings_after_global_namespace_types() {
        let source = r#"
using FileImport;
namespace Outer { class Current { Service field; } }
namespace FileImport { class Service {} }
namespace GlobalImport { class Service {} }
"#;
        let context = context_at(source, "Service", 0);
        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "FileImport.Service".to_string(),
            vec![unit("file-import.cs", "FileImport", "Service")],
        );
        by_fqn.insert(
            "GlobalImport.Service".to_string(),
            vec![unit("global-import.cs", "GlobalImport", "Service")],
        );

        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || Some(vec!["GlobalImport".to_string()]);
        let mut namespace_exists =
            |namespace: &str| Some(matches!(namespace, "FileImport" | "GlobalImport"));
        let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
        let mut continue_lookup = || true;
        let imported = visible_type_candidates_at_with_lookups(
            "Service",
            &context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
        .expect("lookup completes");
        assert_eq!(
            imported
                .iter()
                .map(CodeUnit::package_name)
                .collect::<Vec<_>>(),
            ["FileImport"],
            "a compilation-unit using precedes a workspace global using (#2060)"
        );

        by_fqn.insert(
            "Service".to_string(),
            vec![unit("global.cs", "", "Service")],
        );
        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || Some(vec!["GlobalImport".to_string()]);
        let mut namespace_exists =
            |namespace: &str| Some(matches!(namespace, "FileImport" | "GlobalImport"));
        let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
        let mut continue_lookup = || true;
        let global_type = visible_type_candidates_at_with_lookups(
            "Service",
            &context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
        .expect("lookup completes");
        assert_eq!(global_type.len(), 1);
        assert_eq!(global_type[0].package_name(), "");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6296: a global-namespace List<T> in another compilation stole imported receiver and constructor uses"
    )]
    fn global_namespace_precedence_follows_compilation_visibility() {
        let source = r#"
using Tools;
class Consumer { Service field; Gadget other; }
"#;
        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "Tools.Service".to_string(),
            vec![unit("App/Tools.cs", "Tools", "Service")],
        );
        // `Service` is declared in the global namespace by another file of the
        // reference's compilation, by a file of an unrelated compilation, and
        // by a file whose membership is unknown. Only the unknown file
        // declares `Gadget`.
        by_fqn.insert(
            "Service".to_string(),
            vec![
                unit("App/Shadow.cs", "", "Service"),
                unit("Tests/Service.cs", "", "Service"),
                unit("Loose/Service.cs", "", "Service"),
            ],
        );
        by_fqn.insert(
            "Gadget".to_string(),
            vec![unit("Loose/Gadget.cs", "", "Gadget")],
        );
        let paths = |units: &[CodeUnit]| {
            let mut paths = units
                .iter()
                .map(|unit| brokk_bifrost_core::path_utils::rel_path_string(unit.source()))
                .collect::<Vec<_>>();
            paths.sort();
            paths
        };
        // (candidate view, its unproven part, physical view's unproven part)
        let lookup = |name: &str, visibility: &dyn Fn(&str) -> CSharpCompilationVisibility| {
            let context = context_at(source, name, 0);
            let mut global_alias = |_: &str| Some(None::<String>);
            let mut global_namespaces = || Some(Vec::new());
            let mut namespace_exists = |namespace: &str| Some(namespace == "Tools");
            let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
            let mut compilation_visibility = |candidate: &CodeUnit| {
                Some(visibility(
                    &brokk_bifrost_core::path_utils::rel_path_string(candidate.source()),
                ))
            };
            let mut continue_lookup = || true;
            let types = visible_type_candidates_at_with_lookups(
                name,
                &context,
                &mut global_alias,
                &mut global_namespaces,
                &mut namespace_exists,
                &mut candidates,
                &mut compilation_visibility,
                &mut continue_lookup,
            )
            .expect("lookup completes");
            let physical = visible_type_declarations_at_with_lookups(
                name,
                &context,
                &mut global_alias,
                &mut global_namespaces,
                &mut namespace_exists,
                &mut candidates,
                &mut compilation_visibility,
                &mut continue_lookup,
            )
            .expect("lookup completes");
            (
                paths(&types.declarations),
                paths(&types.unproven),
                paths(&physical.unproven),
            )
        };
        let by_path = |visible: &'static [&'static str], unresolved: &'static [&'static str]| {
            move |path: &str| {
                if visible.contains(&path) {
                    CSharpCompilationVisibility::Visible
                } else if unresolved.contains(&path) {
                    CSharpCompilationVisibility::Unresolved
                } else {
                    CSharpCompilationVisibility::NotVisible
                }
            }
        };
        let none = Vec::<String>::new();

        assert_eq!(
            lookup("Service", &by_path(&["App/Shadow.cs", "App/Tools.cs"], &[])),
            (vec!["App/Shadow.cs".to_owned()], none.clone(), none.clone()),
            "a global type in another file of the same compilation precedes the import"
        );
        assert_eq!(
            lookup("Service", &by_path(&["App/Tools.cs"], &[])),
            (vec!["App/Tools.cs".to_owned()], none.clone(), none.clone()),
            "a global type the compilation cannot see does not shadow the import"
        );
        assert_eq!(
            lookup(
                "Service",
                &by_path(&["App/Tools.cs"], &["Loose/Service.cs"])
            ),
            (
                vec!["App/Tools.cs".to_owned(), "Loose/Service.cs".to_owned()],
                vec!["Loose/Service.cs".to_owned()],
                vec!["Loose/Service.cs".to_owned()],
            ),
            "an unproven global type and the import form one unproven ambiguity"
        );
        assert_eq!(
            lookup(
                "Service",
                &by_path(&["App/Shadow.cs", "App/Tools.cs"], &["Loose/Service.cs"])
            ),
            (
                vec!["App/Shadow.cs".to_owned()],
                none.clone(),
                vec!["Loose/Service.cs".to_owned()],
            ),
            "a proven global type names the type alone; its unproven physical twin stays doubt"
        );
        assert_eq!(
            lookup("Gadget", &by_path(&["App/Tools.cs"], &["Loose/Gadget.cs"])),
            (
                vec!["Loose/Gadget.cs".to_owned()],
                vec!["Loose/Gadget.cs".to_owned()],
                vec!["Loose/Gadget.cs".to_owned()],
            ),
            "a lone unproven global type is reported, not resolved"
        );
    }

    #[test]
    fn inner_namespace_type_precedes_global_using_alias() {
        let source = r#"
global using Svc = GlobalTypes.Service;
namespace Outer { class Svc {} class Current { Svc value; } }
namespace GlobalTypes { class Service {} }
"#;
        let context = context_at(source, "Svc", 1);
        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "Outer.Svc".to_string(),
            vec![unit("local.cs", "Outer", "Svc")],
        );
        by_fqn.insert(
            "GlobalTypes.Service".to_string(),
            vec![unit("global.cs", "GlobalTypes", "Service")],
        );
        let mut global_alias =
            |alias: &str| Some((alias == "Svc").then(|| "GlobalTypes.Service".to_string()));
        let mut global_namespaces = || Some(Vec::new());
        let mut namespace_exists = |_: &str| Some(false);
        let mut candidates = |fqn: &str| Some(by_fqn.get(fqn).cloned().unwrap_or_default());
        let mut continue_lookup = || true;
        let selected = visible_type_candidates_at_with_lookups(
            "Svc",
            &context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
        .expect("lookup completes");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].package_name(), "Outer");
    }

    #[test]
    fn imported_declaration_lookup_preserves_physical_sites_and_exact_dedups() {
        let source = r#"
using Imported;
class Current { Marker field; }
namespace Imported { class Marker {} }
"#;
        let context = context_at(source, "Marker", 0);
        let first = unit("a/Marker.cs", "Imported", "Marker");
        let second = unit("b/Marker.cs", "Imported", "Marker");
        let mut by_fqn = HashMap::default();
        by_fqn.insert(
            "Imported.Marker".to_string(),
            vec![first.clone(), second.clone(), first.clone()],
        );
        let namespaces = ["Imported"];

        let ordinary = lookup(&context, "Marker", &by_fqn, &namespaces)
            .expect("ordinary imported lookup completes");
        assert_eq!(
            ordinary,
            vec![first.clone()],
            "ordinary lookup preserves its existing one-logical-type import policy"
        );

        let declarations = lookup_declarations(&context, "Marker", &by_fqn, &namespaces)
            .expect("declaration lookup completes");
        assert_eq!(
            declarations,
            vec![first.clone(), second.clone()],
            "declaration lookup keeps distinct source paths and drops only identical rows"
        );

        let direct_source = "namespace N { class Current { Marker field; } }";
        let direct_context = context_at(direct_source, "Marker", 0);
        let direct_first = unit("a/Marker.cs", "N", "Marker");
        let direct_second = unit("b/Marker.cs", "N", "Marker");
        let mut direct_by_fqn = HashMap::default();
        direct_by_fqn.insert(
            "N.Marker".to_string(),
            vec![direct_first.clone(), direct_second.clone()],
        );
        let direct_ordinary = lookup(&direct_context, "Marker", &direct_by_fqn, &[])
            .expect("direct lookup completes");
        assert_eq!(
            direct_ordinary,
            vec![direct_first.clone(), direct_second.clone()],
            "ordinary exact namespace lookup remains declaration-preserving"
        );
        let direct_declarations =
            lookup_declarations(&direct_context, "Marker", &direct_by_fqn, &[])
                .expect("direct declaration lookup completes");
        assert_eq!(direct_declarations, vec![direct_first, direct_second]);
    }

    #[test]
    fn repeated_import_rows_collapse_only_identical_declarations() {
        let source = r#"
using Imported;
using Imported;
class Current { Marker field; }
namespace Imported { class Marker {} }
"#;
        let context = context_at(source, "Marker", 0);
        assert_eq!(
            context.scopes[0]
                .using_namespaces
                .iter()
                .filter(|import| import.target == "Imported")
                .count(),
            2,
            "fixture contains two independently traversed import directives"
        );
        let marker = unit("Imported/Marker.cs", "Imported", "Marker");
        let mut candidate_calls = 0;
        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || Some(Vec::new());
        let mut namespace_exists = |namespace: &str| Some(namespace == "Imported");
        let mut candidates = |fqn: &str| {
            if fqn == "Imported.Marker" {
                candidate_calls += 1;
                Some(vec![marker.clone()])
            } else {
                Some(Vec::new())
            }
        };
        let mut continue_lookup = || true;

        let declarations = visible_type_declarations_at_with_lookups(
            "Marker",
            &context,
            &mut global_alias,
            &mut global_namespaces,
            &mut namespace_exists,
            &mut candidates,
            &mut single_compilation_visibility,
            &mut continue_lookup,
        )
        .map(|types| types.declarations)
        .expect("repeated-import lookup completes");
        assert_eq!(candidate_calls, 2, "both real import rows were visited");
        assert_eq!(declarations, vec![marker]);
    }

    #[test]
    fn context_and_lookup_preserve_callback_abort() {
        let source = "namespace N { class C { Missing field; } }";
        let tree = parsed_tree(source);
        let start = source.find("Missing").expect("marker exists");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + "Missing".len())
            .expect("marker has a syntax node");
        assert!(CSharpLookupContext::at(source, node, || false).is_none());

        let context = CSharpLookupContext::at(source, node, || true).unwrap();
        let mut global_alias = |_: &str| Some(None::<String>);
        let mut global_namespaces = || None;
        let mut namespace_exists = |_: &str| Some(false);
        let mut candidates = |_: &str| Some(Vec::new());
        let mut continue_lookup = || true;
        assert!(
            visible_type_candidates_at_with_lookups(
                "Missing",
                &context,
                &mut global_alias,
                &mut global_namespaces,
                &mut namespace_exists,
                &mut candidates,
                &mut single_compilation_visibility,
                &mut continue_lookup,
            )
            .is_none()
        );
    }
}
