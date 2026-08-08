//! The language half of C#'s type-resolution logic: namespace and `using`
//! resolution, visible-type lookup, partial-type grouping and the bounded
//! declaration queries built on top of them, written as free functions over a
//! source trait instead of as methods on [`CSharpAnalyzer`].
//!
//! [`CSharpAnalyzer`] owns the lazy cells (six moka caches, six `OnceLock`s and
//! two `PoolSafeMemo`s) and implements [`CSharpSource`] out of its own
//! accessors, so the functions below reach back for the memoized products they
//! need without naming the analyzer type.
//!
//! One tier is enough here, unlike Rust's `RustSource`/`RustUsageSource`
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
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::imports::{
    csharp_static_using_from_import, csharp_using_alias_from_import, csharp_using_namespace,
};
use crate::syntax::{
    csharp_arity_preserving_full_name, csharp_normalize_full_name, normalize_csharp_type_fragment,
    strip_csharp_generic_arity,
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
pub trait CSharpSource: CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider {
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
    fn global_static_using_type_names(&self) -> &[String];

    /// [`Self::global_static_using_type_names`] under a budget. It fills the
    /// same memo cell when the batch completes.
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
    source: &dyn CSharpSource,
    identifier: &str,
) -> Vec<CodeUnit> {
    source.usage_definitions().identifier(identifier)
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
        .filter(|candidate| csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key)
        .collect()
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
        batch.rows.retain(|candidate| {
            csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key
        });
    }
    batch
}

pub fn usage_member_candidates_for_owner(
    source: &dyn CSharpSource,
    owner_fqn: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let normalized = csharp_normalize_full_name(owner_fqn);
    source
        .usage_definitions()
        .members_for_owner_name(owner_fqn, &normalized, name)
}

pub fn usage_workspace_namespace_exists(source: &dyn CSharpSource, namespace: &str) -> bool {
    source.usage_definitions().package_exists(namespace)
}

pub fn usage_type_candidates_by_fqn(source: &dyn CSharpSource, fqn: &str) -> Vec<CodeUnit> {
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

pub fn usage_definition_candidates_by_fqn(source: &dyn CSharpSource, fqn: &str) -> Vec<CodeUnit> {
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

pub fn type_candidates_by_fqn(source: &dyn CSharpSource, fqn: &str, usage: bool) -> Vec<CodeUnit> {
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

pub fn import_statements_limited(
    source: &dyn CSharpSource,
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
pub fn compute_using_namespaces_of(source: &dyn CSharpSource, file: &ProjectFile) -> Vec<String> {
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
    source: &dyn CSharpSource,
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

// ---------------------------------------------------------------------------
// Import reachability
// ---------------------------------------------------------------------------

/// Whether `source_file` can reference a declaration of `target`.
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
/// from the proof in [`csharp_cannot_reach_target`]. Everything else stays
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
pub fn csharp_import_reachability(
    source: &dyn CSharpSource,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
    target: &ProjectFile,
) -> ImportReachability {
    let target_classes: Vec<CodeUnit> = source
        .declarations(target)
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class)
        .collect();
    if csharp_reaches_target(source, source_file, imports, target, &target_classes) {
        return ImportReachability::Reaches;
    }
    if csharp_cannot_reach_target(source, source_file, imports, &target_classes) {
        return ImportReachability::DoesNotReach;
    }
    ImportReachability::Unknown
}

/// The cheap positive answer: the historical `could_import_file` body, which
/// reports a possible reference and never a proven absence.
fn csharp_reaches_target(
    source: &dyn CSharpSource,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
    target: &ProjectFile,
    target_classes: &[CodeUnit],
) -> bool {
    let arity_sensitive = target_classes
        .iter()
        .any(|unit| unit.identifier().contains('`'));
    if source.namespace_of_file(source_file) == source.namespace_of_file(target) && !arity_sensitive
    {
        return true;
    }
    let target_namespaces: HashSet<String> = target_classes
        .iter()
        .map(|unit| unit.package_name().to_string())
        .collect();
    let target_names: HashSet<String> = target_classes
        .iter()
        .flat_map(|unit| {
            let fq_name = unit.fq_name();
            [
                unit.identifier().to_string(),
                fq_name.clone(),
                fq_name.replace('$', "."),
            ]
        })
        .collect();
    let source_aliases = source.using_aliases_of(source_file);
    if let Some(identifiers) = source.type_identifiers_of(source_file) {
        for identifier in identifiers {
            if target_names.contains(&identifier) {
                return true;
            }
            if identifier
                .strip_prefix("global::")
                .is_some_and(|global_name| target_names.contains(global_name))
            {
                return true;
            }
            let uses_namespace_alias = source_aliases.keys().any(|alias| {
                identifier
                    .strip_prefix(alias)
                    .is_some_and(|suffix| suffix.starts_with("::"))
            });
            if uses_namespace_alias {
                let candidates = visible_type_candidates(source, source_file, &identifier);
                if target_classes
                    .iter()
                    .any(|target| candidates.contains(target))
                {
                    return true;
                }
            }
        }
    }
    let source_imports = source.using_namespaces_of(source_file);
    imports
        .iter()
        .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
        .chain(source_imports)
        .any(|namespace| target_namespaces.contains(&namespace))
        || source_aliases.values().any(|alias_target| {
            let candidates = visible_type_candidates(source, source_file, alias_target);
            target_classes.iter().any(|unit| candidates.contains(unit))
        })
}

/// The proof behind a `DoesNotReach`.
///
/// A reference from `source_file` into one of `target_classes` must do one of
/// two things, and the two checks below close both:
///
/// 1. spell one of the target's type names somewhere in the file -- qualified,
///    `global::`-qualified, alias-qualified or bare. Every such spelling is a
///    type-position or member-access node, which is what the extractor records
///    in the file's type-identifier set.
/// 2. bind a name without spelling the type -- an unqualified type name, an
///    extension-method call, a `using static` member. Every one of those needs
///    the declaring namespace in scope, so none survives an empty intersection
///    between the target's namespaces and the file's visible ones.
///
/// Both checks over-approximate on purpose: any doubt admits a match and the
/// verdict falls back to `Unknown`.
fn csharp_cannot_reach_target(
    source: &dyn CSharpSource,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
    target_classes: &[CodeUnit],
) -> bool {
    if target_classes.is_empty() {
        return false;
    }
    // `None` means the extractor recorded no identifier set for this file,
    // which is not the same as a file that names nothing.
    let Some(identifiers) = source.type_identifiers_of(source_file) else {
        return false;
    };

    let target_names: HashSet<&str> = target_classes
        .iter()
        .flat_map(csharp_target_name_segments)
        .collect();
    for identifier in &identifiers {
        if csharp_reference_name_segments(identifier).any(|segment| target_names.contains(segment))
        {
            return false;
        }
    }

    let visible = csharp_visible_namespaces(source, source_file, imports);
    !target_classes
        .iter()
        .any(|unit| visible.contains(unit.package_name()))
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

/// Every namespace `source_file` can name a type in without qualifying it.
///
/// Over-approximating this set only costs an `Unknown`, so each `using` path
/// contributes every dotted prefix of what it names rather than a decision
/// about which of its segments are namespaces and which are types.
fn csharp_visible_namespaces(
    source: &dyn CSharpSource,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<String> {
    let mut visible: HashSet<String> = HashSet::default();
    // The global namespace is in scope everywhere.
    visible.insert(String::new());
    // Every namespace the file declares into, and every enclosing one:
    // `namespace A.B` sees `A.*` unqualified. Read from the declarations
    // rather than from `namespace_of_file`, which names only the first
    // namespace of a file that opens several (#1726).
    for unit in source.declarations(source_file) {
        insert_namespace_prefixes(unit.package_name(), &mut visible);
    }
    // File-local and global `using` namespaces, and alias targets, both of
    // which already merge the workspace-level `global using` cells.
    for namespace in source.using_namespaces_of(source_file) {
        insert_namespace_prefixes(&namespace, &mut visible);
    }
    for alias_target in source.using_aliases_of(source_file).values() {
        insert_namespace_prefixes(alias_target, &mut visible);
    }
    // `using static N.C;` puts `C`'s members in scope, so `N` is live. The
    // file's own directives arrive twice -- once from the caller's batch, once
    // from the store -- because the caller's batch is the authority for a file
    // whose imports it already loaded.
    for import in imports
        .iter()
        .chain(source.import_info_of(source_file).iter())
    {
        if let Some(namespace) = csharp_using_namespace(&import.raw_snippet) {
            insert_namespace_prefixes(&namespace, &mut visible);
        }
        if let Some(static_target) = csharp_static_using_from_import(import) {
            insert_namespace_prefixes(static_target, &mut visible);
        }
    }
    // `global using static` lives in other files of the compilation, so it
    // comes from the workspace-level cell rather than from per-file facts.
    for static_target in source.global_static_using_type_names() {
        insert_namespace_prefixes(static_target, &mut visible);
    }
    visible
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
    source: &dyn CSharpSource,
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
pub fn compute_global_using_namespaces(source: &dyn CSharpSource) -> HashSet<String> {
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
    source: &dyn CSharpSource,
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
pub fn compute_global_using_aliases(source: &dyn CSharpSource) -> HashMap<String, String> {
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
    source: &dyn CSharpSource,
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
/// The uncached half of the analyzer's `global_static_using_type_names`.
pub fn compute_global_static_using_type_names(source: &dyn CSharpSource) -> Vec<String> {
    let mut names: Vec<_> = source
        .all_files()
        .into_iter()
        .flat_map(|file| source.import_info_of(&file).into_iter())
        .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
        .filter_map(|import| {
            let target = csharp_static_using_from_import(&import)?;
            let target =
                normalize_csharp_type_fragment(target.strip_prefix("global::").unwrap_or(target));
            (!target.is_empty()).then_some(target)
        })
        .collect();
    names.sort();
    names.dedup();
    names
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
pub fn compute_global_static_using_types(source: &dyn CSharpSource) -> Vec<CodeUnit> {
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
pub fn compute_usage_global_static_using_types(source: &dyn CSharpSource) -> Vec<CodeUnit> {
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
    source: &dyn CSharpSource,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    visible_type_candidates_inner(source, file, name, true, false)
}

pub fn usage_visible_type_candidates(
    source: &dyn CSharpSource,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    visible_type_candidates_inner(source, file, name, true, true)
}

fn visible_type_candidates_inner(
    source: &dyn CSharpSource,
    file: &ProjectFile,
    name: &str,
    resolve_aliases: bool,
    usage: bool,
) -> Vec<CodeUnit> {
    let mut using_aliases = || Some(source.using_aliases_of(file));
    let mut namespace_of_file = || Some(source.namespace_of_file(file));
    let mut using_namespaces = || Some(source.using_namespaces_of(file));
    let mut namespace_exists = |namespace: &str| source.workspace_namespace_exists(namespace);
    let mut type_candidates = |fqn: &str| Some(type_candidates_by_fqn(source, fqn, usage));
    visible_type_candidates_with_lookups(
        name,
        resolve_aliases,
        &mut using_aliases,
        &mut namespace_of_file,
        &mut using_namespaces,
        &mut namespace_exists,
        &mut type_candidates,
    )
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
    Usings,
    NamespaceExists,
    Candidates,
>(
    name: &str,
    resolve_aliases: bool,
    using_aliases: &mut Aliases,
    namespace_of_file: &mut Namespace,
    using_namespaces: &mut Usings,
    namespace_exists: &mut NamespaceExists,
    type_candidates_by_fqn: &mut Candidates,
) -> Vec<CodeUnit>
where
    Aliases: FnMut() -> Option<Arc<HashMap<String, String>>>,
    Namespace: FnMut() -> Option<String>,
    Usings: FnMut() -> Option<Vec<String>>,
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
            using_namespaces,
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

    let mut visible = Vec::new();
    let Some(namespaces) = using_namespaces() else {
        return Vec::new();
    };
    for using_namespace in namespaces {
        // This one is gated whatever `normalized` looks like: the filter below
        // already keeps only candidates whose namespace is the `using` itself.
        if !namespace_exists(&using_namespace) {
            continue;
        }
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

pub fn resolve_visible_type(
    source: &dyn CSharpSource,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    unique_logical_type(visible_type_candidates(source, file, name))
}

pub fn resolve_usage_visible_type(
    source: &dyn CSharpSource,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    unique_logical_type(usage_visible_type_candidates(source, file, name))
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
    part: &CodeUnit,
    raw: &str,
    usage: bool,
) -> Vec<CodeUnit> {
    supertype_candidates_with_lookups(
        &part.fq_name(),
        raw,
        &mut |fqn| Some(type_candidates_by_fqn(source, fqn, usage)),
        &mut |name| {
            if usage {
                usage_visible_type_candidates(source, part.source(), name)
            } else {
                visible_type_candidates(source, part.source(), name)
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

pub fn usage_partial_type_parts(source: &dyn CSharpSource, owner: &CodeUnit) -> Vec<CodeUnit> {
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
    source: &dyn CSharpSource,
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
