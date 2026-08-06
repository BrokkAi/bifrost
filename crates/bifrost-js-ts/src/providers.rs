//! The source trait both dialects' language logic resolves through, and the
//! uncached half of the shared `ImportAnalysisProvider` policy.
//!
//! `JavascriptAnalyzer` and `TypescriptAnalyzer` wrap the same
//! `TreeSitterAnalyzer`, the same `JsTsMemoCaches` bucket and the same
//! [`AliasResolver`], and differ only in their `Language` tag. Every function
//! here is parameterized over a [`JsTsSource`], so the two analysis-side
//! `impl` blocks reduce to one-line delegations and the resolution policy lives
//! in exactly one place.
//!
//! # Where the caching went
//!
//! The memo bucket is five moka `Cache`s, and moka is deliberately not a
//! dependency of this crate (the Go, Java and C# precedents: `analyzer/go/
//! imports.rs`, `analyzer/java/imports.rs`, `analyzer/csharp/imports.rs` all
//! keep the cache lookup on the analysis side and call the crate for the
//! uncached work). So the trait below exposes *products* rather than the
//! bucket: `usage_index` is the analyzer-cached resolution index, and the
//! get-then-insert wrappers for imported code units, referencing files,
//! relevant imports, import target files and direct ancestors stay in
//! `analyzer/js_ts/providers.rs`, calling the uncached functions here.

use crate::hierarchy::resolve_direct_ancestors;
use crate::imports::{import_info_tokens, resolve_js_ts_import_paths};
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, Language, ProjectFile,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;

use crate::graph::resolver::JsTsUsageIndex;

/// The shared surface the JS/TS language logic needs from a concrete analyzer,
/// on top of the three core capability traits it reads declarations, imports and
/// supertypes with: its alias resolver, its language tag, the analyzer-cached
/// usage index, the workspace definition index, and the five
/// `TreeSitterAnalyzer` queries that have no core spelling.
///
/// Implemented once per adapter in `brokk-bifrost-analysis` as trivial field
/// accessors and one-line delegations into the wrapped analyzer, so no free
/// function below can reach past this surface. This crate never names
/// `JavascriptAnalyzer` or `TypescriptAnalyzer`.
///
/// Three of the analyzer queries the providers make are already core:
/// `import_info_of` on [`ImportAnalysisProvider`], `top_level_declarations` and
/// `get_source` on [`CodeUnitIndex`] -- both analyzers' impls of all three are
/// the same one-line delegation the free functions used directly before. The
/// ones named below are not: `all_files` is the analyzed *live* file set
/// (`CodeUnitIndex::analyzed_files` is a different query),
/// `bulk_import_infos` has no core counterpart,
/// `raw_supertypes_of` returns the unresolved supertype spellings that
/// [`TypeHierarchyProvider`] never exposes, and `import_statements` reads
/// the raw import statement text the module skeleton renders.
pub trait JsTsSource: CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider {
    /// The analyzer's shared alias resolver. Returned by handle so a caller
    /// that must own one (the receiver-fact provider) shares this instance's
    /// config memo instead of constructing a resolver whose memo starts cold.
    fn alias_resolver(&self) -> &Arc<AliasResolver>;
    fn language(&self) -> Language;

    /// The analyzed live file set (`TreeSitterAnalyzer::all_files`).
    fn all_files(&self) -> Vec<ProjectFile>;

    /// Import facts for a group of files in one read.
    fn bulk_import_infos(&self, files: &[ProjectFile]) -> HashMap<ProjectFile, Vec<ImportInfo>>;

    /// The supertype names written on `code_unit`, unresolved.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// The file's import statements as written, used to render a module skeleton.
    fn import_statements(&self, file: &ProjectFile) -> Vec<String>;

    /// Whether the indexed declaration is a type alias. Distinct from
    /// `TypeAliasProvider::is_type_alias`, which only TypeScript answers: this
    /// reads the analyzer's own index, so both dialects can answer it and only
    /// TypeScript's skeleton path asks.
    ///
    /// The two share a name without ambiguity because `TypeAliasProvider` is
    /// deliberately not a supertrait of this trait, and every caller reaches
    /// this one through `&dyn JsTsSource`.
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool;

    /// The indexed signatures for `code_unit` exactly as stored. TypeScript's
    /// `CodeUnitIndex::signatures` appends a `;` to alias signatures for
    /// rendering, which the alias skeleton must not double up on.
    fn raw_signatures(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// The workspace's usage-definition index, as the bounded lookup contract.
    ///
    /// The `JavaSource::usage_definitions` spelling. Before the extraction the
    /// scan called `IAnalyzer::global_usage_definition_index`, which has no
    /// core spelling because it hands back an analysis-side handle; the bounded
    /// lookup is the part of it this crate actually reads.
    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup;

    /// The analyzer-cached JS/TS resolution index for this source's own language,
    /// built on first use. `None` only when `cancellation` fires mid-build.
    ///
    /// The memo cell behind it is a `PoolSafeMemo` on the analysis-side cache
    /// bucket; this is the product, not the cell.
    fn usage_index(&self, cancellation: Option<&CancellationToken>) -> Option<Arc<JsTsUsageIndex>>;
}

// --- ImportAnalysisProvider ------------------------------------------------

/// Resolve every import in `imports` to the declarations it binds.
///
/// The uncached body behind `ImportAnalysisProvider::imported_code_units_of`,
/// whose per-file memo lives on the analysis-side cache bucket.
pub fn resolve_imported_code_units(
    host: &dyn JsTsSource,
    file: &ProjectFile,
    imports: impl IntoIterator<Item = ImportInfo>,
) -> HashSet<CodeUnit> {
    let language = host.language();
    let alias_resolver = host.alias_resolver();
    let mut resolved = HashSet::default();
    for import in imports {
        for target in
            resolve_js_ts_import_paths(file, &import.raw_snippet, language, Some(alias_resolver))
        {
            let top_level = host.top_level_declarations(&target);
            if import.is_wildcard {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            } else if let Some(identifier) = import.identifier.as_ref().or(import.alias.as_ref()) {
                let mut matched = false;
                for code_unit in top_level
                    .iter()
                    .filter(|code_unit| code_unit.identifier() == identifier)
                {
                    matched = true;
                    resolved.insert(code_unit.clone());
                }
                if !matched {
                    let module_units = top_level
                        .iter()
                        .filter(|code_unit| code_unit.is_module())
                        .cloned()
                        .collect::<Vec<_>>();
                    if !module_units.is_empty() {
                        resolved.extend(module_units);
                    } else if top_level.len() == 1 && !top_level[0].is_module() {
                        resolved.insert(top_level[0].clone());
                    }
                }
            } else {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            }
        }
    }
    resolved
}

pub fn import_infos_for_files(
    host: &dyn JsTsSource,
    files: &[ProjectFile],
) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
    Some(host.bulk_import_infos(files))
}

pub fn imported_files_from_infos(
    host: &dyn JsTsSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Option<HashSet<ProjectFile>> {
    let language = host.language();
    let alias_resolver = host.alias_resolver();
    Some(
        imports
            .iter()
            .flat_map(|import| {
                resolve_js_ts_import_paths(
                    file,
                    &import.raw_snippet,
                    language,
                    Some(alias_resolver),
                )
            })
            .collect(),
    )
}

/// The import snippets of `code_unit`'s file whose bound tokens the unit's own
/// source actually spells, plus every import that binds no token at all.
///
/// The uncached body behind `ImportAnalysisProvider::relevant_imports_for`.
pub fn compute_relevant_imports(host: &dyn JsTsSource, code_unit: &CodeUnit) -> HashSet<String> {
    let source = host.get_source(code_unit, false).unwrap_or_default();
    let mut relevant = HashSet::default();
    for import in host.import_info_of(code_unit.source()) {
        let tokens = import_info_tokens(&import);
        if tokens.is_empty() || tokens.iter().any(|token| source.contains(token)) {
            relevant.insert(import.raw_snippet.clone());
        }
    }
    relevant
}

/// The file-path resolution targets of `file`'s own imports (module specifier ->
/// file).
///
/// The uncached body behind `could_import_file`. Without the memo the analysis
/// side wraps this in, it re-ran for every (candidate, target) pair the shared
/// usages candidate walker checks -- unbounded per-call cost on a large
/// workspace.
pub fn resolve_import_target_files(
    host: &dyn JsTsSource,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    let language = host.language();
    let alias_resolver = host.alias_resolver();
    host.import_info_of(file)
        .iter()
        .flat_map(|import| {
            resolve_js_ts_import_paths(file, &import.raw_snippet, language, Some(alias_resolver))
        })
        .collect()
}

// --- Skeletons -------------------------------------------------------------

/// A module unit's skeleton is its own import block: both dialects render the
/// same thing, so this is one function rather than a method on each analyzer.
pub fn module_import_skeleton(host: &dyn JsTsSource, code_unit: &CodeUnit) -> Option<String> {
    if !code_unit.is_module() {
        return None;
    }

    let imports = host.import_statements(code_unit.source());
    (!imports.is_empty()).then(|| imports.join("\n"))
}

// --- TypeHierarchyProvider -------------------------------------------------

/// Resolve `code_unit`'s unresolved supertype spellings to declarations.
///
/// The uncached body behind `TypeHierarchyProvider::get_direct_ancestors`.
pub fn compute_direct_ancestors(host: &dyn JsTsSource, code_unit: &CodeUnit) -> Vec<CodeUnit> {
    let Some(index) = host.usage_index(None) else {
        return Vec::new();
    };
    resolve_direct_ancestors(
        host,
        index.as_ref(),
        host.language(),
        host.alias_resolver(),
        code_unit,
        &host.raw_supertypes_of(code_unit),
    )
}
