//! The language half of Java's name resolution: package and import tiers,
//! visible-type lookup, the import-resolution map and the same-package
//! reference index, written as free functions over a source trait instead of as
//! methods on `JavaAnalyzer`.
//!
//! `JavaAnalyzer` owns the lazy cells (five moka caches, one `OnceLock` and two
//! `PoolSafeMemo`s) and implements [`JavaSource`] out of its own accessors, so
//! the functions below reach back for the memoized products they need without
//! naming the analyzer type.
//!
//! One tier is enough here, unlike Rust's `RustSource`/`RustUsageSource`
//! split: no cell in the Java memo web re-enters the cell it is filling.
//! `resolved_imports` is the deepest, and its builder resolves through the
//! workspace definition index rather than through another cell.
//!
//! Three members carry more than their signature:
//!
//! * [`JavaSource::external_boundary_evidence`] reads `JvmExternalDeclarationIndex`,
//!   which imports `semantic_model` and therefore stays in
//!   `brokk-bifrost-analysis`. The evidence it returns is core-typed, so the
//!   answer crosses even though the index cannot.
//! * [`JavaSource::trace_type_name_tier`] and
//!   [`JavaSource::trace_explicit_import_win`] hand a resolution decision to the
//!   definition route's trace recorder, whose candidate vocabulary is
//!   analysis-owned. Which tier decided is language knowledge and stays here;
//!   how a decision is recorded does not.
//! * [`JavaSource::all_files`] is `TreeSitterAnalyzer::all_files`, the
//!   analyzed *live* file set. `CodeUnitIndex::analyzed_files` is a different
//!   query, so this is spelled out rather than inferred from the supertrait.
//!
//! `JavaAnalyzer` lives in `brokk-bifrost-analysis`; this crate never names it.

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeHierarchyProvider, build_reverse_file_index,
};
use brokk_bifrost_core::analyzer::model::{CallableArity, ImportInfo};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::resolution::{BoundaryStatus, PrecedenceTier};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::java::declarations::{collect_type_identifiers, parse_tree};
use crate::java::imports::{import_package, non_static_import_path, static_import_path};
use crate::proof::JvmRetainedExternalIndex;

/// The package whose types every Java file sees without importing them.
const JAVA_IMPLICIT_IMPORT_PACKAGE: &str = "java.lang";

/// The analyzer-resident products Java's language logic resolves through, on
/// top of the three core capability traits it reads declarations, imports and
/// supertypes with. The analyzer is the only implementor and every method
/// forwards to one of its own accessors or memo cells, so the cells stay where
/// they are and no free function below can reach past this surface.
///
/// `TypeHierarchyProvider` is a supertrait because the analyzer answers
/// `Some(self)` to `IAnalyzer::type_hierarchy_provider`, and the target-spec
/// and receiver-compatibility paths that hold only the concrete Java analyzer
/// used it in both roles.
pub trait JavaSource: CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider {
    /// The analyzed live file set (`TreeSitterAnalyzer::all_files`).
    fn all_files(&self) -> Vec<ProjectFile>;

    /// The file's `package` declaration, memoized by the analyzer.
    fn cached_package_name(&self, file: &ProjectFile) -> Option<Arc<str>>;

    /// The file's single-type and on-demand imports resolved to declarations,
    /// keyed by the simple name each binds. Memoized by the analyzer; the
    /// uncached build is [`resolve_java_import_infos`].
    fn resolved_imports(&self, file: &ProjectFile) -> Arc<HashMap<String, CodeUnit>>;

    /// Declarations this analyzer indexes under the fully qualified name `fqn`,
    /// answered forward without building the workspace usage index.
    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// The workspace's usage-definition index, as the bounded lookup contract.
    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup;

    /// Every type the usage-definition index holds in `package_name`, sorted and
    /// deduplicated. The index's package projection has no bounded spelling, so
    /// this is the one lookup below that names its own accessor.
    fn source_types_in_package(&self, package_name: &str) -> Vec<CodeUnit>;

    /// The type identifiers a file spells, from the analyzer's persisted parse.
    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>>;

    /// The supertype names written on `code_unit`, unresolved.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// The request-scoped prepared syntax tree for `file`, when one is available.
    fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>>;

    /// How far a lookup for `name` from `file` could see past the workspace, and
    /// the external type it landed on when it landed on one. See this module's
    /// note: the index behind it stays in `brokk-bifrost-analysis`.
    ///
    /// This is the *resolver's* question, and it builds the external index on
    /// demand to answer it. Diagnostics must not: see the two `retained_`
    /// members below.
    fn external_boundary_evidence(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>);

    /// What the analyzer has retained of the JVM dependency surface, read
    /// without building it. See [`crate::proof`] on why a diagnostic peeks.
    fn retained_external_index(&self) -> JvmRetainedExternalIndex;

    /// Whether the retained external index holds `fqn` visibly from
    /// `access_package`. Reads; never builds. Answers `false` for an unbuilt
    /// index, which [`Self::retained_external_index`] reports separately so the
    /// caller can tell "not there" from "nothing to look in".
    fn retained_external_holds_qualified_name(&self, fqn: &str, access_package: &str) -> bool;

    /// Stage `tier` as the tier a type-name lookup for `normalized` resolved at.
    fn trace_type_name_tier(&self, normalized: &str, units: &[CodeUnit], tier: PrecedenceTier);

    /// Record Java's strongest import tier winning for `normalized`, together
    /// with the on-demand import routes that were therefore never consulted.
    fn trace_explicit_import_win(
        &self,
        file: &ProjectFile,
        normalized: &str,
        unit: Option<&CodeUnit>,
        imports: &[ImportInfo],
    );
}

// ---------------------------------------------------------------------------
// Package and file facts
// ---------------------------------------------------------------------------

pub fn java_package_name_of(source: &dyn JavaSource, file: &ProjectFile) -> Option<String> {
    source
        .cached_package_name(file)
        .map(|package| package.to_string())
}

pub fn java_same_package_fqn(source: &dyn JavaSource, file: &ProjectFile, name: &str) -> String {
    let package_name = source
        .cached_package_name(file)
        .unwrap_or_else(|| Arc::from(""));
    if package_name.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", package_name, name)
    }
}

pub fn java_file_is_in_default_package(source: &dyn JavaSource, file: &ProjectFile) -> bool {
    source
        .cached_package_name(file)
        .is_none_or(|package| package.is_empty())
}

/// The type identifiers spelled in a Java source snippet.
pub fn java_extract_type_identifiers(source: &str) -> BTreeSet<String> {
    let Some(tree) = parse_tree(source) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    collect_type_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Type-name resolution
// ---------------------------------------------------------------------------

/// Resolve a source type for a forward definition/type request without
/// constructing the workspace-wide usage index.
pub fn resolve_java_forward_type_name(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<CodeUnit> {
    unique_candidate(resolve_java_forward_type_name_candidates(
        source, file, raw_name,
    ))
}

/// The full candidate set a forward type-name lookup produces. More than
/// one entry means colliding on-demand imports: each candidate is a peer
/// no wildcard tier can prove unique, and the ambiguity stays explicit as
/// multiple rows (issue #1602) rather than as a silent first-route win.
pub fn resolve_java_forward_type_name_candidates(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Vec<CodeUnit> {
    resolve_java_type_name_with(source, file, raw_name, |fqn| {
        forward_source_type_by_fqn(source, fqn)
    })
}

/// Resolve a source type while a usage query already owns the complete
/// workspace declaration index, against this analyzer's own index.
pub fn resolve_java_usage_type_name(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<CodeUnit> {
    resolve_java_usage_type_name_in(source, source.usage_definitions(), file, raw_name)
}

/// Resolve a source type against a *supplied* declaration index, applying
/// Java's own import and package tiers.
///
/// The index is a parameter because Java, Scala, and Kotlin share one JVM
/// candidate space (issue #1237): a Java file can name a Kotlin class
/// declared next door with no ceremony beyond an ordinary import, and the
/// Java-only index cannot see it. Callers holding the realm-aware
/// `MultiAnalyzer` index pass that one, which is what makes the realm
/// symmetric — Kotlin source could already resolve onto Java declarations,
/// and this is the return direction (issue #1239, milestone 4). What does
/// *not* widen is Java's visibility model: the same import, wildcard, and
/// same-package tiers decide, so a Kotlin class in another package still
/// needs an import.
pub fn resolve_java_usage_type_name_in(
    source: &dyn JavaSource,
    index: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<CodeUnit> {
    unique_candidate(resolve_java_type_name_with(source, file, raw_name, |fqn| {
        index
            .fqn(fqn)
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == fqn)
            .cloned()
    }))
}

/// Every candidate the deciding type-name tier produced for `raw_name`,
/// resolved against a realm-wide declaration index.
///
/// More than one entry means colliding on-demand imports supplied the same
/// simple name, so no candidate is provably unique (issue #1602).
pub fn resolve_java_type_name_candidates_in_realm(
    source: &dyn JavaSource,
    index: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    raw_name: &str,
) -> Vec<CodeUnit> {
    resolve_java_type_name_with(source, file, raw_name, |fqn| {
        index
            .fqn(fqn)
            .iter()
            .find(|unit| unit.is_class() && unit.fq_name() == fqn && !unit.is_synthetic())
            .cloned()
    })
}

/// Walk Java's type-name tiers and return every candidate the deciding
/// tier produced.
///
/// Every tier but one is unique by construction, so the result is almost
/// always zero or one unit. The exception is the on-demand tier: two
/// wildcard imports can both supply the simple name, and a selection
/// through that tier is then not provably unique. All peers are returned
/// so the caller can report the ambiguity, mirroring what
/// `resolve_external_imports` already expresses for external targets by
/// refusing to pick one (issue #1602).
pub fn resolve_java_type_name_with(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
    mut source_type_by_fqn: impl FnMut(&str) -> Option<CodeUnit>,
) -> Vec<CodeUnit> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return Vec::new();
    }

    if normalized.contains('.')
        && let Some(unit) = source_type_by_fqn(normalized)
    {
        return vec![unit];
    }

    let imports = source.import_info_of(file);
    for import in &imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            continue;
        }
        let Some(imported_name) = import.identifier.as_deref() else {
            continue;
        };
        // A matching single-type import constrains this name even when its
        // declaration is outside the indexed workspace.
        if normalized == imported_name {
            let unit = source_type_by_fqn(&import_path.render_segments("."));
            source.trace_explicit_import_win(file, normalized, unit.as_ref(), &imports);
            return unit.into_iter().collect();
        }
        if let Some(rest) = normalized
            .strip_prefix(imported_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            let nested_fqn = format!("{}.{rest}", import_path.render_segments("."));
            let unit = source_type_by_fqn(&nested_fqn);
            source.trace_explicit_import_win(file, normalized, unit.as_ref(), &imports);
            return unit.into_iter().collect();
        }
    }

    let mut wildcard_candidates: Vec<CodeUnit> = Vec::new();
    for import in &imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if !import.is_wildcard {
            continue;
        }
        let fqn = format!("{}.{normalized}", import_path.render_segments("."));
        if let Some(unit) = source_type_by_fqn(&fqn)
            && !wildcard_candidates.contains(&unit)
        {
            wildcard_candidates.push(unit);
        }
    }
    if !wildcard_candidates.is_empty() {
        source.trace_type_name_tier(
            normalized,
            &wildcard_candidates,
            PrecedenceTier::WildcardImport,
        );
        return wildcard_candidates;
    }

    let same_package_fqn = java_same_package_fqn(source, file, normalized);
    let unit = source_type_by_fqn(&same_package_fqn).or_else(|| {
        java_file_is_in_default_package(source, file)
            .then(|| source_type_by_fqn(normalized))
            .flatten()
    });
    if let Some(unit) = unit.as_ref() {
        source.trace_type_name_tier(
            normalized,
            std::slice::from_ref(unit),
            PrecedenceTier::PackageOrModule,
        );
    }
    unit.into_iter().collect()
}

/// Every fully-qualified name Java's type-name tiers could give `raw_name` at
/// `file`, strongest tier first.
///
/// [`resolve_java_type_name_with`] answers with workspace [`CodeUnit`]s. An
/// external surface has no `CodeUnit` and must never be handed a fabricated one
/// (#1619), so this walks the same tiers and yields the spellings themselves,
/// leaving the caller to ask whichever index it holds. The single-type import
/// tier is terminal here exactly as it is there: an explicit import claims the
/// spelling whether or not its target is indexed, so the tiers below it are
/// never reachable for that name.
///
/// The last entry is the `java.lang` type of the same name. The `CodeUnit`
/// walker has no such tier because a workspace does not declare `java.lang`;
/// an external surface is precisely where those types live.
pub fn java_type_name_candidate_fqns(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Vec<String> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    if normalized.contains('.') {
        candidates.push(normalized.to_string());
    }

    let imports = source.import_info_of(file);
    for import in &imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            continue;
        }
        let Some(imported_name) = import.identifier.as_deref() else {
            continue;
        };
        if normalized == imported_name {
            candidates.push(import_path.render_segments("."));
            return candidates;
        }
        if let Some(rest) = normalized
            .strip_prefix(imported_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            candidates.push(format!("{}.{rest}", import_path.render_segments(".")));
            return candidates;
        }
    }

    for import in &imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if !import.is_wildcard {
            continue;
        }
        candidates.push(format!("{}.{normalized}", import_path.render_segments(".")));
    }

    candidates.push(java_same_package_fqn(source, file, normalized));
    if java_file_is_in_default_package(source, file) {
        candidates.push(normalized.to_string());
    }
    candidates.push(format!("{JAVA_IMPLICIT_IMPORT_PACKAGE}.{normalized}"));
    candidates.dedup();
    candidates
}

fn forward_source_type_by_fqn(source: &dyn JavaSource, fqn: &str) -> Option<CodeUnit> {
    source
        .forward_definition_fqn(fqn)
        .into_iter()
        .find(|unit| unit.is_class() && unit.fq_name() == fqn)
}

/// The single answer of a candidate set, or `None` when the set is empty or
/// holds ambiguous peers no tier could prove unique.
fn unique_candidate(mut candidates: Vec<CodeUnit>) -> Option<CodeUnit> {
    (candidates.len() == 1).then(|| candidates.remove(0))
}

/// Resolve a spelled type name through the analyzer's own memoized import map,
/// the same-package tier and the default package.
///
/// The [`resolve_java_type_name_with`] family walks the raw import list per
/// call; this one answers from the resolved-import cache and is what the
/// external-aware route above it consults first.
pub fn resolve_java_type_name(
    source: &dyn JavaSource,
    file: &ProjectFile,
    raw_name: &str,
) -> Option<CodeUnit> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return None;
    }

    if normalized.contains('.') {
        if let Some(code_unit) = usage_source_type_by_fqn(source, normalized) {
            return Some(code_unit);
        }
        if let Some(code_unit) = resolve_java_nested_type_name(source, file, normalized) {
            return Some(code_unit);
        }
    }

    let imports = source.resolved_imports(file);
    if let Some(code_unit) = imports.get(normalized) {
        return Some(code_unit.clone());
    }

    let same_package_fqn = java_same_package_fqn(source, file, normalized);
    if let Some(code_unit) = usage_source_type_by_fqn(source, &same_package_fqn) {
        return Some(code_unit);
    }

    java_file_is_in_default_package(source, file)
        .then(|| usage_source_type_by_fqn(source, normalized))
        .flatten()
}

fn resolve_java_nested_type_name(
    source: &dyn JavaSource,
    file: &ProjectFile,
    normalized: &str,
) -> Option<CodeUnit> {
    let (first, rest) = normalized.split_once('.')?;
    let owner = resolve_java_visible_simple_type(source, file, first)?;
    let nested_fqn = format!("{}.{}", owner.fq_name(), rest);
    usage_source_type_by_fqn(source, &nested_fqn)
}

pub fn resolve_java_visible_simple_type(
    source: &dyn JavaSource,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    if let Some(code_unit) = source.resolved_imports(file).get(name) {
        return Some(code_unit.clone());
    }
    let same_package_fqn = java_same_package_fqn(source, file, name);
    usage_source_type_by_fqn(source, &same_package_fqn).or_else(|| {
        java_file_is_in_default_package(source, file)
            .then(|| usage_source_type_by_fqn(source, name))
            .flatten()
    })
}

fn usage_source_type_by_fqn(source: &dyn JavaSource, fqn: &str) -> Option<CodeUnit> {
    source
        .usage_definitions()
        .fqn(fqn)
        .iter()
        .find(|code_unit| code_unit.is_class())
        .cloned()
}

// ---------------------------------------------------------------------------
// Import resolution
// ---------------------------------------------------------------------------

/// The uncached half of the analyzer's `resolve_imports`: the simple names a
/// file's imports bind, resolved to workspace declarations.
pub fn resolve_java_import_infos(
    source: &dyn JavaSource,
    imports: &[ImportInfo],
) -> HashMap<String, CodeUnit> {
    let mut resolved = HashMap::default();
    let mut wildcard_resolved = HashMap::<String, CodeUnit>::default();

    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };

        if !import.is_wildcard {
            if let Some(code_unit) =
                usage_source_type_by_fqn(source, &import_path.render_segments("."))
            {
                resolved.insert(code_unit.identifier().to_string(), code_unit);
            }
            continue;
        }

        let package_name = import_path.render_segments(".");
        for code_unit in source.source_types_in_package(&package_name) {
            let identifier = code_unit.identifier().to_string();
            if resolved.contains_key(&identifier) && !wildcard_resolved.contains_key(&identifier) {
                continue;
            }
            if wildcard_resolved.contains_key(&identifier) {
                continue;
            }
            wildcard_resolved.insert(identifier.clone(), code_unit.clone());
            resolved.insert(identifier, code_unit.clone());
        }
    }

    resolved
}

/// The uncached half of the analyzer's `relevant_imports_for`: which of a
/// declaration's file-level imports its own source actually needs.
pub fn compute_java_relevant_imports(
    source: &dyn JavaSource,
    code_unit: &CodeUnit,
) -> HashSet<String> {
    let Some(unit_source) = source.get_source(code_unit, false) else {
        return HashSet::default();
    };

    let all_imports = source.import_info_of(code_unit.source());
    if all_imports.is_empty() {
        return HashSet::default();
    }

    let type_identifiers = java_extract_type_identifiers(&unit_source);
    if type_identifiers.is_empty() {
        return HashSet::default();
    }

    let explicit_imports: Vec<_> = all_imports
        .iter()
        .filter(|import| !import.is_wildcard && import.identifier.is_some())
        .collect();
    let wildcard_imports: Vec<_> = all_imports
        .iter()
        .filter(|import| import.is_wildcard)
        .collect();

    let mut matched_imports = HashSet::default();
    let mut resolved_identifiers = HashSet::default();

    for import in explicit_imports {
        let Some(identifier) = import.identifier.as_deref() else {
            continue;
        };

        if type_identifiers.contains(identifier) {
            matched_imports.insert(import.raw_snippet.clone());
            resolved_identifiers.insert(identifier.to_string());
        }
    }

    let mut unresolved_identifiers: HashSet<String> = type_identifiers
        .into_iter()
        .filter(|identifier| !resolved_identifiers.contains(identifier))
        .collect();
    if unresolved_identifiers.is_empty() {
        return matched_imports;
    }

    let import_packages: HashSet<String> = all_imports.iter().filter_map(import_package).collect();

    unresolved_identifiers.retain(|identifier| {
        if !identifier.contains('.') {
            return true;
        }

        import_packages
            .iter()
            .any(|package| identifier.starts_with(&format!("{package}.")))
    });
    if unresolved_identifiers.is_empty() {
        return matched_imports;
    }

    let mut resolved_via_wildcard = HashSet::default();
    for identifier in &unresolved_identifiers {
        for import in &wildcard_imports {
            let Some(package) = import_package(import) else {
                continue;
            };

            let lookup_name = format!("{package}.{identifier}");
            if source
                .definitions(&lookup_name)
                .any(|code_unit| code_unit.is_class())
            {
                matched_imports.insert(import.raw_snippet.clone());
                resolved_via_wildcard.insert(identifier.clone());
            }
        }
    }

    let still_unresolved_simple = unresolved_identifiers
        .iter()
        .any(|identifier| !resolved_via_wildcard.contains(identifier) && !identifier.contains('.'));
    if still_unresolved_simple {
        for import in wildcard_imports {
            matched_imports.insert(import.raw_snippet.clone());
        }
    }

    matched_imports
}

pub fn java_could_import_file(
    source: &dyn JavaSource,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    if source_file == target {
        return false;
    }

    let source_package = java_package_name_of(source, source_file).unwrap_or_default();
    let target_package = java_package_name_of(source, target).unwrap_or_default();
    if source_package == target_package {
        return true;
    }

    java_could_import_file_without_source(source, imports, target)
}

pub fn java_could_import_file_without_source(
    source: &dyn JavaSource,
    imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    let target_package = java_package_name_of(source, target).unwrap_or_default();
    let mut target_name = target
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    if let Some(stripped) = target_name.strip_suffix(".java") {
        target_name = stripped.to_string();
    }

    let target_type_fqn = if target_package.is_empty() {
        target_name.clone()
    } else {
        format!("{target_package}.{target_name}")
    };

    for import in imports {
        if let Some(path) = static_import_path(import) {
            // A static import names a member (or `*`) past the type, so
            // the target type's FQN must be a strict dotted prefix.
            if path
                .render_segments(".")
                .strip_prefix(&target_type_fqn)
                .is_some_and(|suffix| suffix.starts_with('.'))
            {
                return true;
            }
            continue;
        }
        let Some(path) = non_static_import_path(import) else {
            continue;
        };

        if !import.is_wildcard {
            if import.identifier.as_deref() == Some(target_name.as_str()) {
                return true;
            }
            // An interior segment (neither the leading package root nor
            // the imported terminal) naming the target type marks a
            // nested-type import through it.
            let segments = &path.segments;
            if segments.len() > 2 && segments[1..segments.len() - 1].contains(&target_name) {
                return true;
            }
            continue;
        }

        let import_package = path.render_segments(".");
        if import_package == target_package
            || import_package == format!("{}.{}", target_package, target_name)
        {
            return true;
        }
    }

    false
}

/// The uncached half of the analyzer's `same_package_reference_index`: which
/// files name a type declared in another file of the same package, which Java
/// makes visible without an import.
pub fn compute_java_same_package_reference_index(
    source: &dyn JavaSource,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
    let mut targets_by_package_and_name: HashMap<(String, String), Vec<ProjectFile>> =
        HashMap::default();
    for file in source.all_files() {
        let package = java_package_name_of(source, &file).unwrap_or_default();
        for declaration in source.top_level_declarations(&file) {
            if declaration.is_class() || declaration.is_module() {
                targets_by_package_and_name
                    .entry((package.clone(), declaration.identifier().to_string()))
                    .or_default()
                    .push(file.clone());
            }
        }
    }

    let files: Vec<_> = source.all_files();
    build_reverse_file_index(
        &files,
        |candidate| {
            let package = java_package_name_of(source, candidate).unwrap_or_default();
            let Some(identifiers) = source.type_identifiers_of(candidate) else {
                return Vec::new();
            };
            let mut targets = Vec::new();
            for identifier in identifiers {
                if let Some(matching_targets) =
                    targets_by_package_and_name.get(&(package.clone(), identifier.clone()))
                {
                    targets.extend(matching_targets.iter().cloned());
                }
            }
            targets
        },
        parallel,
    )
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/// Classify exact-FQN callable candidates and the source-level constructor
/// shape from one coherent parser snapshot.
///
/// Java permits an ordinary method to have the same simple name as its
/// enclosing class, so FQN and arity alone cannot distinguish the two.
pub fn java_constructor_context(
    source: &dyn JavaSource,
    owner: &CodeUnit,
    candidates: Vec<CodeUnit>,
    call_arity: usize,
) -> (Vec<CodeUnit>, bool) {
    let Some(prepared) = source.prepared_syntax(owner.source()) else {
        return (Vec::new(), false);
    };
    let owner_children = prepared.direct_children(owner);
    let has_explicit_constructor = owner_children.iter().any(|child| {
        prepared.declaration_node(child).is_some_and(|node| {
            matches!(
                node.kind(),
                "constructor_declaration" | "compact_constructor_declaration"
            )
        })
    });
    let direct_children = owner_children.iter().collect::<HashSet<_>>();
    let constructors = candidates
        .into_iter()
        .filter(|candidate| direct_children.contains(candidate))
        .filter(|candidate| {
            prepared.declaration_node(candidate).is_some_and(|node| {
                matches!(
                    node.kind(),
                    "constructor_declaration" | "compact_constructor_declaration"
                )
            })
        })
        .collect::<Vec<_>>();
    let owner_shape_accepts = match prepared.declaration_node(owner) {
        Some(node) if node.kind() == "class_declaration" => {
            !has_explicit_constructor && call_arity == 0
        }
        Some(node) if node.kind() == "record_declaration" => {
            let Some(parameters) = node.child_by_field_name("parameters") else {
                return (constructors, false);
            };
            let mut cursor = parameters.walk();
            let mut required = 0;
            let mut repeated = false;
            for parameter in parameters.named_children(&mut cursor) {
                match parameter.kind() {
                    "formal_parameter" => required += 1,
                    "spread_parameter" => repeated = true,
                    _ => {}
                }
            }
            CallableArity::new(required, required + usize::from(repeated), repeated)
                .accepts(call_arity)
        }
        _ => false,
    };
    (constructors, owner_shape_accepts)
}
