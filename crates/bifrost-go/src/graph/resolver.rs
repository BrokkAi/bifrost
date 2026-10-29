//! Legacy Go alias and hierarchy inputs, with diagnostics import support.
//!
//! Inputs come from [`GoGraphSource`]'s core capability traits and workspace
//! path index. Native Go usage queries do not build a legacy project graph.

use crate::imports::{default_go_import_local_name, go_import_path};
use crate::packages::{GoWorkspacePathIndex, source_inventory_role};
use crate::source_facts::{GoFileSourceFacts, GoSourceFactProvider};
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeAliasProvider};
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::go_facts::{
    GoSourceTypeId, GoSourceTypeShape, GoTypeCompoundKind,
};
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
pub use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;

/// Everything Go graph resolution needs from the analyzer, as the core
/// capability traits that answer it plus this crate's workspace path index.
///
/// Grouped because the same graph references thread through every index build;
/// each field is a reference the caller already holds.
#[derive(Clone, Copy)]
pub struct GoGraphSource<'a> {
    /// Proof that a request scope is open: the import accessors below cross
    /// the import tier's storage (issue #2423).
    pub token: QueryToken<'a>,
    pub index: &'a dyn CodeUnitIndex,
    pub imports: &'a dyn ImportAnalysisProvider,
    pub type_aliases: &'a dyn TypeAliasProvider,
    pub workspace_paths: &'a GoWorkspacePathIndex,
    pub package_clauses: &'a dyn GoPackageClauseProvider,
    pub source_facts: &'a dyn GoSourceFactProvider,
}

/// The canonical declared package identifier for one analyzed Go file.
///
/// Package identity is an analyzer-owned source property. Keeping this
/// capability separate from
/// [`CodeUnitIndex`] prevents graph construction from reparsing a package
/// clause or falling back to the working tree when an overlay or persisted
/// property is unavailable.
pub trait GoPackageClauseProvider: Send + Sync {
    fn package_clause_of(&self, file: &ProjectFile) -> Option<String>;
}

/// Input files for a Go graph build whose indexed source or parser facts were
/// unavailable. An authoritatively empty inventory is a valid empty graph;
/// unavailable workspace inventory may have no known file paths to report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoGraphBuildError {
    pub unavailable_files: Vec<ProjectFile>,
}

impl GoGraphBuildError {
    pub fn from_files(files: impl IntoIterator<Item = ProjectFile>) -> Self {
        let mut unavailable_files: Vec<_> = files.into_iter().collect();
        unavailable_files.sort_unstable();
        unavailable_files.dedup();
        Self { unavailable_files }
    }

    fn for_file(file: ProjectFile) -> Self {
        Self::from_files([file])
    }
}

/// Canonical, mounted declaration input shared by the hierarchy and edge
/// indexes. This value never owns source text or a CST:
/// declaration consumers must use the primary source-fact publication.
#[derive(Clone)]
pub(crate) struct GoFactFile {
    pub file: ProjectFile,
    pub facts: Arc<GoFileSourceFacts>,
    pub package_name: String,
    pub imports: HashMap<String, Vec<String>>,
    pub dot_imports: Vec<String>,
    /// Import paths outside the indexed workspace, retained so declaration
    /// MethodKeys can distinguish one canonical external package from an
    /// unknown or ambiguous qualifier.
    pub external_imports: HashMap<String, Vec<String>>,
    pub dot_external_imports: Vec<String>,
}

/// Load mounted Go source facts and checked import/package capabilities for a
/// file set. A missing fact publication, package clause, import publication,
/// or invalid arena link is recorded as unavailable; an explicitly published
/// empty fact inventory remains a usable file.
pub(crate) fn load_go_fact_files(
    source: GoGraphSource<'_>,
    files: impl IntoIterator<Item = ProjectFile>,
) -> (Vec<GoFactFile>, Vec<ProjectFile>) {
    let mut files: Vec<_> = files
        .into_iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .filter(|file| !source.workspace_paths.is_outside_selected_modules(file))
        .collect();
    files.sort();
    files.dedup();
    let dir_index = build_parent_dir_index(files.iter());
    let mut package_clauses = HashMap::default();
    for file in &files {
        if let Some(package) = source
            .package_clauses
            .package_clause_of(file)
            .filter(|package| !package.is_empty())
        {
            package_clauses.insert(file.clone(), package);
        }
    }
    let mut unavailable = Vec::new();
    let mut pending = Vec::new();
    for file in files {
        let Some(package_clause) = package_clauses.get(&file) else {
            unavailable.push(file);
            continue;
        };
        let Some(facts) = source.source_facts.go_source_facts(source.token, &file) else {
            unavailable.push(file);
            continue;
        };
        if !facts.facts.valid_links(&facts.source) {
            unavailable.push(file);
            continue;
        }
        let package_name = source
            .workspace_paths
            .canonical_package_name(&file, package_clause);
        pending.push((file, facts, package_name));
    }
    let mut loaded = Vec::with_capacity(pending.len());
    for (file, facts, package_name) in pending {
        let Ok(imports) = checked_import_infos(source, &file) else {
            unavailable.push(file);
            continue;
        };
        let bindings = import_bindings_from_imports(
            &file,
            &imports,
            &dir_index,
            source.workspace_paths,
            |target| package_clauses.get(target).cloned(),
            |_| None,
        );
        loaded.push(GoFactFile {
            file,
            facts,
            package_name,
            imports: bindings.workspace,
            dot_imports: bindings.dot_workspace,
            external_imports: bindings.external,
            dot_external_imports: bindings.dot_external,
        });
    }
    loaded.sort_by(|left, right| left.file.cmp(&right.file));
    unavailable.sort();
    unavailable.dedup();
    (loaded, unavailable)
}

fn load_complete_go_fact_files(
    source: GoGraphSource<'_>,
    files: impl IntoIterator<Item = ProjectFile>,
) -> Result<Vec<GoFactFile>, GoGraphBuildError> {
    let (fact_files, mut unavailable) = load_go_fact_files(source, files);
    unavailable.extend(
        fact_files
            .iter()
            .filter(|file| !go_fact_file_is_complete(file))
            .map(|file| file.file.clone()),
    );
    if unavailable.is_empty() {
        Ok(fact_files)
    } else {
        Err(GoGraphBuildError::from_files(unavailable))
    }
}

/// Legacy alias projection still read by definition resolution.
/// The native usage engine does not use this index.
#[derive(Default)]
pub struct GoEdgeIndex {
    non_alias_type_fqns: HashSet<String>,
    type_alias_targets: HashMap<String, String>,
}

impl GoEdgeIndex {
    pub fn is_known_non_alias_type(&self, fq_name: &str) -> bool {
        self.non_alias_type_fqns.contains(fq_name)
    }

    pub fn resolve_type_alias(&self, fq_name: &str) -> String {
        resolve_go_alias_fqn(&self.type_alias_targets, fq_name)
    }
}

/// The two workspace products built from one canonical source-fact snapshot.
///
/// The analysis shim memoizes this pair together. Both indexes need the same
/// mounted declarations, imports, and type facts; loading that publication
/// once keeps hierarchy and legacy alias construction on one source-authoritative
/// pass without reparsing project files.
pub struct GoWorkspaceIndexes {
    pub hierarchy: Arc<crate::hierarchy::GoHierarchyIndex>,
    pub edges: Arc<GoEdgeIndex>,
}

/// Build the hierarchy and legacy alias products from one canonical input
/// load. The input file list is normally the analyzer's complete Go inventory.
pub fn build_go_workspace_indexes(
    source: GoGraphSource<'_>,
    files: &[ProjectFile],
) -> Result<GoWorkspaceIndexes, GoGraphBuildError> {
    let _scope = brokk_bifrost_core::profiling::scope("go_workspace_indexes::build");
    let fact_files = load_complete_go_fact_files(source, files.iter().cloned())?;
    let edges = build_go_edge_index_from_facts(source, &fact_files)?;
    let hierarchy = crate::hierarchy::GoHierarchyIndex::build_from_fact_files(source, fact_files);
    Ok(GoWorkspaceIndexes {
        hierarchy: Arc::new(hierarchy),
        edges: Arc::new(edges),
    })
}

pub(crate) fn go_fact_file_is_complete(file: &GoFactFile) -> bool {
    file.facts
        .facts
        .aliases
        .iter()
        .all(|alias| alias.target.is_some())
        && file
            .facts
            .facts
            .fields
            .iter()
            .all(|field| field.ty.is_some())
        && file.facts.facts.callables.iter().all(|callable| {
            callable
                .parameters
                .as_ref()
                .is_some_and(|parameters| parameters.iter().all(|parameter| parameter.ty.is_some()))
                && callable
                    .results
                    .iter()
                    .all(|parameter| parameter.ty.is_some())
                && (callable.result.is_none() || !callable.results.is_empty())
        })
}

fn build_go_edge_index_from_facts(
    _source: GoGraphSource<'_>,
    fact_files: &[GoFactFile],
) -> Result<GoEdgeIndex, GoGraphBuildError> {
    let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::collect_facts");
    let type_maps = collect_go_type_maps(fact_files);
    let type_alias_targets = collect_go_fact_alias_targets(fact_files, &type_maps)?;
    let non_alias_type_fqns = type_maps
        .type_fqns
        .iter()
        .filter(|fqn| !type_alias_targets.contains_key(*fqn))
        .cloned()
        .collect();
    Ok(GoEdgeIndex {
        non_alias_type_fqns,
        type_alias_targets,
    })
}

fn resolve_go_alias_fqn(aliases: &HashMap<String, String>, fq_name: &str) -> String {
    let mut current = fq_name.to_string();
    let mut visited = HashSet::default();
    while let Some(next) = aliases.get(&current) {
        if !visited.insert(current.clone()) {
            return fq_name.to_string();
        }
        current = next.clone();
    }
    current
}

#[derive(Default)]
struct GoFactTypeMaps {
    type_fqns: HashSet<String>,
    /// Every captured struct/interface container, including inline containers
    /// reached through a field. Top-level declarations seed this map; nested
    /// owners are projected from their parent field facts below.
    owner_by_id: HashMap<(ProjectFile, GoSourceTypeId), Vec<String>>,
    alias_names: HashSet<String>,
}

pub(crate) fn mounted_units(
    file: &GoFactFile,
    declaration: brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
) -> impl Iterator<Item = CodeUnit> + '_ {
    file.facts
        .declaration_units
        .get(&declaration)
        .into_iter()
        .flatten()
        .cloned()
}

fn collect_go_type_maps(files: &[GoFactFile]) -> GoFactTypeMaps {
    let mut maps = GoFactTypeMaps::default();
    for file in files {
        for declaration in &file.facts.facts.declarations {
            if !declaration.file_scope {
                continue;
            }
            for unit in mounted_units(file, declaration.declaration) {
                if unit.is_class() {
                    let fqn = unit.fq_name();
                    maps.type_fqns.insert(fqn.clone());
                    maps.owner_by_id
                        .entry((file.file.clone(), declaration.ty))
                        .or_default()
                        .push(fqn);
                }
            }
        }
        for alias in &file.facts.facts.aliases {
            maps.alias_names
                .insert(format!("{}.{}", file.package_name, alias.name));
        }
    }
    for names in maps.owner_by_id.values_mut() {
        names.sort_unstable();
        names.dedup();
    }
    // Inline struct/interface containers have no declaration row of their own.
    // Their stable owner is the containing field's owner plus that field's
    // captured name; walk this relation until all nested containers are named.
    let mut changed = true;
    while changed {
        changed = false;
        for file in files {
            for field in &file.facts.facts.fields {
                let Some(nested) = field.ty else { continue };
                let shape = &file.facts.facts.types[nested.index()].shape;
                if !matches!(
                    shape,
                    GoSourceTypeShape::Struct { .. } | GoSourceTypeShape::Interface { .. }
                ) {
                    continue;
                }
                let Some(parents) = maps
                    .owner_by_id
                    .get(&(file.file.clone(), field.owner))
                    .cloned()
                else {
                    continue;
                };
                let owners = maps
                    .owner_by_id
                    .entry((file.file.clone(), nested))
                    .or_default();
                for parent in parents {
                    let owner = format!("{parent}.{}", field.name);
                    if !owners.contains(&owner) {
                        owners.push(owner);
                        changed = true;
                    }
                }
            }
        }
    }
    for names in maps.owner_by_id.values_mut() {
        names.sort_unstable();
        names.dedup();
    }
    maps
}

/// Return the declaration-backed owner names for every captured struct or
/// interface container, including inline containers reached through fields.
/// Hierarchy uses the same owner projection as the tree-free edge index so an
/// inline interface's methods cannot disappear merely because it has no
/// top-level type declaration row.
pub(crate) fn go_fact_owner_fqns(
    files: &[GoFactFile],
) -> HashMap<(ProjectFile, GoSourceTypeId), Vec<String>> {
    collect_go_type_maps(files).owner_by_id
}

fn collect_go_fact_alias_targets(
    files: &[GoFactFile],
    maps: &GoFactTypeMaps,
) -> Result<HashMap<String, String>, GoGraphBuildError> {
    let mut aliases = HashMap::default();
    let mut ambiguous_files = Vec::new();
    for file in files {
        for alias in &file.facts.facts.aliases {
            let Some(target_id) = alias.target else {
                continue;
            };
            if fact_type_binding_is_ambiguous(file, target_id, maps) {
                ambiguous_files.push(file.file.clone());
                continue;
            }
            let candidates = fact_type_fqns(file, target_id, maps);
            if candidates.len() > 1 {
                ambiguous_files.push(file.file.clone());
                continue;
            }
            let Some(target) = candidates.into_iter().next() else {
                // Predeclared, external and explicitly unsupported source
                // types are valid aliases but have no workspace edge.
                continue;
            };
            aliases.insert(format!("{}.{}", file.package_name, alias.name), target);
        }
    }
    if ambiguous_files.is_empty() {
        Ok(aliases)
    } else {
        Err(GoGraphBuildError::from_files(ambiguous_files))
    }
}

fn fact_type_binding_is_ambiguous(
    file: &GoFactFile,
    id: GoSourceTypeId,
    maps: &GoFactTypeMaps,
) -> bool {
    let mut current = id;
    let mut seen = HashSet::default();
    loop {
        if !seen.insert(current) {
            return false;
        }
        match &file.facts.facts.types[current.index()].shape {
            GoSourceTypeShape::Named(name) => {
                let path = name.path();
                let Some(member) = path.last() else {
                    return false;
                };
                if path.len() == 1 {
                    let local = format!("{}.{}", file.package_name, member);
                    if maps.type_fqns.contains(&local) || maps.alias_names.contains(&local) {
                        return false;
                    }
                    return file.dot_imports.len() + file.dot_external_imports.len() > 1;
                }
                if path.len() == 2 {
                    let qualifier = &path[0];
                    return file.imports.get(qualifier).map_or(0, Vec::len)
                        + file.external_imports.get(qualifier).map_or(0, Vec::len)
                        > 1;
                }
                return false;
            }
            GoSourceTypeShape::Pointer(inner) | GoSourceTypeShape::Negated(inner) => {
                current = *inner
            }
            GoSourceTypeShape::Generic { base, .. } => current = *base,
            GoSourceTypeShape::Compound {
                kind: GoTypeCompoundKind::Parenthesized | GoTypeCompoundKind::Element,
                children,
            } if children.len() == 1 => current = children[0],
            _ => return false,
        }
    }
}

fn fact_type_fqns(file: &GoFactFile, id: GoSourceTypeId, maps: &GoFactTypeMaps) -> Vec<String> {
    let mut current = id;
    let mut seen = HashSet::default();
    loop {
        if !seen.insert(current) {
            return Vec::new();
        }
        let shape = &file.facts.facts.types[current.index()].shape;
        current = match shape {
            GoSourceTypeShape::Pointer(inner) | GoSourceTypeShape::Negated(inner) => *inner,
            GoSourceTypeShape::Generic { base, .. } => *base,
            GoSourceTypeShape::Compound {
                kind: GoTypeCompoundKind::Parenthesized | GoTypeCompoundKind::Element,
                children,
            } if children.len() == 1 => children[0],
            GoSourceTypeShape::Named(name) => {
                let path = name.path();
                let Some(name) = path.last() else {
                    return Vec::new();
                };
                let mut candidates = Vec::new();
                if path.len() == 1 {
                    let candidate = format!("{}.{}", file.package_name, name);
                    if maps.type_fqns.contains(&candidate) || maps.alias_names.contains(&candidate)
                    {
                        candidates.push(candidate);
                    } else if file.dot_imports.len() + file.dot_external_imports.len() == 1 {
                        for package in &file.dot_imports {
                            let candidate = format!("{package}.{name}");
                            if maps.type_fqns.contains(&candidate)
                                || maps.alias_names.contains(&candidate)
                            {
                                candidates.push(candidate);
                            }
                        }
                    }
                } else if path.len() == 2 {
                    let qualifier = &path[0];
                    let packages = file.imports.get(qualifier);
                    let external = file.external_imports.get(qualifier);
                    let package_count = packages.map_or(0, Vec::len) + external.map_or(0, Vec::len);
                    if package_count != 1 {
                        return Vec::new();
                    }
                    if let Some(packages) = packages {
                        for package in packages {
                            let candidate = format!("{package}.{name}");
                            if maps.type_fqns.contains(&candidate)
                                || maps.alias_names.contains(&candidate)
                            {
                                candidates.push(candidate);
                            }
                        }
                    }
                }
                candidates.sort_unstable();
                candidates.dedup();
                return candidates;
            }
            GoSourceTypeShape::Struct { .. }
            | GoSourceTypeShape::Interface { .. }
            | GoSourceTypeShape::Opaque { .. }
            | GoSourceTypeShape::Slice(_)
            | GoSourceTypeShape::Array { .. }
            | GoSourceTypeShape::ImplicitArray { .. }
            | GoSourceTypeShape::Map { .. }
            | GoSourceTypeShape::Channel { .. }
            | GoSourceTypeShape::Compound { .. } => return Vec::new(),
        };
    }
}

/// Every name a Go file's import block binds, split by whether a workspace
/// package answers the import path.
///
/// Semantic diagnostics need both halves: the workspace half decides whether a
/// package member is indexed here, and the external half is the only way to
/// name the package identity an exact API pack publishes. Resolving them in
/// one pass keeps a path from appearing in both halves.
#[derive(Debug, Default)]
pub struct GoImportBindings {
    /// Local name -> canonical, module-qualified workspace package prefixes.
    pub workspace: HashMap<String, Vec<String>>,
    /// Dot-imported canonical workspace package prefixes.
    pub dot_workspace: Vec<String>,
    /// Local name -> import paths that no workspace package answers.
    pub external: HashMap<String, Vec<String>>,
    /// Dot-imported import paths that no workspace package answers.
    pub dot_external: Vec<String>,
}

/// `declared_package_name` answers "what `package` clause does an activated
/// exact API pack record for this import path", which is how an unaliased
/// `import "example.com/m/postgres"` of `package pg` binds `pg`. It reads
/// retained overlay state only; it must never start dependency discovery.
fn import_bindings_from_imports(
    file: &ProjectFile,
    imports: &[ImportInfo],
    dir_index: &ParentDirIndex,
    workspace_paths: &GoWorkspacePathIndex,
    mut target_package_name: impl FnMut(&ProjectFile) -> Option<String>,
    declared_package_name: impl Fn(&str) -> Option<String>,
) -> GoImportBindings {
    let mut bindings = GoImportBindings::default();
    for import in imports {
        let alias = import.alias.as_deref();
        if alias == Some("_") {
            continue;
        }
        let Some(path) = go_import_path(import) else {
            continue;
        };
        let resolved = resolve_go_module(file, &path, dir_index, workspace_paths);
        // Each resolved package is `(clause name, canonical fqn prefix)`: the
        // source refers to it by its `package` clause name (`row`), while the
        // node fqn it must map to uses the canonical, module-qualified path
        // (`example.com/.../row`).
        let mut packages: Vec<(String, String)> = resolved
            .iter()
            .filter_map(|target| {
                let clause = target_package_name(target)?;
                if source_inventory_role(target, &clause) == "xtest" {
                    return None;
                }
                let canonical = workspace_paths.canonical_package_name(target, &clause);
                (!clause.is_empty() && !canonical.is_empty()).then_some((clause, canonical))
            })
            .collect();
        packages.sort();
        packages.dedup();
        if packages.is_empty() {
            // No workspace package answers this path. The local name it binds
            // comes from the alias, then from the package clause an exact API
            // pack records, then from the binding name the Go import parser
            // already derived. That is exactly the precedence `get_definition`
            // applies in `go_import_paths`, so a diagnostic and a definition
            // cannot disagree about which package a qualifier names.
            match alias {
                Some(".") => bindings.dot_external.push(path),
                _ => {
                    let local = match alias {
                        Some(explicit) => Some(default_go_import_local_name(explicit)),
                        None => declared_package_name(&path)
                            .or_else(|| Some(default_go_import_local_name(&path))),
                    };
                    if let Some(local) = local.filter(|local| !local.is_empty() && local != "_") {
                        bindings.external.entry(local).or_default().push(path);
                    }
                }
            }
            continue;
        }
        let canonicals = || packages.iter().map(|(_, canonical)| canonical.clone());
        match alias {
            Some(".") => bindings.dot_workspace.extend(canonicals()),
            Some(explicit) => bindings
                .workspace
                .entry(default_go_import_local_name(explicit))
                .or_default()
                .extend(canonicals()),
            None => {
                // A plain import is referred to by its package-clause name;
                // map that local name to the canonical node fqn prefix.
                for (clause, canonical) in packages {
                    bindings
                        .workspace
                        .entry(clause)
                        .or_default()
                        .push(canonical);
                }
            }
        }
    }
    for names in bindings
        .workspace
        .values_mut()
        .chain(bindings.external.values_mut())
    {
        names.sort();
        names.dedup();
    }
    bindings.dot_workspace.sort();
    bindings.dot_workspace.dedup();
    bindings.dot_external.sort();
    bindings.dot_external.dedup();
    bindings
}

/// Resolve every name `file`'s import block binds, workspace and external.
///
/// `declared_package_name` reads the activated semantic-model overlay from the
/// analysis side; passing it here keeps diagnostics and `get_definition` on
/// one package identity instead of two that agree by accident.
/// Workspace clauses come from canonical target properties on demand. A known
/// workspace target with no clause is unavailable, never an external fallback.
pub fn resolve_go_import_bindings(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
    package_clause: impl Fn(&ProjectFile) -> Option<String>,
    declared_package_name: impl Fn(&str) -> Option<String>,
) -> Result<GoImportBindings, GoGraphBuildError> {
    let files = source.index.analyzed_files();
    let dir_index = build_parent_dir_index(files.iter());
    let imports = checked_import_infos(source, file)?;
    let mut unavailable_files = Vec::new();
    let bindings = import_bindings_from_imports(
        file,
        &imports,
        &dir_index,
        source.workspace_paths,
        |target| {
            let clause = package_clause(target).filter(|clause| !clause.is_empty());
            if clause.is_none() {
                unavailable_files.push(target.clone());
            }
            clause
        },
        declared_package_name,
    );
    if unavailable_files.is_empty() {
        Ok(bindings)
    } else {
        Err(GoGraphBuildError::from_files(unavailable_files))
    }
}

fn checked_import_infos(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
) -> Result<Vec<ImportInfo>, GoGraphBuildError> {
    source
        .imports
        .import_info_of_checked(source.token, file)
        .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))
}

/// Maps each normalized parent directory to its indexed files, so diagnostics
/// and source-fact import resolution use keyed lookups instead of scanning the
/// entire file inventory for each import.
type ParentDirIndex = HashMap<String, Vec<ProjectFile>>;

fn build_parent_dir_index<'a>(files: impl Iterator<Item = &'a ProjectFile>) -> ParentDirIndex {
    let mut index: ParentDirIndex = HashMap::default();
    for file in files {
        let parent = file.parent().to_string_lossy().replace('\\', "/");
        index.entry(parent).or_default().push(file.clone());
    }
    index
}

fn resolve_go_module(
    source_file: &ProjectFile,
    module: &str,
    dir_index: &ParentDirIndex,
    workspace_paths: &GoWorkspacePathIndex,
) -> Vec<ProjectFile> {
    let mut resolved: Vec<ProjectFile> = Vec::new();
    for representative in workspace_paths.import_files(source_file, module) {
        let directory = representative.parent().to_string_lossy().replace('\\', "/");
        if let Some(files) = dir_index.get(&directory) {
            resolved.extend(files.iter().cloned());
        } else {
            // A known workspace package with unavailable indexed files is not
            // an external package. Let its canonical property read report the
            // missing input instead of erasing the workspace identity here.
            resolved.push(representative);
        }
    }
    resolved.sort();
    resolved.dedup();
    resolved
}

#[cfg(test)]
mod tests {
    use super::{build_parent_dir_index, import_bindings_from_imports, resolve_go_module};
    use crate::packages::{GoWorkspacePathIndex, source_inventory_role};
    use brokk_bifrost_core::analyzer::model::{
        ImportInfo, StructuredImportPath, StructuredImportPathKind,
    };
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use brokk_bifrost_core::analyzer::{Language, ProjectFile};
    use brokk_bifrost_core::path_utils::rel_path_string;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeMap;

    #[test]
    #[hardwon("#4474: Go imports admitted external-test siblings as ordinary packages")]
    fn go_import_bindings_exclude_external_test_provider_but_keep_ordinary_suffix_test_package() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        let files = [
            ("go.mod", "module github.com/gohugoio/hugo\n"),
            (
                "consumer.go",
                "package main\n\nimport (\n\ttemplate \"github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate\"\n\t\"github.com/gohugoio/hugo/tpl/internal/go_templates/ordinarysuffix\"\n)\n",
            ),
            (
                "tpl/internal/go_templates/texttemplate/template.go",
                "package template\n\nvar FuncMap int\n",
            ),
            (
                "tpl/internal/go_templates/texttemplate/template_test.go",
                "package template_test\n\nvar ExternalTestOnly int\n",
            ),
            (
                "tpl/internal/go_templates/ordinarysuffix/ordinary.go",
                "package ordinary_test\n\nvar OrdinaryPackage int\n",
            ),
        ];
        for (path, source) in files {
            let file = root.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, source).unwrap();
        }

        let project = TestProject::new(root.clone(), Language::Go);
        let package_clauses = |file: &ProjectFile| match rel_path_string(file).as_str() {
            "consumer.go" => Some("main".to_owned()),
            "tpl/internal/go_templates/texttemplate/template.go" => Some("template".to_owned()),
            "tpl/internal/go_templates/texttemplate/template_test.go" => {
                Some("template_test".to_owned())
            }
            "tpl/internal/go_templates/ordinarysuffix/ordinary.go" => {
                Some("ordinary_test".to_owned())
            }
            _ => None,
        };
        let workspace_paths = GoWorkspacePathIndex::build(
            &project,
            &package_clauses,
            &brokk_bifrost_core::hash::HashSet::default(),
        );
        let all_files = project.all_files().unwrap();
        let consumer = ProjectFile::new(root.clone(), "consumer.go");
        let dir_index = build_parent_dir_index(all_files.iter());
        let imports = vec![
            import_info(
                "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate",
                Some("template"),
            ),
            import_info(
                "github.com/gohugoio/hugo/tpl/internal/go_templates/ordinarysuffix",
                None,
            ),
        ];
        let package_clause = |file: &ProjectFile| package_clauses(file);

        let hugo_targets = resolve_go_module(
            &consumer,
            "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate",
            &dir_index,
            &workspace_paths,
        );
        let mut hugo_canonical_counts = BTreeMap::new();
        for target in &hugo_targets {
            let clause = package_clause(target).unwrap();
            let canonical = workspace_paths.canonical_package_name(target, &clause);
            *hugo_canonical_counts
                .entry((source_inventory_role(target, &clause), canonical))
                .or_insert(0usize) += 1;
        }
        assert_eq!(
            hugo_canonical_counts,
            BTreeMap::from([
                (
                    (
                        "go",
                        "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate"
                            .to_owned(),
                    ),
                    1,
                ),
                (
                    (
                        "xtest",
                        "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate_test"
                            .to_owned(),
                    ),
                    1,
                ),
            ])
        );

        let hugo_alias_targets: Vec<_> = hugo_targets
            .iter()
            .map(|target| {
                let clause = package_clause(target).unwrap();
                workspace_paths.canonical_package_name(target, &clause)
            })
            .collect();
        assert_eq!(
            hugo_alias_targets,
            vec![
                "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate".to_owned(),
                "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate_test".to_owned(),
            ]
        );

        let bindings = import_bindings_from_imports(
            &consumer,
            &imports,
            &dir_index,
            &workspace_paths,
            package_clause,
            |_| None,
        );
        assert_eq!(
            bindings.workspace.get("template"),
            Some(&vec![
                "github.com/gohugoio/hugo/tpl/internal/go_templates/texttemplate".to_owned()
            ])
        );
        assert!(!bindings.workspace.contains_key("template_test"));
        assert_eq!(
            bindings.workspace.get("ordinary_test"),
            Some(&vec![
                "github.com/gohugoio/hugo/tpl/internal/go_templates/ordinarysuffix".to_owned()
            ])
        );
    }

    fn import_info(path: &str, alias: Option<&str>) -> ImportInfo {
        let identifier = alias
            .or_else(|| path.rsplit('/').next())
            .unwrap()
            .to_owned();
        ImportInfo {
            raw_snippet: match alias {
                Some(alias) => format!("import {alias} \"{path}\""),
                None => format!("import \"{path}\""),
            },
            is_wildcard: false,
            is_global: false,
            identifier: Some(identifier),
            alias: alias.map(str::to_owned),
            path: Some(StructuredImportPath {
                segments: path.split('/').map(str::to_owned).collect(),
                kind: Some(StructuredImportPathKind::Namespace),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: 0,
            }),
            binder_span: None,
        }
    }
}
