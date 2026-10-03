//! Go's usage-graph resolution indexes.
//!
//! [`GoProjectGraph`] holds parsed trees for one query's candidate set;
//! [`GoEdgeIndex`] is its tree-free counterpart for the whole-workspace
//! inverted pass. Both are built from a [`GoGraphSource`]: the core capability
//! traits that answer the analyzer-side questions, plus the Go workspace path
//! index. No analyzer handle appears here -- `brokk-bifrost-analysis` downcasts
//! once and hands the pieces over.

use crate::graph::ast::{
    CompositeLiteralContainerStep, field_owner_token, first_named_child, selector_parts,
};
use crate::imports::{default_go_import_local_name, go_import_path};
use crate::packages::{GO_MODULE_SCOPE_SEGMENT, GoWorkspacePathIndex};
use crate::source_facts::{GoFileSourceFacts, GoSourceFactProvider};
use crate::source_properties::go_source_type_identity;
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeAliasProvider};
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::fq_name::segment_interner;
use brokk_bifrost_core::analyzer::go_facts::{
    GoSourceTypeId, GoSourceTypeShape, GoTypeCompoundKind,
};
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredTypeIdentity};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
pub use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::usages::{ImportEdge, ImportEdgeKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Tree};

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
/// The graph keeps the indexed source tree for Go syntax, but package identity
/// is an analyzer-owned source property. Keeping this capability separate from
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

type NamespacePackages = (HashMap<String, Vec<String>>, Vec<String>);

/// Canonical, mounted declaration input shared by the hierarchy and edge
/// indexes. Unlike `ParsedFile`, this value never owns source text or a CST:
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
    pub import_binding_names: HashSet<String>,
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
        let import_binding_names = bindings
            .workspace
            .keys()
            .chain(bindings.external.keys())
            .cloned()
            .collect();
        loaded.push(GoFactFile {
            file,
            facts,
            package_name,
            imports: bindings.workspace,
            dot_imports: bindings.dot_workspace,
            external_imports: bindings.external,
            dot_external_imports: bindings.dot_external,
            import_binding_names,
        });
    }
    loaded.sort_by(|left, right| left.file.cmp(&right.file));
    unavailable.sort();
    unavailable.dedup();
    (loaded, unavailable)
}

pub struct ParsedFile {
    pub source: Arc<String>,
    pub tree: Tree,
    /// Byte offsets of each line start, computed once at parse time so the
    /// per-symbol scan does not recompute them for every symbol that scans this
    /// file.
    pub line_starts: Vec<usize>,
    imports: Vec<ImportInfo>,
    package_name: String,
}

pub struct GoProjectGraph {
    pub parsed: HashMap<ProjectFile, Arc<ParsedFile>>,
    pub edge_index: Arc<GoEdgeIndex>,
}

impl GoProjectGraph {
    pub fn parsed_file(&self, file: &ProjectFile) -> Option<&ParsedFile> {
        self.parsed.get(file).map(|parsed| parsed.as_ref())
    }

    /// The file's canonical (module-qualified) package name, matching the
    /// `package_name` half of the analyzer's `CodeUnit::fq_name()` so the inverted
    /// scan's callee fqns line up with the graph's nodes.
    pub fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.edge_index.package_name_of(file).or_else(|| {
            self.parsed
                .get(file)
                .map(|parsed| parsed.package_name.clone())
        })
    }

    pub fn namespace_packages(&self, file: &ProjectFile) -> NamespacePackages {
        self.edge_index.namespace_packages(file)
    }

    pub fn is_known_non_alias_type(&self, fq_name: &str) -> bool {
        self.edge_index.is_known_non_alias_type(fq_name)
    }

    pub fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        _target: &CodeUnit,
        _spec: &TargetSpec,
    ) -> HashSet<ProjectFile> {
        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| self.parsed.contains_key(*file))
            .cloned()
            .collect();
        files
    }

    /// Go has no re-export aliasing: a declaration is its own seed.
    pub fn seeds_for_target(
        &self,
        target_file: &ProjectFile,
        target_short: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        BTreeSet::from([(target_file.clone(), target_short.to_string())])
    }

    /// The import edges in `importer` that bind one of the `seeds`.
    pub fn matching_edges_for_importer(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<ImportEdge> {
        let (alias_packages, dot_packages) = self.namespace_packages(importer);
        let mut edges = Vec::new();
        for (target_file, target_name) in seeds {
            let Some(target_package) = self.package_name_of(target_file) else {
                continue;
            };
            for (local_name, packages) in &alias_packages {
                if packages.contains(&target_package) {
                    edges.push(ImportEdge {
                        importer: importer.clone(),
                        local_name: local_name.clone(),
                        target_file: target_file.clone(),
                        kind: ImportEdgeKind::Namespace,
                    });
                }
            }
            if dot_packages.contains(&target_package) {
                edges.push(ImportEdge {
                    importer: importer.clone(),
                    local_name: target_name.clone(),
                    target_file: target_file.clone(),
                    kind: ImportEdgeKind::Named(target_name.clone()),
                });
            }
        }
        edges.sort_by(|left, right| {
            (&left.local_name, &left.target_file).cmp(&(&right.local_name, &right.target_file))
        });
        edges
    }
}

/// Tree-free resolution metadata for the whole-workspace inverted edge build:
/// package names/import resolution, constructor-return facts, direct members,
/// and embedded-field promotion links. Built from mounted source facts, so edge
/// scans retain only compact maps; source trees are parsed on demand inside each
/// per-file use-site walk and dropped immediately.
/// Mirrors the JS/TS [`JsTsUsageIndex`]. The tree-holding [`GoProjectGraph`]
/// still backs the per-symbol query and `get_definition` paths, which read node
/// text from trees.
///
/// [`JsTsUsageIndex`]: crate::analyzer::usages::js_ts_graph::JsTsUsageIndex
#[derive(Default)]
pub struct GoEdgeIndex {
    package_names: HashMap<ProjectFile, String>,
    canonical_package_names: HashMap<ProjectFile, String>,
    constructor_return_types: HashMap<String, Vec<String>>,
    type_units: Vec<CodeUnit>,
    non_alias_type_fqns: HashSet<String>,
    type_alias_targets: HashMap<String, String>,
    direct_member_fqns: HashMap<String, HashMap<String, Vec<String>>>,
    embedded_field_type_fqns: HashMap<String, Vec<String>>,
    field_type_fqns: HashMap<String, HashMap<String, Vec<String>>>,
    namespace_packages_by_file: HashMap<ProjectFile, NamespacePackages>,
    import_binding_names_by_file: HashMap<ProjectFile, HashSet<String>>,
    underlying_types_by_fqn: HashMap<String, Vec<GoUnderlyingTypeFact>>,
}

#[derive(Clone)]
struct GoUnderlyingTypeFact {
    file: ProjectFile,
    package: String,
    identity: StructuredTypeIdentity,
}

impl GoEdgeIndex {
    pub fn files(&self) -> impl Iterator<Item = &ProjectFile> {
        self.package_names.keys()
    }

    /// The file's canonical (module-qualified) package name; see
    /// [`GoProjectGraph::package_name_of`].
    pub fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.canonical_package_names.get(file).cloned()
    }

    /// See [`GoProjectGraph::namespace_packages`]; resolves target package names
    /// from the tree-free per-file map instead of retained parse trees.
    pub fn namespace_packages(&self, file: &ProjectFile) -> NamespacePackages {
        self.namespace_packages_by_file
            .get(file)
            .cloned()
            .unwrap_or_default()
    }

    /// Every ordinary package name bound by an import in `file`, including
    /// imports whose package is outside the indexed workspace.
    pub fn import_binding_names(&self, file: &ProjectFile) -> HashSet<String> {
        self.import_binding_names_by_file
            .get(file)
            .cloned()
            .unwrap_or_default()
    }

    pub fn constructor_return_types(&self, callee: &str) -> Option<&Vec<String>> {
        self.constructor_return_types.get(callee)
    }

    pub fn is_known_non_alias_type(&self, fq_name: &str) -> bool {
        self.non_alias_type_fqns.contains(fq_name)
    }

    pub fn resolve_type_alias(&self, fq_name: &str) -> String {
        resolve_go_alias_fqn(&self.type_alias_targets, fq_name)
    }

    /// Resolve the nominal owner reached by walking a named container type's
    /// declaration-backed underlying shape. Every step comes from an elided
    /// composite-literal boundary; no field spelling participates.
    pub fn composite_literal_owner_fqns(
        &self,
        file: &ProjectFile,
        outer: &TypeRef,
        steps: &[CompositeLiteralContainerStep],
    ) -> Vec<String> {
        let Some(name) = outer.name.as_deref() else {
            return Vec::new();
        };
        let mut outer_fqns = Vec::new();
        match outer.qualifier.as_deref() {
            None => {
                if let Some(package) = self.package_name_of(file) {
                    outer_fqns.push(format!("{package}.{name}"));
                }
            }
            Some(qualifier) => {
                if let Some(packages) = self
                    .namespace_packages_by_file
                    .get(file)
                    .and_then(|(packages, _)| packages.get(qualifier))
                {
                    outer_fqns.extend(packages.iter().map(|package| format!("{package}.{name}")));
                }
            }
        }
        let mut owners = Vec::new();
        for outer_fqn in outer_fqns {
            let outer_fqn = self.resolve_type_alias(&outer_fqn);
            let Some(facts) = self.underlying_types_by_fqn.get(&outer_fqn) else {
                continue;
            };
            for fact in facts {
                let mut identity = Some(fact.identity.clone());
                for step in steps {
                    let Some(current) = identity.take() else {
                        break;
                    };
                    let next = match step {
                        CompositeLiteralContainerStep::ElementOrValue => {
                            current.into_container_element_with(|| true)
                        }
                        CompositeLiteralContainerStep::MapKey => current.into_map_key_with(|| true),
                    };
                    identity = next;
                }
                let Some(identity) = identity else {
                    continue;
                };
                let mut pending = vec![(fact.clone(), identity)];
                let mut visited = HashSet::default();
                while let Some((fact, identity)) = pending.pop() {
                    let Some(nominal) = identity.nominal_name() else {
                        continue;
                    };
                    let candidate_fqns: Vec<String> = match nominal.path() {
                        [name] => vec![format!("{}.{}", fact.package, name)],
                        [qualifier, name] => self
                            .namespace_packages_by_file
                            .get(&fact.file)
                            .and_then(|(packages, _)| packages.get(qualifier))
                            .map(|packages| {
                                packages
                                    .iter()
                                    .map(|package| format!("{package}.{name}"))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        _ => Vec::new(),
                    };
                    for candidate in candidate_fqns {
                        let candidate = self.resolve_type_alias(&candidate);
                        if !visited.insert(candidate.clone()) {
                            continue;
                        }
                        if self.non_alias_type_fqns.contains(&candidate) {
                            owners.push(candidate.clone());
                        }
                        if let Some(next_facts) = self.underlying_types_by_fqn.get(&candidate) {
                            pending.extend(next_facts.iter().cloned().map(|next| {
                                let identity = next.identity.clone();
                                (next, identity)
                            }));
                        }
                    }
                }
            }
        }
        owners.sort();
        owners.dedup();
        owners
    }

    fn type_units(&self) -> impl Iterator<Item = &CodeUnit> {
        self.type_units.iter()
    }

    pub fn direct_member_fqns(&self, owner_fqn: &str, member: &str) -> &[String] {
        self.direct_member_fqns
            .get(owner_fqn)
            .and_then(|members| members.get(member))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn embedded_field_type_fqns(&self, owner_fqn: &str) -> &[String] {
        self.embedded_field_type_fqns
            .get(owner_fqn)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn unique_member_fqn(&self, owner_fqn: &str, member: &str) -> Option<String> {
        let direct = |owner: &str, member: &str| self.direct_member_fqns(owner, member).to_vec();
        let embedded = |owner: &str| self.embedded_field_type_fqns(owner).to_vec();
        match go_unique_indexed_member_candidate_at_nearest_depth(
            owner_fqn, member, &direct, &embedded,
        ) {
            GoIndexedMemberLookup::Unique(candidate) => Some(candidate),
            GoIndexedMemberLookup::Missing | GoIndexedMemberLookup::Ambiguous => None,
        }
    }

    /// The declared workspace type fqn of `owner_fqn`'s field `field`, resolved
    /// through Go's embedded-member promotion at the nearest depth. `None` when
    /// the field is unknown, its type is not a workspace type, or promotion is
    /// ambiguous.
    pub(super) fn unique_field_type_fqn(&self, owner_fqn: &str, field: &str) -> Option<String> {
        let direct = |owner: &str, field: &str| {
            self.field_type_fqns
                .get(owner)
                .and_then(|fields| fields.get(field))
                .cloned()
                .unwrap_or_default()
        };
        let embedded = |owner: &str| self.embedded_field_type_fqns(owner).to_vec();
        match go_unique_indexed_member_candidate_at_nearest_depth(
            owner_fqn, field, &direct, &embedded,
        ) {
            GoIndexedMemberLookup::Unique(candidate) => Some(candidate),
            GoIndexedMemberLookup::Missing | GoIndexedMemberLookup::Ambiguous => None,
        }
    }
}

pub fn constructor_call_type_fqns(
    node: Node<'_>,
    source: &str,
    file_package: &str,
    alias_packages: &HashMap<String, Vec<String>>,
    dot_packages: &[String],
    index: &GoEdgeIndex,
    locals: Option<&LocalInferenceEngine<String>>,
) -> Vec<String> {
    if node.kind() != "call_expression" {
        return Vec::new();
    }
    let Some(function) = node
        .child_by_field_name("function")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    let mut return_types = match function.kind() {
        "identifier" => {
            let name = node_text(function, source);
            if locals.is_some_and(|locals| locals.is_shadowed(name)) {
                return Vec::new();
            }
            let mut types = index
                .constructor_return_types(&format!("{file_package}.{name}"))
                .cloned()
                .unwrap_or_default();
            for package in dot_packages {
                types.extend(
                    index
                        .constructor_return_types(&format!("{package}.{name}"))
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            }
            types
        }
        "selector_expression" => {
            let Some((qualifier, _, field)) = selector_parts(function, source) else {
                return Vec::new();
            };
            if locals.is_some_and(|locals| locals.is_shadowed(&qualifier)) {
                return Vec::new();
            }
            let field = node_text(field, source);
            alias_packages
                .get(&qualifier)
                .into_iter()
                .flatten()
                .flat_map(|package| {
                    index
                        .constructor_return_types(&format!("{package}.{field}"))
                        .into_iter()
                        .flatten()
                        .cloned()
                })
                .collect()
        }
        _ => Vec::new(),
    };
    return_types.sort();
    return_types.dedup();
    return_types
}

/// Build the tree-free [`GoEdgeIndex`] over `files` from the mounted source-fact
/// publication. An empty Go inventory is a successful empty index; unavailable
/// selected input is an explicit error so callers cannot mistake omission for
/// completeness.
pub fn build_go_edge_index(
    source: GoGraphSource<'_>,
    files: &[ProjectFile],
) -> Result<GoEdgeIndex, GoGraphBuildError> {
    let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::build");
    let (fact_files, unavailable) = load_go_fact_files(
        source,
        files
            .iter()
            .filter(|file| language_for_file(file) == Language::Go)
            .cloned(),
    );
    let mut unavailable = unavailable;
    unavailable.extend(
        fact_files
            .iter()
            .filter(|file| !go_fact_file_is_complete(file))
            .map(|file| file.file.clone()),
    );
    if !unavailable.is_empty() {
        return Err(GoGraphBuildError::from_files(unavailable));
    }
    build_go_edge_index_from_facts(source, &fact_files)
}

/// The two workspace products built from one canonical source-fact snapshot.
///
/// The analysis shim memoizes this pair together. Both indexes need the same
/// mounted declarations, imports, and type facts; loading that publication
/// once keeps hierarchy and inverse-edge construction on one source-authoritative
/// pass without reparsing project files.
pub struct GoWorkspaceIndexes {
    pub hierarchy: Arc<crate::hierarchy::GoHierarchyIndex>,
    pub edges: Arc<GoEdgeIndex>,
}

/// Build the hierarchy and tree-free edge products from one canonical input
/// load. The input file list is normally the analyzer's complete Go inventory.
pub fn build_go_workspace_indexes(
    source: GoGraphSource<'_>,
    files: &[ProjectFile],
) -> Result<GoWorkspaceIndexes, GoGraphBuildError> {
    let _scope = brokk_bifrost_core::profiling::scope("go_workspace_indexes::build");
    let (fact_files, unavailable) = load_go_fact_files(
        source,
        files
            .iter()
            .filter(|file| language_for_file(file) == Language::Go)
            .cloned(),
    );
    let mut unavailable = unavailable;
    unavailable.extend(
        fact_files
            .iter()
            .filter(|file| !go_fact_file_is_complete(file))
            .map(|file| file.file.clone()),
    );
    if !unavailable.is_empty() {
        return Err(GoGraphBuildError::from_files(unavailable));
    }
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
    let package_names: HashMap<ProjectFile, String> = fact_files
        .iter()
        .map(|file| (file.file.clone(), file.package_name.clone()))
        .collect();
    let canonical_package_names = package_names.clone();
    let type_maps = collect_go_type_maps(fact_files);
    let type_alias_targets = collect_go_fact_alias_targets(fact_files, &type_maps)?;
    let mut constructor_return_types: HashMap<String, Vec<String>> = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::constructors");
        let mut constructor_return_types: HashMap<String, Vec<String>> = HashMap::default();
        for file in fact_files {
            for callable in &file.facts.facts.callables {
                if callable.is_method || !callable.file_scope || callable.result.is_none() {
                    continue;
                }
                let Some(parameter) = callable.results.first() else {
                    continue;
                };
                let Some(ty) = parameter.ty else {
                    continue;
                };
                let owners = fact_type_fqns(file, ty, &type_maps);
                if owners.is_empty() {
                    continue;
                }
                let return_types = constructor_return_types
                    .entry(format!("{}.{}", file.package_name, callable.name))
                    .or_default();
                return_types.extend(
                    owners
                        .iter()
                        .map(|owner| resolve_go_alias_fqn(&type_alias_targets, owner)),
                );
            }
        }
        constructor_return_types
    };
    for return_types in constructor_return_types.values_mut() {
        return_types.sort();
        return_types.dedup();
    }
    let (namespace_packages_by_file, import_binding_names_by_file) = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::imports");
        let mut namespace_packages_by_file = HashMap::default();
        let mut import_binding_names_by_file = HashMap::default();
        for file in fact_files {
            namespace_packages_by_file.insert(
                file.file.clone(),
                (file.imports.clone(), file.dot_imports.clone()),
            );
            import_binding_names_by_file
                .insert(file.file.clone(), file.import_binding_names.clone());
        }
        (namespace_packages_by_file, import_binding_names_by_file)
    };
    let underlying_types_by_fqn = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::underlying_types");
        collect_go_fact_underlying_type_facts(fact_files, &type_maps)
    };
    for return_types in constructor_return_types.values_mut() {
        for return_type in return_types.iter_mut() {
            *return_type = resolve_go_alias_fqn(&type_alias_targets, return_type);
        }
        return_types.sort();
        return_types.dedup();
    }
    let declaration_facts = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::declarations");
        collect_go_fact_declaration_facts(fact_files, &type_maps, &type_alias_targets)
    };
    let non_alias_type_fqns = declaration_facts
        .type_fqns
        .iter()
        .filter(|fqn| !type_alias_targets.contains_key(*fqn))
        .cloned()
        .collect();
    let field_type_facts = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::fields");
        collect_go_fact_field_type_facts(fact_files, &type_maps, &type_alias_targets)
    };

    Ok(GoEdgeIndex {
        package_names,
        canonical_package_names,
        constructor_return_types,
        non_alias_type_fqns,
        type_alias_targets,
        type_units: declaration_facts.type_units,
        direct_member_fqns: declaration_facts.direct_member_fqns,
        embedded_field_type_fqns: field_type_facts.embedded_by_owner,
        field_type_fqns: field_type_facts.field_types_by_owner,
        namespace_packages_by_file,
        import_binding_names_by_file,
        underlying_types_by_fqn,
    })
}

#[derive(Default)]
struct GoDeclarationFacts {
    type_fqns: HashSet<String>,
    type_units: Vec<CodeUnit>,
    direct_member_fqns: HashMap<String, HashMap<String, Vec<String>>>,
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
    type_units: Vec<CodeUnit>,
    type_by_id: HashMap<(ProjectFile, GoSourceTypeId), Vec<String>>,
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

/// Return a mounted unit's exact Go owner from its structured qualified name.
/// The rendered spelling is only the final API key; owner matching must pop a
/// structured segment so package/type names containing dots cannot create a
/// cross-product of repeated inline projections.
pub(crate) fn go_unit_parent_fqn(unit: &CodeUnit) -> Option<String> {
    unit.fq()
        .parent()
        .filter(|parent| !parent.is_empty())
        .map(|parent| parent.display_native(Language::Go, segment_interner()))
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
                    maps.type_units.push(unit);
                    maps.type_by_id
                        .entry((file.file.clone(), declaration.ty))
                        .or_default()
                        .push(fqn.clone());
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
    maps.type_units.sort_unstable();
    maps.type_units.dedup();
    for names in maps.type_by_id.values_mut() {
        names.sort_unstable();
        names.dedup();
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

fn collect_go_fact_underlying_type_facts(
    files: &[GoFactFile],
    maps: &GoFactTypeMaps,
) -> HashMap<String, Vec<GoUnderlyingTypeFact>> {
    let mut collected: HashMap<String, Vec<GoUnderlyingTypeFact>> = HashMap::default();
    for file in files {
        for declaration in &file.facts.facts.declarations {
            if !declaration.file_scope {
                continue;
            }
            let Some(identity) = go_source_type_identity(&file.facts.facts, declaration.ty) else {
                continue;
            };
            for fqn in maps
                .type_by_id
                .get(&(file.file.clone(), declaration.ty))
                .into_iter()
                .flatten()
            {
                collected
                    .entry(fqn.clone())
                    .or_default()
                    .push(GoUnderlyingTypeFact {
                        file: file.file.clone(),
                        package: file.package_name.clone(),
                        identity: identity.clone(),
                    });
            }
        }
    }
    collected
}

fn collect_go_fact_declaration_facts(
    files: &[GoFactFile],
    maps: &GoFactTypeMaps,
    aliases: &HashMap<String, String>,
) -> GoDeclarationFacts {
    let mut facts = GoDeclarationFacts {
        type_fqns: maps.type_fqns.clone(),
        type_units: maps.type_units.clone(),
        direct_member_fqns: HashMap::default(),
    };
    for file in files {
        for field in &file.facts.facts.fields {
            let Some(owners) = maps.owner_by_id.get(&(file.file.clone(), field.owner)) else {
                continue;
            };
            for unit in mounted_units(file, field.declaration) {
                if !unit.is_field() {
                    continue;
                }
                let Some(unit_owner) = go_unit_parent_fqn(&unit) else {
                    continue;
                };
                let Some(owner) = owners.iter().find(|owner| **owner == unit_owner) else {
                    continue;
                };
                facts
                    .direct_member_fqns
                    .entry(owner.clone())
                    .or_default()
                    .entry(unit.identifier().to_string())
                    .or_default()
                    .push(unit.fq_name());
            }
        }
        for callable in &file.facts.facts.callables {
            let owners = if let Some(owner) = callable.owner {
                maps.owner_by_id
                    .get(&(file.file.clone(), owner))
                    .cloned()
                    .unwrap_or_default()
            } else if let Some(receiver) = callable.receiver {
                fact_type_fqns(file, receiver, maps)
            } else {
                Vec::new()
            };
            if owners.is_empty() {
                continue;
            }
            for unit in mounted_units(file, callable.declaration) {
                if !unit.is_function() {
                    continue;
                }
                let Some(unit_owner) = go_unit_parent_fqn(&unit) else {
                    continue;
                };
                let Some(owner) = owners.iter().find(|owner| **owner == unit_owner) else {
                    continue;
                };
                let owner = resolve_go_alias_fqn(aliases, owner);
                facts
                    .direct_member_fqns
                    .entry(owner)
                    .or_default()
                    .entry(unit.identifier().to_string())
                    .or_default()
                    .push(unit.fq_name());
            }
        }
    }
    for members in facts.direct_member_fqns.values_mut() {
        for units in members.values_mut() {
            units.sort_unstable();
            units.dedup();
        }
    }
    facts
}

#[derive(Default)]
struct GoFieldTypeFacts {
    embedded_by_owner: HashMap<String, Vec<String>>,
    field_types_by_owner: HashMap<String, HashMap<String, Vec<String>>>,
}

fn collect_go_fact_field_type_facts(
    files: &[GoFactFile],
    maps: &GoFactTypeMaps,
    aliases: &HashMap<String, String>,
) -> GoFieldTypeFacts {
    let mut collected = GoFieldTypeFacts::default();
    for file in files {
        for field in &file.facts.facts.fields {
            let Some(owners) = maps.owner_by_id.get(&(file.file.clone(), field.owner)) else {
                continue;
            };
            let Some(tys) = field.ty.map(|id| fact_type_fqns(file, id, maps)) else {
                continue;
            };
            for owner in owners {
                for ty in &tys {
                    let ty = resolve_go_alias_fqn(aliases, ty);
                    collected
                        .field_types_by_owner
                        .entry(owner.clone())
                        .or_default()
                        .entry(field.name.clone())
                        .or_default()
                        .push(ty.clone());
                    if field.embedded {
                        collected
                            .embedded_by_owner
                            .entry(owner.clone())
                            .or_default()
                            .push(ty);
                    }
                }
            }
        }
        for embedding in &file.facts.facts.embeddings {
            let Some(owners) = maps.owner_by_id.get(&(file.file.clone(), embedding.owner)) else {
                continue;
            };
            let tys = fact_type_fqns(file, embedding.ty, maps);
            for owner in owners {
                for ty in &tys {
                    collected
                        .embedded_by_owner
                        .entry(owner.clone())
                        .or_default()
                        .push(resolve_go_alias_fqn(aliases, ty));
                }
            }
        }
    }
    for values in collected.embedded_by_owner.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for fields in collected.field_types_by_owner.values_mut() {
        for values in fields.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
    }
    collected
}

/// Resolve `file`'s imports to the workspace package names they bind, given a
/// lookup from a resolved target file to its `package` clause name. Shared by the
/// tree-holding [`GoProjectGraph`] and the tree-free [`GoEdgeIndex`] so the two
/// cannot drift; see [`GoProjectGraph::namespace_packages`] for the contract.
fn namespace_packages_from(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
    dir_index: &ParentDirIndex,
    workspace_paths: &GoWorkspacePathIndex,
    target_package_name: impl Fn(&ProjectFile) -> Option<String>,
) -> Result<NamespacePackages, GoGraphBuildError> {
    let imports = checked_import_infos(source, file)?;
    Ok(namespace_packages_from_imports(
        file,
        &imports,
        dir_index,
        workspace_paths,
        target_package_name,
    ))
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

fn namespace_packages_from_imports(
    file: &ProjectFile,
    imports: &[ImportInfo],
    dir_index: &ParentDirIndex,
    workspace_paths: &GoWorkspacePathIndex,
    target_package_name: impl Fn(&ProjectFile) -> Option<String>,
) -> NamespacePackages {
    namespace_package_facts_from_imports(
        file,
        imports,
        dir_index,
        workspace_paths,
        target_package_name,
    )
    .0
}

fn namespace_package_facts_from_imports(
    file: &ProjectFile,
    imports: &[ImportInfo],
    dir_index: &ParentDirIndex,
    workspace_paths: &GoWorkspacePathIndex,
    target_package_name: impl Fn(&ProjectFile) -> Option<String>,
) -> (NamespacePackages, HashSet<String>) {
    let bindings = import_bindings_from_imports(
        file,
        imports,
        dir_index,
        workspace_paths,
        target_package_name,
        |_| None,
    );
    let import_binding_names = bindings
        .workspace
        .keys()
        .chain(bindings.external.keys())
        .cloned()
        .collect();
    (
        (bindings.workspace, bindings.dot_workspace),
        import_binding_names,
    )
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

pub fn resolve_go_import_namespaces(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
    package_names: &HashMap<ProjectFile, String>,
) -> Result<NamespacePackages, GoGraphBuildError> {
    let dir_index = build_parent_dir_index(package_names.keys());
    namespace_packages_from(source, file, &dir_index, source.workspace_paths, |target| {
        package_names.get(target).cloned()
    })
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

fn parse_go_source(
    source: String,
    imports: Vec<ImportInfo>,
    package_name: String,
) -> Option<ParsedFile> {
    let tree = crate::parse::parse_go(source.as_str())?;
    let line_starts = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    Some(ParsedFile {
        source: Arc::new(source),
        tree,
        line_starts,
        imports,
        package_name,
    })
}

fn graph_package_clause(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
) -> Result<String, GoGraphBuildError> {
    source
        .package_clauses
        .package_clause_of(file)
        .filter(|package_name| !package_name.is_empty())
        .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))
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

fn parse_go_graph_file(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
) -> Result<ParsedFile, GoGraphBuildError> {
    let package_name = graph_package_clause(source, file)?;
    let source_text = source
        .index
        .indexed_source(file)
        .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))?;
    let imports = checked_import_infos(source, file)?;
    parse_go_source(source_text, imports, package_name)
        .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))
}

pub fn build_go_graph(
    source: GoGraphSource<'_>,
    candidate_files: &HashSet<ProjectFile>,
    resolution_files: &[ProjectFile],
    target_file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> Result<GoProjectGraph, GoGraphBuildError> {
    let scoped_files: BTreeSet<ProjectFile> = candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .chain(std::iter::once(target_file.clone()))
        .collect();
    let available_files: BTreeSet<ProjectFile> = resolution_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .chain(scoped_files.iter().cloned())
        .collect();
    let available_dir_index = build_parent_dir_index(available_files.iter());
    let workspace_paths = source.workspace_paths;
    let mut pending: Vec<ProjectFile> = scoped_files.iter().cloned().collect();
    let mut queued: HashSet<ProjectFile> = pending.iter().cloned().collect();
    let mut all_parsed: HashMap<ProjectFile, ParsedFile> = HashMap::default();
    let mut unavailable_files = Vec::new();

    while let Some(file) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        if language_for_file(&file) != Language::Go {
            continue;
        }
        let directory = file.parent().to_string_lossy().replace('\\', "/");
        if let Some(siblings) = available_dir_index.get(&directory) {
            for sibling in siblings {
                if queued.insert(sibling.clone()) {
                    pending.push(sibling.clone());
                }
            }
        }
        let parsed_file = match parse_go_graph_file(source, &file) {
            Ok(parsed_file) => parsed_file,
            Err(error) => {
                unavailable_files.extend(error.unavailable_files);
                continue;
            }
        };
        for import in &parsed_file.imports {
            let Some(path) = go_import_path(import) else {
                continue;
            };
            for representative in workspace_paths.import_files(&file, &path) {
                let directory = representative.parent().to_string_lossy().replace('\\', "/");
                if let Some(imported_files) = available_dir_index.get(&directory) {
                    for imported_file in imported_files {
                        if queued.insert(imported_file.clone()) {
                            pending.push(imported_file.clone());
                        }
                    }
                }
            }
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        all_parsed.insert(file, parsed_file);
    }

    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        all_parsed.clear();
    }

    if !unavailable_files.is_empty() {
        return Err(GoGraphBuildError::from_files(unavailable_files));
    }

    let (fact_files, unavailable) = load_go_fact_files(source, all_parsed.keys().cloned());
    let mut unavailable = unavailable;
    unavailable.extend(
        fact_files
            .iter()
            .filter(|file| !go_fact_file_is_complete(file))
            .map(|file| file.file.clone()),
    );
    if !unavailable.is_empty() {
        return Err(GoGraphBuildError::from_files(unavailable));
    }
    let edge_index = Arc::new(build_go_edge_index_from_facts(source, &fact_files)?);

    // Only candidate and target trees survive the build. The remaining parses
    // contributed compact cross-workspace type/import facts above and are
    // dropped here, so a narrow query does not retain the whole workspace CST.
    let parsed = all_parsed
        .into_iter()
        .filter(|(file, _)| scoped_files.contains(file))
        .map(|(file, parsed)| (file, Arc::new(parsed)))
        .collect();

    Ok(GoProjectGraph { parsed, edge_index })
}

/// Build the tree-holding part of a per-symbol graph against a reusable
/// whole-workspace resolution index. Only candidate and target files are
/// parsed; package, import, type, and member facts come from `edge_index`.
pub fn build_go_graph_with_edge_index(
    source: GoGraphSource<'_>,
    edge_index: Arc<GoEdgeIndex>,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> Result<GoProjectGraph, GoGraphBuildError> {
    let _scope = brokk_bifrost_core::profiling::scope("go_query_graph::build");
    let target_file = target.source();
    let identifier = target.identifier();
    let owner = owner_name(target);
    let scoped_files: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .chain(std::iter::once(target_file.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let parsed = {
        let _scope = brokk_bifrost_core::profiling::scope("go_query_graph::parse_candidates");
        let parsed_results: Vec<_> = scoped_files
            .into_par_iter()
            .map(|file| -> Result<_, GoGraphBuildError> {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Ok(None);
                }
                let source_text = source
                    .index
                    .indexed_source(&file)
                    .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))?;
                if &file != target_file
                    && !source_text.contains(identifier)
                    && !owner
                        .as_deref()
                        .is_some_and(|owner| source_text.contains(owner))
                {
                    return Ok(None);
                }
                let imports = checked_import_infos(source, &file)?;
                let package_name = graph_package_clause(source, &file)?;
                let parsed = parse_go_source(source_text, imports, package_name)
                    .ok_or_else(|| GoGraphBuildError::for_file(file.clone()))?;
                Ok(Some((file, Arc::new(parsed))))
            })
            .collect();
        let mut parsed = HashMap::default();
        let mut unavailable_files = Vec::new();
        for result in parsed_results {
            match result {
                Ok(Some((file, parsed_file))) => {
                    parsed.insert(file, parsed_file);
                }
                Ok(None) => {}
                Err(error) => unavailable_files.extend(error.unavailable_files),
            }
        }
        if !unavailable_files.is_empty() {
            return Err(GoGraphBuildError::from_files(unavailable_files));
        }
        parsed
    };
    Ok(GoProjectGraph { parsed, edge_index })
}

/// Maps a normalized parent directory to the parsed files it contains, so a Go
/// import resolves to its package's files with a couple of map lookups instead of
/// scanning every parsed file. Building this once is what makes a whole-workspace
/// graph build linear rather than quadratic in the file count.
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

pub struct TargetSpec {
    pub target: CodeUnit,
    pub identifier: String,
    pub owner: Option<String>,
    top_level_seeds: Option<BTreeSet<(ProjectFile, String)>>,
    owner_seeds: Option<BTreeSet<(ProjectFile, String)>>,
    compatible_receiver_types: BTreeSet<(ProjectFile, String)>,
    compatible_receiver_fqns: HashSet<String>,
    owner_is_interface: bool,
    field_owner_direct_names: HashMap<ProjectFile, HashMap<String, HashSet<String>>>,
}

impl TargetSpec {
    pub fn new(source: GoGraphSource<'_>, graph: &GoProjectGraph, target: &CodeUnit) -> Self {
        let identifier = target.identifier().to_string();
        let owner = owner_name(target);
        let top_level_seeds = if owner.is_none() || is_module_field(target) {
            let seeds = graph.seeds_for_target(target.source(), &identifier);
            (!seeds.is_empty()).then_some(seeds)
        } else {
            None
        };
        let compatible_receiver_types = owner
            .as_ref()
            .map(|owner| {
                collect_compatible_receiver_types(
                    graph,
                    target,
                    target.source(),
                    owner,
                    &identifier,
                )
            })
            .unwrap_or_default();
        let compatible_receiver_fqns = compatible_receiver_types
            .iter()
            .filter_map(|(file, receiver)| {
                graph
                    .package_name_of(file)
                    .map(|package| format!("{package}.{receiver}"))
            })
            .collect();
        let owner_is_interface = go_target_owner_is_interface(source, graph, target);
        let field_owner_direct_names =
            collect_field_owner_direct_names(graph, &compatible_receiver_types);
        let owner_seeds = (!compatible_receiver_types.is_empty()).then(|| {
            let mut seeds = BTreeSet::new();
            for (file, receiver) in &compatible_receiver_types {
                let receiver_seeds = graph.seeds_for_target(file, receiver);
                if receiver_seeds.is_empty() && source.index.parent_of(target).is_some() {
                    seeds.insert((file.clone(), receiver.clone()));
                } else {
                    seeds.extend(receiver_seeds);
                }
            }
            seeds
        });
        Self {
            target: target.clone(),
            identifier,
            owner,
            top_level_seeds,
            owner_seeds,
            compatible_receiver_types,
            compatible_receiver_fqns,
            owner_is_interface,
            field_owner_direct_names,
        }
    }

    pub fn has_scan_seed(&self) -> bool {
        self.top_level_seeds.is_some() || self.owner_seeds.is_some()
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub fn is_member(&self) -> bool {
        self.owner.is_some() && !is_module_field(&self.target)
    }

    pub fn owner_is_interface(&self) -> bool {
        self.owner_is_interface
    }

    pub fn matches_receiver_fqn(&self, fq_name: &str) -> bool {
        self.compatible_receiver_fqns.contains(fq_name)
    }
}

fn go_target_owner_is_interface(
    source: GoGraphSource<'_>,
    _graph: &GoProjectGraph,
    target: &CodeUnit,
) -> bool {
    let Some(facts) = source
        .source_facts
        .go_source_facts(source.token, target.source())
    else {
        return false;
    };
    if !facts.facts.valid_links(&facts.source) {
        return false;
    }
    facts.facts.callables.iter().any(|callable| {
        callable.owner.is_some_and(|owner| {
            matches!(
                &facts.facts.types[owner.index()].shape,
                GoSourceTypeShape::Interface { .. }
            )
        }) && facts
            .declaration_units
            .get(&callable.declaration)
            .into_iter()
            .flatten()
            .any(|unit| unit == target)
    })
}

fn collect_compatible_receiver_types(
    graph: &GoProjectGraph,
    target: &CodeUnit,
    owner_source: &ProjectFile,
    owner: &str,
    method: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let mut receivers = BTreeSet::from([(owner_source.clone(), owner.to_string())]);
    collect_promoted_receiver_types(graph, target, method, &mut receivers);
    receivers
}

fn collect_promoted_receiver_types(
    graph: &GoProjectGraph,
    target: &CodeUnit,
    member: &str,
    receivers: &mut BTreeSet<(ProjectFile, String)>,
) {
    let target_fqn = target.fq_name();
    for unit in graph.edge_index.type_units() {
        if unit.fq_name() == target_fqn {
            continue;
        }
        let direct =
            |owner: &str, member: &str| graph.edge_index.direct_member_fqns(owner, member).to_vec();
        let embedded = |owner: &str| graph.edge_index.embedded_field_type_fqns(owner).to_vec();
        if matches!(
            go_unique_indexed_member_candidate_at_nearest_depth(
                &unit.fq_name(),
                member,
                &direct,
                &embedded,
            ),
            GoIndexedMemberLookup::Unique(candidate) if candidate == target_fqn
        ) {
            receivers.insert((unit.source().clone(), unit.short_name().to_string()));
        }
    }
}

fn collect_field_owner_direct_names(
    graph: &GoProjectGraph,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> HashMap<ProjectFile, HashMap<String, HashSet<String>>> {
    let mut by_file = HashMap::default();
    if compatible_receiver_types.is_empty() {
        return by_file;
    }
    let target_fqns: HashSet<String> = compatible_receiver_types
        .iter()
        .filter_map(|(file, receiver)| {
            graph
                .package_name_of(file)
                .map(|package| format!("{package}.{receiver}"))
        })
        .collect();
    for owner_unit in graph.edge_index.type_units() {
        let Some(fields) = graph.edge_index.field_type_fqns.get(&owner_unit.fq_name()) else {
            continue;
        };
        for (field, types) in fields {
            if types.iter().any(|ty| target_fqns.contains(ty)) {
                by_file
                    .entry(owner_unit.source().clone())
                    .or_default()
                    .entry(owner_unit.short_name().to_string())
                    .or_default()
                    .insert(field.clone());
            }
        }
    }
    by_file
}

fn receiver_type_seeds(
    graph: &GoProjectGraph,
    receiver_file: &ProjectFile,
    receiver: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = graph.seeds_for_target(receiver_file, receiver);
    if seeds.is_empty() {
        seeds.insert((receiver_file.clone(), receiver.to_string()));
    }
    seeds
}

fn owner_name(target: &CodeUnit) -> Option<String> {
    if is_module_field(target) {
        return None;
    }
    let short = target.short_name();
    short
        .rsplit_once('.') // fqname-M4: package-less short_name owner; fq.parent() would render the package-qualified owner
        .map(|(owner, _)| owner.to_string())
        .filter(|owner| !owner.is_empty())
}

fn is_module_field(target: &CodeUnit) -> bool {
    target.is_field()
        && target
            .short_name()
            .split('.') // fqname-M4: first-segment sentinel check on the package-less short_name; no shared accessor exposes a raw first-segment text without routing through the client-selector normalizer (which strips generic/receiver decoration not applicable to this already-canonical internal string)
            .next()
            .is_some_and(|segment| segment == GO_MODULE_SCOPE_SEGMENT)
}

pub fn go_indexed_member_candidates_at_nearest_depth<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
) -> Option<(usize, Vec<T>)> {
    let mut path = HashSet::default();
    go_indexed_member_candidates_at_nearest_depth_with_path(
        owner_fqn, member, direct, embedded, &mut path,
    )
}

fn go_indexed_member_candidates_at_nearest_depth_with_path<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
    path: &mut HashSet<String>,
) -> Option<(usize, Vec<T>)> {
    if !path.insert(owner_fqn.to_string()) {
        return None;
    }
    let result = go_indexed_member_candidates_at_nearest_depth_inner(
        owner_fqn, member, direct, embedded, path,
    );
    path.remove(owner_fqn);
    result
}

fn go_indexed_member_candidates_at_nearest_depth_inner<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
    path: &mut HashSet<String>,
) -> Option<(usize, Vec<T>)> {
    let direct_candidates = direct(owner_fqn, member);
    if !direct_candidates.is_empty() {
        return Some((0, direct_candidates));
    }

    let mut best_depth = usize::MAX;
    let mut best_candidates = Vec::new();
    for embedded_owner in embedded(owner_fqn) {
        let Some((depth, candidates)) = go_indexed_member_candidates_at_nearest_depth_with_path(
            &embedded_owner,
            member,
            direct,
            embedded,
            path,
        ) else {
            continue;
        };
        let promoted_depth = depth + 1;
        match promoted_depth.cmp(&best_depth) {
            std::cmp::Ordering::Less => {
                best_depth = promoted_depth;
                best_candidates = candidates;
            }
            std::cmp::Ordering::Equal => best_candidates.extend(candidates),
            std::cmp::Ordering::Greater => {}
        }
    }

    (best_depth != usize::MAX).then_some((best_depth, best_candidates))
}

pub enum GoIndexedMemberLookup<T> {
    Missing,
    Unique(T),
    Ambiguous,
}

pub fn go_unique_indexed_member_candidate_at_nearest_depth<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
) -> GoIndexedMemberLookup<T> {
    match go_indexed_member_candidates_at_nearest_depth(owner_fqn, member, direct, embedded) {
        None => GoIndexedMemberLookup::Missing,
        Some((_depth, candidates)) if candidates.len() == 1 => {
            let candidate = candidates
                .into_iter()
                .next()
                .expect("candidate count checked");
            GoIndexedMemberLookup::Unique(candidate)
        }
        Some((_depth, _candidates)) => GoIndexedMemberLookup::Ambiguous,
    }
}

pub struct ScanBindings {
    direct_names: HashSet<String>,
    pub namespace_names: HashSet<String>,
    owner_direct_names: HashSet<String>,
    owner_namespace_type_names: HashMap<String, HashSet<String>>,
    field_owner_direct_names: HashMap<String, HashSet<String>>,
    field_owner_namespace_names: HashMap<String, HashMap<String, HashSet<String>>>,
    mark_non_owner_types: bool,
}

impl ScanBindings {
    pub fn new(graph: &GoProjectGraph, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut direct_names = HashSet::default();
        let mut namespace_names = HashSet::default();
        if let Some(seeds) = &spec.top_level_seeds {
            for edge in graph.matching_edges_for_importer(file, seeds) {
                match edge.kind {
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_) => {
                        namespace_names.insert(edge.local_name);
                    }
                    ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                        direct_names.insert(edge.local_name);
                    }
                }
            }
        }
        if same_go_package(graph, file, spec.target.source()) {
            direct_names.insert(spec.identifier.clone());
        }

        let mut owner_direct_names = HashSet::default();
        if let Some(seeds) = &spec.owner_seeds {
            for edge in graph.matching_edges_for_importer(file, seeds) {
                match edge.kind {
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_) => {}
                    ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                        if let Some(owner) = &spec.owner {
                            owner_direct_names.insert(owner.clone());
                        }
                    }
                }
            }
        }
        let mut owner_namespace_type_names: HashMap<String, HashSet<String>> = HashMap::default();
        for (receiver_file, receiver) in &spec.compatible_receiver_types {
            if same_go_package(graph, file, receiver_file) {
                owner_direct_names.insert(receiver.clone());
            }
            let receiver_seeds = graph.seeds_for_target(receiver_file, receiver);
            for edge in graph.matching_edges_for_importer(file, &receiver_seeds) {
                if matches!(
                    edge.kind,
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_)
                ) {
                    owner_namespace_type_names
                        .entry(edge.local_name)
                        .or_default()
                        .insert(receiver.clone());
                }
            }
        }
        let mut field_owner_direct_names = HashMap::default();
        let mut field_owner_namespace_names: HashMap<String, HashMap<String, HashSet<String>>> =
            HashMap::default();
        for (owner_file, owner_fields) in &spec.field_owner_direct_names {
            if same_go_package(graph, file, owner_file) {
                merge_field_owner_names(&mut field_owner_direct_names, owner_fields);
            }
            for (owner, fields) in owner_fields {
                let seeds = receiver_type_seeds(graph, owner_file, owner);
                for edge in graph.matching_edges_for_importer(file, &seeds) {
                    if matches!(
                        edge.kind,
                        ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_)
                    ) {
                        field_owner_namespace_names
                            .entry(edge.local_name)
                            .or_default()
                            .entry(owner.clone())
                            .or_default()
                            .extend(fields.iter().cloned());
                    }
                }
            }
        }
        Self {
            direct_names,
            namespace_names,
            owner_direct_names,
            owner_namespace_type_names,
            field_owner_direct_names,
            field_owner_namespace_names,
            mark_non_owner_types: spec.owner_is_interface(),
        }
    }

    pub fn matches_direct_target(&self, text: &str) -> bool {
        self.direct_names.contains(text)
    }

    pub fn matches_owner_type(&self, ty: &TypeRef) -> bool {
        let Some(owner) = ty.name.as_deref() else {
            return false;
        };
        if ty.qualifier.is_none() && self.owner_direct_names.contains(owner) {
            return true;
        }
        ty.qualifier.as_ref().is_some_and(|qualifier| {
            self.owner_namespace_type_names
                .get(qualifier)
                .is_some_and(|owners| owners.contains(owner))
        })
    }

    pub fn receiver_tokens_for_type(
        &self,
        ty: &TypeRef,
        known_non_alias_type: bool,
    ) -> Vec<String> {
        let mut tokens = Vec::new();
        if self.matches_owner_type(ty) {
            tokens.push(crate::graph::ast::OWNER_TOKEN.to_string());
        }
        if let Some(name) = ty.name.as_deref() {
            match ty.qualifier.as_deref() {
                None => {
                    if let Some(fields) = self.field_owner_direct_names.get(name) {
                        tokens.extend(fields.iter().map(|field| field_owner_token(field)));
                    }
                }
                Some(qualifier) => {
                    if let Some(fields) = self
                        .field_owner_namespace_names
                        .get(qualifier)
                        .and_then(|owners| owners.get(name))
                    {
                        tokens.extend(fields.iter().map(|field| field_owner_token(field)));
                    }
                }
            }
        }
        if self.mark_non_owner_types
            && known_non_alias_type
            && !tokens
                .iter()
                .any(|token| token == crate::graph::ast::OWNER_TOKEN)
        {
            tokens.push(crate::graph::ast::NON_OWNER_TOKEN.to_string());
        }
        tokens.sort();
        tokens.dedup();
        tokens
    }
}

fn merge_field_owner_names(
    target: &mut HashMap<String, HashSet<String>>,
    source: &HashMap<String, HashSet<String>>,
) {
    for (owner, fields) in source {
        target
            .entry(owner.clone())
            .or_default()
            .extend(fields.iter().cloned());
    }
}

pub struct TypeRef {
    pub qualifier: Option<String>,
    pub name: Option<String>,
}

fn same_go_package(graph: &GoProjectGraph, left: &ProjectFile, right: &ProjectFile) -> bool {
    if left.parent() != right.parent() {
        return false;
    }
    let Some(left_package) = graph.package_name_of(left) else {
        return false;
    };
    let Some(right_package) = graph.package_name_of(right) else {
        return false;
    };
    left_package == right_package
}
