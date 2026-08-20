//! Go's usage-graph resolution indexes.
//!
//! [`GoProjectGraph`] holds parsed trees for one query's candidate set;
//! [`GoEdgeIndex`] is its tree-free counterpart for the whole-workspace
//! inverted pass. Both are built from a [`GoGraphSource`]: the core capability
//! traits that answer the analyzer-side questions, plus the Go workspace path
//! index. No analyzer handle appears here -- `brokk-bifrost-analysis` downcasts
//! once and hands the pieces over.

use crate::declarations::{
    collect_go_import_infos, go_embedded_type_nodes, go_field_declaration_is_embedded,
    go_field_inline_container_type, go_structured_type_identity,
    parse_go_file_with_package_name as parse_go_declarations,
};
use crate::graph::ast::{
    CompositeLiteralContainerStep, field_owner_token, first_named_child, selector_parts,
    type_ref_from_node,
};
use crate::imports::{default_go_import_local_name, go_import_path};
use crate::packages::{GO_MODULE_SCOPE_SEGMENT, GoWorkspacePathIndex};
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeAliasProvider};
use brokk_bifrost_core::analyzer::common::language_for_file;
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
use tree_sitter::{Node, Parser, Tree};

/// Everything Go graph resolution needs from the analyzer, as the core
/// capability traits that answer it plus this crate's workspace path index.
///
/// Grouped because the same four references thread through every index build;
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
}

type NamespacePackages = (HashMap<String, Vec<String>>, Vec<String>);

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
        self.edge_index.package_name_of(file)
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
/// and embedded-field promotion links. Built by parsing each file once and then
/// dropping every tree, so edge scans retain only compact maps; source trees are
/// re-parsed on demand inside each per-file walk and dropped immediately.
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
                    if self.non_alias_type_fqns.contains(&candidate) {
                        owners.push(candidate);
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

/// Build the tree-free [`GoEdgeIndex`] over `files`: parse each Go file once to
/// collect package clauses, constructor-return facts, and embedded-member
/// promotion metadata, then drop those trees before returning. `None` when there
/// are no Go files.
pub fn build_go_edge_index(
    source: GoGraphSource<'_>,
    files: &[ProjectFile],
) -> Option<GoEdgeIndex> {
    let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::build");
    let go_files: Vec<ProjectFile> = files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .collect();

    let parsed_files: Vec<_> = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::parse_files");
        go_files
            .par_iter()
            .filter_map(|file| Some((file.clone(), parse_go_file(file)?)))
            .collect()
    };
    if parsed_files.is_empty() {
        return None;
    }
    let parsed_refs: Vec<_> = parsed_files
        .iter()
        .map(|(file, parsed)| (file.clone(), parsed))
        .collect();
    Some(build_go_edge_index_from_parsed(source, &parsed_refs))
}

fn build_go_edge_index_from_parsed(
    source: GoGraphSource<'_>,
    parsed_files: &[(ProjectFile, &ParsedFile)],
) -> GoEdgeIndex {
    let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::collect_facts");
    let package_names: HashMap<ProjectFile, String> = parsed_files
        .iter()
        .map(|(file, parsed)| (file.clone(), parsed.package_name.clone()))
        .collect();
    let canonical_package_names: HashMap<ProjectFile, String> = package_names
        .iter()
        .map(|(file, declared)| {
            (
                file.clone(),
                source
                    .workspace_paths
                    .canonical_package_name(file, declared),
            )
        })
        .collect();
    let mut constructor_return_types: HashMap<String, Vec<String>> = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::constructors");
        let mut constructor_return_types: HashMap<String, Vec<String>> = HashMap::default();
        for (file, parsed) in parsed_files {
            let package_fqn = canonical_package_names
                .get(file)
                .cloned()
                .unwrap_or_default();
            for (function, owner) in
                collect_constructor_returns(parsed.tree.root_node(), &parsed.source)
            {
                constructor_return_types
                    .entry(format!("{package_fqn}.{function}"))
                    .or_default()
                    .push(format!("{package_fqn}.{owner}"));
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
        let dir_index = build_parent_dir_index(package_names.keys());
        let mut namespace_packages_by_file = HashMap::default();
        let mut import_binding_names_by_file = HashMap::default();
        for (file, parsed) in parsed_files {
            let (namespace_packages, import_binding_names) = namespace_package_facts_from_imports(
                file,
                &parsed.imports,
                &dir_index,
                source.workspace_paths,
                |target| package_names.get(target).cloned(),
            );
            namespace_packages_by_file.insert(file.clone(), namespace_packages);
            import_binding_names_by_file.insert(file.clone(), import_binding_names);
        }
        (namespace_packages_by_file, import_binding_names_by_file)
    };
    let type_alias_targets = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::aliases");
        collect_go_type_alias_targets(
            parsed_files,
            &canonical_package_names,
            &namespace_packages_by_file,
        )
    };
    let underlying_types_by_fqn = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::underlying_types");
        collect_go_underlying_type_facts(parsed_files, &canonical_package_names)
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
        collect_go_declaration_facts(parsed_files, &canonical_package_names)
    };
    let non_alias_type_fqns = declaration_facts
        .type_fqns
        .iter()
        .filter(|fqn| !type_alias_targets.contains_key(*fqn))
        .cloned()
        .collect();
    let field_type_facts = {
        let _scope = brokk_bifrost_core::profiling::scope("go_edge_index::fields");
        collect_go_field_type_facts(
            parsed_files,
            &canonical_package_names,
            &namespace_packages_by_file,
            &declaration_facts.type_fqns,
        )
    };

    GoEdgeIndex {
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
    }
}

fn collect_go_underlying_type_facts(
    parsed_files: &[(ProjectFile, &ParsedFile)],
    canonical_package_names: &HashMap<ProjectFile, String>,
) -> HashMap<String, Vec<GoUnderlyingTypeFact>> {
    let mut facts: HashMap<String, Vec<GoUnderlyingTypeFact>> = HashMap::default();
    for (file, parsed) in parsed_files {
        let package = canonical_package_names
            .get(file)
            .cloned()
            .unwrap_or_default();
        let mut stack = vec![parsed.tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "type_spec"
                && go_type_spec_is_file_scope(node)
                && let (Some(name_node), Some(type_node)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("type"),
                )
                && let Some(identity) = go_structured_type_identity(type_node, &parsed.source)
            {
                facts
                    .entry(format!(
                        "{package}.{}",
                        node_text(name_node, &parsed.source)
                    ))
                    .or_default()
                    .push(GoUnderlyingTypeFact {
                        file: file.clone(),
                        package: package.clone(),
                        identity,
                    });
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    facts
}

fn go_type_spec_is_file_scope(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let declaration = if parent.kind() == "type_declaration" {
        parent
    } else if parent.kind() == "type_spec_list" {
        let Some(declaration) = parent.parent() else {
            return false;
        };
        if declaration.kind() != "type_declaration" {
            return false;
        }
        declaration
    } else {
        return false;
    };
    declaration
        .parent()
        .is_some_and(|parent| parent.kind() == "source_file")
}

#[derive(Default)]
struct GoDeclarationFacts {
    type_fqns: HashSet<String>,
    type_units: Vec<CodeUnit>,
    direct_member_fqns: HashMap<String, HashMap<String, Vec<String>>>,
}

fn collect_go_declaration_facts(
    parsed_files: &[(ProjectFile, &ParsedFile)],
    canonical_package_names: &HashMap<ProjectFile, String>,
) -> GoDeclarationFacts {
    parsed_files
        .par_iter()
        .map(|(file, parsed)| {
            let Some(package_name) = canonical_package_names.get(file) else {
                return GoDeclarationFacts::default();
            };
            let declarations = parse_go_declarations(
                file,
                &parsed.source,
                &parsed.tree,
                parsed.package_name.clone(),
                package_name.clone(),
            );
            let mut facts = GoDeclarationFacts::default();
            // Every declaration the file parse produced, not just the
            // top-level roots and their recorded children. A Go method whose
            // receiver type is declared in another file of the same package
            // (`func (c *Context) BindWith(...)` in `deprecated.go` against
            // `type Context` in `context.go`) hangs off a synthetic owner that
            // this file never declares, so it is reachable through neither
            // `top_level_declarations` nor `children`. Dropping it lost the
            // owner's member entry and made every call through the receiver
            // unresolvable.
            // Sorted so the per-owner member lists stay in a stable order; the
            // parse keeps its declarations in a hash set.
            let mut units: Vec<&CodeUnit> = declarations.declarations().iter().collect();
            units.sort();
            for unit in units {
                let fqn = unit.fq_name();
                if unit.is_class() {
                    facts.type_fqns.insert(fqn.clone());
                    facts.type_units.push(unit.clone());
                }
                if !(unit.is_function() || unit.is_field()) {
                    continue;
                }
                let Some(owner) = brokk_bifrost_core::analyzer::default_parent_fq_name(unit) else {
                    continue;
                };
                facts
                    .direct_member_fqns
                    .entry(owner)
                    .or_default()
                    .entry(unit.identifier().to_string())
                    .or_default()
                    .push(fqn);
            }
            facts
        })
        .reduce(GoDeclarationFacts::default, |mut combined, facts| {
            combined.type_fqns.extend(facts.type_fqns);
            combined.type_units.extend(facts.type_units);
            for (owner, members) in facts.direct_member_fqns {
                let combined_members = combined.direct_member_fqns.entry(owner).or_default();
                for (member, fqns) in members {
                    combined_members.entry(member).or_default().extend(fqns);
                }
            }
            combined
        })
}

fn collect_go_type_alias_targets(
    parsed_files: &[(ProjectFile, &ParsedFile)],
    canonical_package_names: &HashMap<ProjectFile, String>,
    namespace_packages_by_file: &HashMap<ProjectFile, NamespacePackages>,
) -> HashMap<String, String> {
    let mut aliases = HashMap::default();
    for (file, parsed) in parsed_files {
        let package = canonical_package_names
            .get(file)
            .cloned()
            .unwrap_or_default();
        let mut stack = vec![parsed.tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "type_alias"
                && let (Some(name_node), Some(type_node)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("type"),
                )
                && let Some(ty) = type_ref_from_node(type_node, &parsed.source)
                && let Some(name) = ty.name
            {
                let target = match ty.qualifier {
                    None => Some(format!("{package}.{name}")),
                    Some(qualifier) => namespace_packages_by_file
                        .get(file)
                        .and_then(|(packages, _)| packages.get(&qualifier))
                        .and_then(|packages| {
                            let mut packages = packages.iter();
                            let first = packages.next()?;
                            packages.next().is_none().then(|| format!("{first}.{name}"))
                        }),
                };
                if let Some(target) = target {
                    aliases.insert(
                        format!("{package}.{}", node_text(name_node, &parsed.source)),
                        target,
                    );
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    aliases
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
struct GoFieldTypeFacts {
    /// Embedded field/interface type fqns per owner, for member promotion.
    embedded_by_owner: HashMap<String, Vec<String>>,
    /// Declared type fqn(s) per (owner fqn, field name), for named and embedded
    /// struct fields whose type resolves to a workspace type. Lets a scan carry
    /// a field-derived local (`s := pi.field`) forward as the field's type.
    field_types_by_owner: HashMap<String, HashMap<String, Vec<String>>>,
}

fn collect_go_field_type_facts(
    parsed_files: &[(ProjectFile, &ParsedFile)],
    canonical_package_names: &HashMap<ProjectFile, String>,
    namespace_packages_by_file: &HashMap<ProjectFile, NamespacePackages>,
    type_fqns: &HashSet<String>,
) -> GoFieldTypeFacts {
    let resolver = GoEdgeTypeResolver {
        canonical_package_names,
        namespace_packages_by_file,
        type_fqns,
    };
    let mut facts = parsed_files
        .par_iter()
        .map(|(file, parsed)| {
            let mut facts = GoFieldTypeFacts::default();
            if canonical_package_names.contains_key(file) {
                collect_go_embedded_interface_type_fqns(
                    file,
                    parsed,
                    &resolver,
                    &mut facts.embedded_by_owner,
                );
                collect_go_struct_field_type_facts(
                    file,
                    parsed,
                    &resolver,
                    &mut facts.embedded_by_owner,
                    &mut facts.field_types_by_owner,
                );
            }
            facts
        })
        .reduce(GoFieldTypeFacts::default, |mut combined, facts| {
            for (owner, embedded) in facts.embedded_by_owner {
                combined
                    .embedded_by_owner
                    .entry(owner)
                    .or_default()
                    .extend(embedded);
            }
            for (owner, fields) in facts.field_types_by_owner {
                let combined_fields = combined.field_types_by_owner.entry(owner).or_default();
                for (field, types) in fields {
                    combined_fields.entry(field).or_default().extend(types);
                }
            }
            combined
        });
    for embedded in facts.embedded_by_owner.values_mut() {
        embedded.sort();
        embedded.dedup();
    }
    for fields in facts.field_types_by_owner.values_mut() {
        for field_types in fields.values_mut() {
            field_types.sort();
            field_types.dedup();
        }
    }
    facts
}

fn collect_go_struct_field_type_facts(
    file: &ProjectFile,
    parsed: &ParsedFile,
    resolver: &GoEdgeTypeResolver<'_>,
    embedded_by_owner: &mut HashMap<String, Vec<String>>,
    field_types_by_owner: &mut HashMap<String, HashMap<String, Vec<String>>>,
) {
    let Some(package) = resolver.canonical_package_names.get(file) else {
        return;
    };
    let mut pending = Vec::new();
    let mut nodes = vec![parsed.tree.root_node()];
    while let Some(node) = nodes.pop() {
        if node.kind() == "type_spec"
            && go_type_spec_is_file_scope(node)
            && let (Some(name), Some(ty)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            )
            && ty.kind() == "struct_type"
        {
            pending.push((ty, format!("{package}.{}", node_text(name, &parsed.source))));
        }
        let mut cursor = node.walk();
        nodes.extend(node.named_children(&mut cursor));
    }

    while let Some((container, owner_fqn)) = pending.pop() {
        let mut nodes = vec![container];
        while let Some(node) = nodes.pop() {
            if node.kind() != "field_declaration" {
                let mut cursor = node.walk();
                nodes.extend(node.named_children(&mut cursor));
                continue;
            }
            let Some(type_node) = node.child_by_field_name("type") else {
                continue;
            };
            let type_text = node_text(type_node, &parsed.source).trim();
            let mut cursor = node.walk();
            let mut field_names: Vec<String> = node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "field_identifier")
                .map(|child| node_text(child, &parsed.source).to_string())
                .collect();
            let embedded = field_names.is_empty() && go_field_declaration_is_embedded(node);
            if embedded && let Some(field_name) = go_simple_type_name(type_text) {
                field_names.push(field_name.to_string());
            }
            let resolved = resolver.resolve_field_type_fqn(file, &owner_fqn, type_text);
            for field_name in field_names {
                if let Some(field_type_fqn) = resolved.as_ref() {
                    field_types_by_owner
                        .entry(owner_fqn.clone())
                        .or_default()
                        .entry(field_name.clone())
                        .or_default()
                        .push(field_type_fqn.clone());
                    if embedded {
                        embedded_by_owner
                            .entry(owner_fqn.clone())
                            .or_default()
                            .push(field_type_fqn.clone());
                    }
                }
                if let Some(nested) = go_field_inline_container_type(node) {
                    pending.push((nested, format!("{owner_fqn}.{field_name}")));
                }
            }
        }
    }
}

fn collect_go_embedded_interface_type_fqns(
    file: &ProjectFile,
    parsed: &ParsedFile,
    resolver: &GoEdgeTypeResolver<'_>,
    embedded_by_owner: &mut HashMap<String, Vec<String>>,
) {
    let Some(package_fqn) = resolver.canonical_package_names.get(file) else {
        return;
    };
    let mut stack = vec![parsed.tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_spec"
            && let (Some(name_node), Some(type_node)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            )
            && type_node.kind() == "interface_type"
        {
            let owner_name = node_text(name_node, &parsed.source);
            if !owner_name.is_empty() {
                let owner_fqn = format!("{package_fqn}.{owner_name}");
                for embedded in go_embedded_type_nodes(type_node) {
                    let type_text = node_text(embedded, &parsed.source).trim();
                    let Some(embedded_fqn) =
                        resolver.resolve_field_type_fqn(file, &owner_fqn, type_text)
                    else {
                        continue;
                    };
                    embedded_by_owner
                        .entry(owner_fqn.clone())
                        .or_default()
                        .push(embedded_fqn);
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

pub fn go_embedded_field_unit_type_text(
    index: &dyn CodeUnitIndex,
    field: &CodeUnit,
    parsed: Option<&ParsedFile>,
) -> Option<String> {
    let parsed_file;
    let parsed = match parsed {
        Some(parsed) => parsed,
        None => {
            parsed_file = parse_go_file(field.source())?;
            &parsed_file
        }
    };
    if !go_field_unit_is_embedded(index, field, parsed) {
        return None;
    }
    let field_name = field.identifier().to_string();
    let type_text = go_field_unit_type_text(index, field, &field_name)?;
    let simple = go_simple_type_name(&type_text)?;
    (simple == field_name).then_some(type_text)
}

fn go_field_unit_is_embedded(
    index: &dyn CodeUnitIndex,
    field: &CodeUnit,
    parsed: &ParsedFile,
) -> bool {
    let Some(range) = index.ranges(field).into_iter().next() else {
        return false;
    };
    let Some(node) = parsed
        .tree
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)
    else {
        return false;
    };
    go_enclosing_field_declaration(node).is_some_and(go_field_declaration_is_embedded)
}

fn go_enclosing_field_declaration(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "field_declaration" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

struct GoEdgeTypeResolver<'a> {
    canonical_package_names: &'a HashMap<ProjectFile, String>,
    namespace_packages_by_file: &'a HashMap<ProjectFile, NamespacePackages>,
    type_fqns: &'a HashSet<String>,
}

impl GoEdgeTypeResolver<'_> {
    fn resolve_field_type_fqn(
        &self,
        file: &ProjectFile,
        owner_fqn: &str,
        type_text: &str,
    ) -> Option<String> {
        if let Some((Some(qualifier), name)) = go_type_name_parts(type_text) {
            return self
                .namespace_packages_by_file
                .get(file)
                .and_then(|(namespaces, _)| namespaces.get(qualifier))
                .and_then(|packages| {
                    packages.iter().find_map(|package| {
                        let fqn = format!("{package}.{name}");
                        self.type_fqns.contains(&fqn).then_some(fqn)
                    })
                });
        }
        // fqname-M4: `owner_fqn` here is a plain string (the field's owner's
        // rendered fqn, one level further removed than the CodeUnit-owner pop
        // above); popping its OWN owner (the field owner's package) needs a
        // live CodeUnit to call `default_parent_fq_name` on, and `owner_fqn`'s
        // Go import-path head can itself contain literal dots (`github.com`),
        // so the generic segment splitter would over-split it (same reasoning
        // as the go.rs `go_resolve_go_field_type_fqn` deferral). Threading the
        // owner CodeUnit through this call chain instead of a pre-flattened
        // string is a signature change across `collect_go_embedded_field_type_fqns`
        // and this resolver, not a mechanical rewrite here.
        let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
        let name = go_simple_type_name(type_text)?;
        let fqn = format!("{package}.{name}");
        self.type_fqns.contains(&fqn).then_some(fqn)
    }
}

fn collect_constructor_returns(root: Node<'_>, source: &str) -> Vec<(String, String)> {
    let mut returns = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "function_declaration" {
            continue;
        }
        let (Some(name_node), Some(result)) = (
            child.child_by_field_name("name"),
            child.child_by_field_name("result"),
        ) else {
            continue;
        };
        let Some(owner) = first_result_type_ref(result, source)
            .filter(|ty| ty.qualifier.is_none())
            .and_then(|ty| ty.name)
        else {
            continue;
        };
        returns.push((node_text(name_node, source).to_string(), owner));
    }
    returns
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
) -> NamespacePackages {
    let imports = source.imports.import_info_of(source.token, file);
    namespace_packages_from_imports(
        file,
        &imports,
        dir_index,
        workspace_paths,
        target_package_name,
    )
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
    target_package_name: impl Fn(&ProjectFile) -> Option<String>,
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
                        None => declared_package_name(&path).or_else(|| import.identifier.clone()),
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
) -> NamespacePackages {
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
pub fn resolve_go_import_bindings(
    source: GoGraphSource<'_>,
    file: &ProjectFile,
    package_names: &HashMap<ProjectFile, String>,
    declared_package_name: impl Fn(&str) -> Option<String>,
) -> GoImportBindings {
    let dir_index = build_parent_dir_index(package_names.keys());
    let imports = source.imports.import_info_of(source.token, file);
    import_bindings_from_imports(
        file,
        &imports,
        &dir_index,
        source.workspace_paths,
        |target| package_names.get(target).cloned(),
        declared_package_name,
    )
}

fn parse_go_source(source: String) -> Option<ParsedFile> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let package_name = package_name(tree.root_node(), &source);
    let line_starts = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    let imports = collect_go_import_infos(tree.root_node(), &source);
    Some(ParsedFile {
        source: Arc::new(source),
        tree,
        line_starts,
        imports,
        package_name,
    })
}

fn parse_go_file(file: &ProjectFile) -> Option<ParsedFile> {
    parse_go_source(file.read_to_string().ok()?)
}

pub fn build_go_graph(
    source: GoGraphSource<'_>,
    candidate_files: &HashSet<ProjectFile>,
    resolution_files: &[ProjectFile],
    target_file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> GoProjectGraph {
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
        let parsed_file = match parse_go_file(&file) {
            Some(parsed_file) => parsed_file,
            None => continue,
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

    let parsed_refs: Vec<_> = all_parsed
        .iter()
        .map(|(file, parsed)| (file.clone(), parsed))
        .collect();
    let edge_index = Arc::new(build_go_edge_index_from_parsed(source, &parsed_refs));

    // Only candidate and target trees survive the build. The remaining parses
    // contributed compact cross-workspace type/import facts above and are
    // dropped here, so a narrow query does not retain the whole workspace CST.
    let parsed = all_parsed
        .into_iter()
        .filter(|(file, _)| scoped_files.contains(file))
        .map(|(file, parsed)| (file, Arc::new(parsed)))
        .collect();

    GoProjectGraph { parsed, edge_index }
}

/// Build the tree-holding part of a per-symbol graph against a reusable
/// whole-workspace resolution index. Only candidate and target files are
/// parsed; package, import, type, and member facts come from `edge_index`.
pub fn build_go_graph_with_edge_index(
    edge_index: Arc<GoEdgeIndex>,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> GoProjectGraph {
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
        scoped_files
            .into_par_iter()
            .filter_map(|file| {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return None;
                }
                let source = file.read_to_string().ok()?;
                if &file != target_file
                    && !source.contains(identifier)
                    && !owner.as_deref().is_some_and(|owner| source.contains(owner))
                {
                    return None;
                }
                Some((file, Arc::new(parse_go_source(source)?)))
            })
            .collect()
    };
    GoProjectGraph { parsed, edge_index }
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
        }
    }
    resolved.sort();
    resolved.dedup();
    resolved
}

fn package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if matches!(package_child.kind(), "package_identifier" | "identifier") {
                return node_text(package_child, source).to_string();
            }
        }
    }
    String::new()
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
    graph: &GoProjectGraph,
    target: &CodeUnit,
) -> bool {
    let Some(owner) = source.index.parent_of(target) else {
        return false;
    };
    let Some(parsed) = graph.parsed_file(owner.source()) else {
        return false;
    };
    let mut stack = vec![parsed.tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_spec"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, &parsed.source) == owner.identifier())
        {
            return node
                .child_by_field_name("type")
                .is_some_and(|ty| ty.kind() == "interface_type");
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
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
    for type_file in graph.parsed.keys() {
        let Some(parsed) = graph.parsed_file(type_file) else {
            continue;
        };
        let mut by_owner = HashMap::default();
        let mut cursor = parsed.tree.root_node().walk();
        for child in parsed.tree.root_node().named_children(&mut cursor) {
            if child.kind() != "type_declaration" {
                continue;
            }
            collect_struct_fields_with_compatible_types(
                graph,
                type_file,
                parsed.source.as_str(),
                child,
                compatible_receiver_types,
                &mut by_owner,
            );
        }
        if !by_owner.is_empty() {
            by_file.insert(type_file.clone(), by_owner);
        }
    }
    by_file
}

fn collect_struct_fields_with_compatible_types(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
    by_owner: &mut HashMap<String, HashSet<String>>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_spec" | "type_alias" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let Some(type_node) = child.child_by_field_name("type") else {
                    continue;
                };
                if type_node.kind() != "struct_type" {
                    continue;
                }
                let owner = node_text(name_node, source).to_string();
                let fields = struct_fields_with_compatible_types(
                    graph,
                    type_file,
                    source,
                    type_node,
                    compatible_receiver_types,
                );
                if !fields.is_empty() {
                    by_owner.entry(owner).or_default().extend(fields);
                }
            }
            "type_spec_list" => collect_struct_fields_with_compatible_types(
                graph,
                type_file,
                source,
                child,
                compatible_receiver_types,
                by_owner,
            ),
            _ => {}
        }
    }
}

fn struct_fields_with_compatible_types(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    source: &str,
    struct_node: Node<'_>,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<String> {
    let mut fields = HashSet::default();
    let mut stack = vec![struct_node];
    while let Some(current) = stack.pop() {
        if current.kind() == "field_declaration"
            && let Some(type_node) = current.child_by_field_name("type")
            && let Some(ty) = type_ref_from_node(type_node, source)
            && type_ref_matches_compatible_receiver(
                graph,
                type_file,
                &ty,
                compatible_receiver_types,
            )
        {
            let mut names = current.walk();
            for name_node in current.children_by_field_name("name", &mut names) {
                fields.insert(node_text(name_node, source).to_string());
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    fields
}

fn type_ref_matches_compatible_receiver(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    ty: &TypeRef,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> bool {
    let Some(name) = ty.name.as_deref() else {
        return false;
    };
    match ty.qualifier.as_deref() {
        None => compatible_receiver_types
            .iter()
            .any(|(receiver_file, receiver)| {
                receiver == name && same_go_package(graph, type_file, receiver_file)
            }),
        Some(qualifier) => compatible_receiver_types
            .iter()
            .filter(|(_, receiver)| receiver == name)
            .any(|(receiver_file, receiver)| {
                let seeds = receiver_type_seeds(graph, receiver_file, receiver);
                graph
                    .matching_edges_for_importer(type_file, &seeds)
                    .into_iter()
                    .any(|edge| {
                        edge.local_name == qualifier
                            && matches!(
                                edge.kind,
                                ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_)
                            )
                    })
            }),
    }
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

fn first_result_type_ref(result: Node<'_>, source: &str) -> Option<TypeRef> {
    if let Some(ty) = type_ref_from_node(result, source) {
        return Some(ty);
    }
    if result.kind() == "parameter_list"
        && let Some(first) = first_named_child(result)
    {
        let type_node = first.child_by_field_name("type").unwrap_or(first);
        return type_ref_from_node(type_node, source);
    }
    None
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

fn go_field_unit_type_text(
    index: &dyn CodeUnitIndex,
    field_unit: &CodeUnit,
    field: &str,
) -> Option<String> {
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| index.signatures(field_unit).first().cloned())?;
    let trimmed = signature.trim();
    if let Some(suffix) = trimmed.strip_prefix(field)
        && suffix.chars().next().is_some_and(char::is_whitespace)
    {
        return Some(suffix.trim().to_string());
    }
    let simple = go_simple_type_name(trimmed)?;
    (simple == field).then(|| trimmed.to_string())
}

pub fn go_simple_type_name(type_text: &str) -> Option<&str> {
    go_type_name_parts(type_text).map(|(_, name)| name)
}

pub fn go_type_name_parts(type_text: &str) -> Option<(Option<&str>, &str)> {
    let trimmed = type_text
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("[]")
        .trim();
    let raw = trimmed
        .split(['[', '{', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed);
    let (qualifier, name) = raw
        .rsplit_once('.')
        .map(|(qualifier, name)| (Some(qualifier.trim()), name))
        .unwrap_or((None, raw));
    let name = name.trim();
    (!name.is_empty()).then_some((qualifier.filter(|value| !value.is_empty()), name))
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
    let Some(left_parsed) = graph.parsed.get(left) else {
        return false;
    };
    let Some(right_parsed) = graph.parsed.get(right) else {
        return false;
    };
    left_parsed.package_name == right_parsed.package_name
}
