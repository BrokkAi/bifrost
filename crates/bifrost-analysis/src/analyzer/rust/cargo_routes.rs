use crate::analyzer::ProjectFile;
use crate::hash::HashMap;
use semver::{Version, VersionReq};
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tree_sitter::{Node, Parser};

use super::declarations::{
    RustRulesItemMacroDefinition, rust_macro_invocation_arguments, rust_package_name,
    rust_unqualified_macro_invocation_name,
};
use super::facts::{
    RustMacroGateFact, RustModuleRouteFact, RustModuleRouteFacts, RustModuleScopeFact,
};
use super::imports::{
    RustVisibility, rust_external_module_route, rust_external_module_segments, rust_item_visibility,
};

// How many times one Cargo-route build has iterated the complete analyzed
// file set (issue #1817).
//
// Before #1817 the build ran one such sweep per crate -- twice, once in each
// membership pass -- and one per Cargo target, on top of the passes
// themselves, so its cost grew as workspace size times workspace topology and
// reached 9-19 s on the rustc tree. Every loop whose length is the analyzed
// file set reports here, and
// `a_cargo_route_build_sweeps_the_workspace_a_bounded_number_of_times` pins
// the total against a workspace whose crate and target count grows while its
// file count does not.
//
// Loops over the module-declaration list (`build_test_only_files_while`) are
// deliberately not counted: that list is not the file set, and it was one
// bounded pass before this change and after it.
//
// Thread-local rather than a process-global counter or a field, because the
// build is one sequential call stack and the pin then does not depend on
// nextest's process-per-test isolation to stay meaningful.
#[cfg(test)]
thread_local! {
    static WORKSPACE_FILE_SWEEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_workspace_file_sweep() {
    WORKSPACE_FILE_SWEEPS.with(|sweeps| sweeps.set(sweeps.get().saturating_add(1)));
}

#[cfg(not(test))]
fn note_workspace_file_sweep() {}

#[cfg(test)]
fn workspace_file_sweeps_of(build: impl FnOnce()) -> usize {
    WORKSPACE_FILE_SWEEPS.with(|sweeps| sweeps.set(0));
    build();
    WORKSPACE_FILE_SWEEPS.with(std::cell::Cell::get)
}

fn read_manifest(root: &Path, directory: &Path) -> Option<toml::Value> {
    std::fs::read_to_string(root.join(directory).join("Cargo.toml"))
        .ok()
        .and_then(|source| toml::from_str(&source).ok())
}

fn cargo_crate(
    root: &Path,
    directory: PathBuf,
    manifest: toml::Value,
    manifests: &HashMap<PathBuf, toml::Value>,
) -> Option<CargoCrate> {
    let package_name = manifest
        .get("package")?
        .get("name")?
        .as_str()
        .map(str::to_owned)?;
    let edition = cargo_package_edition(root, &directory, &manifest, manifests);
    let explicit_library = manifest.get("lib");
    let library = if explicit_library.is_some()
        || cargo_auto_discovery_enabled(&manifest, "autolib", &edition)
    {
        let library_table = match explicit_library {
            Some(library) => Some(library.as_table()?),
            None => None,
        };
        let library_name = library_table
            .and_then(|library| library.get("name"))
            .and_then(toml::Value::as_str)
            .map(normalize_crate_name)
            .unwrap_or_else(|| normalize_crate_name(&package_name));
        let library_path = library_table
            .and_then(|library| library.get("path"))
            .and_then(toml::Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("src/lib.rs"));
        match workspace_relative_path(root, &directory, &library_path) {
            Some(library_path) => {
                let root_file = ProjectFile::new(root.to_path_buf(), library_path);
                Some(CargoLibrary {
                    name: library_name,
                    root_package: rust_package_name(&root_file),
                    root_file,
                })
            }
            None if explicit_library.is_some() => return None,
            None => None,
        }
    } else {
        None
    };
    Some(CargoCrate {
        directory,
        package_name,
        library,
        edition,
        manifest,
    })
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RustCargoRouteIndex {
    routes_by_manifest_and_name: HashMap<(PathBuf, String), Vec<RustCargoRoute>>,
    declared_dependencies_by_manifest_and_name:
        HashMap<(PathBuf, String), Vec<RustCargoDependencyKind>>,
    target_roots_by_file: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>,
    targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>>,
    files_by_reachable_root: HashMap<ProjectFile, Vec<ProjectFile>>,
    external_module_declarations: Vec<RustCargoModuleDeclaration>,
    test_only_files: crate::hash::HashSet<ProjectFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RustCargoModuleDeclaration {
    pub(super) declaring_file: ProjectFile,
    pub(super) declaring_module: String,
    pub(super) target_file: ProjectFile,
    pub(super) visibility: RustVisibility,
    /// Whether the `mod x;` item carries a bare `#[cfg(test)]`, so the declared
    /// file is compiled into test builds only. See
    /// [`rust_declaration_is_bare_cfg_test_gated`] for why only the bare
    /// predicate counts.
    pub(super) test_gated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RustCargoRouteKind {
    CurrentLibrary,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustCargoTargetRelation {
    Shared,
    Disjoint,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RustCargoTargetKind {
    Library,
    Binary,
    Example,
    Test,
    Bench,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RustCargoTarget {
    manifest: PathBuf,
    kind: RustCargoTargetKind,
    development_capable: bool,
    edition: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RustCargoTargetSpec {
    kind: RustCargoTargetKind,
    development_capable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustCargoDependencyKind {
    Normal,
    Development,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustCargoRoute {
    package: String,
    root_file: ProjectFile,
    kind: RustCargoRouteKind,
    dependency_kind: Option<RustCargoDependencyKind>,
    target_predicate: Option<String>,
}

struct CargoCrate {
    directory: PathBuf,
    package_name: String,
    library: Option<CargoLibrary>,
    edition: String,
    manifest: toml::Value,
}

struct CargoLibrary {
    name: String,
    root_file: ProjectFile,
    root_package: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RustVisibleItemMacroDefinition {
    visible_after: usize,
    scope_start: usize,
    scope_end: usize,
    passthrough: bool,
}

impl RustCargoRouteIndex {
    /// Compose the index from the persisted per-file module-route facts.
    ///
    /// Before issue #1793 this hydrated and parsed every analyzed Rust file --
    /// 34-44 s on the rustc tree, once per analyzer generation, charged inside
    /// the three-second `scan_usages` budget. The syntax those parses were read
    /// for is now `rust_module_scopes` / `rust_module_routes` /
    /// `rust_module_route_gates` / `rust_item_macros`, written when the file was
    /// analyzed, and `module_route_facts` is one batched read of them. What
    /// remains is the manifest topology, which is measured cheap (the rustc
    /// tree's 347 manifests parse in 4.9 ms warm), and the path resolution and
    /// existence checks the content-keyed rows deliberately do not carry.
    ///
    /// A file missing from `module_route_facts` contributes no module edges,
    /// which is exactly what a failed hydration did before.
    ///
    /// Issue #1817 is the orchestration around that read. It used to rediscover
    /// the whole Cargo topology inside each of its two module-membership
    /// passes, search the whole file list once per crate for that crate's
    /// target roots, and sweep the whole file list once per target for the
    /// files the target owns -- so the build grew as workspace times topology
    /// and cost 9-19 s on the rustc tree with the parsing already gone. The
    /// four stages below each cost the workspace once: the topology is
    /// discovered a single time, and every per-target stage iterates the files
    /// that target owns.
    pub(super) fn build_while(
        files: &[ProjectFile],
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<Self> {
        keep_going().then_some(())?;
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Some(Self::default());
        };
        let manifest_directories = discover_cargo_manifest_directories(root, files, keep_going)?;
        if manifest_directories.is_empty() {
            // Without a Cargo manifest there are no target, dependency, or
            // edition identities for this index to model. Stop before the
            // manifest builder reaches the same empty result the long way.
            return Some(Self::default());
        }
        let topology =
            CargoManifestTopology::discover(root, files, manifest_directories, keep_going)?;
        let mut edges = ModuleEdgeCache::default();

        // Stage 1: which target roots reach which file, before any item macro
        // is known to expand. Only the reachability is taken from this walk;
        // the manifest half of the index does not depend on it, which is why
        // the topology is discovered once rather than once per walk.
        let physical_target_roots_by_file = topology.target_memberships_while(
            |file, is_crate_root, _target| {
                edges
                    .gate_free(file, module_route_facts, is_crate_root)
                    .iter()
                    .map(|edge| edge.file.clone())
                    .collect()
            },
            keep_going,
        )?;
        let files_by_target = files_by_target_root(&physical_target_roots_by_file, keep_going)?;

        // Stage 2: where each item macro is visible. `#[macro_use]` climbs to
        // the files that declare the definition's module and descends into
        // everything they declare after it, and both directions stop at the
        // target boundary -- so one file reached through two targets can see
        // different macros, and the walk is per target.
        let mut passthrough_by_target_and_file: HashMap<
            (ProjectFile, ProjectFile),
            HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
        > = HashMap::default();
        for (target, target_files) in &files_by_target {
            keep_going().then_some(())?;
            let mut children_by_file: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>> =
                HashMap::default();
            let mut parents_by_file: HashMap<ProjectFile, Vec<(ProjectFile, bool, usize)>> =
                HashMap::default();
            for file in target_files {
                keep_going().then_some(())?;
                if !module_route_facts.contains_key(file) {
                    continue;
                }
                let file_edges = edges.gate_free(file, module_route_facts, file == target);
                for edge in file_edges.iter() {
                    keep_going().then_some(())?;
                    if physical_target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        parents_by_file.entry(edge.file.clone()).or_default().push((
                            file.clone(),
                            edge.imports_macros,
                            edge.visibility_start_byte,
                        ));
                    }
                }
                children_by_file.insert(file.clone(), file_edges);
            }

            for definition_file in target_files {
                keep_going().then_some(())?;
                let Some(definition_facts) = module_route_facts.get(definition_file) else {
                    continue;
                };
                for definition in &definition_facts.item_macros {
                    keep_going().then_some(())?;
                    let mut visible_files: HashMap<ProjectFile, usize> = HashMap::default();
                    let mut pending = vec![(definition_file.clone(), definition.visible_after)];
                    while let Some((file, visible_after)) = pending.pop() {
                        keep_going().then_some(())?;
                        if visible_files
                            .get(&file)
                            .is_some_and(|known_start| *known_start <= visible_after)
                        {
                            continue;
                        }
                        visible_files.insert(file.clone(), visible_after);
                        let local_scope = (file == *definition_file)
                            .then_some((definition.scope_start, definition.scope_end));
                        if local_scope.is_none_or(|(start, end)| {
                            module_route_facts
                                .get(&file)
                                .and_then(RustModuleRouteFacts::file_extent)
                                .is_some_and(|extent| extent == (start, end))
                        }) && let Some(parents) = parents_by_file.get(&file)
                        {
                            pending.extend(
                                parents
                                    .iter()
                                    .filter(|(_, imports_macros, _)| *imports_macros)
                                    .map(|(parent, _, import_start)| {
                                        (parent.clone(), *import_start)
                                    }),
                            );
                        }
                        if let Some(children) = children_by_file.get(&file) {
                            pending.extend(
                                children
                                    .iter()
                                    .filter(|edge| {
                                        edge.declaration_start_byte >= visible_after
                                            && local_scope.is_none_or(|(start, end)| {
                                                start <= edge.declaration_start_byte
                                                    && edge.declaration_start_byte < end
                                            })
                                    })
                                    .map(|edge| (edge.file.clone(), 0)),
                            );
                        }
                    }
                    for (file, visible_after) in visible_files {
                        keep_going().then_some(())?;
                        let (scope_start, scope_end) = if file == *definition_file {
                            (definition.scope_start, definition.scope_end)
                        } else {
                            let Some(extent) = module_route_facts
                                .get(&file)
                                .and_then(RustModuleRouteFacts::file_extent)
                            else {
                                continue;
                            };
                            extent
                        };
                        passthrough_by_target_and_file
                            .entry((target.clone(), file))
                            .or_default()
                            .entry(definition.name.clone())
                            .or_default()
                            .push(RustVisibleItemMacroDefinition {
                                visible_after,
                                scope_start,
                                scope_end,
                                passthrough: definition.passthrough,
                            });
                    }
                }
            }
        }

        // Stage 3: a `#[macro_use] mod child;` re-exports the macros its parent
        // could see into the child, so the visible set has to be pushed down
        // the module tree until it stops growing.
        for (target, target_files) in &files_by_target {
            keep_going().then_some(())?;
            let mut pending = target_files.iter().cloned().collect::<VecDeque<_>>();
            let mut processed_binding_counts: HashMap<ProjectFile, usize> = HashMap::default();
            while let Some(file) = pending.pop_front() {
                keep_going().then_some(())?;
                let Some(facts) = module_route_facts.get(&file) else {
                    continue;
                };
                let key = (target.clone(), file.clone());
                let binding_count = passthrough_by_target_and_file
                    .get(&key)
                    .into_iter()
                    .flat_map(|bindings| bindings.values())
                    .map(Vec::len)
                    .sum();
                if processed_binding_counts.get(&file) == Some(&binding_count) {
                    continue;
                }
                processed_binding_counts.insert(file.clone(), binding_count);
                let bindings = passthrough_by_target_and_file
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                let file_edges = if bindings.is_empty() {
                    edges.gate_free(&file, module_route_facts, file == *target)
                } else {
                    Arc::new(module_child_edges(&file, facts, file == *target, &bindings))
                };
                for edge in file_edges.iter() {
                    keep_going().then_some(())?;
                    if physical_target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        continue;
                    }
                    let Some(child_facts) = module_route_facts.get(&edge.file) else {
                        continue;
                    };
                    let Some((child_start, child_end)) = child_facts.file_extent() else {
                        continue;
                    };
                    let child_bindings = passthrough_by_target_and_file
                        .entry((target.clone(), edge.file.clone()))
                        .or_default();
                    let before = child_bindings.values().map(Vec::len).sum::<usize>();
                    for (name, definitions) in &bindings {
                        keep_going().then_some(())?;
                        let Some(passthrough) = rust_latest_visible_item_macro(
                            definitions,
                            edge.declaration_start_byte,
                        ) else {
                            continue;
                        };
                        let inherited = RustVisibleItemMacroDefinition {
                            visible_after: 0,
                            scope_start: child_start,
                            scope_end: child_end,
                            passthrough,
                        };
                        let definitions = child_bindings.entry(name.clone()).or_default();
                        if !definitions.contains(&inherited) {
                            definitions.push(inherited);
                        }
                    }
                    for definition in &child_facts.item_macros {
                        keep_going().then_some(())?;
                        let local = RustVisibleItemMacroDefinition {
                            visible_after: definition.visible_after,
                            scope_start: definition.scope_start,
                            scope_end: definition.scope_end,
                            passthrough: definition.passthrough,
                        };
                        let definitions =
                            child_bindings.entry(definition.name.clone()).or_default();
                        if !definitions.contains(&local) {
                            definitions.push(local);
                        }
                    }
                    let after = child_bindings.values().map(Vec::len).sum::<usize>();
                    if after != before || !processed_binding_counts.contains_key(&edge.file) {
                        pending.push_back(edge.file.clone());
                    }
                }
            }
        }

        // Stage 4: the membership walk again, now with the macro-expanded
        // declarations, which is also where the declaration list the usage
        // walks read comes from.
        let no_passthrough_macros = HashMap::default();
        let mut external_module_declarations = Vec::new();
        let target_roots_by_file = topology.target_memberships_while(
            |file, is_crate_root, target| {
                let Some(facts) = module_route_facts.get(file) else {
                    return Vec::new();
                };
                let passthrough_macros = passthrough_by_target_and_file
                    .get(&(target.clone(), file.clone()))
                    .unwrap_or(&no_passthrough_macros);
                let file_edges = if passthrough_macros.is_empty() {
                    edges.gate_free(file, module_route_facts, is_crate_root)
                } else {
                    Arc::new(module_child_edges(
                        file,
                        facts,
                        is_crate_root,
                        passthrough_macros,
                    ))
                };
                external_module_declarations.extend(file_edges.iter().map(|edge| {
                    RustCargoModuleDeclaration {
                        declaring_file: file.clone(),
                        declaring_module: edge.declaring_module.clone(),
                        target_file: edge.file.clone(),
                        visibility: edge.visibility.clone(),
                        test_gated: edge.test_gated,
                    }
                }));
                file_edges.iter().map(|edge| edge.file.clone()).collect()
            },
            keep_going,
        )?;

        let mut index = topology.into_index(target_roots_by_file, keep_going)?;
        sort_and_dedup_external_module_declarations(&mut external_module_declarations);
        index.external_module_declarations = external_module_declarations;
        index.test_only_files = index.build_test_only_files_while(keep_going)?;
        Some(index)
    }

    /// The index over a caller-supplied module-edge function, with no macro
    /// expansion stage. Only the manifest topology and the membership it
    /// implies; the declaration list and the test-only complement stay empty,
    /// as they did before issue #1817.
    #[cfg(test)]
    fn build_from_module_children(
        files: &[ProjectFile],
        module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
    ) -> Self {
        let keep_going = || true;
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Self::default();
        };
        let manifest_directories = discover_cargo_manifest_directories(root, files, &keep_going)
            .expect("uninterrupted Cargo manifest discovery");
        let topology =
            CargoManifestTopology::discover(root, files, manifest_directories, &keep_going)
                .expect("uninterrupted Cargo topology discovery");
        let target_roots_by_file = topology
            .target_memberships_while(module_children, &keep_going)
            .expect("uninterrupted Cargo target membership walk");
        topology
            .into_index(target_roots_by_file, &keep_going)
            .expect("uninterrupted Rust Cargo manifest-route construction")
    }

    #[cfg(test)]
    fn build_from_disk(files: &[ProjectFile]) -> Self {
        Self::build_from_module_children(files, |file, is_crate_root, _target| {
            let Ok(source) = file.read_to_string() else {
                return Vec::new();
            };
            let mut parser = tree_sitter::Parser::new();
            if parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .is_err()
            {
                return Vec::new();
            }
            let Some(tree) = parser.parse(&source, None) else {
                return Vec::new();
            };
            rust_external_module_children(
                file,
                &source,
                tree.root_node(),
                is_crate_root,
                &HashMap::default(),
            )
        })
    }

    pub(super) fn candidates_in_same_target_root(
        &self,
        source_file: &ProjectFile,
        candidates: Vec<crate::analyzer::CodeUnit>,
    ) -> Option<Vec<crate::analyzer::CodeUnit>> {
        let source_roots = self.target_roots_by_file.get(source_file)?;
        let local: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                self.target_roots_by_file
                    .get(candidate.source())
                    .is_some_and(|candidate_roots| {
                        candidate_roots
                            .iter()
                            .any(|root| source_roots.contains(root))
                    })
            })
            .cloned()
            .collect();
        Some(local)
    }

    pub(super) fn target_roots_for_file(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        self.target_roots_by_file
            .get(file)
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    pub(super) fn file_uses_rust_2015_edition(&self, file: &ProjectFile) -> bool {
        let Some(roots) = self.target_roots_by_file.get(file) else {
            return false;
        };
        let mut targets = roots
            .iter()
            .filter_map(|root| self.targets_by_root.get(root))
            .flatten();
        let Some(first) = targets.next() else {
            return false;
        };
        first.edition == "2015" && targets.all(|target| target.edition == "2015")
    }

    pub(super) fn has_available_declared_dependency(
        &self,
        file: &ProjectFile,
        route_name: &str,
    ) -> bool {
        let normalized = normalize_crate_name(route_name);
        self.target_roots_by_file
            .get(file)
            .into_iter()
            .flatten()
            .filter_map(|root| self.targets_by_root.get(root))
            .flatten()
            .any(|target| {
                self.declared_dependencies_by_manifest_and_name
                    .get(&(target.manifest.clone(), normalized.clone()))
                    .is_some_and(|kinds| {
                        kinds
                            .iter()
                            .copied()
                            .any(|kind| cargo_dependency_available_to_target(kind, target))
                    })
            })
    }

    pub(super) fn external_module_declarations(&self) -> &[RustCargoModuleDeclaration] {
        &self.external_module_declarations
    }

    /// Whether `file` is compiled only into test builds, because every route
    /// that reaches it passes through a `#[cfg(test)] mod ...;` declaration.
    ///
    /// This is the file-level half of Rust test detection (#1546). Rust has no
    /// test filename or directory convention for the sibling test-module layout
    /// (`#[cfg(test)] mod tests;` in `mod.rs`, tests in `tests.rs`), and the
    /// declared file holds no local evidence -- its plain helper functions carry
    /// no attribute at all. The evidence lives on the parent's declaration, so
    /// it can only be read off the module graph.
    pub(super) fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.test_only_files.contains(file)
    }

    /// Files that no production build can reach.
    ///
    /// Rather than pushing test-ness down from the gated declarations, push
    /// *production reachability* down from the roots and take the complement.
    /// That is what makes the transitive case fall out for free: in
    /// `#[cfg(test)] mod tests;` -> `tests/mod.rs` -> un-gated `mod helpers;`
    /// -> `tests/helpers.rs`, the second edge carries no gate of its own, and
    /// `helpers.rs` is test-only purely because nothing production-reachable
    /// declares it.
    ///
    /// The seeds are every file that no external `mod` item declares -- crate
    /// and target roots, plus any file outside the module tree -- so a file is
    /// only ever classified test-only on positive evidence that some
    /// declaration reaches it.
    fn build_test_only_files_while(
        &self,
        keep_going: &impl Fn() -> bool,
    ) -> Option<crate::hash::HashSet<ProjectFile>> {
        let mut declared = crate::hash::HashSet::default();
        for declaration in &self.external_module_declarations {
            keep_going().then_some(())?;
            declared.insert(&declaration.target_file);
        }
        if declared.is_empty() {
            return Some(crate::hash::HashSet::default());
        }
        let mut production_children: HashMap<&ProjectFile, Vec<&ProjectFile>> = HashMap::default();
        let mut pending: Vec<&ProjectFile> = self.targets_by_root.keys().collect();
        for declaration in &self.external_module_declarations {
            keep_going().then_some(())?;
            if !declaration.test_gated {
                production_children
                    .entry(&declaration.declaring_file)
                    .or_default()
                    .push(&declaration.target_file);
            }
            if !declared.contains(&declaration.declaring_file) {
                pending.push(&declaration.declaring_file);
            }
        }
        let mut production: crate::hash::HashSet<&ProjectFile> = crate::hash::HashSet::default();
        while let Some(file) = pending.pop() {
            keep_going().then_some(())?;
            if !production.insert(file) {
                continue;
            }
            pending.extend(production_children.get(file).into_iter().flatten().copied());
        }
        let mut test_only = crate::hash::HashSet::default();
        for file in declared {
            keep_going().then_some(())?;
            if !production.contains(file) {
                test_only.insert(file.clone());
            }
        }
        Some(test_only)
    }

    pub(super) fn files_that_can_reference_target_of(
        &self,
        target_file: &ProjectFile,
    ) -> Vec<ProjectFile> {
        let Some(target_roots) = self.target_roots_by_file.get(target_file) else {
            return Vec::new();
        };
        let mut files = target_roots
            .iter()
            .flat_map(|root| {
                self.files_by_reachable_root
                    .get(root)
                    .into_iter()
                    .flatten()
                    .cloned()
            })
            .collect::<crate::hash::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    /// Every file that can name something in each target root, materialised
    /// per root.
    ///
    /// A file reaches its own target root and every root a Cargo route makes
    /// available to one of that root's targets. Which roots those are is a
    /// question about the root, not about the file, so it is answered once per
    /// root and then applied to that root's files (issue #1817). It used to be
    /// answered inside the per-file loop, by scanning every route entry in the
    /// workspace for each (file, root, target) triple.
    fn build_files_by_reachable_root_while(
        &self,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, Vec<ProjectFile>>> {
        let mut routes_by_manifest: HashMap<&Path, Vec<&RustCargoRoute>> = HashMap::default();
        for ((manifest, _), routes) in &self.routes_by_manifest_and_name {
            keep_going().then_some(())?;
            routes_by_manifest
                .entry(manifest.as_path())
                .or_default()
                .extend(routes);
        }
        let mut visible_roots_by_root: HashMap<&ProjectFile, Vec<&ProjectFile>> =
            HashMap::default();
        for (root, targets) in &self.targets_by_root {
            keep_going().then_some(())?;
            let mut visible = Vec::new();
            for target in targets {
                keep_going().then_some(())?;
                visible.extend(
                    routes_by_manifest
                        .get(target.manifest.as_path())
                        .into_iter()
                        .flatten()
                        .filter(|route| cargo_route_available_to_target(route, target))
                        .map(|route| &route.root_file),
                );
            }
            visible.sort();
            visible.dedup();
            visible_roots_by_root.insert(root, visible);
        }
        note_workspace_file_sweep();
        let mut files_by_root: HashMap<&ProjectFile, crate::hash::HashSet<&ProjectFile>> =
            HashMap::default();
        for (file, target_roots) in &self.target_roots_by_file {
            keep_going().then_some(())?;
            for root in target_roots {
                keep_going().then_some(())?;
                files_by_root.entry(root).or_default().insert(file);
                for visible in visible_roots_by_root
                    .get(root)
                    .into_iter()
                    .flatten()
                    .copied()
                {
                    keep_going().then_some(())?;
                    files_by_root.entry(visible).or_default().insert(file);
                }
            }
        }
        let mut sorted = HashMap::default();
        for (root, files) in files_by_root {
            keep_going().then_some(())?;
            let mut files = files.into_iter().cloned().collect::<Vec<_>>();
            files.sort();
            sorted.insert(root.clone(), files);
        }
        Some(sorted)
    }

    pub(super) fn candidates_in_library_route(
        &self,
        source_file: &ProjectFile,
        route: &str,
        candidates: Vec<crate::analyzer::CodeUnit>,
    ) -> Option<Vec<crate::analyzer::CodeUnit>> {
        let root = self.resolve_crate_root_file(source_file, route)?;
        let routed: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| {
                candidate.source() == &root
                    || self
                        .target_roots_by_file
                        .get(candidate.source())
                        .is_some_and(|roots| roots.contains(&root))
            })
            .collect();
        Some(routed)
    }

    pub(super) fn target_relation(
        &self,
        left: &ProjectFile,
        right: &ProjectFile,
    ) -> RustCargoTargetRelation {
        let Some(left_roots) = self.target_roots_by_file.get(left) else {
            return RustCargoTargetRelation::Unknown;
        };
        let Some(right_roots) = self.target_roots_by_file.get(right) else {
            return RustCargoTargetRelation::Unknown;
        };
        if left_roots.iter().any(|root| right_roots.contains(root)) {
            RustCargoTargetRelation::Shared
        } else {
            RustCargoTargetRelation::Disjoint
        }
    }

    pub(super) fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        let (root, nested) = rust_external_module_route(module_specifier)?;
        let route = self.resolve_available_route(importing_file, root)?;
        Some(append_module_package(route.package, nested.as_deref()))
    }

    pub(super) fn resolve_module_package_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(String, RustCargoRouteKind)> {
        let (root, nested) = rust_external_module_segments(segments)?;
        let route = self.resolve_available_route(importing_file, root)?;
        Some((
            append_module_package(route.package, nested.as_deref()),
            route.kind,
        ))
    }

    pub(super) fn resolve_crate_root_file(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<ProjectFile> {
        let (root, nested) = rust_external_module_route(module_specifier)?;
        if nested.is_some() {
            return None;
        }
        Some(
            self.resolve_available_route(importing_file, root)?
                .root_file,
        )
    }

    pub(super) fn resolve_crate_root_file_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(ProjectFile, RustCargoRouteKind)> {
        let (root, nested) = rust_external_module_segments(segments)?;
        if nested.is_some() {
            return None;
        }
        let route = self.resolve_available_route(importing_file, root)?;
        Some((route.root_file, route.kind))
    }

    fn resolve_available_route(
        &self,
        file: &ProjectFile,
        route_name: &str,
    ) -> Option<RustCargoRoute> {
        let normalized = normalize_crate_name(route_name);
        let mut resolved = self
            .target_roots_by_file
            .get(file)?
            .iter()
            .filter_map(|root| self.targets_by_root.get(root))
            .flatten()
            .flat_map(|target| {
                self.routes_by_manifest_and_name
                    .get(&(target.manifest.clone(), normalized.clone()))
                    .into_iter()
                    .flatten()
                    .filter(move |route| cargo_route_available_to_target(route, target))
            })
            .cloned()
            .collect::<Vec<_>>();
        resolved.sort_by(|left, right| {
            left.root_file
                .cmp(&right.root_file)
                .then_with(|| left.package.cmp(&right.package))
                .then_with(|| left.target_predicate.cmp(&right.target_predicate))
        });
        resolved.dedup_by(|duplicate, retained| {
            duplicate.root_file == retained.root_file
                && duplicate.package == retained.package
                && duplicate.kind == retained.kind
        });
        match resolved.as_slice() {
            [route] => Some(route.clone()),
            _ => None,
        }
    }
}

fn sort_and_dedup_external_module_declarations(declarations: &mut Vec<RustCargoModuleDeclaration>) {
    declarations.sort_by(|left, right| {
        left.target_file
            .cmp(&right.target_file)
            .then_with(|| left.declaring_file.cmp(&right.declaring_file))
            .then_with(|| left.declaring_module.cmp(&right.declaring_module))
            .then_with(|| left.visibility.cmp(&right.visibility))
    });
    declarations.dedup();
}

fn cargo_route_available_to_target(route: &RustCargoRoute, target: &RustCargoTarget) -> bool {
    match route.dependency_kind {
        None => !matches!(
            target.kind,
            RustCargoTargetKind::Library | RustCargoTargetKind::Build
        ),
        Some(kind) => cargo_dependency_available_to_target(kind, target),
    }
}

fn cargo_dependency_available_to_target(
    kind: RustCargoDependencyKind,
    target: &RustCargoTarget,
) -> bool {
    match kind {
        RustCargoDependencyKind::Normal => target.kind != RustCargoTargetKind::Build,
        RustCargoDependencyKind::Development => target.development_capable,
        RustCargoDependencyKind::Build => target.kind == RustCargoTargetKind::Build,
    }
}

/// The Cargo topology of the workspace: every manifest's crate, target,
/// dependency and edition identity, and the target roots those imply.
///
/// Discovered once per build (issue #1817). It used to be rediscovered inside
/// each of the two module-membership passes, which read and TOML-parsed every
/// manifest a second time and, far more expensively, searched the whole
/// analyzed file list once per crate for the files that crate's auto-discovered
/// targets are rooted at.
struct CargoManifestTopology {
    routes_by_manifest_and_name: HashMap<(PathBuf, String), Vec<RustCargoRoute>>,
    declared_dependencies_by_manifest_and_name:
        HashMap<(PathBuf, String), Vec<RustCargoDependencyKind>>,
    targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>>,
    /// Every target root in the workspace, sorted. One membership walk is
    /// seeded from all of them at once: a walk frontier carries the target it
    /// came from, so per-crate walks and one shared walk reach the same
    /// (file, target) pairs.
    target_roots: Vec<ProjectFile>,
    analyzed: crate::hash::HashSet<ProjectFile>,
}

impl CargoManifestTopology {
    fn discover(
        root: &Path,
        files: &[ProjectFile],
        manifest_directories: crate::hash::HashSet<PathBuf>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<Self> {
        let mut manifests = HashMap::default();
        for directory in manifest_directories {
            keep_going().then_some(())?;
            if let Some(value) = read_manifest(root, &directory) {
                manifests.insert(directory, value);
            }
        }
        let mut crates = Vec::new();
        for (directory, manifest) in &manifests {
            keep_going().then_some(())?;
            if let Some(cargo_crate) =
                cargo_crate(root, directory.clone(), manifest.clone(), &manifests)
            {
                crates.push(cargo_crate);
            }
        }
        let mut crate_by_directory = HashMap::default();
        for (index, cargo_crate) in crates.iter().enumerate() {
            keep_going().then_some(())?;
            crate_by_directory.insert(cargo_crate.directory.clone(), index);
        }
        note_workspace_file_sweep();
        let analyzed: crate::hash::HashSet<ProjectFile> = files.iter().cloned().collect();
        let files_by_manifest_directory = files_by_auto_target_directory(files, keep_going)?;

        let mut routes_by_manifest_and_name: HashMap<_, Vec<RustCargoRoute>> = HashMap::default();
        let mut declared_dependencies_by_manifest_and_name: HashMap<
            _,
            Vec<RustCargoDependencyKind>,
        > = HashMap::default();
        let mut targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>> =
            HashMap::default();
        for cargo_crate in &crates {
            keep_going().then_some(())?;
            for (target_root, kinds) in cargo_target_roots(
                root,
                cargo_crate,
                &analyzed,
                files_by_manifest_directory
                    .get(&cargo_crate.directory)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            ) {
                keep_going().then_some(())?;
                targets_by_root
                    .entry(target_root)
                    .or_default()
                    .extend(kinds.iter().copied().map(|kind| RustCargoTarget {
                        manifest: cargo_crate.directory.clone(),
                        kind: kind.kind,
                        development_capable: kind.development_capable,
                        edition: cargo_crate.edition.clone(),
                    }));
            }
            if let Some(library) = cargo_crate.library.as_ref() {
                let own_route = (cargo_crate.directory.clone(), library.name.clone());
                routes_by_manifest_and_name
                    .entry(own_route)
                    .or_default()
                    .push(RustCargoRoute {
                        package: library.root_package.clone(),
                        root_file: library.root_file.clone(),
                        kind: RustCargoRouteKind::CurrentLibrary,
                        dependency_kind: None,
                        target_predicate: None,
                    });
            }
            for (dependency_kind, target_predicate, dependencies) in
                cargo_dependency_tables_with_kind(&cargo_crate.manifest)
            {
                keep_going().then_some(())?;
                for (exposed_name, raw_dependency) in dependencies {
                    keep_going().then_some(())?;
                    declared_dependencies_by_manifest_and_name
                        .entry((
                            cargo_crate.directory.clone(),
                            normalize_crate_name(exposed_name),
                        ))
                        .or_default()
                        .push(dependency_kind);
                    let dependency = effective_cargo_dependency(
                        root,
                        &cargo_crate.directory,
                        &cargo_crate.manifest,
                        exposed_name,
                        raw_dependency,
                        &manifests,
                    );
                    let target = dependency
                        .as_ref()
                        .and_then(|(dependency, _)| dependency.get("path"))
                        .and_then(toml::Value::as_str)
                        .and_then(|path| {
                            workspace_relative_path(
                                root,
                                dependency
                                    .as_ref()
                                    .map(|(_, base)| base.as_path())
                                    .unwrap_or(&cargo_crate.directory),
                                Path::new(path),
                            )
                        })
                        .or_else(|| {
                            cargo_patched_dependency_directory(
                                root,
                                &cargo_crate.directory,
                                &cargo_crate.manifest,
                                exposed_name,
                                dependency.as_ref().map(|(dependency, _)| *dependency),
                                raw_dependency,
                                &manifests,
                            )
                        })
                        .and_then(|directory| crate_by_directory.get(&directory).copied());
                    if let Some(target) = target {
                        let Some(target_library) = crates[target].library.as_ref() else {
                            continue;
                        };
                        let is_renamed = dependency
                            .as_ref()
                            .is_some_and(|(dependency, _)| dependency.contains_key("package"));
                        let exposed_name = if is_renamed {
                            normalize_crate_name(exposed_name)
                        } else {
                            target_library.name.clone()
                        };
                        routes_by_manifest_and_name
                            .entry((cargo_crate.directory.clone(), exposed_name))
                            .or_default()
                            .push(RustCargoRoute {
                                package: target_library.root_package.clone(),
                                root_file: target_library.root_file.clone(),
                                kind: RustCargoRouteKind::Dependency,
                                dependency_kind: Some(dependency_kind),
                                target_predicate: target_predicate.map(str::to_string),
                            });
                    }
                }
            }
        }
        for routes in routes_by_manifest_and_name.values_mut() {
            keep_going().then_some(())?;
            routes.sort_by(|left, right| {
                left.root_file
                    .cmp(&right.root_file)
                    .then_with(|| left.package.cmp(&right.package))
            });
            routes.dedup();
        }
        let mut target_roots: Vec<_> = targets_by_root.keys().cloned().collect();
        target_roots.sort();
        Some(Self {
            routes_by_manifest_and_name,
            declared_dependencies_by_manifest_and_name,
            targets_by_root,
            target_roots,
            analyzed,
        })
    }

    fn target_memberships_while(
        &self,
        module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>> {
        cargo_target_memberships(
            &self.analyzed,
            &self.target_roots,
            module_children,
            keep_going,
        )
    }

    fn into_index(
        self,
        target_roots_by_file: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<RustCargoRouteIndex> {
        let mut index = RustCargoRouteIndex {
            routes_by_manifest_and_name: self.routes_by_manifest_and_name,
            declared_dependencies_by_manifest_and_name: self
                .declared_dependencies_by_manifest_and_name,
            target_roots_by_file,
            targets_by_root: self.targets_by_root,
            files_by_reachable_root: HashMap::default(),
            // Both are filled by `build_while` once the module edges exist;
            // the topology only knows the manifests.
            external_module_declarations: Vec::new(),
            test_only_files: crate::hash::HashSet::default(),
        };
        index.files_by_reachable_root = index.build_files_by_reachable_root_while(keep_going)?;
        Some(index)
    }
}

/// One file's module edges as they resolve with no macro gate satisfied.
///
/// The same `(file, is_crate_root)` pair is asked for by the first membership
/// walk, by every target the file belongs to while macro visibility is
/// computed, and again by the second walk for every file no passthrough macro
/// reaches -- which is nearly all of them. Each answer costs a `#[path]`
/// resolution per scope and an `exists()` per candidate file, so resolving it
/// once per pair is part of what keeps the build proportional to the workspace
/// rather than to the workspace times its Cargo targets (issue #1817).
#[derive(Default)]
struct ModuleEdgeCache {
    as_crate_root: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>>,
    as_module: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>>,
}

impl ModuleEdgeCache {
    fn gate_free(
        &mut self,
        file: &ProjectFile,
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        is_crate_root: bool,
    ) -> Arc<Vec<RustExternalModuleChild>> {
        let resolved = if is_crate_root {
            &mut self.as_crate_root
        } else {
            &mut self.as_module
        };
        if let Some(edges) = resolved.get(file) {
            return Arc::clone(edges);
        }
        let edges = Arc::new(
            module_route_facts
                .get(file)
                .map(|facts| module_child_edges(file, facts, is_crate_root, &HashMap::default()))
                .unwrap_or_default(),
        );
        resolved.insert(file.clone(), Arc::clone(&edges));
        edges
    }
}

/// The files each target root owns, sorted: the inverse of the membership map.
///
/// Every per-target stage of the build iterates this instead of re-scanning the
/// whole analyzed file list for the files that belong to the target it is on,
/// which is what made the macro-visibility stage cost targets times files
/// (issue #1817).
fn files_by_target_root(
    target_roots_by_file: &HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>,
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<ProjectFile, Vec<ProjectFile>>> {
    note_workspace_file_sweep();
    let mut files_by_root: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    for (file, roots) in target_roots_by_file {
        keep_going().then_some(())?;
        for root in roots {
            keep_going().then_some(())?;
            files_by_root
                .entry(root.clone())
                .or_default()
                .push(file.clone());
        }
    }
    for files in files_by_root.values_mut() {
        keep_going().then_some(())?;
        files.sort();
    }
    Some(files_by_root)
}

/// How far below its manifest directory an auto-discovered Cargo target can
/// sit. `auto_cargo_target_kind` matches relative paths of two, three or four
/// components and nothing else, which
/// `auto_target_paths_stay_within_the_grouped_depth` pins.
const AUTO_TARGET_MAX_DEPTH: usize = 4;
const AUTO_TARGET_MIN_DEPTH: usize = 2;

/// Group every analyzed file under each manifest directory that could
/// auto-discover it as a target root.
///
/// The search used to run the other way -- for each crate, walk every analyzed
/// file in the workspace and ask whether it sits under that crate -- which is
/// crates times files, and was one of the two quadratic terms issue #1817
/// removed. A file has at most three ancestors at an auto-target depth, so
/// grouping costs the workspace once.
fn files_by_auto_target_directory(
    files: &[ProjectFile],
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<PathBuf, Vec<ProjectFile>>> {
    note_workspace_file_sweep();
    let mut grouped: HashMap<PathBuf, Vec<ProjectFile>> = HashMap::default();
    for file in files {
        keep_going().then_some(())?;
        let relative = file.rel_path();
        let components = relative.components().count();
        let mut directory = relative.to_path_buf();
        for depth in 1..=AUTO_TARGET_MAX_DEPTH {
            if components < depth || !directory.pop() {
                break;
            }
            if depth >= AUTO_TARGET_MIN_DEPTH {
                grouped
                    .entry(directory.clone())
                    .or_default()
                    .push(file.clone());
            }
        }
    }
    Some(grouped)
}

/// The files each of one crate's Cargo targets is rooted at.
///
/// `explicit` targets name their file, so they are looked up in the analyzed
/// set rather than searched for; auto-discovered ones are found among
/// `files_below`, the analyzed files this crate's manifest directory could
/// auto-discover (see [`files_by_auto_target_directory`]).
fn cargo_target_roots(
    root: &Path,
    cargo_crate: &CargoCrate,
    analyzed: &crate::hash::HashSet<ProjectFile>,
    files_below: &[ProjectFile],
) -> HashMap<ProjectFile, crate::hash::HashSet<RustCargoTargetSpec>> {
    let mut explicit = explicit_cargo_targets(root, cargo_crate);
    if let Some(build_script) = cargo_build_script_path(root, cargo_crate) {
        explicit
            .entry(build_script)
            .or_default()
            .insert(RustCargoTargetSpec {
                kind: RustCargoTargetKind::Build,
                development_capable: false,
            });
    }
    let auto_bins =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autobins", &cargo_crate.edition);
    let auto_examples =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autoexamples", &cargo_crate.edition);
    let auto_tests =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autotests", &cargo_crate.edition);
    let auto_benches =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autobenches", &cargo_crate.edition);
    let mut roots: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTargetSpec>> =
        HashMap::default();
    if let Some(library) = cargo_crate.library.as_ref()
        && analyzed.contains(&library.root_file)
    {
        roots
            .entry(library.root_file.clone())
            .or_default()
            .insert(RustCargoTargetSpec {
                kind: RustCargoTargetKind::Library,
                development_capable: cargo_crate
                    .manifest
                    .get("lib")
                    .and_then(|library| library.get("test"))
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true),
            });
    }
    for (path, kinds) in explicit {
        let file = ProjectFile::new(root.to_path_buf(), path);
        if !analyzed.contains(&file) {
            continue;
        }
        roots.entry(file).or_default().extend(kinds);
    }
    for file in files_below {
        let Ok(relative) = file.rel_path().strip_prefix(&cargo_crate.directory) else {
            continue;
        };
        if let Some(kind) =
            auto_cargo_target_kind(relative, auto_bins, auto_examples, auto_tests, auto_benches)
        {
            roots
                .entry(file.clone())
                .or_default()
                .insert(RustCargoTargetSpec {
                    kind,
                    development_capable: true,
                });
        }
    }
    roots
}

/// Which target roots reach which files, along `mod name;` edges.
fn cargo_target_memberships(
    analyzed: &crate::hash::HashSet<ProjectFile>,
    target_roots: &[ProjectFile],
    mut module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>> {
    let mut owners: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> = HashMap::default();
    let mut pending = VecDeque::new();
    let mut visited = crate::hash::HashSet::default();
    for target in target_roots {
        keep_going().then_some(())?;
        owners
            .entry(target.clone())
            .or_default()
            .insert(target.clone());
        pending.push_back((target.clone(), target.clone(), true));
    }
    while let Some((file, target, is_crate_root)) = pending.pop_front() {
        keep_going().then_some(())?;
        if !visited.insert((file.clone(), target.clone(), is_crate_root)) {
            continue;
        }
        for child in module_children(&file, is_crate_root, &target) {
            keep_going().then_some(())?;
            if analyzed.contains(&child) {
                owners
                    .entry(child.clone())
                    .or_default()
                    .insert(target.clone());
                pending.push_back((child, target.clone(), false));
            }
        }
    }
    Some(owners)
}

/// Extract what the Cargo route index needs from one parsed Rust file.
///
/// Called from `parse_rust_file` with the tree that pass already holds, and
/// content-only by construction: nothing here reads the file's path or the file
/// system, because the rows are keyed by content hash and two byte-identical
/// files at different paths share them. Directory resolution, `#[path]`
/// normalization and the on-disk existence check are
/// [`module_child_edges`]'s job.
///
/// Item-position macro invocations are expanded OPTIMISTICALLY: whether the
/// invoked name resolves to a macro that replays its item parameters verbatim
/// depends on the `#[macro_use]` graph across files, which no single file's
/// bytes can answer. Each route the expansion produces records the invocations
/// it came out of, and the reader drops it unless every one of them resolves.
pub(super) fn extract_rust_module_route_facts(
    root: Node<'_>,
    source: &str,
    item_macros: &[RustRulesItemMacroDefinition],
) -> RustModuleRouteFacts {
    let mut facts = RustModuleRouteFacts {
        scopes: vec![RustModuleScopeFact {
            parent: None,
            module_name: String::new(),
            path_attribute: None,
            imports_macros: true,
            body_start: root.start_byte(),
            body_end: root.end_byte(),
        }],
        routes: Vec::new(),
        item_macros: item_macros.to_vec(),
    };
    let mut pending_fragments = VecDeque::new();
    collect_module_route_facts(root, source, 0, 0, &[], &mut pending_fragments, &mut facts);
    let mut parser = None;
    while let Some(fragment) = pending_fragments.pop_front() {
        if parser.is_none() {
            let mut prepared_parser = Parser::new();
            if prepared_parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .is_err()
            {
                break;
            }
            parser = Some(prepared_parser);
        }
        let Some(parser) = parser.as_mut() else {
            break;
        };
        let Some(tree) = parser.parse(&fragment.source, None) else {
            continue;
        };
        if tree.root_node().has_error() {
            continue;
        }
        collect_module_route_facts(
            tree.root_node(),
            &fragment.source,
            fragment.source_base_byte,
            fragment.scope,
            &fragment.gates,
            &mut pending_fragments,
            &mut facts,
        );
    }
    facts
}

/// The item stream of one macro invocation, waiting to be parsed and walked.
struct RustPendingRouteFragment {
    source: String,
    /// Where `source` starts in the declaring file, so every recorded byte
    /// offset is a file offset.
    source_base_byte: usize,
    /// The scope the invocation was written in; a fragment introduces no scope
    /// of its own, because a macro's items land where it was invoked.
    scope: usize,
    gates: Vec<RustMacroGateFact>,
}

/// Walk one item stream, recording the scopes it opens and the external `mod`
/// declarations it writes.
///
/// Explicit stack, never recursion: this runs over every analyzed Rust file.
fn collect_module_route_facts(
    node: Node<'_>,
    source: &str,
    source_base_byte: usize,
    scope: usize,
    gates: &[RustMacroGateFact],
    pending_fragments: &mut VecDeque<RustPendingRouteFragment>,
    facts: &mut RustModuleRouteFacts,
) {
    let mut pending_nodes = vec![(node, scope)];
    while let Some((node, scope)) = pending_nodes.pop() {
        let mut cursor = node.walk();
        let named_children: Vec<_> = node.named_children(&mut cursor).collect();
        // Inline bodies are collected here and pushed in reverse below, so the
        // stack pops them in source order: the rows are then a plain
        // source-order pre-order walk, which is what makes a re-analysis of
        // unchanged bytes produce byte-identical rows.
        let mut descend = Vec::new();
        for child in named_children {
            if child.kind() == "macro_invocation" {
                let Some(name) = rust_unqualified_macro_invocation_name(child, source) else {
                    continue;
                };
                let Some(arguments) = rust_macro_invocation_arguments(child) else {
                    continue;
                };
                let Some(items) = rust_macro_argument_items(arguments, source) else {
                    continue;
                };
                let mut nested = gates.to_vec();
                nested.push(RustMacroGateFact {
                    macro_name: name.to_string(),
                    invocation_start: source_base_byte.saturating_add(child.start_byte()),
                });
                pending_fragments.push_back(RustPendingRouteFragment {
                    source: items.to_string(),
                    source_base_byte: source_base_byte
                        .saturating_add(arguments.start_byte().saturating_add(1)),
                    scope,
                    gates: nested,
                });
                continue;
            }
            if child.kind() != "mod_item" {
                continue;
            }
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(name) = source.get(name.start_byte()..name.end_byte()) else {
                continue;
            };
            let inherits_macros = facts.scopes[scope].imports_macros;
            let imports_macros = inherits_macros && rust_has_macro_use_attribute(child, source);
            let path_attribute = rust_path_attribute_value(child, source);
            if let Some(body) = child.child_by_field_name("body") {
                facts.scopes.push(RustModuleScopeFact {
                    parent: Some(scope),
                    module_name: name.to_string(),
                    path_attribute,
                    imports_macros,
                    body_start: source_base_byte.saturating_add(body.start_byte()),
                    body_end: source_base_byte.saturating_add(body.end_byte()),
                });
                // A scope is appended before its body is walked, so a parent
                // index is always smaller than its children's -- the pre-order
                // the stored rows and the reader both rely on.
                descend.push((body, facts.scopes.len().saturating_sub(1)));
                continue;
            }
            facts.routes.push(RustModuleRouteFact {
                scope,
                module_name: name.to_string(),
                path_attribute,
                visibility: rust_item_visibility(child, source),
                imports_macros,
                test_gated: rust_declaration_is_bare_cfg_test_gated(child, source),
                declaration_start: source_base_byte.saturating_add(child.start_byte()),
                declaration_end: source_base_byte.saturating_add(child.end_byte()),
                gates: gates.to_vec(),
            });
        }
        pending_nodes.extend(descend.into_iter().rev());
    }
}

/// One scope's resolved directories and qualified module name, for one live
/// file. Path-derived, so it is recomputed per file and never stored.
struct ResolvedModuleScope {
    /// Where a plain `mod name;` in this scope looks for its file. `None` when
    /// a `#[path]` on this scope or an enclosing one did not resolve, which
    /// drops every declaration below it exactly as the syntax walk did.
    module_directory: Option<PathBuf>,
    /// Where a `#[path = "..."]` written in this scope resolves from.
    path_directory: Option<PathBuf>,
    declaring_module: String,
}

/// Resolve one file's persisted module-route facts into the module edges the
/// index consumes.
///
/// This is the reader half of [`extract_rust_module_route_facts`], and it holds
/// everything the stored rows deliberately do not: the file's own location,
/// which decides the directory a `mod name;` searches; `#[path]` normalization,
/// which must run step by step because `canonicalize` resolves symbolic links
/// at every level; and the on-disk existence check that turns a declaration
/// into an edge.
fn module_child_edges(
    file: &ProjectFile,
    facts: &RustModuleRouteFacts,
    is_crate_root: bool,
    passthrough_macros: &HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
) -> Vec<RustExternalModuleChild> {
    if facts.routes.is_empty() {
        return Vec::new();
    }
    let root = file.root();
    let parent = file.rel_path().parent().unwrap_or(Path::new(""));
    let stem = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let base_directory = if is_crate_root || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let package = rust_package_name(file);
    let mut scopes: Vec<ResolvedModuleScope> = Vec::with_capacity(facts.scopes.len());
    for scope in &facts.scopes {
        let resolved = match scope.parent {
            None => ResolvedModuleScope {
                module_directory: Some(base_directory.clone()),
                path_directory: Some(parent.to_path_buf()),
                declaring_module: package.clone(),
            },
            Some(index) => {
                assert!(
                    index < scopes.len(),
                    "module scope rows are stored in pre-order: {scope:?} in {facts:?}"
                );
                let enclosing = &scopes[index];
                let directory = match &scope.path_attribute {
                    Some(attribute) => enclosing
                        .path_directory
                        .as_ref()
                        .and_then(|base| workspace_relative_path(root, base, Path::new(attribute))),
                    None => enclosing
                        .module_directory
                        .as_ref()
                        .map(|base| base.join(&scope.module_name)),
                };
                ResolvedModuleScope {
                    module_directory: directory.clone(),
                    path_directory: directory,
                    declaring_module: append_module_package(
                        enclosing.declaring_module.clone(),
                        Some(&scope.module_name),
                    ),
                }
            }
        };
        scopes.push(resolved);
    }

    let mut children = Vec::new();
    for route in &facts.routes {
        assert!(
            route.scope < scopes.len(),
            "module route names a scope it does not have: {route:?} in {facts:?}"
        );
        if !route.gates.iter().all(|gate| {
            passthrough_macros
                .get(&gate.macro_name)
                .and_then(|definitions| {
                    rust_latest_visible_item_macro(definitions, gate.invocation_start)
                })
                .unwrap_or(false)
        }) {
            continue;
        }
        let scope = &scopes[route.scope];
        match &route.path_attribute {
            Some(attribute) => {
                let Some(base) = scope.path_directory.as_ref() else {
                    continue;
                };
                let Some(relative) = workspace_relative_path(root, base, Path::new(attribute))
                else {
                    continue;
                };
                push_module_child(root, relative, route, scope, &mut children);
            }
            None => {
                let Some(base) = scope.module_directory.as_ref() else {
                    continue;
                };
                for relative in [
                    base.join(&route.module_name).with_extension("rs"),
                    base.join(&route.module_name).join("mod.rs"),
                ] {
                    push_module_child(root, relative, route, scope, &mut children);
                }
            }
        }
    }
    sort_and_merge_module_children(&mut children);
    children
}

/// Keep `relative` as a module edge when it names a file that exists.
fn push_module_child(
    root: &Path,
    relative: PathBuf,
    route: &RustModuleRouteFact,
    scope: &ResolvedModuleScope,
    children: &mut Vec<RustExternalModuleChild>,
) {
    let candidate = ProjectFile::new(root.to_path_buf(), relative);
    if !candidate.exists() {
        return;
    }
    children.push(RustExternalModuleChild {
        file: candidate,
        declaring_module: scope.declaring_module.clone(),
        visibility: route.visibility.clone(),
        imports_macros: route.imports_macros,
        test_gated: route.test_gated,
        declaration_start_byte: route.declaration_start,
        visibility_start_byte: if route.imports_macros {
            route.declaration_end
        } else {
            usize::MAX
        },
    });
}

#[cfg(test)]
fn rust_external_module_children(
    file: &ProjectFile,
    source: &str,
    root_node: Node<'_>,
    is_crate_root: bool,
    passthrough_macros: &HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
) -> Vec<ProjectFile> {
    rust_external_module_child_edges(file, source, root_node, is_crate_root, passthrough_macros)
        .into_iter()
        .map(|edge| edge.file)
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustExternalModuleChild {
    file: ProjectFile,
    declaring_module: String,
    visibility: RustVisibility,
    imports_macros: bool,
    test_gated: bool,
    declaration_start_byte: usize,
    visibility_start_byte: usize,
}

/// The pre-#1793 syntax walk, frozen as the reference the equivalence pin
/// compares against.
///
/// This is what the Cargo-route build called for every analyzed file, with that
/// file's hydrated tree. `extract_rust_module_route_facts` plus
/// [`module_child_edges`] must reproduce it exactly, and
/// `module_child_edges_reproduce_the_syntax_walk` is what holds that honest.
/// It also still backs `build_from_disk`, whose fixtures have no store.
#[cfg(test)]
fn rust_external_module_child_edges(
    file: &ProjectFile,
    source: &str,
    root_node: Node<'_>,
    is_crate_root: bool,
    passthrough_macros: &HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
) -> Vec<RustExternalModuleChild> {
    let parent = file.rel_path().parent().unwrap_or(Path::new(""));
    let stem = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let module_directory = if is_crate_root || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let mut children = Vec::new();
    let mut pending_fragments = VecDeque::new();
    collect_external_module_children(
        file,
        source,
        root_node,
        &module_directory,
        parent,
        passthrough_macros,
        true,
        0,
        &rust_package_name(file),
        &mut pending_fragments,
        &mut children,
    );
    let mut parser = None;
    while let Some(fragment) = pending_fragments.pop_front() {
        if parser.is_none() {
            let mut prepared_parser = Parser::new();
            if prepared_parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .is_err()
            {
                break;
            }
            parser = Some(prepared_parser);
        }
        let Some(parser) = parser.as_mut() else {
            break;
        };
        let Some(tree) = parser.parse(&fragment.source, None) else {
            continue;
        };
        if tree.root_node().has_error() {
            continue;
        }
        collect_external_module_children(
            file,
            &fragment.source,
            tree.root_node(),
            &fragment.module_directory,
            &fragment.path_attribute_directory,
            passthrough_macros,
            fragment.imports_macros_to_file_scope,
            fragment.source_base_byte,
            &fragment.declaring_module,
            &mut pending_fragments,
            &mut children,
        );
    }
    sort_and_merge_module_children(&mut children);
    children
}

/// Collapse repeated declarations of the same file into one edge.
///
/// Shared by the fact reader and the frozen syntax walk so the equivalence pin
/// compares the derivations rather than two copies of this merge.
fn sort_and_merge_module_children(children: &mut Vec<RustExternalModuleChild>) {
    children.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.declaring_module.cmp(&right.declaring_module))
            .then_with(|| left.visibility.cmp(&right.visibility))
    });
    children.dedup_by(|duplicate, retained| {
        if duplicate.file == retained.file
            && duplicate.declaring_module == retained.declaring_module
            && duplicate.visibility == retained.visibility
        {
            retained.declaration_start_byte = retained
                .declaration_start_byte
                .min(duplicate.declaration_start_byte);
            if duplicate.imports_macros {
                retained.visibility_start_byte = retained
                    .visibility_start_byte
                    .min(duplicate.visibility_start_byte);
            }
            retained.imports_macros |= duplicate.imports_macros;
            // Mutually exclusive declarations of the same module
            // (`#[cfg(test)] mod x;` beside `#[cfg(not(test))] mod x;`) merge
            // into one edge here. The file is compiled outside tests as soon as
            // any one of them is un-gated, so the merged edge is gated only if
            // every declaration was.
            retained.test_gated &= duplicate.test_gated;
            true
        } else {
            false
        }
    });
}

#[cfg(test)]
struct RustPendingMacroFragment {
    source: String,
    source_base_byte: usize,
    module_directory: PathBuf,
    path_attribute_directory: PathBuf,
    imports_macros_to_file_scope: bool,
    declaring_module: String,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn collect_external_module_children(
    source_file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    module_directory: &Path,
    path_attribute_directory: &Path,
    passthrough_macros: &HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
    imports_macros_to_file_scope: bool,
    source_base_byte: usize,
    declaring_module: &str,
    pending_fragments: &mut VecDeque<RustPendingMacroFragment>,
    children: &mut Vec<RustExternalModuleChild>,
) {
    let mut pending_nodes = vec![(
        node,
        module_directory.to_path_buf(),
        path_attribute_directory.to_path_buf(),
        imports_macros_to_file_scope,
        declaring_module.to_string(),
    )];
    while let Some((
        node,
        module_directory,
        path_attribute_directory,
        imports_macros_to_file_scope,
        declaring_module,
    )) = pending_nodes.pop()
    {
        let mut cursor = node.walk();
        let mut named_children: Vec<_> = node.named_children(&mut cursor).collect();
        named_children.reverse();
        for child in named_children {
            if child.kind() == "macro_invocation" {
                let invocation_start = source_base_byte.saturating_add(child.start_byte());
                let is_passthrough = rust_unqualified_macro_invocation_name(child, source)
                    .and_then(|name| passthrough_macros.get(name))
                    .and_then(|definitions| {
                        rust_latest_visible_item_macro(definitions, invocation_start)
                    })
                    .unwrap_or(false);
                let Some(arguments) = is_passthrough
                    .then(|| rust_macro_invocation_arguments(child))
                    .flatten()
                else {
                    continue;
                };
                let Some(items) = rust_macro_argument_items(arguments, source) else {
                    continue;
                };
                pending_fragments.push_back(RustPendingMacroFragment {
                    source: items.to_string(),
                    source_base_byte: source_base_byte
                        .saturating_add(arguments.start_byte().saturating_add(1)),
                    module_directory: module_directory.clone(),
                    path_attribute_directory: path_attribute_directory.clone(),
                    imports_macros_to_file_scope,
                    declaring_module: declaring_module.clone(),
                });
                continue;
            }
            if child.kind() != "mod_item" {
                continue;
            }
            let Some(name) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(name) = source.get(name.start_byte()..name.end_byte()) else {
                continue;
            };
            if let Some(body) = child.child_by_field_name("body") {
                let imports_macros =
                    imports_macros_to_file_scope && rust_has_macro_use_attribute(child, source);
                let inline_directory = match rust_path_attribute(child, source) {
                    Some(path) => {
                        let Some(relative) = workspace_relative_path(
                            source_file.root(),
                            &path_attribute_directory,
                            &path,
                        ) else {
                            continue;
                        };
                        relative
                    }
                    None => module_directory.join(name),
                };
                pending_nodes.push((
                    body,
                    inline_directory.clone(),
                    inline_directory,
                    imports_macros,
                    if declaring_module.is_empty() {
                        name.to_string()
                    } else {
                        format!("{declaring_module}.{name}")
                    },
                ));
                continue;
            }
            if let Some(path) = rust_path_attribute(child, source) {
                let Some(relative) =
                    workspace_relative_path(source_file.root(), &path_attribute_directory, &path)
                else {
                    continue;
                };
                let candidate = ProjectFile::new(source_file.root().to_path_buf(), relative);
                if candidate.exists() {
                    let imports_macros =
                        imports_macros_to_file_scope && rust_has_macro_use_attribute(child, source);
                    children.push(RustExternalModuleChild {
                        file: candidate,
                        declaring_module: declaring_module.clone(),
                        visibility: rust_item_visibility(child, source),
                        imports_macros,
                        test_gated: rust_declaration_is_bare_cfg_test_gated(child, source),
                        declaration_start_byte: source_base_byte.saturating_add(child.start_byte()),
                        visibility_start_byte: if imports_macros {
                            source_base_byte.saturating_add(child.end_byte())
                        } else {
                            usize::MAX
                        },
                    });
                }
                continue;
            }
            for relative in [
                module_directory.join(name).with_extension("rs"),
                module_directory.join(name).join("mod.rs"),
            ] {
                let candidate = ProjectFile::new(source_file.root().to_path_buf(), relative);
                if candidate.exists() {
                    let imports_macros =
                        imports_macros_to_file_scope && rust_has_macro_use_attribute(child, source);
                    children.push(RustExternalModuleChild {
                        file: candidate,
                        declaring_module: declaring_module.clone(),
                        visibility: rust_item_visibility(child, source),
                        imports_macros,
                        test_gated: rust_declaration_is_bare_cfg_test_gated(child, source),
                        declaration_start_byte: source_base_byte.saturating_add(child.start_byte()),
                        visibility_start_byte: if imports_macros {
                            source_base_byte.saturating_add(child.end_byte())
                        } else {
                            usize::MAX
                        },
                    });
                }
            }
        }
    }
}

fn rust_latest_visible_item_macro(
    definitions: &[RustVisibleItemMacroDefinition],
    invocation_start: usize,
) -> Option<bool> {
    let latest = definitions
        .iter()
        .filter(|definition| {
            definition.visible_after <= invocation_start
                && definition.scope_start <= invocation_start
                && invocation_start < definition.scope_end
        })
        .map(|definition| (definition.scope_start, definition.visible_after))
        .max()?;
    let mut matching = definitions.iter().filter(|definition| {
        definition.scope_start == latest.0
            && definition.visible_after == latest.1
            && definition.scope_start <= invocation_start
            && invocation_start < definition.scope_end
    });
    let passthrough = matching.next()?.passthrough;
    matching
        .all(|definition| definition.passthrough == passthrough)
        .then_some(passthrough)
}

fn rust_has_macro_use_attribute(module: Node<'_>, source: &str) -> bool {
    let mut sibling = module.prev_named_sibling();
    while let Some(attribute_item) = sibling {
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let Some(attribute) = attribute_item.named_child(0) else {
            return false;
        };
        let Some(path) = attribute.named_child(0) else {
            return false;
        };
        if source.get(path.start_byte()..path.end_byte()) == Some("macro_use") {
            return true;
        }
        sibling = attribute_item.prev_named_sibling();
    }
    false
}

/// Whether the `mod x;` item at `module` is gated by a bare `#[cfg(test)]`.
///
/// This is the only place the test-gating of a module edge is decided, and it
/// is deliberately conservative: **only** the bare `#[cfg(test)]` predicate
/// counts. Any composition -- `all`, `any`, `not`, or a nested predicate such
/// as `#[cfg(any(test, feature = "test-support"))]`, which is this repository's
/// own pattern for fixtures shared with dependents -- can still evaluate true
/// in a non-test build, so the declared file is reachable from production code
/// and must not be classified as test-only. Getting that wrong hides real
/// production files, which is far worse than leaving a test file visible.
///
/// The shape is read from the AST: `#[cfg(test)]` is an `attribute` whose path
/// is the bare identifier `cfg` and whose `arguments` token tree holds exactly
/// one named token, the identifier `test`. Every composition puts an operator
/// identifier beside a nested `token_tree`, and `#[cfg(feature = "test")]`
/// puts a `string_literal` beside `feature`, so both fail the single-identifier
/// check without inspecting any text beyond those two identifiers.
///
/// Attributes attach to an item as preceding siblings in tree-sitter-rust, and
/// comments may sit between them, so walk back over the contiguous run exactly
/// as `declarations::rust_item_carries_test_attribute` does.
fn rust_declaration_is_bare_cfg_test_gated(module: Node<'_>, source: &str) -> bool {
    let mut prev = module.prev_sibling();
    while let Some(node) = prev {
        match node.kind() {
            "attribute_item" => {
                if rust_attribute_is_bare_cfg_test(node, source) {
                    return true;
                }
            }
            "inner_attribute_item" | "line_comment" | "block_comment" => {}
            _ => break,
        }
        prev = node.prev_sibling();
    }
    false
}

fn rust_attribute_is_bare_cfg_test(attribute_item: Node<'_>, source: &str) -> bool {
    let mut item_cursor = attribute_item.walk();
    let Some(attribute) = attribute_item
        .named_children(&mut item_cursor)
        .find(|child| child.kind() == "attribute")
    else {
        return false;
    };
    let Some(path) = attribute.named_child(0) else {
        return false;
    };
    if path.kind() != "identifier" || node_source_text(path, source) != Some("cfg") {
        return false;
    }
    let Some(arguments) = attribute.child_by_field_name("arguments") else {
        return false;
    };
    let mut argument_cursor = arguments.walk();
    let mut tokens = arguments.named_children(&mut argument_cursor);
    let Some(token) = tokens.next() else {
        return false;
    };
    tokens.next().is_none()
        && token.kind() == "identifier"
        && node_source_text(token, source) == Some("test")
}

fn node_source_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

fn rust_macro_argument_items<'a>(arguments: Node<'_>, source: &'a str) -> Option<&'a str> {
    let start = arguments.start_byte().checked_add(1)?;
    let end = arguments.end_byte().checked_sub(1)?;
    (start <= end).then(|| source.get(start..end)).flatten()
}

/// The decoded `#[path = "..."]` value written on `module`, if any.
///
/// Kept as the decoded string rather than a `PathBuf` because this is what the
/// `rust_module_scopes` / `rust_module_routes` rows carry: the attribute is a
/// content fact, and turning it into a path is the reader's job.
fn rust_path_attribute_value(module: Node<'_>, source: &str) -> Option<String> {
    let mut sibling = module.prev_named_sibling();
    while let Some(attribute_item) = sibling {
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let attribute = attribute_item.named_child(0)?;
        let path = attribute.named_child(0)?;
        let path = source.get(path.start_byte()..path.end_byte())?;
        if path == "path" {
            let value = attribute.child_by_field_name("value")?;
            return rust_static_string_literal(value, source).filter(|path| !path.is_empty());
        }
        sibling = attribute_item.prev_named_sibling();
    }
    None
}

#[cfg(test)]
fn rust_path_attribute(module: Node<'_>, source: &str) -> Option<PathBuf> {
    rust_path_attribute_value(module, source).map(PathBuf::from)
}

/// Decode a static Rust string literal from its tree-sitter nodes.
///
/// `#[path]` accepts both cooked and raw strings.  Decode cooked escape nodes
/// individually so the filesystem path sees the value Rust assigns the
/// attribute, rather than the literal's source spelling.
fn rust_static_string_literal(literal: Node<'_>, source: &str) -> Option<String> {
    match literal.kind() {
        "raw_string_literal" => {
            let spelling = source.get(literal.start_byte()..literal.end_byte())?;
            if !spelling.starts_with('r') {
                return None;
            }
            let content = literal.named_child(0)?;
            (content.kind() == "string_content" && content.next_named_sibling().is_none()).then(
                || {
                    source
                        .get(content.start_byte()..content.end_byte())
                        .map(str::to_string)
                },
            )?
        }
        "string_literal" => {
            let spelling = source.get(literal.start_byte()..literal.end_byte())?;
            if !spelling.starts_with('"') {
                return None;
            }
            let mut decoded = String::new();
            let mut trim_continuation_whitespace = false;
            let mut cursor = literal.walk();
            for child in literal.named_children(&mut cursor) {
                let text = source.get(child.start_byte()..child.end_byte())?;
                match child.kind() {
                    "string_content" => {
                        let text = if trim_continuation_whitespace {
                            trim_continuation_whitespace = false;
                            text.trim_start_matches(char::is_whitespace)
                        } else {
                            text
                        };
                        decoded.push_str(text);
                    }
                    "escape_sequence" => {
                        let continuation = rust_cooked_string_escape(text, &mut decoded)?;
                        trim_continuation_whitespace = continuation;
                    }
                    _ => return None,
                }
            }
            Some(decoded)
        }
        _ => None,
    }
}

fn rust_cooked_string_escape(escape: &str, decoded: &mut String) -> Option<bool> {
    let escaped = escape.strip_prefix('\\')?;
    if escaped == "\n" || escaped == "\r\n" {
        return Some(true);
    }
    let character = match escaped {
        "n" => '\n',
        "r" => '\r',
        "t" => '\t',
        "0" => '\0',
        "\\" => '\\',
        "\"" => '"',
        "'" => '\'',
        _ if escaped.starts_with('x') => {
            let value = u8::from_str_radix(escaped.get(1..)?, 16).ok()?;
            if !value.is_ascii() {
                return None;
            }
            char::from(value)
        }
        _ if escaped.starts_with("u{") && escaped.ends_with('}') => {
            let value =
                u32::from_str_radix(escaped.get(2..escaped.len().checked_sub(1)?)?, 16).ok()?;
            char::from_u32(value)?
        }
        _ if escaped.starts_with('u') => {
            let value = u32::from_str_radix(escaped.get(1..)?, 16).ok()?;
            char::from_u32(value)?
        }
        _ => return None,
    };
    decoded.push(character);
    Some(false)
}

fn explicit_cargo_targets(
    root: &Path,
    cargo_crate: &CargoCrate,
) -> HashMap<PathBuf, crate::hash::HashSet<RustCargoTargetSpec>> {
    let mut paths: HashMap<PathBuf, crate::hash::HashSet<RustCargoTargetSpec>> = HashMap::default();
    for table_name in ["bin", "example", "test", "bench"] {
        let kind = match table_name {
            "bin" => RustCargoTargetKind::Binary,
            "example" => RustCargoTargetKind::Example,
            "test" => RustCargoTargetKind::Test,
            "bench" => RustCargoTargetKind::Bench,
            _ => unreachable!(),
        };
        let Some(targets) = cargo_crate
            .manifest
            .get(table_name)
            .and_then(toml::Value::as_array)
        else {
            continue;
        };
        for target in targets {
            let Some(target) = target.as_table() else {
                continue;
            };
            let spec = RustCargoTargetSpec {
                kind,
                development_capable: match kind {
                    RustCargoTargetKind::Binary => target
                        .get("test")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(true),
                    RustCargoTargetKind::Example
                    | RustCargoTargetKind::Test
                    | RustCargoTargetKind::Bench => true,
                    RustCargoTargetKind::Library | RustCargoTargetKind::Build => false,
                },
            };
            if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
                if let Some(path) =
                    workspace_relative_path(root, &cargo_crate.directory, Path::new(path))
                {
                    paths.entry(path).or_default().insert(spec);
                }
                continue;
            }
            let Some(name) = target.get("name").and_then(toml::Value::as_str) else {
                continue;
            };
            for inferred in inferred_cargo_target_paths(table_name, name, &cargo_crate.package_name)
            {
                if let Some(path) = workspace_relative_path(root, &cargo_crate.directory, &inferred)
                {
                    paths.entry(path).or_default().insert(spec);
                }
            }
        }
    }
    paths
}

fn inferred_cargo_target_paths(table_name: &str, name: &str, package_name: &str) -> Vec<PathBuf> {
    let name_path = Path::new(name);
    if !matches!(
        name_path.components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ) {
        return Vec::new();
    }
    match table_name {
        "bin" => {
            let mut paths = Vec::new();
            if normalize_crate_name(name) == normalize_crate_name(package_name) {
                paths.push(PathBuf::from("src/main.rs"));
            }
            paths.push(Path::new("src/bin").join(name).with_extension("rs"));
            paths.push(Path::new("src/bin").join(name).join("main.rs"));
            paths
        }
        "example" => vec![
            Path::new("examples").join(name).with_extension("rs"),
            Path::new("examples").join(name).join("main.rs"),
        ],
        "test" => vec![Path::new("tests").join(name).with_extension("rs")],
        "bench" => vec![
            Path::new("benches").join(name).with_extension("rs"),
            Path::new("benches").join(name).join("main.rs"),
        ],
        _ => Vec::new(),
    }
}

fn cargo_build_script_path(root: &Path, cargo_crate: &CargoCrate) -> Option<PathBuf> {
    let package = cargo_crate.manifest.get("package")?.as_table()?;
    let path = match package.get("build") {
        Some(toml::Value::String(path)) => Path::new(path),
        Some(toml::Value::Boolean(false)) => return None,
        Some(toml::Value::Boolean(true)) | None => Path::new("build.rs"),
        Some(_) => return None,
    };
    workspace_relative_path(root, &cargo_crate.directory, path)
}

fn cargo_auto_discovery_enabled(manifest: &toml::Value, key: &str, edition: &str) -> bool {
    let package = manifest.get("package").and_then(toml::Value::as_table);
    if let Some(enabled) = package
        .and_then(|package| package.get(key))
        .and_then(toml::Value::as_bool)
    {
        return enabled;
    }

    edition != "2015" || !cargo_manifest_has_explicit_target(manifest)
}

fn cargo_manifest_has_explicit_target(manifest: &toml::Value) -> bool {
    manifest.get("lib").is_some()
        || ["bin", "example", "test", "bench"].iter().any(|name| {
            manifest
                .get(name)
                .and_then(toml::Value::as_array)
                .is_some_and(|targets| !targets.is_empty())
        })
}

fn auto_cargo_target_kind(
    relative: &Path,
    bins: bool,
    examples: bool,
    tests: bool,
    benches: bool,
) -> Option<RustCargoTargetKind> {
    let components: Vec<_> = relative.components().collect();
    match components.as_slice() {
        [Component::Normal(directory), Component::Normal(file)] => {
            if bins && *directory == "src" && *file == "main.rs" {
                Some(RustCargoTargetKind::Binary)
            } else if Path::new(file).extension().is_some_and(|ext| ext == "rs") {
                match directory.to_str() {
                    Some("examples") if examples => Some(RustCargoTargetKind::Example),
                    Some("tests") if tests => Some(RustCargoTargetKind::Test),
                    Some("benches") if benches => Some(RustCargoTargetKind::Bench),
                    _ => None,
                }
            } else {
                None
            }
        }
        [
            Component::Normal(first),
            Component::Normal(second),
            Component::Normal(third),
        ] => {
            if bins
                && *first == "src"
                && *second == "bin"
                && Path::new(third).extension().is_some_and(|ext| ext == "rs")
            {
                Some(RustCargoTargetKind::Binary)
            } else if *third == "main.rs" {
                match first.to_str() {
                    Some("examples") if examples => Some(RustCargoTargetKind::Example),
                    Some("benches") if benches => Some(RustCargoTargetKind::Bench),
                    _ => None,
                }
            } else {
                None
            }
        }
        [
            Component::Normal(src),
            Component::Normal(bin),
            Component::Normal(_),
            Component::Normal(main),
        ] => (bins && *src == "src" && *bin == "bin" && *main == "main.rs")
            .then_some(RustCargoTargetKind::Binary),
        _ => None,
    }
}

fn cargo_dependency_tables_with_kind(
    manifest: &toml::Value,
) -> Vec<(
    RustCargoDependencyKind,
    Option<&str>,
    &toml::map::Map<String, toml::Value>,
)> {
    let mut tables = Vec::new();
    for (table_name, kind) in [
        ("dependencies", RustCargoDependencyKind::Normal),
        ("dev-dependencies", RustCargoDependencyKind::Development),
        ("build-dependencies", RustCargoDependencyKind::Build),
    ] {
        if let Some(table) = manifest.get(table_name).and_then(toml::Value::as_table) {
            tables.push((kind, None, table));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for (predicate, target) in targets {
            let Some(target) = target.as_table() else {
                continue;
            };
            for (table_name, kind) in [
                ("dependencies", RustCargoDependencyKind::Normal),
                ("dev-dependencies", RustCargoDependencyKind::Development),
                ("build-dependencies", RustCargoDependencyKind::Build),
            ] {
                if let Some(table) = target.get(table_name).and_then(toml::Value::as_table) {
                    tables.push((kind, Some(predicate.as_str()), table));
                }
            }
        }
    }
    tables
}

fn cargo_dependency_tables(manifest: &toml::Value) -> Vec<&toml::map::Map<String, toml::Value>> {
    cargo_dependency_tables_with_kind(manifest)
        .into_iter()
        .map(|(_, _, table)| table)
        .collect()
}

fn effective_cargo_dependency<'a>(
    root: &Path,
    manifest_directory: &Path,
    manifest: &'a toml::Value,
    exposed_name: &str,
    dependency: &'a toml::Value,
    manifests: &'a HashMap<PathBuf, toml::Value>,
) -> Option<(&'a toml::map::Map<String, toml::Value>, PathBuf)> {
    let dependency = dependency.as_table()?;
    if !dependency
        .get("workspace")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return Some((dependency, manifest_directory.to_path_buf()));
    }
    let workspace_directory =
        cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)?;
    let dependency = manifests
        .get(&workspace_directory)?
        .get("workspace")?
        .get("dependencies")?
        .get(exposed_name)?
        .as_table()?;
    Some((dependency, workspace_directory))
}

fn cargo_patched_dependency_directory(
    root: &Path,
    manifest_directory: &Path,
    manifest: &toml::Value,
    exposed_name: &str,
    dependency: Option<&toml::map::Map<String, toml::Value>>,
    raw_dependency: &toml::Value,
    manifests: &HashMap<PathBuf, toml::Value>,
) -> Option<PathBuf> {
    let package_name = dependency
        .and_then(|dependency| dependency.get("package"))
        .and_then(toml::Value::as_str)
        .unwrap_or(exposed_name);
    let workspace_directory =
        cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)?;
    let patch_sources = manifests
        .get(&workspace_directory)?
        .get("patch")?
        .as_table()?;
    let source_name = cargo_dependency_patch_source(dependency, raw_dependency)?;
    let source = patch_sources.get(source_name)?.as_table()?;
    let version_requirement =
        match cargo_dependency_version_requirement(dependency, raw_dependency)? {
            Some(requirement) => Some(VersionReq::parse(requirement).ok()?),
            None => None,
        };
    let mut compatible_directories = source
        .iter()
        .filter(|(patch_name, candidate)| {
            patch_name.as_str() == package_name
                || candidate
                    .as_table()
                    .and_then(|candidate| candidate.get("package"))
                    .and_then(toml::Value::as_str)
                    == Some(package_name)
        })
        .filter_map(|(_, patch)| {
            let path = patch.as_table()?.get("path")?.as_str().map(Path::new)?;
            let directory = workspace_relative_path(root, &workspace_directory, path)?;
            let patched_manifest = manifests.get(&directory)?;
            let package = patched_manifest.get("package")?.as_table()?;
            if package.get("name")?.as_str()? != package_name {
                return None;
            }
            let patched_version =
                cargo_package_string(root, &directory, patched_manifest, manifests, "version")
                    .and_then(|version| Version::parse(&version).ok())?;
            version_requirement
                .as_ref()
                .is_none_or(|requirement| requirement.matches(&patched_version))
                .then_some(directory)
        })
        .collect::<Vec<_>>();
    compatible_directories.sort();
    compatible_directories.dedup();
    match compatible_directories.as_slice() {
        [directory] => Some(directory.clone()),
        _ => None,
    }
}

fn cargo_dependency_patch_source<'a>(
    dependency: Option<&'a toml::map::Map<String, toml::Value>>,
    raw_dependency: &'a toml::Value,
) -> Option<&'a str> {
    let table = dependency.or_else(|| raw_dependency.as_table());
    if table.is_some_and(|dependency| dependency.contains_key("path")) {
        return None;
    }
    if let Some(git) = table
        .and_then(|dependency| dependency.get("git"))
        .and_then(toml::Value::as_str)
    {
        return Some(git);
    }
    match table
        .and_then(|dependency| dependency.get("registry"))
        .and_then(toml::Value::as_str)
    {
        None | Some("crates-io") => Some("crates-io"),
        Some(_) => None,
    }
}

fn cargo_dependency_version_requirement<'a>(
    dependency: Option<&'a toml::map::Map<String, toml::Value>>,
    raw_dependency: &'a toml::Value,
) -> Option<Option<&'a str>> {
    let version = dependency
        .and_then(|dependency| dependency.get("version"))
        .and_then(toml::Value::as_str)
        .or_else(|| raw_dependency.as_str());
    if dependency.is_none() && raw_dependency.as_table().is_some() {
        return None;
    }
    Some(version)
}

fn cargo_package_edition(
    root: &Path,
    manifest_directory: &Path,
    manifest: &toml::Value,
    manifests: &HashMap<PathBuf, toml::Value>,
) -> String {
    let edition = manifest
        .get("package")
        .and_then(|package| package.get("edition"));
    if let Some(edition) = edition.and_then(toml::Value::as_str) {
        return edition.to_string();
    }
    let inherited = edition
        .and_then(toml::Value::as_table)
        .and_then(|edition| edition.get("workspace"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    if !inherited {
        return "2015".to_string();
    }
    cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)
        .and_then(|workspace_directory| manifests.get(&workspace_directory))
        .and_then(|workspace| workspace.get("workspace"))
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("edition"))
        .and_then(toml::Value::as_str)
        .unwrap_or("2015")
        .to_string()
}

fn cargo_package_string(
    root: &Path,
    manifest_directory: &Path,
    manifest: &toml::Value,
    manifests: &HashMap<PathBuf, toml::Value>,
    field: &str,
) -> Option<String> {
    let value = manifest.get("package")?.get(field)?;
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    if !value
        .as_table()
        .and_then(|value| value.get("workspace"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)
        .and_then(|workspace_directory| manifests.get(&workspace_directory))
        .and_then(|workspace| workspace.get("workspace"))
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get(field))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn cargo_workspace_manifest_directory(
    root: &Path,
    manifest_directory: &Path,
    manifest: &toml::Value,
    manifests: &HashMap<PathBuf, toml::Value>,
) -> Option<PathBuf> {
    let explicit_workspace = manifest
        .get("package")
        .and_then(|package| package.get("workspace"))
        .and_then(toml::Value::as_str)
        .and_then(|path| workspace_relative_path(root, manifest_directory, Path::new(path)));
    explicit_workspace
        .or_else(|| {
            manifest_directory.ancestors().find_map(|directory| {
                manifests
                    .get(directory)
                    .filter(|manifest| manifest.get("workspace").is_some())
                    .map(|_| directory.to_path_buf())
            })
        })
        .or_else(|| {
            manifest
                .get("package")
                .is_some()
                .then(|| manifest_directory.to_path_buf())
        })
}

fn discover_cargo_manifest_directories(
    root: &Path,
    files: &[ProjectFile],
    keep_going: &impl Fn() -> bool,
) -> Option<crate::hash::HashSet<PathBuf>> {
    let mut discovered = crate::hash::HashSet::default();
    let mut pending = VecDeque::new();
    if root.join("Cargo.toml").is_file() {
        pending.push_back(PathBuf::new());
    }
    note_workspace_file_sweep();
    for file in files {
        keep_going().then_some(())?;
        if let Some(directory) = nearest_manifest_directory(file) {
            pending.push_back(directory);
        }
    }

    while let Some(directory) = pending.pop_front() {
        keep_going().then_some(())?;
        if !discovered.insert(directory.clone()) {
            continue;
        }
        let Some(manifest) = read_manifest(root, &directory) else {
            continue;
        };
        pending.extend(cargo_workspace_member_directories(
            root, &directory, &manifest,
        ));
        pending.extend(cargo_patch_path_directories(root, &directory, &manifest));
        for dependencies in cargo_dependency_tables(&manifest).into_iter().chain(
            manifest
                .get("workspace")
                .and_then(|workspace| workspace.get("dependencies"))
                .and_then(toml::Value::as_table),
        ) {
            keep_going().then_some(())?;
            for dependency in dependencies.values() {
                keep_going().then_some(())?;
                let Some(path) = dependency
                    .as_table()
                    .and_then(|dependency| dependency.get("path"))
                    .and_then(toml::Value::as_str)
                    .map(Path::new)
                else {
                    continue;
                };
                let Some(dependency_directory) = workspace_relative_path(root, &directory, path)
                else {
                    continue;
                };
                if root
                    .join(&dependency_directory)
                    .join("Cargo.toml")
                    .is_file()
                {
                    pending.push_back(dependency_directory);
                }
            }
        }
    }
    Some(discovered)
}

fn cargo_patch_path_directories(
    root: &Path,
    manifest_directory: &Path,
    manifest: &toml::Value,
) -> Vec<PathBuf> {
    manifest
        .get("patch")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|sources| sources.values())
        .filter_map(toml::Value::as_table)
        .flat_map(|source| source.values())
        .filter_map(|patch| {
            let path = patch.as_table()?.get("path")?.as_str()?;
            let directory = workspace_relative_path(root, manifest_directory, Path::new(path))?;
            root.join(&directory)
                .join("Cargo.toml")
                .is_file()
                .then_some(directory)
        })
        .collect()
}

fn cargo_workspace_member_directories(
    root: &Path,
    workspace_directory: &Path,
    manifest: &toml::Value,
) -> Vec<PathBuf> {
    let Some(workspace) = manifest.get("workspace").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    let excludes: Vec<_> = workspace
        .get("exclude")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(|pattern| glob::Pattern::new(pattern).ok())
        .collect();
    let mut directories = Vec::new();
    for member in workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
    {
        let manifest_pattern = root
            .join(workspace_directory)
            .join(member)
            .join("Cargo.toml");
        let Some(manifest_pattern) = manifest_pattern.to_str() else {
            continue;
        };
        let Ok(matches) = glob::glob(manifest_pattern) else {
            continue;
        };
        for manifest_path in matches.flatten() {
            let Some(member_directory) = manifest_path.parent() else {
                continue;
            };
            let Some(relative) = canonical_workspace_relative_path(root, member_directory) else {
                continue;
            };
            let member_relative = relative
                .strip_prefix(workspace_directory)
                .unwrap_or(&relative);
            if excludes
                .iter()
                .any(|pattern| pattern.matches_path(member_relative))
            {
                continue;
            }
            directories.push(relative);
        }
    }
    directories
}

fn nearest_manifest_directory(file: &ProjectFile) -> Option<PathBuf> {
    let mut directory = file.rel_path().parent();
    loop {
        let relative = directory.unwrap_or_else(|| Path::new(""));
        if file.root().join(relative).join("Cargo.toml").is_file() {
            return Some(relative.to_path_buf());
        }
        directory = relative.parent();
        directory?;
    }
}

fn workspace_relative_path(root: &Path, base: &Path, path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return canonical_workspace_relative_path(root, path);
    }
    let mut normalized = base.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(component) => normalized.push(component),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    canonical_workspace_relative_path(root, &root.join(normalized))
}

fn canonical_workspace_relative_path(root: &Path, target: &Path) -> Option<PathBuf> {
    let canonical_root = root.canonicalize().ok()?;
    let canonical_target = target.canonicalize().ok()?;
    canonical_target
        .strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn append_module_package(mut package: String, nested: Option<&str>) -> String {
    let Some(nested) = nested else {
        return package;
    };
    if !package.is_empty() {
        package.push('.');
    }
    package.push_str(nested);
    package
}

/// The pre-#1817 Cargo-route orchestration, frozen as the reference the
/// equivalence pin compares against.
///
/// Issue #1817 rewrote the orchestration's shape, not its answer: the manifest
/// topology is now discovered once instead of once per membership pass, the
/// per-crate and per-target loops iterate the files they own instead of the
/// whole workspace, and a gate-free file's module edges are resolved once
/// instead of once per pass and target. Every one of those is an algebraic
/// rewrite of the same derivation, so the guard has to be a direct comparison
/// against what it replaced rather than a sample of its answers. This is the
/// `#1793` idiom (`rust_external_module_child_edges`) one layer up.
///
/// Everything the rewrite did not touch is shared rather than copied:
/// `discover_cargo_manifest_directories`, `cargo_crate`, `module_child_edges`,
/// `explicit_cargo_targets`, `sort_and_dedup_external_module_declarations`,
/// `cargo_route_available_to_target` and `build_test_only_files_while`.
#[cfg(test)]
mod frozen_orchestration {
    use super::*;

    pub(super) fn reference_build_while(
        files: &[ProjectFile],
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<RustCargoRouteIndex> {
        keep_going().then_some(())?;
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Some(RustCargoRouteIndex::default());
        };
        if discover_cargo_manifest_directories(root, files, keep_going)?.is_empty() {
            // Without a Cargo manifest there are no target, dependency, or
            // edition identities for this index to model. Stop before the
            // manifest builder reaches the same empty result the long way.
            return Some(RustCargoRouteIndex::default());
        }
        note_workspace_file_sweep();
        let mut macro_definitions = Vec::new();
        for file in files {
            keep_going().then_some(())?;
            let Some(facts) = module_route_facts.get(file) else {
                continue;
            };
            macro_definitions.extend(
                facts
                    .item_macros
                    .iter()
                    .map(|definition| (file.clone(), definition.clone())),
            );
        }
        let no_passthrough_macros = HashMap::default();
        let physical_routes = reference_build_from_module_children_while(
            files,
            |file, is_crate_root, _target| {
                module_route_facts
                    .get(file)
                    .map(|facts| {
                        module_child_edges(file, facts, is_crate_root, &no_passthrough_macros)
                            .into_iter()
                            .map(|edge| edge.file)
                            .collect()
                    })
                    .unwrap_or_default()
            },
            keep_going,
        )?;
        let mut visible_definition_starts: HashMap<
            (ProjectFile, ProjectFile),
            HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
        > = HashMap::default();
        let target_roots: crate::hash::HashSet<_> = physical_routes
            .target_roots_by_file
            .values()
            .flatten()
            .cloned()
            .collect();
        for target in &target_roots {
            keep_going().then_some(())?;
            let mut children_by_file: HashMap<ProjectFile, Vec<RustExternalModuleChild>> =
                HashMap::default();
            let mut parents_by_file: HashMap<ProjectFile, Vec<(ProjectFile, bool, usize)>> =
                HashMap::default();
            note_workspace_file_sweep();
            for file in files {
                keep_going().then_some(())?;
                if !physical_routes
                    .target_roots_by_file
                    .get(file)
                    .is_some_and(|roots| roots.contains(target))
                {
                    continue;
                }
                let Some(facts) = module_route_facts.get(file) else {
                    continue;
                };
                let edges = module_child_edges(file, facts, file == target, &no_passthrough_macros);
                for edge in &edges {
                    keep_going().then_some(())?;
                    if physical_routes
                        .target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        parents_by_file.entry(edge.file.clone()).or_default().push((
                            file.clone(),
                            edge.imports_macros,
                            edge.visibility_start_byte,
                        ));
                    }
                }
                children_by_file.insert(file.clone(), edges);
            }

            for (definition_file, definition) in &macro_definitions {
                keep_going().then_some(())?;
                if !physical_routes
                    .target_roots_by_file
                    .get(definition_file)
                    .is_some_and(|roots| roots.contains(target))
                {
                    continue;
                }
                let mut visible_files: HashMap<ProjectFile, usize> = HashMap::default();
                let mut pending = vec![(definition_file.clone(), definition.visible_after)];
                while let Some((file, visible_after)) = pending.pop() {
                    keep_going().then_some(())?;
                    if visible_files
                        .get(&file)
                        .is_some_and(|known_start| *known_start <= visible_after)
                    {
                        continue;
                    }
                    visible_files.insert(file.clone(), visible_after);
                    let local_scope = (file == *definition_file)
                        .then_some((definition.scope_start, definition.scope_end));
                    if local_scope.is_none_or(|(start, end)| {
                        module_route_facts
                            .get(&file)
                            .and_then(RustModuleRouteFacts::file_extent)
                            .is_some_and(|extent| extent == (start, end))
                    }) && let Some(parents) = parents_by_file.get(&file)
                    {
                        pending.extend(
                            parents
                                .iter()
                                .filter(|(_, imports_macros, _)| *imports_macros)
                                .map(|(parent, _, import_start)| (parent.clone(), *import_start)),
                        );
                    }
                    if let Some(children) = children_by_file.get(&file) {
                        pending.extend(
                            children
                                .iter()
                                .filter(|edge| {
                                    edge.declaration_start_byte >= visible_after
                                        && local_scope.is_none_or(|(start, end)| {
                                            start <= edge.declaration_start_byte
                                                && edge.declaration_start_byte < end
                                        })
                                })
                                .map(|edge| (edge.file.clone(), 0)),
                        );
                    }
                }
                for (file, visible_after) in visible_files {
                    keep_going().then_some(())?;
                    let (scope_start, scope_end) = if file == *definition_file {
                        (definition.scope_start, definition.scope_end)
                    } else {
                        let Some(extent) = module_route_facts
                            .get(&file)
                            .and_then(RustModuleRouteFacts::file_extent)
                        else {
                            continue;
                        };
                        extent
                    };
                    visible_definition_starts
                        .entry((target.clone(), file))
                        .or_default()
                        .entry(definition.name.clone())
                        .or_default()
                        .push(RustVisibleItemMacroDefinition {
                            visible_after,
                            scope_start,
                            scope_end,
                            passthrough: definition.passthrough,
                        });
                }
            }
        }
        let mut passthrough_by_target_and_file = visible_definition_starts;
        for target in &target_roots {
            keep_going().then_some(())?;
            note_workspace_file_sweep();
            let mut pending = physical_routes
                .target_roots_by_file
                .iter()
                .filter(|(_, roots)| roots.contains(target))
                .map(|(file, _)| file.clone())
                .collect::<VecDeque<_>>();
            let mut processed_binding_counts: HashMap<ProjectFile, usize> = HashMap::default();
            while let Some(file) = pending.pop_front() {
                keep_going().then_some(())?;
                let Some(facts) = module_route_facts.get(&file) else {
                    continue;
                };
                let key = (target.clone(), file.clone());
                let binding_count = passthrough_by_target_and_file
                    .get(&key)
                    .into_iter()
                    .flat_map(|bindings| bindings.values())
                    .map(Vec::len)
                    .sum();
                if processed_binding_counts.get(&file) == Some(&binding_count) {
                    continue;
                }
                processed_binding_counts.insert(file.clone(), binding_count);
                let bindings = passthrough_by_target_and_file
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                let edges = module_child_edges(&file, facts, file == *target, &bindings);
                for edge in edges {
                    keep_going().then_some(())?;
                    if physical_routes
                        .target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        continue;
                    }
                    let Some((child_start, child_end)) = module_route_facts
                        .get(&edge.file)
                        .and_then(RustModuleRouteFacts::file_extent)
                    else {
                        continue;
                    };
                    let child_bindings = passthrough_by_target_and_file
                        .entry((target.clone(), edge.file.clone()))
                        .or_default();
                    let before = child_bindings.values().map(Vec::len).sum::<usize>();
                    for (name, definitions) in &bindings {
                        keep_going().then_some(())?;
                        let Some(passthrough) = rust_latest_visible_item_macro(
                            definitions,
                            edge.declaration_start_byte,
                        ) else {
                            continue;
                        };
                        let inherited = RustVisibleItemMacroDefinition {
                            visible_after: 0,
                            scope_start: child_start,
                            scope_end: child_end,
                            passthrough,
                        };
                        let definitions = child_bindings.entry(name.clone()).or_default();
                        if !definitions.contains(&inherited) {
                            definitions.push(inherited);
                        }
                    }
                    for (_, definition) in macro_definitions
                        .iter()
                        .filter(|(definition_file, _)| definition_file == &edge.file)
                    {
                        keep_going().then_some(())?;
                        let local = RustVisibleItemMacroDefinition {
                            visible_after: definition.visible_after,
                            scope_start: definition.scope_start,
                            scope_end: definition.scope_end,
                            passthrough: definition.passthrough,
                        };
                        let definitions =
                            child_bindings.entry(definition.name.clone()).or_default();
                        if !definitions.contains(&local) {
                            definitions.push(local);
                        }
                    }
                    let after = child_bindings.values().map(Vec::len).sum::<usize>();
                    if after != before || !processed_binding_counts.contains_key(&edge.file) {
                        pending.push_back(edge.file);
                    }
                }
            }
        }
        let no_passthrough_macros = HashMap::default();
        let mut external_module_declarations = Vec::new();
        let mut index = reference_build_from_module_children_while(
            files,
            |file, is_crate_root, target| {
                module_route_facts
                    .get(file)
                    .map(|facts| {
                        let passthrough_macros = passthrough_by_target_and_file
                            .get(&(target.clone(), file.clone()))
                            .unwrap_or(&no_passthrough_macros);
                        let edges =
                            module_child_edges(file, facts, is_crate_root, passthrough_macros);
                        external_module_declarations.extend(edges.iter().map(|edge| {
                            RustCargoModuleDeclaration {
                                declaring_file: file.clone(),
                                declaring_module: edge.declaring_module.clone(),
                                target_file: edge.file.clone(),
                                visibility: edge.visibility.clone(),
                                test_gated: edge.test_gated,
                            }
                        }));
                        edges.into_iter().map(|edge| edge.file).collect()
                    })
                    .unwrap_or_default()
            },
            keep_going,
        )?;
        sort_and_dedup_external_module_declarations(&mut external_module_declarations);
        index.external_module_declarations = external_module_declarations;
        index.test_only_files = index.build_test_only_files_while(keep_going)?;
        Some(index)
    }

    fn reference_build_from_module_children_while(
        files: &[ProjectFile],
        mut module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<RustCargoRouteIndex> {
        keep_going().then_some(())?;
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Some(RustCargoRouteIndex::default());
        };
        let mut manifests = HashMap::default();
        for directory in discover_cargo_manifest_directories(root, files, keep_going)? {
            keep_going().then_some(())?;
            if let Some(value) = read_manifest(root, &directory) {
                manifests.insert(directory, value);
            }
        }
        let mut crates = Vec::new();
        for (directory, manifest) in &manifests {
            keep_going().then_some(())?;
            if let Some(cargo_crate) =
                cargo_crate(root, directory.clone(), manifest.clone(), &manifests)
            {
                crates.push(cargo_crate);
            }
        }

        let mut crate_by_directory = HashMap::default();
        for (index, cargo_crate) in crates.iter().enumerate() {
            keep_going().then_some(())?;
            crate_by_directory.insert(cargo_crate.directory.clone(), index);
        }
        let mut routes_by_manifest_and_name: HashMap<_, Vec<RustCargoRoute>> = HashMap::default();
        let mut declared_dependencies_by_manifest_and_name: HashMap<
            _,
            Vec<RustCargoDependencyKind>,
        > = HashMap::default();
        let mut target_roots_by_file: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> =
            HashMap::default();
        let mut targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>> =
            HashMap::default();
        for cargo_crate in &crates {
            keep_going().then_some(())?;
            let target_roots = reference_cargo_target_roots(root, cargo_crate, files);
            for (target_root, kinds) in &target_roots {
                keep_going().then_some(())?;
                targets_by_root
                    .entry(target_root.clone())
                    .or_default()
                    .extend(kinds.iter().copied().map(|kind| RustCargoTarget {
                        manifest: cargo_crate.directory.clone(),
                        kind: kind.kind,
                        development_capable: kind.development_capable,
                        edition: cargo_crate.edition.clone(),
                    }));
            }
            let target_root_files: Vec<_> = target_roots.keys().cloned().collect();
            for (file, roots) in reference_cargo_target_memberships(
                files,
                &target_root_files,
                &mut module_children,
                keep_going,
            )? {
                keep_going().then_some(())?;
                target_roots_by_file.entry(file).or_default().extend(roots);
            }
            if let Some(library) = cargo_crate.library.as_ref() {
                let own_route = (cargo_crate.directory.clone(), library.name.clone());
                routes_by_manifest_and_name
                    .entry(own_route)
                    .or_default()
                    .push(RustCargoRoute {
                        package: library.root_package.clone(),
                        root_file: library.root_file.clone(),
                        kind: RustCargoRouteKind::CurrentLibrary,
                        dependency_kind: None,
                        target_predicate: None,
                    });
            }
            for (dependency_kind, target_predicate, dependencies) in
                cargo_dependency_tables_with_kind(&cargo_crate.manifest)
            {
                keep_going().then_some(())?;
                for (exposed_name, raw_dependency) in dependencies {
                    keep_going().then_some(())?;
                    declared_dependencies_by_manifest_and_name
                        .entry((
                            cargo_crate.directory.clone(),
                            normalize_crate_name(exposed_name),
                        ))
                        .or_default()
                        .push(dependency_kind);
                    let dependency = effective_cargo_dependency(
                        root,
                        &cargo_crate.directory,
                        &cargo_crate.manifest,
                        exposed_name,
                        raw_dependency,
                        &manifests,
                    );
                    let target = dependency
                        .as_ref()
                        .and_then(|(dependency, _)| dependency.get("path"))
                        .and_then(toml::Value::as_str)
                        .and_then(|path| {
                            workspace_relative_path(
                                root,
                                dependency
                                    .as_ref()
                                    .map(|(_, base)| base.as_path())
                                    .unwrap_or(&cargo_crate.directory),
                                Path::new(path),
                            )
                        })
                        .or_else(|| {
                            cargo_patched_dependency_directory(
                                root,
                                &cargo_crate.directory,
                                &cargo_crate.manifest,
                                exposed_name,
                                dependency.as_ref().map(|(dependency, _)| *dependency),
                                raw_dependency,
                                &manifests,
                            )
                        })
                        .and_then(|directory| crate_by_directory.get(&directory).copied());
                    if let Some(target) = target {
                        let Some(target_library) = crates[target].library.as_ref() else {
                            continue;
                        };
                        let is_renamed = dependency
                            .as_ref()
                            .is_some_and(|(dependency, _)| dependency.contains_key("package"));
                        let exposed_name = if is_renamed {
                            normalize_crate_name(exposed_name)
                        } else {
                            target_library.name.clone()
                        };
                        routes_by_manifest_and_name
                            .entry((cargo_crate.directory.clone(), exposed_name))
                            .or_default()
                            .push(RustCargoRoute {
                                package: target_library.root_package.clone(),
                                root_file: target_library.root_file.clone(),
                                kind: RustCargoRouteKind::Dependency,
                                dependency_kind: Some(dependency_kind),
                                target_predicate: target_predicate.map(str::to_string),
                            });
                    }
                }
            }
        }
        for routes in routes_by_manifest_and_name.values_mut() {
            keep_going().then_some(())?;
            routes.sort_by(|left, right| {
                left.root_file
                    .cmp(&right.root_file)
                    .then_with(|| left.package.cmp(&right.package))
            });
            routes.dedup();
        }
        let mut index = RustCargoRouteIndex {
            routes_by_manifest_and_name,
            declared_dependencies_by_manifest_and_name,
            target_roots_by_file,
            targets_by_root,
            files_by_reachable_root: HashMap::default(),
            // Both are filled by `build` once the module edges exist;
            // `build_from_module_children` only knows the manifest topology.
            external_module_declarations: Vec::new(),
            test_only_files: crate::hash::HashSet::default(),
        };
        index.files_by_reachable_root =
            reference_files_by_reachable_root_while(&index, keep_going)?;
        Some(index)
    }

    fn reference_files_by_reachable_root_while(
        index: &RustCargoRouteIndex,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, Vec<ProjectFile>>> {
        note_workspace_file_sweep();
        let mut files_by_root: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> =
            HashMap::default();
        for (file, target_roots) in &index.target_roots_by_file {
            keep_going().then_some(())?;
            for root in target_roots {
                keep_going().then_some(())?;
                files_by_root
                    .entry(root.clone())
                    .or_default()
                    .insert(file.clone());
                let Some(targets) = index.targets_by_root.get(root) else {
                    continue;
                };
                for target in targets {
                    keep_going().then_some(())?;
                    for ((manifest, _), routes) in &index.routes_by_manifest_and_name {
                        keep_going().then_some(())?;
                        if manifest != &target.manifest {
                            continue;
                        }
                        for route in routes
                            .iter()
                            .filter(|route| cargo_route_available_to_target(route, target))
                        {
                            keep_going().then_some(())?;
                            files_by_root
                                .entry(route.root_file.clone())
                                .or_default()
                                .insert(file.clone());
                        }
                    }
                }
            }
        }
        let mut sorted = HashMap::default();
        for (root, files) in files_by_root {
            keep_going().then_some(())?;
            let mut files = files.into_iter().collect::<Vec<_>>();
            files.sort();
            sorted.insert(root, files);
        }
        Some(sorted)
    }

    fn reference_cargo_target_roots(
        root: &Path,
        cargo_crate: &CargoCrate,
        files: &[ProjectFile],
    ) -> HashMap<ProjectFile, crate::hash::HashSet<RustCargoTargetSpec>> {
        let mut explicit = explicit_cargo_targets(root, cargo_crate);
        if let Some(build_script) = cargo_build_script_path(root, cargo_crate) {
            explicit
                .entry(build_script)
                .or_default()
                .insert(RustCargoTargetSpec {
                    kind: RustCargoTargetKind::Build,
                    development_capable: false,
                });
        }
        let auto_bins =
            cargo_auto_discovery_enabled(&cargo_crate.manifest, "autobins", &cargo_crate.edition);
        let auto_examples = cargo_auto_discovery_enabled(
            &cargo_crate.manifest,
            "autoexamples",
            &cargo_crate.edition,
        );
        let auto_tests =
            cargo_auto_discovery_enabled(&cargo_crate.manifest, "autotests", &cargo_crate.edition);
        let auto_benches = cargo_auto_discovery_enabled(
            &cargo_crate.manifest,
            "autobenches",
            &cargo_crate.edition,
        );
        note_workspace_file_sweep();
        let analyzed: crate::hash::HashSet<_> = files.iter().cloned().collect();
        let mut roots: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTargetSpec>> =
            HashMap::default();
        if let Some(library) = cargo_crate.library.as_ref()
            && analyzed.contains(&library.root_file)
        {
            roots
                .entry(library.root_file.clone())
                .or_default()
                .insert(RustCargoTargetSpec {
                    kind: RustCargoTargetKind::Library,
                    development_capable: cargo_crate
                        .manifest
                        .get("lib")
                        .and_then(|library| library.get("test"))
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(true),
                });
        }
        note_workspace_file_sweep();
        for file in files {
            if let Some(kinds) = explicit.get(file.rel_path()) {
                roots
                    .entry(file.clone())
                    .or_default()
                    .extend(kinds.iter().copied());
            }
            let Ok(relative) = file.rel_path().strip_prefix(&cargo_crate.directory) else {
                continue;
            };
            if let Some(kind) =
                auto_cargo_target_kind(relative, auto_bins, auto_examples, auto_tests, auto_benches)
            {
                roots
                    .entry(file.clone())
                    .or_default()
                    .insert(RustCargoTargetSpec {
                        kind,
                        development_capable: true,
                    });
            }
        }
        roots
    }

    fn reference_cargo_target_memberships(
        files: &[ProjectFile],
        target_roots: &[ProjectFile],
        module_children: &mut impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>> {
        note_workspace_file_sweep();
        let analyzed: crate::hash::HashSet<_> = files.iter().cloned().collect();
        let mut owners: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> =
            HashMap::default();
        let mut pending = VecDeque::new();
        let mut visited = crate::hash::HashSet::default();
        for target in target_roots {
            keep_going().then_some(())?;
            owners
                .entry(target.clone())
                .or_default()
                .insert(target.clone());
            pending.push_back((target.clone(), target.clone(), true));
        }
        while let Some((file, target, is_crate_root)) = pending.pop_front() {
            keep_going().then_some(())?;
            if !visited.insert((file.clone(), target.clone(), is_crate_root)) {
                continue;
            }
            for child in module_children(&file, is_crate_root, &target) {
                keep_going().then_some(())?;
                if analyzed.contains(&child) {
                    owners
                        .entry(child.clone())
                        .or_default()
                        .insert(target.clone());
                    pending.push_back((child, target.clone(), false));
                }
            }
        }
        Some(owners)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::rust::declarations::rust_rules_item_macro_definitions;

    /// Gating verdict for the single `mod_item` in `source`.
    fn module_is_test_gated(source: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("rust language");
        let tree = parser.parse(source, None).expect("parse");
        let root = tree.root_node();
        assert!(!root.has_error(), "fixture must parse: {source}");
        let mut cursor = root.walk();
        let module = root
            .named_children(&mut cursor)
            .find(|child| child.kind() == "mod_item")
            .expect("fixture declares a module");
        rust_declaration_is_bare_cfg_test_gated(module, source)
    }

    /// Only the bare `#[cfg(test)]` gates a module edge. Every composition can
    /// still evaluate true outside a test build, so it must leave the declared
    /// file production-reachable -- misclassifying production as test hides
    /// real code, which is the expensive direction to be wrong in.
    #[test]
    fn only_a_bare_cfg_test_attribute_gates_a_module_declaration() {
        assert!(module_is_test_gated("#[cfg(test)]\nmod tests;\n"));
        assert!(module_is_test_gated("#[cfg(test)] pub mod tests;\n"));
        assert!(
            module_is_test_gated("#[cfg(test)]\n#[allow(dead_code)]\nmod tests;\n"),
            "the gate may sit anywhere in the attribute run"
        );
        assert!(
            module_is_test_gated("#[cfg(test)]\n// the sibling test module\nmod tests;\n"),
            "a comment between the attribute and the item does not break the run"
        );

        assert!(!module_is_test_gated("mod tests;\n"));
        assert!(!module_is_test_gated(
            "#[cfg(any(test, feature = \"test-support\"))]\nmod tests;\n"
        ));
        assert!(!module_is_test_gated("#[cfg(all(test))]\nmod tests;\n"));
        assert!(!module_is_test_gated("#[cfg(not(test))]\nmod tests;\n"));
        assert!(
            !module_is_test_gated("#[cfg(feature = \"test\")]\nmod tests;\n"),
            "a feature merely named `test` is not the `test` predicate"
        );
        assert!(
            !module_is_test_gated("#[cfg_attr(test, allow(dead_code))]\nmod tests;\n"),
            "`cfg_attr` re-gates other attributes; it does not gate the item"
        );
        assert!(
            !module_is_test_gated("#[test]\nmod tests;\n"),
            "a bare `#[test]` is a test-case attribute, not a compilation gate"
        );
    }

    #[test]
    fn path_dependency_routes_honor_library_name_aliases_and_ignore_registry_matches() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "matcher/Cargo.toml",
            "[package]\nname = \"matcher-package\"\nversion = \"0.1.0\"\n[lib]\nname = \"matcher_lib\"\n",
        );
        write(&root, "matcher/src/lib.rs", "pub struct Pattern;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nmatcher-package = { path = \"../matcher\" }\nregistry_alias = { package = \"matcher-package\", version = \"1\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        write(
            &root,
            "renamed/Cargo.toml",
            "[package]\nname = \"renamed\"\nversion = \"0.1.0\"\n[dependencies]\ncustom_alias = { package = \"matcher-package\", path = \"../matcher\" }\n",
        );
        write(&root, "renamed/src/lib.rs", "pub fn run() {}\n");

        let matcher = ProjectFile::new(root.clone(), "matcher/src/lib.rs");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");
        let renamed = ProjectFile::new(root.clone(), "renamed/src/lib.rs");
        let routes =
            RustCargoRouteIndex::build_from_disk(&[matcher, consumer.clone(), renamed.clone()]);

        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_lib"),
            Some("matcher.src".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_lib::nested"),
            Some("matcher.src.nested".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&renamed, "custom_alias"),
            Some("matcher.src".to_string())
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "registry_alias"),
            None
        );
        assert_eq!(
            routes.resolve_module_package(&consumer, "matcher_package"),
            None
        );
    }

    #[test]
    fn self_crate_nested_routes_do_not_add_a_leading_package_separator() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"selfroute\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "pub mod options;\n");
        write(&root, "src/options.rs", "pub struct Options;\n");
        write(
            &root,
            "src/main.rs",
            "use selfroute::options;\nfn main() {}\n",
        );
        write(&root, "examples/example.rs", "use selfroute::options;\n");

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let options = ProjectFile::new(root.clone(), "src/options.rs");
        let binary = ProjectFile::new(root.clone(), "src/main.rs");
        let example = ProjectFile::new(root.clone(), "examples/example.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            library.clone(),
            options,
            binary.clone(),
            example.clone(),
        ]);
        let segments = ["selfroute".to_string(), "options".to_string()];

        assert_eq!(
            routes.resolve_module_package(&library, "selfroute::options"),
            None,
            "the implicit current-library route is not in scope inside the library target"
        );
        assert_eq!(
            routes.resolve_module_package(&binary, "selfroute::options"),
            Some("options".to_string()),
            "the package binary may import its library by crate name"
        );
        assert_eq!(
            routes.resolve_module_package(&example, "selfroute::options"),
            Some("options".to_string())
        );
        assert_eq!(
            routes.resolve_module_package_segments_with_kind(&example, &segments),
            Some(("options".to_string(), RustCargoRouteKind::CurrentLibrary))
        );
    }

    #[test]
    fn cargo_routes_reject_paths_outside_the_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        let outside = temp.path().join("outside");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        write(
            &root,
            "consumer/Cargo.toml",
            &format!(
                "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nparent_escape = {{ path = \"../../outside\" }}\nabsolute_escape = {{ path = {:?} }}\n",
                outside.to_string_lossy()
            ),
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        let routes = RustCargoRouteIndex::build_from_disk(std::slice::from_ref(&consumer));
        for name in ["parent_escape", "absolute_escape"] {
            assert_eq!(routes.resolve_module_package(&consumer, name), None);
        }
    }

    #[test]
    fn patched_dependencies_require_matching_source_and_semver() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "shared-v1", "future-v1", "git-wrong"]
resolver = "2"

[patch.crates-io]
shared = { path = "shared-v1" }
future = { package = "future-shared", path = "future-v1" }

[patch."https://wrong.example/repository"]
git_shared = { package = "git-shared", path = "git-wrong" }
"#,
        );
        for (directory, package, version) in [
            ("shared-v1", "shared", "1.4.0"),
            ("future-v1", "future-shared", "1.9.0"),
            ("git-wrong", "git-shared", "3.0.0"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Patched;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
shared = "^1.2"
future = { package = "future-shared", version = "^2" }
git_shared = { package = "git-shared", git = "https://good.example/repository" }
"#,
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared-v1/src/lib.rs");
        let future = ProjectFile::new(root.clone(), "future-v1/src/lib.rs");
        let wrong_git = ProjectFile::new(root.clone(), "git-wrong/src/lib.rs");
        let routes =
            RustCargoRouteIndex::build_from_disk(&[app.clone(), shared.clone(), future, wrong_git]);

        assert_eq!(
            routes.resolve_crate_root_file(&app, "shared"),
            Some(shared),
            "a crates.io patch with an applicable version is a proven route"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&app, "future"),
            None,
            "an incompatible patched package version must fail closed"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&app, "git_shared"),
            None,
            "a patch for a different source must not satisfy the dependency"
        );
    }

    #[test]
    fn patched_dependency_uses_workspace_inherited_package_version() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "patched"]
resolver = "2"

[workspace.package]
version = "1.4.0"

[patch.crates-io]
patched = { path = "patched" }
"#,
        );
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\npatched = \"^1.2\"\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");
        write(
            &root,
            "patched/Cargo.toml",
            "[package]\nname = \"patched\"\nversion.workspace = true\n",
        );
        write(&root, "patched/src/lib.rs", "pub struct Patched;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let patched = ProjectFile::new(root, "patched/src/lib.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[app.clone(), patched.clone()]);

        assert_eq!(
            routes.resolve_crate_root_file(&app, "patched"),
            Some(patched),
            "a path patch remains applicable when its package version is inherited"
        );
    }

    #[test]
    fn standalone_package_root_applies_its_patch_table() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
patched = "^1"

[patch.crates-io]
patched = { path = "patched" }
"#,
        );
        write(&root, "src/lib.rs", "pub struct App;\n");
        write(
            &root,
            "patched/Cargo.toml",
            "[package]\nname = \"patched\"\nversion = \"1.2.0\"\nedition = \"2021\"\n",
        );
        write(&root, "patched/src/lib.rs", "pub struct Patched;\n");

        let app = ProjectFile::new(root.clone(), "src/lib.rs");
        let patched = ProjectFile::new(root.clone(), "patched/src/lib.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[app.clone(), patched.clone()]);

        assert_eq!(
            routes.resolve_crate_root_file(&app, "patched"),
            Some(patched)
        );
    }

    #[test]
    fn patch_aliases_filter_by_semver_before_unique_selection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            r#"[workspace]
members = ["app", "shared-*", "ambiguous-*"]
resolver = "2"

[patch.crates-io]
shared_old = { package = "shared", path = "shared-old" }
shared_new = { package = "shared", path = "shared-new" }
ambiguous_left = { package = "ambiguous", path = "ambiguous-left" }
ambiguous_right = { package = "ambiguous", path = "ambiguous-right" }
"#,
        );
        for (directory, package, version) in [
            ("shared-old", "shared", "1.9.0"),
            ("shared-new", "shared", "2.1.0"),
            ("ambiguous-left", "ambiguous", "3.1.0"),
            ("ambiguous-right", "ambiguous", "3.2.0"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Item;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nshared = \"^2\"\nambiguous = \"^3\"\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared-new/src/lib.rs");
        let files = [
            app.clone(),
            ProjectFile::new(root.clone(), "shared-old/src/lib.rs"),
            shared.clone(),
            ProjectFile::new(root.clone(), "ambiguous-left/src/lib.rs"),
            ProjectFile::new(root, "ambiguous-right/src/lib.rs"),
        ];
        let routes = RustCargoRouteIndex::build_from_disk(&files);

        assert_eq!(
            routes.resolve_crate_root_file(&app, "shared"),
            Some(shared),
            "an incompatible first alias must not hide the unique compatible patch"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&app, "ambiguous"),
            None,
            "multiple compatible patch destinations must fail closed"
        );
    }

    #[test]
    fn workspace_relative_paths_accept_contained_absolute_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(root.join("inside")).expect("inside directory");
        let root = root.canonicalize().expect("canonical root");
        let inside = root
            .join("inside")
            .canonicalize()
            .expect("canonical inside");
        let outside = temp.path().canonicalize().expect("canonical outside");

        assert_eq!(
            workspace_relative_path(&root, Path::new("ignored"), &inside),
            Some(PathBuf::from("inside"))
        );
        assert_eq!(
            workspace_relative_path(&root, Path::new("ignored"), &outside),
            None,
            "an absolute target outside the canonical workspace must remain rejected"
        );
    }

    #[test]
    fn external_module_declarations_deduplicate_by_full_sort_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let declaring_file = ProjectFile::new(root.clone(), "src/lib.rs");
        let target_file = ProjectFile::new(root, "src/child.rs");
        let declaration =
            |declaring_module: &str, visibility: RustVisibility| RustCargoModuleDeclaration {
                declaring_file: declaring_file.clone(),
                declaring_module: declaring_module.to_string(),
                target_file: target_file.clone(),
                visibility,
                test_gated: false,
            };
        let mut declarations = vec![
            declaration("crate.alpha", RustVisibility::Private),
            declaration("crate.beta", RustVisibility::Private),
            declaration("crate.alpha", RustVisibility::Private),
            declaration("crate.alpha", RustVisibility::Public),
        ];

        sort_and_dedup_external_module_declarations(&mut declarations);

        assert_eq!(declarations.len(), 3);
        assert_eq!(declarations[0].declaring_module, "crate.alpha");
        assert_eq!(declarations[1].declaring_module, "crate.alpha");
        assert_eq!(declarations[2].declaring_module, "crate.beta");
    }

    #[cfg(unix)]
    #[test]
    fn cargo_routes_reject_symlinked_dependency_and_library_paths() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).expect("workspace root");
        let root = root.canonicalize().expect("canonical root");
        write(
            temp.path(),
            "outside/Cargo.toml",
            "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
        );
        write(temp.path(), "outside/src/lib.rs", "pub struct Escaped;\n");
        symlink(temp.path().join("outside"), root.join("linked")).expect("dependency symlink");
        write(
            &root,
            "consumer/Cargo.toml",
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[dependencies]\nlinked = { path = \"../linked\" }\n",
        );
        write(&root, "consumer/src/lib.rs", "pub fn run() {}\n");
        let consumer = ProjectFile::new(root.clone(), "consumer/src/lib.rs");

        let routes = RustCargoRouteIndex::build_from_disk(std::slice::from_ref(&consumer));
        assert_eq!(routes.resolve_module_package(&consumer, "linked"), None);

        write(
            &root,
            "bad_lib/Cargo.toml",
            "[package]\nname = \"bad-lib\"\nversion = \"0.1.0\"\n[lib]\npath = \"../linked/src/lib.rs\"\n",
        );
        let manifest = read_manifest(&root, Path::new("bad_lib")).expect("manifest");
        assert!(
            cargo_crate(
                &root,
                PathBuf::from("bad_lib"),
                manifest,
                &HashMap::default(),
            )
            .is_none()
        );
    }

    #[test]
    fn path_attributes_distinguish_physical_file_and_inline_module_bases() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        write(&root, "src/lib.rs", "mod outer;\n");
        write(
            &root,
            "src/outer.rs",
            "#[path = \"top.rs\"]\nmod top;\n\n#[path = \"relocated\"]\nmod inline {\n    #[path = \"mapped.rs\"]\n    mod mapped;\n    mod ordinary;\n}\n",
        );
        write(&root, "src/top.rs", "pub struct Top;\n");
        write(&root, "src/relocated/mapped.rs", "pub struct Mapped;\n");
        write(&root, "src/relocated/ordinary.rs", "pub struct Ordinary;\n");
        write(&root, "src/outer/top.rs", "pub struct WrongTop;\n");
        write(
            &root,
            "src/outer/inline/mapped.rs",
            "pub struct WrongMapped;\n",
        );

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let outer = ProjectFile::new(root.clone(), "src/outer.rs");
        let top = ProjectFile::new(root.clone(), "src/top.rs");
        let mapped = ProjectFile::new(root.clone(), "src/relocated/mapped.rs");
        let ordinary = ProjectFile::new(root.clone(), "src/relocated/ordinary.rs");
        let wrong_top = ProjectFile::new(root.clone(), "src/outer/top.rs");
        let wrong_mapped = ProjectFile::new(root.clone(), "src/outer/inline/mapped.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            library.clone(),
            outer,
            top.clone(),
            mapped.clone(),
            ordinary.clone(),
            wrong_top.clone(),
            wrong_mapped.clone(),
        ]);

        for expected in [top, mapped, ordinary] {
            assert_eq!(
                routes.target_roots_for_file(&expected),
                std::slice::from_ref(&library),
                "{} should follow the physical #[path] module tree",
                expected.rel_path().display()
            );
        }
        for decoy in [wrong_top, wrong_mapped] {
            assert!(
                routes.target_roots_for_file(&decoy).is_empty(),
                "{} uses the obsolete logical base",
                decoy.rel_path().display()
            );
        }
    }

    #[test]
    fn path_attributes_decode_raw_and_cooked_string_literals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        write(
            &root,
            "src/lib.rs",
            r##"#[path = r#"nested/raw.rs"#]
mod raw;
#[path = "nested\x2fcooked.rs"]
mod cooked;
"##,
        );
        write(&root, "src/nested/raw.rs", "pub struct Raw;\n");
        write(&root, "src/nested/cooked.rs", "pub struct Cooked;\n");

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let raw = ProjectFile::new(root.clone(), "src/nested/raw.rs");
        let cooked = ProjectFile::new(root.clone(), "src/nested/cooked.rs");
        let routes =
            RustCargoRouteIndex::build_from_disk(&[library.clone(), raw.clone(), cooked.clone()]);

        for expected in [raw, cooked] {
            assert_eq!(
                routes.target_roots_for_file(&expected),
                std::slice::from_ref(&library),
                "{} should follow the decoded #[path] value",
                expected.rel_path().display()
            );
        }
    }

    #[test]
    fn cargo_target_membership_crosses_nearest_manifest_boundaries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"shared\", \"runner\"]\nresolver = \"2\"\n",
        );
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "#[path = \"../../shared/src/model.rs\"]\nmod imported;\n",
        );
        write(
            &root,
            "shared/Cargo.toml",
            "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "shared/src/lib.rs", "mod model;\n");
        write(&root, "shared/src/model.rs", "pub struct Model;\n");
        write(&root, "shared/tool.rs", "fn main() {}\n");
        write(
            &root,
            "runner/Cargo.toml",
            "[package]\nname = \"runner\"\nversion = \"0.1.0\"\nedition = \"2021\"\nautobins = false\n\n[[bin]]\nname = \"tool\"\npath = \"../shared/tool.rs\"\n",
        );

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let shared = ProjectFile::new(root.clone(), "shared/src/lib.rs");
        let model = ProjectFile::new(root.clone(), "shared/src/model.rs");
        let tool = ProjectFile::new(root.clone(), "shared/tool.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            app.clone(),
            shared.clone(),
            model.clone(),
            tool.clone(),
        ]);

        let model_roots: crate::hash::HashSet<_> =
            routes.target_roots_for_file(&model).into_iter().collect();
        assert_eq!(model_roots.len(), 2);
        assert!(model_roots.contains(&app));
        assert!(model_roots.contains(&shared));
        assert_eq!(
            routes.target_roots_for_file(&tool),
            std::slice::from_ref(&tool)
        );
    }

    #[test]
    fn dependency_kinds_are_scoped_to_compatible_cargo_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"normal\", \"development\", \"build-dep\", \"target-normal\", \"target-dev\", \"target-build\"]\nresolver = \"2\"\n",
        );
        for (directory, package) in [
            ("normal", "normal-package"),
            ("development", "development-package"),
            ("build-dep", "build-package"),
            ("target-normal", "target-normal-package"),
            ("target-dev", "target-dev-package"),
            ("target-build", "target-build-package"),
        ] {
            write(
                &root,
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{directory}/src/lib.rs"),
                "pub struct Shared;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"no-test\"\npath = \"src/bin/no_test.rs\"\ntest = false\n\n[dependencies]\nnormal_dep = { package = \"normal-package\", path = \"../normal\" }\noverlap = { package = \"normal-package\", path = \"../normal\" }\n\n[dev-dependencies]\ndev_dep = { package = \"development-package\", path = \"../development\" }\noverlap = { package = \"normal-package\", path = \"../normal\" }\n\n[build-dependencies]\nbuild_dep = { package = \"build-package\", path = \"../build-dep\" }\n\n[target.'cfg(unix)'.dependencies]\ntarget_normal = { package = \"target-normal-package\", path = \"../target-normal\" }\n\n[target.'cfg(unix)'.dev-dependencies]\ntarget_dev = { package = \"target-dev-package\", path = \"../target-dev\" }\n\n[target.'cfg(unix)'.build-dependencies]\ntarget_build = { package = \"target-build-package\", path = \"../target-build\" }\n",
        );
        write(&root, "app/src/lib.rs", "mod shared;\n");
        write(&root, "app/src/main.rs", "fn main() {}\n");
        write(&root, "app/src/bin/no_test.rs", "fn main() {}\n");
        write(&root, "app/src/shared.rs", "pub struct Local;\n");
        write(&root, "app/examples/demo.rs", "fn main() {}\n");
        write(
            &root,
            "app/tests/integration.rs",
            "#[path = \"../src/shared.rs\"]\nmod shared;\n",
        );
        write(&root, "app/benches/bench.rs", "fn main() {}\n");
        write(&root, "app/build.rs", "fn main() {}\n");

        let library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let binary = ProjectFile::new(root.clone(), "app/src/main.rs");
        let no_test_binary = ProjectFile::new(root.clone(), "app/src/bin/no_test.rs");
        let shared = ProjectFile::new(root.clone(), "app/src/shared.rs");
        let example = ProjectFile::new(root.clone(), "app/examples/demo.rs");
        let test = ProjectFile::new(root.clone(), "app/tests/integration.rs");
        let bench = ProjectFile::new(root.clone(), "app/benches/bench.rs");
        let build = ProjectFile::new(root.clone(), "app/build.rs");
        let mut files = vec![
            library.clone(),
            binary.clone(),
            no_test_binary.clone(),
            shared.clone(),
            example.clone(),
            test.clone(),
            bench.clone(),
            build.clone(),
        ];
        files.extend(
            [
                "normal",
                "development",
                "build-dep",
                "target-normal",
                "target-dev",
                "target-build",
            ]
            .into_iter()
            .map(|directory| ProjectFile::new(root.clone(), format!("{directory}/src/lib.rs"))),
        );
        let routes = RustCargoRouteIndex::build_from_disk(&files);

        let normal_root = ProjectFile::new(root.clone(), "normal/src/lib.rs");
        let development_root = ProjectFile::new(root.clone(), "development/src/lib.rs");
        let build_root = ProjectFile::new(root.clone(), "build-dep/src/lib.rs");
        let target_normal_root = ProjectFile::new(root.clone(), "target-normal/src/lib.rs");
        let target_dev_root = ProjectFile::new(root.clone(), "target-dev/src/lib.rs");
        let target_build_root = ProjectFile::new(root.clone(), "target-build/src/lib.rs");

        for target in [
            &library,
            &binary,
            &no_test_binary,
            &example,
            &test,
            &bench,
            &shared,
        ] {
            assert_eq!(
                routes.resolve_crate_root_file(target, "normal_dep"),
                Some(normal_root.clone()),
                "normal dependency from {}",
                target.rel_path().display()
            );
            assert_eq!(
                routes.resolve_crate_root_file(target, "target_normal"),
                Some(target_normal_root.clone()),
                "target-specific normal dependency from {}",
                target.rel_path().display()
            );
        }
        assert_eq!(routes.resolve_crate_root_file(&build, "normal_dep"), None);
        assert_eq!(
            routes.resolve_crate_root_file(&build, "target_normal"),
            None
        );

        for target in [
            &library,
            &binary,
            &no_test_binary,
            &example,
            &test,
            &bench,
            &shared,
        ] {
            assert_eq!(
                routes.resolve_crate_root_file(target, "dev_dep"),
                Some(development_root.clone()),
                "development dependency from {}",
                target.rel_path().display()
            );
            assert_eq!(
                routes.resolve_crate_root_file(target, "target_dev"),
                Some(target_dev_root.clone()),
                "target-specific development dependency from {}",
                target.rel_path().display()
            );
        }
        assert_eq!(routes.resolve_crate_root_file(&build, "dev_dep"), None);
        assert_eq!(routes.resolve_crate_root_file(&build, "target_dev"), None);

        assert_eq!(
            routes.resolve_crate_root_file(&build, "build_dep"),
            Some(build_root)
        );
        assert_eq!(
            routes.resolve_crate_root_file(&build, "target_build"),
            Some(target_build_root)
        );
        for target in [
            &library,
            &binary,
            &no_test_binary,
            &example,
            &test,
            &bench,
            &shared,
        ] {
            assert_eq!(routes.resolve_crate_root_file(target, "build_dep"), None);
            assert_eq!(routes.resolve_crate_root_file(target, "target_build"), None);
        }
        assert_eq!(
            routes.resolve_crate_root_file(&example, "overlap"),
            Some(normal_root),
            "identical normal/dev declarations must deduplicate by destination"
        );
        assert_eq!(routes.resolve_crate_root_file(&build, "app"), None);
    }

    #[test]
    fn workspace_inherited_dependencies_keep_member_dependency_classes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"dependency\"]\nresolver = \"2\"\n\n[workspace.dependencies]\ninherited_normal = { package = \"workspace-dependency\", path = \"dependency\" }\ninherited_dev = { package = \"workspace-dependency\", path = \"dependency\" }\n",
        );
        write(
            &root,
            "dependency/Cargo.toml",
            "[package]\nname = \"workspace-dependency\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "dependency/src/lib.rs", "pub struct Shared;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ntest = false\n\n[dependencies]\ninherited_normal = { workspace = true }\n\n[dev-dependencies]\ninherited_dev = { workspace = true }\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");
        write(&root, "app/tests/integration.rs", "fn test() {}\n");

        let dependency = ProjectFile::new(root.clone(), "dependency/src/lib.rs");
        let library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let test = ProjectFile::new(root.clone(), "app/tests/integration.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            dependency.clone(),
            library.clone(),
            test.clone(),
        ]);

        assert_eq!(
            routes.resolve_crate_root_file(&library, "inherited_normal"),
            Some(dependency.clone())
        );
        assert_eq!(
            routes.resolve_crate_root_file(&library, "inherited_dev"),
            None
        );
        assert_eq!(
            routes.resolve_crate_root_file(&test, "inherited_dev"),
            Some(dependency)
        );
    }

    #[test]
    fn edition_2015_manual_targets_disable_implicit_auto_discovery() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"manual\"\npath = \"cmd/manual.rs\"\n",
        );
        write(&root, "cmd/manual.rs", "fn main() {}\n");
        write(&root, "src/lib.rs", "pub struct ImplicitLibrary;\n");
        write(&root, "src/main.rs", "fn main() {}\n");
        write(&root, "examples/implicit.rs", "fn main() {}\n");

        let manual = ProjectFile::new(root.clone(), "cmd/manual.rs");
        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let main = ProjectFile::new(root.clone(), "src/main.rs");
        let example = ProjectFile::new(root.clone(), "examples/implicit.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            manual.clone(),
            library.clone(),
            main.clone(),
            example.clone(),
        ]);

        assert_eq!(
            routes.target_roots_for_file(&manual),
            std::slice::from_ref(&manual)
        );
        for implicit in [library, main, example] {
            assert!(
                routes.target_roots_for_file(&implicit).is_empty(),
                "{} must not be auto-discovered for a legacy manifest with a manual target",
                implicit.rel_path().display()
            );
        }
    }

    #[test]
    fn inherited_modern_edition_preserves_auto_targets_and_same_file_target_modes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"dev-dep\"]\nresolver = \"2\"\n\n[workspace.package]\nedition = \"2021\"\n",
        );
        write(
            &root,
            "dev-dep/Cargo.toml",
            "[package]\nname = \"dev-dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "dev-dep/src/lib.rs", "pub struct Dev;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n\n[[bin]]\nname = \"manual-main\"\npath = \"src/main.rs\"\ntest = false\n\n[dev-dependencies]\ndev_dep = { package = \"dev-dep\", path = \"../dev-dep\" }\n",
        );
        write(&root, "app/src/main.rs", "fn main() {}\n");
        write(&root, "app/examples/implicit.rs", "fn main() {}\n");

        let dependency = ProjectFile::new(root.clone(), "dev-dep/src/lib.rs");
        let main = ProjectFile::new(root.clone(), "app/src/main.rs");
        let example = ProjectFile::new(root.clone(), "app/examples/implicit.rs");
        let routes = RustCargoRouteIndex::build_from_disk(&[
            dependency.clone(),
            main.clone(),
            example.clone(),
        ]);

        assert_eq!(
            routes.target_roots_for_file(&example),
            std::slice::from_ref(&example)
        );
        assert_eq!(
            routes.resolve_crate_root_file(&main, "dev_dep"),
            Some(dependency.clone()),
            "the auto binary mode on the same file must coexist with test=false explicit mode"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&example, "dev_dep"),
            Some(dependency)
        );
    }

    #[test]
    fn target_specific_dependency_conflicts_fail_closed_by_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"left\", \"right\"]\nresolver = \"2\"\n",
        );
        for dependency in ["left", "right"] {
            write(
                &root,
                &format!("{dependency}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{dependency}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &root,
                &format!("{dependency}/src/lib.rs"),
                "pub struct Shared;\n",
            );
        }
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstable = { package = \"left\", path = \"../left\" }\n\n[target.'cfg(unix)'.dependencies]\nconflict = { package = \"left\", path = \"../left\" }\nstable = { package = \"left\", path = \"../left\" }\nsingle = { package = \"left\", path = \"../left\" }\n\n[target.'cfg(windows)'.dependencies]\nconflict = { package = \"right\", path = \"../right\" }\n",
        );
        write(&root, "app/src/lib.rs", "pub struct App;\n");

        let app = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let left = ProjectFile::new(root.clone(), "left/src/lib.rs");
        let right = ProjectFile::new(root.clone(), "right/src/lib.rs");
        let routes =
            RustCargoRouteIndex::build_from_disk(&[app.clone(), left.clone(), right.clone()]);

        assert_eq!(routes.resolve_crate_root_file(&app, "conflict"), None);
        assert_eq!(
            routes.resolve_crate_root_file(&app, "single"),
            Some(left.clone()),
            "one conditional destination is a structured target-agnostic best effort"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&app, "stable"),
            Some(left.clone()),
            "unconditional and conditional declarations with one destination deduplicate"
        );
        assert!(
            routes
                .files_that_can_reference_target_of(&left)
                .contains(&app),
            "the inverse candidate index must retain reachable dependency roots"
        );
    }

    #[test]
    fn passthrough_macro_routes_require_faithful_item_replay_and_lexical_visibility() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let source = r#"
macro_rules! replay {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
replay! { mod replayed; }

late! { mod defined_too_late; }
macro_rules! late {
    ($($item:item)*) => { $($item)* };
}

macro_rules! feature_items {
    (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* };
}
feature_items! { #![cfg(any())] mod feature_replayed; }

macro_rules! delegated_items {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
macro_rules! nested_delegated_items {
    ($($item:item)*) => {
        #[cfg(unix)]
        delegated_items! { $($item)* }
    };
}
nested_delegated_items! { mod transitively_replayed; }

macro_rules! dropped {
    ($($left:item)* $($right:item)*) => { $($left)* };
}
dropped! { mod dropped_left; mod dropped_right; }

macro_rules! stringified {
    ($($item:item)*) => { stringify!($($item)*) };
}
stringified! { mod stringified_item; }

macro_rules! nested {
    ($($item:item)*) => { wrapper! { $($item)* } };
}
nested! { mod nested_item; }

macro_rules! mixed {
    ($name:ident, $item:item) => { $item };
}
mixed! { marker, mod mixed_item; }

macro_rules! shadowed {
    ($($item:item)*) => { $($item)* };
}
shadowed! { mod before_shadow; }
macro_rules! shadowed {
    (mod $name:ident;) => {};
}
shadowed! { mod after_shadow; }

macro_rules! scoped {
    ($($item:item)*) => { $($item)* };
}
mod inline_scope {
    macro_rules! scoped {
        (mod $name:ident;) => {};
    }
    scoped! { mod inner_shadowed; }

    macro_rules! inline_only {
        ($($item:item)*) => { $($item)* };
    }
    inline_only! { mod inline_replayed; }
}
scoped! { mod outer_replayed; }
inline_only! { mod escaped_inline; }
"#;
        write(&root, "src/lib.rs", source);
        for module in [
            "replayed",
            "feature_replayed",
            "transitively_replayed",
            "defined_too_late",
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "before_shadow",
            "after_shadow",
            "inner_shadowed",
            "inline_scope/inline_replayed",
            "outer_replayed",
            "escaped_inline",
        ] {
            write(&root, &format!("src/{module}.rs"), "pub struct Marker;\n");
        }

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let bindings = rust_rules_item_macro_definitions(tree.root_node(), source)
            .into_iter()
            .fold(HashMap::default(), |mut bindings, definition| {
                bindings
                    .entry(definition.name)
                    .or_insert_with(Vec::new)
                    .push(RustVisibleItemMacroDefinition {
                        visible_after: definition.visible_after,
                        scope_start: definition.scope_start,
                        scope_end: definition.scope_end,
                        passthrough: definition.passthrough,
                    });
                bindings
            });
        let direct_edges =
            rust_external_module_child_edges(&library, source, tree.root_node(), true, &bindings);
        assert!(
            direct_edges
                .iter()
                .any(|edge| edge.file.rel_path() == Path::new("src/replayed.rs")),
            "direct structured macro discovery should replay the positive rule"
        );
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        let routes = analyzer.cargo_routes();

        for module in [
            "replayed",
            "feature_replayed",
            "transitively_replayed",
            "before_shadow",
            "inline_scope/inline_replayed",
            "outer_replayed",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            assert_eq!(
                routes.target_roots_for_file(&file),
                std::slice::from_ref(&library),
                "{module} should be emitted by the latest visible passthrough macro"
            );
        }
        for module in [
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "after_shadow",
            "inner_shadowed",
            "escaped_inline",
            "defined_too_late",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            assert!(
                routes.target_roots_for_file(&file).is_empty(),
                "{module} must not be claimed through an unproven passthrough macro"
            );
        }
    }

    #[test]
    fn duplicate_module_edges_merge_into_the_retained_edge() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let source = "#[path = \"shared.rs\"]\nmod private;\n#[macro_use]\n#[path = \"shared.rs\"]\nmod imported;\n";
        write(&root, "src/lib.rs", source);
        write(
            &root,
            "src/shared.rs",
            "macro_rules! shared_macro { () => {}; }\n",
        );
        let library = ProjectFile::new(root, "src/lib.rs");
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");

        let edges = rust_external_module_child_edges(
            &library,
            source,
            tree.root_node(),
            true,
            &HashMap::default(),
        );

        assert_eq!(edges.len(), 1);
        assert!(edges[0].imports_macros);
        assert_eq!(
            edges[0].declaration_start_byte,
            source.find("mod private").expect("first declaration")
        );
        assert_eq!(
            edges[0].visibility_start_byte,
            source.find("mod imported").expect("macro-use declaration") + "mod imported;".len()
        );
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write fixture");
    }

    /// Every module-declaration shape the syntax walk knows about, in one file:
    /// plain, directory-backed, `#[path]` on a declaration and on an inline
    /// module, `#[macro_use]`, `#[cfg(test)]`, nested inline scopes, duplicate
    /// declarations of one file, and both a replaying and a non-replaying item
    /// macro.
    const MODULE_ROUTE_FIXTURE: &str = r####"
macro_rules! replay {
    ($($item:item)*) => { $($item)* };
}
macro_rules! swallow {
    ($($item:item)*) => {};
}

mod plain;
mod directory_backed;
#[path = "relocated/target.rs"]
mod relocated_declaration;
#[macro_use]
mod macro_source;
#[cfg(test)]
mod gated;
#[cfg(any(test, feature = "fixtures"))]
mod composed_gate;
pub(crate) mod published;

mod outer {
    pub mod inner {
        mod nested_child;
    }
    #[path = "elsewhere"]
    mod relocated_scope {
        mod deep_child;
    }
}

#[path = "shared.rs"]
mod first_alias;
#[macro_use]
#[path = "shared.rs"]
mod second_alias;

replay! { mod replayed; }
swallow! { mod swallowed; }
replay! { replay! { mod doubly_replayed; } }
"####;

    /// Lay the fixture's declared files down on disk. Returns the workspace
    /// root, whose `Cargo.toml` makes it a single-crate workspace.
    fn module_route_fixture(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", MODULE_ROUTE_FIXTURE);
        for relative in [
            "src/plain.rs",
            "src/directory_backed/mod.rs",
            "src/relocated/target.rs",
            "src/macro_source.rs",
            "src/gated.rs",
            "src/composed_gate.rs",
            "src/published.rs",
            "src/outer/inner/nested_child.rs",
            "src/elsewhere/deep_child.rs",
            "src/shared.rs",
            "src/replayed.rs",
            "src/swallowed.rs",
            "src/doubly_replayed.rs",
            // A file the crate root does not declare, used to exercise a
            // non-crate-root declaring file.
            "src/sub.rs",
            "src/sub/child.rs",
        ] {
            write(&root, relative, "pub struct Marker;\n");
        }
        write(
            &root,
            "src/sub.rs",
            "mod child;\n#[path = \"../shared.rs\"]\nmod escaped;\n",
        );
        root
    }

    fn parse_fixture(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        parser.parse(source, None).expect("parse Rust fixture")
    }

    fn visible_item_macros(
        source: &str,
        root_node: Node<'_>,
    ) -> HashMap<String, Vec<RustVisibleItemMacroDefinition>> {
        rust_rules_item_macro_definitions(root_node, source)
            .into_iter()
            .fold(HashMap::default(), |mut bindings, definition| {
                bindings
                    .entry(definition.name)
                    .or_insert_with(Vec::new)
                    .push(RustVisibleItemMacroDefinition {
                        visible_after: definition.visible_after,
                        scope_start: definition.scope_start,
                        scope_end: definition.scope_end,
                        passthrough: definition.passthrough,
                    });
                bindings
            })
    }

    /// The equivalence pin for issue #1793.
    ///
    /// `extract_rust_module_route_facts` plus [`module_child_edges`] replaced
    /// the syntax walk the Cargo-route build ran over every hydrated file, and
    /// this requires the pair to reproduce it edge for edge -- including the
    /// byte offsets, the `#[macro_use]` visibility point, the test gate, and
    /// the merge of duplicate declarations. The walk is frozen at its pre-#1793
    /// form for exactly this comparison.
    ///
    /// Both values of `is_crate_root` matter: it decides whether a file's
    /// declarations search its own directory or its stem's, and the stored rows
    /// deliberately do not know which of the two applies.
    #[test]
    fn module_child_edges_reproduce_the_frozen_syntax_walk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        for relative in ["src/lib.rs", "src/sub.rs"] {
            let file = ProjectFile::new(root.clone(), relative);
            let source = file.read_to_string().expect("read fixture");
            let tree = parse_fixture(&source);
            let item_macros = rust_rules_item_macro_definitions(tree.root_node(), &source);
            let facts = extract_rust_module_route_facts(tree.root_node(), &source, &item_macros);
            for passthrough in [
                HashMap::default(),
                visible_item_macros(&source, tree.root_node()),
            ] {
                for is_crate_root in [true, false] {
                    let expected = rust_external_module_child_edges(
                        &file,
                        &source,
                        tree.root_node(),
                        is_crate_root,
                        &passthrough,
                    );
                    let actual = module_child_edges(&file, &facts, is_crate_root, &passthrough);
                    assert_eq!(
                        actual,
                        expected,
                        "{relative} (crate root {is_crate_root}, {} visible macros)",
                        passthrough.len()
                    );
                }
            }
        }
    }

    /// The fixture must actually exercise the shapes the pin claims to cover,
    /// or the comparison above would hold vacuously.
    #[test]
    fn the_module_route_fixture_exercises_every_declaration_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        let source = file.read_to_string().expect("read fixture");
        let tree = parse_fixture(&source);
        let item_macros = rust_rules_item_macro_definitions(tree.root_node(), &source);
        let facts = extract_rust_module_route_facts(tree.root_node(), &source, &item_macros);

        assert!(
            facts
                .scopes
                .iter()
                .any(|scope| scope.path_attribute.is_some()),
            "an inline module carries a #[path]: {facts:?}"
        );
        assert!(
            facts.scopes.iter().any(|scope| scope.parent == Some(0)
                && scope.module_name == "outer"
                && !scope.imports_macros),
            "the inline scopes are recorded with their macro-use chain: {facts:?}"
        );
        assert!(
            facts
                .routes
                .iter()
                .any(|route| route.path_attribute.is_some()),
            "a declaration carries a #[path]: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.test_gated),
            "a bare #[cfg(test)] declaration is gated: {facts:?}"
        );
        assert!(
            facts
                .routes
                .iter()
                .any(|route| route.module_name == "composed_gate" && !route.test_gated),
            "a composed cfg predicate must not gate: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.imports_macros),
            "a #[macro_use] declaration is recorded: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.gates.len() == 1),
            "a single-macro gate is recorded: {facts:?}"
        );
        assert!(
            facts.routes.iter().any(|route| route.gates.len() == 2),
            "a nested-macro gate chain is recorded: {facts:?}"
        );
        assert!(
            facts.item_macros.len() == 2,
            "both item macros are recorded: {facts:?}"
        );

        // The gates are what the reader filters on, so the two macros must
        // reach opposite verdicts through the real build.
        let passthrough = visible_item_macros(&source, tree.root_node());
        let edges = module_child_edges(&file, &facts, true, &passthrough);
        let named = |name: &str| {
            edges
                .iter()
                .any(|edge| edge.file.rel_path() == Path::new(name))
        };
        assert!(named("src/replayed.rs"), "edges: {edges:?}");
        assert!(named("src/doubly_replayed.rs"), "edges: {edges:?}");
        assert!(!named("src/swallowed.rs"), "edges: {edges:?}");
    }

    /// The point of issue #1793: composing the index reads rows, and parses
    /// nothing. The counter is the `2ba5dda4` structural-pin idiom.
    #[test]
    fn composing_the_cargo_route_index_parses_no_workspace_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        // Analysis is what writes the fact rows; the warm is the catch-up that
        // notices any file analysis did not reach.
        analyzer.warm_usage_facts();
        analyzer.reset_module_route_fact_fallback_count_for_test();

        let routes = analyzer.cargo_routes();

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        assert_eq!(
            routes.target_roots_for_file(&ProjectFile::new(root.clone(), "src/plain.rs")),
            std::slice::from_ref(&library),
            "the index still answers from rows"
        );
        assert_eq!(
            analyzer.module_route_fact_fallback_count_for_test(),
            0,
            "composing the Cargo routes must not parse a single workspace file"
        );
    }

    /// Every Rust file the fixture wrote, in the order an analyzed-file set
    /// presents them.
    fn analyzed_rust_files(root: &Path) -> Vec<ProjectFile> {
        let mut files = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("read fixture directory") {
                let path = entry.expect("fixture entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let relative = path.strip_prefix(root).expect("relative fixture path");
                    files.push(ProjectFile::new(root.to_path_buf(), relative));
                }
            }
        }
        files.sort();
        files
    }

    /// The rows analysis would have written for each file, derived here by
    /// parsing the fixture. `module_child_edges_reproduce_the_frozen_syntax_walk`
    /// is what ties this to what the store actually holds.
    fn route_facts_for(files: &[ProjectFile]) -> HashMap<ProjectFile, RustModuleRouteFacts> {
        let mut facts = HashMap::default();
        for file in files {
            let source = file.read_to_string().expect("read fixture file");
            let tree = parse_fixture(&source);
            let item_macros = rust_rules_item_macro_definitions(tree.root_node(), &source);
            facts.insert(
                file.clone(),
                extract_rust_module_route_facts(tree.root_node(), &source, &item_macros),
            );
        }
        facts
    }

    fn assert_route_indexes_match(actual: &RustCargoRouteIndex, expected: &RustCargoRouteIndex) {
        assert_eq!(
            actual.routes_by_manifest_and_name, expected.routes_by_manifest_and_name,
            "manifest routes"
        );
        assert_eq!(
            actual.declared_dependencies_by_manifest_and_name,
            expected.declared_dependencies_by_manifest_and_name,
            "declared dependencies"
        );
        assert_eq!(
            actual.target_roots_by_file, expected.target_roots_by_file,
            "target membership"
        );
        assert_eq!(actual.targets_by_root, expected.targets_by_root, "targets");
        assert_eq!(
            actual.files_by_reachable_root, expected.files_by_reachable_root,
            "files by reachable root"
        );
        assert_eq!(
            actual.external_module_declarations, expected.external_module_declarations,
            "module declarations"
        );
        assert_eq!(
            actual.test_only_files, expected.test_only_files,
            "test-only files"
        );
    }

    /// A workspace with the shapes target-level composition can get wrong:
    /// several targets per crate (library, binary, extra binary, integration
    /// test, bench, example, build script), a module file two targets share, a
    /// crate whose explicit `[[bin]]` disables auto discovery, a dev-dependency
    /// edge, a `#[path]` declaration, a `#[cfg(test)]` subtree, and a
    /// `#[macro_use]` passthrough macro that expands to a module declaration.
    fn multi_target_workspace(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"engine\", \"app\", \"legacy\"]\nresolver = \"2\"\n",
        );

        write(
            &root,
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[dev-dependencies]\napp = { path = \"../app\" }\n",
        );
        write(&root, "engine/build.rs", "fn main() {}\n");
        write(
            &root,
            "engine/src/lib.rs",
            "#[macro_use]\nmod macros;\npub mod part;\n#[cfg(test)]\nmod tests;\nreplay! { mod expanded; }\nswallow! { mod swallowed; }\n",
        );
        write(
            &root,
            "engine/src/macros.rs",
            "macro_rules! replay {\n    ($($item:item)*) => { $($item)* };\n}\nmacro_rules! swallow {\n    ($($item:item)*) => {};\n}\n",
        );
        write(&root, "engine/src/part.rs", "pub struct Part;\n");
        write(&root, "engine/src/expanded.rs", "pub struct Marker;\n");
        write(&root, "engine/src/swallowed.rs", "pub struct Marker;\n");
        write(&root, "engine/src/tests.rs", "mod helpers;\n");
        write(&root, "engine/src/tests/helpers.rs", "pub fn helper() {}\n");
        // The binary shares the library's module file, so one file belongs to
        // two targets of the same crate.
        write(&root, "engine/src/main.rs", "mod part;\nfn main() {}\n");
        write(
            &root,
            "engine/src/bin/tool.rs",
            "mod support;\nfn main() {}\n",
        );
        write(&root, "engine/src/bin/support.rs", "pub fn support() {}\n");
        // The deepest shape auto discovery accepts, four components below the
        // manifest directory.
        write(
            &root,
            "engine/src/bin/nested/main.rs",
            "mod inner;\nfn main() {}\n",
        );
        write(
            &root,
            "engine/src/bin/nested/inner.rs",
            "pub fn inner() {}\n",
        );
        write(&root, "engine/tests/it.rs", "mod fixtures;\n");
        // `tests/fixtures.rs` is an auto-discovered integration test target in
        // its own right AND a module of `tests/it.rs`, so its own declaration
        // resolves to a different file under each reading. Nothing else in the
        // fixture asks one file for its edges both ways.
        write(
            &root,
            "engine/tests/fixtures.rs",
            "mod shared;\npub fn fixture() {}\n",
        );
        write(&root, "engine/tests/shared.rs", "pub fn shared() {}\n");
        write(
            &root,
            "engine/tests/fixtures/shared.rs",
            "pub fn shared() {}\n",
        );
        write(&root, "engine/benches/bench.rs", "fn main() {}\n");
        write(&root, "engine/examples/demo/main.rs", "fn main() {}\n");

        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nengine = { path = \"../engine\" }\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "pub mod feature;\n#[path = \"custom/relocated.rs\"]\nmod relocated;\n",
        );
        write(&root, "app/src/feature.rs", "pub struct Marker;\n");
        write(
            &root,
            "app/src/custom/relocated.rs",
            "pub struct Relocated;\n",
        );
        write(&root, "app/src/main.rs", "fn main() {}\n");

        write(
            &root,
            "legacy/Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2015\"\n\n[[bin]]\nname = \"legacy-cli\"\npath = \"src/cli.rs\"\n",
        );
        write(&root, "legacy/src/cli.rs", "mod util;\nfn main() {}\n");
        write(&root, "legacy/src/util.rs", "pub fn util() {}\n");
        // Auto discovery is off in this crate, so nothing reaches this file.
        write(&root, "legacy/src/lib.rs", "pub struct Unreachable;\n");
        root
    }

    /// `crates` member crates, each with a library, a binary that shares the
    /// library's module files, and an integration test target, and `modules`
    /// module files each. The shape is deliberately uniform: what the sweep pin
    /// varies is the crate and target count, not the file count.
    fn synthetic_workspace(
        root: &Path,
        crates: usize,
        modules: usize,
    ) -> (Vec<ProjectFile>, HashMap<ProjectFile, RustModuleRouteFacts>) {
        let members: Vec<String> = (0..crates).map(|index| format!("\"c{index}\"")).collect();
        write(
            root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [{}]\nresolver = \"2\"\n",
                members.join(", ")
            ),
        );
        for index in 0..crates {
            let dependency = if index > 0 {
                format!(
                    "\n[dependencies]\nc{} = {{ path = \"../c{}\" }}\n",
                    index - 1,
                    index - 1
                )
            } else {
                String::new()
            };
            write(
                root,
                &format!("c{index}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"c{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{dependency}"
                ),
            );
            let declarations: String = (0..modules)
                .map(|module| format!("pub mod m{module};\n"))
                .collect();
            write(root, &format!("c{index}/src/lib.rs"), &declarations);
            write(root, &format!("c{index}/src/main.rs"), &declarations);
            for module in 0..modules {
                write(
                    root,
                    &format!("c{index}/src/m{module}.rs"),
                    "pub struct Marker;\n",
                );
            }
            write(root, &format!("c{index}/tests/t0.rs"), "mod helpers;\n");
            write(
                root,
                &format!("c{index}/tests/helpers.rs"),
                "pub fn helper() {}\n",
            );
        }
        let files = analyzed_rust_files(root);
        let facts = route_facts_for(&files);
        (files, facts)
    }

    /// The equivalence pin for issue #1817.
    ///
    /// The orchestration was rewritten, not redesigned: the same manifest
    /// topology, the same membership walks, the same macro-visibility fixed
    /// point and the same test-only complement, arranged so that none of them
    /// costs the whole workspace once per crate or once per target. Every
    /// product of the index therefore has to be identical to what the frozen
    /// pre-#1817 orchestration produces from the same rows.
    #[test]
    fn cargo_route_composition_matches_the_pre_1817_orchestration() {
        type Fixture = fn(&tempfile::TempDir) -> PathBuf;
        for (label, build_fixture) in [
            ("multi-target workspace", multi_target_workspace as Fixture),
            (
                "single-crate module shapes",
                module_route_fixture as Fixture,
            ),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let root = build_fixture(&temp);
            let files = analyzed_rust_files(&root);
            let facts = route_facts_for(&files);

            let actual =
                RustCargoRouteIndex::build_while(&files, &facts, &|| true).expect("composed index");
            let expected = frozen_orchestration::reference_build_while(&files, &facts, &|| true)
                .expect("reference index");

            // The comparison is only worth as much as the fixture behind it.
            // What the multi-target workspace additionally covers is pinned by
            // `the_multi_target_fixture_exercises_shared_targets_and_expanded_modules`.
            assert!(
                !expected.targets_by_root.is_empty(),
                "{label}: the fixture must have a Cargo target"
            );
            assert!(
                !expected.external_module_declarations.is_empty(),
                "{label}: the fixture must declare modules"
            );
            assert_route_indexes_match(&actual, &expected);
        }
    }

    /// The multi-target fixture must exercise the shapes the equivalence pin
    /// claims, or that pin holds over a workspace no harder than the one that
    /// already existed.
    #[test]
    fn the_multi_target_fixture_exercises_shared_targets_and_expanded_modules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = multi_target_workspace(&temp);
        let files = analyzed_rust_files(&root);
        let facts = route_facts_for(&files);
        let index = RustCargoRouteIndex::build_while(&files, &facts, &|| true).expect("index");

        let library = ProjectFile::new(root.clone(), "engine/src/lib.rs");
        let binary = ProjectFile::new(root.clone(), "engine/src/main.rs");
        let part = ProjectFile::new(root.clone(), "engine/src/part.rs");
        let mut part_roots = index.target_roots_for_file(&part);
        part_roots.sort();
        let mut shared = vec![binary, library];
        shared.sort();
        assert_eq!(
            part_roots, shared,
            "one module file must belong to two targets of the same crate"
        );
        assert!(
            index.targets_by_root.len() >= 8,
            "library, three binaries, integration test, bench, example and build script: {:?}",
            index.targets_by_root.keys().collect::<Vec<_>>()
        );
        assert!(
            index
                .target_roots_for_file(&ProjectFile::new(
                    root.clone(),
                    "engine/src/bin/nested/inner.rs"
                ))
                .contains(&ProjectFile::new(
                    root.clone(),
                    "engine/src/bin/nested/main.rs"
                )),
            "the deepest auto-discovered target shape must still own its modules"
        );
        let declared: Vec<_> = index
            .external_module_declarations
            .iter()
            .map(|declaration| declaration.target_file.rel_path().to_path_buf())
            .collect();
        assert!(
            declared.contains(&PathBuf::from("engine/src/expanded.rs")),
            "a passthrough macro's module declaration must survive: {declared:?}"
        );
        assert!(
            !declared.contains(&PathBuf::from("engine/src/swallowed.rs")),
            "a macro that does not replay its items must not declare a module: {declared:?}"
        );
        assert!(
            declared.contains(&PathBuf::from("app/src/custom/relocated.rs")),
            "a #[path] declaration must resolve: {declared:?}"
        );
        assert!(
            index.file_is_test_only(&ProjectFile::new(
                root.clone(),
                "engine/src/tests/helpers.rs"
            )),
            "the #[cfg(test)] subtree must stay test-only"
        );
        assert!(
            index
                .target_roots_for_file(&ProjectFile::new(root.clone(), "legacy/src/lib.rs"))
                .is_empty(),
            "an explicit [[bin]] on a 2015 crate disables the auto library target"
        );
        let it = ProjectFile::new(root.clone(), "engine/tests/it.rs");
        let fixtures = ProjectFile::new(root.clone(), "engine/tests/fixtures.rs");
        assert!(
            index
                .target_roots_for_file(&ProjectFile::new(root.clone(), "engine/tests/shared.rs"))
                .contains(&fixtures),
            "a file that is both a target root and a declared module must resolve \
             its own declarations as a crate root"
        );
        assert!(
            index
                .target_roots_for_file(&ProjectFile::new(
                    root.clone(),
                    "engine/tests/fixtures/shared.rs"
                ))
                .contains(&it),
            "and as a module when it is reached through the file that declares it"
        );
    }

    /// The structural pin for issue #1817: composing the routes sweeps the
    /// analyzed file set a bounded number of times, whatever the workspace's
    /// Cargo topology is.
    ///
    /// The defect was that the sweep count grew with the topology -- two per
    /// crate in each of the two membership passes, one per Cargo target for
    /// macro visibility and another for the passthrough fixed point -- which is
    /// what made the build 9-19 s on the rustc tree once #1793 had removed the
    /// parsing that used to hide it. The frozen pre-#1817 orchestration is
    /// measured beside the new one on the same two workspaces, so the
    /// fail-before is inside the pin rather than beside it.
    #[test]
    fn a_cargo_route_build_sweeps_the_workspace_a_bounded_number_of_times() {
        let mut measured = Vec::new();
        for (crates, modules) in [(2usize, 24usize), (16usize, 3usize)] {
            let temp = tempfile::tempdir().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            let (files, facts) = synthetic_workspace(&root, crates, modules);
            let sweeps = workspace_file_sweeps_of(|| {
                RustCargoRouteIndex::build_while(&files, &facts, &|| true).expect("composed index");
            });
            let reference = workspace_file_sweeps_of(|| {
                frozen_orchestration::reference_build_while(&files, &facts, &|| true)
                    .expect("reference index");
            });
            measured.push((crates, files.len(), sweeps, reference));
        }
        let [
            (small_crates, _, small, small_reference),
            (large_crates, _, large, large_reference),
        ] = measured.as_slice()
        else {
            unreachable!("two measurements: {measured:?}");
        };
        assert_eq!(
            small, large,
            "the sweep count must not depend on the crate count ({small_crates} against {large_crates} crates): {measured:?}"
        );
        assert!(
            *large <= 8,
            "the build must sweep the workspace a bounded number of times: {measured:?}"
        );
        assert!(
            large_reference > small_reference && *large_reference >= large * 8,
            "the pre-#1817 orchestration swept once per crate and once per target, which is what this pin exists to keep out: {measured:?}"
        );
    }

    /// The grouping bound in `files_by_auto_target_directory` and the shapes
    /// `auto_cargo_target_kind` accepts are two halves of one rule: a file is
    /// only offered to the manifest directories that could auto-discover it.
    /// A new target shape deeper than the bound would silently stop being
    /// discovered, so the coupling is pinned rather than commented.
    #[test]
    fn auto_target_paths_stay_within_the_grouped_depth() {
        let mut discovered_depths = crate::hash::HashSet::default();
        for relative in [
            "src/main.rs",
            "tests/it.rs",
            "examples/demo.rs",
            "benches/bench.rs",
            "src/bin/tool.rs",
            "examples/demo/main.rs",
            "benches/bench/main.rs",
            "src/bin/tool/main.rs",
            "src/lib.rs",
            "top.rs",
            "src/bin/tool/nested/main.rs",
            "src/deep/nested/module/thing.rs",
        ] {
            let path = Path::new(relative);
            let depth = path.components().count();
            let Some(kind) = auto_cargo_target_kind(path, true, true, true, true) else {
                continue;
            };
            assert!(
                (AUTO_TARGET_MIN_DEPTH..=AUTO_TARGET_MAX_DEPTH).contains(&depth),
                "{relative} is discovered as {kind:?} at depth {depth}, outside the grouped range"
            );
            discovered_depths.insert(depth);
        }
        assert_eq!(
            discovered_depths.len(),
            AUTO_TARGET_MAX_DEPTH - AUTO_TARGET_MIN_DEPTH + 1,
            "every grouped depth must actually discover a target: {discovered_depths:?}"
        );
    }

    /// The index answers the same questions across a multi-crate workspace
    /// when it is composed from rows: target membership, cross-crate route
    /// resolution, the module-declaration list the usage walks read, and the
    /// test-only classification that only the module graph can decide.
    #[test]
    fn cargo_routes_compose_from_rows_across_a_multi_crate_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"engine\"]\nresolver = \"2\"\n",
        );
        write(
            &root,
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "engine/src/lib.rs", "pub mod part;\n");
        write(&root, "engine/src/part.rs", "pub struct Part;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nengine = { path = \"../engine\" }\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "pub mod feature;\n#[cfg(test)]\nmod tests;\n",
        );
        write(&root, "app/src/feature.rs", "pub struct Feature;\n");
        write(&root, "app/src/tests.rs", "mod helpers;\n");
        write(&root, "app/src/tests/helpers.rs", "pub fn helper() {}\n");

        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        analyzer.warm_usage_facts();
        let routes = analyzer.cargo_routes();

        let app_library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let engine_library = ProjectFile::new(root.clone(), "engine/src/lib.rs");
        let feature = ProjectFile::new(root.clone(), "app/src/feature.rs");
        let tests = ProjectFile::new(root.clone(), "app/src/tests.rs");
        let helpers = ProjectFile::new(root.clone(), "app/src/tests/helpers.rs");
        let part = ProjectFile::new(root.clone(), "engine/src/part.rs");

        assert_eq!(
            routes.target_roots_for_file(&feature),
            std::slice::from_ref(&app_library)
        );
        assert_eq!(
            routes.target_roots_for_file(&part),
            std::slice::from_ref(&engine_library)
        );
        assert_eq!(
            routes.resolve_crate_root_file(&feature, "engine"),
            Some(engine_library.clone()),
            "a path dependency still resolves across crates"
        );
        assert_eq!(
            routes.target_relation(&feature, &part),
            RustCargoTargetRelation::Disjoint
        );
        assert!(
            routes.file_is_test_only(&tests) && routes.file_is_test_only(&helpers),
            "test-only reachability still propagates through the module graph"
        );
        assert!(
            !routes.file_is_test_only(&feature),
            "a production module must stay production"
        );
        let declared: Vec<_> = routes
            .external_module_declarations()
            .iter()
            .map(|declaration| {
                (
                    declaration.declaring_file.rel_path().to_path_buf(),
                    declaration.declaring_module.clone(),
                    declaration.target_file.rel_path().to_path_buf(),
                    declaration.test_gated,
                )
            })
            .collect();
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/lib.rs"),
                "app.src".to_string(),
                PathBuf::from("app/src/tests.rs"),
                true,
            )),
            "declarations: {declared:?}"
        );
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/tests.rs"),
                "app.src.tests".to_string(),
                PathBuf::from("app/src/tests/helpers.rs"),
                false,
            )),
            "declarations: {declared:?}"
        );
    }
}
