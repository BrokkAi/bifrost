use crate::analyzer::ProjectFile;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::hash::HashMap;
use semver::{Version, VersionReq};
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tree_sitter::{Node, Parser};

use super::declarations::{
    rust_macro_invocation_arguments, rust_package_name, rust_rules_item_macro_definitions,
    rust_unqualified_macro_invocation_name,
};
use super::imports::{
    RustVisibility, rust_external_module_route, rust_external_module_segments, rust_item_visibility,
};

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
    target_roots_by_file: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>>,
    targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>>,
    files_by_reachable_root: HashMap<ProjectFile, Vec<ProjectFile>>,
    external_module_declarations: Vec<RustCargoModuleDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RustCargoModuleDeclaration {
    pub(super) declaring_file: ProjectFile,
    pub(super) declaring_module: String,
    pub(super) target_file: ProjectFile,
    pub(super) visibility: RustVisibility,
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
    pub(super) fn build(
        files: &[ProjectFile],
        mut prepared_syntax: impl FnMut(&ProjectFile) -> Option<Arc<PreparedSyntaxTree>>,
    ) -> Self {
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Self::default();
        };
        if discover_cargo_manifest_directories(root, files).is_empty() {
            // Without a Cargo manifest there are no target, dependency, or
            // edition identities for this index to model. Avoid hydrating and
            // parsing every Rust file before the manifest builder reaches the
            // same empty result.
            return Self::default();
        }
        let mut prepared_by_file = HashMap::default();
        let mut macro_definitions = Vec::new();
        for file in files {
            let Some(prepared) = prepared_syntax(file) else {
                continue;
            };
            for definition in
                rust_rules_item_macro_definitions(prepared.tree().root_node(), prepared.source())
            {
                macro_definitions.push((file.clone(), definition));
            }
            prepared_by_file.insert(file.clone(), prepared);
        }
        let no_passthrough_macros = HashMap::default();
        let physical_routes =
            Self::build_from_module_children(files, |file, is_crate_root, _target| {
                prepared_by_file
                    .get(file)
                    .map(|prepared| {
                        rust_external_module_children(
                            file,
                            prepared.source(),
                            prepared.tree().root_node(),
                            is_crate_root,
                            &no_passthrough_macros,
                        )
                    })
                    .unwrap_or_default()
            });
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
            let mut children_by_file: HashMap<ProjectFile, Vec<RustExternalModuleChild>> =
                HashMap::default();
            let mut parents_by_file: HashMap<ProjectFile, Vec<(ProjectFile, bool, usize)>> =
                HashMap::default();
            for file in files {
                if !physical_routes
                    .target_roots_by_file
                    .get(file)
                    .is_some_and(|roots| roots.contains(target))
                {
                    continue;
                }
                let Some(prepared) = prepared_by_file.get(file) else {
                    continue;
                };
                let edges = rust_external_module_child_edges(
                    file,
                    prepared.source(),
                    prepared.tree().root_node(),
                    file == target,
                    &no_passthrough_macros,
                );
                for edge in &edges {
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
                        prepared_by_file.get(&file).is_some_and(|prepared| {
                            let root = prepared.tree().root_node();
                            start == root.start_byte() && end == root.end_byte()
                        })
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
                    let (scope_start, scope_end) = if file == *definition_file {
                        (definition.scope_start, definition.scope_end)
                    } else {
                        let Some(prepared) = prepared_by_file.get(&file) else {
                            continue;
                        };
                        let root = prepared.tree().root_node();
                        (root.start_byte(), root.end_byte())
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
            let mut pending = physical_routes
                .target_roots_by_file
                .iter()
                .filter(|(_, roots)| roots.contains(target))
                .map(|(file, _)| file.clone())
                .collect::<VecDeque<_>>();
            let mut processed_binding_counts: HashMap<ProjectFile, usize> = HashMap::default();
            while let Some(file) = pending.pop_front() {
                let Some(prepared) = prepared_by_file.get(&file) else {
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
                let edges = rust_external_module_child_edges(
                    &file,
                    prepared.source(),
                    prepared.tree().root_node(),
                    file == *target,
                    &bindings,
                );
                for edge in edges {
                    if physical_routes
                        .target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        continue;
                    }
                    let Some(child_prepared) = prepared_by_file.get(&edge.file) else {
                        continue;
                    };
                    let child_root = child_prepared.tree().root_node();
                    let child_bindings = passthrough_by_target_and_file
                        .entry((target.clone(), edge.file.clone()))
                        .or_default();
                    let before = child_bindings.values().map(Vec::len).sum::<usize>();
                    for (name, definitions) in &bindings {
                        let Some(passthrough) = rust_latest_visible_item_macro(
                            definitions,
                            edge.declaration_start_byte,
                        ) else {
                            continue;
                        };
                        let inherited = RustVisibleItemMacroDefinition {
                            visible_after: 0,
                            scope_start: child_root.start_byte(),
                            scope_end: child_root.end_byte(),
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
        let mut index = Self::build_from_module_children(files, |file, is_crate_root, target| {
            prepared_by_file
                .get(file)
                .map(|prepared| {
                    let passthrough_macros = passthrough_by_target_and_file
                        .get(&(target.clone(), file.clone()))
                        .unwrap_or(&no_passthrough_macros);
                    let edges = rust_external_module_child_edges(
                        file,
                        prepared.source(),
                        prepared.tree().root_node(),
                        is_crate_root,
                        passthrough_macros,
                    );
                    external_module_declarations.extend(edges.iter().map(|edge| {
                        RustCargoModuleDeclaration {
                            declaring_file: file.clone(),
                            declaring_module: edge.declaring_module.clone(),
                            target_file: edge.file.clone(),
                            visibility: edge.visibility.clone(),
                        }
                    }));
                    edges.into_iter().map(|edge| edge.file).collect()
                })
                .unwrap_or_default()
        });
        sort_and_dedup_external_module_declarations(&mut external_module_declarations);
        index.external_module_declarations = external_module_declarations;
        index
    }

    fn build_from_module_children(
        files: &[ProjectFile],
        mut module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
    ) -> Self {
        let Some(root) = files.first().map(ProjectFile::root) else {
            return Self::default();
        };
        let manifests: HashMap<_, _> = discover_cargo_manifest_directories(root, files)
            .into_iter()
            .filter_map(|directory| read_manifest(root, &directory).map(|value| (directory, value)))
            .collect();
        let crates: Vec<_> = manifests
            .iter()
            .filter_map(|(directory, manifest)| {
                cargo_crate(root, directory.clone(), manifest.clone(), &manifests)
            })
            .collect();

        let mut crate_by_directory = HashMap::default();
        for (index, cargo_crate) in crates.iter().enumerate() {
            crate_by_directory.insert(cargo_crate.directory.clone(), index);
        }
        let mut routes_by_manifest_and_name: HashMap<_, Vec<RustCargoRoute>> = HashMap::default();
        let mut target_roots_by_file: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> =
            HashMap::default();
        let mut targets_by_root: HashMap<ProjectFile, crate::hash::HashSet<RustCargoTarget>> =
            HashMap::default();
        for cargo_crate in &crates {
            let target_roots = cargo_target_roots(root, cargo_crate, files);
            for (target_root, kinds) in &target_roots {
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
            for (file, roots) in
                cargo_target_memberships(files, &target_root_files, &mut module_children)
            {
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
                for (exposed_name, raw_dependency) in dependencies {
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
            routes.sort_by(|left, right| {
                left.root_file
                    .cmp(&right.root_file)
                    .then_with(|| left.package.cmp(&right.package))
            });
            routes.dedup();
        }
        let mut index = Self {
            routes_by_manifest_and_name,
            target_roots_by_file,
            targets_by_root,
            files_by_reachable_root: HashMap::default(),
            external_module_declarations: Vec::new(),
        };
        index.files_by_reachable_root = index.build_files_by_reachable_root();
        index
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

    pub(super) fn external_module_declarations(&self) -> &[RustCargoModuleDeclaration] {
        &self.external_module_declarations
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

    fn build_files_by_reachable_root(&self) -> HashMap<ProjectFile, Vec<ProjectFile>> {
        let mut files_by_root: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> =
            HashMap::default();
        for (file, target_roots) in &self.target_roots_by_file {
            for root in target_roots {
                files_by_root
                    .entry(root.clone())
                    .or_default()
                    .insert(file.clone());
                let Some(targets) = self.targets_by_root.get(root) else {
                    continue;
                };
                for target in targets {
                    for ((manifest, _), routes) in &self.routes_by_manifest_and_name {
                        if manifest != &target.manifest {
                            continue;
                        }
                        for route in routes
                            .iter()
                            .filter(|route| cargo_route_available_to_target(route, target))
                        {
                            files_by_root
                                .entry(route.root_file.clone())
                                .or_default()
                                .insert(file.clone());
                        }
                    }
                }
            }
        }
        files_by_root
            .into_iter()
            .map(|(root, files)| {
                let mut files = files.into_iter().collect::<Vec<_>>();
                files.sort();
                (root, files)
            })
            .collect()
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
        Some(RustCargoDependencyKind::Normal) => target.kind != RustCargoTargetKind::Build,
        Some(RustCargoDependencyKind::Development) => target.development_capable,
        Some(RustCargoDependencyKind::Build) => target.kind == RustCargoTargetKind::Build,
    }
}

fn cargo_target_roots(
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
    let auto_examples =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autoexamples", &cargo_crate.edition);
    let auto_tests =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autotests", &cargo_crate.edition);
    let auto_benches =
        cargo_auto_discovery_enabled(&cargo_crate.manifest, "autobenches", &cargo_crate.edition);
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

fn cargo_target_memberships(
    files: &[ProjectFile],
    target_roots: &[ProjectFile],
    module_children: &mut impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
) -> HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> {
    let analyzed: crate::hash::HashSet<_> = files.iter().cloned().collect();
    let mut owners: HashMap<ProjectFile, crate::hash::HashSet<ProjectFile>> = HashMap::default();
    let mut pending = VecDeque::new();
    let mut visited = crate::hash::HashSet::default();
    for target in target_roots {
        owners
            .entry(target.clone())
            .or_default()
            .insert(target.clone());
        pending.push_back((target.clone(), target.clone(), true));
    }
    while let Some((file, target, is_crate_root)) = pending.pop_front() {
        if !visited.insert((file.clone(), target.clone(), is_crate_root)) {
            continue;
        }
        for child in module_children(&file, is_crate_root, &target) {
            if analyzed.contains(&child) {
                owners
                    .entry(child.clone())
                    .or_default()
                    .insert(target.clone());
                pending.push_back((child, target.clone(), false));
            }
        }
    }
    owners
}

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

#[derive(Clone)]
struct RustExternalModuleChild {
    file: ProjectFile,
    declaring_module: String,
    visibility: RustVisibility,
    imports_macros: bool,
    declaration_start_byte: usize,
    visibility_start_byte: usize,
}

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
            true
        } else {
            false
        }
    });
    children
}

struct RustPendingMacroFragment {
    source: String,
    source_base_byte: usize,
    module_directory: PathBuf,
    path_attribute_directory: PathBuf,
    imports_macros_to_file_scope: bool,
    declaring_module: String,
}

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

fn rust_macro_argument_items<'a>(arguments: Node<'_>, source: &'a str) -> Option<&'a str> {
    let start = arguments.start_byte().checked_add(1)?;
    let end = arguments.end_byte().checked_sub(1)?;
    (start <= end).then(|| source.get(start..end)).flatten()
}

fn rust_path_attribute(module: Node<'_>, source: &str) -> Option<PathBuf> {
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
            return rust_static_string_literal(value, source)
                .filter(|path| !path.is_empty())
                .map(PathBuf::from);
        }
        sibling = attribute_item.prev_named_sibling();
    }
    None
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
) -> crate::hash::HashSet<PathBuf> {
    let mut discovered = crate::hash::HashSet::default();
    let mut pending = VecDeque::new();
    if root.join("Cargo.toml").is_file() {
        pending.push_back(PathBuf::new());
    }
    pending.extend(files.iter().filter_map(nearest_manifest_directory));

    while let Some(directory) = pending.pop_front() {
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
            pending.extend(dependencies.values().filter_map(|dependency| {
                let path = dependency
                    .as_table()?
                    .get("path")?
                    .as_str()
                    .map(Path::new)?;
                let directory = workspace_relative_path(root, &directory, path)?;
                root.join(&directory)
                    .join("Cargo.toml")
                    .is_file()
                    .then_some(directory)
            }));
        }
    }
    discovered
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
