use crate::analyzer::usages::{ExportEntry, ExportIndex, ImportBinder, ImportKind, ReexportStar};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use super::RustAnalyzer;
use super::declarations::rust_package_name;
use super::imports::{
    RustVisibility, resolve_rust_module_path_with_crate, rust_crate_root_package,
    rust_imports_with_visibility_from_use_declaration,
};
use super::lexical_scope::{insert_rust_import_binding, parse_rust_tree, visible_import_binder_at};

/// Per-file reference-resolution context for Rust — the one primitive both usage
/// paths share. Holds the binder-derived maps a reference resolves through, built
/// once per file and cached on the analyzer ([`RustAnalyzer::reference_context_of`]).
///
/// Rust node fqns are file-independent dotted module paths (`util.format_value`),
/// so a resolved value *is* the graph node key — projecting to the node fqn is the
/// identity. (For JS/TS, where fqns are bare, the resolved value must carry the
/// file; see the execplan's "Identity model".)
#[derive(Debug, Default)]
pub struct RustReferenceContext {
    /// Dotted module/package name for the file this context resolves from.
    package: String,
    /// Dotted module/package name for this file's crate root.
    crate_package: String,
    /// local name -> fqn for `use path::Item;` / `use path::func;` named bindings.
    pub(super) named: HashMap<String, String>,
    /// local alias -> package for `use crate::util;` namespace bindings.
    pub(super) namespace: HashMap<String, String>,
    /// scoped import path -> canonical declaration fqn for namespace imports
    /// whose members are re-exported from another module.
    scoped: HashMap<String, String>,
    /// local name -> canonical declaration fqn for unambiguous glob imports.
    glob: HashMap<String, String>,
    /// identifier -> fqn for items declared in this file.
    pub(super) same_file: HashMap<String, String>,
}

impl RustReferenceContext {
    /// The callee fqn a bare `name` refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` (the binder classifies
    /// the latter as a namespace whose resolved value is the function's own fqn).
    pub fn resolve_bare(&self, name: &str) -> Option<&str> {
        self.named
            .get(name)
            .or_else(|| self.namespace.get(name))
            .or_else(|| self.same_file.get(name))
            .or_else(|| self.glob.get(name))
            .map(String::as_str)
    }

    pub(crate) fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String> {
        self.named
            .iter()
            .chain(self.namespace.iter())
            .chain(self.same_file.iter())
            .chain(self.glob.iter())
            .filter(|&(_, fqn)| fqn == target_fqn)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// The callee fqn a `path::name` refers to: a module function via a namespace
    /// import, or an associated function on an imported / same-file type.
    pub fn resolve_scoped(&self, path: &str, name: &str) -> Option<String> {
        self.resolve_scoped_owner(path)
            .map(|owner| join_rust_fqn(&owner, name))
    }

    /// The owner fqn a scoped `path::name` begins from: a namespace import, a
    /// rooted module path, or an imported / same-file type.
    pub fn resolve_scoped_owner(&self, path: &str) -> Option<String> {
        if let Some(canonical) = self.scoped.get(path) {
            return Some(canonical.clone());
        }
        if let Some((module_path, item_name)) = path.rsplit_once("::")
            && let Some(package) = self.resolve_scoped_owner(module_path)
        {
            return Some(join_rust_fqn(&package, item_name));
        }
        if let Some(package) = self.namespace.get(path) {
            return Some(package.clone());
        }
        if is_rooted_rust_module_path(path)
            && let Some(package) =
                resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
        {
            return Some(package);
        }
        self.named
            .get(path)
            .or_else(|| self.same_file.get(path))
            .or_else(|| self.glob.get(path))
            .cloned()
    }
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

fn insert_single_reexport_target(
    named: &mut HashMap<String, String>,
    exported_name: String,
    targets: BTreeSet<(ProjectFile, String)>,
) {
    let mut targets = targets.into_iter();
    let Some((target_file, target_name)) = targets.next() else {
        return;
    };
    if targets.next().is_some() {
        return;
    }
    named
        .entry(exported_name)
        .or_insert_with(|| join_rust_fqn(&rust_package_name(&target_file), &target_name));
}

fn single_rust_target_fqn(
    analyzer: &RustAnalyzer,
    targets: BTreeSet<(ProjectFile, String)>,
) -> Option<String> {
    let mut fq_names = targets
        .into_iter()
        .flat_map(|(target_file, target_name)| {
            analyzer
                .declarations(&target_file)
                .into_iter()
                .filter(move |unit| unit.identifier() == target_name)
                .filter(|unit| analyzer.is_rust_export_visible_declaration(unit))
                .map(|unit| unit.fq_name())
        })
        .collect::<Vec<_>>();
    fq_names.sort();
    fq_names.dedup();
    (fq_names.len() == 1).then(|| fq_names.remove(0))
}

fn is_rooted_rust_module_path(path: &str) -> bool {
    path == "crate"
        || path == "self"
        || path == "super"
        || path.starts_with("crate::")
        || path.starts_with("self::")
        || path.starts_with("super::")
}

fn rust_declaration_targets_in_files(
    analyzer: &RustAnalyzer,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    let mut targets: Vec<_> = files
        .iter()
        .flat_map(|file| {
            analyzer
                .declarations(file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
                .map(|unit| (file.clone(), unit.identifier().to_string()))
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

impl RustAnalyzer {
    pub fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        if let Some(cached) = self.export_indexes.get(file) {
            return (*cached).clone();
        }
        let declarations = self.declarations(file);
        let index = Arc::new(self.export_index_of_declarations(file, &declarations));
        self.export_indexes.insert(file.clone(), index.clone());
        (*index).clone()
    }

    pub(super) fn export_index_of_declarations(
        &self,
        file: &ProjectFile,
        declarations: &BTreeSet<CodeUnit>,
    ) -> ExportIndex {
        let _scope = crate::profiling::scope("RustAnalyzer::export_index_of_declarations");
        let mut index = ExportIndex::empty();
        let export_visible = self.export_visible_declarations(file, declarations);
        let mut external_visibility = HashMap::default();

        for code_unit in declarations {
            let identifier = code_unit.identifier().trim();
            if identifier.is_empty() || identifier.starts_with('_') {
                continue;
            }
            if !self.is_module_export_candidate(
                file,
                code_unit,
                &export_visible,
                &mut external_visibility,
            ) {
                continue;
            }
            index.exports_by_name.insert(
                identifier.to_string(),
                ExportEntry::Local {
                    local_name: identifier.to_string(),
                },
            );
        }

        if let Some(prepared) = self.prepared_syntax(file) {
            let source = prepared.source();
            let root = prepared.tree().root_node();
            for index_in_root in 0..root.named_child_count() {
                let Some(node) = root.named_child(index_in_root) else {
                    continue;
                };
                if node.kind() != "use_declaration" {
                    continue;
                }
                for import in rust_imports_with_visibility_from_use_declaration(node, source) {
                    if matches!(
                        import.visibility,
                        RustVisibility::Private | RustVisibility::SelfModule
                    ) {
                        continue;
                    }
                    if import.info.is_wildcard {
                        if !import.path.is_empty() {
                            index.reexport_stars.push(ReexportStar {
                                module_specifier: import.path.join("::"),
                            });
                        }
                        continue;
                    }
                    let Some(imported_name) = import.path.last().cloned() else {
                        continue;
                    };
                    let Some(local_name) = import
                        .info
                        .alias
                        .clone()
                        .or_else(|| import.info.identifier.clone())
                    else {
                        continue;
                    };
                    let module_specifier = import.path[..import.path.len() - 1].join("::");
                    index.exports_by_name.insert(
                        local_name,
                        ExportEntry::ReexportedNamed {
                            module_specifier,
                            imported_name,
                        },
                    );
                }
            }
        }

        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            insert_rust_import_binding(&mut binder, &import);
        }

        binder
    }

    pub(crate) fn resolve_imported_export_from_binder_forward(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
    ) -> Vec<(ProjectFile, String)> {
        self.resolve_imported_export_from_binder_with_mode(file, binder, reference, true)
    }

    pub(crate) fn resolve_imported_export_from_binder(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
    ) -> Vec<(ProjectFile, String)> {
        self.resolve_imported_export_from_binder_with_mode(file, binder, reference, false)
    }

    fn resolve_imported_export_from_binder_with_mode(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
        forward: bool,
    ) -> Vec<(ProjectFile, String)> {
        let mut targets = HashSet::default();
        let mut saw_explicit_binding = false;
        for (local_name, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named if local_name == reference => {
                    saw_explicit_binding = true;
                    let imported = binding.imported_name.as_deref().unwrap_or(reference);
                    let files = self.resolve_module_files(file, &binding.module_specifier);
                    targets.extend(if forward {
                        self.forward_exported_targets_from_files(&files, imported)
                    } else {
                        self.exported_targets_from_files(&files, imported)
                    });
                    if targets.is_empty() {
                        targets.extend(rust_declaration_targets_in_files(self, &files, imported));
                    }
                }
                ImportKind::Namespace if local_name == reference => {
                    saw_explicit_binding = true;
                    let Some((module_specifier, imported)) =
                        binding.module_specifier.rsplit_once("::")
                    else {
                        continue;
                    };
                    let files = self.resolve_module_files(file, module_specifier);
                    targets.extend(if forward {
                        self.forward_exported_targets_from_files(&files, imported)
                    } else {
                        self.exported_targets_from_files(&files, imported)
                    });
                    if targets.is_empty() {
                        targets.extend(rust_declaration_targets_in_files(self, &files, imported));
                    }
                }
                ImportKind::Named
                | ImportKind::Namespace
                | ImportKind::Default
                | ImportKind::CommonJsRequire
                | ImportKind::Glob => {}
            }
        }
        if saw_explicit_binding {
            let mut sorted: Vec<_> = targets.into_iter().collect();
            sorted.sort();
            return sorted;
        }
        for binding in binder.bindings.values() {
            if matches!(binding.kind, ImportKind::Glob) {
                let files = self.resolve_module_files(file, &binding.module_specifier);
                targets.extend(if forward {
                    self.forward_exported_targets_from_files(&files, reference)
                } else {
                    self.exported_targets_from_files(&files, reference)
                });
            }
        }
        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Resolve a `use`-path module specifier (e.g. `crate::util`, `super::svc`)
    /// to the dotted package it names, relative to `importing_file`. This is the
    /// `package_name` half of a `CodeUnit::fq_name()` for items in that module, so
    /// the inverted usage-graph builder can turn `(module_specifier, name)` into a
    /// callee fqn without re-deriving the path arithmetic.
    pub fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        if let Some(package) =
            super::cargo_routes::resolve_module_package_for_file(importing_file, module_specifier)
        {
            return Some(package);
        }
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
    }

    /// The cached per-file [`RustReferenceContext`] — the one primitive both the
    /// inverted usage-graph builder and the forward scan resolve references
    /// through. Built once per file from its import binder + same-file
    /// declarations; the cache is dropped on `update`/`update_all`, so a changed
    /// file rebuilds it.
    pub fn reference_context_of(&self, file: &ProjectFile) -> Arc<RustReferenceContext> {
        if let Some(cached) = self.reference_contexts.get(file) {
            return cached;
        }
        let context = Arc::new(self.build_reference_context(file, false));
        self.reference_contexts
            .insert(file.clone(), context.clone());
        context
    }

    pub(crate) fn forward_reference_context_of(
        &self,
        file: &ProjectFile,
    ) -> Arc<RustReferenceContext> {
        if let Some(cached) = self.forward_reference_contexts.get(file) {
            return cached;
        }
        let context = Arc::new(self.build_reference_context(file, true));
        self.forward_reference_contexts
            .insert(file.clone(), context.clone());
        context
    }

    fn build_reference_context(&self, file: &ProjectFile, forward: bool) -> RustReferenceContext {
        let _scope = crate::profiling::scope("RustAnalyzer::build_reference_context");
        let binder = self.import_binder_of(file);
        let same_file: HashMap<String, String> = self
            .declarations(file)
            .into_iter()
            .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
            .collect();
        let mut named: HashMap<String, String> = HashMap::default();
        let mut namespace: HashMap<String, String> = HashMap::default();
        let mut scoped: HashMap<String, String> = HashMap::default();
        let mut glob_candidates: HashMap<String, HashSet<String>> = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        let resolved = self
                            .canonical_export_fqn(
                                file,
                                &binding.module_specifier,
                                imported,
                                forward,
                            )
                            .or_else(|| {
                                self.resolve_module_package(file, &binding.module_specifier)
                                    .map(|package| join_rust_fqn(&package, imported))
                            });
                        if let Some(resolved) = resolved {
                            named.insert(local.clone(), resolved);
                        }
                    }
                }
                ImportKind::Namespace => {
                    if let Some(package) =
                        self.resolve_module_package(file, &binding.module_specifier)
                    {
                        namespace.insert(local.clone(), package);
                    }
                    self.insert_namespace_export_bindings(
                        file,
                        local,
                        &binding.module_specifier,
                        forward,
                        &mut scoped,
                    );
                }
                ImportKind::Glob => self.collect_glob_reference_bindings(
                    file,
                    &binding.module_specifier,
                    forward,
                    &mut glob_candidates,
                ),
                ImportKind::Default | ImportKind::CommonJsRequire => {}
            }
        }
        self.insert_reexport_reference_bindings(file, &mut named, forward);
        let glob = glob_candidates
            .into_iter()
            .filter_map(|(name, mut candidates)| {
                (candidates.len() == 1)
                    .then(|| (name, candidates.drain().next().expect("one glob candidate")))
            })
            .collect();
        RustReferenceContext {
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            named,
            namespace,
            scoped,
            glob,
            same_file,
        }
    }

    fn canonical_export_fqn(
        &self,
        file: &ProjectFile,
        module_specifier: &str,
        name: &str,
        forward: bool,
    ) -> Option<String> {
        let module_files = self.resolve_module_files(file, module_specifier);
        let targets = if forward {
            self.forward_exported_targets_from_files(&module_files, name)
        } else {
            self.exported_targets_from_files(&module_files, name)
        };
        single_rust_target_fqn(self, targets)
    }

    fn insert_namespace_export_bindings(
        &self,
        file: &ProjectFile,
        local: &str,
        module_specifier: &str,
        forward: bool,
        scoped: &mut HashMap<String, String>,
    ) {
        let module_files = self.resolve_module_files(file, module_specifier);
        let mut names = HashSet::default();
        self.collect_export_names_from_files(&module_files, &mut HashSet::default(), &mut names);
        for name in names {
            if let Some(fqn) = self.canonical_export_fqn(file, module_specifier, &name, forward) {
                scoped.insert(format!("{local}::{name}"), fqn);
            }
        }
    }

    fn collect_glob_reference_bindings(
        &self,
        file: &ProjectFile,
        module_specifier: &str,
        forward: bool,
        candidates: &mut HashMap<String, HashSet<String>>,
    ) {
        let module_files = self.resolve_module_files(file, module_specifier);
        let mut names = HashSet::default();
        self.collect_export_names_from_files(&module_files, &mut HashSet::default(), &mut names);
        for name in names {
            if let Some(fqn) = self.canonical_export_fqn(file, module_specifier, &name, forward) {
                candidates.entry(name).or_default().insert(fqn);
            }
        }
    }

    fn insert_reexport_reference_bindings(
        &self,
        file: &ProjectFile,
        named: &mut HashMap<String, String>,
        forward: bool,
    ) {
        let export_index = self.export_index_of(file);
        for (exported_name, entry) in export_index.exports_by_name {
            if let ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            } = entry
            {
                let module_files = self.resolve_module_files(file, &module_specifier);
                let mut targets = if forward {
                    self.forward_exported_targets_from_files(&module_files, &imported_name)
                } else {
                    self.exported_targets_from_files(&module_files, &imported_name)
                };
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(
                        self,
                        &module_files,
                        &imported_name,
                    ));
                }
                insert_single_reexport_target(named, exported_name, targets);
            }
        }

        for star in export_index.reexport_stars {
            let module_files = self.resolve_module_files(file, &star.module_specifier);
            let mut export_names = HashSet::default();
            self.collect_export_names_from_files(
                &module_files,
                &mut HashSet::default(),
                &mut export_names,
            );
            for export_name in export_names {
                let mut targets = if forward {
                    self.forward_exported_targets_from_files(&module_files, &export_name)
                } else {
                    self.exported_targets_from_files(&module_files, &export_name)
                };
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(
                        self,
                        &module_files,
                        &export_name,
                    ));
                }
                insert_single_reexport_target(named, export_name, targets);
            }
        }
    }

    fn collect_export_names_from_files(
        &self,
        module_files: &[ProjectFile],
        visited: &mut HashSet<ProjectFile>,
        names: &mut HashSet<String>,
    ) {
        let mut pending = module_files.to_vec();
        while let Some(module_file) = pending.pop() {
            if !visited.insert(module_file.clone()) {
                continue;
            }
            let export_index = self.export_index_of(&module_file);
            names.extend(export_index.exports_by_name.keys().cloned());
            for star in export_index.reexport_stars {
                pending.extend(self.resolve_module_files(&module_file, &star.module_specifier));
            }
        }
    }

    fn forward_exported_targets_from_files(
        &self,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let mut targets = BTreeSet::new();
        let mut visited = HashSet::default();
        let mut pending: Vec<_> = module_files
            .iter()
            .cloned()
            .map(|file| (file, export_name.to_string(), false))
            .collect();
        while let Some((file, name, reached_through_reexport)) = pending.pop() {
            if !visited.insert((file.clone(), name.clone(), reached_through_reexport)) {
                continue;
            }
            let index = self.export_index_of(&file);
            match index.exports_by_name.get(&name) {
                Some(ExportEntry::Local { local_name }) => {
                    targets.insert((file.clone(), local_name.clone()));
                }
                Some(ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                }) => {
                    pending.extend(
                        self.resolve_module_files(&file, module_specifier)
                            .into_iter()
                            .map(|target_file| (target_file, imported_name.clone(), true)),
                    );
                }
                Some(ExportEntry::Default {
                    local_name: Some(local_name),
                }) => {
                    targets.insert((file.clone(), local_name.clone()));
                }
                Some(ExportEntry::Default { local_name: None }) => {}
                None if reached_through_reexport => {
                    targets.extend(
                        self.declarations(&file)
                            .into_iter()
                            .filter(|unit| unit.identifier() == name)
                            .filter(|unit| self.is_rust_export_visible_declaration(unit))
                            .map(|unit| (file.clone(), unit.identifier().to_string())),
                    );
                }
                None => {}
            }
            for star in index.reexport_stars {
                pending.extend(
                    self.resolve_module_files(&file, &star.module_specifier)
                        .into_iter()
                        .map(|target_file| (target_file, name.clone(), true)),
                );
            }
        }
        targets
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        let analyzed_files = self.get_analyzed_files();
        if let Some(root_file) = self
            .cargo_routes()
            .resolve_crate_root_file(importing_file, module_specifier)
        {
            return analyzed_files
                .into_iter()
                .filter(|file| file == &root_file)
                .collect();
        }
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        let Some(resolved_module) = self
            .resolve_module_package(importing_file, module_specifier)
            .or_else(|| {
                resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
            })
        else {
            return rust_module_files_from_path(importing_file, module_specifier);
        };

        let mut files: Vec<_> = analyzed_files
            .into_iter()
            .filter(|file| rust_package_name(file) == resolved_module)
            .collect();
        files.extend(
            self.inner
                .definitions(&resolved_module)
                .filter(|code_unit| {
                    code_unit.is_module()
                        && (code_unit.source() == importing_file
                            || self.is_visible_module_path(code_unit))
                })
                .map(|code_unit| code_unit.source().clone()),
        );
        files.extend(rust_module_files_from_path(
            importing_file,
            module_specifier,
        ));
        files.sort();
        files.dedup();
        files
    }

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        _instance_receiver: bool,
    ) -> Option<CodeUnit> {
        self.declarations(source_file)
            .into_iter()
            .find(|code_unit| {
                code_unit.identifier() == member_name
                    && self
                        .parent_of(code_unit)
                        .map(|parent| parent.identifier() == owner_name)
                        .unwrap_or(false)
            })
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        let owner_source = self
            .parent_of(target)
            .map(|owner| owner.source().clone())
            .unwrap_or_else(|| target.source().clone());
        let member_name = target.identifier().to_string();

        let project = self.inner.project();
        self.referencing_files_of(&owner_source)
            .into_iter()
            .filter(|file| {
                project.read_source(file).ok().is_some_and(|source| {
                    export_names.iter().any(|name| source.contains(name))
                        || source.contains(&member_name)
                })
            })
            .collect()
    }

    pub fn trait_implementer_names(
        &self,
        trait_owner: &CodeUnit,
        _importer_file: &ProjectFile,
    ) -> HashSet<String> {
        let project = self.inner.project();
        self.get_analyzed_files()
            .into_iter()
            .filter_map(|file| {
                let source = project.read_source(&file).ok()?;
                Some((file, source))
            })
            .flat_map(|(file, source)| {
                let binder = self.import_binder_of(&file);
                trait_implementer_names_from_source(self, trait_owner, &file, &source, &binder)
            })
            .collect()
    }

    pub(crate) fn rust_trait_member_implementations(
        &self,
        trait_member: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        let trait_owner = self.parent_of(trait_member)?;
        if !self.is_rust_trait_declaration(&trait_owner) {
            return None;
        }
        let member_kind = rust_trait_member_kind(self, trait_member)?;
        let member_name = trait_member.identifier();

        let mut implementations = Vec::new();
        let mut seen = HashSet::default();
        for file in self.get_analyzed_files() {
            let Ok(source) = self.inner.project().read_source(&file) else {
                continue;
            };
            let Some(tree) = parse_rust_tree(&source) else {
                continue;
            };
            for impl_item in named_descendants_of_kind(tree.root_node(), "impl_item") {
                let Some((trait_ref, _implementer)) = trait_impl_parts(impl_item, &source) else {
                    continue;
                };
                let binder = visible_import_binder_at(&source, impl_item.start_byte());
                if !trait_reference_matches(self, &trait_owner, &file, &trait_ref, &binder) {
                    continue;
                }
                for member_node in
                    rust_impl_member_nodes(impl_item, &source, member_name, member_kind)
                {
                    let Some(candidate) = self.rust_declaration_for_exact_node(
                        &file,
                        member_node,
                        member_name,
                        member_kind,
                    ) else {
                        continue;
                    };
                    if seen.insert(candidate.clone()) {
                        implementations.push(candidate);
                    }
                }
            }
        }
        Some(implementations)
    }

    pub(crate) fn is_rust_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "trait_item")
    }

    pub(crate) fn is_rust_trait_impl_member_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| {
            let mut parent = node.parent();
            while let Some(candidate) = parent {
                if candidate.kind() == "impl_item" {
                    return candidate.child_by_field_name("trait").is_some();
                }
                parent = candidate.parent();
            }
            false
        })
    }

    pub(crate) fn is_rust_struct_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "struct_item")
    }

    pub(crate) fn is_rust_enum_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "enum_item")
    }

    pub(crate) fn is_rust_type_alias_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "type_item")
    }

    pub(crate) fn is_rust_public_like_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source)
                .is_some_and(|visibility| visibility.starts_with("pub"))
        })
    }

    pub(super) fn rust_declaration_visibility(&self, code_unit: &CodeUnit) -> RustVisibility {
        let Some(prepared) = self.prepared_syntax(code_unit.source()) else {
            return RustVisibility::Private;
        };
        self.rust_named_declaration_node(code_unit, prepared.tree().root_node(), prepared.source())
            .map(|node| super::imports::rust_item_visibility(node, prepared.source()))
            .unwrap_or(RustVisibility::Private)
    }

    /// Whether the declaration's own visibility makes it part of the crate's
    /// exported surface (`pub` / `pub(crate)`), unlike the looser
    /// [`Self::is_rust_public_like_declaration`] which also accepts module-private
    /// forms such as `pub(self)`.
    pub(crate) fn is_rust_export_visible_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.is_export_public_declaration(code_unit)
    }

    fn is_export_public_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source).is_some_and(is_export_visibility)
        })
    }

    fn export_visible_declarations(
        &self,
        file: &ProjectFile,
        declarations: &BTreeSet<CodeUnit>,
    ) -> HashSet<CodeUnit> {
        let Ok(source) = self.inner.project().read_source(file) else {
            return HashSet::default();
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return HashSet::default();
        };
        declarations
            .iter()
            .filter(|code_unit| {
                self.rust_declaration_node(code_unit, tree.root_node())
                    .and_then(|node| rust_visibility_text(node, &source))
                    .is_some_and(is_export_visibility)
            })
            .cloned()
            .collect()
    }

    fn is_module_export_candidate(
        &self,
        file: &ProjectFile,
        code_unit: &CodeUnit,
        export_visible: &HashSet<CodeUnit>,
        external_visibility: &mut HashMap<CodeUnit, bool>,
    ) -> bool {
        if !export_visible.contains(code_unit) {
            return false;
        }

        let mut current = code_unit.clone();
        while let Some(parent) = self.parent_of(&current) {
            let parent_is_export_visible = if parent.source() == file {
                export_visible.contains(&parent)
            } else if let Some(visible) = external_visibility.get(&parent) {
                *visible
            } else {
                let visible = self.is_export_public_declaration(&parent);
                external_visibility.insert(parent.clone(), visible);
                visible
            };
            if !parent.is_module() || !parent_is_export_visible {
                return false;
            }
            current = parent;
        }

        !code_unit.is_function() || self.parent_of(code_unit).is_none()
    }

    pub(super) fn is_visible_module_path(&self, code_unit: &CodeUnit) -> bool {
        let mut current = code_unit.clone();
        loop {
            if !current.is_module() || !self.is_export_public_declaration(&current) {
                return false;
            }
            let Some(parent) = self.parent_of(&current) else {
                return true;
            };
            current = parent;
        }
    }

    pub(crate) fn is_external_module_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_module()
            && self.rust_declaration_node_is(code_unit, |node, _source| {
                node.kind() == "mod_item" && node.child_by_field_name("body").is_none()
            })
    }

    fn rust_declaration_node_is<F>(&self, code_unit: &CodeUnit, predicate: F) -> bool
    where
        F: FnOnce(Node<'_>, &str) -> bool,
    {
        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
            return false;
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return false;
        };
        self.rust_named_declaration_node(code_unit, tree.root_node(), &source)
            .map(|node| predicate(node, &source))
            .unwrap_or(false)
    }

    fn rust_named_declaration_node<'tree>(
        &self,
        code_unit: &CodeUnit,
        root: Node<'tree>,
        source: &str,
    ) -> Option<Node<'tree>> {
        let mut node = self.rust_declaration_node(code_unit, root)?;
        loop {
            if node.child_by_field_name("name").is_some_and(|name| {
                source.get(name.start_byte()..name.end_byte()) == Some(code_unit.identifier())
            }) {
                return Some(node);
            }
            node = node.parent()?;
        }
    }

    fn rust_declaration_node<'tree>(
        &self,
        code_unit: &CodeUnit,
        root: Node<'tree>,
    ) -> Option<Node<'tree>> {
        let ranges = self.ranges(code_unit);
        let range = ranges.first()?;
        root.descendant_for_byte_range(range.start_byte, range.end_byte)
    }

    fn rust_declaration_for_exact_node(
        &self,
        file: &ProjectFile,
        node: Node<'_>,
        member_name: &str,
        member_kind: RustTraitMemberKind,
    ) -> Option<CodeUnit> {
        self.declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == member_name)
            .filter(|unit| rust_code_unit_kind_matches(unit, member_kind))
            .find(|unit| {
                self.ranges(unit).iter().any(|range| {
                    range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
                })
            })
    }
}

#[derive(Clone, Copy)]
enum RustTraitMemberKind {
    AssociatedType,
    Method,
}

fn rust_trait_member_kind(
    analyzer: &RustAnalyzer,
    trait_member: &CodeUnit,
) -> Option<RustTraitMemberKind> {
    if trait_member.is_function() {
        return Some(RustTraitMemberKind::Method);
    }
    if trait_member.is_field() && analyzer.is_type_alias(trait_member) {
        return Some(RustTraitMemberKind::AssociatedType);
    }
    None
}

fn rust_code_unit_kind_matches(code_unit: &CodeUnit, member_kind: RustTraitMemberKind) -> bool {
    match member_kind {
        RustTraitMemberKind::AssociatedType => code_unit.is_field(),
        RustTraitMemberKind::Method => code_unit.is_function(),
    }
}

fn rust_impl_member_nodes<'tree>(
    impl_item: Node<'tree>,
    source: &'tree str,
    member_name: &str,
    member_kind: RustTraitMemberKind,
) -> Vec<Node<'tree>> {
    let Some(body) = impl_item.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|child| rust_impl_member_node_matches(*child, source, member_name, member_kind))
        .collect()
}

fn rust_impl_member_node_matches(
    node: Node<'_>,
    source: &str,
    member_name: &str,
    member_kind: RustTraitMemberKind,
) -> bool {
    let expected_kind = match member_kind {
        RustTraitMemberKind::AssociatedType => "type_item",
        RustTraitMemberKind::Method => "function_item",
    };
    node.kind() == expected_kind
        && node
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == member_name)
}

pub(super) fn rust_module_files_from_path(
    file: &ProjectFile,
    module_specifier: &str,
) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_path(file, module_specifier) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub(super) fn rust_module_files_from_segments(
    file: &ProjectFile,
    segments: &[String],
) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_segments(file, segments) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

fn rust_relative_module_segments(file: &ProjectFile, segments: &[String]) -> Option<PathBuf> {
    let (first, rest) = segments.split_first()?;
    let append = |base: &mut PathBuf, parts: &[String]| {
        for part in parts {
            base.push(part);
        }
    };
    let mut module = match first.as_str() {
        "crate" | "self" => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        "super" => {
            let mut path = file
                .parent()
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf();
            let mut index = 0;
            while rest.get(index).is_some_and(|part| part == "super") {
                path.pop();
                index += 1;
            }
            append(&mut path, &rest[index..]);
            path
        }
        crate_name if Some(crate_name) == rust_current_crate_name(file).as_deref() => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        _ => {
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let mut path = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            append(&mut path, segments);
            path
        }
    };
    (!module.as_os_str().is_empty()).then_some(std::mem::take(&mut module))
}

fn rust_relative_module_path(file: &ProjectFile, module_specifier: &str) -> Option<PathBuf> {
    let module = module_specifier
        .strip_prefix("crate::")
        .or_else(|| module_specifier.strip_prefix("self::"))
        .map(PathBuf::from)
        .or_else(|| {
            module_specifier
                .strip_prefix("super::")
                .map(|rest| file.parent().parent().unwrap_or(Path::new("")).join(rest))
        })
        .or_else(|| {
            let (crate_name, rest) = module_specifier.split_once("::")?;
            (Some(crate_name) == rust_current_crate_name(file).as_deref()).then(|| rest.into())
        })
        .or_else(|| {
            let relative = PathBuf::from(module_specifier);
            if relative.as_os_str().is_empty() {
                return None;
            }
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let module_root = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            Some(module_root.join(relative))
        })?;
    Some(module.to_string_lossy().replace("::", "/").into())
}

fn rust_current_crate_name(file: &ProjectFile) -> Option<String> {
    let manifest = file.root().join("Cargo.toml");
    let source = std::fs::read_to_string(manifest).ok()?;
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = trimmed.strip_prefix("name")?.trim_start();
        let value = value.strip_prefix('=')?.trim();
        value
            .trim_matches('"')
            .split('"')
            .next()
            .filter(|name| !name.is_empty())
            .map(|name| name.replace('-', "_"))
    })
}

fn rust_visibility_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| child.kind() == "visibility_modifier")
        .and_then(|child| source.get(child.start_byte()..child.end_byte()))
        .map(str::trim)
}

fn is_export_visibility(visibility: &str) -> bool {
    let compact: String = visibility
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    compact == "pub" || compact == "pub(crate)" || compact.starts_with("pub(incrate")
}

fn named_descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            matches.push(current);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    matches.reverse();
    matches
}

fn trait_implementer_names_from_source(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
) -> Vec<String> {
    let Some(tree) = parse_rust_tree(source) else {
        return Vec::new();
    };
    let mut implementers = Vec::new();
    collect_trait_implementer_names(
        tree.root_node(),
        analyzer,
        trait_owner,
        impl_file,
        source,
        binder,
        &mut implementers,
    );
    implementers
}

fn collect_trait_implementer_names(
    node: Node<'_>,
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
    implementers: &mut Vec<String>,
) {
    if node.kind() == "impl_item"
        && let Some((trait_ref, implementer)) = trait_impl_parts(node, source)
        && trait_reference_matches(analyzer, trait_owner, impl_file, &trait_ref, binder)
    {
        implementers.push(implementer);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_trait_implementer_names(
            child,
            analyzer,
            trait_owner,
            impl_file,
            source,
            binder,
            implementers,
        );
    }
}

fn trait_impl_parts(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let trait_node = node.child_by_field_name("trait")?;
    let type_node = node.child_by_field_name("type")?;
    Some((
        node_text(trait_node, source).to_string(),
        simple_type_name(type_node, source)?,
    ))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(node_text(node, source).to_string()),
        "scoped_type_identifier" | "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|name| node_text(name, source).to_string()),
        "generic_type" | "reference_type" => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
        _ => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}

fn trait_reference_matches(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && analyzer
                .resolve_module_files(impl_file, module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source());
    }

    if impl_file == trait_owner.source() && trait_ref == trait_owner.identifier() {
        return true;
    }

    impl_binder
        .bindings
        .get(trait_ref)
        .filter(|binding| binding.imported_name.as_deref() == Some(trait_owner.identifier()))
        .is_some_and(|binding| {
            analyzer
                .resolve_module_files(impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn forward_reference_context_is_reused_within_analyzer_generation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod exports;\n"),
                ("src/exports.rs", "pub use std::collections::HashMap;\n"),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/exports.rs");

        let first = analyzer.forward_reference_context_of(&file);
        let second = analyzer.forward_reference_context_of(&file);

        assert!(Arc::ptr_eq(&first, &second));
        assert!(analyzer.export_indexes.get(&file).is_some());

        let unrelated_watcher_noise = ProjectFile::new(fixture.project_root(), ".brokk/cache.db");
        let updated = analyzer.update(&BTreeSet::from([file.clone(), unrelated_watcher_noise]));
        let after_noop_update = updated.forward_reference_context_of(&file);

        assert!(Arc::ptr_eq(&first, &after_noop_update));
        assert!(updated.export_indexes.get(&file).is_some());
    }
}
