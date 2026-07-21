//! Analyzer-level re-export + importer index for Rust, so both usage paths
//! resolve references through analyzer state. Built once from the analyzer's own
//! export and import projections plus a compact module-file routing index, and
//! cached on [`RustAnalyzer`] (dropped on `update`/`update_all` like the other
//! caches).
//!
//! Forward export seeds follow re-export chains
//! ([`RustUsageIndex::seeds_for_target`]); the reverse importer index narrows the
//! candidate file set ([`RustUsageIndex::importers_of_seeds`]) and resolves which
//! local names in an importer bind a seed
//! ([`RustUsageIndex::matching_edges_for_importer`]).

use crate::analyzer::usages::{ExportEntry, ExportIndex};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use super::RustAnalyzer;
use super::cargo_routes::{RustCargoRouteIndex, RustCargoRouteKind};
use super::declarations::rust_package_name;
use super::graph_support::{rust_module_files_from_path, rust_module_files_from_segments};
use super::imports::{
    RustImportOwner, RustProjectedImport, RustVisibility, resolve_rust_module_path_with_crate,
    resolve_rust_module_segments_with_crate, rust_crate_root_package, rust_import_projection,
    rust_module_extents,
};

/// How a local binding in an importer refers to its target: a named import
/// (`use path::Item;`) or a namespace import (`use crate::module;`). A glob
/// (`use path::*;`) carries no single name, so it is lowered to one `Named` edge
/// per export of the target file in [`build_importer_reverse`] rather than getting
/// its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RustImportEdgeKind {
    Named(String),
    Namespace,
    Glob,
    Qualified(Vec<String>),
}

#[derive(Debug, Clone)]
pub(super) struct RustImportEdge {
    pub(super) importer: ProjectFile,
    importer_module: ModuleKey,
    extent: RustImportExtent,
    pub(super) local_name: String,
    pub(super) target_file: ProjectFile,
    target_module: ModuleKey,
    pub(super) kind: RustImportEdgeKind,
    propagate_alias: bool,
    domain: Domain,
    namespace: Option<RustSymbolNamespace>,
    provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum RustRouteProvenance {
    Local,
    CurrentLibrary,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RustSymbolNamespace {
    Type,
    Value,
    Macro,
    Module,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustReferenceNamespace {
    Type,
    Value,
    Macro,
    PathPrefix,
    Any,
}

impl RustSymbolNamespace {
    fn of(analyzer: &RustAnalyzer, declaration: &CodeUnit) -> Option<Self> {
        if analyzer.is_type_alias(declaration) {
            return Some(Self::Type);
        }
        match declaration.kind() {
            crate::analyzer::CodeUnitType::Class => Some(Self::Type),
            crate::analyzer::CodeUnitType::Function | crate::analyzer::CodeUnitType::Field => {
                Some(Self::Value)
            }
            crate::analyzer::CodeUnitType::Macro => Some(Self::Macro),
            crate::analyzer::CodeUnitType::Module => Some(Self::Module),
            crate::analyzer::CodeUnitType::FileScope => None,
        }
    }

    fn accepts(self, reference: RustReferenceNamespace) -> bool {
        matches!(reference, RustReferenceNamespace::Any)
            || matches!(
                (self, reference),
                (
                    Self::Type,
                    RustReferenceNamespace::Type | RustReferenceNamespace::PathPrefix
                ) | (Self::Value, RustReferenceNamespace::Value)
                    | (Self::Macro, RustReferenceNamespace::Macro)
                    | (Self::Module, RustReferenceNamespace::PathPrefix)
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RustSymbolIdentity {
    file: ProjectFile,
    module: ModuleKey,
    name: String,
    namespace: RustSymbolNamespace,
}

impl RustSymbolIdentity {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RustImportExtent {
    Module {
        start: usize,
        end: usize,
    },
    LocalOnly {
        module_start: usize,
        module_end: usize,
        start: usize,
        end: usize,
    },
}

impl RustImportExtent {
    fn contains(&self, byte: usize) -> bool {
        match self {
            Self::Module { start, end } => *start <= byte && byte < *end,
            Self::LocalOnly {
                module_start,
                module_end,
                start,
                end,
            } => *module_start <= byte && byte < *module_end && *start <= byte && byte < *end,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModuleKey {
    crate_root: String,
    components: Vec<String>,
}

impl ModuleKey {
    fn new(file: &ProjectFile, module: &str) -> Self {
        let crate_root = rust_crate_root_package(file);
        let relative = if module == crate_root {
            ""
        } else {
            module
                .strip_prefix(&crate_root)
                .and_then(|suffix| suffix.strip_prefix('.'))
                .unwrap_or(module)
        };
        let components = relative
            .split('.')
            .filter(|component| !component.is_empty())
            .map(str::to_string)
            .collect();
        Self {
            crate_root,
            components,
        }
    }

    fn contains(&self, candidate: &Self) -> bool {
        self.crate_root == candidate.crate_root
            && candidate.components.starts_with(&self.components)
    }

    fn parent(&self) -> Option<Self> {
        let mut components = self.components.clone();
        components.pop()?;
        Some(Self {
            crate_root: self.crate_root.clone(),
            components,
        })
    }

    fn with_suffix(&self, suffix: &[String]) -> Self {
        let mut components = Vec::with_capacity(self.components.len() + suffix.len());
        components.extend(self.components.iter().cloned());
        components.extend(suffix.iter().cloned());
        Self {
            crate_root: self.crate_root.clone(),
            components,
        }
    }

    fn package(&self) -> String {
        if self.crate_root.is_empty() {
            self.components.join(".")
        } else if self.components.is_empty() {
            self.crate_root.clone()
        } else {
            format!("{}.{}", self.crate_root, self.components.join("."))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Domain {
    Public,
    Crate(String),
    Module(ModuleKey),
}

impl Domain {
    fn contains_module(&self, importer: &ModuleKey) -> bool {
        match self {
            Self::Public => true,
            Self::Crate(crate_package) => importer.crate_root == *crate_package,
            Self::Module(module) => module.contains(importer),
        }
    }

    fn intersect(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Public, domain) | (domain, Self::Public) => Some(domain.clone()),
            (Self::Crate(left), Self::Crate(right)) => {
                (left == right).then(|| Self::Crate(left.clone()))
            }
            (Self::Crate(crate_root), Self::Module(module))
            | (Self::Module(module), Self::Crate(crate_root)) => {
                (&module.crate_root == crate_root).then(|| Self::Module(module.clone()))
            }
            (Self::Module(left), Self::Module(right)) => {
                if left.contains(right) {
                    Some(Self::Module(right.clone()))
                } else if right.contains(left) {
                    Some(Self::Module(left.clone()))
                } else {
                    None
                }
            }
        }
    }
}

pub(crate) struct RustBindingSeeds {
    roots: BTreeSet<CodeUnit>,
    root_origins: HashSet<RustSymbolIdentity>,
    identities: HashSet<RustSymbolIdentity>,
    identity_domains: HashMap<RustSymbolIdentity, Vec<Domain>>,
    edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>>,
}

#[derive(Debug, Clone)]
struct RustOriginRoute {
    importer_module: ModuleKey,
    extent: RustImportExtent,
    path: Vec<String>,
    namespace: RustSymbolNamespace,
    origin: RustSymbolIdentity,
    domain: Domain,
}

#[derive(Debug, Default)]
struct RustPhysicalOwnerIndex {
    roots_by_file: HashMap<ProjectFile, HashSet<ProjectFile>>,
    inferred_crates_by_file: HashMap<ProjectFile, String>,
}

impl RustPhysicalOwnerIndex {
    fn build(
        analyzer: &RustAnalyzer,
        module_files: &RustModuleFiles,
        physical_roots: &HashMap<ProjectFile, ModuleKey>,
        declarations: &HashMap<CodeUnit, RustSymbolIdentity>,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        let mut edges: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for (_declaration, identity) in declarations.iter().filter(|(declaration, identity)| {
            identity.namespace == RustSymbolNamespace::Module
                && analyzer.is_external_module_declaration(declaration)
        }) {
            let declared = identity
                .module
                .with_suffix(std::slice::from_ref(&identity.name));
            let mut children: Vec<_> = module_files
                .files_for_module(&declared)
                .into_iter()
                .filter(|file| {
                    file != &identity.file && physical_roots.get(file) == Some(&declared)
                })
                .collect();
            if let Some(physical_root) = physical_roots.get(&identity.file)
                && let Some(relative_segments) = declared
                    .components
                    .strip_prefix(physical_root.components.as_slice())
            {
                children.extend(
                    rust_module_files_from_segments(&identity.file, relative_segments)
                        .into_iter()
                        .filter(|file| file != &identity.file && physical_roots.contains_key(file)),
                );
            }
            children.sort();
            children.dedup();
            edges
                .entry(identity.file.clone())
                .or_default()
                .extend(children);
        }

        let mut index = Self::default();
        let mut pending = VecDeque::new();
        for root in roots {
            pending.push_back((root.clone(), root.clone()));
        }
        while let Some((file, owner)) = pending.pop_front() {
            if !index
                .roots_by_file
                .entry(file.clone())
                .or_default()
                .insert(owner.clone())
            {
                continue;
            }
            pending.extend(
                edges
                    .get(&file)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .map(|child| (child, owner.clone())),
            );
        }
        let rooted_crates: HashSet<_> = roots
            .iter()
            .filter_map(|root| physical_roots.get(root))
            .map(|module| module.crate_root.clone())
            .collect();
        index.inferred_crates_by_file.extend(
            physical_roots
                .iter()
                .filter(|(_, module)| !rooted_crates.contains(&module.crate_root))
                .map(|(file, module)| (file.clone(), module.crate_root.clone())),
        );
        index
    }

    fn intersects(&self, left: &ProjectFile, right: &ProjectFile) -> bool {
        self.roots_by_file.get(left).is_some_and(|left| {
            self.roots_by_file
                .get(right)
                .is_some_and(|right| left.iter().any(|root| right.contains(root)))
        }) || self.inferred_crates_by_file.get(left).is_some_and(|left| {
            self.inferred_crates_by_file
                .get(right)
                .is_some_and(|right| left == right)
        })
    }

    fn owned_by(&self, file: &ProjectFile, root: &ProjectFile) -> bool {
        self.roots_by_file
            .get(file)
            .is_some_and(|roots| roots.contains(root))
    }

    fn has_owners(&self, file: &ProjectFile) -> bool {
        self.roots_by_file
            .get(file)
            .is_some_and(|roots| !roots.is_empty())
            || self.inferred_crates_by_file.contains_key(file)
    }
}

#[derive(Debug)]
pub(crate) enum RustReferenceResolution {
    Exact(RustSymbolIdentity),
    Ambiguous(Vec<RustSymbolIdentity>),
    Unresolved,
}

impl RustReferenceResolution {
    pub(crate) fn is_exact(&self) -> bool {
        match self {
            Self::Exact(identity) => {
                let _ = identity;
                true
            }
            Self::Ambiguous(identities) => {
                let _ = identities;
                false
            }
            Self::Unresolved => false,
        }
    }
}

impl RustBindingSeeds {
    pub(crate) fn candidate_names(&self) -> impl Iterator<Item = &str> {
        self.identities
            .iter()
            .map(|identity| identity.name.as_str())
    }

    pub(crate) fn identities_in_file<'a>(
        &'a self,
        file: &'a ProjectFile,
    ) -> impl Iterator<Item = &'a RustSymbolIdentity> {
        self.identities
            .iter()
            .filter(move |identity| &identity.file == file)
    }

    pub(crate) fn has_import_edges(&self) -> bool {
        !self.edges_by_importer.is_empty()
    }
}

/// Re-export and reverse-import indices over the Rust workspace.
#[derive(Debug, Default)]
pub(super) struct RustUsageIndex {
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    importer_reverse: HashMap<ProjectFile, Vec<RustImportEdge>>,
    declaration_domains: HashMap<RustSymbolIdentity, Vec<Domain>>,
    declaration_identities: HashMap<CodeUnit, RustSymbolIdentity>,
    module_domains: HashMap<ModuleKey, Vec<Domain>>,
    module_extents: HashMap<ProjectFile, Vec<(ModuleKey, usize, usize)>>,
    physical_roots: HashMap<ProjectFile, ModuleKey>,
    actual_crate_roots: HashSet<ProjectFile>,
    physical_owners: RustPhysicalOwnerIndex,
    origin_routes_by_file: HashMap<ProjectFile, Vec<RustOriginRoute>>,
    module_files: RustModuleFiles,
}

#[derive(Debug, Default)]
struct RustModuleFiles {
    files: Vec<ProjectFile>,
    by_package: HashMap<String, Vec<usize>>,
    inline_by_name: HashMap<String, Vec<usize>>,
    cargo_routes: Arc<RustCargoRouteIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustModuleAliasRoute {
    target_file: ProjectFile,
    target_module: ModuleKey,
    domain: Domain,
    provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustResolvedModuleRoute {
    target_file: ProjectFile,
    target_module: ModuleKey,
    provenance: RustRouteProvenance,
}

#[derive(Debug, Default)]
struct RustModuleAliasRoutes {
    by_alias: HashMap<ModuleKey, Vec<RustModuleAliasRoute>>,
}

impl RustModuleFiles {
    /// Compact routing projection over the same file/declaration pass already
    /// required for export and import indices. It retains file IDs and module
    /// names only, never persisted rows, file states, declarations, or source.
    fn new(files: &[ProjectFile], cargo_routes: Arc<RustCargoRouteIndex>) -> Self {
        let mut routing = Self {
            files: files.to_vec(),
            cargo_routes,
            ..Self::default()
        };
        for (file_id, file) in files.iter().enumerate() {
            routing
                .by_package
                .entry(rust_package_name(file))
                .or_default()
                .push(file_id);
        }
        routing
    }

    fn index_inline_modules(
        &mut self,
        file_id: usize,
        declarations: &BTreeSet<crate::analyzer::CodeUnit>,
    ) {
        for declaration in declarations {
            if declaration.is_module() {
                self.inline_by_name
                    .entry(declaration.fq_name())
                    .or_default()
                    .push(file_id);
            }
        }
    }

    fn resolve(&self, importing_file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
        if let Some(root_file) = self
            .cargo_routes
            .resolve_crate_root_file(importing_file, module_specifier)
        {
            return self
                .files
                .iter()
                .filter(|file| *file == &root_file)
                .cloned()
                .collect();
        }
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        let Some(resolved_module) = self
            .cargo_routes
            .resolve_module_package(importing_file, module_specifier)
            .or_else(|| {
                resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
            })
        else {
            return rust_module_files_from_path(importing_file, module_specifier);
        };

        let mut files = self
            .by_package
            .get(&resolved_module)
            .into_iter()
            .flatten()
            .map(|file_id| self.files[*file_id].clone())
            .collect::<Vec<_>>();
        if let Some(inline) = self.inline_by_name.get(&resolved_module) {
            files.extend(inline.iter().map(|file_id| self.files[*file_id].clone()));
        }
        files.extend(rust_module_files_from_path(
            importing_file,
            module_specifier,
        ));
        files.sort();
        files.dedup();
        files
    }

    fn resolve_segments(
        &self,
        importing_file: &ProjectFile,
        importing_module: &str,
        segments: &[String],
    ) -> Vec<RustResolvedModuleRoute> {
        if let Some((root_file, kind)) = self
            .cargo_routes
            .resolve_crate_root_file_segments_with_kind(importing_file, segments)
        {
            let Some((package, _)) = self
                .cargo_routes
                .resolve_module_package_segments_with_kind(importing_file, segments)
            else {
                return Vec::new();
            };
            return self
                .files
                .iter()
                .filter(|file| *file == &root_file)
                .map(|file| RustResolvedModuleRoute {
                    target_file: file.clone(),
                    target_module: ModuleKey::new(file, &package),
                    provenance: RustRouteProvenance::from(kind),
                })
                .collect();
        }
        let crate_package = rust_crate_root_package(importing_file);
        if let Some((resolved_module, kind)) = self
            .cargo_routes
            .resolve_module_package_segments_with_kind(importing_file, segments)
        {
            let mut files = self
                .by_package
                .get(&resolved_module)
                .into_iter()
                .flatten()
                .map(|file_id| self.files[*file_id].clone())
                .collect::<Vec<_>>();
            if let Some(inline) = self.inline_by_name.get(&resolved_module) {
                files.extend(inline.iter().map(|file_id| self.files[*file_id].clone()));
            }
            files.sort();
            files.dedup();
            return files
                .into_iter()
                .map(|file| RustResolvedModuleRoute {
                    target_module: ModuleKey::new(&file, &resolved_module),
                    target_file: file,
                    provenance: RustRouteProvenance::from(kind),
                })
                .collect();
        }

        let Some(resolved_module) =
            resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
        else {
            return rust_module_files_from_segments(importing_file, segments)
                .into_iter()
                .map(|file| RustResolvedModuleRoute {
                    target_module: ModuleKey::new(&file, &rust_package_name(&file)),
                    target_file: file,
                    provenance: RustRouteProvenance::Local,
                })
                .collect();
        };

        let mut files = self
            .by_package
            .get(&resolved_module)
            .into_iter()
            .flatten()
            .map(|file_id| self.files[*file_id].clone())
            .collect::<Vec<_>>();
        if let Some(inline) = self.inline_by_name.get(&resolved_module) {
            files.extend(inline.iter().map(|file_id| self.files[*file_id].clone()));
        }
        files.extend(rust_module_files_from_segments(importing_file, segments));
        files.sort();
        files.dedup();
        files
            .into_iter()
            .map(|file| RustResolvedModuleRoute {
                target_module: ModuleKey::new(&file, &resolved_module),
                target_file: file,
                provenance: RustRouteProvenance::Local,
            })
            .collect()
    }

    fn files_for_module(&self, module: &ModuleKey) -> Vec<ProjectFile> {
        let package = module.package();
        let mut files = self
            .by_package
            .get(&package)
            .into_iter()
            .flatten()
            .map(|file_id| self.files[*file_id].clone())
            .collect::<Vec<_>>();
        if let Some(inline) = self.inline_by_name.get(&package) {
            files.extend(inline.iter().map(|file_id| self.files[*file_id].clone()));
        }
        files.sort();
        files.dedup();
        files
    }
}

impl From<RustCargoRouteKind> for RustRouteProvenance {
    fn from(kind: RustCargoRouteKind) -> Self {
        match kind {
            RustCargoRouteKind::CurrentLibrary => Self::CurrentLibrary,
            RustCargoRouteKind::Dependency => Self::Dependency,
        }
    }
}

impl RustModuleAliasRoutes {
    fn resolve_segments(
        &self,
        module_files: &RustModuleFiles,
        importing_file: &ProjectFile,
        importing_module: &str,
        segments: &[String],
    ) -> Vec<RustResolvedModuleRoute> {
        let crate_package = rust_crate_root_package(importing_file);
        let owner_relative = if segments.is_empty() {
            Some(importing_module.to_string())
        } else if matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
        } else {
            Some(if importing_module.is_empty() {
                segments.join(".")
            } else {
                format!("{importing_module}.{}", segments.join("."))
            })
        };
        if let Some(owner_relative) = owner_relative {
            let candidate = ModuleKey::new(importing_file, &owner_relative);
            let importing_key = ModuleKey::new(importing_file, importing_module);
            let longest = self
                .by_alias
                .keys()
                .filter(|alias| alias.crate_root == candidate.crate_root)
                .filter(|alias| candidate.components.starts_with(&alias.components))
                .map(|alias| alias.components.len())
                .max();
            if let Some(longest) = longest {
                let suffix = &candidate.components[longest..];
                let mut resolved = Vec::new();
                for (alias, routes) in &self.by_alias {
                    if alias.crate_root != candidate.crate_root
                        || alias.components.len() != longest
                        || !candidate.components.starts_with(&alias.components)
                    {
                        continue;
                    }
                    for route in routes
                        .iter()
                        .filter(|route| route.domain.contains_module(&importing_key))
                    {
                        let target_module = route.target_module.with_suffix(suffix);
                        let mut target_files = module_files.files_for_module(&target_module);
                        if suffix.is_empty() && !target_files.contains(&route.target_file) {
                            target_files.push(route.target_file.clone());
                        }
                        resolved.extend(target_files.into_iter().map(|file| {
                            RustResolvedModuleRoute {
                                target_file: file,
                                target_module: target_module.clone(),
                                provenance: route.provenance,
                            }
                        }));
                    }
                }
                resolved.sort_by(|left, right| {
                    left.target_file
                        .cmp(&right.target_file)
                        .then_with(|| {
                            left.target_module
                                .crate_root
                                .cmp(&right.target_module.crate_root)
                        })
                        .then_with(|| {
                            left.target_module
                                .components
                                .cmp(&right.target_module.components)
                        })
                        .then_with(|| left.provenance.cmp(&right.provenance))
                });
                resolved.dedup();
                if !resolved.is_empty() {
                    return resolved;
                }
            }
        }

        module_files
            .resolve_segments(importing_file, importing_module, segments)
            .into_iter()
            .filter(|route| module_files.files.contains(&route.target_file))
            .collect()
    }
}

impl RustUsageIndex {
    fn exact_root_for_resolution(
        &self,
        resolution: &RustReferenceResolution,
        seeds: &RustBindingSeeds,
    ) -> Option<CodeUnit> {
        let RustReferenceResolution::Exact(identity) = resolution else {
            return None;
        };
        let mut matches = seeds.roots.iter().filter(|root| {
            self.declaration_identities
                .get(*root)
                .is_some_and(|candidate| candidate == identity)
        });
        let root = matches.next()?.clone();
        matches.next().is_none().then_some(root)
    }

    fn module_at_byte(&self, file: &ProjectFile, byte: usize) -> Option<&ModuleKey> {
        self.module_extents
            .get(file)?
            .iter()
            .filter(|(_, start, end)| *start <= byte && byte < *end)
            .min_by_key(|(_, start, end)| end.saturating_sub(*start))
            .map(|(module, _, _)| module)
    }

    fn declaration_owner_visible_to(
        &self,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
    ) -> bool {
        if identity.file != *caller_file
            && !self.physical_owners.intersects(&identity.file, caller_file)
        {
            return false;
        }
        self.module_domains
            .get(&identity.module)
            .is_some_and(|domains| {
                domains
                    .iter()
                    .any(|domain| domain.contains_module(caller_module))
            })
            || self
                .physical_roots
                .get(&identity.file)
                .is_some_and(|physical_root| {
                    identity.module == *physical_root
                        && ((identity.file == *caller_file
                            && physical_root.contains(caller_module))
                            || (self.actual_crate_roots.contains(&identity.file)
                                && self.physical_owners.owned_by(caller_file, &identity.file)))
                })
    }

    fn declaration_visible_at(
        &self,
        analyzer: &RustAnalyzer,
        declaration: &CodeUnit,
        caller_file: &ProjectFile,
        caller_byte: usize,
    ) -> bool {
        let Some(caller_module) = self.module_at_byte(caller_file, caller_byte) else {
            return false;
        };
        let immediate_parent = analyzer.structural_parent_of(declaration);
        let visibility_declaration = immediate_parent
            .as_ref()
            .filter(|parent| analyzer.is_rust_trait_declaration(parent))
            .unwrap_or(declaration);
        let visibility = analyzer.rust_declaration_visibility(visibility_declaration);
        let mut parent = immediate_parent;
        let owner = loop {
            match parent {
                Some(ref candidate) if candidate.is_module() => {
                    break ModuleKey::new(declaration.source(), &candidate.fq_name());
                }
                Some(candidate) => parent = analyzer.structural_parent_of(&candidate),
                None => {
                    break ModuleKey::new(
                        declaration.source(),
                        &rust_package_name(declaration.source()),
                    );
                }
            }
        };
        let Some(domain) =
            direct_import_scope_for_module(declaration.source(), &owner.package(), visibility)
        else {
            return false;
        };
        if domain == Domain::Public {
            return true;
        }
        (declaration.source() == caller_file
            || self
                .physical_owners
                .intersects(declaration.source(), caller_file))
            && domain.contains_module(caller_module)
    }

    pub(super) fn build(analyzer: &RustAnalyzer) -> Self {
        let files: Vec<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();
        let physical_roots: HashMap<ProjectFile, ModuleKey> = files
            .iter()
            .map(|file| (file.clone(), ModuleKey::new(file, &rust_package_name(file))))
            .collect();
        let actual_crate_roots = files
            .iter()
            .filter(|file| rust_package_name(file) == rust_crate_root_package(file))
            .cloned()
            .collect();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut imports_by_file: HashMap<ProjectFile, Vec<RustProjectedImport>> =
            HashMap::default();
        let mut declaration_domains: HashMap<RustSymbolIdentity, Vec<Domain>> = HashMap::default();
        let mut declaration_identities: HashMap<CodeUnit, RustSymbolIdentity> = HashMap::default();
        let mut declared_module_domains: HashMap<ModuleKey, Vec<Domain>> = HashMap::default();
        let mut module_extents: HashMap<ProjectFile, Vec<(ModuleKey, usize, usize)>> =
            HashMap::default();
        let mut module_files = RustModuleFiles::new(&files, analyzer.cargo_routes());
        for (file_id, file) in files.iter().enumerate() {
            let declarations = analyzer.declarations(file);
            let imports = analyzer
                .prepared_syntax(file)
                .map(|syntax| {
                    for (module, start, end) in rust_module_extents(
                        syntax.tree().root_node(),
                        syntax.source(),
                        &rust_package_name(file),
                    ) {
                        let module_key = ModuleKey::new(file, &module);
                        module_extents
                            .entry(file.clone())
                            .or_default()
                            .push((module_key, start, end));
                    }
                    rust_import_projection(
                        syntax.tree().root_node(),
                        syntax.source(),
                        &rust_package_name(file),
                    )
                })
                .unwrap_or_default();
            for declaration in &declarations {
                let (owner, declared_module) = if declaration.is_module() {
                    let declared = ModuleKey::new(file, &declaration.fq_name());
                    let owner = declared
                        .parent()
                        .unwrap_or_else(|| ModuleKey::new(file, &rust_package_name(file)));
                    (owner, Some(declared))
                } else {
                    let owner = match analyzer.structural_parent_of(declaration) {
                        None => ModuleKey::new(file, &rust_package_name(file)),
                        Some(parent) if parent.is_module() => {
                            ModuleKey::new(file, &parent.fq_name())
                        }
                        Some(_) => continue,
                    };
                    (owner, None)
                };
                let Some(namespace) = RustSymbolNamespace::of(analyzer, declaration) else {
                    continue;
                };
                let identity = RustSymbolIdentity {
                    file: file.clone(),
                    module: owner.clone(),
                    name: declaration.identifier().to_string(),
                    namespace,
                };
                declaration_identities.insert(declaration.clone(), identity.clone());
                if let Some(domain) = direct_import_scope_for_module(
                    file,
                    &owner.package(),
                    analyzer.rust_declaration_visibility(declaration),
                ) {
                    if let Some(declared_module) = declared_module {
                        declared_module_domains
                            .entry(declared_module)
                            .or_default()
                            .push(domain.clone());
                    }
                    declaration_domains
                        .entry(identity)
                        .or_default()
                        .push(domain);
                }
            }
            exports_by_file.insert(
                file.clone(),
                analyzer.export_index_of_declarations(file, &declarations),
            );
            imports_by_file.insert(file.clone(), imports);
            module_files.index_inline_modules(file_id, &declarations);
        }

        let module_domains = effective_module_domains(declared_module_domains);
        let physical_owners = RustPhysicalOwnerIndex::build(
            analyzer,
            &module_files,
            &physical_roots,
            &declaration_identities,
            &actual_crate_roots,
        );
        let module_aliases = build_module_alias_routes(&module_files, &files, &imports_by_file);
        let importer_reverse = build_importer_reverse(
            &module_files,
            &module_aliases,
            &physical_owners,
            &files,
            &imports_by_file,
        );
        let origin_routes_by_file =
            build_origin_routes(&importer_reverse, &declaration_domains, &module_domains);

        Self {
            exports_by_file,
            importer_reverse,
            declaration_domains,
            declaration_identities,
            module_domains,
            module_extents,
            physical_roots,
            actual_crate_roots,
            physical_owners,
            origin_routes_by_file,
            module_files,
        }
    }

    /// Files that import one of the `seeds` (plus the seed files themselves) —
    /// the candidate set the forward scan narrows to. Named imports are followed
    /// transitively because a private parent-module import can itself be imported
    /// by a child module without becoming a public re-export.
    pub(super) fn importers_of_seeds(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = seeds.edges_by_importer.keys().cloned().collect();
        out.extend(
            seeds
                .identities
                .iter()
                .map(|identity| identity.file.clone()),
        );
        out.extend(seeds.roots.iter().map(|root| root.source().clone()));
        out
    }

    fn matching_edges_for_importer<'a>(
        &self,
        importer: &ProjectFile,
        seeds: &'a RustBindingSeeds,
    ) -> impl Iterator<Item = &'a RustImportEdge> {
        seeds.edges_by_importer.get(importer).into_iter().flatten()
    }

    fn binding_seeds(
        &self,
        analyzer: &RustAnalyzer,
        roots: &BTreeSet<CodeUnit>,
    ) -> RustBindingSeeds {
        let mut identities = HashSet::default();
        let mut identity_domains: HashMap<RustSymbolIdentity, Vec<Domain>> = HashMap::default();
        let mut pending = VecDeque::new();
        for root in roots {
            let identity = self
                .declaration_identities
                .get(root)
                .cloned()
                .unwrap_or_else(|| RustSymbolIdentity {
                    file: root.source().clone(),
                    module: ModuleKey::new(root.source(), root.package_name()),
                    name: root.identifier().to_string(),
                    namespace: RustSymbolNamespace::of(analyzer, root)
                        .unwrap_or(RustSymbolNamespace::Value),
                });
            identities.insert(identity.clone());
            if let Some(domains) = self.declaration_domains.get(&identity) {
                identity_domains
                    .entry(identity.clone())
                    .or_default()
                    .extend(domains.iter().cloned());
                pending.extend(
                    domains
                        .iter()
                        .cloned()
                        .map(|domain| (identity.clone(), domain, identity.clone())),
                );
            }
        }
        let mut edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
        let mut visited = HashSet::default();
        while let Some((target, domain, canonical_origin)) = pending.pop_front() {
            if !visited.insert((target.clone(), domain.clone(), canonical_origin.clone())) {
                continue;
            }
            let Some(edges) = self.importer_reverse.get(&target.file) else {
                continue;
            };
            for edge in edges {
                if !edge_matches_single_seed(edge, &target) {
                    continue;
                }
                // A module-private alias may flow into actual descendant modules,
                // including modules backed by another file. Two different files
                // cannot, however, both be the same Rust module. Without this
                // guard root files such as lib.rs and main.rs collapse to the same
                // empty ModuleKey and a `pub(self) use` becomes a false barrel.
                if matches!(&domain, Domain::Module(module)
                    if *module == target.module
                        && *module == edge.importer_module
                        && target.file != edge.importer)
                {
                    continue;
                }
                if self
                    .module_domains
                    .get(&edge.target_module)
                    .is_some_and(|domains| {
                        !domains
                            .iter()
                            .any(|domain| domain.contains_module(&edge.importer_module))
                    })
                {
                    continue;
                }
                let Some(effective_domain) = domain.intersect(&edge.domain) else {
                    continue;
                };
                if !effective_domain.contains_module(&edge.importer_module) {
                    continue;
                }
                let mut matched = edge.clone();
                matched.namespace = Some(target.namespace);
                if matches!(matched.kind, RustImportEdgeKind::Glob) {
                    matched.local_name = target.name.clone();
                    matched.kind = RustImportEdgeKind::Named(target.name.clone());
                }
                if matches!(matched.kind, RustImportEdgeKind::Namespace) {
                    matched.kind = RustImportEdgeKind::Qualified(vec![
                        matched.local_name.clone(),
                        target.name.clone(),
                    ]);
                }
                edges_by_importer
                    .entry(edge.importer.clone())
                    .or_default()
                    .push(matched.clone());
                if edge.propagate_alias && matches!(matched.kind, RustImportEdgeKind::Named(_)) {
                    let alias = RustSymbolIdentity {
                        file: edge.importer.clone(),
                        module: edge.importer_module.clone(),
                        name: matched.local_name.clone(),
                        namespace: target.namespace,
                    };
                    identities.insert(alias.clone());
                    identity_domains
                        .entry(alias.clone())
                        .or_default()
                        .push(effective_domain.clone());
                    pending.push_back((alias, effective_domain, canonical_origin.clone()));
                }
            }
        }
        RustBindingSeeds {
            roots: roots.clone(),
            root_origins: roots
                .iter()
                .filter_map(|root| self.declaration_identities.get(root).cloned())
                .collect(),
            identities,
            identity_domains,
            edges_by_importer,
        }
    }

    pub(super) fn export_targets_from_files(
        &self,
        analyzer: &RustAnalyzer,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        enum Work {
            Visit(ProjectFile, String),
            DeclarationFallback {
                files: Vec<ProjectFile>,
                name: String,
                target_count: usize,
            },
        }

        let mut targets = BTreeSet::new();
        let mut visited = HashSet::default();
        let mut pending = module_files
            .iter()
            .rev()
            .map(|file| Work::Visit(file.clone(), export_name.to_string()))
            .collect::<Vec<_>>();
        while let Some(work) = pending.pop() {
            let (module_file, export_name) = match work {
                Work::DeclarationFallback {
                    files,
                    name,
                    target_count,
                } => {
                    if targets.len() == target_count {
                        targets.extend(rust_declaration_targets_in_files(analyzer, &files, &name));
                    }
                    continue;
                }
                Work::Visit(file, name) => (file, name),
            };
            if !visited.insert((module_file.clone(), export_name.clone())) {
                continue;
            }
            let Some(index) = self.exports_by_file.get(&module_file) else {
                continue;
            };

            for star in index.reexport_stars.iter().rev() {
                let files = self
                    .module_files
                    .resolve(&module_file, &star.module_specifier);
                pending.push(Work::DeclarationFallback {
                    files: files.clone(),
                    name: export_name.clone(),
                    target_count: targets.len(),
                });
                pending.extend(
                    files
                        .into_iter()
                        .rev()
                        .map(|file| Work::Visit(file, export_name.clone())),
                );
            }

            if let Some(entry) = index.exports_by_name.get(&export_name) {
                match entry {
                    ExportEntry::Local { local_name } => {
                        targets.insert((module_file, local_name.clone()));
                    }
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        let files = self.module_files.resolve(&module_file, module_specifier);
                        pending.push(Work::DeclarationFallback {
                            files: files.clone(),
                            name: imported_name.clone(),
                            target_count: targets.len(),
                        });
                        pending.extend(
                            files
                                .into_iter()
                                .rev()
                                .map(|file| Work::Visit(file, imported_name.clone())),
                        );
                    }
                    ExportEntry::Default { .. } => {}
                }
            }
        }
        targets
    }
}

fn effective_module_domains(
    declared: HashMap<ModuleKey, Vec<Domain>>,
) -> HashMap<ModuleKey, Vec<Domain>> {
    let mut declared = declared.into_iter().collect::<Vec<_>>();
    declared.sort_unstable_by_key(|(module, _)| module.components.len());

    let mut effective: HashMap<ModuleKey, Vec<Domain>> = HashMap::default();
    for (module, direct_domains) in declared {
        let parent_domains = module
            .parent()
            .and_then(|parent| effective.get(&parent).cloned())
            .unwrap_or_else(|| vec![Domain::Public]);
        let domains = direct_domains
            .iter()
            .flat_map(|direct| {
                parent_domains
                    .iter()
                    .filter_map(|parent| direct.intersect(parent))
            })
            .collect::<Vec<_>>();
        effective.insert(module, domains);
    }
    effective
}

fn direct_import_scope_for_module(
    file: &ProjectFile,
    package: &str,
    visibility: RustVisibility,
) -> Option<Domain> {
    let package = package.to_string();
    let crate_package = rust_crate_root_package(file);
    match visibility {
        RustVisibility::Private | RustVisibility::SelfModule => {
            Some(Domain::Module(ModuleKey::new(file, &package)))
        }
        RustVisibility::Public => Some(Domain::Public),
        RustVisibility::Crate => Some(Domain::Crate(crate_package)),
        RustVisibility::SuperModule => {
            let parent = package
                .rsplit_once('.')
                .map(|(parent, _)| parent.to_string())
                .unwrap_or_else(|| crate_package.clone());
            Some(Domain::Module(ModuleKey::new(file, &parent)))
        }
        RustVisibility::InPath(path) => {
            resolve_rust_module_segments_with_crate(&package, &crate_package, &path)
                .map(|module| Domain::Module(ModuleKey::new(file, &module)))
        }
    }
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
    /// The cached re-export/importer index, built once per analyzer generation.
    fn usage_index(&self) -> &RustUsageIndex {
        self.usage_index.get_or_init(|| RustUsageIndex::build(self))
    }

    /// Candidate files: those importing a seed, plus the seed files themselves.
    pub(crate) fn usage_importers(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        self.usage_index().importers_of_seeds(seeds)
    }

    /// Canonical local binding identities for a target, including named private
    /// imports that can be imported again by descendant modules.
    pub(crate) fn usage_binding_seeds(&self, roots: &BTreeSet<CodeUnit>) -> RustBindingSeeds {
        self.usage_index().binding_seeds(self, roots)
    }

    /// `(direct_names, qualified_names)` — local names that bind a seed directly
    /// (`use path::Item;`) and exact paths that reach a seed through a namespace
    /// binding (`use crate_name;` followed by `crate_name::Item`).
    pub(crate) fn usage_binding_names(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
    ) -> (HashSet<String>, HashSet<String>) {
        let mut direct = HashSet::default();
        let mut qualified = HashSet::default();
        let index = self.usage_index();
        for edge in index.matching_edges_for_importer(file, seeds) {
            match &edge.kind {
                RustImportEdgeKind::Namespace => {
                    qualified.extend(
                        seeds
                            .identities
                            .iter()
                            .filter(|identity| identity.file == edge.target_file)
                            .map(|identity| format!("{}::{}", edge.local_name, identity.name)),
                    );
                }
                RustImportEdgeKind::Named(_) => {
                    direct.insert(edge.local_name.clone());
                }
                RustImportEdgeKind::Glob => {}
                RustImportEdgeKind::Qualified(name) => {
                    qualified.insert(name.join("::"));
                }
            }
        }
        (direct, qualified)
    }

    /// All local names in `file` binding a seed (direct or namespace) — the
    /// owner-binding names the member scan keys on.
    pub(crate) fn usage_binding_local_names(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
    ) -> HashSet<String> {
        self.usage_index()
            .matching_edges_for_importer(file, seeds)
            .map(|edge| edge.local_name.clone())
            .collect()
    }

    pub(crate) fn usage_root_declaration_matches_at(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        name: &str,
        byte: usize,
    ) -> bool {
        let index = self.usage_index();
        let Some(module) = index.module_at_byte(file, byte) else {
            return false;
        };
        seeds.roots.iter().any(|root| {
            index
                .declaration_identities
                .get(root)
                .is_some_and(|identity| {
                    identity.file == *file && identity.module == *module && identity.name == name
                })
        })
    }

    pub(crate) fn usage_declaration_visible_at(
        &self,
        declaration: &CodeUnit,
        file: &ProjectFile,
        byte: usize,
    ) -> bool {
        self.usage_index()
            .declaration_visible_at(self, declaration, file, byte)
    }

    pub(crate) fn usage_exact_root_for_resolution(
        &self,
        resolution: &RustReferenceResolution,
        seeds: &RustBindingSeeds,
    ) -> Option<CodeUnit> {
        self.usage_index()
            .exact_root_for_resolution(resolution, seeds)
    }

    pub(crate) fn usage_local_module_prefix_visible_at(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        name: &str,
        byte: usize,
    ) -> bool {
        let index = self.usage_index();
        let Some(module) = index.module_at_byte(file, byte) else {
            return false;
        };
        let module_identity = RustSymbolIdentity {
            file: file.clone(),
            module: module.clone(),
            name: name.to_string(),
            namespace: RustSymbolNamespace::Module,
        };
        if !index
            .declaration_domains
            .get(&module_identity)
            .is_some_and(|domains| domains.iter().any(|domain| domain.contains_module(module)))
        {
            return false;
        }

        let child_module = module.with_suffix(&[name.to_string()]);
        seeds.identities.iter().any(|identity| {
            let target_module = if identity.namespace == RustSymbolNamespace::Module {
                identity
                    .module
                    .with_suffix(std::slice::from_ref(&identity.name))
            } else {
                identity.module.clone()
            };
            child_module.contains(&target_module)
                && seeds.identity_domains.get(identity).is_some_and(|domains| {
                    domains.iter().any(|domain| domain.contains_module(module))
                })
        })
    }

    pub(crate) fn usage_reference_at(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        root_shadowed: bool,
    ) -> RustReferenceResolution {
        if segments.is_empty() || root_shadowed {
            return RustReferenceResolution::Unresolved;
        }
        let index = self.usage_index();
        let Some(module) = index.module_at_byte(file, byte) else {
            return RustReferenceResolution::Unresolved;
        };
        let mut matches: HashSet<RustSymbolIdentity> = index
            .origin_routes_by_file
            .get(file)
            .into_iter()
            .flatten()
            .filter(|route| {
                route.importer_module == *module
                    && route.extent.contains(byte)
                    && route.namespace.accepts(namespace)
                    && route.domain.contains_module(module)
                    && segments
                        .iter()
                        .copied()
                        .eq(route.path.iter().map(String::as_str))
            })
            .map(|route| route.origin.clone())
            .collect();

        if segments.len() == 1 {
            matches.extend(
                index
                    .declaration_domains
                    .iter()
                    .filter(|(identity, domains)| {
                        identity.file == *file
                            && identity.module == *module
                            && identity.name == segments[0]
                            && identity.namespace.accepts(namespace)
                            && domains.iter().any(|domain| domain.contains_module(module))
                            && index.declaration_owner_visible_to(identity, file, module)
                    })
                    .map(|(identity, _)| identity.clone()),
            );
        } else {
            let terminal = segments[segments.len() - 1];
            let prefix = &segments[..segments.len() - 1];
            let package = module.package();
            let resolved = if matches!(prefix.first(), Some(&"crate" | &"self" | &"super")) {
                resolve_rust_module_segments_with_crate(&package, &module.crate_root, prefix)
                    .map(|package| ModuleKey::new(file, &package))
            } else {
                Some(ModuleKey {
                    crate_root: module.crate_root.clone(),
                    components: module
                        .components
                        .iter()
                        .cloned()
                        .chain(prefix.iter().map(|segment| (*segment).to_string()))
                        .collect(),
                })
            };
            if let Some(resolved) = resolved {
                matches.extend(
                    index
                        .declaration_domains
                        .iter()
                        .filter(|(identity, domains)| {
                            identity.module == resolved
                                && identity.name == terminal
                                && identity.namespace.accepts(namespace)
                                && domains.iter().any(|domain| domain.contains_module(module))
                                && index.declaration_owner_visible_to(identity, file, module)
                        })
                        .map(|(identity, _)| identity.clone()),
                );
            }
        }

        let mut matches = matches.into_iter().collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.name.cmp(&right.name))
        });
        match matches.len() {
            0 => RustReferenceResolution::Unresolved,
            1 if seeds.root_origins.contains(&matches[0]) => {
                RustReferenceResolution::Exact(matches.remove(0))
            }
            1 => RustReferenceResolution::Unresolved,
            _ => RustReferenceResolution::Ambiguous(matches),
        }
    }

    pub(crate) fn exported_targets_from_files(
        &self,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        self.usage_index()
            .export_targets_from_files(self, module_files, export_name)
    }
}

fn edge_matches_single_seed(edge: &RustImportEdge, target: &RustSymbolIdentity) -> bool {
    if edge.target_file != target.file || edge.target_module != target.module {
        return false;
    }
    match &edge.kind {
        RustImportEdgeKind::Named(name) => name == &target.name,
        RustImportEdgeKind::Namespace => true,
        RustImportEdgeKind::Glob => true,
        RustImportEdgeKind::Qualified(_) => false,
    }
}

fn build_origin_routes(
    importer_reverse: &HashMap<ProjectFile, Vec<RustImportEdge>>,
    declaration_domains: &HashMap<RustSymbolIdentity, Vec<Domain>>,
    module_domains: &HashMap<ModuleKey, Vec<Domain>>,
) -> HashMap<ProjectFile, Vec<RustOriginRoute>> {
    type ExactKey = (ProjectFile, ModuleKey, String);
    type ModuleEdgeKey = (ProjectFile, ModuleKey);
    let mut exact_edges: HashMap<ExactKey, Vec<&RustImportEdge>> = HashMap::default();
    let mut module_edges: HashMap<ModuleEdgeKey, Vec<&RustImportEdge>> = HashMap::default();
    for edges in importer_reverse.values() {
        for edge in edges {
            match &edge.kind {
                RustImportEdgeKind::Named(name) => exact_edges
                    .entry((
                        edge.target_file.clone(),
                        edge.target_module.clone(),
                        name.clone(),
                    ))
                    .or_default()
                    .push(edge),
                RustImportEdgeKind::Namespace | RustImportEdgeKind::Glob => module_edges
                    .entry((edge.target_file.clone(), edge.target_module.clone()))
                    .or_default()
                    .push(edge),
                RustImportEdgeKind::Qualified(_) => {}
            }
        }
    }

    let mut pending = VecDeque::new();
    for (identity, domains) in declaration_domains {
        pending.extend(
            domains
                .iter()
                .cloned()
                .map(|domain| (identity.clone(), identity.clone(), domain)),
        );
    }
    let mut visited = HashSet::default();
    let mut routes: HashMap<ProjectFile, Vec<RustOriginRoute>> = HashMap::default();
    while let Some((target, origin, domain)) = pending.pop_front() {
        if !visited.insert((target.clone(), origin.clone(), domain.clone())) {
            continue;
        }
        let exact_key = (
            target.file.clone(),
            target.module.clone(),
            target.name.clone(),
        );
        let module_key = (target.file.clone(), target.module.clone());
        for edge in exact_edges
            .get(&exact_key)
            .into_iter()
            .flatten()
            .chain(module_edges.get(&module_key).into_iter().flatten())
        {
            if matches!(&domain, Domain::Module(module)
                if *module == target.module
                    && *module == edge.importer_module
                    && target.file != edge.importer)
            {
                continue;
            }
            if module_domains
                .get(&edge.target_module)
                .is_some_and(|domains| {
                    !domains
                        .iter()
                        .any(|domain| domain.contains_module(&edge.importer_module))
                })
            {
                continue;
            }
            let Some(effective_domain) = domain.intersect(&edge.domain) else {
                continue;
            };
            if !effective_domain.contains_module(&edge.importer_module) {
                continue;
            }
            let path = match &edge.kind {
                RustImportEdgeKind::Named(_) => vec![edge.local_name.clone()],
                RustImportEdgeKind::Namespace => {
                    vec![edge.local_name.clone(), target.name.clone()]
                }
                RustImportEdgeKind::Glob => vec![target.name.clone()],
                RustImportEdgeKind::Qualified(path) => path.clone(),
            };
            routes
                .entry(edge.importer.clone())
                .or_default()
                .push(RustOriginRoute {
                    importer_module: edge.importer_module.clone(),
                    extent: edge.extent.clone(),
                    path,
                    namespace: target.namespace,
                    origin: origin.clone(),
                    domain: effective_domain.clone(),
                });

            let propagated_alias = match &edge.kind {
                RustImportEdgeKind::Named(_) => Some(edge.local_name.clone()),
                RustImportEdgeKind::Glob => Some(target.name.clone()),
                RustImportEdgeKind::Namespace | RustImportEdgeKind::Qualified(_) => None,
            };
            if edge.propagate_alias
                && let Some(alias_name) = propagated_alias
            {
                pending.push_back((
                    RustSymbolIdentity {
                        file: edge.importer.clone(),
                        module: edge.importer_module.clone(),
                        name: alias_name,
                        namespace: target.namespace,
                    },
                    origin.clone(),
                    effective_domain,
                ));
            }
        }
    }
    routes
}

fn build_module_alias_routes(
    module_files: &RustModuleFiles,
    files: &[ProjectFile],
    imports_by_file: &HashMap<ProjectFile, Vec<RustProjectedImport>>,
) -> RustModuleAliasRoutes {
    let mut routes = RustModuleAliasRoutes::default();
    let import_count = imports_by_file.values().map(Vec::len).sum::<usize>();
    for _ in 0..=import_count {
        let mut changed = false;
        for file in files {
            let Some(imports) = imports_by_file.get(file) else {
                continue;
            };
            for projected in imports {
                let RustImportOwner::Module { module: owner, .. } = &projected.owner else {
                    continue;
                };
                let import = &projected.import;
                if import.info.is_wildcard {
                    continue;
                }
                let Some(local_name) = import
                    .info
                    .alias
                    .as_ref()
                    .or(import.info.identifier.as_ref())
                else {
                    continue;
                };
                let Some(domain) =
                    direct_import_scope_for_module(file, owner, import.visibility.clone())
                else {
                    continue;
                };
                let alias_package = if owner.is_empty() {
                    local_name.clone()
                } else {
                    format!("{owner}.{local_name}")
                };
                let alias = ModuleKey::new(file, &alias_package);
                for resolved in routes.resolve_segments(module_files, file, owner, &import.path) {
                    let route = RustModuleAliasRoute {
                        target_file: resolved.target_file,
                        target_module: resolved.target_module,
                        domain: domain.clone(),
                        provenance: resolved.provenance,
                    };
                    let entries = routes.by_alias.entry(alias.clone()).or_default();
                    if !entries.contains(&route) {
                        entries.push(route);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    routes
}

fn build_importer_reverse(
    module_files: &RustModuleFiles,
    module_aliases: &RustModuleAliasRoutes,
    physical_owners: &RustPhysicalOwnerIndex,
    files: &[ProjectFile],
    imports_by_file: &HashMap<ProjectFile, Vec<RustProjectedImport>>,
) -> HashMap<ProjectFile, Vec<RustImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
    for file in files {
        let Some(imports) = imports_by_file.get(file) else {
            continue;
        };
        for projected in imports {
            let import = &projected.import;
            let (owner, extent) = match &projected.owner {
                RustImportOwner::Module { module, start, end } => (
                    module.clone(),
                    RustImportExtent::Module {
                        start: *start,
                        end: *end,
                    },
                ),
                RustImportOwner::LocalOnly {
                    module,
                    module_start,
                    module_end,
                    start,
                    end,
                } => (
                    module.clone(),
                    RustImportExtent::LocalOnly {
                        module_start: *module_start,
                        module_end: *module_end,
                        start: *start,
                        end: *end,
                    },
                ),
            };
            let propagate_alias = matches!(extent, RustImportExtent::Module { .. });
            let importer_module = ModuleKey::new(file, &owner);
            let Some(edge_domain) =
                direct_import_scope_for_module(file, &owner, import.visibility.clone())
            else {
                continue;
            };
            let local_name = import
                .info
                .alias
                .clone()
                .or_else(|| import.info.identifier.clone())
                .unwrap_or_default();
            if import.info.is_wildcard {
                for resolved in
                    module_aliases.resolve_segments(module_files, file, &owner, &import.path)
                {
                    add_import_edge(
                        &mut reverse,
                        physical_owners,
                        RustImportEdge {
                            importer: file.clone(),
                            importer_module: importer_module.clone(),
                            extent: extent.clone(),
                            local_name: String::new(),
                            target_file: resolved.target_file,
                            target_module: resolved.target_module,
                            kind: RustImportEdgeKind::Glob,
                            propagate_alias,
                            domain: edge_domain.clone(),
                            namespace: None,
                            provenance: resolved.provenance,
                        },
                    );
                }
                continue;
            }
            let Some(imported_name) = import.path.last().cloned() else {
                continue;
            };
            for resolved in module_aliases.resolve_segments(
                module_files,
                file,
                &owner,
                &import.path[..import.path.len() - 1],
            ) {
                add_import_edge(
                    &mut reverse,
                    physical_owners,
                    RustImportEdge {
                        importer: file.clone(),
                        importer_module: importer_module.clone(),
                        extent: extent.clone(),
                        local_name: local_name.clone(),
                        target_file: resolved.target_file,
                        target_module: resolved.target_module,
                        kind: RustImportEdgeKind::Named(imported_name.clone()),
                        propagate_alias,
                        domain: edge_domain.clone(),
                        namespace: None,
                        provenance: resolved.provenance,
                    },
                );
            }
            for resolved in
                module_aliases.resolve_segments(module_files, file, &owner, &import.path)
            {
                add_import_edge(
                    &mut reverse,
                    physical_owners,
                    RustImportEdge {
                        importer: file.clone(),
                        importer_module: importer_module.clone(),
                        extent: extent.clone(),
                        local_name: local_name.clone(),
                        target_file: resolved.target_file,
                        target_module: resolved.target_module,
                        kind: RustImportEdgeKind::Namespace,
                        propagate_alias,
                        domain: edge_domain.clone(),
                        namespace: None,
                        provenance: resolved.provenance,
                    },
                );
            }
        }
    }
    reverse
}

fn add_import_edge(
    reverse: &mut HashMap<ProjectFile, Vec<RustImportEdge>>,
    physical_owners: &RustPhysicalOwnerIndex,
    edge: RustImportEdge,
) {
    let cross_file = edge.target_file != edge.importer;
    let owners_intersect = physical_owners.intersects(&edge.importer, &edge.target_file);
    let admitted = match edge.provenance {
        RustRouteProvenance::Local => !cross_file || owners_intersect,
        RustRouteProvenance::CurrentLibrary => {
            !cross_file
                || owners_intersect
                || (physical_owners.has_owners(&edge.importer)
                    && physical_owners.has_owners(&edge.target_file))
        }
        RustRouteProvenance::Dependency => true,
    };
    if !admitted {
        return;
    }
    reverse
        .entry(edge.target_file.clone())
        .or_default()
        .push(edge);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::ExportEntry;
    use crate::analyzer::{Language, TestProject};

    #[test]
    fn rust_domains_intersect_without_cross_crate_or_sibling_widening() {
        let crate_a = "workspace.a.src".to_string();
        let crate_b = "workspace.b.src".to_string();
        let parent = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["parent".to_string()],
        });
        let child = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["parent".to_string(), "child".to_string()],
        });
        let sibling = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["sibling".to_string()],
        });

        assert_eq!(Some(child.clone()), parent.intersect(&child));
        assert_eq!(
            Some(child.clone()),
            Domain::Crate(crate_a.clone()).intersect(&child)
        );
        assert_eq!(None, parent.intersect(&sibling));
        assert_eq!(
            None,
            Domain::Crate(crate_a).intersect(&Domain::Crate(crate_b))
        );
        assert_eq!(Some(child.clone()), Domain::Public.intersect(&child));
    }

    fn project_file(root: &std::path::Path, index: usize) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), format!("src/m{index}.rs"))
    }

    fn analyzer_for(root: &std::path::Path) -> RustAnalyzer {
        RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    fn reexport_chain(
        root: &std::path::Path,
        len: usize,
        cyclic: bool,
    ) -> (RustUsageIndex, Vec<ProjectFile>) {
        let files = (0..len)
            .map(|index| project_file(root, index))
            .collect::<Vec<_>>();
        let mut exports_by_file = HashMap::default();
        let mut by_package = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            by_package.insert(format!("m{index}"), vec![index]);
            let entry = if index + 1 < len {
                ExportEntry::ReexportedNamed {
                    module_specifier: format!("crate::m{}", index + 1),
                    imported_name: "Value".to_string(),
                }
            } else if cyclic {
                ExportEntry::ReexportedNamed {
                    module_specifier: "crate::m0".to_string(),
                    imported_name: "Value".to_string(),
                }
            } else {
                ExportEntry::Local {
                    local_name: "Value".to_string(),
                }
            };
            exports_by_file.insert(
                file.clone(),
                ExportIndex {
                    exports_by_name: [("Value".to_string(), entry)].into_iter().collect(),
                    reexport_stars: Vec::new(),
                },
            );
        }
        (
            RustUsageIndex {
                exports_by_file,
                module_files: RustModuleFiles {
                    files: files.clone(),
                    by_package,
                    inline_by_name: HashMap::default(),
                    cargo_routes: Arc::new(RustCargoRouteIndex::default()),
                },
                ..RustUsageIndex::default()
            },
            files,
        )
    }

    #[test]
    fn export_target_walk_handles_deep_reexport_chains_without_recursion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, false);

        assert_eq!(
            index.export_targets_from_files(&analyzer, &files[..1], "Value"),
            BTreeSet::from([(files[4_999].clone(), "Value".to_string())])
        );
    }

    #[test]
    fn export_target_walk_terminates_on_deep_reexport_cycle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, true);

        assert!(
            index
                .export_targets_from_files(&analyzer, &files[..1], "Value")
                .is_empty()
        );
    }

    #[test]
    fn module_file_snapshot_preserves_package_inline_and_path_candidates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let importer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let module_file = ProjectFile::new(root.clone(), "src/service.rs");
        let inline_file = ProjectFile::new(root.clone(), "src/lib.rs");
        let snapshot = RustModuleFiles {
            files: vec![module_file.clone(), inline_file.clone()],
            by_package: [("service".to_string(), vec![0])].into_iter().collect(),
            inline_by_name: [("service".to_string(), vec![1])].into_iter().collect(),
            cargo_routes: Arc::new(RustCargoRouteIndex::default()),
        };

        assert_eq!(snapshot.files.len(), 2);
        assert_eq!(snapshot.by_package.values().map(Vec::len).sum::<usize>(), 1);
        assert_eq!(
            snapshot
                .inline_by_name
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            1
        );

        let resolved = snapshot.resolve(&importer, "crate::service");
        assert!(resolved.contains(&module_file));
        assert!(resolved.contains(&inline_file));
    }
}
