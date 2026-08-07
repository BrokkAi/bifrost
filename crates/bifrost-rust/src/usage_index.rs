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

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::symbol_path::{parse_symbol_path, strip_raw_identifier_prefix};
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ExportIndex, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use tree_sitter::Node;

use crate::cargo_routes::{RustCargoRouteIndex, RustCargoRouteKind, RustCargoTargetRelation};
use crate::declarations::rust_package_name;
use crate::graph_support::{
    RustSource, RustUsageSource, export_index_of_declarations, is_external_module_declaration,
    is_rust_macro_export_declaration, is_rust_trait_declaration,
    resolve_imported_export_from_binder_forward, rust_declaration_visibility,
    rust_module_files_from_path, rust_module_files_from_segments, rust_named_declaration_node,
    rust_value_constructor_visibilities,
};
use crate::imports::{
    RustImportOwner, RustProjectedImport, RustVisibility, resolve_rust_import_package_scoped,
    resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_import_projection, rust_module_extents,
    rust_target_kind_root_package,
};

/// How a local binding in an importer refers to its target: a named import
/// (`use path::Item;`) or a namespace import (`use crate::module;`). A glob
/// (`use path::*;`) carries no single name, so it is lowered to one `Named` edge
/// per export of the target file in [`build_importer_reverse`] rather than getting
/// its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustImportEdgeKind {
    Named(String),
    Namespace,
    Glob,
    Qualified(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct RustImportEdge {
    pub importer: ProjectFile,
    importer_module: ModuleKey,
    extent: RustImportExtent,
    pub local_name: String,
    pub target_file: ProjectFile,
    target_module: ModuleKey,
    pub kind: RustImportEdgeKind,
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
pub enum RustSymbolNamespace {
    Type,
    Value,
    Macro,
    Module,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustReferenceNamespace {
    Type,
    Value,
    Macro,
    PathPrefix,
    Any,
}

impl RustSymbolNamespace {
    fn of(rust: &dyn RustSource, declaration: &CodeUnit) -> Option<Self> {
        if rust.is_type_alias(declaration) {
            return Some(Self::Type);
        }
        match declaration.kind() {
            CodeUnitType::Class => Some(Self::Type),
            CodeUnitType::Function | CodeUnitType::Field => Some(Self::Value),
            CodeUnitType::Macro => Some(Self::Macro),
            CodeUnitType::Module => Some(Self::Module),
            CodeUnitType::FileScope => None,
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
pub struct RustSymbolIdentity {
    pub file: ProjectFile,
    pub module: ModuleKey,
    pub name: String,
    pub namespace: RustSymbolNamespace,
}

impl RustSymbolIdentity {
    pub fn name(&self) -> &str {
        &self.name
    }

    fn fq_name(&self) -> String {
        let package = self.module.package();
        if package.is_empty() {
            self.name.clone()
        } else {
            format!("{package}.{}", self.name)
        }
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
pub struct ModuleKey {
    crate_root: String,
    components: Vec<String>,
}

impl ModuleKey {
    pub fn new(file: &ProjectFile, module: &str) -> Self {
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
pub enum Domain {
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

pub struct RustBindingSeeds {
    roots: BTreeSet<CodeUnit>,
    root_origins: HashSet<RustSymbolIdentity>,
    root_identities: HashMap<CodeUnit, Vec<RustSymbolIdentity>>,
    canonical_identities: HashMap<RustSymbolIdentity, HashSet<RustSymbolIdentity>>,
    identities: HashSet<RustSymbolIdentity>,
    identity_domains: HashMap<RustSymbolIdentity, Vec<Domain>>,
    edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>>,
}

#[derive(Debug, Clone)]
pub struct RustOriginRoute {
    importer_module: ModuleKey,
    extent: RustImportExtent,
    path: Vec<String>,
    namespace: RustSymbolNamespace,
    origin: RustSymbolIdentity,
    domain: Domain,
    provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RustMacroScopeKey {
    file: ProjectFile,
    module: ModuleKey,
}

#[derive(Debug, Clone)]
struct RustMacroScopeEdge {
    parent: RustMacroScopeKey,
    child: RustMacroScopeKey,
    declaration_start: usize,
    visibility_start: usize,
    imports_macros: bool,
}

pub type RustMacroVisibleRanges =
    HashMap<CodeUnit, HashMap<RustMacroScopeKey, Vec<(usize, usize)>>>;

#[derive(Debug, Default)]
pub struct RustPhysicalOwnerIndex {
    roots_by_file: HashMap<ProjectFile, HashSet<ProjectFile>>,
    inferred_crates_by_file: HashMap<ProjectFile, String>,
}

impl RustPhysicalOwnerIndex {
    fn build(
        rust: &dyn RustSource,
        module_files: &RustModuleFiles,
        physical_roots: &HashMap<ProjectFile, ModuleKey>,
        declarations: &HashMap<CodeUnit, RustSymbolIdentity>,
        roots: &HashSet<ProjectFile>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<Self> {
        let mut edges: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for (_declaration, identity) in declarations.iter().filter(|(declaration, identity)| {
            identity.namespace == RustSymbolNamespace::Module
                && is_external_module_declaration(rust, declaration)
        }) {
            keep_going().then_some(())?;
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
            keep_going().then_some(())?;
            pending.push_back((root.clone(), root.clone()));
        }
        while let Some((file, owner)) = pending.pop_front() {
            keep_going().then_some(())?;
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
        let mut rooted_crates = HashSet::default();
        for root in roots {
            keep_going().then_some(())?;
            if let Some(module) = physical_roots.get(root) {
                rooted_crates.insert(module.crate_root.clone());
            }
        }
        for (file, module) in physical_roots {
            keep_going().then_some(())?;
            if !rooted_crates.contains(&module.crate_root) {
                index
                    .inferred_crates_by_file
                    .insert(file.clone(), module.crate_root.clone());
            }
        }
        Some(index)
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
pub enum RustReferenceResolution {
    Exact(RustSymbolIdentity),
    Ambiguous(Vec<RustSymbolIdentity>),
    Unresolved,
}

impl RustReferenceResolution {
    pub fn is_exact(&self) -> bool {
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
    pub fn candidate_names(&self) -> impl Iterator<Item = &str> {
        self.identities
            .iter()
            .map(|identity| identity.name.as_str())
    }

    pub fn identities_in_file<'a>(
        &'a self,
        file: &'a ProjectFile,
    ) -> impl Iterator<Item = &'a RustSymbolIdentity> {
        self.identities
            .iter()
            .filter(move |identity| &identity.file == file)
    }

    pub fn has_import_edges(&self) -> bool {
        !self.edges_by_importer.is_empty()
    }
}

/// Re-export and reverse-import indices over the Rust workspace.
#[derive(Debug, Default)]
pub struct RustUsageIndex {
    pub exports_by_file: HashMap<ProjectFile, ExportIndex>,
    pub importer_reverse: HashMap<ProjectFile, Vec<RustImportEdge>>,
    pub declaration_domains: HashMap<RustSymbolIdentity, Vec<Domain>>,
    /// `declaration_domains` keys bucketed by identity name, so per-reference
    /// resolution can look up the handful of same-named declarations instead of
    /// scanning every declaration in the workspace.
    pub identities_by_name: HashMap<String, Vec<RustSymbolIdentity>>,
    /// Importer files per imported module, derived from `importer_reverse`, so
    /// `binding_seeds` avoids scanning every import edge per call.
    pub module_importers: HashMap<ModuleKey, HashSet<ProjectFile>>,
    pub declaration_identities: HashMap<CodeUnit, RustSymbolIdentity>,
    pub value_constructor_identities: HashMap<CodeUnit, RustSymbolIdentity>,
    pub module_domains: HashMap<ModuleKey, Vec<Domain>>,
    pub module_extents: HashMap<ProjectFile, Vec<(ModuleKey, usize, usize)>>,
    pub physical_roots: HashMap<ProjectFile, ModuleKey>,
    pub actual_crate_roots: HashSet<ProjectFile>,
    pub physical_owners: RustPhysicalOwnerIndex,
    pub origin_routes_by_file: HashMap<ProjectFile, HashMap<String, Vec<RustOriginRoute>>>,
    pub macro_visible_ranges: RustMacroVisibleRanges,
    pub module_aliases: RustModuleAliasRoutes,
    pub module_files: RustModuleFiles,
}

#[derive(Debug, Default)]
pub struct RustModuleFiles {
    pub files: Vec<ProjectFile>,
    pub by_package: HashMap<String, Vec<usize>>,
    pub inline_by_name: HashMap<String, Vec<usize>>,
    pub cargo_routes: Arc<RustCargoRouteIndex>,
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
pub struct RustModuleAliasRoutes {
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

    fn index_inline_modules(&mut self, file_id: usize, declarations: &BTreeSet<CodeUnit>) {
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

        let resolved_module = if matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            let Some(resolved) =
                resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
            else {
                return Vec::new();
            };
            resolved
        } else {
            let relative = ModuleKey::new(importing_file, importing_module).with_suffix(segments);
            if self.files_for_module(&relative).is_empty() {
                resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
                    .unwrap_or_else(|| relative.package())
            } else {
                relative.package()
            }
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
        let mut routes = files
            .into_iter()
            .map(|file| RustResolvedModuleRoute {
                target_module: ModuleKey::new(&file, &resolved_module),
                target_file: file,
                provenance: RustRouteProvenance::Local,
            })
            .collect::<Vec<_>>();
        // Second candidate for a target root file: the same name spelled under
        // the kind root, where the modules shared with sibling targets live.
        // Appended, so the target's own route still comes first.
        if let Some(alternative) = self.kind_root_alternative(importing_file, &resolved_module) {
            for file in self.files_for_package(&alternative) {
                if routes.iter().all(|route| route.target_file != file) {
                    routes.push(RustResolvedModuleRoute {
                        target_module: ModuleKey::new(&file, &alternative),
                        target_file: file,
                        provenance: RustRouteProvenance::Local,
                    });
                }
            }
        }
        routes.retain(|route| {
            self.cargo_routes
                .target_relation(importing_file, &route.target_file)
                != RustCargoTargetRelation::Disjoint
        });
        routes
    }

    fn files_for_module(&self, module: &ModuleKey) -> Vec<ProjectFile> {
        self.files_for_package(&module.package())
    }

    fn files_for_package(&self, package: &str) -> Vec<ProjectFile> {
        let mut files = self
            .by_package
            .get(package)
            .into_iter()
            .flatten()
            .map(|file_id| self.files[*file_id].clone())
            .collect::<Vec<_>>();
        if let Some(inline) = self.inline_by_name.get(package) {
            files.extend(inline.iter().map(|file_id| self.files[*file_id].clone()));
        }
        files.sort();
        files.dedup();
        files
    }

    /// Re-spell `package` -- a name resolved against `importing_file`'s own
    /// `crate::` root -- under the kind root shared with its sibling targets,
    /// when that names files and the own-root spelling did not.
    ///
    /// This is the second half of the target-root chain: `crate::common::x` and
    /// `common::x` in `benches/b.rs` first mean this bench's own `common`, and
    /// only then the `benches/common/mod.rs` every bench shares.
    fn kind_root_alternative(&self, importing_file: &ProjectFile, package: &str) -> Option<String> {
        let kind_root = rust_target_kind_root_package(importing_file)?;
        let own_root = rust_crate_root_package(importing_file);
        let suffix = package.strip_prefix(&own_root)?;
        let alternative = format!("{kind_root}{suffix}");
        (!self.files_for_package(&alternative).is_empty()).then_some(alternative)
    }
}

fn build_macro_scope_edges(
    rust: &dyn RustSource,
    files: &[ProjectFile],
    module_files: &RustModuleFiles,
    physical_owners: &RustPhysicalOwnerIndex,
    parallel: bool,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<Vec<RustMacroScopeEdge>> {
    // Per-file scope walks are independent; collect in file order so edge
    // order matches a serial walk.
    let per_file_edges = |file: &ProjectFile| {
        keep_going().then_some(())?;
        let mut edges = Vec::new();
        let Some(prepared) = rust.prepared_syntax(file) else {
            return Some(edges);
        };
        let source = prepared.source();
        let root_module = ModuleKey::new(file, &rust_package_name(file));
        let mut pending = vec![(prepared.tree().root_node(), root_module)];
        while let Some((node, owner)) = pending.pop() {
            keep_going().then_some(())?;
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            for child in children.into_iter().rev() {
                keep_going().then_some(())?;
                if child.kind() != "mod_item" {
                    pending.push((child, owner.clone()));
                    continue;
                }
                let Some(name) = child.child_by_field_name("name").and_then(|name| {
                    source
                        .get(name.start_byte()..name.end_byte())
                        .map(str::trim)
                        .map(strip_raw_identifier_prefix)
                        .filter(|name| !name.is_empty())
                }) else {
                    continue;
                };
                let child_module = owner.with_suffix(&[name.to_string()]);
                let parent = RustMacroScopeKey {
                    file: file.clone(),
                    module: owner.clone(),
                };
                let imports_macros = rust_mod_item_has_macro_use(child, source);
                if let Some(body) = child.child_by_field_name("body") {
                    let scope = RustMacroScopeKey {
                        file: file.clone(),
                        module: child_module.clone(),
                    };
                    edges.push(RustMacroScopeEdge {
                        parent,
                        child: scope,
                        declaration_start: child.start_byte(),
                        visibility_start: child.end_byte(),
                        imports_macros,
                    });
                    pending.push((body, child_module));
                    continue;
                }
                for child_file in module_files
                    .files_for_module(&child_module)
                    .into_iter()
                    .filter(|child_file| {
                        child_file != file && physical_owners.intersects(file, child_file)
                    })
                {
                    keep_going().then_some(())?;
                    edges.push(RustMacroScopeEdge {
                        parent: parent.clone(),
                        child: RustMacroScopeKey {
                            file: child_file,
                            module: child_module.clone(),
                        },
                        declaration_start: child.start_byte(),
                        visibility_start: child.end_byte(),
                        imports_macros,
                    });
                }
            }
        }
        Some(edges)
    };
    let per_file_edges: Vec<Vec<RustMacroScopeEdge>> = if parallel {
        files
            .par_iter()
            .map(per_file_edges)
            .collect::<Option<Vec<_>>>()
    } else {
        files.iter().map(per_file_edges).collect::<Option<Vec<_>>>()
    }?;
    keep_going().then_some(per_file_edges.into_iter().flatten().collect())
}

fn rust_mod_item_has_macro_use(module: Node<'_>, source: &str) -> bool {
    let mut sibling = module.prev_named_sibling();
    while let Some(attribute_item) = sibling {
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let Some(attribute) = attribute_item.named_child(0) else {
            break;
        };
        let Some(path) = attribute.named_child(0) else {
            break;
        };
        if source.get(path.start_byte()..path.end_byte()) == Some("macro_use") {
            return true;
        }
        sibling = attribute_item.prev_named_sibling();
    }
    false
}

fn build_macro_visible_ranges(
    index: &dyn CodeUnitIndex,
    declarations: &HashMap<CodeUnit, RustSymbolIdentity>,
    edges: Vec<RustMacroScopeEdge>,
    keep_going: &impl Fn() -> bool,
) -> Option<RustMacroVisibleRanges> {
    let mut incoming: HashMap<RustMacroScopeKey, Vec<RustMacroScopeEdge>> = HashMap::default();
    let mut outgoing: HashMap<RustMacroScopeKey, Vec<RustMacroScopeEdge>> = HashMap::default();
    for edge in edges {
        keep_going().then_some(())?;
        outgoing
            .entry(edge.parent.clone())
            .or_default()
            .push(edge.clone());
        incoming.entry(edge.child.clone()).or_default().push(edge);
    }

    let mut definitions_by_scope_name: HashMap<
        (RustMacroScopeKey, String),
        Vec<(CodeUnit, usize)>,
    > = HashMap::default();
    for (declaration, identity) in declarations
        .iter()
        .filter(|(_, identity)| identity.namespace == RustSymbolNamespace::Macro)
    {
        keep_going().then_some(())?;
        if let Some(definition_start) = index
            .ranges(declaration)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
        {
            definitions_by_scope_name
                .entry((
                    RustMacroScopeKey {
                        file: identity.file.clone(),
                        module: identity.module.clone(),
                    },
                    identity.name.clone(),
                ))
                .or_default()
                .push((declaration.clone(), definition_start));
        }
    }

    let mut visible_by_macro = HashMap::default();
    for (declaration, identity) in declarations
        .iter()
        .filter(|(_, identity)| identity.namespace == RustSymbolNamespace::Macro)
    {
        keep_going().then_some(())?;
        let Some(definition_end) = index
            .ranges(declaration)
            .into_iter()
            .map(|range| range.end_byte)
            .min()
        else {
            continue;
        };
        let initial = RustMacroScopeKey {
            file: identity.file.clone(),
            module: identity.module.clone(),
        };
        let mut visible: HashMap<RustMacroScopeKey, Vec<(usize, usize)>> = HashMap::default();
        let mut visited = HashSet::default();
        let mut pending = vec![(initial, definition_end)];
        while let Some((scope, visible_after)) = pending.pop() {
            keep_going().then_some(())?;
            if !visited.insert((scope.clone(), visible_after)) {
                continue;
            }
            let shadow_start = definitions_by_scope_name
                .get(&(scope.clone(), identity.name.clone()))
                .into_iter()
                .flatten()
                .filter(|(candidate, start)| *candidate != *declaration && *start >= visible_after)
                .map(|(_, start)| *start)
                .min()
                .unwrap_or(usize::MAX);
            visible
                .entry(scope.clone())
                .or_default()
                .push((visible_after, shadow_start));
            pending.extend(
                incoming
                    .get(&scope)
                    .into_iter()
                    .flatten()
                    .filter(|edge| edge.imports_macros && edge.visibility_start < shadow_start)
                    .map(|edge| (edge.parent.clone(), edge.visibility_start)),
            );
            pending.extend(
                outgoing
                    .get(&scope)
                    .into_iter()
                    .flatten()
                    .filter(|edge| {
                        edge.declaration_start >= visible_after
                            && edge.declaration_start < shadow_start
                    })
                    .map(|edge| (edge.child.clone(), 0)),
            );
        }
        visible_by_macro.insert(declaration.clone(), visible);
    }
    Some(visible_by_macro)
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
    pub fn exact_root_for_resolution(
        &self,
        resolution: &RustReferenceResolution,
        seeds: &RustBindingSeeds,
    ) -> Option<CodeUnit> {
        let RustReferenceResolution::Exact(identity) = resolution else {
            return None;
        };
        let mut matches = seeds.roots.iter().filter(|root| {
            seeds
                .root_identities
                .get(*root)
                .is_some_and(|candidates| candidates.contains(identity))
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
        rust: &dyn RustSource,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
    ) -> bool {
        if identity.file != *caller_file
            && !self.physical_owners.intersects(&identity.file, caller_file)
            && rust
                .cargo_routes()
                .files_share_target(&identity.file, caller_file)
                != Some(true)
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
                                && (self.physical_owners.owned_by(caller_file, &identity.file)
                                    || rust
                                        .cargo_routes()
                                        .files_share_target(&identity.file, caller_file)
                                        == Some(true))))
                })
    }

    fn resolved_declaration_visible_to(
        &self,
        rust: &dyn RustSource,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
        provenance: RustRouteProvenance,
    ) -> bool {
        match provenance {
            RustRouteProvenance::Local => {
                self.declaration_owner_visible_to(rust, identity, caller_file, caller_module)
            }
            RustRouteProvenance::CurrentLibrary | RustRouteProvenance::Dependency => {
                self.physical_roots
                    .get(&identity.file)
                    .is_some_and(|root| root == &identity.module)
                    || self
                        .module_domains
                        .get(&identity.module)
                        .is_some_and(|domains| domains.contains(&Domain::Public))
            }
        }
    }

    fn declaration_visible_at(
        &self,
        rust: &dyn RustSource,
        declaration: &CodeUnit,
        caller_file: &ProjectFile,
        caller_byte: usize,
    ) -> bool {
        let Some(caller_module) = self.module_at_byte(caller_file, caller_byte) else {
            return false;
        };
        let immediate_parent = rust.structural_parent_of(declaration);
        let visibility_declaration = immediate_parent
            .as_ref()
            .filter(|parent| is_rust_trait_declaration(rust.code_units(), parent))
            .unwrap_or(declaration);
        let visibility = rust_declaration_visibility(rust, visibility_declaration);
        let mut parent = immediate_parent;
        let owner = loop {
            match parent {
                Some(ref candidate) if candidate.is_module() => {
                    break ModuleKey::new(declaration.source(), &candidate.fq_name());
                }
                Some(candidate) => parent = rust.structural_parent_of(&candidate),
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
                .intersects(declaration.source(), caller_file)
            || rust
                .cargo_routes()
                .files_share_target(declaration.source(), caller_file)
                == Some(true))
            && domain.contains_module(caller_module)
    }

    pub fn build(rust: &dyn RustSource, parallel: bool) -> Self {
        Self::build_while(rust, parallel, &|| true)
            .expect("uninterrupted Rust usage-index construction")
    }

    pub fn build_while(
        rust: &dyn RustSource,
        parallel: bool,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<Self> {
        /// One file's contribution to the index, collected off-thread and merged
        /// in `files` order so accumulator ordering matches a serial walk.
        #[derive(Default)]
        struct RustFileFacts {
            declarations: BTreeSet<CodeUnit>,
            module_extents: Vec<(ModuleKey, usize, usize)>,
            declaration_identities: Vec<(CodeUnit, RustSymbolIdentity)>,
            declared_module_domains: Vec<(ModuleKey, Domain)>,
            declaration_domains: Vec<(RustSymbolIdentity, Domain)>,
            value_constructor_identities: Vec<(CodeUnit, RustSymbolIdentity)>,
            exports: ExportIndex,
            imports: Vec<RustProjectedImport>,
        }

        let _build_scope = profiling::scope("RustUsageIndex::build");
        keep_going().then_some(())?;
        let files: Vec<ProjectFile> = rust.get_analyzed_files().into_iter().collect();
        let physical_roots: HashMap<ProjectFile, ModuleKey> = files
            .iter()
            .map(|file| (file.clone(), ModuleKey::new(file, &rust_package_name(file))))
            .collect();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut imports_by_file: HashMap<ProjectFile, Vec<RustProjectedImport>> =
            HashMap::default();
        let mut declaration_domains: HashMap<RustSymbolIdentity, Vec<Domain>> = HashMap::default();
        let mut declaration_identities: HashMap<CodeUnit, RustSymbolIdentity> = HashMap::default();
        let mut value_constructor_identities: HashMap<CodeUnit, RustSymbolIdentity> =
            HashMap::default();
        let mut declared_module_domains: HashMap<ModuleKey, Vec<Domain>> = HashMap::default();
        let mut module_extents: HashMap<ProjectFile, Vec<(ModuleKey, usize, usize)>> =
            HashMap::default();
        let cargo_routes = {
            let _scope = profiling::scope("RustUsageIndex::build::cargo_routes");
            rust.cargo_routes_while(keep_going)?
        };
        keep_going().then_some(())?;
        let mut module_files = RustModuleFiles::new(&files, cargo_routes);
        let actual_crate_roots = {
            let _scope = profiling::scope("RustUsageIndex::build::crate_roots");
            let is_crate_root = |file: &&ProjectFile| {
                rust_package_name(file) == rust_crate_root_package(file)
                    || module_files
                        .cargo_routes
                        .target_roots_for_file(file)
                        .contains(file)
            };
            if parallel {
                files.par_iter().filter(is_crate_root).cloned().collect()
            } else {
                files.iter().filter(is_crate_root).cloned().collect()
            }
        };
        // Everything this pass derives is a function of one file. Keys either
        // carry the file themselves or are folded below in `files` order, so the
        // merged maps are identical to a serial walk. `parallel` is false when
        // building from inside a rayon worker (see `usage_index()`): running
        // par_iter there lets the join steal a job that re-enters the memo.
        let per_file_facts = |file: &ProjectFile| {
            keep_going().then_some(())?;
            let mut facts = RustFileFacts::default();
            let declarations = rust.declarations(file);
            let prepared = rust.prepared_syntax(file);
            let imports = prepared
                .as_ref()
                .map(|syntax| {
                    for (module, start, end) in rust_module_extents(
                        syntax.tree().root_node(),
                        syntax.source(),
                        &rust_package_name(file),
                    ) {
                        let module_key = ModuleKey::new(file, &module);
                        facts.module_extents.push((module_key, start, end));
                    }
                    rust_import_projection(
                        syntax.tree().root_node(),
                        syntax.source(),
                        &rust_package_name(file),
                    )
                })
                .unwrap_or_default();
            for declaration in &declarations {
                keep_going().then_some(())?;
                let (owner, declared_module) = if declaration.is_module() {
                    let declared = ModuleKey::new(file, &declaration.fq_name());
                    let owner = declared
                        .parent()
                        .unwrap_or_else(|| ModuleKey::new(file, &rust_package_name(file)));
                    (owner, Some(declared))
                } else {
                    let owner = match rust.structural_parent_of(declaration) {
                        None => ModuleKey::new(file, &rust_package_name(file)),
                        Some(parent) if parent.is_module() => {
                            ModuleKey::new(file, &parent.fq_name())
                        }
                        Some(_) => continue,
                    };
                    (owner, None)
                };
                let Some(namespace) = RustSymbolNamespace::of(rust, declaration) else {
                    continue;
                };
                let identity = RustSymbolIdentity {
                    file: file.clone(),
                    module: owner.clone(),
                    name: declaration.identifier().to_string(),
                    namespace,
                };
                facts
                    .declaration_identities
                    .push((declaration.clone(), identity.clone()));
                let constructor_domain = prepared.as_ref().and_then(|syntax| {
                    let node = rust_named_declaration_node(
                        rust.code_units(),
                        declaration,
                        syntax.tree().root_node(),
                        syntax.source(),
                    )?;
                    rust_value_constructor_visibilities(node, syntax.source())?
                        .into_iter()
                        .map(|visibility| {
                            direct_import_scope_for_module(file, &owner.package(), visibility)
                        })
                        .try_fold(Domain::Public, |effective, domain| {
                            effective.intersect(&domain?)
                        })
                });
                let declaration_domain = if namespace == RustSymbolNamespace::Macro
                    && is_rust_macro_export_declaration(rust.code_units(), declaration)
                {
                    Some(Domain::Public)
                } else {
                    direct_import_scope_for_module(
                        file,
                        &owner.package(),
                        rust_declaration_visibility(rust, declaration),
                    )
                };
                if let Some(domain) = declaration_domain {
                    if let Some(declared_module) = declared_module {
                        facts
                            .declared_module_domains
                            .push((declared_module, domain.clone()));
                    }
                    facts
                        .declaration_domains
                        .push((identity.clone(), domain.clone()));
                    if let Some(constructor_domain) = constructor_domain {
                        let constructor = RustSymbolIdentity {
                            namespace: RustSymbolNamespace::Value,
                            ..identity
                        };
                        facts
                            .declaration_domains
                            .push((constructor.clone(), constructor_domain));
                        facts
                            .value_constructor_identities
                            .push((declaration.clone(), constructor));
                    }
                }
            }
            facts.exports = export_index_of_declarations(rust, file, &declarations);
            facts.imports = imports;
            facts.declarations = declarations;
            Some(facts)
        };
        let per_file_scope = profiling::scope("RustUsageIndex::build::per_file");
        let file_facts: Vec<RustFileFacts> = if parallel {
            files
                .par_iter()
                .map(per_file_facts)
                .collect::<Option<Vec<_>>>()
        } else {
            files.iter().map(per_file_facts).collect::<Option<Vec<_>>>()
        }?;

        for (file_id, (file, facts)) in files.iter().zip(file_facts).enumerate() {
            keep_going().then_some(())?;
            if !facts.module_extents.is_empty() {
                module_extents.insert(file.clone(), facts.module_extents);
            }
            declaration_identities.extend(facts.declaration_identities);
            for (declared_module, domain) in facts.declared_module_domains {
                declared_module_domains
                    .entry(declared_module)
                    .or_default()
                    .push(domain);
            }
            for (identity, domain) in facts.declaration_domains {
                declaration_domains
                    .entry(identity)
                    .or_default()
                    .push(domain);
            }
            value_constructor_identities.extend(facts.value_constructor_identities);
            exports_by_file.insert(file.clone(), facts.exports);
            imports_by_file.insert(file.clone(), facts.imports);
            module_files.index_inline_modules(file_id, &facts.declarations);
        }
        drop(per_file_scope);

        for declaration in module_files.cargo_routes.external_module_declarations() {
            keep_going().then_some(())?;
            if !physical_roots.contains_key(&declaration.target_file) {
                continue;
            }
            let Some(domain) = direct_import_scope_for_module(
                &declaration.declaring_file,
                &declaration.declaring_module,
                declaration.visibility.clone(),
            ) else {
                continue;
            };
            declared_module_domains
                .entry(ModuleKey::new(
                    &declaration.target_file,
                    &rust_package_name(&declaration.target_file),
                ))
                .or_default()
                .push(domain);
        }

        let module_domains = effective_module_domains(declared_module_domains);
        let physical_owners = {
            let _scope = profiling::scope("RustUsageIndex::build::physical_owners");
            RustPhysicalOwnerIndex::build(
                rust,
                &module_files,
                &physical_roots,
                &declaration_identities,
                &actual_crate_roots,
                keep_going,
            )?
        };
        keep_going().then_some(())?;
        let module_aliases = {
            let _scope = profiling::scope("RustUsageIndex::build::module_aliases");
            build_module_alias_routes(&module_files, &files, &imports_by_file, keep_going)?
        };
        keep_going().then_some(())?;
        let importer_reverse = {
            let _scope = profiling::scope("RustUsageIndex::build::importer_reverse");
            build_importer_reverse(
                &module_files,
                &module_aliases,
                &physical_owners,
                &files,
                &imports_by_file,
                parallel,
                keep_going,
            )?
        };
        keep_going().then_some(())?;
        let origin_routes_by_file = {
            let _scope = profiling::scope("RustUsageIndex::build::origin_routes");
            build_origin_routes(
                &importer_reverse,
                &declaration_domains,
                &module_domains,
                keep_going,
            )?
        };
        keep_going().then_some(())?;
        let macro_visible_ranges = {
            let _scope = profiling::scope("RustUsageIndex::build::macro_visible_ranges");
            build_macro_visible_ranges(
                rust.code_units(),
                &declaration_identities,
                build_macro_scope_edges(
                    rust,
                    &files,
                    &module_files,
                    &physical_owners,
                    parallel,
                    keep_going,
                )?,
                keep_going,
            )?
        };
        keep_going().then_some(())?;

        let mut identities_by_name: HashMap<String, Vec<RustSymbolIdentity>> = HashMap::default();
        for identity in declaration_domains.keys() {
            keep_going().then_some(())?;
            identities_by_name
                .entry(identity.name.clone())
                .or_default()
                .push(identity.clone());
        }
        let mut module_importers: HashMap<ModuleKey, HashSet<ProjectFile>> = HashMap::default();
        for edge in importer_reverse.values().flatten() {
            keep_going().then_some(())?;
            module_importers
                .entry(edge.target_module.clone())
                .or_default()
                .insert(edge.importer.clone());
        }

        Some(Self {
            exports_by_file,
            importer_reverse,
            declaration_domains,
            identities_by_name,
            module_importers,
            declaration_identities,
            value_constructor_identities,
            module_domains,
            module_extents,
            physical_roots,
            actual_crate_roots,
            physical_owners,
            origin_routes_by_file,
            macro_visible_ranges,
            module_aliases,
            module_files,
        })
    }

    /// Files that import one of the `seeds` (plus the seed files themselves) —
    /// the candidate set the forward scan narrows to. Named imports are followed
    /// transitively because a private parent-module import can itself be imported
    /// by a child module without becoming a public re-export.
    pub fn importers_of_seeds(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        self.importers_of_seeds_while(seeds, &|| true)
            .expect("uninterrupted Rust importer selection")
    }

    fn importers_of_seeds_while(
        &self,
        seeds: &RustBindingSeeds,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashSet<ProjectFile>> {
        keep_going().then_some(())?;
        let mut out = HashSet::default();
        for importer in seeds.edges_by_importer.keys() {
            keep_going().then_some(())?;
            out.insert(importer.clone());
        }
        // Module-prefix importers are computed here, not in `binding_seeds`:
        // only this forward-scan candidate-set path consumes them, and the
        // whole-workspace inverted build calls `binding_seeds` per candidate
        // symbol, where paying a workspace-wide file union per call is the
        // dominant cost (#1504).
        let mut target_modules = HashSet::default();
        for root in &seeds.roots {
            keep_going().then_some(())?;
            if let Some(identity) = self
                .declaration_identities
                .get(root)
                .filter(|identity| identity.namespace == RustSymbolNamespace::Module)
            {
                target_modules.insert(
                    identity
                        .module
                        .with_suffix(std::slice::from_ref(&identity.name)),
                );
            }
        }
        for module in target_modules {
            for importer in self.module_importers.get(&module).into_iter().flatten() {
                keep_going().then_some(())?;
                out.insert(importer.clone());
            }
        }
        for root in &seeds.roots {
            for file in self
                .module_files
                .cargo_routes
                .files_that_can_reference_target_of(root.source())
            {
                keep_going().then_some(())?;
                out.insert(file);
            }
        }
        for identity in &seeds.identities {
            keep_going().then_some(())?;
            out.insert(identity.file.clone());
        }
        for root in &seeds.roots {
            keep_going().then_some(())?;
            out.insert(root.source().clone());
            for scope in self.macro_visible_ranges.get(root).into_iter().flatten() {
                keep_going().then_some(())?;
                out.insert(scope.0.file.clone());
            }
        }
        Some(out)
    }

    fn matching_edges_for_importer<'a>(
        &self,
        importer: &ProjectFile,
        seeds: &'a RustBindingSeeds,
    ) -> impl Iterator<Item = &'a RustImportEdge> {
        seeds.edges_by_importer.get(importer).into_iter().flatten()
    }

    pub fn binding_seeds(
        &self,
        rust: &dyn RustSource,
        roots: &BTreeSet<CodeUnit>,
    ) -> RustBindingSeeds {
        self.binding_seeds_while(rust, roots, &|| true)
            .expect("uninterrupted Rust binding-seed construction")
    }

    fn binding_seeds_while(
        &self,
        rust: &dyn RustSource,
        roots: &BTreeSet<CodeUnit>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<RustBindingSeeds> {
        let mut identities = HashSet::default();
        let mut identity_domains: HashMap<RustSymbolIdentity, Vec<Domain>> = HashMap::default();
        let mut root_identities: HashMap<CodeUnit, Vec<RustSymbolIdentity>> = HashMap::default();
        let mut canonical_identities: HashMap<RustSymbolIdentity, HashSet<RustSymbolIdentity>> =
            HashMap::default();
        let mut pending = VecDeque::new();
        for root in roots {
            keep_going().then_some(())?;
            let mut candidate_identities = self
                .declaration_identities
                .get(root)
                .cloned()
                .into_iter()
                .chain(self.value_constructor_identities.get(root).cloned())
                .collect::<Vec<_>>();
            if candidate_identities.is_empty() {
                candidate_identities.push(RustSymbolIdentity {
                    file: root.source().clone(),
                    module: ModuleKey::new(root.source(), root.package_name()),
                    name: root.identifier().to_string(),
                    namespace: RustSymbolNamespace::of(rust, root)
                        .unwrap_or(RustSymbolNamespace::Value),
                });
            }
            for identity in candidate_identities {
                keep_going().then_some(())?;
                root_identities
                    .entry(root.clone())
                    .or_default()
                    .push(identity.clone());
                identities.insert(identity.clone());
                canonical_identities
                    .entry(identity.clone())
                    .or_default()
                    .insert(identity.clone());
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
        }
        let mut edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
        let mut visited = HashSet::default();
        while let Some((target, domain, canonical_origin)) = pending.pop_front() {
            keep_going().then_some(())?;
            if !visited.insert((target.clone(), domain.clone(), canonical_origin.clone())) {
                continue;
            }
            let Some(edges) = self.importer_reverse.get(&target.file) else {
                continue;
            };
            for edge in edges {
                keep_going().then_some(())?;
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
                let Some(effective_domain) = imported_identity_domain(&target, &domain, edge)
                else {
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
                    canonical_identities
                        .entry(alias.clone())
                        .or_default()
                        .insert(canonical_origin.clone());
                    identity_domains
                        .entry(alias.clone())
                        .or_default()
                        .push(effective_domain.clone());
                    pending.push_back((alias, effective_domain, canonical_origin.clone()));
                }
            }
        }
        Some(RustBindingSeeds {
            roots: roots.clone(),
            root_origins: root_identities.values().flatten().cloned().collect(),
            root_identities,
            canonical_identities,
            identities,
            identity_domains,
            edges_by_importer,
        })
    }

    pub fn export_targets_from_files(
        &self,
        index: &dyn CodeUnitIndex,
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
                        targets.extend(rust_declaration_targets_in_files(index, &files, &name));
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
                    ExportEntry::Default { .. } | ExportEntry::ReexportedModule { .. } => {}
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
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    let mut targets: Vec<_> = files
        .iter()
        .flat_map(|file| {
            index
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

/// Candidate files: those importing a seed, plus the seed files themselves.
pub fn usage_importers(
    rust: &dyn RustUsageSource,
    seeds: &RustBindingSeeds,
) -> HashSet<ProjectFile> {
    rust.usage_index().importers_of_seeds(seeds)
}

/// [`usage_importers`] composed with [`usage_binding_seeds`] over a cancellable
/// index build. A cold candidate discovery pays for the whole usage index, so
/// every stage from the memo down has to observe the same `keep_going`.
pub fn usage_candidate_files_while(
    rust: &dyn RustUsageSource,
    roots: &BTreeSet<CodeUnit>,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<HashSet<ProjectFile>> {
    let index = rust.usage_index_while(keep_going)?;
    keep_going().then_some(())?;
    let seeds = index.binding_seeds_while(rust, roots, keep_going)?;
    keep_going().then_some(())?;
    index.importers_of_seeds_while(&seeds, keep_going)
}

/// Canonical local binding identities for a target, including named private
/// imports that can be imported again by descendant modules.
pub fn usage_binding_seeds(
    rust: &dyn RustUsageSource,
    roots: &BTreeSet<CodeUnit>,
) -> RustBindingSeeds {
    rust.usage_index().binding_seeds(rust, roots)
}

/// [`usage_binding_seeds`] over a cancellable index build.
pub fn usage_binding_seeds_while(
    rust: &dyn RustUsageSource,
    roots: &BTreeSet<CodeUnit>,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<RustBindingSeeds> {
    let index = rust.usage_index_while(keep_going)?;
    keep_going().then_some(())?;
    index.binding_seeds_while(rust, roots, keep_going)
}

/// `(direct_names, qualified_names)` — local names that bind a seed directly
/// (`use path::Item;`) and exact paths that reach a seed through a namespace
/// binding (`use crate_name;` followed by `crate_name::Item`).
pub fn usage_binding_names(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
) -> (HashSet<String>, HashSet<String>) {
    let mut direct = HashSet::default();
    let mut qualified = HashSet::default();
    let index = rust.usage_index();
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
    for root in seeds.roots.iter().filter(|root| root.is_macro()) {
        if index
            .macro_visible_ranges
            .get(root)
            .is_some_and(|visible| visible.keys().any(|scope| &scope.file == file))
        {
            direct.insert(root.identifier().to_string());
        }
    }
    (direct, qualified)
}

pub fn usage_has_exact_scoped_binding(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
    namespace: RustReferenceNamespace,
) -> bool {
    scoped_explicit_import(rust, file, byte, name).is_some_and(|scoped| {
        unique_seed_identity_for_import_targets(
            rust,
            file,
            seeds,
            &scoped.targets,
            &scoped.dependency_roots,
            namespace,
            byte,
        )
        .is_some()
            || scoped.fqn.as_deref().is_some_and(|fqn| {
                unique_seed_identity_for_fqn(
                    rust,
                    file,
                    byte,
                    seeds,
                    fqn,
                    &scoped.dependency_roots,
                    namespace,
                )
                .is_some()
            })
    })
}

/// All local names in `file` binding a seed (direct or namespace) — the
/// owner-binding names the member scan keys on.
pub fn usage_binding_local_names(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
) -> HashSet<String> {
    rust.usage_index()
        .matching_edges_for_importer(file, seeds)
        .map(|edge| edge.local_name.clone())
        .collect()
}

pub fn usage_root_declaration_matches_at(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
) -> bool {
    let index = rust.usage_index();
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

pub fn usage_declaration_visible_at(
    rust: &dyn RustUsageSource,
    declaration: &CodeUnit,
    file: &ProjectFile,
    byte: usize,
) -> bool {
    rust.usage_index()
        .declaration_visible_at(rust, declaration, file, byte)
}

pub fn usage_exact_root_for_resolution(
    rust: &dyn RustUsageSource,
    resolution: &RustReferenceResolution,
    seeds: &RustBindingSeeds,
) -> Option<CodeUnit> {
    rust.usage_index()
        .exact_root_for_resolution(resolution, seeds)
}

pub fn usage_local_module_prefix_visible_at(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
) -> bool {
    let index = rust.usage_index();
    let Some(module) = index.module_at_byte(file, byte) else {
        return false;
    };
    if index.matching_edges_for_importer(file, seeds).any(|edge| {
        edge.importer_module == *module
            && edge.extent.contains(byte)
            && edge.local_name == name
            && (edge.namespace == Some(RustSymbolNamespace::Module)
                || matches!(edge.kind, RustImportEdgeKind::Qualified(_)))
    }) {
        return true;
    }
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

    let prefix = [name.to_string()];
    if index
        .module_aliases
        .resolve_segments(&index.module_files, file, &module.package(), &prefix)
        .into_iter()
        .any(|route| {
            seeds.identities.iter().any(|identity| {
                let target_module = if identity.namespace == RustSymbolNamespace::Module {
                    identity
                        .module
                        .with_suffix(std::slice::from_ref(&identity.name))
                } else {
                    identity.module.clone()
                };
                (route.target_file == identity.file
                    || index
                        .physical_owners
                        .intersects(&route.target_file, &identity.file)
                    || rust
                        .cargo_routes()
                        .files_share_target(&route.target_file, &identity.file)
                        == Some(true))
                    && route.target_module.contains(&target_module)
                    && seeds.identity_domains.get(identity).is_some_and(|domains| {
                        domains.iter().any(|domain| domain.contains_module(module))
                    })
            })
        })
    {
        return true;
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
            && seeds
                .identity_domains
                .get(identity)
                .is_some_and(|domains| domains.iter().any(|domain| domain.contains_module(module)))
    })
}

#[allow(clippy::too_many_arguments)]
pub fn usage_reference_at(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    segments: &[&str],
    byte: usize,
    namespace: RustReferenceNamespace,
    root_shadowed: bool,
    leading_absolute: bool,
) -> RustReferenceResolution {
    if segments.is_empty() || (root_shadowed && !leading_absolute) {
        return RustReferenceResolution::Unresolved;
    }
    let index = rust.usage_index();
    let Some(module) = index.module_at_byte(file, byte) else {
        return RustReferenceResolution::Unresolved;
    };
    let leading_absolute_local = leading_absolute
        && index
            .module_files
            .cargo_routes
            .file_uses_rust_2015_edition(file);
    let absolute_route_admitted = |provenance| {
        !leading_absolute
            || matches!(
                provenance,
                RustRouteProvenance::CurrentLibrary | RustRouteProvenance::Dependency
            )
            || (leading_absolute_local && provenance == RustRouteProvenance::Local)
    };
    let mut matches: HashSet<RustSymbolIdentity> = index
        .origin_routes_by_file
        .get(file)
        .and_then(|routes| routes.get(segments[0]))
        .into_iter()
        .flatten()
        .filter(|route| {
            route.importer_module == *module
                && route.extent.contains(byte)
                && route.namespace.accepts(namespace)
                && route.domain.contains_module(module)
                && absolute_route_admitted(route.provenance)
                && segments
                    .iter()
                    .copied()
                    .eq(route.path.iter().map(String::as_str))
        })
        .map(|route| route.origin.clone())
        .collect();
    if namespace == RustReferenceNamespace::Macro
        && segments.len() == 1
        && (!leading_absolute || leading_absolute_local)
    {
        let scope = RustMacroScopeKey {
            file: file.clone(),
            module: module.clone(),
        };
        let visible_macros = index
            .macro_visible_ranges
            .iter()
            .filter(|(declaration, visible)| {
                declaration.identifier() == segments[0]
                    && visible.get(&scope).is_some_and(|ranges| {
                        ranges
                            .iter()
                            .any(|(start, end)| *start <= byte && byte < *end)
                    })
            })
            .map(|(declaration, _)| declaration)
            .collect::<Vec<_>>();
        if !visible_macros.is_empty() {
            matches.clear();
            matches.extend(
                visible_macros
                    .into_iter()
                    .filter(|declaration| seeds.roots.contains(*declaration))
                    .filter_map(|declaration| {
                        index.declaration_identities.get(declaration).cloned()
                    }),
            );
        }
    }

    if matches!(
        namespace,
        RustReferenceNamespace::PathPrefix | RustReferenceNamespace::Any
    ) {
        let owned_segments = segments
            .iter()
            .map(|segment| (*segment).to_string())
            .collect::<Vec<_>>();
        for route in index.module_aliases.resolve_segments(
            &index.module_files,
            file,
            &module.package(),
            &owned_segments,
        ) {
            if !absolute_route_admitted(route.provenance) {
                continue;
            }
            matches.extend(
                seeds
                    .root_origins
                    .iter()
                    .filter(|identity| {
                        // Iterating the (small) root-origin set instead of every
                        // declaration; membership in `declaration_domains` is
                        // still required, as the old whole-map scan implied.
                        let Some(domains) = index.declaration_domains.get(*identity) else {
                            return false;
                        };
                        let domains = seeds.identity_domains.get(*identity).unwrap_or(domains);
                        identity.namespace == RustSymbolNamespace::Module
                            && identity
                                .module
                                .with_suffix(std::slice::from_ref(&identity.name))
                                == route.target_module
                            && domains.iter().any(|domain| domain.contains_module(module))
                    })
                    .cloned(),
            );
        }
    }
    if segments.len() == 1
        && namespace != RustReferenceNamespace::Macro
        && (!leading_absolute || leading_absolute_local)
    {
        matches.extend(
            index
                .identities_by_name
                .get(segments[0])
                .into_iter()
                .flatten()
                .filter(|identity| {
                    let domains = index
                        .declaration_domains
                        .get(*identity)
                        .expect("identities_by_name entries are declaration_domains keys");
                    let domains = seeds.identity_domains.get(*identity).unwrap_or(domains);
                    identity.file == *file
                        && identity.module == *module
                        && identity.namespace.accepts(namespace)
                        && domains.iter().any(|domain| domain.contains_module(module))
                        && index.declaration_owner_visible_to(rust, identity, file, module)
                })
                .cloned(),
        );
        if matches.is_empty() {
            let scoped_import = scoped_explicit_import(rust, file, byte, segments[0]);
            let identity = match scoped_import {
                Some(scoped) => unique_seed_identity_for_import_targets(
                    rust,
                    file,
                    seeds,
                    &scoped.targets,
                    &scoped.dependency_roots,
                    namespace,
                    byte,
                )
                .or_else(|| {
                    scoped.fqn.as_deref().and_then(|fqn| {
                        unique_seed_identity_for_fqn(
                            rust,
                            file,
                            byte,
                            seeds,
                            fqn,
                            &scoped.dependency_roots,
                            namespace,
                        )
                    })
                }),
                None if index
                    .origin_routes_by_file
                    .get(file)
                    .and_then(|routes| routes.get(segments[0]))
                    .is_some_and(|routes| !routes.is_empty()) =>
                {
                    // A structured import for this name exists, but none
                    // is visible at this byte. The file-wide reference
                    // context cannot restore a function-local import
                    // outside its lexical extent.
                    None
                }
                None => rust
                    .reference_context_of(file)
                    .resolve_bare(segments[0])
                    .and_then(|resolved_fqn| {
                        unique_seed_identity_for_fqn(
                            rust,
                            file,
                            byte,
                            seeds,
                            resolved_fqn,
                            &[],
                            namespace,
                        )
                    }),
            };
            if let Some(identity) = identity {
                matches.insert(identity);
            }
        }
    } else if segments.len() > 1 && matches.is_empty() {
        let terminal = segments[segments.len() - 1];
        let prefix = &segments[..segments.len() - 1];
        let package = module.package();
        let owned_prefix = prefix
            .iter()
            .map(|segment| (*segment).to_string())
            .collect::<Vec<_>>();
        for resolved in index.module_aliases.resolve_segments(
            &index.module_files,
            file,
            &package,
            &owned_prefix,
        ) {
            if !absolute_route_admitted(resolved.provenance) {
                continue;
            }
            matches.extend(
                index
                    .identities_by_name
                    .get(terminal)
                    .into_iter()
                    .flatten()
                    .filter(|identity| {
                        let domains = index
                            .declaration_domains
                            .get(*identity)
                            .expect("identities_by_name entries are declaration_domains keys");
                        identity.file == resolved.target_file
                            && identity.module == resolved.target_module
                            && identity.namespace.accepts(namespace)
                            && domains.iter().any(|domain| domain.contains_module(module))
                            && index.resolved_declaration_visible_to(
                                rust,
                                identity,
                                file,
                                module,
                                resolved.provenance,
                            )
                    })
                    .cloned(),
            );
            matches.extend(
                index
                    .origin_routes_by_file
                    .get(&resolved.target_file)
                    .and_then(|routes| routes.get(terminal))
                    .into_iter()
                    .flatten()
                    .filter(|route| {
                        route.importer_module == resolved.target_module
                            && route.path.len() == 1
                            && route.path[0] == terminal
                            && route.namespace.accepts(namespace)
                            && route.domain.contains_module(module)
                    })
                    .map(|route| route.origin.clone()),
            );
        }
        let resolved_modules = if leading_absolute && !leading_absolute_local {
            Vec::new()
        } else if matches!(prefix.first(), Some(&"crate" | &"self" | &"super")) {
            let mut crate_packages = index
                .module_files
                .cargo_routes
                .target_roots_for_file(file)
                .into_iter()
                .map(|root| rust_package_name(&root))
                .collect::<Vec<_>>();
            if crate_packages.is_empty() {
                crate_packages.push(module.crate_root.clone());
            }
            crate_packages.sort();
            crate_packages.dedup();
            crate_packages
                .into_iter()
                .filter_map(|crate_package| {
                    resolve_rust_module_segments_with_crate(&package, &crate_package, prefix)
                        .map(|package| ModuleKey::new(file, &package))
                })
                .collect()
        } else {
            vec![ModuleKey {
                crate_root: module.crate_root.clone(),
                components: if leading_absolute {
                    prefix
                        .iter()
                        .map(|segment| (*segment).to_string())
                        .collect()
                } else {
                    module
                        .components
                        .iter()
                        .cloned()
                        .chain(prefix.iter().map(|segment| (*segment).to_string()))
                        .collect()
                },
            }]
        };
        for resolved in resolved_modules {
            matches.extend(
                index
                    .identities_by_name
                    .get(terminal)
                    .into_iter()
                    .flatten()
                    .filter(|identity| {
                        let domains = index
                            .declaration_domains
                            .get(*identity)
                            .expect("identities_by_name entries are declaration_domains keys");
                        let domains = seeds.identity_domains.get(*identity).unwrap_or(domains);
                        identity.module == resolved
                            && identity.namespace.accepts(namespace)
                            && domains.iter().any(|domain| domain.contains_module(module))
                            && index.declaration_owner_visible_to(rust, identity, file, module)
                    })
                    .cloned(),
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

pub fn exported_targets_from_files(
    rust: &dyn RustUsageSource,
    module_files: &[ProjectFile],
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    rust.usage_index()
        .export_targets_from_files(rust.code_units(), module_files, export_name)
}

pub fn usage_crate_export_targets(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let index = rust.usage_index();
    let mut crate_roots = index
        .physical_owners
        .roots_by_file
        .get(file)
        .into_iter()
        .flatten()
        .filter(|root| index.actual_crate_roots.contains(*root))
        .cloned()
        .collect::<Vec<_>>();
    if index.actual_crate_roots.contains(file) {
        crate_roots.push(file.clone());
    }
    crate_roots.sort();
    crate_roots.dedup();
    let mut targets = index.export_targets_from_files(rust.code_units(), &crate_roots, export_name);
    targets.extend(
        index
            .importer_reverse
            .values()
            .flatten()
            .filter(|edge| crate_roots.contains(&edge.importer) && edge.local_name == export_name)
            .filter_map(|edge| match &edge.kind {
                RustImportEdgeKind::Named(target_name) => {
                    Some((edge.target_file.clone(), target_name.clone()))
                }
                RustImportEdgeKind::Namespace
                | RustImportEdgeKind::Glob
                | RustImportEdgeKind::Qualified(_) => None,
            }),
    );
    targets
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

fn unique_seed_identity_for_fqn(
    rust: &dyn RustUsageSource,
    importer: &ProjectFile,
    byte: usize,
    seeds: &RustBindingSeeds,
    resolved_fqn: &str,
    dependency_roots: &[ProjectFile],
    namespace: RustReferenceNamespace,
) -> Option<RustSymbolIdentity> {
    let index = rust.usage_index();
    let importer_module = index.module_at_byte(importer, byte)?;
    let mut matches = seeds
        .identities
        .iter()
        .filter(|identity| {
            identity.fq_name() == resolved_fqn
                && identity.namespace.accepts(namespace)
                && seed_identity_admitted_at(
                    rust,
                    importer,
                    byte,
                    seeds,
                    identity,
                    dependency_roots,
                )
                && seeds.identity_domains.get(*identity).is_none_or(|domains| {
                    domains
                        .iter()
                        .any(|domain| domain.contains_module(importer_module))
                })
        })
        .flat_map(|identity| {
            seeds
                .canonical_identities
                .get(identity)
                .into_iter()
                .flatten()
                .cloned()
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.name.cmp(&right.name))
    });
    matches.dedup();
    (matches.len() == 1).then(|| matches.remove(0))
}

struct ScopedExplicitImport {
    targets: Vec<(ProjectFile, String)>,
    dependency_roots: Vec<ProjectFile>,
    fqn: Option<String>,
}

fn scoped_explicit_import(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    byte: usize,
    name: &str,
) -> Option<ScopedExplicitImport> {
    let syntax = rust.prepared_syntax(file)?;
    // The prepared tree is already in hand; deriving the binders from its
    // source text instead would parse the same file a second time.
    for (scope_start, binder) in crate::lexical_scope::visible_import_binders_with_scopes_in_tree(
        syntax.tree().root_node(),
        syntax.source(),
        byte,
    ) {
        let Some(binding) = binder.bindings.get(name) else {
            continue;
        };
        let fqn = match binding.kind {
            ImportKind::Named => {
                let imported = binding.imported_name.as_deref().unwrap_or(name);
                resolve_rust_import_package_scoped(
                    rust,
                    file,
                    syntax.source(),
                    scope_start,
                    &binding.module_specifier,
                )
                .map(|package| format!("{package}.{imported}"))
            }
            ImportKind::Namespace => resolve_rust_import_package_scoped(
                rust,
                file,
                syntax.source(),
                scope_start,
                &binding.module_specifier,
            ),
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => continue,
        };
        let index = rust.usage_index();
        let importer_module = index.module_at_byte(file, byte)?;
        let segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
        let dependency_roots = index
            .module_aliases
            .resolve_segments(
                &index.module_files,
                file,
                &importer_module.package(),
                &segments,
            )
            .into_iter()
            .filter(|route| route.provenance == RustRouteProvenance::Dependency)
            .map(|route| route.target_file)
            .collect();
        return Some(ScopedExplicitImport {
            targets: resolve_imported_export_from_binder_forward(rust, file, &binder, name),
            dependency_roots,
            fqn,
        });
    }
    None
}

fn unique_seed_identity_for_import_targets(
    rust: &dyn RustUsageSource,
    importer: &ProjectFile,
    seeds: &RustBindingSeeds,
    targets: &[(ProjectFile, String)],
    dependency_roots: &[ProjectFile],
    namespace: RustReferenceNamespace,
    byte: usize,
) -> Option<RustSymbolIdentity> {
    let index = rust.usage_index();
    let importer_module = index.module_at_byte(importer, byte)?;
    let mut matches = seeds
        .identities
        .iter()
        .filter(|identity| {
            identity.namespace.accepts(namespace)
                && seed_identity_admitted_at(
                    rust,
                    importer,
                    byte,
                    seeds,
                    identity,
                    dependency_roots,
                )
                && seeds.identity_domains.get(*identity).is_none_or(|domains| {
                    domains
                        .iter()
                        .any(|domain| domain.contains_module(importer_module))
                })
                && targets
                    .iter()
                    .any(|(file, name)| identity.file == *file && identity.name == *name)
        })
        .flat_map(|identity| {
            seeds
                .canonical_identities
                .get(identity)
                .into_iter()
                .flatten()
                .cloned()
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.name.cmp(&right.name))
    });
    matches.dedup();
    (matches.len() == 1).then(|| matches.remove(0))
}

fn seed_identity_admitted_at(
    rust: &dyn RustUsageSource,
    importer: &ProjectFile,
    byte: usize,
    seeds: &RustBindingSeeds,
    identity: &RustSymbolIdentity,
    dependency_roots: &[ProjectFile],
) -> bool {
    if seeds
        .canonical_identities
        .get(identity)
        .is_some_and(|origins| origins.iter().any(|origin| origin != identity))
    {
        // A propagated alias is already backed by an exact structured import
        // edge. It may legitimately cross Cargo targets, as facade re-exports
        // do, while its domain still controls visibility at the use site.
        return true;
    }

    let index = rust.usage_index();
    if dependency_roots.iter().any(|root| {
        index.physical_owners.intersects(root, &identity.file)
            || index
                .module_files
                .cargo_routes
                .target_relation(root, &identity.file)
                == RustCargoTargetRelation::Shared
    }) {
        return true;
    }

    seeds.root_identities.iter().any(|(root, identities)| {
        identities.contains(identity)
            && index.declaration_visible_at(rust, root, importer, byte)
            && (index.physical_owners.intersects(importer, &identity.file)
                || index
                    .module_files
                    .cargo_routes
                    .target_relation(importer, &identity.file)
                    == RustCargoTargetRelation::Shared
                || rust
                    .cargo_routes()
                    .files_share_target(importer, &identity.file)
                    == Some(true))
    })
}

fn imported_identity_domain(
    target: &RustSymbolIdentity,
    target_domain: &Domain,
    edge: &RustImportEdge,
) -> Option<Domain> {
    if target.namespace == RustSymbolNamespace::Macro
        && target.file == edge.importer
        && target.module == edge.importer_module
        && matches!(target_domain, Domain::Module(module) if module == &target.module)
        && matches!(edge.kind, RustImportEdgeKind::Named(_))
    {
        // A module commonly gives a local `macro_rules!` definition a stable
        // path with `pub use name;`. That declaration creates a new
        // macro-namespace binding in the owning module, so its visibility is
        // the import's visibility rather than the definition's lexical extent.
        // Rust does not permit a private macro to become externally public;
        // retain crate scope when the syntax says plain `pub use`.
        return Some(match &edge.domain {
            Domain::Public => Domain::Crate(target.module.crate_root.clone()),
            domain => domain.clone(),
        });
    }
    target_domain.intersect(&edge.domain)
}

fn build_origin_routes(
    importer_reverse: &HashMap<ProjectFile, Vec<RustImportEdge>>,
    declaration_domains: &HashMap<RustSymbolIdentity, Vec<Domain>>,
    module_domains: &HashMap<ModuleKey, Vec<Domain>>,
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<ProjectFile, HashMap<String, Vec<RustOriginRoute>>>> {
    type ExactKey = (ProjectFile, ModuleKey, String);
    type ModuleEdgeKey = (ProjectFile, ModuleKey);
    let mut exact_edges: HashMap<ExactKey, Vec<&RustImportEdge>> = HashMap::default();
    let mut module_edges: HashMap<ModuleEdgeKey, Vec<&RustImportEdge>> = HashMap::default();
    for edges in importer_reverse.values() {
        keep_going().then_some(())?;
        for edge in edges {
            keep_going().then_some(())?;
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
        keep_going().then_some(())?;
        pending.extend(
            domains
                .iter()
                .cloned()
                .map(|domain| (identity.clone(), identity.clone(), domain)),
        );
    }
    let mut visited = HashSet::default();
    let mut routes: HashMap<ProjectFile, HashMap<String, Vec<RustOriginRoute>>> =
        HashMap::default();
    while let Some((target, origin, domain)) = pending.pop_front() {
        keep_going().then_some(())?;
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
            keep_going().then_some(())?;
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
            let Some(effective_domain) = imported_identity_domain(&target, &domain, edge) else {
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
            let first_segment = path
                .first()
                .expect("origin routes always have a non-empty path")
                .clone();
            routes
                .entry(edge.importer.clone())
                .or_default()
                .entry(first_segment)
                .or_default()
                .push(RustOriginRoute {
                    importer_module: edge.importer_module.clone(),
                    extent: edge.extent.clone(),
                    path,
                    namespace: target.namespace,
                    origin: origin.clone(),
                    domain: effective_domain.clone(),
                    provenance: edge.provenance,
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
    Some(routes)
}

fn build_module_alias_routes(
    module_files: &RustModuleFiles,
    files: &[ProjectFile],
    imports_by_file: &HashMap<ProjectFile, Vec<RustProjectedImport>>,
    keep_going: &impl Fn() -> bool,
) -> Option<RustModuleAliasRoutes> {
    let mut routes = RustModuleAliasRoutes::default();
    let import_count = imports_by_file.values().map(Vec::len).sum::<usize>();
    for _ in 0..=import_count {
        keep_going().then_some(())?;
        let mut changed = false;
        for file in files {
            keep_going().then_some(())?;
            let Some(imports) = imports_by_file.get(file) else {
                continue;
            };
            for projected in imports {
                keep_going().then_some(())?;
                let RustImportOwner::Module { module: owner, .. } = &projected.owner else {
                    continue;
                };
                let import = &projected.import;
                let Some(domain) =
                    direct_import_scope_for_module(file, owner, import.visibility.clone())
                else {
                    continue;
                };
                if import.info.is_wildcard {
                    let imported_modules =
                        routes.resolve_segments(module_files, file, owner, &import.path);
                    let mut inherited = Vec::new();
                    for imported in &imported_modules {
                        keep_going().then_some(())?;
                        for (alias, aliases) in &routes.by_alias {
                            keep_going().then_some(())?;
                            if alias.parent().as_ref() != Some(&imported.target_module) {
                                continue;
                            }
                            let Some(local_name) = alias.components.last() else {
                                continue;
                            };
                            for route in aliases.iter().filter(|route| {
                                route.domain.contains_module(&imported.target_module)
                            }) {
                                keep_going().then_some(())?;
                                let Some(effective_domain) = route.domain.intersect(&domain) else {
                                    continue;
                                };
                                inherited.push((
                                    local_name.clone(),
                                    RustModuleAliasRoute {
                                        target_file: route.target_file.clone(),
                                        target_module: route.target_module.clone(),
                                        domain: effective_domain,
                                        provenance: route.provenance,
                                    },
                                ));
                            }
                        }
                    }
                    let owner = ModuleKey::new(file, owner);
                    for (local_name, route) in inherited {
                        keep_going().then_some(())?;
                        let alias = owner.with_suffix(&[local_name]);
                        let entries = routes.by_alias.entry(alias).or_default();
                        if !entries.contains(&route) {
                            entries.push(route);
                            changed = true;
                        }
                    }
                    continue;
                }
                let Some(local_name) = import.info.local_name() else {
                    continue;
                };
                let alias_package = if owner.is_empty() {
                    local_name.to_string()
                } else {
                    format!("{owner}.{local_name}")
                };
                let alias = ModuleKey::new(file, &alias_package);
                for resolved in routes.resolve_segments(module_files, file, owner, &import.path) {
                    keep_going().then_some(())?;
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
    Some(routes)
}

fn build_importer_reverse(
    module_files: &RustModuleFiles,
    module_aliases: &RustModuleAliasRoutes,
    physical_owners: &RustPhysicalOwnerIndex,
    files: &[ProjectFile],
    imports_by_file: &HashMap<ProjectFile, Vec<RustProjectedImport>>,
    parallel: bool,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<HashMap<ProjectFile, Vec<RustImportEdge>>> {
    // Per-file edge production only reads the shared route indices; collect in
    // file order so the merged reverse map matches a serial walk. `parallel`
    // is false when building from inside a rayon worker (see `usage_index()`).
    let per_file_edges = |file: &ProjectFile| {
        keep_going().then_some(())?;
        let mut edges: Vec<RustImportEdge> = Vec::new();
        let Some(imports) = imports_by_file.get(file) else {
            return Some(edges);
        };
        for projected in imports {
            keep_going().then_some(())?;
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
            let local_name = import.info.local_name().unwrap_or_default().to_string();
            if import.info.is_wildcard {
                for resolved in
                    module_aliases.resolve_segments(module_files, file, &owner, &import.path)
                {
                    keep_going().then_some(())?;
                    add_import_edge(
                        &mut edges,
                        module_files,
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
                keep_going().then_some(())?;
                add_import_edge(
                    &mut edges,
                    module_files,
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
                keep_going().then_some(())?;
                add_import_edge(
                    &mut edges,
                    module_files,
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
        Some(edges)
    };
    let per_file_edges: Vec<Vec<RustImportEdge>> = if parallel {
        files
            .par_iter()
            .map(per_file_edges)
            .collect::<Option<Vec<_>>>()
    } else {
        files.iter().map(per_file_edges).collect::<Option<Vec<_>>>()
    }?;
    let mut reverse: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
    for edge in per_file_edges.into_iter().flatten() {
        keep_going().then_some(())?;
        reverse
            .entry(edge.target_file.clone())
            .or_default()
            .push(edge);
    }
    Some(reverse)
}

fn add_import_edge(
    edges: &mut Vec<RustImportEdge>,
    module_files: &RustModuleFiles,
    physical_owners: &RustPhysicalOwnerIndex,
    edge: RustImportEdge,
) {
    let cross_file = edge.target_file != edge.importer;
    let owners_intersect = physical_owners.intersects(&edge.importer, &edge.target_file)
        || (module_files
            .cargo_routes
            .target_relation(&edge.importer, &edge.target_file)
            == RustCargoTargetRelation::Shared
            && edge_target_matches_exact_module(&edge));
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
    edges.push(edge);
}

fn edge_target_matches_exact_module(edge: &RustImportEdge) -> bool {
    ModuleKey::new(&edge.target_file, &rust_package_name(&edge.target_file)) == edge.target_module
}

#[cfg(test)]
mod tests {
    use super::*;

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
