//! The Rust usage vocabulary and the analyzer's usage entry points.
//!
//! Three things live here. The shared value types every usage answer is
//! phrased in -- module keys, visibility domains, symbol identities, import
//! edges and the route shapes -- which the store reader, the walks and the
//! graph scan all speak. The seed and reference capabilities on
//! [`RustUsageWalks`], which compose those walks into the answers
//! `scan_usages` and `usage_graph` ask for. And the `RustAnalyzer` methods
//! that are the outside world's way in.
//!
//! Until ExecPlan Milestone 5 (`.agents/plans/rust-usage-index-v2.md`) this
//! file also held a workspace-wide index of seventeen maps that every one of
//! those answers was read out of. There is no index any more: the per-file
//! facts are rows in the store (`facts.rs`, read by `usage_queries.rs`) and
//! the cross-file composition is a memoized walk (`usage_walks.rs`), so
//! nothing workspace-sized is built or retained.

use crate::analyzer::usages::{ExportEntry, ImportKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use tree_sitter::Node;

use super::RustAnalyzer;
use super::cargo_routes::{RustCargoRouteKind, RustCargoTargetRelation};
use super::declarations::rust_package_name;
use super::imports::{
    RustVisibility, resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package,
};
use super::usage_queries::RustUsageQueries;
use super::usage_walks::RustUsageWalks;

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
    pub(super) importer_module: ModuleKey,
    pub(super) extent: RustImportExtent,
    pub(super) local_name: String,
    pub(super) target_file: ProjectFile,
    pub(super) target_module: ModuleKey,
    pub(super) kind: RustImportEdgeKind,
    pub(super) propagate_alias: bool,
    pub(super) domain: Domain,
    pub(super) namespace: Option<RustSymbolNamespace>,
    pub(super) provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum RustRouteProvenance {
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
    pub(super) fn of(analyzer: &RustAnalyzer, declaration: &CodeUnit) -> Option<Self> {
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
    pub(super) file: ProjectFile,
    pub(super) module: ModuleKey,
    pub(super) name: String,
    pub(super) namespace: RustSymbolNamespace,
}

impl RustSymbolIdentity {
    pub(crate) fn name(&self) -> &str {
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
pub(super) enum RustImportExtent {
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
    pub(super) fn contains(&self, byte: usize) -> bool {
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
pub(super) struct ModuleKey {
    pub(super) crate_root: String,
    pub(super) components: Vec<String>,
}

impl ModuleKey {
    pub(super) fn new(file: &ProjectFile, module: &str) -> Self {
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

    pub(super) fn contains(&self, candidate: &Self) -> bool {
        self.crate_root == candidate.crate_root
            && candidate.components.starts_with(&self.components)
    }

    /// Heap bytes this key owns, for the memo cache's byte budget.
    pub(super) fn weight_bytes(&self) -> usize {
        self.crate_root.len()
            + self
                .components
                .iter()
                .map(|component| component.len() + std::mem::size_of::<String>())
                .sum::<usize>()
            + std::mem::size_of::<Self>()
    }

    pub(super) fn parent(&self) -> Option<Self> {
        let mut components = self.components.clone();
        components.pop()?;
        Some(Self {
            crate_root: self.crate_root.clone(),
            components,
        })
    }

    pub(super) fn with_suffix(&self, suffix: &[String]) -> Self {
        let mut components = Vec::with_capacity(self.components.len() + suffix.len());
        components.extend(self.components.iter().cloned());
        components.extend(suffix.iter().cloned());
        Self {
            crate_root: self.crate_root.clone(),
            components,
        }
    }

    pub(super) fn package(&self) -> String {
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
pub(super) enum Domain {
    Public,
    Crate(String),
    Module(ModuleKey),
}

impl Domain {
    /// Heap bytes this domain owns, for the memo cache's byte budget.
    pub(super) fn weight_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Public => 0,
                Self::Crate(crate_root) => crate_root.len(),
                Self::Module(module) => module.weight_bytes(),
            }
    }

    pub(super) fn contains_module(&self, importer: &ModuleKey) -> bool {
        match self {
            Self::Public => true,
            Self::Crate(crate_package) => importer.crate_root == *crate_package,
            Self::Module(module) => module.contains(importer),
        }
    }

    pub(super) fn intersect(&self, other: &Self) -> Option<Self> {
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
    root_identities: HashMap<CodeUnit, Vec<RustSymbolIdentity>>,
    canonical_identities: HashMap<RustSymbolIdentity, HashSet<RustSymbolIdentity>>,
    identities: HashSet<RustSymbolIdentity>,
    identity_domains: HashMap<RustSymbolIdentity, Vec<Domain>>,
    edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>>,
}

#[derive(Debug, Clone)]
pub(super) struct RustOriginRoute {
    pub(super) importer_module: ModuleKey,
    pub(super) extent: RustImportExtent,
    pub(super) path: Vec<String>,
    pub(super) namespace: RustSymbolNamespace,
    pub(super) origin: RustSymbolIdentity,
    pub(super) domain: Domain,
    pub(super) provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct RustMacroScopeKey {
    pub(super) file: ProjectFile,
    pub(super) module: ModuleKey,
}

#[derive(Debug, Clone)]
pub(super) struct RustMacroScopeEdge {
    pub(super) parent: RustMacroScopeKey,
    pub(super) child: RustMacroScopeKey,
    pub(super) declaration_start: usize,
    pub(super) visibility_start: usize,
    pub(super) imports_macros: bool,
}

/// One macro's visible byte ranges per scope, the lazy form's answer shape.
pub(super) type RustMacroScopeRanges = HashMap<RustMacroScopeKey, Vec<(usize, usize)>>;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RustModuleAliasRoute {
    pub(super) target_file: ProjectFile,
    pub(super) target_module: ModuleKey,
    pub(super) domain: Domain,
    pub(super) provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RustResolvedModuleRoute {
    pub(super) target_file: ProjectFile,
    pub(super) target_module: ModuleKey,
    pub(super) provenance: RustRouteProvenance,
}

pub(super) fn rust_mod_item_has_macro_use(module: Node<'_>, source: &str) -> bool {
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

impl From<RustCargoRouteKind> for RustRouteProvenance {
    fn from(kind: RustCargoRouteKind) -> Self {
        match kind {
            RustCargoRouteKind::CurrentLibrary => Self::CurrentLibrary,
            RustCargoRouteKind::Dependency => Self::Dependency,
        }
    }
}

/// The seed and reference capabilities, answered from the lazy cross-file
/// walks.
///
/// Each method here was a probe into a workspace-wide map before ExecPlan
/// Milestone 2c; the control flow is deliberately unchanged from that form,
/// because the milestone's acceptance bar was byte-for-byte parity of the
/// answers rather than a better algorithm.
impl RustUsageWalks<'_> {
    fn exact_root_for_resolution(
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

    fn declaration_owner_visible_to(
        &self,
        analyzer: &RustAnalyzer,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
    ) -> bool {
        if identity.file != *caller_file
            && !self.owners_intersect(&identity.file, caller_file)
            && analyzer.files_share_cargo_target(&identity.file, caller_file) != Some(true)
        {
            return false;
        }
        self.effective_module_domains_of(&identity.module)
            .is_some_and(|domains| {
                domains
                    .iter()
                    .any(|domain| domain.contains_module(caller_module))
            })
            || self
                .physical_root_of(&identity.file)
                .is_some_and(|physical_root| {
                    identity.module == physical_root
                        && ((identity.file == *caller_file
                            && physical_root.contains(caller_module))
                            || (self.is_actual_crate_root(&identity.file)
                                && (self.owned_by(caller_file, &identity.file)
                                    || analyzer
                                        .files_share_cargo_target(&identity.file, caller_file)
                                        == Some(true))))
                })
    }

    fn resolved_declaration_visible_to(
        &self,
        analyzer: &RustAnalyzer,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
        provenance: RustRouteProvenance,
    ) -> bool {
        match provenance {
            RustRouteProvenance::Local => {
                self.declaration_owner_visible_to(analyzer, identity, caller_file, caller_module)
            }
            RustRouteProvenance::CurrentLibrary | RustRouteProvenance::Dependency => {
                self.physical_root_of(&identity.file)
                    .is_some_and(|root| root == identity.module)
                    || self
                        .effective_module_domains_of(&identity.module)
                        .is_some_and(|domains| domains.contains(&Domain::Public))
            }
        }
    }

    fn declaration_visible_at(
        &self,
        analyzer: &RustAnalyzer,
        declaration: &CodeUnit,
        caller_file: &ProjectFile,
        caller_byte: usize,
    ) -> bool {
        let Some(caller_module) = self.queries().module_at_byte(caller_file, caller_byte) else {
            return false;
        };
        let caller_module = &caller_module;
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
            || self.owners_intersect(declaration.source(), caller_file)
            || analyzer.files_share_cargo_target(declaration.source(), caller_file) == Some(true))
            && domain.contains_module(caller_module)
    }

    /// Files that import one of the `seeds` (plus the seed files themselves).
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
        let mut target_modules = HashSet::default();
        for root in &seeds.roots {
            keep_going().then_some(())?;
            if let Some(identity) = self
                .identity_of(root)
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
            for importer in self.importers_of_module(&module) {
                keep_going().then_some(())?;
                out.insert(importer);
            }
        }
        for root in &seeds.roots {
            for file in self
                .cargo_routes()
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
            for scope in self.macro_visible_ranges_of(root).keys() {
                keep_going().then_some(())?;
                out.insert(scope.file.clone());
            }
        }
        Some(out)
    }

    fn matching_edges_for_importer<'seeds>(
        &self,
        importer: &ProjectFile,
        seeds: &'seeds RustBindingSeeds,
    ) -> impl Iterator<Item = &'seeds RustImportEdge> {
        seeds.edges_by_importer.get(importer).into_iter().flatten()
    }

    fn binding_seeds_while(
        &self,
        analyzer: &RustAnalyzer,
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
                .identity_of(root)
                .into_iter()
                .chain(self.value_constructor_identity_of(root))
                .collect::<Vec<_>>();
            if candidate_identities.is_empty() {
                candidate_identities.push(RustSymbolIdentity {
                    file: root.source().clone(),
                    module: ModuleKey::new(root.source(), root.package_name()),
                    name: root.identifier().to_string(),
                    namespace: RustSymbolNamespace::of(analyzer, root)
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
                if let Some(domains) = self.declared_domains_of(&identity) {
                    identity_domains
                        .entry(identity.clone())
                        .or_default()
                        .extend(domains.iter().cloned());
                    pending.extend(
                        domains
                            .into_iter()
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
            for edge in self.edges_binding_identity(&target) {
                keep_going().then_some(())?;
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
                    .effective_module_domains_of(&edge.target_module)
                    .is_some_and(|domains| {
                        !domains
                            .iter()
                            .any(|domain| domain.contains_module(&edge.importer_module))
                    })
                {
                    continue;
                }
                let Some(effective_domain) = imported_identity_domain(&target, &domain, &edge)
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

    fn export_targets_from_files(
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
            if !self.is_analyzed(&module_file) {
                continue;
            }
            let index = analyzer.export_index_of(&module_file);

            for star in index.reexport_stars.iter().rev() {
                let files = self.resolve(&module_file, &star.module_specifier);
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
                        let files = self.resolve(&module_file, module_specifier);
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

pub(super) fn direct_import_scope_for_module(
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
    /// Build every per-file reference context now, so an interactive usage
    /// query does not spend most of a warm scan constructing them one file at
    /// a time.
    ///
    /// Separate from [`RustAnalyzer::warm_usage_facts`]: this is a
    /// whole-workspace fan-out over every Rust file, which a large C++
    /// workspace with a vendored Rust tree pays for work it never queries, so
    /// sessions can leave it out (d8920a38). The fact catch-up always runs.
    pub fn warm_usage_reference_contexts(&self) {
        let _scope = crate::profiling::scope("RustAnalyzer::warm_usage_reference_contexts");
        let files: Vec<ProjectFile> = self.get_analyzed_files().into_iter().collect();
        files.par_iter().for_each(|file| {
            self.reference_context_of(file);
        });
    }

    /// Candidate files: those importing a seed, plus the seed files themselves.
    pub(crate) fn usage_importers(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        RustUsageWalks::new(self)
            .importers_of_seeds_while(seeds, &|| true)
            .expect("uninterrupted Rust importer selection")
    }

    pub(crate) fn usage_candidate_files_while(
        &self,
        roots: &BTreeSet<CodeUnit>,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<HashSet<ProjectFile>> {
        let walks = RustUsageWalks::new_while(self, keep_going)?;
        keep_going().then_some(())?;
        let seeds = walks.binding_seeds_while(self, roots, keep_going)?;
        keep_going().then_some(())?;
        walks.importers_of_seeds_while(&seeds, keep_going)
    }

    pub(crate) fn usage_binding_seeds_while(
        &self,
        roots: &BTreeSet<CodeUnit>,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<RustBindingSeeds> {
        let walks = RustUsageWalks::new_while(self, keep_going)?;
        keep_going().then_some(())?;
        walks.binding_seeds_while(self, roots, keep_going)
    }

    /// Canonical local binding identities for a target, including named private
    /// imports that can be imported again by descendant modules.
    pub(crate) fn usage_binding_seeds(&self, roots: &BTreeSet<CodeUnit>) -> RustBindingSeeds {
        RustUsageWalks::new(self)
            .binding_seeds_while(self, roots, &|| true)
            .expect("uninterrupted Rust binding-seed construction")
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
        let walks = RustUsageWalks::new(self);
        for edge in walks.matching_edges_for_importer(file, seeds) {
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
            if walks
                .macro_visible_ranges_of(root)
                .keys()
                .any(|scope| &scope.file == file)
            {
                direct.insert(root.identifier().to_string());
            }
        }
        (direct, qualified)
    }

    pub(crate) fn usage_has_exact_scoped_binding(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        name: &str,
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        scoped_explicit_import(self, file, byte, name).is_some_and(|scoped| {
            unique_seed_identity_for_import_targets(
                self,
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
                        self,
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
    pub(crate) fn usage_binding_local_names(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
    ) -> HashSet<String> {
        RustUsageWalks::new(self)
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
        let walks = RustUsageWalks::new(self);
        let Some(module) = walks.queries().module_at_byte(file, byte) else {
            return false;
        };
        let module = &module;
        seeds.roots.iter().any(|root| {
            walks.identity_of(root).is_some_and(|identity| {
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
        RustUsageWalks::new(self).declaration_visible_at(self, declaration, file, byte)
    }

    pub(crate) fn usage_exact_root_for_resolution(
        &self,
        resolution: &RustReferenceResolution,
        seeds: &RustBindingSeeds,
    ) -> Option<CodeUnit> {
        RustUsageWalks::new(self).exact_root_for_resolution(resolution, seeds)
    }

    pub(crate) fn usage_local_module_prefix_visible_at(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        name: &str,
        byte: usize,
    ) -> bool {
        let walks = RustUsageWalks::new(self);
        let Some(module) = walks.queries().module_at_byte(file, byte) else {
            return false;
        };
        let module = &module;
        if walks.matching_edges_for_importer(file, seeds).any(|edge| {
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
        if !walks
            .declared_domains_of(&module_identity)
            .is_some_and(|domains| domains.iter().any(|domain| domain.contains_module(module)))
        {
            return false;
        }

        let prefix = [name.to_string()];
        if walks
            .resolve_segments(file, &module.package(), &prefix)
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
                        || walks.owners_intersect(&route.target_file, &identity.file)
                        || self.files_share_cargo_target(&route.target_file, &identity.file)
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
                && seeds.identity_domains.get(identity).is_some_and(|domains| {
                    domains.iter().any(|domain| domain.contains_module(module))
                })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn usage_reference_at(
        &self,
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
        let walks = RustUsageWalks::new(self);
        let queries = RustUsageQueries::new(self);
        let Some(module) = queries.module_at_byte(file, byte) else {
            return RustReferenceResolution::Unresolved;
        };
        let module = &module;
        let leading_absolute_local =
            leading_absolute && walks.cargo_routes().file_uses_rust_2015_edition(file);
        let absolute_route_admitted = |provenance| {
            !leading_absolute
                || matches!(
                    provenance,
                    RustRouteProvenance::CurrentLibrary | RustRouteProvenance::Dependency
                )
                || (leading_absolute_local && provenance == RustRouteProvenance::Local)
        };
        let file_origin_routes = walks.origin_routes_of(file);
        let mut matches: HashSet<RustSymbolIdentity> = file_origin_routes
            .get(segments[0])
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
            let visible_macros = walks
                .macro_declarations_named(segments[0])
                .into_iter()
                .filter(|declaration| {
                    walks
                        .macro_visible_ranges_of(declaration)
                        .get(&scope)
                        .is_some_and(|ranges| {
                            ranges
                                .iter()
                                .any(|(start, end)| *start <= byte && byte < *end)
                        })
                })
                .collect::<Vec<_>>();
            if !visible_macros.is_empty() {
                matches.clear();
                matches.extend(
                    visible_macros
                        .into_iter()
                        .filter(|declaration| seeds.roots.contains(declaration))
                        .filter_map(|declaration| walks.identity_of(&declaration)),
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
            for route in walks.resolve_segments(file, &module.package(), &owned_segments) {
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
                            let Some(declared_domains) = walks.declared_domains_of(identity) else {
                                return false;
                            };
                            let domains = seeds
                                .identity_domains
                                .get(*identity)
                                .unwrap_or(&declared_domains);
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
            // The old lookup was by name across the workspace and then
            // filtered to this file. Asking the file directly is the same
            // question with the filter applied first (ExecPlan Milestone 2b).
            matches.extend(
                queries
                    .identities_in_file_named(file, segments[0])
                    .into_iter()
                    .filter(|(identity, declared_domains)| {
                        let domains = seeds
                            .identity_domains
                            .get(identity)
                            .unwrap_or(declared_domains);
                        identity.module == *module
                            && identity.namespace.accepts(namespace)
                            && domains.iter().any(|domain| domain.contains_module(module))
                            && walks.declaration_owner_visible_to(self, identity, file, module)
                    })
                    .map(|(identity, _)| identity),
            );
            if matches.is_empty() {
                let scoped_import = scoped_explicit_import(self, file, byte, segments[0]);
                let identity = match scoped_import {
                    Some(scoped) => unique_seed_identity_for_import_targets(
                        self,
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
                                self,
                                file,
                                byte,
                                seeds,
                                fqn,
                                &scoped.dependency_roots,
                                namespace,
                            )
                        })
                    }),
                    None if file_origin_routes
                        .get(segments[0])
                        .is_some_and(|routes| !routes.is_empty()) =>
                    {
                        // A structured import for this name exists, but none
                        // is visible at this byte. The file-wide reference
                        // context cannot restore a function-local import
                        // outside its lexical extent.
                        None
                    }
                    None => self
                        .reference_context_of(file)
                        .resolve_bare(segments[0])
                        .and_then(|resolved_fqn| {
                            unique_seed_identity_for_fqn(
                                self,
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
            for resolved in walks.resolve_segments(file, &package, &owned_prefix) {
                if !absolute_route_admitted(resolved.provenance) {
                    continue;
                }
                matches.extend(
                    queries
                        .identities_in_file_named(&resolved.target_file, terminal)
                        .into_iter()
                        .filter(|(identity, domains)| {
                            identity.module == resolved.target_module
                                && identity.namespace.accepts(namespace)
                                && domains.iter().any(|domain| domain.contains_module(module))
                                && walks.resolved_declaration_visible_to(
                                    self,
                                    identity,
                                    file,
                                    module,
                                    resolved.provenance,
                                )
                        })
                        .map(|(identity, _)| identity),
                );
                let target_origin_routes = walks.origin_routes_of(&resolved.target_file);
                matches.extend(
                    target_origin_routes
                        .get(terminal)
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
                let mut crate_packages = walks
                    .cargo_routes()
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
            // The one site that genuinely searches by name: the module is
            // resolved but the file that declares the terminal is not known.
            // `identities_named` answers it with the store's indexed short-name
            // lookup plus per-candidate verification (ExecPlan Milestone 2b).
            let named_terminals = if resolved_modules.is_empty() {
                Vec::new()
            } else {
                queries.identities_named(terminal)
            };
            for resolved in resolved_modules {
                matches.extend(
                    named_terminals
                        .iter()
                        .filter(|(identity, declared_domains)| {
                            let domains = seeds
                                .identity_domains
                                .get(identity)
                                .unwrap_or(declared_domains);
                            identity.module == resolved
                                && identity.namespace.accepts(namespace)
                                && domains.iter().any(|domain| domain.contains_module(module))
                                && walks.declaration_owner_visible_to(self, identity, file, module)
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
        RustUsageWalks::new(self).export_targets_from_files(self, module_files, export_name)
    }

    pub(crate) fn usage_crate_export_targets(
        &self,
        file: &ProjectFile,
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let walks = RustUsageWalks::new(self);
        let mut crate_roots = walks
            .owner_roots_of(file)
            .iter()
            .filter(|root| walks.is_actual_crate_root(root))
            .cloned()
            .collect::<Vec<_>>();
        if walks.is_actual_crate_root(file) {
            crate_roots.push(file.clone());
        }
        crate_roots.sort();
        crate_roots.dedup();
        let mut targets = walks.export_targets_from_files(self, &crate_roots, export_name);
        // The v1 index scanned every import edge in the workspace for one
        // whose importer is a crate root. Edges are produced per importer, so
        // asking each crate root for its own forward edges is the same set.
        targets.extend(
            crate_roots
                .iter()
                .flat_map(|root| walks.forward_import_edges_of(root).as_ref().clone())
                .filter(|edge| edge.local_name == export_name)
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
}

pub(super) fn edge_matches_single_seed(edge: &RustImportEdge, target: &RustSymbolIdentity) -> bool {
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
    analyzer: &RustAnalyzer,
    importer: &ProjectFile,
    byte: usize,
    seeds: &RustBindingSeeds,
    resolved_fqn: &str,
    dependency_roots: &[ProjectFile],
    namespace: RustReferenceNamespace,
) -> Option<RustSymbolIdentity> {
    let importer_module = RustUsageQueries::new(analyzer).module_at_byte(importer, byte)?;
    let importer_module = &importer_module;
    let mut matches = seeds
        .identities
        .iter()
        .filter(|identity| {
            identity.fq_name() == resolved_fqn
                && identity.namespace.accepts(namespace)
                && seed_identity_admitted_at(
                    analyzer,
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
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    byte: usize,
    name: &str,
) -> Option<ScopedExplicitImport> {
    let syntax = analyzer.prepared_syntax(file)?;
    // The prepared tree is already in hand; deriving the binders from its
    // source text instead would parse the same file a second time.
    for (scope_start, binder) in super::lexical_scope::visible_import_binders_with_scopes_in_tree(
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
                    analyzer,
                    file,
                    syntax.source(),
                    scope_start,
                    &binding.module_specifier,
                )
                .map(|package| format!("{package}.{imported}"))
            }
            ImportKind::Namespace => resolve_rust_import_package_scoped(
                analyzer,
                file,
                syntax.source(),
                scope_start,
                &binding.module_specifier,
            ),
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => continue,
        };
        let walks = RustUsageWalks::new(analyzer);
        let importer_module = walks.queries().module_at_byte(file, byte)?;
        let importer_module = &importer_module;
        let segments = crate::analyzer::symbol_lookup::parse_symbol_path(
            crate::analyzer::Language::Rust,
            &binding.module_specifier,
        );
        let dependency_roots = walks
            .resolve_segments(file, &importer_module.package(), &segments)
            .into_iter()
            .filter(|route| route.provenance == RustRouteProvenance::Dependency)
            .map(|route| route.target_file)
            .collect();
        return Some(ScopedExplicitImport {
            targets: analyzer.resolve_imported_export_from_binder_forward(file, &binder, name),
            dependency_roots,
            fqn,
        });
    }
    None
}

fn unique_seed_identity_for_import_targets(
    analyzer: &RustAnalyzer,
    importer: &ProjectFile,
    seeds: &RustBindingSeeds,
    targets: &[(ProjectFile, String)],
    dependency_roots: &[ProjectFile],
    namespace: RustReferenceNamespace,
    byte: usize,
) -> Option<RustSymbolIdentity> {
    let importer_module = RustUsageQueries::new(analyzer).module_at_byte(importer, byte)?;
    let importer_module = &importer_module;
    let mut matches = seeds
        .identities
        .iter()
        .filter(|identity| {
            identity.namespace.accepts(namespace)
                && seed_identity_admitted_at(
                    analyzer,
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
    analyzer: &RustAnalyzer,
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

    let walks = RustUsageWalks::new(analyzer);
    if dependency_roots.iter().any(|root| {
        walks.owners_intersect(root, &identity.file)
            || walks.cargo_routes().target_relation(root, &identity.file)
                == RustCargoTargetRelation::Shared
    }) {
        return true;
    }

    seeds.root_identities.iter().any(|(root, identities)| {
        identities.contains(identity)
            && walks.declaration_visible_at(analyzer, root, importer, byte)
            && (walks.owners_intersect(importer, &identity.file)
                || walks
                    .cargo_routes()
                    .target_relation(importer, &identity.file)
                    == RustCargoTargetRelation::Shared
                || analyzer.files_share_cargo_target(importer, &identity.file) == Some(true))
    })
}

pub(super) fn imported_identity_domain(
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
        // path with `pub(crate) use name;`. That declaration creates a new
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

pub(super) fn edge_target_matches_exact_module(edge: &RustImportEdge) -> bool {
    ModuleKey::new(&edge.target_file, &rust_package_name(&edge.target_file)) == edge.target_module
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitType, Language, ProjectFile, TestProject};

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
    fn fallback_binding_identity_remains_an_exact_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let source = ProjectFile::new(root, "src/db.rs");
        let target = CodeUnit::new(
            source.clone(),
            CodeUnitType::Function,
            "crate.src.db",
            "get_connection",
        );
        let roots = BTreeSet::from([target.clone()]);
        let walks = RustUsageWalks::new(&analyzer);
        let seeds = walks
            .binding_seeds_while(&analyzer, &roots, &|| true)
            .expect("an uncancelled walk answers");
        let resolution = RustReferenceResolution::Exact(RustSymbolIdentity {
            file: source,
            module: ModuleKey::new(target.source(), target.package_name()),
            name: target.identifier().to_string(),
            namespace: RustSymbolNamespace::Value,
        });

        assert_eq!(
            walks.exact_root_for_resolution(&resolution, &seeds),
            Some(target)
        );
    }

    fn analyzer_for(root: &std::path::Path) -> RustAnalyzer {
        RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    /// The store-backed name lookup must offer every declaring file for a
    /// shared short name, with each identity's own visibility domain.
    ///
    /// The v1 index answered this from `identities_by_name`, a map over every
    /// declaration in the workspace. Its replacement asks the store's indexed
    /// short-name lookup for candidate files and verifies each against that
    /// file's own declaration facts, so what this pins is that the candidate
    /// set misses no file and that verification drops no identity. The
    /// associated function `Shared::helper` is the false positive the
    /// verification exists to reject: it carries the right short name and no
    /// module-scope identity.
    #[test]
    fn identities_named_covers_every_declaring_file_for_a_shared_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write(
                "pub mod worker;\n\
                 pub mod util;\n\
                 pub struct Shared;\n\
                 pub fn helper() {}\n",
            )
            .expect("write lib.rs");
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write(
                "pub struct Shared(pub u8);\n\
                 impl Shared {\n    \
                     pub fn helper(&self) {}\n\
                 }\n",
            )
            .expect("write worker.rs");
        ProjectFile::new(root.clone(), "src/util.rs")
            .write(
                "fn helper() {}\n\
                 mod inner {\n    \
                     pub(crate) struct Shared;\n\
                 }\n",
            )
            .expect("write util.rs");
        let analyzer = analyzer_for(&root);
        let queries = RustUsageQueries::new(&analyzer);

        let mut rendered: Vec<String> = ["Shared", "helper", "worker", "util", "inner"]
            .into_iter()
            .flat_map(|name| queries.identities_named(name))
            .map(|(identity, domains)| render_identity(&identity, &domains))
            .collect();
        rendered.sort();

        assert_eq!(
            rendered,
            vec![
                "src/lib.rs crate Shared Type = [Public]",
                "src/lib.rs crate Shared Value = [Public]",
                "src/lib.rs crate helper Value = [Public]",
                "src/lib.rs crate util Module = [Public]",
                "src/lib.rs crate worker Module = [Public]",
                "src/util.rs crate::util helper Value = [Module(crate::util)]",
                "src/util.rs crate::util inner Module = [Module(crate::util)]",
                "src/util.rs crate::util::inner Shared Type = [Crate]",
                "src/util.rs crate::util::inner Shared Value = [Crate]",
                "src/worker.rs crate::worker Shared Type = [Public]",
                "src/worker.rs crate::worker Shared Value = [Public]",
            ]
        );
    }

    /// Path-independent rendering of one identity and its domains: the fixture
    /// lives under a temporary root, so neither the absolute path nor the
    /// crate-root package name may reach an assertion. Every identity here is
    /// in the one crate, so the crate root renders as the literal `crate`.
    fn render_identity(identity: &RustSymbolIdentity, domains: &[Domain]) -> String {
        let render_module = |module: &ModuleKey| {
            std::iter::once("crate")
                .chain(module.components.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("::")
        };
        let render_domain = |domain: &Domain| match domain {
            Domain::Public => "Public".to_string(),
            Domain::Crate(_) => "Crate".to_string(),
            Domain::Module(module) => format!("Module({})", render_module(module)),
        };
        format!(
            "{} {} {} {:?} = [{}]",
            crate::path_utils::rel_path_string(&identity.file),
            render_module(&identity.module),
            identity.name,
            identity.namespace,
            domains
                .iter()
                .map(render_domain)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}
