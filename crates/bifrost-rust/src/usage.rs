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

use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};

use crate::graph_support::RustFactSource;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::{BTreeSet, VecDeque};
use tree_sitter::Node;

use crate::cargo_routes::{RustCargoRouteKind, RustCargoTargetRelation};
use crate::declarations::rust_package_name;
use crate::imports::{
    RustVisibility, resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package,
};
use crate::lexical_scope::{
    RustCfgCondition, lexical_package_at, local_type_item_name_shadowed_in_tree,
    visible_import_binders_with_scopes_in_tree,
};
use crate::usage_queries::RustUsageQueries;
use crate::usage_walks::RustUsageWalks;

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
    pub importer_module: ModuleKey,
    pub extent: RustImportExtent,
    pub local_name: String,
    pub target_file: ProjectFile,
    pub target_module: ModuleKey,
    pub kind: RustImportEdgeKind,
    pub propagate_alias: bool,
    pub domain: Domain,
    pub namespace: Option<RustSymbolNamespace>,
    pub provenance: RustRouteProvenance,
    /// The `#[cfg(...)]` predicate the `use` was written under, carried so that
    /// two alternatives of one binding are not read as an ambiguity (#1377).
    pub cfg_condition: RustCfgCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RustRouteProvenance {
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
    pub fn of(analyzer: &dyn RustFactSource, declaration: &CodeUnit) -> Option<Self> {
        if analyzer.is_type_alias(declaration) {
            return Some(Self::Type);
        }
        match declaration.kind() {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class => Some(Self::Type),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function
            | brokk_bifrost_core::analyzer::model::CodeUnitType::Field => Some(Self::Value),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Macro => Some(Self::Macro),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Module => Some(Self::Module),
            brokk_bifrost_core::analyzer::model::CodeUnitType::FileScope => None,
        }
    }

    pub fn accepts(self, reference: RustReferenceNamespace) -> bool {
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
pub enum RustImportExtent {
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
    pub fn contains(&self, byte: usize) -> bool {
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

    /// Whether the binding is confined to a function body, block, or closure.
    /// A visible local import shadows the enclosing module's own declaration of
    /// the same name, which is what makes it the answer rather than one of two.
    pub fn is_local_only(&self) -> bool {
        matches!(self, Self::LocalOnly { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleKey {
    pub crate_root: String,
    pub components: Vec<String>,
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

    pub fn contains(&self, candidate: &Self) -> bool {
        self.crate_root == candidate.crate_root
            && candidate.components.starts_with(&self.components)
    }

    /// Heap bytes this key owns, for the memo cache's byte budget.
    pub fn weight_bytes(&self) -> usize {
        self.crate_root.len()
            + self
                .components
                .iter()
                .map(|component| component.len() + std::mem::size_of::<String>())
                .sum::<usize>()
            + std::mem::size_of::<Self>()
    }

    pub fn parent(&self) -> Option<Self> {
        let mut components = self.components.clone();
        components.pop()?;
        Some(Self {
            crate_root: self.crate_root.clone(),
            components,
        })
    }

    pub fn with_suffix(&self, suffix: &[String]) -> Self {
        let mut components = Vec::with_capacity(self.components.len() + suffix.len());
        components.extend(self.components.iter().cloned());
        components.extend(suffix.iter().cloned());
        Self {
            crate_root: self.crate_root.clone(),
            components,
        }
    }

    pub fn package(&self) -> String {
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
    /// Heap bytes this domain owns, for the memo cache's byte budget.
    pub fn weight_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Public => 0,
                Self::Crate(crate_root) => crate_root.len(),
                Self::Module(module) => module.weight_bytes(),
            }
    }

    pub fn contains_module(&self, importer: &ModuleKey) -> bool {
        match self {
            Self::Public => true,
            Self::Crate(crate_package) => importer.crate_root == *crate_package,
            Self::Module(module) => module.contains(importer),
        }
    }

    pub fn intersect(&self, other: &Self) -> Option<Self> {
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
    pub importer_module: ModuleKey,
    pub extent: RustImportExtent,
    pub path: Vec<String>,
    /// Whether this route came from `use path::*`. Glob imports have lower
    /// name-resolution precedence than explicit imports and local items.
    pub is_glob_import: bool,
    pub namespace: RustSymbolNamespace,
    pub origin: RustSymbolIdentity,
    pub domain: Domain,
    pub provenance: RustRouteProvenance,
    pub cfg_condition: RustCfgCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RustMacroScopeKey {
    pub file: ProjectFile,
    pub module: ModuleKey,
}

#[derive(Debug, Clone)]
pub struct RustMacroScopeEdge {
    pub parent: RustMacroScopeKey,
    pub child: RustMacroScopeKey,
    pub declaration_start: usize,
    pub visibility_start: usize,
    pub imports_macros: bool,
}

/// One macro's visible byte ranges per scope, the lazy form's answer shape.
pub type RustMacroScopeRanges = HashMap<RustMacroScopeKey, Vec<(usize, usize)>>;

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

    pub fn verified_importer_files(&self) -> impl Iterator<Item = &ProjectFile> {
        self.edges_by_importer.keys()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleAliasRoute {
    pub target_file: ProjectFile,
    pub target_module: ModuleKey,
    pub domain: Domain,
    pub provenance: RustRouteProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustResolvedModuleRoute {
    pub target_file: ProjectFile,
    pub target_module: ModuleKey,
    pub provenance: RustRouteProvenance,
}

pub fn rust_mod_item_has_macro_use(module: Node<'_>, source: &str) -> bool {
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

    fn declaration_owner_visible_to(
        &self,
        analyzer: &dyn RustFactSource,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_module: &ModuleKey,
    ) -> bool {
        if identity.file != *caller_file
            && !self.owners_intersect(&identity.file, caller_file)
            && analyzer
                .cargo_routes()
                .files_share_target(&identity.file, caller_file)
                != Some(true)
        {
            return false;
        }
        self.effective_module_domains_of(&identity.module)
            .is_some_and(|domains| {
                domains.iter().any(|domain| {
                    domain_contains_module_for_file(domain, analyzer, caller_file, caller_module)
                })
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
                                        .cargo_routes()
                                        .files_share_target(&identity.file, caller_file)
                                        == Some(true))))
                })
    }

    fn resolved_declaration_visible_to(
        &self,
        analyzer: &dyn RustFactSource,
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
        analyzer: &dyn RustFactSource,
        token: QueryToken<'_>,
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
            .filter(|parent| {
                crate::graph_support::is_rust_trait_declaration(analyzer.code_units(), parent)
            })
            .unwrap_or(declaration);
        let visibility = crate::graph_support::rust_declaration_visibility(
            analyzer,
            token,
            visibility_declaration,
        );
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
        let Some(domain) = direct_import_scope_for_module(
            declaration.source(),
            &owner.package(),
            visibility,
            self.is_actual_crate_root(declaration.source()),
        ) else {
            return false;
        };
        let files_share_visibility_domain = declaration.source() == caller_file
            || self.owners_intersect(declaration.source(), caller_file)
            || analyzer
                .cargo_routes()
                .files_share_target(declaration.source(), caller_file)
                == Some(true);
        if domain == Domain::Crate(rust_crate_root_package(declaration.source()))
            && files_share_visibility_domain
        {
            return true;
        }
        let domain_reaches_caller = |effective: &Domain| {
            *effective == Domain::Public
                || (files_share_visibility_domain
                    && domain_contains_module_for_file(
                        effective,
                        analyzer,
                        caller_file,
                        caller_module,
                    ))
        };
        match self.effective_module_domains_of(&owner) {
            Some(owner_domains) => owner_domains
                .iter()
                .filter_map(|owner_domain| domain.intersect(owner_domain))
                .any(|effective| domain_reaches_caller(&effective)),
            None => domain_reaches_caller(&domain),
        }
    }

    fn identity_visible_at(
        &self,
        analyzer: &dyn RustFactSource,
        identity: &RustSymbolIdentity,
        caller_file: &ProjectFile,
        caller_byte: usize,
    ) -> bool {
        let Some(caller_module) = self.queries().module_at_byte(caller_file, caller_byte) else {
            return false;
        };
        let files_share_visibility_domain = identity.file == *caller_file
            || self.owners_intersect(&identity.file, caller_file)
            || analyzer
                .cargo_routes()
                .files_share_target(&identity.file, caller_file)
                == Some(true);
        let domain_reaches_caller = |domain: &Domain| {
            *domain == Domain::Public
                || (files_share_visibility_domain
                    && domain_contains_module_for_file(
                        domain,
                        analyzer,
                        caller_file,
                        &caller_module,
                    ))
        };
        let Some(domains) = self.declared_domains_of(identity) else {
            return false;
        };
        match self.effective_module_domains_of(&identity.module) {
            Some(module_domains) => domains
                .iter()
                .flat_map(|domain| {
                    module_domains
                        .iter()
                        .filter_map(|module_domain| domain.intersect(module_domain))
                })
                .any(|effective| domain_reaches_caller(&effective)),
            None => domains.iter().any(domain_reaches_caller),
        }
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
            // A module reference can be spelled through its crate-relative
            // path without naming an imported item, so it retains the broad
            // Cargo-target reachability route. Named targets are already
            // covered by their exact textual candidates and the verified
            // binding-seed importers above; admitting every file in the same
            // Cargo target makes a private item in a large library degenerate
            // into a near-workspace scan.
            if root.is_module() {
                for file in self
                    .cargo_routes()
                    .files_that_can_reference_target_of(root.source())
                {
                    keep_going().then_some(())?;
                    out.insert(file);
                }
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

    pub fn binding_seeds_while(
        &self,
        analyzer: &dyn RustFactSource,
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

    pub fn export_targets_from_files(
        &self,
        analyzer: &dyn RustFactSource,
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
                    ExportEntry::Default { .. } | ExportEntry::ReexportedModule { .. } => {}
                }
            }
        }
        targets
    }
}

/// The visibility domain a declared `visibility` gives an item owned by
/// `package` in `file`.
///
/// `is_actual_crate_root` re-spells the owner as the crate package when the file
/// IS a Cargo target root: `benches/b.rs` is its own crate, so a private item at
/// its file root is visible to the whole of that crate rather than only to the
/// path-derived module the file's location suggests.
pub fn direct_import_scope_for_module(
    file: &ProjectFile,
    package: &str,
    visibility: RustVisibility,
    is_actual_crate_root: bool,
) -> Option<Domain> {
    let crate_package = rust_crate_root_package(file);
    let package = if is_actual_crate_root && package == rust_package_name(file) {
        crate_package.clone()
    } else {
        package.to_string()
    };
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

/// Whether `file` is a Cargo target root, and therefore its own crate.
pub fn rust_file_is_actual_crate_root(analyzer: &dyn RustFactSource, file: &ProjectFile) -> bool {
    analyzer.is_analyzed(file)
        && (rust_package_name(file) == rust_crate_root_package(file)
            || analyzer
                .cargo_routes()
                .target_roots_for_file(file)
                .contains(file))
}

/// Whether `domain` reaches `caller_module`, allowing for the caller sitting in
/// a Cargo target whose shared modules carry a kind-root module key.
///
/// `benches/left.rs` is its own crate but `benches/common/mod.rs` is spelled
/// under the shared `benches` root, so the plain key comparison misses a
/// visibility that Cargo grants. Widening through the caller's target roots is
/// what makes the two agree.
pub fn domain_contains_module_for_file(
    domain: &Domain,
    analyzer: &dyn RustFactSource,
    caller_file: &ProjectFile,
    caller_module: &ModuleKey,
) -> bool {
    if domain.contains_module(caller_module) {
        return true;
    }
    let target_roots = analyzer
        .cargo_routes()
        .target_roots_for_file(caller_file)
        .iter()
        .map(|root| ModuleKey::new(root, &rust_package_name(root)))
        .collect::<Vec<_>>();
    match domain {
        Domain::Public => true,
        Domain::Crate(crate_package) => target_roots
            .iter()
            .any(|root| root.crate_root == *crate_package),
        Domain::Module(domain_module) => target_roots.iter().any(|root| {
            root.crate_root == domain_module.crate_root
                && caller_module
                    .components
                    .starts_with(&domain_module.components)
        }),
    }
}

fn rust_declaration_targets_in_files(
    analyzer: &dyn RustFactSource,
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

/// Candidate files: those importing a seed, plus the seed files themselves.
pub fn usage_importers(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    seeds: &RustBindingSeeds,
) -> HashSet<ProjectFile> {
    RustUsageWalks::new(analyzer, token)
        .importers_of_seeds_while(seeds, &|| true)
        .expect("uninterrupted Rust importer selection")
}

pub fn usage_candidate_files_while(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    roots: &BTreeSet<CodeUnit>,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<HashSet<ProjectFile>> {
    let walks = RustUsageWalks::new_while(analyzer, token, keep_going)?;
    keep_going().then_some(())?;
    let seeds = walks.binding_seeds_while(analyzer, roots, keep_going)?;
    keep_going().then_some(())?;
    walks.importers_of_seeds_while(&seeds, keep_going)
}

/// Candidate files derived from binding seeds that a caller already prepared.
///
/// This is the second half of [`usage_candidate_files_while`]. Keeping it public
/// lets an analysis-layer query retain the expensive binding-seed result for its
/// semantic scan instead of rebuilding it only to recover the same file set.
pub fn usage_candidate_files_from_binding_seeds_while(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    seeds: &RustBindingSeeds,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<HashSet<ProjectFile>> {
    let walks = RustUsageWalks::new_while(analyzer, token, keep_going)?;
    keep_going().then_some(())?;
    walks.importers_of_seeds_while(seeds, keep_going)
}

pub fn usage_binding_seeds_while(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    roots: &BTreeSet<CodeUnit>,
    keep_going: &(impl Fn() -> bool + Sync),
) -> Option<RustBindingSeeds> {
    let walks = RustUsageWalks::new_while(analyzer, token, keep_going)?;
    keep_going().then_some(())?;
    walks.binding_seeds_while(analyzer, roots, keep_going)
}

/// Canonical local binding identities for a target, including named private
/// imports that can be imported again by descendant modules.
pub fn usage_binding_seeds(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    roots: &BTreeSet<CodeUnit>,
) -> RustBindingSeeds {
    RustUsageWalks::new(analyzer, token)
        .binding_seeds_while(analyzer, roots, &|| true)
        .expect("uninterrupted Rust binding-seed construction")
}

/// `(direct_names, qualified_names)` — local names that bind a seed directly
/// (`use path::Item;`) and exact paths that reach a seed through a namespace
/// binding (`use crate_name;` followed by `crate_name::Item`).
pub fn usage_binding_names(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
) -> (HashSet<String>, HashSet<String>) {
    let mut direct = HashSet::default();
    let mut qualified = HashSet::default();
    let walks = RustUsageWalks::new(analyzer, token);
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

pub fn usage_has_exact_scoped_binding(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
    namespace: RustReferenceNamespace,
) -> bool {
    scoped_explicit_import(analyzer, token, file, byte, name).is_some_and(|scoped| {
        unique_seed_identity_for_import_targets(
            analyzer,
            token,
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
                    analyzer,
                    token,
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
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
) -> HashSet<String> {
    RustUsageWalks::new(analyzer, token)
        .matching_edges_for_importer(file, seeds)
        .map(|edge| edge.local_name.clone())
        .collect()
}

pub fn usage_root_declaration_matches_at(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
) -> bool {
    let walks = RustUsageWalks::new(analyzer, token);
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

pub fn usage_declaration_visible_at(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    declaration: &CodeUnit,
    file: &ProjectFile,
    byte: usize,
) -> bool {
    RustUsageWalks::new(analyzer, token).declaration_visible_at(
        analyzer,
        token,
        declaration,
        file,
        byte,
    )
}

pub fn usage_identity_visible_at(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    declaration: &CodeUnit,
    file: &ProjectFile,
    byte: usize,
) -> bool {
    let walks = RustUsageWalks::new(analyzer, token);
    if let Some(identity) = walks
        .identity_of(declaration)
        .or_else(|| walks.value_constructor_identity_of(declaration))
    {
        return walks.identity_visible_at(analyzer, &identity, file, byte);
    }
    walks.declaration_visible_at(analyzer, token, declaration, file, byte)
}

pub fn usage_exact_root_for_resolution(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    resolution: &RustReferenceResolution,
    seeds: &RustBindingSeeds,
) -> Option<CodeUnit> {
    RustUsageWalks::new(analyzer, token).exact_root_for_resolution(resolution, seeds)
}

pub fn usage_local_module_prefix_visible_at(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    seeds: &RustBindingSeeds,
    name: &str,
    byte: usize,
) -> bool {
    let walks = RustUsageWalks::new(analyzer, token);
    let queries = RustUsageQueries::new(analyzer);
    let Some(module) = queries.module_at_byte(file, byte) else {
        return false;
    };
    let module = &module;

    if let Some(syntax) = analyzer.prepared_syntax(token, file) {
        if local_type_item_name_shadowed_in_tree(
            syntax.tree().root_node(),
            syntax.source(),
            name,
            byte,
        ) {
            return false;
        }

        // Resolve a function-local namespace before checking the physical child
        // module identity. A local `use crate::extjson;` is not a declaration in
        // the current module, but it still owns this path at the reference site.
        if let Some(routes) = visible_namespace_module_routes(
            analyzer,
            token,
            &walks,
            &queries,
            file,
            module,
            byte,
            &[name],
            false,
        ) {
            return routes.iter().any(|route| {
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
                        || analyzer
                            .cargo_routes()
                            .files_share_target(&route.target_file, &identity.file)
                            == Some(true))
                        && route.target_module.contains(&target_module)
                        && seeds.identity_domains.get(identity).is_some_and(|domains| {
                            domains.iter().any(|domain| domain.contains_module(module))
                        })
                })
            });
        }
    }

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
                    || analyzer
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

/// Resolve a path prefix through the nearest visible namespace import.
///
/// The regular module-alias table only contains imports owned by a module. A
/// `use` inside a function (or another local scope) is therefore absent from
/// that table, even though Rust resolves the binding at the reference site.
/// Keep this route query-local: the visible binder is authoritative, and an
/// unresolved local namespace must not fall through to a relative module path.
///
/// `None` means no binder at this byte binds the prefix's first segment, which
/// is the only case where the caller may fall back to relative resolution.
#[allow(clippy::too_many_arguments)]
fn visible_namespace_module_routes(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    walks: &RustUsageWalks<'_>,
    queries: &RustUsageQueries<'_>,
    file: &ProjectFile,
    module: &ModuleKey,
    byte: usize,
    path_prefix: &[&str],
    leading_absolute: bool,
) -> Option<Vec<RustResolvedModuleRoute>> {
    let first = path_prefix.first()?;
    let syntax = analyzer.prepared_syntax(token, file)?;
    let leading_absolute_local =
        leading_absolute && walks.cargo_routes().file_uses_rust_2015_edition(file);
    let admitted = |provenance| {
        !leading_absolute
            || matches!(
                provenance,
                RustRouteProvenance::CurrentLibrary | RustRouteProvenance::Dependency
            )
            || (leading_absolute_local && provenance == RustRouteProvenance::Local)
    };
    for (scope_start, binder) in
        visible_import_binders_with_scopes_in_tree(syntax.tree().root_node(), syntax.source(), byte)
    {
        let Some(binding) = binder.bindings.get(*first) else {
            continue;
        };
        let base_segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
        if base_segments.is_empty() {
            return Some(Vec::new());
        }
        let lexical_package = lexical_package_at(&module.package(), syntax.source(), scope_start);
        let mut base_routes = walks.resolve_segments(file, &lexical_package, &base_segments);
        base_routes.retain(|route| admitted(route.provenance));

        let resolve_routes = |mut segments: Vec<String>| {
            segments.extend(
                path_prefix
                    .iter()
                    .skip(1)
                    .map(|segment| (*segment).to_string()),
            );
            let mut routes = walks.resolve_segments(file, &lexical_package, &segments);
            routes.retain(|route| admitted(route.provenance));
            routes
        };

        match binding.kind {
            ImportKind::Namespace => return Some(resolve_routes(base_segments)),
            ImportKind::Named => {
                let Some(imported_name) = binding.imported_name.as_deref() else {
                    return Some(Vec::new());
                };

                let mut module_item = false;
                let mut type_item = false;
                let mut value_or_macro_item = false;
                // One indexed short-name lookup for the whole route set: the
                // answer does not depend on the route, only the filter does.
                let named = queries.identities_named(imported_name);
                for route in &base_routes {
                    let mut candidate_identities = named
                        .iter()
                        .map(|(identity, _)| identity.clone())
                        .filter(|identity| {
                            (identity.file == route.target_file
                                || walks.owners_intersect(&identity.file, &route.target_file)
                                || analyzer
                                    .cargo_routes()
                                    .files_share_target(&identity.file, &route.target_file)
                                    == Some(true))
                                && identity.module == route.target_module
                        })
                        .collect::<Vec<_>>();
                    if candidate_identities.is_empty() {
                        let export_targets = walks.export_targets_from_files(
                            analyzer,
                            std::slice::from_ref(&route.target_file),
                            imported_name,
                        );
                        candidate_identities = export_targets
                            .into_iter()
                            .flat_map(|(target_file, target_name)| {
                                queries
                                    .identities_in_file_named(&target_file, &target_name)
                                    .into_iter()
                                    .map(|(identity, _)| identity)
                            })
                            .collect();
                    }
                    for identity in candidate_identities {
                        match identity.namespace {
                            RustSymbolNamespace::Module => module_item = true,
                            RustSymbolNamespace::Type => type_item = true,
                            RustSymbolNamespace::Value | RustSymbolNamespace::Macro => {
                                value_or_macro_item = true;
                            }
                        }
                    }
                }

                if module_item && !type_item {
                    let mut segments = base_segments.clone();
                    segments.push(imported_name.to_string());
                    return Some(resolve_routes(segments));
                }
                if value_or_macro_item && !module_item && !type_item {
                    // Value- and macro-only imports do not occupy the
                    // type/module namespace. Keep searching for an outer
                    // binder with the same alias, such as a module import.
                    continue;
                }
                // A named type, module, or unresolved item is authoritative at
                // this scope. Do not use a relative path fallback that could
                // resolve a different declaration.
                return Some(Vec::new());
            }
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {
                return Some(Vec::new());
            }
        }
    }
    None
}

/// The seed identities a resolved module route can name under `terminal`.
///
/// Two sources, exactly as the v1 index had: declarations the target file makes
/// in that module, and re-export origin routes the target file publishes under
/// the same terminal name.
#[allow(clippy::too_many_arguments)]
fn seed_identities_for_resolved_module_route(
    analyzer: &dyn RustFactSource,
    walks: &RustUsageWalks<'_>,
    queries: &RustUsageQueries<'_>,
    seeds: &RustBindingSeeds,
    file: &ProjectFile,
    module: &ModuleKey,
    resolved: &RustResolvedModuleRoute,
    terminal: &str,
    namespace: RustReferenceNamespace,
) -> HashSet<RustSymbolIdentity> {
    let mut matches = queries
        .identities_in_file_named(&resolved.target_file, terminal)
        .into_iter()
        .filter(|(identity, declared_domains)| {
            let domains = seeds
                .identity_domains
                .get(identity)
                .unwrap_or(declared_domains);
            identity.module == resolved.target_module
                && identity.namespace.accepts(namespace)
                && domains.iter().any(|domain| domain.contains_module(module))
                && walks.resolved_declaration_visible_to(
                    analyzer,
                    identity,
                    file,
                    module,
                    resolved.provenance,
                )
        })
        .map(|(identity, _)| identity)
        .collect::<HashSet<_>>();
    matches.extend(
        walks
            .origin_routes_of(&resolved.target_file)
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
    matches
}

/// Whether two guard sets are proven to be alternatives of one declaration.
///
/// Both must be non-empty and every pairing must be a proven exclusion; an
/// `Unknown` on either side proves nothing and leaves the candidates competing.
fn cfg_conditions_proven_disjoint(left: &[RustCfgCondition], right: &[RustCfgCondition]) -> bool {
    !left.is_empty()
        && !right.is_empty()
        && left.iter().all(|left| {
            right
                .iter()
                .all(|right| left.proven_mutually_exclusive(right))
        })
}

#[allow(clippy::too_many_arguments)]
pub fn usage_reference_at(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
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
    let walks = RustUsageWalks::new(analyzer, token);
    let queries = RustUsageQueries::new(analyzer);
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
    let origin_routes = file_origin_routes
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
        .collect::<Vec<_>>();
    // A `use` inside a function body shadows the enclosing module's own
    // declaration of the same name for the rest of that body, so the local
    // import is the answer rather than one of two competing ones (#1377).
    let local_import_visible = origin_routes
        .iter()
        .any(|route| !route.is_glob_import && route.extent.is_local_only());
    let mut matches: HashSet<RustSymbolIdentity> = origin_routes
        .iter()
        .map(|route| route.origin.clone())
        .collect();
    // The guards each candidate was written under, so that two candidates whose
    // guards are proven disjoint read as alternatives of one declaration.
    let mut candidate_conditions: HashMap<RustSymbolIdentity, Vec<RustCfgCondition>> =
        HashMap::default();
    let mut higher_precedence_conditions: HashMap<RustSymbolIdentity, Vec<RustCfgCondition>> =
        HashMap::default();
    let mut glob_conditions: HashMap<RustSymbolIdentity, Vec<RustCfgCondition>> =
        HashMap::default();
    for route in &origin_routes {
        candidate_conditions
            .entry(route.origin.clone())
            .or_default()
            .push(route.cfg_condition.clone());
        let conditions = if route.is_glob_import {
            &mut glob_conditions
        } else {
            &mut higher_precedence_conditions
        };
        conditions
            .entry(route.origin.clone())
            .or_default()
            .push(route.cfg_condition.clone());
    }
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
        if !local_import_visible {
            for identity in queries
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
                        && walks.declaration_owner_visible_to(analyzer, identity, file, module)
                })
                .map(|(identity, _)| identity)
            {
                let declared_conditions = walks
                    .declared_cfg_conditions_of(&identity)
                    .unwrap_or_else(|| vec![RustCfgCondition::Unknown]);
                candidate_conditions
                    .entry(identity.clone())
                    .or_insert_with(|| declared_conditions.clone());
                higher_precedence_conditions
                    .entry(identity.clone())
                    .or_insert(declared_conditions);
                matches.insert(identity);
            }
        }
        // Rust glob imports are the lowest-precedence way to introduce a name.
        // Keep a glob candidate only when no explicit import or same-module
        // declaration can be active at the same time. Mutually exclusive cfg
        // arms remain peers so each target can still receive the shared site.
        for (identity, conditions) in &glob_conditions {
            if higher_precedence_conditions.contains_key(identity) {
                continue;
            }
            let shadowed = higher_precedence_conditions
                .values()
                .any(|higher_conditions| {
                    !cfg_conditions_proven_disjoint(higher_conditions, conditions)
                });
            if shadowed {
                matches.remove(identity);
                candidate_conditions.remove(identity);
            }
        }
        if matches.is_empty() {
            let scoped_import = scoped_explicit_import(analyzer, token, file, byte, segments[0]);
            let identity = match scoped_import {
                Some(scoped) => unique_seed_identity_for_import_targets(
                    analyzer,
                    token,
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
                            analyzer,
                            token,
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
                None => analyzer
                    .reference_context_of(token, file)
                    .resolve_bare(segments[0])
                    .and_then(|resolved_fqn| {
                        unique_seed_identity_for_fqn(
                            analyzer,
                            token,
                            file,
                            byte,
                            seeds,
                            &resolved_fqn,
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
        let local_namespace_routes = visible_namespace_module_routes(
            analyzer,
            token,
            &walks,
            &queries,
            file,
            module,
            byte,
            prefix,
            leading_absolute,
        );
        if let Some(routes) = local_namespace_routes {
            // The visible binder is authoritative at this byte: an unresolved
            // local namespace must not fall through to a relative module path.
            for resolved in routes {
                matches.extend(seed_identities_for_resolved_module_route(
                    analyzer, &walks, &queries, seeds, file, module, &resolved, terminal, namespace,
                ));
            }
            return resolution_of(matches, seeds);
        }
        for resolved in walks.resolve_segments(file, &package, &owned_prefix) {
            if !absolute_route_admitted(resolved.provenance) {
                continue;
            }
            matches.extend(seed_identities_for_resolved_module_route(
                analyzer, &walks, &queries, seeds, file, module, &resolved, terminal, namespace,
            ));
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
        let rooted_local_prefix = matches!(prefix.first(), Some(&"crate" | &"self" | &"super"));
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
                            && (!rooted_local_prefix
                                || walks.owners_intersect(file, &identity.file)
                                || analyzer
                                    .cargo_routes()
                                    .target_relation(file, &identity.file)
                                    == RustCargoTargetRelation::Shared)
                            && walks.declaration_owner_visible_to(analyzer, identity, file, module)
                    })
                    .map(|(identity, _)| identity.clone()),
            );
        }
        if matches.is_empty()
            && !leading_absolute
            && let Some(resolved_fqn) = analyzer
                .reference_context_of(token, file)
                .resolve_scoped(&prefix.join("::"), terminal)
            && let Some(identity) = unique_seed_identity_for_fqn(
                analyzer,
                token,
                file,
                byte,
                seeds,
                &resolved_fqn,
                &[],
                namespace,
            )
        {
            // A module-level glob can introduce the first path segment without
            // creating a named namespace binder (`use crate::types::*;` followed
            // by `use ast_elements::Target;`). The forward reference context
            // already resolves that structured path. Consult it only after the
            // authoritative binder and physical-module routes fail, and still
            // require the resolved identity to be one of this query's seeds.
            matches.insert(identity);
        }
    }

    if segments.len() == 1 && namespace != RustReferenceNamespace::Macro {
        // `#[cfg(x)] use path::name;` beside `#[cfg(not(x))] fn name()` is one
        // declaration with two arms, not two competing ones. A seed root whose
        // guard excludes every other candidate is therefore exact.
        let exact_roots = matches
            .iter()
            .filter(|candidate| seeds.root_origins.contains(*candidate))
            .filter(|candidate| {
                let Some(root_conditions) = candidate_conditions.get(*candidate) else {
                    return false;
                };
                matches.iter().all(|other| {
                    other == *candidate
                        || candidate_conditions
                            .get(other)
                            .is_some_and(|other_conditions| {
                                cfg_conditions_proven_disjoint(root_conditions, other_conditions)
                            })
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if exact_roots.len() == 1 {
            return RustReferenceResolution::Exact(exact_roots.into_iter().next().unwrap());
        }
    }

    resolution_of(matches, seeds)
}

/// One resolution out of the candidate set: exact only when a single candidate
/// survives and it is one of the seed roots.
fn resolution_of(
    matches: HashSet<RustSymbolIdentity>,
    seeds: &RustBindingSeeds,
) -> RustReferenceResolution {
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
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    RustUsageWalks::new(analyzer, token).export_targets_from_files(
        analyzer,
        module_files,
        export_name,
    )
}

pub fn usage_crate_export_targets(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let walks = RustUsageWalks::new(analyzer, token);
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
    let mut targets = walks.export_targets_from_files(analyzer, &crate_roots, export_name);
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

pub fn edge_matches_single_seed(edge: &RustImportEdge, target: &RustSymbolIdentity) -> bool {
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

#[allow(clippy::too_many_arguments)]
fn unique_seed_identity_for_fqn(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
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
                    token,
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
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    byte: usize,
    name: &str,
) -> Option<ScopedExplicitImport> {
    let syntax = analyzer.prepared_syntax(token, file)?;
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
                    token,
                    file,
                    syntax.source(),
                    scope_start,
                    &binding.module_specifier,
                )
                .map(|package| format!("{package}.{imported}"))
            }
            ImportKind::Namespace => resolve_rust_import_package_scoped(
                analyzer,
                token,
                file,
                syntax.source(),
                scope_start,
                &binding.module_specifier,
            ),
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => continue,
        };
        let walks = RustUsageWalks::new(analyzer, token);
        let importer_module = walks.queries().module_at_byte(file, byte)?;
        let importer_module = &importer_module;
        let segments = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
            brokk_bifrost_core::analyzer::Language::Rust,
            &binding.module_specifier,
        );
        let dependency_roots = walks
            .resolve_segments(file, &importer_module.package(), &segments)
            .into_iter()
            .filter(|route| route.provenance == RustRouteProvenance::Dependency)
            .map(|route| route.target_file)
            .collect();
        return Some(ScopedExplicitImport {
            targets: crate::graph_support::resolve_imported_export_from_binder_forward(
                analyzer, token, file, &binder, name,
            ),
            dependency_roots,
            fqn,
        });
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn unique_seed_identity_for_import_targets(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    seeds: &RustBindingSeeds,
    targets: &[(ProjectFile, String)],
    dependency_roots: &[ProjectFile],
    namespace: RustReferenceNamespace,
    byte: usize,
) -> Option<RustSymbolIdentity> {
    let importer_module = RustUsageQueries::new(analyzer).module_at_byte(importer, byte)?;
    let importer_module = &importer_module;
    let walks = RustUsageWalks::new(analyzer, token);
    let mut matches = seeds
        .identities
        .iter()
        .filter(|identity| {
            identity.namespace.accepts(namespace)
                && targets
                    .iter()
                    .any(|(file, name)| identity.file == *file && identity.name == *name)
                // The visible forward binder already returned a query root as
                // an exact target. Auxiliary Cargo and inferred-module domains
                // still constrain propagated aliases, but must not veto that
                // authoritative root for workspace or custom-target layouts.
                && ((seeds.root_origins.contains(identity)
                    && seeds.root_identities.iter().any(|(_, identities)| {
                        identities.contains(identity)
                            && walks.identity_visible_at(analyzer, identity, importer, byte)
                    })
                    && (identity.file == *importer
                        || walks.owners_intersect(importer, &identity.file)
                        || dependency_roots.iter().any(|root| {
                            walks
                                .cargo_routes()
                                .target_relation(root, &identity.file)
                                == RustCargoTargetRelation::Shared
                        })
                        || analyzer
                            .cargo_routes()
                            .files_share_target(importer, &identity.file)
                            == Some(true)))
                    || (seed_identity_admitted_at(
                        analyzer, token, importer,
                        byte,
                        seeds,
                        identity,
                        dependency_roots,
                    ) && seeds.identity_domains.get(*identity).is_none_or(|domains| {
                        domains
                            .iter()
                            .any(|domain| domain.contains_module(importer_module))
                    })))
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
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
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

    let walks = RustUsageWalks::new(analyzer, token);
    if dependency_roots.iter().any(|root| {
        walks.owners_intersect(root, &identity.file)
            || walks.cargo_routes().target_relation(root, &identity.file)
                == RustCargoTargetRelation::Shared
    }) {
        return true;
    }

    seeds.root_identities.iter().any(|(_, identities)| {
        identities.contains(identity)
            && walks.identity_visible_at(analyzer, identity, importer, byte)
            && (walks.owners_intersect(importer, &identity.file)
                || walks
                    .cargo_routes()
                    .file_can_reference_target_of(importer, &identity.file)
                || walks
                    .cargo_routes()
                    .target_relation(importer, &identity.file)
                    == RustCargoTargetRelation::Shared
                || analyzer
                    .cargo_routes()
                    .files_share_target(importer, &identity.file)
                    == Some(true))
    })
}

pub fn imported_identity_domain(
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

pub fn edge_target_matches_exact_module(edge: &RustImportEdge) -> bool {
    ModuleKey::new(&edge.target_file, &rust_package_name(&edge.target_file)) == edge.target_module
}
