//! Query-time composition over the persisted per-file Rust usage facts.
//!
//! This is the read side of the tables Milestone 1 of
//! `.agents/plans/rust-usage-index-v2.md` added. Where Rust usage analysis
//! used to answer a question from seventeen workspace-wide maps built
//! wholesale into heap, `RustUsageQueries` answers it from rows: the file's own
//! facts for a per-file question, and one indexed lookup plus per-candidate
//! verification for a name question.
//!
//! Two contracts govern everything here, both taken from IntelliJ (see
//! `.agents/docs/intellij-indexing-research-2026-08.md`):
//!
//! An inverted lookup returns CANDIDATES, never answers. "This file mentions
//! the name `foo`" is all `rust_identifier_occurrences` claims; deciding
//! whether that mention is a usage of a particular declaration is the caller's
//! verification step. IntelliJ states the same contract on `IdIndex`, where it
//! is forced by hash collisions; here it is forced by the fact that a name is
//! not an identity.
//!
//! Nothing persisted is path-derived, because blob rows are content-keyed and
//! two byte-identical files share one row set. The stored module names are
//! relative to each file's own root, and this module composes them with the
//! live file's package name on the way out. That composition is the only place
//! a path enters, and it is why `facts_of` takes a `ProjectFile` rather than an
//! `Oid`.

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use std::collections::BTreeSet;
use std::sync::Arc;

use git2::Oid;

use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};

use crate::graph_support::RustFactSource;
use brokk_bifrost_core::hash::HashSet;

use crate::declarations::rust_package_name;
use crate::graph_support::rust_value_constructor_visibilities;
use crate::imports::RustVisibility;
use crate::lexical_scope::{RustCfgCondition, rust_cfg_condition};
use crate::usage::{
    Domain, ModuleKey, RustImportExtent, RustSymbolIdentity, RustSymbolNamespace,
    direct_import_scope_for_module, rust_file_is_actual_crate_root,
};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustExportFact, RustImportTargetFact, RustUsageFacts,
};

/// One `use` binding of one file, with its module names composed against the
/// live path and its lexical reach in the shape the usage graph consumes.
///
/// This is the persisted `rust_import_targets` row plus that composition. It is
/// deliberately narrower than `RustProjectedImport`: the rendered snippet and
/// the structured import path that value also carries are not usage facts, and
/// reproducing them would mean re-parsing the file, which is the cost this
/// design exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RustImportBinding {
    /// The leaf path as written, split into segments. For a glob this is the
    /// module path; for a named import it is the module path plus the imported
    /// name, which is exactly `RustProjectedImport::import.path`.
    pub path: Vec<String>,
    /// The name the import binds locally, empty for a glob -- matching what
    /// `ImportInfo::local_name().unwrap_or_default()` yields today.
    pub local_name: String,
    pub is_glob: bool,
    /// True for `extern crate name as alias;`: it binds a namespace and nothing
    /// in the current module's own namespace.
    pub is_extern_crate: bool,
    pub visibility: RustVisibility,
    /// The `#[cfg(...)]` predicate the `use` was written under.
    pub cfg_condition: RustCfgCondition,
    /// The enclosing module as a dotted package name, composed with the live
    /// file's package.
    pub owner_module: String,
    pub importer_module: ModuleKey,
    pub extent: RustImportExtent,
}

/// Every symbol identity one file introduces, with the visibility domain each
/// identity carries.
///
/// A per-file product in the plan's classification: deriving it needs the
/// file's own declarations, their structural parents and their visibility, and
/// nothing from any other file. The v1 index folded exactly this derivation
/// into its workspace-wide build; both callers now go through
/// [`rust_declaration_facts`], so the workspace map and the query-time answer
/// cannot drift apart.
#[derive(Debug, Default)]
pub struct RustDeclarationFacts {
    /// Declaration -> the identity it introduces, in declaration order. A
    /// declaration whose visibility does not resolve to a domain still appears
    /// here; it simply contributes no entry to `domains`.
    pub identities: Vec<(CodeUnit, RustSymbolIdentity)>,
    /// Tuple-struct and tuple-variant constructors, which bind a
    /// value-namespace identity of the declaration's own name under the
    /// constructor's (possibly narrower) visibility.
    pub value_constructors: Vec<(CodeUnit, RustSymbolIdentity)>,
    /// `mod name` declarations of this file, as (declared module, domain).
    pub declared_module_domains: Vec<(ModuleKey, Domain)>,
    /// Identity -> the domains it was declared with, grouped in first-appearance
    /// order. Two declarations can share one identity (a `#[cfg]`-duplicated
    /// item, say), so the value is a list rather than a single domain.
    pub domains: Vec<(RustSymbolIdentity, Vec<Domain>)>,
    /// Identity -> the `#[cfg(...)]` predicate each declaration of it was
    /// written under, grouped the same way. This is what lets a reference see
    /// a `#[cfg(not(x))]` local declaration and a `#[cfg(x)]` import of the
    /// same name as alternatives rather than as an ambiguity (#1377).
    ///
    /// Derived from the file's own tree, so it is a per-file product like the
    /// rest of this struct and needs no stored row: the predicate sits on the
    /// declaration's own item, in the file that declares it.
    pub cfg_conditions: Vec<(RustSymbolIdentity, Vec<RustCfgCondition>)>,
}

/// Derive one file's declaration facts.
///
/// `declarations` is passed in rather than fetched, because both callers
/// already hold the file's declaration set and re-reading it would double the
/// store work on the build path.
///
/// `None` only when `keep_going` asked to stop.
pub fn rust_declaration_facts(
    analyzer: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
    keep_going: &impl Fn() -> bool,
) -> Option<RustDeclarationFacts> {
    let mut facts = RustDeclarationFacts::default();
    let mut ordered_domains: Vec<(RustSymbolIdentity, Domain)> = Vec::new();
    let mut ordered_cfg_conditions: Vec<(RustSymbolIdentity, RustCfgCondition)> = Vec::new();
    let prepared = analyzer.prepared_syntax(token, file);
    let is_actual_crate_root = rust_file_is_actual_crate_root(analyzer, file);
    for declaration in declarations {
        keep_going().then_some(())?;
        let (owner, declared_module) = if declaration.is_module() {
            let declared = ModuleKey::new(file, &declaration.fq_name());
            let owner = declared
                .parent()
                .unwrap_or_else(|| ModuleKey::new(file, &rust_package_name(file)));
            (owner, Some(declared))
        } else {
            let owner = match analyzer.structural_parent_of(declaration) {
                None => ModuleKey::new(file, &rust_package_name(file)),
                Some(parent) if parent.is_module() => ModuleKey::new(file, &parent.fq_name()),
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
        facts
            .identities
            .push((declaration.clone(), identity.clone()));
        let declaration_cfg_condition = prepared.as_ref().and_then(|syntax| {
            crate::graph_support::inspect_rust_named_declaration_node(
                analyzer.code_units(),
                declaration,
                syntax.tree().root_node(),
                syntax.source(),
                rust_cfg_condition,
            )
        });
        // A declaration whose node this build cannot find proves nothing about
        // its guard, so it is `Unknown` rather than `Always`.
        ordered_cfg_conditions.push((
            identity.clone(),
            declaration_cfg_condition.unwrap_or(RustCfgCondition::Unknown),
        ));
        let constructor_domain = prepared.as_ref().and_then(|syntax| {
            crate::graph_support::inspect_rust_named_declaration_node(
                analyzer.code_units(),
                declaration,
                syntax.tree().root_node(),
                syntax.source(),
                rust_value_constructor_visibilities,
            )??
            .into_iter()
            .map(|visibility| {
                direct_import_scope_for_module(
                    file,
                    &owner.package(),
                    visibility,
                    is_actual_crate_root,
                )
            })
            .try_fold(Domain::Public, |effective, domain| {
                effective.intersect(&domain?)
            })
        });
        let declaration_domain = if namespace == RustSymbolNamespace::Macro
            && crate::graph_support::is_rust_macro_export_declaration(
                analyzer.code_units(),
                declaration,
            ) {
            Some(Domain::Public)
        } else {
            direct_import_scope_for_module(
                file,
                &owner.package(),
                crate::graph_support::rust_declaration_visibility(analyzer, token, declaration),
                is_actual_crate_root,
            )
        };
        let Some(domain) = declaration_domain else {
            continue;
        };
        if let Some(declared_module) = declared_module {
            facts
                .declared_module_domains
                .push((declared_module, domain.clone()));
        }
        ordered_domains.push((identity.clone(), domain));
        if let Some(constructor_domain) = constructor_domain {
            let constructor = RustSymbolIdentity {
                namespace: RustSymbolNamespace::Value,
                ..identity
            };
            ordered_domains.push((constructor.clone(), constructor_domain));
            facts
                .value_constructors
                .push((declaration.clone(), constructor));
        }
    }
    for (identity, domain) in ordered_domains {
        keep_going().then_some(())?;
        match facts
            .domains
            .iter_mut()
            .find(|(existing, _)| *existing == identity)
        {
            Some((_, domains)) => domains.push(domain),
            None => facts.domains.push((identity, vec![domain])),
        }
    }
    for (identity, condition) in ordered_cfg_conditions {
        keep_going().then_some(())?;
        match facts
            .cfg_conditions
            .iter_mut()
            .find(|(existing, _)| *existing == identity)
        {
            Some((_, conditions)) => conditions.push(condition),
            None => facts.cfg_conditions.push((identity, vec![condition])),
        }
    }
    Some(facts)
}

/// A stateless view over the store, borrowing the analyzer for its store
/// handle, its live path mapping, and its bounded per-file fact cache.
pub struct RustUsageQueries<'a> {
    analyzer: &'a dyn RustFactSource,
}

/// The query surface every Rust usage answer reads through: `usage.rs` for
/// `module_at_byte`, `graph_support.rs` for the re-export half of
/// `export_index_of_declarations`, and `usage_walks.rs` for everything
/// cross-file.
impl<'a> RustUsageQueries<'a> {
    pub fn new(analyzer: &'a dyn RustFactSource) -> Self {
        Self { analyzer }
    }

    /// Every persisted fact for `file`, memoized per `(generation, blob)`.
    ///
    /// `None` when the file has no live blob or its blob has no rows -- a file
    /// outside the analyzed set, or one whose analysis has not been persisted
    /// yet. Callers treat that as "no facts", not as an error: the catch-up
    /// policy that makes it impossible is Milestone 3.
    pub fn facts_of(&self, file: &ProjectFile) -> Option<Arc<RustUsageFacts>> {
        let oid = self.oid_of(file)?;
        self.analyzer.rust_usage_facts_of_blob(oid)
    }

    fn oid_of(&self, file: &ProjectFile) -> Option<Oid> {
        self.analyzer.live_blobs().oid_for_path(file)
    }

    /// One file's declaration identities and their domains, memoized.
    pub fn declaration_facts_of(&self, file: &ProjectFile) -> Arc<RustDeclarationFacts> {
        self.analyzer.rust_declaration_facts_of(file)
    }

    /// The identities `file` declares under `name`, with their domains.
    ///
    /// A per-file question despite looking like a name search: the caller
    /// already knows which file it means, so no inverted lookup is involved.
    pub fn identities_in_file_named(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<(RustSymbolIdentity, Vec<Domain>)> {
        self.declaration_facts_of(file)
            .domains
            .iter()
            .filter(|(identity, _)| identity.name == name)
            .cloned()
            .collect()
    }

    /// Every declaration identity in the workspace named `name`, with its
    /// domains.
    ///
    /// Candidate lookup plus verification, replacing the v1 index's
    /// `identities_by_name` map. `lookup_candidates_by_identifier` is the
    /// store's indexed short-name lookup over `code_units`, so the candidate
    /// set is the handful of files that declare this identifier rather than
    /// the workspace; each candidate is then verified against its own
    /// declaration facts, which decide whether an identity of that name really
    /// exists there and what visibility it carries. A candidate whose only
    /// declaration of `name` has no resolvable domain contributes nothing,
    /// exactly as it contributed no `declaration_domains` key in v1.
    pub fn identities_named(&self, name: &str) -> Vec<(RustSymbolIdentity, Vec<Domain>)> {
        let mut candidates: Vec<ProjectFile> = self
            .analyzer
            .lookup_candidates_by_identifier(name)
            .into_iter()
            .map(|declaration| declaration.source().clone())
            .filter(|file| self.analyzer.is_analyzed(file))
            .collect();
        candidates.sort();
        candidates.dedup();
        candidates
            .iter()
            .flat_map(|file| self.identities_in_file_named(file, name))
            .collect()
    }

    /// The modules `file` introduces, as `(module, start_byte, end_byte)` with
    /// the file's package composed in.
    ///
    /// Only extents whose body is in this file are returned, because the
    /// question this answers is "which module encloses a byte of this file".
    /// A `mod name;` declaration has no body here; resolving it to another file
    /// is a separate, cross-file question.
    pub fn module_extents_of(&self, file: &ProjectFile) -> Vec<(ModuleKey, usize, usize)> {
        let Some(facts) = self.facts_of(file) else {
            return Vec::new();
        };
        let package = rust_package_name(file);
        facts
            .modules
            .iter()
            .filter(|module| module.is_inline)
            .map(|module| {
                (
                    ModuleKey::new(file, &compose_module(&package, &module.module_name)),
                    module.start_byte,
                    module.end_byte,
                )
            })
            .collect()
    }

    /// The narrowest module of `file` whose body contains `byte`.
    pub fn module_at_byte(&self, file: &ProjectFile, byte: usize) -> Option<ModuleKey> {
        self.module_extents_of(file)
            .into_iter()
            .filter(|(_, start, end)| *start <= byte && byte < *end)
            .min_by_key(|(_, start, end)| end.saturating_sub(*start))
            .map(|(module, _, _)| module)
    }

    /// Every `use` binding of `file`, in source order.
    pub fn import_bindings_of(&self, file: &ProjectFile) -> Vec<RustImportBinding> {
        let Some(facts) = self.facts_of(file) else {
            return Vec::new();
        };
        let package = rust_package_name(file);
        facts
            .import_targets
            .iter()
            .map(|target| binding_from_fact(file, &package, target))
            .collect()
    }

    /// The names `file` re-exports through a non-private root `use`.
    pub fn re_exports_of(&self, file: &ProjectFile) -> Vec<RustExportFact> {
        self.facts_of(file)
            .map(|facts| facts.exports.clone())
            .unwrap_or_default()
    }

    /// Live files that import `module_path`, spelled exactly as they write it.
    ///
    /// One indexed lookup. The result is a candidate set: an importer that
    /// writes `crate::a` and one that writes `super::a` may name the same
    /// module, and two crates may both write `alpha`. Verification is the
    /// caller's.
    pub fn files_importing_module_path(&self, module_path: &str) -> Vec<ProjectFile> {
        self.live_files(self.analyzer.rust_import_target_blobs(module_path))
    }

    /// Live files whose structured imports can name `component` as a module.
    ///
    /// This covers named namespace imports and module paths ending in the
    /// component, including globs and named imports below that module. It does
    /// not include ordinary code mentions; callers still verify every returned
    /// file by resolving its forward import edges.
    pub fn files_importing_module_component(&self, component: &str) -> Vec<ProjectFile> {
        self.live_files(self.analyzer.rust_module_import_candidate_blobs(component))
    }

    /// Live files whose text mentions `identifier` in at least one of the
    /// contexts in `context_mask`.
    ///
    /// This is the `IdIndex` analogue and the entry point of a name search.
    /// Pass [`RUST_OCCURRENCE_CODE`](brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE) to
    /// exclude comments and string literals,
    /// which is what a reference search wants.
    pub fn files_mentioning(&self, identifier: &str, context_mask: u32) -> Vec<ProjectFile> {
        let snapshot = self.analyzer.live_blobs();
        let mut files = Vec::new();
        for (oid, mask) in self.analyzer.rust_identifier_occurrence_blobs(identifier) {
            if mask & context_mask == 0 {
                continue;
            }
            files.extend(snapshot.paths_for_oid(oid));
        }
        dedup_files(files)
    }

    /// Live files with an `include!` whose literal ends in `file_name`.
    ///
    /// One indexed lookup on `rust_include_edges.file_name`. The result is a
    /// candidate set under the same contract as the other inverted lookups
    /// here: two directories can both hold a `table.rs`, and only resolving
    /// each candidate's own literal against its own directory decides which
    /// one it names.
    pub fn files_with_include_named(&self, file_name: &str) -> Vec<ProjectFile> {
        self.live_files(self.analyzer.rust_include_blobs(file_name))
    }

    fn live_files(&self, oids: Vec<Oid>) -> Vec<ProjectFile> {
        let snapshot = self.analyzer.live_blobs();
        dedup_files(
            oids.into_iter()
                .flat_map(|oid| snapshot.paths_for_oid(oid))
                .collect(),
        )
    }
}

/// Compose a stored, file-root-relative module name with the live file's
/// package name. The empty stored name is the file root itself.
pub fn compose_module(package: &str, stored: &str) -> String {
    if stored.is_empty() {
        package.to_string()
    } else if package.is_empty() {
        stored.to_string()
    } else {
        format!("{package}.{stored}")
    }
}

#[allow(dead_code)]
fn binding_from_fact(
    file: &ProjectFile,
    package: &str,
    target: &RustImportTargetFact,
) -> RustImportBinding {
    let mut path: Vec<String> = target
        .module_path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(imported_name) = &target.imported_name {
        path.push(imported_name.clone());
    }
    let owner_module = compose_module(package, &target.owner_module);
    let extent = match target.local_extent {
        Some((start, end)) => RustImportExtent::LocalOnly {
            module_start: target.owner_start,
            module_end: target.owner_end,
            start,
            end,
        },
        None => RustImportExtent::Module {
            start: target.owner_start,
            end: target.owner_end,
        },
    };
    RustImportBinding {
        path,
        local_name: target.bound_name.clone().unwrap_or_default(),
        is_glob: target.is_glob,
        is_extern_crate: target.is_extern_crate,
        visibility: target.visibility.clone(),
        cfg_condition: target.cfg_condition.clone(),
        importer_module: ModuleKey::new(file, &owner_module),
        owner_module,
        extent,
    }
}

#[allow(dead_code)]
fn dedup_files(files: Vec<ProjectFile>) -> Vec<ProjectFile> {
    let mut seen = HashSet::default();
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        if seen.insert(file.clone()) {
            out.push(file);
        }
    }
    out.sort();
    out
}
