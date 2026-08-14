//! Byte weighing for the Rust usage caches.
//!
//! Every memo in `usage_walks.rs`, plus the analyzer's per-blob fact cache and
//! per-file declaration-fact cache, is bounded by a byte budget rather than by
//! an entry count, so each value shape needs a weigher that reports what it
//! actually holds. The shapes are Rust's, so the weighers live beside them
//! here; the generic builder and the language-neutral weighers are
//! [`brokk_bifrost_core::analyzer::weighted_cache`].

use brokk_bifrost_core::analyzer::rust_facts::{
    RustExportFact, RustIdentifierOccurrence, RustImportTargetFact, RustModuleFact, RustUsageFacts,
};
pub use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use std::mem::size_of;
use std::path::PathBuf;
use std::sync::Arc;

pub fn weight_declaration_facts(
    _key: &ProjectFile,
    value: &Arc<crate::usage_queries::RustDeclarationFacts>,
) -> u32 {
    let identity_bytes = |identity: &crate::usage::RustSymbolIdentity| {
        identity.name.len()
            + identity.module.weight_bytes()
            + size_of::<crate::usage::RustSymbolIdentity>()
    };
    let identities = value
        .identities
        .iter()
        .chain(value.value_constructors.iter())
        .map(|(declaration, identity)| {
            declaration.fq_name().len() + identity_bytes(identity) + size_of::<CodeUnit>()
        })
        .sum::<usize>();
    let declared_modules = value
        .declared_module_domains
        .iter()
        .map(|(module, domain)| module.weight_bytes() + domain.weight_bytes())
        .sum::<usize>();
    let domains = value
        .domains
        .iter()
        .map(|(identity, domains)| {
            identity_bytes(identity)
                + domains
                    .iter()
                    .map(crate::usage::Domain::weight_bytes)
                    .sum::<usize>()
        })
        .sum::<usize>();
    (identities
        + declared_modules
        + domains
        + size_of::<crate::usage_queries::RustDeclarationFacts>())
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one blob's persisted Rust usage facts.
///
/// The identifier-occurrence rows dominate: one entry per distinct identifier
/// in the file, where imports and modules are a handful each. Weighing the
/// strings rather than counting entries keeps the budget honest for a file with
/// a few very long paths.
pub fn weight_rust_usage_facts<K>(_key: &K, value: &Arc<RustUsageFacts>) -> u32 {
    let exports = value
        .exports
        .iter()
        .map(|export| {
            export.exported_name.as_ref().map_or(0, String::len)
                + export.source_path.len()
                + export.imported_name.as_ref().map_or(0, String::len)
                + size_of::<RustExportFact>()
        })
        .sum::<usize>();
    let imports = value
        .import_targets
        .iter()
        .map(|target| {
            target.module_path.len()
                + target.bound_name.as_ref().map_or(0, String::len)
                + target.imported_name.as_ref().map_or(0, String::len)
                + target.owner_module.len()
                + size_of::<RustImportTargetFact>()
        })
        .sum::<usize>();
    let modules = value
        .modules
        .iter()
        .map(|module| module.module_name.len() + size_of::<RustModuleFact>())
        .sum::<usize>();
    let occurrences = value
        .identifier_occurrences
        .iter()
        .map(|occurrence| occurrence.identifier.len() + size_of::<RustIdentifierOccurrence>())
        .sum::<usize>();
    (exports + imports + modules + occurrences + size_of::<RustUsageFacts>()).min(u32::MAX as usize)
        as u32
}

/// Byte weight of a memoized file list (module-backing files, owner crate
/// roots). The paths dominate; the vector header is noise beside them.
pub fn weight_project_file_list<K>(_key: &K, value: &Arc<Vec<ProjectFile>>) -> u32 {
    let size = value
        .iter()
        .map(|file| file.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<Vec<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

/// Byte weight of one memoized module probe.
///
/// The key carries the cost here, not the value: most probes find nothing, and
/// memoizing "nothing" is the point, so a weigher that only counted the file
/// list would let unbounded distinct module paths accumulate for free.
// The signature is moka's: a weigher is `Fn(&K, &V)`, and the key type is
// `PathBuf`.
#[allow(clippy::ptr_arg)]
pub fn weight_module_probe(key: &PathBuf, value: &Arc<Vec<ProjectFile>>) -> u32 {
    let files = value
        .iter()
        .map(|file| file.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>();
    (key.as_os_str().len() + files + size_of::<Vec<ProjectFile>>()).min(u32::MAX as usize) as u32
}

/// Byte weight of one module's effective visibility domains. A `None` value is
/// the answer "no file declares this module", which costs only its key.
pub fn weight_module_domains(
    key: &crate::usage::ModuleKey,
    value: &Option<Arc<Vec<crate::usage::Domain>>>,
) -> u32 {
    let domains = value
        .iter()
        .flat_map(|domains| domains.iter())
        .map(crate::usage::Domain::weight_bytes)
        .sum::<usize>();
    (key.weight_bytes() + domains).min(u32::MAX as usize) as u32
}

/// Byte weight of one module alias's routes. Each route owns a target path, a
/// target module key, and a domain.
pub fn weight_alias_routes(
    key: &crate::usage::ModuleKey,
    value: &Arc<Vec<crate::usage::RustModuleAliasRoute>>,
) -> u32 {
    let routes = value
        .iter()
        .map(|route| {
            route.target_file.rel_path().to_string_lossy().len()
                + route.target_module.weight_bytes()
                + route.domain.weight_bytes()
                + size_of::<crate::usage::RustModuleAliasRoute>()
        })
        .sum::<usize>();
    (key.weight_bytes() + routes).min(u32::MAX as usize) as u32
}

/// Byte weight of one file's forward import edges. Each edge owns the importer
/// and target paths, two module keys, its local name, and its domain.
pub fn weight_forward_import_edges(
    _key: &ProjectFile,
    value: &Arc<Vec<crate::usage::RustImportEdge>>,
) -> u32 {
    let size = value.iter().map(weight_import_edge).sum::<usize>()
        + size_of::<Vec<crate::usage::RustImportEdge>>();
    size.min(u32::MAX as usize) as u32
}

/// Byte weight of the import edges that bind one symbol identity.
pub fn weight_binding_edges(
    key: &crate::usage::RustSymbolIdentity,
    value: &Arc<Vec<crate::usage::RustImportEdge>>,
) -> u32 {
    let size = key.file.rel_path().to_string_lossy().len()
        + key.module.weight_bytes()
        + key.name.len()
        + size_of::<crate::usage::RustSymbolIdentity>()
        + value.iter().map(weight_import_edge).sum::<usize>()
        + size_of::<Vec<crate::usage::RustImportEdge>>();
    size.min(u32::MAX as usize) as u32
}

fn weight_import_edge(edge: &crate::usage::RustImportEdge) -> usize {
    edge.importer.rel_path().to_string_lossy().len()
        + edge.target_file.rel_path().to_string_lossy().len()
        + edge.importer_module.weight_bytes()
        + edge.target_module.weight_bytes()
        + edge.local_name.len()
        + edge.domain.weight_bytes()
        + size_of::<crate::usage::RustImportEdge>()
}

fn weight_identity(identity: &crate::usage::RustSymbolIdentity) -> usize {
    identity.name.len()
        + identity.module.weight_bytes()
        + identity.file.rel_path().to_string_lossy().len()
        + size_of::<crate::usage::RustSymbolIdentity>()
}

/// Byte weight of what one module binds.
pub fn weight_module_bindings(
    key: &(ProjectFile, crate::usage::ModuleKey),
    value: &Arc<Vec<crate::usage_walks::RustModuleBinding>>,
) -> u32 {
    let bindings = value
        .iter()
        .map(|binding| {
            binding.name.len()
                + weight_identity(&binding.origin)
                + binding.domain.weight_bytes()
                + size_of::<crate::usage_walks::RustModuleBinding>()
        })
        .sum::<usize>();
    (key.0.rel_path().to_string_lossy().len() + key.1.weight_bytes() + bindings)
        .min(u32::MAX as usize) as u32
}

/// Byte weight of one file's origin routes, bucketed by first path segment.
pub fn weight_origin_routes(
    _key: &ProjectFile,
    value: &Arc<HashMap<String, Vec<crate::usage::RustOriginRoute>>>,
) -> u32 {
    let size = value
        .iter()
        .map(|(segment, routes)| {
            segment.len()
                + routes
                    .iter()
                    .map(|route| {
                        route.importer_module.weight_bytes()
                            + route
                                .path
                                .iter()
                                .map(|part| part.len() + size_of::<String>())
                                .sum::<usize>()
                            + weight_identity(&route.origin)
                            + route.domain.weight_bytes()
                            + size_of::<crate::usage::RustOriginRoute>()
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    size.min(u32::MAX as usize) as u32
}

/// Byte weight of one file's macro scope edges.
pub fn weight_macro_scope_edges(
    _key: &ProjectFile,
    value: &Arc<Vec<crate::usage::RustMacroScopeEdge>>,
) -> u32 {
    let size = value
        .iter()
        .map(|edge| {
            edge.parent.module.weight_bytes()
                + edge.child.module.weight_bytes()
                + edge.child.file.rel_path().to_string_lossy().len()
                + size_of::<crate::usage::RustMacroScopeEdge>()
        })
        .sum::<usize>();
    size.min(u32::MAX as usize) as u32
}

/// Byte weight of one macro's visible ranges, per scope.
pub fn weight_macro_visible_ranges(
    key: &CodeUnit,
    value: &Arc<crate::usage::RustMacroScopeRanges>,
) -> u32 {
    let size = value
        .iter()
        .map(|(scope, ranges)| {
            scope.file.rel_path().to_string_lossy().len()
                + scope.module.weight_bytes()
                + ranges.len() * size_of::<(usize, usize)>()
        })
        .sum::<usize>();
    (key.fq_name().len() + size).min(u32::MAX as usize) as u32
}

/// Byte weight of one file's composed include-expansion routes. The host
/// bindings dominate: a deeply nested include accumulates one per binding
/// visible at each splice it passed through.
pub fn weight_include_routes(
    _key: &ProjectFile,
    value: &Arc<Vec<crate::usage_includes::RustIncludeRoute>>,
) -> u32 {
    let size = value
        .iter()
        .map(|route| {
            route.root_file.rel_path().to_string_lossy().len()
                + route.crate_package.len()
                + route.module_package.len()
                + route
                    .host_bindings
                    .iter()
                    .map(|binding| {
                        binding.local_name.len()
                            + binding.module_specifier.len()
                            + binding.imported_name.as_ref().map_or(0, String::len)
                            + binding.module_package.len()
                            + size_of::<crate::usage_includes::RustIncludeHostBinding>()
                    })
                    .sum::<usize>()
                + size_of::<crate::usage_includes::RustIncludeRoute>()
        })
        .sum::<usize>()
        + size_of::<Vec<crate::usage_includes::RustIncludeRoute>>();
    size.min(u32::MAX as usize) as u32
}
