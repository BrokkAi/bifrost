use super::graph_support::RustReferenceContext;
use crate::analyzer::usages::{ExportEntry, ExportIndex};
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

pub(super) fn weight_reference_context(
    _key: &ProjectFile,
    value: &Arc<RustReferenceContext>,
) -> u32 {
    let map_bytes = |map: &HashMap<String, String>| {
        map.iter()
            .map(|(key, val)| key.len() + val.len() + size_of::<(String, String)>())
            .sum::<usize>()
    };
    let size = map_bytes(&value.named)
        + map_bytes(&value.namespace)
        + map_bytes(&value.same_file)
        + size_of::<RustReferenceContext>();
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_export_index(_key: &ProjectFile, value: &Arc<ExportIndex>) -> u32 {
    let exports = value
        .exports_by_name
        .iter()
        .map(|(exported, entry)| {
            exported.len()
                + match entry {
                    ExportEntry::Local { local_name } => local_name.len(),
                    ExportEntry::Default { local_name } => {
                        local_name.as_ref().map_or(0, String::len)
                    }
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => module_specifier.len() + imported_name.len(),
                }
        })
        .sum::<usize>();
    let stars = value
        .reexport_stars
        .iter()
        .map(|star| star.module_specifier.len())
        .sum::<usize>();
    (exports + stars + size_of::<ExportIndex>()).min(u32::MAX as usize) as u32
}

pub(super) fn weight_project_file_set(
    _key: &ProjectFile,
    value: &Arc<HashSet<ProjectFile>>,
) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<HashSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

/// Byte weight of one file's declaration identities and domains.
///
/// The identity strings dominate: a module key holds a crate root plus one
/// component per module level, and every entry repeats the declaration's name.
/// Counting the strings rather than the entries keeps the budget honest for a
/// file of deeply nested modules.
pub(super) fn weight_declaration_facts(
    _key: &ProjectFile,
    value: &Arc<super::usage_queries::RustDeclarationFacts>,
) -> u32 {
    let identity_bytes = |identity: &super::usage_index::RustSymbolIdentity| {
        identity.name.len()
            + identity.module.weight_bytes()
            + size_of::<super::usage_index::RustSymbolIdentity>()
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
                    .map(super::usage_index::Domain::weight_bytes)
                    .sum::<usize>()
        })
        .sum::<usize>();
    (identities
        + declared_modules
        + domains
        + size_of::<super::usage_queries::RustDeclarationFacts>())
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one blob's persisted Rust usage facts.
///
/// The identifier-occurrence rows dominate: one entry per distinct identifier
/// in the file, where imports and modules are a handful each. Weighing the
/// strings rather than counting entries keeps the budget honest for a file with
/// a few very long paths.
pub(super) fn weight_rust_usage_facts(
    _key: &super::RustFactCacheKey,
    value: &Arc<super::facts::RustUsageFacts>,
) -> u32 {
    let exports = value
        .exports
        .iter()
        .map(|export| {
            export.exported_name.as_ref().map_or(0, String::len)
                + export.source_path.len()
                + export.imported_name.as_ref().map_or(0, String::len)
                + size_of::<super::facts::RustExportFact>()
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
                + size_of::<super::facts::RustImportTargetFact>()
        })
        .sum::<usize>();
    let modules = value
        .modules
        .iter()
        .map(|module| module.module_name.len() + size_of::<super::facts::RustModuleFact>())
        .sum::<usize>();
    let occurrences = value
        .identifier_occurrences
        .iter()
        .map(|occurrence| {
            occurrence.identifier.len() + size_of::<super::facts::RustIdentifierOccurrence>()
        })
        .sum::<usize>();
    (exports + imports + modules + occurrences + size_of::<super::facts::RustUsageFacts>())
        .min(u32::MAX as usize) as u32
}
