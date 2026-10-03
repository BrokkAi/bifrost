//! Graph projections of published JavaScript/TypeScript source facts.

use crate::source_facts::JsTsFileSourceFacts;
use brokk_bifrost_core::analyzer::js_ts_facts::{JsTsExportKind, JsTsSourceFacts};
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ExportIndex, ReexportStar};

fn import_module_specifier(import: &SourceImportFact) -> Option<String> {
    let path = import.path.as_ref()?;
    let module_specifier = path.segments.join("/");
    (!module_specifier.is_empty()).then_some(module_specifier)
}

fn import_at(
    imports: &[SourceImportFact],
    id: brokk_bifrost_core::analyzer::source_facts::SourceImportId,
) -> Option<&SourceImportFact> {
    imports.get(id.index())
}

/// Find the canonical declaration identities linked to one display unit.
///
/// The link is an exact source-publication relation.  Consumers must use this
/// instead of comparing analyzer ranges with a freshly parsed tree.
pub fn declaration_ids_for_unit(
    facts: &JsTsFileSourceFacts,
    unit: &CodeUnit,
) -> Vec<SourceDeclarationId> {
    facts
        .declaration_units
        .iter()
        .filter_map(|(declaration, units)| {
            units
                .iter()
                .any(|candidate| candidate == unit)
                .then_some(*declaration)
        })
        .collect()
}

/// Project canonical JS/TS export rows into the graph's export index.
pub fn export_index_from_source_facts(
    facts: &JsTsSourceFacts,
    imports: &[SourceImportFact],
) -> ExportIndex {
    let mut index = ExportIndex::empty();
    for fact in &facts.exports {
        match &fact.kind {
            JsTsExportKind::Local { local_name } => {
                let Some(name) = fact.name.as_ref() else {
                    continue;
                };
                index.exports_by_name.insert(
                    name.clone(),
                    ExportEntry::Local {
                        local_name: local_name.clone(),
                    },
                );
            }
            JsTsExportKind::Default { local_name } => {
                let Some(name) = fact.name.as_ref() else {
                    continue;
                };
                index.exports_by_name.insert(
                    name.clone(),
                    ExportEntry::Default {
                        local_name: local_name.clone(),
                    },
                );
            }
            JsTsExportKind::ReexportNamed { import } => {
                let Some(name) = fact.name.as_ref() else {
                    continue;
                };
                let Some(import) = import_at(imports, *import) else {
                    continue;
                };
                let Some(module_specifier) = import_module_specifier(import) else {
                    continue;
                };
                let Some(imported_name) = import.identifier.clone() else {
                    continue;
                };
                index.exports_by_name.insert(
                    name.clone(),
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    },
                );
            }
            JsTsExportKind::ReexportModule { import } => {
                let Some(name) = fact.name.as_ref() else {
                    continue;
                };
                let Some(import) = import_at(imports, *import) else {
                    continue;
                };
                let Some(module_specifier) = import_module_specifier(import) else {
                    continue;
                };
                index.exports_by_name.insert(
                    name.clone(),
                    ExportEntry::ReexportedModule { module_specifier },
                );
            }
            JsTsExportKind::Star { import } => {
                let Some(import) = import_at(imports, *import) else {
                    continue;
                };
                let Some(module_specifier) = import_module_specifier(import) else {
                    continue;
                };
                index.reexport_stars.push(ReexportStar { module_specifier });
            }
        }
    }
    index.reexport_stars.sort();
    index.reexport_stars.dedup();
    index
}
