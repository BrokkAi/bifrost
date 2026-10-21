//! PHP's `ImportAnalysisProvider` impl and the memo cells behind it.
//!
//! What one PHP file imports is decided in `brokk-bifrost-php` while the
//! parser tree is present and persisted as that file's `type_identifiers`:
//! the FQ name every `use` declaration binds, plus the FQ name every type
//! reference resolves to through PHP's namespace rule. What stays here is the
//! lookup from those names to the declarations other workspace files publish,
//! the cache over it, and the reverse index built from it.

use std::sync::Arc;

use crate::analyzer::php::PhpAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_core::analyzer::capabilities::ImportedFileEdgeFacts;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;
use std::path::Path;

impl ImportAnalysisProvider for PhpAnalyzer {
    fn for_each_import_edge_facts_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, Vec<ImportedFileEdgeFacts>) -> bool,
    ) -> Option<()> {
        let project_files = self.inner.project().all_files_shared().ok()?;
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let token = scope.token();
        for file in files {
            if cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            {
                break;
            }
            let owned_imports;
            let imports = if let Some(imports) = import_infos.and_then(|infos| infos.get(file)) {
                imports.as_slice()
            } else {
                owned_imports = self.inner.import_info_of(token, file);
                &owned_imports
            };
            let selected = selected_ordinals.get(file);
            let mut facts = Vec::new();
            let mut needs_declaration_edges = selected.is_none();
            for (ordinal, import) in imports.iter().enumerate() {
                let ordinal = u32::try_from(ordinal).expect("PHP import ordinal fits in u32");
                if selected.is_some_and(|selected| !selected.contains(&ordinal)) {
                    continue;
                }
                let kind = import.path.as_ref().and_then(|path| path.kind);
                if matches!(
                    kind,
                    Some(
                        StructuredImportPathKind::FileInclude
                            | StructuredImportPathKind::DynamicInclude
                    )
                ) {
                    let mut edges = HashMap::default();
                    if let Some(target) = php_include_target(&project_files, file, import) {
                        edges.insert(
                            target,
                            vec![
                                serde_json::json!({ "kind": "php_include_import", "fact": import }),
                            ],
                        );
                    }
                    facts.push(ImportedFileEdgeFacts {
                        import_ordinal: ordinal,
                        edges,
                    });
                } else {
                    needs_declaration_edges = true;
                }
            }
            if needs_declaration_edges {
                let edges = self
                    .imported_code_units_of(file)
                    .iter()
                    .map(|unit| unit.source().clone())
                    .filter(|target| target != file)
                    .map(|target| {
                        (
                            target,
                            vec![serde_json::json!({ "kind": "php_imported_declaration" })],
                        )
                    })
                    .collect();
                facts.push(ImportedFileEdgeFacts {
                    import_ordinal: u32::MAX,
                    edges,
                });
            }
            if !visit(file, facts) {
                break;
            }
        }
        Some(())
    }

    fn imported_file_edge_provenance_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashMap<ProjectFile, Vec<serde_json::Value>>> {
        let project_files = self.inner.project().all_files_shared().ok()?;
        let mut edges: HashMap<ProjectFile, Vec<serde_json::Value>> = HashMap::default();
        for import in imports {
            if let Some(target) = php_include_target(&project_files, file, import) {
                edges
                    .entry(target)
                    .or_default()
                    .push(serde_json::json!({ "kind": "php_include_import", "fact": import }));
            }
        }
        for unit in self.imported_code_units_of(file).iter() {
            if unit.source() != file {
                edges
                    .entry(unit.source().clone())
                    .or_default()
                    .push(serde_json::json!({ "kind": "php_imported_declaration" }));
            }
        }
        Some(edges)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let project_files = self.inner.project().all_files_shared().ok()?;
        let mut imported = self
            .imported_code_units_of(file)
            .iter()
            .map(|unit| unit.source().clone())
            .filter(|target| target != file)
            .collect::<HashSet<_>>();
        imported.extend(
            imports
                .iter()
                .filter_map(|import| php_include_target(&project_files, file, import)),
        );
        Some(imported)
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let names: Vec<String> = self
            .inner
            .type_identifiers_of(file)
            .unwrap_or_default()
            .into_iter()
            .collect();
        // One batched read for the whole file rather than one store round trip
        // per imported name (#1748's shape).
        let scope = AnalyzerQueryScope::new(self);
        let _token = scope.token();
        self.inner.prefetch_definitions(&names);

        let mut imported: HashSet<CodeUnit> = HashSet::default();
        for name in &names {
            // A file's own declarations are not imports: PHP reaches them
            // because they are declared here, not because a name was bound.
            imported.extend(self.definitions(name).filter(|unit| unit.source() != file));
        }

        let imported = Arc::new(imported);
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&imported));
        imported
    }

    /// The `use` declarations the parser recorded for this file, one row per
    /// bound local name (#2962). This is what the lexical-environment layer
    /// derives PHP's import binders from; `imported_code_units_of` above stays
    /// on `type_identifiers`, which additionally covers the names PHP's
    /// namespace rule binds with no `use` declaration at all (#1713).
    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        brokk_bifrost_core::analyzer::capabilities::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        )
        .get(file)
        .map(|files| (**files).clone())
        .unwrap_or_default()
    }
}

fn php_include_target(
    project_files: &BTreeSet<ProjectFile>,
    importer: &ProjectFile,
    import: &ImportInfo,
) -> Option<ProjectFile> {
    let path = import.path.as_ref()?;
    if path.kind != Some(StructuredImportPathKind::FileInclude) {
        return None;
    }
    let target = brokk_bifrost_core::path_utils::normalize_relative_path_from(
        importer.rel_path().parent().unwrap_or(Path::new("")),
        Path::new(&path.segments.join("/")),
    )?;
    let target_file = importer.with_rel_path(target);
    project_files.contains(&target_file).then_some(target_file)
}
