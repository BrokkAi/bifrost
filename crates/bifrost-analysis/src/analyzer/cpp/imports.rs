//! The `CppAnalyzer` half of C++ include analysis.
//!
//! `#include` parsing, the workspace-wide [`IncludeTargetIndex`] and every
//! target-resolution rule moved to [`brokk_bifrost_cpp::imports`]; what stays
//! here is the two provider impls the analyzer satisfies and the memo cells
//! (`OnceLock`, `PoolSafeMemo`) whose contents those functions produce.
//!
//! Every resolution point here reads `#include <...>` and `#include "..."` the
//! same way, through [`parse_include_path`] / [`include_paths`]. The
//! quoted-only spellings this module used to carry made a project that reaches
//! its own headers with angle brackets invisible to the inverse while the
//! forward resolved it (#1829).
//!
//! The two include-to-file rules differ by what the caller does with the
//! answer, not by include spelling. A *visibility* claim
//! (`imported_code_units_of`, `imported_files_from_infos`) uses
//! [`resolve_include_targets_with_index`], the same direct-then-unique-suffix
//! rule the forward resolver's include closure uses; its unique-suffix step is
//! what makes admitting `<...>` safe without a compiler include path, because
//! it refuses an ambiguous basename rather than picking one. *Candidate
//! discovery* (`referencing_files_of`, via `include_targets_for_file`) uses
//! `IncludeTargetIndex::resolve_indexed`, which deliberately over-approximates:
//! a file that only might reach the target still has to be scanned, and the
//! usage strategy proves or rejects each hit from the syntax tree.

use super::*;
use brokk_bifrost_cpp::imports::{
    include_paths, parse_include_path, resolve_include_targets_with_index,
};
use std::path::Path;
use std::sync::Arc;

impl TestDetectionProvider for CppAnalyzer {}

impl ImportAnalysisProvider for CppAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let mut resolved = HashSet::default();
        let include_targets = self.include_target_index();
        let imports = self.import_statements_from_projection(file);
        for path in include_paths(&imports) {
            for target in resolve_include_targets_with_index(file, &path, include_targets) {
                resolved.extend(self.inner.top_level_declarations(&target));
            }
        }

        let resolved = Arc::new(resolved);
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let references = self
            .reverse_include_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        self.referencing_files
            .insert(file.clone(), Arc::new(references.clone()));
        references
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let include_targets = self.include_target_index();
        Some(
            imports
                .iter()
                .filter_map(|import| parse_include_path(&import.raw_snippet))
                .flat_map(|path| resolve_include_targets_with_index(file, &path, include_targets))
                .collect(),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = code_unit.source();
        let identifiers = brokk_bifrost_cpp::imports::extract_type_identifiers(
            &self.inner.get_source(code_unit, true).unwrap_or_default(),
        );
        self.import_statements_from_projection(source)
            .iter()
            .filter(|line| {
                parse_include_path(line).is_some_and(|path| {
                    let stem = Path::new(&path)
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("");
                    identifiers.contains(stem)
                })
            })
            .cloned()
            .collect()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_name = target
            .rel_path()
            .file_name()
            .and_then(|value| value.to_str());
        imports.iter().any(|import| {
            parse_include_path(&import.raw_snippet).is_some_and(|include| {
                target.rel_path() == Path::new(&include)
                    || target_name.is_some_and(|name| include.ends_with(name))
                    || source_file.parent().join(&include) == target.rel_path()
            })
        })
    }
}

impl CppAnalyzer {
    pub(crate) fn include_target_index(&self) -> &IncludeTargetIndex {
        self.include_target_index.get_or_init(|| {
            let files = self.inner.all_files();
            IncludeTargetIndex::build(files.iter())
        })
    }

    fn reverse_include_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_include_index,
            || self.inner.all_files(),
            |candidate| self.include_targets_for_file(candidate),
        )
    }

    fn include_targets_for_file(&self, candidate: &ProjectFile) -> Vec<ProjectFile> {
        let include_targets = self.include_target_index();
        let mut matched_targets = HashSet::default();
        let mut resolved_targets = Vec::new();
        let imports = self.import_statements_from_projection(candidate);
        for include in include_paths(&imports) {
            for target in include_targets.resolve_indexed(&include) {
                if matched_targets.insert(target.clone()) {
                    resolved_targets.push(target);
                }
            }
        }
        resolved_targets
    }
}
