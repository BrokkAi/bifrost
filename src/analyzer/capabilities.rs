use crate::analyzer::pool_memo::PoolSafeMemo;
use crate::analyzer::{CodeUnit, IAnalyzer, ImportInfo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::any::Any;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use rayon::prelude::*;

pub trait CapabilityProvider: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> CapabilityProvider for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait ImportAnalysisProvider: CapabilityProvider {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit>;
    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile>;

    /// Return import facts for a group of files without requiring each caller
    /// to hydrate a complete per-file analyzer state. `None` preserves the
    /// existing file-at-a-time behavior for providers without a bulk read model.
    fn import_infos_for_files(
        &self,
        _files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        None
    }

    fn import_info_of(&self, _file: &ProjectFile) -> Vec<ImportInfo> {
        Vec::new()
    }

    /// Resolve imported source units from already-loaded import facts. Providers
    /// that cannot do this cheaply return `None` and use `imported_code_units_of`.
    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        None
    }

    /// Resolve directly imported project files from already-loaded import facts.
    /// Providers that do not expose file-level edges return `None` and callers
    /// can derive a conservative approximation from imported declarations.
    fn imported_files_from_infos(
        &self,
        _file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        None
    }

    fn relevant_imports_for(&self, _code_unit: &CodeUnit) -> HashSet<String> {
        HashSet::default()
    }

    fn could_import_file(
        &self,
        _source_file: &ProjectFile,
        _imports: &[ImportInfo],
        _target: &ProjectFile,
    ) -> bool {
        false
    }
}

/// Resolve direct project-file edges from structured import facts. Prefer a
/// provider's file-level resolver so imports whose target has no declarations
/// remain visible; otherwise conservatively project resolved declaration
/// identities back to their source files.
pub(crate) fn resolve_imported_files_from_infos(
    provider: &dyn ImportAnalysisProvider,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<ProjectFile> {
    provider
        .imported_files_from_infos(file, imports)
        .unwrap_or_else(|| {
            provider
                .imported_code_units_from_infos(file, imports)
                .unwrap_or_else(|| provider.imported_code_units_of(file))
                .into_iter()
                .map(|unit| unit.source().clone())
                .collect()
        })
}

pub(crate) fn build_reverse_import_index<F>(
    files: &[ProjectFile],
    resolve_imported: F,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>
where
    F: Fn(&ProjectFile) -> HashSet<CodeUnit> + Sync,
{
    build_reverse_file_index(
        files,
        |file| {
            resolve_imported(file)
                .into_iter()
                .map(|code_unit| code_unit.source().clone())
                .collect::<Vec<_>>()
        },
        parallel,
    )
}

pub(crate) type ReverseFileIndex = HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>;

pub(crate) fn memoized_reverse_import_index<F, Files>(
    memo: &PoolSafeMemo<ReverseFileIndex>,
    files: Files,
    resolve_imported: F,
) -> Arc<ReverseFileIndex>
where
    F: Fn(&ProjectFile) -> HashSet<CodeUnit> + Sync + Copy,
    Files: Fn() -> Vec<ProjectFile> + Copy,
{
    memoized_reverse_file_index(memo, files, |file| {
        resolve_imported(file)
            .into_iter()
            .map(|code_unit| code_unit.source().clone())
            .collect::<Vec<_>>()
    })
}

pub(crate) fn memoized_reverse_file_index<F, I, Files>(
    memo: &PoolSafeMemo<ReverseFileIndex>,
    files: Files,
    resolve_targets: F,
) -> Arc<ReverseFileIndex>
where
    F: Fn(&ProjectFile) -> I + Sync + Copy,
    I: IntoIterator<Item = ProjectFile>,
    Files: Fn() -> Vec<ProjectFile> + Copy,
{
    memo.get_or_build(
        || {
            let files = files();
            build_reverse_file_index(&files, resolve_targets, true)
        },
        || {
            let files = files();
            build_reverse_file_index(&files, resolve_targets, false)
        },
    )
}

pub(crate) fn build_reverse_file_index<F, I>(
    files: &[ProjectFile],
    resolve_targets: F,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>
where
    F: Fn(&ProjectFile) -> I + Sync,
    I: IntoIterator<Item = ProjectFile>,
{
    let collect_edges = |file: &ProjectFile| {
        let source = file.clone();
        resolve_targets(file)
            .into_iter()
            .filter_map(move |target| (target != source).then(|| (target, source.clone())))
            .collect::<Vec<_>>()
    };
    let edges: Vec<_> = if parallel {
        files.par_iter().flat_map(collect_edges).collect()
    } else {
        files.iter().flat_map(collect_edges).collect()
    };

    let mut reverse: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
    for (target, source) in edges {
        reverse.entry(target).or_default().insert(source);
    }
    reverse
        .into_iter()
        .map(|(file, refs)| (file, Arc::new(refs)))
        .collect()
}

pub trait TypeAliasProvider: CapabilityProvider {
    fn is_type_alias(&self, _code_unit: &CodeUnit) -> bool {
        false
    }
}

pub trait TestDetectionProvider: CapabilityProvider {}

pub trait TypeHierarchyProvider: CapabilityProvider {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit>;

    fn supports_type_hierarchy(&self, _code_unit: &CodeUnit) -> bool {
        true
    }

    fn get_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        traverse_hierarchy(code_unit, |next| self.get_direct_ancestors(next))
    }

    fn get_descendants(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        traverse_hierarchy(code_unit, |next| {
            self.get_direct_descendants(next).into_iter().collect()
        })
    }

    fn get_polymorphic_matches<T: IAnalyzer>(
        &self,
        target: &CodeUnit,
        analyzer: &T,
    ) -> Vec<CodeUnit>
    where
        Self: Sized,
    {
        if !target.is_function() {
            return Vec::new();
        }

        let Some(parent) = analyzer.parent_of(target) else {
            return Vec::new();
        };

        self.get_descendants(&parent)
    }
}

pub(crate) fn build_direct_descendant_index<A, P>(
    analyzer: &A,
    provider: &P,
) -> HashMap<String, Arc<HashSet<CodeUnit>>>
where
    A: IAnalyzer,
    P: TypeHierarchyProvider + ?Sized,
{
    let mut reverse: HashMap<String, HashSet<CodeUnit>> = HashMap::default();
    for candidate in analyzer
        .all_declarations()
        .filter(|candidate| candidate.is_class())
    {
        for ancestor in provider.get_direct_ancestors(&candidate) {
            reverse
                .entry(ancestor.fq_name())
                .or_default()
                .insert(candidate.clone());
        }
    }

    reverse
        .into_iter()
        .map(|(ancestor, descendants)| (ancestor, Arc::new(descendants)))
        .collect()
}

fn traverse_hierarchy<F>(root: &CodeUnit, mut next: F) -> Vec<CodeUnit>
where
    F: FnMut(&CodeUnit) -> Vec<CodeUnit>,
{
    let direct = next(root);
    if direct.is_empty() {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    let mut queue = VecDeque::new();

    for item in direct {
        if seen.insert(item.fq_name()) {
            queue.push_back(item.clone());
            result.push(item);
        }
    }

    while let Some(current) = queue.pop_front() {
        for item in next(&current) {
            if seen.insert(item.fq_name()) {
                queue.push_back(item.clone());
                result.push(item);
            }
        }
    }

    result
}
