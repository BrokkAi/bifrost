use crate::analyzer::{CodeUnit, IAnalyzer, ImportInfo, ProjectFile};
use std::any::Any;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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

    fn import_info_of<'a>(&'a self, _file: &ProjectFile) -> &'a [ImportInfo] {
        &[]
    }

    fn relevant_imports_for(&self, _code_unit: &CodeUnit) -> HashSet<String> {
        HashSet::new()
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

pub(crate) fn referencing_files_via_imports<A, P>(
    analyzer: &A,
    provider: &P,
    file: &ProjectFile,
) -> HashSet<ProjectFile>
where
    A: IAnalyzer,
    P: ImportAnalysisProvider + ?Sized,
{
    analyzer
        .analyzed_files()
        .filter(|candidate| *candidate != file)
        .filter(|candidate| {
            let imports = provider.import_info_of(candidate);
            provider.could_import_file(candidate, imports, file)
                && provider
                    .imported_code_units_of(candidate)
                    .into_iter()
                    .any(|code_unit| code_unit.source() == file)
        })
        .cloned()
        .collect()
}

pub(crate) fn build_reverse_import_index<F>(
    files: &[ProjectFile],
    resolve_imported: F,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>
where
    F: Fn(&ProjectFile) -> HashSet<CodeUnit> + Sync,
{
    let imported_by_file: Vec<_> = files
        .par_iter()
        .map(|file| (file.clone(), resolve_imported(file)))
        .collect();

    let mut reverse: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::new();
    for (file, imported) in imported_by_file {
        for code_unit in imported {
            let target = code_unit.source();
            if target != &file {
                reverse
                    .entry(target.clone())
                    .or_default()
                    .insert(file.clone());
            }
        }
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

pub(crate) fn direct_descendants_via_ancestors<A, P>(
    analyzer: &A,
    provider: &P,
    code_unit: &CodeUnit,
) -> HashSet<CodeUnit>
where
    A: IAnalyzer,
    P: TypeHierarchyProvider + ?Sized,
{
    analyzer
        .all_declarations()
        .filter(|candidate| candidate.is_class())
        .filter(|candidate| *candidate != code_unit)
        .filter(|candidate| {
            provider
                .get_direct_ancestors(candidate)
                .into_iter()
                .any(|ancestor| ancestor.fq_name() == code_unit.fq_name())
        })
        .cloned()
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
