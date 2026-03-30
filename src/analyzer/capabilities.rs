use crate::analyzer::{CodeUnit, IAnalyzer, ImportInfo, ProjectFile};
use std::any::Any;
use std::collections::{BTreeSet, VecDeque};

pub trait CapabilityProvider: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> CapabilityProvider for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait ImportAnalysisProvider: CapabilityProvider {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile>;

    fn import_info_of(&self, _file: &ProjectFile) -> Vec<ImportInfo> {
        Vec::new()
    }

    fn relevant_imports_for(&self, _code_unit: &CodeUnit) -> BTreeSet<String> {
        BTreeSet::new()
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
) -> BTreeSet<ProjectFile>
where
    A: IAnalyzer,
    P: ImportAnalysisProvider + ?Sized,
{
    analyzer
        .get_analyzed_files()
        .into_iter()
        .filter(|candidate| candidate != file)
        .filter(|candidate| {
            provider
                .imported_code_units_of(candidate)
                .into_iter()
                .any(|code_unit| code_unit.source() == file)
        })
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
    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> BTreeSet<CodeUnit>;

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
) -> BTreeSet<CodeUnit>
where
    A: IAnalyzer,
    P: TypeHierarchyProvider + ?Sized,
{
    analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|candidate| candidate.is_class())
        .filter(|candidate| candidate != code_unit)
        .filter(|candidate| {
            provider
                .get_direct_ancestors(candidate)
                .into_iter()
                .any(|ancestor| ancestor.fq_name() == code_unit.fq_name())
        })
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
