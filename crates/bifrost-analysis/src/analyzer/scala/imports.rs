//! `ScalaAnalyzer`'s import resolution: the analyzer-facing half of Scala's
//! import handling.
//!
//! The node-reading half -- structured import/export parsing and the lexical
//! scope path -- is [`brokk_bifrost_jvm::scala::imports`].

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    CodeUnit, ImportAnalysisProvider, ImportInfo, Language, ProjectFile, build_reverse_file_index,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

pub(crate) use brokk_bifrost_jvm::scala::imports::scala_import_infos_from_node;
use brokk_bifrost_jvm::scala::imports::{
    is_scala_importable_direct_member, is_scala_importable_top_level,
};
use brokk_bifrost_jvm::scala::wildcard_imports::{
    ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaWildcardImportEnvironment,
    ScalaWildcardImportOwner, ScalaWildcardOwnerFacts, ScalaWildcardOwnerKind,
    resolve_scala_explicit_import_tier, resolve_scala_wildcard_import_environment,
    scala_import_path,
};

use super::{ScalaAnalyzer, scala_enclosing_template_owner_fq_names};

impl ScalaAnalyzer {
    fn resolve_import_info(
        &self,
        file: &ProjectFile,
        import_index: usize,
        info: &ImportInfo,
        wildcard_environment: &ScalaWildcardImportEnvironment,
    ) -> Vec<CodeUnit> {
        let Some(path) = scala_import_path(info) else {
            return Vec::new();
        };
        if info.is_wildcard {
            let mut imported = Vec::new();
            for owner in wildcard_environment
                .owners
                .iter()
                .filter(|owner| owner.import_index == import_index)
            {
                imported.extend(self.resolve_wildcard_owner(owner));
            }
            imported.sort();
            imported.dedup();
            return imported;
        }
        let Some(source_package) = self.inner.package_name_of(file) else {
            return Vec::new();
        };
        let Some(tier) =
            self.explicit_import_tier(info, &path, std::slice::from_ref(&source_package))
        else {
            return Vec::new();
        };
        let mut imported = Vec::new();
        if tier.declaration {
            imported.extend(self.inner.definitions(&tier.candidate));
        }
        if tier.package {
            let descendant_prefix = format!("{}.", tier.candidate);
            let packages = self.package_namespaces();
            let start = packages.partition_point(|package| package < &tier.candidate);
            for package in packages[start..].iter().take_while(|package| {
                package.as_str() == tier.candidate || package.starts_with(&descendant_prefix)
            }) {
                if let Some(declarations) = self.importable_declarations_by_package().get(package) {
                    imported.extend(declarations.iter().cloned());
                }
            }
        }
        imported.sort();
        imported.dedup();
        imported
    }

    fn resolve_wildcard_owner(&self, owner: &ScalaWildcardImportOwner) -> Vec<CodeUnit> {
        match owner.kind {
            ScalaWildcardOwnerKind::Package => self
                .importable_declarations_by_package()
                .get(&owner.fqn)
                .map(|units| units.iter().cloned().collect())
                .unwrap_or_default(),
            ScalaWildcardOwnerKind::StableSingleton => {
                let mut imported = Vec::new();
                for declaration in self
                    .inner
                    .definitions(&owner.declaration_fqn())
                    .filter(CodeUnit::is_class)
                {
                    imported.extend(
                        self.inner
                            .direct_children(&declaration)
                            .into_iter()
                            .filter(is_scala_importable_direct_member),
                    );
                    for (_, target_fqn) in self
                        .project_types()
                        .exported_member_bindings(self, &declaration)
                    {
                        imported.extend(
                            self.inner
                                .definitions(&target_fqn)
                                .filter(is_scala_importable_direct_member),
                        );
                    }
                }
                imported.sort();
                imported.dedup();
                imported
            }
        }
    }

    fn wildcard_owner_facts(&self, candidate: &str) -> ScalaWildcardOwnerFacts {
        let singleton_fqn = format!("{}$", candidate.trim_end_matches('$'));
        ScalaWildcardOwnerFacts {
            package: self
                .importable_declarations_by_package()
                .contains_key(candidate),
            stable_singleton: self
                .inner
                .definitions(&singleton_fqn)
                .any(|unit| unit.is_class() && unit.fq_name() == singleton_fqn),
        }
    }

    fn wildcard_import_environment(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> ScalaWildcardImportEnvironment {
        let mut package_prefixes = Vec::new();
        if package_prefixes.is_empty()
            && let Some(package) = self.inner.package_name_of(file)
        {
            package_prefixes.push(package.to_string());
        }
        resolve_scala_wildcard_import_environment(
            imports,
            &package_prefixes,
            |declaration_start_byte| {
                scala_enclosing_template_owner_fq_names(self, self, file, declaration_start_byte)
            },
            |candidate| self.wildcard_owner_facts(candidate),
        )
    }

    fn importable_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>> {
        self.importable_declarations_by_package.get_or_init(|| {
            let mut declarations: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in self.inner.all_declarations() {
                if is_scala_importable_top_level(&unit) {
                    declarations
                        .entry(unit.package_name().to_string())
                        .or_default()
                        .push(unit.clone());
                }
            }
            declarations
                .into_iter()
                .map(|(package, units)| (package, Arc::new(units)))
                .collect()
        })
    }

    fn package_namespaces(&self) -> &[String] {
        self.package_namespaces.get_or_init(|| {
            let mut packages = self
                .importable_declarations_by_package()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            packages.sort_unstable();
            packages
        })
    }

    fn package_namespace_exists(&self, candidate: &str) -> bool {
        let descendant_prefix = format!("{candidate}.");
        let packages = self.package_namespaces();
        let index = packages.partition_point(|package| package.as_str() < candidate);
        packages
            .get(index)
            .is_some_and(|package| package == candidate || package.starts_with(&descendant_prefix))
    }

    fn explicit_import_tier(
        &self,
        info: &ImportInfo,
        path: &str,
        fallback_package_prefixes: &[String],
    ) -> Option<ScalaExplicitImportTier> {
        let lexical_prefixes = info
            .path
            .as_ref()
            .map(|path| path.lexical_prefixes.as_slice())
            .filter(|prefixes| !prefixes.is_empty());
        let package_prefixes = lexical_prefixes.unwrap_or(fallback_package_prefixes);
        resolve_scala_explicit_import_tier(path, package_prefixes, |candidate| {
            ScalaExplicitImportFacts {
                declaration: self.inner.definitions(candidate).next().is_some(),
                package: self.package_namespace_exists(candidate),
            }
        })
    }

    fn same_package_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.same_package_reference_index.get_or_build(
            || self.compute_same_package_reference_index(true),
            || self.compute_same_package_reference_index(false),
        )
    }

    fn compute_same_package_reference_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut files_by_package: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in self.inner.all_files() {
            if file_language(&file) != Language::Scala {
                continue;
            }
            if let Some(package) = self.inner.package_name_of(&file) {
                files_by_package
                    .entry(package.to_string())
                    .or_default()
                    .push(file.clone());
            }
        }

        let files: Vec<_> = self.inner.all_files();
        build_reverse_file_index(
            &files,
            |candidate| {
                if file_language(candidate) != Language::Scala {
                    return Vec::new();
                }
                let Some(package) = self.inner.package_name_of(candidate) else {
                    return Vec::new();
                };
                files_by_package.get(&package).cloned().unwrap_or_default()
            },
            parallel,
        )
    }
}

impl ImportAnalysisProvider for ScalaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Scala {
            return HashSet::default();
        }
        let imports = self.inner.import_info_of(file);
        let wildcard_environment = self.wildcard_import_environment(file, &imports);
        let mut imported = HashSet::default();
        for (import_index, info) in imports.iter().enumerate() {
            for code_unit in
                self.resolve_import_info(file, import_index, info, &wildcard_environment)
            {
                imported.insert(code_unit);
            }
        }
        self.imported_code_units
            .insert(file.clone(), Arc::new(imported.clone()));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Scala {
            return HashSet::default();
        }
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if source_file == target {
            return false;
        }
        if file_language(source_file) != Language::Scala || file_language(target) != Language::Scala
        {
            return false;
        }

        let Some(source_package) = self.inner.package_name_of(source_file) else {
            return false;
        };
        let Some(target_package) = self.inner.package_name_of(target) else {
            return false;
        };
        if source_package == target_package {
            return true;
        }

        let wildcard_environment = self.wildcard_import_environment(source_file, imports);
        if wildcard_environment
            .owners
            .iter()
            .any(|owner| match owner.kind {
                ScalaWildcardOwnerKind::Package => owner.fqn == target_package,
                ScalaWildcardOwnerKind::StableSingleton => self
                    .resolve_wildcard_owner(owner)
                    .iter()
                    .any(|declaration| declaration.source() == target),
            })
        {
            return true;
        }

        imports.iter().any(|info| {
            let Some(path) = scala_import_path(info) else {
                return false;
            };
            if info.is_wildcard {
                return false;
            }
            let Some(tier) =
                self.explicit_import_tier(info, &path, std::slice::from_ref(&source_package))
            else {
                return false;
            };
            let declaration_reaches = tier.declaration
                && self
                    .inner
                    .definitions(&tier.candidate)
                    .any(|declaration| declaration.source() == target);
            let package_reaches = tier.package
                && (target_package == tier.candidate
                    || target_package
                        .strip_prefix(&tier.candidate)
                        .is_some_and(|suffix| suffix.starts_with('.')));
            declaration_reaches || package_reaches
        })
    }
}
