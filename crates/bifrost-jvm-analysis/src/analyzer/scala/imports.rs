//! `ScalaAnalyzer`'s import resolution: the analyzer-facing half of Scala's
//! import handling.
//!
//! The node-reading half -- structured import/export parsing and the lexical
//! scope path -- is [`brokk_bifrost_jvm::scala::imports`].

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_core::analyzer::capabilities::ImportReachability;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::capabilities::build_reverse_file_index;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;
use std::sync::Arc;

use brokk_bifrost_jvm::scala::imports::{
    is_scala_importable_direct_member, is_scala_importable_top_level,
};
use brokk_bifrost_jvm::scala::wildcard_imports::{
    ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaWildcardImportEnvironment,
    ScalaWildcardImportOwner, ScalaWildcardOwnerFacts, ScalaWildcardOwnerKind,
    resolve_scala_explicit_import_tier, resolve_scala_wildcard_import_environment,
    scala_import_path, scala_import_path_candidates, scala_import_reachability,
};

use crate::analyzer::scala::ScalaAnalyzer;

use brokk_bifrost_jvm::scala::imports::scala_enclosing_template_owner_fq_names;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

#[derive(Default)]
pub(crate) struct ScalaFileDependencyIndex {
    package_by_file: HashMap<ProjectFile, String>,
    type_identifiers_by_file: HashMap<ProjectFile, HashSet<String>>,
    same_package_declarations_by_name: HashMap<String, HashMap<String, HashSet<ProjectFile>>>,
    importable_files_by_package: HashMap<String, HashSet<ProjectFile>>,
    declaration_files: HashMap<String, HashSet<ProjectFile>>,
    direct_member_files: HashMap<String, HashSet<ProjectFile>>,
    stable_singletons: HashSet<String>,
    package_namespaces: Vec<String>,
    export_dependencies: HashMap<ProjectFile, HashSet<ProjectFile>>,
}

impl ScalaFileDependencyIndex {
    fn build(
        analyzer: &ScalaAnalyzer,
        files: &[ProjectFile],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Option<Self> {
        let states = analyzer.bulk_file_states(files.iter().cloned(), BulkFileStateSource::Omit);
        if cancellation.is_cancelled() {
            return None;
        }
        let scala_file_count = files
            .iter()
            .filter(|file| file_language(file) == Language::Scala)
            .count();
        if states.len() != scala_file_count {
            return None;
        }

        let mut index = Self::default();
        let mut export_sources = Vec::new();
        for (file, state) in &states {
            if cancellation.is_cancelled() {
                return None;
            }
            index
                .package_by_file
                .insert(file.clone(), state.package_name.clone());
            index
                .type_identifiers_by_file
                .insert(file.clone(), state.type_identifiers.clone());
            for declaration in &state.declarations {
                let normalized =
                    brokk_bifrost_jvm::scala::scala_normalize_full_name(&declaration.fq_name());
                index
                    .declaration_files
                    .entry(normalized.clone())
                    .or_default()
                    .insert(file.clone());
                if declaration.is_class() && declaration.fq_name().ends_with('$') {
                    index.stable_singletons.insert(normalized);
                }
                if is_scala_importable_top_level(declaration) {
                    index
                        .importable_files_by_package
                        .entry(declaration.package_name().to_string())
                        .or_default()
                        .insert(file.clone());
                    index
                        .same_package_declarations_by_name
                        .entry(declaration.package_name().to_string())
                        .or_default()
                        .entry(
                            brokk_bifrost_jvm::scala::scala_short_name_terminal_segment(
                                declaration.short_name(),
                            )
                            .trim_end_matches('$')
                            .to_string(),
                        )
                        .or_default()
                        .insert(file.clone());
                }
            }
            for (owner, children) in &state.children {
                let owner = brokk_bifrost_jvm::scala::scala_normalize_full_name(&owner.fq_name());
                for child in children
                    .iter()
                    .filter(|child| is_scala_importable_direct_member(child))
                {
                    index
                        .direct_member_files
                        .entry(owner.clone())
                        .or_default()
                        .insert(child.source().clone());
                }
            }
            if !state.scala_exports.is_empty() {
                export_sources.push((
                    file.clone(),
                    state.package_name.clone(),
                    state.imports.clone(),
                    state
                        .scala_exports
                        .values()
                        .flatten()
                        .map(|export| export.owner_path.clone())
                        .collect::<Vec<_>>(),
                ));
            }
        }
        index.package_namespaces = index.importable_files_by_package.keys().cloned().collect();
        index.package_namespaces.sort_unstable();

        for (file, package, imports, export_paths) in export_sources {
            if cancellation.is_cancelled() {
                return None;
            }
            let mut dependencies = index.resolve_imports(&file, &imports);
            for owner_path in export_paths {
                let rendered = owner_path.join(".");
                for candidate in
                    scala_import_path_candidates(&rendered, std::slice::from_ref(&package))
                {
                    dependencies.extend(index.declaration_files(&candidate));
                }
            }
            if dependencies.is_empty() {
                dependencies.extend(
                    index
                        .same_package_declarations_by_name
                        .get(&package)
                        .into_iter()
                        .flat_map(HashMap::values)
                        .flatten()
                        .cloned(),
                );
            }
            dependencies.remove(&file);
            if !dependencies.is_empty() {
                index.export_dependencies.insert(file, dependencies);
            }
        }
        Some(index)
    }

    fn package_exists(&self, candidate: &str) -> bool {
        let descendant_prefix = format!("{candidate}.");
        let index = self
            .package_namespaces
            .partition_point(|package| package.as_str() < candidate);
        self.package_namespaces
            .get(index)
            .is_some_and(|package| package == candidate || package.starts_with(&descendant_prefix))
    }

    fn declaration_files(&self, candidate: &str) -> impl Iterator<Item = ProjectFile> + '_ {
        let candidate = brokk_bifrost_jvm::scala::scala_normalize_full_name(candidate);
        self.declaration_files
            .get(&candidate)
            .into_iter()
            .flatten()
            .cloned()
    }

    fn files_in_package_tree(&self, package: &str) -> HashSet<ProjectFile> {
        let descendant_prefix = format!("{package}.");
        let start = self
            .package_namespaces
            .partition_point(|candidate| candidate.as_str() < package);
        let mut files = HashSet::default();
        for candidate in self.package_namespaces[start..]
            .iter()
            .take_while(|candidate| {
                candidate.as_str() == package || candidate.starts_with(&descendant_prefix)
            })
        {
            files.extend(
                self.importable_files_by_package
                    .get(candidate)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
        }
        files
    }

    fn declaration_owner_files(
        &self,
        info: &ImportInfo,
        package_prefixes: &[String],
    ) -> HashSet<ProjectFile> {
        let Some(path) = info.path.as_ref() else {
            return HashSet::default();
        };
        for prefix_len in (1..path.segments.len()).rev() {
            let rendered = path.segments[..prefix_len].join(".");
            let mut files = HashSet::default();
            for candidate in scala_import_path_candidates(&rendered, package_prefixes) {
                files.extend(self.declaration_files(&candidate));
            }
            if !files.is_empty() {
                return files;
            }
        }
        HashSet::default()
    }

    fn owner_facts(&self, candidate: &str) -> ScalaWildcardOwnerFacts {
        let normalized = brokk_bifrost_jvm::scala::scala_normalize_full_name(candidate);
        ScalaWildcardOwnerFacts {
            package: self.importable_files_by_package.contains_key(candidate),
            stable_singleton: self.stable_singletons.contains(&normalized),
        }
    }

    fn resolve_imports(&self, file: &ProjectFile, imports: &[ImportInfo]) -> HashSet<ProjectFile> {
        let Some(source_package) = self.package_by_file.get(file) else {
            return HashSet::default();
        };
        let wildcard_environment = resolve_scala_wildcard_import_environment(
            imports,
            std::slice::from_ref(source_package),
            |_| Vec::new(),
            |candidate| self.owner_facts(candidate),
        );
        let mut imported = HashSet::default();
        for (import_index, info) in imports.iter().enumerate() {
            let Some(path) = scala_import_path(info) else {
                continue;
            };
            if info.is_wildcard {
                for owner in wildcard_environment
                    .owners
                    .iter()
                    .filter(|owner| owner.import_index == import_index)
                {
                    match owner.kind {
                        ScalaWildcardOwnerKind::Package => {
                            imported.extend(
                                self.importable_files_by_package
                                    .get(&owner.fqn)
                                    .into_iter()
                                    .flatten()
                                    .cloned(),
                            );
                        }
                        ScalaWildcardOwnerKind::StableSingleton => {
                            let normalized = brokk_bifrost_jvm::scala::scala_normalize_full_name(
                                &owner.declaration_fqn(),
                            );
                            imported.extend(self.declaration_files(&normalized));
                            imported.extend(
                                self.direct_member_files
                                    .get(&normalized)
                                    .into_iter()
                                    .flatten()
                                    .cloned(),
                            );
                        }
                    }
                }
                continue;
            }
            let package_prefixes = info
                .path
                .as_ref()
                .map(|path| path.lexical_prefixes.as_slice())
                .filter(|prefixes| !prefixes.is_empty())
                .unwrap_or(std::slice::from_ref(source_package));
            let Some(tier) =
                resolve_scala_explicit_import_tier(&path, package_prefixes, |candidate| {
                    ScalaExplicitImportFacts {
                        declaration: self.declaration_files(candidate).next().is_some(),
                        package: self.package_exists(candidate),
                    }
                })
            else {
                imported.extend(self.declaration_owner_files(info, package_prefixes));
                continue;
            };
            if tier.declaration {
                imported.extend(self.declaration_files(&tier.candidate));
            }
            if tier.package {
                imported.extend(self.files_in_package_tree(&tier.candidate));
            }
        }
        imported.remove(file);
        imported
    }
}

impl ScalaAnalyzer {
    fn resolve_import_info(
        &self,
        token: QueryToken<'_>,
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
                imported.extend(self.resolve_wildcard_owner(token, owner));
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

    fn resolve_wildcard_owner(
        &self,
        token: QueryToken<'_>,
        owner: &ScalaWildcardImportOwner,
    ) -> Vec<CodeUnit> {
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
                    for (_, target_fqn) in
                        self.project_types()
                            .exported_member_bindings(self, token, &declaration)
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

    fn importable_declarations_by_package(&self) -> Arc<HashMap<String, Arc<Vec<CodeUnit>>>> {
        self.importable_declarations_by_package.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || {
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
                    },
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        )
    }

    fn package_namespaces(&self) -> Arc<Vec<String>> {
        self.package_namespaces.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || {
                        let mut packages = self
                            .importable_declarations_by_package()
                            .keys()
                            .cloned()
                            .collect::<Vec<_>>();
                        packages.sort_unstable();
                        packages
                    },
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        )
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
        self.same_package_reference_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_pool(
                    self,
                    memo,
                    || self.compute_same_package_reference_index(true),
                    || self.compute_same_package_reference_index(false),
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Java,
                    Language::Kotlin,
                    Language::Scala,
                ])
            },
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
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            brokk_bifrost_core::analyzer::capabilities::FileDependencyFacts,
        >,
    > {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        crate::analyzer::jvm::hierarchy::derived_read(&self.imported_code_units, self, file, || {
            if file_language(file) != Language::Scala {
                return (Arc::new(HashSet::default()), 0);
            }
            let imported = {
                let imports = self.inner.import_info_of(token, file);
                let wildcard_environment = self.wildcard_import_environment(file, &imports);
                let mut imported = HashSet::default();
                for (import_index, info) in imports.iter().enumerate() {
                    for code_unit in self.resolve_import_info(
                        token,
                        file,
                        import_index,
                        info,
                        &wildcard_environment,
                    ) {
                        imported.insert(code_unit);
                    }
                }
                imported
            };
            let imported = Arc::new(imported);
            let bytes =
                brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set(file, &imported)
                    as usize;
            (imported, bytes)
        })
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.referencing_files.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |cache| {
                if let Some(cached) = cache.get(file) {
                    return (*cached).clone();
                }
                if file_language(file) != Language::Scala {
                    return HashSet::default();
                }
                let cache_fill =
                    brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                let reverse_index = self.reverse_import_index.read(
                    &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
                    |memo| {
                        let parallel = || {
                            brokk_bifrost_core::analyzer::capabilities::build_reverse_import_index(
                                &self.inner.all_files(),
                                |candidate| self.imported_code_units_of(candidate),
                                true,
                            )
                        };
                        let serial = || {
                            brokk_bifrost_core::analyzer::capabilities::build_reverse_import_index(
                                &self.inner.all_files(),
                                |candidate| self.imported_code_units_of(candidate),
                                false,
                            )
                        };
                        brokk_bifrost_analysis::analyzer::common::complete_query_cache_pool(
                            self, memo, parallel, serial,
                        )
                    },
                    |_| {
                        brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(
                            &[Language::Java, Language::Kotlin, Language::Scala],
                        )
                    },
                );
                let mut result = reverse_index
                    .get(file)
                    .map(|files| (**files).clone())
                    .unwrap_or_default();
                if let Some(files) = self.same_package_reference_index().get(file) {
                    result.extend(files.iter().cloned());
                }

                if cache_fill.is_complete() {
                cache.insert(file.clone(), Arc::new(result.clone()));
                }
                result
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(
                    &[Language::Java, Language::Kotlin, Language::Scala],
                )
            },
        )
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Some(
            self.inner
                .bulk_import_facts(files.iter().cloned())
                .into_iter()
                .map(|(file, facts)| (file, facts.imports))
                .collect(),
        )
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.file_dependency_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| memo.get().map(|index| index.resolve_imports(file, imports)),
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        )
    }

    fn prefetch_file_dependency_targets(
        &self,
        files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) {
        self.file_dependency_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                if memo.get().is_none()
                    && let Some(index) =
                        brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                            self,
                            || ScalaFileDependencyIndex::build(self, files, cancellation),
                        )
                        .ok()
                        .flatten()
                {
                    let _ = memo.set(index);
                }
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        );
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Option<brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies> {
        self.file_dependency_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                let index = memo.get()?;
                let selected = files.iter().cloned().collect::<HashSet<_>>();
                let mut dependencies = HashMap::default();
                for file in files {
                    if cancellation.is_cancelled() {
                        return None;
                    }
                    let direct = dependencies
                        .entry(file.clone())
                        .or_insert_with(HashSet::default);
                    if let (Some(package), Some(identifiers)) = (
                        index.package_by_file.get(file),
                        index.type_identifiers_by_file.get(file),
                    ) && let Some(targets_by_name) =
                        index.same_package_declarations_by_name.get(package)
                    {
                        for identifier in identifiers {
                            direct.extend(
                                targets_by_name
                                    .get(identifier)
                                    .into_iter()
                                    .flatten()
                                    .filter(|target| *target != file && selected.contains(*target))
                                    .cloned(),
                            );
                        }
                    }
                    if let Some(exported) = index.export_dependencies.get(file) {
                        direct.extend(
                            exported
                                .iter()
                                .filter(|target| selected.contains(*target))
                                .cloned(),
                        );
                    }
                }
                Some(
                    brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies::complete(
                        dependencies,
                    ),
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(
                    &[Language::Scala],
                )
            },
        )
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        matches!(
            self.import_reachability(source_file, imports, target),
            ImportReachability::Reaches
        )
    }

    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        if source_file == target {
            return ImportReachability::DoesNotReach;
        }
        if file_language(source_file) != Language::Scala || file_language(target) != Language::Scala
        {
            return ImportReachability::Unknown;
        }

        let Some(source_package) = self.inner.package_name_of(source_file) else {
            return ImportReachability::Unknown;
        };
        let Some(target_package) = self.inner.package_name_of(target) else {
            return ImportReachability::Unknown;
        };
        let declarations = self.declarations(target);
        scala_import_reachability(
            imports,
            &source_package,
            &target_package,
            &declarations,
            |candidate| ScalaExplicitImportFacts {
                declaration: self.inner.definitions(candidate).next().is_some(),
                package: self.package_namespace_exists(candidate),
            },
        )
    }
}
