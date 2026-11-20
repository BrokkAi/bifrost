//! Java's `ImportAnalysisProvider` impl and the memo cells behind it, plus the
//! external half of type-name resolution.
//!
//! What an `import` declaration *says*, and how Java's import, wildcard and
//! same-package tiers decide a written type name, moved to
//! [`brokk_bifrost_jvm::java::imports`] and
//! [`brokk_bifrost_jvm::java::graph_support`]. The caching, the reverse import
//! index and the same-package reference index stay here because they read the
//! analyzer's own cells, and so does everything that consults
//! [`JvmExternalDeclarationIndex`]: that index imports `semantic_model` and
//! cannot cross the crate line.

use crate::analyzer::java::*;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use crate::analyzer::java::unshadowed::{
    EnclosingMemberType, JavaAnalyzerMemberTypeEnv, MemberTypeStep, UnshadowedScope, UseSite,
    enclosing_class_units_at, enclosing_member_type, resolve_accessible_member_types_of_owner,
};
use crate::analyzer::jvm::external::ExplicitImportHit;
use crate::analyzer::jvm::external::LazyExternal;

use crate::analyzer::jvm::external::JvmExternalMember;

use crate::analyzer::jvm::external::{LadderMisses, QueryGapRecorder};

use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

use brokk_bifrost_core::analyzer::structural::resolution::RejectionReason;

use brokk_bifrost_analysis::analyzer::usages::get_definition::trace;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::java::graph_support::{
    JavaTypeName, compute_java_relevant_imports, compute_java_same_package_reference_index,
    java_could_import_file, java_could_import_file_without_source, java_same_package_fqn,
    java_source_class_by_fqn, resolve_java_import_infos,
};
use brokk_bifrost_jvm::java::imports::{non_static_import_path, static_import_path};
use rayon::prelude::*;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JavaTypeResolution {
    Source(CodeUnit),
    /// An external type. Its witness, when it has one, proves that no missing
    /// dependency jar can change what the name means (see
    /// [`UnshadowedScope`]); member lookups on it then record only the gaps not
    /// attributed to a dependency artifact.
    External(ExplicitImportHit),
}

impl ImportAnalysisProvider for JavaAnalyzer {
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

    fn imported_code_units_of(
        &self,
        file: &ProjectFile,
    ) -> Arc<brokk_bifrost_core::retention_budget::Accounted<HashSet<CodeUnit>>> {
        brokk_bifrost_core::analyzer::capabilities::uncharged_imported_code_units(
            || -> HashSet<CodeUnit> {
                let scope = AnalyzerQueryScope::new(self);
                let token = scope.token();
                self.resolve_imports(token, file)
                    .values()
                    .cloned()
                    .collect()
            },
        )
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let mut imports_by_file = HashMap::default();
        for (file, facts) in self.inner.bulk_import_facts(files.iter().cloned()) {
            {
                let cache_key = file.clone();
                let cache_value = Arc::from(facts.package_name);
                if cache_fill.is_complete() {
                    self.memo_caches
                        .package_names
                        .insert(cache_key, cache_value);
                }
            };
            imports_by_file.insert(file, facts.imports);
        }
        Some(imports_by_file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaReferencingFiles,
        );

        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let reverse_index = self.reverse_import_index();
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        {
            let cache_key = file.clone();
            let cache_value = Arc::new(result.clone());
            if cache_fill.is_complete() {
                self.memo_caches
                    .referencing_files
                    .insert(cache_key, cache_value);
            }
        };
        result
    }

    fn referencing_files_of_targets(
        &self,
        targets: &HashSet<ProjectFile>,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> HashSet<ProjectFile> {
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let _scope =
            brokk_bifrost_core::profiling::scope("JavaAnalyzer::referencing_files_of_targets");
        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaReferencingFiles,
        );

        if targets.is_empty() || cancellation.is_cancelled() {
            return HashSet::default();
        }

        let mut result = HashSet::default();
        let mut uncached_targets = HashSet::default();
        for target in targets {
            if let Some(cached) = self.memo_caches.referencing_files.get(target) {
                result.extend(cached.iter().cloned());
            } else {
                uncached_targets.insert(target.clone());
            }
        }
        if uncached_targets.is_empty() {
            return result;
        }

        // The cheap half of Java reverse-import resolution is exact and fully
        // structured: an explicit import path must equal a class FQN, while a
        // wildcard path must equal its package. Only candidates that pass one
        // of those tests pay the existing resolver to settle shadowing and
        // duplicate-name precedence. This is the seed-directed distinction:
        // unrelated workspace files never perform definition lookup.
        let (
            exact_targets,
            wildcard_targets,
            explicit_import_segments,
            wildcard_import_segments,
            same_package_targets,
        ) = {
            let _scope = brokk_bifrost_core::profiling::scope("JavaAnalyzer::reverse.target_keys");
            let mut exact_targets = HashSet::default();
            let mut wildcard_targets = HashSet::default();
            let mut explicit_import_segments = HashSet::default();
            let mut wildcard_import_segments = HashSet::default();
            let mut same_package_targets: HashMap<String, HashMap<String, HashSet<ProjectFile>>> =
                HashMap::default();
            for target in &uncached_targets {
                for declaration in self.get_declarations(target) {
                    if !declaration.is_class() {
                        continue;
                    }
                    exact_targets.insert(declaration.fq_name());
                    wildcard_targets.insert(declaration.package_name().to_string());
                    explicit_import_segments.insert(declaration.terminal_name().to_string());
                    if let Some(segment) = declaration.package_terminal_name() {
                        wildcard_import_segments.insert(segment.to_string());
                    }
                }
                let package = java_package_name_of(self, target).unwrap_or_default();
                for declaration in self.top_level_declarations(target) {
                    if declaration.is_class() || declaration.is_module() {
                        same_package_targets
                            .entry(package.clone())
                            .or_default()
                            .entry(declaration.terminal_name().to_string())
                            .or_default()
                            .insert(target.clone());
                    }
                }
            }
            (
                exact_targets,
                wildcard_targets,
                explicit_import_segments,
                wildcard_import_segments,
                same_package_targets,
            )
        };

        let same_package_identifiers = same_package_targets
            .values()
            .flat_map(HashMap::keys)
            .cloned()
            .collect::<HashSet<_>>();
        let plausible = {
            let _scope =
                brokk_bifrost_core::profiling::scope("JavaAnalyzer::reverse.candidate_lookup");
            self.inner.reverse_reference_candidates(
                &explicit_import_segments,
                &wildcard_import_segments,
                &same_package_identifiers,
                cancellation,
            )
        };
        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        let plausible = plausible.into_iter().collect::<Vec<_>>();

        // The indexed lookup above is only a superset filter. Hydrate the
        // surviving files and retain the complete structured-path and Java
        // precedence checks below for the exact result.
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "JavaAnalyzer::reverse uncached_targets={uncached_targets:?} \
                 exact_targets={exact_targets:?} wildcard_targets={wildcard_targets:?} \
                 same_package_targets={same_package_targets:?} plausible={plausible:?}"
            )
        });
        let imports_by_file = {
            let _scope = brokk_bifrost_core::profiling::scope("JavaAnalyzer::reverse.import_facts");
            let Some(imports_by_file) = self.import_infos_for_files(&plausible) else {
                return result;
            };
            imports_by_file
        };
        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        let same_packages: HashSet<String> = same_package_targets.keys().cloned().collect();
        let identifiers_by_file = {
            let _scope =
                brokk_bifrost_core::profiling::scope("JavaAnalyzer::reverse.type_identifiers");
            self.inner.bulk_type_identifiers(
                plausible
                    .iter()
                    .filter(|candidate| {
                        java_package_name_of(self, candidate)
                            .is_some_and(|package| same_packages.contains(&package))
                    })
                    .cloned(),
            )
        };
        let target_set = &uncached_targets;

        let context = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        let matches = {
            let _scope =
                brokk_bifrost_core::profiling::scope("JavaAnalyzer::reverse.exact_verification");
            plausible
                .par_iter()
                .filter_map(|candidate| {
                    context.run(|| {
                        if cancellation.is_cancelled() {
                            return None;
                        }
                        let imports = imports_by_file.get(candidate)?;
                        let package = java_package_name_of(self, candidate).unwrap_or_default();
                        let mut matched = HashSet::default();

                        if let Some(identifiers) = identifiers_by_file.get(candidate) {
                            let targets_by_identifier = same_package_targets
                                .get(&package)
                                .expect("bulk type identifiers were restricted to seed packages");
                            for identifier in identifiers {
                                if let Some(matching_targets) =
                                    targets_by_identifier.get(identifier)
                                {
                                    matched.extend(matching_targets.iter().cloned());
                                }
                            }
                        }

                        let could_resolve_to_target = imports.iter().any(|import| {
                            let Some(path) = non_static_import_path(import) else {
                                return false;
                            };
                            let path = path.render_segments(".");
                            if import.is_wildcard {
                                wildcard_targets.contains(&path)
                            } else {
                                exact_targets.contains(&path)
                            }
                        });
                        if could_resolve_to_target {
                            let resolved = self
                                .imported_code_units_from_infos(candidate, imports)
                                .expect("Java resolves already-loaded import facts");
                            matched.extend(
                                resolved
                                    .iter()
                                    .map(CodeUnit::source)
                                    .filter(|source| target_set.contains(*source))
                                    .cloned(),
                            );
                        }

                        (!matched.is_empty()).then_some((candidate.clone(), matched))
                    })
                })
                .collect::<Vec<_>>()
        };

        if cancellation.is_cancelled() {
            return HashSet::default();
        }
        let mut computed: HashMap<ProjectFile, HashSet<ProjectFile>> = uncached_targets
            .iter()
            .cloned()
            .map(|target| (target, HashSet::default()))
            .collect();
        for (candidate, matched_targets) in matches {
            for target in matched_targets {
                computed
                    .get_mut(&target)
                    .expect("matched Java target came from the requested set")
                    .insert(candidate.clone());
            }
        }
        for (target, referencing) in computed {
            result.extend(referencing.iter().cloned());
            {
                let cache_key = target;
                let cache_value = Arc::new(referencing);
                if cache_fill.is_complete() {
                    self.memo_caches
                        .referencing_files
                        .insert(cache_key, cache_value);
                }
            };
        }
        result
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        let scope = AnalyzerQueryScope::new(self);
        Some(Arc::new(
            self.resolve_import_infos(scope.token(), imports)
                .into_values()
                .collect(),
        ))
    }

    fn imported_files_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let wildcard_packages = imports
            .iter()
            .filter_map(|import| {
                import
                    .is_wildcard
                    .then(|| non_static_import_path(import))
                    .flatten()
                    .map(|path| path.render_segments("."))
            })
            .collect::<Vec<_>>();
        let types_by_package =
            <Self as JavaSource>::source_types_in_packages(self, token, &wildcard_packages);
        let mut files = HashSet::default();
        for import in imports {
            if let Some(package) = import
                .is_wildcard
                .then(|| non_static_import_path(import))
                .flatten()
                .map(|path| path.render_segments("."))
            {
                files.extend(
                    types_by_package
                        .get(&package)
                        .into_iter()
                        .flatten()
                        .map(|unit| unit.source().clone()),
                );
                continue;
            }
            let Some(fqn) = java_import_dependency_fqn(import) else {
                continue;
            };
            files.extend(
                self.inner
                    .definitions(&fqn)
                    .map(|unit| unit.source().clone()),
            );
        }
        Some(files)
    }

    fn prefetch_file_dependency_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let mut definitions = Vec::new();
        for file in files {
            if cancellation.is_cancelled() {
                return;
            }
            let owned_imports;
            let imports = match import_infos {
                Some(all) => {
                    let Some(imports) = all.get(file) else {
                        continue;
                    };
                    imports.as_slice()
                }
                None => {
                    owned_imports = self.inner.import_info_of(token, file);
                    &owned_imports
                }
            };
            definitions.extend(imports.iter().filter_map(java_import_dependency_fqn));
        }
        definitions.sort_unstable();
        definitions.dedup();
        self.inner.prefetch_definitions(&definitions);
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Option<brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies> {
        let selected = files.iter().cloned().collect::<HashSet<_>>();
        let packages = self.inner.bulk_import_facts(files.iter().cloned());
        let identifiers = self.inner.bulk_type_identifiers(files.iter().cloned());
        let mut targets_by_package_and_name: HashMap<String, HashMap<String, Vec<ProjectFile>>> =
            HashMap::default();
        for declaration in self.inner.all_declarations() {
            if cancellation.is_cancelled() {
                return None;
            }
            if declaration.is_class()
                && declaration.short_name() == declaration.identifier()
                && selected.contains(declaration.source())
            {
                targets_by_package_and_name
                    .entry(declaration.package_name().to_string())
                    .or_default()
                    .entry(declaration.identifier().to_string())
                    .or_default()
                    .push(declaration.source().clone());
            }
        }
        let mut dependencies: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
        for source in files {
            if cancellation.is_cancelled() {
                return None;
            }
            let Some(package) = packages
                .get(source)
                .map(|facts| facts.package_name.as_str())
            else {
                continue;
            };
            for identifier in identifiers.get(source).into_iter().flatten() {
                let Some(targets) = targets_by_package_and_name
                    .get(package)
                    .and_then(|by_name| by_name.get(identifier))
                else {
                    continue;
                };
                dependencies
                    .entry(source.clone())
                    .or_default()
                    .extend(targets.iter().filter(|target| *target != source).cloned());
            }
        }
        Some(
            brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies::complete(
                dependencies,
            ),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let matched = crate::analyzer::jvm::hierarchy::derived_read(
            &self.memo_caches.relevant_imports,
            self,
            code_unit,
            || {
                let matched = Arc::new(compute_java_relevant_imports(self, token, code_unit));
                let bytes = super::cache::weight_string_set(code_unit, &matched) as usize;
                (matched, bytes)
            },
        );
        (*matched).clone()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        java_could_import_file(self, source_file, imports, target)
    }
}

impl TestDetectionProvider for JavaAnalyzer {}

fn java_import_dependency_fqn(import: &ImportInfo) -> Option<String> {
    if let Some(path) = non_static_import_path(import) {
        return (!import.is_wildcard).then(|| path.render_segments("."));
    }
    let path = static_import_path(import)?;
    let owner_segments = if import.is_wildcard {
        path.segments.as_slice()
    } else {
        path.segments.split_last()?.1
    };
    (!owner_segments.is_empty()).then(|| owner_segments.join("."))
}

impl JavaAnalyzer {
    pub(super) fn reverse_import_index(
        &self,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaReverseImports,
        );
        brokk_bifrost_analysis::analyzer::common::complete_query_cache_pool(
            self,
            &self.memo_caches.reverse_import_index,
            || {
                brokk_bifrost_core::analyzer::capabilities::build_reverse_import_index(
                    &(self.inner.all_files()),
                    |candidate| self.imported_code_units_of(candidate),
                    true,
                )
            },
            || {
                brokk_bifrost_core::analyzer::capabilities::build_reverse_import_index(
                    &(self.inner.all_files()),
                    |candidate| self.imported_code_units_of(candidate),
                    false,
                )
            },
        )
    }

    pub(crate) fn same_package_reference_index(
        &self,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::jvm::authority::source_read(
            self,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaSamePackageReferences,
        );

        brokk_bifrost_analysis::analyzer::common::complete_query_cache_pool(
            self,
            &self.memo_caches.same_package_reference_index,
            || compute_java_same_package_reference_index(self, true),
            || compute_java_same_package_reference_index(self, false),
        )
    }

    pub fn could_import_file_without_source(
        &self,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        java_could_import_file_without_source(self, imports, target)
    }

    pub(crate) fn resolve_imports(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<HashMap<String, CodeUnit>> {
        crate::analyzer::jvm::hierarchy::derived_read(
            &self.memo_caches.resolved_imports,
            self,
            file,
            || {
                let resolved = Arc::new(self.resolve_imports_uncached(token, file));
                let bytes = super::cache::weight_import_map(file, &resolved) as usize;
                (resolved, bytes)
            },
        )
    }

    fn resolve_imports_uncached(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> HashMap<String, CodeUnit> {
        let imports = self.inner.import_info_of(token, file);
        let resolved = self.resolve_import_infos(token, &imports);
        // The memo above answers from workspace sources only. A single-type
        // import that no workspace class satisfies is an entry a missing
        // dependency jar could satisfy: it may hold the class, or a class
        // whose member the path names, so the alternative package-prefix
        // splits stay open. A `java.*` path is not such an entry, because no
        // jar can supply or split a `java.*` package. The index's gaps are
        // recorded here, in the fill, so a reader of this file's imports gets
        // them from the memo's receipt and only a file that writes such an
        // entry pays for them (#10470).
        let open_entry = imports.iter().any(|import| {
            !import.is_wildcard
                && non_static_import_path(import).is_some_and(|path| {
                    path.segments.first().is_some_and(|first| first != "java")
                        && import
                            .identifier
                            .as_deref()
                            .is_none_or(|identifier| !resolved.contains_key(identifier))
                })
        });
        if open_entry {
            QueryGapRecorder::new(self).whole_index(&self.external_declaration_index());
        }
        resolved
    }

    pub(crate) fn resolve_import_infos(
        &self,
        token: QueryToken<'_>,
        imports: &[ImportInfo],
    ) -> HashMap<String, CodeUnit> {
        resolve_java_import_infos(self, token, imports)
    }

    /// Resolve `raw_name` in `file` against the workspace and then the external
    /// declaration surface.
    ///
    /// `packs` is the *dispatching* analyzer's activated semantic-model overlay,
    /// passed in for the same reason `collect_java_semantic_diagnostics` takes
    /// it as a parameter: activation publishes onto the analyzer a host asked,
    /// which in a mixed JVM workspace is the `MultiAnalyzer` and never this Java
    /// delegate. A caller that has no dispatching analyzer in hand passes
    /// `None` and reads the artifact half alone.
    pub(crate) fn resolve_type_name_with_external(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<JavaTypeResolution> {
        self.resolve_type_name_with_selected_jdk(token, packs, file, raw_name, None)
    }

    pub(crate) fn resolve_type_name_with_selected_jdk(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
        selected_jdk_artifact_sha256: Option<&str>,
    ) -> Option<JavaTypeResolution> {
        let name = JavaTypeName::from_normalized_spelling(raw_name)?;
        self.resolve_type_name_at(
            token,
            packs,
            file,
            &name,
            selected_jdk_artifact_sha256,
            None,
        )
    }

    /// Resolve a written type name through one ladder in Java's order (JLS 6.4.1
    /// and 6.5.2).
    ///
    /// The first segment of the name is bound first, by: single-type imports
    /// (a single-static-import of a member type counts as one), then types of
    /// the same package, then one on-demand tier that holds every on-demand
    /// import, every static-import-on-demand's member types and `java.lang`.
    /// When the first segment names a type, the rest of the name is a chain of
    /// member types of that type, and the package-qualified reading is not
    /// attempted: Java does not consider it. When the first segment names no
    /// type, the whole name is read as a package-qualified type.
    ///
    /// Three outcomes end the ladder with no resolution, because the code knows
    /// that a lower tier's answer would be wrong or undecided: a single-type
    /// import that binds the name but whose target nothing supplies (a bound
    /// miss), two single-type imports or two on-demand candidates that bind
    /// different types (an ambiguity, a compile error), and an inherited member
    /// type that the ladder cannot resolve. Each records every gap the index
    /// carries and an independent reason, because the index has nothing to say
    /// when every dependency is present, and incompleteness and ambiguity must
    /// be reported.
    ///
    /// This differs on purpose from a supertype the index cannot inspect (it
    /// comes from a missing jar). That supertype only might declare a competing
    /// binding, so the best structured target is still returned, with every gap
    /// recorded. Turning "might shadow" into a stop, or "known to shadow" into
    /// a best-effort target, would each lose information.
    ///
    /// Every external lookup in the ladder, `java.lang` included, records every
    /// gap: a name found through the implicit import is hidden by a same-package
    /// type, and a non-JDK package can be split across jars, so no missing jar
    /// can be ruled out without a classpath model.
    pub(crate) fn resolve_type_name_at(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &JavaTypeName,
        selected_jdk_artifact_sha256: Option<&str>,
        site: Option<&UseSite<'_>>,
    ) -> Option<JavaTypeResolution> {
        match self.resolve_type_name_outcome_at(
            token,
            packs,
            file,
            name,
            selected_jdk_artifact_sha256,
            site,
        ) {
            TypeNameOutcome::Resolved(resolution) => Some(resolution),
            TypeNameOutcome::BoundMiss | TypeNameOutcome::Stopped | TypeNameOutcome::Unbound => {
                None
            }
        }
    }

    /// [`Self::resolve_type_name_at`] with the reason a name did not resolve: the
    /// ladder stopped on a bound miss, an ambiguity or an unresolved inherited
    /// member type (and recorded why), or nothing binds the name.
    pub(crate) fn resolve_type_name_outcome_at(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &JavaTypeName,
        selected_jdk_artifact_sha256: Option<&str>,
        site: Option<&UseSite<'_>>,
    ) -> TypeNameOutcome {
        self.with_type_ladder(
            token,
            packs,
            file,
            name,
            selected_jdk_artifact_sha256,
            site,
            |ladder| ladder.resolve(name),
        )
    }

    /// Whether the simple type name written at `site` can be bound only by
    /// Java's implicit `java.lang.*` import (JLS 6.4.1, 7.3), so a caller may
    /// read it as `java.lang.<name>` without any declaration of that type.
    ///
    /// The name must bind to nothing at the ladder's single-type, scope and
    /// same-package tiers, and `names_only_through_implicit_java_lang` must
    /// show that no on-demand import, type parameter, enclosing member type,
    /// dependency gap or platform override could bind it instead. Every other
    /// case, including an ambiguity or a stop, answers `false`.
    pub(crate) fn names_only_through_implicit_java_lang(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &JavaTypeName,
        site: &UseSite<'_>,
    ) -> bool {
        if name.is_dotted() {
            return false;
        }
        self.with_type_ladder(
            token,
            packs.clone(),
            file,
            name,
            None,
            Some(site),
            |ladder| {
                // `bind` also reads the on-demand tier, which holds `java.lang`
                // itself: a name found there is not unbound, and with no JDK the
                // tier finds nothing, which is the case this answers.
                matches!(ladder.bind(name.first()), NameBinding::Unbound)
                    && super::unshadowed::names_only_through_implicit_java_lang(
                        self,
                        packs,
                        None,
                        ladder.external.get(),
                        file,
                        site,
                        name.first(),
                    )
            },
        )
    }

    #[allow(clippy::too_many_arguments)] // The ladder's full lookup state.
    fn with_type_ladder<R>(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &JavaTypeName,
        selected_jdk_artifact_sha256: Option<&str>,
        site: Option<&UseSite<'_>>,
        read: impl FnOnce(&TypeLadder<'_, '_, '_>) -> R,
    ) -> R {
        let recorder = QueryGapRecorder::new(self);
        let surface_recorder = match site {
            Some(site) => recorder.at_type_lookup(
                file,
                site.node.byte_range(),
                name,
                LookupTier::ExternalSurface.label(),
            ),
            None => recorder,
        };
        let surface_empty = std::cell::Cell::new(false);
        let external = LazyExternal::deferred(|| {
            let external = match selected_jdk_artifact_sha256 {
                Some(digest) => self.external_declarations_for_source_jdk(packs.clone(), digest),
                None => self.external_declarations(packs.clone()),
            };
            // Only an actual external step owns these gaps. Preparing a source
            // answer must not make an unrelated missing jar its dependency.
            surface_empty.set(external.empty_surface(&surface_recorder));
            external
        });
        let access_package = self.package_name_of(file).unwrap_or_default();
        let ladder = TypeLadder {
            java: self,
            token,
            packs: packs.clone(),
            selected_jdk_artifact_sha256,
            file,
            external: &external,
            recorder: &recorder,
            misses: LadderMisses::default(),
            access_package: &access_package,
            surface_empty: &surface_empty,
            imports: self.inner.import_info_of(token, file),
            site,
        };
        read(&ladder)
    }

    /// The FQN a file's explicit non-static single-type import binds to
    /// `simple_name`.
    ///
    /// An `import java.net.URLDecoder;` is file-local structured evidence that
    /// `URLDecoder` is `java.net.URLDecoder`. The jar index and activated
    /// overlay are not required. Wildcard and static imports do not answer:
    /// they need the declaration surface to name the member.
    ///
    /// Two explicit imports of the same simple name are a compile error in
    /// Java. If they appear anyway, this returns nothing rather than picking
    /// one.
    pub(crate) fn explicit_imported_type_fqn(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        simple_name: &str,
    ) -> Option<String> {
        if simple_name.is_empty() || simple_name.contains('.') {
            return None;
        }
        let mut match_fqn = None;
        for import in self.inner.import_info_of(token, file) {
            if import.is_wildcard {
                continue;
            }
            // A single-static-import of the name may bind a member type instead
            // of the single-type import (JLS 6.4.1), so the name has no single
            // file-local owner.
            if import.identifier.as_deref() == Some(simple_name)
                && static_import_path(&import).is_some()
            {
                return None;
            }
            let Some(import_path) = non_static_import_path(&import) else {
                continue;
            };
            if import.identifier.as_deref() != Some(simple_name) {
                continue;
            }
            let fqn = import_path.render_segments(".");
            if !fqn.contains('.') {
                continue;
            }
            match match_fqn.as_deref() {
                Some(existing) if existing == fqn => {}
                Some(_) => return None,
                None => match_fqn = Some(fqn),
            }
        }
        match_fqn
    }

    /// Resolve `raw_name` in `file` as a member spelling -- a written
    /// `Owner.member` whose head is a type and whose last segment is a member
    /// the external declaration surface declares (#1900).
    ///
    /// This runs only after [`JavaAnalyzer::resolve_type_name_with_external`]
    /// has failed, because the same written dot spells a nested type, and a
    /// nested type is decided by the type ladder. The owner is resolved through
    /// that very ladder, so a member reaches the same declaration a type
    /// spelling would; a workspace owner answers nothing here, because a
    /// workspace type's members are indexed and the resolver found them or did
    /// not.
    ///
    /// `packs` reaches here for the same reason it reaches
    /// [`JavaAnalyzer::resolve_type_name_with_external`]: activation publishes
    /// onto the dispatching analyzer, never onto this Java delegate.
    pub(crate) fn resolve_member_name_with_external(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<JvmExternalMember> {
        self.resolve_member_name_with_selected_jdk(token, packs, file, raw_name, None)
    }

    pub(crate) fn resolve_member_name_with_selected_jdk(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
        selected_jdk_artifact_sha256: Option<&str>,
    ) -> Option<JvmExternalMember> {
        self.resolve_member_name_at(
            token,
            packs,
            file,
            raw_name,
            selected_jdk_artifact_sha256,
            None,
        )
    }

    /// The member `member_name` of an owner the type ladder already resolved. A
    /// witness-backed owner records only the gaps not attributed to a dependency
    /// artifact; any other owner records every gap.
    pub(crate) fn resolve_member_of_hit(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        owner: &ExplicitImportHit,
        member_name: &str,
        selected_jdk_artifact_sha256: Option<&str>,
    ) -> Option<JvmExternalMember> {
        let external = match selected_jdk_artifact_sha256 {
            Some(digest) => self.external_declarations_for_source_jdk(packs, digest),
            None => self.external_declarations(packs),
        };
        let recorder = QueryGapRecorder::new(self);
        let access_package = self.package_name_of(file).unwrap_or_default();
        match owner.witness() {
            Some(witness) => external.resolve_member_of_unshadowed_owner(
                &recorder,
                witness,
                member_name,
                &access_package,
            ),
            None => {
                external.resolve_member_of_owner(&recorder, owner, member_name, &access_package)
            }
        }
    }

    /// Resolve `Owner.member`. The owner is resolved through the type ladder at
    /// `site`; when that gives a witness-backed owner, the member lookup records
    /// only the gaps not attributed to a dependency artifact, and otherwise it
    /// records every gap.
    pub(crate) fn resolve_member_name_at(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
        selected_jdk_artifact_sha256: Option<&str>,
        site: Option<&UseSite<'_>>,
    ) -> Option<JvmExternalMember> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }
        let external = match selected_jdk_artifact_sha256 {
            Some(digest) => self.external_declarations_for_source_jdk(packs.clone(), digest),
            None => self.external_declarations(packs.clone()),
        };
        let recorder = QueryGapRecorder::new(self);
        if external.empty_surface(&recorder) {
            return None;
        }
        let access_package = self.package_name_of(file).unwrap_or_default();
        // `Owner.member` is a canonical or already-normalized spelling: the
        // member is its last segment and the owner is read as a type name.
        let (owner_spelling, member_name) = normalized.rsplit_once('.')?;
        if member_name.is_empty() {
            return None;
        }
        let owner = JavaTypeName::from_normalized_spelling(owner_spelling)?;
        let JavaTypeResolution::External(hit) = self.resolve_type_name_at(
            token,
            packs,
            file,
            &owner,
            selected_jdk_artifact_sha256,
            site,
        )?
        else {
            return None;
        };
        match hit.witness() {
            Some(witness) => external.resolve_member_of_unshadowed_owner(
                &recorder,
                witness,
                member_name,
                &access_package,
            ),
            None => external.resolve_member_of_owner(&recorder, &hit, member_name, &access_package),
        }
    }
}

/// What the type ladder made of a written name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeNameOutcome {
    Resolved(JavaTypeResolution),
    /// A single-type import binds the name and nothing supplies its target. The
    /// import still names the type structurally, so a caller may read the
    /// import's canonical name; no lower tier may answer. The index's gaps and
    /// the independent reason are already recorded.
    BoundMiss,
    /// The name is bound to something the ladder cannot name: an ambiguity, or
    /// an inherited member type or type parameter that shadows every import. No
    /// caller may name a type for it. The index's gaps and the independent
    /// reason are already recorded.
    Stopped,
    /// Nothing binds the name as a type.
    Unbound,
}

impl TypeNameOutcome {
    fn from_option(resolution: Option<JavaTypeResolution>) -> Self {
        resolution.map_or(Self::Unbound, Self::Resolved)
    }
}

/// Marker returned when projecting a `.Member` segment stopped the type ladder
/// on an ambiguous or incomplete workspace member-type hierarchy.
struct MemberTypeStopped;

/// What binding one simple name found.
enum NameBinding {
    Hit(JavaTypeResolution),
    BoundMiss,
    /// The name is bound, but not to anything the ladder can name. The index's
    /// gaps and the independent reason are already recorded.
    Stopped,
    /// No scope, import, package or on-demand tier binds the name as a type.
    Unbound,
}

/// Java resolution phases supplied at the consuming external read (#10984).
#[derive(Clone, Copy)]
enum LookupTier {
    ExternalSurface,
    PackageQualified,
    MemberType,
    ExplicitImport,
    SamePackage,
    OnDemand,
    Outcome,
}
impl LookupTier {
    fn label(self) -> &'static str {
        match self {
            Self::ExternalSurface => "external-surface",
            Self::PackageQualified => "package-qualified",
            Self::MemberType => "member-type",
            Self::ExplicitImport => "explicit-import",
            Self::SamePackage => "same-package",
            Self::OnDemand => "on-demand",
            Self::Outcome => "ladder-outcome",
        }
    }
}

/// One type-name lookup's state: what the ladder reads at every tier.
struct TypeLadder<'a, 'q, 'x> {
    java: &'a JavaAnalyzer,
    token: QueryToken<'q>,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&'a str>,
    file: &'a ProjectFile,
    external: &'a LazyExternal<'x>,
    recorder: &'a QueryGapRecorder<'a>,
    /// The external rungs this ladder probed and missed.
    misses: LadderMisses,
    access_package: &'a str,
    surface_empty: &'a std::cell::Cell<bool>,
    imports: Vec<ImportInfo>,
    /// Where the name is written, when the caller holds a node. Without it the
    /// ladder cannot read lexical scope, so it never applies the reduced gap
    /// rule and every external lookup records every gap.
    site: Option<&'a UseSite<'q>>,
}

fn resolution_fqn(resolution: &JavaTypeResolution) -> String {
    match resolution {
        JavaTypeResolution::Source(unit) => unit.fq_name(),
        JavaTypeResolution::External(external_type) => external_type.fqn().to_owned(),
    }
}

impl TypeLadder<'_, '_, '_> {
    fn surface_empty(&self) -> bool {
        self.external.get();
        self.surface_empty.get()
    }

    fn lookup_recorder<'a>(&'a self, name: &'a str, tier: LookupTier) -> QueryGapRecorder<'a> {
        match self.site {
            Some(site) => {
                self.recorder
                    .at_lookup(self.file, site.node.byte_range(), name, tier.label())
            }
            None => *self.recorder,
        }
    }

    /// The ladder's final outcome records the gaps its rungs leave open: a
    /// miss, or a hit some earlier rung missed (see `finish_ladder`). Each gap
    /// is attributed to the phase of the rung that missed. A bound miss and a
    /// stop recorded theirs where they were decided, and an empty surface
    /// already recorded every gap at the surface lookup.
    fn resolve(&self, name: &JavaTypeName) -> TypeNameOutcome {
        let outcome = self.resolve_name(name);
        let resolved = match &outcome {
            TypeNameOutcome::Resolved(_) => true,
            TypeNameOutcome::Unbound => false,
            TypeNameOutcome::BoundMiss | TypeNameOutcome::Stopped => return outcome,
        };
        let missed = self.misses.missed_tiers();
        if self.surface_empty.get() || (resolved && missed.is_empty()) {
            return outcome;
        }
        let record = |tier: &'static str| {
            let recorder = match self.site {
                Some(site) => {
                    self.recorder
                        .at_type_lookup(self.file, site.node.byte_range(), name, tier)
                }
                None => *self.recorder,
            };
            self.external.get().record_all_gaps(&recorder);
        };
        if missed.is_empty() {
            record(LookupTier::Outcome.label());
        }
        for tier in missed {
            record(tier);
        }
        outcome
    }

    fn resolve_name(&self, name: &JavaTypeName) -> TypeNameOutcome {
        let owner = match self.bind(name.first()) {
            NameBinding::Hit(owner) => owner,
            NameBinding::BoundMiss => return TypeNameOutcome::BoundMiss,
            NameBinding::Stopped => return TypeNameOutcome::Stopped,
            NameBinding::Unbound if name.is_dotted() => {
                return TypeNameOutcome::from_option(self.package_qualified(name));
            }
            NameBinding::Unbound => return TypeNameOutcome::Unbound,
        };
        let mut current = owner;
        for segment in name.rest() {
            match self.member_type(&current, segment) {
                Ok(Some(next)) => current = next,
                Ok(None) => return TypeNameOutcome::Unbound,
                Err(MemberTypeStopped) => return TypeNameOutcome::Stopped,
            }
        }
        TypeNameOutcome::Resolved(current)
    }

    /// The whole name read as `package.Type` (or `package.Type.Member`), which
    /// is the reading Java takes only when the first segment names no type.
    fn package_qualified(&self, name: &JavaTypeName) -> Option<JavaTypeResolution> {
        let fqn = name.render();
        if let Some(unit) = java_source_class_by_fqn(self.java, self.token, &fqn) {
            return Some(JavaTypeResolution::Source(unit));
        }
        if self.surface_empty() {
            return None;
        }

        let recorder = self.lookup_recorder(&fqn, LookupTier::PackageQualified);
        self.external
            .get()
            .resolve_qualified_name(&recorder, &fqn, self.access_package)
            .map(|found| JavaTypeResolution::External(found.into()))
    }

    fn member_type(
        &self,
        owner: &JavaTypeResolution,
        name: &str,
    ) -> Result<Option<JavaTypeResolution>, MemberTypeStopped> {
        let recorder = self.lookup_recorder(name, LookupTier::MemberType);

        let fqn = format!("{}.{name}", resolution_fqn(owner));
        match owner {
            JavaTypeResolution::Source(owner_unit) => {
                let env = JavaAnalyzerMemberTypeEnv {
                    java: self.java,
                    token: self.token,
                    packs: self.packs.clone(),
                    selected_jdk_artifact_sha256: self.selected_jdk_artifact_sha256,
                    external: self.external,
                    site: self.site.map(|site| (self.file, site)),
                };
                let site_enclosing = self
                    .site
                    .map(|site| {
                        enclosing_class_units_at(self.java, self.file, site.node.start_byte())
                    })
                    .unwrap_or_default();
                match resolve_accessible_member_types_of_owner(
                    &env,
                    owner_unit,
                    name,
                    self.file,
                    &site_enclosing,
                ) {
                    MemberTypeStep::Resolved(unit) => Ok(Some(JavaTypeResolution::Source(unit))),
                    MemberTypeStep::ResolvedExternal(ext) => {
                        Ok(Some(JavaTypeResolution::External(ext.into())))
                    }
                    MemberTypeStep::Missing => Ok(None),
                    MemberTypeStep::Ambiguous(units) => {
                        let mut names = units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>();
                        names.sort_unstable();
                        let candidates = units
                            .into_iter()
                            .map(|unit| Some(JavaTypeResolution::Source(unit)))
                            .collect::<Vec<_>>();
                        let _ =
                            self.stop_ambiguous(name, LookupTier::MemberType, &names, &candidates);
                        Err(MemberTypeStopped)
                    }
                    MemberTypeStep::AmbiguousResolutions(resolutions) => {
                        let mut names = resolutions.iter().map(resolution_fqn).collect::<Vec<_>>();
                        names.sort_unstable();
                        let candidates = resolutions.into_iter().map(Some).collect::<Vec<_>>();
                        let _ =
                            self.stop_ambiguous(name, LookupTier::MemberType, &names, &candidates);
                        Err(MemberTypeStopped)
                    }
                    MemberTypeStep::Incomplete(blame) => {
                        self.external.get().record_all_gaps(&recorder);
                        self.report(format!(
                            "jvm.member_type.inherited_unresolved: {name} in {}",
                            blame.fq_name()
                        ));
                        Err(MemberTypeStopped)
                    }
                }
            }
            JavaTypeResolution::External(_) if self.surface_empty() => Ok(None),
            JavaTypeResolution::External(_) => Ok(self
                .misses
                .probe_at(
                    LookupTier::MemberType.label(),
                    self.external.get().resolve_qualified_name(
                        &recorder,
                        &fqn,
                        self.access_package,
                    ),
                )
                .map(|found| JavaTypeResolution::External(found.into()))),
        }
    }

    fn bind(&self, name: &str) -> NameBinding {
        // Declared and inherited workspace member types, interleaved with
        // enclosing class and callable type parameters in Java's innermost-outward
        // order (JLS 6.3, 6.4.1, 8.5), shadow every import tier.
        if let Some(site) = self.site {
            match enclosing_member_type(
                self.java,
                self.packs.clone(),
                self.selected_jdk_artifact_sha256,
                self.external,
                self.file,
                site,
                name,
            ) {
                EnclosingMemberType::None => {}
                EnclosingMemberType::ShadowedByTypeParameter => {
                    return NameBinding::Stopped;
                }
                EnclosingMemberType::Resolved(resolution) => {
                    return NameBinding::Hit(resolution);
                }
                EnclosingMemberType::Ambiguous(resolutions) => {
                    let mut names = resolutions.iter().map(resolution_fqn).collect::<Vec<_>>();
                    names.sort_unstable();
                    let candidates = resolutions.into_iter().map(Some).collect::<Vec<_>>();
                    return self.stop_ambiguous(name, LookupTier::MemberType, &names, &candidates);
                }
                EnclosingMemberType::Incomplete { enclosing } => {
                    self.external
                        .get()
                        .record_all_gaps(&self.lookup_recorder(name, LookupTier::MemberType));
                    self.report(format!(
                        "jvm.member_type.inherited_unresolved: {name} in {enclosing}"
                    ));
                    return NameBinding::Stopped;
                }
                // A supertype nothing resolves may declare a member type that
                // shadows the import tiers. Like an unresolved on-demand
                // package, the gap lowers certainty and the tiers below still
                // bind (#14293).
                EnclosingMemberType::OpenSupertype(open) => {
                    self.external
                        .get()
                        .record_all_gaps(&self.lookup_recorder(name, LookupTier::MemberType));
                    self.report(open.gap(name));
                }
            }
        }
        self.bind_single_type_imports(name)
            .or_else(|| self.same_package(name).map(NameBinding::Hit))
            .unwrap_or_else(|| self.bind_on_demand(name))
    }

    /// The type a canonical name denotes: a workspace class, else an external
    /// declaration.
    fn canonical_type(&self, fqn: &str) -> Option<JavaTypeResolution> {
        let recorder = self.lookup_recorder(fqn, LookupTier::ExplicitImport);

        if let Some(unit) = java_source_class_by_fqn(self.java, self.token, fqn) {
            return Some(JavaTypeResolution::Source(unit));
        }
        if self.surface_empty() {
            return None;
        }
        self.external
            .get()
            .resolve_explicit_import(&recorder, fqn, self.access_package)
            .map(|found| JavaTypeResolution::External(found.into()))
    }

    /// The type a single-type import of `canonical` binds to `name`: a
    /// workspace class, else an external declaration.
    ///
    /// When the use site is known and nothing in scope can shadow the name, the
    /// external lookup records only the gaps not attributed to a dependency
    /// artifact for a JDK type in an unshadowable package.
    fn single_type_import_target(&self, name: &str, canonical: &str) -> Option<JavaTypeResolution> {
        let recorder = self.lookup_recorder(name, LookupTier::ExplicitImport);

        if let Some(unit) = java_source_class_by_fqn(self.java, self.token, canonical) {
            return Some(JavaTypeResolution::Source(unit));
        }
        if self.surface_empty() {
            return None;
        }
        let scope = self.site.and_then(|site| {
            UnshadowedScope::check(
                self.java,
                self.packs.clone(),
                self.selected_jdk_artifact_sha256,
                self.external.get(),
                self.file,
                site,
                name,
            )
        });
        match scope {
            Some(scope) => self
                .external
                .get()
                .resolve_explicit_import_in_unshadowed_scope(
                    &recorder,
                    canonical,
                    self.access_package,
                    scope,
                ),
            None => self
                .external
                .get()
                .resolve_explicit_import(&recorder, canonical, self.access_package)
                .map(ExplicitImportHit::from),
        }
        .map(JavaTypeResolution::External)
    }

    /// The single-type import tier. `None` means no single-type import binds
    /// the name, so lower tiers apply.
    ///
    /// Non-static imports are compared by canonical name from the source alone,
    /// with no index lookup: JLS 7.5.1 makes two single-type imports of
    /// different types with one simple name a compile error, whatever the class
    /// path holds. A single-static-import of a member type is different. Two
    /// spellings can name one inherited member type (`import static p.A.X;` and
    /// `import static p.B.X;` when `B extends A` and `A` declares `X`), so each
    /// is resolved to its declaring type and compared by declaration. A static
    /// import whose declaring type cannot be resolved is a bound miss, not a
    /// distinct type, and one whose declaring type has no member type of that
    /// name names a method or a field and binds no type.
    ///
    /// Outcomes have a fixed precedence: an ambiguity, then a bound miss, then
    /// a hit.
    fn bind_single_type_imports(&self, name: &str) -> Option<NameBinding> {
        let mut canonical_names = Vec::<String>::new();
        let mut static_paths = Vec::new();
        for import in &self.imports {
            if import.is_wildcard || import.identifier.as_deref() != Some(name) {
                continue;
            }
            if let Some(path) = non_static_import_path(import) {
                let canonical = path.render_segments(".");
                if !canonical_names.contains(&canonical) {
                    canonical_names.push(canonical);
                }
            } else if let Some(path) = static_import_path(import) {
                static_paths.push(path);
            }
        }
        if canonical_names.is_empty() && static_paths.is_empty() {
            return None;
        }
        canonical_names.sort_unstable();
        if canonical_names.len() >= 2 {
            let candidates = canonical_names
                .iter()
                .map(|canonical| self.canonical_type(canonical))
                .collect::<Vec<_>>();
            return Some(self.stop_ambiguous(
                name,
                LookupTier::ExplicitImport,
                &canonical_names,
                &candidates,
            ));
        }

        let mut resolved = Vec::<JavaTypeResolution>::new();
        // Each unresolved candidate: its rendered path, and whether it is a
        // `java.*` path.
        let mut unresolved = Vec::<(String, bool)>::new();
        let mut keep = |candidate: JavaTypeResolution| {
            let fqn = resolution_fqn(&candidate);
            if !resolved.iter().any(|known| resolution_fqn(known) == fqn) {
                resolved.push(candidate);
            }
        };
        for canonical in &canonical_names {
            match self.single_type_import_target(name, canonical) {
                Some(candidate) => keep(candidate),
                None => unresolved.push((canonical.clone(), canonical.starts_with("java."))),
            }
        }
        for path in static_paths {
            let Some((member, declaring_segments)) = path.segments.split_last() else {
                continue;
            };
            debug_assert_eq!(member, name);
            match self.canonical_type(&declaring_segments.join(".")) {
                None => unresolved.push((
                    path.render_segments("."),
                    declaring_segments
                        .first()
                        .is_some_and(|first| first == "java"),
                )),
                Some(declaring) => match self.member_type(&declaring, name) {
                    Ok(Some(member_type)) => keep(member_type),
                    Ok(None) => {}
                    Err(MemberTypeStopped) => return Some(NameBinding::Stopped),
                },
            }
        }

        if resolved.len() >= 2 {
            let mut names = resolved.iter().map(resolution_fqn).collect::<Vec<_>>();
            names.sort_unstable();
            let candidates = resolved.iter().cloned().map(Some).collect::<Vec<_>>();
            return Some(self.stop_ambiguous(
                name,
                LookupTier::ExplicitImport,
                &names,
                &candidates,
            ));
        }
        if !unresolved.is_empty() {
            return Some(self.stop_bound_miss(name, &unresolved));
        }
        resolved.pop().map(NameBinding::Hit)
    }

    /// Types of the same package: a workspace class, then an external one.
    fn same_package(&self, name: &str) -> Option<JavaTypeResolution> {
        let recorder = self.lookup_recorder(name, LookupTier::SamePackage);

        let fqn = java_same_package_fqn(self.java, self.file, name);
        if let Some(unit) = java_source_class_by_fqn(self.java, self.token, &fqn) {
            return Some(JavaTypeResolution::Source(unit));
        }
        if self.surface_empty() {
            return None;
        }
        self.misses
            .probe_at(
                LookupTier::SamePackage.label(),
                self.external
                    .get()
                    .resolve_same_package(&recorder, self.access_package, name),
            )
            .map(|found| JavaTypeResolution::External(found.into()))
    }

    /// The on-demand tier. In JLS terms `java.lang.*` is an on-demand import at
    /// the same level as the explicit ones, and a static-import-on-demand
    /// contributes the member types of its type (JLS 7.5.4), so all of them
    /// compete together. One distinct candidate binds the name. Several are an
    /// ambiguity the compiler would reject, reported with no target instead of
    /// being resolved by order.
    fn bind_on_demand(&self, name: &str) -> NameBinding {
        let recorder = self.lookup_recorder(name, LookupTier::OnDemand);

        let mut found = Vec::<JavaTypeResolution>::new();
        let mut keep = |candidate: JavaTypeResolution| {
            let fqn = resolution_fqn(&candidate);
            if !found.iter().any(|known| resolution_fqn(known) == fqn) {
                found.push(candidate);
            }
        };
        for import in self.imports.iter().filter(|import| import.is_wildcard) {
            if let Some(path) = non_static_import_path(import) {
                let package = path.render_segments(".");
                if let Some(unit) =
                    java_source_class_by_fqn(self.java, self.token, &format!("{package}.{name}"))
                {
                    keep(JavaTypeResolution::Source(unit));
                }
                if !self.surface_empty()
                    && let Some(external_type) = self.misses.probe_at(
                        LookupTier::OnDemand.label(),
                        self.external.get().resolve_wildcard_import(
                            &recorder,
                            &package,
                            name,
                            self.access_package,
                        ),
                    )
                {
                    keep(JavaTypeResolution::External(external_type.into()));
                }
            } else if let Some(path) = static_import_path(import) {
                let fqn = format!("{}.{name}", path.render_segments("."));
                if let Some(unit) = java_source_class_by_fqn(self.java, self.token, &fqn) {
                    keep(JavaTypeResolution::Source(unit));
                }
                if !self.surface_empty()
                    && let Some(external_type) = self.misses.probe_at(
                        LookupTier::OnDemand.label(),
                        self.external.get().resolve_qualified_name(
                            &recorder,
                            &fqn,
                            self.access_package,
                        ),
                    )
                {
                    keep(JavaTypeResolution::External(external_type.into()));
                }
            }
        }
        if !self.surface_empty()
            && let Some(external_type) = self.misses.probe_at(
                LookupTier::OnDemand.label(),
                self.external.get().resolve_java_lang(&recorder, name),
            )
        {
            keep(JavaTypeResolution::External(external_type.into()));
        }
        match found.len() {
            0 => NameBinding::Unbound,
            1 => NameBinding::Hit(found.remove(0)),
            _ => {
                let mut names = found.iter().map(resolution_fqn).collect::<Vec<_>>();
                names.sort_unstable();
                let candidates = found.iter().cloned().map(Some).collect::<Vec<_>>();
                self.stop_ambiguous(name, LookupTier::OnDemand, &names, &candidates)
            }
        }
    }

    /// An import binds the name, but nothing supplies its target. Falling
    /// through would return a definite wrong target (`java.lang.String` for
    /// `import com.missing.String;`), so the ladder stops.
    ///
    /// A `java.*` import while no JDK declaration extraction is selected is the one exception: the
    /// analyzer cannot tell which other packages belong to the JDK (`javax.*`
    /// comes from third-party jars), but `java.*` is guaranteed to be the JDK's,
    /// and an unacquired JDK stays a query obligation handled elsewhere. It
    /// records the index's gaps and no new reason.
    fn stop_bound_miss(&self, name: &str, unresolved: &[(String, bool)]) -> NameBinding {
        self.external
            .get()
            .record_all_gaps(&self.lookup_recorder(name, LookupTier::ExplicitImport));
        let jdk_obligation = unresolved.iter().all(|(_, java_package)| *java_package)
            && !self.java.active_semantic_models().is_some_and(|models| {
                brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::jdk_declaration_extraction_selected(&models)
            });
        if !jdk_obligation {
            let mut paths = unresolved
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>();
            paths.sort_unstable();
            self.report(format!("jvm.import.unresolved: {}", paths.join(", ")));
        }
        NameBinding::BoundMiss
    }

    /// Two single-type imports, or two on-demand candidates, bind different
    /// types. `candidates` is the resolution of each named type when it is
    /// known, and `None` for a name nothing resolved.
    ///
    /// When every candidate is a workspace class, the ambiguity is a known fact
    /// that the workspace resolver already reports with every peer on the trace
    /// (#1602), so it ends the ladder silently: it adds no gap to a complete
    /// answer. When an external surface took part, another surface could hold a
    /// further peer, so the index's gaps and the independent ambiguity reason
    /// are recorded.
    fn stop_ambiguous(
        &self,
        name: &str,
        tier: LookupTier,
        names: &[String],
        candidates: &[Option<JavaTypeResolution>],
    ) -> NameBinding {
        let all_workspace = candidates
            .iter()
            .all(|candidate| matches!(candidate, Some(JavaTypeResolution::Source(_))));
        if !all_workspace {
            self.external
                .get()
                .record_all_gaps(&self.lookup_recorder(name, tier));
            self.report(format!("jvm.import.ambiguous: {}", names.join(", ")));
        }
        NameBinding::Stopped
    }

    fn report(&self, detail: String) {
        brokk_bifrost_analysis::analyzer::IAnalyzer::record_query_incomplete(
            self.java,
            brokk_bifrost_analysis::analyzer::QueryReadIncomplete::SemanticEvidenceGap(
                detail.into_boxed_str(),
            ),
        );
    }
}

/// Stage the tier a type-name lookup resolved at, so the outcome constructor
/// these units flow into records them at that tier.
///
/// The staging is guarded twice, because `resolve_java_type_name_with` also runs
/// for receiver types and owners on the way to an answer: only a lookup for the
/// name the traced resolver path is currently resolving stages anything, and
/// the staged tier is spent only by an outcome that reports these very units.
pub(crate) fn trace_tier(normalized: &str, units: &[CodeUnit], tier: PrecedenceTier) {
    if trace::recording() && trace::deep_scope_is(normalized) {
        trace::stage_tier(tier, units.iter().map(CodeUnit::fq_name).collect());
    }
}

/// Record Java's strongest import tier winning, together with the on-demand
/// import routes that were therefore never consulted.
///
/// Java resolves a simple type name against single-type imports before
/// on-demand (`.*`) imports, which is why the wildcard loop runs only when the
/// explicit loop found nothing. The wildcard routes are the resolver's own
/// enumerated import list, not a re-derivation, so recording them as rejected
/// peers reports a decision the resolver made rather than inventing one.
///
/// The rejected route keeps the wildcard marker as its `name` -- an on-demand
/// import binds no single identifier -- and names what it pointed at through
/// `target_segments`, the parser-derived package path `parse_import_info`
/// read from the `import_declaration` node (#1600).
pub(crate) fn trace_explicit_import_win(
    file: &ProjectFile,
    normalized: &str,
    unit: Option<&CodeUnit>,
    imports: &[ImportInfo],
) {
    if !trace::recording() || !trace::deep_scope_is(normalized) {
        return;
    }
    if let Some(unit) = unit {
        trace::stage_tier(PrecedenceTier::ExplicitImport, vec![unit.fq_name()]);
    }
    trace::record_all(
        imports
            .iter()
            .filter(|import| import.is_wildcard)
            .map(|import| {
                trace::TraceCandidate::rejected(
                    trace::TraceCandidateRef::ImportBinder {
                        file: file.clone(),
                        node: None,
                        name: trace::WILDCARD_ROUTE_NAME.to_owned(),
                        target_segments: import
                            .path
                            .as_ref()
                            .map(|path| path.segments.clone())
                            .unwrap_or_default(),
                    },
                    Some(PrecedenceTier::WildcardImport),
                    RejectionReason::ShadowedByNearer,
                )
            }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_test_macros::hardwon;

    fn ladder_outcome_at(
        java: &JavaAnalyzer,
        file: &ProjectFile,
        source: &str,
        anchor: &str,
        name: &str,
    ) -> TypeNameOutcome {
        let scope = AnalyzerQueryScope::new(java);
        let token = scope.token();
        let parsed =
            brokk_bifrost_jvm::java::declarations::parse_tree(source).expect("parse site source");
        let start = source.find(anchor).expect("anchor");
        let site_node = parsed
            .root_node()
            .named_descendant_for_byte_range(start, start + name.len())
            .expect("site node");
        let site = UseSite {
            token,
            source,
            node: site_node,
        };
        let parsed_name = JavaTypeName::from_normalized_spelling(name).expect("type name");
        java.resolve_type_name_outcome_at(token, None, file, &parsed_name, None, Some(&site))
    }

    #[test]
    #[hardwon(
        "#10858: The type ladder stops on two inherited member types instead of falling through to the single-type import."
    )]
    fn ladder_stops_on_ambiguous_inherited_member_types() {
        let app_source = "package app;\n\
             import org.acme.Files;\n\
             class App extends p.Grand implements p.OtherFiles {\n\
             \x20   Files field;\n\
             }\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "p/Grand.java",
                "package p;\npublic class Grand { public static class Files {} }\n",
            )
            .file(
                "p/OtherFiles.java",
                "package p;\npublic interface OtherFiles { class Files {} }\n",
            )
            .file(
                "org/acme/Files.java",
                "package org.acme;\npublic class Files {}\n",
            )
            .file("app/App.java", app_source)
            .build();
        let java = JavaAnalyzer::new_with_config(project.project_dyn(), Default::default());
        let file = project.file("app/App.java");
        let outcome = ladder_outcome_at(&java, &file, app_source, "Files field", "Files");
        assert!(
            matches!(outcome, TypeNameOutcome::Stopped),
            "two inherited member types must stop the ladder: {outcome:?}"
        );
    }

    #[test]
    #[hardwon(
        "#10858: A private superclass member type is not inherited, so the ladder binds the single-type import instead of stopping."
    )]
    fn ladder_binds_import_when_superclass_member_type_is_private() {
        let app_source = "package app;\n\
             import org.acme.Files;\n\
             class App extends p.SecretBase {\n\
             \x20   Files field;\n\
             }\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "p/SecretBase.java",
                "package p;\npublic class SecretBase { private static class Files {} }\n",
            )
            .file(
                "org/acme/Files.java",
                "package org.acme;\npublic class Files {}\n",
            )
            .file("app/App.java", app_source)
            .build();
        let java = JavaAnalyzer::new_with_config(project.project_dyn(), Default::default());
        let file = project.file("app/App.java");
        let outcome = ladder_outcome_at(&java, &file, app_source, "Files field", "Files");
        match outcome {
            TypeNameOutcome::Resolved(JavaTypeResolution::Source(unit)) => {
                assert_eq!(unit.fq_name(), "org.acme.Files");
            }
            other => panic!("expected Resolved(org.acme.Files), got {other:?}"),
        }
    }
}
