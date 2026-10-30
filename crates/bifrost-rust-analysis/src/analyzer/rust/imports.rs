//! `ImportAnalysisProvider` for Rust: the memoization shell around
//! [`brokk_bifrost_rust::imports`].
//!
//! Only the caching stays here. The two moka caches are analyzer state, so each
//! method below fetches or fills a cache slot and hands the actual resolution to
//! the Rust crate through the [`RustSource`] the analyzer implements.

use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustSummaryBindingSurfaceRow;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::capabilities::ImportGraphBindingSurface;

use brokk_bifrost_core::analyzer::capabilities::ImportGraphInputDigests;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_core::analyzer::capabilities::ImportedFileEdgeFacts;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::rust_facts::{RustCfgInstruction, RustVisibility};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_rust::declarations::rust_package_name;
use brokk_bifrost_rust::imports::RustImportBindingName;
use brokk_bifrost_rust::imports::{
    resolve_rust_import_fq_name, resolve_rust_module_path_with_crate,
    resolve_rust_module_segments_with_crate, rust_could_import_file, rust_crate_root_package,
    rust_imported_code_units,
};
use brokk_bifrost_rust::lexical_scope::RustCfgCondition;
use brokk_bifrost_rust::usage::{
    Domain, ModuleKey, RustOriginRoute, RustRouteProvenance, RustSymbolIdentity,
    RustSymbolNamespace,
};
use brokk_bifrost_rust::usage_queries::{
    RustDeclarationFacts, RustImportBinding, RustUsageQueries,
};
#[cfg(test)]
use brokk_bifrost_rust::usage_walks::RustUsageWalks;
use std::sync::Arc;

use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

impl ImportAnalysisProvider for RustAnalyzer {
    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            Vec<brokk_bifrost_core::analyzer::model::ImportInfo>,
        >,
    > {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

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

    fn has_complete_import_resolution_dependencies(&self) -> bool {
        true
    }

    fn import_graph_module_path_keys_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<String>>> {
        let mut keys = brokk_bifrost_core::hash::HashMap::default();
        for file in files {
            let crate_root = rust_crate_root_package(file);
            let package = rust_package_name(file);
            let module = ModuleKey::with_crate_root(&crate_root, &package);
            keys.insert(
                file.clone(),
                vec![format!(
                    "{}::{}",
                    module.crate_root,
                    module.components.join("::")
                )],
            );
        }
        Some(keys)
    }

    fn import_graph_binding_surfaces_for_files(
        &self,
        files: &[ProjectFile],
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportGraphBindingSurface>>>
    {
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        if files.is_empty() {
            return Some(brokk_bifrost_core::hash::HashMap::default());
        }
        if !keep_going() {
            return None;
        }
        let rows = persisted_binding_surface_rows_for_files(self, files, &keep_going)?;
        let mut surfaces = brokk_bifrost_core::hash::HashMap::default();
        let mut grouped: brokk_bifrost_core::hash::HashMap<
            (String, i64, i64),
            (ImportGraphBindingSurface, HashSet<ProjectFile>),
        > = brokk_bifrost_core::hash::HashMap::default();
        for row in rows {
            let file = files.iter().find(|file| {
                brokk_bifrost_core::path_utils::rel_path_string(file) == row.rel_path
            })?;
            let file_root = file.root().to_path_buf();
            let root_components: Vec<String> = serde_json::from_str(&row.root_components).ok()?;
            let crate_root = root_components.join(".");
            let module_package =
                resolve_rust_module_path_with_crate(&crate_root, &crate_root, &row.module_path)?;
            let module = ModuleKey::with_crate_root(&crate_root, &module_package);
            let origin_root_components: Vec<String> =
                serde_json::from_str(&row.origin_root_components).ok()?;
            let origin_crate_root = origin_root_components.join(".");
            let origin_package = resolve_rust_module_path_with_crate(
                &origin_crate_root,
                &origin_crate_root,
                &row.origin_module_path,
            )?;
            let origin_module = ModuleKey::with_crate_root(&origin_crate_root, &origin_package);
            let visibility_scope = match row.visibility_kind.as_str() {
                "public" => String::new(),
                "crate" => row.visibility_crate_root.clone()?,
                "module" => {
                    let visibility_path = row.visibility_module_path.as_deref()?;
                    let package = resolve_rust_module_path_with_crate(
                        &crate_root,
                        &crate_root,
                        visibility_path,
                    )?;
                    rust_module_surface_key(&ModuleKey::with_crate_root(&crate_root, &package))
                }
                _ => return None,
            };
            let key = (row.rel_path.clone(), row.member_ordinal, row.route_ordinal);
            let entry = grouped.entry(key).or_insert_with(|| {
                (
                    ImportGraphBindingSurface {
                        module_path: rust_module_surface_key(&module),
                        name: row.name.clone(),
                        namespace: row.namespace.clone(),
                        visibility_kind: row.visibility_kind.clone(),
                        visibility_scope,
                        origin_file: ProjectFile::new(file_root.clone(), row.origin_file.clone()),
                        origin_module_path: rust_module_surface_key(&origin_module),
                        origin_name: row.origin_name.clone(),
                        route_files: Vec::new(),
                    },
                    HashSet::default(),
                )
            });
            entry
                .1
                .insert(ProjectFile::new(file_root, row.route_file.clone()));
        }
        for ((rel_path, _, _), (mut surface, route_files)) in grouped {
            let file = files
                .iter()
                .find(|file| brokk_bifrost_core::path_utils::rel_path_string(file) == rel_path)?;
            surface.route_files = route_files.into_iter().collect();
            surface.route_files.sort();
            surfaces
                .entry(file.clone())
                .or_insert_with(Vec::new)
                .push(surface);
        }
        for file in files {
            let surface = surfaces.entry(file.clone()).or_insert_with(Vec::new);
            surface.sort_by(|left, right| {
                left.module_path
                    .cmp(&right.module_path)
                    .then_with(|| left.name.cmp(&right.name))
                    .then_with(|| left.namespace.cmp(&right.namespace))
                    .then_with(|| left.visibility_kind.cmp(&right.visibility_kind))
                    .then_with(|| left.visibility_scope.cmp(&right.visibility_scope))
                    .then_with(|| left.origin_file.cmp(&right.origin_file))
                    .then_with(|| left.origin_module_path.cmp(&right.origin_module_path))
                    .then_with(|| left.origin_name.cmp(&right.origin_name))
                    .then_with(|| left.route_files.cmp(&right.route_files))
            });
            surface.dedup();
        }
        Some(surfaces)
    }

    fn import_graph_input_digests_for_files(
        &self,
        files: &[ProjectFile],
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<brokk_bifrost_core::hash::HashMap<ProjectFile, ImportGraphInputDigests>> {
        let queries = RustUsageQueries::new(self);
        let mut digests = brokk_bifrost_core::hash::HashMap::default();
        for file in files {
            if cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            {
                return None;
            }
            let facts = queries.facts_of(file).ok()??;
            let declarations = queries.declaration_facts_of(file).ok()?;
            let imports = queries.import_bindings_of(file).ok()?;
            digests.insert(
                file.clone(),
                rust_import_graph_input_digests(&facts, &declarations, &imports),
            );
        }
        Some(digests)
    }

    fn import_resolution_dependencies_for_files(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            brokk_bifrost_core::analyzer::capabilities::ImportResolutionDependencies,
        >,
    > {
        self.import_resolution_dependencies_for_ordinals(
            files,
            import_infos,
            &brokk_bifrost_core::hash::HashMap::default(),
            cancellation,
        )
    }

    fn import_resolution_dependencies_for_ordinals(
        &self,
        files: &[ProjectFile],
        _import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            brokk_bifrost_core::analyzer::capabilities::ImportResolutionDependencies,
        >,
    > {
        if files.is_empty() {
            return Some(brokk_bifrost_core::hash::HashMap::default());
        }
        let _scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let cargo_routes = self.cargo_routes_while(&keep_going).ok()?;
        if !keep_going() {
            return None;
        }
        let store = self.inner.analyzer_store();
        let snapshots = self.inner.selected_workspace_snapshots();
        let rel_paths = files
            .iter()
            .map(brokk_bifrost_core::path_utils::rel_path_string)
            .collect::<Vec<_>>();
        let completeness =
            match store.rust_summary_binding_completeness_rows(&snapshots, &rel_paths) {
                Ok(rows) => rows,
                Err(error) => {
                    self.inner.record_store_error(error.context(
                        "reading live Rust summary binding completeness for import graph",
                    ));
                    return None;
                }
            };
        if !keep_going() {
            return None;
        }
        let requested_files: brokk_bifrost_core::hash::HashMap<_, _> = files
            .iter()
            .cloned()
            .map(|file| (brokk_bifrost_core::path_utils::rel_path_string(&file), file))
            .collect();
        let mut completeness_by_path = brokk_bifrost_core::hash::HashMap::default();
        for row in completeness {
            if !row.complete {
                return None;
            }
            assert!(
                completeness_by_path
                    .insert(row.rel_path.clone(), row)
                    .is_none(),
                "one live Rust summary completeness row exists per member"
            );
        }
        if completeness_by_path.len() != requested_files.len()
            || requested_files
                .keys()
                .any(|path| !completeness_by_path.contains_key(path))
        {
            return None;
        }

        let queries = RustUsageQueries::new(self);
        let surface_rows = match store.rust_summary_binding_surface_rows(&snapshots, &rel_paths) {
            Ok(rows) => rows,
            Err(error) => {
                self.inner.record_store_error(
                    error.context("reading live Rust summary routes for import graph dependencies"),
                );
                return None;
            }
        };
        if !keep_going() {
            return None;
        }
        let mut context_paths = surface_rows
            .iter()
            .map(|row| row.route_file.clone())
            .chain(rel_paths.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        let project_root = files[0].root();
        let mut foreign_roots = Vec::new();
        for path in &context_paths {
            if !keep_going() {
                return None;
            }
            let file = ProjectFile::new(project_root.to_path_buf(), path);
            let facts = queries.facts_of(&file).ok()??;
            for target in &facts.import_targets {
                let Some(first) = target.module_path.first() else {
                    continue;
                };
                if let Some((root, _)) = cargo_routes
                    .resolve_crate_root_file_segments_with_kind(&file, std::slice::from_ref(first))
                {
                    foreign_roots.push(brokk_bifrost_core::path_utils::rel_path_string(&root));
                }
            }
        }
        context_paths.extend(foreign_roots);
        let route_paths = context_paths
            .into_iter()
            .filter(|path| !completeness_by_path.contains_key(path))
            .collect::<Vec<_>>();
        if !route_paths.is_empty() {
            let route_completeness =
                match store.rust_summary_binding_completeness_rows(&snapshots, &route_paths) {
                    Ok(rows) => rows,
                    Err(error) => {
                        self.inner.record_store_error(error.context(
                            "reading live Rust route-member completeness for import graph",
                        ));
                        return None;
                    }
                };
            for row in route_completeness {
                if !row.complete {
                    return None;
                }
                assert!(
                    !completeness_by_path.contains_key(&row.rel_path),
                    "one live Rust summary completeness row exists per member path: new={row:?}, previous={:?}",
                    completeness_by_path.get(&row.rel_path)
                );
                completeness_by_path.insert(row.rel_path.clone(), row);
            }
        }
        let mut module_candidates = Vec::new();
        let mut seen_module_candidates = HashSet::default();
        for file in files {
            if !keep_going() {
                return None;
            }
            let rel_path = brokk_bifrost_core::path_utils::rel_path_string(file);
            let member = completeness_by_path.get(&rel_path)?;
            let package_components: Vec<String> =
                serde_json::from_str(&member.package_components).ok()?;
            let root_components: Vec<String> =
                serde_json::from_str(&member.root_components).ok()?;
            let facts = queries.facts_of(file).ok()??;
            for (ordinal, target) in facts.import_targets.iter().enumerate() {
                let import_ordinal =
                    u32::try_from(ordinal).expect("Rust source import ordinal fits u32");
                if selected_ordinals
                    .get(file)
                    .is_some_and(|ordinals| !ordinals.contains(&import_ordinal))
                {
                    continue;
                }
                let root_lookup_names = target.imported_name.iter().cloned().collect::<Vec<_>>();
                append_rust_summary_import_module_candidates(
                    &mut module_candidates,
                    &mut seen_module_candidates,
                    file,
                    member.summary_id,
                    import_ordinal,
                    target,
                    &package_components,
                    &root_components,
                    &root_lookup_names,
                    target.module_path.first().and_then(|first| {
                        let (root, _) = cargo_routes.resolve_crate_root_file_segments_with_kind(
                            file,
                            std::slice::from_ref(first),
                        )?;
                        completeness_by_path
                            .get(&brokk_bifrost_core::path_utils::rel_path_string(&root))
                    }),
                );
            }
        }
        for row in &surface_rows {
            if !keep_going() {
                return None;
            }
            let Some(root_import_ordinal) = row.source_import_ordinal else {
                continue;
            };
            let Some(route_import_id) = row.route_source_import_id else {
                assert!(
                    row.route_source_import_ordinal.is_none(),
                    "Rust route source import id and ordinal are both present or absent"
                );
                continue;
            };
            let Some(route_import_ordinal) = row.route_source_import_ordinal else {
                assert!(
                    row.route_source_import_id.is_none(),
                    "Rust route source import id and ordinal are both present or absent"
                );
                continue;
            };
            if row.route_file == row.rel_path {
                continue;
            }
            let Some(owner_file) = requested_files.get(&row.rel_path) else {
                continue;
            };
            let root_import_ordinal = u32::try_from(root_import_ordinal)
                .expect("Rust source import ordinal is nonnegative and fits u32");
            if selected_ordinals
                .get(owner_file)
                .is_some_and(|ordinals| !ordinals.contains(&root_import_ordinal))
            {
                continue;
            }
            let route_member = completeness_by_path.get(&row.route_file)?;
            let route_file = ProjectFile::new(owner_file.root().to_path_buf(), &row.route_file);
            let route_facts = queries.facts_of(&route_file).ok()??;
            let route_import_ordinal = usize::try_from(route_import_ordinal)
                .expect("Rust route source import ordinal is nonnegative");
            let target = route_facts.import_targets.get(route_import_ordinal)?;
            let decoded_import_id = target.source_import_id.map(|id| i64::from(id.get()));
            assert_eq!(
                decoded_import_id,
                Some(route_import_id),
                "Rust route source import ordinal identifies its source import id"
            );
            let package_components: Vec<String> =
                serde_json::from_str(&route_member.package_components).ok()?;
            let root_components: Vec<String> =
                serde_json::from_str(&route_member.root_components).ok()?;
            append_rust_summary_import_module_candidates(
                &mut module_candidates,
                &mut seen_module_candidates,
                owner_file,
                route_member.summary_id,
                root_import_ordinal,
                target,
                &package_components,
                &root_components,
                &[row.route_name.clone(), row.origin_name.clone()],
                target.module_path.first().and_then(|first| {
                    let (root, _) = cargo_routes.resolve_crate_root_file_segments_with_kind(
                        &route_file,
                        std::slice::from_ref(first),
                    )?;
                    completeness_by_path
                        .get(&brokk_bifrost_core::path_utils::rel_path_string(&root))
                }),
            );
        }
        let candidates = module_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.summary_id,
                    rust_summary_module_path(&candidate.module),
                )
            })
            .collect::<Vec<_>>();
        let candidate_rows = match store.rust_summary_module_candidate_rows(&snapshots, &candidates)
        {
            Ok(rows) => rows,
            Err(error) => {
                self.inner.record_store_error(
                    error.context("reading Rust summary module candidates for import graph"),
                );
                return None;
            }
        };
        if !keep_going() {
            return None;
        }
        let mut dependencies = requested_files
            .values()
            .cloned()
            .map(|file| {
                (
                    file,
                    brokk_bifrost_core::analyzer::capabilities::ImportResolutionDependencies::default(),
                )
            })
            .collect::<brokk_bifrost_core::hash::HashMap<_, _>>();
        let mut seen_lookups: HashSet<(ProjectFile, u32, String, String)> = HashSet::default();
        let mut seen_missing: HashSet<(ProjectFile, u32, String)> = HashSet::default();
        let mut candidate_present = vec![false; module_candidates.len()];
        for row in candidate_rows {
            let candidate = module_candidates
                .get(row.candidate_ordinal)
                .expect("module candidate row refers to its requested candidate");
            candidate_present[row.candidate_ordinal] |= row.present;
            let Some(consulted_path) = row.rel_path else {
                continue;
            };
            let names = candidate
                .lookup_name
                .iter()
                .chain(&candidate.additional_lookup_names);
            for name in names {
                let key = (
                    candidate.owner_file.clone(),
                    candidate.import_ordinal,
                    consulted_path.clone(),
                    name.clone(),
                );
                if seen_lookups.insert(key) {
                    dependencies
                        .get_mut(&candidate.owner_file)
                        .expect("requested Rust member has dependency facts")
                        .lookups
                        .push(
                            brokk_bifrost_core::analyzer::capabilities::ImportLookupDependency {
                                import_ordinal: candidate.import_ordinal,
                                consulted_file: ProjectFile::new(
                                    candidate.owner_file.root().to_path_buf(),
                                    consulted_path.clone(),
                                ),
                                name: name.clone(),
                            },
                        );
                }
            }
        }
        for (index, candidate) in module_candidates.iter().enumerate() {
            if candidate.record_missing && !candidate_present[index] {
                let path_key = format!(
                    "{}::{}",
                    candidate.module.crate_root,
                    candidate.module.components.join("::")
                );
                if seen_missing.insert((
                    candidate.owner_file.clone(),
                    candidate.import_ordinal,
                    path_key.clone(),
                )) {
                    dependencies
                        .get_mut(&candidate.owner_file)
                        .expect("requested Rust member has dependency facts")
                        .missing_module_path_keys
                        .push((candidate.import_ordinal, path_key));
                }
            }
        }
        for row in surface_rows {
            if !keep_going() {
                return None;
            }
            let Some(import_ordinal) = row.source_import_ordinal else {
                assert!(
                    row.source_import_id.is_none(),
                    "Rust summary route import id and ordinal are both present or absent"
                );
                continue;
            };
            assert!(
                row.source_import_id.is_some(),
                "Rust summary route import id and ordinal are both present or absent"
            );
            let import_ordinal = u32::try_from(import_ordinal)
                .expect("Rust source import ordinal is nonnegative and fits u32");
            let Some(file) = requested_files.get(&row.rel_path) else {
                continue;
            };
            if selected_ordinals
                .get(file)
                .is_some_and(|ordinals| !ordinals.contains(&import_ordinal))
            {
                continue;
            }
            if row.route_file == row.rel_path {
                continue;
            }
            let facts = dependencies
                .get_mut(file)
                .expect("selected Rust summary path maps to the request file");
            for name in [row.name, row.origin_name] {
                let key = (
                    file.clone(),
                    import_ordinal,
                    row.route_file.clone(),
                    name.clone(),
                );
                if seen_lookups.insert(key) {
                    facts.lookups.push(
                        brokk_bifrost_core::analyzer::capabilities::ImportLookupDependency {
                            import_ordinal,
                            consulted_file: ProjectFile::new(
                                file.root().to_path_buf(),
                                row.route_file.clone(),
                            ),
                            name,
                        },
                    );
                }
            }
        }
        for facts in dependencies.values_mut() {
            facts.lookups.sort_by(|left, right| {
                left.import_ordinal
                    .cmp(&right.import_ordinal)
                    .then_with(|| left.consulted_file.cmp(&right.consulted_file))
                    .then_with(|| left.name.cmp(&right.name))
            });
            facts.missing_module_path_keys.sort_unstable();
            facts.missing_module_path_keys.dedup();
        }
        Some(dependencies)
    }

    fn for_each_import_edge_facts_from_infos(
        &self,
        files: &[ProjectFile],
        _import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, Vec<ImportedFileEdgeFacts>) -> bool,
    ) -> Option<()> {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let token = scope.token();
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        if files.is_empty() {
            return Some(());
        }
        let package_files = match self.package_file_index_while(token, &keep_going) {
            Ok(files) => files,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                return Some(());
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return None;
            }
        };
        let Some(surface_rows) = persisted_binding_surface_rows_for_files(self, files, &keep_going)
        else {
            return cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
                .then_some(());
        };
        let queries = RustUsageQueries::new(self);
        for file in files {
            if !keep_going() {
                return Some(());
            }
            let bindings = match queries.import_bindings_of(file) {
                Ok(bindings) => bindings,
                Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                    return Some(());
                }
                Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                    return None;
                }
            };
            let Some(facts) = rust_import_edge_facts_from_summary(
                &package_files,
                file,
                &bindings,
                &surface_rows,
                selected_ordinals.get(file).map(Vec::as_slice),
                &keep_going,
            ) else {
                if !keep_going() {
                    return Some(());
                }
                return None;
            };
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
        let scope = AnalyzerQueryScope::new(self);
        let keep_going = || true;
        let package_files = self
            .package_file_index_while(scope.token(), &keep_going)
            .ok()?;
        let Some(surface_rows) =
            persisted_binding_surface_rows_for_files(self, std::slice::from_ref(file), &keep_going)
        else {
            return Some(direct_import_file_edges(&package_files, file, imports));
        };
        let queries = RustUsageQueries::new(self);
        let bindings = match queries.import_bindings_of(file) {
            Ok(bindings) => bindings,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return Some(direct_import_file_edges(&package_files, file, imports));
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                unreachable!("uncancelled Rust provenance query cannot be cancelled")
            }
        };
        let Some(facts) = rust_import_edge_facts_from_summary(
            &package_files,
            file,
            &bindings,
            &surface_rows,
            None,
            &keep_going,
        ) else {
            return Some(direct_import_file_edges(&package_files, file, imports));
        };
        let mut edges = HashMap::default();
        for fact in facts {
            for (target, provenance) in fact.edges {
                edges
                    .entry(target)
                    .or_insert_with(Vec::new)
                    .extend(provenance);
            }
        }
        Some(edges)
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let resolved =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                Arc::new(rust_imported_code_units(
                    self,
                    file,
                    &self.inner.import_info_of(token, file),
                ))
            });
        match resolved {
            Ok(resolved) => {
                {
                    let cache_key = file.clone();
                    let cache_value = Arc::clone(&resolved);
                    if cache_fill.is_complete() {
                        self.imported_code_units.insert(cache_key, cache_value);
                    }
                };
                resolved
            }
            Err(resolved) => resolved,
        }
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        let referencing = brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
            self,
            || match self.live_path_snapshot().oid_for_path(file) {
                Some(oid) => {
                    self.inner
                        .analyzer_store()
                        .rust_summary_importing_file_paths(
                            self.inner.selected_workspace_snapshots().as_ref(),
                            &oid.to_string(),
                            &brokk_bifrost_core::path_utils::rel_path_string(file),
                            &self
                                .inner
                                .declarations(file)
                                .iter()
                                .map(|unit| (unit.identifier().to_owned(), unit.fq_name()))
                                .collect::<Vec<_>>(),
                        )
                        .map(|paths| {
                            paths
                                .into_iter()
                                .map(|path| ProjectFile::new(file.root().to_path_buf(), path))
                                .collect()
                        })
                        .unwrap_or_else(|error| {
                            self.inner.record_store_error(error.context(format!(
                                "reading live Rust summary importers for {file:?}"
                            )));
                            HashSet::default()
                        })
                }
                None => HashSet::default(),
            },
        );
        match referencing {
            Ok(referencing) => {
                {
                    let cache_key = file.clone();
                    let cache_value = Arc::new(referencing.clone());
                    if cache_fill.is_complete() {
                        self.referencing_files.insert(cache_key, cache_value);
                    }
                };
                referencing
            }
            Err(referencing) => referencing,
        }
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let scope = AnalyzerQueryScope::new(self);
        let package_files = self
            .package_file_index_while(scope.token(), &|| true)
            .ok()?;
        let mut imported_files = direct_imported_files(&package_files, file, imports);
        if imports.is_empty() {
            return Some(imported_files);
        }
        let Some(surface_rows) =
            persisted_binding_surface_rows_for_files(self, std::slice::from_ref(file), &|| true)
        else {
            return Some(imported_files);
        };
        for row in surface_rows {
            if row.source_import_ordinal.is_some() {
                imported_files.insert(ProjectFile::new(file.root().to_path_buf(), row.origin_file));
            }
        }
        Some(imported_files)
    }

    fn for_each_imported_files_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, HashSet<ProjectFile>) -> bool,
    ) -> Option<()> {
        let mut visit_edges =
            |file: &ProjectFile, edges: HashMap<ProjectFile, Vec<serde_json::Value>>| {
                visit(file, edges.into_keys().collect())
            };
        self.for_each_imported_file_edges_from_infos(
            files,
            import_infos,
            cancellation,
            &mut visit_edges,
        )
    }

    fn for_each_imported_file_edges_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, HashMap<ProjectFile, Vec<serde_json::Value>>) -> bool,
    ) -> Option<()> {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let token = scope.token();
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let package_files = match self.package_file_index_while(token, &keep_going) {
            Ok(files) => files,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                return Some(());
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return None;
            }
        };
        let surface_rows = match persisted_binding_surface_rows_for_files(self, files, &keep_going)
        {
            Some(rows) => rows,
            None if !keep_going() => return Some(()),
            None => Vec::new(),
        };
        let queries = RustUsageQueries::new(self);
        for file in files {
            if cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            {
                return Some(());
            }
            let owned_imports;
            let imports = if let Some(imports) = import_infos.and_then(|infos| infos.get(file)) {
                imports.as_slice()
            } else {
                owned_imports = self.inner.import_info_of(token, file);
                &owned_imports
            };
            let mut imported_edges = direct_import_file_edges(&package_files, file, imports);
            if !imports.is_empty() && !surface_rows.is_empty() {
                let bindings = match queries.import_bindings_of(file) {
                    Ok(bindings) => bindings,
                    Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                        return Some(());
                    }
                    Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                        if !visit(file, imported_edges) {
                            break;
                        }
                        continue;
                    }
                };
                let Some(route_facts) = rust_import_origin_route_facts_from_summary(
                    file,
                    &bindings,
                    &surface_rows,
                    None,
                    &keep_going,
                ) else {
                    if !keep_going() {
                        return Some(());
                    }
                    return None;
                };
                for route_edges in route_facts.into_values() {
                    for (target, provenance) in route_edges {
                        imported_edges.entry(target).or_default().extend(provenance);
                    }
                }
            }
            if !visit(file, imported_edges) {
                break;
            }
        }
        Some(())
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Option<brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies> {
        let routes = match self.cargo_routes_while(&|| !cancellation.is_cancelled()) {
            Ok(routes) => routes,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => return None,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                // The route reader records the publication error on the query.
                // Preserve incompleteness here so no caller caches an empty graph.
                return Some(brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies::incomplete(
                    brokk_bifrost_core::hash::HashMap::default(),
                ));
            }
        };
        let selected: HashSet<_> = files.iter().cloned().collect();
        let mut dependencies: brokk_bifrost_core::hash::HashMap<ProjectFile, HashSet<ProjectFile>> =
            brokk_bifrost_core::hash::HashMap::default();
        for declaration in routes.external_module_declarations() {
            if cancellation.is_cancelled() {
                return None;
            }
            if selected.contains(&declaration.declaring_file)
                && selected.contains(&declaration.target_file)
            {
                dependencies
                    .entry(declaration.declaring_file.clone())
                    .or_default()
                    .insert(declaration.target_file.clone());
            }
        }
        Some(
            brokk_bifrost_core::analyzer::capabilities::AdditionalFileDependencies::complete(
                dependencies,
            ),
        )
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        rust_could_import_file(self, source_file, imports, target)
    }

    /// Rust answers "could this file import the target" by resolving each
    /// `use` path to an fq name and asking the store which files define it,
    /// so the shared candidate walk charged one `definition_candidates` query
    /// per `use` statement in the workspace (#1748). Every path the walk will
    /// ask about is derivable from the import facts it already has, so resolve
    /// them all here and hand the whole set to one batched store read.
    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&brokk_bifrost_core::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        use rayon::prelude::*;

        let context = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        let mut fq_names: Vec<String> = files
            .par_iter()
            .flat_map_iter(|file| {
                context.run(|| {
                    if cancellation.is_cancelled() {
                        return Vec::new().into_iter();
                    }
                    let package = rust_package_name(file);
                    let imports = import_infos
                        .and_then(|infos| infos.get(file).cloned())
                        .unwrap_or_else(|| self.inner.import_info_of(token, file));
                    imports
                        .iter()
                        .filter_map(|import| resolve_rust_import_fq_name(file, &package, import))
                        .collect::<Vec<_>>()
                        .into_iter()
                })
            })
            .collect();
        if cancellation.is_cancelled() {
            return;
        }
        fq_names.sort_unstable();
        fq_names.dedup();
        self.inner.prefetch_definitions(&fq_names);
    }
}

fn rust_module_surface_key(module: &ModuleKey) -> String {
    std::iter::once(module.crate_root.as_str())
        .chain(module.components.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("::")
}

#[derive(Debug)]
struct RustSummaryImportModuleCandidate {
    owner_file: ProjectFile,
    summary_id: i64,
    import_ordinal: u32,
    module: ModuleKey,
    lookup_name: Option<String>,
    additional_lookup_names: Vec<String>,
    record_missing: bool,
}

type ImportModuleCandidateKey = (
    ProjectFile,
    u32,
    ModuleKey,
    Option<String>,
    bool,
    Vec<String>,
);

#[allow(clippy::too_many_arguments)]
fn append_rust_summary_import_module_candidates(
    candidates: &mut Vec<RustSummaryImportModuleCandidate>,
    seen: &mut HashSet<ImportModuleCandidateKey>,
    owner_file: &ProjectFile,
    summary_id: i64,
    import_ordinal: u32,
    target: &brokk_bifrost_core::analyzer::rust_facts::RustImportTargetFact,
    package_components: &[String],
    root_components: &[String],
    additional_lookup_names: &[String],
    external_root: Option<
        &brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustSummaryBindingCompletenessRow,
    >,
) {
    let package = package_components.join(".");
    let crate_root = root_components.join(".");
    let owner_package =
        brokk_bifrost_rust::usage_queries::compose_module(&package, &target.owner_module);
    let importer_module = ModuleKey::with_crate_root(&crate_root, &owner_package);
    let mut path = target.module_path.clone();
    if let Some(imported_name) = &target.imported_name {
        path.push(imported_name.clone());
    }

    let external_root = external_root.map(|root| {
        let components: Vec<String> = serde_json::from_str(&root.root_components)
            .expect("Rust summary root components were validated at publication");
        (root.summary_id, components.join("."))
    });
    for prefix_len in 0..=path.len() {
        let prefix = &path[..prefix_len];
        if prefix_len == 0
            && matches!(
                path.first().map(String::as_str),
                Some("crate" | "self" | "super")
            )
        {
            continue;
        }
        let mut modules = Vec::new();
        if prefix.is_empty()
            || !matches!(
                prefix.first().map(String::as_str),
                Some("crate" | "self" | "super")
            )
        {
            for depth in (0..=importer_module.components.len()).rev() {
                let mut components = importer_module.components[..depth].to_vec();
                components.extend(prefix.iter().cloned());
                modules.push((
                    summary_id,
                    ModuleKey {
                        crate_root: importer_module.crate_root.clone(),
                        components,
                    },
                ));
            }
        } else if let Some(package) =
            resolve_rust_module_segments_with_crate(&owner_package, &crate_root, prefix)
        {
            modules.push((
                summary_id,
                ModuleKey::with_crate_root(&crate_root, &package),
            ));
        }
        if !prefix.is_empty()
            && let Some((external_summary, root)) = &external_root
        {
            modules.push((
                *external_summary,
                ModuleKey {
                    crate_root: root.clone(),
                    components: prefix[1..].to_vec(),
                },
            ));
        }
        modules.sort_by_key(|(summary, module)| (*summary, module.package()));
        modules.dedup();

        let lookup_name = path
            .get(prefix_len)
            .cloned()
            .or_else(|| target.is_glob.then(|| "*".to_owned()));
        let additional_lookup_names = if prefix_len == 1
            && (external_root.is_some()
                || matches!(
                    path.first().map(String::as_str),
                    Some("crate" | "self" | "super")
                )) {
            let mut names = additional_lookup_names.to_vec();
            names.sort_unstable();
            names.dedup();
            names
        } else {
            Vec::new()
        };
        for (summary_id, module) in modules {
            let record_missing = !prefix.is_empty();
            let key = (
                owner_file.clone(),
                import_ordinal,
                module.clone(),
                lookup_name.clone(),
                record_missing,
                additional_lookup_names.clone(),
            );
            if seen.insert(key) {
                candidates.push(RustSummaryImportModuleCandidate {
                    owner_file: owner_file.clone(),
                    summary_id,
                    import_ordinal,
                    module,
                    lookup_name: lookup_name.clone(),
                    additional_lookup_names: additional_lookup_names.clone(),
                    record_missing,
                });
            }
        }
    }
}

fn rust_summary_module_path(module: &ModuleKey) -> String {
    if module.components.is_empty() {
        "crate".to_owned()
    } else {
        format!("crate::{}", module.components.join("::"))
    }
}

fn rust_symbol_namespace_key(namespace: RustSymbolNamespace) -> &'static str {
    match namespace {
        RustSymbolNamespace::Type => "type",
        RustSymbolNamespace::Value => "value",
        RustSymbolNamespace::Macro => "macro",
        RustSymbolNamespace::Module => "module",
    }
}

fn rust_import_graph_input_digests(
    usage: &brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts,
    declarations: &RustDeclarationFacts,
    imports: &[RustImportBinding],
) -> ImportGraphInputDigests {
    let mut binding_rows = Vec::new();
    for (identity, occurrences) in &declarations.domain_cfg_occurrences {
        for (domain, cfg) in occurrences {
            let mut row = CanonicalHasher::new(b"bifrost-rust-import-binding-input:v1");
            hash_symbol_identity(&mut row, identity);
            hash_domain(&mut row, domain);
            hash_cfg_condition(&mut row, cfg);
            binding_rows.push(row.finish());
        }
    }
    for (module, domain) in &declarations.declared_module_domains {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-module-input:v1");
        hash_module_key(&mut row, module);
        hash_domain(&mut row, domain);
        binding_rows.push(row.finish());
    }
    for module in &usage.modules {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-inline-module-input:v1");
        row.field("module", module.module_name.as_bytes());
        row.field("inline", &[u8::from(module.is_inline)]);
        hash_cfg_condition(&mut row, &module.cfg_condition);
        binding_rows.push(row.finish());
    }
    for scope in &usage.module_routes.scopes {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-module-scope-input:v1");
        hash_optional_usize(&mut row, "parent", scope.parent);
        row.field("module", scope.module_name.as_bytes());
        hash_optional_string(&mut row, "path", scope.path_attribute.as_deref());
        hash_visibility(&mut row, &scope.visibility);
        row.field("imports_macros", &[u8::from(scope.imports_macros)]);
        binding_rows.push(row.finish());
    }
    for route in &usage.module_routes.routes {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-module-route-input:v1");
        hash_usize(&mut row, "scope", route.scope);
        row.field("module", route.module_name.as_bytes());
        hash_optional_string(&mut row, "path", route.path_attribute.as_deref());
        hash_visibility(&mut row, &route.visibility);
        row.field("imports_macros", &[u8::from(route.imports_macros)]);
        row.field("test_gated", &[u8::from(route.test_gated)]);
        hash_cfg_condition(&mut row, &route.cfg_condition);
        row.sequence("gates", &route.gates, |hasher, gate| {
            hasher.field("macro", gate.macro_name.as_bytes());
        });
        binding_rows.push(row.finish());
    }
    for definition in &usage.module_routes.item_macros {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-item-macro-input:v1");
        row.field("name", definition.name.as_bytes());
        row.field("passthrough", &[u8::from(definition.passthrough)]);
        row.field("arguments_only", &[u8::from(definition.arguments_only)]);
        if let Some(decoration) = &definition.decoration {
            row.field("decoration_present", &[1]);
            hash_cfg_condition(&mut row, decoration);
        } else {
            row.field("decoration_present", &[0]);
        }
        row.field("declares_no_item", &[u8::from(definition.declares_no_item)]);
        row.field(
            "writes_only_impls",
            &[u8::from(definition.writes_only_impls)],
        );
        row.field("exported", &[u8::from(definition.exported)]);
        binding_rows.push(row.finish());
    }
    let binding_surface = digest_rows(b"bifrost-rust-import-binding-inputs:v1", binding_rows);

    let mut import_rows = Vec::new();
    for import in imports {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-row-input:v1");
        row.sequence("path", &import.path, |hasher, segment| {
            hasher.value(segment.as_bytes());
        });
        match &import.local_name {
            RustImportBindingName::Named(name) => {
                row.field("binding_kind", b"named");
                row.field("local_name", name.as_bytes());
            }
            RustImportBindingName::Unnamed => row.field("binding_kind", b"unnamed"),
            RustImportBindingName::Glob => row.field("binding_kind", b"glob"),
        }
        row.field("extern_crate", &[u8::from(import.is_extern_crate)]);
        row.field("macro_use", &[u8::from(import.is_macro_use)]);
        hash_visibility(&mut row, &import.visibility);
        hash_cfg_condition(&mut row, &import.cfg_condition);
        row.field("owner_module", import.owner_module.as_bytes());
        hash_module_key(&mut row, &import.importer_module);
        row.field(
            "extent_kind",
            match import.extent {
                brokk_bifrost_rust::usage::RustImportExtent::Module { .. } => b"module" as &[u8],
                brokk_bifrost_rust::usage::RustImportExtent::LocalOnly { .. } => b"local",
            },
        );
        import_rows.push(row.finish());
    }
    for export in &usage.exports {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-export-row-input:v1");
        hash_optional_string(&mut row, "exported_name", export.exported_name.as_deref());
        row.field("source_path", export.source_path.as_bytes());
        hash_optional_string(&mut row, "imported_name", export.imported_name.as_deref());
        row.field("glob", &[u8::from(export.is_glob)]);
        import_rows.push(row.finish());
    }
    for include in &usage.include_edges {
        let mut row = CanonicalHasher::new(b"bifrost-rust-import-include-row-input:v1");
        row.field("relative_path", include.relative_path.as_bytes());
        row.field("file_name", include.file_name.as_bytes());
        row.sequence(
            "host_bindings",
            &include.host_bindings,
            |hasher, binding| {
                hasher.field("local_name", binding.local_name.as_bytes());
                hasher.field("module_specifier", binding.module_specifier.as_bytes());
                hash_optional_string(hasher, "imported_name", binding.imported_name.as_deref());
                hasher.field(
                    "kind",
                    brokk_bifrost_core::analyzer::rust_facts::encode_rust_include_binding_kind(
                        binding.kind,
                    )
                    .as_bytes(),
                );
            },
        );
        import_rows.push(row.finish());
    }
    let import_rows = digest_rows(b"bifrost-rust-import-rows-inputs:v1", import_rows);
    ImportGraphInputDigests {
        binding_surface,
        import_rows,
    }
}

fn digest_rows(domain: &[u8], mut rows: Vec<[u8; 32]>) -> [u8; 32] {
    rows.sort_unstable();
    rows.dedup();
    let mut hasher = CanonicalHasher::new(domain);
    hasher.sequence("rows", &rows, |hasher, row| hasher.value(row));
    hasher.finish()
}

fn hash_symbol_identity(
    hasher: &mut CanonicalHasher,
    identity: &brokk_bifrost_rust::usage::RustSymbolIdentity,
) {
    hasher.field(
        "file",
        brokk_bifrost_core::path_utils::rel_path_string(&identity.file).as_bytes(),
    );
    hash_module_key(hasher, &identity.module);
    hasher.field("name", identity.name.as_bytes());
    hasher.field(
        "namespace",
        rust_symbol_namespace_key(identity.namespace).as_bytes(),
    );
}

fn hash_module_key(hasher: &mut CanonicalHasher, module: &ModuleKey) {
    hasher.field("crate_root", module.crate_root.as_bytes());
    hasher.sequence("components", &module.components, |hasher, component| {
        hasher.value(component.as_bytes());
    });
}

fn hash_domain(hasher: &mut CanonicalHasher, domain: &Domain) {
    match domain {
        Domain::Public => hasher.field("domain", b"public"),
        Domain::Crate(crate_root) => {
            hasher.field("domain", b"crate");
            hasher.field("crate_root", crate_root.as_bytes());
        }
        Domain::Module(module) => {
            hasher.field("domain", b"module");
            hash_module_key(hasher, module);
        }
    }
}

fn hash_visibility(hasher: &mut CanonicalHasher, visibility: &RustVisibility) {
    match visibility {
        RustVisibility::Private => hasher.field("visibility", b"private"),
        RustVisibility::Public => hasher.field("visibility", b"public"),
        RustVisibility::Crate => hasher.field("visibility", b"crate"),
        RustVisibility::SelfModule => hasher.field("visibility", b"self"),
        RustVisibility::SuperModule => hasher.field("visibility", b"super"),
        RustVisibility::InPath(segments) => {
            hasher.field("visibility", b"in_path");
            hasher.sequence("visibility_path", segments, |hasher, segment| {
                hasher.value(segment.as_bytes());
            });
        }
    }
}

fn hash_cfg_condition(hasher: &mut CanonicalHasher, condition: &RustCfgCondition) {
    match condition {
        RustCfgCondition::Always => hasher.field("cfg", b"always"),
        RustCfgCondition::Atom(atom) => {
            hasher.field("cfg", b"atom");
            hasher.field("atom", atom.as_bytes());
        }
        RustCfgCondition::NotAtom(atom) => {
            hasher.field("cfg", b"not_atom");
            hasher.field("atom", atom.as_bytes());
        }
        RustCfgCondition::Expression(instructions) => {
            hasher.field("cfg", b"expression");
            hasher.sequence(
                "instructions",
                instructions,
                |hasher, instruction| match instruction {
                    RustCfgInstruction::Atom(atom) => {
                        hasher.field("instruction", b"atom");
                        hasher.field("atom", atom.as_bytes());
                    }
                    RustCfgInstruction::KeyValue { key, value } => {
                        hasher.field("instruction", b"key_value");
                        hasher.field("key", key.as_bytes());
                        hasher.field("value", value.as_bytes());
                    }
                    RustCfgInstruction::Not => hasher.field("instruction", b"not"),
                    RustCfgInstruction::All(count) => {
                        hasher.field("instruction", b"all");
                        hash_usize(hasher, "count", *count);
                    }
                    RustCfgInstruction::Any(count) => {
                        hasher.field("instruction", b"any");
                        hash_usize(hasher, "count", *count);
                    }
                    RustCfgInstruction::Unknown => hasher.field("instruction", b"unknown"),
                },
            );
        }
        RustCfgCondition::Unknown => hasher.field("cfg", b"unknown"),
    }
}

fn hash_optional_string(hasher: &mut CanonicalHasher, name: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.field(&format!("{name}_present"), &[1]);
            hasher.field(name, value.as_bytes());
        }
        None => hasher.field(&format!("{name}_present"), &[0]),
    }
}

fn hash_optional_usize(hasher: &mut CanonicalHasher, name: &str, value: Option<usize>) {
    match value {
        Some(value) => {
            hasher.field(&format!("{name}_present"), &[1]);
            hash_usize(hasher, name, value);
        }
        None => hasher.field(&format!("{name}_present"), &[0]),
    }
}

fn hash_usize(hasher: &mut CanonicalHasher, name: &str, value: usize) {
    let value = u64::try_from(value).expect("usize fits u64 on supported targets");
    hasher.field(name, &value.to_be_bytes());
}

fn direct_imported_files(
    package_files: &brokk_bifrost_rust::graph_support::RustPackageFileIndex,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<ProjectFile> {
    imports
        .iter()
        .filter_map(|import| import.path.as_ref())
        .flat_map(|path| {
            brokk_bifrost_rust::graph_support::resolve_direct_import_files(
                package_files,
                file,
                &path.segments,
            )
        })
        .collect()
}

fn direct_import_file_edges(
    package_files: &brokk_bifrost_rust::graph_support::RustPackageFileIndex,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashMap<ProjectFile, Vec<serde_json::Value>> {
    let mut edges = HashMap::default();
    for import in imports {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        for target in brokk_bifrost_rust::graph_support::resolve_direct_import_files(
            package_files,
            file,
            &path.segments,
        ) {
            edges
                .entry(target)
                .or_insert_with(Vec::new)
                .push(serde_json::json!({ "kind": "rust_import_fact", "fact": import }));
        }
    }
    edges
}

fn persisted_binding_surface_rows_for_files(
    analyzer: &RustAnalyzer,
    files: &[ProjectFile],
    keep_going: &impl Fn() -> bool,
) -> Option<Vec<RustSummaryBindingSurfaceRow>> {
    if files.is_empty() {
        return Some(Vec::new());
    }
    if !keep_going() {
        return None;
    }
    let store = analyzer.inner.analyzer_store();
    let snapshots = analyzer.inner.selected_workspace_snapshots();
    let rel_paths = files
        .iter()
        .map(brokk_bifrost_core::path_utils::rel_path_string)
        .collect::<Vec<_>>();
    let completeness = match store.rust_summary_binding_completeness_rows(&snapshots, &rel_paths) {
        Ok(rows) => rows,
        Err(error) => {
            analyzer.inner.record_store_error(
                error.context("reading Rust import graph binding completeness for member routes"),
            );
            return None;
        }
    };
    let mut complete_paths = HashSet::default();
    for row in completeness {
        if !row.complete {
            return None;
        }
        assert!(
            complete_paths.insert(row.rel_path),
            "one complete Rust summary completeness row exists per member"
        );
    }
    if !keep_going() || complete_paths.len() != rel_paths.len() {
        return None;
    }
    let rows = match store.rust_summary_binding_surface_rows(&snapshots, &rel_paths) {
        Ok(rows) => rows,
        Err(error) => {
            analyzer
                .inner
                .record_store_error(error.context("reading Rust import graph member routes"));
            return None;
        }
    };
    keep_going().then_some(rows)
}

fn rust_import_edge_facts_from_summary(
    package_files: &brokk_bifrost_rust::graph_support::RustPackageFileIndex,
    file: &ProjectFile,
    bindings: &[RustImportBinding],
    surface_rows: &[RustSummaryBindingSurfaceRow],
    selected_ordinals: Option<&[u32]>,
    keep_going: &impl Fn() -> bool,
) -> Option<Vec<ImportedFileEdgeFacts>> {
    let mut ordinals = selected_ordinals.map_or_else(
        || {
            (0..bindings.len())
                .map(|ordinal| {
                    u32::try_from(ordinal)
                        .expect("one Rust source cannot contain more than u32 imports")
                })
                .collect::<Vec<_>>()
        },
        <[u32]>::to_vec,
    );
    ordinals.sort_unstable();
    ordinals.dedup();
    let mut by_ordinal = std::collections::BTreeMap::new();
    for ordinal in &ordinals {
        assert!(
            usize::try_from(*ordinal).is_ok_and(|index| index < bindings.len()),
            "selected Rust import ordinal exists in the canonical source facts"
        );
        by_ordinal.insert(*ordinal, HashMap::default());
    }
    for ordinal in &ordinals {
        if !keep_going() {
            return None;
        }
        let binding = &bindings
            [usize::try_from(*ordinal).expect("Rust import ordinal fits the source binding index")];
        let edges = by_ordinal
            .get_mut(ordinal)
            .expect("selected Rust import ordinal was initialized");
        for target in brokk_bifrost_rust::graph_support::resolve_direct_import_files(
            package_files,
            file,
            &binding.path,
        ) {
            edges
                .entry(target)
                .or_insert_with(Vec::new)
                .push(serde_json::json!({
                    "kind": "rust_import_fact",
                    "import_ordinal": ordinal,
                    "path": binding.path,
                    "owner_module": binding.owner_module
                }));
        }
    }

    let route_facts = rust_import_origin_route_facts_from_summary(
        file,
        bindings,
        surface_rows,
        Some(&ordinals),
        keep_going,
    )?;
    for (ordinal, route_edges) in route_facts {
        let edges = by_ordinal
            .get_mut(&ordinal)
            .expect("persisted route belongs to a selected source import");
        for (target, provenance) in route_edges {
            edges
                .entry(target)
                .or_insert_with(Vec::new)
                .extend(provenance);
        }
    }
    Some(
        by_ordinal
            .into_iter()
            .map(|(import_ordinal, edges)| ImportedFileEdgeFacts {
                import_ordinal,
                edges,
            })
            .collect(),
    )
}

fn rust_import_origin_route_facts_from_summary(
    file: &ProjectFile,
    bindings: &[RustImportBinding],
    surface_rows: &[RustSummaryBindingSurfaceRow],
    selected_ordinals: Option<&[u32]>,
    keep_going: &impl Fn() -> bool,
) -> Option<std::collections::BTreeMap<u32, HashMap<ProjectFile, Vec<serde_json::Value>>>> {
    let selected =
        selected_ordinals.map(|ordinals| ordinals.iter().copied().collect::<HashSet<_>>());
    let rel_path = brokk_bifrost_core::path_utils::rel_path_string(file);
    let mut route_groups: std::collections::BTreeMap<
        (u32, i64),
        Vec<&RustSummaryBindingSurfaceRow>,
    > = std::collections::BTreeMap::new();
    for row in surface_rows.iter().filter(|row| row.rel_path == rel_path) {
        let Some(import_ordinal) = row.source_import_ordinal else {
            assert!(
                row.source_import_id.is_none(),
                "Rust summary source import id and ordinal are both present or absent"
            );
            continue;
        };
        assert!(
            row.source_import_id.is_some(),
            "Rust summary source import id and ordinal are both present or absent"
        );
        let import_ordinal = u32::try_from(import_ordinal)
            .expect("Rust source import ordinal is nonnegative and fits u32");
        if selected
            .as_ref()
            .is_none_or(|selected| selected.contains(&import_ordinal))
        {
            route_groups
                .entry((import_ordinal, row.route_ordinal))
                .or_default()
                .push(row);
        }
    }
    let mut route_facts = std::collections::BTreeMap::new();
    for ((import_ordinal, _), rows) in route_groups {
        if !keep_going() {
            return None;
        }
        let binding = bindings
            .get(usize::try_from(import_ordinal).expect("Rust import ordinal fits usize"))?;
        let route_files = rows
            .iter()
            .filter(|row| row.route_file != rel_path)
            .map(|row| ProjectFile::new(file.root().to_path_buf(), row.route_file.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let route = rust_origin_route_provenance_from_summary(file, binding, &rows, route_files)?;
        let origin_file = ProjectFile::new(file.root().to_path_buf(), rows[0].origin_file.clone());
        route_facts
            .entry(import_ordinal)
            .or_insert_with(HashMap::default)
            .entry(origin_file)
            .or_insert_with(Vec::new)
            .push(route);
    }
    Some(route_facts)
}

#[cfg(test)]
fn rust_import_edge_facts_for_file(
    walks: &RustUsageWalks<'_>,
    file: &ProjectFile,
    selected_ordinals: Option<&[u32]>,
    keep_going: &impl Fn() -> bool,
) -> Result<Vec<ImportedFileEdgeFacts>, brokk_bifrost_rust::graph_support::RustCargoRouteError> {
    let bindings = walks.import_bindings_of(file)?;
    let mut ordinals = selected_ordinals.map_or_else(
        || {
            (0..bindings.len())
                .map(|ordinal| {
                    u32::try_from(ordinal)
                        .expect("one Rust source cannot contain more than u32 imports")
                })
                .collect::<Vec<_>>()
        },
        <[u32]>::to_vec,
    );
    ordinals.sort_unstable();
    ordinals.dedup();

    let mut by_ordinal = std::collections::BTreeMap::new();
    for ordinal in &ordinals {
        assert!(
            usize::try_from(*ordinal).is_ok_and(|index| index < bindings.len()),
            "selected Rust import ordinal exists in the canonical source facts"
        );
        by_ordinal.insert(*ordinal, HashMap::default());
    }
    for ordinal in &ordinals {
        if !keep_going() {
            return Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled);
        }
        let binding = &bindings
            [usize::try_from(*ordinal).expect("Rust import ordinal fits the source binding index")];
        let edges = by_ordinal
            .get_mut(ordinal)
            .expect("selected Rust import ordinal was initialized");
        for target in brokk_bifrost_rust::graph_support::resolve_direct_import_files(
            walks.package_files(),
            file,
            &binding.path,
        ) {
            edges
                .entry(target)
                .or_insert_with(Vec::new)
                .push(serde_json::json!({
                    "kind": "rust_import_fact",
                    "import_ordinal": ordinal,
                    "path": binding.path,
                    "owner_module": binding.owner_module
                }));
        }
    }
    match walks.origin_routes_of(file) {
        Ok(routes) => {
            for route in routes.values().flatten() {
                if !keep_going() {
                    return Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled);
                }
                if let Some(edges) = by_ordinal.get_mut(&route.import_ordinal) {
                    edges
                        .entry(route.origin.file.clone())
                        .or_insert_with(Vec::new)
                        .push(rust_origin_route_provenance(route));
                }
            }
        }
        Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {}
        Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
            return Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled);
        }
    }
    Ok(by_ordinal
        .into_iter()
        .map(|(import_ordinal, edges)| ImportedFileEdgeFacts {
            import_ordinal,
            edges,
        })
        .collect())
}

fn rust_origin_route_provenance(
    route: &brokk_bifrost_rust::usage::RustOriginRoute,
) -> serde_json::Value {
    let extent = match &route.extent {
        brokk_bifrost_rust::usage::RustImportExtent::Module { start, end } => {
            serde_json::json!({ "kind": "module", "start": start, "end": end })
        }
        brokk_bifrost_rust::usage::RustImportExtent::LocalOnly {
            module_start,
            module_end,
            start,
            end,
        } => serde_json::json!({
            "kind": "local_only",
            "module_start": module_start,
            "module_end": module_end,
            "start": start,
            "end": end
        }),
    };
    serde_json::json!({
        "kind": "rust_origin_route",
        "importer_module": {
            "crate_root": route.importer_module.crate_root,
            "components": route.importer_module.components
        },
        "extent": extent,
        "path": route.path,
        "is_glob_import": route.is_glob_import,
        "namespace": format!("{:?}", route.namespace),
        "route_files": route
            .route_files
            .iter()
            .map(crate::path_utils::rel_path_string)
            .collect::<Vec<_>>(),
        "origin": {
            "file": crate::path_utils::rel_path_string(&route.origin.file),
            "module": {
                "crate_root": route.origin.module.crate_root,
                "components": route.origin.module.components
            },
            "name": route.origin.name,
            "namespace": format!("{:?}", route.origin.namespace)
        },
        "domain": format!("{:?}", route.domain),
        "provenance": format!("{:?}", route.provenance),
        "cfg_condition": format!("{:?}", route.cfg_condition)
    })
}

fn rust_origin_route_provenance_from_summary(
    root_file: &ProjectFile,
    binding: &RustImportBinding,
    rows: &[&RustSummaryBindingSurfaceRow],
    route_files: Vec<ProjectFile>,
) -> Option<serde_json::Value> {
    let row = *rows.first()?;
    let import_ordinal = u32::try_from(row.source_import_ordinal?)
        .expect("Rust source import ordinal is nonnegative and fits u32");
    let path = match &binding.local_name {
        RustImportBindingName::Glob => vec![row.origin_name.clone()],
        RustImportBindingName::Unnamed => return None,
        RustImportBindingName::Named(local_name) if row.namespace == "module" => {
            vec![local_name.to_string(), row.origin_name.clone()]
        }
        RustImportBindingName::Named(local_name) => vec![local_name.to_string()],
    };
    let namespace = match row.namespace.as_str() {
        "type" => RustSymbolNamespace::Type,
        "value" => RustSymbolNamespace::Value,
        "macro" => RustSymbolNamespace::Macro,
        "module" => RustSymbolNamespace::Module,
        other => panic!("unknown Rust summary namespace {other:?}"),
    };
    let root_components: Vec<String> = serde_json::from_str(&row.root_components).ok()?;
    let crate_root = root_components.join(".");
    let module_package =
        resolve_rust_module_path_with_crate(&crate_root, &crate_root, &row.module_path)?;
    let module = ModuleKey::with_crate_root(&crate_root, &module_package);
    let origin_root_components: Vec<String> =
        serde_json::from_str(&row.origin_root_components).ok()?;
    let origin_crate_root = origin_root_components.join(".");
    let origin_package = resolve_rust_module_path_with_crate(
        &origin_crate_root,
        &origin_crate_root,
        &row.origin_module_path,
    )?;
    let origin_module = ModuleKey::with_crate_root(&origin_crate_root, &origin_package);
    let origin = RustSymbolIdentity {
        file: ProjectFile::new(root_file.root().to_path_buf(), row.origin_file.clone()),
        module: origin_module,
        name: row.origin_name.clone(),
        namespace,
    };
    let domain = match row.visibility_kind.as_str() {
        "public" => Domain::Public,
        "crate" => Domain::Crate(row.visibility_crate_root.clone()?),
        "module" => Domain::Module(module),
        other => panic!("unknown Rust summary visibility kind {other:?}"),
    };
    let provenance = match (
        row.root_crate_name.as_deref(),
        row.root_target_kind.as_deref(),
        row.edge_crate_name.as_deref(),
        row.edge_target_kind.as_deref(),
    ) {
        (Some(root_crate), Some(root_kind), Some(edge_crate), Some(edge_kind))
            if root_crate == edge_crate && root_kind == edge_kind =>
        {
            RustRouteProvenance::Local
        }
        (Some(root_crate), Some(_), Some(edge_crate), Some("lib")) if root_crate == edge_crate => {
            RustRouteProvenance::CurrentLibrary
        }
        _ => RustRouteProvenance::Dependency,
    };
    let route = RustOriginRoute {
        import_ordinal,
        importer_module: binding.importer_module.clone(),
        extent: binding.extent.clone(),
        path,
        is_glob_import: binding.local_name.is_glob(),
        namespace,
        origin,
        domain,
        route_files,
        provenance,
        cfg_condition: binding.cfg_condition.clone(),
    };
    Some(rust_origin_route_provenance(&route))
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::imports::*;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    use std::collections::BTreeSet;

    #[test]
    fn reverse_importers_from_live_summaries_match_import_resolution() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"reverse_summary\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub mod api; mod named; mod glob;\n")
            .file("src/api.rs", "pub struct Api; pub fn call() {}\n")
            .file(
                "src/named.rs",
                "use crate::api::Api; pub fn named(_: Api) {}\n",
            )
            .file("src/glob.rs", "use crate::api::*; pub fn glob(_: Api) {}\n")
            .build();
        let workspace = fixture
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer())
            .expect("workspace contains the Rust analyzer");
        let target = fixture.file("src/api.rs");
        let files = analyzer.inner.all_files();
        let expected = files
            .iter()
            .filter(|candidate| {
                analyzer
                    .imported_code_units_of(candidate)
                    .iter()
                    .any(|definition| definition.source() == &target)
            })
            .cloned()
            .collect::<HashSet<_>>();

        let actual = analyzer.referencing_files_of(&target);
        assert_eq!(
            actual, expected,
            "summary reverse-importer symmetric difference"
        );
        assert_eq!(
            actual,
            [fixture.file("src/named.rs")]
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn persisted_import_graph_binding_surfaces_match_rust_usage_walks() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"binding_surface_diff\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod api; pub mod facade; mod consumer;\n")
            .file("src/api.rs", "pub struct Item; pub fn call() {}\n")
            .file(
                "src/facade.rs",
                "pub use crate::api::Item as Renamed; pub use crate::api::*; pub mod child;\n",
            )
            .file(
                "src/facade/child.rs",
                "use super::Renamed; pub fn child(_: Renamed) {}\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::facade::Renamed as Consumed; pub fn consumer(_: Consumed) {}\n",
            )
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer())
            .expect("workspace contains the Rust analyzer");
        let files = analyzer.inner.all_files();
        let actual = analyzer
            .import_graph_binding_surfaces_for_files(&files, None)
            .expect("live summaries provide complete binding surfaces");

        let scope = AnalyzerQueryScope::new(analyzer);
        let walks = RustUsageWalks::new(analyzer, scope.token())
            .expect("fixture Rust routes are available");
        for file in &files {
            let mut expected = Vec::new();
            for module in walks
                .binding_modules_of(file)
                .expect("legacy walk enumerates the file's binding modules")
            {
                for binding in walks
                    .bindings_at(file, &module)
                    .expect("legacy walk resolves the module's binding closure")
                    .iter()
                {
                    let (visibility_kind, visibility_scope) = match &binding.domain {
                        Domain::Public => ("public", String::new()),
                        Domain::Crate(crate_root) => ("crate", crate_root.clone()),
                        Domain::Module(module) => ("module", rust_module_surface_key(module)),
                    };
                    let mut route_files = binding.route_files.clone();
                    route_files.sort();
                    expected.push(ImportGraphBindingSurface {
                        module_path: rust_module_surface_key(&module),
                        name: binding.name.clone(),
                        namespace: rust_symbol_namespace_key(binding.namespace).to_owned(),
                        visibility_kind: visibility_kind.to_owned(),
                        visibility_scope,
                        origin_file: binding.origin.file.clone(),
                        origin_module_path: rust_module_surface_key(&binding.origin.module),
                        origin_name: binding.origin.name.clone(),
                        route_files,
                    });
                }
            }
            let expected: HashSet<_> = expected.into_iter().collect();
            let actual_for_file: HashSet<_> = actual
                .get(file)
                .expect("summary reader returns each requested file")
                .iter()
                .cloned()
                .collect();
            let walk_only = expected.difference(&actual_for_file).collect::<Vec<_>>();
            let persisted_only = actual_for_file.difference(&expected).collect::<Vec<_>>();
            assert!(
                walk_only.is_empty() && persisted_only.is_empty(),
                "persisted versus walk binding surfaces differ for {file:?}: walk-only={walk_only:#?}; persisted-only={persisted_only:#?}"
            );
        }
    }

    #[test]
    fn persisted_import_resolution_dependencies_match_rust_usage_walks() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"import_dependencies_diff\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod origin; pub mod facade; mod client;\n")
            .file("src/origin.rs", "pub struct Item;\n")
            .file("src/facade.rs", "pub use crate::origin::Item as Renamed;\n")
            .file(
                "src/client.rs",
                "use crate::facade::Renamed as Local; fn use_item(_: Local) {}\n",
            )
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer())
            .expect("workspace contains the Rust analyzer");
        let files = analyzer.inner.all_files();
        let actual = analyzer
            .import_resolution_dependencies_for_ordinals(
                &files,
                None,
                &brokk_bifrost_core::hash::HashMap::default(),
                None,
            )
            .expect("live Rust summaries provide import dependencies");

        let scope = AnalyzerQueryScope::new(analyzer);
        let walks = RustUsageWalks::new(analyzer, scope.token())
            .expect("fixture Rust routes are available");
        let mut actual_edge_facts = HashMap::default();
        analyzer
            .for_each_import_edge_facts_from_infos(
                &files,
                None,
                &HashMap::default(),
                None,
                &mut |file, facts| {
                    actual_edge_facts.insert(file.clone(), facts);
                    true
                },
            )
            .expect("live summary rows provide import edge facts");
        let normalize_edge_facts = |facts: &[ImportedFileEdgeFacts]| {
            let mut normalized = std::collections::BTreeMap::new();
            for fact in facts {
                for (target, values) in &fact.edges {
                    let key = (
                        fact.import_ordinal,
                        brokk_bifrost_core::path_utils::rel_path_string(target),
                    );
                    let mut values = values
                        .iter()
                        .map(|value| serde_json::to_string(value).expect("JSON value serializes"))
                        .collect::<Vec<_>>();
                    values.sort_unstable();
                    normalized.insert(key, values);
                }
            }
            normalized
        };
        let package_files = analyzer
            .package_file_index_while(scope.token(), &|| true)
            .expect("fixture package members are published");
        let mut actual_bulk_edges = HashMap::default();
        analyzer
            .for_each_imported_file_edges_from_infos(&files, None, None, &mut |file, edges| {
                actual_bulk_edges.insert(file.clone(), edges);
                true
            })
            .expect("live summary rows provide imported-file edge facts");
        let normalize_file_edges = |edges: &HashMap<ProjectFile, Vec<serde_json::Value>>| {
            edges
                .iter()
                .map(|(file, values)| {
                    let mut values = values
                        .iter()
                        .map(|value| serde_json::to_string(value).expect("JSON value serializes"))
                        .collect::<Vec<_>>();
                    values.sort_unstable();
                    (
                        brokk_bifrost_core::path_utils::rel_path_string(file),
                        values,
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        for file in &files {
            let expected = walks
                .import_resolution_dependencies_for_ordinals(file, None)
                .expect("legacy walk enumerates import dependencies");
            let actual = actual
                .get(file)
                .expect("summary reader returns every requested file");
            let lookups = |dependencies: &brokk_bifrost_core::analyzer::capabilities::ImportResolutionDependencies| {
                dependencies
                    .lookups
                    .iter()
                    .map(|lookup| {
                        (
                            lookup.import_ordinal,
                            brokk_bifrost_core::path_utils::rel_path_string(&lookup.consulted_file),
                            lookup.name.clone(),
                        )
                    })
                    .collect::<std::collections::BTreeSet<_>>()
            };
            let expected_lookups = lookups(&expected);
            let actual_lookups = lookups(actual);
            let walk_only = expected_lookups
                .difference(&actual_lookups)
                .collect::<Vec<_>>();
            let summary_only = actual_lookups
                .difference(&expected_lookups)
                .collect::<Vec<_>>();
            let expected_missing = expected
                .missing_module_path_keys
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let actual_missing = actual
                .missing_module_path_keys
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let walk_missing = expected_missing
                .difference(&actual_missing)
                .collect::<Vec<_>>();
            let summary_missing = actual_missing
                .difference(&expected_missing)
                .collect::<Vec<_>>();
            assert!(
                walk_only.is_empty()
                    && summary_only.is_empty()
                    && walk_missing.is_empty()
                    && summary_missing.is_empty(),
                "persisted versus walk import dependencies differ for {file:?}: \
                 walk-only lookups={walk_only:#?}; summary-only lookups={summary_only:#?}; \
                 walk-only missing modules={walk_missing:#?}; \
                 summary-only missing modules={summary_missing:#?}"
            );
            let walk_edges = rust_import_edge_facts_for_file(&walks, file, None, &|| true)
                .expect("legacy walk enumerates import edge facts");
            let summary_edges = actual_edge_facts
                .get(file)
                .expect("summary reader returns each requested file");
            let walk_edges = normalize_edge_facts(&walk_edges);
            let summary_edges = normalize_edge_facts(summary_edges);
            let walk_only = walk_edges
                .iter()
                .filter(|(key, value)| summary_edges.get(key) != Some(value))
                .collect::<Vec<_>>();
            let summary_only = summary_edges
                .iter()
                .filter(|(key, value)| walk_edges.get(key) != Some(value))
                .collect::<Vec<_>>();
            assert!(
                walk_only.is_empty() && summary_only.is_empty(),
                "persisted versus walk import edge facts differ for {file:?}: \
                 walk-only={walk_only:#?}; summary-only={summary_only:#?}"
            );

            let imports = analyzer.inner.import_info_of(scope.token(), file);
            let expected_imported = direct_imported_files(&package_files, file, &imports);
            let mut expected_imported = expected_imported;
            for route in walks
                .origin_routes_of(file)
                .expect("legacy walk enumerates origin routes")
                .values()
                .flatten()
            {
                expected_imported.insert(route.origin.file.clone());
            }
            let actual_imported = analyzer
                .imported_files_from_infos(file, &imports)
                .expect("live summary rows provide imported files");
            let expected_imported = expected_imported
                .iter()
                .map(brokk_bifrost_core::path_utils::rel_path_string)
                .collect::<std::collections::BTreeSet<_>>();
            let actual_imported = actual_imported
                .iter()
                .map(brokk_bifrost_core::path_utils::rel_path_string)
                .collect::<std::collections::BTreeSet<_>>();
            let walk_only = expected_imported
                .difference(&actual_imported)
                .collect::<Vec<_>>();
            let summary_only = actual_imported
                .difference(&expected_imported)
                .collect::<Vec<_>>();
            assert!(
                walk_only.is_empty() && summary_only.is_empty(),
                "persisted versus walk imported files differ for {file:?}: \
                 walk-only={walk_only:#?}; summary-only={summary_only:#?}"
            );

            let expected_provenance = rust_import_edge_facts_for_file(&walks, file, None, &|| true)
                .expect("legacy walk enumerates imported-file provenance")
                .into_iter()
                .flat_map(|fact| fact.edges)
                .fold(HashMap::default(), |mut all, (target, values)| {
                    all.entry(target).or_insert_with(Vec::new).extend(values);
                    all
                });
            let actual_provenance = analyzer
                .imported_file_edge_provenance_from_infos(file, &imports)
                .expect("live summary rows provide imported-file provenance");
            let expected_provenance = normalize_file_edges(&expected_provenance);
            let actual_provenance = normalize_file_edges(&actual_provenance);
            assert_eq!(
                actual_provenance, expected_provenance,
                "persisted versus walk imported-file provenance differs for {file:?}"
            );

            let mut expected_bulk = direct_import_file_edges(&package_files, file, &imports);
            for route in walks
                .origin_routes_of(file)
                .expect("legacy walk enumerates bulk origin routes")
                .values()
                .flatten()
            {
                expected_bulk
                    .entry(route.origin.file.clone())
                    .or_default()
                    .push(rust_origin_route_provenance(route));
            }
            let actual_bulk = actual_bulk_edges
                .get(file)
                .expect("bulk summary reader returns every requested file");
            assert_eq!(
                normalize_file_edges(actual_bulk),
                normalize_file_edges(&expected_bulk),
                "persisted versus walk bulk imported-file edges differ for {file:?}"
            );
        }
    }

    #[test]
    fn rust_import_graph_input_digests_ignore_bodies_but_track_bindings_and_imports() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"input_digest_cutoff\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub struct Existing;\npub fn run() { let local = 1; let _ = local; }\n",
            )
            .build();
        let file: ProjectFile = project.file("src/lib.rs");
        let analyzer = RustAnalyzer::new(project.project_dyn());
        assert_eq!(
            analyzer.get_analyzed_files(),
            BTreeSet::from([file.clone()])
        );

        let digest_for = |analyzer: &RustAnalyzer| {
            analyzer
                .import_graph_input_digests_for_files(std::slice::from_ref(&file), None)
                .expect("complete Rust input digests")
                .remove(&file)
                .expect("one input digest for the source")
        };
        let before = digest_for(&analyzer);

        file.write("pub struct Existing;\npub fn run() { let local = 2; let _ = local; }\n")
            .expect("edit only the function body");
        let body_edit = analyzer.update(&BTreeSet::from([file.clone()]));
        let body_digest = digest_for(&body_edit);
        assert_eq!(body_digest, before, "body-only edits preserve both digests");

        file.write(
            "pub struct Existing;\npub fn added_public_item() {}\npub fn run() { let local = 2; let _ = local; }\n",
        )
        .expect("add a module-level item");
        let binding_edit = body_edit.update(&BTreeSet::from([file.clone()]));
        let binding_digest = digest_for(&binding_edit);
        assert_ne!(
            binding_digest.binding_surface, body_digest.binding_surface,
            "new module-level bindings change the binding digest"
        );
        assert_eq!(
            binding_digest.import_rows, body_digest.import_rows,
            "a declaration-only edit leaves import binders unchanged"
        );

        file.write(
            "use std::fmt::Display;\npub struct Existing;\npub fn added_public_item() {}\npub fn run() { let local = 2; let _ = local; }\n",
        )
        .expect("add an import binder");
        let import_edit = binding_edit.update(&BTreeSet::from([file.clone()]));
        let import_digest = digest_for(&import_edit);
        assert_eq!(
            import_digest.binding_surface, binding_digest.binding_surface,
            "a use-only edit leaves declared binding surface unchanged"
        );
        assert_ne!(
            import_digest.import_rows, binding_digest.import_rows,
            "new import binders change the import digest"
        );
    }
}
