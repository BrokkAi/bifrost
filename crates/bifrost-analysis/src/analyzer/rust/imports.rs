//! `ImportAnalysisProvider` for Rust: the memoization shell around
//! [`brokk_bifrost_rust::imports`].
//!
//! Only the caching stays here. The two moka caches are analyzer state, so each
//! method below fetches or fills a cache slot and hands the actual resolution to
//! the Rust crate through the [`RustSource`] the analyzer implements.

use crate::analyzer::{
    CodeUnit, ImportAnalysisProvider, ImportGraphBindingSurface, ImportGraphInputDigests,
    ImportInfo, ImportedFileEdgeFacts, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::rust_facts::{RustCfgInstruction, RustVisibility};
use brokk_bifrost_rust::declarations::rust_package_name;
use brokk_bifrost_rust::imports::RustImportBindingName;
use brokk_bifrost_rust::imports::{
    resolve_rust_import_fq_name, rust_could_import_file, rust_crate_root_package,
    rust_imported_code_units,
};
use brokk_bifrost_rust::lexical_scope::RustCfgCondition;
use brokk_bifrost_rust::usage::{Domain, ModuleKey, RustSymbolNamespace};
use brokk_bifrost_rust::usage_queries::{
    RustDeclarationFacts, RustImportBinding, RustUsageQueries,
};
use brokk_bifrost_rust::usage_walks::RustUsageWalks;
use std::sync::Arc;

use super::RustAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

impl ImportAnalysisProvider for RustAnalyzer {
    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, Vec<crate::analyzer::ImportInfo>>> {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn has_complete_import_resolution_dependencies(&self) -> bool {
        true
    }

    fn import_graph_module_path_keys_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, Vec<String>>> {
        let mut keys = crate::hash::HashMap::default();
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
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<crate::hash::HashMap<ProjectFile, Vec<ImportGraphBindingSurface>>> {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let walks = match RustUsageWalks::new_while(self, scope.token(), &keep_going) {
            Ok(walks) => walks,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
            | Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                return None;
            }
        };
        let mut surfaces = crate::hash::HashMap::default();
        for file in files {
            if !keep_going() {
                return None;
            }
            let mut surface = Vec::new();
            for module in walks.binding_modules_of(file).ok()? {
                if !keep_going() {
                    return None;
                }
                for binding in walks.bindings_at(file, &module).ok()?.iter() {
                    let (visibility_kind, visibility_scope) = match &binding.domain {
                        Domain::Public => ("public", String::new()),
                        Domain::Crate(crate_root) => ("crate", crate_root.clone()),
                        Domain::Module(module) => ("module", rust_module_surface_key(module)),
                    };
                    surface.push(ImportGraphBindingSurface {
                        module_path: rust_module_surface_key(&module),
                        name: binding.name.clone(),
                        namespace: rust_symbol_namespace_key(binding.namespace).to_owned(),
                        visibility_kind: visibility_kind.to_owned(),
                        visibility_scope,
                        origin_file: binding.origin.file.clone(),
                        origin_module_path: rust_module_surface_key(&binding.origin.module),
                        origin_name: binding.origin.name.clone(),
                        route_files: binding.route_files.clone(),
                    });
                }
            }
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
            surfaces.insert(file.clone(), surface);
        }
        Some(surfaces)
    }

    fn import_graph_input_digests_for_files(
        &self,
        files: &[ProjectFile],
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<crate::hash::HashMap<ProjectFile, ImportGraphInputDigests>> {
        let queries = RustUsageQueries::new(self);
        let mut digests = crate::hash::HashMap::default();
        for file in files {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
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
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::ImportResolutionDependencies>>
    {
        self.import_resolution_dependencies_for_ordinals(
            files,
            import_infos,
            &crate::hash::HashMap::default(),
            cancellation,
        )
    }

    fn import_resolution_dependencies_for_ordinals(
        &self,
        files: &[ProjectFile],
        _import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &crate::hash::HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::ImportResolutionDependencies>>
    {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let walks = match RustUsageWalks::new_while(self, scope.token(), &keep_going) {
            Ok(walks) => walks,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable)
            | Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                return None;
            }
        };
        let mut dependencies = crate::hash::HashMap::default();
        for file in files {
            if !keep_going() {
                return None;
            }
            let selected = selected_ordinals
                .get(file)
                .map(|ordinals| ordinals.as_slice());
            dependencies.insert(
                file.clone(),
                walks
                    .import_resolution_dependencies_for_ordinals(file, selected)
                    .ok()?,
            );
        }
        Some(dependencies)
    }

    fn for_each_import_edge_facts_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &crate::hash::HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, Vec<ImportedFileEdgeFacts>) -> bool,
    ) -> Option<()> {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let token = scope.token();
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let walks = match RustUsageWalks::new_while(self, token, &keep_going) {
            Ok(walks) => walks,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return None;
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                return Some(());
            }
        };
        for file in files {
            if !keep_going() {
                return Some(());
            }
            let owned_imports;
            let imports = if let Some(imports) = import_infos.and_then(|infos| infos.get(file)) {
                imports.as_slice()
            } else {
                owned_imports = self.inner.import_info_of(token, file);
                &owned_imports
            };
            let facts = match rust_import_edge_facts_for_file(
                self,
                &walks,
                file,
                selected_ordinals.get(file).map(Vec::as_slice),
                &keep_going,
            ) {
                Ok(facts) => facts,
                Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                    return Some(());
                }
                Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                    vec![ImportedFileEdgeFacts {
                        import_ordinal: u32::MAX,
                        edges: direct_import_file_edges(self, file, imports),
                    }]
                }
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
        let walks = match RustUsageWalks::new(self, scope.token()) {
            Ok(walks) => walks,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return Some(direct_import_file_edges(self, file, imports));
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                unreachable!("uncancelled Rust import provenance lookup cannot be cancelled")
            }
        };
        let facts = match rust_import_edge_facts_for_file(self, &walks, file, None, &|| true) {
            Ok(facts) => facts,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                return Some(direct_import_file_edges(self, file, imports));
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                unreachable!("uncancelled Rust import provenance lookup cannot be cancelled")
            }
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

        let resolved = Arc::new(rust_imported_code_units(
            self,
            file,
            &self.inner.import_info_of(token, file),
        ));

        self.imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let mut imported_files = direct_imported_files(self, file, imports);
        if imports.is_empty() {
            return Some(imported_files);
        }

        let scope = AnalyzerQueryScope::new(self);
        let walks = match RustUsageWalks::new(self, scope.token()) {
            Ok(walks) => walks,
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                // Cargo route construction records its structured store
                // failure on the active query. Keep the module-file edges
                // already resolved; the query boundary reports that failure.
                return Some(imported_files);
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                unreachable!("uncancelled Rust import-file resolution cannot be cancelled")
            }
        };
        match extend_origin_files(&walks, file, &mut imported_files) {
            Ok(()) => {}
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable) => {
                // Route reads record the store failure on the active query.
            }
            Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                unreachable!("uncancelled Rust import-file resolution cannot be cancelled")
            }
        }
        Some(imported_files)
    }

    fn for_each_imported_files_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
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
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, HashMap<ProjectFile, Vec<serde_json::Value>>) -> bool,
    ) -> Option<()> {
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |cancellation| AnalyzerQueryScope::with_cancellation(self, cancellation),
        );
        let token = scope.token();
        let keep_going = || cancellation.is_none_or(|token| !token.is_cancelled());
        let mut walks = None;
        let mut walks_unavailable = false;
        for file in files {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                return Some(());
            }
            let owned_imports;
            let imports = if let Some(imports) = import_infos.and_then(|infos| infos.get(file)) {
                imports.as_slice()
            } else {
                owned_imports = self.inner.import_info_of(token, file);
                &owned_imports
            };
            let mut imported_edges = direct_import_file_edges(self, file, imports);
            if !imports.is_empty() && !walks_unavailable {
                if walks.is_none() {
                    let walk = if cancellation.is_some() {
                        RustUsageWalks::new_while(self, token, &keep_going)
                    } else {
                        RustUsageWalks::new(self, token)
                    };
                    match walk {
                        Ok(resolved) => walks = Some(resolved),
                        Err(
                            brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable,
                        ) => {
                            walks_unavailable = true;
                        }
                        Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                            return Some(());
                        }
                    }
                }
                if let Some(walks) = &walks {
                    match walks.origin_routes_of(file) {
                        Ok(routes) => {
                            for route in routes.values().flatten() {
                                imported_edges
                                    .entry(route.origin.file.clone())
                                    .or_default()
                                    .push(rust_origin_route_provenance(route));
                            }
                        }
                        Err(
                            brokk_bifrost_rust::graph_support::RustCargoRouteError::Unavailable,
                        ) => {}
                        Err(brokk_bifrost_rust::graph_support::RustCargoRouteError::Cancelled) => {
                            return Some(());
                        }
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
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Option<crate::analyzer::AdditionalFileDependencies> {
        let routes = match self.cargo_routes_while(&|| !cancellation.is_cancelled()) {
            Ok(routes) => routes,
            Err(super::RustCargoRouteError::Cancelled) => return None,
            Err(super::RustCargoRouteError::Unavailable) => {
                // The route reader records the publication error on the query.
                // Preserve incompleteness here so no caller caches an empty graph.
                return Some(crate::analyzer::AdditionalFileDependencies::incomplete(
                    crate::hash::HashMap::default(),
                ));
            }
        };
        let selected: HashSet<_> = files.iter().cloned().collect();
        let mut dependencies: crate::hash::HashMap<ProjectFile, HashSet<ProjectFile>> =
            crate::hash::HashMap::default();
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
        Some(crate::analyzer::AdditionalFileDependencies::complete(
            dependencies,
        ))
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
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::cancellation::CancellationToken,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        use rayon::prelude::*;

        let mut fq_names: Vec<String> = files
            .par_iter()
            .flat_map_iter(|file| {
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
        crate::path_utils::rel_path_string(&identity.file).as_bytes(),
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
    rust: &RustAnalyzer,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<ProjectFile> {
    imports
        .iter()
        .filter_map(|import| import.path.as_ref())
        .flat_map(|path| {
            brokk_bifrost_rust::graph_support::resolve_direct_import_files(
                rust,
                file,
                &path.segments,
            )
        })
        .collect()
}

fn direct_import_file_edges(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashMap<ProjectFile, Vec<serde_json::Value>> {
    let mut edges = HashMap::default();
    for import in imports {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        for target in brokk_bifrost_rust::graph_support::resolve_direct_import_files(
            rust,
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

fn rust_import_edge_facts_for_file(
    rust: &RustAnalyzer,
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
            rust,
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

fn extend_origin_files(
    walks: &RustUsageWalks<'_>,
    file: &ProjectFile,
    imported_files: &mut HashSet<ProjectFile>,
) -> Result<(), brokk_bifrost_rust::graph_support::RustCargoRouteError> {
    let routes = walks.origin_routes_of(file)?;
    imported_files.extend(
        routes
            .values()
            .flatten()
            .map(|route| route.origin.file.clone()),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language, ProjectFile};
    use crate::inline_project::InlineTestProject;
    use std::collections::BTreeSet;

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
