//! Explicit typed endpoint-set dependency closure within the registry transaction.

use super::*;
use crate::identity::{EndpointSetSemanticHash, PolicySourceHash};
use crate::source::{
    PolicySelectorContext, PolicySourceDiagnostic, PolicySourceDiagnosticSeverity,
    parse_rqlp_source_with_context,
};
use brokk_bifrost_analysis::workspace_document::read_workspace_document;
use serde_json::{Value, json};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub(super) struct EndpointSetCacheEntry {
    source: PolicySourceIdentity,
    content: PolicySourceHash,
    context: PolicySelectorContext,
    parsed: Arc<ParsedRqlpDocument>,
    source_bytes: usize,
}

#[derive(Debug, Default)]
pub(super) struct EndpointSetClosure {
    pub(super) cache: Vec<EndpointSetCacheEntry>,
    pub(super) retained_bytes: usize,
    pub(super) dependencies: Vec<ResolvedEndpointSetDependency>,
    pub(super) parsed_documents: usize,
    pub(super) cache_hits: usize,
    pub(super) released_cache_bytes: usize,
    selectors: HashMap<PolicySelectorPath, ResolvedPolicySelector>,
    origins: HashMap<PolicyDependencyPath, Vec<PolicySourceIdentity>>,
    import_ranges: HashMap<PolicySourceIdentity, (PolicySourceIdentity, std::ops::Range<usize>)>,
}

impl EndpointSetClosure {
    pub(super) fn attach_origins(
        &self,
        spec: &mut ResolvedTaintPolicySpec,
        dependencies: &mut [ResolvedEndpointDependency],
    ) -> Result<(), PolicyRegistryError> {
        let paths: HashMap<_, _> = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.identity.clone(),
                    dependency.selector_path.clone(),
                )
            })
            .collect();
        for dependency in dependencies {
            self.extend_origins(&dependency.selector_path, &mut dependency.origins)?;
        }
        for endpoint in &mut spec.sources {
            self.extend_origins(
                paths
                    .get(&endpoint.identity)
                    .expect("resolved endpoint has a dependency"),
                &mut endpoint.origins,
            )?;
        }
        for endpoint in &mut spec.sinks {
            self.extend_origins(
                paths
                    .get(&endpoint.identity)
                    .expect("resolved endpoint has a dependency"),
                &mut endpoint.origins,
            )?;
        }
        for endpoint in &mut spec.entry_points {
            self.extend_origins(
                paths
                    .get(&endpoint.identity)
                    .expect("resolved endpoint has a dependency"),
                &mut endpoint.origins,
            )?;
        }
        for endpoint in &mut spec.sanitizers {
            self.extend_origins(&endpoint.selector_path, &mut endpoint.origins)?;
        }
        for endpoint in &mut spec.transforms {
            self.extend_origins(&endpoint.selector_path, &mut endpoint.origins)?;
        }
        for endpoint in &mut spec.external_models {
            self.extend_origins(&endpoint.selector_path, &mut endpoint.origins)?;
        }
        for endpoint in &mut spec.store_writes {
            self.extend_origins(&endpoint.selector_path, &mut endpoint.origins)?;
        }
        for endpoint in &mut spec.store_reads {
            self.extend_origins(&endpoint.selector_path, &mut endpoint.origins)?;
        }
        Ok(())
    }

    fn extend_origins(
        &self,
        selector: &PolicySelectorPath,
        origins: &mut Vec<EndpointOrigin>,
    ) -> Result<(), PolicyRegistryError> {
        let base = selector
            .as_str()
            .strip_suffix("/selector")
            .expect("entry selector has the structured selector suffix");
        let path = dependency_path(base)?;
        if let Some(sources) = self.origins.get(&path) {
            origins.extend(
                sources
                    .iter()
                    .map(|source| EndpointOrigin::EndpointSetFile {
                        path: path.clone(),
                        source: source.clone(),
                    }),
            );
            origins.sort();
            origins.dedup();
        }
        Ok(())
    }
}

struct ImportFrame {
    reference: EndpointSetFileRef,
    referrer: Arc<ParsedRqlpDocument>,
    kind: EndpointSetKind,
    depth: usize,
    exit: bool,
}

impl PolicyRegistry {
    pub(super) fn resolve_imported_selector(
        &self,
        parsed: &ParsedRqlpDocument,
        path: PolicySelectorPath,
        authored: &PolicySelector,
        retained_bytes: &mut usize,
        analyzer: Option<&dyn IAnalyzer>,
        imports: &EndpointSetClosure,
    ) -> Result<ResolvedPolicySelector, PolicyRegistryError> {
        if let Some(selector) = imports.selectors.get(&path) {
            return Ok(selector.clone());
        }
        self.resolve_selector(parsed, path, authored, retained_bytes, analyzer)
    }

    pub(super) fn close_endpoint_sets(
        &self,
        parsed: &ParsedRqlpDocument,
        definition: &mut PolicyDefinition,
        source_bytes: usize,
        analyzer: Option<&dyn IAnalyzer>,
    ) -> Result<EndpointSetClosure, PolicyRegistryError> {
        self.ensure_local_retained_bytes(source_bytes)?;
        let mut closure = EndpointSetClosure {
            cache: self.endpoint_set_cache.clone(),
            retained_bytes: source_bytes,
            ..Default::default()
        };
        let flow = matches!(definition.analysis, PolicyAnalysis::Flow { .. });
        let spec = match &mut definition.analysis {
            PolicyAnalysis::Taint { spec } | PolicyAnalysis::Flow { spec } => spec,
            _ => return Ok(closure),
        };
        let roots = import_references(spec, flow);
        if roots.is_empty() {
            return Ok(closure);
        }
        let root = self
            .workspace_root
            .as_ref()
            .ok_or(PolicyRegistryError::WorkspaceAccessUnavailable)?;
        let mut ids: HashSet<TaintEntryId> = all_entries(spec, flow)
            .into_iter()
            .map(|(_, id, _)| id.clone())
            .collect();
        let mut selected_dependency_paths = HashSet::new();
        let parsed = Arc::new(parsed.clone());
        let mut stack: Vec<_> = roots
            .into_iter()
            .rev()
            .map(|(kind, reference)| ImportFrame {
                reference,
                referrer: Arc::clone(&parsed),
                kind,
                depth: 1,
                exit: false,
            })
            .collect();
        let mut active = HashSet::new();
        let mut completed: HashMap<
            WorkspaceRelativePath,
            (
                EndpointSetKind,
                EndpointSetSemanticHash,
                PolicySelectorContext,
            ),
        > = HashMap::new();
        let mut documents: HashMap<
            WorkspaceRelativePath,
            (Arc<ParsedRqlpDocument>, EndpointSetDocument),
        > = HashMap::new();
        while let Some(frame) = stack.pop() {
            self.check_cancellation()?;
            let path = &frame.reference.path;
            if frame.exit {
                let (document, mut typed) = documents
                    .remove(path)
                    .expect("entered document has an exit frame");
                let nested = import_references(&typed.spec, typed.kind.is_flow());
                let mut nested_hashes: Vec<_> = nested
                    .iter()
                    .map(|(_, edge)| {
                        completed
                            .get(&edge.path)
                            .expect("children complete before parent")
                            .1
                            .to_string()
                    })
                    .collect();
                nested_hashes.sort();
                nested_hashes.dedup();
                let mut selector_values = Vec::new();
                let mut paths = Vec::new();
                for (segment, id, selector) in
                    all_entries_mut(&mut typed.spec, typed.kind.is_flow())
                {
                    self.check_cancellation()?;
                    if !ids.insert(id.clone()) {
                        return Err(import_error(
                            &frame,
                            "duplicate-endpoint-set-entry",
                            format!(
                                "duplicate endpoint entry ID `{id}` in the policy dependency closure"
                            ),
                        ));
                    }
                    if ids.len() > self.limits.max_endpoint_set_entries {
                        return Err(import_error(
                            &frame,
                            "endpoint-set-entry-limit",
                            format!(
                                "endpoint-set closure exceeds {} entries",
                                self.limits.max_endpoint_set_entries
                            ),
                        ));
                    }
                    resolve_selector_locators(selector, analyzer)?;
                    let source_path = selector_path(format!(
                        "/set/entries/{}/selector",
                        pointer_segment(id.as_str())
                    ))?;
                    let loaded = resolve_parsed_selector(
                        Some(root),
                        &document,
                        source_path,
                        selector,
                        analyzer,
                    )
                    .map_err(|error| {
                        import_error(&frame, "endpoint-set-selector", error.to_string())
                    })?;
                    if let Some(reference) = &loaded.referenced {
                        self.charge_local(
                            &mut closure.retained_bytes,
                            reference.document().source().len(),
                        )?;
                    }
                    let mut resolved = loaded.selector;
                    let base = format!(
                        "/analysis/{segment}/entries/{}",
                        pointer_segment(id.as_str())
                    );
                    resolved.path = selector_path(format!("{base}/selector"))?;
                    selector_values.push(json!({"id": id.as_str(), "selector": crate::canonical_loaded::resolved_selector_to_json(&resolved)}));
                    let base = dependency_path(base)?;
                    paths.push(base.clone());
                    closure
                        .origins
                        .entry(base)
                        .or_default()
                        .push(document.identity().clone());
                    closure.selectors.insert(resolved.path.clone(), resolved);
                }
                let mut catalog_selectors = BTreeMap::new();
                let mut catalog_dependencies = BTreeMap::new();
                let mut endpoint_dependencies = Vec::new();
                self.build_catalog_taint_inputs(
                    &typed.spec,
                    &mut catalog_selectors,
                    &mut catalog_dependencies,
                    &mut endpoint_dependencies,
                    &mut closure.retained_bytes,
                    analyzer,
                )?;
                let match_inputs = self.build_match_inputs(
                    &taint_match_uses(&typed.spec)?,
                    &mut catalog_dependencies,
                    &mut closure.retained_bytes,
                    analyzer,
                )?;
                endpoint_dependencies.extend(match_inputs.dependencies);
                for path in catalog_selectors.keys().chain(catalog_dependencies.keys()) {
                    let path = dependency_path(
                        path.as_str()
                            .strip_suffix("/selector")
                            .expect("resolved selector path has selector suffix"),
                    )?;
                    paths.push(path.clone());
                    selected_dependency_paths.insert(path.clone());
                    closure
                        .origins
                        .entry(path)
                        .or_default()
                        .push(document.identity().clone());
                }
                if ids.len().saturating_add(selected_dependency_paths.len())
                    > self.limits.max_endpoint_set_entries
                {
                    return Err(import_error(
                        &frame,
                        "endpoint-set-entry-limit",
                        format!(
                            "endpoint-set closure exceeds {} entries",
                            self.limits.max_endpoint_set_entries
                        ),
                    ));
                }
                let mut endpoint_hashes: Vec<_> = endpoint_dependencies
                    .iter()
                    .map(|dependency| dependency.semantic_hash.to_string())
                    .collect();
                endpoint_hashes.sort();
                endpoint_hashes.dedup();
                let mut catalog_hashes = Vec::new();
                for refs in [
                    &typed.spec.sources.include_sets,
                    &typed.spec.sinks.include_sets,
                    &typed.spec.sanitizers.include_sets,
                    &typed.spec.transforms.include_sets,
                    &typed.spec.entry_points.include_sets,
                    &typed.spec.external_models.include_sets,
                ] {
                    for reference in refs {
                        catalog_hashes.push(
                            self.catalogs
                                .resolve(reference)?
                                .semantic_hash()
                                .to_string(),
                        );
                    }
                }
                catalog_hashes.sort();
                catalog_hashes.dedup();
                clear_imports(&mut typed.spec);
                let semantic = json!({
                    "schema_version": typed.schema_version.version,
                    "kind": typed.kind.label(),
                    "entries": resolved_set_projection(&typed, &selector_values),
                    "dependencies": nested_hashes,
                    "catalogs": catalog_hashes,
                    "match_endpoints": endpoint_hashes,
                });
                let hash = EndpointSetSemanticHash::from_canonical_value(&semantic);
                check_pin(&frame, hash)?;
                merge_spec(spec, typed.spec);
                paths.sort();
                paths.dedup();
                closure.dependencies.push(ResolvedEndpointSetDependency {
                    source: document.identity().clone(),
                    semantic_hash: hash,
                    entries: paths,
                });
                completed.insert(
                    path.clone(),
                    (frame.kind, hash, frame.referrer.selector_context().clone()),
                );
                active.remove(path);
                continue;
            }
            if active.contains(path) {
                return Err(import_error(
                    &frame,
                    "endpoint-set-cycle",
                    format!("endpoint-set dependency cycle at `{path}`"),
                ));
            }
            if frame.depth > self.limits.max_endpoint_set_depth {
                return Err(import_error(
                    &frame,
                    "endpoint-set-depth-limit",
                    format!(
                        "endpoint-set dependency depth exceeds {}",
                        self.limits.max_endpoint_set_depth
                    ),
                ));
            }
            if let Some((kind, hash, context)) = completed.get(path) {
                if *kind != frame.kind {
                    return Err(import_error(
                        &frame,
                        "endpoint-set-wrong-kind",
                        format!(
                            "endpoint-set `{path}` has kind {}, expected {}",
                            kind.label(),
                            frame.kind.label()
                        ),
                    ));
                }
                if !context.same_scope(frame.referrer.selector_context()) {
                    return Err(import_error(
                        &frame,
                        "endpoint-set-context-conflict",
                        format!(
                            "endpoint-set `{path}` is imported with conflicting inherited selector contexts"
                        ),
                    ));
                }
                check_pin(&frame, *hash)?;
                continue;
            }
            if active.len() + completed.len() >= self.limits.max_endpoint_set_files {
                return Err(import_error(
                    &frame,
                    "endpoint-set-file-limit",
                    format!(
                        "endpoint-set closure exceeds {} files",
                        self.limits.max_endpoint_set_files
                    ),
                ));
            }
            let available = self
                .available_local_bytes(closure.retained_bytes)?
                .min(MAX_RQLP_SOURCE_BYTES);
            let loaded = read_workspace_document(root, path.as_path(), &["rqlp"], available as u64)
                .map_err(|error| {
                    let code = if matches!(error, WorkspaceDocumentError::TooLarge { .. }) {
                        "endpoint-set-byte-limit"
                    } else {
                        "endpoint-set-unavailable"
                    };
                    import_error(&frame, code, error.to_string())
                })?;
            self.charge_local(&mut closure.retained_bytes, loaded.source().len())?;
            let source = PolicySourceIdentity::new(path.as_str());
            closure.import_ranges.insert(
                source.clone(),
                (
                    frame.referrer.identity().clone(),
                    frame.reference.range.clone(),
                ),
            );
            let content = PolicySourceHash::from_source_bytes(loaded.source().as_bytes());
            let context = frame.referrer.selector_context().clone();
            let document = if let Some(cached) = closure.cache.iter().find(|cached| {
                cached.source == source
                    && cached.content == content
                    && cached.context.same_scope(&context)
            }) {
                closure.cache_hits += 1;
                Arc::clone(&cached.parsed)
            } else {
                // Retain the parser cache independently of this policy's typed
                // entry copy. Reserve its source budget before parsing/mutation.
                self.charge_local(&mut closure.retained_bytes, loaded.source().len())?;
                let document = Arc::new(
                    parse_rqlp_source_with_context(
                        loaded.source(),
                        source.clone(),
                        context.clone(),
                    )
                    .map_err(|error| {
                        PolicyRegistryError::EndpointSetImport {
                            source: source.clone(),
                            error: Box::new(error),
                        }
                    })?,
                );
                closure.cache.retain(|cached| {
                    let keep = cached.source != source || !cached.context.same_scope(&context);
                    if !keep {
                        closure.released_cache_bytes += cached.source_bytes;
                    }
                    keep
                });
                closure.cache.push(EndpointSetCacheEntry {
                    source,
                    content,
                    context,
                    parsed: Arc::clone(&document),
                    source_bytes: loaded.source().len(),
                });
                if closure.cache.len() > self.limits.max_endpoint_set_files {
                    closure.released_cache_bytes += closure.cache.remove(0).source_bytes;
                }
                closure.parsed_documents += 1;
                document
            };
            let RqlpDocument::EndpointSet { definition: typed } = document.document() else {
                return Err(import_error(
                    &frame,
                    "endpoint-set-wrong-document",
                    format!("`{path}` is not an endpoint-set document"),
                ));
            };
            if typed.kind != frame.kind {
                return Err(import_error(
                    &frame,
                    "endpoint-set-wrong-kind",
                    format!(
                        "endpoint-set `{path}` has kind {}, expected {}",
                        typed.kind.label(),
                        frame.kind.label()
                    ),
                ));
            }
            let children = import_references(&typed.spec, typed.kind.is_flow());
            documents.insert(
                path.clone(),
                (Arc::clone(&document), typed.as_ref().clone()),
            );
            active.insert(path.clone());
            let depth = frame.depth + 1;
            stack.push(ImportFrame {
                exit: true,
                ..frame
            });
            stack.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|(kind, reference)| ImportFrame {
                        reference,
                        referrer: Arc::clone(&document),
                        kind,
                        depth,
                        exit: false,
                    }),
            );
        }
        clear_imports(spec);
        sort_entries(spec);
        self.validate_imported_store_conflicts(&parsed, spec, analyzer, &closure)?;
        closure
            .dependencies
            .sort_by(|left, right| left.source.cmp(&right.source));
        Ok(closure)
    }

    fn validate_imported_store_conflicts(
        &self,
        parsed: &ParsedRqlpDocument,
        spec: &TaintPolicySpec,
        analyzer: Option<&dyn IAnalyzer>,
        closure: &EndpointSetClosure,
    ) -> Result<(), PolicyRegistryError> {
        let mut contracts = HashMap::new();
        for (phase, id, selector, store, key, instance, port) in spec
            .store_writes
            .iter()
            .map(|entry| {
                (
                    "write",
                    &entry.id,
                    &entry.selector,
                    &entry.store,
                    &entry.key,
                    &entry.instance,
                    &entry.input,
                )
            })
            .chain(spec.store_reads.iter().map(|entry| {
                (
                    "read",
                    &entry.id,
                    &entry.selector,
                    &entry.store,
                    &entry.key,
                    &entry.instance,
                    &entry.output,
                )
            }))
        {
            let path = selector_path(format!(
                "/analysis/stores/entries/{}/selector",
                pointer_segment(id.as_str())
            ))?;
            let mut retained = closure.retained_bytes;
            let resolved = self.resolve_imported_selector(
                parsed,
                path.clone(),
                selector,
                &mut retained,
                analyzer,
                closure,
            )?;
            let contract = (key, instance, port);
            if let Some((previous, previous_path)) = contracts.insert(
                (phase, store, resolved.semantic_hash),
                (contract, path.clone()),
            ) && previous != contract
            {
                let message = format!(
                    "conflicting persistence store {phase} definitions for `{store}` at {previous_path} and entry `{id}`"
                );
                let imported_source = [path.as_str(), previous_path.as_str()]
                    .into_iter()
                    .filter_map(|path| path.strip_suffix("/selector"))
                    .filter_map(|path| PolicyDependencyPath::new(path).ok())
                    .find_map(|path| {
                        closure
                            .origins
                            .get(&path)
                            .and_then(|sources| sources.first())
                    });
                let Some((source, range)) = imported_source
                    .and_then(|source| closure.import_ranges.get(source))
                    .cloned()
                else {
                    // This check concerns composition with imported stores;
                    // existing policy-local behavior remains authoritative.
                    continue;
                };
                return Err(PolicyRegistryError::EndpointSetImport {
                    source,
                    error: Box::new(PolicySourceError {
                        diagnostic: PolicySourceDiagnostic {
                            code: "endpoint-set-store-conflict",
                            severity: PolicySourceDiagnosticSeverity::Error,
                            message,
                            range,
                            fix: None,
                            related: Vec::new(),
                        },
                    }),
                });
            }
        }
        Ok(())
    }
}

fn import_error(frame: &ImportFrame, code: &'static str, message: String) -> PolicyRegistryError {
    PolicyRegistryError::EndpointSetImport {
        source: frame.referrer.identity().clone(),
        error: Box::new(PolicySourceError {
            diagnostic: PolicySourceDiagnostic {
                code,
                severity: PolicySourceDiagnosticSeverity::Error,
                message,
                range: frame.reference.range.clone(),
                fix: None,
                related: Vec::new(),
            },
        }),
    }
}

fn check_pin(
    frame: &ImportFrame,
    actual: EndpointSetSemanticHash,
) -> Result<(), PolicyRegistryError> {
    if let Some(expected) = frame.reference.sha256
        && expected != actual
    {
        return Err(import_error(
            frame,
            "endpoint-set-hash-mismatch",
            format!(
                "endpoint-set `{}` pin {expected} does not match {actual}",
                frame.reference.path
            ),
        ));
    }
    Ok(())
}

fn import_references(
    spec: &TaintPolicySpec,
    flow: bool,
) -> Vec<(EndpointSetKind, EndpointSetFileRef)> {
    let families = [
        (
            if flow {
                EndpointSetKind::Origins
            } else {
                EndpointSetKind::Sources
            },
            &spec.sources.include_files,
        ),
        (
            if flow {
                EndpointSetKind::Observations
            } else {
                EndpointSetKind::Sinks
            },
            &spec.sinks.include_files,
        ),
        (
            if flow {
                EndpointSetKind::Kills
            } else {
                EndpointSetKind::Sanitizers
            },
            &spec.sanitizers.include_files,
        ),
        (
            if flow {
                EndpointSetKind::FlowTransforms
            } else {
                EndpointSetKind::Transforms
            },
            &spec.transforms.include_files,
        ),
        (
            EndpointSetKind::EntryPoints,
            &spec.entry_points.include_files,
        ),
        (
            EndpointSetKind::ExternalModels,
            &spec.external_models.include_files,
        ),
        (EndpointSetKind::Stores, &spec.store_include_files),
    ];
    let mut references: Vec<_> = families
        .into_iter()
        .flat_map(|(kind, refs)| refs.iter().cloned().map(move |reference| (kind, reference)))
        .collect();
    references.sort_by(|(lk, left), (rk, right)| {
        (lk.label(), left.path.as_str(), left.sha256).cmp(&(
            rk.label(),
            right.path.as_str(),
            right.sha256,
        ))
    });
    references
}

fn clear_imports(spec: &mut TaintPolicySpec) {
    spec.sources.include_files.clear();
    spec.sinks.include_files.clear();
    spec.sanitizers.include_files.clear();
    spec.transforms.include_files.clear();
    spec.entry_points.include_files.clear();
    spec.external_models.include_files.clear();
    spec.store_include_files.clear();
}

fn all_entries(
    spec: &TaintPolicySpec,
    flow: bool,
) -> Vec<(&'static str, &TaintEntryId, &PolicySelector)> {
    let segments = if flow {
        FLOW_SET_SEGMENTS
    } else {
        TAINT_SET_SEGMENTS
    };
    let mut entries = Vec::new();
    macro_rules! add {
        ($segment:expr, $entries:expr) => {
            entries.extend(
                $entries
                    .iter()
                    .map(|entry| ($segment, &entry.id, &entry.selector)),
            );
        };
    }
    add!(segments.sources, spec.sources.entries);
    add!(segments.sinks, spec.sinks.entries);
    add!(segments.sanitizers, spec.sanitizers.entries);
    add!(segments.transforms, spec.transforms.entries);
    add!(segments.entry_points, spec.entry_points.entries);
    add!(segments.external_models, spec.external_models.entries);
    add!(segments.stores, spec.store_writes);
    add!(segments.stores, spec.store_reads);
    entries
}

fn all_entries_mut(
    spec: &mut TaintPolicySpec,
    flow: bool,
) -> Vec<(&'static str, &TaintEntryId, &mut PolicySelector)> {
    let segments = if flow {
        FLOW_SET_SEGMENTS
    } else {
        TAINT_SET_SEGMENTS
    };
    let mut entries = Vec::new();
    macro_rules! add {
        ($segment:expr, $entries:expr) => {
            entries.extend(
                $entries
                    .iter_mut()
                    .map(|entry| ($segment, &entry.id, &mut entry.selector)),
            );
        };
    }
    add!(segments.sources, spec.sources.entries);
    add!(segments.sinks, spec.sinks.entries);
    add!(segments.sanitizers, spec.sanitizers.entries);
    add!(segments.transforms, spec.transforms.entries);
    add!(segments.entry_points, spec.entry_points.entries);
    add!(segments.external_models, spec.external_models.entries);
    add!(segments.stores, spec.store_writes);
    add!(segments.stores, spec.store_reads);
    entries
}

fn merge_spec(target: &mut TaintPolicySpec, source: TaintPolicySpec) {
    macro_rules! merge_set {
        ($field:ident) => {
            target.$field.entries.extend(source.$field.entries);
            target
                .$field
                .include_sets
                .extend(source.$field.include_sets);
            target
                .$field
                .include_matches
                .extend(source.$field.include_matches);
        };
    }
    merge_set!(sources);
    merge_set!(sinks);
    merge_set!(sanitizers);
    merge_set!(transforms);
    merge_set!(entry_points);
    merge_set!(external_models);
    target.store_writes.extend(source.store_writes);
    target.store_reads.extend(source.store_reads);
}

fn sort_entries(spec: &mut TaintPolicySpec) {
    macro_rules! sort {
        ($entries:expr) => {
            $entries.sort_by(|left, right| left.id.cmp(&right.id));
        };
    }
    sort!(spec.sources.entries);
    sort!(spec.sinks.entries);
    sort!(spec.sanitizers.entries);
    sort!(spec.transforms.entries);
    sort!(spec.entry_points.entries);
    sort!(spec.external_models.entries);
    sort!(spec.store_writes);
    sort!(spec.store_reads);
}

fn resolved_set_projection(typed: &EndpointSetDocument, selectors: &[Value]) -> Value {
    let analysis = if typed.kind.is_flow() {
        PolicyAnalysis::Flow {
            spec: typed.spec.clone(),
        }
    } else {
        PolicyAnalysis::Taint {
            spec: typed.spec.clone(),
        }
    };
    let mut value = crate::canonical::policy_analysis_authored_json(&analysis);
    let selectors: HashMap<_, _> = selectors
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().expect("entry ID is a string"),
                &entry["selector"],
            )
        })
        .collect();
    // Walk the normalized typed projection, replacing selector bodies by their
    // resolved query form. This traverses a model serialization, never source text.
    let mut stack = vec![&mut value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                // The referenced contents above determine dependency meaning;
                // authoring order, paths and optional pins are provenance only.
                object.remove("include_sets");
                object.remove("include_matches");
                object.remove("include_files");
                if let Some(id) = object.get("id").and_then(Value::as_str)
                    && let Some(selector) = selectors.get(id)
                    && object.contains_key("selector")
                {
                    object.insert("selector".to_string(), (*selector).clone());
                }
                stack.extend(object.values_mut());
            }
            Value::Array(values) => stack.extend(values),
            _ => {}
        }
    }
    value
}
