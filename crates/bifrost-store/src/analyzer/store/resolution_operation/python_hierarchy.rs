//! A selected Python class's declared bases and ordered ancestry, requested of
//! the shared fact-resolution driver without a member lookup. Python supplies
//! only its base and C3 policies; the driver owns the walk and the merge.
use super::native_units::{
    HierarchyCrosswalkCache, SelectedNativeDefinition, SelectedNativeDefinitions,
};
use super::python_demand::selected_external_imports;
use super::python_members::{PYTHON_C3, PYTHON_HIERARCHY};
use super::*;
use crate::analyzer::resolution::{
    HierarchyDemandRequest, HierarchyOrderRequest, HierarchyProjection, SharedNameInterner,
};
use crate::analyzer::semantic_model::{SemanticModelSymbol, SemanticModelSymbolKind};

/// What an identity in the walk denotes, projected while its operation is alive.
#[derive(Debug, Clone, PartialEq)]
#[doc(hidden)]
pub enum PythonHierarchyOwner {
    Source(CodeUnit),
    /// A language-fixed class, such as the implicit `builtins.object`.
    Intrinsic {
        canonical_name: String,
    },
    /// A class declared by the selected semantic models.
    Model(Box<SemanticModelSymbol>),
    /// The walk reached an identity that no selected projection names.
    Unprojected,
}

/// One class hierarchy request. The walk, its identities and its evidence die
/// with the request; nothing here is a cache key.
#[derive(Debug)]
#[doc(hidden)]
pub struct PythonClassHierarchy {
    pub projection: HierarchyProjection,
    /// Every identity in `projection`, projected in the operation that ran it.
    pub owners: Vec<(SemanticId, PythonHierarchyOwner)>,
    /// Unbound bases, as (owner, written ordinal), whose import left the
    /// workspace for a selected external provider.
    pub provider_open: Vec<(SemanticId, u32)>,
    /// Absolute external import names for runtime-base claim diagnostics only.
    pub provider_names: Vec<(SemanticId, u32, String)>,
    /// Source classes in the walk that carry a decorator. A decorator may
    /// return any object, so a decorated class names no class by itself.
    pub decorated: Vec<SemanticId>,
}

/// A missing hierarchy identity is content evidence, not an interrupted walk.
#[doc(hidden)]
pub enum PythonHierarchyRead {
    Ready(Box<PythonClassHierarchy>),
    Unavailable,
    Stopped {
        stop: crate::analyzer::resolution::HierarchyStop,
        hierarchy: Option<Box<PythonClassHierarchy>>,
    },
}

impl PythonClassHierarchy {
    pub fn owner(&self, id: SemanticId) -> &PythonHierarchyOwner {
        self.owners
            .iter()
            .find(|(owner, _)| *owner == id)
            .map(|(_, owner)| owner)
            .unwrap_or(&PythonHierarchyOwner::Unprojected)
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Prove the selected class's metaclass chain cannot customize its MRO.
    pub fn python_metaclass_mro_free(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        definition: SemanticId,
        session: &ResolutionSession,
    ) -> Result<BoundedResolution<SelectedResolutionOperationOutcome<bool>>> {
        let cancellation = session.cancellation().cloned().unwrap_or_default();
        let mut run = || -> Result<_> {
            let context = self.empty_contexts(&ResolutionCompletion::Complete)?;
            let Some(blueprint) = self.prepare_prefix_blueprint(context, &cancellation)? else {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            };
            let shape = self.python_hierarchy_shape();
            let proven = self.with_python_forward_operation(
                environment.summary,
                environment.python_version,
                &blueprint,
                session,
                &cancellation,
                |operation, provider, _, _, _, external_imports, _, _| {
                    external_imports.borrow_mut().requested_reference = Some(definition);
                    operation.prove_guard_by_demand(
                        HierarchyDemandRequest {
                            policy: &PYTHON_HIERARCHY,
                            order: None,
                            root: definition,
                            shape,
                            language: Language::Python,
                        },
                        super::super::python_member_rows::PYTHON_MRO_ONLY_RULE,
                        provider,
                    )
                },
            )?;
            self.finish_native(proven, &ResolutionCompletion::Complete, &cancellation)
        };
        Ok(match session.finish(run()) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: value?,
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Unavailable { reason, work } => {
                BoundedResolution::Unavailable { reason, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        })
    }

    /// Dynamic writes are source inputs, not a reason to reparse source during a query.
    fn python_unproven_bases(
        &self,
        projection: &HierarchyProjection,
        operation: &crate::analyzer::resolution::FactResolutionOperation<'_>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<Vec<(SemanticId, u32)>>> {
        use super::super::python_binding_rows::PythonBindingRows;
        use super::python_lexical::{self, PythonBindingProfile, PythonBindingProofs};
        use crate::analyzer::resolution::temporal_binding::SessionBudget;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            PythonNativeImportForm, ResolutionGapKind,
        };
        let conn = self.ready.inventory.connection();
        let origin = super::super::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedRoute,
            ),
        );
        let mut unproven = Vec::new();
        let mut binding_rows = HashMap::default();
        for node in &projection.nodes {
            for edge in &node.edges {
                if edge.implicit || edge.targets.is_empty() {
                    continue;
                }
                for reference in std::iter::once(edge.reference).chain(
                    operation
                        .hierarchy_alias_sources(edge.reference)
                        .iter()
                        .copied(),
                ) {
                    if !session.scope_step() || cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let (Some(ordinal), Some(key)) = (reference.ordinal(), reference.local_key())
                    else {
                        continue;
                    };
                    let mount = self
                        .ready
                        .inventory
                        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                    let blob = mount.blob_id();
                    let candidate: bool = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_gaps gap JOIN resolution_gap_reasons reason
                       ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
                       JOIN resolution_node_catalog scope ON scope.blob_id=gap.blob_id AND scope.local_key=gap.subject
                       WHERE gap.blob_id=?1 AND gap.covers=5 AND gap.lookup=0 AND reason.origin=?2 AND scope.source_scope=0)
                     OR EXISTS(SELECT 1 FROM resolution_binding_events event JOIN resolution_binding_slots slot
                       ON slot.blob_id=event.blob_id AND slot.slot=event.slot
                       WHERE event.blob_id=?1 AND slot.scope=0 AND event.execution_scope<>0)
                     OR EXISTS(SELECT 1 FROM resolution_identities name
                       JOIN resolution_reference_lookup_identities lookup ON lookup.identity_id=name.id
                       JOIN resolution_semantic_sites target ON target.blob_id=lookup.blob_id AND target.semantic_key=lookup.semantic_key AND target.semantic_role='reference'
                       JOIN python_member_receiver_writes writes ON writes.blob_id=target.blob_id AND writes.site=target.source_site
                       WHERE writes.blob_id=?1 AND name.spelling='cell_contents')")?.query_row(
                    rusqlite::params![blob,origin], |row| row.get(0))?;
                    if !candidate {
                        continue;
                    }
                    let reference: Option<(u32,String)> = conn.prepare_cached("SELECT semantic.source_site,name.spelling FROM resolution_semantic_sites semantic
                     JOIN resolution_sites site ON site.blob_id=semantic.blob_id AND site.site=semantic.semantic_key
                     JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id AND lookup.semantic_key=semantic.semantic_key
                     JOIN resolution_identities name ON name.id=lookup.identity_id
                     WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='reference' AND site.prefix=-1")?.query_row(
                    rusqlite::params![blob,key], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
                    let Some((reference, name)) = reference else {
                        continue;
                    };
                    // Keep one input per blob even if the shared cache declines admission.
                    let rows = &*match binding_rows.entry(blob) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            let Some(rows) = PythonBindingRows::load(
                                conn,
                                &self.ready.store.cache_budget,
                                blob,
                                Some(mount.blob_oid()),
                                cancellation,
                            )?
                            else {
                                return Ok(None);
                            };
                            entry.insert(rows)
                        }
                    };
                    // Module reload with old globals is out of scope (#5668).
                    let deferred_mutation_applies = |mutation, read| match (
                        rows.module_statement_start(mutation),
                        rows.module_statement_start(read),
                    ) {
                        (Some(mutation), Some(read)) => mutation <= read,
                        _ => true,
                    };
                    let Some(observation) = rows
                        .observations
                        .iter()
                        .find(|row| row.reference.get() == reference)
                    else {
                        continue;
                    };
                    let Some(mut state) = python_lexical::lexical_selection(
                        rows,
                        reference,
                        &name,
                        PythonBindingProfile::Runtime,
                        PythonBindingProofs::default(),
                    ) else {
                        continue;
                    };
                    python_lexical::select_lexical(
                        &mut state,
                        rows,
                        &mut SessionBudget {
                            session,
                            cancellation,
                        },
                        cancellation,
                    )?;
                    if state.selection.stopped.is_some() {
                        return Ok(None);
                    }
                    let scopes = rows
                        .events
                        .iter()
                        .filter(|event| {
                            state
                                .selection
                                .selected
                                .iter()
                                .any(|selected| selected.occurrence == event.event)
                        })
                        .filter_map(|event| {
                            rows.slots
                                .iter()
                                .find(|slot| slot.slot == event.slot)
                                .map(|slot| slot.scope)
                        })
                        .collect::<Vec<_>>();
                    let module_binding = scopes.contains(&0) || state.builtin_fallback;
                    let mut blocked = false;
                    if module_binding {
                        let dynamic_sites = conn.prepare_cached(
                        "SELECT DISTINCT reason.site FROM resolution_gaps gap JOIN resolution_gap_reasons reason
                         ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
                         JOIN resolution_node_catalog scope ON scope.blob_id=gap.blob_id AND scope.local_key=gap.subject
                         WHERE gap.blob_id=?1 AND gap.covers=5 AND gap.lookup=0 AND reason.origin=?2 AND scope.source_scope=0")?
                        .query_map(rusqlite::params![blob,origin],|row| row.get::<_,u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                        for site in dynamic_sites {
                            if blocked {
                                break;
                            }
                            if !session.scope_step() || cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            if rows.imports.iter().any(|import| {
                                import.import_site.get() == site
                                    && import.form == PythonNativeImportForm::Star
                            }) {
                                continue;
                            }
                            let positioned: Option<(u32,usize)> = conn.prepare_cached("SELECT scope,start_byte FROM python_member_sites WHERE blob_id=?1 AND site=?2")?.query_row(
                            rusqlite::params![blob,site],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
                            let Some((mutation_scope, mut point)) = positioned else {
                                blocked = true;
                                continue;
                            };
                            if !rows.executes_at_import_time(observation.execution_scope.get()) {
                                blocked = true;
                                continue;
                            }
                            if !rows.executes_at_import_time(mutation_scope) {
                                blocked |= deferred_mutation_applies(point, observation.point_byte);
                                continue;
                            }
                            let mut guard = rows
                                .site_guards
                                .iter()
                                .find(|row| row.site.get() == site)
                                .map(|row| row.guard);
                            while let Some(id) = guard {
                                if !session.scope_step() {
                                    return Ok(None);
                                }
                                let enclosing = rows
                                    .guards
                                    .iter()
                                    .find(|row| row.id == id)
                                    .expect("retained guard");
                                let start: Option<usize> = conn.prepare_cached("SELECT start_byte FROM python_member_sites WHERE blob_id=?1 AND site=?2")?.query_row(
                                rusqlite::params![blob,enclosing.site.get()],|row|row.get(0)).optional()?;
                                match start {
                                    Some(start) => point = point.min(start),
                                    None => blocked = true,
                                }
                                guard = enclosing.parent;
                            }
                            blocked |= point <= observation.point_byte;
                        }
                        for event in &rows.events {
                            if blocked {
                                break;
                            }
                            if !session.scope_step() || cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            if event.execution_scope == 0
                                || !rows.slots.iter().any(|slot| {
                                    slot.slot == event.slot && slot.scope == 0 && slot.name == name
                                })
                            {
                                continue;
                            }
                            blocked |= if !rows
                                .executes_at_import_time(observation.execution_scope.get())
                            {
                                true
                            } else if rows.executes_at_import_time(event.execution_scope) {
                                event.entry_byte <= observation.point_byte
                            } else {
                                deferred_mutation_applies(event.entry_byte, observation.point_byte)
                            };
                        }
                    }
                    if !blocked && scopes.iter().any(|scope| *scope != 0) {
                        let mut scope = Some(observation.execution_scope.get());
                        let mut outer = None;
                        while let Some(current) = scope {
                            if !session.scope_step() {
                                return Ok(None);
                            }
                            let range: Option<(usize,usize)> = conn.prepare_cached("SELECT declaration.start_byte,declaration.end_byte FROM resolution_member_scope_properties properties
                             JOIN resolution_node_catalog nodes ON nodes.blob_id=properties.blob_id AND nodes.local_key=properties.scope_head_node_key
                             JOIN resolution_semantic_sites semantic ON semantic.blob_id=properties.blob_id AND semantic.semantic_key=properties.definition_semantic_key AND semantic.semantic_role='definition'
                             JOIN source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
                             JOIN source_declarations declaration ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
                             WHERE properties.blob_id=?1 AND properties.scope_kind='executable' AND nodes.source_scope=?2")?.query_row(
                            rusqlite::params![blob,current],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
                            if range.is_some() {
                                outer = range;
                            }
                            scope = rows
                                .scopes
                                .iter()
                                .find(|row| row.scope == current)
                                .and_then(|row| row.parent);
                        }
                        if let Some((start, end)) = outer {
                            // Deliberately coarse, including class namespaces that copy cells; cross-function reflection is not modeled, as with master.
                            blocked |= conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_identities name
                             JOIN resolution_reference_lookup_identities lookup ON lookup.identity_id=name.id
                             JOIN resolution_semantic_sites target ON target.blob_id=lookup.blob_id AND target.semantic_key=lookup.semantic_key AND target.semantic_role='reference'
                             JOIN python_member_receiver_writes writes ON writes.blob_id=target.blob_id AND writes.site=target.source_site
                             JOIN python_member_sites site ON site.blob_id=writes.blob_id AND site.site=writes.site
                             WHERE writes.blob_id=?1 AND name.spelling='cell_contents' AND site.start_byte>=?2 AND site.end_byte<=?3)")?.query_row(
                            rusqlite::params![blob,start,end],|row|row.get::<_,bool>(0))?;
                        }
                    }
                    if blocked {
                        unproven.push((node.owner, edge.ordinal));
                        break;
                    }
                }
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(unproven))
    }

    /// Select the declared bases and C3 order of one class, given as the
    /// identity the selected definition crosswalk returned for it.
    #[doc(hidden)]
    pub fn python_class_hierarchy(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        definition: SemanticId,
        session: &ResolutionSession,
    ) -> Result<BoundedResolution<SelectedResolutionOperationOutcome<PythonClassHierarchy>>> {
        self.python_hierarchy_demand(
            environment,
            definition,
            Some(HierarchyOrderRequest {
                policy: &PYTHON_C3,
                start_after: None,
            }),
            session,
        )
    }

    /// Read only the class's own declared bases: no base is expanded and no
    /// order is computed. The result's single node is the class itself.
    #[doc(hidden)]
    pub fn python_direct_bases(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        definition: SemanticId,
        session: &ResolutionSession,
    ) -> Result<BoundedResolution<SelectedResolutionOperationOutcome<PythonClassHierarchy>>> {
        self.python_hierarchy_demand(environment, definition, None, session)
    }

    fn python_hierarchy_demand(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        definition: SemanticId,
        order: Option<HierarchyOrderRequest>,
        session: &ResolutionSession,
    ) -> Result<BoundedResolution<SelectedResolutionOperationOutcome<PythonClassHierarchy>>> {
        let cancellation = session.cancellation().cloned().unwrap_or_default();
        let mut run = || -> Result<_> {
            let context = self.empty_contexts(&ResolutionCompletion::Complete)?;
            let Some(blueprint) = self.prepare_prefix_blueprint(context, &cancellation)? else {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            };
            let shape = self.python_hierarchy_shape();
            let projected = self.with_python_forward_operation(
                environment.summary,
                environment.python_version,
                &blueprint,
                session,
                &cancellation,
                |operation, provider, _, _, _, external_imports, _, _| {
                    self.hierarchy_in_operation(
                        operation,
                        provider,
                        external_imports,
                        definition,
                        shape,
                        order,
                        &cancellation,
                        session,
                    )
                },
            )?;
            match projected {
                Some(hierarchy) => {
                    let completion = hierarchy.projection.completion.clone();
                    self.finish_native(hierarchy, &completion, &cancellation)
                }
                None => Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                )),
            }
        };
        Ok(match session.finish(run()) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: value?,
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Unavailable { reason, work } => {
                BoundedResolution::Unavailable { reason, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        })
    }

    /// One class's hierarchy on a forward operation that is already running.
    #[allow(clippy::too_many_arguments)]
    fn hierarchy_in_operation(
        &self,
        operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        provider: &mut (impl crate::analyzer::resolution::DemandRootProvider + ?Sized),
        external_imports: &RefCell<super::python_demand::PythonExternalImports>,
        definition: SemanticId,
        shape: SemanticId,
        order: Option<HierarchyOrderRequest>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<PythonClassHierarchy>> {
        // Model admission of an imported external class is keyed by the
        // reference it binds; a hierarchy request admits every base
        // reference of the walk.
        external_imports.borrow_mut().requested_reference = Some(definition);
        let Some(mut projection) = operation.resolve_hierarchy_by_demand(
            HierarchyDemandRequest {
                policy: &PYTHON_HIERARCHY,
                order,
                root: definition,
                shape,
                language: Language::Python,
            },
            provider,
        )?
        else {
            return Ok(None);
        };
        let owners = self.project_python_hierarchy_owners(&projection, cancellation, session)?;
        // An unbound base is external when native reaching-import selection
        // found exactly one absolute import that left the workspace for a
        // selected provider. A relative import resolves inside its package,
        // and a conditional, repeated or rebound import is not the only way
        // the name is bound.
        let mut provider_open = Vec::new();
        let mut provider_names = Vec::new();
        for node in &projection.nodes {
            for edge in &node.edges {
                // The implicit trailing operand is admitted only after the
                // selected environment excludes a workspace typing module.
                if edge.implicit_external && edge.targets.is_empty() {
                    provider_open.push((node.owner, edge.ordinal));
                    provider_names.push((node.owner, edge.ordinal, "typing.Generic".to_owned()));
                    continue;
                }
                if edge.targets.is_empty()
                    && matches!(
                        selected_external_imports(external_imports, edge.reference).as_slice(),
                        [import] if import.boundary_is_unique
                            && import.boundary.relative_level == 0
                    )
                {
                    provider_open.push((node.owner, edge.ordinal));
                    let imports = selected_external_imports(external_imports, edge.reference);
                    let import = &imports[0];
                    let name = import
                        .boundary
                        .route
                        .iter()
                        .chain(&import.remaining_member_path)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(".");
                    provider_names.push((node.owner, edge.ordinal, name));
                }
            }
        }
        // A stopped mutation check proves no prefix or unchecked base.
        let unproven =
            match self.python_unproven_bases(&projection, operation, cancellation, session)? {
                Some(unproven) => unproven,
                None if projection.stop.is_some() => projection
                    .nodes
                    .iter()
                    .flat_map(|node| {
                        node.edges
                            .iter()
                            .map(move |edge| (node.owner, edge.ordinal))
                    })
                    .collect(),
                None => return Ok(None),
            };
        for node in &mut projection.nodes {
            for edge in &mut node.edges {
                if unproven.contains(&(node.owner, edge.ordinal)) {
                    let completion = ResolutionCompletion::incomplete([
                        crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(edge.reference),
                    ]);
                    edge.residual = edge.residual.combine(&completion);
                    projection.completion = projection.completion.combine(&completion);
                    projection.order_completion = projection.order_completion.combine(&completion);
                    projection.order_complete = false;
                    projection.order.clear();
                }
            }
        }
        let decorated = self.decorated_python_classes(&projection)?;
        // A refused walk still carries its original refusal if a projection
        // cannot name an owner. Such identities remain Unprojected.
        let owners = if projection.stop.is_some() {
            Some(owners.unwrap_or_default())
        } else {
            owners
        };
        Ok(owners.map(|owners| PythonClassHierarchy {
            projection,
            owners,
            provider_open,
            provider_names,
            decorated,
        }))
    }

    /// Read the own bases of many classes on ONE forward operation, as the JVM
    /// languages hold theirs for a walk. `run` receives a reader that takes a
    /// source class; setup is paid once, not per class. The reader returns
    /// `None` when the class is not in the selected crosswalk or the walk was
    /// cancelled. The walk is bounded by the caller's cancellation, as the JVM
    /// walk is. The operation is revalidated once when `run` returns; a stale
    /// or cancelled selection is returned for the caller to treat as a stopped
    /// walk.
    #[doc(hidden)]
    pub fn with_python_direct_bases<T>(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        cancellation: &CancellationToken,
        run: impl FnOnce(&mut dyn FnMut(&CodeUnit) -> Result<PythonHierarchyRead>) -> T,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        let session = ResolutionSession::unbounded();
        let session = &session;
        let context = self.empty_contexts(&ResolutionCompletion::Complete)?;
        let Some(blueprint) = self.prepare_prefix_blueprint(context, cancellation)? else {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        };
        let shape = self.python_hierarchy_shape();
        let value = self.with_python_forward_operation(
            environment.summary,
            environment.python_version,
            &blueprint,
            session,
            cancellation,
            |operation, provider, _, _, _, external_imports, _, _| {
                let mut crosswalks = HierarchyCrosswalkCache::default();
                let mut direct = |unit: &CodeUnit| {
                    let definition = match self.selected_hierarchy_definition_cached(
                        unit,
                        &mut crosswalks,
                        cancellation,
                        session,
                    )? {
                        LocatedSemantic::Found(definition) => definition,
                        LocatedSemantic::Missing => return Ok(PythonHierarchyRead::Unavailable),
                        LocatedSemantic::Cancelled => {
                            return Ok(PythonHierarchyRead::Stopped {
                                stop: crate::analyzer::resolution::HierarchyStop::Cancelled(
                                    cancelled_completion(),
                                ),
                                hierarchy: None,
                            });
                        }
                    };
                    self.hierarchy_in_operation(
                        operation,
                        provider,
                        external_imports,
                        definition,
                        shape,
                        None,
                        cancellation,
                        session,
                    )
                    .map(|hierarchy| match hierarchy {
                        Some(mut hierarchy) => match hierarchy.projection.stop.take() {
                            Some(stop) => PythonHierarchyRead::Stopped {
                                stop,
                                hierarchy: Some(Box::new(hierarchy)),
                            },
                            None => PythonHierarchyRead::Ready(Box::new(hierarchy)),
                        },
                        None => PythonHierarchyRead::Stopped {
                            stop: if cancellation.is_cancelled() {
                                crate::analyzer::resolution::HierarchyStop::Cancelled(
                                    cancelled_completion(),
                                )
                            } else {
                                crate::analyzer::resolution::HierarchyStop::Provider(
                                    ResolutionCompletion::Complete,
                                )
                            },
                            hierarchy: None,
                        },
                    })
                };
                Ok(run(&mut direct))
            },
        )?;
        self.finish_native(value, &ResolutionCompletion::Complete, cancellation)
    }

    fn python_hierarchy_shape(&self) -> SemanticId {
        let mut hasher = CanonicalHasher::new(b"python-hierarchy-only-shape:v1");
        hasher.field("language", b"python");
        SemanticId::shared_name(self.ready.shared_names().intern(hasher.finish()))
    }

    fn decorated_python_classes(
        &self,
        projection: &HierarchyProjection,
    ) -> Result<Vec<SemanticId>> {
        let mut decorated = Vec::new();
        // A decorator can replace a base as well as the class it decorates, so
        // the targets of every read edge are checked, not only the owners the
        // walk expanded (a direct-bases request expands only the root).
        let mut owners = std::collections::BTreeSet::new();
        for node in &projection.nodes {
            owners.insert(node.owner);
            owners.extend(
                node.edges
                    .iter()
                    .flat_map(|edge| edge.targets.iter().copied()),
            );
        }
        for owner in owners {
            let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
                continue;
            };
            let mount = self
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            if mount.semantic_language() != Language::Python {
                continue;
            }
            if self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites semantic
                       JOIN python_member_classes class
                         ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site
                       JOIN python_member_decorators decorator
                         ON decorator.blob_id=class.blob_id AND decorator.declaration=class.class
                      WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                        AND semantic.semantic_role='definition')",
                )?
                .query_row(rusqlite::params![mount.blob_id(), key], |row| row.get(0))?
            {
                decorated.push(owner);
            }
        }
        Ok(decorated)
    }

    /// Name every identity the walk reached. A model or fixed-universe class is
    /// named by its selected authority; any other is a selected source class.
    fn project_python_hierarchy_owners(
        &self,
        projection: &HierarchyProjection,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<Option<Vec<(SemanticId, PythonHierarchyOwner)>>> {
        let mut identities = std::collections::BTreeSet::new();
        for node in &projection.nodes {
            identities.insert(node.owner);
            for edge in &node.edges {
                identities.extend(edge.targets.iter().copied());
            }
        }
        let mut owners = Vec::with_capacity(identities.len());
        let mut source = Vec::new();
        for id in identities {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if let Some(model) = self.ready.context_identities.model_member_identity(id) {
                let declaration =
                    match self.ready.analyzer.and_then(|analyzer| {
                        analyzer.model_authority().zip(analyzer.active_models())
                    }) {
                        Some((authority, active)) => super::python_models::declaration(
                            &*authority,
                            &active,
                            &model,
                            cancellation,
                        )?,
                        None => None,
                    };
                owners.push((
                    id,
                    match declaration {
                        Some(owner) if owner.declaration.kind == SemanticModelSymbolKind::Class => {
                            PythonHierarchyOwner::Model(Box::new(owner.declaration))
                        }
                        _ => PythonHierarchyOwner::Unprojected,
                    },
                ));
            } else if let Some(entry) = crate::analyzer::resolution::universe_entry_for_identity(
                &self.ready.lexical_source(),
                id,
                cancellation,
            )? {
                owners.push((
                    id,
                    PythonHierarchyOwner::Intrinsic {
                        canonical_name: entry.identity_spelling.to_owned(),
                    },
                ));
            } else {
                source.push(id);
            }
        }
        match super::native_units::project_native_definition_units(
            &self.ready,
            &source,
            cancellation,
            session,
        )? {
            SelectedNativeDefinitions::Ready(definitions) => {
                for (id, definition) in definitions {
                    owners.push((
                        id,
                        match definition {
                            SelectedNativeDefinition::Unit(unit) => {
                                PythonHierarchyOwner::Source(unit)
                            }
                            _ => PythonHierarchyOwner::Unprojected,
                        },
                    ));
                }
            }
            SelectedNativeDefinitions::Cancelled => return Ok(None),
            SelectedNativeDefinitions::Unavailable => {
                owners.extend(
                    source
                        .into_iter()
                        .map(|id| (id, PythonHierarchyOwner::Unprojected)),
                );
            }
        }
        Ok(Some(owners))
    }
}

/// The C3 order of a Python class graph whose bases a source already knows,
/// such as the selected model authority's declarations. It runs the same
/// cursor and policy as the selected walk; only the supertype source differs.
/// `step_limit` bounds the merge, which is the whole cost of the order.
#[doc(hidden)]
pub fn python_model_c3<T: Clone + Eq + std::hash::Hash>(
    root: &T,
    source: &mut impl crate::analyzer::resolution::SupertypeSource<T>,
    step_limit: usize,
) -> std::result::Result<Vec<T>, crate::analyzer::resolution::LinearizationFailure> {
    crate::analyzer::resolution::linearize(root, source, &PYTHON_C3, step_limit)
}
