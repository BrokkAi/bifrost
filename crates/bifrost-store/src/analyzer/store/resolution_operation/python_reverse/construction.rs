//! Initializer construction families, retained only for one reverse query.
use super::super::native_units::{SelectedNativeDefinition, SelectedNativeDefinitions};
use super::*;
use crate::analyzer::resolution::{
    BindingFragmentId, DemandReferenceKey, FactPageVisitor, HierarchyPolicy, QualifiedMemberInput,
    QualifiedMemberRegistration, ResolutionLookupSemanticRecipe, ResolutionTypeRef,
    SelectedTypedFactSource, TypedConstructionInput, TypedFactRequest,
};
use std::collections::VecDeque;

#[derive(Debug, Default)]
pub(super) struct ConstructionFamily {
    pub(super) calls: HashMap<SelectedSemanticLocator, ConstructionBinding>,
    pub(super) obligations: Vec<String>,
}
#[derive(Debug)]
pub(super) struct ConstructionBinding {
    targets: Vec<SemanticId>,
    completion: ResolutionCompletion,
}
impl ConstructionFamily {
    fn finish(mut self, session: &ResolutionSession) -> Self {
        match session.finish(()) {
            BoundedResolution::Exceeded { limit, .. } => self.obligations.push(format!(
                "python_reverse_resolution_budget_exceeded:{}",
                limit.as_str()
            )),
            BoundedResolution::Unavailable { reason, .. } => self
                .obligations
                .push(format!("python_reverse_input_unavailable:{reason}")),
            BoundedResolution::Cancelled { .. } => self.obligations.push("cancelled".into()),
            BoundedResolution::Complete { .. } => {}
        }
        self.obligations.sort();
        self.obligations.dedup();
        self
    }

    pub(super) fn project(
        &self,
        locator: &SelectedSemanticLocator,
        answer: FactResolutionAnswer,
    ) -> FactResolutionAnswer {
        match self.calls.get(locator) {
            None => answer,
            Some(binding) => {
                let mut projected = FactResolutionAnswer::from_selected_summary_binding(
                    answer.site_metadata().expect("selected callee metadata"),
                    binding.targets.clone(),
                    binding.completion.clone(),
                );
                // A construction changes the callee binding, not the query's scope.
                projected.query_obligations = answer.query_obligations;
                projected
            }
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn python_construction_family(
        &self,
        view: &PythonReverseView,
        target: &CodeUnit,
        semantics: &[SemanticId],
        request: &PythonReverseRequest<'_>,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    ) -> Result<ConstructionFamily> {
        let mut family = ConstructionFamily::default();
        if target.identifier() != "__init__" {
            return Ok(family);
        }
        let owned_session = ResolutionSession::bounded(
            ReceiverAnalysisBudget::default(),
            Some(request.cancellation),
        );
        let session = request.session.unwrap_or(&owned_session);
        let cancel = request.cancellation;
        let typed = self.ready.typed_source();
        let mut owners = Vec::new();
        let read = typed.visit_member_owner_pages_for_definitions(
            TypedFactRequest::new(semantics),
            cancel,
            &mut FactPageVisitor::new(&mut |page| {
                for row in page {
                    owners.push(row.row().owner_definition());
                }
                Ok(true)
            }),
        )?;
        if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
            family
                .obligations
                .push("python_initializer_owner_open".into());
        }
        owners.sort_unstable();
        owners.dedup();
        let mut classes = Vec::new();
        for owner in owners {
            if super::super::python_members::is_class(&self.ready, owner)? {
                classes.push(owner);
            }
        }
        let owners = classes;
        if owners.is_empty() {
            return Ok(family.finish(session));
        }
        let context = empty_contexts_for(
            self.mount_table(),
            &ResolutionCompletion::Complete,
            &selected_mount_lookup(self.mount_table()),
            self.ready.context_identities.clone(),
        )?;
        let SelectedResolutionContextValidationOutcome::Ready(context) = self
            .prepare_context_in_session(
                context,
                cancel,
                &SelectedResolutionContextMetrics,
                session,
            )?
        else {
            family
                .obligations
                .push("python_initializer_context_open".into());
            return Ok(family.finish(session));
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = self
            .ready
            .collect_blueprint_in_session(context, cancel, session)?
        else {
            family
                .obligations
                .push("python_initializer_context_open".into());
            return Ok(family.finish(session));
        };
        if !matches!(
            self.ready.register_context(&blueprint, cancel)?,
            ContextRegistrationOutcome::Ready
        ) {
            family
                .obligations
                .push("python_initializer_context_open".into());
            return Ok(family.finish(session));
        }
        self.with_python_forward_operation(view.summary, python_version, &blueprint, session, cancel,
            |operation, provider, _, _, _, _, _, _mutations| {
                let mut pending = VecDeque::from(owners);
                let mut visited = HashSet::default();
                // Query-local syntax inventory, shared by every exposure of one blob.
                let mut open_bases = HashMap::<i64, Vec<(usize, usize)>>::default();
                while let Some(owner) = pending.pop_front() {
                    if !visited.insert(owner) { continue; }
                    if !session.scope_step() || cancel.is_cancelled() { break; }
                    let units = super::super::native_units::project_native_definition_units(&self.ready, &[owner], cancel, session)?;
                    let SelectedNativeDefinitions::Ready(units) = units else {
                        family.obligations.push("python_initializer_class_projection_open".into());
                        continue;
                    };
                    for (_, definition) in units {
                        let SelectedNativeDefinition::Unit(class) = definition else { continue; };
                        let hooks = PythonReverseHooks { operation: self, view, cancellation: cancel, coordinate: None, target: &class };
                        let coordinates = hooks.coordinates(&class, cancel)?;
                        if coordinates.is_empty() {
                            family.obligations.push("python_initializer_class_exposure_open".into());
                        }
                        for coordinate in coordinates {
                            let exact = PythonReverseHooks { operation: self, view, cancellation: cancel, coordinate: Some(coordinate), target: &class };
                            let Some(candidates) = nominate_reverse_target(self, &exact, &class, &[], cancel)? else {
                                family.obligations.push("python_initializer_class_exposure_open".into());
                                continue;
                            };
                            for locator in candidates.locators {
                                if !session.scope_step() || cancel.is_cancelled() { break; }
                                let mount = self.mount_table().mount_for_path("python", locator.relative_path())?.expect("selected construction candidate");
                                let blob = self.ready.inventory.mount_record_by_ordinal(mount.ordinal())?.blob_id();
                                let site = locator.source_site().expect("source candidate").get();
                                let conn = self.ready.inventory.connection();
                                let callee: Option<(u32, u32)> = conn.prepare_cached("SELECT semantic.semantic_key,call.result_slot FROM resolution_semantic_sites semantic
                                     JOIN resolution_call_obligations call ON call.blob_id=semantic.blob_id AND call.callee_reference=semantic.semantic_key
                                     WHERE semantic.blob_id=?1 AND semantic.source_site=?2 AND semantic.semantic_role='reference' LIMIT 1")?.query_row(
                                    params![blob, site], |row| Ok((row.get(0)?, row.get(1)?)),
                                ).optional()?;
                                let bases = conn.prepare_cached(
                                    "SELECT child.semantic_key,semantic.semantic_key FROM python_member_base_operands base
                                     JOIN resolution_semantic_sites child ON child.blob_id=base.blob_id AND child.source_site=base.class AND child.semantic_role='definition'
                                     JOIN resolution_semantic_sites semantic ON semantic.blob_id=base.blob_id AND semantic.source_site=base.expression_site AND semantic.semantic_role='reference'
                                     WHERE base.blob_id=?1 AND base.expression_site=?2",
                                )?.query_map(params![blob,site], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                                if let std::collections::hash_map::Entry::Vacant(entry) = open_bases.entry(blob) {
                                    let mut statement = conn.prepare_cached(
                                        "SELECT position.start_byte,position.end_byte FROM python_member_base_operands base
                                         JOIN python_member_sites position ON position.blob_id=base.blob_id AND position.site=base.expression_site
                                         WHERE base.blob_id=?1 AND NOT EXISTS(
                                           SELECT 1 FROM resolution_semantic_sites semantic WHERE semantic.blob_id=base.blob_id
                                             AND semantic.source_site=base.expression_site AND semantic.semantic_role='reference')
                                         ORDER BY position.start_byte,position.end_byte",
                                    )?;
                                    let mut positions = Vec::new();
                                    let mut last_end = 0;
                                    for row in statement.query_map([blob], |row| Ok((row.get::<_, usize>(0)?, row.get::<_, usize>(1)?)))? {
                                        let (start, end) = row?;
                                        if !session.scope_step() || cancel.is_cancelled() { break; }
                                        // A prefix maximum also covers overlapping recovery nodes.
                                        last_end = last_end.max(end);
                                        positions.push((start, last_end));
                                    }
                                    entry.insert(positions);
                                }
                                let positions = &open_bases[&blob];
                                if !positions.is_empty() {
                                    let (start, end) = python_site_range(conn, blob, site)?;
                                    let before = positions.partition_point(|&(base_start, _)| base_start <= start);
                                    if before > 0 && end <= positions[before - 1].1 {
                                        // The class exposure reaches a base operand that has no
                                        // forward reference. It cannot certify subclass closure.
                                        family.obligations.push(format!("python_initializer_base_open:{}:{site}", locator.relative_path()));
                                    }
                                }
                                if let Some((callee, result)) = callee {
                                    let semantic = SemanticId::local(mount.ordinal().get(), callee);
                                    let FactDemandResolution::Ready(answer) = operation.resolve_reference_by_demand(semantic, provider)? else {
                                        family.obligations.push("python_initializer_callee_open".into());
                                        continue;
                                    };
                                    let binding = answer.binding();
                                    let mut completion = binding.completion().clone();
                                    let mut targets = binding.targets().to_vec();
                                    if let [class] = binding.targets()
                                        && completion == ResolutionCompletion::Complete
                                        && super::super::python_members::is_class(&self.ready, *class)? {
                                            let (constructed, proof) = operation.prove_construction_by_demand(&TypedConstructionInput {
                                                reference: DemandReferenceKey::caller(semantic), output: SemanticId::local(mount.ordinal().get(), result),
                                                language: Language::Python, binding: binding.clone(),
                                            }, provider)?;
                                            completion = completion.combine(&proof);
                                            if constructed.is_some() && completion == ResolutionCompletion::Complete {
                                                (targets, completion) = self.python_initializer_selection(operation, provider, semantic, *class)?;
                                            } else {
                                                targets.clear();
                                                completion = completion.combine(&ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(semantic)]));
                                            }
                                    }
                                    if binding.targets().len() != 1 {
                                        completion = completion.combine(&ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(semantic)]));
                                    }
                                    if completion != ResolutionCompletion::Complete {
                                        family.obligations.push(format!("python_initializer_construction_open:{}:{site}", locator.relative_path()));
                                    }
                                    family.calls.insert(locator.clone(), ConstructionBinding { targets, completion });
                                }
                                for (subtype, reference) in bases {
                                    let reference = SemanticId::local(mount.ordinal().get(), reference);
                                    let FactDemandResolution::Ready(answer) = operation.resolve_reference_by_demand(reference, provider)? else {
                                        family.obligations.push("python_initializer_base_open".into()); continue;
                                    };
                                    if answer.binding().completion() != &ResolutionCompletion::Complete {
                                        family.obligations.push(format!("python_initializer_base_open:{}:{site}", locator.relative_path())); continue;
                                    }
                                    if answer.binding().targets().len() != 1 {
                                        family.obligations.push(format!("python_initializer_base_open:{}:{site}", locator.relative_path()));
                                        continue;
                                    }
                                    if answer.binding().targets() != [owner] { continue; }
                                    let subtype = SemanticId::local(mount.ordinal().get(), subtype);
                                    let (selected, completion) = self.python_initializer_selection(operation, provider, reference, subtype)?;
                                    if completion != ResolutionCompletion::Complete {
                                        family.obligations.push(format!("python_initializer_mro_open:{}:{site}", locator.relative_path()));
                                    }
                                    if selected.iter().any(|selected| semantics.contains(selected)) {
                                        pending.push_back(subtype);
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(())
            },
        )?;
        Ok(family.finish(session))
    }

    fn python_initializer_selection(
        &self,
        operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        provider: &mut impl crate::analyzer::resolution::DemandRootProvider,
        reference: SemanticId,
        class: SemanticId,
    ) -> Result<(Vec<SemanticId>, ResolutionCompletion)> {
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Python,
            ResolutionNamespace::Value,
            "__init__",
        )
        .semantic(&self.ready.shared_names());
        operation.qualified_member_by_demand(
            &QualifiedMemberInput {
                reference: DemandReferenceKey::caller(reference),
                route_ordinal: 0,
                precedence: 0,
                fragment: BindingFragmentId::at_ordinal(
                    reference.ordinal().expect("source constructor or base"),
                ),
                source_lookup: lookup,
                lookup,
                namespace: ResolutionNamespace::Value,
                values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    class, 0,
                ))],
                completion: ResolutionCompletion::Complete,
                registration: QualifiedMemberRegistration {
                    language: Language::Python,
                    hierarchy_identity: super::super::python_members::PYTHON_HIERARCHY.identity().0,
                    member_access: true,
                },
            },
            provider,
        )
    }
}
