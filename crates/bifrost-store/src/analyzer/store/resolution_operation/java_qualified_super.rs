//! Selected, request-local Java qualified-super receiver proofs.
use super::*;
use crate::analyzer::resolution::fact_resolution::{
    JavaReceiverOverrideSidecar, ReceiverOverrideLanguage, SelectedReceiverSlotOverride,
    SelectedSlotEvidence,
};
use crate::analyzer::resolution::{
    ClassifiedSupertypeKind, JavaInheritanceDeclarationKind, LoweringGapOrigin,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_BINDING_PROJECTION_KINDS, ALL_RESOLUTION_TYPE_SLOT_ROLES, BindingProjectionKind,
    ResolutionCallableReceiverOrigin, ResolutionGapKind, ResolutionSupertypeKind,
    ResolutionTypeSlotRole,
};

// The qualifier projection's output and the receiver are both owned by the
// call's exact producer gap. No transfer feeds the qualifier into the receiver:
// a failed admission therefore leaves the original empty receiver untouched.
const QUALIFIER: &str = r#"
SELECT DISTINCT projection.reference, call.call, call.receiver_slot, reason.reason
FROM temp.selected_resolution_mounts mount
JOIN main.resolution_sites callee ON callee.blob_id=mount.blob_id AND callee.site=?2
JOIN main.resolution_call_obligations call
 ON call.blob_id=callee.blob_id AND call.callee_reference=callee.site
JOIN main.resolution_gaps receiver_gap
 ON receiver_gap.blob_id=call.blob_id
 AND receiver_gap.covers=7 AND receiver_gap.subject=call.receiver_slot
JOIN main.resolution_gap_reasons reason
 ON reason.blob_id=call.blob_id AND reason.reason=receiver_gap.reason AND reason.origin=?3
JOIN main.resolution_gaps qualifier_gap
 ON qualifier_gap.blob_id=call.blob_id AND qualifier_gap.reason=reason.reason
 AND qualifier_gap.covers=7
JOIN main.resolution_type_frontiers qualifier
 ON qualifier.blob_id=call.blob_id AND qualifier.slot=qualifier_gap.subject AND qualifier.role=?4
JOIN main.resolution_binding_projections projection
 ON projection.blob_id=qualifier.blob_id AND projection.output_slot=qualifier.slot AND projection.kind=?5
WHERE mount.mount_ordinal=?1 AND mount.semantic_language='java' AND callee.receiver_origin=?6
"#;

impl SelectedResolutionOperation<'_, '_> {
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub(super) fn java_qualified_super_override(
        &self,
        context: jvm_demand::JvmForwardOperationContext<'_>,
        reference: SemanticId,
    ) -> Result<Option<SelectedReceiverSlotOverride>> {
        let (Some(mount), Some(key)) = (reference.ordinal(), reference.local_key()) else {
            return Ok(None);
        };
        if context.storage_language != "java" || context.cancellation.is_cancelled() {
            return Ok(None);
        }
        let code = |values: &[ResolutionTypeSlotRole], value| {
            i64::try_from(
                values
                    .iter()
                    .position(|candidate| *candidate == value)
                    .unwrap(),
            )
            .unwrap()
        };
        let projection_kind = i64::try_from(
            ALL_BINDING_PROJECTION_KINDS
                .iter()
                .position(|kind| *kind == BindingProjectionKind::TargetTypeIdentity)
                .unwrap(),
        )
        .unwrap();
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(QUALIFIER)?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    mount,
                    key,
                    super::super::resolution_prepare::resolution_rows::gap_origin_code(
                        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpression)
                    ),
                    code(
                        ALL_RESOLUTION_TYPE_SLOT_ROLES,
                        ResolutionTypeSlotRole::TargetTypeIdentity
                    ),
                    projection_kind,
                    super::super::resolution_prepare::resolution_rows::receiver_origin_code(
                        ResolutionCallableReceiverOrigin::Super
                    ),
                ],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u32>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        self.profile_jvm_read("qualified_super_rows", (reference, &rows));
        let [(qualifier, call, receiver, gap)] = rows.as_slice() else {
            return Ok(None);
        };
        let (qualifier, call, receiver, gap) = (
            SemanticId::local(mount, *qualifier),
            SemanticId::local(mount, *call),
            SemanticId::local(mount, *receiver),
            SemanticId::local(mount, *gap),
        );
        let Some(endpoints) = context
            .typed
            .jvm_access_endpoints(&[reference], context.cancellation)?
        else {
            return Ok(None);
        };
        self.profile_jvm_read("qualified_super_context", (reference, &endpoints));
        let [endpoint] = endpoints.as_slice() else {
            return Ok(None);
        };
        let Some(&immediate) = endpoint.enclosing_templates.first() else {
            return Ok(None);
        };
        let typed = context.typed;
        let cancellation = context.cancellation;
        self.with_jvm_hierarchy_query(context, |hierarchy| {
            let answer = hierarchy.qualified_super_qualifier(qualifier)?;
            self.profile_jvm_read("qualified_super_qualifier", (qualifier, answer));
            let Some(selected) = answer else {
                return Ok(None);
            };
            let Some(declarations) =
                typed.java_inheritance_declarations(&[selected], cancellation)?
            else {
                return Ok(None);
            };
            let [declaration] = declarations.as_slice() else {
                return Ok(None);
            };
            let JavaInheritanceDeclarationKind::Type { is_interface, .. } = declaration.kind else {
                return Ok(None);
            };
            let owner = if is_interface { immediate } else { selected };
            if !is_interface && !endpoint.enclosing_templates.contains(&selected) {
                return Ok(None);
            }
            let enclosing_instance =
                self.java_super_has_enclosing_instance(reference, owner, cancellation)?;
            self.profile_jvm_read(
                "qualified_super_instance",
                (reference, owner, enclosing_instance),
            );
            if !enclosing_instance {
                return Ok(None);
            }
            let parents = hierarchy.jvm_direct_supertype_answer(owner)?;
            self.profile_jvm_read("qualified_super_parents", (reference, &parents));
            if parents.completion != ResolutionCompletion::Complete
                || parents.parents.iter().any(|parent| {
                    parent.completion != ResolutionCompletion::Complete || parent.targets.len() != 1
                })
            {
                return Ok(None);
            }
            let root = if is_interface {
                let matches = parents
                    .parents
                    .iter()
                    .filter(|parent| {
                        parent.kind == Some(ClassifiedSupertypeKind::Interface)
                            && parent.targets == [selected]
                    })
                    .count();
                if matches != 1 {
                    return Ok(None);
                }
                // JLS 15.12.1: another direct parent that is a subtype of I
                // makes I.super redundant. Prove absence over its complete
                // ancestor closure, not just the direct-parent edge list.
                let mut pending = parents
                    .parents
                    .iter()
                    .filter(|parent| {
                        parent.kind != Some(ClassifiedSupertypeKind::Interface)
                            || parent.targets[0] != selected
                    })
                    .map(|parent| (parent.kind, parent.targets[0]))
                    .collect::<Vec<_>>();
                let mut visited = HashSet::default();
                while let Some((kind, ancestor)) = pending.pop() {
                    if cancellation.is_cancelled() || ancestor == selected {
                        return Ok(None);
                    }
                    // Only the selected language-defined implicit superclass
                    // is a closed leaf without a further hierarchy read.
                    let external = self.hierarchy_external_owner(ancestor);
                    if kind == Some(ClassifiedSupertypeKind::ImplicitSuperclass)
                        && let Some(intrinsic) = jvm_direct_supertypes::jvm_intrinsic_parent(
                            Language::Java,
                            Some(ResolutionSupertypeKind::ImplicitSuperclass),
                        )
                        && external.as_ref() == Some(&intrinsic)
                    {
                        continue;
                    }
                    if !visited.insert(ancestor) {
                        continue;
                    }
                    // Exhausting stored rows does not close an unindexed
                    // external hierarchy. Require its selected inventory proof;
                    // a non-external node must be a selected source declaration.
                    let hierarchy_available = match external {
                        Some(owner) => typed.jvm_external_owner_is_indexed(&owner)?,
                        None => ancestor.ordinal().is_some(),
                    };
                    if !hierarchy_available {
                        return Ok(None);
                    }
                    let ancestors = hierarchy.jvm_direct_supertype_answer(ancestor)?;
                    if ancestors.completion != ResolutionCompletion::Complete
                        || ancestors.parents.iter().any(|parent| {
                            parent.completion != ResolutionCompletion::Complete
                                || parent.targets.len() != 1
                        })
                    {
                        return Ok(None);
                    }
                    pending.extend(
                        ancestors
                            .parents
                            .iter()
                            .map(|parent| (parent.kind, parent.targets[0])),
                    );
                }
                selected
            } else {
                let superclasses = parents
                    .parents
                    .iter()
                    .filter(|parent| {
                        matches!(
                            parent.kind,
                            Some(
                                ClassifiedSupertypeKind::Superclass
                                    | ClassifiedSupertypeKind::ImplicitSuperclass
                            )
                        )
                    })
                    .collect::<Vec<_>>();
                let [superclass] = superclasses.as_slice() else {
                    return Ok(None);
                };
                superclass.targets[0]
            };
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            Ok(Some(SelectedReceiverSlotOverride {
                receiver: SelectedSlotEvidence {
                    slot: receiver,
                    value: crate::analyzer::resolution::ResolutionSlotValue::runtime(
                        crate::analyzer::resolution::ResolutionTypeRef::new(root, 0),
                        false,
                    ),
                    completion: parents.completion,
                },
                supporting_slots: Box::new([]),
                language: ReceiverOverrideLanguage::Java(JavaReceiverOverrideSidecar {
                    callee: reference,
                    call,
                    receiver_slot: receiver,
                    receiver_gap: gap,
                }),
            }))
        })
    }

    /// Exact selected declaration ranges establish lexical containment. The
    /// source metadata and execution frame reject every static scope between
    /// the call and its selected enclosing type, including initializers.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn java_super_has_enclosing_instance(
        &self,
        reference: SemanticId,
        owner: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if cancellation.is_cancelled() || reference.ordinal() != owner.ordinal() {
            return Ok(false);
        }
        let answer = self.ready.inventory.connection().prepare_cached(r#"
SELECT execution.disposition='callable'
 AND COALESCE(execution.initializer_is_static, 0)=0
 AND NOT EXISTS (
  SELECT 1 FROM source_declarations boundary
  JOIN source_declaration_metadata_bridges link ON link.blob_id=boundary.blob_id AND link.declaration_id=boundary.declaration_id
  JOIN unit_signature_metadata_values metadata ON metadata.blob_id=link.blob_id AND metadata.unit_key=link.unit_key AND metadata.ordinal=link.metadata_ordinal
  WHERE boundary.blob_id=mount.blob_id AND boundary.start_byte>enclosing.start_byte
    AND boundary.start_byte<=site.start_byte AND boundary.end_byte>=site.end_byte
    AND (metadata.callable_is_static=1 OR metadata.field_is_static=1 OR metadata.class_like_is_static=1)
 )
FROM temp.selected_resolution_mounts mount
JOIN resolution_sites site ON site.blob_id=mount.blob_id AND site.site=?2
JOIN source_native_declaration_bridges bridge ON bridge.blob_id=mount.blob_id AND bridge.source_site=?3
JOIN source_declarations enclosing ON enclosing.blob_id=bridge.blob_id AND enclosing.declaration_id=bridge.declaration_id
JOIN resolution_reference_execution_contexts execution ON execution.blob_id=site.blob_id AND execution.site=site.site
WHERE mount.mount_ordinal=?1
"#)?.query_row(rusqlite::params![reference.ordinal(), reference.local_key(), owner.local_key()], |row| row.get::<_, bool>(0)).optional()?;
        Ok(answer == Some(true) && !cancellation.is_cancelled())
    }
}
