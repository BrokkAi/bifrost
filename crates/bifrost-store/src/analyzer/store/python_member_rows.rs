//! Retained member syntax for one selected source owner. Every result is query-local.
use super::{Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::resolution::SharedNameInterner;
use brokk_bifrost_core::analyzer::resolution_facts::*;
use rusqlite::{Transaction, params};

/// Selected mutable-owner domain, requested only by shared no-hit reduction.
/// The source inventory is indexed by selected blob and name bounds. An exact
/// empty set has no child spelling and therefore never matches this read.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const LATE_OPERATIONS_SQL: &str = r#"
SELECT mounts.mount_ordinal,op.site,op.form,callee.semantic_key,receiver.semantic_key
FROM temp.selected_resolution_mounts mounts
JOIN resolution_unit_summary_members member ON member.summary_id=?3
 AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?1
CROSS JOIN python_member_operations op INDEXED BY python_member_operations_inventory
 ON op.blob_id=mounts.blob_id AND op.name_kind IN (0,1,2) AND op.effect IN (1,2)
LEFT JOIN resolution_semantic_sites callee
 ON callee.blob_id=op.blob_id AND callee.source_site=op.callee_reference AND callee.semantic_role='reference'
LEFT JOIN resolution_semantic_sites receiver
 ON receiver.blob_id=op.blob_id AND receiver.source_site=op.receiver_reference AND receiver.semantic_role='reference'
WHERE mounts.storage_language='python' AND (op.name_kind=2 OR EXISTS(
 SELECT 1 FROM python_member_operation_names names WHERE names.operation=op.id
 AND ((op.name_kind=0 AND names.spelling=?2)
   OR (op.name_kind=1 AND substr(?2,1,length(names.spelling))=names.spelling))))
ORDER BY mounts.mount_ordinal,op.site,op.form
"#;

/// Same-name class-object candidates. Exact names enter through the spelling
/// index; matching prefixes and Any use indexed selected-blob arms. Computed receivers have no
/// direct reference and therefore remain in the late inventory only.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const OWNER_OPERATIONS_SQL: &str = r#"
WITH candidates AS (
 SELECT op.blob_id,op.site,op.form,op.callee_reference,op.receiver_reference
 FROM python_member_operation_names names INDEXED BY python_member_operation_names_spelling
 JOIN python_member_operations op ON op.id=names.operation
 WHERE names.spelling=?2 AND op.name_kind=0 AND op.effect IN (1,2)
 UNION ALL
 SELECT op.blob_id,op.site,op.form,op.callee_reference,op.receiver_reference
 FROM temp.selected_resolution_mounts selected
 CROSS JOIN python_member_operations op INDEXED BY python_member_operations_inventory
 ON op.blob_id=selected.blob_id AND op.name_kind IN (1,2) AND op.effect IN (1,2)
 WHERE selected.storage_language='python' AND (op.name_kind=2 OR EXISTS(
  SELECT 1 FROM python_member_operation_names names WHERE names.operation=op.id
   AND substr(?2,1,length(names.spelling))=names.spelling))
)
SELECT mounts.mount_ordinal,op.site,op.form,callee.semantic_key,receiver.semantic_key
FROM candidates op
JOIN temp.selected_resolution_mounts mounts ON mounts.blob_id=op.blob_id
JOIN resolution_unit_summary_members member ON member.summary_id=?3
 AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
JOIN python_binding_source source ON source.blob_id=op.blob_id AND source.format=?1
LEFT JOIN resolution_semantic_sites callee
 ON callee.blob_id=op.blob_id AND callee.source_site=op.callee_reference AND callee.semantic_role='reference'
JOIN resolution_semantic_sites receiver
 ON receiver.blob_id=op.blob_id AND receiver.source_site=op.receiver_reference AND receiver.semantic_role='reference'
WHERE mounts.storage_language='python'
ORDER BY mounts.mount_ordinal,op.site,op.form
"#;

/// Direct attribute writes already have reference lookup and receiver-slot
/// coordinates. Reuse them rather than publishing a duplicate operation form.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const DIRECT_MEMBER_WRITES_SQL: &str = r#"
SELECT DISTINCT mounts.mount_ordinal,writes.site,7,NULL,coalesce(direct.reference,incoming.reference)
FROM resolution_identities name INDEXED BY resolution_identities_spelling
CROSS JOIN resolution_reference_lookup_identities lookup INDEXED BY resolution_reference_lookup_identities_identity
 ON lookup.identity_id=name.id
JOIN resolution_semantic_sites target ON target.blob_id=lookup.blob_id
 AND target.semantic_key=lookup.semantic_key AND target.semantic_role='reference'
JOIN python_member_receiver_writes writes ON writes.blob_id=target.blob_id AND writes.site=target.source_site
JOIN resolution_qualified_routes qualified ON qualified.blob_id=target.blob_id AND qualified.reference=target.semantic_key
LEFT JOIN resolution_binding_projections direct ON direct.blob_id=qualified.blob_id
 AND direct.output_slot=qualified.qualifier_slot AND direct.kind<>?4
LEFT JOIN resolution_type_transfers transfer ON transfer.blob_id=qualified.blob_id AND transfer.target_slot=qualified.qualifier_slot
LEFT JOIN resolution_binding_projections incoming ON incoming.blob_id=transfer.blob_id
 AND incoming.output_slot=transfer.source_slot AND incoming.kind<>?4
JOIN temp.selected_resolution_mounts mounts ON mounts.blob_id=writes.blob_id
JOIN resolution_unit_summary_members member ON member.summary_id=?3
 AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?1
WHERE name.spelling=?2 AND mounts.storage_language='python'
ORDER BY mounts.mount_ordinal,writes.site
"#;

/// Canonical lookup name for one prepared source reference.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const UNIVERSE_REFERENCE_NAME_SQL: &str = "SELECT name.spelling,site.source_site FROM resolution_semantic_sites site JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=site.blob_id AND lookup.semantic_key=site.semantic_key JOIN resolution_identities name ON name.id=lookup.identity_id WHERE site.blob_id=?1 AND site.semantic_key=?2 AND site.semantic_role='reference'";

/// Retained lexical hazards and a structurally selected class namespace.
/// Neither is a second authority for builtin-module mutation operations.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const BUILTIN_NAMESPACE_CLOSED_SQL: &str = r#"
SELECT NOT EXISTS (
 SELECT 1 FROM resolution_gaps gap JOIN resolution_gap_reasons reason
 ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
 WHERE gap.blob_id=?1 AND gap.covers IN (2,5) AND gap.lookup=0 AND reason.origin=?3
) AND NOT EXISTS (
 SELECT 1 FROM python_member_sites site
 JOIN resolution_node_catalog node ON node.blob_id=site.blob_id AND node.source_scope=site.scope
 JOIN resolution_member_scope_properties scope ON scope.blob_id=node.blob_id
 AND scope.scope_head_node_key=node.local_key AND scope.scope_kind='type_body'
 JOIN resolution_semantic_sites definition ON definition.blob_id=scope.blob_id
 AND definition.semantic_key=scope.definition_semantic_key AND definition.semantic_role='definition'
 JOIN python_member_classes class ON class.blob_id=definition.blob_id AND class.class=definition.source_site
 WHERE site.blob_id=?1 AND site.site=?2 AND (class.metaclass IS NOT NULL OR class.bases_complete=0
 OR EXISTS(SELECT 1 FROM python_member_base_operands base WHERE base.blob_id=class.blob_id AND base.class=class.class)
 OR EXISTS(SELECT 1 FROM python_member_class_keywords keyword WHERE keyword.blob_id=class.blob_id AND keyword.class=class.class))
)
"#;

/// Structural nodes already retain the AST-decoded string at tuple field 16
/// (`StructuralNodeJson`). Join the selected native name site's exact span;
/// never reinterpret source bytes or depend on semantic-IR materialization.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const PATCH_TARGET_LITERAL_SQL: &str = r#"
SELECT node.value->>'$[16]'
FROM python_member_sites site
JOIN source_fact_manifests manifest
 ON manifest.blob_id=site.blob_id AND manifest.publication_state='complete'
JOIN source_structural_facts facts ON facts.blob_id=site.blob_id
CROSS JOIN json_each(facts.nodes) node
WHERE site.blob_id=?1 AND site.site=?2
 AND node.value->>'$[3]'=site.start_byte
 AND node.value->>'$[4]'=site.end_byte
 AND json_type(node.value,'$[16]')='text'
"#;

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn patch_target_literal(
    connection: &rusqlite::Connection,
    blob: i64,
    name_site: u32,
    cancellation: &CancellationToken,
) -> Result<Option<String>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(PATCH_TARGET_LITERAL_SQL)?;
            let mut value = None;
            for row in
                statement.query_map(params![blob, name_site], |row| row.get::<_, String>(0))?
            {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let decoded = row?;
                if let Some(previous) = &value {
                    assert_eq!(previous, &decoded, "one literal span has one decoded value");
                } else {
                    value = Some(decoded);
                }
            }
            Ok(value)
        },
    )
}

fn code<T: PartialEq>(variants: &[T], value: &T) -> i64 {
    variants
        .iter()
        .position(|candidate| candidate == value)
        .expect("known source variant") as i64
}

#[doc(hidden)]
pub fn publish(
    tx: &Transaction<'_>,
    blob: i64,
    facts: &FileResolutionFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let receivers = facts
        .type_transfers
        .iter()
        .filter(|row| row.kind == ResolutionTypeTransferKind::Receiver)
        .map(|row| (row.output, row.input))
        .collect::<crate::hash::HashMap<_, _>>();
    let calls = facts
        .python_super_contexts
        .iter()
        .map(|row| row.call)
        .collect::<crate::hash::HashSet<_>>();
    // Retain the two reader domains plus every python_member_* foreign-key
    // target. This set belongs to this one file's publication transaction.
    let mut retained = crate::hash::HashSet::default();
    retained.extend(facts.type_slots.iter().map(|row| row.site));
    for row in &facts.python_classes {
        retained.insert(row.class);
        retained.extend(row.metaclass_expression);
    }
    retained.extend(
        facts
            .python_base_operands
            .iter()
            .map(|row| row.expression_site),
    );
    retained.extend(
        facts
            .python_class_keywords
            .iter()
            .map(|row| row.expression_site),
    );
    for row in &facts.python_member_roles {
        retained.extend([row.owner, row.member]);
        retained.extend(row.callable);
        retained.extend(row.receiver_parameter);
    }
    for row in &facts.python_decorators {
        retained.extend([row.declaration, row.expression_site]);
    }
    for row in &facts.python_parameters {
        retained.extend([row.callable, row.parameter]);
    }
    retained.extend(facts.python_call_arguments.iter().map(|row| row.call));
    for row in &facts.python_annotations {
        retained.extend([row.owner, row.syntax_site]);
    }
    for row in &facts.python_super_contexts {
        retained.extend([row.call, row.callee]);
        retained.extend(row.callable);
        retained.extend(row.class_cell);
        retained.extend(row.first_parameter);
    }
    retained.extend(facts.python_receiver_writes.iter().map(|row| row.site));
    for row in &facts.python_member_operations {
        // Both coordinates are FK targets, including PatchPath's literal name.
        retained.extend([row.site, row.name_site]);
    }
    for identifier in &facts.identifiers {
        let site = facts.sites[identifier.site.index()];
        if identifier.role == ResolutionIdentifierRole::Reference
            && facts.scopes[site.scope.index()].kind == ResolutionScopeKind::TypeBody
        {
            retained.insert(identifier.site);
        }
        if let Some(input) = identifier.qualifier.and_then(|slot| receivers.get(&slot))
            && calls.contains(&facts.type_slots[input.index()].site)
        {
            retained.insert(identifier.site);
        }
    }
    for (ordinal, row) in facts.sites.iter().enumerate() {
        if !retained.contains(&ResolutionSiteId::new(ordinal as u32)) {
            continue;
        }
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member sites"));
        }
        tx.prepare_cached("INSERT INTO python_member_sites VALUES(?1,?2,?3,?4,?5)")?
            .execute(params![
                blob,
                ordinal as u32,
                row.scope.get(),
                row.start_byte as i64,
                row.end_byte as i64
            ])?;
    }
    for (ordinal, row) in facts.type_slots.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member slots"));
        }
        tx.prepare_cached("INSERT INTO python_member_type_slots VALUES(?1,?2,?3)")?
            .execute(params![blob, ordinal as u32, row.site.get()])?;
    }
    for row in &facts.python_classes {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_classes VALUES(?1,?2,?3,?4)")?
            .execute(params![
                blob,
                row.class.get(),
                row.metaclass_expression.map(|id| id.get()),
                row.bases_complete
            ])?;
    }
    for row in &facts.python_base_operands {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_base_operands VALUES(?1,?2,?3,?4,?5,?6)")?
            .execute(params![
                blob,
                row.class.get(),
                row.ordinal,
                row.expression_site.get(),
                row.slot.get(),
                code(
                    &[PythonNativeBaseKind::Plain, PythonNativeBaseKind::Star],
                    &row.kind
                )
            ])?;
    }
    for row in &facts.python_class_keywords {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_class_keywords VALUES(?1,?2,?3,?4,?5,?6)")?
            .execute(params![
                blob,
                row.class.get(),
                row.ordinal,
                row.expression_site.get(),
                row.value.get(),
                row.name.map(|id| facts.names[id.index()].spelling.as_str())
            ])?;
    }
    for row in &facts.python_member_roles {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_member_roles VALUES(?1,?2,?3,?4,?5,?6)")?
            .execute(params![
                blob,
                row.owner.get(),
                row.member.get(),
                code(
                    &[
                        PythonNativeMemberRole::OrdinaryFunction,
                        PythonNativeMemberRole::ClassMethodCandidate,
                        PythonNativeMemberRole::StaticMethodCandidate,
                        PythonNativeMemberRole::PropertyCandidate,
                        PythonNativeMemberRole::DescriptorCandidate,
                        PythonNativeMemberRole::OrdinaryValue,
                        PythonNativeMemberRole::Unknown
                    ],
                    &row.kind
                ),
                row.callable.map(|id| id.get()),
                row.receiver_parameter.map(|id| id.get())
            ])?;
    }
    for row in &facts.python_decorators {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_decorators VALUES(?1,?2,?3,?4,?5,?6)")?
            .execute(params![
                blob,
                row.declaration.get(),
                row.ordinal,
                row.expression_site.get(),
                row.value_slot.get(),
                code(
                    &[
                        PythonNativeDecoratorRole::Property,
                        PythonNativeDecoratorRole::ClassMethod,
                        PythonNativeDecoratorRole::StaticMethod,
                        PythonNativeDecoratorRole::PropertyGetter,
                        PythonNativeDecoratorRole::PropertySetter,
                        PythonNativeDecoratorRole::PropertyDeleter,
                        PythonNativeDecoratorRole::Other
                    ],
                    &row.role
                )
            ])?;
    }
    for row in &facts.python_parameters {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_parameters VALUES(?1,?2,?3,?4,?5)")?
            .execute(params![
                blob,
                row.callable.get(),
                row.parameter.get(),
                row.ordinal,
                code(
                    &[
                        PythonNativeParameterKind::PositionalOnly,
                        PythonNativeParameterKind::PositionalOrKeyword,
                        PythonNativeParameterKind::KeywordOnly,
                        PythonNativeParameterKind::VarPositional,
                        PythonNativeParameterKind::VarKeyword
                    ],
                    &row.kind
                )
            ])?;
    }
    // The call's Argument slot is anchored at the whole call, not its
    // operand. Retain the expression selected by the producer's Argument
    // transfer so proxy prerequisites can ask for that exact Reference.
    let argument_inputs = facts
        .type_transfers
        .iter()
        .filter(|row| row.kind == ResolutionTypeTransferKind::Argument)
        .map(|row| (row.output, row.input))
        .collect::<crate::hash::HashMap<_, _>>();
    let argument_values = facts
        .call_arguments
        .iter()
        .map(|row| ((row.call, row.ordinal), argument_inputs[&row.value]))
        .collect::<crate::hash::HashMap<_, _>>();
    for row in &facts.python_call_arguments {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_call_arguments VALUES(?1,?2,?3,?4,?5)")?
            .execute(params![
                blob,
                row.call.get(),
                row.ordinal,
                code(
                    &[
                        PythonNativeArgumentKind::Positional,
                        PythonNativeArgumentKind::Keyword,
                        PythonNativeArgumentKind::Star,
                        PythonNativeArgumentKind::DoubleStar
                    ],
                    &row.kind
                ),
                argument_values[&(row.call, row.ordinal)].get(),
            ])?;
    }
    for row in &facts.python_annotations {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_annotations VALUES(?1,?2,?3,?4,?5)")?
            .execute(params![
                blob,
                row.owner.get(),
                row.syntax_site.get(),
                row.type_slot.get(),
                code(
                    &[
                        PythonNativeAnnotationMode::Eager,
                        PythonNativeAnnotationMode::Deferred,
                        PythonNativeAnnotationMode::Quoted
                    ],
                    &row.mode
                )
            ])?;
    }
    for row in &facts.python_super_contexts {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining super context"));
        }
        tx.prepare_cached("INSERT INTO python_member_super_contexts VALUES(?1,?2,?3,?4,?5,?6)")?
            .execute(params![
                blob,
                row.call.get(),
                row.callee.get(),
                row.callable.map(|id| id.get()),
                row.class_cell.map(|id| id.get()),
                row.first_parameter.map(|id| id.get())
            ])?;
    }
    for identifier in &facts.identifiers {
        if cancellation.is_cancelled() {
            return Err(StoreError::new(
                "cancelled retaining structured member receiver",
            ));
        }
        let Some(input) = identifier.qualifier.and_then(|slot| receivers.get(&slot)) else {
            continue;
        };
        let source = facts.type_slots[input.index()].site;
        if calls.contains(&source) {
            tx.prepare_cached("INSERT INTO python_member_super_members VALUES(?1,?2,?3)")?
                .execute(params![blob, source.get(), identifier.site.get()])?;
        }
    }
    for decorator in &facts.python_decorators {
        let Some(receiver) = facts
            .identifiers
            .iter()
            .find(|id| id.site == decorator.expression_site)
            .and_then(|id| id.qualifier)
            .and_then(|slot| receivers.get(&slot))
            .map(|slot| facts.type_slots[slot.index()].site)
        else {
            continue;
        };
        tx.prepare_cached("INSERT INTO python_member_decorator_receivers VALUES(?1,?2,?3,?4)")?
            .execute(params![
                blob,
                decorator.declaration.get(),
                decorator.ordinal,
                receiver.get()
            ])?;
    }
    for row in &facts.python_receiver_writes {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member inputs"));
        }
        tx.prepare_cached("INSERT INTO python_member_receiver_writes VALUES(?1,?2,?3,?4)")?
            .execute(params![
                blob,
                row.site.get(),
                row.receiver.get(),
                row.value.map(|id| id.get())
            ])?;
    }
    for row in &facts.python_member_operations {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("cancelled retaining member operations"));
        }
        let (name_kind, names) = match &row.names {
            PythonMemberNames::Exact(names) => (0, names.as_slice()),
            PythonMemberNames::Prefix(name) => {
                assert!(
                    !facts.names[name.index()].spelling.is_empty(),
                    "empty prefix is Any"
                );
                (1, std::slice::from_ref(name))
            }
            PythonMemberNames::Any => (2, &[][..]),
        };
        tx.prepare_cached("INSERT INTO python_member_operations(blob_id,site,name_site,form,effect,name_kind,callee_reference,receiver_reference,receiver_slot) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")?
            .execute(params![blob, row.site.get(), row.name_site.get(), code(&[
                PythonMemberForm::Getattr, PythonMemberForm::Setattr, PythonMemberForm::Delattr,
                PythonMemberForm::DictWrite, PythonMemberForm::DictUpdate,
                PythonMemberForm::PatchObject, PythonMemberForm::PatchPath,
            ], &row.form), code(&[PythonMemberEffect::Read, PythonMemberEffect::Write, PythonMemberEffect::Delete], &row.effect),
                name_kind, row.callee_reference.map(|id| id.get()), row.receiver_reference.map(|id| id.get()), row.receiver_slot.map(|id| id.get())])?;
        let operation = tx.last_insert_rowid();
        for (ordinal, name) in names.iter().enumerate() {
            tx.prepare_cached("INSERT INTO python_member_operation_names VALUES(?1,?2,?3)")?
                .execute(params![
                    operation,
                    ordinal as i64,
                    facts.names[name.index()].spelling
                ])?;
        }
    }
    Ok(())
}

use super::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::resolution::{
    ClassCreationKind, ImplicitBaseInputs, ImplicitRootObject, ResolutionCompletion,
    ResolutionIncompleteReason, SelectedResolutionMountOrdinal, SelectedTypedRowIdentity,
    SemanticId,
};
use rusqlite::OptionalExtension;

/// This is one selected owner seek, including a real empty operand inventory.
/// The environment is an already selected publication, never the newest row.
#[doc(hidden)]
pub fn implicit_inputs(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    owner: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<ImplicitBaseInputs>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
        return Ok(None);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    if mount.semantic_language() != crate::analyzer::Language::Python {
        return Ok(None);
    }
    let conn = selection.connection();
    let row = conn.prepare_cached(
        "SELECT class.class,class.bases_complete,class.metaclass,
          (SELECT count(*) FROM python_member_base_operands base WHERE base.blob_id=class.blob_id AND base.class=class.class),
          EXISTS(SELECT 1 FROM python_member_base_operands base WHERE base.blob_id=class.blob_id AND base.class=class.class AND base.kind<>0),
          EXISTS(SELECT 1 FROM python_member_class_keywords keyword WHERE keyword.blob_id=class.blob_id AND keyword.class=class.class),
          EXISTS(SELECT 1 FROM python_member_decorators decorator WHERE decorator.blob_id=class.blob_id AND decorator.declaration=class.class)
         FROM resolution_semantic_sites semantic
         JOIN python_member_classes class ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site
         JOIN python_binding_source source ON source.blob_id=class.blob_id AND source.format=?3
         WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'")?
        .query_row(params![mount.blob_id(), key, super::python_binding_rows::NATIVE_SOURCE_FORMAT], |r|
            Ok((r.get::<_,u32>(0)?,r.get::<_,bool>(1)?,r.get::<_,Option<u32>>(2)?,r.get::<_,u32>(3)?,r.get::<_,bool>(4)?,r.get::<_,bool>(5)?,r.get::<_,bool>(6)?)))
        .optional()?;
    let Some((_site, complete, metaclass, count, expanded, keywords, decorated)) = row else {
        return Ok(None);
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let creation = if metaclass.is_some() || keywords {
        ClassCreationKind::Custom
    } else if expanded || !complete || decorated {
        ClassCreationKind::Unknown
    } else {
        ClassCreationKind::Ordinary
    };
    // This reader proves authored creation inputs only. The language hook
    // supplies a version-selected universe root; without that rule the root
    // obligation remains explicit. A configuration digest is not a root.
    let _environment = environment;
    let root_object: Option<ImplicitRootObject> = None;
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let completion = if creation != ClassCreationKind::Ordinary
        || (count == 0 && root_object.is_none())
    {
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(owner)])
    } else {
        ResolutionCompletion::Complete
    };
    Ok(Some(ImplicitBaseInputs {
        written_inventory_complete: complete,
        written_base_count: count,
        creation,
        root_object,
        authority: crate::analyzer::resolution::ImplicitBaseAuthority::Selected(
            SelectedTypedRowIdentity::SelectedSource {
                fragment: mount.fragment_id(),
            },
        ),
        completion,
    }))
}

/// The retained role identifies a direct class-body function and its first
/// positional parameter. Decorator spellings remain observations, never proof.
/// Implicit static/class hooks stay open until their special binding is modeled.
#[doc(hidden)]
pub fn receiver_seed(
    selection: &SelectedResolutionMountInventory<'_>,
    slot: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<crate::analyzer::resolution::ConditionalTypeSeed>> {
    use crate::analyzer::resolution::{
        ConditionalTypeSeed, ResolutionSlotValue, ResolutionTypeRef,
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let (Some(ordinal), Some(key)) = (slot.ordinal(), slot.local_key()) else {
        return Ok(None);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let conn = selection.connection();
    let rows = conn.prepare_cached(
        "SELECT DISTINCT owner.semantic_key,role.member
         FROM resolution_declaration_types declaration
         JOIN resolution_semantic_sites parameter ON parameter.blob_id=declaration.blob_id
           AND parameter.semantic_key=declaration.definition AND parameter.semantic_role='definition'
         JOIN python_member_member_roles role ON role.blob_id=parameter.blob_id AND role.receiver_parameter=parameter.source_site
         JOIN resolution_semantic_sites callable ON callable.blob_id=role.blob_id
           AND callable.source_site=role.member AND callable.semantic_role='definition'
         JOIN resolution_member_owner_properties member ON member.blob_id=callable.blob_id
           AND member.definition_semantic_key=callable.semantic_key
         JOIN python_member_parameters positional ON positional.blob_id=role.blob_id
           AND positional.callable=role.callable AND positional.parameter=role.receiver_parameter AND positional.kind IN (0,1)
         JOIN resolution_semantic_sites owner ON owner.blob_id=role.blob_id
           AND owner.source_site=role.owner AND owner.semantic_role='definition'
         JOIN python_binding_source source ON source.blob_id=declaration.blob_id AND source.format=?3
         WHERE declaration.blob_id=?1 AND declaration.slot=?2 AND declaration.role=?4
           AND member.member_name NOT IN ('__new__','__init_subclass__','__class_getitem__')")?
        .query_map(params![mount.blob_id(),key,super::python_binding_rows::NATIVE_SOURCE_FORMAT,
            code(ALL_DECLARATION_TYPE_ROLES,&DeclarationTypeRole::Parameter)], |r| Ok((r.get::<_,u32>(0)?,r.get::<_,u32>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let [(owner, member)] = rows.as_slice() else {
        return Ok(None);
    };
    let decorators = conn
        .prepare_cached(
            "SELECT decorator.ordinal,semantic.semantic_key FROM python_member_decorators decorator
         LEFT JOIN resolution_semantic_sites semantic ON semantic.blob_id=decorator.blob_id
          AND semantic.source_site=decorator.expression_site AND semantic.semantic_role='reference'
         WHERE decorator.blob_id=?1 AND decorator.declaration=?2 ORDER BY decorator.ordinal",
        )?
        .query_map(params![mount.blob_id(), member], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, Option<u32>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let ty = ResolutionTypeRef::new(SemanticId::local(ordinal, *owner), 0);
    let (value, prerequisites) = match decorators.as_slice() {
        [] => (ResolutionSlotValue::runtime(ty, false), Vec::new()),
        [(_, Some(reference))] => {
            // Only one proven classmethod can transform a function into a
            // class-bound callable. All other/stacked transformations stay open.
            let Some(entry) = crate::analyzer::resolution::universe::lookup(
                crate::analyzer::Language::Python,
                ResolutionNamespace::TypeOrValue,
                "classmethod",
            ) else {
                return Ok(None);
            };
            let identity = SemanticId::shared_name(selection.shared_names().intern(
                crate::analyzer::resolution::universe::identity_digest(entry),
            ));
            (
                ResolutionSlotValue::type_object(ty),
                vec![(SemanticId::local(ordinal, *reference), identity)],
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(ConditionalTypeSeed {
        slot,
        value: value.with_receiver_subclass_obligation(),
        prerequisites,
    }))
}
