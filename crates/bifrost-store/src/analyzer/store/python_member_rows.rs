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
pub(crate) const UNIVERSE_REFERENCE_NAME_SQL: &str = "SELECT name.spelling,site.source_site FROM resolution_semantic_sites site JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=site.blob_id AND lookup.semantic_key=site.semantic_key JOIN resolution_identities name ON name.id=lookup.identity_id WHERE site.blob_id=?1 AND site.semantic_key=?2 AND site.semantic_role='reference'";

/// Retained lexical hazards and a structurally selected class namespace.
/// Neither is a second authority for builtin-module mutation operations.
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
 WHERE site.blob_id=?1 AND site.site=?2 AND (?4 IS NULL OR definition.semantic_key<>?4)
 AND (class.metaclass IS NOT NULL OR class.bases_complete=0
 OR EXISTS(SELECT 1 FROM python_member_base_operands base WHERE base.blob_id=class.blob_id AND base.class=class.class)
 OR EXISTS(SELECT 1 FROM python_member_class_keywords keyword WHERE keyword.blob_id=class.blob_id AND keyword.class=class.class))
)
"#;

/// Structural nodes already retain the AST-decoded string at tuple field 16
/// (`StructuralNodeJson`). Join the selected native name site's exact span;
/// never reinterpret source bytes or depend on semantic-IR materialization.
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

pub(crate) fn decorator_role_code(role: PythonNativeDecoratorRole) -> i64 {
    code(
        &[
            PythonNativeDecoratorRole::Property,
            PythonNativeDecoratorRole::ClassMethod,
            PythonNativeDecoratorRole::StaticMethod,
            PythonNativeDecoratorRole::PropertyGetter,
            PythonNativeDecoratorRole::PropertySetter,
            PythonNativeDecoratorRole::PropertyDeleter,
            PythonNativeDecoratorRole::Other,
        ],
        &role,
    )
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
    let sites = facts
        .sites
        .iter()
        .enumerate()
        .filter(|(ordinal, _)| retained.contains(&ResolutionSiteId::new(*ordinal as u32)))
        .map(|(ordinal, row)| {
            (
                blob,
                ordinal as u32,
                row.scope.get(),
                row.start_byte as i64,
                row.end_byte as i64,
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_sites VALUES",
        "(?,?,?,?,?)",
        &sites,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member sites"));
    }
    let slots = facts
        .type_slots
        .iter()
        .enumerate()
        .map(|(ordinal, row)| (blob, ordinal as u32, row.site.get()))
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_type_slots VALUES",
        "(?,?,?)",
        &slots,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member slots"));
    }
    let batch = facts
        .python_classes
        .iter()
        .map(|row| {
            (
                blob,
                row.class.get(),
                row.metaclass_expression.map(|id| id.get()),
                row.bases_complete,
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_classes VALUES",
        "(?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_base_operands
        .iter()
        .map(|row| {
            (
                blob,
                row.class.get(),
                row.ordinal,
                row.expression_site.get(),
                row.slot.get(),
                code(
                    &[PythonNativeBaseKind::Plain, PythonNativeBaseKind::Star],
                    &row.kind,
                ),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_base_operands VALUES",
        "(?,?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_class_keywords
        .iter()
        .map(|row| {
            (
                blob,
                row.class.get(),
                row.ordinal,
                row.expression_site.get(),
                row.value.get(),
                row.name.map(|id| facts.names[id.index()].spelling.as_str()),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_class_keywords VALUES",
        "(?,?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_member_roles
        .iter()
        .map(|row| {
            (
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
                        PythonNativeMemberRole::Unknown,
                    ],
                    &row.kind,
                ),
                row.callable.map(|id| id.get()),
                row.receiver_parameter.map(|id| id.get()),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_member_roles VALUES",
        "(?,?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_decorators
        .iter()
        .map(|row| {
            (
                blob,
                row.declaration.get(),
                row.ordinal,
                row.expression_site.get(),
                row.value_slot.get(),
                decorator_role_code(row.role),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_decorators VALUES",
        "(?,?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_parameters
        .iter()
        .map(|row| {
            (
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
                        PythonNativeParameterKind::VarKeyword,
                    ],
                    &row.kind,
                ),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_parameters VALUES",
        "(?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
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
    let batch = facts
        .python_call_arguments
        .iter()
        .map(|row| {
            (
                blob,
                row.call.get(),
                row.ordinal,
                code(
                    &[
                        PythonNativeArgumentKind::Positional,
                        PythonNativeArgumentKind::Keyword,
                        PythonNativeArgumentKind::Star,
                        PythonNativeArgumentKind::DoubleStar,
                    ],
                    &row.kind,
                ),
                argument_values[&(row.call, row.ordinal)].get(),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_call_arguments VALUES",
        "(?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_annotations
        .iter()
        .map(|row| {
            (
                blob,
                row.owner.get(),
                row.syntax_site.get(),
                row.type_slot.get(),
                code(
                    &[
                        PythonNativeAnnotationMode::Eager,
                        PythonNativeAnnotationMode::Deferred,
                        PythonNativeAnnotationMode::Quoted,
                    ],
                    &row.mode,
                ),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_annotations VALUES",
        "(?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_super_contexts
        .iter()
        .map(|row| {
            (
                blob,
                row.call.get(),
                row.callee.get(),
                row.callable.map(|id| id.get()),
                row.class_cell.map(|id| id.get()),
                row.first_parameter.map(|id| id.get()),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_super_contexts VALUES",
        "(?,?,?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining super context"));
    }
    let super_members = facts
        .identifiers
        .iter()
        .filter_map(|identifier| {
            let input = identifier.qualifier.and_then(|slot| receivers.get(&slot))?;
            let source = facts.type_slots[input.index()].site;
            calls
                .contains(&source)
                .then_some((blob, source.get(), identifier.site.get()))
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_super_members VALUES",
        "(?,?,?)",
        &super_members,
        cancellation,
    )? {
        return Err(StoreError::new(
            "cancelled retaining structured member receiver",
        ));
    }
    let decorator_receivers = facts
        .python_decorators
        .iter()
        .filter_map(|decorator| {
            let receiver = facts
                .identifiers
                .iter()
                .find(|id| id.site == decorator.expression_site)
                .and_then(|id| id.qualifier)
                .and_then(|slot| receivers.get(&slot))
                .map(|slot| facts.type_slots[slot.index()].site)?;
            Some((
                blob,
                decorator.declaration.get(),
                decorator.ordinal,
                receiver.get(),
            ))
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_decorator_receivers VALUES",
        "(?,?,?,?)",
        &decorator_receivers,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    let batch = facts
        .python_receiver_writes
        .iter()
        .map(|row| {
            (
                blob,
                row.site.get(),
                row.receiver.get(),
                row.value.map(|id| id.get()),
            )
        })
        .collect::<Vec<_>>();
    if !super::row_batch::insert_typed_rows(
        tx,
        "INSERT INTO python_member_receiver_writes VALUES",
        "(?,?,?,?)",
        &batch,
        cancellation,
    )? {
        return Err(StoreError::new("cancelled retaining member inputs"));
    }
    // Operation names need each generated operation ID from last_insert_rowid.
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

/// The authored root reference and its structurally selected optional member.
#[derive(Debug)]
pub(crate) struct PythonImportReference<'a> {
    pub(crate) blob: i64,
    pub(crate) path: &'a str,
    pub(crate) site: u32,
    pub(crate) spelling: &'a str,
    pub(crate) member: Option<&'a str>,
    pub(crate) ordinary_class_namespace: Option<SemanticId>,
}

/// Prove an exact imported module/member spelling in the selected environment.
/// Callers supply matching binding rows and keep the mutation memo query-local.
/// This admits identity only; each consumer owns its intrinsic/semantic table.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admitted_python_import_member(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    rows: &super::python_binding_rows::PythonBindingRows,
    profile: super::resolution_operation::python_lexical::PythonBindingProfile,
    reference: PythonImportReference<'_>,
    session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    cancellation: &CancellationToken,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<Option<(String, String)>> {
    use super::resolution_operation::python_lexical::{self, PythonBindingProofs};
    use crate::analyzer::resolution::temporal_binding::SessionBudget;
    let PythonImportReference {
        blob,
        path,
        site,
        spelling,
        member,
        ordinary_class_namespace,
    } = reference;
    let conn = selection.connection();
    let Some(mut state) = python_lexical::lexical_selection(
        rows,
        site,
        spelling,
        profile,
        PythonBindingProofs::default(),
    ) else {
        return Ok(None);
    };
    let mut budget = SessionBudget {
        session,
        cancellation,
    };
    python_lexical::select_lexical(&mut state, rows, &mut budget, cancellation)?;
    let [selected] = state.selection.selected.as_slice() else {
        return Ok(None);
    };
    let Some(event) = rows
        .events
        .iter()
        .find(|event| event.event == selected.occurrence)
    else {
        return Ok(None);
    };
    let Some(slot) = rows.slots.iter().find(|slot| slot.slot == event.slot) else {
        return Ok(None);
    };
    if !state.selected_import_identity_is_unique(rows, slot.scope, event.event) {
        return Ok(None);
    }
    let Some(import) = rows
        .imports
        .iter()
        .find(|import| import.binding_event == Some(event.event))
    else {
        return Ok(None);
    };
    if !python_lexical::unconditional_import(rows, import.import_site.get()) {
        return Ok(None);
    }
    let imports = conn.prepare_cached(
                        "SELECT DISTINCT imported.module_name,imported.requested_name,imported.form,imported.relative_level,
                          imported.importer_container,imported.target_container,
                          EXISTS(SELECT 1 FROM python_unit_summary_providers provider
                           WHERE provider.summary_id=imported.summary_id AND provider.container_path=imported.target_container
                            AND provider.state IN ('selected','alternative') AND (provider.member_ordinal IS NOT NULL OR provider.kind='namespace'))
                         FROM python_unit_summary_imports imported
                         JOIN resolution_unit_summary_members source ON source.summary_id=imported.summary_id AND source.member_ordinal=imported.member_ordinal
                         WHERE imported.summary_id=?1 AND source.blob_id=?2 AND imported.import_site=?3 AND source.rel_path=?4",
                    )?.query_map(params![environment, blob, import.import_site.get(), path], |row|
                        Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,u32>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,bool>(6)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
    let [(module, requested, form, 0, importer, provider, false)] = imports.as_slice() else {
        return Ok(None);
    };
    let member = match (form.as_str(), member) {
        ("from", None) => requested.as_str(),
        ("module", Some(member)) => member,
        _ => return Ok(None),
    };
    let origin = super::resolution_prepare::resolution_rows::gap_origin_code(
        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnsupportedRoute,
        ),
    );
    let namespace_closed: bool = conn
        .prepare_cached(BUILTIN_NAMESPACE_CLOSED_SQL)?
        .query_row(
            params![
                blob,
                site,
                origin,
                ordinary_class_namespace.and_then(SemanticId::local_key)
            ],
            |row| row.get(0),
        )?;
    if !namespace_closed {
        return Ok(None);
    }
    if !mutations.preserves_import(importer, spelling, provider, member)? {
        return Ok(None);
    }
    Ok(Some((module.clone(), member.to_owned())))
}

/// Resolve only retained decorator syntax and the native temporal import binder.
/// No source spelling alone proves standard-library authority.
/// Resolve a structurally selected name, attribute or call to its admitted import identity.
#[allow(clippy::too_many_arguments)]
fn expression_import_identity(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    blob: i64,
    path: &str,
    expression_site: u32,
    rows: &super::python_binding_rows::PythonBindingRows,
    cancellation: &CancellationToken,
    ordinary_class_namespace: Option<SemanticId>,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<(Option<(String, String)>, String)> {
    use crate::analyzer::store::resolution_operation::python_lexical::PythonBindingProfile;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    let conn = selection.connection();
    let profile: String = conn
        .prepare_cached(
            "SELECT observation FROM python_unit_summary_roots WHERE summary_id=?1 LIMIT 1",
        )?
        .query_row([environment], |row| row.get(0))?;
    let profile = match profile.as_str() {
        "runtime" => PythonBindingProfile::Runtime,
        "typing" => PythonBindingProfile::Typing,
        _ => return Err(StoreError::corrupt("invalid Python decorator observation")),
    };
    let session = ResolutionSession::unbounded();
    // A call decorator is classified by its AST-produced callee, not its
    // result. Ordinary name and attribute decorators already name a reference.
    let call =
        crate::analyzer::resolution::call_semantic_identity(ResolutionSiteId::new(expression_site))
            .fragment_local_digest();
    let reference = conn.prepare_cached(
            "SELECT semantic.semantic_key,semantic.source_site,name.spelling
             FROM resolution_semantic_sites semantic
             JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id AND lookup.semantic_key=semantic.semantic_key
             JOIN resolution_identities name ON name.id=lookup.identity_id
             WHERE semantic.blob_id=?1 AND semantic.semantic_role='reference' AND
               (semantic.source_site=?2 OR semantic.semantic_key IN (
                 SELECT obligation.callee_reference FROM resolution_semantic_catalog call
                 JOIN resolution_call_obligations obligation ON obligation.blob_id=call.blob_id AND obligation.call=call.local_key
                 WHERE call.blob_id=?1 AND call.identity_digest=?3))
             ORDER BY semantic.semantic_key",
        )?.query_map(params![blob, expression_site, call.as_slice()], |row|
            Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?,row.get::<_,String>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut identity = None;
    let mut spelling = String::from("<unknown>");
    if let [(reference, reference_site, terminal)] = reference.as_slice() {
        // The AST qualifier is a receiver transfer from its prefix expression.
        let prefixes = conn.prepare_cached(
                "SELECT DISTINCT prefix.source_site,name.spelling
                 FROM resolution_qualified_routes route
                 JOIN resolution_binding_projections projection ON projection.blob_id=route.blob_id
                  AND (projection.output_slot=route.qualifier_slot OR projection.output_slot IN (
                    SELECT source_slot FROM resolution_type_transfers transfer
                    WHERE transfer.blob_id=route.blob_id AND transfer.target_slot=route.qualifier_slot))
                 JOIN resolution_semantic_sites prefix ON prefix.blob_id=projection.blob_id AND prefix.semantic_key=projection.reference AND prefix.semantic_role='reference'
                 JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=prefix.blob_id AND lookup.semantic_key=prefix.semantic_key
                 JOIN resolution_identities name ON name.id=lookup.identity_id
                 WHERE route.blob_id=?1 AND route.reference=?2",
            )?.query_map(params![blob, reference], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        let root = match prefixes.as_slice() {
            [] => Some((*reference_site, terminal.as_str(), None)),
            [(site, name)] => Some((*site, name.as_str(), Some(terminal.as_str()))),
            _ => None,
        };
        spelling = match root {
            Some((_, name, Some(member))) => format!("{name}.{member}"),
            _ => terminal.clone(),
        };
        if let Some((site, name, member)) = root {
            identity = admitted_python_import_member(
                selection,
                environment,
                rows,
                profile,
                PythonImportReference {
                    blob,
                    path,
                    site,
                    spelling: name,
                    member,
                    ordinary_class_namespace,
                },
                &session,
                cancellation,
                mutations,
            )?;
        }
    }
    Ok((identity, spelling))
}

#[allow(clippy::too_many_arguments)]
fn class_decorator_completion(
    selection: &SelectedResolutionMountInventory<'_>,
    identities: &crate::analyzer::resolution::SelectedContextIdentities,
    environment: i64,
    blob: i64,
    class_site: u32,
    path: &str,
    cancellation: &CancellationToken,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<Option<ResolutionCompletion>> {
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

    let conn = selection.connection();
    let decorators = conn
        .prepare_cached(
            "SELECT expression_site FROM python_member_decorators
         WHERE blob_id=?1 AND declaration=?2 ORDER BY ordinal",
        )?
        .query_map(params![blob, class_site], |row| row.get::<_, u32>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if decorators.is_empty() {
        return Ok(Some(ResolutionCompletion::Complete));
    }
    let Some(rows) = super::python_binding_rows::PythonBindingRows::read(conn, blob, cancellation)?
    else {
        return Ok(None);
    };
    let mut completion = ResolutionCompletion::Complete;
    for expression_site in decorators {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (identity, spelling) = expression_import_identity(
            selection,
            environment,
            blob,
            path,
            expression_site,
            &rows,
            cancellation,
            None,
            mutations,
        )?;
        let admitted = identity.as_ref().is_some_and(|(module, member)| {
            brokk_bifrost_python::intrinsics::MEMBER_PRESERVING_CLASS_DECORATORS
                .contains(&(module.as_str(), member.as_str()))
        });
        if !admitted {
            // #7979: workspace decorators preserve candidates without a member-preservation proof.
            let kind = "python_class_decorator_unproven";
            let label = format!("{kind}:{path}#class={class_site}:{spelling}");
            let mut hash = CanonicalHasher::new(b"python-class-decorator-unproven:v1");
            hash.field("subject", label.as_bytes());
            let reason = identities.named_semantic(hash.finish(), kind, &label);
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
    }
    Ok((!cancellation.is_cancelled()).then_some(completion))
}

/// This is one selected owner seek, including a real empty operand inventory.
/// The environment is an already selected publication, never the newest row.
#[doc(hidden)]
pub fn implicit_inputs(
    selection: &SelectedResolutionMountInventory<'_>,
    identities: &crate::analyzer::resolution::SelectedContextIdentities,
    environment: i64,
    owner: SemanticId,
    cancellation: &CancellationToken,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
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
    let Some((site, complete, metaclass, count, expanded, keywords, decorated)) = row else {
        return Ok(None);
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let creation = if metaclass.is_some() || keywords {
        ClassCreationKind::Custom
    } else if expanded || !complete {
        ClassCreationKind::Unknown
    } else {
        ClassCreationKind::Ordinary
    };
    // This reader proves authored creation inputs only. The language hook
    // supplies a version-selected universe root; without that rule the root
    // obligation remains explicit. A configuration digest is not a root.
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
    let completion = if decorated {
        let decorator_completion = class_decorator_completion(
            selection,
            identities,
            environment,
            mount.blob_id(),
            site,
            mount.persisted_relative_path(),
            cancellation,
            mutations,
        )?;
        let Some(decorator_completion) = decorator_completion else {
            return Ok(None);
        };
        completion.combine(&decorator_completion)
    } else {
        completion
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }
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
    let memo_key = (mount.blob_id(), key);
    let cached = selection
        .python_receiver_rows
        .borrow()
        .get(&memo_key)
        .cloned();
    let rows = if let Some(rows) = cached {
        rows
    } else {
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
        assert!(
            selection
                .python_receiver_rows
                .borrow_mut()
                .insert(memo_key, rows.clone())
                .is_none()
        );
        rows
    };
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
    // An unchanged first parameter of an unreplaced method denotes its owner.
    // Alternative ordinary definitions retain that identity. A value
    // replacement or another decorated definition can change argument binding;
    // the method's own decorator is judged by the match below.
    let unchanged: bool = conn
        .prepare_cached(
            "SELECT COUNT(*)=1 AND
                   EXISTS(SELECT 1 FROM resolution_binding_events def
                    WHERE def.blob_id=?1 AND def.authored=?3 AND def.kind=6)
                   AND NOT EXISTS(SELECT 1 FROM resolution_binding_events writes
                    WHERE writes.blob_id=?1 AND writes.kind<>4 AND writes.slot=(
                      SELECT def.slot FROM resolution_binding_events def
                      WHERE def.blob_id=?1 AND def.authored=?3 AND def.kind=6 LIMIT 1)
                    AND (writes.kind<>6 OR writes.authored IS NULL OR EXISTS(
                      SELECT 1 FROM python_member_decorators decorator
                      WHERE decorator.blob_id=writes.blob_id
                       AND decorator.declaration=writes.authored
                       AND writes.authored<>?3)))
                 FROM resolution_binding_events e
                 WHERE e.blob_id=?1 AND e.kind<>4 AND e.slot=(
                   SELECT parameter.slot FROM resolution_binding_events parameter
                   JOIN resolution_declaration_types d ON d.blob_id=parameter.blob_id
                   JOIN resolution_semantic_sites site ON site.blob_id=d.blob_id
                    AND site.semantic_key=d.definition AND site.semantic_role='definition'
                   WHERE d.blob_id=?1 AND d.slot=?2 AND parameter.authored=site.source_site
                    AND parameter.kind=0 AND EXISTS (
                      SELECT 1 FROM resolution_binding_slots slot
                      WHERE slot.blob_id=parameter.blob_id AND slot.slot=parameter.slot
                       ) LIMIT 1)",
        )?
        .query_row(params![mount.blob_id(), key, *member], |row| row.get(0))?;
    let (value, prerequisites, discharged_gap_reasons) = match decorators.as_slice() {
        [] => {
            let value = ResolutionSlotValue::runtime(ty, false);
            (
                if unchanged {
                    value
                } else {
                    value.with_receiver_subclass_obligation()
                },
                Vec::new(),
                Vec::new(),
            )
        }
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
            // The seed supersedes only this parameter's own unannotated-parameter
            // gap. The shared activation removes it in the step that applies the
            // seed, so a failed decorator proof keeps the gap.
            let discharged_gap_reasons = if unchanged {
                let origin = super::resolution_prepare::resolution_rows::gap_origin_code(
                    crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedExpressionType,
                    ),
                );
                conn
                    .prepare_cached(
                    "SELECT DISTINCT reason.reason FROM resolution_gap_reasons reason
                     JOIN resolution_declaration_types declaration ON declaration.blob_id=reason.blob_id
                     JOIN resolution_semantic_sites parameter ON parameter.blob_id=declaration.blob_id
                      AND parameter.semantic_key=declaration.definition AND parameter.semantic_role='definition'
                     WHERE declaration.blob_id=?1 AND declaration.slot=?2 AND declaration.role=?3
                      AND reason.site=parameter.source_site AND reason.origin=?4",
                    )?
                    .query_map(
                        params![
                            mount.blob_id(),
                            key,
                            code(ALL_DECLARATION_TYPE_ROLES, &DeclarationTypeRole::Parameter),
                            origin
                        ],
                        |row| Ok(SemanticId::local(ordinal, row.get::<_, u32>(0)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            (
                ResolutionSlotValue::type_object(ty).with_receiver_subclass_obligation(),
                vec![(SemanticId::local(ordinal, *reference), identity)],
                discharged_gap_reasons,
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(ConditionalTypeSeed {
        slot,
        value,
        prerequisites,
        discharged_gap_reasons,
    }))
}

/// No initializer is synthesized when the class body already owns __init__.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DataclassKeywordInitializer {
    Ordinary,
    Fields,
    Open,
}

/// Only literal init options close synthesis. The selected call and argument
/// rows supply syntax; the structural publication supplies the decoded boolean.
fn dataclass_init_option(
    selection: &SelectedResolutionMountInventory<'_>,
    blob: i64,
    expression: u32,
) -> Result<Option<bool>> {
    let conn = selection.connection();
    let args = conn.prepare_cached(
        "SELECT argument.kind, label.label, site.start_byte, site.end_byte
         FROM python_member_call_arguments argument
         JOIN python_member_type_slots slot ON slot.blob_id=argument.blob_id AND slot.slot=argument.value
         JOIN python_member_sites site ON site.blob_id=slot.blob_id AND site.site=slot.site
         LEFT JOIN resolution_call_arguments label ON label.blob_id=argument.blob_id
           AND label.call_site=argument.call AND label.ordinal=argument.ordinal
         WHERE argument.blob_id=?1 AND argument.call=?2 ORDER BY argument.ordinal",
    )?.query_map(params![blob,expression], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,u32>(2)?,row.get::<_,u32>(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut enabled = true;
    for (kind, name, start, end) in args {
        if kind != 1 {
            return Ok(None);
        }
        if name.as_deref() != Some("init") {
            continue;
        }
        let values = conn
            .prepare_cached(
                "SELECT node.value->>'$[1]' FROM source_structural_facts facts
             CROSS JOIN json_each(facts.nodes) node
             WHERE facts.blob_id=?1 AND node.value->>'$[3]'=?2 AND node.value->>'$[4]'=?3
               AND json_type(node.value,'$[1]')='integer'",
            )?
            .query_map(params![blob, start, end], |row| row.get::<_, bool>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let [value] = values.as_slice() else {
            return Ok(None);
        };
        enabled = *value;
    }
    Ok(Some(enabled))
}

pub(crate) fn dataclass_keyword_initializer(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    owner: SemanticId,
    rows: &super::python_binding_rows::PythonBindingRows,
    cancellation: &CancellationToken,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<DataclassKeywordInitializer> {
    let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
        return Ok(DataclassKeywordInitializer::Ordinary);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let conn = selection.connection();
    let explicit: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM resolution_member_owner_properties
         WHERE blob_id=?1 AND owner_definition_semantic_key=?2 AND member_name='__init__')",
        )?
        .query_row(params![mount.blob_id(), key], |row| row.get(0))?;
    if explicit {
        return Ok(DataclassKeywordInitializer::Ordinary);
    }
    let Some(expression) = admitted_dataclass_expression(
        selection,
        environment,
        owner,
        rows,
        cancellation,
        mutations,
    )?
    else {
        return Ok(DataclassKeywordInitializer::Ordinary);
    };
    Ok(
        match dataclass_init_option(selection, mount.blob_id(), expression)? {
            Some(true) => DataclassKeywordInitializer::Fields,
            Some(false) => DataclassKeywordInitializer::Ordinary,
            None => DataclassKeywordInitializer::Open,
        },
    )
}

pub(crate) fn admitted_dataclass_expression(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    owner: SemanticId,
    rows: &super::python_binding_rows::PythonBindingRows,
    cancellation: &CancellationToken,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<Option<u32>> {
    let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
        return Ok(None);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let conn = selection.connection();
    let decorators = conn.prepare_cached(
        "SELECT decorator.expression_site FROM resolution_semantic_sites owner
         JOIN python_member_decorators decorator ON decorator.blob_id=owner.blob_id AND decorator.declaration=owner.source_site
         WHERE owner.blob_id=?1 AND owner.semantic_key=?2 AND owner.semantic_role='definition' ORDER BY decorator.ordinal",
    )?.query_map(params![mount.blob_id(),key], |row| row.get::<_,u32>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for expression in decorators {
        let (identity, _) = expression_import_identity(
            selection,
            environment,
            mount.blob_id(),
            mount.persisted_relative_path(),
            expression,
            rows,
            cancellation,
            None,
            mutations,
        )?;
        if identity
            .as_ref()
            .is_some_and(|(module, name)| module == "dataclasses" && name == "dataclass")
        {
            return Ok(Some(expression));
        }
    }
    Ok(None)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DataclassAnnotationIdentity {
    Builtin,
    SourceClass,
    Unknown,
}

/// A selected C3 declaration must have a retained annotation. Generic heads
/// use their structured identity reference; an unreadable head remains open.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dataclass_keyword_field(
    selection: &SelectedResolutionMountInventory<'_>,
    environment: i64,
    field: SemanticId,
    constructor: SemanticId,
    rows: &super::python_binding_rows::PythonBindingRows,
    cancellation: &CancellationToken,
    resolve_annotation: &mut dyn FnMut(SemanticId) -> Result<DataclassAnnotationIdentity>,
    mutations: &super::resolution_operation::PythonMutationQuery<'_, '_>,
) -> Result<Option<bool>> {
    let (Some(ordinal), Some(key)) = (field.ordinal(), field.local_key()) else {
        return Ok(None);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let conn = selection.connection();
    let owner: Option<u32> = conn.prepare_cached("SELECT owner_definition_semantic_key FROM resolution_member_owner_properties WHERE blob_id=?1 AND definition_semantic_key=?2")?.query_row(
        params![mount.blob_id(),key], |row| row.get(0),
    ).optional()?;
    let Some(owner) = owner else {
        return Ok(None);
    };
    let owner = SemanticId::local(ordinal, owner);
    if owner != constructor
        && admitted_dataclass_expression(
            selection,
            environment,
            owner,
            rows,
            cancellation,
            mutations,
        )?
        .is_none()
    {
        return Ok(None);
    }
    let annotations = conn.prepare_cached(
        "SELECT annotation.syntax_site, slot.site FROM resolution_semantic_sites field
         JOIN python_member_annotations annotation ON annotation.blob_id=field.blob_id AND annotation.owner=field.source_site
         JOIN python_member_type_slots slot ON slot.blob_id=annotation.blob_id AND slot.slot=annotation.type_slot
         WHERE field.blob_id=?1 AND field.semantic_key=?2 AND field.semantic_role='definition'",
    )?.query_map(params![mount.blob_id(),key], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (annotation, value_site) = match annotations.as_slice() {
        [] => return Ok(Some(false)),
        [annotation] => *annotation,
        _ => return Ok(None),
    };
    let reference: Option<u32> = conn.prepare_cached("SELECT semantic_key FROM resolution_semantic_sites WHERE blob_id=?1 AND source_site=?2 AND semantic_role='reference'")?.query_row(
        params![mount.blob_id(),annotation], |row| row.get(0),
    ).optional()?;
    let Some(reference) = reference else {
        return Ok(None);
    };
    let (identity, _) = expression_import_identity(
        selection,
        environment,
        mount.blob_id(),
        mount.persisted_relative_path(),
        annotation,
        rows,
        cancellation,
        Some(owner),
        mutations,
    )?;
    if identity
        .as_ref()
        .is_some_and(|(module, name)| module == "typing" && name == "ClassVar")
    {
        return Ok(Some(false));
    }
    let init_var = identity
        .as_ref()
        .is_some_and(|(module, name)| module == "dataclasses" && name == "InitVar");
    if !init_var {
        let identity = resolve_annotation(SemanticId::local(ordinal, reference))?;
        if identity == DataclassAnnotationIdentity::Unknown
            || (annotation != value_site && identity != DataclassAnnotationIdentity::Builtin)
        {
            // A user-defined __class_getitem__ can return ClassVar. Knowing
            // its head names a source class does not prove the annotation value.
            return Ok(None);
        }
    }
    // InitVar is intentionally accepted as a parameter declaration, without
    // claiming that it has instance storage. No value flow is changed here.
    let initializers = conn.prepare_cached(
        "SELECT slot.site FROM resolution_semantic_sites field
         JOIN resolution_binding_events event ON event.blob_id=field.blob_id AND event.authored=field.source_site
         JOIN python_member_type_slots slot ON slot.blob_id=event.blob_id AND slot.slot=event.value_slot
         WHERE field.blob_id=?1 AND field.semantic_key=?2 AND field.semantic_role='definition'",
    )?.query_map(params![mount.blob_id(),key], |row| row.get::<_,u32>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for expression in initializers {
        let (identity, _) = expression_import_identity(
            selection,
            environment,
            mount.blob_id(),
            mount.persisted_relative_path(),
            expression,
            rows,
            cancellation,
            Some(owner),
            mutations,
        )?;
        if identity
            .as_ref()
            .is_some_and(|(module, name)| module == "dataclasses" && name == "field")
        {
            return dataclass_init_option(selection, mount.blob_id(), expression);
        }
        // A factory or variable can hide a Field(init=False). Literal defaults
        // cannot be Field objects; other unreadable values remain explicit open.
        use brokk_bifrost_core::analyzer::structural::{
            code::VocabularyCode, kinds::NormalizedKind,
        };
        let kinds = conn
            .prepare_cached(
                "SELECT node.value->>'$[0]' FROM python_member_sites site
             JOIN source_structural_facts facts ON facts.blob_id=site.blob_id
             CROSS JOIN json_each(facts.nodes) node
             WHERE site.blob_id=?1 AND site.site=?2
               AND node.value->>'$[3]'=site.start_byte AND node.value->>'$[4]'=site.end_byte",
            )?
            .query_map(params![mount.blob_id(), expression], |row| {
                row.get::<_, u8>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !kinds
            .into_iter()
            .filter_map(NormalizedKind::from_code)
            .any(|kind| {
                matches!(
                    kind,
                    NormalizedKind::StringLiteral
                        | NormalizedKind::NumericLiteral
                        | NormalizedKind::BooleanLiteral
                        | NormalizedKind::NullLiteral
                        | NormalizedKind::CollectionLiteral
                        | NormalizedKind::TupleLiteral
                        | NormalizedKind::ListLiteral
                )
            })
        {
            return Ok(None);
        }
    }
    Ok(Some(true))
}
