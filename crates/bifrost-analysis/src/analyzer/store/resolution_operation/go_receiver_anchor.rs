//! Keyed Go receiver anchors shared by point and reverse resolution.

use super::*;
use crate::analyzer::resolution::{ResolutionSlotValue, ResolutionTypeRef};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoReceiverAnchorRole {
    FieldType,
    BindingValue,
    BindingParameter,
    CallableResult,
}

impl GoReceiverAnchorRole {
    const fn persisted(self) -> i64 {
        match self {
            Self::FieldType | Self::BindingValue => 0,
            Self::BindingParameter => 1,
            // The callable's first result: DeclarationTypeRole::CallableFirstResult,
            // the enum's last index in ALL_DECLARATION_TYPE_ROLES.
            Self::CallableResult => 5,
        }
    }
}

/// A selected Go field or concrete callable whose declared type anchors a
/// receiver. The declaration is already selected in its owning blob; callers
/// can share the following keyed declared-type/member reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoReceiverTypeAnchor {
    pub(crate) mount: SelectedResolutionMountOrdinal,
    pub(crate) definition: SemanticId,
    pub(crate) role: GoReceiverAnchorRole,
    pub(crate) member_name: String,
}

impl GoReceiverTypeAnchor {
    pub(crate) fn field_type(member: SemanticId, member_name: String) -> Self {
        let mount = SelectedResolutionMountOrdinal::new(
            member
                .ordinal()
                .expect("a selected Go member has a mount ordinal"),
        );
        Self {
            mount,
            definition: member,
            role: GoReceiverAnchorRole::FieldType,
            member_name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GoReceiverReferenceBinding {
    pub(crate) reference: SemanticId,
    pub(crate) definition: SemanticId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoReceiverAnchorTypes {
    pub(crate) receiver_type: ResolutionTypeRef,
    pub(crate) reference_bindings: Box<[GoReceiverReferenceBinding]>,
    pub(crate) typed_slots: Box<[(SemanticId, ResolutionSlotValue)]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoReceiverAnchorMember {
    Known {
        receiver_type: ResolutionTypeRef,
        member: SemanticId,
        member_result_type: Option<ResolutionTypeRef>,
        reference_bindings: Box<[GoReceiverReferenceBinding]>,
        typed_slots: Box<[(SemanticId, ResolutionSlotValue)]>,
    },
    Unknown,
}

const GO_POINT_NULL_RECEIVER_FRONTIER: &str = r#"
SELECT DISTINCT obligation.receiver_slot
FROM temp.selected_resolution_mounts mounted
JOIN main.go_context_source_files selected_file
  ON selected_file.file_version_id=mounted.file_version_id AND selected_file.context_id=?4
JOIN main.resolution_sites site
  ON site.blob_id=mounted.blob_id AND site.start_byte=?2 AND site.end_byte=?3
 AND site.receiver_origin IS NOT NULL
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=site.blob_id AND semantic.source_site=site.site
 AND semantic.semantic_role='reference'
JOIN main.resolution_call_obligations obligation
  ON obligation.blob_id=semantic.blob_id
 AND obligation.callee_reference=semantic.semantic_key
JOIN main.resolution_type_frontiers frontier
  ON frontier.blob_id=obligation.blob_id AND frontier.slot=obligation.receiver_slot
WHERE mounted.mount_ordinal=?1 AND frontier.identity_reference IS NULL
"#;

const GO_POINT_RECEIVER_ANCHOR: &str = r#"
WITH RECURSIVE package_files(mount_ordinal,blob_id) AS (
  SELECT mounted.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
    AND mounted.mount_ordinal<>?4
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
  UNION
  SELECT placed.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3) AND placed.mount_ordinal<>?4
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
), callable_receiver_types(mount_ordinal,blob_id,declaration_id,type_id) AS (
  SELECT peer.mount_ordinal,peer.blob_id,callable.declaration_id,callable.receiver_type_id
  FROM package_files peer
  JOIN main.source_go_callables callable ON callable.blob_id=peer.blob_id
  WHERE ?5=1 AND callable.name=?7 AND callable.is_method=1
    AND callable.receiver_type_id IS NOT NULL
  UNION
  SELECT receiver.mount_ordinal,receiver.blob_id,receiver.declaration_id,type.child1
  FROM callable_receiver_types receiver
  JOIN main.source_go_types type
    ON type.blob_id=receiver.blob_id AND type.type_id=receiver.type_id
  WHERE type.child1 IS NOT NULL
), anchors(mount_ordinal,blob_id,declaration_id,role) AS (
  SELECT peer.mount_ordinal,peer.blob_id,field.declaration_id,0
  FROM package_files peer
  JOIN main.source_go_fields field ON field.blob_id=peer.blob_id
  JOIN main.source_go_type_declarations owner
    ON owner.blob_id=field.blob_id AND owner.type_id=field.owner_type_id
  WHERE ?5=0 AND field.name=?7 AND owner.name=?6
  UNION ALL
  SELECT peer.mount_ordinal,peer.blob_id,callable.declaration_id,2
  FROM package_files peer
  JOIN main.source_go_callables callable
    ON callable.blob_id=peer.blob_id AND callable.name=?7
  JOIN callable_receiver_types receiver
    ON receiver.mount_ordinal=peer.mount_ordinal
   AND receiver.blob_id=callable.blob_id
   AND receiver.declaration_id=callable.declaration_id
  JOIN main.source_go_type_names receiver_name
    ON receiver_name.blob_id=receiver.blob_id
   AND receiver_name.type_id=receiver.type_id
  JOIN main.source_go_type_declarations owner
    ON owner.blob_id=peer.blob_id AND owner.name=?6
  WHERE ?5=1 AND receiver_name.name=owner.name
), anchor_definitions(mount_ordinal,blob_id,definition,role) AS (
  SELECT anchor.mount_ordinal,anchor.blob_id,semantic.semantic_key,anchor.role
  FROM anchors anchor
  JOIN main.source_native_declaration_bridges bridge
    ON bridge.blob_id=anchor.blob_id AND bridge.declaration_id=anchor.declaration_id
  JOIN main.resolution_semantic_sites semantic
    ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site
   AND semantic.semantic_role='definition'
)
SELECT DISTINCT mount_ordinal,definition,role
FROM anchor_definitions
ORDER BY mount_ordinal,definition,role
"#;

const GO_POINT_CALLABLE_RESULT_ANCHOR: &str = r#"
WITH package_files(mount_ordinal,blob_id) AS (
  SELECT mounted.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
  UNION
  SELECT placed.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3)
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
), caller_reference(namespace,domain_shared,lookup_shared) AS (
  SELECT package_reference.namespace,domain.shared_identity,lookup.shared_identity
  FROM temp.selected_resolution_mounts mounted
  JOIN main.go_context_source_files caller
    ON caller.file_version_id=mounted.file_version_id AND caller.context_id=?1
   AND caller.package_id=?2 AND caller.source_role=?3
  JOIN main.resolution_semantic_sites semantic
    ON semantic.blob_id=mounted.blob_id AND semantic.semantic_key=?5
   AND semantic.semantic_role='reference'
  JOIN main.resolution_package_references package_reference
    ON package_reference.blob_id=semantic.blob_id
   AND package_reference.reference_key=semantic.semantic_key
   AND package_reference.source_site=semantic.source_site
   AND package_reference.namespace IN ('value','callable')
  JOIN main.resolution_semantic_catalog lookup
    ON lookup.blob_id=package_reference.blob_id
   AND lookup.local_key=package_reference.lookup_key
  JOIN main.resolution_semantic_catalog domain
    ON domain.blob_id=package_reference.blob_id
   AND domain.local_key=package_reference.domain_key
  WHERE mounted.mount_ordinal=?4 AND mounted.storage_language='go'
)
SELECT DISTINCT package_file.mount_ordinal,definition.semantic_key
FROM package_files package_file
JOIN main.resolution_package_members member
  ON member.blob_id=package_file.blob_id
JOIN main.resolution_semantic_catalog lookup
  ON lookup.blob_id=member.blob_id AND lookup.local_key=member.lookup_key
JOIN main.resolution_semantic_catalog domain
  ON domain.blob_id=member.blob_id AND domain.local_key=member.domain_key
JOIN caller_reference reference
  ON reference.namespace=member.namespace
 AND reference.domain_shared=domain.shared_identity
 AND reference.lookup_shared=lookup.shared_identity
JOIN main.source_native_declaration_bridges bridge
  ON bridge.blob_id=member.blob_id AND bridge.source_site=member.source_site
JOIN main.source_go_callables callable
  ON callable.blob_id=bridge.blob_id AND callable.declaration_id=bridge.declaration_id
 AND callable.is_method=0
JOIN main.resolution_semantic_sites definition
  ON definition.blob_id=bridge.blob_id AND definition.source_site=bridge.source_site
 AND definition.semantic_role='definition'
WHERE member.namespace IN ('value','callable')
ORDER BY package_file.mount_ordinal,definition.semantic_key
"#;

const GO_POINT_TYPE_NAME: &str = r#"
SELECT type.name
FROM temp.selected_resolution_mounts mounted
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=mounted.blob_id AND semantic.semantic_key=?2
 AND semantic.semantic_role='definition'
JOIN main.source_native_declaration_bridges bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_go_type_declarations type
  ON type.blob_id=bridge.blob_id AND type.declaration_id=bridge.declaration_id
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
"#;

pub(crate) const GO_POINT_BINDING_RECEIVER_ANCHOR: &str = r#"
SELECT semantic.semantic_key,declared.role
FROM temp.selected_resolution_mounts mounted
CROSS JOIN main.source_declarations declaration INDEXED BY source_declarations_name_range
  ON declaration.blob_id=mounted.blob_id
 AND declaration.name_start_byte=?2 AND declaration.name_end_byte=?3
CROSS JOIN main.source_native_declaration_bridges bridge INDEXED BY source_native_declaration_bridges_declaration
  ON bridge.blob_id=declaration.blob_id
 AND bridge.declaration_id=declaration.declaration_id
CROSS JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site
 AND semantic.semantic_role='definition'
CROSS JOIN main.resolution_declaration_types declared
  ON declared.blob_id=semantic.blob_id AND declared.definition=semantic.semantic_key
 AND declared.role IN (0,1)
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
"#;

const GO_RECEIVER_ANCHOR_DECLARED_TYPE: &str = r#"
WITH RECURSIVE package_files(mount_ordinal,blob_id) AS (
  SELECT mounted.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
  UNION
  SELECT placed.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3)
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
), anchor_slots(mount_ordinal,blob_id,slot) AS (
  SELECT mounted.mount_ordinal,mounted.blob_id,declared.slot
  FROM temp.selected_resolution_mounts mounted
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  JOIN main.resolution_semantic_sites semantic
    ON semantic.blob_id=mounted.blob_id
   AND semantic.semantic_key=?5 AND semantic.semantic_role='definition'
  JOIN main.resolution_declaration_types declared
    ON declared.blob_id=semantic.blob_id AND declared.definition=semantic.semantic_key
   AND declared.role=?6
  WHERE mounted.mount_ordinal=?4 AND mounted.storage_language='go'
), slots(mount_ordinal,blob_id,slot,indirection,reference_indirection,visited) AS (
  SELECT mount_ordinal,blob_id,slot,0,0,printf(',%d,',slot)
  FROM anchor_slots
  UNION ALL
  SELECT slots.mount_ordinal,slots.blob_id,transfer.source_slot,
         slots.indirection+transfer.indirection_delta,
         slots.reference_indirection+transfer.reference_indirection_delta,
         slots.visited||printf('%d,',transfer.source_slot)
  FROM slots
  JOIN main.resolution_type_transfers transfer
    ON transfer.blob_id=slots.blob_id AND transfer.target_slot=slots.slot
  WHERE instr(slots.visited,printf(',%d,',transfer.source_slot))=0
), type_references(mount_ordinal,blob_id,slot,indirection,reference_indirection,reference_key) AS (
  SELECT slots.mount_ordinal,slots.blob_id,slots.slot,slots.indirection,slots.reference_indirection,
         frontier.identity_reference
  FROM slots
  JOIN main.resolution_type_frontiers frontier
    ON frontier.blob_id=slots.blob_id AND frontier.slot=slots.slot
  WHERE frontier.identity_reference IS NOT NULL
  UNION ALL
  SELECT slots.mount_ordinal,slots.blob_id,slots.slot,slots.indirection,slots.reference_indirection,
         projection.reference
  FROM slots
  JOIN main.resolution_binding_projections projection
    ON projection.blob_id=slots.blob_id AND projection.output_slot=slots.slot
), package_members(mount_ordinal,blob_id,definition,domain_shared,namespace,lookup_shared) AS (
  SELECT package_file.mount_ordinal,package_file.blob_id,member.definition_key,
         domain.shared_identity,member.namespace,lookup.shared_identity
  FROM package_files package_file
  JOIN main.resolution_package_members member ON member.blob_id=package_file.blob_id
  JOIN main.resolution_semantic_catalog lookup
    ON lookup.blob_id=member.blob_id AND lookup.local_key=member.lookup_key
  JOIN main.resolution_semantic_catalog domain
    ON domain.blob_id=member.blob_id AND domain.local_key=member.domain_key
)
SELECT DISTINCT reference.mount_ordinal,reference_site.semantic_key,
       member.mount_ordinal,member.definition,
       reference.indirection,reference.reference_indirection,
       reference.slot,anchor_slots.slot
FROM type_references reference
JOIN anchor_slots ON anchor_slots.mount_ordinal=reference.mount_ordinal
 AND anchor_slots.blob_id=reference.blob_id
JOIN main.resolution_package_references package_reference
  ON package_reference.blob_id=reference.blob_id
 AND package_reference.reference_key=reference.reference_key
 AND package_reference.namespace='type'
JOIN main.resolution_sites site
  ON site.blob_id=package_reference.blob_id
 AND site.site=package_reference.source_site
 AND site.unqualified=1 AND site.go_package_qualifier=0
JOIN main.resolution_semantic_sites reference_site
  ON reference_site.blob_id=package_reference.blob_id
 AND reference_site.source_site=package_reference.source_site
 AND reference_site.semantic_role='reference'
JOIN main.resolution_semantic_catalog lookup
  ON lookup.blob_id=package_reference.blob_id
 AND lookup.local_key=package_reference.lookup_key
JOIN main.resolution_semantic_catalog domain
  ON domain.blob_id=package_reference.blob_id
 AND domain.local_key=package_reference.domain_key
JOIN package_members member
  ON member.namespace=package_reference.namespace
 AND member.domain_shared=domain.shared_identity
 AND member.lookup_shared=lookup.shared_identity
JOIN main.resolution_semantic_sites definition_site
  ON definition_site.blob_id=member.blob_id
 AND definition_site.semantic_key=member.definition
 AND definition_site.semantic_role='definition'
WHERE member.namespace='type'
ORDER BY reference.mount_ordinal,reference_site.semantic_key,
         member.mount_ordinal,member.definition,
         reference.indirection,reference.reference_indirection,
         reference.slot,anchor_slots.slot
"#;

const GO_POINT_REFERENCE_AT: &str = r#"
SELECT semantic.semantic_key
FROM temp.selected_resolution_mounts mounted
JOIN main.resolution_sites site
  ON site.blob_id=mounted.blob_id AND site.start_byte=?2 AND site.end_byte=?3
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=site.blob_id AND semantic.source_site=site.site
 AND semantic.semantic_role='reference'
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
"#;

const GO_POINT_CALL_REFERENCE_AT: &str = r#"
SELECT semantic.semantic_key
FROM temp.selected_resolution_mounts mounted
JOIN main.resolution_sites site
  ON site.blob_id=mounted.blob_id AND site.start_byte=?2 AND site.end_byte=?3
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=site.blob_id AND semantic.source_site=site.site
 AND semantic.semantic_role='reference'
JOIN main.resolution_call_obligations obligation
  ON obligation.blob_id=semantic.blob_id AND obligation.callee_reference=semantic.semantic_key
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
"#;

const GO_POINT_CALLABLE_RESULT_SLOT: &str = r#"
SELECT obligation.result_slot
FROM temp.selected_resolution_mounts mounted
JOIN main.resolution_call_obligations obligation
  ON obligation.blob_id=mounted.blob_id AND obligation.callee_reference=?2
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
"#;

const GO_RECEIVER_ANCHOR_MEMBER: &str = r#"
WITH RECURSIVE package_files(mount_ordinal,blob_id) AS (
  SELECT mounted.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3) AND mounted.storage_language='go'
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=mounted.mount_ordinal
    )
  UNION
  SELECT placed.mount_ordinal,mounted.blob_id
  FROM main.go_context_source_files provider
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=provider.file_version_id
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
  WHERE provider.context_id=?1 AND provider.package_id=?2
    AND provider.source_role IN ('go',?3)
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_references staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
    AND NOT EXISTS(
      SELECT 1 FROM temp.selected_resolution_stage_package_members staged
      WHERE staged.host_ordinal=placed.mount_ordinal
    )
), selected_type AS (
  SELECT declaration.blob_id,declaration.name,declaration.type_id
  FROM temp.selected_resolution_mounts mounted
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  JOIN main.resolution_semantic_sites semantic
    ON semantic.blob_id=mounted.blob_id
   AND semantic.semantic_key=?5 AND semantic.semantic_role='definition'
  JOIN main.source_native_declaration_bridges bridge
    ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
  JOIN main.source_go_type_declarations declaration
    ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
  WHERE mounted.mount_ordinal=?4 AND mounted.storage_language='go'
), callable_receiver_types(mount_ordinal,blob_id,declaration_id,type_id) AS (
  SELECT package_file.mount_ordinal,package_file.blob_id,callable.declaration_id,callable.receiver_type_id
  FROM package_files package_file
  JOIN main.source_go_callables callable ON callable.blob_id=package_file.blob_id
  JOIN selected_type selected ON 1=1
  WHERE callable.name=?6 AND callable.is_method=1
    AND callable.receiver_type_id IS NOT NULL
  UNION
  SELECT receiver.mount_ordinal,receiver.blob_id,receiver.declaration_id,type.child1
  FROM callable_receiver_types receiver
  JOIN main.source_go_types type
    ON type.blob_id=receiver.blob_id AND type.type_id=receiver.type_id
  WHERE type.child1 IS NOT NULL
), member_declarations(blob_id,declaration_id) AS (
  SELECT callable.blob_id,callable.declaration_id
  FROM package_files package_file
  JOIN main.source_go_callables callable ON callable.blob_id=package_file.blob_id
  JOIN selected_type selected ON 1=1
  WHERE callable.name=?6
    AND (callable.owner_type_id=selected.type_id OR EXISTS (
      SELECT 1 FROM callable_receiver_types receiver
      JOIN main.source_go_type_names receiver_name
        ON receiver_name.blob_id=receiver.blob_id
       AND receiver_name.type_id=receiver.type_id
      WHERE receiver.mount_ordinal=package_file.mount_ordinal
        AND receiver.blob_id=callable.blob_id
        AND receiver.declaration_id=callable.declaration_id
        AND receiver_name.name=selected.name
    ))
  UNION ALL
  SELECT field.blob_id,field.declaration_id
  FROM package_files package_file
  JOIN main.source_go_fields field ON field.blob_id=package_file.blob_id
  JOIN selected_type selected
    ON selected.blob_id=field.blob_id AND selected.type_id=field.owner_type_id
  WHERE field.name=?6
)
SELECT DISTINCT package_file.mount_ordinal,semantic.semantic_key
FROM member_declarations member
JOIN package_files package_file ON package_file.blob_id=member.blob_id
JOIN main.source_native_declaration_bridges bridge
  ON bridge.blob_id=member.blob_id AND bridge.declaration_id=member.declaration_id
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site
 AND semantic.semantic_role='definition'
ORDER BY package_file.mount_ordinal,semantic.semantic_key
"#;

impl SelectedResolutionOperation<'_, '_> {
    pub(crate) fn go_point_reference_at(
        &self,
        caller_path: &str,
        start_byte: usize,
        end_byte: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_REFERENCE_AT)?;
        let mut rows = statement.query(rusqlite::params![
            caller.ordinal().get(),
            i64::try_from(start_byte).expect("Go source offsets fit SQLite integers"),
            i64::try_from(end_byte).expect("Go source offsets fit SQLite integers")
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let key: i64 = row.get(0)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(SemanticId::local(
            caller.ordinal().get(),
            u32::try_from(key).expect("a Go reference has a nonnegative local identity"),
        )))
    }

    /// Select the callable identity at a call site. Generic Go invocations
    /// can publish a type-name and callable reference at the same byte range.
    pub(crate) fn go_point_call_reference_at(
        &self,
        caller_path: &str,
        start_byte: usize,
        end_byte: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_CALL_REFERENCE_AT)?;
        let mut rows = statement.query(rusqlite::params![
            caller.ordinal().get(),
            i64::try_from(start_byte).expect("Go source offsets fit SQLite integers"),
            i64::try_from(end_byte).expect("Go source offsets fit SQLite integers")
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let key: i64 = row.get(0)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(SemanticId::local(
            caller.ordinal().get(),
            u32::try_from(key).expect("a Go call has a nonnegative callable identity"),
        )))
    }

    pub(crate) fn go_point_callable_result_slot(
        &self,
        caller_path: &str,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let Some(reference_key) = reference.local_key() else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_CALLABLE_RESULT_SLOT)?;
        let mut rows = statement.query(rusqlite::params![
            caller.ordinal().get(),
            i64::from(reference_key)
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let slot: i64 = row.get(0)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(SemanticId::local(
            caller.ordinal().get(),
            u32::try_from(slot).expect("a Go result slot has a nonnegative local identity"),
        )))
    }

    /// Select a package function's persisted callable-result anchor from one
    /// exact call reference in the caller blob.
    pub(crate) fn go_point_callable_result_anchor(
        &self,
        context_id: i64,
        caller_path: &str,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, String, GoReceiverTypeAnchor)>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let Some(source_role) =
            self.go_source_role_for_mount(context_id, caller.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        if source_role == "xtest" {
            return Ok(None);
        }
        let Some(version) = self
            .ready
            .inventory
            .mount_record_by_ordinal(caller.ordinal())?
            .file_version_id()
        else {
            return Ok(None);
        };
        let Some(package_id) = self.go_selected_package_id(context_id, version, &source_role)?
        else {
            return Ok(None);
        };
        let Some(reference_key) = reference.local_key() else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_CALLABLE_RESULT_ANCHOR)?;
        let mut rows = statement.query(rusqlite::params![
            context_id,
            package_id,
            source_role,
            caller.ordinal().get(),
            i64::from(reference_key)
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let mount = SelectedResolutionMountOrdinal::new(row.get(0)?);
        let definition_key: i64 = row.get(1)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some((
            package_id,
            source_role,
            GoReceiverTypeAnchor {
                mount,
                definition: SemanticId::local(
                    mount.get(),
                    u32::try_from(definition_key)
                        .expect("a Go callable anchor has a nonnegative definition key"),
                ),
                role: GoReceiverAnchorRole::CallableResult,
                member_name: String::new(),
            },
        )))
    }

    /// Read the declared Go type name belonging to one selected type identity.
    pub(crate) fn go_point_type_name(
        &self,
        identity: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (Some(mount), Some(local_key)) = (identity.ordinal(), identity.local_key()) else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_TYPE_NAME)?;
        let mut rows = statement.query(rusqlite::params![mount, i64::from(local_key)])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let name: String = row.get(0)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(name))
    }

    pub(crate) fn go_point_receiver_slot(
        &self,
        context_id: i64,
        caller_path: &str,
        focus_start_byte: usize,
        focus_end_byte: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_NULL_RECEIVER_FRONTIER)?;
        let mut rows = statement.query(rusqlite::params![
            caller.ordinal().get(),
            i64::try_from(focus_start_byte).expect("Go source offsets fit SQLite integers"),
            i64::try_from(focus_end_byte).expect("Go source offsets fit SQLite integers"),
            context_id
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let slot: i64 = row.get(0)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(SemanticId::local(
            caller.ordinal().get(),
            u32::try_from(slot).expect("a Go receiver slot has a nonnegative local identity"),
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn go_point_receiver_type_anchor(
        &self,
        context_id: i64,
        caller_path: &str,
        anchor_kind: u8,
        owner_type_name: &str,
        anchor_name: &str,
        member_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, String, GoReceiverTypeAnchor)>> {
        if cancellation.is_cancelled() || anchor_kind > 1 {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let Some(source_role) =
            self.go_source_role_for_mount(context_id, caller.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        if source_role == "xtest" {
            return Ok(None);
        }
        let Some(version) = self
            .ready
            .inventory
            .mount_record_by_ordinal(caller.ordinal())?
            .file_version_id()
        else {
            return Ok(None);
        };
        let Some(package_id) = self.go_selected_package_id(context_id, version, &source_role)?
        else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_RECEIVER_ANCHOR)?;
        let mut rows = statement.query(rusqlite::params![
            context_id,
            package_id,
            source_role,
            caller.ordinal().get(),
            i64::from(anchor_kind),
            owner_type_name,
            anchor_name
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let mount = SelectedResolutionMountOrdinal::new(row.get(0)?);
        let definition_key: i64 = row.get(1)?;
        let role: i64 = row.get(2)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let role = match role {
            0 => GoReceiverAnchorRole::FieldType,
            2 => GoReceiverAnchorRole::CallableResult,
            _ => unreachable!("the Go receiver anchor query selects field or callable rows"),
        };
        Ok(Some((
            package_id,
            source_role,
            GoReceiverTypeAnchor {
                mount,
                definition: SemanticId::local(
                    mount.get(),
                    u32::try_from(definition_key)
                        .expect("a Go anchor definition has a nonnegative local identity"),
                ),
                role,
                member_name: member_name.to_owned(),
            },
        )))
    }

    /// Select the exact local or parameter binding whose declared type
    /// anchors a Go receiver. The AST supplies the selected declaration-name
    /// range; each join stays within that caller blob.
    pub(crate) fn go_point_binding_type_anchor(
        &self,
        context_id: i64,
        caller_path: &str,
        declaration_start_byte: usize,
        declaration_end_byte: usize,
        member_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, String, GoReceiverTypeAnchor)>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(caller) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(None);
        };
        let Some(source_role) =
            self.go_source_role_for_mount(context_id, caller.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        if source_role == "xtest" {
            return Ok(None);
        }
        let Some(version) = self
            .ready
            .inventory
            .mount_record_by_ordinal(caller.ordinal())?
            .file_version_id()
        else {
            return Ok(None);
        };
        let Some(package_id) = self.go_selected_package_id(context_id, version, &source_role)?
        else {
            return Ok(None);
        };
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_POINT_BINDING_RECEIVER_ANCHOR)?;
        let mut rows = statement.query(rusqlite::params![
            caller.ordinal().get(),
            i64::try_from(declaration_start_byte)
                .expect("Go declaration offsets fit SQLite integers"),
            i64::try_from(declaration_end_byte)
                .expect("Go declaration offsets fit SQLite integers")
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let definition_key: i64 = row.get(0)?;
        let role: i64 = row.get(1)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let role = match role {
            0 => GoReceiverAnchorRole::BindingValue,
            1 => GoReceiverAnchorRole::BindingParameter,
            _ => unreachable!("the binding anchor query selects value or parameter rows"),
        };
        let mount = caller.ordinal();
        Ok(Some((
            package_id,
            source_role,
            GoReceiverTypeAnchor {
                mount,
                definition: SemanticId::local(
                    mount.get(),
                    u32::try_from(definition_key)
                        .expect("a Go binding anchor has a nonnegative definition key"),
                ),
                role,
                member_name: member_name.to_owned(),
            },
        )))
    }

    /// Resolve the type declared by one selected field/callable anchor and the
    /// declaration of `member_name` under that type. This is a fixed number of
    /// keyed reads, shared by Go point confirmation and reverse candidates.
    pub(crate) fn resolve_go_receiver_anchor_member(
        &self,
        context_id: i64,
        package_id: i64,
        source_role: &str,
        anchor: &GoReceiverTypeAnchor,
        cancellation: &CancellationToken,
    ) -> Result<GoReceiverAnchorMember> {
        if cancellation.is_cancelled() || source_role == "xtest" {
            return Ok(GoReceiverAnchorMember::Unknown);
        }
        let Some(types) = self.go_receiver_anchor_types(
            context_id,
            package_id,
            source_role,
            anchor,
            cancellation,
        )?
        else {
            return Ok(GoReceiverAnchorMember::Unknown);
        };
        let receiver_type = types.receiver_type;
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_RECEIVER_ANCHOR_MEMBER)?;
        let mut rows = statement.query(rusqlite::params![
            context_id,
            package_id,
            source_role,
            receiver_type
                .identity()
                .ordinal()
                .expect("the Go receiver type is selected"),
            i64::from(
                receiver_type
                    .identity()
                    .local_key()
                    .expect("selected type has local key")
            ),
            anchor.member_name
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(GoReceiverAnchorMember::Unknown);
        };
        let member_mount = SelectedResolutionMountOrdinal::new(row.get(0)?);
        let member_key: i64 = row.get(1)?;
        if rows.next()?.is_some() || cancellation.is_cancelled() {
            return Ok(GoReceiverAnchorMember::Unknown);
        }
        let member = SemanticId::local(
            member_mount.get(),
            u32::try_from(member_key)
                .expect("a Go member declaration has a nonnegative local identity"),
        );
        let member_result_anchor = GoReceiverTypeAnchor {
            mount: member_mount,
            definition: member,
            role: GoReceiverAnchorRole::CallableResult,
            member_name: String::new(),
        };
        let mut reference_bindings = types.reference_bindings.into_vec();
        let mut typed_slots = types.typed_slots.into_vec();
        let mut member_result_type = None;
        if let Some(result_types) = self.go_receiver_anchor_types(
            context_id,
            package_id,
            source_role,
            &member_result_anchor,
            cancellation,
        )? {
            member_result_type = Some(result_types.receiver_type);
            reference_bindings.extend(result_types.reference_bindings.iter().copied());
            typed_slots.extend(result_types.typed_slots.iter().copied());
        }
        reference_bindings.sort_unstable();
        reference_bindings.dedup();
        Ok(GoReceiverAnchorMember::Known {
            receiver_type,
            member,
            member_result_type,
            reference_bindings: reference_bindings.into_boxed_slice(),
            typed_slots: typed_slots.into_boxed_slice(),
        })
    }

    pub(crate) fn go_receiver_anchor_types(
        &self,
        context_id: i64,
        package_id: i64,
        source_role: &str,
        anchor: &GoReceiverTypeAnchor,
        cancellation: &CancellationToken,
    ) -> Result<Option<GoReceiverAnchorTypes>> {
        if cancellation.is_cancelled() || source_role == "xtest" {
            return Ok(None);
        }
        let anchor_key = anchor
            .definition
            .local_key()
            .expect("a selected Go receiver anchor has a fragment-local definition");
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(GO_RECEIVER_ANCHOR_DECLARED_TYPE)?;
        let mut rows = statement.query(rusqlite::params![
            context_id,
            package_id,
            source_role,
            anchor.mount.get(),
            i64::from(anchor_key),
            anchor.role.persisted()
        ])?;
        let mut types = Vec::new();
        let mut reference_bindings = Vec::new();
        let mut typed_slots = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let reference_mount = SelectedResolutionMountOrdinal::new(row.get(0)?);
            let reference_key: i64 = row.get(1)?;
            let definition_mount = SelectedResolutionMountOrdinal::new(row.get(2)?);
            let definition_key: i64 = row.get(3)?;
            let indirection: i64 = row.get(4)?;
            let reference_indirection: i64 = row.get(5)?;
            let reference_slot = SemanticId::local(
                reference_mount.get(),
                u32::try_from(row.get::<_, i64>(6)?)
                    .expect("a Go type-reference slot has a nonnegative identity"),
            );
            let declaration_slot = SemanticId::local(
                anchor.mount.get(),
                u32::try_from(row.get::<_, i64>(7)?)
                    .expect("a Go declaration type slot has a nonnegative identity"),
            );
            let (Ok(indirection), Ok(reference_indirection)) = (
                u32::try_from(indirection),
                u32::try_from(reference_indirection),
            ) else {
                return Ok(None);
            };
            if reference_indirection > indirection {
                return Ok(None);
            }
            types.push((
                SemanticId::local(
                    definition_mount.get(),
                    u32::try_from(definition_key)
                        .expect("a Go declared type definition has a nonnegative local identity"),
                ),
                indirection,
                reference_indirection,
            ));
            let type_identity = SemanticId::local(
                definition_mount.get(),
                u32::try_from(definition_key)
                    .expect("a Go declared type definition has a nonnegative local identity"),
            );
            typed_slots.push((
                reference_slot,
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(type_identity, 0)),
            ));
            typed_slots.push((
                declaration_slot,
                ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new_with_reference_indirection(
                        type_identity,
                        indirection,
                        reference_indirection,
                    ),
                    anchor.role == GoReceiverAnchorRole::FieldType,
                ),
            ));
            reference_bindings.push(GoReceiverReferenceBinding {
                reference: SemanticId::local(
                    reference_mount.get(),
                    u32::try_from(reference_key)
                        .expect("a Go declared type reference has a nonnegative local identity"),
                ),
                definition: SemanticId::local(
                    definition_mount.get(),
                    u32::try_from(definition_key)
                        .expect("a Go declared type definition has a nonnegative local identity"),
                ),
            });
        }
        types.sort_unstable();
        types.dedup();
        let [(type_definition, indirection, reference_indirection)] = types.as_slice() else {
            return Ok(None);
        };
        let receiver_type = ResolutionTypeRef::new_with_reference_indirection(
            *type_definition,
            *indirection,
            *reference_indirection,
        );
        reference_bindings.sort_unstable();
        reference_bindings.dedup();
        typed_slots.sort_unstable();
        typed_slots.dedup();
        Ok(Some(GoReceiverAnchorTypes {
            receiver_type,
            reference_bindings: reference_bindings.into_boxed_slice(),
            typed_slots: typed_slots.into_boxed_slice(),
        }))
    }
}
