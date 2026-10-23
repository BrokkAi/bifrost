-- CodeUnit -> source declaration -> native declaration site -> the selected
-- summary member/export bridge. `unit_key` belongs to the summary version;
-- exports address its declaration through declaration_member_ordinal/site.
-- Only complete topologies valid in the selected workspace generation/revision
-- participate. Both UNION ALL arms seek their subject index before binding
-- topology; neither a historical profile nor a building topology adds members.
WITH subjects AS (
 SELECT DISTINCT asked.id AS blob_id, bridge.source_site, member.rel_path
 FROM blobs AS asked
 CROSS JOIN code_units AS owner ON owner.blob_id=asked.id
 CROSS JOIN source_declaration_units AS source
   ON source.blob_id=owner.blob_id AND source.unit_key=owner.unit_key
 CROSS JOIN source_native_declaration_bridges AS bridge
   INDEXED BY source_native_declaration_bridges_declaration
   ON bridge.blob_id=source.blob_id AND bridge.declaration_id=source.declaration_id
 CROSS JOIN resolution_unit_summary_members AS member
   INDEXED BY resolution_unit_summary_members_blob
   ON member.blob_id=asked.id AND member.rel_path=?2
 CROSS JOIN selected_rust_unit_summaries AS selected
   ON selected.summary_id=member.summary_id
 CROSS JOIN rust_resolution_unit_summary_exports AS exports
   INDEXED BY rust_resolution_unit_summary_exports_declaration
   ON exports.summary_id=member.summary_id
  AND exports.declaration_member_ordinal=member.member_ordinal
  AND exports.declaration_site=bridge.source_site
  AND exports.namespace='type' AND exports.origin='declaration'
 WHERE asked.blob_oid=?1 AND asked.lang='rust'
  AND owner.kind=?3 AND owner.signature IS ?4 AND owner.synthetic=?5
  AND owner.fq_anchor_kind IS ?6 AND owner.fq_anchor_pop IS ?7
  AND owner.fq_package_tail_segments=?8 AND owner.exact_fqn_tail=?9
), members AS (
 SELECT DISTINCT impl.impl_blob_id AS blob_id, impl.impl_rel_path AS rel_path,
                 units.unit_key
 FROM rust_crate_impls_of_subject AS impl
 CROSS JOIN rust_crate_versions AS versions INDEXED BY rust_crate_versions_topology
   ON versions.topology_id=impl.topology_id
 CROSS JOIN selected_workspace_revisions AS selected
   ON selected.workspace_id=versions.workspace_id AND selected.lang=versions.lang
  AND selected.generation=versions.generation
  AND versions.valid_from<=selected.revision
  AND (versions.valid_until IS NULL OR selected.revision<versions.valid_until)
 CROSS JOIN rust_crate_topologies AS topology
   ON topology.topology_id=versions.topology_id
  AND topology.publication_state='complete'
 CROSS JOIN analysis_epochs AS epoch
   ON epoch.lang='rust' AND epoch.generation=selected.generation
  AND epoch.epoch=topology.producer_epoch
 CROSS JOIN rust_crate_reconciliations AS reconciliation
   ON reconciliation.workspace_id=selected.workspace_id
  AND reconciliation.generation=selected.generation
  AND reconciliation.revision=selected.revision AND reconciliation.derivation_version=?10
 CROSS JOIN selected_workspace_file_versions AS file
   ON file.workspace_id=selected.workspace_id AND file.lang=selected.lang
  AND file.generation=selected.generation AND file.rel_path=impl.impl_rel_path
 CROSS JOIN blobs AS impl_blob
   ON impl_blob.id=impl.impl_blob_id AND impl_blob.blob_oid=file.blob_oid
  AND impl_blob.lang=file.lang AND impl_blob.generation=file.generation
 CROSS JOIN source_rust_item_body_children AS child
   ON child.blob_id=impl.impl_blob_id
  AND child.owner_declaration_id=impl.impl_declaration_id
 CROSS JOIN source_declaration_units AS units
   ON units.blob_id=child.blob_id AND units.declaration_id=child.declaration_id
 WHERE impl.subject_declaration_blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust')
  AND impl.subject_declaration_site IN (SELECT source_site FROM subjects)
  AND impl.subject_rel_path=?2
)
SELECT {projection}, members.rel_path,
       ranges.start_byte, ranges.end_byte, ranges.start_line, ranges.end_line
FROM members
CROSS JOIN code_units AS child
 ON child.blob_id=members.blob_id AND child.unit_key=members.unit_key
CROSS JOIN blobs AS keys ON keys.id=child.blob_id
CROSS JOIN blob_meta AS meta ON meta.blob_id=child.blob_id
LEFT JOIN unit_ranges AS ranges
 ON ranges.blob_id=child.blob_id AND ranges.unit_key=child.unit_key AND ranges.ordinal=0
WHERE {complete}
ORDER BY members.rel_path, ranges.start_byte, ranges.end_byte, child.unit_key
LIMIT ?11
