-- CodeUnit -> source declaration -> native declaration site -> the selected
-- summary member/export bridge (the subjects CTE below), then the impls that name that
-- declaration as their subject, all read from the selected unit summaries:
--   trait impls   trait endpoint rows, subject resolved (independent of the trait endpoint), found by
--                 the subject's (unit key, module path, identity);
--   inherent impls whose subject is a member and site of the impl's own unit, found
--                 by (summary, subject member, subject site);
--   inherent impls whose subject is another unit's name form, found by that name
--                 form, and only when exactly one declaration export carries it.
-- A name form that several exports carry (cfg alternatives) or an endpoint the
-- summary left unresolved cannot attribute its impl to one declaration;
-- rust_impl_children_gaps.sql reports that, and this statement returns no child for it.
-- Only complete topologies valid in the selected workspace generation/revision
-- participate (the reconcile-currency guard, reached through the summary's
-- topology id until the topology tables go); neither a historical profile nor a
-- building topology adds members.
WITH {subjects}, impls AS (
 SELECT subject.summary_id, subject.member_ordinal AS impl_member_ordinal,
        subject.impl_declaration_id
 FROM subjects
 CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS subject
   INDEXED BY rust_resolution_unit_summary_trait_endpoints_target
   ON subject.target_unit_key=subjects.unit_key
  AND subject.target_module_path=subjects.module_path
  AND subject.target_identity_id=subjects.identity_id
  AND subject.endpoint_role='subject' AND subject.endpoint_state='resolved'
 WHERE (SELECT count(*) FROM rust_resolution_unit_summary_exports AS same_name
        INDEXED BY rust_summary_decl_export_endpoint
        WHERE same_name.summary_id=subjects.summary_id
          AND same_name.module_path=subjects.module_path
          AND same_name.namespace='type' AND same_name.name=subjects.name
          AND same_name.origin='declaration')=1
 UNION ALL
 SELECT inherent.summary_id, inherent.impl_member_ordinal, inherent.impl_declaration_id
 FROM subjects
 CROSS JOIN rust_resolution_unit_summary_inherent_impls AS inherent
   INDEXED BY rust_summary_inherent_local_subject
   ON inherent.summary_id=subjects.summary_id
  AND inherent.subject_member_ordinal=subjects.member_ordinal
  AND inherent.subject_site=subjects.source_site
  AND inherent.subject_form='local_site'
 UNION ALL
 SELECT inherent.summary_id, inherent.impl_member_ordinal, inherent.impl_declaration_id
 FROM subjects
 CROSS JOIN rust_resolution_unit_summary_inherent_impls AS inherent
   INDEXED BY rust_summary_inherent_subject
   ON inherent.subject_unit_key=subjects.unit_key
  AND inherent.subject_module_path=subjects.module_path
  AND inherent.subject_kind='declaration' AND inherent.subject_namespace='type'
  AND inherent.subject_name=subjects.name AND inherent.subject_origin='declaration'
  AND inherent.subject_form='foreign'
 WHERE (SELECT count(*) FROM rust_resolution_unit_summary_exports AS same_name
        INDEXED BY rust_summary_decl_export_endpoint
        WHERE same_name.summary_id=subjects.summary_id
          AND same_name.module_path=subjects.module_path
          AND same_name.namespace='type' AND same_name.name=subjects.name
          AND same_name.origin='declaration')=1
), members AS (
 SELECT DISTINCT impl_member.blob_id AS blob_id, impl_member.rel_path AS rel_path,
                 units.unit_key
 FROM impls
 CROSS JOIN resolution_unit_summary_members AS impl_member
   ON impl_member.summary_id=impls.summary_id
  AND impl_member.member_ordinal=impls.impl_member_ordinal
 CROSS JOIN selected_rust_unit_summaries AS impl_unit ON impl_unit.summary_id=impls.summary_id
 CROSS JOIN rust_crate_versions AS versions INDEXED BY rust_crate_versions_topology
   ON versions.topology_id=impl_unit.topology_id
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
  AND reconciliation.revision=selected.revision AND reconciliation.derivation_identity=?10
 CROSS JOIN selected_workspace_file_versions AS file
   ON file.workspace_id=selected.workspace_id AND file.lang=selected.lang
  AND file.generation=selected.generation AND file.rel_path=impl_member.rel_path
 -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
 CROSS JOIN blobs AS impl_blob
   ON impl_blob.id=impl_member.blob_id AND impl_blob.blob_oid=file.blob_oid
  AND impl_blob.lang=file.lang AND impl_blob.generation=file.generation
 CROSS JOIN source_rust_item_body_children AS child
   ON child.blob_id=impl_member.blob_id
  AND child.owner_declaration_id=impls.impl_declaration_id
 CROSS JOIN source_declaration_units AS units
   ON units.blob_id=child.blob_id AND units.declaration_id=child.declaration_id
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
