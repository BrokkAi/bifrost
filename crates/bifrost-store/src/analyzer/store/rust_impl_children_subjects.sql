-- The asked declaration as the selected summaries name it: one row per member of
-- a selected unit that places the asked blob at the asked path and exports the
-- declaration. Shared by the children statement and its incompleteness statement.
subjects AS (
 SELECT DISTINCT asked.id AS blob_id, bridge.source_site, member.rel_path,
        member.summary_id, member.member_ordinal, selected.unit_key,
        exports.module_path, exports.name, exports.identity_id
 FROM blobs AS asked
 CROSS JOIN code_units AS owner ON owner.blob_id=asked.id
 CROSS JOIN source_declaration_units AS source
   ON source.blob_id=owner.blob_id AND source.unit_key=owner.unit_key
 CROSS JOIN source_native_declaration_bridges AS bridge
   INDEXED BY source_native_declaration_bridges_declaration
   ON bridge.blob_id=source.blob_id AND bridge.declaration_id=source.declaration_id
 CROSS JOIN resolution_unit_summary_members AS member
   INDEXED BY resolution_unit_summary_members_path
   ON member.rel_path=?2
 CROSS JOIN temp.selected_unit_member_blobs AS attachment
   ON attachment.summary_id=member.summary_id
  AND attachment.member_ordinal=member.member_ordinal
  AND attachment.blob_id=asked.id
 CROSS JOIN selected_rust_unit_summaries AS selected
   ON selected.summary_id=member.summary_id
 CROSS JOIN rust_resolution_unit_summary_exports AS exports
   INDEXED BY rust_resolution_unit_summary_exports_declaration
   ON exports.summary_id=member.summary_id
  AND exports.declaration_member_ordinal=member.member_ordinal
  -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
  AND member.blob_id=asked.id
  AND exports.declaration_site=bridge.source_site
  AND exports.namespace='type' AND exports.origin='declaration'
 LEFT JOIN resolution_unit_summary_exports AS shared_export
   INDEXED BY resolution_unit_summary_exports_surface_lookup
   ON shared_export.summary_id=member.summary_id
  -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
  AND shared_export.declaration_member_ordinal=(
      SELECT min(shared_member.member_ordinal)
      FROM resolution_unit_summary_members AS shared_member
      WHERE shared_member.summary_id=member.summary_id
        AND shared_member.blob_id=member.blob_id)
  AND shared_export.site_surface_ordinal=(
      SELECT surface_ordinal FROM main.surface_ids
      WHERE set_id=(SELECT set_id FROM main.surface_sets
                    WHERE blob_id=member.blob_id AND list_digest=x'{rust_digest}')
        AND id_space=0 AND dense_id=bridge.source_site)
  AND shared_export.identity_id=exports.identity_id
  AND shared_export.namespace=exports.namespace
  AND shared_export.target_kind='own'
 WHERE asked.blob_oid=?1 AND asked.lang='rust'
  AND owner.kind=?3 AND owner.signature IS ?4 AND owner.synthetic=?5
  AND owner.fq_anchor_kind IS ?6 AND owner.fq_anchor_pop IS ?7
  AND owner.fq_package_tail_segments=?8 AND owner.exact_fqn_tail=?9
  AND (exports.visibility<>'public' OR shared_export.identity_id IS NOT NULL)
)
