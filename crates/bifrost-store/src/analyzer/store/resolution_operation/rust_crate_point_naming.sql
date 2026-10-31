SELECT json(naming.package_components), json(naming.root_components)
FROM selected_workspace_file_versions AS file
CROSS JOIN main.blobs AS blob
 ON blob.blob_oid=file.blob_oid AND blob.lang=file.lang AND blob.generation=file.generation
AND blob.parse_variant=x''
CROSS JOIN main.resolution_unit_summary_members AS candidate
 INDEXED BY resolution_unit_summary_members_blob
 ON candidate.blob_id=blob.id AND candidate.rel_path=file.rel_path
-- Bind both member key columns before opening the shared validity view. This
-- avoids scanning every selected unit or automatically indexing member paths.
CROSS JOIN selected_rust_unit_members AS member
 ON member.summary_id=candidate.summary_id AND member.member_ordinal=candidate.member_ordinal
CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
 ON naming.summary_id=member.summary_id
AND naming.member_ordinal=member.member_ordinal
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
 ON context.summary_id=member.summary_id
WHERE file.lang='rust' AND file.rel_path=?1
ORDER BY context.target_kind <> 'lib', member.unit_key LIMIT 1
