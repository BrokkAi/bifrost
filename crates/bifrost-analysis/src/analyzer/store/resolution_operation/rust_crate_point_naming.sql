SELECT json(naming.package_components), json(naming.root_components)
FROM selected_rust_unit_members AS member
CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
 ON naming.summary_id=member.summary_id
AND naming.member_ordinal=member.member_ordinal
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
 ON context.summary_id=member.summary_id
WHERE member.rel_path=?1
ORDER BY context.target_kind <> 'lib', member.unit_key LIMIT 1
