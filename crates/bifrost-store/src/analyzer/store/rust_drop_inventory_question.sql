SELECT u.unit_key, e.module_path, identity.identity_digest,
                    context.target_kind, context.crate_name, context.edition,
                    context.prelude, json(context.cfg_atoms), context.development_capable
             FROM blobs AS blob INDEXED BY sqlite_autoindex_blobs_1
             CROSS JOIN source_declarations AS declaration ON declaration.blob_id = blob.id
             CROSS JOIN resolution_unit_summary_members AS m
               INDEXED BY resolution_unit_summary_members_blob
               ON m.blob_id = blob.id AND m.rel_path = ?1
             CROSS JOIN selected_rust_unit_summaries AS u ON u.summary_id = m.summary_id
             JOIN workspace_file_versions AS live
               ON live.workspace_id = u.workspace_id AND live.lang = u.lang
              AND live.generation = u.generation AND live.rel_path = m.rel_path
              AND live.input_kind = 'source' AND live.blob_oid = blob.blob_oid
              AND live.valid_from <= u.revision
              AND (live.valid_until IS NULL OR u.revision < live.valid_until)
             JOIN rust_resolution_unit_summary_contexts AS context
               ON context.summary_id = m.summary_id
             JOIN source_rust_declaration_properties AS property
               ON property.blob_id = declaration.blob_id
              AND property.declaration_id = declaration.declaration_id
             JOIN resolution_rust_declaration_authorities AS authority
               ON authority.blob_id = declaration.blob_id
              AND authority.declaration = declaration.declaration_id
             JOIN rust_resolution_unit_summary_exports AS e
               ON e.summary_id = m.summary_id
              AND e.declaration_member_ordinal = m.member_ordinal
              AND e.declaration_site = authority.source_site
              AND e.origin = 'declaration' AND e.namespace = 'type'
             JOIN resolution_identities AS identity ON identity.id = e.identity_id
             WHERE blob.blob_oid = ?2 AND blob.lang = 'rust'
               AND declaration.start_byte = ?3 AND declaration.end_byte = ?4
               AND property.declaration_kind IN (0, 1)
             ORDER BY u.unit_key, e.module_path, identity.identity_digest;
