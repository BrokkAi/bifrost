INSERT INTO cr_gaps
SELECT 'unknown_activation', candidate.module_path || '::' || candidate.identifier,
       json_object('member_blob', candidate.blob_id,
                   'declaration_id', candidate.declaration_id,
                   'cfg_condition', candidate.cfg_condition)
FROM cr_source_declarations AS candidate
WHERE candidate.nearest_declaration_boundary=0 AND candidate.activation=-1
UNION ALL
-- A conditional import has no declaration candidate. Retain its selected
-- uncertainty alongside conditional declarations instead of proving absence
-- merely because it cannot contribute an active import binding.
SELECT 'unknown_activation', imports.module_path ||
       CASE WHEN imports.is_glob=1 OR imports.is_macro_use=1 THEN ''
            ELSE '::' || imports.bound_name END,
       json_object('member_blob', imports.blob_id,
                   'import_ordinal', imports.import_ordinal,
                   'cfg_condition', imports.cfg_condition)
FROM cr_member_imports AS imports
WHERE cr_cfg(imports.cfg_condition, ?1)=-1 AND imports.local_start IS NULL
  AND (imports.bound_name IS NOT NULL OR imports.is_glob=1 OR imports.is_macro_use=1)
