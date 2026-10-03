INSERT INTO cr_gaps
SELECT 'unknown_activation', candidate.module_path || '::' || candidate.identifier,
       json_object('member_blob', candidate.blob_id,
                   'declaration_id', candidate.declaration_id,
                   'cfg_condition', candidate.cfg_condition)
FROM cr_source_declarations AS candidate
WHERE candidate.nearest_declaration_boundary=0 AND candidate.activation=-1
