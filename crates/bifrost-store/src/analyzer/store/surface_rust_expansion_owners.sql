SELECT expansion.blob_id, expansion.invocation_occurrence_id AS invocation,
       COALESCE(module.ordinal, 0) AS module_scope,
       expansion.context_occurrence_id AS context,
       expansion.source_position IN (0, 1) AS item_position
FROM main.source_rust_item_macro_expansions AS expansion
LEFT JOIN main.rust_module_scopes AS module
  ON module.blob_id=expansion.blob_id AND expansion.invocation_start_byte>=module.body_start
 AND expansion.invocation_end_byte<=module.body_end
 AND NOT EXISTS(SELECT 1 FROM main.rust_module_scopes AS inner_module
                WHERE inner_module.blob_id=expansion.blob_id
                  AND expansion.invocation_start_byte>=inner_module.body_start
                  AND expansion.invocation_end_byte<=inner_module.body_end
                  AND inner_module.body_start>module.body_start)
WHERE expansion.blob_id=?1
