COALESCE((
 SELECT inner_module.scope_ordinal FROM {scopes} AS inner_module
 WHERE inner_module.blob_id=declaration.blob_id
   AND declaration.start_byte>=inner_module.start_byte
   AND declaration.end_byte<=inner_module.end_byte
 ORDER BY inner_module.start_byte DESC LIMIT 1
),0)
