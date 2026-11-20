SELECT edge.blob_id, edge.invocation_occurrence_id AS invocation,
       expansion.context_occurrence_id AS including_owner, edge.relative_path
FROM main.rust_include_edges AS edge
LEFT JOIN main.source_rust_item_macro_expansions AS expansion
  ON expansion.blob_id=edge.blob_id
 AND expansion.invocation_occurrence_id=edge.invocation_occurrence_id
WHERE edge.blob_id=?1
