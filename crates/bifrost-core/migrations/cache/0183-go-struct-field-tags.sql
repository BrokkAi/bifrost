-- Field order, name, embeddedness and type already belong to source_go_fields.
-- A Go struct tag is a scalar byte string; NULL records a failed literal decode.
-- Readers: Go source hydration and structural method-signature comparison.
ALTER TABLE source_go_fields ADD COLUMN tag BLOB;
DROP VIEW source_go_fact_costs;
CREATE VIEW source_go_fact_costs AS
SELECT blob.id AS blob_id,
       1
       + (SELECT COUNT(*) FROM source_go_types WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_type_names WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_type_children WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_type_declarations WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_aliases WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_fields WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_callables WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_callable_parameters WHERE blob_id = blob.id)
       + (SELECT COUNT(*) FROM source_go_embeddings WHERE blob_id = blob.id) AS logical_rows,
       COALESCE((SELECT SUM(length(CAST(text AS BLOB))) FROM source_go_types WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB))) FROM source_go_type_names WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB))) FROM source_go_type_declarations WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB))) FROM source_go_aliases WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB)) + COALESCE(length(tag), 0)) FROM source_go_fields WHERE blob_id = blob.id), 0)
       + COALESCE((SELECT SUM(length(CAST(name AS BLOB))) FROM source_go_callables WHERE blob_id = blob.id), 0) AS payload_bytes
FROM blobs AS blob;
