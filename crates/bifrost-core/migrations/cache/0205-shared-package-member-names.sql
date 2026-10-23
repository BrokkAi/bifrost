CREATE INDEX resolution_semantic_catalog_shared_identity ON resolution_semantic_catalog(shared_identity, blob_id, local_key) WHERE shared_identity IS NOT NULL;
