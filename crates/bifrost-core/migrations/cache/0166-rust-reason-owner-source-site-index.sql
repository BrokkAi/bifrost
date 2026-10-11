-- Resolve persisted Rust gap identities to declaration authority by exact
-- source site without scanning every declaration in the mounted blob.
CREATE INDEX resolution_rust_declaration_authorities_source_site
  ON resolution_rust_declaration_authorities(blob_id, source_site);
