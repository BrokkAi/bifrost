ALTER TABLE workspace_import_sources
    ADD COLUMN binding_surface_digest BLOB
        CHECK (binding_surface_digest IS NULL OR length(binding_surface_digest) = 32);

ALTER TABLE workspace_import_sources
    ADD COLUMN import_rows_digest BLOB
        CHECK (import_rows_digest IS NULL OR length(import_rows_digest) = 32);
