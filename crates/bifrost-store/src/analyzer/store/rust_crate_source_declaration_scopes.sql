-- Source-only scope and eligibility shared by crate derivation and overlays.
-- No CodeUnit or native declaration bridge is required.
CREATE TEMP VIEW IF NOT EXISTS rust_source_module_intervals AS
SELECT scope.blob_id,scope.ordinal AS scope_ordinal,
       module.body_start_byte AS start_byte,module.body_end_byte AS end_byte
FROM source_rust_module_scopes AS scope
JOIN source_rust_module_declarations AS module
 ON module.blob_id=scope.blob_id AND module.declaration_id=scope.declaration_id
WHERE module.body_start_byte IS NOT NULL;
CREATE TEMP VIEW IF NOT EXISTS rust_source_declaration_scopes AS
SELECT declaration.*, {module_scope} AS module_scope_ordinal
FROM source_declarations AS declaration;
CREATE TEMP VIEW IF NOT EXISTS rust_body_local_macro_exports AS
SELECT declaration.blob_id,declaration.declaration_id,declaration.module_scope_ordinal,
       properties.cfg_condition
FROM rust_source_declaration_scopes AS declaration
JOIN source_rust_declaration_properties AS properties
 ON properties.blob_id=declaration.blob_id
 AND properties.declaration_id=declaration.declaration_id
WHERE properties.macro_exported=1 AND properties.nearest_declaration_boundary<>0;
