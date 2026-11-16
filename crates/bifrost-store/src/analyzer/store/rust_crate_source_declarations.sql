-- Several physical paths can place the same blob in the same module. Their
-- declaration facts have this content-level key; source paths remain in the
-- path-aware member relation.
INSERT INTO cr_source_declarations(
  module_path, blob_id, declaration_id, visibility, cfg_condition, activation,
  declaration_kind, macro_exported, nearest_declaration_boundary, identifier
)
SELECT * FROM (
SELECT declaration.module_path, declaration.blob_id, declaration.declaration_id,
       properties.visibility, properties.cfg_condition,
       cr_cfg(properties.cfg_condition, ?1),
       properties.declaration_kind, properties.macro_exported,
       properties.nearest_declaration_boundary, unit.identifier
FROM cr_placed_source_declarations AS declaration
CROSS JOIN source_declaration_visibilities AS visibility
  ON visibility.blob_id = declaration.blob_id
 AND visibility.declaration_id = declaration.declaration_id
CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id = declaration.blob_id
 AND properties.declaration_id = declaration.declaration_id
CROSS JOIN source_declaration_units AS mapping
  ON mapping.blob_id = declaration.blob_id
 AND mapping.declaration_id = declaration.declaration_id
CROSS JOIN code_units AS unit
  ON unit.blob_id = mapping.blob_id AND unit.unit_key = mapping.unit_key
) WHERE true ON CONFLICT DO NOTHING;
