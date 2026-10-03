INSERT INTO cr_source_declarations(
  module_path, blob_id, declaration_id, visibility, cfg_condition, activation,
  declaration_kind, macro_exported, nearest_declaration_boundary, identifier
)
SELECT member.module_path, declaration.blob_id, declaration.declaration_id,
       properties.visibility, properties.cfg_condition,
       cr_cfg(properties.cfg_condition, ?1),
       properties.declaration_kind, properties.macro_exported,
       properties.nearest_declaration_boundary, unit.identifier
FROM cr_member_blobs AS selected
CROSS JOIN source_declarations AS declaration
  ON declaration.blob_id = selected.blob_id
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
CROSS JOIN cr_members AS member
  ON member.blob_id = declaration.blob_id
 AND member.scope_ordinal = COALESCE((
   SELECT inner_module.scope_ordinal
   FROM cr_scopes AS inner_module
   WHERE inner_module.blob_id = declaration.blob_id
     AND declaration.start_byte >= inner_module.start_byte
     AND declaration.end_byte <= inner_module.end_byte
   ORDER BY inner_module.start_byte DESC
   LIMIT 1
 ), 0);
