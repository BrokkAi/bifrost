-- Continues `rust_crate_point_targets.sql`. Topology routes determine
-- placement. Changed content supplies its own canonical export name, declaration site, visibility and module authority.
-- The returned site always belongs to the returned blob and mount ordinal.
--
-- One lookup reads both kinds of declaration a module can export. A persisted
-- declaration returns its site and a NULL declaration id. An item the crate
-- declared for a cross-file passthrough invocation (`rust_crate_macro_items`)
-- has no persisted site: it returns a NULL site and declaration replay's
-- declaration id in the invoking file, which the caller maps to the item's
-- request-scoped capsule definition. Its visibility predicate is the same one
-- the persisted arm applies.
, changed_sources AS (
 -- The module's own sources, sought by (topology, container path). A macro
 -- target at the crate root reads every source of the crate instead: the
 -- second arm. They are two arms, not one join with an OR, because the OR's
 -- macro branch names no source column, so SQLite could seek only by
 -- topology and read every source of the crate for every target row. On
 -- tract_core that is 179 sources per target.
 SELECT targets.topology_id, targets.module_path, targets.name,
        source.enum_scope_node_key, mount.blob_id AS selected_blob, mount.mount_ordinal
 FROM targets
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=targets.topology_id AND source.container_path=targets.module_path
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=source.rel_path
 WHERE mount.blob_id<>source.blob_id
 UNION
 SELECT targets.topology_id, targets.module_path, targets.name,
        source.enum_scope_node_key, mount.blob_id AS selected_blob, mount.mount_ordinal
 FROM targets
 CROSS JOIN rust_crate_container_sources AS source
  ON source.topology_id=targets.topology_id
 CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.storage_language='rust' AND mount.persisted_relative_path=source.rel_path
 WHERE ?3='macro' AND targets.module_path='crate' AND mount.blob_id<>source.blob_id
), selected_exports AS (
 SELECT source.selected_blob, source.mount_ordinal, authority.source_site, source.topology_id,
        source.module_path,
        CASE WHEN properties.macro_exported=1 OR source.enum_scope_node_key IS NOT NULL
             THEN 'public' ELSE properties.visibility END AS visibility,
        cr_restriction(properties.visibility,source.module_path,
          (SELECT parent.container_path FROM rust_crate_container_sources AS parent
           CROSS JOIN source_rust_module_declarations AS declaration
            ON declaration.blob_id=parent.blob_id
           WHERE parent.topology_id=source.topology_id
            AND parent.container_path || '::' || declaration.module_name=source.module_path
           LIMIT 1)) AS restricted_module_path
 FROM changed_sources AS source
 CROSS JOIN resolution_identities AS name
  ON name.identity_digest=cr_lookup_digest(?3,source.name)
 CROSS JOIN resolution_paths AS path INDEXED BY resolution_paths_forward
  ON path.blob_id=source.selected_blob AND path.start_node=-1
  AND path.start_lead_identity=name.id
 CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=path.blob_id AND authority.semantic_key=path.end_node
 CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=authority.blob_id AND properties.declaration_id=authority.declaration
 CROSS JOIN selected_rust_module_placements AS placement
  ON placement.mount_ordinal=source.mount_ordinal
  AND placement.module_declaration IS authority.module_declaration
  AND placement.topology_id=source.topology_id
 CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
 LEFT JOIN resolution_member_owner_properties AS member
  ON member.blob_id=authority.blob_id AND member.definition_semantic_key=authority.semantic_key
 LEFT JOIN resolution_rust_declaration_authorities AS enum_authority
  ON enum_authority.blob_id=member.blob_id AND enum_authority.semantic_key=member.owner_definition_semantic_key
 LEFT JOIN source_declaration_units AS enum_mapping
  ON enum_mapping.blob_id=enum_authority.blob_id AND enum_mapping.declaration_id=enum_authority.declaration
 LEFT JOIN code_units AS enum_unit
  ON enum_unit.blob_id=enum_mapping.blob_id AND enum_unit.unit_key=enum_mapping.unit_key
 WHERE ((source.enum_scope_node_key IS NULL
        AND properties.nearest_declaration_boundary=0
        AND properties.declaration_kind NOT IN (8,9,14)
        AND ((properties.macro_exported=1 AND source.module_path='crate')
             OR (properties.macro_exported<>1 AND placement.container_path=source.module_path)))
       OR (source.enum_scope_node_key IS NOT NULL AND properties.declaration_kind=9
           AND source.module_path=placement.container_path || '::' || enum_unit.identifier))
  AND cr_cfg(properties.cfg_condition,json(owner.cfg_atoms))=1
)
SELECT DISTINCT exports.declaration_blob_id, exports.declaration_site, exports.topology_id, exports.module_path, mount.mount_ordinal, NULL
FROM targets CROSS JOIN rust_crate_exports AS exports ON exports.topology_id=targets.topology_id AND exports.module_path=targets.module_path AND exports.namespace=?3 AND exports.name=targets.name
CROSS JOIN rust_crate_container_sources AS source
 ON source.topology_id=exports.topology_id AND source.blob_id=exports.declaration_blob_id
 AND (source.container_path=exports.module_path OR ?3='macro')
CROSS JOIN temp.selected_resolution_mounts AS mount
 ON mount.storage_language='rust' AND mount.persisted_relative_path=source.rel_path
 AND mount.blob_id=exports.declaration_blob_id
WHERE exports.origin='declaration' AND (exports.visibility='public' OR (targets.topology_id=?5 AND (exports.visibility='crate' OR (exports.visibility='private' AND (?6=exports.module_path OR substr(?6,1,length(exports.module_path)+2)=exports.module_path || '::')) OR (exports.visibility='restricted' AND (?6=exports.restricted_module_path OR substr(?6,1,length(exports.restricted_module_path)+2)=exports.restricted_module_path || '::')))))

UNION
SELECT item.blob_id, NULL, item.topology_id, item.module_path, mount.mount_ordinal, item.declaration_id
FROM targets CROSS JOIN rust_crate_macro_items AS item ON item.topology_id=targets.topology_id AND item.module_path=targets.module_path AND item.namespace=?3 AND item.name=targets.name
CROSS JOIN rust_crate_container_sources AS source
 ON source.topology_id=item.topology_id AND source.blob_id=item.blob_id AND source.container_path=item.module_path
CROSS JOIN temp.selected_resolution_mounts AS mount
 ON mount.storage_language='rust' AND mount.persisted_relative_path=source.rel_path
 AND mount.blob_id=item.blob_id
WHERE item.visibility='public' OR (targets.topology_id=?5 AND (item.visibility='crate' OR (item.visibility='private' AND (?6=item.module_path OR substr(?6,1,length(item.module_path)+2)=item.module_path || '::')) OR (item.visibility='restricted' AND (?6=item.restricted_module_path OR substr(?6,1,length(item.restricted_module_path)+2)=item.restricted_module_path || '::'))))
UNION
SELECT selected_blob,source_site,topology_id,module_path,mount_ordinal,NULL FROM selected_exports AS exports
WHERE cr_visibility(exports.visibility)='public'
 OR (exports.topology_id=?5 AND (
  cr_visibility(exports.visibility)='crate'
  OR (cr_visibility(exports.visibility)='private'
      AND (?6=exports.module_path OR substr(?6,1,length(exports.module_path)+2)=exports.module_path || '::'))
  OR (cr_visibility(exports.visibility)='restricted'
      AND (exports.module_path=exports.restricted_module_path
           OR substr(exports.module_path,1,length(exports.restricted_module_path)+2)=exports.restricted_module_path || '::')
      AND (?6=exports.restricted_module_path OR substr(?6,1,length(exports.restricted_module_path)+2)=exports.restricted_module_path || '::'))))
