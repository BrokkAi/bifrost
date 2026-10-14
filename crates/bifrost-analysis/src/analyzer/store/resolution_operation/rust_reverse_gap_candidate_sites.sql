-- Materialize each target's host blobs, summary-backed name closure, and candidate sites
-- once. The result feeds the two reference-inventory gap checks for this target.
-- Parameters: ?1 definition mount, ?2 target names (JSON), ?3 admitted (0/1),
-- ?4 admitted fragments (JSON), ?5 member-reference site kind, ?6 target owner
-- is a type scope, ?7 callable-reference site kind, ?8-?12 macro/expression gap
-- origins, ?13 target key.
INSERT INTO temp.selected_rust_reverse_gap_sites(target_key,host,blob_id,site)
WITH RECURSIVE target_scope(topology_id,crate_key,summary_id) AS (
  SELECT placement.topology_id,placement.unit_key,placement.summary_id
  FROM temp.selected_rust_module_placements AS placement
  WHERE placement.mount_ordinal=?1
  UNION
  SELECT importer.topology_id,importer.unit_key,importer.summary_id
  FROM target_scope AS target
  JOIN main.resolution_unit_summary_dependencies AS dependency
    INDEXED BY resolution_unit_summary_dependencies_unit
    ON dependency.dependency_unit_key=target.crate_key
   AND dependency.boundary='workspace'
  JOIN selected_rust_unit_summaries AS importer
    ON importer.summary_id=dependency.summary_id
),
target_hosts(host,topology_id,blob_id,summary_id) AS (
  SELECT DISTINCT placement.mount_ordinal,placement.topology_id,placement.blob_id,placement.summary_id
  FROM target_scope AS scope
  JOIN temp.selected_rust_module_placements AS placement
    ON placement.topology_id=scope.topology_id
  JOIN temp.selected_resolution_scope_mounts AS selected
    ON selected.mount_ordinal=placement.mount_ordinal
  WHERE ?3=0 OR placement.mount_ordinal IN (SELECT value FROM json_each(?4))
  UNION
  SELECT DISTINCT mount.mount_ordinal,NULL,mount.blob_id,NULL
  FROM json_each(?4) AS fragment
  JOIN temp.selected_resolution_scope_mounts AS selected
    ON selected.mount_ordinal=fragment.value
  JOIN temp.selected_resolution_mounts AS mount
    ON mount.mount_ordinal=selected.mount_ordinal
  WHERE ?1 IS NULL
),
target_name_closure(host,name,namespace) AS (
  SELECT host.host,seed.value->>0,seed.value->>1
  FROM target_hosts AS host
  CROSS JOIN json_each(?2) AS seed
  WHERE seed.value->>2 IS NULL OR EXISTS (
    SELECT 1 FROM temp.selected_rust_module_placements AS placement
    WHERE placement.mount_ordinal=host.host
      AND placement.topology_id=seed.value->>2
      AND placement.container_path=seed.value->>3
  )
  UNION
  SELECT names.host,imported.bound_name,names.namespace
  FROM target_name_closure AS names
  CROSS JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN source_imports AS source INDEXED BY idx_source_imports_identifier
    ON source.blob_id=host.blob_id AND source.identifier=names.name
  CROSS JOIN rust_import_targets AS imported INDEXED BY idx_rust_import_targets_source_import
    ON imported.blob_id=source.blob_id AND imported.source_import_id=source.import_id
  WHERE imported.bound_name IS NOT NULL
    AND imported.bound_name<>names.name
    -- Exact reverse discovery already seeds every selected import binding to
    -- this declaration. A bound import of a same-named decoy cannot invent
    -- another alias here; only unresolved imports need the name closure.
    -- Bind the import through its selected canonical module placement: a
    -- file-local `crate` scope can be mounted as `crate::child`.
    AND NOT EXISTS (
      SELECT 1 FROM temp.selected_rust_module_placements AS placement
      JOIN main.rust_resolution_unit_summary_import_routes AS bound
        INDEXED BY rust_resolution_unit_summary_import_routes_site
        ON bound.summary_id=placement.summary_id
       AND bound.member_ordinal=placement.member_ordinal
       AND bound.module_path=placement.container_path
       AND bound.import_id=imported.source_import_id
       AND bound.route_ordinal=imported.ordinal
      WHERE placement.mount_ordinal=host.host
        AND placement.topology_id=host.topology_id
        AND placement.blob_id=host.blob_id
        AND ((names.namespace='type' AND bound.namespace='type')
          OR (names.namespace='macro' AND bound.namespace='macro')
          OR (names.namespace IN ('value','callable','constant') AND bound.namespace='value')
          OR (names.namespace='constructor' AND bound.namespace IN ('type','value')))
    )
  UNION
  SELECT names.host,imported.bound_name,names.namespace
  FROM target_name_closure AS names
  CROSS JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN rust_import_targets AS imported INDEXED BY idx_rust_import_targets_imported_name
    ON imported.blob_id=host.blob_id AND imported.imported_name=names.name
  WHERE imported.source_import_id IS NULL
    AND imported.bound_name IS NOT NULL
    AND imported.bound_name<>names.name
    AND NOT EXISTS (
      SELECT 1 FROM temp.selected_rust_module_placements AS placement
      JOIN main.rust_resolution_unit_summary_import_routes AS bound
        INDEXED BY rust_resolution_unit_summary_import_routes_site
        ON bound.summary_id=placement.summary_id
       AND bound.member_ordinal=placement.member_ordinal
       AND bound.module_path=placement.container_path
       AND bound.import_id=imported.source_import_id
       AND bound.route_ordinal=imported.ordinal
      WHERE placement.mount_ordinal=host.host
        AND placement.topology_id=host.topology_id
        AND placement.blob_id=host.blob_id
        AND ((names.namespace='type' AND bound.namespace='type')
          OR (names.namespace='macro' AND bound.namespace='macro')
          OR (names.namespace IN ('value','callable','constant') AND bound.namespace='value')
          OR (names.namespace='constructor' AND bound.namespace IN ('type','value')))
    )
  UNION
  SELECT names.host,imported.bound_name,names.namespace
  FROM target_name_closure AS names
  CROSS JOIN target_hosts AS host
    ON host.host=names.host
  CROSS JOIN source_imports AS unresolved
    ON unresolved.blob_id=host.blob_id
   AND unresolved.identifier IS NULL
  CROSS JOIN rust_import_targets AS imported INDEXED BY idx_rust_import_targets_unresolved_source_alias
    ON imported.blob_id=unresolved.blob_id
   AND imported.source_import_id=unresolved.import_id
  WHERE imported.bound_name IS NOT NULL
    AND imported.bound_name<>names.name
    AND NOT EXISTS (
      SELECT 1 FROM temp.selected_rust_module_placements AS placement
      JOIN main.rust_resolution_unit_summary_import_routes AS bound
        INDEXED BY rust_resolution_unit_summary_import_routes_site
        ON bound.summary_id=placement.summary_id
       AND bound.member_ordinal=placement.member_ordinal
       AND bound.module_path=placement.container_path
       AND bound.import_id=imported.source_import_id
       AND bound.route_ordinal=imported.ordinal
      WHERE placement.mount_ordinal=host.host
        AND placement.topology_id=host.topology_id
        AND placement.blob_id=host.blob_id
        AND ((names.namespace='type' AND bound.namespace='type')
          OR (names.namespace='macro' AND bound.namespace='macro')
          OR (names.namespace IN ('value','callable','constant') AND bound.namespace='value')
          OR (names.namespace='constructor' AND bound.namespace IN ('type','value')))
    )
  UNION
  SELECT names.host,imported.bound_name,names.namespace
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  JOIN rust_import_targets AS imported INDEXED BY idx_rust_import_targets_unresolved_legacy_alias
    ON imported.blob_id=host.blob_id
   AND imported.source_import_id IS NULL
   AND imported.imported_name IS NULL
  WHERE imported.bound_name IS NOT NULL
    AND imported.bound_name<>names.name
    AND NOT EXISTS (
      SELECT 1 FROM temp.selected_rust_module_placements AS placement
      JOIN main.rust_resolution_unit_summary_import_routes AS bound
        INDEXED BY rust_resolution_unit_summary_import_routes_site
        ON bound.summary_id=placement.summary_id
       AND bound.member_ordinal=placement.member_ordinal
       AND bound.module_path=placement.container_path
       AND bound.import_id=imported.source_import_id
       AND bound.route_ordinal=imported.ordinal
      WHERE placement.mount_ordinal=host.host
        AND placement.topology_id=host.topology_id
        AND placement.blob_id=host.blob_id
        AND ((names.namespace='type' AND bound.namespace='type')
          OR (names.namespace='macro' AND bound.namespace='macro')
          OR (names.namespace IN ('value','callable','constant') AND bound.namespace='value')
          OR (names.namespace='constructor' AND bound.namespace IN ('type','value')))
    )
  UNION
  -- Keep the selected name and host ahead of shared fact rows so alias
  -- discovery seeks both the source name index and the selected blob.
  SELECT names.host,alias_unit.identifier,'type'
  FROM target_name_closure AS names
  CROSS JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN resolution_identities AS identity INDEXED BY resolution_identities_spelling
    ON identity.spelling=names.name
  CROSS JOIN resolution_reference_lookup_identities AS lookup
    INDEXED BY resolution_reference_lookup_identities_identity
    ON lookup.identity_id=identity.id AND lookup.blob_id=host.blob_id
  CROSS JOIN resolution_binding_projections AS projection
    INDEXED BY resolution_binding_projections_output
    ON projection.blob_id=lookup.blob_id
   AND projection.reference=lookup.semantic_key
  CROSS JOIN resolution_underlying_types AS underlying
    INDEXED BY resolution_underlying_types_slot
    ON underlying.blob_id=projection.blob_id
   AND underlying.slot=projection.output_slot
  CROSS JOIN resolution_semantic_sites AS alias_site
    ON alias_site.blob_id=underlying.blob_id
   AND alias_site.semantic_role='definition'
   AND alias_site.semantic_key=underlying.definition
  CROSS JOIN source_native_declaration_bridges AS bridge
    ON bridge.blob_id=alias_site.blob_id
   AND bridge.source_site=alias_site.source_site
  CROSS JOIN source_declaration_units AS alias_declaration
    ON alias_declaration.blob_id=bridge.blob_id
   AND alias_declaration.declaration_id=bridge.declaration_id
  CROSS JOIN code_units AS alias_unit
    ON alias_unit.blob_id=alias_declaration.blob_id
   AND alias_unit.unit_key=alias_declaration.unit_key
   AND alias_unit.is_type_alias=1
  WHERE names.namespace='type'
  UNION
  SELECT names.host,alias_unit.identifier,'type'
  FROM target_name_closure AS names
  CROSS JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN source_rust_type_segments AS terminal
    INDEXED BY source_rust_type_segments_name
    ON terminal.name=names.name AND terminal.blob_id=host.blob_id
  CROSS JOIN source_rust_alias_items AS alias
    ON alias.blob_id=terminal.blob_id
   AND alias.target_type_occurrence_id=terminal.type_occurrence_id
  CROSS JOIN source_rust_type_segments AS root
    ON root.blob_id=terminal.blob_id
   AND root.type_occurrence_id=terminal.type_occurrence_id
   AND root.ordinal=0
  CROSS JOIN main.rust_resolution_unit_summary_dependency_names AS dependency_name
    INDEXED BY rust_resolution_unit_summary_dependency_names_extern
    ON dependency_name.summary_id=host.summary_id
   AND dependency_name.extern_name=root.name
  CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
    ON dependency.summary_id=dependency_name.summary_id
   AND dependency.dependency_ordinal=dependency_name.dependency_ordinal
  CROSS JOIN target_scope AS reachable
    ON reachable.crate_key=dependency.dependency_unit_key
  CROSS JOIN source_declaration_units AS alias_declaration
    ON alias_declaration.blob_id=alias.blob_id
   AND alias_declaration.declaration_id=alias.declaration_id
  CROSS JOIN code_units AS alias_unit
    ON alias_unit.blob_id=alias_declaration.blob_id
   AND alias_unit.unit_key=alias_declaration.unit_key
   AND alias_unit.is_type_alias=1
  WHERE names.namespace='type'
    AND terminal.ordinal>0
),
candidate_sites_unfiltered(host,blob_id,site) AS (
  -- The name-keyed branches use CROSS JOIN so the name closure drives the loop
  -- and each name seeks the candidate name index. A plain JOIN let the planner
  -- scan that index once per branch with a bloom filter on the names. The
  -- wildcard branches below key on the constant '*' and keep their order.
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.candidate_name=names.name
   AND candidate.blob_id=host.blob_id
   AND candidate.namespace=names.namespace
  UNION
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.candidate_name=names.name
   AND candidate.blob_id=host.blob_id
   AND candidate.namespace='*'
  UNION
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.candidate_name=names.name
   AND candidate.blob_id=host.blob_id
   AND names.namespace='callable'
   AND candidate.namespace='value'
  UNION
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  CROSS JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.candidate_name=names.name
   AND candidate.blob_id=host.blob_id
   AND candidate.namespace='type_or_value'
  WHERE names.namespace IN ('type','value','callable','constructor')
  UNION
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.blob_id=host.blob_id
   AND candidate.candidate_name='*' AND candidate.namespace='*'
  JOIN main.rust_identifier_occurrences AS occurrence
    ON occurrence.blob_id=host.blob_id
   AND occurrence.identifier=names.name
   AND (occurrence.context_mask & 1)<>0
  UNION
  -- An unexpanded macro frontier can synthesize a reference without spelling
  -- the target in its input. Expression-position macros are recorded as
  -- UnsupportedExpression. Keep these typed frontiers even when the name
  -- index has no target occurrence; ordinary nameless gaps stay name-scoped.
  SELECT names.host,candidate.blob_id,candidate.site
  FROM target_name_closure AS names
  JOIN target_hosts AS host ON host.host=names.host
  JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.blob_id=host.blob_id
   AND candidate.candidate_name='*' AND candidate.namespace='*'
  JOIN main.resolution_gap_reasons AS reason
    INDEXED BY resolution_gap_reasons_site
    ON reason.blob_id=candidate.blob_id
   AND reason.site=candidate.site
  -- The wildcard exception is for an explicit macro invocation whose input
  -- may synthesize a target identifier. Broader binder/scope gaps, such as an
  -- attribute macro on another item, stay scoped by the candidate names above.
  JOIN main.source_rust_macro_inputs AS input
    ON input.blob_id=candidate.blob_id
   AND input.native_gap_site=candidate.site
  WHERE reason.origin IN (?8,?9,?10,?11,?12)
),
candidate_sites(host,blob_id,site) AS (
  -- A member call cannot name a free function. Conversely, a method target
  -- cannot be named by an unqualified callable reference. Keep malformed or
  -- recovered sites whose shape is missing; only exclude a structured shape
  -- that proves the candidate belongs to the other call form.
  SELECT DISTINCT candidate.host,candidate.blob_id,candidate.site
  FROM candidate_sites_unfiltered AS candidate
  LEFT JOIN main.resolution_sites AS source_site
    ON source_site.blob_id=candidate.blob_id
   AND source_site.site=candidate.site
   AND source_site.role=0
  WHERE source_site.site IS NULL
     OR (?6=0 AND source_site.site_kind IS NOT ?5)
     OR (?6=1 AND (source_site.site_kind IS NOT ?7 OR source_site.unqualified IS NOT 1))
)
SELECT ?13,candidate.host,candidate.blob_id,candidate.site
FROM candidate_sites AS candidate;
