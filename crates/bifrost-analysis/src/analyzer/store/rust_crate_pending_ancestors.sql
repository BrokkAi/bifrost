-- One source-only wave's pending dependency ancestors. The source-only scope
-- preserves Cargo dependency inputs, so the selected previous topology rows
-- describe the current dependency graph even through seeded complete facades.
-- UNION deduplicates (origin, crate_key), making cycles finite.
WITH RECURSIVE ancestors(origin, crate_key) AS (
    SELECT crate_key, crate_key FROM temp.rust_crate_pending_keys
    UNION
    SELECT ancestors.origin, dependencies.dependency_crate_key
    FROM ancestors
    CROSS JOIN rust_crate_versions AS versions
    CROSS JOIN rust_crate_dependencies AS dependencies
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
      AND versions.generation = ?2 AND versions.crate_key = ancestors.crate_key
      AND versions.valid_from <= ?3
      AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
      AND dependencies.topology_id = versions.topology_id
      AND dependencies.dependency_crate_key IS NOT NULL
)
SELECT DISTINCT ancestors.origin
FROM ancestors
CROSS JOIN temp.rust_crate_pending_keys AS origin
CROSS JOIN temp.rust_crate_pending_keys AS pending
WHERE origin.crate_key = ancestors.origin
  AND pending.crate_key = ancestors.crate_key
  -- Direct readiness and the existing SCC forcing path own internal edges.
  AND pending.component_key <> origin.component_key
