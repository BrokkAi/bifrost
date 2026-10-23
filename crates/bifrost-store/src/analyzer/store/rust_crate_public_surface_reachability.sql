-- The digest conservatively retains ambiguous candidates. Membership is a
-- proof: follow only selected public module edges whose binding is unambiguous
-- and available. A different proven path may still reach an ambiguous candidate.
-- UNION deduplicates canonical nodes, so cycles terminate without a depth cap.
WITH RECURSIVE reachable(crate_key, module_path) AS (
  SELECT crate_key, 'crate' FROM cr_identity
  UNION
  SELECT edge.target_crate_key, edge.target_module_path
  FROM reachable
  CROSS JOIN cr_surface_facts AS edge
    ON edge.kind = 'public_module_edge'
   AND edge.crate_key = reachable.crate_key
   AND edge.module_path = reachable.module_path
   AND edge.namespace = 'type'
  WHERE NOT EXISTS (
    SELECT 1 FROM cr_surface_facts AS uncertainty
    WHERE uncertainty.kind IN ('public_module_ambiguous', 'public_module_unavailable')
      AND uncertainty.crate_key = edge.crate_key
      AND uncertainty.module_path = edge.module_path
      AND uncertainty.namespace = 'type'
      AND uncertainty.name = edge.name
  )
)
SELECT crate_key, module_path FROM reachable ORDER BY crate_key, module_path;
