-- Shared predicates for a target's reference-inventory gaps, given the sites its
-- materialization statement (rust_reverse_gap_candidate_sites.sql) kept in
-- temp.selected_rust_reverse_gap_sites. The sites depend only on the target, so
-- they are computed once. The initial locator projection fixes accounted and
-- qualified reference sets to empty; the final certificate projection binds
-- the references and qualified routes that confirmation accounted for.
--
-- Parameters: ?1 target key, ?2 target names (JSON), ?3 qualified-reference gap
-- origin, ?4 local semantic base, ?5 accounted reference sites (JSON),
-- ?6 target owner is a type scope, ?7 callable-reference site kind,
-- ?8 closed qualified reference sites (JSON), ?9 generated-item gap origin,
-- ?10 call-applicability gap origin. The initial locator projection also binds
-- ?11 argument-coercion rule, ?12 primary provenance, ?13 member-reference kind.
WITH raw_gaps(host,reason_key,origin,blob_id,source_site) AS (
  -- The reason and gap joins are CROSS JOIN so the candidate sites drive the
  -- loop: each site seeks its reasons, and each reason seeks its gap rows. A
  -- plain JOIN let the planner scan resolution_gap_reasons_site as the outer
  -- loop, reading every reason row in the workspace per execution.
  SELECT candidate.host,
         :local_base+(candidate.host<<32)+gap.reason,
         reason.origin,candidate.blob_id,reason.site
  FROM temp.selected_rust_reverse_gap_sites AS candidate
  CROSS JOIN main.resolution_gap_reasons AS reason
    INDEXED BY resolution_gap_reasons_site
    ON reason.blob_id=candidate.blob_id AND reason.site=candidate.site
  CROSS JOIN main.resolution_gaps AS gap
    INDEXED BY resolution_gaps_reason_covers
    ON gap.blob_id=reason.blob_id AND gap.reason=reason.reason
   -- A qualified reference whose member name is known keeps its reverse
   -- uncertainty as endpoint coverage keyed by that name (covers 6) instead of
   -- a fragment-wide inventory row (covers 3). The candidate-name join that
   -- built the candidate sites already limits this to sites that can name the
   -- target, so the endpoint row nominates the same reason the inventory row did.
   AND gap.covers IN (0,1,3,6)
  -- GeneratedItemSurface records an additive expansion, not omitted authored
  -- reference sites. Keep its persisted reason and all binding uncertainty,
  -- but do not interpret the provenance-only fallback as missing source
  -- inventory. Actual fragment/enumeration gaps remain obligations.
  -- The covers list is an index constraint (blob, reason, covers), so each
  -- gap row is read only when its covers value can qualify. An OR in the join
  -- predicate kept the planner from seeking on covers.
  WHERE candidate.target_key=?1
    AND NOT (reason.origin=?9 AND gap.covers=3)
    AND (gap.covers<>6 OR reason.origin=?3)
  UNION
  SELECT candidate.host,
         :local_base+(candidate.host<<32)+gap.reason,
         reason.origin,candidate.blob_id,reason.site
  FROM temp.selected_rust_reverse_gap_sites AS candidate
  CROSS JOIN main.resolution_gap_reasons AS reason
    INDEXED BY resolution_gap_reasons_site
    ON reason.blob_id=candidate.blob_id AND reason.site=candidate.site
  CROSS JOIN main.resolution_gaps AS gap
    INDEXED BY resolution_gaps_reason_covers
    ON gap.blob_id=reason.blob_id AND gap.reason=reason.reason
   AND gap.covers=4
  WHERE candidate.target_key=?1
    AND NOT EXISTS (
    SELECT 1
    FROM json_each(?5) AS confirmed
    WHERE confirmed.value->>0=candidate.host
      AND confirmed.value->>1=reason.site
  )
),
-- #11173 removed external_roots: qualified paths with an external root are
-- not discharged. Such gaps stay open, so answers can be incomplete where
-- they could have been complete. No candidate site had an external root on
-- the measured corpora.
-- effective_gaps probes out_of_scope_local_alias_roots once per raw gap.
-- MATERIALIZED computes it once per execution instead of rerunning it as a
-- correlated co-routine; CROSS JOIN keeps the bounded raw gaps driving it.
out_of_scope_local_alias_roots(host,blob_id,source_site,reason_key,origin) AS MATERIALIZED (
  -- A local `use` alias only closes a route inside its lexical extent. A
  -- same-spelled path outside that extent cannot name the imported target.
  SELECT DISTINCT gap.host,gap.blob_id,gap.source_site,gap.reason_key,gap.origin
  FROM raw_gaps AS gap
  CROSS JOIN main.resolution_sites AS reference_site
    ON reference_site.blob_id=gap.blob_id
   AND reference_site.site=gap.source_site
   AND reference_site.role=0
  CROSS JOIN main.resolution_rust_reference_contexts AS context
    ON context.blob_id=gap.blob_id AND context.source_site=gap.source_site
  JOIN temp.selected_rust_container_placements AS placement
    ON placement.mount_ordinal=gap.host
   AND placement.blob_id=gap.blob_id
   AND placement.module_declaration IS context.module_declaration
  JOIN main.resolution_rust_reverse_gap_candidates AS candidate
    INDEXED BY resolution_rust_reverse_gap_candidates_name
    ON candidate.blob_id=gap.blob_id
   AND candidate.site=gap.source_site
   AND candidate.namespace='type'
  JOIN source_rust_import_targets AS inactive
    ON inactive.blob_id=gap.blob_id
   AND inactive.module_path=placement.container_path
   AND inactive.bound_name=candidate.candidate_name
  WHERE (
      gap.origin=?3
      OR (
        -- Invocation applicability cannot make an out-of-scope module alias
        -- name this free function. Close only that exact call reason; macro,
        -- activation and source-inventory obligations remain independent.
        gap.origin=?10
        AND ?6=0 AND json_extract(?2,'$[0][1]')='callable'
        AND NOT EXISTS (
          SELECT 1 FROM json_each(?2) AS seed
          WHERE seed.value->>1<>'callable'
        )
        AND reference_site.site_kind=?7
        AND NOT EXISTS (
          SELECT 1 FROM main.resolution_gaps AS obligation
            INDEXED BY resolution_gaps_reason_covers
          WHERE obligation.blob_id=gap.blob_id
            AND obligation.reason=gap.reason_key-(:local_base+(gap.host<<32))
            AND obligation.covers IN (0,1,3)
        )
      )
    )
    AND inactive.local_start IS NOT NULL
    AND NOT (inactive.local_start<=reference_site.start_byte
             AND reference_site.start_byte<inactive.local_end)
    AND NOT EXISTS (
      SELECT 1
      FROM source_rust_import_targets AS active
      WHERE active.blob_id=gap.blob_id
        AND active.module_path=placement.container_path
        AND active.bound_name=candidate.candidate_name
        AND (active.local_start IS NULL
             OR (active.local_start<=reference_site.start_byte
                 AND reference_site.start_byte<active.local_end))
    )
    AND NOT EXISTS (
      SELECT 1
      FROM source_rust_module_inventory AS module
      WHERE module.blob_id=gap.blob_id
        AND module.parent_scope_ordinal=placement.scope_ordinal
        AND module.module_name=candidate.candidate_name
    )
),
effective_gaps AS (
  SELECT g.reason_key,g.host,g.source_site,g.origin,g.blob_id
  FROM raw_gaps AS g
  -- Each Cargo view retained a binding or concretely closed this route.
  -- Complete empty applicability alone cannot close an unresolved route.
  -- Macro, binder and enumeration gaps remain independent below.
  WHERE NOT (g.origin=?3 AND EXISTS (
    SELECT 1 FROM json_each(?8) AS resolved
    WHERE resolved.value->>0=g.host AND resolved.value->>1=g.source_site
  ))
    AND NOT EXISTS (
    SELECT 1 FROM temp.selected_resolution_stage_closed_reasons AS closed
    WHERE closed.semantic_key=g.reason_key
  )
    AND NOT EXISTS (
    SELECT 1 FROM out_of_scope_local_alias_roots AS outside
    WHERE outside.host=g.host
      AND outside.blob_id=g.blob_id
      AND outside.source_site=g.source_site
      AND outside.reason_key=g.reason_key
      AND outside.origin=g.origin
  )
    AND (
      g.origin=?3
      OR (g.origin<>?3 AND ({effective_gap_remains}))
    )
)
{projection}
