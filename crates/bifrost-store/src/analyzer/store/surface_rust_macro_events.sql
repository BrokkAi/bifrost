-- Rank semantic events at every ancestor context as well as their direct
-- owner. This retains the relative order of a definition and an invocation in
-- a nested block, without turning ordinary body blocks/statements into events.
-- Ordinary Other=2 invocations never enter this order. Their existing
-- unconditional expansion seeds remain until unfiltered readers are rewritten.
-- Verified include edges are mounts even in expression positions: today's
-- module walk mounts them without a position filter. Narrowing this exception
-- belongs with the consumer rewrite and its read-guard proof.
-- Other currently also includes block statement macros that can declare items;
-- correcting that producer classification is separate from this projection.
-- Only a module context can lack a parent (the file root has none), so only
-- a module event may be dropped for a NULL context. Definitions and
-- invocations always have a source context (the reader treats NULL as
-- corruption); one that arrives with NULL is kept so the surface refuses it
-- as an unknown owner instead of losing the event.
WITH RECURSIVE events(blob_id, context, event, event_kind, position, definition) AS (
  SELECT definition.blob_id, definition.context_occurrence_id, declaration.occurrence_id,
         'definition', declaration.end_byte, definition.declaration_id
  FROM main.source_rust_macro_definitions AS definition
  JOIN main.source_declarations AS declaration USING(blob_id, declaration_id)
  WHERE definition.blob_id=?1
  UNION ALL
  SELECT expansion.blob_id, expansion.context_occurrence_id, expansion.invocation_occurrence_id,
         CASE WHEN EXISTS(SELECT 1 FROM main.rust_include_edges AS include_edge
                          WHERE include_edge.blob_id=expansion.blob_id
                            AND include_edge.invocation_occurrence_id=expansion.invocation_occurrence_id)
              THEN 'include' ELSE 'invocation' END, expansion.invocation_start_byte, NULL
  FROM main.source_rust_item_macro_expansions AS expansion
  WHERE expansion.blob_id=?1
    AND (expansion.source_position IN (0, 1)
         OR EXISTS(SELECT 1 FROM main.rust_include_edges AS include_edge
                   WHERE include_edge.blob_id=expansion.blob_id
                     AND include_edge.invocation_occurrence_id=expansion.invocation_occurrence_id))
  UNION ALL
  SELECT module.blob_id, context.parent_occurrence_id, declaration.occurrence_id,
         'module', declaration.start_byte, module.declaration_id
  FROM main.source_rust_module_declarations AS module
  JOIN main.source_declarations AS declaration USING(blob_id, declaration_id)
  JOIN main.source_rust_item_contexts AS context
    ON context.blob_id=module.blob_id AND context.owner_declaration_id=module.declaration_id
   AND context.context_kind=1
  WHERE module.blob_id=?1
), contained(blob_id, context, event, event_kind, position, definition) AS (
  SELECT * FROM events WHERE context IS NOT NULL OR event_kind<>'module'
  UNION
  SELECT contained.blob_id, context.parent_occurrence_id, contained.event, contained.event_kind,
         contained.position, contained.definition
  FROM contained
  JOIN main.source_rust_item_contexts AS context
    ON context.blob_id=contained.blob_id AND context.occurrence_id=contained.context
  WHERE context.parent_occurrence_id IS NOT NULL
)
SELECT blob_id, context, event, event_kind,
       dense_rank() OVER (PARTITION BY blob_id, context ORDER BY position)-1 AS order_in_context,
       definition
FROM contained
