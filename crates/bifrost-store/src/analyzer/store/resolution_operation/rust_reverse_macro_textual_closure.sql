-- Whether unqualified macro invocation ?2 of blob ?1, mounted at selection
-- ordinal ?4, names the target of exactly one named import of ?3 with no
-- textual-scope macro that could stand between them (#6140).
--
-- A `macro_rules!` in textual scope wins over a `use` import of the same
-- name, and a macro- or attribute-expanded definition can introduce one this
-- store never names. The invocation is closed only when every source of
-- textual scope that reaches it is known to define nothing:
--
-- * Every enclosing context is primary source without parser errors, and
--   published its expanding attributes (NULL is a row from an older producer
--   and proves nothing).
-- * No enclosing context holds an expanding attribute, a macro invocation or
--   an authored macro definition other than a differently named one before
--   the invocation. Textual scope flows only forward from such an item, and a
--   sibling body's items cannot reach this one. An attribute on an enclosing
--   item precedes the invocation, so it is covered too. `macro_use` counts as
--   expanding: it imports a child's or crate's textual macros.
-- * The file is a declared crate root in every selected crate that compiles
--   it, so no parent module's textual scope flows in. A child module or an
--   included file stays open.
-- * Exactly one import of ?3 is declared in the enclosing contexts up to the
--   nearest module, and it is a non-glob, unconditional `use` with a
--   qualified path.
--
-- ?5 and ?6 are the macro source-fact and macro context versions.
WITH RECURSIVE
invocation AS (
  SELECT expansion.context_occurrence_id AS context,
         expansion.invocation_start_byte AS start_byte
  FROM source_rust_item_macro_expansions AS expansion
  WHERE expansion.blob_id=?1 AND expansion.invocation_occurrence_id=?2
),
chain(occurrence_id, parent_occurrence_id, context_kind, provenance,
      expanding_attribute_starts, depth) AS (
  SELECT context.occurrence_id, context.parent_occurrence_id, context.context_kind,
         context.provenance, context.expanding_attribute_starts, 0
  FROM invocation
  CROSS JOIN source_rust_item_contexts AS context
    ON context.blob_id=?1 AND context.occurrence_id=invocation.context
  UNION ALL
  SELECT context.occurrence_id, context.parent_occurrence_id, context.context_kind,
         context.provenance, context.expanding_attribute_starts, chain.depth + 1
  FROM chain
  CROSS JOIN source_rust_item_contexts AS context
    ON context.blob_id=?1 AND context.occurrence_id=chain.parent_occurrence_id
),
-- Path-based scope ends at the nearest module or file root (kinds 1 and 0).
path_scope AS (
  SELECT occurrence_id FROM chain
  WHERE depth <= (SELECT min(depth) FROM chain WHERE context_kind IN (0, 1))
),
imports AS (
  SELECT target.is_glob, target.is_extern_crate, target.is_macro_use,
         target.cfg_condition, target.module_path
  FROM source_rust_import_targets AS target
  CROSS JOIN source_rust_item_import_contexts AS import_context
    ON import_context.blob_id=target.blob_id
   AND import_context.declaration_occurrence_id=target.declaration_occurrence_id
  WHERE target.blob_id=?1 AND target.bound_name=?3
    AND import_context.context_occurrence_id IN (SELECT occurrence_id FROM path_scope)
),
placements AS (
  SELECT attribute.placement, attribute.source_kind
  FROM temp.selected_resolution_mounts AS mount
  CROSS JOIN main.resolution_unit_summary_members AS member
    INDEXED BY resolution_unit_summary_members_blob
    ON member.blob_id=mount.blob_id AND member.rel_path=mount.persisted_relative_path
  CROSS JOIN selected_rust_unit_summaries AS unit
    ON unit.summary_id=member.summary_id
  LEFT JOIN main.rust_resolution_unit_summary_placement_attributes AS attribute
    ON attribute.summary_id=member.summary_id
   AND attribute.member_ordinal=member.member_ordinal
  WHERE mount.mount_ordinal=?4 AND mount.blob_id=?1
)
SELECT EXISTS (SELECT 1 FROM invocation)
  AND EXISTS (
    SELECT 1 FROM source_rust_item_manifests AS manifest
    WHERE manifest.blob_id=?1
      AND manifest.macro_facts_version=?5 AND manifest.macro_contexts_version=?6
  )
  AND EXISTS (SELECT 1 FROM chain WHERE parent_occurrence_id IS NULL AND context_kind=0)
  AND NOT EXISTS (
    SELECT 1 FROM chain
    WHERE provenance<>0 OR expanding_attribute_starts IS NULL
  )
  AND NOT EXISTS (
    SELECT 1 FROM chain
    LEFT JOIN source_rust_item_syntax AS syntax
      ON syntax.blob_id=?1 AND syntax.occurrence_id=chain.occurrence_id
    WHERE syntax.has_error IS NOT 0
  )
  AND NOT EXISTS (
    SELECT 1 FROM chain
    CROSS JOIN json_each(chain.expanding_attribute_starts) AS hazard
    CROSS JOIN invocation
    WHERE hazard.value < invocation.start_byte
  )
  AND NOT EXISTS (
    SELECT 1 FROM chain
    CROSS JOIN source_rust_item_macro_expansions AS earlier
      INDEXED BY source_rust_item_macro_expansions_fk_context_occurrence_id
      ON earlier.context_occurrence_id=chain.occurrence_id AND earlier.blob_id=?1
    CROSS JOIN invocation
    WHERE earlier.invocation_start_byte < invocation.start_byte
  )
  AND NOT EXISTS (
    SELECT 1 FROM chain
    CROSS JOIN source_rust_macro_definitions AS definition
      INDEXED BY source_rust_macro_definitions_fk_context_occurrence_id
      ON definition.context_occurrence_id=chain.occurrence_id AND definition.blob_id=?1
    CROSS JOIN source_declarations AS declaration
      ON declaration.blob_id=definition.blob_id
     AND declaration.declaration_id=definition.declaration_id
    CROSS JOIN invocation
    WHERE declaration.start_byte < invocation.start_byte
      AND NOT EXISTS (
        SELECT 1 FROM source_rust_item_macros AS named
        WHERE named.blob_id=definition.blob_id
          AND named.declaration_id=definition.declaration_id
          AND named.macro_name<>?3
      )
  )
  AND EXISTS (SELECT 1 FROM placements)
  AND NOT EXISTS (
    SELECT 1 FROM placements
    WHERE placement IS NOT 'root' OR source_kind IS NOT 'declared'
  )
  AND (SELECT count(*) FROM imports)=1
  AND EXISTS (
    SELECT 1 FROM imports
    WHERE is_glob=0 AND is_extern_crate=0 AND is_macro_use=0
      AND cfg_condition='always' AND module_path<>''
  )
