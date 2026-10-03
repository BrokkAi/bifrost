-- Every item a decided passthrough invocation's expansion writes at module
-- level, as a candidate for a crate-level declaration.
--
-- A per-file producer declares an invocation's items (one declaration per
-- source item, bridged to a definition site) only when the macro is defined
-- in the same file and its rules expand to their arguments and nothing else.
-- Every other decided invocation's items are the crate's to declare: when the
-- macro is defined in another file (tokio's `cfg_*` shape), the invoking file
-- cannot see the definition, because its facts are content-addressed and must
-- not depend on another file; when the rules add a `cfg` to each item, the
-- file's producer does not record what they add. The crate decides the
-- invocation in `rust_crate_item_macro_decisions.sql` with every member file
-- in view, and a decided invocation carries its definition's decoration: the
-- activation the rules add to each replayed item, `always` when they add
-- nothing. An invocation whose rules add anything other than a `cfg` is not
-- decided and has no candidates.
--
-- This writes one candidate per item of the expansion -- its direct items and
-- the items of every inline module it writes, at that module's path -- for a
-- decided
-- invocation written at module level (the file root or an inline module; not
-- an `impl` or trait body, whose items are members, and not another
-- expansion's root, whose own level this does not follow) whose items the file
-- left behind its frontier. `MACRO_ITEM_ROWS_SQL` declares the active ones and
-- `rust_crate_macro_item_coverage.sql` decides whether every item of the
-- invocation is accounted for.
--
-- The item's identity is the declaration replay already made for it in the
-- invoking file (`blob_id`, `declaration_id`), which carries its `CodeUnit`;
-- its name is that unit's identifier. Its activation combines replay's
-- declaration `cfg`, which already includes the invocation's own
-- (`record_embedded`), with the decoration, as `cr_cfg` states each: 1 active,
-- 0 inactive, -1 unknown. `value_constructor` marks a tuple or unit struct,
-- which a module exports in the value namespace as well as the type
-- namespace. `declarable` says whether a row can name the item:
-- a kind a module exports, at the item's own declaration boundary, with a
-- `CodeUnit` and a resolvable restriction.
--
-- `?1` is the crate's cfg atom set, as `rust_crate_source_declarations.sql`
-- takes it.
WITH RECURSIVE decided AS (
  SELECT expansion.blob_id, expansion.invocation_occurrence_id,
         expansion.root_occurrence_id, member.module_path, decision.decoration_cfg
  FROM cr_item_macro_decisions AS decision
  CROSS JOIN source_rust_item_macro_expansions AS expansion
    ON expansion.blob_id = decision.blob_id
   AND expansion.invocation_occurrence_id = decision.invocation_occurrence_id
  CROSS JOIN source_rust_macro_inputs AS input
    ON input.blob_id = expansion.blob_id
   AND input.invocation_occurrence_id = expansion.invocation_occurrence_id
  -- The context the invocation is written in: the file root, or the body
  -- (`DeclarationBody`) of the item that owns it, a module, trait or `impl`.
  CROSS JOIN source_rust_item_contexts AS host
    ON host.blob_id = expansion.blob_id
   AND host.occurrence_id = expansion.context_occurrence_id
  LEFT JOIN source_rust_item_contexts AS body_owner
    ON host.context_kind = 6
   AND body_owner.blob_id = host.blob_id
   AND body_owner.occurrence_id = host.parent_occurrence_id
  CROSS JOIN cr_members AS member
    ON member.blob_id = expansion.blob_id
   AND member.scope_ordinal = COALESCE((
     SELECT inner_module.scope_ordinal
     FROM cr_scopes AS inner_module
     WHERE inner_module.blob_id = expansion.blob_id
       AND expansion.invocation_start_byte >= inner_module.start_byte
       AND expansion.invocation_end_byte <= inner_module.end_byte
     ORDER BY inner_module.start_byte DESC
     LIMIT 1
   ), 0)
  WHERE expansion.expansion_kind = 0
    AND input.native_gap_site IS NOT NULL
    AND ((host.context_kind = 0 AND host.parent_occurrence_id IS NULL)
         OR host.context_kind = 1 OR body_owner.context_kind = 1)
), containers(blob_id, invocation_occurrence_id, context_occurrence_id, module_path,
               decoration_cfg) AS (
  -- The expansion's root, and the body of every inline module the expansion
  -- writes, with the module path the module walk placed it at. A body is only
  -- followed into a module the walk placed (`cr_members`), so no row names a
  -- container that does not exist.
  SELECT decided.blob_id, decided.invocation_occurrence_id, decided.root_occurrence_id,
         decided.module_path, decided.decoration_cfg
  FROM decided
  UNION ALL
  SELECT containers.blob_id, containers.invocation_occurrence_id, body.occurrence_id,
         placed.module_path, containers.decoration_cfg
  FROM containers
  CROSS JOIN source_rust_item_contexts AS module
    ON module.parent_occurrence_id = containers.context_occurrence_id
   AND module.blob_id = containers.blob_id AND module.context_kind = 1
  CROSS JOIN source_rust_item_contexts AS body
    ON body.parent_occurrence_id = module.occurrence_id
   AND body.blob_id = module.blob_id AND body.context_kind = 6
  CROSS JOIN source_rust_module_declarations AS declaration
    ON declaration.blob_id = module.blob_id
   AND declaration.declaration_id = module.owner_declaration_id
  CROSS JOIN cr_members AS placed
    ON placed.blob_id = containers.blob_id
   AND placed.module_path = containers.module_path || '::' || declaration.module_name
), items(blob_id, invocation_occurrence_id, module_path, decoration_cfg, declaration_id) AS (
  SELECT containers.blob_id, containers.invocation_occurrence_id, containers.module_path,
         containers.decoration_cfg, item.declaration_id
  FROM containers CROSS JOIN source_rust_callable_items AS item
    ON item.context_occurrence_id = containers.context_occurrence_id
   AND item.blob_id = containers.blob_id
  UNION
  SELECT containers.blob_id, containers.invocation_occurrence_id, containers.module_path,
         containers.decoration_cfg, item.declaration_id
  FROM containers CROSS JOIN source_rust_value_items AS item
    ON item.context_occurrence_id = containers.context_occurrence_id
   AND item.blob_id = containers.blob_id
  UNION
  SELECT containers.blob_id, containers.invocation_occurrence_id, containers.module_path,
         containers.decoration_cfg, item.declaration_id
  FROM containers CROSS JOIN source_rust_alias_items AS item
    ON item.context_occurrence_id = containers.context_occurrence_id
   AND item.blob_id = containers.blob_id
  UNION
  SELECT containers.blob_id, containers.invocation_occurrence_id, containers.module_path,
         containers.decoration_cfg, context.owner_declaration_id
  FROM containers CROSS JOIN source_rust_item_contexts AS context
    ON context.parent_occurrence_id = containers.context_occurrence_id
   AND context.blob_id = containers.blob_id
  -- A module, trait, function or type body is owned by the item that declares
  -- it. An `impl` block's context is owned by the type it implements, which the
  -- block does not declare, and the block declares no name of its own.
  WHERE context.context_kind IN (1, 2, 4, 7)
), activation AS (
  SELECT items.*, properties.declaration_kind, properties.nearest_declaration_boundary,
         properties.visibility,
         properties.constructor_non_exhaustive IS NOT NULL AS value_constructor,
         cr_cfg(properties.cfg_condition, ?1) AS own, cr_cfg(items.decoration_cfg, ?1) AS added
  FROM items
  CROSS JOIN source_rust_declaration_properties AS properties
    ON properties.blob_id = items.blob_id AND properties.declaration_id = items.declaration_id
)
INSERT INTO cr_macro_item_candidates(blob_id, invocation_occurrence_id, module_path,
                                     declaration_id, declaration_kind, value_constructor, name,
                                     visibility, restricted_module_path, activation, declarable)
SELECT activation.blob_id, activation.invocation_occurrence_id, activation.module_path,
       activation.declaration_id, activation.declaration_kind, activation.value_constructor,
       unit.identifier,
       cr_visibility(activation.visibility),
       (SELECT restriction.restricted_module_path FROM cr_restrictions AS restriction
         WHERE restriction.module_path = activation.module_path
           AND restriction.visibility = activation.visibility),
       CASE WHEN activation.own = 0 OR activation.added = 0 THEN 0
            WHEN activation.own = -1 OR activation.added = -1 THEN -1
            ELSE 1 END,
       activation.nearest_declaration_boundary = 0
       AND activation.declaration_kind IN (0, 1, 2, 3, 4, 5, 6, 10, 11, 13)
       AND unit.identifier IS NOT NULL
       AND (cr_visibility(activation.visibility) <> 'restricted'
            OR EXISTS(SELECT 1 FROM cr_restrictions AS restriction
                      WHERE restriction.module_path = activation.module_path
                        AND restriction.visibility = activation.visibility
                        AND restriction.restricted_module_path IS NOT NULL))
FROM activation
LEFT JOIN source_declaration_units AS mapping
  ON mapping.blob_id = activation.blob_id AND mapping.declaration_id = activation.declaration_id
LEFT JOIN code_units AS unit
  ON unit.blob_id = mapping.blob_id AND unit.unit_key = mapping.unit_key
WHERE true
ON CONFLICT DO NOTHING;
