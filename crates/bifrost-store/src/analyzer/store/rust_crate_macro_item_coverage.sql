-- The decided invocations every item of which is accounted for, so their
-- module's export inventory can close.
--
-- `rust_crate_open_inventory.sql` keeps a module's inventory open while one of
-- its item-position invocations may add a name no export row records. A
-- decided invocation adds exactly its expansion's items, with the activation
-- its decoration and each item's own `cfg` give them. It is accounted for when:
--
-- - it is written in an `impl` or trait body, whose items are members of that
--   body and add no name to the module; or
-- - it is written at module level and every direct item of its expansion is
--   either inactive or declared by a `rust_crate_macro_items` row
--   (`declarable` and active in `cr_macro_item_candidates`, which follows the
--   bodies of the inline modules the expansion writes), and the expansion
--   holds nothing a row cannot account for, at any depth of its range: no item
--   whose activation is unknown, no `use` or `extern crate`, no
--   `macro_rules!`, no nested invocation, and no syntax error.
--
-- Anything else keeps the inventory open, with `decided` true in its
-- evidence. The exclusions read the rows the producer records for each of
-- those item kinds under the expansion's root context; an item kind the
-- producer records nowhere is not recognized here.
INSERT INTO cr_macro_item_covered(blob_id, invocation_occurrence_id)
SELECT expansion.blob_id, expansion.invocation_occurrence_id
FROM cr_item_macro_decisions AS decision
CROSS JOIN source_rust_item_macro_expansions AS expansion
  ON expansion.blob_id = decision.blob_id
 AND expansion.invocation_occurrence_id = decision.invocation_occurrence_id
CROSS JOIN source_rust_item_contexts AS host
  ON host.blob_id = expansion.blob_id
 AND host.occurrence_id = expansion.context_occurrence_id
LEFT JOIN source_rust_item_contexts AS body_owner
  ON host.context_kind = 6
 AND body_owner.blob_id = host.blob_id
 AND body_owner.occurrence_id = host.parent_occurrence_id
WHERE expansion.expansion_kind = 0
  AND (host.context_kind IN (2, 3) OR body_owner.context_kind IN (2, 3)
       OR (((host.context_kind = 0 AND host.parent_occurrence_id IS NULL)
            OR host.context_kind = 1 OR body_owner.context_kind = 1)
           AND NOT EXISTS (SELECT 1 FROM cr_macro_item_candidates AS item
                           WHERE item.blob_id = expansion.blob_id
                             AND item.invocation_occurrence_id = expansion.invocation_occurrence_id
                             AND (item.activation = -1
                                  OR (item.activation = 1 AND item.declarable = 0)))
           -- The module-level contexts of the expansion: its root, and the
           -- body of each inline module in it. A `use`, `macro_rules!` or
           -- item-position invocation there adds a name no row records; one
           -- inside a function body does not.
           AND NOT EXISTS (SELECT 1 FROM source_rust_item_contexts AS context
                           LEFT JOIN source_rust_item_contexts AS owner
                             ON context.context_kind = 6
                            AND owner.blob_id = context.blob_id
                            AND owner.occurrence_id = context.parent_occurrence_id
                           WHERE context.blob_id = expansion.blob_id
                             AND context.start_byte >= expansion.invocation_start_byte
                             AND context.end_byte <= expansion.invocation_end_byte
                             AND (context.occurrence_id = expansion.root_occurrence_id
                                  OR owner.context_kind = 1)
                             AND (EXISTS (SELECT 1 FROM source_rust_item_macro_expansions AS nested
                                          WHERE nested.blob_id = context.blob_id
                                            AND nested.context_occurrence_id = context.occurrence_id)
                                  OR EXISTS (SELECT 1 FROM source_rust_item_import_contexts AS import
                                             WHERE import.blob_id = context.blob_id
                                               AND import.context_occurrence_id = context.occurrence_id)
                                  OR EXISTS (SELECT 1 FROM source_rust_macro_definitions AS definition
                                             WHERE definition.blob_id = context.blob_id
                                               AND definition.context_occurrence_id = context.occurrence_id)))
           AND NOT EXISTS (SELECT 1 FROM source_rust_item_syntax AS syntax
                           WHERE syntax.blob_id = expansion.blob_id
                             AND syntax.occurrence_id = expansion.root_occurrence_id
                             AND syntax.has_error = 1)));
