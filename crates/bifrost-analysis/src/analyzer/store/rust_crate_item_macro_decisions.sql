-- Decide the item-position `macro_rules!` invocations this crate's member
-- files carry. A row records either a passthrough route or a proven route
-- absence; all other invocations remain open.
--
-- Decided item passthrough: the matcher proved every rule replays each of its
-- item arguments exactly once, at the repetition depth the matcher bound it
-- at, and every token a rule adds is a `cfg` attribute on the replayed item
-- (or a documentation attribute, which adds nothing). The passthrough proof
-- alone is weaker: `item_passthrough_classifier_requires_a_safe_matcher_and_faithful_replay`
-- in `crates/bifrost-rust/src/declarations.rs` pins that `$( #[cfg(any())]
-- $item )*` and `$( #[$meta] $item )*` are passthroughs. The first is decided
-- here, with the encoded empty `any()` predicate, which no profile activates;
-- the second is not, because `$meta` can be anything. The Cargo route index
-- (`cargo_routes.rs::module_child_edges`) still admits a route on the
-- passthrough proof alone and does not evaluate the decoration.
--
-- Proven to declare no item: a definite expansion that adds no names. Same-file
-- lowering proves selected no-item arms by leaving no native gap. The
-- all-rules `declares_no_item` property remains persisted on the definition.
--
-- A local matcher can also prove that an invocation creates no item: its
-- selected arm declares nothing, or no arm matches. Such a source invocation
-- has no native gap site. An unqualified invocation with no gap and no
-- passthrough route is therefore closed. A same-named source `macro_rules!`
-- can separately prove an unavailable unqualified name when it is defined in
-- this crate but not visible at the invocation and no import, macro-use
-- module, macro prelude, or `macro_export` candidate can supply it. These
-- rows use the encoded empty `any()` predicate so the module walk drops their
-- routes, while `no_route` keeps them out of macro-expansion coverage.
--
-- Undecided: no same-named local definition can establish an absent binding,
-- or an import/prelude could supply it; equally, a visible definition the
-- matcher did not prove to be a passthrough. `macro_rules! make { () => {
-- pub fn generated() {} } }` is visible and is not a passthrough, and it does
-- declare an item, so calling it decided closed its module's export inventory
-- on no proof at all. Such an invocation leaves inventory open and a `mod
-- child;` route at unknown activation.
--
-- A `mod child;` written inside such an invocation is a module route with one
-- gate per enclosing invocation; the route is active when every gate is
-- decided and every gate's decoration is active.
--
-- Each passthrough row carries the visible definition's decoration: the
-- activation its rules add to each item they replay, encoded like an item's
-- `cfg_condition` (`always` when they add nothing). A definition whose rules
-- add anything other than a `cfg` attribute has no decoration
-- (`source_rust_item_macros.decoration_cfg` is NULL), and its invocations are
-- not decided: the expansion is still the arguments' items, but what else it
-- adds, or under which activation, has no row. The module walk evaluates the
-- decoration on a gated `mod` route, and crate derivation evaluates it on
-- every item it declares (`rust_crate_macro_items.sql`).
--
-- `?1` is a JSON array of `[child_blob, mount_blob, mount_start]`, the file
-- mount edges the module walk produced, and `?2` a JSON array of the member
-- blob ids. Textual `macro_rules!` scoping runs down that tree: a definition
-- visible in the mounting file at the `mod` declaration is visible throughout
-- the mounted file, so the nearest ancestor that defines the name wins. Within
-- one file the latest definition in the innermost scope wins, as Rust's
-- textual scoping has it; the invoking file's own definitions are distance 0.
--
-- Scoping also runs up the tree. `#[macro_use] mod child;` keeps the
-- `macro_rules!` definitions written at the top level of the child's file in
-- scope after the `mod` item ends, in the module that declares it (Rust
-- Reference, "The `macro_use` attribute"), and a `#[macro_use]` mount of that
-- module carries them one level further up. `exported` holds those
-- definitions as the mounting file sees them: visible after the `mod` item,
-- in the innermost inline module around it or else the whole file. They then
-- scope like the mounting file's own definitions, down into files it mounts
-- later and onto its own invocations.
WITH RECURSIVE
mounts(child_blob, mount_blob, mount_start) AS (
  SELECT edge.value ->> 0, edge.value ->> 1, edge.value ->> 2 FROM json_each(?1) AS edge
),
macro_use_mounts(child_blob, mount_blob, visible_after, scope_start, scope_end) AS (
  SELECT mount.child_blob, mount.mount_blob, placed.end_byte,
         COALESCE((SELECT enclosing.body_start_byte
                   FROM source_rust_module_declarations AS enclosing
                   WHERE enclosing.blob_id = mount.mount_blob
                     AND enclosing.body_start_byte <= mount.mount_start
                     AND mount.mount_start < enclosing.body_end_byte
                   ORDER BY enclosing.body_start_byte DESC LIMIT 1), 0),
         COALESCE((SELECT enclosing.body_end_byte
                   FROM source_rust_module_declarations AS enclosing
                   WHERE enclosing.blob_id = mount.mount_blob
                     AND enclosing.body_start_byte <= mount.mount_start
                     AND mount.mount_start < enclosing.body_end_byte
                   ORDER BY enclosing.body_start_byte DESC LIMIT 1), 9223372036854775807)
  FROM mounts AS mount
  CROSS JOIN source_declarations AS placed
    ON placed.blob_id = mount.mount_blob AND placed.start_byte = mount.mount_start
  CROSS JOIN source_rust_module_declarations AS module
    ON module.blob_id = placed.blob_id AND module.declaration_id = placed.declaration_id
   AND module.body_occurrence_id IS NULL AND module.macro_use = 1
),
exported(blob_id, macro_name, passthrough, decoration_cfg, scope_start, scope_end,
         visible_after, depth) AS (
  SELECT use_mount.mount_blob, macro.macro_name, macro.passthrough, macro.decoration_cfg,
         use_mount.scope_start, use_mount.scope_end, use_mount.visible_after, 1
  FROM macro_use_mounts AS use_mount
  CROSS JOIN rust_item_macros AS macro ON macro.blob_id = use_mount.child_blob
  WHERE EXISTS (SELECT 1 FROM source_rust_item_contexts AS root
                WHERE root.blob_id = macro.blob_id AND root.context_kind = 0
                  AND root.parent_occurrence_id IS NULL
                  AND root.start_byte = macro.scope_start AND root.end_byte = macro.scope_end)
  UNION ALL
  SELECT use_mount.mount_blob, child.macro_name, child.passthrough, child.decoration_cfg,
         use_mount.scope_start, use_mount.scope_end, use_mount.visible_after, child.depth + 1
  FROM exported AS child
  CROSS JOIN macro_use_mounts AS use_mount ON use_mount.child_blob = child.blob_id
  WHERE child.depth < 256
),
inherited(blob_id, macro_name, passthrough, decoration_cfg, scope_start, visible_after,
          distance) AS (
  SELECT mount.child_blob, macro.macro_name, macro.passthrough, macro.decoration_cfg,
         macro.scope_start, macro.visible_after, 1
  FROM mounts AS mount
  CROSS JOIN rust_item_macros AS macro
    ON macro.blob_id = mount.mount_blob
   AND macro.visible_after <= mount.mount_start
   AND macro.scope_start <= mount.mount_start
   AND mount.mount_start < macro.scope_end
  UNION ALL
  SELECT mount.child_blob, macro.macro_name, macro.passthrough, macro.decoration_cfg,
         macro.scope_start, macro.visible_after, 1
  FROM mounts AS mount
  CROSS JOIN exported AS macro
    ON macro.blob_id = mount.mount_blob
   AND macro.visible_after <= mount.mount_start
   AND macro.scope_start <= mount.mount_start
   AND mount.mount_start < macro.scope_end
  UNION ALL
  SELECT mount.child_blob, ancestor.macro_name, ancestor.passthrough, ancestor.decoration_cfg,
         ancestor.scope_start, ancestor.visible_after, ancestor.distance + 1
  FROM inherited AS ancestor
  CROSS JOIN mounts AS mount ON mount.mount_blob = ancestor.blob_id
  WHERE ancestor.distance < 256
),
invocations AS (
  SELECT invocation.blob_id, invocation.invocation_occurrence_id,
         invocation.invocation_start_byte, head.macro_name
  FROM source_rust_item_macro_expansions AS invocation
  CROSS JOIN source_rust_macro_invocations AS head
    ON head.blob_id = invocation.blob_id
   AND head.occurrence_id = invocation.invocation_occurrence_id
  WHERE invocation.source_position IN (0, 1)
    AND invocation.blob_id IN (SELECT member.value FROM json_each(?2) AS member)
),
visible AS (
  SELECT invocations.blob_id, invocations.invocation_occurrence_id, macro.passthrough,
         macro.decoration_cfg, 0 AS distance, macro.scope_start, macro.visible_after
  FROM invocations
  CROSS JOIN rust_item_macros AS macro
    ON macro.blob_id = invocations.blob_id
   AND macro.macro_name = invocations.macro_name
   AND macro.visible_after <= invocations.invocation_start_byte
   AND macro.scope_start <= invocations.invocation_start_byte
   AND invocations.invocation_start_byte < macro.scope_end
  UNION ALL
  SELECT invocations.blob_id, invocations.invocation_occurrence_id, macro.passthrough,
         macro.decoration_cfg, 0 AS distance, macro.scope_start, macro.visible_after
  FROM invocations
  CROSS JOIN exported AS macro
    ON macro.blob_id = invocations.blob_id
   AND macro.macro_name = invocations.macro_name
   AND macro.visible_after <= invocations.invocation_start_byte
   AND macro.scope_start <= invocations.invocation_start_byte
   AND invocations.invocation_start_byte < macro.scope_end
  UNION ALL
  SELECT invocations.blob_id, invocations.invocation_occurrence_id, ancestor.passthrough,
         ancestor.decoration_cfg, ancestor.distance, ancestor.scope_start, ancestor.visible_after
  FROM invocations
  CROSS JOIN inherited AS ancestor
    ON ancestor.blob_id = invocations.blob_id
   AND ancestor.macro_name = invocations.macro_name
),
chosen AS (
  SELECT blob_id, invocation_occurrence_id, passthrough, decoration_cfg,
         row_number() OVER (PARTITION BY blob_id, invocation_occurrence_id
                            ORDER BY distance, scope_start DESC, visible_after DESC) AS rank
  FROM visible
), no_route AS (
  -- A selected no-item arm has no native gap, which closes its module route
  -- even when another arm of the same macro is an item passthrough. Do not
  -- override a crate route proved by the item-passthrough query above.
  SELECT invocation.blob_id, invocation.invocation_occurrence_id,
         'expression [{"Any":0}]' AS decoration_cfg, 1 AS no_route
  FROM invocations AS invocation
  WHERE invocation.macro_name IS NOT NULL
    AND EXISTS (SELECT 1 FROM source_rust_macro_inputs AS input
                WHERE input.blob_id=invocation.blob_id
                  AND input.invocation_occurrence_id=invocation.invocation_occurrence_id
                  AND input.native_gap_site IS NULL)
    AND NOT EXISTS (SELECT 1 FROM chosen
                    WHERE chosen.blob_id=invocation.blob_id
                      AND chosen.invocation_occurrence_id=invocation.invocation_occurrence_id
                      AND chosen.rank=1 AND chosen.passthrough=1)
  UNION
  -- A same-named local macro_rules definition is not enough to make an
  -- invocation visible. Keep unknown external and prelude macros open.
  SELECT invocation.blob_id, invocation.invocation_occurrence_id,
         'expression [{"Any":0}]' AS decoration_cfg, 1 AS no_route
  FROM invocations AS invocation
  WHERE invocation.macro_name IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM chosen
                    WHERE chosen.blob_id=invocation.blob_id
                      AND chosen.invocation_occurrence_id=invocation.invocation_occurrence_id
                      AND chosen.rank=1)
    AND EXISTS (SELECT 1 FROM rust_item_macros AS definition
                WHERE definition.macro_name=invocation.macro_name
                  AND definition.blob_id IN (SELECT member.value FROM json_each(?2) AS member))
    AND NOT EXISTS (SELECT 1 FROM rust_item_macros AS definition
                    CROSS JOIN source_rust_declaration_properties AS properties
                      ON properties.blob_id=definition.blob_id
                     AND properties.declaration_id=definition.declaration_id
                    WHERE definition.macro_name=invocation.macro_name
                      AND properties.macro_exported=1
                      AND definition.blob_id IN (SELECT member.value FROM json_each(?2) AS member))
    AND NOT EXISTS (SELECT 1 FROM source_rust_import_targets AS imported
                    WHERE imported.blob_id IN (SELECT member.value FROM json_each(?2) AS member)
                      AND (imported.bound_name=invocation.macro_name
                           OR imported.is_glob=1 OR imported.is_macro_use=1))
    AND NOT EXISTS (SELECT 1 FROM source_rust_module_declarations AS module
                    WHERE module.blob_id IN (SELECT member.value FROM json_each(?2) AS member)
                      AND module.macro_use=1)
    AND invocation.macro_name NOT IN (
      'assert', 'assert_eq', 'assert_matches', 'assert_ne', 'asm', 'cfg',
      'column', 'compile_error', 'concat', 'concat_bytes', 'concat_idents',
      'dbg', 'debug_assert', 'debug_assert_eq', 'debug_assert_ne', 'env',
      'eprint', 'eprintln', 'file', 'format', 'format_args', 'format_args_nl',
      'global_asm', 'include', 'include_bytes', 'include_str', 'line',
      'log_syntax', 'matches', 'module_path', 'naked_asm', 'offset_of',
      'option_env', 'panic', 'print', 'println', 'stringify', 'thread_local',
      'todo', 'trace_macros', 'unimplemented', 'unreachable', 'vec', 'write',
      'writeln'
    )
)
SELECT blob_id, invocation_occurrence_id, decoration_cfg, 0 AS no_route FROM chosen
WHERE rank=1 AND passthrough=1 AND decoration_cfg IS NOT NULL
UNION ALL
SELECT blob_id, invocation_occurrence_id, decoration_cfg, no_route FROM no_route
ORDER BY blob_id, invocation_occurrence_id;
