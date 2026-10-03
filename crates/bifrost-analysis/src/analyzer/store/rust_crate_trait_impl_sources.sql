-- Every trait implementation a member blob declares, placed in the module whose
-- body contains its impl header. The tier-1 trait-implementation family carries
-- both halves of `impl Trait for Type` as spelled routes and the impl's own
-- site, so this reads one relation per member blob, exactly as the root-route
-- family is read. The terminal row's position is the number of module segments
-- the side spells, which is 0 for a bare name.
--
-- The impl's own source declaration is found from its site. `impl_site` is the
-- subject type's reference site, whose reference context names the source
-- occurrence of the reference; that occurrence is a path segment of exactly
-- one Rust type, and that type is the subject of exactly one impl item. A
-- reference site is also its blob-local semantic key, so each step is a key
-- seek. When the steps do not name exactly one impl item the column is NULL.
INSERT INTO cr_impl_sources
SELECT members.blob_id, subject.relation_key, members.module_path, subject.impl_site,
       subject.terminal_spelling, subject.position,
       implemented.terminal_spelling, implemented.position,
       (SELECT CASE WHEN count(DISTINCT item.declaration_id) = 1
                    THEN min(item.declaration_id) END
        FROM resolution_rust_reference_contexts AS context
        CROSS JOIN source_rust_type_segments AS segment
          ON segment.blob_id=context.blob_id AND segment.occurrence_id=context.source_occurrence
        CROSS JOIN source_rust_impl_items AS item
          ON item.blob_id=segment.blob_id
         AND item.target_type_occurrence_id=segment.type_occurrence_id
        WHERE context.blob_id=subject.blob_id AND context.semantic_key=subject.impl_site)
FROM cr_members AS members
CROSS JOIN resolution_trait_implementations AS subject
  ON subject.blob_id=members.blob_id AND subject.side='subject'
 AND subject.terminal_spelling IS NOT NULL
CROSS JOIN resolution_trait_implementations AS implemented
  ON implemented.blob_id=subject.blob_id
 AND implemented.relation_key=subject.relation_key
 AND implemented.side='trait' AND implemented.terminal_spelling IS NOT NULL
WHERE subject.impl_start_byte >= members.start_byte
  AND subject.impl_end_byte <= members.end_byte
  AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module
      WHERE inner_module.blob_id=members.blob_id
        AND inner_module.scope_ordinal<>members.scope_ordinal
        AND inner_module.start_byte>=members.start_byte
        AND inner_module.end_byte<=members.end_byte
        AND subject.impl_start_byte>=inner_module.start_byte
        AND subject.impl_end_byte<=inner_module.end_byte);
