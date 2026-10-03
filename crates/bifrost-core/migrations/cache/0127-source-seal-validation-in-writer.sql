-- Move three source-fact seal checks out of SQL (#3737).
--
-- These BEFORE UPDATE triggers re-read every row just written for a blob when
-- its source_fact_manifests row is sealed. That cost about 2 us for each source
-- row and was most of the seal statement's time on a cold build. The writer now
-- guarantees the same invariants over the in-memory facts before it inserts
-- them: counts, dense ids and inline spans come from the collections and arena
-- lookups the insert loops use, and assertions check the rest
-- (ParsedSourceFacts::assert_storable, StructuralFactRows::new,
-- SourceFactRows::new, the language valid_links checks and the Rust item and
-- Ruby writers). The per-column CHECK constraints, foreign keys and the other
-- seal triggers stay.
DROP TRIGGER source_fact_manifests_validate_contents;
DROP TRIGGER source_occurrence_arenas_validate_seal;
DROP TRIGGER source_inline_occurrences_validate_seal;
