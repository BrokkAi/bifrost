-- Bare-name identifier resolution (declaration_candidate_rows_by_identifier_for_langs,
-- the sole backer of IAnalyzer::lookup_candidates_by_identifier) must see every
-- unit the fq lookup path already resolves, or a spelling that resolves cleanly
-- by fq can silently pick a single unrelated declaration when queried bare (see
-- #1088). Definition-lookup-only units (e.g. JS/TS object-literal properties,
-- classified DefinitionLookupOnly) carry in_definition_lookup=1 with
-- in_declarations=0 and were invisible to the old in_declarations-only
-- predicate. The old partial index cannot serve the widened
-- `in_declarations = 1 OR in_definition_lookup = 1` predicate (SQLite can only
-- use a partial index when the query implies its WHERE clause), so replace it
-- with one that does. This is a resolution-visibility fix only: declaration
-- listings (get_all_declarations, search, summaries) are unaffected and still
-- rely on the unchanged in_declarations-only surfaces (#397).
DROP INDEX idx_code_units_lang_identifier_declarations;
CREATE INDEX idx_code_units_lang_identifier_lookup
  ON code_units(lang, identifier)
  WHERE in_declarations = 1 OR in_definition_lookup = 1;
