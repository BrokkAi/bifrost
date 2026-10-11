-- Go rename collision checks join the parsed binder range to the source import
-- that owns the declaration. Keep that byte-range lookup indexed.
CREATE INDEX source_imports_declaration_range
  ON source_imports(blob_id, declaration_start_byte, declaration_end_byte);
