-- Existing sets remain open; derivation v3 prevents their reuse.
ALTER TABLE csharp_compilations ADD COLUMN configuration TEXT NOT NULL DEFAULT 'Debug';
ALTER TABLE csharp_compilations ADD COLUMN target_framework TEXT;
ALTER TABLE csharp_compilations ADD COLUMN symbols_closed INTEGER NOT NULL DEFAULT 0 CHECK(symbols_closed IN (0,1));
ALTER TABLE csharp_compilations ADD COLUMN open_reason TEXT DEFAULT 'unrestored'
 CHECK ((symbols_closed = 1 AND open_reason IS NULL) OR
        (symbols_closed = 0 AND open_reason IS NOT NULL AND open_reason IN ('loose_files','unrestored','condition','dynamic_property','unevaluated_import','package_build_import','unsupported_framework')));
ALTER TABLE csharp_compilations ADD COLUMN symbol_set_digest BLOB CHECK(length(symbol_set_digest) = 32);
CREATE TABLE csharp_compilation_symbols (
 compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
 symbol TEXT NOT NULL,
 source TEXT NOT NULL CHECK(source IN ('sdk','define_constants')),
 PRIMARY KEY(compilation_id, symbol)
) WITHOUT ROWID, STRICT;
