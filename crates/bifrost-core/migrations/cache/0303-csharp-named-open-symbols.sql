-- Compatible: an additive SQL-readable symbol array defaults to empty for
-- existing environments, preserving their defined symbols and owner identities.
-- Derivation version 19 republishes configuration-independent environments;
-- version-suffixed cache files prevent mixed-version writers.
ALTER TABLE csharp_compilations ADD COLUMN named_open_symbols BLOB NOT NULL
 DEFAULT X'0B' CHECK(json_valid(named_open_symbols,8) AND json_type(named_open_symbols)='array');
