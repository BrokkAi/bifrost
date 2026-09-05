-- Class-set summary lookup v2 addresses one procedure-local entry relation
-- independently of its mutable child-summary evidence. Version 45 rows used
-- a dependency-sensitive lookup digest, which cannot be distinguished from
-- the new identity after the fact. Discard this derived cache family so stale
-- v1 rows cannot remain visible through lineage, dependency, or read indexes.

DELETE FROM class_set_summaries;
