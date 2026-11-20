-- Migration 0467: clear JVM external inventory before rotating its projection identity.
-- #9559 step 3d rotates the jvm-external-projection identity. Until #12245
-- scopes JVM provider ids by projection identity, answer reads and the
-- inventory shortcut key on provider_id alone, so rows published under the
-- previous identity must not survive the upgrade. Migration 0425 also clears
-- these tables, but a store can run 0425, re-project rows under master's
-- identity and only then upgrade here (#12445); this purge withdraws them.
-- Certificates go first, before the inventory their seal guards. Members and
-- supertypes are deleted explicitly because the upgrader runs with foreign
-- keys off. Every provider republishes on first use. This runs before 0468
-- creates the inventory generation triggers, so the deleted rows do not
-- advance the generation.
DELETE FROM jvm_external_provider_publications;
DELETE FROM jvm_external_owner_members;
DELETE FROM jvm_external_owner_supertypes;
DELETE FROM jvm_external_owners;
