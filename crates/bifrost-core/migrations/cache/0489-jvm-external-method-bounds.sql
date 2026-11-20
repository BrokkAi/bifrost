-- #12385 M2; COMPATIBLE: clears a derived cache.
-- JAR-route providers are keyed by input artifact SHA and are never re-projected.
-- Clearing the inventory lets an upgraded store read newly known bounds like a fresh store.
DELETE FROM jvm_external_provider_publications;
DELETE FROM jvm_external_owner_members;
DELETE FROM jvm_external_owner_supertypes;
DELETE FROM jvm_external_owners;
