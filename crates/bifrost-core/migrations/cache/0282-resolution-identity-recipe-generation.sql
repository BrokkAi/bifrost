-- The counter moves on every insert and on every first fill.
-- A filled resolution recipe is immutable. Its first publication advances this
-- generation even when selected blob identities do not change.
CREATE TABLE resolution_identity_recipe_generation (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 0)
) STRICT;
INSERT INTO resolution_identity_recipe_generation(id, generation) VALUES(1, 0);

CREATE TRIGGER resolution_identity_recipe_insert_generation
AFTER INSERT ON resolution_identities
BEGIN
  UPDATE resolution_identity_recipe_generation SET generation = generation + 1 WHERE id = 1;
END;

CREATE TRIGGER resolution_identity_recipe_fill_generation
AFTER UPDATE ON resolution_identities
WHEN OLD.semantic_language IS NULL AND NEW.semantic_language IS NOT NULL
BEGIN
  UPDATE resolution_identity_recipe_generation SET generation = generation + 1 WHERE id = 1;
END;

CREATE TRIGGER resolution_identity_recipe_update_guard
BEFORE UPDATE ON resolution_identities
WHEN OLD.id IS NOT NEW.id
  OR OLD.identity_digest IS NOT NEW.identity_digest
  OR (OLD.semantic_language IS NOT NULL AND
      (OLD.semantic_language IS NOT NEW.semantic_language
       OR OLD.namespace IS NOT NEW.namespace
       OR OLD.spelling IS NOT NEW.spelling))
BEGIN
  SELECT RAISE(ABORT, 'resolution identity or filled recipe is immutable');
END;

-- REPLACE advances the counter through the insert trigger whether or not recursive
-- triggers fire. With recursive_triggers=ON (every configured cache connection),
-- this delete guard also rejects replacing a filled row.
CREATE TRIGGER resolution_identity_recipe_delete_guard
BEFORE DELETE ON resolution_identities
WHEN OLD.semantic_language IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'filled resolution recipe cannot be deleted');
END;
