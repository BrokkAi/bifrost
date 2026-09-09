-- Replayable declaration and signature fact reads for persisted policy units.
--
-- Version 58 policy units can carry a file read for Java declaration facts
-- and a language-wide scope read for a direct-descendant answer. Version 59
-- records those dependencies as replayable lookup answers instead. Retaining
-- an old unit would preserve the obsolete coarse read set and defeat the new
-- reuse contract, so discard the derived base evaluations, units, and their
-- interned keys. The evaluation memberships cascade before the unit rows are
-- deleted.

DELETE FROM policy_evaluations;
DELETE FROM policy_units;
DELETE FROM policy_read_keys;
