-- Which override-family modifier one callable declaration states.
--
-- Method families (#1721) must tell overriding from hiding. C# spells the
-- difference with keywords: a derived member that writes `override` redefines
-- a `virtual` or `abstract` base member, and one that writes `new` -- or that
-- writes nothing, which is implicit `new` plus compiler warning CS0108 --
-- hides it instead. Nothing in the store carried that fact.
-- `dispatch_extensibility` looks close but is not it: it collapses `virtual`,
-- `abstract`, `override` and "member of an interface" into one `open` value,
-- and a `new`-hiding member with no other modifier is `closed` exactly like an
-- ordinary method.
--
-- Additive column with a NULL default, in its own migration, per the rule
-- `0023-signature-metadata-columns.sql` states: never add a field to a
-- serialized struct.
--
-- NULL means the adapter never read this declaration's modifier nodes for this
-- family, which is what every row written before this column says. It is a
-- different fact from 'not_declared', which means the adapter read them and
-- the declaration states none of the family; a consumer that could not tell
-- the two apart would report a warm cache's Java rows as hiding members. The
-- adapters that record the fact bump their per-language epoch salt so their
-- warm rows are reparsed rather than read as unread.
ALTER TABLE unit_signature_metadata
  ADD COLUMN callable_override_modifier TEXT DEFAULT NULL
    CHECK(callable_override_modifier IS NULL
          OR callable_override_modifier IN
             ('not_declared', 'virtual', 'abstract', 'override', 'hiding'));
