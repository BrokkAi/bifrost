-- General comparison operands are persisted under the guard-value IR contract.
-- BREAKING: older RowCode readers reject predicate tags 11 and 12. Versioned
-- cache files and the user_version fence exclude older daemons after upgrade.
-- General policy-owned comparisons preserve both exact operand reads. The
-- existing scalar predicate codes retain their identities and refinements.
CREATE TABLE semantic_ir_guard_facts_value_comparisons(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  guard        INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  subject      INTEGER,
  predicate    INTEGER NOT NULL CHECK(predicate BETWEEN 0 AND 12),
  flag         INTEGER CHECK(flag IN (0, 1)),
  relation     INTEGER CHECK(relation BETWEEN 0 AND 3),
  constant     INTEGER,
  operand_a    INTEGER,
  operand_b    INTEGER,
  digest       INTEGER,
  true_target  INTEGER,
  true_kind    INTEGER,
  false_target INTEGER,
  false_kind   INTEGER,
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, guard),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO semantic_ir_guard_facts_value_comparisons SELECT * FROM semantic_ir_guard_facts;
DROP TABLE semantic_ir_guard_facts;
ALTER TABLE semantic_ir_guard_facts_value_comparisons RENAME TO semantic_ir_guard_facts;

CREATE TABLE candidate_macro_semantic_ir_guard_facts_value_comparisons(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  guard        INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  subject      INTEGER,
  predicate    INTEGER NOT NULL CHECK(predicate BETWEEN 0 AND 12),
  flag         INTEGER CHECK(flag IN (0, 1)),
  relation     INTEGER CHECK(relation BETWEEN 0 AND 3),
  constant     INTEGER,
  operand_a    INTEGER,
  operand_b    INTEGER,
  digest       INTEGER,
  true_target  INTEGER,
  true_kind    INTEGER,
  false_target INTEGER,
  false_kind   INTEGER,
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, guard),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO candidate_macro_semantic_ir_guard_facts_value_comparisons SELECT * FROM candidate_macro_semantic_ir_guard_facts;
DROP TABLE candidate_macro_semantic_ir_guard_facts;
ALTER TABLE candidate_macro_semantic_ir_guard_facts_value_comparisons RENAME TO candidate_macro_semantic_ir_guard_facts;
