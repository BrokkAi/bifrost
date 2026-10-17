-- Every manifest/shard pair receives a marker, including shards whose
-- callable-values profile is absent or contains no facts. The version lets a
-- later index-shape change force demand-scoped reconciliation.
CREATE TABLE catalog_callable_values_indexed_shards(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  index_version INTEGER NOT NULL CHECK(index_version = 1),
  PRIMARY KEY(manifest_digest, shard_id),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

-- Profile fields used by readers are scalar columns. The callback location is
-- valid, queryable JSON and is compared as the canonical serde representation
-- of CsmiInputLocation. Arguments and provenance are ordered JSON arrays that
-- consumers read whole; no opaque serialized fact payload is retained.
CREATE TABLE catalog_callable_value_facts(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  fact_ordinal INTEGER NOT NULL CHECK(fact_ordinal >= 0),
  family TEXT NOT NULL CHECK(family IN ('returned-callables', 'callback-invocations')),
  callable TEXT NOT NULL CHECK(length(callable) BETWEEN 1 AND 256),
  result_ordinal INTEGER CHECK(
    result_ordinal IS NULL OR result_ordinal BETWEEN 0 AND 4294967295
  ),
  target TEXT CHECK(target IS NULL OR length(target) BETWEEN 1 AND 256),
  callback_location_json TEXT
    CHECK(callback_location_json IS NULL OR
      (json_valid(callback_location_json) AND json_type(callback_location_json) = 'object')),
  callback_parameters INTEGER CHECK(
    callback_parameters IS NULL OR callback_parameters BETWEEN 0 AND 65535
  ),
  callback_results INTEGER CHECK(
    callback_results IS NULL OR callback_results BETWEEN 0 AND 65535
  ),
  arguments_json TEXT CHECK(arguments_json IS NULL OR
    (json_valid(arguments_json) AND json_type(arguments_json) = 'array')),
  timing TEXT CHECK(timing IS NULL OR timing IN ('during-call')),
  modality TEXT CHECK(modality IS NULL OR modality IN ('may')),
  provenance_json TEXT NOT NULL CHECK(
    json_valid(provenance_json) AND json_type(provenance_json) = 'array'
  ),
  PRIMARY KEY(manifest_digest, shard_id, fact_ordinal),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE,
  CHECK(
    (family = 'returned-callables'
      AND result_ordinal IS NOT NULL AND target IS NOT NULL
      AND callback_location_json IS NULL
      AND callback_parameters IS NULL AND callback_results IS NULL
      AND arguments_json IS NULL AND timing IS NULL AND modality IS NULL)
    OR
    (family = 'callback-invocations'
      AND result_ordinal IS NULL AND target IS NULL
      AND callback_location_json IS NOT NULL
      AND callback_parameters IS NOT NULL AND callback_results IS NOT NULL
      AND arguments_json IS NOT NULL AND timing IS NOT NULL AND modality IS NOT NULL)
  )
) STRICT;

-- `returned_callable_targets`: exact manifest/shard/callable/result alternatives.
CREATE INDEX catalog_callable_value_returned_lookup
  ON catalog_callable_value_facts(
    manifest_digest, shard_id, callable, result_ordinal, fact_ordinal
  ) WHERE family = 'returned-callables';

-- `callback_invocations`: exact structured location and target shape.
CREATE INDEX catalog_callable_value_callback_lookup
  ON catalog_callable_value_facts(
    manifest_digest, shard_id, callable, callback_location_json,
    callback_parameters, callback_results, fact_ordinal
  ) WHERE family = 'callback-invocations';

CREATE TABLE catalog_callable_value_coverage(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  coverage_ordinal INTEGER NOT NULL CHECK(coverage_ordinal >= 0),
  family TEXT NOT NULL CHECK(family IN ('returned-callables', 'callback-invocations')),
  callable TEXT NOT NULL CHECK(length(callable) BETWEEN 1 AND 256),
  status TEXT NOT NULL CHECK(status IN ('unknown', 'partial', 'complete')),
  limitations_json TEXT NOT NULL CHECK(
    json_valid(limitations_json) AND json_type(limitations_json) = 'array'
  ),
  provenance_json TEXT NOT NULL CHECK(
    json_valid(provenance_json) AND json_type(provenance_json) = 'array'
  ),
  PRIMARY KEY(manifest_digest, shard_id, coverage_ordinal),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

-- Coverage remains an independent claim for each profile family and callable.
CREATE INDEX catalog_callable_value_coverage_lookup
  ON catalog_callable_value_coverage(
    manifest_digest, shard_id, family, callable, coverage_ordinal
  );

-- Go anonymous function identities are looked up from a returned-callable
-- target under one exact manifest/shard. Every byte range remains scalar so
-- its canonical path and nonempty-span rules stay checked. Ordered chains and
-- positional parameter/result shapes are child rows.
CREATE TABLE catalog_anonymous_callable_identities(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  callable_id TEXT NOT NULL CHECK(length(callable_id) BETWEEN 1 AND 256),
  artifact_sha256 TEXT NOT NULL
    CHECK(length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
  package_import_path TEXT NOT NULL CHECK(
    length(package_import_path) > 0 AND package_import_path NOT LIKE '/%'
    AND package_import_path NOT LIKE '%/' AND instr(package_import_path, '//') = 0
    AND instr(package_import_path, char(92)) = 0
    AND package_import_path <> '.' AND package_import_path <> '..'
    AND package_import_path NOT LIKE './%' AND package_import_path NOT LIKE '../%'
    AND package_import_path NOT LIKE '%/./%' AND package_import_path NOT LIKE '%/../%'
    AND package_import_path NOT LIKE '%/.' AND package_import_path NOT LIKE '%/..'
  ),
  anchor_file TEXT NOT NULL CHECK(
    length(anchor_file) > 0 AND anchor_file NOT LIKE '/%'
    AND anchor_file NOT LIKE '%/' AND instr(anchor_file, char(92)) = 0
    AND instr(anchor_file, '//') = 0 AND anchor_file <> '.' AND anchor_file <> '..'
    AND anchor_file NOT LIKE './%' AND anchor_file NOT LIKE '../%'
    AND anchor_file NOT LIKE '%/./%' AND anchor_file NOT LIKE '%/../%'
    AND anchor_file NOT LIKE '%/.' AND anchor_file NOT LIKE '%/..'
  ),
  anchor_start INTEGER NOT NULL CHECK(anchor_start >= 0),
  anchor_end INTEGER NOT NULL CHECK(anchor_end > anchor_start),
  anchor_kind TEXT NOT NULL CHECK(anchor_kind = 'function-literal'),
  signature_file TEXT NOT NULL CHECK(
    length(signature_file) > 0 AND signature_file NOT LIKE '/%'
    AND signature_file NOT LIKE '%/' AND instr(signature_file, char(92)) = 0
    AND instr(signature_file, '//') = 0 AND signature_file <> '.' AND signature_file <> '..'
    AND signature_file NOT LIKE './%' AND signature_file NOT LIKE '../%'
    AND signature_file NOT LIKE '%/./%' AND signature_file NOT LIKE '%/../%'
    AND signature_file NOT LIKE '%/.' AND signature_file NOT LIKE '%/..'
  ),
  signature_start INTEGER NOT NULL CHECK(signature_start >= 0),
  signature_end INTEGER NOT NULL CHECK(signature_end > signature_start),
  PRIMARY KEY(manifest_digest, shard_id, callable_id),
  CHECK(anchor_file = signature_file
    AND signature_start = anchor_start AND signature_end <= anchor_end),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE catalog_anonymous_callable_identity_anchors(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  callable_id TEXT NOT NULL,
  chain_kind TEXT NOT NULL CHECK(chain_kind IN ('lexical_owner', 'signature_declaration')),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  file TEXT NOT NULL CHECK(
    length(file) > 0 AND file NOT LIKE '/%' AND file NOT LIKE '%/'
    AND instr(file, char(92)) = 0 AND instr(file, '//') = 0
    AND file <> '.' AND file <> '..' AND file NOT LIKE './%'
    AND file NOT LIKE '../%' AND file NOT LIKE '%/./%'
    AND file NOT LIKE '%/../%' AND file NOT LIKE '%/.' AND file NOT LIKE '%/..'
  ),
  byte_start INTEGER NOT NULL CHECK(byte_start >= 0),
  byte_end INTEGER NOT NULL CHECK(byte_end > byte_start),
  declaration_kind TEXT NOT NULL
    CHECK(declaration_kind IN (
      'function', 'method', 'function-literal', 'type', 'type-alias', 'struct-field'
    )),
  CHECK(chain_kind <> 'lexical_owner'
    OR declaration_kind IN ('function', 'method', 'function-literal')),
  PRIMARY KEY(manifest_digest, shard_id, callable_id, chain_kind, ordinal),
  FOREIGN KEY(manifest_digest, shard_id, callable_id)
    REFERENCES catalog_anonymous_callable_identities(
      manifest_digest, shard_id, callable_id
    ) ON DELETE CASCADE
) STRICT;

CREATE TABLE catalog_anonymous_callable_signature_shapes(
  manifest_digest TEXT NOT NULL,
  shard_id TEXT NOT NULL,
  callable_id TEXT NOT NULL,
  shape_kind TEXT NOT NULL CHECK(shape_kind IN ('parameter', 'result')),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  file TEXT NOT NULL CHECK(
    length(file) > 0 AND file NOT LIKE '/%' AND file NOT LIKE '%/'
    AND instr(file, char(92)) = 0 AND instr(file, '//') = 0
    AND file <> '.' AND file <> '..' AND file NOT LIKE './%'
    AND file NOT LIKE '../%' AND file NOT LIKE '%/./%'
    AND file NOT LIKE '%/../%' AND file NOT LIKE '%/.' AND file NOT LIKE '%/..'
  ),
  byte_start INTEGER NOT NULL CHECK(byte_start >= 0),
  byte_end INTEGER NOT NULL CHECK(byte_end > byte_start),
  variadic INTEGER NOT NULL CHECK(variadic IN (0, 1)),
  arity INTEGER NOT NULL CHECK(arity > 0),
  PRIMARY KEY(manifest_digest, shard_id, callable_id, shape_kind, ordinal),
  FOREIGN KEY(manifest_digest, shard_id, callable_id)
    REFERENCES catalog_anonymous_callable_identities(
      manifest_digest, shard_id, callable_id
    ) ON DELETE CASCADE
) STRICT;

-- Lexical owners are source containers for the anonymous literal. Each new
-- ordinal must extend the preceding outer-to-inner chain and contain it.
CREATE TRIGGER catalog_anonymous_identity_owner_anchor_insert
BEFORE INSERT ON catalog_anonymous_callable_identity_anchors
WHEN NEW.chain_kind = 'lexical_owner'
BEGIN
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM catalog_anonymous_callable_identities AS identity
    WHERE identity.manifest_digest = NEW.manifest_digest
      AND identity.shard_id = NEW.shard_id
      AND identity.callable_id = NEW.callable_id
      AND identity.anchor_file = NEW.file
      AND NEW.byte_start <= identity.anchor_start
      AND NEW.byte_end >= identity.anchor_end
      AND (NEW.byte_start < identity.anchor_start OR NEW.byte_end > identity.anchor_end)
  ) THEN RAISE(ABORT, 'lexical owner must contain its anonymous callable') END;
  SELECT CASE WHEN NEW.ordinal <> COALESCE((
    SELECT MAX(ordinal) + 1
    FROM catalog_anonymous_callable_identity_anchors
    WHERE manifest_digest = NEW.manifest_digest
      AND shard_id = NEW.shard_id AND callable_id = NEW.callable_id
      AND chain_kind = 'lexical_owner'
  ), 0) THEN RAISE(ABORT, 'lexical owner ordinals must be contiguous') END;
  SELECT CASE WHEN NEW.ordinal > 0 AND NOT EXISTS(
    SELECT 1 FROM catalog_anonymous_callable_identity_anchors AS previous
    WHERE previous.manifest_digest = NEW.manifest_digest
      AND previous.shard_id = NEW.shard_id
      AND previous.callable_id = NEW.callable_id
      AND previous.chain_kind = 'lexical_owner'
      AND previous.ordinal = NEW.ordinal - 1
      AND previous.byte_start <= NEW.byte_start
      AND previous.byte_end >= NEW.byte_end
      AND (previous.byte_start < NEW.byte_start OR previous.byte_end > NEW.byte_end)
  ) THEN RAISE(ABORT, 'lexical owner chain must be nested outer-to-inner') END;
END;

CREATE TRIGGER catalog_anonymous_identity_declaration_anchor_insert
BEFORE INSERT ON catalog_anonymous_callable_identity_anchors
WHEN NEW.chain_kind = 'signature_declaration'
BEGIN
  SELECT CASE WHEN NEW.ordinal <> COALESCE((
    SELECT MAX(ordinal) + 1
    FROM catalog_anonymous_callable_identity_anchors
    WHERE manifest_digest = NEW.manifest_digest
      AND shard_id = NEW.shard_id AND callable_id = NEW.callable_id
      AND chain_kind = 'signature_declaration'
  ), 0) THEN RAISE(ABORT, 'signature declaration ordinals must be contiguous') END;
END;

CREATE TRIGGER catalog_anonymous_identity_signature_shape_insert
BEFORE INSERT ON catalog_anonymous_callable_signature_shapes
BEGIN
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM catalog_anonymous_callable_identities AS identity
    WHERE identity.manifest_digest = NEW.manifest_digest
      AND identity.shard_id = NEW.shard_id
      AND identity.callable_id = NEW.callable_id
      AND identity.signature_file = NEW.file
      AND NEW.byte_start >= identity.signature_start
      AND NEW.byte_end <= identity.signature_end
  ) THEN RAISE(ABORT, 'signature shape must be inside its function type') END;
  SELECT CASE WHEN NEW.ordinal <> COALESCE((
    SELECT MAX(ordinal) + 1
    FROM catalog_anonymous_callable_signature_shapes
    WHERE manifest_digest = NEW.manifest_digest
      AND shard_id = NEW.shard_id AND callable_id = NEW.callable_id
      AND shape_kind = NEW.shape_kind
  ), 0) THEN RAISE(ABORT, 'signature shape ordinals must be contiguous') END;
END;
