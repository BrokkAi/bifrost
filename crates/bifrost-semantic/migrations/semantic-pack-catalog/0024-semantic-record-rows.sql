-- Semantic record rows. Source facts are published once per shard at index version 2.
-- Reader paths in comments are relative to the repository root.
-- M = crates/bifrost-store/src/analyzer/store/active_models.rs
-- A = crates/bifrost-analysis/src/analyzer/semantic_model/overlay.rs
-- C = crates/bifrost-semantic/src/analyzer/semantic_model/catalog/mod.rs
-- MC = crates/bifrost-store/src/analyzer/store/model_catalog.rs
-- CC = crates/bifrost-analysis/src/analyzer/semantic_model/overlay/composition.rs
-- model.rs = crates/bifrost-semantic/src/analyzer/semantic_model/model.rs
-- runtime_values.rs =
-- crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs
-- rust/modeled_members.rs = crates/bifrost-rust-analysis/src/analyzer/rust/modeled_members.rs
-- tools/searchtools/scan_usages.rs = crates/bifrost-tools/src/searchtools/scan_usages.rs
-- Readiness: MC:319-341, analysis/catalog/mod.rs:3672,3711.
-- Invalidation: reindex deletes a marker; all derived rows cascade.
-- Marker insertion, all row families, and completeness version are atomic.
-- Existing callable tables, text keys, child rows and constraints stay intact.
DROP TABLE catalog_callable_values_indexed_shards;
CREATE TABLE catalog_semantic_rows_indexed_shards(
  shard_key INTEGER PRIMARY KEY, -- every row-reader joins exact selected shard
  manifest_digest TEXT NOT NULL, -- MC:319 exact manifest/shard readiness
  shard_id TEXT NOT NULL, -- MC:319 exact manifest/shard readiness
  index_version INTEGER NOT NULL CHECK(index_version = 2), -- MC:335 readiness
  UNIQUE(manifest_digest, shard_id),
  FOREIGN KEY(manifest_digest, shard_id)
    REFERENCES catalog_pack_shards(manifest_digest, shard_id) ON DELETE CASCADE
) STRICT;
-- Marker is inserted FIRST within the transaction so child FKs can reference
-- it. Version 2 is visible to other connections only after the whole commit.
-- A rolled-back/failed publication cannot leave a complete marker behind.

CREATE TABLE catalog_declaration_types(
  record_key INTEGER PRIMARY KEY, -- M:584,604: row identity / record fetch
  shard_key INTEGER NOT NULL, -- M:584,604: active manifest/shard membership
  record_id TEXT NOT NULL, -- M:584,604 equality by source declaration ID
-- Rust visible-trait owner query at modeled_members.rs:367; no kind index
  type_kind TEXT GENERATED ALWAYS AS (json_extract(record_json, '$.type_kind')) STORED NOT NULL
    CHECK(type_kind IN ('class', 'annotation', 'delegate', 'interface', 'trait', 'struct',
    'union', 'enum', 'record', 'module', 'type_alias')),
  authored_path TEXT, -- A:782 candidate equality, translated at A:3983-4060
-- M:584,604: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- M:584,604; CC:127: exact type/source-record lookup
CREATE INDEX catalog_declaration_types_id ON catalog_declaration_types(record_id);

-- A:782: authored-path candidates; apply anchor translation before parity
CREATE INDEX catalog_declaration_types_path ON catalog_declaration_types(authored_path);

-- M:584,604: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_declaration_types_shard ON catalog_declaration_types(shard_key);

CREATE TABLE catalog_declaration_members(
  record_key INTEGER PRIMARY KEY, -- M:627,692: row identity / record fetch
  shard_key INTEGER NOT NULL, -- M:627,692: active manifest/shard membership
  record_id TEXT NOT NULL, -- M:627,688 exact member ID
  owner_id TEXT NOT NULL, -- M:692 and A:789 owner/member bucket
  name TEXT NOT NULL, -- M:692; rust/modeled_members.rs:367 requested-member query
  language TEXT NOT NULL, -- rust/modeled_members.rs:367 language-scoped visible traits
  authored_path TEXT, -- A:782 candidate equality, translated at A:3983-4060
-- M:627,692: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- M:627,688: exact source member ID
CREATE INDEX catalog_declaration_members_id ON catalog_declaration_members(record_id);

-- M:692, A:789,794; fetch whole family and inspect JSON in Rust
CREATE INDEX catalog_declaration_members_owner_name ON catalog_declaration_members(owner_id, name);

-- crates/bifrost-rust-analysis/src/analyzer/rust/modeled_members.rs:367: requested-name trait
-- discovery; type join tests json_extract(type.record_json,'$.type_kind')
CREATE INDEX catalog_declaration_members_name ON catalog_declaration_members(name, language);

-- A:782: source locator candidates, final anchor translation
CREATE INDEX catalog_declaration_members_path ON catalog_declaration_members(authored_path);

-- M:627,692: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_declaration_members_shard ON catalog_declaration_members(shard_key);

-- M:588/A:731 type names; CC:43-61 owner alias closure. Only source-local
-- type canonical, simple and alias spellings live here. Member requests use
-- split_qualified_member (semantic/oracle/dispatch.rs:527), then owner lookup
-- and members(owner_id,name) or member_aliases. Never store owner-derived
-- qualified member names: reindexing another shard would invalidate them.
CREATE TABLE catalog_declaration_names(
  shard_key INTEGER NOT NULL, -- M:588 selected shard
  record_key INTEGER NOT NULL, -- CC:43-61 exact owner -> names
  name TEXT NOT NULL, -- M:588/A:731 spelling equality
  language TEXT NOT NULL, -- CC:48 owner language equality
  namespace TEXT NOT NULL CHECK(namespace IN ('module','type')), -- CC:49
  identity_name INTEGER NOT NULL CHECK(identity_name IN (0,1)), -- M:1358/CC:43 canonical/alias
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  FOREIGN KEY(record_key) REFERENCES catalog_declaration_types(record_key) ON DELETE CASCADE
) STRICT;
-- M:588/A:731/CC:43-61: exact spelling, language and namespace.
CREATE INDEX catalog_declaration_names_lookup ON catalog_declaration_names(name, language,
    namespace, identity_name);
-- CC:43-61 owner -> identity spellings and source record FK probes.
CREATE INDEX catalog_declaration_names_record ON catalog_declaration_names(record_key);
-- M:588 selected-shard enumeration and marker FK probes.
CREATE INDEX catalog_declaration_names_shard ON catalog_declaration_names(shard_key);
CREATE TABLE catalog_member_aliases(
  shard_key INTEGER NOT NULL, -- M:692 selected shard
  member_key INTEGER NOT NULL, -- M:692 fetch source member / owner
  alias TEXT NOT NULL, -- M:692 member alias spelling equality
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  FOREIGN KEY(member_key) REFERENCES catalog_declaration_members(record_key) ON DELETE CASCADE
) STRICT;
-- M:692/A:731 alias lookup then owner filtering via member row.
CREATE INDEX catalog_member_aliases_lookup ON catalog_member_aliases(alias);
-- Member deletion FK probes / M:692 exact member aliases.
CREATE INDEX catalog_member_aliases_member ON catalog_member_aliases(member_key);
-- M:692 selected-shard enumeration and marker deletion FK probes.
CREATE INDEX catalog_member_aliases_shard ON catalog_member_aliases(shard_key);

CREATE TABLE catalog_declaration_relations(
  record_key INTEGER PRIMARY KEY, -- M:701,705,709; A:1685,1689: row identity / record fetch
  shard_key INTEGER NOT NULL, -- M:701,705,709; A:1685,1689: active manifest/shard membership
-- M:701,705,709 raw matcher excludes hierarchy; A:1685,1689 includes it
  origin TEXT NOT NULL CHECK(origin IN ('relation_fact', 'type_hierarchy')),
  record_id TEXT NOT NULL, -- M:701 exact raw relation ID; origin disambiguates generated IDs
  from_id TEXT NOT NULL, -- M:705/A:1685 exact source endpoint
  to_id TEXT NOT NULL, -- M:709/A:1689 exact normalized target endpoint
-- A:1784 hierarchy-kind IN predicate; tools/searchtools/scan_usages.rs:7376 references
-- predicate
  relation_kind TEXT NOT NULL,
  declaration_ordinal INTEGER, -- A:1780 hierarchy declaration ordering; raw RelationFact has none
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- M:701: ID and origin=relation_fact
CREATE INDEX catalog_declaration_relations_id ON catalog_declaration_relations(record_id, origin);

-- M:705 / A:1685,1784: source endpoint plus pushed-down hierarchy-kind filter
CREATE INDEX catalog_declaration_relations_from ON catalog_declaration_relations(from_id,
    relation_kind,  origin);

-- M:709 / A:1689 / crates/bifrost-tools/src/searchtools/scan_usages.rs:7376: target plus
-- references kind
CREATE INDEX catalog_declaration_relations_to ON catalog_declaration_relations(to_id,
    relation_kind,  origin);

-- M:701,705,709; A:1685,1689: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_declaration_relations_shard ON catalog_declaration_relations(shard_key);

-- Hierarchy row structure is the pure projection inside A:3955-3978:
-- from=TypeFact.id; to=Declared.id / Named.name / render_type_ref(other);
-- kind=hierarchy_kind_label; id=hierarchy:{from}:{kind}:{to}; ordinal from edge.
-- project_hierarchy_relation in semantic_model/overlay.rs is shared by the
-- publisher and runtime wrapper. The wrapper adds active provenance/ambiguity;
-- that active-set-dependent part is not persisted.
-- Hierarchy rows index TypeFact.hierarchy. The edge payload (type arguments,
-- bindings) is read from the from-type record, not from this row. RelationFact
-- has exactly id, relation_kind, from, to; these rows are columns only.

CREATE TABLE catalog_generator_rules(
  record_key INTEGER PRIMARY KEY, -- M:713,733: row identity / record fetch
  shard_key INTEGER NOT NULL, -- M:713,733: active manifest/shard membership
  record_id TEXT NOT NULL, -- M:733 exact rule ID; A:2328,2700 DISTINCT IDs
  trigger_family TEXT NOT NULL, -- M:713 key variant; M:1821 shared insertion
  trigger_key TEXT NOT NULL, -- M:713 trigger name/owner/construct equality
  call_member TEXT, -- M:713 ResolvedCall owner+member equality
-- M:713,733: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- M:733 / A:2328,2700: exact ID or ID inventory
CREATE INDEX catalog_generator_rules_id ON catalog_generator_rules(record_id);

-- M:713,1821: seven trigger variants; both annotation variants share family
CREATE INDEX catalog_generator_rules_trigger ON catalog_generator_rules(trigger_family,
    trigger_key,  call_member);

-- M:713,733: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_generator_rules_shard ON catalog_generator_rules(shard_key);

CREATE TABLE catalog_procedure_summaries(
  record_key INTEGER PRIMARY KEY, -- M:737,823,1021: row identity / record fetch
  shard_key INTEGER NOT NULL, -- M:737,823,1021: active manifest/shard membership
  language TEXT NOT NULL, -- M:737,823 semantic_pack_realm language key
  target_path TEXT NOT NULL, -- M:737 exact artifact path
  target_symbol TEXT NOT NULL, -- M:737 exact parameter-typed symbol
  owner_fqn TEXT, -- M:823,1021 owner-family key / discovered owners
  member TEXT, -- M:823,1021 member-family key
  has_receiver INTEGER NOT NULL CHECK(has_receiver IN (0,1)), -- M:737,823 shape equality
-- M:737 / M:1974 exact or optional upper bound
  declared_arity INTEGER NOT NULL CHECK(declared_arity>=0),
-- M:1921 / M:1974 distinguish exact and variadic
  variadic INTEGER NOT NULL CHECK(variadic IN (0, 1)),
-- M:1974 variadic lower bound
  minimum_actual_count INTEGER NOT NULL CHECK(minimum_actual_count>=0),
-- M:1999 optional-fixed lower bound
  optional_minimum INTEGER CHECK(optional_minimum IS NULL OR optional_minimum>=0),
-- M:1707 raw-claim discovery only; NEVER excludes false competitors from family read
  normal_continuation_absent INTEGER GENERATED ALWAYS AS (coalesce(json_extract(record_json,
    '$.normal_continuation_absent'), 0)) VIRTUAL,
-- M:737,823,1021: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- M:737,1921: exact formal shape
CREATE INDEX catalog_procedure_summaries_target ON catalog_procedure_summaries(language,
    target_path,  target_symbol,  has_receiver,  declared_arity,  variadic);

-- M:823,1974: fetch ALL true/false competing claims for family, filter shape bounds in SQL only
-- when answering one arity
CREATE INDEX catalog_procedure_summaries_member ON catalog_procedure_summaries(language,
    owner_fqn,  member,  has_receiver);

-- M:1009,1021,1707: discover raw true families then resolve all family claims over arity boundaries
CREATE INDEX catalog_procedure_summaries_absence ON catalog_procedure_summaries(language,
    member,  has_receiver,  normal_continuation_absent,  owner_fqn);

-- M:737,823,1021: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_procedure_summaries_shard ON catalog_procedure_summaries(shard_key);

CREATE TABLE catalog_collection_flows(
  record_key INTEGER PRIMARY KEY, -- A:547: row identity / record fetch
  shard_key INTEGER NOT NULL, -- A:547: active manifest/shard membership
  callable TEXT NOT NULL, -- A:547,560 exact contributor callable ID
-- A:547: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- A:547,560: contributor-scoped keyed collection flows
CREATE INDEX catalog_collection_flows_callable ON catalog_collection_flows(callable);

-- A:547: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_collection_flows_shard ON catalog_collection_flows(shard_key);

CREATE TABLE catalog_conditional_type_refinements(
  record_key INTEGER PRIMARY KEY, -- A:600: row identity / record fetch
  shard_key INTEGER NOT NULL, -- A:600: active manifest/shard membership
  callable TEXT NOT NULL, -- A:600,607 payload.callable equality
-- A:600: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- A:600: callable plus exact contributor pack/activation
CREATE INDEX catalog_conditional_type_refinements_callable ON
    catalog_conditional_type_refinements(callable);

-- A:600: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_conditional_type_refinements_shard ON
    catalog_conditional_type_refinements(shard_key);

CREATE TABLE catalog_deferred_yields(
  record_key INTEGER PRIMARY KEY, -- A:639,671: row identity / record fetch
  shard_key INTEGER NOT NULL, -- A:639,671: active manifest/shard membership
  factory TEXT NOT NULL, -- A:639,671 factory equality after contributor expansion
  resume TEXT NOT NULL, -- A:639,653 resume equality
  handle_type TEXT NOT NULL, -- A:639,654 handle-type equality
-- A:639,671: full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE
) STRICT;

-- A:639,671: scope / factory-prefix keyed reads; expand contributor IDs first
CREATE INDEX catalog_deferred_yields_scope ON catalog_deferred_yields(factory, resume, handle_type);

-- A:639,671: shard-scoped enumeration; FK cascade probes this key on reindex.
CREATE INDEX catalog_deferred_yields_shard ON catalog_deferred_yields(shard_key);

CREATE TABLE catalog_runtime_value_payloads(
-- M:500;
-- crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:395,699: row
-- identity / record fetch
  record_key INTEGER PRIMARY KEY,
-- M:500;
-- crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:395,699:
-- active manifest/shard membership
  shard_key INTEGER NOT NULL,
-- M:500;
-- crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:395,699:
-- full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  UNIQUE(shard_key)
) STRICT;

-- Full RuntimeValuesPayload is stored ONCE above; these child postings
-- select a JSON array element, not another full exposure/behavior copy.
CREATE TABLE catalog_runtime_exposures(
  shard_key INTEGER NOT NULL, -- runtime_values.rs:699 selected shard
  payload_key INTEGER NOT NULL, -- A:704 fetch parent payload
  exposure_ordinal INTEGER NOT NULL CHECK(exposure_ordinal>=0), -- A:704 json_extract exposures[i]
  exposure_id TEXT NOT NULL, -- runtime_values.rs:736 exposure/behavior join equality
  binding_name TEXT NOT NULL, -- A:704 / runtime_values.rs:701 root binding equality
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  FOREIGN KEY(payload_key) REFERENCES catalog_runtime_value_payloads(record_key) ON DELETE CASCADE
) STRICT;
-- A:704 / crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:701.
CREATE INDEX catalog_runtime_exposures_binding ON catalog_runtime_exposures(binding_name);
-- A:704: parent payload to exposures, and payload FK cascade.
CREATE INDEX catalog_runtime_exposures_payload ON catalog_runtime_exposures(payload_key);
-- M:500: selected-shard enumeration and marker FK cascade.
CREATE INDEX catalog_runtime_exposures_shard ON catalog_runtime_exposures(shard_key);
CREATE TABLE catalog_runtime_behaviors(
  shard_key INTEGER NOT NULL, -- runtime_values.rs:736 selected shard
  payload_key INTEGER NOT NULL, -- runtime_values.rs:736 fetch parent payload
-- runtime_values.rs:736 json_extract behaviors[i]
  behavior_ordinal INTEGER NOT NULL CHECK(behavior_ordinal>=0),
  exposure_id TEXT NOT NULL, -- runtime_values.rs:736 joins matching exposure
  container_member TEXT NOT NULL, -- runtime_values.rs:737 read.container equality
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  FOREIGN KEY(payload_key) REFERENCES catalog_runtime_value_payloads(record_key) ON DELETE CASCADE
) STRICT;
-- crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:736-737.
CREATE INDEX catalog_runtime_behaviors_exposure ON catalog_runtime_behaviors(exposure_id,
    container_member);
-- runtime_values.rs:736: parent payload enumeration, payload FK cascade.
CREATE INDEX catalog_runtime_behaviors_payload ON catalog_runtime_behaviors(payload_key);
-- M:500: selected shard enumeration and marker FK cascade.
CREATE INDEX catalog_runtime_behaviors_shard ON catalog_runtime_behaviors(shard_key);

CREATE TABLE catalog_runtime_contract_payloads(
-- M:511; crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:688:
-- row identity / record fetch
  record_key INTEGER PRIMARY KEY,
-- M:511; crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:688:
-- active manifest/shard membership
  shard_key INTEGER NOT NULL,
-- M:511; crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/runtime_values.rs:688:
-- full record result
  record_json TEXT NOT NULL CHECK(json_valid(record_json) AND json_type(record_json) =
    'object'),
  FOREIGN KEY(shard_key) REFERENCES catalog_semantic_rows_indexed_shards(shard_key) ON DELETE
    CASCADE,
  UNIQUE(shard_key)
) STRICT;

-- Existing callable-value table structures and text keys remain unchanged.
-- Marker ownership is generalized without rebuilding their exact-source child
-- tables. Deleting one marker also discards its callable rows; anonymous
-- anchors/signature rows cascade through their existing parent FK.
CREATE TRIGGER catalog_semantic_rows_delete_callable AFTER DELETE ON
    catalog_semantic_rows_indexed_shards
BEGIN
 DELETE FROM catalog_callable_value_facts WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
 DELETE FROM catalog_callable_value_coverage WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
 DELETE FROM catalog_anonymous_callable_identities WHERE manifest_digest=OLD.manifest_digest AND
    shard_id=OLD.shard_id;
END;

-- Reader setup is connection-local and performed once when attaching the WAL
-- session catalog. Each connection belongs to exactly one active set and uses
-- SQLite's default bounded page cache. TEMP active_shards(shard_key,source_db)
-- is filled with selected shards. Every view joins records/postings/marker to
-- that TEMP table INSIDE main or session before UNION ALL. Never join DB-local
-- keys across schemas. The writer/catalog connection is separate.
-- Decode outside lock; BEGIN IMMEDIATE; recheck marker; publish if missing.
-- Nothing reindexes on catalog open. M1 still hydrates/reconciles active shards.
