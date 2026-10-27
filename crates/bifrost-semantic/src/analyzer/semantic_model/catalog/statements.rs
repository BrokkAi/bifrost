//! Raw questions on one immutable active set. Guards, ranking, composition and
//! language interpretation remain with the shared runtime algorithms.

pub const TYPES_BY_ID: &str =
    r#"SELECT t.* FROM active_catalog_declaration_types AS t WHERE t.record_id=:id;"#;

/// Batch the same indexed raw-ID question for matching search records and
/// identity conflicts. No owner/member family is hydrated by this question.
pub const TYPES_BY_IDS: &str = r#"WITH ids AS MATERIALIZED (
 SELECT DISTINCT CAST(value AS TEXT) AS id FROM json_each(:ids)
)
SELECT t.* FROM ids CROSS JOIN active_catalog_declaration_types t ON t.record_id=ids.id;"#;

pub const MEMBERS_BY_IDS: &str = r#"WITH ids AS MATERIALIZED (
 SELECT DISTINCT CAST(value AS TEXT) AS id FROM json_each(:ids)
)
SELECT m.* FROM ids CROSS JOIN active_catalog_declaration_members m ON m.record_id=ids.id;"#;

/// Raw IDs are pack-local. Count every active owner before taking the scalar
/// qualification shortcut; guarded or shared owners use the existing ranked
/// and guarded qualification reader instead. Materialize only scalar metadata
/// after the indexed seeks: aggregating directly over the compound active view
/// would materialize whole records before applying the requested IDs.
pub const SEARCH_OWNER_QUALIFICATIONS: &str = r#"WITH ids AS MATERIALIZED (
 SELECT DISTINCT CAST(value AS TEXT) AS id FROM json_each(:ids)
), selected AS MATERIALIZED (
 SELECT t.record_id,
        COALESCE(json_type(t.record_json,'$.guard') <> 'null',0) AS guarded,
        json_extract(t.record_json,'$.name') AS owner_name
 FROM ids CROSS JOIN active_catalog_declaration_types t ON t.record_id=ids.id
)
SELECT record_id AS owner_id,COUNT(*) AS record_count,MAX(guarded) AS guarded,
       MIN(owner_name) AS owner_name FROM selected GROUP BY record_id;"#;

pub const TYPES_BY_IDENTITY_NAME: &str = r#"SELECT t.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t
  USING(source_db,shard_key,record_key)
WHERE n.name=:name AND n.identity_name=1;"#;

pub const MEMBERS_BY_ID: &str =
    r#"SELECT m.* FROM active_catalog_declaration_members AS m WHERE m.record_id=:id;"#;

pub const MEMBERS_BY_OWNER_NAME: &str = r#"SELECT m.* FROM active_catalog_declaration_members AS m
WHERE m.owner_id=:owner AND m.name=:name
UNION ALL
SELECT m.* FROM active_catalog_member_aliases AS a
JOIN active_catalog_declaration_members AS m
  ON m.source_db=a.source_db AND m.shard_key=a.shard_key
 AND m.record_key=a.member_key
WHERE a.alias=:name AND m.owner_id=:owner;"#;

pub const MEMBER_IDS_BY_OWNERS: &str = r#"WITH owners AS MATERIALIZED (
  SELECT DISTINCT value FROM json_each(:owner_ids)
)
SELECT m.source_db,m.shard_key,m.record_key,m.record_id
FROM owners CROSS JOIN active_catalog_declaration_members m
WHERE m.owner_id=owners.value;"#;

pub const MEMBERS_BY_OWNERS: &str = r#"SELECT m.* FROM active_catalog_declaration_members AS m
WHERE m.owner_id IN (SELECT value FROM json_each(:owner_ids));"#;

pub const TYPES_BY_NAME: &str = r#"SELECT t.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t
  USING(source_db,shard_key,record_key)
WHERE n.name=:name;"#;

pub const TYPE_IDENTITY_NAMES: &str = r#"SELECT n.* FROM active_catalog_declaration_names AS n
WHERE n.source_db=:source_db AND n.shard_key=:shard_key
  AND n.record_key=:record_key AND n.identity_name=1;"#;

pub const GROUP_OWNER_IDS: &str = r#"SELECT t.source_db,t.shard_key,t.record_key,t.record_id
FROM active_catalog_declaration_names n
JOIN active_catalog_declaration_types t USING(source_db,shard_key,record_key)
WHERE n.name=:name AND n.language=:language AND n.namespace=:namespace
  AND n.identity_name=1;"#;

pub const GROUP_OWNERS: &str = r#"SELECT t.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t
  USING(source_db,shard_key,record_key)
WHERE n.name=:name AND n.language=:language AND n.namespace=:namespace
  AND n.identity_name=1;"#;

pub const RELATIONS_BY_ID: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.record_id=:id AND r.origin='relation_fact';"#;

pub const RELATIONS_FROM: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.from_id=:id AND r.origin='relation_fact';"#;

pub const RELATIONS_TO: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.to_id=:id AND r.origin='relation_fact';"#;

pub const OVERLAY_RELATIONS_FROM: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.from_id IN (SELECT value FROM json_each(:owner_ids));"#;

pub const OVERLAY_RELATIONS_TO: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.to_id IN (SELECT value FROM json_each(:raw_targets));"#;

pub const ANCESTOR_RELATIONS: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.from_id IN (SELECT value FROM json_each(:owner_ids))
  AND r.relation_kind IN ('extends','implements','uses_trait',
                         'mixin_include','mixin_prepend');"#;

pub const REFERENCE_RELATIONS: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r
WHERE r.to_id IN (SELECT value FROM json_each(:raw_targets))
  AND r.relation_kind='references';"#;

pub const RULES_BY_ID: &str =
    r#"SELECT g.* FROM active_catalog_generator_rules AS g WHERE g.record_id=:id;"#;

pub const RULES: &str = r#"SELECT g.* FROM active_catalog_generator_rules AS g;"#;

pub const RULES_BY_TRIGGER: &str = r#"SELECT g.* FROM active_catalog_generator_rules AS g
WHERE g.trigger_family=:family AND g.trigger_key=:key;"#;

pub const RULES_BY_CALL: &str = r#"SELECT g.* FROM active_catalog_generator_rules AS g
WHERE g.trigger_family='call' AND g.trigger_key=:owner AND g.call_member=:member;"#;

pub const SUMMARY_TARGET: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.target_path=:path AND p.target_symbol=:symbol
  AND p.has_receiver=:receiver AND p.declared_arity=:formal_arity;"#;

pub const SUMMARY_PATH: &str = "SELECT p.* FROM active_catalog_procedure_summaries p WHERE p.language=:realm AND p.target_path=:path";

pub const SUMMARY_MEMBER: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.owner_fqn IN (SELECT value FROM json_each(:owners))
  AND p.member=:member AND p.has_receiver=:receiver;"#;

pub const SUMMARY_APPLICABLE: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.owner_fqn IN (SELECT value FROM json_each(:owners))
  AND p.member=:member AND p.has_receiver=:receiver
  AND ((p.variadic=0 AND p.declared_arity=:actual_arity)
    OR (p.variadic=1 AND p.minimum_actual_count<=:actual_arity)
    OR (p.optional_minimum IS NOT NULL
        AND p.optional_minimum<=:actual_arity AND p.declared_arity>=:actual_arity));"#;

pub const SUMMARY_ABSENT_OWNERS: &str = r#"SELECT DISTINCT p.owner_fqn FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.member=:member AND p.has_receiver=:receiver
  AND p.normal_continuation_absent=1 AND p.owner_fqn IS NOT NULL;"#;

pub const SUMMARY_ABSENT_FAMILIES: &str = r#"SELECT DISTINCT p.owner_fqn,p.member,p.has_receiver
FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.normal_continuation_absent=1
  AND p.owner_fqn IS NOT NULL AND p.member IS NOT NULL;"#;

pub const SUMMARY_MEMBER_CANDIDATES: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.member=:member AND p.has_receiver=:receiver;"#;

pub const SUMMARY_RECEIVERLESS: &str = r#"SELECT 1 FROM active_catalog_procedure_summaries AS p
WHERE p.language=:realm AND p.owner_fqn=:owner AND p.member=:member
  AND p.has_receiver=0 LIMIT 1;"#;

pub const SUMMARY_TARGETS_BY_SHARD: &str = "SELECT p.source_db,p.shard_key,p.record_id,json_extract(p.record_json,'$.target') AS target_json FROM active_catalog_procedure_summaries p WHERE p.source_db=:source_db AND p.shard_key=:shard_key ORDER BY p.record_key";
pub const SUMMARY_CONTRACT_TARGETS_BY_SHARD: &str = "SELECT p.source_db,p.shard_key,p.record_id,json_extract(p.record_json,'$.target') AS target_json FROM active_catalog_procedure_summaries p WHERE p.source_db=:source_db AND p.shard_key=:shard_key AND json_array_length(p.record_json,'$.result_contracts')>0 ORDER BY p.record_key";

pub const SUMMARY_BY_ID: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p
WHERE p.source_db=:source_db AND p.shard_key=:shard_key
  AND p.record_id=:id;"#;

// The schema does not prove the first (model_id, id) key unique across
// shards. Equal first keys require the full-sequence tie-break; it must not
// be removed as redundant.
pub const SUMMARY_SHARD_SEQUENCE: &str = r#"SELECT p.record_id,json_extract(p.record_json,'$.model_id') AS model_id
FROM active_catalog_procedure_summaries AS p
WHERE p.source_db=:source_db AND p.shard_key=:shard_key
ORDER BY p.record_id;"#;

// The schema does not prove the first (model_id, id) key unique across
// shards. Equal first keys require the full-sequence tie-break; it must not
// be removed as redundant.
pub const SUMMARY_SHARD_FIRST: &str = r#"SELECT p.record_id,json_extract(p.record_json,'$.model_id') AS model_id
FROM active_catalog_procedure_summaries AS p
WHERE p.source_db=:source_db AND p.shard_key=:shard_key
ORDER BY p.record_id LIMIT 1;"#;

pub const COLLECTION_FLOWS: &str = r#"SELECT f.* FROM active_catalog_collection_flows AS f
WHERE f.callable IN (SELECT value FROM json_each(:callable_ids));"#;

pub const CONDITIONAL_REFINEMENTS: &str = r#"SELECT f.* FROM active_catalog_conditional_type_refinements AS f
WHERE f.callable IN (SELECT value FROM json_each(:callable_ids));"#;

pub const DEFERRED_YIELDS: &str = r#"SELECT y.* FROM active_catalog_deferred_yields AS y
WHERE y.factory IN (SELECT value FROM json_each(:factory_ids))
  AND y.resume=:resume AND y.handle_type=:handle_type;"#;

pub const DEFERRED_YIELDS_BY_FACTORY: &str = r#"SELECT y.* FROM active_catalog_deferred_yields AS y
WHERE y.factory IN (SELECT value FROM json_each(:factory_ids));"#;

pub const COLLECTION_FLOWS_BY_SHARD: &str = "SELECT f.* FROM active_catalog_collection_flows f WHERE f.source_db=:source_db AND f.shard_key=:shard_key ORDER BY f.record_key";
pub const CONDITIONAL_REFINEMENTS_BY_SHARD: &str = "SELECT f.* FROM active_catalog_conditional_type_refinements f WHERE f.source_db=:source_db AND f.shard_key=:shard_key ORDER BY f.record_key";
pub const DEFERRED_YIELDS_BY_SHARD: &str = "SELECT f.* FROM active_catalog_deferred_yields f WHERE f.source_db=:source_db AND f.shard_key=:shard_key ORDER BY f.record_key";
pub const RULES_BY_SHARD: &str = "SELECT f.* FROM active_catalog_generator_rules f WHERE f.source_db=:source_db AND f.shard_key=:shard_key ORDER BY f.record_key";
pub const SOURCE_TYPES: &str =
    "SELECT t.* FROM active_catalog_declaration_types t WHERE t.authored_path IS NOT NULL";
pub const SOURCE_MEMBERS: &str =
    "SELECT m.* FROM active_catalog_declaration_members m WHERE m.authored_path IS NOT NULL";

pub const RUNTIME_VALUES: &str = r#"SELECT p.* FROM active_catalog_runtime_value_payloads AS p
WHERE p.source_db=:source_db AND p.shard_key=:shard_key;"#;

pub const RUNTIME_CONTRACTS: &str = r#"SELECT p.* FROM active_catalog_runtime_contract_payloads AS p
WHERE p.source_db=:source_db AND p.shard_key=:shard_key;"#;

pub const ALL_RUNTIME_VALUES: &str =
    r#"SELECT p.* FROM active_catalog_runtime_value_payloads AS p;"#;

pub const ALL_RUNTIME_CONTRACTS: &str =
    r#"SELECT p.* FROM active_catalog_runtime_contract_payloads AS p;"#;

pub const RUNTIME_EXPOSURES: &str = r#"SELECT e.source_db,e.shard_key,e.payload_key,e.exposure_ordinal,
       p.manifest_digest,p.shard_id,
       json_extract(p.record_json,'$.exposures['||e.exposure_ordinal||']') AS exposure_json
FROM active_catalog_runtime_exposures AS e
JOIN active_catalog_runtime_value_payloads AS p
  ON p.source_db=e.source_db AND p.shard_key=e.shard_key
 AND p.record_key=e.payload_key
WHERE e.binding_name=:binding;"#;

pub const RUNTIME_BEHAVIORS: &str = r#"SELECT b.source_db,b.shard_key,b.payload_key,b.behavior_ordinal,
       p.manifest_digest,p.shard_id,
       json_extract(p.record_json,'$.behaviors['||b.behavior_ordinal||']') AS behavior_json
FROM active_catalog_runtime_behaviors AS b
JOIN active_catalog_runtime_value_payloads AS p
  ON p.source_db=b.source_db AND p.shard_key=b.shard_key
 AND p.record_key=b.payload_key
WHERE b.exposure_id=:exposure AND b.container_member=:container;"#;

pub const PAYLOAD_FAMILY_PRESENCE: &str = r#"SELECT EXISTS(
SELECT 1 FROM active_catalog_semantic_payload_families AS f
WHERE f.source_db=:source_db AND f.shard_key=:shard_key AND f.family=:family);"#;

pub const TYPE_SPELLINGS: &str = r#"SELECT t.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t USING(source_db,shard_key,record_key)
WHERE n.name=:name;"#;

pub const MEMBER_SPELLINGS: &str =
    r#"SELECT m.* FROM active_catalog_declaration_members AS m WHERE m.name=:name;"#;

pub const MEMBER_ALIASES: &str = r#"SELECT m.* FROM active_catalog_member_aliases AS a
JOIN active_catalog_declaration_members AS m
  ON m.source_db=a.source_db AND m.shard_key=a.shard_key
 AND m.record_key=a.member_key
WHERE a.alias=:name;"#;

pub const MEMBERS_QUALIFIED: &str = r#"SELECT m.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t USING(source_db,shard_key,record_key)
JOIN active_catalog_declaration_members AS m
  ON m.owner_id=t.record_id AND m.language=n.language
WHERE n.name=:owner_name AND n.identity_name=1 AND m.name=:member;"#;

pub const MEMBERS_ALIAS_QUALIFIED: &str = r#"SELECT m.* FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t USING(source_db,shard_key,record_key)
JOIN active_catalog_declaration_members AS m
  ON m.owner_id=t.record_id AND m.language=n.language
JOIN active_catalog_member_aliases AS a
  ON a.source_db=m.source_db AND a.shard_key=m.shard_key
 AND a.member_key=m.record_key
WHERE n.name=:owner_name AND n.identity_name=1 AND a.alias=:member;"#;

pub const TYPES_BY_PATH: &str =
    r#"SELECT t.* FROM active_catalog_declaration_types AS t WHERE t.authored_path=:path;"#;

pub const MEMBERS_BY_PATH: &str =
    r#"SELECT m.* FROM active_catalog_declaration_members AS m WHERE m.authored_path=:path;"#;

pub const SEARCH_TYPES: &str = r#"SELECT n.source_db,n.shard_key,n.record_key,n.manifest_digest,n.shard_id,
       n.name AS spelling,n.language,n.namespace,n.identity_name,t.record_id,t.record_json
FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t USING(source_db,shard_key,record_key);"#;

pub const SEARCH_MEMBERS: &str = r#"SELECT m.source_db,m.shard_key,m.record_key,m.manifest_digest,m.shard_id,
       m.name AS spelling,m.record_id,m.record_json
FROM active_catalog_declaration_members AS m;"#;

pub const SEARCH_RAW_QUALIFIED_MEMBERS: &str = r#"SELECT m.source_db,m.shard_key,m.record_key,m.manifest_digest,m.shard_id,
       m.owner_id||'.'||m.name AS spelling,m.record_id,m.record_json
FROM active_catalog_declaration_members AS m;"#;

pub const SEARCH_OWNER_QUALIFIED_MEMBERS: &str = r#"SELECT m.source_db,m.shard_key,m.record_key,m.manifest_digest,m.shard_id,
       json_extract(t.record_json,'$.name')||'.'||m.name AS spelling,
       m.record_id,m.record_json
FROM active_catalog_declaration_members AS m
JOIN active_catalog_declaration_types AS t ON t.record_id=m.owner_id
JOIN active_catalog_declaration_names AS n
  ON n.source_db=t.source_db AND n.shard_key=t.shard_key
 AND n.record_key=t.record_key AND n.name=json_extract(t.record_json,'$.name')
 AND n.language=m.language AND n.identity_name=1;"#;

pub const SEARCH_MEMBER_ALIASES: &str = r#"SELECT m.source_db,m.shard_key,m.record_key,m.manifest_digest,m.shard_id,
       a.alias AS spelling,m.record_id,m.record_json
FROM active_catalog_member_aliases AS a
JOIN active_catalog_declaration_members AS m
  ON m.source_db=a.source_db AND m.shard_key=a.shard_key
 AND m.record_key=a.member_key;"#;

pub const SEARCH_TYPES_LITERAL: &str = r#"SELECT n.source_db,n.shard_key,n.record_key,n.manifest_digest,n.shard_id,
       n.name AS spelling,t.record_id,t.record_json
FROM active_catalog_declaration_names AS n
JOIN active_catalog_declaration_types AS t USING(source_db,shard_key,record_key)
WHERE n.name LIKE :prefilter ESCAPE '\';"#;

pub const RELATION_ORIGINS: &str =
    "SELECT DISTINCT r.from_id FROM active_catalog_declaration_relations r ORDER BY r.from_id";

pub const ALL_RELATIONS: &str = r#"SELECT r.* FROM active_catalog_declaration_relations AS r;"#;

pub const VISIBLE_TRAIT_CANDIDATES: &str = r#"SELECT t.* FROM active_catalog_declaration_members AS m
JOIN active_catalog_declaration_types AS t ON t.record_id=m.owner_id
JOIN active_catalog_declaration_names AS n
  ON n.source_db=t.source_db AND n.shard_key=t.shard_key
 AND n.record_key=t.record_key AND n.name=json_extract(t.record_json,'$.name')
 AND n.language=m.language AND n.identity_name=1
WHERE m.name=:member AND m.language=:language AND t.type_kind='trait';"#;

pub const ALL_SUMMARIES: &str = r#"SELECT p.* FROM active_catalog_procedure_summaries AS p;"#;

pub const SUMMARIES_BY_LANGUAGE: &str =
    r#"SELECT p.* FROM active_catalog_procedure_summaries AS p WHERE p.language=:realm;"#;

pub const MEMBERS_BY_NAME_LANGUAGE: &str = "SELECT m.* FROM active_catalog_declaration_members m WHERE m.name=:name AND m.language=:language";

/// Target family before formal-shape posting selection (including variadic minima).
pub const SUMMARY_TARGET_FAMILY: &str = "SELECT p.* FROM active_catalog_procedure_summaries p WHERE p.language=:realm AND p.target_path=:path AND p.target_symbol=:symbol AND p.has_receiver=:receiver";

/// Scalar candidate buffer only; composing a candidate releases this cursor
/// before issuing nested keyed questions on the same active-set connection.
pub const SEARCH_OWNER_KEYS: &str = "SELECT DISTINCT m.language,m.owner_id FROM active_catalog_declaration_members m ORDER BY m.language,m.owner_id";
/// Owner keys come from SEARCH_OWNER_KEYS's DISTINCT pairs. Materialization
/// decodes that map once; TEXT affinity lets SQLite index both join columns.
/// Materializing the scalar member stream keeps every alias arm on that keyed
/// join in both statistics states. Both streams and the index are query-local.
pub const SEARCH_ORDERED_CANDIDATES: &str = r#"
WITH owner_names AS MATERIALIZED (
 SELECT CAST(json_extract(owner_json.value,'$.language') AS TEXT) AS language,
        CAST(json_extract(owner_json.value,'$.id') AS TEXT) AS owner_id,
        json_extract(owner_json.value,'$.name') AS name
 FROM json_each(:owner_names) AS owner_json
), member_names AS MATERIALIZED (
 SELECT m.source_db,m.shard_key,m.record_key,m.record_id,m.owner_id,m.language,m.name,
        m.name AS spelling FROM active_catalog_declaration_members m
 UNION ALL
 SELECT m.source_db,m.shard_key,m.record_key,m.record_id,m.owner_id,m.language,m.name,
        a.alias AS spelling FROM active_catalog_member_aliases a
 JOIN active_catalog_declaration_members m
   ON m.source_db=a.source_db AND m.shard_key=a.shard_key AND m.record_key=a.member_key
), candidates AS (
 SELECT t.source_db,t.shard_key,t.record_key,t.record_id,NULL AS owner_id,n.language AS language,
        json_extract(t.record_json,'$.name') AS qualified_name,
        n.name AS spelling,json_extract(t.record_json,'$.name') AS record_name
 FROM active_catalog_declaration_types t JOIN active_catalog_declaration_names n
 USING(source_db,shard_key,record_key)
 UNION ALL
 SELECT m.source_db,m.shard_key,m.record_key,m.record_id,m.owner_id,m.language,
        COALESCE(o.name,m.owner_id)||'.'||m.name,
        m.spelling,m.name AS record_name
 FROM member_names m LEFT JOIN owner_names o
   ON o.language=m.language AND o.owner_id=m.owner_id
)
SELECT c.*,json_extract(s.value,'$.digest') AS pack_digest
FROM candidates c JOIN json_each(:shards) s
  ON json_extract(s.value,'$.source_db')=c.source_db
 AND json_extract(s.value,'$.shard_key')=c.shard_key
ORDER BY c.qualified_name,c.record_id,pack_digest;
"#;

pub const ALL_TYPES: &str = "SELECT r.* FROM active_catalog_declaration_types r";

pub const ALL_MEMBERS: &str = "SELECT r.* FROM active_catalog_declaration_members r";

pub const ALL_COLLECTION_FLOWS: &str = "SELECT r.* FROM active_catalog_collection_flows r";

pub const ALL_CONDITIONAL_REFINEMENTS: &str =
    "SELECT r.* FROM active_catalog_conditional_type_refinements r";

pub const ALL_DEFERRED_YIELDS: &str = "SELECT r.* FROM active_catalog_deferred_yields r";

pub const ALL_RUNTIME_EXPOSURES: &str = "SELECT r.* FROM active_catalog_runtime_exposures r";

pub const ALL_RUNTIME_BEHAVIORS: &str = "SELECT r.* FROM active_catalog_runtime_behaviors r";

/// The product statements, shared with the schema/decoded parity oracle.
pub const RAW_STATEMENTS: &[(&str, &str)] = &[
    ("SUMMARY_TARGETS_BY_SHARD", SUMMARY_TARGETS_BY_SHARD),
    (
        "SUMMARY_CONTRACT_TARGETS_BY_SHARD",
        SUMMARY_CONTRACT_TARGETS_BY_SHARD,
    ),
    ("COLLECTION_FLOWS_BY_SHARD", COLLECTION_FLOWS_BY_SHARD),
    (
        "CONDITIONAL_REFINEMENTS_BY_SHARD",
        CONDITIONAL_REFINEMENTS_BY_SHARD,
    ),
    ("DEFERRED_YIELDS_BY_SHARD", DEFERRED_YIELDS_BY_SHARD),
    ("RULES_BY_SHARD", RULES_BY_SHARD),
    ("SOURCE_TYPES", SOURCE_TYPES),
    ("SOURCE_MEMBERS", SOURCE_MEMBERS),
    ("ALL_RUNTIME_BEHAVIORS", ALL_RUNTIME_BEHAVIORS),
    ("ALL_RUNTIME_EXPOSURES", ALL_RUNTIME_EXPOSURES),
    ("ALL_DEFERRED_YIELDS", ALL_DEFERRED_YIELDS),
    ("ALL_CONDITIONAL_REFINEMENTS", ALL_CONDITIONAL_REFINEMENTS),
    ("ALL_COLLECTION_FLOWS", ALL_COLLECTION_FLOWS),
    ("ALL_MEMBERS", ALL_MEMBERS),
    ("SEARCH_OWNER_KEYS", SEARCH_OWNER_KEYS),
    ("SEARCH_ORDERED_CANDIDATES", SEARCH_ORDERED_CANDIDATES),
    ("ALL_TYPES", ALL_TYPES),
    ("SUMMARY_TARGET_FAMILY", SUMMARY_TARGET_FAMILY),
    ("SUMMARY_PATH", SUMMARY_PATH),
    ("TYPES_BY_ID", TYPES_BY_ID),
    ("TYPES_BY_IDS", TYPES_BY_IDS),
    ("MEMBERS_BY_IDS", MEMBERS_BY_IDS),
    ("SEARCH_OWNER_QUALIFICATIONS", SEARCH_OWNER_QUALIFICATIONS),
    ("TYPES_BY_IDENTITY_NAME", TYPES_BY_IDENTITY_NAME),
    ("MEMBERS_BY_ID", MEMBERS_BY_ID),
    ("MEMBERS_BY_OWNER_NAME", MEMBERS_BY_OWNER_NAME),
    ("MEMBERS_BY_OWNERS", MEMBERS_BY_OWNERS),
    ("MEMBER_IDS_BY_OWNERS", MEMBER_IDS_BY_OWNERS),
    ("TYPES_BY_NAME", TYPES_BY_NAME),
    ("TYPE_IDENTITY_NAMES", TYPE_IDENTITY_NAMES),
    ("GROUP_OWNERS", GROUP_OWNERS),
    ("GROUP_OWNER_IDS", GROUP_OWNER_IDS),
    ("RELATIONS_BY_ID", RELATIONS_BY_ID),
    ("RELATIONS_FROM", RELATIONS_FROM),
    ("RELATIONS_TO", RELATIONS_TO),
    ("OVERLAY_RELATIONS_FROM", OVERLAY_RELATIONS_FROM),
    ("OVERLAY_RELATIONS_TO", OVERLAY_RELATIONS_TO),
    ("ANCESTOR_RELATIONS", ANCESTOR_RELATIONS),
    ("REFERENCE_RELATIONS", REFERENCE_RELATIONS),
    ("RULES_BY_ID", RULES_BY_ID),
    ("RULES", RULES),
    ("RULES_BY_TRIGGER", RULES_BY_TRIGGER),
    ("RULES_BY_CALL", RULES_BY_CALL),
    ("SUMMARY_TARGET", SUMMARY_TARGET),
    ("SUMMARY_MEMBER", SUMMARY_MEMBER),
    ("SUMMARY_APPLICABLE", SUMMARY_APPLICABLE),
    ("SUMMARY_ABSENT_OWNERS", SUMMARY_ABSENT_OWNERS),
    ("SUMMARY_ABSENT_FAMILIES", SUMMARY_ABSENT_FAMILIES),
    ("SUMMARY_MEMBER_CANDIDATES", SUMMARY_MEMBER_CANDIDATES),
    ("SUMMARY_RECEIVERLESS", SUMMARY_RECEIVERLESS),
    ("SUMMARY_BY_ID", SUMMARY_BY_ID),
    ("SUMMARY_SHARD_SEQUENCE", SUMMARY_SHARD_SEQUENCE),
    ("SUMMARY_SHARD_FIRST", SUMMARY_SHARD_FIRST),
    ("COLLECTION_FLOWS", COLLECTION_FLOWS),
    ("CONDITIONAL_REFINEMENTS", CONDITIONAL_REFINEMENTS),
    ("DEFERRED_YIELDS", DEFERRED_YIELDS),
    ("DEFERRED_YIELDS_BY_FACTORY", DEFERRED_YIELDS_BY_FACTORY),
    ("RUNTIME_VALUES", RUNTIME_VALUES),
    ("RUNTIME_CONTRACTS", RUNTIME_CONTRACTS),
    ("ALL_RUNTIME_VALUES", ALL_RUNTIME_VALUES),
    ("ALL_RUNTIME_CONTRACTS", ALL_RUNTIME_CONTRACTS),
    ("RUNTIME_EXPOSURES", RUNTIME_EXPOSURES),
    ("RUNTIME_BEHAVIORS", RUNTIME_BEHAVIORS),
    ("PAYLOAD_FAMILY_PRESENCE", PAYLOAD_FAMILY_PRESENCE),
    ("TYPE_SPELLINGS", TYPE_SPELLINGS),
    ("MEMBER_SPELLINGS", MEMBER_SPELLINGS),
    ("MEMBER_ALIASES", MEMBER_ALIASES),
    ("MEMBERS_QUALIFIED", MEMBERS_QUALIFIED),
    ("MEMBERS_ALIAS_QUALIFIED", MEMBERS_ALIAS_QUALIFIED),
    ("TYPES_BY_PATH", TYPES_BY_PATH),
    ("MEMBERS_BY_PATH", MEMBERS_BY_PATH),
    ("SEARCH_TYPES", SEARCH_TYPES),
    ("SEARCH_MEMBERS", SEARCH_MEMBERS),
    ("SEARCH_RAW_QUALIFIED_MEMBERS", SEARCH_RAW_QUALIFIED_MEMBERS),
    (
        "SEARCH_OWNER_QUALIFIED_MEMBERS",
        SEARCH_OWNER_QUALIFIED_MEMBERS,
    ),
    ("SEARCH_MEMBER_ALIASES", SEARCH_MEMBER_ALIASES),
    ("SEARCH_TYPES_LITERAL", SEARCH_TYPES_LITERAL),
    ("ALL_RELATIONS", ALL_RELATIONS),
    ("RELATION_ORIGINS", RELATION_ORIGINS),
    ("VISIBLE_TRAIT_CANDIDATES", VISIBLE_TRAIT_CANDIDATES),
    ("ALL_SUMMARIES", ALL_SUMMARIES),
    ("SUMMARIES_BY_LANGUAGE", SUMMARIES_BY_LANGUAGE),
    ("MEMBERS_BY_NAME_LANGUAGE", MEMBERS_BY_NAME_LANGUAGE),
];
