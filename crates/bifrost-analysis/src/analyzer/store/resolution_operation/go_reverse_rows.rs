//! Query-local Go reverse candidates from selected package rows and shared
//! reference lookup identities. Every row is provisional until the selected
//! Go forward operation confirms it.

use super::*;
use crate::analyzer::resolution::seam_profile::{
    GoReverseCandidateDiagnostic, GoReverseFallbackCause,
};
use crate::analyzer::resolution::{
    LoweredSemanticRole, MAX_REFERENCE_SEEDS_PER_BATCH, ResolutionLookupSemanticRecipe,
    SelectedSemanticLocator, SharedNameInterner,
};
use crate::analyzer::store::resolution_operation::native_units;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_RESOLUTION_NAMESPACES, ResolutionNamespace, ResolutionSiteKind,
};
use brokk_bifrost_go::declarations::go_identifier_is_exported;
use rusqlite::{OptionalExtension, params};

#[cfg(test)]
thread_local! {
    static LAST_GO_REVERSE_CANDIDATE_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static LAST_GO_REVERSE_CANDIDATE_PATHS: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static LAST_GO_REVERSE_DEFINITION_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static LAST_GO_REVERSE_ALIAS_FALLBACKS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static LAST_GO_REVERSE_QUALIFIED_IMPORTS: std::cell::RefCell<Vec<(u32, u32, Option<i64>)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

fn record_go_reverse_fallback(cause: GoReverseFallbackCause) {
    crate::analyzer::resolution::seam_profile::record_go_reverse_fallback(cause);
    #[cfg(test)]
    if matches!(cause, GoReverseFallbackCause::AliasUnresolved) {
        LAST_GO_REVERSE_ALIAS_FALLBACKS.with(|count| count.set(count.get() + 1));
    }
}

fn classify_go_reverse_path_evidence_miss(
    connection: &rusqlite::Connection,
    candidate: &GoReverseCandidate,
) -> Result<GoReverseCandidateDiagnostic> {
    let site = candidate
        .locator
        .source_site()
        .expect("Go reverse candidate has a source-site locator")
        .get();
    let path_uses_site_key: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM main.resolution_paths AS path
           WHERE path.blob_id=?1 AND path.start_node=?2
         )",
        params![candidate.blob_id, site],
        |row| row.get(0),
    )?;
    let path_uses_mapped_key: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1
           FROM main.resolution_semantic_sites AS semantic
           JOIN main.resolution_paths AS path
             ON path.blob_id=semantic.blob_id
            AND path.start_node=semantic.semantic_key
           WHERE semantic.blob_id=?1 AND semantic.semantic_role='reference'
             AND (semantic.source_site=?2 OR semantic.semantic_key=?2)
         )",
        params![candidate.blob_id, site],
        |row| row.get(0),
    )?;
    Ok(if path_uses_site_key || path_uses_mapped_key {
        GoReverseCandidateDiagnostic::PathSiteKeyMismatch
    } else {
        GoReverseCandidateDiagnostic::NonNameReference
    })
}

// Admit source members before confirming candidates or their completeness.
// A go member stays in scope even when mounted in an augmented test variant.
pub(crate) const GO_REVERSE_CANDIDATE_SITES_SQL: &str = r#"
WITH RECURSIVE target_package(package_id, tool_import_path, package_name) AS (
  SELECT package.package_id, package.tool_import_path, package.package_name
  FROM main.go_package_files AS members
  JOIN main.go_package_instances AS package
    ON package.package_id=members.package_id
  WHERE package.context_id=?1 AND members.file_version_id=?2
), visible_packages(package_id) AS (
  SELECT package_id FROM target_package
  UNION
  SELECT test_package.package_id
  FROM main.go_package_instances AS test_package
  JOIN target_package AS target ON test_package.for_test=target.tool_import_path
  WHERE test_package.context_id=?1 AND test_package.for_test<>''
    AND (?4=1 OR test_package.package_name=target.package_name)
  UNION
  SELECT imports.importer_package_id
  FROM main.go_package_imports AS imports INDEXED BY idx_go_package_imports_target
  JOIN visible_packages AS visible ON visible.package_id=imports.target_package_id
  WHERE imports.context_id=?1 AND ?4=1
), candidate_mounts(mount_ordinal, source_role, package_id, transient, summary_role) AS (
  SELECT mounted.mount_ordinal, members.source_role, package.package_id, 0,
         CASE WHEN package.for_test<>'' AND members.source_role='go'
              THEN CASE WHEN package.package_name=(
                   SELECT base.package_name FROM main.go_package_instances AS base
                   WHERE base.context_id=package.context_id
                     AND base.tool_import_path=package.for_test AND base.for_test=''
                   LIMIT 1) THEN 'test' ELSE 'xtest' END
              ELSE members.source_role END
  FROM visible_packages AS visible
  CROSS JOIN main.go_package_instances AS package
    ON package.context_id=?1 AND package.package_id=visible.package_id
  CROSS JOIN main.go_package_files AS members
    ON members.package_id=package.package_id
  JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.file_version_id=members.file_version_id
  WHERE mounted.storage_language='go'
    AND (?5=1 OR members.source_role NOT IN ('test','xtest'))
  UNION
  SELECT placed.mount_ordinal, members.source_role, package.package_id, 1,
         CASE WHEN package.for_test<>'' AND members.source_role='go'
              THEN CASE WHEN package.package_name=(
                   SELECT base.package_name FROM main.go_package_instances AS base
                   WHERE base.context_id=package.context_id
                     AND base.tool_import_path=package.for_test AND base.for_test=''
                   LIMIT 1) THEN 'test' ELSE 'xtest' END
              ELSE members.source_role END
  FROM visible_packages AS visible
  CROSS JOIN main.go_package_instances AS package
    ON package.context_id=?1 AND package.package_id=visible.package_id
  CROSS JOIN main.go_package_files AS members
    ON members.package_id=package.package_id
  JOIN temp.selected_go_transient_placements AS placed
    ON placed.file_version_id=members.file_version_id
  JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  WHERE mounted.storage_language='go'
    AND (?5=1 OR members.source_role NOT IN ('test','xtest'))
)
SELECT mounted.mount_ordinal, mounted.persisted_relative_path,
       candidate.source_role, mounted.blob_id, candidate.package_id,
       candidate.transient, package.tool_import_path, package.for_test,
       candidate.summary_role,
       EXISTS(
         SELECT 1 FROM temp.selected_resolution_overlay_masks AS mask
         WHERE mask.storage_language='go'
           AND mask.persisted_relative_path=mounted.persisted_relative_path
       ) AS overlay_masked,
       EXISTS(
         SELECT 1 FROM main.resolution_qualified_routes AS qualified
           INDEXED BY resolution_qualified_routes_source_lookup
         WHERE qualified.blob_id=mounted.blob_id AND qualified.source_lookup=?3
       ) AS has_qualified_route,
       EXISTS(
         SELECT 1 FROM main.resolution_paths AS root
           INDEXED BY resolution_paths_root_terminal
         WHERE root.blob_id=mounted.blob_id AND root.root_terminal=?3
           AND root.end_node=-1
       ) AS has_root_demand
FROM candidate_mounts AS candidate
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.mount_ordinal=candidate.mount_ordinal
JOIN main.go_package_instances AS package
  ON package.context_id=?1 AND package.package_id=candidate.package_id
WHERE mounted.storage_language='go'
  AND (
    EXISTS(
      SELECT 1 FROM main.resolution_reference_lookup_identities AS names
        INDEXED BY resolution_reference_lookup_identities_identity
      WHERE names.blob_id=mounted.blob_id AND names.identity_id=?3
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_qualified_routes AS qualified
        INDEXED BY resolution_qualified_routes_source_lookup
      WHERE qualified.blob_id=mounted.blob_id AND qualified.source_lookup=?3
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_paths AS root
        INDEXED BY resolution_paths_root_terminal
      WHERE root.blob_id=mounted.blob_id AND root.root_terminal=?3
        AND root.end_node=-1
    )
  )
"#;

const GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL: &str = r#"
SELECT mounted.persisted_relative_path,
       declaration.name_start_byte, declaration.name_end_byte,
       declaration.name_start_line, declaration.name_end_line
FROM temp.selected_resolution_mounts AS mounted
JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=mounted.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=?2
JOIN main.source_fact_manifests AS source
  ON source.blob_id=mounted.blob_id AND source.publication_state='complete'
JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_declarations AS declaration
  ON declaration.blob_id=bridge.blob_id
 AND declaration.declaration_id=bridge.declaration_id
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
  AND declaration.name_occurrence_id IS NOT NULL
"#;

pub(crate) static GO_TARGET_DEFINITION_SEMANTICS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT DISTINCT semantic.semantic_key,semantic.namespace,semantic.source_site
FROM temp.selected_resolution_mounts AS mount
JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
 AND interior.semantic_language=mount.semantic_language
 AND interior.producer_epoch=mount.producer_epoch
 AND interior.interior_digest=mount.interior_digest
 AND interior.publication_state='complete'
JOIN main.source_fact_manifests AS source
  ON source.blob_id=interior.blob_id AND source.publication_state='complete'
JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_declaration_units AS link
  ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id
JOIN main.code_units AS units
  ON units.blob_id=link.blob_id AND units.unit_key=link.unit_key
JOIN main.blobs AS keys ON keys.id=units.blob_id
JOIN main.blob_meta AS meta ON meta.blob_id=units.blob_id
WHERE mount.mount_ordinal=?1 AND units.in_declarations=1
  AND {complete}
ORDER BY semantic.semantic_key,semantic.namespace
"#,
            complete = super::super::PARSED_BLOB_COMPLETE_CONDITION,
        )
    });

pub(crate) const GO_REVERSE_SUMMARY_EXPORT_ROWS_SQL: &str = r#"
WITH demanded(identity_id,namespace) AS (
  SELECT CAST(value->>0 AS INTEGER),value->>1 FROM json_each(?2)
)
SELECT demanded.identity_id,demanded.namespace,
       export.visibility,export.origin,export.alias_dependency_ordinal,
       export.alias_identity_id,export.declaration_blob_id,export.declaration_site,
       EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
         WHERE gap.summary_id=?1 AND gap.gap_kind='incomplete_provider'
       AND (json_type(gap.detail)<>'array'
         OR json_array_length(gap.detail)=0
         OR EXISTS(
           SELECT 1 FROM json_each(gap.detail) AS package_gap
           WHERE COALESCE(json_extract(package_gap.value,'$.code'),'') NOT IN (
             'source_file_build_selection_unavailable',
             'source_build_constraint_facts_unavailable')))),
       EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
         WHERE gap.summary_id=?1 AND gap.gap_kind='conflicting_names'
           AND gap.subject=demanded.namespace||':'||CAST(demanded.identity_id AS TEXT)),
       (?4=1 AND EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_members AS member
         JOIN temp.selected_resolution_overlay_masks AS mask
           ON mask.storage_language='go'
          AND mask.persisted_relative_path=member.rel_path
         WHERE member.summary_id=?1 AND NOT (
           ?12=1 AND EXISTS(
             SELECT 1 FROM temp.selected_go_transient_placements AS placed
             JOIN temp.selected_resolution_mounts AS mounted
               ON mounted.mount_ordinal=placed.mount_ordinal
             WHERE mounted.persisted_relative_path=member.rel_path)))),
       CASE WHEN export.origin IN ('alias','reexport')
            THEN CASE WHEN export.alias_dependency_ordinal IS NULL
                      THEN ?1 ELSE child.summary_id END END,
       (export.origin IN ('alias','reexport')
        AND export.alias_dependency_ordinal IS NOT NULL
        AND child.summary_id IS NULL),
       EXISTS(
         SELECT 1 FROM json_each(?11) AS target
         JOIN temp.selected_resolution_mounts AS target_mount
           ON target_mount.mount_ordinal=CAST(target.value->>0 AS INTEGER)
          AND target_mount.blob_id=export.declaration_blob_id
         WHERE CAST(target.value->>1 AS INTEGER)=export.declaration_site)
FROM demanded
LEFT JOIN main.resolution_unit_summary_exports AS export
  ON export.summary_id=?1 AND export.identity_id=demanded.identity_id
 AND export.namespace=demanded.namespace
 AND (?3=0 OR export.visibility='exported')
 AND NOT EXISTS(
       SELECT 1 FROM main.resolution_unit_summary_members AS masked_member
       JOIN temp.selected_resolution_overlay_masks AS mask
         ON mask.storage_language='go'
        AND mask.persisted_relative_path=masked_member.rel_path
       WHERE masked_member.summary_id=export.summary_id
         AND masked_member.blob_id=export.declaration_blob_id)
LEFT JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=export.summary_id
 AND dependency.dependency_ordinal=export.alias_dependency_ordinal
LEFT JOIN main.resolution_unit_summary_versions AS versions
  ON export.alias_dependency_ordinal IS NOT NULL
 AND versions.workspace_id=?5 AND versions.lang='go' AND versions.generation=?6
 AND versions.unit_key=dependency.dependency_unit_key AND versions.valid_from<=?7
 AND (versions.valid_until IS NULL OR ?7<versions.valid_until)
LEFT JOIN main.resolution_unit_summaries AS child
  ON child.summary_id=versions.summary_id
 AND child.publication_state='complete'
 AND child.producer_epoch=?8 AND child.derivation_version=?9
 AND EXISTS(
   SELECT 1 FROM main.resolution_unit_summary_reads AS profile
   WHERE profile.summary_id=child.summary_id
     AND profile.key_digest=bifrost_go_profile_read_key(versions.unit_key)
     AND profile.digest=?10)
"#;

/// A selected overlay's own export replaces the saved member it masks. The
/// target's site coordinate is joined only within that transient blob.
pub(crate) const GO_REVERSE_TRANSIENT_TARGET_EXPORTS_SQL: &str = r#"
WITH targets(mount_ordinal,source_site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?2)
), demanded(identity_id,namespace) AS (
  SELECT CAST(value->>0 AS INTEGER),value->>1
  FROM json_each(?3)
)
SELECT catalog.shared_identity,members.namespace,identities.spelling,
       members.blob_id,members.source_site
FROM targets AS target
CROSS JOIN temp.selected_go_transient_placements AS placed
  ON placed.mount_ordinal=target.mount_ordinal
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.mount_ordinal=placed.mount_ordinal
CROSS JOIN main.resolution_unit_summary_members AS unit_member
  ON unit_member.summary_id=?1
 AND unit_member.rel_path=mounted.persisted_relative_path
CROSS JOIN main.resolution_package_members AS members
  ON members.blob_id=mounted.blob_id AND members.source_site=target.source_site
CROSS JOIN main.resolution_semantic_catalog AS catalog
  ON catalog.blob_id=members.blob_id AND catalog.local_key=members.lookup_key
CROSS JOIN main.resolution_identities AS identities
  ON identities.id=catalog.shared_identity
CROSS JOIN demanded
  ON demanded.identity_id=catalog.shared_identity
 AND demanded.namespace=members.namespace
WHERE NOT EXISTS(
  SELECT 1 FROM main.source_go_aliases AS alias
  WHERE alias.blob_id=members.blob_id AND alias.name=identities.spelling)
"#;

/// Rebuild alias export rows for overlaid members from their transient Go facts.
pub(crate) const GO_REVERSE_TRANSIENT_ALIAS_EXPORTS_SQL: &str = r#"
WITH demanded(identity_id,namespace) AS (
  SELECT CAST(value->>0 AS INTEGER),value->>1 FROM json_each(?2)
), target_declarations(mount_ordinal,source_site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?12)
), transient_members AS (
  SELECT mounted.mount_ordinal,mounted.blob_id
  FROM main.resolution_unit_summary_members AS member
  JOIN temp.selected_resolution_overlay_masks AS mask
    ON mask.storage_language='go' AND mask.persisted_relative_path=member.rel_path
  JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.persisted_relative_path=member.rel_path
  JOIN temp.selected_go_transient_placements AS placed
    ON placed.mount_ordinal=mounted.mount_ordinal
  WHERE member.summary_id=?1
)
SELECT alias_identity.id,alias_identity.spelling,
       target_identity.id,
       CASE WHEN qualifier.name IS NULL
              OR target_package.package_id IS NULL
              OR NOT ((source_import.alias IS NOT NULL
                       AND source_import.alias NOT IN ('.','_')
                       AND source_import.alias=qualifier.name)
                    OR (source_import.alias IS NULL
                        AND target_package.package_name=qualifier.name))
            THEN NULL
            ELSE bifrost_go_unit_key(
              target_package.tool_import_path,target_package.for_test,
              CASE WHEN target_package.for_test='' THEN 'go'
                   WHEN EXISTS(
                     SELECT 1 FROM main.go_package_files AS tests
                     WHERE tests.package_id=target_package.package_id
                       AND tests.source_role='xtest') THEN 'xtest'
                   ELSE 'test' END)
       END,
       (qualifier.name IS NOT NULL),
       EXISTS(
         SELECT 1 FROM target_declarations AS target
         WHERE target.mount_ordinal=transient.mount_ordinal
           AND target.source_site=member.source_site)
FROM transient_members AS transient
JOIN main.source_go_aliases AS alias
  ON alias.blob_id=transient.blob_id
JOIN main.resolution_package_members AS member
  ON member.blob_id=alias.blob_id AND member.namespace='type'
JOIN main.resolution_semantic_catalog AS catalog
  ON catalog.blob_id=member.blob_id AND catalog.local_key=member.lookup_key
JOIN main.resolution_identities AS alias_identity
  ON alias_identity.id=catalog.shared_identity
 AND alias_identity.spelling=alias.name
JOIN demanded
  ON demanded.identity_id=alias_identity.id AND demanded.namespace='type'
LEFT JOIN main.source_go_types AS target_type
  ON target_type.blob_id=alias.blob_id
 AND target_type.type_id=alias.target_type_id AND target_type.kind=0
LEFT JOIN main.source_occurrence_arenas AS target_arena
  ON target_arena.blob_id=alias.blob_id
LEFT JOIN json_each(target_arena.spans) AS target_occurrence
  ON target_occurrence.key=CAST(target_type.occurrence_id AS TEXT)
LEFT JOIN main.source_go_type_names AS qualifier
  ON qualifier.blob_id=target_type.blob_id
 AND qualifier.type_id=target_type.type_id AND qualifier.ordinal=0
LEFT JOIN main.source_go_type_names AS terminal_name
  ON terminal_name.blob_id=target_type.blob_id
 AND terminal_name.type_id=target_type.type_id AND terminal_name.ordinal=1
LEFT JOIN main.resolution_sites AS target_site
  ON target_site.blob_id=alias.blob_id AND target_site.role=0
 AND target_site.start_byte>=CAST(json_extract(
       CASE WHEN target_occurrence.type='array' THEN target_occurrence.value ELSE '[]' END,
       '$[0]') AS INTEGER)
 AND target_site.end_byte<=CAST(json_extract(
       CASE WHEN target_occurrence.type='array' THEN target_occurrence.value ELSE '[]' END,
       '$[1]') AS INTEGER)
LEFT JOIN main.resolution_paths AS target_path
  ON target_path.blob_id=target_site.blob_id
 AND target_path.start_node=target_site.site
LEFT JOIN main.resolution_identities AS target_identity
  ON target_identity.id=CASE WHEN target_path.end_node=-1
                             THEN target_path.root_terminal
                             ELSE target_path.end_lead_identity END
 AND target_identity.spelling=COALESCE(terminal_name.name,qualifier.name)
LEFT JOIN main.resolution_go_package_imports AS binder
  ON binder.blob_id=alias.blob_id AND binder.kind='named'
LEFT JOIN main.source_imports AS source_import
  ON source_import.blob_id=binder.blob_id
 AND source_import.declaration_start_byte=binder.start_byte
 AND source_import.declaration_end_byte=binder.end_byte
LEFT JOIN main.go_package_imports AS selected_import
  ON selected_import.context_id=?5
 AND selected_import.importer_package_id=?3
 AND selected_import.import_role=?4
 AND selected_import.source_spelling=(
       SELECT group_concat(segment,'/') FROM (
         SELECT segment FROM main.source_import_segments
         WHERE blob_id=source_import.blob_id
           AND import_id=source_import.import_id
         ORDER BY ordinal))
LEFT JOIN main.go_package_instances AS target_package
  ON target_package.context_id=selected_import.context_id
 AND target_package.package_id=selected_import.target_package_id
"#;

// Resolved source packages contribute their selected package clause name. An
// unresolved import still has a parser-owned default binder spelling in
// source_imports.identifier; reading it lets the summary answer unresolved
// without rebuilding the old forward import context.
pub(crate) const GO_REVERSE_QUALIFIED_IMPORT_SQL: &str = r#"
WITH scope_spellings(scope_key,spelling) AS (
  SELECT DISTINCT CAST(value->>0 AS INTEGER),value->>1
  FROM json_each(?4)
)
SELECT DISTINCT source_import.import_id,
       COALESCE(imports.kind,binder.kind),
       COALESCE(imports.state,
         CASE WHEN ?7=1
              THEN CASE WHEN overlay_target.package_id IS NULL
                        THEN 'unresolved' ELSE 'resolved' END
         END),
       COALESCE(dependency.dependency_unit_key,
         CASE WHEN ?7=1 AND overlay_target.package_id IS NOT NULL
              THEN overlay_target.unit_key
         END)
FROM scope_spellings AS scope
CROSS JOIN main.resolution_go_package_imports AS binder
  INDEXED BY resolution_go_package_imports_scope
  ON binder.blob_id=?3 AND binder.file_scope_key=scope.scope_key
CROSS JOIN main.source_imports AS source_import
  ON source_import.blob_id=binder.blob_id
 AND source_import.declaration_start_byte=binder.start_byte
 AND source_import.declaration_end_byte=binder.end_byte
LEFT JOIN main.resolution_unit_summary_imports AS imports
  ON imports.summary_id=?1 AND imports.blob_id=source_import.blob_id
 AND imports.import_id=source_import.import_id
LEFT JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=imports.summary_id
 AND dependency.dependency_ordinal=imports.dependency_ordinal
LEFT JOIN main.go_package_instances AS target_package
  ON target_package.context_id=?2
 AND target_package.unit_key=dependency.dependency_unit_key
LEFT JOIN main.go_package_imports AS overlay_import
  ON ?7=1 AND overlay_import.context_id=?2
 AND overlay_import.importer_package_id=?5
 AND overlay_import.import_role=?6
 AND overlay_import.source_spelling=(
       SELECT group_concat(segment,'/') FROM (
         SELECT segment FROM main.source_import_segments
         WHERE blob_id=source_import.blob_id
           AND import_id=source_import.import_id
         ORDER BY ordinal))
LEFT JOIN main.go_package_instances AS overlay_target
  ON overlay_target.context_id=overlay_import.context_id
 AND overlay_target.package_id=overlay_import.target_package_id
WHERE binder.kind='named'
  AND (source_import.alias=scope.spelling
       OR (source_import.alias IS NULL
           AND (target_package.package_name=scope.spelling
                OR (COALESCE(imports.state,
                     CASE WHEN ?7=1 AND overlay_target.package_id IS NULL
                          THEN 'unresolved' END)='unresolved'
                    AND source_import.identifier=scope.spelling))))
"#;

pub(crate) const GO_REVERSE_DOT_EXPORT_ROWS_SQL: &str = r#"
WITH dot_imports AS (
  SELECT COALESCE(imports.state,
           CASE WHEN ?14=1
                THEN CASE WHEN overlay_target.package_id IS NULL
                          THEN 'unresolved' ELSE 'resolved' END END) AS state,
         COALESCE(dependency.dependency_unit_key,
           CASE WHEN ?14=1 AND overlay_target.package_id IS NOT NULL
                THEN overlay_target.unit_key END) AS dependency_unit_key
  FROM main.source_imports AS source_import
  LEFT JOIN main.resolution_unit_summary_imports AS imports
    ON imports.summary_id=?1 AND imports.blob_id=source_import.blob_id
   AND imports.import_id=source_import.import_id
  LEFT JOIN main.resolution_unit_summary_dependencies AS dependency
    ON dependency.summary_id=imports.summary_id
   AND dependency.dependency_ordinal=imports.dependency_ordinal
  LEFT JOIN main.go_package_imports AS overlay_import
    ON ?14=1 AND overlay_import.context_id=?11
   AND overlay_import.importer_package_id=?12
   AND overlay_import.import_role=?13
   AND overlay_import.source_spelling=(
         SELECT group_concat(segment,'/') FROM (
           SELECT segment FROM main.source_import_segments
           WHERE blob_id=source_import.blob_id
             AND import_id=source_import.import_id
           ORDER BY ordinal))
  LEFT JOIN main.go_package_instances AS overlay_target
    ON overlay_target.context_id=overlay_import.context_id
   AND overlay_target.package_id=overlay_import.target_package_id
  WHERE source_import.blob_id=?2 AND source_import.alias='.'
), live_children AS (
  SELECT dot.state,dot.dependency_unit_key AS unit_key,summary.summary_id
  FROM dot_imports AS dot
  LEFT JOIN main.resolution_unit_summary_versions AS versions
    ON versions.workspace_id=?4 AND versions.lang='go' AND versions.generation=?5
   AND versions.unit_key=dot.dependency_unit_key AND versions.valid_from<=?6
   AND (versions.valid_until IS NULL OR ?6<versions.valid_until)
  LEFT JOIN main.resolution_unit_summaries AS summary
    ON summary.summary_id=versions.summary_id
   AND summary.publication_state='complete'
   AND summary.producer_epoch=?7 AND summary.derivation_version=?8
   AND EXISTS(
     SELECT 1 FROM main.resolution_unit_summary_reads AS profile
     WHERE profile.summary_id=summary.summary_id
       AND profile.key_digest=bifrost_go_profile_read_key(versions.unit_key)
       AND profile.digest=?9)
)
SELECT child.state,child.unit_key,child.summary_id,
       demanded.identity_id,demanded.namespace,
       export.visibility,export.origin,export.alias_dependency_ordinal,
       export.alias_identity_id,export.declaration_blob_id,export.declaration_site,
       EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
         WHERE gap.summary_id=child.summary_id AND gap.gap_kind='incomplete_provider'
       AND (json_type(gap.detail)<>'array'
         OR json_array_length(gap.detail)=0
         OR EXISTS(
           SELECT 1 FROM json_each(gap.detail) AS package_gap
           WHERE COALESCE(json_extract(package_gap.value,'$.code'),'') NOT IN (
             'source_file_build_selection_unavailable',
             'source_build_constraint_facts_unavailable')))),
       EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
         WHERE gap.summary_id=child.summary_id AND gap.gap_kind='conflicting_names'
           AND gap.subject=demanded.namespace||':'||CAST(demanded.identity_id AS TEXT)),
       EXISTS(
         SELECT 1 FROM main.resolution_unit_summary_members AS member
         JOIN temp.selected_resolution_overlay_masks AS mask
           ON mask.storage_language='go'
          AND mask.persisted_relative_path=member.rel_path
         WHERE member.summary_id=child.summary_id),
       dependency.dependency_unit_key,
       CASE WHEN export.origin IN ('alias','reexport')
            THEN CASE WHEN export.alias_dependency_ordinal IS NULL
                      THEN child.summary_id ELSE alias_child.summary_id END END,
       (export.origin IN ('alias','reexport')
        AND export.alias_dependency_ordinal IS NOT NULL
        AND alias_child.summary_id IS NULL),
       EXISTS(
         SELECT 1 FROM json_each(?10) AS target
         JOIN temp.selected_resolution_mounts AS target_mount
           ON target_mount.mount_ordinal=CAST(target.value->>0 AS INTEGER)
          AND target_mount.blob_id=export.declaration_blob_id
         WHERE CAST(target.value->>1 AS INTEGER)=export.declaration_site)
FROM live_children AS child
CROSS JOIN (SELECT CAST(value->>0 AS INTEGER) AS identity_id,
                   value->>1 AS namespace FROM json_each(?3)) AS demanded
LEFT JOIN main.resolution_unit_summary_exports AS export
  ON export.summary_id=child.summary_id
 AND export.identity_id=demanded.identity_id
 AND export.namespace=demanded.namespace
 AND export.visibility='exported'
LEFT JOIN main.resolution_unit_summary_dependencies AS dependency
  ON dependency.summary_id=export.summary_id
 AND dependency.dependency_ordinal=export.alias_dependency_ordinal
LEFT JOIN main.resolution_unit_summary_versions AS alias_versions
  ON export.alias_dependency_ordinal IS NOT NULL
 AND alias_versions.workspace_id=?4 AND alias_versions.lang='go'
 AND alias_versions.generation=?5
 AND alias_versions.unit_key=dependency.dependency_unit_key
 AND alias_versions.valid_from<=?6
 AND (alias_versions.valid_until IS NULL OR ?6<alias_versions.valid_until)
LEFT JOIN main.resolution_unit_summaries AS alias_child
  ON alias_child.summary_id=alias_versions.summary_id
 AND alias_child.publication_state='complete'
 AND alias_child.producer_epoch=?7 AND alias_child.derivation_version=?8
 AND EXISTS(
   SELECT 1 FROM main.resolution_unit_summary_reads AS profile
   WHERE profile.summary_id=alias_child.summary_id
     AND profile.key_digest=bifrost_go_profile_read_key(alias_versions.unit_key)
     AND profile.digest=?9)
"#;

pub(crate) const GO_REVERSE_INVENTORY_COMPLETE_SQL: &str = r#"
WITH target_packages(package_id,tool_import_path,package_name,for_test,source_role) AS (
  SELECT package.package_id,package.tool_import_path,package.package_name,
         package.for_test,members.source_role
  FROM main.go_package_files AS members
  JOIN main.go_package_instances AS package ON package.package_id=members.package_id
  WHERE package.context_id=?1 AND members.file_version_id=?2
    AND ((members.source_role='go' AND package.for_test='')
      OR (members.source_role IN ('test','xtest') AND package.for_test<>'')
      OR (members.source_role IN ('test','xtest')
          AND package.provider_provenance='source_inventory'))
), target_units(unit_key,tool_import_path,package_name) AS (
  SELECT bifrost_go_unit_key(tool_import_path,for_test,source_role),
         tool_import_path,package_name
  FROM target_packages
), test_units(unit_key) AS (
  SELECT bifrost_go_unit_key(test_package.tool_import_path,
                             test_package.for_test,members.source_role)
  FROM target_units AS target
  CROSS JOIN main.go_package_instances AS test_package
    ON test_package.context_id=?1 AND test_package.for_test=target.tool_import_path
  CROSS JOIN main.go_package_files AS members ON members.package_id=test_package.package_id
  WHERE ?4=1 AND test_package.for_test<>''
    AND members.source_role IN ('test','xtest')
    AND (?3=1 OR test_package.package_name=target.package_name)
), target_keys(unit_key) AS (
  SELECT unit_key FROM target_units
  UNION ALL SELECT unit_key FROM test_units
), dependent_units(unit_key,summary_id) AS (
  SELECT versions.unit_key,versions.summary_id
  FROM target_keys AS target
  CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
    ON dependency.dependency_unit_key=target.unit_key
  CROSS JOIN main.resolution_unit_summary_versions AS versions
    ON versions.summary_id=dependency.summary_id
  WHERE versions.workspace_id=?6 AND versions.lang='go' AND versions.generation=?7
    AND versions.valid_from<=?8
    AND (versions.valid_until IS NULL OR ?8<versions.valid_until)
    AND (?4=1 OR NOT EXISTS(
      SELECT 1 FROM main.resolution_unit_summary_members AS member
      WHERE member.summary_id=versions.summary_id
        AND member.source_role IN ('test','xtest')))
), visible_units(unit_key,summary_id) AS (
  SELECT target.unit_key,versions.summary_id
  FROM target_keys AS target
  LEFT JOIN main.resolution_unit_summary_versions AS versions
    ON versions.workspace_id=?6 AND versions.lang='go' AND versions.generation=?7
   AND versions.unit_key=target.unit_key AND versions.valid_from<=?8
   AND (versions.valid_until IS NULL OR ?8<versions.valid_until)
  UNION ALL
  SELECT unit_key,summary_id FROM dependent_units
), live_summaries(unit_key,summary_id) AS (
  SELECT visible.unit_key,summary.summary_id
  FROM visible_units AS visible
  JOIN main.resolution_unit_summary_versions AS versions
    ON versions.workspace_id=?6 AND versions.lang='go' AND versions.generation=?7
   AND versions.unit_key=visible.unit_key AND versions.valid_from<=?8
   AND (versions.valid_until IS NULL OR ?8<versions.valid_until)
  JOIN main.resolution_unit_summaries AS summary
    ON summary.summary_id=versions.summary_id
  WHERE summary.publication_state='complete'
    AND summary.producer_epoch=?9 AND summary.derivation_version=?11
    AND EXISTS(
      SELECT 1 FROM main.resolution_unit_summary_reads AS profile
      WHERE profile.summary_id=summary.summary_id
        AND profile.key_digest=bifrost_go_profile_read_key(versions.unit_key)
        AND profile.digest=?10)
)
SELECT NOT EXISTS(
         SELECT 1 FROM visible_units AS visible
         WHERE visible.summary_id IS NULL
            OR NOT EXISTS(SELECT 1 FROM live_summaries AS live
                          WHERE live.unit_key=visible.unit_key))
   AND EXISTS(
         SELECT 1 FROM main.go_context_publications AS publication
         WHERE publication.context_id=?1
           AND (publication.complete
             OR NOT EXISTS(
               SELECT 1 FROM json_each(publication.gaps) AS gap
               WHERE COALESCE(json_extract(gap.value,'$.code'),'') NOT IN (
                 'build_selection_unavailable',
                 'source_cgo_build_selection_unavailable',
                 'conflicting_source_package_names',
                 'source_import_provider_unavailable'))))
   AND NOT EXISTS(
         SELECT 1 FROM live_summaries AS live
         WHERE EXISTS(
           SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
           WHERE gap.summary_id=live.summary_id
             AND gap.gap_kind='incomplete_provider'
             AND (json_type(gap.detail)<>'array'
               OR json_array_length(gap.detail)=0
               OR EXISTS(
                 SELECT 1 FROM json_each(gap.detail) AS package_gap
                 WHERE COALESCE(json_extract(package_gap.value,'$.code'),'') NOT IN (
                   'source_file_build_selection_unavailable',
                   'source_build_constraint_facts_unavailable'))))
            OR EXISTS(
           SELECT 1 FROM main.resolution_unit_summary_gaps AS gap
           JOIN json_each(?5) AS demanded
           WHERE gap.summary_id=live.summary_id
             AND gap.gap_kind='conflicting_names'
             AND gap.subject=(demanded.value->>1)||':'||CAST(demanded.value->>0 AS TEXT)))
   AND NOT EXISTS(
         SELECT 1 FROM live_summaries AS live
         JOIN main.resolution_unit_summary_gaps AS gap
           ON gap.summary_id=live.summary_id AND gap.gap_kind='unresolved_import'
         JOIN main.resolution_unit_summary_imports AS imported
           ON imported.summary_id=live.summary_id AND imported.kind='dot'
          AND imported.state='unresolved'
         -- Retained headers change cardinality estimates. Bound summary imports
         -- must drive the keyed source-import lookup, never a table-wide scan.
         CROSS JOIN main.source_imports AS source_import
           ON source_import.blob_id=imported.blob_id
          AND source_import.import_id=imported.import_id AND source_import.alias='.'
         JOIN target_units AS target ON target.tool_import_path=gap.subject
          AND gap.subject=(
            SELECT group_concat(segment,'/') FROM (
              SELECT segment FROM main.source_import_segments
              WHERE blob_id=source_import.blob_id AND import_id=source_import.import_id
              ORDER BY ordinal)))
"#;

#[derive(Clone)]
pub(crate) struct GoReverseCandidate {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) source_role: String,
    pub(crate) unit_key: [u8; 32],
    pub(crate) package_id: i64,
    pub(crate) summary_role: String,
    pub(crate) mount_ordinal: u32,
    pub(crate) blob_id: i64,
    pub(crate) transient: bool,
    pub(crate) overlay_masked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GoReverseTargetSurface {
    identity_id: i64,
    namespace: String,
}

#[derive(Clone)]
struct GoReverseSummaryContext {
    context_id: i64,
    workspace_id: String,
    generation: i64,
    revision: i64,
    producer_epoch: String,
    profile: [u8; 32],
}

pub(crate) struct GoReverseCandidateSet {
    pub(crate) target: SemanticId,
    target_declarations: Vec<(u32, i64)>,
    target_surfaces: Vec<GoReverseTargetSurface>,
    summary_context: GoReverseSummaryContext,
    pub(crate) candidates: Vec<GoReverseCandidate>,
    candidate_inventory_complete: bool,
}

pub(crate) enum GoReverseMemberConfirmation {
    /// The keyed receiver helper found the member declaration directly.
    ReceiverAnchor(SemanticId),
    /// The receiver helper was unknown and the native point path ran.
    Point(Option<Box<FactResolutionAnswer>>),
}

pub(crate) struct GoReverseRenameContext {
    summary_context: GoReverseSummaryContext,
    target_declarations: Vec<(u32, i64)>,
}

impl GoReverseCandidateSet {
    pub(crate) fn rename_context(&self) -> GoReverseRenameContext {
        GoReverseRenameContext {
            summary_context: self.summary_context.clone(),
            target_declarations: self.target_declarations.clone(),
        }
    }
}

#[derive(Debug)]
struct GoReverseSummaryExport {
    identity_id: i64,
    namespace: String,
    origin: Option<String>,
    alias_dependency_ordinal: Option<i64>,
    alias_identity_id: Option<i64>,
    incomplete_provider: bool,
    conflicting_names: bool,
    overlay_masked: bool,
    next_summary_id: Option<i64>,
    alias_child_missing: bool,
    target_declaration: bool,
}

#[derive(Debug)]
struct GoReverseDotExport {
    state: String,
    unit_key: Option<Vec<u8>>,
    summary_id: Option<i64>,
    export: GoReverseSummaryExport,
}

#[derive(Debug)]
struct GoReverseImportBinding {
    import_id: Option<i64>,
    kind: Option<String>,
    state: Option<String>,
    dependency_unit_key: Option<Vec<u8>>,
}

#[derive(Debug)]
enum GoReverseSummaryResult {
    Hit,
    Miss,
    Fallback(GoReverseFallbackCause),
}

fn go_reverse_demand_json(surfaces: &[GoReverseTargetSurface]) -> String {
    serde_json::to_string(
        &surfaces
            .iter()
            .map(|surface| (surface.identity_id, surface.namespace.as_str()))
            .collect::<Vec<_>>(),
    )
    .expect("Go reverse summary demands serialize")
}

fn go_reverse_target_declarations_json(declarations: &[(u32, i64)]) -> String {
    serde_json::to_string(declarations).expect("Go reverse target declarations serialize")
}

fn go_reverse_scope_spellings_json(scope_spellings: &[(u32, String)]) -> String {
    serde_json::to_string(scope_spellings).expect("Go qualifier scope spellings serialize")
}

fn read_go_live_reverse_summary(
    connection: &rusqlite::Connection,
    context: &GoReverseSummaryContext,
    unit_key: &[u8; 32],
) -> Result<Option<i64>> {
    Ok(connection
        .prepare_cached(super::super::go_unit_summaries::GO_LIVE_SUMMARY_SQL)?
        .query_row(
            params![
                context.workspace_id,
                "go",
                context.generation,
                unit_key.as_slice(),
                context.revision,
                context.producer_epoch,
                super::super::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                super::super::go_unit_summaries::go_profile_read_key(unit_key).as_slice(),
                context.profile.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?)
}

pub(crate) const GO_RENAME_TARGET_UNITS_SQL: &str = r#"
SELECT DISTINCT package.tool_import_path,package.for_test,members.source_role,
       CASE WHEN package.for_test<>'' AND members.source_role='go'
            THEN CASE WHEN package.package_name=(
                 SELECT base.package_name FROM main.go_package_instances AS base
                 WHERE base.context_id=package.context_id
                   AND base.tool_import_path=package.for_test AND base.for_test=''
                 LIMIT 1) THEN 'test' ELSE 'xtest' END
            ELSE members.source_role END
FROM temp.selected_resolution_mounts AS mounted
JOIN main.go_package_files AS members
  ON members.file_version_id=mounted.file_version_id
JOIN main.go_package_instances AS package
  ON package.package_id=members.package_id AND package.context_id=?1
WHERE mounted.storage_language='go' AND mounted.persisted_relative_path=?2
"#;

pub(crate) const GO_RENAME_LOCAL_NAME_CONFLICT_SQL: &str = r#"
WITH scopes(blob_id,site,scope_key) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER),
         CAST(value->>2 AS INTEGER)
  FROM json_each(?1)
), names(identity_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?2)
), matches(blob_id,site,scope_key,definition_key,identity_id) AS (
  SELECT scopes.blob_id,scopes.site,scopes.scope_key,binding.end_node,
         binding.start_lead_identity
  FROM scopes
  CROSS JOIN names
  CROSS JOIN main.resolution_paths AS binding INDEXED BY resolution_paths_forward
    ON binding.blob_id=scopes.blob_id AND binding.start_node=scopes.scope_key
   AND binding.start_lead_identity=names.identity_id
  WHERE binding.end_node>=0 AND binding.root_terminal IS NULL
  UNION
  SELECT scopes.blob_id,scopes.site,scopes.scope_key,binding.end_node,
         names.identity_id
  FROM scopes
  CROSS JOIN names
  CROSS JOIN main.resolution_semantic_catalog AS semantic
    ON semantic.blob_id=scopes.blob_id
   AND semantic.shared_identity=names.identity_id
  CROSS JOIN main.resolution_paths AS binding INDEXED BY resolution_paths_forward
    ON binding.blob_id=scopes.blob_id AND binding.start_node=scopes.scope_key
   AND binding.start_lead_local=semantic.local_key
  WHERE binding.end_node>=0 AND binding.root_terminal IS NULL
)
SELECT DISTINCT mounted.persisted_relative_path,declaration.name_start_byte,
       declaration.name_end_byte,identity.spelling,semantic.source_site
FROM matches
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.blob_id=matches.blob_id
JOIN main.resolution_node_catalog AS endpoint
  ON endpoint.blob_id=matches.blob_id AND endpoint.local_key=matches.definition_key
 AND endpoint.semantic_local_key IS NOT NULL
JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=endpoint.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=endpoint.semantic_local_key
JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_declarations AS declaration
  ON declaration.blob_id=bridge.blob_id
 AND declaration.declaration_id=bridge.declaration_id
JOIN main.resolution_identities AS identity
  ON identity.id=matches.identity_id
WHERE matches.identity_id IN (SELECT identity_id FROM names)
  AND declaration.name_start_byte IS NOT NULL
  AND declaration.name_end_byte IS NOT NULL
"#;

pub(crate) const GO_RENAME_EDIT_SITE_SCOPE_KEYS_SQL: &str = r#"
WITH rename_sites(blob_id,site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?1)
), stored_scopes(blob_id,site,scope_key) AS (
  SELECT path.blob_id,path.start_node,CAST(scope.value AS INTEGER)
  FROM rename_sites
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_forward
    ON path.blob_id=rename_sites.blob_id AND path.start_node=rename_sites.site
  CROSS JOIN json_each(path.body,'$[2]') AS scope
  UNION
  SELECT path.blob_id,path.start_node,CAST(symbol_scope.value AS INTEGER)
  FROM rename_sites
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_forward
    ON path.blob_id=rename_sites.blob_id AND path.start_node=rename_sites.site
  CROSS JOIN json_each(path.body,'$[0]') AS symbol
  CROSS JOIN json_each(
    CASE WHEN json_type(symbol.value)='array'
         THEN json_extract(symbol.value,'$[1]') ELSE '[]' END
  ) AS symbol_scope
  UNION
  SELECT path.blob_id,path.start_node,CAST(witness.value AS INTEGER)
  FROM rename_sites
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_forward
    ON path.blob_id=rename_sites.blob_id AND path.start_node=rename_sites.site
  CROSS JOIN json_each(path.body,'$[9]') AS witness
  WHERE json_type(witness.value)='integer'
)
SELECT DISTINCT stored_scopes.blob_id,stored_scopes.site,stored_scopes.scope_key
FROM stored_scopes
JOIN main.resolution_node_catalog AS scope
  ON scope.blob_id=stored_scopes.blob_id
 AND scope.local_key=stored_scopes.scope_key AND scope.kind=1
"#;

pub(crate) const GO_RENAME_IMPORT_NAME_CONFLICT_SQL: &str = r#"
WITH rename_sites(blob_id,site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?1)
), names(identity_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?2)
)
SELECT DISTINCT mounted.persisted_relative_path,source_import.import_id,
       source_import.declaration_start_byte,source_import.declaration_end_byte
FROM rename_sites
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.blob_id=rename_sites.blob_id
CROSS JOIN names
CROSS JOIN main.resolution_semantic_catalog AS semantic
  ON semantic.blob_id=rename_sites.blob_id
 AND semantic.shared_identity=names.identity_id
CROSS JOIN main.resolution_go_package_imports AS binder
  INDEXED BY resolution_go_package_imports_choice
  ON binder.blob_id=rename_sites.blob_id
 AND binder.spelling_choice_key=semantic.local_key
CROSS JOIN main.source_imports AS source_import
  ON source_import.blob_id=binder.blob_id
 AND source_import.declaration_start_byte=binder.start_byte
 AND source_import.declaration_end_byte=binder.end_byte
WHERE binder.kind='named'
"#;

pub(crate) const GO_RENAME_PACKAGE_NAME_CONFLICT_SQL: &str = r#"
WITH summaries(summary_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?1)
), demanded(identity_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?2)
)
SELECT DISTINCT member.rel_path,export.namespace,export.declaration_site
FROM summaries
CROSS JOIN demanded
CROSS JOIN main.resolution_unit_summary_exports AS export
  ON export.summary_id=summaries.summary_id
 AND export.identity_id=demanded.identity_id
JOIN main.resolution_unit_summary_members AS member
  ON member.summary_id=export.summary_id
 AND member.blob_id=export.declaration_blob_id
"#;

pub(crate) const GO_RENAME_REBOUND_ROOT_REFERENCES_SQL: &str = r#"
WITH summaries(summary_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?1)
), names(identity_id) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?2)
), renamed_sites(blob_id,site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?3)
), target_declarations(mount_ordinal,source_site) AS (
  SELECT CAST(value->>0 AS INTEGER),CAST(value->>1 AS INTEGER)
  FROM json_each(?4)
), target_semantics(blob_id,semantic_key) AS MATERIALIZED (
  SELECT DISTINCT mounted.blob_id,semantic.semantic_key
  FROM target_declarations AS target
  CROSS JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.mount_ordinal=target.mount_ordinal
  CROSS JOIN main.resolution_semantic_sites AS semantic
    ON semantic.blob_id=mounted.blob_id
   AND semantic.source_site=target.source_site
   AND semantic.semantic_role='definition'
), target_scopes(blob_id,scope_key,is_package_scope) AS MATERIALIZED (
  SELECT DISTINCT member.blob_id,member.root_scope_key,1
  FROM target_semantics AS target
  CROSS JOIN main.resolution_package_members AS member
    ON member.blob_id=target.blob_id
   AND member.definition_key=target.semantic_key
  UNION
  SELECT DISTINCT node.blob_id,node.source_scope,0
  FROM target_semantics AS target
  CROSS JOIN main.resolution_node_catalog AS node
    ON node.blob_id=target.blob_id
   AND node.semantic_local_key=target.semantic_key
  WHERE node.source_scope IS NOT NULL
    AND NOT EXISTS(
      SELECT 1 FROM main.resolution_package_members AS member
      WHERE member.blob_id=target.blob_id
        AND member.definition_key=target.semantic_key)
)
, candidates(blob_id,rel_path,start_byte,end_byte,site,path_body) AS (
  SELECT member.blob_id,member.rel_path,site.start_byte,site.end_byte,site.site,path.body
  FROM summaries
  CROSS JOIN main.resolution_unit_summary_members AS member
    ON member.summary_id=summaries.summary_id
  CROSS JOIN names
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_root_terminal
    ON path.blob_id=member.blob_id AND path.root_terminal=names.identity_id
   AND path.end_node=-1
  JOIN main.resolution_sites AS site
    ON site.blob_id=path.blob_id AND site.site=path.start_node
   AND site.role=0 AND site.unqualified=1
  UNION
  SELECT member.blob_id,member.rel_path,site.start_byte,site.end_byte,site.site,path.body
  FROM summaries
  CROSS JOIN main.resolution_unit_summary_members AS member
    ON member.summary_id=summaries.summary_id
  CROSS JOIN main.resolution_identities AS identity
    ON identity.spelling=?5
  CROSS JOIN main.resolution_paths AS path INDEXED BY resolution_paths_end_lookup_identity
    ON path.blob_id=member.blob_id AND path.end_lead_identity=identity.id
  JOIN main.resolution_node_catalog AS endpoint
    ON endpoint.blob_id=path.blob_id AND endpoint.local_key=path.end_node
   AND endpoint.kind=1
  JOIN main.resolution_sites AS site
    ON site.blob_id=path.blob_id AND site.site=path.start_node
   AND site.role=0 AND site.unqualified=1
   AND site.go_spelling_namespace IS NOT NULL
  WHERE path.root_terminal IS NULL AND path.end_node>=0
)
SELECT DISTINCT candidate.rel_path,candidate.start_byte,candidate.end_byte,candidate.site
FROM candidates AS candidate
JOIN main.resolution_sites AS site
  ON site.blob_id=candidate.blob_id AND site.site=candidate.site
WHERE NOT EXISTS(
  SELECT 1 FROM renamed_sites AS renamed
  WHERE renamed.blob_id=candidate.blob_id AND renamed.site=candidate.site
)
AND EXISTS(
  SELECT 1 FROM target_scopes AS target
  WHERE target.is_package_scope
     OR (target.blob_id=candidate.blob_id AND NOT target.is_package_scope
         AND EXISTS(
           SELECT 1 FROM json_each(candidate.path_body,'$[2]') AS enclosing_scope
           WHERE CAST(enclosing_scope.value AS INTEGER)=target.scope_key))
     OR (target.blob_id=candidate.blob_id AND NOT target.is_package_scope
         AND EXISTS(
           SELECT 1 FROM json_each(candidate.path_body,'$[9]') AS witness
           WHERE json_type(witness.value)='integer'
             AND CAST(witness.value AS INTEGER)=target.scope_key))
     OR (target.blob_id=candidate.blob_id AND NOT target.is_package_scope
         AND EXISTS(
           SELECT 1 FROM json_each(candidate.path_body,'$[0]') AS symbol
           CROSS JOIN json_each(
             CASE WHEN json_type(symbol.value)='array'
                  THEN json_extract(symbol.value,'$[1]') ELSE '[]' END
           ) AS enclosing_scope
           WHERE CAST(enclosing_scope.value AS INTEGER)=target.scope_key))
)
"#;

#[allow(clippy::too_many_arguments)]
fn read_go_reverse_summary_exports(
    connection: &rusqlite::Connection,
    context: &GoReverseSummaryContext,
    summary_id: i64,
    demands_json: &str,
    require_exported: bool,
    check_overlay: bool,
    target_declarations_json: &str,
    transient_caller: Option<&GoReverseCandidate>,
) -> Result<Vec<GoReverseSummaryExport>> {
    let allow_transient_overlay =
        transient_caller.is_some_and(|candidate| candidate.overlay_masked && candidate.transient);
    let mut statement = connection.prepare_cached(GO_REVERSE_SUMMARY_EXPORT_ROWS_SQL)?;
    let mut rows = statement.query(params![
        summary_id,
        demands_json,
        require_exported,
        check_overlay,
        context.workspace_id,
        context.generation,
        context.revision,
        context.producer_epoch,
        super::super::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
        context.profile.as_slice(),
        target_declarations_json,
        allow_transient_overlay,
    ])?;
    let mut exports = Vec::new();
    while let Some(row) = rows.next()? {
        exports.push(GoReverseSummaryExport {
            identity_id: row.get(0)?,
            namespace: row.get(1)?,
            origin: row.get(3)?,
            alias_dependency_ordinal: row.get(4)?,
            alias_identity_id: row.get(5)?,
            incomplete_provider: row.get(8)?,
            conflicting_names: row.get(9)?,
            overlay_masked: row.get(10)?,
            next_summary_id: row.get(11)?,
            alias_child_missing: row.get(12)?,
            target_declaration: row.get(13)?,
        });
    }
    if let Some(candidate) =
        transient_caller.filter(|candidate| candidate.overlay_masked && candidate.transient)
    {
        let mut statement = connection.prepare_cached(GO_REVERSE_TRANSIENT_TARGET_EXPORTS_SQL)?;
        let mut rows =
            statement.query(params![summary_id, target_declarations_json, demands_json,])?;
        while let Some(row) = rows.next()? {
            let identity_id: i64 = row.get(0)?;
            let namespace: String = row.get(1)?;
            let spelling: String = row.get(2)?;
            if require_exported && !go_identifier_is_exported(&spelling) {
                continue;
            }
            exports.push(GoReverseSummaryExport {
                identity_id,
                namespace,
                origin: Some("declaration".to_owned()),
                alias_dependency_ordinal: None,
                alias_identity_id: None,
                incomplete_provider: false,
                conflicting_names: false,
                overlay_masked: false,
                next_summary_id: Some(summary_id),
                alias_child_missing: false,
                target_declaration: true,
            });
        }

        let mut statement = connection.prepare_cached(GO_REVERSE_TRANSIENT_ALIAS_EXPORTS_SQL)?;
        let mut rows = statement.query(params![
            summary_id,
            demands_json,
            candidate.package_id,
            candidate.summary_role,
            context.context_id,
            context.workspace_id,
            context.generation,
            context.revision,
            context.producer_epoch,
            super::super::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
            context.profile.as_slice(),
            target_declarations_json,
        ])?;
        while let Some(row) = rows.next()? {
            let identity_id: i64 = row.get(0)?;
            let spelling: String = row.get(1)?;
            if require_exported && !go_identifier_is_exported(&spelling) {
                continue;
            }
            let alias_identity_id: Option<i64> = row.get(2)?;
            let dependency_key: Option<Vec<u8>> = row.get(3)?;
            let external = row.get::<_, bool>(4)?;
            let next_summary_id = if external {
                if let Some(key) = dependency_key.as_deref() {
                    let key: [u8; 32] = key
                        .try_into()
                        .expect("Go summary dependency keys have 32 bytes");
                    read_go_live_reverse_summary(connection, context, &key)?
                } else {
                    None
                }
            } else {
                Some(summary_id)
            };
            exports.push(GoReverseSummaryExport {
                identity_id,
                namespace: "type".to_owned(),
                origin: Some("alias".to_owned()),
                alias_dependency_ordinal: external.then_some(0),
                alias_identity_id,
                incomplete_provider: false,
                conflicting_names: false,
                overlay_masked: false,
                next_summary_id,
                alias_child_missing: external && next_summary_id.is_none(),
                target_declaration: row.get(5)?,
            });
        }
    }
    Ok(exports)
}

fn go_reverse_summary_status_fallback(
    exports: &[GoReverseSummaryExport],
) -> Option<GoReverseFallbackCause> {
    // A live summary can have an unavailable dependency unrelated to this
    // site's route. Named imports, dot imports, and alias hops check the
    // specific child summary they cross before accepting its exports.
    if exports.iter().any(|export| export.overlay_masked) {
        Some(GoReverseFallbackCause::Overlay)
    } else if exports.iter().any(|export| export.incomplete_provider) {
        Some(GoReverseFallbackCause::IncompleteProvider)
    } else if exports.iter().any(|export| export.conflicting_names) {
        Some(GoReverseFallbackCause::ConflictingNames)
    } else {
        None
    }
}

fn read_go_reverse_qualified_import(
    connection: &rusqlite::Connection,
    context_id: i64,
    caller_summary_id: Option<i64>,
    candidate: &GoReverseCandidate,
    scope_spellings_json: &str,
) -> Result<Option<GoReverseImportBinding>> {
    let mut statement = connection.prepare_cached(GO_REVERSE_QUALIFIED_IMPORT_SQL)?;
    let mut rows = statement.query(params![
        caller_summary_id,
        context_id,
        candidate.blob_id,
        scope_spellings_json,
        candidate.package_id,
        candidate.summary_role,
        candidate.transient,
    ])?;
    let mut binding: Option<GoReverseImportBinding> = None;
    let mut observed_imports = Vec::new();
    while let Some(row) = rows.next()? {
        let next = GoReverseImportBinding {
            import_id: row.get(0)?,
            kind: row.get(1)?,
            state: row.get(2)?,
            dependency_unit_key: row.get(3)?,
        };
        observed_imports.push((
            candidate.mount_ordinal,
            candidate
                .locator
                .source_site()
                .expect("Go reverse candidate has a source-site locator")
                .get(),
            next.import_id,
        ));
        if let Some(previous) = &binding {
            if previous.import_id != next.import_id
                || previous.kind != next.kind
                || previous.state != next.state
                || previous.dependency_unit_key != next.dependency_unit_key
            {
                return Ok(Some(GoReverseImportBinding {
                    import_id: None,
                    kind: Some("ambiguous".to_owned()),
                    state: Some("ambiguous".to_owned()),
                    dependency_unit_key: None,
                }));
            }
        } else {
            binding = Some(next);
        }
    }
    #[cfg(test)]
    LAST_GO_REVERSE_QUALIFIED_IMPORTS.with(|seen| {
        seen.borrow_mut().extend(observed_imports);
    });
    Ok(binding)
}

fn read_go_reverse_dot_exports(
    connection: &rusqlite::Connection,
    context: &GoReverseSummaryContext,
    caller_summary_id: i64,
    candidate: &GoReverseCandidate,
    demands_json: &str,
    target_declarations_json: &str,
) -> Result<Vec<GoReverseDotExport>> {
    let mut statement = connection.prepare_cached(GO_REVERSE_DOT_EXPORT_ROWS_SQL)?;
    let mut rows = statement.query(params![
        caller_summary_id,
        candidate.blob_id,
        demands_json,
        context.workspace_id,
        context.generation,
        context.revision,
        context.producer_epoch,
        super::super::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
        context.profile.as_slice(),
        target_declarations_json,
        context.context_id,
        candidate.package_id,
        candidate.summary_role,
        candidate.transient,
    ])?;
    let mut exports = Vec::new();
    while let Some(row) = rows.next()? {
        exports.push(GoReverseDotExport {
            state: row.get(0)?,
            unit_key: row.get(1)?,
            summary_id: row.get(2)?,
            export: GoReverseSummaryExport {
                identity_id: row.get(3)?,
                namespace: row.get(4)?,
                origin: row.get(6)?,
                alias_dependency_ordinal: row.get(7)?,
                alias_identity_id: row.get(8)?,
                incomplete_provider: row.get(11)?,
                conflicting_names: row.get(12)?,
                overlay_masked: row.get(13)?,
                next_summary_id: row.get(15)?,
                alias_child_missing: row.get(16)?,
                target_declaration: row.get(17)?,
            },
        });
    }
    Ok(exports)
}

#[allow(clippy::too_many_arguments)]
fn confirm_go_reverse_summary_site(
    connection: &rusqlite::Connection,
    context: &GoReverseSummaryContext,
    candidate_set: &GoReverseCandidateSet,
    candidate: &GoReverseCandidate,
    caller_summary_id: Option<i64>,
    demands_json: &str,
    declarations_json: &str,
    qualified_import: Option<GoReverseImportBinding>,
    metadata: crate::analyzer::resolution::FactReferenceSiteMetadata,
) -> Result<GoReverseSummaryResult> {
    let Some(caller_summary_id) = caller_summary_id else {
        return Ok(GoReverseSummaryResult::Fallback(
            GoReverseFallbackCause::UnitSummaryUnavailable,
        ));
    };
    if candidate_set.target_surfaces.is_empty() {
        return Ok(GoReverseSummaryResult::Miss);
    }

    if !metadata.unqualified() {
        let Some(binding) = qualified_import else {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::QualifiedImportMissing,
            ));
        };
        if binding.kind.as_deref() != Some("named") || binding.state.is_none() {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::QualifiedImportMissing,
            ));
        }
        if binding.state.as_deref() == Some("unresolved") {
            return Ok(GoReverseSummaryResult::Miss);
        }
        if binding.state.as_deref() != Some("resolved") {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::QualifiedImportMissing,
            ));
        }
        let Some(dependency_unit_key) = binding.dependency_unit_key else {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::CrossedSummaryUnavailable,
            ));
        };
        let dependency_unit_key: [u8; 32] = dependency_unit_key
            .as_slice()
            .try_into()
            .expect("Go summary dependency keys have 32 bytes");
        let Some(child_summary_id) =
            read_go_live_reverse_summary(connection, context, &dependency_unit_key)?
        else {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::CrossedSummaryUnavailable,
            ));
        };
        let exports = read_go_reverse_summary_exports(
            connection,
            context,
            child_summary_id,
            demands_json,
            true,
            true,
            declarations_json,
            None,
        )?;
        return follow_go_reverse_aliases(
            connection,
            context,
            exports,
            true,
            declarations_json,
            None,
        );
    }

    let caller_exports = read_go_reverse_summary_exports(
        connection,
        context,
        caller_summary_id,
        demands_json,
        false,
        true,
        declarations_json,
        (candidate.overlay_masked && candidate.transient).then_some(candidate),
    )?;
    if let Some(cause) = go_reverse_summary_status_fallback(&caller_exports) {
        return Ok(GoReverseSummaryResult::Fallback(cause));
    }
    if caller_exports.iter().any(|export| export.origin.is_some()) {
        let outcome = follow_go_reverse_aliases(
            connection,
            context,
            caller_exports,
            false,
            declarations_json,
            (candidate.overlay_masked && candidate.transient).then_some(candidate),
        )?;
        return Ok(outcome);
    }

    let dot_exports = read_go_reverse_dot_exports(
        connection,
        context,
        caller_summary_id,
        candidate,
        demands_json,
        declarations_json,
    )?;
    let mut hit = false;
    let mut fallback = None;
    for child in dot_exports {
        if child.state == "unresolved" {
            continue;
        }
        if child.state != "resolved" || child.unit_key.is_none() {
            fallback = Some(GoReverseFallbackCause::CrossedSummaryUnavailable);
            continue;
        }
        if child.summary_id.is_none() {
            fallback = Some(GoReverseFallbackCause::CrossedSummaryUnavailable);
            continue;
        }
        let result = follow_go_reverse_aliases(
            connection,
            context,
            vec![child.export],
            true,
            declarations_json,
            None,
        )?;
        match result {
            GoReverseSummaryResult::Hit => hit = true,
            GoReverseSummaryResult::Miss => {}
            GoReverseSummaryResult::Fallback(cause) => fallback = Some(cause),
        }
    }
    if let Some(cause) = fallback {
        Ok(GoReverseSummaryResult::Fallback(cause))
    } else if hit {
        Ok(GoReverseSummaryResult::Hit)
    } else {
        Ok(GoReverseSummaryResult::Miss)
    }
}

fn follow_go_reverse_aliases(
    connection: &rusqlite::Connection,
    context: &GoReverseSummaryContext,
    initial: Vec<GoReverseSummaryExport>,
    check_overlay: bool,
    target_declarations_json: &str,
    transient_caller: Option<&GoReverseCandidate>,
) -> Result<GoReverseSummaryResult> {
    let mut found_target = false;
    let mut frontier = vec![(initial, 0usize, false, check_overlay, transient_caller)];
    while let Some((exports, depth, alias_hop, check_overlay, transient_caller)) = frontier.pop() {
        if let Some(cause) = go_reverse_summary_status_fallback(&exports) {
            return Ok(GoReverseSummaryResult::Fallback(cause));
        }
        let mut found_export = false;
        for export in exports {
            let Some(origin) = export.origin.as_deref() else {
                if alias_hop {
                    return Ok(GoReverseSummaryResult::Fallback(
                        GoReverseFallbackCause::AliasUnresolved,
                    ));
                }
                continue;
            };
            found_export = true;
            if matches!(origin, "alias" | "reexport") {
                if depth >= 8 || export.alias_child_missing {
                    return Ok(GoReverseSummaryResult::Fallback(
                        GoReverseFallbackCause::AliasUnresolved,
                    ));
                }
                let Some(alias_identity) = export.alias_identity_id else {
                    return Ok(GoReverseSummaryResult::Fallback(
                        GoReverseFallbackCause::AliasUnresolved,
                    ));
                };
                let Some(next_summary_id) = export.next_summary_id else {
                    return Ok(GoReverseSummaryResult::Fallback(
                        GoReverseFallbackCause::AliasUnresolved,
                    ));
                };
                let next_demands =
                    serde_json::to_string(&[(alias_identity, export.namespace.as_str())])
                        .expect("one Go alias target serializes");
                let next_transient_caller = if export.alias_dependency_ordinal.is_none() {
                    transient_caller
                } else {
                    None
                };
                let next_exports = read_go_reverse_summary_exports(
                    connection,
                    context,
                    next_summary_id,
                    &next_demands,
                    export.alias_dependency_ordinal.is_some(),
                    export.alias_dependency_ordinal.is_some() || check_overlay,
                    target_declarations_json,
                    next_transient_caller,
                )?;
                frontier.push((
                    next_exports,
                    depth + 1,
                    true,
                    export.alias_dependency_ordinal.is_some() || check_overlay,
                    next_transient_caller,
                ));
            } else if export.target_declaration {
                found_target = true;
            }
        }
        if alias_hop && !found_export {
            return Ok(GoReverseSummaryResult::Fallback(
                GoReverseFallbackCause::AliasUnresolved,
            ));
        }
    }
    Ok(if found_target {
        GoReverseSummaryResult::Hit
    } else {
        GoReverseSummaryResult::Miss
    })
}

pub(crate) enum GoReverseCandidateOutcome {
    Ready(GoReverseCandidateSet),
    Unavailable(String),
    Cancelled,
}

pub(crate) struct GoReverseConfirmedReference {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) owner: Option<CodeUnit>,
    pub(crate) binding_targets: Vec<GoReverseBindingTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoReverseBindingTarget {
    Unit(CodeUnit),
    Lexical {
        source_file: ProjectFile,
        name_range: crate::analyzer::Range,
    },
}

pub(crate) struct GoReverseConfirmed {
    pub(crate) target: SemanticId,
    pub(crate) references: Vec<GoReverseConfirmedReference>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) candidate_inventory_complete: bool,
}

pub(crate) enum GoReverseConfirmationOutcome {
    Ready(GoReverseConfirmed),
    Unavailable(String),
    Stale(String),
    Cancelled,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Refuse a rename when saved Go bundles show a binding that the new
    /// package name would capture or rebind. All reads are keyed by selected
    /// sites, scope endpoints, summary ids, and lookup identities.
    pub(crate) fn go_rename_conflict(
        &self,
        rename_context: &GoReverseRenameContext,
        target: &CodeUnit,
        edited_sites: &[(u32, u32)],
        new_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>> {
        assert!(
            !rename_context.target_declarations.is_empty(),
            "a selected Go rename target has declaration sites"
        );
        let summary_context = &rename_context.summary_context;
        let context_id = summary_context.context_id;
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Go rename conflict read was cancelled"));
        }

        let mut identity_ids = ALL_RESOLUTION_NAMESPACES
            .iter()
            .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
            .filter_map(|namespace| {
                ResolutionLookupSemanticRecipe::new(Language::Go, *namespace, new_name)
                    .semantic(&self.ready.shared_names())
                    .shared_name_id()
                    .map(|identity| i64::from(identity.get()))
            })
            .collect::<Vec<_>>();
        for namespace in [
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ] {
            let Some(digest) =
                crate::analyzer::resolution::go_universe_identity_digest(namespace, new_name)
            else {
                continue;
            };
            let identity = self.ready.shared_names().intern(digest);
            identity_ids.push(i64::from(identity.get()));
        }
        identity_ids.sort_unstable();
        identity_ids.dedup();
        let identity_ids_json =
            serde_json::to_string(&identity_ids).expect("Go rename lookup identities serialize");

        let target_path = crate::path_utils::rel_path_string(target.source());
        let connection = self.ready.inventory.connection();
        let mut target_units_statement = connection.prepare_cached(GO_RENAME_TARGET_UNITS_SQL)?;
        let target_units = target_units_statement
            .query_map(params![context_id, target_path], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if target_units.is_empty() {
            return Err(StoreError::new(format!(
                "Go rename target has no selected package unit: {target:?}"
            )));
        }
        let mut summary_ids = Vec::with_capacity(target_units.len());
        for (import_path, for_test, _source_role, summary_role) in target_units {
            let unit_key = super::super::go_unit_summaries::go_unit_key(
                &import_path,
                &for_test,
                &summary_role,
            );
            let Some(summary_id) =
                read_go_live_reverse_summary(connection, summary_context, &unit_key)?
            else {
                return Err(StoreError::new(format!(
                    "Go rename target unit has no live profile-matching summary: {import_path} {for_test} {summary_role}"
                )));
            };
            summary_ids.push(summary_id);
        }
        summary_ids.sort_unstable();
        summary_ids.dedup();
        let summary_ids_json =
            serde_json::to_string(&summary_ids).expect("Go rename summary ids serialize");

        let export_demands_json =
            serde_json::to_string(&identity_ids).expect("Go rename export demands serialize");
        let package_conflicts = connection
            .prepare_cached(GO_RENAME_PACKAGE_NAME_CONFLICT_SQL)?
            .query_map(params![summary_ids_json, export_demands_json], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some((path, namespace, site)) = package_conflicts.first() {
            return Ok(Some(format!(
                "Go rename to {new_name:?} conflicts with the existing {namespace} declaration at {path} (site {site})"
            )));
        }

        let mut reference_rows = Vec::<(i64, i64)>::new();
        for &(mount_ordinal, source_site) in edited_sites {
            if cancellation.is_cancelled() {
                return Err(StoreError::new("Go rename conflict read was cancelled"));
            }
            let mount = SelectedResolutionMountOrdinal::new(mount_ordinal);
            let record = self.ready.inventory.mount_record_by_ordinal(mount)?;
            let blob_id = record.blob_id();
            reference_rows.push((blob_id, i64::from(source_site)));
        }
        reference_rows.sort_unstable();
        reference_rows.dedup();
        let reference_rows_json =
            serde_json::to_string(&reference_rows).expect("Go rename reference sites serialize");

        let scope_rows = connection
            .prepare_cached(GO_RENAME_EDIT_SITE_SCOPE_KEYS_SQL)?
            .query_map([reference_rows_json.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let scope_rows_json =
            serde_json::to_string(&scope_rows).expect("Go rename scope endpoints serialize");

        if !scope_rows.is_empty() {
            let conflicts = connection
                .prepare_cached(GO_RENAME_LOCAL_NAME_CONFLICT_SQL)?
                .query_map(params![scope_rows_json, identity_ids_json], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if let Some((path, start, end, spelling, _site)) = conflicts.first() {
                return Ok(Some(format!(
                    "Go rename to {new_name:?} is captured at byte range {start}..{end} in {path} by {spelling:?}"
                )));
            }
        }

        if !reference_rows.is_empty() {
            let imports = connection
                .prepare_cached(GO_RENAME_IMPORT_NAME_CONFLICT_SQL)?
                .query_map(params![reference_rows_json, identity_ids_json], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if let Some((path, import_id, start, end)) = imports.first() {
                return Ok(Some(format!(
                    "Go rename to {new_name:?} conflicts with import binder {import_id} at {path}:{start}..{end}"
                )));
            }
        }

        let universe_scope_name = if [
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ]
        .into_iter()
        .any(|namespace| {
            crate::analyzer::resolution::go_universe_identity_digest(namespace, new_name).is_some()
        }) {
            new_name
        } else {
            ""
        };
        let rebound = connection
            .prepare_cached(GO_RENAME_REBOUND_ROOT_REFERENCES_SQL)?
            .query_map(
                params![
                    summary_ids_json,
                    identity_ids_json,
                    reference_rows_json,
                    go_reverse_target_declarations_json(&rename_context.target_declarations),
                    universe_scope_name,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some((path, start, end, _site)) = rebound.first() {
            return Ok(Some(format!(
                "Go rename to {new_name:?} rebinds an existing root reference at {path}:{start}..{end}"
            )));
        }
        Ok(None)
    }

    /// Select all structured same-package and importing-package sites whose
    /// shared lookup identity could name `target`. The caller still has to
    /// resolve each site in its own file-scoped Go context.
    pub(crate) fn go_reverse_candidate_sites(
        &self,
        target: &CodeUnit,
        context_id: i64,
        include_tests: bool,
        profile: &[u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<GoReverseCandidateOutcome> {
        let _key_scope = brokk_bifrost_core::cache_db::sql_profile::key_scope(1);
        if cancellation.is_cancelled() {
            return Ok(GoReverseCandidateOutcome::Cancelled);
        }
        let relative_path = crate::path_utils::rel_path_string(target.source());
        let Some(mount) = self.mount_table().mount_for_path("go", &relative_path)? else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target is outside the selected source mounts: {relative_path}"
            )));
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let Some(file_version) = super::go_context::go_placement_file_version(connection, &record)?
        else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target has no proven selected package placement: {relative_path}"
            )));
        };
        let mut statement =
            connection.prepare_cached(GO_TARGET_DEFINITION_SEMANTICS_SQL.as_str())?;
        let semantics = statement
            .query_map([i64::from(mount.ordinal().get())], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .map(|row| {
                row.map(|(key, namespace, source_site)| {
                    (
                        SemanticId::local(
                            mount.ordinal().get(),
                            u32::try_from(key).expect("Go definition catalog key fits u32"),
                        ),
                        namespace,
                        source_site,
                    )
                })
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let mut semantic_ids = semantics
            .iter()
            .map(|(semantic, _, _)| *semantic)
            .collect::<Vec<_>>();
        semantic_ids.sort_unstable();
        semantic_ids.dedup();
        let projected = match native_units::project_native_definition_units(
            &self.ready,
            &semantic_ids,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            SelectedNativeDefinitions::Ready(projected) => projected,
            SelectedNativeDefinitions::Unavailable => {
                return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                    "Go target definitions are not projectable: {relative_path}"
                )));
            }
            SelectedNativeDefinitions::Cancelled => {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
        };
        let mut target_semantics = Vec::new();
        let mut target_declarations = Vec::new();
        let mut target_surfaces = Vec::new();
        for (semantic, definition) in projected {
            if !matches!(definition, SelectedNativeDefinition::Unit(unit) if unit == *target) {
                continue;
            }
            target_semantics.push(semantic);
            if let Some((_, namespace, source_site)) = semantics
                .iter()
                .find(|(candidate, _, _)| *candidate == semantic)
            {
                let namespace = ResolutionNamespace::from_label(namespace)
                    .expect("Go definition semantic has a known lookup namespace");
                if let Some(identity_id) = ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    namespace,
                    target.identifier(),
                )
                .semantic(&self.ready.shared_names())
                .shared_name_id()
                {
                    target_surfaces.push(GoReverseTargetSurface {
                        identity_id: i64::from(identity_id.get()),
                        namespace: namespace.label().to_owned(),
                    });
                }
                target_declarations.push((mount.ordinal().get(), *source_site));
            }
        }
        target_semantics.sort_unstable();
        target_semantics.dedup();
        target_declarations.sort_unstable();
        target_declarations.dedup();
        target_surfaces.sort_unstable();
        target_surfaces.dedup();
        let Some(target_semantic) = target_semantics.first().copied() else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target has no selected definition identity: {target:?}"
            )));
        };
        if target_surfaces.is_empty() {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target has no shared summary identity: {target:?}"
            )));
        }
        assert!(
            !target_declarations.is_empty(),
            "a Go target has declaration sites"
        );

        let target_exported = go_identifier_is_exported(target.terminal_name());
        super::super::go_unit_summaries::register_go_summary_sql_functions(connection)?;
        let Some(language) = self
            .ready
            .inventory
            .languages()?
            .iter()
            .find(|language| language.storage_language() == "go")
        else {
            return Ok(GoReverseCandidateOutcome::Unavailable(
                "Go is absent from the selected summary revisions".into(),
            ));
        };
        let producer_epoch: String = connection.query_row(
            "SELECT expected_producer_epoch FROM temp.selected_resolution_languages WHERE storage_language='go'",
            [],
            |row| row.get(0),
        )?;
        let summary_context = GoReverseSummaryContext {
            context_id,
            workspace_id: language.workspace_id().to_owned(),
            generation: language.generation(),
            revision: language.revision(),
            producer_epoch,
            profile: *profile,
        };
        let target_surfaces_json = serde_json::to_string(
            &target_surfaces
                .iter()
                .map(|surface| (surface.identity_id, surface.namespace.as_str()))
                .collect::<Vec<_>>(),
        )
        .expect("Go summary surfaces serialize");
        let inventory_complete: bool = connection
            .prepare_cached(GO_REVERSE_INVENTORY_COMPLETE_SQL)?
            .query_row(
                params![
                    context_id,
                    file_version,
                    target_exported,
                    include_tests,
                    target_surfaces_json,
                    summary_context.workspace_id,
                    summary_context.generation,
                    summary_context.revision,
                    summary_context.producer_epoch,
                    summary_context.profile.as_slice(),
                    super::super::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false);
        let mut candidate_inventory_complete = inventory_complete;
        let mut candidates = HashMap::<
            (String, String, [u8; 32], i64, String, u32, i64, bool, bool),
            HashMap<ResolutionSiteId, ()>,
        >::default();
        let mut candidate_mounts = HashSet::<u32>::default();
        let lexical = self.ready.lexical_source();
        for namespace in ALL_RESOLUTION_NAMESPACES
            .iter()
            .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
        {
            if cancellation.is_cancelled() {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
            let lookup =
                ResolutionLookupSemanticRecipe::new(Language::Go, *namespace, target.identifier())
                    .semantic(&self.ready.shared_names());
            let identity = lookup
                .shared_name_id()
                .map(|identity| i64::from(identity.get()));
            #[cfg(test)]
            if let Some(identity) = identity {
                LAST_GO_REVERSE_CANDIDATE_PLAN.with(|last| {
                    *last.borrow_mut() = explain_go_reverse_candidate_plan(
                        connection,
                        context_id,
                        file_version,
                        identity,
                        target_exported,
                        include_tests,
                    )
                    .expect("explain populated Go reverse candidate query");
                });
            }
            let mut statement = connection.prepare_cached(GO_REVERSE_CANDIDATE_SITES_SQL)?;
            for row in statement.query_map(
                params![
                    context_id,
                    file_version,
                    identity,
                    target_exported,
                    include_tests
                ],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, bool>(9)?,
                        row.get::<_, bool>(10)?,
                        row.get::<_, bool>(11)?,
                    ))
                },
            )? {
                let (
                    mount_ordinal,
                    path,
                    source_role,
                    blob_id,
                    package_id,
                    transient,
                    tool_import_path,
                    for_test,
                    summary_role,
                    overlay_masked,
                    has_qualified,
                    has_root,
                ) = row?;
                candidate_mounts.insert(mount_ordinal);
                let unit_key = super::super::go_unit_summaries::go_unit_key(
                    &tool_import_path,
                    &for_test,
                    &summary_role,
                );
                let Some(sites) =
                    lexical.lookup_reference_sites(blob_id, lookup, None, cancellation)?
                else {
                    return Ok(GoReverseCandidateOutcome::Cancelled);
                };
                let mut site_routes = sites
                    .into_iter()
                    .map(|site| (site, ()))
                    .collect::<HashMap<_, _>>();
                if has_root {
                    let Some(prefixed) = lexical.prefixed_root_demand_reference_sites(
                        blob_id,
                        lookup,
                        cancellation,
                    )?
                    else {
                        return Ok(GoReverseCandidateOutcome::Cancelled);
                    };
                    for site in prefixed {
                        site_routes.entry(site).or_insert(());
                    }
                }
                if has_qualified {
                    let Some(qualified) =
                        lexical.qualified_route_reference_sites(blob_id, lookup, cancellation)?
                    else {
                        return Ok(GoReverseCandidateOutcome::Cancelled);
                    };
                    for site in qualified {
                        site_routes.entry(site).or_insert(());
                    }
                }
                let candidate_sites = candidates
                    .entry((
                        path.clone(),
                        source_role.clone(),
                        unit_key,
                        package_id,
                        summary_role.clone(),
                        mount_ordinal,
                        blob_id,
                        transient,
                        overlay_masked,
                    ))
                    .or_default();
                for site in site_routes.into_keys() {
                    candidate_sites.insert(site, ());
                }
            }
        }

        let session = ResolutionSession::unbounded();
        let mut candidate_mounts = candidate_mounts.into_iter().collect::<Vec<_>>();
        candidate_mounts.sort_unstable();
        for &ordinal in &candidate_mounts {
            if cancellation.is_cancelled() {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
            let mount = self
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let enumeration = lexical.reference_inventory_completion(
                mount.fragment_id(),
                cancellation,
                &session,
            )?;
            let Some(enumeration) = lexical.close_completion(&enumeration, cancellation)? else {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            };
            candidate_inventory_complete &= matches!(enumeration, ResolutionCompletion::Complete);
        }

        let mut candidates = candidates
            .into_iter()
            .flat_map(
                |(
                    (
                        path,
                        source_role,
                        unit_key,
                        package_id,
                        summary_role,
                        mount_ordinal,
                        blob_id,
                        transient,
                        overlay_masked,
                    ),
                    sites,
                )| {
                    sites.into_iter().map(move |(site, ())| GoReverseCandidate {
                        locator: SelectedSemanticLocator::new(
                            "go",
                            path.clone(),
                            site,
                            LoweredSemanticRole::Reference,
                        ),
                        source_role: source_role.clone(),
                        unit_key,
                        package_id,
                        summary_role: summary_role.clone(),
                        mount_ordinal,
                        blob_id,
                        transient,
                        overlay_masked,
                    })
                },
            )
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.locator
                .relative_path()
                .cmp(right.locator.relative_path())
                .then_with(|| left.source_role.cmp(&right.source_role))
                .then_with(|| left.locator.cmp(&right.locator))
        });
        #[cfg(test)]
        LAST_GO_REVERSE_CANDIDATE_PATHS.with(|last| {
            *last.borrow_mut() = candidates
                .iter()
                .map(|candidate| candidate.locator.relative_path().to_owned())
                .collect();
        });
        Ok(GoReverseCandidateOutcome::Ready(GoReverseCandidateSet {
            target: target_semantic,
            target_declarations,
            target_surfaces,
            summary_context,
            candidates,
            candidate_inventory_complete,
        }))
    }

    /// Summary-confirm name candidates, keyed-confirm receiver members, and
    /// use point/forward confirmation only for unknown or incomplete cases.
    pub(crate) fn confirm_go_reverse_candidates<F>(
        &mut self,
        context_id: i64,
        mut candidates: GoReverseCandidateSet,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        mut confirm_member_access: F,
    ) -> Result<SelectedResolutionOperationOutcome<GoReverseConfirmed>>
    where
        F: FnMut(
            &Self,
            &GoReverseCandidate,
            FactReferenceSiteMetadata,
        ) -> Result<BoundedResolution<GoReverseMemberConfirmation>>,
    {
        let candidate_inventory_complete = candidates.candidate_inventory_complete;
        let target_semantic = candidates.target;
        let summary_context = candidates.summary_context.clone();
        let connection = self.ready.inventory.connection();
        let lexical = self.ready.lexical_source();
        let demands_json = go_reverse_demand_json(&candidates.target_surfaces);
        let declarations_json =
            go_reverse_target_declarations_json(&candidates.target_declarations);
        let mut caller_summaries = HashMap::<[u8; 32], Option<i64>>::default();
        let mut forward_groups = HashMap::<(String, String), Vec<GoReverseCandidate>>::default();
        let mut confirmed_answers = Vec::with_capacity(candidates.candidates.len());
        let mut name_candidate_count = 0;
        let mut forward_candidate_count = 0;
        let mut completion = ResolutionCompletion::Complete;
        for candidate in std::mem::take(&mut candidates.candidates) {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let reference = SemanticId::local(
                candidate.mount_ordinal,
                candidate
                    .locator
                    .source_site()
                    .expect("Go reverse candidate has a source-site locator")
                    .get(),
            );
            let Some(evidence) = lexical.reference_local_path_evidence(reference, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
                let diagnostic = classify_go_reverse_path_evidence_miss(connection, &candidate)?;
                crate::analyzer::resolution::seam_profile::record_go_reverse_candidate_diagnostic(
                    diagnostic,
                );
                continue;
            };
            let metadata = evidence.metadata();
            if metadata.site_kind() == ResolutionSiteKind::CompositeLiteralKeyReference {
                crate::analyzer::resolution::seam_profile::record_go_reverse_candidate_diagnostic(
                    GoReverseCandidateDiagnostic::NonNameReference,
                );
                continue;
            }
            name_candidate_count += 1;
            let syntactic_member_access = metadata.site_kind()
                == ResolutionSiteKind::MemberReference
                || metadata.callable_receiver_origin().is_some();
            let mut targets = evidence.local_definitions().to_vec();
            // Selector roots may bind to imports supplied by the selected Go
            // context. File-local paths alone cannot prove that they refer to
            // a package declaration; confirm their binding before using exports.
            if metadata.go_package_qualifier() && targets.is_empty() {
                let has_import_binding: bool = connection
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM main.resolution_go_package_imports
                         WHERE blob_id=?1 AND kind='named')",
                    )?
                    .query_row([candidate.blob_id], |row| row.get(0))?;
                if has_import_binding {
                    record_go_reverse_fallback(GoReverseFallbackCause::QualifiedImportMissing);
                    forward_candidate_count += 1;
                    forward_groups
                        .entry((
                            candidate.locator.relative_path().to_owned(),
                            candidate.source_role.clone(),
                        ))
                        .or_default()
                        .push(candidate);
                    continue;
                }
            }
            let reaches_package_scope =
                metadata.unqualified() && evidence.reaches_package_root_scope();
            let reaches_root_or_package_scope = evidence.reaches_root() || reaches_package_scope;
            let mut caller_summary_id = None;
            let mut qualified_import = None;
            if targets.is_empty() && (!metadata.unqualified() || reaches_root_or_package_scope) {
                caller_summary_id =
                    if let Some(summary_id) = caller_summaries.get(&candidate.unit_key) {
                        *summary_id
                    } else {
                        let summary_id = read_go_live_reverse_summary(
                            connection,
                            &summary_context,
                            &candidate.unit_key,
                        )?;
                        caller_summaries.insert(candidate.unit_key, summary_id);
                        summary_id
                    };
                if !metadata.unqualified()
                    && evidence.prefix_local_definitions().is_empty()
                    && !evidence.prefix_scope_spellings().is_empty()
                {
                    let scope_spellings_json =
                        go_reverse_scope_spellings_json(evidence.prefix_scope_spellings());
                    qualified_import = read_go_reverse_qualified_import(
                        connection,
                        context_id,
                        caller_summary_id,
                        &candidate,
                        &scope_spellings_json,
                    )?;
                }
            }
            let reaches_summary = reaches_root_or_package_scope
                || (!metadata.unqualified() && qualified_import.is_some());
            // Go package selectors and value member accesses both lower as
            // qualified syntax. The selected Go import binder identifies the
            // former; only the latter needs the native point path.
            let member_access = syntactic_member_access && qualified_import.is_none();
            if member_access && targets.is_empty() {
                crate::analyzer::resolution::seam_profile::record_go_reverse_member_access();
                match confirm_member_access(self, &candidate, metadata)? {
                    BoundedResolution::Complete {
                        value: GoReverseMemberConfirmation::ReceiverAnchor(member),
                        ..
                    } => {
                        if member == target_semantic {
                            confirmed_answers.push((
                                candidate,
                                FactResolutionAnswer::from_selected_summary_binding(
                                    metadata,
                                    vec![target_semantic],
                                    ResolutionCompletion::Complete,
                                ),
                            ));
                        }
                    }
                    BoundedResolution::Complete {
                        value: GoReverseMemberConfirmation::Point(Some(answer)),
                        ..
                    } => {
                        completion = completion.combine(answer.binding().completion());
                        confirmed_answers.push((candidate, *answer));
                    }
                    BoundedResolution::Complete {
                        value: GoReverseMemberConfirmation::Point(None),
                        ..
                    } => {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                        ]));
                    }
                    BoundedResolution::Exceeded { .. } => {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::ReceiverBudgetExhausted(target_semantic),
                        ]));
                    }
                    BoundedResolution::Cancelled { .. } => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                }
                continue;
            }
            if candidate.overlay_masked && !candidate.transient {
                record_go_reverse_fallback(GoReverseFallbackCause::Overlay);
                forward_candidate_count += 1;
                forward_groups
                    .entry((
                        candidate.locator.relative_path().to_owned(),
                        candidate.source_role.clone(),
                    ))
                    .or_default()
                    .push(candidate);
                continue;
            }
            if targets.is_empty() && reaches_summary {
                match confirm_go_reverse_summary_site(
                    connection,
                    &summary_context,
                    &candidates,
                    &candidate,
                    caller_summary_id,
                    &demands_json,
                    &declarations_json,
                    qualified_import,
                    metadata,
                )? {
                    GoReverseSummaryResult::Hit => {
                        targets.push(target_semantic);
                    }
                    GoReverseSummaryResult::Miss => {}
                    GoReverseSummaryResult::Fallback(cause) => {
                        record_go_reverse_fallback(cause);
                        forward_candidate_count += 1;
                        forward_groups
                            .entry((
                                candidate.locator.relative_path().to_owned(),
                                candidate.source_role.clone(),
                            ))
                            .or_default()
                            .push(candidate);
                        continue;
                    }
                }
                crate::analyzer::resolution::seam_profile::record_go_reverse_summary_confirmation();
            }
            confirmed_answers.push((
                candidate,
                FactResolutionAnswer::from_selected_summary_binding(
                    metadata,
                    targets,
                    ResolutionCompletion::Complete,
                ),
            ));
        }
        crate::analyzer::resolution::seam_profile::record_go_reverse_candidates(
            name_candidate_count,
        );
        crate::analyzer::resolution::seam_profile::record_go_reverse_forward_candidates(
            forward_candidate_count,
        );
        drop(lexical);
        let groups = forward_groups;
        // One read of every caller file's import bindings and selected import
        // rows; the per-file context builds below take them from this operation.
        let caller_files = groups
            .keys()
            .map(|(path, role)| (path.as_str(), role.as_str()))
            .collect::<Vec<_>>();
        if !self.prefetch_go_import_inputs(context_id, &caller_files, cancellation)? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        drop(caller_files);
        // Keep source inventory uncertainty separate from the forward proof of
        // each candidate; the public reverse result reports both independently.
        for ((path, source_role), mut candidates) in groups {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            candidates.sort_by(|left, right| left.locator.cmp(&right.locator));
            let _context_key_scope = brokk_bifrost_core::cache_db::sql_profile::key_scope(1);
            let prepared = match self.go_file_import_context_with_role(
                context_id,
                &path,
                &source_role,
                cancellation,
            )? {
                GoPreparedImportContextOutcome::Ready(context) => *context,
                GoPreparedImportContextOutcome::Unavailable => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]));
                    continue;
                }
                GoPreparedImportContextOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            crate::analyzer::resolution::seam_profile::record_go_prepared_context();
            let demand = prepared.demand;
            let context =
                match self.prepare_context(prepared.context, cancellation, context_metrics)? {
                    SelectedResolutionContextValidationOutcome::Ready(context) => context,
                    SelectedResolutionContextValidationOutcome::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                };
            drop(_context_key_scope);
            let ready = &self.ready;
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion,
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let mut located = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                match ready.lookup_locator(&persisted_lexical, &candidate.locator, cancellation)? {
                    LocatedSemantic::Found(reference) => located.push((candidate, reference)),
                    LocatedSemantic::Missing => {
                        return Err(StoreError::corrupt(format!(
                            "Go reverse candidate locator is absent from selected source: {:?}",
                            candidate.locator
                        )));
                    }
                    LocatedSemantic::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                }
            }
            let (answers, forward_completion) = self.with_go_reverse_confirmation_operation(
                GoForwardOperationContext {
                    blueprint: &blueprint,
                    demand,
                    caller_path: &path,
                    lexical: &observed_lexical,
                    typed: &observed_typed,
                    cancellation,
                    session: &ResolutionSession::unbounded(),
                },
                |operation| {
                    let mut answers = Vec::with_capacity(located.len());
                    for chunk in located.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
                        if cancellation.is_cancelled() {
                            return Ok((Vec::new(), cancelled_completion()));
                        }
                        let references = chunk
                            .iter()
                            .map(|(_, reference)| *reference)
                            .collect::<Vec<_>>();
                        let mut metrics = ResolutionBatchMetrics::default();
                        let batch = operation
                            .resolve_references_by_demand_with_metrics(&references, &mut metrics)?;
                        crate::analyzer::resolution::seam_profile::record_go_reverse_forward_batch(
                            batch.answers().len(),
                        );
                        if batch.answers().len() != chunk.len() {
                            return Ok((Vec::new(), batch.completion().clone()));
                        }
                        for ((candidate, reference), answer) in chunk.iter().zip(batch.answers()) {
                            assert_eq!(
                                answer.reference(),
                                *reference,
                                "forward resolution preserves requested Go candidate order"
                            );
                            let answer = answer.answer();
                            if answer
                                .site_metadata()
                                .is_some_and(|site| site.go_package_qualifier())
                            {
                                let binding_keys = answer
                                    .binding()
                                    .targets()
                                    .iter()
                                    .filter(|target| {
                                        target.ordinal() == Some(candidate.mount_ordinal)
                                    })
                                    .map(|target| {
                                        target.local_key().expect("local import binding has a key")
                                    })
                                    .collect::<Vec<_>>();
                                let imported_root: bool = connection
                                    .prepare_cached(
                                        "SELECT EXISTS(
                                       SELECT 1 FROM json_each(?2) AS target
                                       JOIN main.resolution_go_package_imports AS binder
                                         ON binder.blob_id=?1 AND binder.definition_key=target.value
                                       WHERE binder.kind='named')",
                                    )?
                                    .query_row(
                                        params![
                                            candidate.blob_id,
                                            serde_json::to_string(&binding_keys)
                                                .expect("Go import binding keys serialize")
                                        ],
                                        |row| row.get(0),
                                    )?;
                                if imported_root {
                                    continue;
                                }
                            }
                            answers.push((candidate.clone(), answer.clone()));
                        }
                    }
                    let completion = answers.iter().fold(
                        ResolutionCompletion::Complete,
                        |completion, (_, answer)| {
                            // Usage confirmation needs exact binding evidence;
                            // an incomplete type projection such as a generic
                            // call result does not make the name binding
                            // unproven.
                            completion.combine(answer.binding().completion())
                        },
                    );
                    Ok((answers, completion))
                },
            )?;
            completion = completion.combine(&forward_completion);
            confirmed_answers.extend(answers);
        }
        let mut references = Vec::new();
        let mut definition_semantics = Vec::new();
        for (_, answer) in &confirmed_answers {
            if let Some(Some(owner)) = answer.reference_owner() {
                definition_semantics.push(owner);
            }
            definition_semantics.extend(answer.binding().targets().iter().copied());
        }
        definition_semantics.sort_unstable();
        definition_semantics.dedup();
        // One batch for every definition: a definition the batch cannot
        // project (a shared name, or a unit it cannot select) is incomplete on
        // its own and does not force the others to be projected one by one.
        let definitions = match native_units::project_native_definition_units_each(
            &self.ready,
            &definition_semantics,
            cancellation,
        )? {
            Some(rows) => rows,
            None => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        let mut owner_units = HashMap::default();
        let mut lexical_definition_locations = HashMap::default();
        for (semantic, definition) in definitions {
            match definition {
                Some(SelectedNativeDefinition::Unit(unit)) => {
                    owner_units.insert(semantic, Some(unit));
                }
                Some(SelectedNativeDefinition::Lexical(definition)) => {
                    if let Some(source_file) = definition.source_file {
                        lexical_definition_locations
                            .insert(semantic, (source_file, definition.name_range));
                    }
                    owner_units.insert(semantic, None);
                }
                None => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                    ]));
                }
            }
        }
        let connection = self.ready.inventory.connection();
        let mut lexical_location =
            connection.prepare_cached(GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL)?;
        for &semantic in &definition_semantics {
            if owner_units.contains_key(&semantic)
                || lexical_definition_locations.contains_key(&semantic)
            {
                continue;
            }
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let Some(crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(local)) =
                self.ready
                    .lexical_source()
                    .semantic_provenance(semantic, cancellation)?
            else {
                continue;
            };
            #[cfg(test)]
            {
                let plan = explain_go_reverse_definition_plan(
                    connection,
                    i64::from(local.mount().ordinal().get()),
                    local.local_key().get(),
                )?;
                LAST_GO_REVERSE_DEFINITION_PLAN.with(|last| *last.borrow_mut() = plan);
            }
            let location = lexical_location
                .query_row(
                    params![
                        i64::from(local.mount().ordinal().get()),
                        local.local_key().get()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            crate::analyzer::Range {
                                start_byte: row.get(1)?,
                                end_byte: row.get(2)?,
                                start_line: row.get(3)?,
                                end_line: row.get(4)?,
                            },
                        ))
                    },
                )
                .optional()?;
            if let Some((relative_path, name_range)) = location {
                lexical_definition_locations.insert(
                    semantic,
                    (
                        crate::analyzer::ProjectFile::new(self.ready.project.root(), relative_path),
                        name_range,
                    ),
                );
            }
        }
        drop(lexical_location);
        for (candidate, answer) in confirmed_answers {
            let owner = answer
                .reference_owner()
                .flatten()
                .and_then(|semantic| owner_units.get(&semantic).cloned().flatten());
            let binding_targets =
                answer
                    .binding()
                    .targets()
                    .iter()
                    .filter_map(|semantic| {
                        if let Some(Some(unit)) = owner_units.get(semantic) {
                            return Some(GoReverseBindingTarget::Unit(unit.clone()));
                        }
                        lexical_definition_locations.get(semantic).map(
                            |(source_file, name_range)| GoReverseBindingTarget::Lexical {
                                source_file: source_file.clone(),
                                name_range: *name_range,
                            },
                        )
                    })
                    .collect();
            references.push(GoReverseConfirmedReference {
                locator: candidate.locator,
                answer,
                owner,
                binding_targets,
            });
        }
        self.ready.finish(
            GoReverseConfirmed {
                target: candidates.target,
                references,
                completion: completion.clone(),
                candidate_inventory_complete,
            },
            &completion,
            cancellation,
        )
    }
}

#[cfg(test)]
pub(crate) fn explain_go_reverse_candidate_plan(
    connection: &rusqlite::Connection,
    context_id: i64,
    file_version: i64,
    identity: i64,
    target_exported: bool,
    include_tests: bool,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {GO_REVERSE_CANDIDATE_SITES_SQL}"
    ))?;
    statement
        .query_map(
            params![
                context_id,
                file_version,
                identity,
                target_exported,
                include_tests
            ],
            |row| row.get(3),
        )?
        .collect()
}

#[cfg(test)]
pub(crate) fn explain_go_reverse_definition_plan(
    connection: &rusqlite::Connection,
    mount_ordinal: i64,
    semantic_key: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL}"
    ))?;
    statement
        .query_map(params![mount_ordinal, semantic_key], |row| row.get(3))?
        .collect()
}

#[cfg(test)]
pub(crate) fn last_go_reverse_candidate_plan_for_test() -> Vec<String> {
    LAST_GO_REVERSE_CANDIDATE_PLAN.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn last_go_reverse_candidate_paths_for_test() -> Vec<String> {
    LAST_GO_REVERSE_CANDIDATE_PATHS.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn last_go_reverse_definition_plan_for_test() -> Vec<String> {
    LAST_GO_REVERSE_DEFINITION_PLAN.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn last_go_reverse_qualified_imports_for_test() -> Vec<(u32, u32, Option<i64>)> {
    LAST_GO_REVERSE_QUALIFIED_IMPORTS.with(|seen| {
        let mut rows = seen.borrow().clone();
        rows.sort_unstable();
        rows.dedup();
        rows
    })
}

#[cfg(test)]
pub(crate) fn reset_go_reverse_qualified_imports_for_test() {
    LAST_GO_REVERSE_QUALIFIED_IMPORTS.with(|seen| seen.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn reset_go_reverse_alias_fallbacks_for_test() {
    LAST_GO_REVERSE_ALIAS_FALLBACKS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn last_go_reverse_alias_fallbacks_for_test() -> usize {
    LAST_GO_REVERSE_ALIAS_FALLBACKS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn mark_go_context_incomplete_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
) -> Result<()> {
    store.conn.execute(move |connection| {
        connection.execute(
            "UPDATE go_context_publications SET complete=0,gaps=jsonb('[{\"code\":\"test_incomplete\"}]') WHERE context_id=?1",
            [context_id],
        )?;
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn mark_go_package_complete_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
    import_path: &'static str,
) -> Result<()> {
    store.conn.execute(move |connection| {
        let changed = connection.execute(
            "UPDATE go_package_instances SET complete=1,gaps=jsonb('[]')
             WHERE context_id=?1 AND tool_import_path=?2 AND for_test=''",
            params![context_id, import_path],
        )?;
        assert_eq!(changed, 1, "one selected Go package row is updated");
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn mark_go_import_incomplete_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
    source_spelling: &'static str,
) -> Result<usize> {
    store.conn.execute(move |connection| {
        Ok(connection.execute(
            "UPDATE go_package_imports SET complete=0,gaps=jsonb('[{\"code\":\"source_import_provider_unavailable\"}]') WHERE context_id=?1 AND source_spelling=?2",
            params![context_id, source_spelling],
        )?)
    })
}

#[cfg(test)]
pub(crate) fn mark_go_unit_summary_unavailable_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
    unit_key: [u8; 32],
) -> Result<usize> {
    store.conn.execute(move |connection| {
        Ok(connection.execute(
            "DELETE FROM resolution_unit_summary_versions AS versions
             WHERE versions.lang='go' AND versions.unit_key=?2 AND versions.valid_until IS NULL
               AND EXISTS(
                 SELECT 1 FROM go_context_publications AS publication
                 JOIN go_context_selections AS selection USING(selection_id)
                 WHERE publication.context_id=?1
                   AND selection.workspace_id=versions.workspace_id
                   AND selection.generation=versions.generation
                   AND selection.revision>=versions.valid_from)",
            params![context_id, unit_key.as_slice()],
        )?)
    })
}

#[cfg(test)]
pub(crate) fn seed_go_reverse_plan_decoys_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
    importer_path: &'static str,
    count: usize,
) -> Result<()> {
    store.conn.execute(move |connection| {
        let tx = connection.transaction()?;
        let importer_package: i64 = tx.query_row(
            "SELECT package_id FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2",
            params![context_id, importer_path],
            |row| row.get(0),
        )?;
        for index in 0..count {
            let import_path = format!("example.test/reverse-decoy{index}");
            let unit_key = crate::analyzer::store::go_unit_summaries::go_unit_key(&import_path, "", "go");
            tx.execute(
                "INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key) VALUES(?1,?2,'decoy','','',zeroblob(32),1,jsonb('[]'),?3)",
                params![context_id, import_path, unit_key.as_slice()],
            )?;
            let decoy = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,?3,'go',?4,1,jsonb('[]'))",
                params![context_id, importer_package, format!("example.test/reverse-decoy{index}"), decoy],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
}
