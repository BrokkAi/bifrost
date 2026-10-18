//! The Go unit definition for the shared per-unit resolution summary
//! (`unit_summaries.rs`).
//!
//! A Go unit is one package instance of the selected tool publication plus a
//! source role: the same key as the graph stage's `GoPackageStageUnit`. A plain
//! package is a `go` unit. A test variant instance is a `test` or `xtest` unit,
//! whose members are the instance's compiled files plus its test files, exactly
//! the files `PACKAGE_PEER_MOUNTS` reads as same-package peers. Source-less
//! providers (the standard library and module dependencies) are not units; a
//! dependency on one records the digest of its provider.
//!
//! The summary is names only. Its export rows are the package-scope members each
//! member file's resolution bundle publishes, and its import rows are the
//! bindings of each file's import declarations to the tool's package instances.
//! Member references, which need the receiver's type, are not summarized.

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use super::unit_summaries::{
    ConsumedDependency, UnitDependency, UnitExport, UnitGap, UnitImport, UnitInputs, UnitMember,
    UnitOutputs, UnitRead, UnitSummaryLanguage,
};
use super::{Result, StoreError, WorkspaceSnapshotId};
use crate::analyzer::canonical_hash::CanonicalHasher;

/// Version 6 records imports from every source role included in a test unit.
// Version 8 consumes the anonymous/local declaration inventory (#5074).
pub(crate) const GO_UNIT_SUMMARY_DERIVATION_VERSION: i64 = 8;

fn go_provider_gap_detail(gaps_json: &str) -> Option<String> {
    let mut gaps: Value =
        serde_json::from_str(gaps_json).expect("Go package provider gaps are serialized JSON");
    let entries = gaps
        .as_array_mut()
        .expect("Go package provider gaps are an array");
    if entries.is_empty() {
        return Some("[]".to_owned());
    }
    entries.retain(|gap| {
        !matches!(
            gap.get("code").and_then(Value::as_str),
            Some(
                "source_file_build_selection_unavailable"
                    | "source_build_constraint_facts_unavailable"
            )
        )
    });
    if entries.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&gaps).expect("Go provider gaps serialize"))
    }
}

/// The Go unit definition over one published context: the tool profile or the
/// source-inventory profile. `profile` is that context's profile digest; it is
/// recorded in each summary's read ledger, so a reader matches the summary of the
/// profile its request selected. (The publication digest cannot be recorded: it
/// folds file mtimes and moves on every edit.)
pub(crate) struct GoUnitSummaries {
    pub context_id: i64,
    pub profile: [u8; 32],
}

// Package instance plus role pairs. A file's role selects its package instance
// as `CALLER_PACKAGE` does: a `go` file belongs to the plain instance, a `test`
// or `xtest` file belongs to the tool's test-variant instance, and in the
// source-inventory profile (no test variants) a `test` or `xtest` file belongs
// to the plain instance. The `CALLER_PACKAGE` arm for a `test` file in an
// incomplete plain tool instance with no selected test variant is not a unit:
// readers fall back for such a file.
const STAGE_UNITS_SQL: &str = "INSERT INTO temp.go_unit_summary_units(package_id, source_role)
     SELECT DISTINCT files.package_id, files.source_role
     FROM main.go_context_source_files AS files
     JOIN main.go_package_instances AS packages
       ON packages.context_id = files.context_id AND packages.package_id = files.package_id
     WHERE files.context_id = ?1
       AND ((files.source_role = 'go' AND packages.for_test = '')
         OR (files.source_role IN ('test', 'xtest') AND packages.for_test <> '')
         OR (files.source_role IN ('test', 'xtest') AND packages.provider_provenance = 'source_inventory'))
     ORDER BY files.package_id, files.source_role";

// A unit consumes the instance each of its import rows resolves to, under the
// role that instance is a unit of.
const STAGE_IMPORT_EDGES_SQL: &str =
    "INSERT OR IGNORE INTO temp.unit_summary_edges(unit_id, dependency_unit_id)
     SELECT units.unit_id, dependency.unit_id
     FROM temp.go_unit_summary_units AS units
     JOIN main.go_package_imports AS imports
       ON imports.importer_package_id = units.package_id
      AND imports.import_role IN ('go', units.source_role)
      AND imports.target_package_id IS NOT NULL
     JOIN main.go_package_instances AS targets ON targets.package_id = imports.target_package_id
     JOIN temp.go_unit_summary_units AS dependency
       ON dependency.package_id = targets.package_id
      AND dependency.source_role = CASE WHEN targets.for_test = '' THEN 'go'
            WHEN EXISTS (SELECT 1 FROM main.go_package_files AS tests
                         WHERE tests.package_id = targets.package_id AND tests.source_role = 'xtest')
              THEN 'xtest'
            ELSE 'test' END";

// A test unit also consumes the plain package it tests: the instance whose tool
// import path is a tool test variant's `for_test`, or the unit's own instance in
// the source-inventory profile.
const STAGE_TEST_EDGES_SQL: &str =
    "INSERT OR IGNORE INTO temp.unit_summary_edges(unit_id, dependency_unit_id)
     SELECT units.unit_id, plain_unit.unit_id
     FROM temp.go_unit_summary_units AS units
     JOIN main.go_package_instances AS tested ON tested.package_id = units.package_id
     JOIN main.go_package_instances AS plain
       ON plain.context_id = tested.context_id
      AND ((plain.tool_import_path = tested.for_test AND plain.for_test = '')
        OR (tested.provider_provenance = 'source_inventory' AND plain.package_id = tested.package_id))
     JOIN temp.go_unit_summary_units AS plain_unit
       ON plain_unit.package_id = plain.package_id AND plain_unit.source_role = 'go'
     WHERE units.source_role IN ('test', 'xtest')";

const UNIT_INSTANCE_SQL: &str =
    "SELECT units.package_id, units.source_role, packages.tool_import_path,
       packages.package_name, packages.for_test, packages.provider_digest, packages.complete,
       json(packages.gaps)
     FROM temp.go_unit_summary_units AS units
     JOIN main.go_package_instances AS packages ON packages.package_id = units.package_id
     WHERE units.unit_id = ?1";

const UNIT_MEMBERS_SQL: &str = "SELECT blobs.id, files.blob_oid, files.rel_path, files.source_role
     FROM main.go_context_source_files AS files
     LEFT JOIN main.blobs AS blobs
       ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'go' AND blobs.generation = ?4
     WHERE files.context_id = ?1 AND files.package_id = ?2 AND files.source_role IN ('go', ?3)
     ORDER BY files.rel_path, files.source_role";

// The consumed package instances, with the role each is a unit of and, when it
// is a unit of this pass, its unit id.
const UNIT_DEPENDENCIES_SQL: &str = "SELECT targets.tool_import_path, targets.for_test, targets.provider_kind,
       targets.provider_digest, targets.provider_module_path, targets.provider_module_version,
       CASE WHEN targets.for_test = '' THEN 'go'
            WHEN EXISTS (SELECT 1 FROM main.go_package_files AS tests
                         WHERE tests.package_id = targets.package_id AND tests.source_role = 'xtest')
              THEN 'xtest'
            ELSE 'test' END AS target_role,
       (SELECT dependency.unit_id FROM temp.go_unit_summary_units AS dependency
        WHERE dependency.package_id = targets.package_id
          AND dependency.source_role = CASE WHEN targets.for_test = '' THEN 'go'
            WHEN EXISTS (SELECT 1 FROM main.go_package_files AS tests
                         WHERE tests.package_id = targets.package_id AND tests.source_role = 'xtest')
              THEN 'xtest'
            ELSE 'test' END)
     FROM main.go_package_instances AS targets
     WHERE targets.package_id IN (
       SELECT imports.target_package_id FROM main.go_package_imports AS imports
       WHERE imports.importer_package_id = ?1 AND imports.import_role IN ('go', ?2)
         AND imports.target_package_id IS NOT NULL)
     ORDER BY targets.tool_import_path, targets.for_test";

// The plain package a test unit tests. Absent from the unit set when the plain
// package has no selected files.
const TESTED_PACKAGE_SQL: &str =
    "SELECT plain.tool_import_path, plain.for_test, plain.provider_digest,
       (SELECT plain_unit.unit_id FROM temp.go_unit_summary_units AS plain_unit
        WHERE plain_unit.package_id = plain.package_id AND plain_unit.source_role = 'go')
     FROM main.go_package_instances AS tested
     JOIN main.go_package_instances AS plain
       ON plain.context_id = tested.context_id
      AND ((plain.tool_import_path = tested.for_test AND plain.for_test = '')
        OR (tested.provider_provenance = 'source_inventory' AND plain.package_id = tested.package_id))
     WHERE tested.package_id = ?1";

// The unit's slice of the tool publication: its own import rows.
const UNIT_IMPORT_ROWS_SQL: &str = "SELECT imports.import_role, imports.source_spelling, targets.tool_import_path, targets.for_test, imports.complete
     FROM main.go_package_imports AS imports
     LEFT JOIN main.go_package_instances AS targets ON targets.package_id = imports.target_package_id
     WHERE imports.importer_package_id = ?1 AND imports.import_role IN ('go', ?2)
     ORDER BY imports.import_role, imports.source_spelling";

// Members whose resolution bundle is missing or sealed under another epoch
// publish no names, so the summary is incomplete.
const MEMBERS_WITHOUT_BUNDLE_SQL: &str = "SELECT files.rel_path
     FROM main.go_context_source_files AS files
     JOIN main.blobs AS blobs
       ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'go' AND blobs.generation = ?4
     WHERE files.context_id = ?1 AND files.package_id = ?2 AND files.source_role IN ('go', ?3)
       AND NOT EXISTS (
         SELECT 1 FROM main.resolution_fragment_interiors AS interiors
         WHERE interiors.blob_id = blobs.id AND interiors.publication_state = 'complete'
           AND interiors.producer_epoch = ?5)
     ORDER BY files.rel_path";

// Package-scope members of every member file's bundle: the relation the
// same-package peer reader (`ORDINARY_MEMBERS_BY_MOUNT`) reads per mount.
const UNIT_EXPORTS_SQL: &str =
    "SELECT DISTINCT blobs.id, members.source_site, members.definition_key,
       members.namespace, catalog.shared_identity, identities.spelling, identities.identity_digest
     FROM main.go_context_source_files AS files
     JOIN main.blobs AS blobs
       ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'go' AND blobs.generation = ?4
     JOIN main.resolution_fragment_interiors AS interiors
       ON interiors.blob_id = blobs.id AND interiors.publication_state = 'complete'
      AND interiors.producer_epoch = ?5
     JOIN main.resolution_package_members AS members ON members.blob_id = blobs.id
     JOIN main.resolution_semantic_catalog AS catalog
       ON catalog.blob_id = members.blob_id AND catalog.local_key = members.lookup_key
     JOIN main.resolution_identities AS identities ON identities.id = catalog.shared_identity
     WHERE files.context_id = ?1 AND files.package_id = ?2 AND files.source_role IN ('go', ?3)
     ORDER BY blobs.id, members.source_site, members.definition_key, members.namespace";

// A Go alias with a named target exports its own name and resolves through the
// target identity. An alias whose RHS has no named identity remains an ordinary
// declaration export. The target path is selected from sealed source
// occurrences and resolution rows; no source text is inspected.
const UNIT_ALIAS_EXPORTS_SQL: &str =
    "SELECT DISTINCT blobs.id, members.source_site, aliases.name,
       CASE WHEN terminal_name.name IS NOT NULL THEN qualifier.name END,
       target_identity.id, target_identity.identity_digest,
       imported.import_id, target_type.kind
     FROM main.go_context_source_files AS files
     JOIN main.blobs AS blobs
       ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'go' AND blobs.generation = ?4
     JOIN main.resolution_fragment_interiors AS interiors
       ON interiors.blob_id = blobs.id AND interiors.publication_state = 'complete'
      AND interiors.producer_epoch = ?5
     JOIN main.source_go_aliases AS aliases
       ON aliases.blob_id = blobs.id
     JOIN main.resolution_package_members AS members
       ON members.blob_id = aliases.blob_id AND members.namespace = 'type'
     JOIN main.resolution_semantic_catalog AS alias_name
       ON alias_name.blob_id = members.blob_id AND alias_name.local_key = members.lookup_key
     JOIN main.resolution_identities AS alias_identity
       ON alias_identity.id = alias_name.shared_identity
      AND alias_identity.spelling = aliases.name
     LEFT JOIN main.source_go_types AS target_type
       ON target_type.blob_id = aliases.blob_id AND target_type.type_id = aliases.target_type_id
     -- Filter the join view before the LEFT JOIN: SQLite otherwise materializes
     -- occurrences for every blob in the store (#5658).
     LEFT JOIN (
       SELECT occurrence.* FROM main.source_occurrences AS occurrence
       WHERE occurrence.blob_id IN (
         SELECT selected_blob.id
         FROM main.go_context_source_files AS selected_file
         JOIN main.blobs AS selected_blob
           ON selected_blob.blob_oid = selected_file.blob_oid
          AND selected_blob.lang = 'go' AND selected_blob.generation = ?4
         WHERE selected_file.context_id = ?1 AND selected_file.package_id = ?2
           AND selected_file.source_role IN ('go', ?3)
       )
     ) AS target_occurrence
       ON target_occurrence.blob_id = target_type.blob_id
      AND target_occurrence.occurrence_id = target_type.occurrence_id
     LEFT JOIN main.source_go_type_names AS qualifier
       ON qualifier.blob_id = target_type.blob_id AND qualifier.type_id = target_type.type_id
      AND qualifier.ordinal = 0
     LEFT JOIN main.source_go_type_names AS terminal_name
       ON terminal_name.blob_id = target_type.blob_id AND terminal_name.type_id = target_type.type_id
      AND terminal_name.ordinal = 1
     LEFT JOIN main.resolution_sites AS target_site
       ON target_site.blob_id = blobs.id AND target_site.role = 0
      AND target_site.start_byte >= target_occurrence.start_byte
      AND target_site.end_byte <= target_occurrence.end_byte
     LEFT JOIN main.resolution_paths AS target_path
       ON target_path.blob_id = target_site.blob_id AND target_path.start_node = target_site.site
     LEFT JOIN main.resolution_identities AS target_identity
       ON target_identity.id = CASE WHEN target_path.end_node = -1
                                    THEN target_path.root_terminal
                                    ELSE target_path.end_lead_identity END
      AND target_identity.spelling = COALESCE(terminal_name.name, qualifier.name)
     LEFT JOIN main.source_imports AS imported
       ON imported.blob_id = blobs.id
      AND EXISTS (
        SELECT 1
        FROM main.resolution_go_package_imports AS binding
        JOIN main.go_package_imports AS selected_import
          ON selected_import.importer_package_id = files.package_id
         AND selected_import.import_role = files.source_role
         AND selected_import.source_spelling = (
           SELECT group_concat(path_segment.segment, '/')
           FROM (
             SELECT segment
             FROM main.source_import_segments
             WHERE blob_id = imported.blob_id AND import_id = imported.import_id
             ORDER BY ordinal
           ) AS path_segment)
        JOIN main.go_package_instances AS target_package
          ON target_package.context_id = files.context_id
         AND target_package.package_id = selected_import.target_package_id
        WHERE binding.blob_id = imported.blob_id
          AND binding.start_byte = imported.declaration_start_byte
          AND binding.end_byte = imported.declaration_end_byte
          AND binding.kind = 'named'
          AND ((imported.alias IS NOT NULL AND imported.alias NOT IN ('.', '_')
                AND imported.alias = qualifier.name)
            OR (imported.alias IS NULL AND target_package.package_name = qualifier.name))
      )
     WHERE files.context_id = ?1 AND files.package_id = ?2 AND files.source_role IN ('go', ?3)
     ORDER BY blobs.id, members.source_site, (target_identity.id IS NULL), target_path.root_terminal";

// One row per path segment of every import declaration, in declaration order.
// Every import declaration has a `source_imports` row; a named or blank import
// also has a `resolution_go_package_imports` row, and a dot import (alias ".")
// has none. The spelling the tool resolves is the segments joined by '/', as
// `go_import_binding_context_for_selection` joins them.
const UNIT_IMPORTS_SQL: &str = "SELECT blobs.id, files.source_role, source_imports.import_id, source_imports.alias,
       imports.definition_key, imports.kind, segments.segment
     FROM main.go_context_source_files AS files
     JOIN main.blobs AS blobs
       ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'go' AND blobs.generation = ?4
     JOIN main.source_imports AS source_imports ON source_imports.blob_id = blobs.id
     LEFT JOIN main.resolution_go_package_imports AS imports
       ON imports.blob_id = source_imports.blob_id
      AND imports.start_byte = source_imports.declaration_start_byte
      AND imports.end_byte = source_imports.declaration_end_byte
     LEFT JOIN main.source_import_segments AS segments
       ON segments.blob_id = source_imports.blob_id AND segments.import_id = source_imports.import_id
     WHERE files.context_id = ?1 AND files.package_id = ?2 AND files.source_role IN ('go', ?3)
     ORDER BY blobs.id, files.source_role, source_imports.import_id, segments.ordinal";

// The tool's binding of each import spelling of this unit, as
// `IMPORT_PACKAGE_NAME` reads it.
const UNIT_IMPORT_TARGETS_SQL: &str = "SELECT imports.import_role, imports.source_spelling, targets.tool_import_path, targets.for_test, targets.package_id,
       CASE WHEN targets.for_test = '' THEN 'go'
            WHEN EXISTS (SELECT 1 FROM main.go_package_files AS tests
                         WHERE tests.package_id = targets.package_id AND tests.source_role = 'xtest')
              THEN 'xtest'
            ELSE 'test' END
     FROM main.go_package_imports AS imports
     JOIN main.go_package_instances AS targets ON targets.package_id = imports.target_package_id
     WHERE imports.importer_package_id = ?1 AND imports.import_role IN ('go', ?2)";

/// The Go validity predicate: the shared one plus the profile match. The read
/// ledger records which context profile each summary derives from (key
/// `go-context-profile` of the unit). Its version interval is selected by the
/// same profile, so publishing another profile cannot replace this one.
pub(crate) const GO_LIVE_SUMMARY_SQL: &str = concat!(
    super::unit_summaries::live_summary_select!("?9"),
    " AND EXISTS (SELECT 1 FROM resolution_unit_summary_reads AS profile
       WHERE profile.summary_id = versions.summary_id
         AND profile.key_digest = ?8 AND profile.digest = ?9)"
);

/// The read-ledger key under which a Go summary records its context profile.
pub(crate) fn go_profile_read_key(unit_key: &[u8; 32]) -> [u8; 32] {
    read_key("go-context-profile", Some(unit_key))
}

/// The live Go summary of one unit key under the Go validity predicate, for the
/// selected context profile. `None` when no summary is live, or when the live
/// one derives from the other profile.
pub(crate) fn go_live_summary(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
    unit_key: &[u8; 32],
    profile: &[u8; 32],
) -> Result<Option<(i64, Vec<u8>)>> {
    Ok(conn
        .prepare_cached(GO_LIVE_SUMMARY_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                "go",
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision,
                producer_epoch,
                GO_UNIT_SUMMARY_DERIVATION_VERSION,
                go_profile_read_key(unit_key).as_slice(),
                profile.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

pub(crate) fn go_unit_key(tool_import_path: &str, for_test: &str, source_role: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-go-unit-key:v1");
    hash.field("tool-import-path", tool_import_path.as_bytes());
    hash.field("for-test", for_test.as_bytes());
    hash.field("source-role", source_role.as_bytes());
    hash.finish()
}

/// Register deterministic SQL helpers used by bulk summary predicates. The
/// keys are fixed-width values and every call is over rows already selected by
/// the Go context or summary dependency indexes.
#[allow(dead_code)] // Used by the Milestone 3 reverse summary reader.
pub(crate) fn register_go_summary_sql_functions(conn: &Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        "bifrost_go_unit_key",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let path = context.get::<String>(0)?;
            let for_test = context.get::<String>(1)?;
            let role = context.get::<String>(2)?;
            Ok(go_unit_key(&path, &for_test, &role).to_vec())
        },
    )?;
    conn.create_scalar_function(
        "bifrost_go_profile_read_key",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let unit_key: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                rusqlite::Error::UserFunctionError(Box::new(StoreError::corrupt(format!(
                    "Go summary unit key is {} bytes",
                    bytes.len()
                ))))
            })?;
            Ok(go_profile_read_key(&unit_key).to_vec())
        },
    )?;
    Ok(())
}

fn read_key(name: &str, unit_key: Option<&[u8; 32]>) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-read-key:v1");
    hash.field("name", name.as_bytes());
    if let Some(unit_key) = unit_key {
        hash.field("unit", unit_key);
    }
    hash.finish()
}

fn digest_of(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StoreError::corrupt(format!("digest is {} bytes", bytes.len())))
}

struct UnitInstance {
    package_id: i64,
    source_role: String,
    tool_import_path: String,
    for_test: String,
    provider_digest: [u8; 32],
    complete: bool,
    gaps: String,
}

impl GoUnitSummaries {
    fn instance(&self, conn: &Connection, unit_id: i64) -> Result<UnitInstance> {
        let (package_id, source_role, tool_import_path, _name, for_test, digest, complete, gaps) =
            conn.prepare_cached(UNIT_INSTANCE_SQL)?
                .query_row([unit_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                })?;
        Ok(UnitInstance {
            package_id,
            source_role,
            tool_import_path,
            for_test,
            provider_digest: digest_of(digest)?,
            complete,
            gaps,
        })
    }
}

impl UnitSummaryLanguage for GoUnitSummaries {
    fn lang(&self) -> &'static str {
        "go"
    }

    fn unit_kind(&self) -> &'static str {
        "go_package"
    }

    fn derivation_version(&self) -> i64 {
        GO_UNIT_SUMMARY_DERIVATION_VERSION
    }

    fn profile_digest(&self) -> [u8; 32] {
        self.profile
    }

    fn stage(&self, conn: &Connection, _snapshot: &WorkspaceSnapshotId) -> Result<()> {
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS go_unit_summary_units(
               unit_id INTEGER PRIMARY KEY,
               package_id INTEGER NOT NULL,
               source_role TEXT NOT NULL,
               UNIQUE(package_id, source_role)
             ) STRICT;
             DELETE FROM temp.go_unit_summary_units;",
        )?;
        conn.execute(STAGE_UNITS_SQL, [self.context_id])?;
        conn.execute(
            "INSERT INTO temp.unit_summary_work(unit_id) SELECT unit_id FROM temp.go_unit_summary_units",
            [],
        )?;
        conn.execute(STAGE_IMPORT_EDGES_SQL, [])?;
        conn.execute(STAGE_TEST_EDGES_SQL, [])?;
        Ok(())
    }

    fn clear_stage(&self, conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM temp.go_unit_summary_units", [])?;
        Ok(())
    }

    fn live_summary(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        producer_epoch: &str,
        unit_key: &[u8; 32],
    ) -> Result<Option<(i64, Vec<u8>)>> {
        go_live_summary(conn, snapshot, producer_epoch, unit_key, &self.profile)
    }

    fn inputs(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs> {
        let instance = self.instance(conn, unit_id)?;
        let unit_key = go_unit_key(
            &instance.tool_import_path,
            &instance.for_test,
            &instance.source_role,
        );
        let label = format!(
            "go unit {} [{}]",
            instance.tool_import_path, instance.source_role
        );

        let mut members = Vec::new();
        {
            let mut statement = conn.prepare_cached(UNIT_MEMBERS_SQL)?;
            let generation = snapshot.generation.get();
            let mut rows = statement.query(params![
                self.context_id,
                instance.package_id,
                instance.source_role,
                generation
            ])?;
            while let Some(row) = rows.next()? {
                let rel_path: String = row.get(2)?;
                let blob_id: i64 = row.get::<_, Option<i64>>(0)?.ok_or_else(|| {
                    StoreError::corrupt(format!(
                        "{label}: member {rel_path} has no blob row in generation {}",
                        snapshot.generation.get()
                    ))
                })?;
                members.push(UnitMember {
                    blob_id,
                    blob_oid: row.get(1)?,
                    rel_path,
                    source_role: row.get(3)?,
                });
            }
        }

        let mut dependencies = Vec::new();
        {
            let mut statement = conn.prepare_cached(UNIT_DEPENDENCIES_SQL)?;
            let mut rows = statement.query(params![instance.package_id, instance.source_role])?;
            while let Some(row) = rows.next()? {
                let tool_import_path: String = row.get(0)?;
                let for_test: String = row.get(1)?;
                let provider_kind: String = row.get(2)?;
                let provider_digest = digest_of(row.get(3)?)?;
                let module_path: Option<String> = row.get(4)?;
                let module_version: Option<String> = row.get(5)?;
                let target_role: String = row.get(6)?;
                let target_unit: Option<i64> = row.get(7)?;
                let boundary = match provider_kind.as_str() {
                    "workspace" => "workspace",
                    "module" => "external",
                    "standard" => "standard",
                    other => {
                        return Err(StoreError::corrupt(format!(
                            "{label}: package {tool_import_path} has provider kind {other:?}"
                        )));
                    }
                };
                dependencies.push(UnitDependency {
                    unit_key: go_unit_key(&tool_import_path, &for_test, &target_role),
                    unit_id: target_unit,
                    label: format!("go unit {tool_import_path} [{target_role}]"),
                    boundary,
                    provenance: module_path.map(|path| match module_version {
                        Some(version) if !version.is_empty() => format!("{path}@{version}"),
                        _ => path,
                    }),
                    external_digest: (boundary != "workspace").then_some(provider_digest),
                });
            }
        }
        if matches!(instance.source_role.as_str(), "test" | "xtest") {
            let tested = conn
                .prepare_cached(TESTED_PACKAGE_SQL)?
                .query_row([instance.package_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })
                .optional()?;
            if let Some((tool_import_path, for_test, plain_unit)) = tested {
                let unit_key = go_unit_key(&tool_import_path, &for_test, "go");
                if !dependencies
                    .iter()
                    .any(|dependency| dependency.unit_key == unit_key)
                {
                    dependencies.push(UnitDependency {
                        unit_key,
                        unit_id: plain_unit,
                        label: format!("go unit {tool_import_path} [go]"),
                        boundary: "workspace",
                        provenance: None,
                        external_digest: None,
                    });
                }
            }
        }

        // The unit's slice of the tool publication. The publication digest folds
        // every workspace file's mtime, so it moves on every edit; the slice moves
        // only when this package's own instance row or import rows move.
        let mut slice = CanonicalHasher::new(b"bifrost-go-unit-context-slice:v1");
        slice.field("tool-import-path", instance.tool_import_path.as_bytes());
        slice.field("for-test", instance.for_test.as_bytes());
        slice.field("source-role", instance.source_role.as_bytes());
        slice.field("provider", &instance.provider_digest);
        slice.field("complete", &[u8::from(instance.complete)]);
        slice.field("gaps", instance.gaps.as_bytes());
        {
            let mut statement = conn.prepare_cached(UNIT_IMPORT_ROWS_SQL)?;
            let mut rows = statement.query(params![instance.package_id, instance.source_role])?;
            while let Some(row) = rows.next()? {
                slice.field("import-role", row.get::<_, String>(0)?.as_bytes());
                slice.field("import-spelling", row.get::<_, String>(1)?.as_bytes());
                slice.field(
                    "import-target",
                    row.get::<_, Option<String>>(2)?
                        .unwrap_or_default()
                        .as_bytes(),
                );
                slice.field(
                    "import-target-for-test",
                    row.get::<_, Option<String>>(3)?
                        .unwrap_or_default()
                        .as_bytes(),
                );
                slice.field("import-complete", &[u8::from(row.get::<_, bool>(4)?)]);
            }
        }
        Ok(UnitInputs {
            unit_id,
            unit_key,
            label,
            members,
            reads: vec![
                UnitRead {
                    kind: "context_publication",
                    key_digest: read_key("go-package-instance", Some(&unit_key)),
                    digest: slice.finish(),
                },
                // Which profile's publication this summary derives from. A reader
                // that selected a context profile matches this digest, so the
                // tool and source-inventory summaries of one unit key never serve
                // each other's requests.
                UnitRead {
                    kind: "context_publication",
                    key_digest: go_profile_read_key(&unit_key),
                    digest: self.profile,
                },
            ],
            dependencies,
        })
    }

    fn derive(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        producer_epoch: &str,
    ) -> Result<UnitOutputs> {
        let instance = {
            // The unit id is the temp table's own row id; the instance row is
            // the one `inputs` read.
            self.instance(conn, unit.unit_id)?
        };
        let generation = snapshot.generation.get();
        let bound = params![
            self.context_id,
            instance.package_id,
            instance.source_role,
            generation,
            producer_epoch
        ];
        let bound_without_epoch = params![
            self.context_id,
            instance.package_id,
            instance.source_role,
            generation
        ];
        let mut gaps = Vec::new();
        if !instance.complete
            && let Some(detail) = go_provider_gap_detail(&instance.gaps)
        {
            gaps.push(UnitGap {
                kind: "incomplete_provider",
                subject: instance.tool_import_path.clone(),
                detail,
            });
        }
        {
            let mut statement = conn.prepare_cached(MEMBERS_WITHOUT_BUNDLE_SQL)?;
            let mut rows = statement.query(bound)?;
            while let Some(row) = rows.next()? {
                gaps.push(UnitGap {
                    kind: "incomplete_provider",
                    subject: row.get(0)?,
                    detail: "{\"reason\":\"member_bundle_missing\"}".to_owned(),
                });
            }
        }
        for dependency in dependencies
            .iter()
            .filter(|dependency| !dependency.available)
        {
            gaps.push(UnitGap {
                kind: "unit_summary_unavailable",
                subject: dependency.label.clone(),
                detail: "{}".to_owned(),
            });
        }

        let mut exports: Vec<UnitExport> = Vec::new();
        {
            let mut statement = conn.prepare_cached(UNIT_EXPORTS_SQL)?;
            let mut rows = statement.query(bound)?;
            while let Some(row) = rows.next()? {
                let spelling: String = row.get(5)?;
                let exported = spelling.chars().next().is_some_and(char::is_uppercase);
                exports.push(UnitExport {
                    declaration_blob_id: row.get(0)?,
                    declaration_site: row.get(1)?,
                    declaration_key: row.get(2)?,
                    namespace: row.get(3)?,
                    identity_id: row.get(4)?,
                    identity_digest: digest_of(row.get(6)?)?,
                    visibility: if exported { "exported" } else { "unit" },
                    origin: "declaration",
                    alias_dependency_ordinal: None,
                    alias_identity_id: None,
                    alias_identity_digest: None,
                });
            }
        }
        // Two declarations of one name in one namespace cannot both compile, but
        // build-constrained siblings or a partial tool selection can publish
        // them; both are kept and the unit says so.
        {
            let mut by_name: std::collections::HashMap<(i64, &str), usize> =
                std::collections::HashMap::new();
            for export in &exports {
                *by_name
                    .entry((export.identity_id, export.namespace.as_str()))
                    .or_default() += 1;
            }
            let mut conflicts: Vec<_> = by_name
                .into_iter()
                .filter(|(_, count)| *count > 1)
                .map(|((identity, namespace), count)| (identity, namespace.to_owned(), count))
                .collect();
            conflicts.sort_unstable();
            for (identity, namespace, count) in conflicts {
                gaps.push(UnitGap {
                    kind: "conflicting_names",
                    subject: format!("{namespace}:{identity}"),
                    detail: format!("{{\"declarations\":{count}}}"),
                });
            }
        }

        let mut targets: std::collections::HashMap<(String, String), [u8; 32]> =
            std::collections::HashMap::new();
        {
            let mut statement = conn.prepare_cached(UNIT_IMPORT_TARGETS_SQL)?;
            let mut rows = statement.query(params![instance.package_id, instance.source_role])?;
            while let Some(row) = rows.next()? {
                let import_role: String = row.get(0)?;
                let spelling: String = row.get(1)?;
                let path: String = row.get(2)?;
                let for_test: String = row.get(3)?;
                let target_role: String = row.get(5)?;
                targets.insert(
                    (import_role, spelling),
                    go_unit_key(&path, &for_test, &target_role),
                );
            }
        }
        let ordinal_of = |unit_key: &[u8; 32]| {
            dependencies
                .iter()
                .find(|dependency| &dependency.unit_key == unit_key)
                .map(|dependency| dependency.ordinal)
        };
        let mut imports: Vec<UnitImport> = Vec::new();
        {
            struct Pending {
                blob_id: i64,
                source_role: String,
                import_id: i64,
                kind: &'static str,
                definition_key: Option<i64>,
                segments: Vec<String>,
            }
            let mut statement = conn.prepare_cached(UNIT_IMPORTS_SQL)?;
            let mut rows = statement.query(bound_without_epoch)?;
            let mut current: Option<Pending> = None;
            let mut finish = |current: Option<Pending>| -> Result<()> {
                let Some(pending) = current else {
                    return Ok(());
                };
                if pending.segments.is_empty() {
                    return Err(StoreError::corrupt(format!(
                        "{}: Go import {} of blob {} lacks its sealed source import path",
                        unit.label, pending.import_id, pending.blob_id
                    )));
                }
                let spelling = pending.segments.join("/");
                let dependency_ordinal = targets
                    .get(&(pending.source_role.clone(), spelling.clone()))
                    .and_then(&ordinal_of);
                let state = if pending.kind == "blank" {
                    "blank"
                } else if dependency_ordinal.is_some() {
                    "resolved"
                } else {
                    "unresolved"
                };
                imports.push(UnitImport {
                    blob_id: pending.blob_id,
                    import_id: pending.import_id,
                    kind: pending.kind,
                    definition_key: pending.definition_key,
                    spelling,
                    dependency_ordinal,
                    state,
                });
                Ok(())
            };
            while let Some(row) = rows.next()? {
                let key = (
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                );
                if current.as_ref().is_none_or(|pending| {
                    (
                        pending.blob_id,
                        pending.source_role.as_str(),
                        pending.import_id,
                    ) != (key.0, key.1.as_str(), key.2)
                }) {
                    finish(current.take())?;
                    let alias: Option<String> = row.get(3)?;
                    let definition_key: Option<i64> = row.get(4)?;
                    let source_kind: Option<String> = row.get(5)?;
                    // A dot import is the one declaration without an import
                    // binding row: the Go producer emits one for every other.
                    let kind = match (source_kind.as_deref(), alias.as_deref()) {
                        (Some("named"), _) => "named",
                        (Some("blank"), _) => "blank",
                        (None, Some(".")) => "dot",
                        (kind, alias) => {
                            return Err(StoreError::corrupt(format!(
                                "{}: Go import {} of blob {} has binding kind {kind:?} and alias {alias:?}",
                                unit.label, key.2, key.0
                            )));
                        }
                    };
                    current = Some(Pending {
                        blob_id: key.0,
                        source_role: key.1,
                        import_id: key.2,
                        kind,
                        definition_key,
                        segments: Vec::new(),
                    });
                }
                if let Some(segment) = row.get::<_, Option<String>>(6)? {
                    current
                        .as_mut()
                        .expect("a current import exists for its segment row")
                        .segments
                        .push(segment);
                }
            }
            finish(current.take())?;
        }
        {
            let mut by_import: std::collections::HashMap<(i64, i64), Option<usize>> =
                std::collections::HashMap::new();
            for import in &imports {
                by_import.insert(
                    (import.blob_id, import.import_id),
                    import.dependency_ordinal,
                );
            }
            let mut statement = conn.prepare_cached(UNIT_ALIAS_EXPORTS_SQL)?;
            let mut rows = statement.query(bound)?;
            let mut seen = std::collections::HashSet::new();
            while let Some(row) = rows.next()? {
                let blob_id: i64 = row.get(0)?;
                let declaration_site: i64 = row.get(1)?;
                if !seen.insert((blob_id, declaration_site)) {
                    continue;
                }
                let alias_name: String = row.get(2)?;
                let qualifier: Option<String> = row.get(3)?;
                let alias_identity_id: Option<i64> = row.get(4)?;
                let alias_identity_digest: Option<Vec<u8>> = row.get(5)?;
                let import_id: Option<i64> = row.get(6)?;
                let target_kind: Option<i64> = row.get(7)?;
                if target_kind.is_some_and(|kind| kind != 0) {
                    // The alias target has no direct named identity. Its own
                    // package member is the declaration other units resolve.
                    continue;
                }
                let alias_dependency_ordinal = match (qualifier, import_id) {
                    (None, None) => Some(None),
                    (Some(_), Some(import_id)) => by_import
                        .get(&(blob_id, import_id))
                        .copied()
                        .flatten()
                        .map(Some),
                    _ => None,
                };
                let Some(alias_dependency_ordinal) = alias_dependency_ordinal else {
                    gaps.push(UnitGap {
                        kind: "incomplete_provider",
                        subject: format!("{}:{alias_name}", unit.label),
                        detail: "{\"reason\":\"go_alias_target_unavailable\"}".to_owned(),
                    });
                    continue;
                };
                let (Some(alias_identity_id), Some(alias_identity_digest)) =
                    (alias_identity_id, alias_identity_digest)
                else {
                    gaps.push(UnitGap {
                        kind: "incomplete_provider",
                        subject: format!("{}:{alias_name}", unit.label),
                        detail: "{\"reason\":\"go_alias_target_unavailable\"}".to_owned(),
                    });
                    continue;
                };
                let export = exports
                    .iter_mut()
                    .find(|export| {
                        export.declaration_blob_id == blob_id
                            && export.declaration_site == declaration_site
                    })
                    .expect("every Go type alias has a package-member export row");
                export.origin = "alias";
                export.alias_dependency_ordinal = alias_dependency_ordinal;
                export.alias_identity_id = Some(alias_identity_id);
                export.alias_identity_digest = Some(digest_of(alias_identity_digest)?);
            }
        }
        let mut unresolved: Vec<&str> = imports
            .iter()
            .filter(|import| import.state == "unresolved")
            .map(|import| import.spelling.as_str())
            .collect();
        unresolved.sort_unstable();
        unresolved.dedup();
        for spelling in unresolved {
            gaps.push(UnitGap {
                kind: "unresolved_import",
                subject: spelling.to_owned(),
                detail: "{}".to_owned(),
            });
        }
        let complete = gaps.is_empty();
        Ok(UnitOutputs {
            exports,
            imports,
            gaps,
            complete,
            public_surface_digest: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::go_provider_gap_detail;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "6f2e89eab80f: build-selection gaps falsely marked Go unit summaries incomplete"
    )]
    fn build_selection_gaps_do_not_mark_go_unit_summaries_incomplete() {
        assert_eq!(
            go_provider_gap_detail(
                r#"[{"code":"source_file_build_selection_unavailable","evidence":{"path":"pkg/symlink_other.go"}},{"code":"source_build_constraint_facts_unavailable","evidence":{"path":"pkg/symlink_windows.go"}}]"#
            ),
            None
        );
        assert_eq!(
            go_provider_gap_detail(
                r#"[{"code":"source_file_build_selection_unavailable","evidence":{"path":"pkg/symlink_other.go"}},{"code":"missing_provider","evidence":{"path":"pkg/provider.go"}}]"#
            ),
            Some(
                r#"[{"code":"missing_provider","evidence":{"path":"pkg/provider.go"}}]"#.to_owned()
            )
        );
        assert_eq!(go_provider_gap_detail("[]"), Some("[]".to_owned()));
    }
}
