//! Differential test for the Go unit summaries (`store/go_unit_summaries.rs`).
//!
//! A real Go workspace is built and published through the production path, which
//! reconciles the summaries. The test then asks the incumbent readers the same
//! questions the summary answers and compares the answers as sets:
//!
//! - the unit set, against the package placement the point reader uses
//!   (`CALLER_PACKAGE`) for every selected file;
//! - each unit's member files, against the same-package peers
//!   (`PACKAGE_PEER_MOUNTS`);
//! - each unit's export rows, against the package members the same-package reader
//!   (`selected_package_members_by_lookup`) reads per peer;
//! - each unit's import rows, against the `(binding, package)` pairs the import
//!   binding reader (`go_file_import_context_with_role`) publishes.
//!
//! Any difference is printed in full, one side at a time.

use super::super::unit_summaries as unit_summaries_sql;
use super::*;
use crate::analyzer::go::GoAdapter;
use crate::analyzer::go::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
use crate::analyzer::resolution::SharedNameInterner;
use crate::analyzer::semantic_model::{
    DependencyPackLimits, SemanticModelActivationRequest, SemanticModelRuntimeLimits,
    SemanticPackCatalog,
};
use crate::analyzer::store::PersistBatchTargets;
use crate::analyzer::store::go_unit_summaries::go_unit_key;
use crate::analyzer::store::go_unit_summaries::{go_live_summary, go_profile_read_key};
use crate::analyzer::store::resolution_operation::go_same_package::PACKAGE_PEER_MOUNTS;
use crate::analyzer::store::resolution_operation::package_context::SelectedPackageRows;
use crate::analyzer::{
    AnalyzerConfig, DependencyPackEcosystem, DependencyPackWorkspaceContext, GoAnalyzer,
    GoAnalyzerConfig, GoDependencyDiscoveryConfig, GoDependencyDiscoveryMode, Language,
    WorkspaceAnalyzer, resolve_analyzer,
};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use git2::{ObjectType, Oid};
use rusqlite::OptionalExtension;
use rusqlite::params;

const GO_FIXTURE: &[(&str, &str)] = &[
    ("go.mod", "module example.test/native\n\ngo 1.22\n"),
    (
        "util/util.go",
        "package util\n\ntype Helper struct{}\n\nfunc Public() int { return private() }\n\nfunc private() int { return 1 }\n\nconst Limit = 10\n\nvar shared = 2\n\nfunc Map[T any](x T) T { return x }\n\ntype Pair[K comparable, V any] struct{ Key K; Val V }\n",
    ),
    (
        "other/other.go",
        "package other\n\nfunc Extra() int { return 0 }\n\ntype Thing struct{}\n",
    ),
    ("blank/blank.go", "package blank\n\nfunc init() {}\n"),
    (
        "api/api.go",
        "package api\n\nimport (\n\t\"strings\"\n\n\t. \"example.test/native/other\"\n\t_ \"example.test/native/blank\"\n\tu \"example.test/native/util\"\n)\n\ntype Client struct{ name string }\ntype LocalClient = Client\ntype HelperAlias = u.Helper\ntype CommandCtx = func()\n\nfunc NewClient() *Client {\n\t_ = strings.ToUpper(\"x\")\n\t_ = u.Public()\n\t_ = Extra()\n\treturn &Client{}\n}\n",
    ),
    (
        "api/helpers.go",
        "package api\n\nvar Version = \"1\"\n\nvar (\n\tAlpha, beta = 1, 2\n)\n\nconst (\n\tfirst = iota\n\tSecond\n)\n\ntype internalState struct{}\n\nfunc helper() {}\n",
    ),
    (
        "api/platform_windows.go",
        "//go:build windows\n\npackage api\n\nfunc platform() {}\n",
    ),
    (
        "api/platform_other.go",
        "//go:build !windows\n\npackage api\n\nfunc platform() {}\n",
    ),
    (
        "api/api_internal_test.go",
        "package api\n\nimport \"testing\"\n\nfunc TestClient(t *testing.T) { helper(); _ = internalState{} }\n",
    ),
    (
        "api/api_ext_test.go",
        "package api_test\n\nimport (\n\t\"testing\"\n\n\t\"example.test/native/api\"\n\t\"example.test/native/util\"\n)\n\nfunc TestExt(t *testing.T) { _ = api.NewClient(); _ = util.Limit }\n",
    ),
    (
        "cmd/main.go",
        "package main\n\nimport \"example.test/native/api\"\n\nfunc main() { api.NewClient() }\n",
    ),
];

fn go_full_production_config() -> AnalyzerConfig {
    AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                // The fixture has mutually exclusive Linux/Windows files.
                // Pin the Go target so expected unit paths do not depend on
                // the operating system running the test.
                goos: Some("linux".to_owned()),
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    }
}

/// Publish the Go dependency context of `workspace` through the production path,
/// which reconciles the unit summaries after the head publication.
fn activate_go_context(workspace: &WorkspaceAnalyzer) {
    activate_go_context_with(workspace, &go_full_production_config());
}

fn activate_go_context_with(workspace: &WorkspaceAnalyzer, config: &AnalyzerConfig) {
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    let discovery = format!("{discovery:#?}");
    assert!(!discovery.contains("go.unit_summary_failed"), "{discovery}");
}

/// Build a Go workspace and publish its dependency context. `None` when this
/// host has no Go toolchain: without `go list` the context is the partial
/// source-inventory one, which is not summarized.
fn published_go_workspace(
    files: &[(&str, &str)],
) -> Option<(BuiltInlineTestProject, WorkspaceAnalyzer)> {
    if std::process::Command::new("go")
        .arg("version")
        .output()
        .is_err()
    {
        return None;
    }
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let fixture = project.build();
    let workspace = fixture.workspace_analyzer(go_full_production_config());
    activate_go_context(&workspace);
    Some((fixture, workspace))
}

/// One member file of one unit, as the incumbent same-package reader sees it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnitMemberFact {
    blob_id: i64,
    rel_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExportFact {
    blob_id: i64,
    site: u32,
    key: u32,
    namespace: String,
    identity_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ImportFact {
    blob_id: i64,
    definition_key: u32,
    dependency_unit_key: String,
}

/// A dot import, which the incumbent import binding reader does not publish. The
/// oracle is the tool's own import rows for the spelling the file declares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DotImportFact {
    blob_id: i64,
    import_id: i64,
    dependency_unit_key: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn symmetric_difference<T: Ord + Clone + std::fmt::Debug>(
    incumbent: &std::collections::BTreeSet<T>,
    summary: &std::collections::BTreeSet<T>,
) -> Option<String> {
    let only_incumbent: Vec<&T> = incumbent.difference(summary).collect();
    let only_summary: Vec<&T> = summary.difference(incumbent).collect();
    (!only_incumbent.is_empty() || !only_summary.is_empty()).then(|| {
        format!("only in the incumbent reader: {only_incumbent:#?}\nonly in the summary: {only_summary:#?}")
    })
}

/// What the differential saw, for the test to assert that it compared something.
#[derive(Debug, Default)]
struct DifferentialCounts {
    units: usize,
    members: usize,
    exports: usize,
    exported_visibility: usize,
    unit_visibility: usize,
    imports: usize,
    blank_imports: usize,
    dot_imports: usize,
    unresolved_imports: usize,
    dependency_keys: std::collections::BTreeSet<String>,
}

fn assert_summaries_match_incumbent_readers(workspace: &WorkspaceAnalyzer) -> DifferentialCounts {
    let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).expect("a Go analyzer");
    let snapshot = go
        .selected_snapshot_for_test()
        .expect("a selected Go snapshot");
    let cancellation = CancellationToken::new();
    let GoNativePointRequestOpen::Ready(request) =
        GoNativePointRequest::open(go, None, &cancellation).expect("open the Go point request")
    else {
        panic!("the Go point request is unavailable");
    };
    let (operation, context_id) = request.oracle_for_test();
    let connection = operation.ready.inventory.connection();
    let names = operation.ready.shared_names();
    let producer_epoch: String = connection
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let profile: [u8; 32] = connection
        .query_row(
            "SELECT selections.profile_digest FROM main.go_context_publications AS publications
             JOIN main.go_context_selections AS selections ON selections.selection_id = publications.selection_id
             WHERE publications.context_id = ?1",
            [context_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let mut counts = DifferentialCounts::default();

    // The incumbent's units: the package placement of every selected file under
    // the role the file declares.
    let mut files = Vec::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT file_version_id, source_role, rel_path FROM main.go_context_source_files
                 WHERE context_id = ?1 ORDER BY rel_path, source_role",
            )
            .unwrap();
        let mut rows = statement.query([context_id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            files.push((
                row.get::<_, i64>(0).unwrap(),
                row.get::<_, String>(1).unwrap(),
                row.get::<_, String>(2).unwrap(),
            ));
        }
    }
    assert!(!files.is_empty(), "the Go context selected no files");
    let mut units: std::collections::BTreeSet<(i64, String)> = std::collections::BTreeSet::new();
    let mut alias_exports = std::collections::BTreeSet::new();
    for (file_version_id, role, rel_path) in &files {
        let package = connection
            .query_row(
                super::go_same_package::CALLER_PACKAGE,
                rusqlite::params![context_id, file_version_id, role],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap();
        // A file of a role that has no placement (a `go` file listed again under a
        // test variant) is the same file seen as a peer of that variant.
        if let Some(package) = package {
            units.insert((package, role.clone()));
        } else {
            let listed_under_variant: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.go_context_source_files
                     WHERE context_id = ?1 AND file_version_id = ?2 AND source_role <> ?3)",
                    rusqlite::params![context_id, file_version_id, role],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                listed_under_variant,
                "{rel_path} [{role}] has no package placement and no other role"
            );
        }
    }
    let instance_key = |package_id: i64, role: &str| -> [u8; 32] {
        let (path, for_test): (String, String) = connection
            .query_row(
                "SELECT tool_import_path, for_test FROM main.go_package_instances WHERE package_id = ?1",
                [package_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        go_unit_key(&path, &for_test, role)
    };
    let unit_role_of_package = |package_id: i64| -> String {
        let for_test: String = connection
            .query_row(
                "SELECT for_test FROM main.go_package_instances WHERE package_id = ?1",
                [package_id],
                |row| row.get(0),
            )
            .unwrap();
        if for_test.is_empty() {
            return "go".to_owned();
        }
        let roles: Vec<&str> = units
            .iter()
            .filter(|(package, _)| *package == package_id)
            .map(|(_, role)| role.as_str())
            .collect();
        assert_eq!(
            roles.len(),
            1,
            "a test variant instance is the unit of one role: {roles:?}"
        );
        roles[0].to_owned()
    };

    // Every incumbent unit has a live summary, and nothing else is live.
    let live_versions: i64 = connection
        .query_row(
            "SELECT count(*) FROM main.resolution_unit_summary_versions
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2 AND valid_until IS NULL",
            rusqlite::params![snapshot.workspace_id.as_str(), snapshot.generation.get()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        usize::try_from(live_versions).unwrap(),
        units.len(),
        "live version rows against the incumbent's units {units:#?}"
    );

    for (package_id, role) in &units {
        let key = instance_key(*package_id, role);
        let label = format!("package {package_id} [{role}]");
        let (summary_id, _) =
            go_live_summary(connection, &snapshot, &producer_epoch, &key, &profile)
                .unwrap()
                .unwrap_or_else(|| panic!("{label} has no live summary of the selected profile"));
        counts.units += 1;

        // Peers: the same-package reader's mounts.
        let mut peers = Vec::new();
        {
            let mut statement = connection.prepare(PACKAGE_PEER_MOUNTS).unwrap();
            let mut rows = statement
                .query(rusqlite::params![context_id, package_id, role])
                .unwrap();
            while let Some(row) = rows.next().unwrap() {
                peers.push(SelectedResolutionMountOrdinal::new(row.get(0).unwrap()));
            }
        }
        assert!(!peers.is_empty(), "{label} has no peers");
        let mut incumbent_members = std::collections::BTreeSet::new();
        let mut incumbent_exports = std::collections::BTreeSet::new();
        for peer in &peers {
            let record = operation
                .ready
                .inventory
                .mount_record_by_ordinal(*peer)
                .unwrap();
            incumbent_members.insert(UnitMemberFact {
                blob_id: record.blob_id(),
                rel_path: record.persisted_relative_path().to_owned(),
            });
            let SelectedPackageRows::Ready(by_lookup) = operation
                .selected_package_members_by_lookup(*peer, &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            for member in by_lookup.values().flatten() {
                incumbent_exports.insert(ExportFact {
                    blob_id: record.blob_id(),
                    site: member.source_site.get(),
                    key: member
                        .definition
                        .local_key()
                        .expect("an ordinary package member is local to its mount"),
                    namespace: member.namespace.label().to_owned(),
                    identity_id: i64::from(
                        names
                            .to_persisted(
                                member
                                    .lookup
                                    .shared_name_id()
                                    .expect("a package member lookup is a shared name"),
                            )
                            .expect("a persisted lookup name")
                            .get(),
                    ),
                });
            }
        }

        let mut summary_members = std::collections::BTreeSet::new();
        {
            let mut statement = connection
                .prepare(
                    "SELECT blob_id, rel_path FROM main.resolution_unit_summary_members WHERE summary_id = ?1",
                )
                .unwrap();
            let mut rows = statement.query([summary_id]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                summary_members.insert(UnitMemberFact {
                    blob_id: row.get(0).unwrap(),
                    rel_path: row.get(1).unwrap(),
                });
            }
        }
        if let Some(difference) = symmetric_difference(&incumbent_members, &summary_members) {
            panic!("{label}: member files differ\n{difference}");
        }
        counts.members += summary_members.len();

        let mut summary_exports = std::collections::BTreeSet::new();
        {
            let mut statement = connection
                .prepare(
                    "SELECT exports.declaration_blob_id, exports.declaration_site, exports.declaration_key,
                            exports.namespace, exports.identity_id, exports.visibility, identities.spelling,
                            exports.origin, exports.alias_dependency_ordinal, alias_identity.spelling,
                            dependencies.dependency_unit_key
                     FROM main.resolution_unit_summary_exports AS exports
                     JOIN main.resolution_identities AS identities ON identities.id = exports.identity_id
                     LEFT JOIN main.resolution_identities AS alias_identity
                       ON alias_identity.id = exports.alias_identity_id
                     LEFT JOIN main.resolution_unit_summary_dependencies AS dependencies
                       ON dependencies.summary_id = exports.summary_id
                      AND dependencies.dependency_ordinal = exports.alias_dependency_ordinal
                     WHERE exports.summary_id = ?1",
                )
                .unwrap();
            let mut rows = statement.query([summary_id]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                summary_exports.insert(ExportFact {
                    blob_id: row.get(0).unwrap(),
                    site: row.get(1).unwrap(),
                    key: row.get(2).unwrap(),
                    namespace: row.get(3).unwrap(),
                    identity_id: row.get(4).unwrap(),
                });
                // Go exports a name whose first letter is upper case; the fixture
                // names are ASCII.
                let visibility: String = row.get(5).unwrap();
                let spelling: String = row.get(6).unwrap();
                let origin: String = row.get(7).unwrap();
                let alias_dependency_ordinal: Option<i64> = row.get(8).unwrap();
                let alias_target: Option<String> = row.get(9).unwrap();
                let dependency_unit_key: Option<Vec<u8>> = row.get(10).unwrap();
                if origin == "alias" {
                    let alias_target = alias_target.unwrap_or_else(|| {
                        panic!("{label}: alias {spelling:?} has no target identity")
                    });
                    let dependency_unit_key = dependency_unit_key.map(|key| hex(&key));
                    match spelling.as_str() {
                        "LocalClient" => {
                            assert_eq!(alias_target, "Client", "{label}: local alias target");
                            assert!(
                                alias_dependency_ordinal.is_none(),
                                "{label}: local alias has dependency ordinal"
                            );
                            assert!(
                                dependency_unit_key.is_none(),
                                "{label}: local alias has dependency row"
                            );
                        }
                        "HelperAlias" => {
                            assert_eq!(alias_target, "Helper", "{label}: imported alias target");
                            assert!(
                                alias_dependency_ordinal.is_some(),
                                "{label}: imported alias lacks dependency ordinal"
                            );
                            assert_eq!(
                                dependency_unit_key.as_deref(),
                                Some(
                                    hex(&go_unit_key("example.test/native/util", "", "go"))
                                        .as_str()
                                ),
                                "{label}: imported alias dependency"
                            );
                        }
                        _ => panic!("{label}: unexpected alias export {spelling:?}"),
                    }
                    alias_exports.insert((spelling.clone(), alias_target, dependency_unit_key));
                } else {
                    assert!(
                        alias_dependency_ordinal.is_none(),
                        "{label}: non-alias has dependency ordinal"
                    );
                    assert!(
                        alias_target.is_none(),
                        "{label}: non-alias has target identity"
                    );
                    assert!(
                        dependency_unit_key.is_none(),
                        "{label}: non-alias has dependency row"
                    );
                }
                let expected = if spelling.starts_with(|first: char| first.is_ascii_uppercase()) {
                    "exported"
                } else {
                    "unit"
                };
                assert_eq!(visibility, expected, "{label}: visibility of {spelling:?}");
                if visibility == "exported" {
                    counts.exported_visibility += 1;
                } else {
                    counts.unit_visibility += 1;
                }
            }
        }
        if let Some(difference) = symmetric_difference(&incumbent_exports, &summary_exports) {
            panic!("{label}: export rows differ\n{difference}");
        }
        counts.exports += summary_exports.len();
        {
            let mut statement = connection
                .prepare(
                    "SELECT dependency_unit_key FROM main.resolution_unit_summary_dependencies WHERE summary_id = ?1",
                )
                .unwrap();
            let mut rows = statement.query([summary_id]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                counts
                    .dependency_keys
                    .insert(hex(&row.get::<_, Vec<u8>>(0).unwrap()));
            }
        }

        // Imports: only the files whose own role is the unit's role, because the
        // incumbent binds a file's imports under the role it declares.
        let covered_blobs: std::collections::BTreeSet<i64> = files
            .iter()
            .filter(|(_, file_role, _)| file_role == role)
            .filter_map(|(_, _, rel_path)| {
                incumbent_members
                    .iter()
                    .find(|member| &member.rel_path == rel_path)
                    .map(|member| member.blob_id)
            })
            .collect();
        let mut incumbent_imports = std::collections::BTreeSet::new();
        for (file_version_id, file_role, rel_path) in &files {
            if file_role != role
                || connection
                    .query_row(
                        super::go_same_package::CALLER_PACKAGE,
                        rusqlite::params![context_id, file_version_id, file_role],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .unwrap()
                    != Some(*package_id)
            {
                continue;
            }
            let outcome = operation
                .go_file_import_context_with_role(context_id, rel_path, role, &cancellation)
                .unwrap();
            let GoPreparedImportContextOutcome::Ready(prepared) = outcome else {
                panic!("{label}: {rel_path} has no prepared import context");
            };
            for ((mount, definition), target_package) in &prepared.demand.import_packages {
                let record = operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(*mount)
                    .unwrap();
                incumbent_imports.insert(ImportFact {
                    blob_id: record.blob_id(),
                    definition_key: definition
                        .local_key()
                        .expect("an import binding definition is local to its mount"),
                    dependency_unit_key: hex(&instance_key(
                        *target_package,
                        &unit_role_of_package(*target_package),
                    )),
                });
            }
        }
        let mut summary_imports = std::collections::BTreeSet::new();
        let mut summary_dots = std::collections::BTreeSet::new();
        {
            let mut statement = connection
                .prepare(
                    "SELECT imports.blob_id, imports.import_id, imports.kind, imports.import_definition_key,
                            imports.state, dependencies.dependency_unit_key
                     FROM main.resolution_unit_summary_imports AS imports
                     LEFT JOIN main.resolution_unit_summary_dependencies AS dependencies
                       ON dependencies.summary_id = imports.summary_id
                      AND dependencies.dependency_ordinal = imports.dependency_ordinal
                     WHERE imports.summary_id = ?1",
                )
                .unwrap();
            let mut rows = statement.query([summary_id]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let blob_id: i64 = row.get(0).unwrap();
                let import_id: i64 = row.get(1).unwrap();
                let kind: String = row.get(2).unwrap();
                let state: String = row.get(4).unwrap();
                let dependency: Option<Vec<u8>> = row.get(5).unwrap();
                match kind.as_str() {
                    "blank" => counts.blank_imports += 1,
                    "dot" => counts.dot_imports += 1,
                    _ => {}
                }
                if state == "unresolved" {
                    counts.unresolved_imports += 1;
                }
                if !covered_blobs.contains(&blob_id) {
                    continue;
                }
                match (kind.as_str(), dependency) {
                    ("named", Some(dependency)) => {
                        summary_imports.insert(ImportFact {
                            blob_id,
                            definition_key: row.get(3).unwrap(),
                            dependency_unit_key: hex(&dependency),
                        });
                    }
                    ("dot", Some(dependency)) => {
                        summary_dots.insert(DotImportFact {
                            blob_id,
                            import_id,
                            dependency_unit_key: hex(&dependency),
                        });
                    }
                    _ => {}
                }
            }
        }
        if let Some(difference) = symmetric_difference(&incumbent_imports, &summary_imports) {
            panic!("{label}: import rows differ\n{difference}");
        }
        counts.imports += summary_imports.len();

        let mut incumbent_dots = std::collections::BTreeSet::new();
        for blob_id in &covered_blobs {
            let mut statement = connection
                .prepare(
                    "SELECT imports.import_id,
                            (SELECT group_concat(segment, '/') FROM
                               (SELECT segment FROM main.source_import_segments AS segments
                                WHERE segments.blob_id = imports.blob_id AND segments.import_id = imports.import_id
                                ORDER BY ordinal))
                     FROM main.source_imports AS imports
                     WHERE imports.blob_id = ?1 AND imports.alias = '.'",
                )
                .unwrap();
            let mut rows = statement.query([blob_id]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let import_id: i64 = row.get(0).unwrap();
                let spelling: String = row.get(1).unwrap();
                let target: Option<i64> = connection
                    .query_row(
                        "SELECT target_package_id FROM main.go_package_imports
                         WHERE importer_package_id = ?1 AND import_role = ?2 AND source_spelling = ?3",
                        rusqlite::params![package_id, role, spelling],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .optional()
                    .unwrap()
                    .flatten();
                if let Some(target) = target {
                    incumbent_dots.insert(DotImportFact {
                        blob_id: *blob_id,
                        import_id,
                        dependency_unit_key: hex(&instance_key(
                            target,
                            &unit_role_of_package(target),
                        )),
                    });
                }
            }
        }
        if let Some(difference) = symmetric_difference(&incumbent_dots, &summary_dots) {
            panic!("{label}: dot import rows differ\n{difference}");
        }
    }
    assert_eq!(
        alias_exports,
        [
            ("LocalClient".to_owned(), "Client".to_owned(), None),
            (
                "HelperAlias".to_owned(),
                "Helper".to_owned(),
                Some(hex(&go_unit_key("example.test/native/util", "", "go"))),
            ),
        ]
        .into(),
        "summary alias targets agree with the saved target identity and dependency unit"
    );
    counts
}

#[brokk_bifrost_test_macros::hardwon(
    "800772caaffe: an alias to an anonymous Go type was misclassified as an incomplete provider"
)]
#[test]
fn go_unit_summaries_equal_the_incumbent_member_and_import_readers() {
    let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
        return;
    };
    let counts = assert_summaries_match_incumbent_readers(&workspace);
    // The fixture has plain, internal-test and external-test units, exported and
    // package-private names, dot, aliased, blank and standard-library imports.
    assert!(counts.units >= 7, "{counts:?}");
    assert!(
        counts.exported_visibility > 0 && counts.unit_visibility > 0,
        "{counts:?}"
    );
    assert!(counts.blank_imports >= 1, "{counts:?}");
    assert!(counts.dot_imports >= 1, "{counts:?}");
    // The tool context binds every import of the fixture, the standard library
    // included.
    assert_eq!(counts.unresolved_imports, 0, "{counts:?}");
    for (path, role) in [("example.test/native/other", "go"), ("strings", "go")] {
        assert!(
            counts
                .dependency_keys
                .contains(&hex(&go_unit_key(path, "", role))),
            "{path} is not a recorded dependency: {counts:?}"
        );
    }
    assert!(counts.imports >= 7, "{counts:?}");
    let connection = workspace.store().unwrap().read_conn().unwrap();
    type AliasRow = (Option<i64>, String, Option<Vec<u8>>);
    let aliases: std::collections::HashMap<String, AliasRow> = {
        let mut statement = connection
            .prepare(
                "SELECT exported.spelling, exports.alias_dependency_ordinal,
                        target.spelling, dependency.dependency_unit_key
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id=exports.summary_id
                 JOIN resolution_unit_summary_members AS members
                   ON members.summary_id=summaries.summary_id
                  AND members.rel_path='api/api.go'
                 JOIN resolution_identities AS exported ON exported.id=exports.identity_id
                 JOIN resolution_identities AS target ON target.id=exports.alias_identity_id
                 LEFT JOIN resolution_unit_summary_dependencies AS dependency
                   ON dependency.summary_id=exports.summary_id
                  AND dependency.dependency_ordinal=exports.alias_dependency_ordinal
                 WHERE exports.origin='alias'",
            )
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let mut aliases = std::collections::HashMap::new();
        while let Some(row) = rows.next().unwrap() {
            aliases.insert(
                row.get(0).unwrap(),
                (
                    row.get(1).unwrap(),
                    row.get(2).unwrap(),
                    row.get(3).unwrap(),
                ),
            );
        }
        aliases
    };
    let local = aliases
        .get("LocalClient")
        .unwrap_or_else(|| panic!("same-unit Go alias target is published: {aliases:?}"));
    assert_eq!(local.0, None);
    assert_eq!(local.1, "Client");
    assert_eq!(local.2, None);
    let qualified = aliases
        .get("HelperAlias")
        .expect("qualified Go alias target is published");
    assert!(
        qualified.0.is_some(),
        "qualified alias has a dependency ordinal"
    );
    assert_eq!(qualified.1, "Helper");
    assert_eq!(
        qualified.2.as_deref(),
        Some(go_unit_key("example.test/native/util", "", "go").as_slice()),
        "qualified Go alias points to the dependency unit"
    );
    let (anonymous_origin, alias_dependency, alias_identity, alias_gap_count): (
        String,
        Option<i64>,
        Option<i64>,
        i64,
    ) = connection
        .query_row(
            "SELECT exports.origin, exports.alias_dependency_ordinal,
                    exports.alias_identity_id,
                    (SELECT COUNT(*) FROM resolution_unit_summary_gaps AS gaps
                     WHERE gaps.summary_id=exports.summary_id
                       AND gaps.gap_kind='incomplete_provider'
                       AND json_extract(gaps.detail, '$.reason')='go_alias_target_unavailable')
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_unit_summaries AS summaries
               ON summaries.summary_id=exports.summary_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id=summaries.summary_id
              AND members.rel_path='api/api.go'
             JOIN resolution_identities AS identity ON identity.id=exports.identity_id
             WHERE identity.spelling='CommandCtx'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(anonymous_origin, "declaration");
    assert_eq!(alias_dependency, None);
    assert_eq!(alias_identity, None);
    assert_eq!(
        alias_gap_count, 0,
        "anonymous alias targets are not provider gaps"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "51e2e4668128: test package summaries lost alias targets imported by ordinary Go files"
)]
#[test]
fn go_test_unit_aliases_reach_imports_from_package_files() {
    let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
        return;
    };
    let connection = workspace.store().unwrap().read_conn().unwrap();
    let summary_id: i64 = connection
        .query_row(
            "SELECT members.summary_id
             FROM resolution_unit_summary_members AS members
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id=members.summary_id AND versions.valid_until IS NULL
             WHERE members.rel_path='api/api_internal_test.go'",
            [],
            |row| row.get(0),
        )
        .expect("the internal test variant has a live unit summary");
    let (origin, target, dependency_key): (String, String, Option<Vec<u8>>) = connection
        .query_row(
            "SELECT exports.origin, target.spelling, dependency.dependency_unit_key
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS exported ON exported.id=exports.identity_id
             JOIN resolution_identities AS target ON target.id=exports.alias_identity_id
             LEFT JOIN resolution_unit_summary_dependencies AS dependency
               ON dependency.summary_id=exports.summary_id
              AND dependency.dependency_ordinal=exports.alias_dependency_ordinal
             WHERE exports.summary_id=?1 AND exported.spelling='HelperAlias'",
            [summary_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the test unit publishes the named alias from api/api.go");
    assert_eq!(origin, "alias");
    assert_eq!(target, "Helper");
    assert_eq!(
        dependency_key.as_deref(),
        Some(go_unit_key("example.test/native/util", "", "go").as_slice())
    );
}

/// One open version row of the live summaries, keyed by the unit's member paths.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenUnit {
    valid_from: i64,
    summary_id: i64,
    summary_digest: Vec<u8>,
    output_digest: Vec<u8>,
}

fn open_units(workspace: &WorkspaceAnalyzer) -> std::collections::BTreeMap<String, OpenUnit> {
    let conn = workspace.store().unwrap().read_conn().unwrap();
    let mut statement = conn
        .prepare(
            "SELECT (SELECT group_concat(rel_path, ',') FROM
                       (SELECT rel_path FROM resolution_unit_summary_members AS members
                        WHERE members.summary_id = versions.summary_id ORDER BY rel_path)),
                    versions.valid_from, versions.summary_id, summaries.summary_digest, summaries.output_digest
             FROM resolution_unit_summary_versions AS versions
             JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
             WHERE versions.lang = 'go' AND versions.valid_until IS NULL",
        )
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    let mut units = std::collections::BTreeMap::new();
    while let Some(row) = rows.next().unwrap() {
        let label: String = row.get(0).unwrap();
        let previous = units.insert(
            label.clone(),
            OpenUnit {
                valid_from: row.get(1).unwrap(),
                summary_id: row.get(2).unwrap(),
                summary_digest: row.get(3).unwrap(),
                output_digest: row.get(4).unwrap(),
            },
        );
        assert!(
            previous.is_none(),
            "two live units list the members {label}"
        );
    }
    units
}

fn units_with_a_new_summary(
    before: &std::collections::BTreeMap<String, OpenUnit>,
    after: &std::collections::BTreeMap<String, OpenUnit>,
) -> std::collections::BTreeSet<String> {
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the unit set changed"
    );
    before
        .iter()
        .filter(|(label, unit)| after[*label].summary_id != unit.summary_id)
        .map(|(label, _)| label.clone())
        .collect()
}

fn edit_and_republish(
    fixture: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    path: &str,
    source: &str,
) -> WorkspaceAnalyzer {
    std::fs::write(fixture.root().join(path), source).unwrap();
    let file = fixture.file(path);
    let updated = workspace.update(&std::collections::BTreeSet::from([file]));
    activate_go_context(&updated);
    updated
}

/// Early cutoff, end to end. A body edit to a package with dependents derives
/// exactly that package again and leaves every dependent's version row alone,
/// because the package's output digest is unchanged. An edit that adds an
/// exported name derives the package and its direct importers, and stops at the
/// importers' own dependents because their output digests are unchanged.
#[test]
fn a_body_edit_derives_one_unit_and_stops_at_the_output_digest() {
    let Some((fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
        return;
    };
    let initial = open_units(&workspace);
    assert_eq!(
        initial.len(),
        7,
        "{:#?}",
        initial.keys().collect::<Vec<_>>()
    );
    let util_source = GO_FIXTURE
        .iter()
        .find(|(path, _)| *path == "util/util.go")
        .unwrap()
        .1;

    let body_edit = util_source.replace(
        "func private() int { return 1 }",
        "func private() int { return 2 }",
    );
    assert_ne!(body_edit, util_source);
    let after_body = edit_and_republish(&fixture, &workspace, "util/util.go", &body_edit);
    let body_units = open_units(&after_body);
    assert_eq!(
        units_with_a_new_summary(&initial, &body_units),
        ["util/util.go".to_owned()].into(),
        "a body edit derives the one unit that lists the file"
    );
    assert_eq!(
        initial["util/util.go"].output_digest, body_units["util/util.go"].output_digest,
        "a body edit leaves the output digest"
    );
    assert_ne!(
        initial["util/util.go"].summary_digest, body_units["util/util.go"].summary_digest,
        "the member oid is part of the input digest"
    );
    for (label, unit) in &initial {
        if label != "util/util.go" {
            assert_eq!(
                unit, &body_units[label],
                "{label}: a dependent's version row is untouched"
            );
        }
    }

    let surface_edit = format!("{body_edit}\nfunc Added() int {{ return 3 }}\n");
    let after_surface = edit_and_republish(&fixture, &after_body, "util/util.go", &surface_edit);
    let surface_units = open_units(&after_surface);
    let rederived = units_with_a_new_summary(&body_units, &surface_units);
    assert_eq!(
        rederived,
        [
            "util/util.go",
            "api/api.go,api/api_internal_test.go,api/helpers.go,api/platform_other.go",
            "api/api.go,api/helpers.go,api/platform_other.go",
            "api/api_ext_test.go",
        ]
        .map(str::to_owned)
        .into(),
        "an exported addition derives the package and its direct importers"
    );
    assert_ne!(
        body_units["util/util.go"].output_digest, surface_units["util/util.go"].output_digest,
        "an exported addition moves the output digest"
    );
    for importer in &rederived {
        if importer != "util/util.go" {
            assert_eq!(
                body_units[importer].output_digest, surface_units[importer].output_digest,
                "{importer}: an importer's own surface is unchanged"
            );
        }
    }
    assert_eq!(
        body_units["cmd/main.go"], surface_units["cmd/main.go"],
        "the importers' dependents stop at their unchanged output digests"
    );

    // An added import is not caller-visible (Go has no re-exports): it derives
    // the unit that gained it and no importer.
    let import_edit = surface_edit.replacen(
        "package util\n",
        "package util\n\nimport _ \"example.test/native/other\"\n",
        1,
    );
    assert_ne!(import_edit, surface_edit);
    let after_import = edit_and_republish(&fixture, &after_surface, "util/util.go", &import_edit);
    let import_units = open_units(&after_import);
    assert_eq!(
        units_with_a_new_summary(&surface_units, &import_units),
        ["util/util.go".to_owned()].into(),
        "an added import derives only the unit that gained it"
    );
    assert_eq!(
        surface_units["util/util.go"].output_digest, import_units["util/util.go"].output_digest,
        "an added import leaves the output digest"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#4994: retained summary statistics let Go reverse completeness scan source imports"
)]
fn go_unit_summary_readers_seek_in_both_statistics_states() {
    use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::types::Value;

    let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
        return;
    };
    let store = workspace.store().unwrap();
    // The two pinned states, then the store's own ANALYZE of this fixture, whose
    // statistics describe the summary tables themselves.
    for statistics in PlannerStatisticsState::BOTH
        .into_iter()
        .map(Some)
        .chain([None])
    {
        match statistics {
            Some(statistics) => {
                store
                    .conn
                    .execute(move |connection| statistics.install(connection));
                store.recycle_readers_for_new_statistics();
            }
            None => {
                store.refresh_planner_statistics().unwrap();
            }
        }
        let statistics = statistics.map_or_else(
            || "the store's own ANALYZE".to_owned(),
            |statistics| statistics.to_string(),
        );
        let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
        let snapshot = go.selected_snapshot_for_test().unwrap();
        let cancellation = CancellationToken::new();
        let GoNativePointRequestOpen::Ready(request) =
            GoNativePointRequest::open(go, None, &cancellation).unwrap()
        else {
            panic!("the Go point request is unavailable");
        };
        let (operation, _) = request.oracle_for_test();
        let connection = operation.ready.inventory.connection();
        super::super::go_unit_summaries::register_go_summary_sql_functions(connection).unwrap();
        let epoch: String = connection
            .query_row(
                "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // The unit with the most dependents and exports in the fixture is the
        // util package, so its rows are the realistic bindings.
        let (summary_id, unit_key): (i64, Vec<u8>) = connection
            .query_row(
                "SELECT versions.summary_id, versions.unit_key
                 FROM resolution_unit_summary_versions AS versions
                 JOIN resolution_unit_summary_members AS members ON members.summary_id = versions.summary_id
                 WHERE versions.valid_until IS NULL AND members.rel_path = 'util/util.go'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let unit_key_array: [u8; 32] = unit_key.clone().try_into().unwrap();
        let profile: Vec<u8> = connection
            .query_row(
                "SELECT selections.profile_digest FROM main.go_context_selections AS selections
                 WHERE selections.workspace_id = ?1 AND selections.generation = ?2 AND selections.revision = ?3",
                rusqlite::params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| row.get(0),
            )
            .unwrap();
        let (namespace, identity_id): (String, i64) = connection
            .query_row(
                "SELECT namespace, identity_id FROM resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND visibility = 'exported' ORDER BY identity_id LIMIT 1",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (blob_oid, lang): (String, String) = connection
            .query_row(
                "SELECT blobs.blob_oid, blobs.lang FROM resolution_unit_summary_members AS members
                 JOIN blobs ON blobs.id = members.blob_id WHERE members.summary_id = ?1 LIMIT 1",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let workspace_id = snapshot.workspace_id.as_str().to_owned();
        let (caller_blob_id, caller_summary_id, caller_unit_key, caller_reference, source_lookup): (
            i64,
            i64,
            Vec<u8>,
            i64,
            i64,
        ) = connection
            .query_row(
                "SELECT route.blob_id,versions.summary_id,versions.unit_key,
                        route.reference,route.source_lookup
                 FROM main.resolution_qualified_routes AS route
                 JOIN temp.selected_resolution_mounts AS mount
                   ON mount.blob_id=route.blob_id AND mount.storage_language='go'
                 JOIN main.resolution_unit_summary_members AS member
                   ON member.blob_id=route.blob_id
                 JOIN main.resolution_unit_summary_versions AS versions
                   ON versions.summary_id=member.summary_id
                 WHERE versions.workspace_id=?1 AND versions.lang='go'
                   AND versions.generation=?2 AND versions.valid_from<=?3
                   AND (versions.valid_until IS NULL OR ?3<versions.valid_until)
                 LIMIT 1",
                params![workspace_id, snapshot.generation.get(), snapshot.revision],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        let caller_unit_key: [u8; 32] = caller_unit_key.try_into().unwrap();
        let inventory_context_id: i64 = connection
            .query_row(
                "SELECT heads.context_id FROM main.go_context_selections AS selections
                 JOIN main.go_context_heads AS heads USING(selection_id)
                 WHERE selections.workspace_id=?1 AND selections.generation=?2
                   AND selections.revision=?3 LIMIT 1",
                params![workspace_id, snapshot.generation.get(), snapshot.revision],
                |row| row.get(0),
            )
            .unwrap();
        let (caller_package_id, caller_summary_role): (i64, String) = connection
            .query_row(
                "SELECT package.package_id,
                        CASE WHEN package.for_test='' THEN 'go'
                             WHEN EXISTS(SELECT 1 FROM main.go_package_files AS tests
                                         WHERE tests.package_id=package.package_id
                                           AND tests.source_role='xtest') THEN 'xtest'
                             ELSE 'test' END
                 FROM main.go_context_source_files AS source
                 JOIN temp.selected_resolution_mounts AS mount
                   ON mount.file_version_id=source.file_version_id
                 JOIN main.go_package_instances AS package
                   ON package.context_id=source.context_id
                  AND package.package_id=source.package_id
                 WHERE source.context_id=?1 AND mount.blob_id=?2 LIMIT 1",
                params![inventory_context_id, caller_blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let inventory_file_version: i64 = connection
            .query_row(
                "SELECT file_version_id FROM main.workspace_file_versions
                 WHERE workspace_id=?1 AND lang='go' AND generation=?2
                   AND rel_path='util/util.go' LIMIT 1",
                params![workspace_id, snapshot.generation.get()],
                |row| row.get(0),
            )
            .unwrap();
        let demand_json = serde_json::to_string(&[(identity_id, namespace.as_str())]).unwrap();
        let qualified_demand_json = serde_json::to_string(&[(source_lookup, "type")]).unwrap();

        let bind = |name: &str, params: Vec<Value>| {
            let mut pin = pinned(name);
            pin.params = params;
            let plan = explain_pin(connection, &pin);
            eprintln!("UNIT SUMMARY PLAN {statistics} {name}: {plan:#?}");
            let allowed = |detail: &&String| {
                let bounded_path_walk = name == "reference_local_path_evidence";
                let bounded_qualifier_spellings = name == "go_reverse_qualified_import";
                let bounded_import_segment_walk = [
                    "go_reverse_inventory_complete",
                    "go_reverse_qualified_import",
                    "go_reverse_dot_export_rows",
                    "go_reverse_transient_alias_exports",
                ]
                .contains(&name)
                    && (detail.starts_with("CO-ROUTINE (subquery-")
                        || detail.starts_with("SCAN (subquery-"));
                // The path CTEs follow one keyed (blob_id, site) request. The
                // qualifier CTE contains only that request's scope spellings.
                // The import-segment subqueries seek one selected source
                // import before walking its bounded path segments.
                let bounded_cte_scan = [
                    "SCAN CONSTANT ROW",
                    "SCAN target_packages",
                    "SCAN target_units",
                    "SCAN test_units",
                    "SCAN target_keys",
                    "SCAN target ",
                    "SCAN dependent_units",
                    "SCAN visible",
                    "SCAN live_summaries",
                    "SCAN prefix",
                    "SCAN prefix_site_paths",
                    "SCAN prefix_matched_bindings",
                    "SCAN nearest",
                    // Candidate-local relation materialized from the one
                    // keyed qualifier path read above.
                    "SCAN prefix_definition_row",
                ]
                .iter()
                .any(|prefix| detail.starts_with(prefix))
                    || (bounded_path_walk
                        && ["SCAN paths LEFT-JOIN", "SCAN site_paths", "SCAN walk"]
                            .iter()
                            .any(|prefix| detail.starts_with(prefix)))
                    || (bounded_qualifier_spellings && detail.starts_with("SCAN scope"));
                let bounded_cte_scan = bounded_cte_scan
                    || (bounded_import_segment_walk && detail.starts_with("SCAN (subquery-"));
                let unindexed_table_scan = detail.starts_with("SCAN ")
                    && !detail.contains("VIRTUAL TABLE")
                    && !bounded_cte_scan;
                let bounded_cte_index = detail
                    .starts_with("SEARCH target_packages USING AUTOMATIC")
                    || detail.starts_with("SEARCH visible USING AUTOMATIC")
                    || (bounded_path_walk
                        && (detail.starts_with("SEARCH walk USING AUTOMATIC COVERING INDEX")
                            || detail
                                .starts_with("SEARCH binding USING AUTOMATIC COVERING INDEX")
                            || detail.starts_with(
                                "SEARCH prefix_definition USING AUTOMATIC PARTIAL COVERING INDEX",
                            )
                            || detail.starts_with(
                                "SEARCH prefix_scope USING AUTOMATIC PARTIAL COVERING INDEX",
                            )));
                let bounded_path_temp_btree = bounded_path_walk
                    && [
                        "USE TEMP B-TREE FOR GROUP BY",
                        "USE TEMP B-TREE FOR count(DISTINCT)",
                        "USE TEMP B-TREE FOR ORDER BY",
                        "USE TEMP B-TREE FOR DISTINCT",
                    ]
                    .iter()
                    .any(|prefix| detail.starts_with(prefix));
                let bounded_qualifier_temp_btree = bounded_qualifier_spellings
                    && detail.starts_with("USE TEMP B-TREE FOR DISTINCT");
                let bounded_qualifier_co_routine =
                    bounded_qualifier_spellings && detail.starts_with("CO-ROUTINE scope_spellings");
                !unindexed_table_scan
                    && (!detail.contains("AUTOMATIC") || bounded_cte_index)
                    && (!detail.contains("TEMP B-TREE")
                        || bounded_path_temp_btree
                        || bounded_qualifier_temp_btree)
                    && (!detail.contains("CO-ROUTINE")
                        || bounded_qualifier_co_routine
                        || bounded_import_segment_walk)
                    && (!detail.starts_with("SCAN (subquery-") || bounded_import_segment_walk)
            };
            let violations: Vec<_> = plan.iter().filter(|detail| !allowed(detail)).collect();
            assert!(
                violations.is_empty(),
                "{name} with {statistics} has forbidden plan entries {violations:?}: {plan:?}"
            );
            plan
        };
        let uses = |plan: &[String], needle: &str, name: &str| {
            assert!(
                plan.iter()
                    .any(|detail| detail.starts_with("SEARCH") && detail.contains(needle)),
                "{name} with {statistics} must seek {needle}: {plan:?}"
            );
        };

        let plan = bind(
            "unit_summary_live_version",
            vec![
                Value::Text(workspace_id.clone()),
                Value::Text("go".into()),
                Value::Integer(snapshot.generation.get()),
                Value::Blob(unit_key.clone()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    crate::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&unit_key_array).to_vec()),
                Value::Blob(profile.clone()),
            ],
        );
        uses(&plan, "versions USING PRIMARY KEY", "live version");
        uses(&plan, "profile EXISTS USING INDEX", "live version");
        uses(&plan, "summaries USING INTEGER PRIMARY KEY", "live version");

        let plan = bind(
            "unit_summary_export_point",
            vec![
                Value::Integer(summary_id),
                Value::Text(namespace.clone()),
                Value::Integer(identity_id),
            ],
        );
        uses(&plan, "resolution_unit_summary_exports", "export point");

        let plan = bind(
            "unit_summary_dependents",
            vec![
                Value::Blob(unit_key),
                Value::Text(workspace_id.clone()),
                Value::Text("go".into()),
                Value::Integer(snapshot.generation.get()),
            ],
        );
        assert!(
            plan[0].starts_with("SEARCH dependencies USING")
                && plan[0].contains("resolution_unit_summary_dependencies_unit"),
            "dependents with {statistics} must start from the dependency index: {plan:?}"
        );
        uses(&plan, "versions USING", "dependents");

        let plan = bind("unit_summary_graph_join", vec![Value::Integer(summary_id)]);
        uses(&plan, "members USING", "graph join");
        let position = |needle: &str| {
            plan.iter()
                .position(|detail| detail.starts_with("SEARCH") && detail.contains(needle))
                .unwrap_or_else(|| {
                    panic!("graph join with {statistics} must seek {needle}: {plan:?}")
                })
        };
        assert!(
            position("paths USING COVERING INDEX resolution_paths_root_terminal (blob_id=?")
                < position("exports USING PRIMARY KEY (summary_id=? AND identity_id=?"),
            "graph join with {statistics} must probe the exports once per root path: {plan:?}"
        );

        let plan = bind(
            "unit_summary_withdraw_replaced_blob",
            vec![Value::Text(blob_oid), Value::Text(lang)],
        );
        uses(&plan, "blobs USING", "withdraw replaced blob");
        uses(&plan, "members USING", "withdraw replaced blob");
        uses(
            &plan,
            "resolution_unit_summary_versions USING",
            "withdraw replaced blob",
        );

        let plan = bind(
            "reference_local_path_evidence",
            vec![
                Value::Integer(caller_blob_id),
                Value::Integer(caller_reference),
            ],
        );
        uses(
            &plan,
            "resolution_paths_forward (blob_id=? AND start_node=?",
            "keyed local path evidence",
        );

        let plan = bind(
            "go_reverse_summary_export_rows",
            vec![
                Value::Integer(caller_summary_id),
                Value::Text(demand_json.clone()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    crate::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                Value::Text("[]".into()),
                Value::Integer(1),
            ],
        );
        uses(&plan, "export USING PRIMARY KEY", "reverse export rows");

        for (name, params) in [
            (
                "go_reverse_transient_target_exports",
                vec![
                    Value::Integer(caller_summary_id),
                    Value::Text("[]".into()),
                    Value::Text(demand_json.clone()),
                ],
            ),
            (
                "go_reverse_transient_alias_exports",
                vec![
                    Value::Integer(caller_summary_id),
                    Value::Text(demand_json.clone()),
                    Value::Integer(caller_package_id),
                    Value::Text(caller_summary_role.clone()),
                    Value::Integer(inventory_context_id),
                    Value::Text(workspace_id.clone()),
                    Value::Integer(snapshot.generation.get()),
                    Value::Integer(snapshot.revision),
                    Value::Text(epoch.clone()),
                    Value::Integer(
                        crate::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                    ),
                    Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                    Value::Text("[]".into()),
                ],
            ),
        ] {
            bind(name, params);
        }

        let plan = bind(
            "go_reverse_qualified_import",
            vec![
                Value::Integer(caller_summary_id),
                Value::Integer(caller_blob_id),
                Value::Integer(caller_reference),
                Value::Text(qualified_demand_json),
                Value::Integer(caller_package_id),
                Value::Text(caller_summary_role.clone()),
                Value::Integer(1),
            ],
        );
        uses(
            &plan,
            "resolution_go_package_imports_scope (blob_id=? AND file_scope_key=?)",
            "qualified import binder",
        );

        let plan = bind(
            "go_reverse_dot_export_rows",
            vec![
                Value::Integer(caller_summary_id),
                Value::Integer(caller_blob_id),
                Value::Text(demand_json.clone()),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    crate::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                Value::Text("[]".into()),
                Value::Integer(inventory_context_id),
                Value::Integer(caller_package_id),
                Value::Text(caller_summary_role),
                Value::Integer(1),
            ],
        );
        uses(&plan, "export USING PRIMARY KEY", "dot reverse exports");

        let target_surfaces = serde_json::to_string(&[(identity_id, "type")]).unwrap();
        let plan = bind(
            "go_reverse_inventory_complete",
            vec![
                Value::Integer(inventory_context_id),
                Value::Integer(inventory_file_version),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text(target_surfaces),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Blob(profile.clone()),
                Value::Integer(
                    crate::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Text("[]".into()),
            ],
        );
        uses(
            &plan,
            "resolution_unit_summary_dependencies_unit",
            "reverse inventory dependents",
        );
        uses(
            &plan,
            "resolution_unit_summary_versions",
            "reverse inventory live versions",
        );
        uses(
            &plan,
            "main.source_import_segments USING PRIMARY KEY (blob_id=? AND import_id=?)",
            "unresolved dot-import path",
        );
    }
}

/// Operator measurement of the reconcile on a real repository.
///
/// `BIFROST_UNIT_SUMMARY_CORPUS` names a writable copy of a Go repository whose
/// `go list` works offline (the test appends a comment to a file when
/// `BIFROST_UNIT_SUMMARY_EDIT` names one). Run it with `BIFROST_TIMING=1 --no-capture`:
/// each reconcile prints its `UnitSummaryReconciliation` (units derived, rows,
/// statements, writer hold times), and the test prints the table row counts.
/// Build and activation use `CuratedPackEvidence`, which publishes the same tool
/// context as `FullProduction` without preparing dependency packs.
#[test]
#[ignore = "operator measurement: needs BIFROST_UNIT_SUMMARY_CORPUS, a writable copy of a Go repository"]
fn measure_go_unit_summary_reconcile_on_a_corpus() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    let root = std::path::PathBuf::from(
        std::env::var("BIFROST_UNIT_SUMMARY_CORPUS")
            .expect("BIFROST_UNIT_SUMMARY_CORPUS names a Go repository copy"),
    )
    .canonicalize()
    .unwrap();
    let mut config = go_full_production_config();
    config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
    let project: Arc<dyn crate::analyzer::Project> = Arc::new(crate::analyzer::TestProject::new(
        root.clone(),
        Language::Go,
    ));
    let started = Instant::now();
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config.clone())
            .expect("build the corpus workspace");
    eprintln!("MEASURE build {:?}", started.elapsed());
    let store = workspace.store().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    *store.crate_statement_counter.lock().unwrap() = Some(counter.clone());

    // `BIFROST_UNIT_SUMMARY_PROFILE=inventory` measures the production default:
    // the source-inventory context the build already published and reconciled.
    // Its first pass ran before the counter existed, so the pass is withdrawn and
    // derived again through an unchanged update of `BIFROST_UNIT_SUMMARY_EDIT`.
    let inventory = std::env::var("BIFROST_UNIT_SUMMARY_PROFILE").as_deref() == Ok("inventory");
    let touched = std::env::var("BIFROST_UNIT_SUMMARY_EDIT")
        .ok()
        .map(|edit| crate::analyzer::ProjectFile::new(root.clone(), edit));
    let reconcile_again = |workspace: &WorkspaceAnalyzer| -> Option<WorkspaceAnalyzer> {
        if inventory {
            let file = touched
                .clone()
                .expect("inventory mode names a file to touch");
            Some(workspace.update(&std::collections::BTreeSet::from([file])))
        } else {
            activate_go_context_with(workspace, &config);
            None
        }
    };
    let started = Instant::now();
    if inventory {
        store
            .conn
            .execute(|conn| -> crate::analyzer::store::Result<()> {
                conn.execute(unit_summaries_sql::DELETE_LANGUAGE_VERSIONS_SQL, ["go"])?;
                conn.execute(unit_summaries_sql::DELETE_UNBOUND_SUMMARIES_SQL, [])?;
                Ok(())
            })
            .unwrap();
    }
    let _ = reconcile_again(&workspace);
    eprintln!(
        "MEASURE fresh pass ({}) {:?}",
        if inventory {
            "source inventory, derived again"
        } else {
            "tool context, no dependency packs"
        },
        started.elapsed()
    );
    let table_counts = |label: &str| {
        let conn = store.read_conn().unwrap();
        for table in [
            "resolution_unit_summaries",
            "resolution_unit_summary_versions",
            "resolution_unit_summary_members",
            "resolution_unit_summary_dependencies",
            "resolution_unit_summary_reads",
            "resolution_unit_summary_exports",
            "resolution_unit_summary_imports",
            "resolution_unit_summary_gaps",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            eprintln!("MEASURE {label} {table} {count}");
        }
    };
    let dump = |label: &str| {
        let Ok(directory) = std::env::var("BIFROST_UNIT_SUMMARY_DUMP") else {
            return;
        };
        let conn = store.read_conn().unwrap();
        let mut lines = Vec::new();
        let mut statement = conn
            .prepare(
                "SELECT hex(versions.unit_key),
                        (SELECT group_concat(rel_path, ',') FROM
                           (SELECT rel_path FROM resolution_unit_summary_members AS members
                            WHERE members.summary_id = versions.summary_id ORDER BY rel_path)),
                        hex(summaries.summary_digest), hex(summaries.output_digest), summaries.complete,
                        (SELECT group_concat(hex(dependency_unit_key) || '=' || hex(consumed_output_digest) || '=' || boundary, ' ')
                         FROM (SELECT * FROM resolution_unit_summary_dependencies AS deps
                               WHERE deps.summary_id = versions.summary_id ORDER BY dependency_ordinal)),
                        (SELECT group_concat(gap_kind || ':' || subject || ':' || json(detail), ' | ')
                         FROM (SELECT * FROM resolution_unit_summary_gaps AS gaps
                               WHERE gaps.summary_id = versions.summary_id ORDER BY gap_kind, subject)),
                        (SELECT group_concat(hex(key_digest) || '=' || hex(digest), ' ')
                         FROM (SELECT * FROM resolution_unit_summary_reads AS reads
                               WHERE reads.summary_id = versions.summary_id ORDER BY read_ordinal))
                 FROM resolution_unit_summary_versions AS versions
                 JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
                 WHERE versions.lang = 'go' AND versions.valid_until IS NULL
                 ORDER BY 2, 1",
            )
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let columns: Vec<String> = (0..8)
                .map(|index| {
                    row.get::<_, Option<rusqlite::types::Value>>(index)
                        .unwrap()
                        .map_or_else(String::new, |value| match value {
                            rusqlite::types::Value::Integer(value) => value.to_string(),
                            rusqlite::types::Value::Text(value) => value,
                            other => format!("{other:?}"),
                        })
                })
                .collect();
            lines.push(columns.join("\t"));
        }
        std::fs::write(
            std::path::Path::new(&directory).join(format!("units-{label}.tsv")),
            lines.join("\n"),
        )
        .unwrap();
    };
    if std::env::var_os("BIFROST_UNIT_SUMMARY_DIFFERENTIAL").is_some() {
        // The differential on a real repository store: the summaries against the
        // incumbent readers, for every unit of the corpus.
        let started = Instant::now();
        let counts = assert_summaries_match_incumbent_readers(&workspace);
        eprintln!(
            "MEASURE differential equal in {:?}: units {} members {} exports {} imports {} blank {} dot {} unresolved {}",
            started.elapsed(),
            counts.units,
            counts.members,
            counts.exports,
            counts.imports,
            counts.blank_imports,
            counts.dot_imports,
            counts.unresolved_imports
        );
    }
    dump("fresh");
    table_counts("fresh");

    let started = Instant::now();
    let _ = reconcile_again(&workspace);
    eprintln!(
        "MEASURE pass again, nothing changed {:?}",
        started.elapsed()
    );
    dump("again");

    if let Ok(edit) = std::env::var("BIFROST_UNIT_SUMMARY_EDIT") {
        let path = root.join(&edit);
        let mut source = std::fs::read_to_string(&path).unwrap();
        source.push_str("\n// unit summary measurement edit\n");
        std::fs::write(&path, source).unwrap();
        let file = crate::analyzer::ProjectFile::new(root.clone(), edit);
        let started = Instant::now();
        let updated = workspace.update(&std::collections::BTreeSet::from([file]));
        eprintln!("MEASURE update after the edit {:?}", started.elapsed());
        let started = Instant::now();
        if !inventory {
            activate_go_context_with(&updated, &config);
        }
        eprintln!("MEASURE pass after the edit {:?}", started.elapsed());
        table_counts("edited");
    }
}

/// Blob replacement. Persisting a blob that already exists deletes its row and
/// inserts a new one, and the unit summary rows that reference the old row
/// cascade away. The persist path withdraws the version rows of every summary
/// that listed the blob in the same transaction, so a reader finds no live
/// summary for the unit (it falls back) instead of a complete summary whose rows
/// are gone. The next reconcile rebuilds the header in place and rebinds the
/// unit, and the rebuilt rows equal the incumbent readers' again.
#[test]
fn a_replaced_blob_withdraws_its_summaries_until_the_next_reconcile() {
    let Some((fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
        return;
    };
    let before = open_units(&workspace);
    let store = workspace.store().unwrap();
    let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
    let generation = go.selected_snapshot_for_test().unwrap().generation;
    let source = GO_FIXTURE
        .iter()
        .find(|(path, _)| *path == "util/util.go")
        .unwrap()
        .1;
    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
    let (state, _) = super::tests::parsed_go_state(fixture.root(), "util/util.go", source);
    let prepared =
        AnalyzerStore::prepare_parsed_blob(oid, "go", generation, &GoAdapter, state).unwrap();
    let (outcomes, _) =
        store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert!(
        outcomes.iter().all(|outcome| outcome.error.is_none()),
        "{:#?}",
        outcomes
            .iter()
            .map(|outcome| &outcome.error)
            .collect::<Vec<_>>()
    );

    let hollow = open_units(&workspace);
    let missing: Vec<&String> = before
        .keys()
        .filter(|label| !hollow.contains_key(*label))
        .collect();
    assert_eq!(
        missing,
        ["util/util.go"],
        "exactly the units that listed the replaced blob lose their live summary"
    );
    for (label, unit) in &hollow {
        assert_eq!(
            &before[label], unit,
            "{label}: unrelated units are untouched"
        );
    }

    activate_go_context(&workspace);
    let rebuilt = open_units(&workspace);
    assert_eq!(
        rebuilt.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        rebuilt["util/util.go"].summary_id, before["util/util.go"].summary_id,
        "the header with the same digest is rebuilt in place"
    );
    assert_eq!(
        rebuilt["util/util.go"].output_digest,
        before["util/util.go"].output_digest
    );
    for (label, unit) in &before {
        if label != "util/util.go" {
            assert_eq!(
                unit, &rebuilt[label],
                "{label}: dependents are not derived again"
            );
        }
    }
    assert_summaries_match_incumbent_readers(&workspace);
}

/// The comparison point for the writer hold: build a Rust workspace and let the
/// existing crate reconcile run. Run it with `BIFROST_TIMING=1 --no-capture` and
/// read the `rust_crates.reconcile.*` scopes. `BIFROST_UNIT_SUMMARY_RUST_CORPUS`
/// names a Rust repository copy.
#[test]
#[ignore = "operator measurement: needs BIFROST_UNIT_SUMMARY_RUST_CORPUS, a Rust repository"]
fn measure_rust_crate_reconcile_on_a_corpus() {
    let root = std::path::PathBuf::from(
        std::env::var("BIFROST_UNIT_SUMMARY_RUST_CORPUS")
            .expect("BIFROST_UNIT_SUMMARY_RUST_CORPUS names a Rust repository"),
    )
    .canonicalize()
    .unwrap();
    let project: std::sync::Arc<dyn crate::analyzer::Project> =
        std::sync::Arc::new(crate::analyzer::TestProject::new(root, Language::Rust));
    let started = std::time::Instant::now();
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("build the Rust corpus workspace");
    eprintln!("MEASURE rust build {:?}", started.elapsed());
    let conn = workspace.store().unwrap().read_conn().unwrap();
    for table in [
        "rust_crate_topologies",
        "rust_crate_versions",
        "rust_crate_exports",
        "rust_crate_imports",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        eprintln!("MEASURE rust {table} {count}");
    }
}

/// The production default context: no Go tool, so the publication is the source
/// inventory, whose test and external-test files sit in the plain instance. The
/// summaries must equal the incumbent readers there too, and a body edit must
/// derive exactly the unit that lists the file.
#[test]
fn source_inventory_unit_summaries_equal_the_incumbent_readers_and_cut_off() {
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in GO_FIXTURE {
        project = project.file(*path, *source);
    }
    let fixture = project.build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let counts = assert_summaries_match_incumbent_readers(&workspace);
    // plain units: api, util, other, blank, cmd; test unit and external-test unit of api.
    assert_eq!(counts.units, 7, "{counts:?}");
    assert!(
        counts.dot_imports >= 1 && counts.blank_imports >= 1,
        "{counts:?}"
    );
    // The standard library is not a package of this publication.
    assert!(counts.unresolved_imports >= 1, "{counts:?}");
    assert!(
        counts
            .dependency_keys
            .contains(&hex(&go_unit_key("example.test/native/other", "", "go"))),
        "{counts:?}"
    );

    let initial = open_units(&workspace);
    let util_source = GO_FIXTURE
        .iter()
        .find(|(path, _)| *path == "util/util.go")
        .unwrap()
        .1;
    let edited = util_source.replace(
        "func private() int { return 1 }",
        "func private() int { return 2 }",
    );
    std::fs::write(fixture.root().join("util/util.go"), &edited).unwrap();
    let file = fixture.file("util/util.go");
    let updated = workspace.update(&std::collections::BTreeSet::from([file]));
    let after = open_units(&updated);
    assert_eq!(
        units_with_a_new_summary(&initial, &after),
        ["util/util.go".to_owned()].into()
    );
    assert_eq!(
        initial["util/util.go"].output_digest,
        after["util/util.go"].output_digest
    );
    assert_summaries_match_incumbent_readers(&updated);

    // An added workspace import is not caller-visible: no importer is derived.
    let with_import = edited.replacen(
        "package util\n",
        "package util\n\nimport _ \"example.test/native/other\"\n",
        1,
    );
    std::fs::write(fixture.root().join("util/util.go"), &with_import).unwrap();
    let file = fixture.file("util/util.go");
    let again = updated.update(&std::collections::BTreeSet::from([file]));
    let imported = open_units(&again);
    assert_eq!(
        units_with_a_new_summary(&after, &imported),
        ["util/util.go".to_owned()].into()
    );
    assert_eq!(
        after["util/util.go"].output_digest,
        imported["util/util.go"].output_digest
    );
}

/// How many live summaries record `profile` as the context profile they derive
/// from, in their read ledger.
fn live_summaries_of_profile(workspace: &WorkspaceAnalyzer, profile: [u8; 32]) -> usize {
    let conn = workspace.store().unwrap().read_conn().unwrap();
    conn.query_row(
        "SELECT count(*) FROM resolution_unit_summary_versions AS versions
         WHERE versions.lang = 'go' AND versions.valid_until IS NULL
           AND EXISTS (SELECT 1 FROM resolution_unit_summary_reads AS reads
                       WHERE reads.summary_id = versions.summary_id
                         AND reads.kind = 'context_publication' AND reads.digest = ?1)",
        [profile.as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn a_summary_records_the_profile_of_the_publication_it_derives_from() {
    use crate::analyzer::store::go_package_context::source_inventory_profile;
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in GO_FIXTURE {
        project = project.file(*path, *source);
    }
    let fixture = project.build();
    let workspace = fixture.workspace_analyzer(go_full_production_config());
    let inventory = source_inventory_profile();
    let before = open_units(&workspace).len();
    assert_eq!(live_summaries_of_profile(&workspace, inventory), before);
    {
        // The Go validity predicate matches the selected profile: the live
        // summary of the inventory profile is not live for another one.
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
        let snapshot = go.selected_snapshot_for_test().unwrap();
        let epoch: String = conn
            .query_row(
                "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let key = go_unit_key("example.test/native/util", "", "go");
        assert!(
            go_live_summary(&conn, &snapshot, &epoch, &key, &inventory)
                .unwrap()
                .is_some()
        );
        assert!(
            go_live_summary(&conn, &snapshot, &epoch, &key, &[9; 32])
                .unwrap()
                .is_none()
        );
    }
    if std::process::Command::new("go")
        .arg("version")
        .output()
        .is_err()
    {
        return;
    }
    // The tool context replaces the inventory summaries: one live summary per
    // unit key, and each records the profile its publication came from.
    activate_go_context(&workspace);
    assert_eq!(open_units(&workspace).len(), 7);
    // A unit key that both profiles define is rebound to the tool summary; the
    // inventory-only keys (its test units) are closed.
    assert_eq!(live_summaries_of_profile(&workspace, inventory), 0);
}
