//! Revision-selected Go tool output. Canonical discovery is request-owned;
//! reusable package membership and provider relationships live in SQLite.

use std::collections::BTreeSet;
use std::path::Path;

use git2::{ObjectType, Oid};
use rusqlite::{OptionalExtension, params};

use super::{AnalyzerStore, Result, WorkspaceConfigurationInput, WorkspaceSnapshotId};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::go::dependency_discovery::GoPackageDiscovery;
use crate::analyzer::{Language, Project};
use brokk_bifrost_core::analyzer::go_facts::GO_BUILD_SELECTION_FACTS_VERSION;

pub(crate) const DERIVATION_VERSION: i64 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoContextIdentity {
    pub selection_id: i64,
    pub context_id: i64,
    pub publication_digest: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum GoContextHeadStatus {
    Current,
    Withdrawn,
    Cancelled,
}

#[derive(Debug)]
pub(crate) enum GoInputObservationOutcome {
    Ready(GoInputObservation),
    InputsChanged,
    Cancelled,
}

/// Fixed-size observation, held only through one discovery invocation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GoInputObservation {
    digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) enum GoContextPublicationOutcome {
    Published(GoContextIdentity),
    InputsChanged,
    Cancelled,
}

pub(crate) const RECHECK_CONTEXT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM go_context_heads h
             JOIN go_context_publications p ON p.context_id=h.context_id
             WHERE h.selection_id=?1 AND h.context_id=?2 AND p.publication_digest=?3)";

pub(crate) const OBSERVE_INPUTS_SQL: &str =
    "SELECT input_kind, rel_path, blob_oid FROM workspace_file_versions
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2
               AND valid_from <= ?3 AND (valid_until IS NULL OR ?3 < valid_until)
             ORDER BY input_kind, rel_path";

pub(crate) const PRIOR_HEADS_SQL: &str =
    "SELECT s.profile_digest,s.selection_id,p.context_id,p.publication_digest
     FROM go_context_selections s JOIN go_context_heads h USING(selection_id)
     JOIN go_context_publications p ON p.context_id=h.context_id
     WHERE s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
       AND s.revision=?3 AND s.derivation_version=?4";

pub(crate) const CANONICAL_SOURCE_SQL: &str = "SELECT f.file_version_id,f.blob_oid,m.content_package,manifest.publication_state,manifest.facts_version
                             FROM workspace_file_versions f
                             LEFT JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
                             LEFT JOIN blob_meta m ON m.blob_id=b.id
                             LEFT JOIN source_fact_manifests manifest ON manifest.blob_id=b.id
                             WHERE f.workspace_id=?1 AND f.lang='go' AND f.generation=?2 AND f.input_kind='source'
                               AND f.rel_path=?3 AND f.valid_from<=?4 AND (f.valid_until IS NULL OR ?4<f.valid_until)";

pub(crate) const SELECT_CONTEXT_SQL: &str =
    "SELECT s.selection_id, p.context_id, p.publication_digest
     FROM go_context_selections s
     JOIN go_context_heads h USING(selection_id)
     JOIN go_context_publications p ON p.context_id = h.context_id
     WHERE s.workspace_id = ?1 AND s.lang = 'go' AND s.generation = ?2
       AND s.revision = ?3 AND s.profile_digest = ?4 AND s.derivation_version = ?5";

pub(crate) fn profile_digest(discovery: &GoPackageDiscovery) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-go-context-profile:v1");
    for (key, value) in [
        ("goos", discovery.goos.as_str()),
        ("goarch", discovery.goarch.as_str()),
        ("goversion", discovery.environment.goversion.as_str()),
        ("gowork", discovery.environment.gowork.as_str()),
    ] {
        hash.field(key, value.as_bytes());
    }
    for (key, value) in [
        ("goroot", &discovery.environment.goroot),
        ("gopath", &discovery.environment.gopath),
        ("gomodcache", &discovery.environment.gomodcache),
    ] {
        hash.field(key, value.as_os_str().as_encoded_bytes());
    }
    hash.field("vendor", &[u8::from(discovery.vendor)]);
    hash.field("cgo", &[0]);
    hash.field("tests", &[1]);
    for tag in &discovery.build_tags {
        hash.field("tag", tag.as_bytes());
    }
    for pattern in &discovery.workspace_patterns {
        hash.field("pattern", pattern.as_bytes());
    }
    hash.finish()
}

fn import_mappings<'a>(
    package: &'a crate::analyzer::go::dependency_discovery::GoPackage,
    imports: &'a [String],
) -> std::collections::BTreeMap<&'a str, &'a str> {
    let mut mappings = std::collections::BTreeMap::new();
    for imported in imports {
        if let Some(target) = package.import_map.get(imported) {
            mappings.insert(imported.as_str(), target.as_str());
            continue;
        }
        let mut mapped = false;
        for (spelling, target) in &package.import_map {
            if target == imported {
                mappings.insert(spelling.as_str(), target.as_str());
                mapped = true;
            }
        }
        if !mapped {
            mappings.insert(imported.as_str(), imported.as_str());
        }
    }
    mappings
}

impl AnalyzerStore {
    /// Recheck through a newly checked-out store reader, not the operation's
    /// retained inventory transaction. Old revision contexts remain readable;
    /// only replacement of that selection's context head withdraws authority.
    pub(crate) fn go_context_head_status(
        &self,
        identity: &GoContextIdentity,
        cancellation: &CancellationToken,
    ) -> Result<GoContextHeadStatus> {
        if cancellation.is_cancelled() {
            return Ok(GoContextHeadStatus::Cancelled);
        }
        let conn = self.read_conn()?;
        let current: bool = conn.query_row(
            RECHECK_CONTEXT_SQL,
            params![
                identity.selection_id,
                identity.context_id,
                identity.publication_digest
            ],
            |row| row.get(0),
        )?;
        Ok(if cancellation.is_cancelled() {
            GoContextHeadStatus::Cancelled
        } else if current {
            GoContextHeadStatus::Current
        } else {
            GoContextHeadStatus::Withdrawn
        })
    }

    /// Observe the disk input domain against the exact selected revision.
    /// Fresh inventory and byte/stat checks detect ordinary concurrent edits;
    /// this is an optimistic check, not an atomic filesystem snapshot.
    pub(crate) fn observe_go_context_inputs(
        &self,
        snapshot: &WorkspaceSnapshotId,
        project: &dyn Project,
        cancellation: &CancellationToken,
    ) -> Result<GoInputObservationOutcome> {
        assert_eq!(snapshot.lang, "go");
        if cancellation.is_cancelled() {
            return Ok(GoInputObservationOutcome::Cancelled);
        }
        project.invalidate_cached_file_listing();
        let files = project.all_files_shared()?;
        let mut configuration = files
            .iter()
            .filter(|file| {
                WorkspaceConfigurationInput::is_native_input(Language::Go, file.rel_path())
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        WorkspaceConfigurationInput::include_native_metadata_paths(
            project.root(),
            Language::Go,
            &mut configuration,
        )?;
        let mut inventory = project
            .analyzable_files_from(files.as_ref(), Language::Go)?
            .iter()
            .map(|file| {
                (
                    "source".to_owned(),
                    crate::path_utils::rel_path_string(file),
                )
            })
            .collect::<BTreeSet<_>>();
        inventory.extend(configuration.iter().map(|file| {
            (
                "configuration".to_owned(),
                crate::path_utils::rel_path_string(file),
            )
        }));
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(OBSERVE_INPUTS_SQL)?;
        let mut rows = statement.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ])?;
        let mut hash = CanonicalHasher::new(b"bifrost-go-observed-inputs:v1");
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoInputObservationOutcome::Cancelled);
            }
            let kind: String = row.get(0)?;
            let path: String = row.get(1)?;
            let oid: String = row.get(2)?;
            if !inventory.remove(&(kind.clone(), path.clone())) {
                return Ok(GoInputObservationOutcome::InputsChanged);
            }
            let absolute = project.root().join(&path);
            let bytes = match std::fs::read(&absolute) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(GoInputObservationOutcome::InputsChanged);
                }
                Err(error) => return Err(error.into()),
            };
            if Oid::hash_object(ObjectType::Blob, &bytes)?.to_string() != oid {
                return Ok(GoInputObservationOutcome::InputsChanged);
            }
            let metadata = std::fs::metadata(&absolute)?;
            hash.field("kind", kind.as_bytes());
            hash.field("path", path.as_bytes());
            hash.field("oid", oid.as_bytes());
            hash.field("modified", format!("{:?}", metadata.modified()?).as_bytes());
            hash.field("length", &metadata.len().to_le_bytes());
        }
        if !inventory.is_empty() {
            return Ok(GoInputObservationOutcome::InputsChanged);
        }
        if cancellation.is_cancelled() {
            return Ok(GoInputObservationOutcome::Cancelled);
        }
        Ok(GoInputObservationOutcome::Ready(GoInputObservation {
            digest: hash.finish(),
        }))
    }

    /// Bind/recheck immutable publication identity for one selected profile.
    pub(crate) fn selected_go_context(
        &self,
        snapshot: &WorkspaceSnapshotId,
        profile: &[u8; 32],
    ) -> Result<Option<GoContextIdentity>> {
        let conn = self.read_conn()?;
        Ok(conn
            .query_row(
                SELECT_CONTEXT_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                    profile,
                    DERIVATION_VERSION
                ],
                |row| {
                    Ok(GoContextIdentity {
                        selection_id: row.get(0)?,
                        context_id: row.get(1)?,
                        publication_digest: row
                            .get::<_, Vec<u8>>(2)?
                            .try_into()
                            .expect("schema checks publication digest width"),
                    })
                },
            )
            .optional()?)
    }
}

struct PackageRows {
    import_path: String,
    name: String,
    for_test: String,
    directory: std::path::PathBuf,
    provider_kind: &'static str,
    provider_provenance: &'static str,
    provider_module_path: Option<String>,
    provider_module_version: Option<String>,
    provider: [u8; 32],
    gaps: Vec<serde_json::Value>,
    complete: bool,
    files: Vec<(i64, &'static str)>,
    imports: std::collections::BTreeMap<(&'static str, String), Option<String>>,
}

impl AnalyzerStore {
    /// Consume one canonical tool result after matching before/after input
    /// observations. All normalization collections die with this publication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_go_package_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        root: std::path::PathBuf,
        expected_head: Option<GoContextIdentity>,
        before: &GoInputObservation,
        after: &GoInputObservation,
        mut discovery: GoPackageDiscovery,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        use serde_json::json;
        if cancellation.is_cancelled() {
            return Ok(GoContextPublicationOutcome::Cancelled);
        }
        if before != after {
            return Ok(GoContextPublicationOutcome::InputsChanged);
        }
        let profile = profile_digest(&discovery);
        let mut context_gaps = Vec::new();
        let conn = self.read_conn()?;
        let configuration_oid = |path: &Path| -> Result<Option<String>> {
            let Ok(relative) = path.strip_prefix(&root) else {
                return Ok(None);
            };
            let Some(relative) = crate::path_utils::workspace_rel_path(&relative.to_string_lossy())
            else {
                return Ok(None);
            };
            Ok(conn.query_row(
                "SELECT blob_oid FROM workspace_file_versions
                 WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND input_kind='configuration'
                   AND rel_path=?3 AND valid_from<=?4 AND (valid_until IS NULL OR ?4<valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.generation.get(), relative.to_string_lossy().replace('\\', "/"), snapshot.revision],
                |row| row.get(0),
            ).optional()?)
        };
        if !discovery.environment.gowork.is_empty()
            && discovery.environment.gowork != "off"
            && configuration_oid(Path::new(&discovery.environment.gowork))?.is_none()
        {
            context_gaps.push(
                json!({"code":"uncaptured_go_workspace", "evidence":discovery.environment.gowork}),
            );
        }
        discovery
            .packages
            .sort_by(|left, right| left.import_path.cmp(&right.import_path));
        let conflicts = discovery
            .packages
            .windows(2)
            .filter(|pair| pair[0].import_path == pair[1].import_path)
            .map(|pair| pair[0].import_path.clone())
            .collect::<BTreeSet<_>>();
        let mut normalized = Vec::new();
        let mut publication = CanonicalHasher::new(b"bifrost-go-context-publication:v1");
        publication.field("profile", &profile);
        publication.field("inputs", &before.digest);
        for package in discovery.packages {
            if cancellation.is_cancelled() {
                return Ok(GoContextPublicationOutcome::Cancelled);
            }
            if package.import_path.is_empty() || conflicts.contains(&package.import_path) {
                context_gaps.push(
                    json!({"code":"conflicting_package_identity", "evidence":package.import_path}),
                );
                continue;
            }
            let provider_kind = if package.standard {
                "standard"
            } else if package.module.as_ref().is_some_and(|module| !module.main) {
                "module"
            } else {
                "workspace"
            };
            let source_less_provider = provider_kind != "workspace";
            let provider_module_path = package.module.as_ref().map(|module| module.path.clone());
            let provider_module_version =
                package.module.as_ref().map(|module| module.version.clone());
            let mut gaps = Vec::new();
            if !source_less_provider && !package.cgo_files.is_empty() {
                gaps.push(
                    json!({"code":"cgo_build_selection_unavailable", "evidence":package.cgo_files}),
                );
            }
            if let Some(error) = &package.error {
                gaps.push(json!({"code":"tool_package_error", "evidence":{"error":error.err,"position":error.pos,"import_stack":error.import_stack}}));
            }
            for error in &package.deps_errors {
                gaps.push(json!({"code":"tool_dependency_error", "evidence":{"error":error.err,"position":error.pos,"import_stack":error.import_stack}}));
            }
            if package.incomplete {
                gaps.push(json!({"code":"tool_incomplete", "evidence":package.import_path}));
            }
            if package.name.is_empty() {
                gaps.push(json!({"code":"missing_package_name", "evidence":package.import_path}));
            }
            let mut provider = CanonicalHasher::new(b"bifrost-go-provider:v1");
            provider.field("directory", package.dir.as_os_str().as_encoded_bytes());
            provider.field("standard", &[u8::from(package.standard)]);
            let mut module = package.module.as_ref();
            while let Some(current) = module {
                provider.field("module", current.path.as_bytes());
                provider.field("version", current.version.as_bytes());
                provider.field("sum", current.sum.as_bytes());
                provider.field("directory", current.dir.as_os_str().as_encoded_bytes());
                provider.field("main", &[u8::from(current.main)]);
                if !source_less_provider && !current.go_mod.as_os_str().is_empty() {
                    match configuration_oid(&current.go_mod)? {
                        Some(oid) => provider.field("manifest", oid.as_bytes()),
                        None => gaps.push(json!({"code":"uncaptured_provider_configuration", "evidence":current.go_mod})),
                    }
                }
                module = current.replace.as_deref();
            }
            let provider = provider.finish();
            let mut members = Vec::new();
            // GoFiles/CgoFiles are the files compiled for this exact tool
            // instance. TestGoFiles/XTestGoFiles alone describe possible tests;
            // they do not select an internal or external test variant.
            let selected_paths = if source_less_provider {
                BTreeSet::new()
            } else {
                package
                    .go_files
                    .iter()
                    .chain(&package.cgo_files)
                    .collect::<BTreeSet<_>>()
            };
            for path in selected_paths {
                let absolute = package.dir.join(path);
                let relative = absolute.strip_prefix(&root).ok().and_then(|path| {
                    crate::path_utils::workspace_rel_path(&path.to_string_lossy())
                });
                let member = if let Some(relative) = &relative {
                    conn.query_row(
                        CANONICAL_SOURCE_SQL,
                        params![
                            snapshot.workspace_id.as_str(),
                            snapshot.generation.get(),
                            relative.to_string_lossy().replace('\\', "/"),
                            snapshot.revision
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, Option<i64>>(4)?,
                            ))
                        },
                    )
                    .optional()?
                } else {
                    None
                };
                let Some((id, oid, declared, state, version)) = member else {
                    gaps.push(
                        json!({"code":"unselected_source_input", "evidence":{"path":absolute}}),
                    );
                    continue;
                };
                if declared.as_deref() != Some(package.name.as_str())
                    || state.as_deref() != Some("complete")
                    || version != Some(super::source_facts::SOURCE_FACTS_VERSION)
                {
                    gaps.push(json!({"code":"package_source_identity_mismatch", "evidence":{"path":absolute,"declared":declared,"tool_name":package.name,"source_state":state,"source_version":version}}));
                    continue;
                }
                let file = crate::analyzer::ProjectFile::new(
                    root.clone(),
                    relative.expect("selected source has a workspace-relative path"),
                );
                let role = brokk_bifrost_go::packages::source_inventory_role(&file, &package.name);
                if role != "go" && package.for_test.is_empty() {
                    gaps.push(json!({"code":"test_variant_unselected", "evidence":{"path":absolute,"role":role,"package":package.import_path}}));
                    continue;
                }
                members.push((id, role));
                publication.field("source-role", role.as_bytes());
                publication.field("source-path", absolute.as_os_str().as_encoded_bytes());
                publication.field("source-oid", oid.as_bytes());
            }
            if members.is_empty() && !source_less_provider {
                gaps.push(json!({"code":"missing_selected_package_source", "evidence":package.import_path}));
            }
            let complete = gaps.is_empty() && context_gaps.is_empty();
            let gaps_json = serde_json::to_string(&gaps).expect("Go gap evidence is JSON");
            publication.field("package", package.import_path.as_bytes());
            publication.field("name", package.name.as_bytes());
            publication.field("for-test", package.for_test.as_bytes());
            publication.field("provider-kind", provider_kind.as_bytes());
            publication.field("provider-provenance", b"go_tool");
            if let Some(module_path) = &provider_module_path {
                publication.field("provider-module-path", module_path.as_bytes());
            }
            if let Some(module_version) = &provider_module_version {
                publication.field("provider-module-version", module_version.as_bytes());
            }
            publication.field("provider", &provider);
            publication.field("gaps", gaps_json.as_bytes());
            let admitted_roles = members
                .iter()
                .map(|(_, role)| *role)
                .collect::<BTreeSet<_>>();
            for role in &admitted_roles {
                for import in package.imports.iter().collect::<BTreeSet<_>>() {
                    publication.field("import-role", role.as_bytes());
                    publication.field("import", import.as_bytes());
                }
            }
            for (spelling, target) in &package.import_map {
                publication.field("spelling", spelling.as_bytes());
                publication.field("target", target.as_bytes());
            }
            let imports = admitted_roles
                .into_iter()
                .flat_map(|role| {
                    import_mappings(&package, &package.imports).into_iter().map(
                        move |(spelling, target)| {
                            ((role, spelling.to_owned()), Some(target.to_owned()))
                        },
                    )
                })
                .collect();
            normalized.push(PackageRows {
                import_path: package.import_path,
                name: package.name,
                for_test: package.for_test,
                directory: package.dir,
                provider_kind,
                provider_provenance: "go_tool",
                provider_module_path,
                provider_module_version,
                provider,
                gaps,
                complete,
                files: members,
                imports,
            });
        }
        let context_complete = {
            let providers = normalized
                .iter()
                .map(|row| (row.import_path.as_str(), row.complete))
                .collect::<crate::hash::HashMap<_, _>>();
            context_gaps.is_empty()
                && normalized.iter().all(|row| {
                    row.complete
                        && row.imports.values().all(|target| {
                            target
                                .as_deref()
                                .and_then(|target| providers.get(target))
                                .copied()
                                == Some(true)
                        })
                })
        };
        let context_gaps = serde_json::to_string(&context_gaps).expect("Go gap evidence is JSON");
        publication.field("context-gaps", context_gaps.as_bytes());
        let digest = publication.finish();
        drop(conn);
        self.publish_normalized_go_context(
            snapshot,
            profile,
            expected_head,
            normalized,
            digest,
            context_complete,
            context_gaps,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_normalized_go_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        profile: [u8; 32],
        expected_head: Option<GoContextIdentity>,
        normalized: Vec<PackageRows>,
        digest: [u8; 32],
        context_complete: bool,
        context_gaps: String,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        use serde_json::json;
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| -> Result<_> {
            let tx = conn.transaction()?;
            super::require_current_generation(&tx, "go", snapshot.generation)?;
            let revision: Option<i64> = tx.query_row(
                "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go' AND generation=?2",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get()], |row|row.get(0),
            ).optional()?;
            if revision != Some(snapshot.revision) { return Ok(GoContextPublicationOutcome::InputsChanged); }
            let current: Option<i64> = tx.query_row(SELECT_CONTEXT_SQL,
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,profile,DERIVATION_VERSION],|row|row.get(1),
            ).optional()?;
            if current != expected_head.as_ref().map(|head|head.context_id) { return Ok(GoContextPublicationOutcome::InputsChanged); }
            if cancellation.is_cancelled() { return Ok(GoContextPublicationOutcome::Cancelled); }
            tx.execute("INSERT OR IGNORE INTO go_context_selections(workspace_id,lang,generation,revision,profile_digest,derivation_version) VALUES(?1,'go',?2,?3,?4,?5)",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,profile,DERIVATION_VERSION])?;
            let selection_id: i64 = tx.query_row("SELECT selection_id FROM go_context_selections WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND revision=?3 AND profile_digest=?4 AND derivation_version=?5",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,profile,DERIVATION_VERSION],|row|row.get(0))?;
            let inserted = tx.execute("INSERT OR IGNORE INTO go_context_publications(selection_id,publication_digest,complete,gaps) VALUES(?1,?2,?3,jsonb(?4))",params![selection_id,digest,context_complete,context_gaps])?;
            let context_id: i64 = tx.query_row("SELECT context_id FROM go_context_publications WHERE selection_id=?1 AND publication_digest=?2",params![selection_id,digest],|row|row.get(0))?;
            if inserted != 0 {
                for row in &normalized {
                    if cancellation.is_cancelled() { return Ok(GoContextPublicationOutcome::Cancelled); }
                    let gaps = serde_json::to_string(&row.gaps).expect("Go package gap evidence is JSON");
                    tx.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,provider_kind,provider_module_path,provider_module_version,provider_provenance) VALUES(?1,?2,?3,?4,?5,?6,?7,jsonb(?8),?9,?10,?11,?12)",
                        params![context_id,row.import_path,row.name,row.for_test,row.directory.to_string_lossy(),row.provider,row.complete,gaps,row.provider_kind,row.provider_module_path,row.provider_module_version,row.provider_provenance])?;
                    let package_id = tx.last_insert_rowid();
                    for (file,role) in &row.files { tx.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role) VALUES(?1,?2,?3)",params![package_id,file,role])?; }
                }
                for row in &normalized {
                    let importer: i64 = tx.query_row("SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path=?2",params![context_id,row.import_path],|value|value.get(0))?;
                    for ((role,spelling),target) in &row.imports {
                            if cancellation.is_cancelled() { return Ok(GoContextPublicationOutcome::Cancelled); }
                            let target: Option<(i64,bool)> = tx.query_row("SELECT package_id,complete FROM go_package_instances WHERE context_id=?1 AND tool_import_path=?2",params![context_id,target],|value|Ok((value.get(0)?,value.get(1)?))).optional()?;
                            let complete = row.complete && target.is_some_and(|(_,complete)|complete);
                            let gaps = if complete { "[]".to_owned() } else { serde_json::to_string(&json!([{"code":"incomplete_import_provider","evidence":spelling}])).expect("Go gap evidence is JSON") };
                            tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7))",params![context_id,importer,spelling,role,target.map(|(id,_)|id),complete,gaps])?;
                    }
                }
            }
            if cancellation.is_cancelled() { return Ok(GoContextPublicationOutcome::Cancelled); }
            tx.execute("INSERT INTO go_context_heads(selection_id,context_id) VALUES(?1,?2) ON CONFLICT(selection_id) DO UPDATE SET context_id=excluded.context_id",params![selection_id,context_id])?;
            tx.commit()?;
            Ok(GoContextPublicationOutcome::Published(GoContextIdentity { selection_id,context_id,publication_digest:digest }))
        })
    }
}

pub(crate) fn source_inventory_profile() -> [u8; 32] {
    CanonicalHasher::new(b"bifrost-go-source-inventory-profile:v2").finish()
}

pub(crate) const SOURCE_INVENTORY_SQL: &str =
    "SELECT f.file_version_id,f.rel_path,f.blob_oid,a.package_name,b.id,m.content_package,
            manifest.publication_state,manifest.facts_version,m.is_complete,
            COALESCE(go_manifest.has_build_constraints,0),
            COALESCE(go_manifest.build_selection_facts_version,0)
     FROM workspace_file_versions f
     LEFT JOIN workspace_file_anchor_rows a ON a.file_version_id=f.file_version_id
       AND a.anchor_kind='own_module' AND a.anchor_pop=0
     LEFT JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation
     LEFT JOIN blob_meta m ON m.blob_id=b.id
     LEFT JOIN source_fact_manifests manifest ON manifest.blob_id=b.id
     LEFT JOIN source_go_manifests go_manifest ON go_manifest.blob_id=b.id
     WHERE f.workspace_id=?1 AND f.lang='go' AND f.generation=?2 AND f.input_kind='source'
       AND f.valid_from<=?3 AND (f.valid_until IS NULL OR ?3<f.valid_until)
     ORDER BY f.rel_path";

impl AnalyzerStore {
    /// Derive partial local evidence only from the selected immutable source
    /// publication. This service never reads live source or invokes the tool.
    pub(crate) fn publish_go_source_context(
        &self,
        snapshot: WorkspaceSnapshotId,
        root: &Path,
        cancellation: &CancellationToken,
    ) -> Result<GoContextPublicationOutcome> {
        use serde_json::json;
        use std::collections::{BTreeMap, BTreeSet};
        if cancellation.is_cancelled() {
            return Ok(GoContextPublicationOutcome::Cancelled);
        }
        let profile = source_inventory_profile();
        let expected = self.selected_go_context(&snapshot, &profile)?;
        let conn = self.read_conn()?;
        let mut publication = CanonicalHasher::new(b"bifrost-go-source-inventory-publication:v2");
        publication.field("profile", &profile);
        let mut gaps = vec![json!({"code":"build_selection_unavailable","evidence":
            "Source inventory has no selected platform, build tags, cgo admission, tool test variants or external provider authority"})];
        // Both maps are this derivation query's transient result, never analyzer state.
        let mut packages = BTreeMap::<String, PackageRows>::new();
        let mut names = BTreeMap::<String, BTreeSet<String>>::new();
        let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
        let mut query = conn.prepare_cached(SOURCE_INVENTORY_SQL)?;
        let mut files = query.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ])?;
        while let Some(file) = files.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoContextPublicationOutcome::Cancelled);
            }
            let id: i64 = file.get(0)?;
            let path: String = file.get(1)?;
            let oid: String = file.get(2)?;
            let anchor: Option<String> = file.get(3)?;
            let blob: Option<i64> = file.get(4)?;
            let name: Option<String> = file.get(5)?;
            let state: Option<String> = file.get(6)?;
            let version: Option<i64> = file.get(7)?;
            let complete: Option<bool> = file.get(8)?;
            let has_build_constraints: bool = file.get(9)?;
            let build_selection_facts_version: i64 = file.get(10)?;
            publication.field("path", path.as_bytes());
            publication.field("oid", oid.as_bytes());
            let (Some(anchor), Some(blob), Some(name)) = (anchor, blob, name) else {
                gaps.push(json!({"code":"missing_source_package_authority","evidence":path}));
                continue;
            };
            if state.as_deref() != Some("complete")
                || version != Some(super::source_facts::SOURCE_FACTS_VERSION)
                || complete != Some(true)
                || name.is_empty()
            {
                gaps.push(json!({"code":"unavailable_source_publication","evidence":path}));
                continue;
            }
            let directory = root.join(Path::new(&path).parent().unwrap_or(Path::new("")));
            let source_file = crate::analyzer::ProjectFile::new(
                root.to_path_buf(),
                std::path::PathBuf::from(&path),
            );
            let role = brokk_bifrost_go::packages::source_inventory_role(&source_file, &name);
            let file_has_build_constraints =
                brokk_bifrost_go::packages::source_file_has_build_constraints(
                    &source_file,
                    has_build_constraints,
                );
            publication.field("package", anchor.as_bytes());
            publication.field("name", name.as_bytes());
            publication.field("role", role.as_bytes());
            publication.field("provider-provenance", b"source_inventory");
            names
                .entry(anchor.clone())
                .or_default()
                .insert(name.clone());
            let package = packages.entry(anchor.clone()).or_insert_with(|| {
                let mut provider = CanonicalHasher::new(b"bifrost-go-source-provider:v2");
                provider.field("package", anchor.as_bytes());
                provider.field("provenance", b"source_inventory");
                PackageRows {
                    import_path: anchor.clone(),
                    name,
                    for_test: String::new(),
                    directory,
                    provider_kind: "workspace",
                    provider_provenance: "source_inventory",
                    provider_module_path: None,
                    provider_module_version: None,
                    provider: provider.finish(),
                    gaps: Vec::new(),
                    complete: true,
                    files: Vec::new(),
                    imports: BTreeMap::new(),
                }
            });
            if file_has_build_constraints {
                package.complete = false;
                package.gaps.push(json!({
                    "code":"source_file_build_selection_unavailable",
                    "evidence":{"path":path}
                }));
                publication.field("build-constrained-file", path.as_bytes());
            }
            if build_selection_facts_version != GO_BUILD_SELECTION_FACTS_VERSION {
                package.complete = false;
                package.gaps.push(json!({
                    "code":"source_build_constraint_facts_unavailable",
                    "evidence":{"path":path,"version":build_selection_facts_version}
                }));
                publication.field(
                    "build-selection-facts-version",
                    &build_selection_facts_version.to_le_bytes(),
                );
            }
            package.files.push((id, role));
            let Some(imports) = super::source_facts::read_source_imports(&conn, blob, &|| {
                !cancellation.is_cancelled()
            })?
            else {
                return Ok(GoContextPublicationOutcome::Cancelled);
            };
            for import in imports {
                let Some(import_path) = import.path.filter(|path| !path.segments.is_empty()) else {
                    gaps.push(json!({"code":"unavailable_source_import","evidence":{"path":path,"occurrence":import.declaration.index()}}));
                    continue;
                };
                let spelling = import_path.segments.join("/");
                if spelling == "C" {
                    package.complete = false;
                    package.gaps.push(json!({
                        "code":"source_cgo_build_selection_unavailable",
                        "evidence":{"path":path}
                    }));
                    gaps.push(json!({"code":"source_cgo_build_selection_unavailable","evidence":{"path":path}}));
                    publication.field("cgo-file", path.as_bytes());
                    continue;
                }
                publication.field("import-role", role.as_bytes());
                publication.field("import", spelling.as_bytes());
                package.imports.insert((role, spelling), None);
            }
            let mut alias_query = conn.prepare_cached("SELECT package_name FROM workspace_file_package_rows WHERE file_version_id=?1 ORDER BY package_name")?;
            let alias_rows = alias_query.query_map([id], |row| row.get::<_, String>(0))?;
            for alias in alias_rows {
                let alias = alias?;
                publication.field("alias", alias.as_bytes());
                aliases.entry(alias).or_default().insert(anchor.clone());
            }
            aliases.entry(anchor.clone()).or_default().insert(anchor);
        }
        drop(files);
        drop(query);
        // Configuration bytes were already captured with this revision. Include
        // their OIDs without reading a newer disk selection.
        let mut configuration = conn.prepare_cached("SELECT rel_path,blob_oid FROM workspace_file_versions WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND input_kind='configuration' AND valid_from<=?3 AND (valid_until IS NULL OR ?3<valid_until) ORDER BY rel_path")?;
        let mut rows = configuration.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision
        ])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoContextPublicationOutcome::Cancelled);
            }
            publication.field("configuration-path", row.get::<_, String>(0)?.as_bytes());
            publication.field("configuration-oid", row.get::<_, String>(1)?.as_bytes());
        }
        drop(rows);
        drop(configuration);
        for package in packages.values_mut() {
            let declared = &names[&package.import_path];
            if declared.len() != 1 {
                package.name.clear();
                package.complete = false;
                package.gaps.push(json!({"code":"conflicting_source_package_names","evidence":{"package":package.import_path,"names":declared}}));
                gaps.push(json!({"code":"conflicting_source_package_names","evidence":{"package":package.import_path,"names":declared}}));
            }
            for ((_, spelling), target) in &mut package.imports {
                match aliases.get(spelling) {
                    Some(candidates) if candidates.len()==1 => {
                        let candidate = candidates.first().expect("one source provider");
                        if names[candidate].len()==1 { *target=Some(candidate.clone()); }
                    }
                    candidates => gaps.push(json!({"code":"source_import_provider_unavailable","evidence":{"importer":package.import_path,"spelling":spelling,"candidates":candidates}})),
                }
            }
        }
        let gaps = serde_json::to_string(&gaps).expect("Go source gap evidence is JSON");
        publication.field("gaps", gaps.as_bytes());
        for package in packages.values() {
            publication.field("package-complete", &[u8::from(package.complete)]);
            let package_gaps = serde_json::to_string(&package.gaps)
                .expect("Go source package gap evidence is JSON");
            publication.field("package-gaps", package_gaps.as_bytes());
        }
        let digest = publication.finish();
        drop(conn);
        self.publish_normalized_go_context(
            snapshot,
            profile,
            expected,
            packages.into_values().collect(),
            digest,
            false,
            gaps,
            cancellation,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
    use crate::inline_project::InlineTestProject;
    use serde_json::json;

    struct Fixture {
        project: crate::inline_project::BuiltInlineTestProject,
        workspace: WorkspaceAnalyzer,
        snapshot: WorkspaceSnapshotId,
    }

    impl Fixture {
        fn new() -> Self {
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                .file(
                    "consumer/use.go",
                    "package consumer\nimport . \"example.test/root/provider\"\nvar Use *Item\n",
                )
                .file("provider/item.go", "package provider\ntype Item struct{}\n")
                .build();
            Self::from_project(project)
        }
        fn from_project(project: crate::inline_project::BuiltInlineTestProject) -> Self {
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let id = super::super::WorkspaceId::for_root(project.root());
            let snapshot = conn.query_row("SELECT generation,revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",[id.as_str()],|row|Ok(WorkspaceSnapshotId {
                workspace_id:id.clone(),lang:"go".into(),generation:super::super::GenerationId::from_persisted(row.get(0)?),revision:row.get(1)?,
            })).unwrap();
            drop(conn);
            Self {
                project,
                workspace,
                snapshot,
            }
        }
        fn store(&self) -> &AnalyzerStore {
            self.workspace.store().unwrap()
        }
        fn observe(&self) -> GoInputObservation {
            let GoInputObservationOutcome::Ready(observation) = self
                .store()
                .observe_go_context_inputs(
                    &self.snapshot,
                    self.workspace.analyzer().project(),
                    &CancellationToken::new(),
                )
                .unwrap()
            else {
                panic!("fixture input is selected");
            };
            observation
        }
        fn discovery(&self) -> GoPackageDiscovery {
            let root = self.project.root();
            let module = json!({"Path":"example.test/root","Dir":root,"Main":true,"GoMod":root.join("go.mod")});
            GoPackageDiscovery {
                packages: vec![
                    serde_json::from_value(json!({"ImportPath":"example.test/root/consumer","Name":"consumer","Dir":root.join("consumer"),"Module":module,"GoFiles":["use.go"],"Imports":["example.test/root/provider"]})).unwrap(),
                    serde_json::from_value(json!({"ImportPath":"example.test/root/provider","Name":"provider","Dir":root.join("provider"),"Module":module,"GoFiles":["item.go"]})).unwrap(),
                ],
                environment:serde_json::from_value(json!({"GOROOT":root.join("sdk"),"GOPATH":root.join("gopath"),"GOMODCACHE":root.join("modules"),"GOVERSION":"go1.22.0","GOWORK":"off","GOOS":"linux","GOARCH":"amd64"})).unwrap(),
                goos:"linux".into(),goarch:"amd64".into(),build_tags:Vec::new(),workspace_patterns:vec!["./consumer".into()],vendor:false,
            }
        }
        fn publish(
            &self,
            discovery: GoPackageDiscovery,
            expected: Option<GoContextIdentity>,
        ) -> GoContextIdentity {
            let before = self.observe();
            let after = self.observe();
            let GoContextPublicationOutcome::Published(identity) = self
                .store()
                .publish_go_package_context(
                    self.snapshot.clone(),
                    self.project.root().to_path_buf(),
                    expected,
                    &before,
                    &after,
                    discovery,
                    &CancellationToken::new(),
                )
                .unwrap()
            else {
                panic!("fixture publication must succeed");
            };
            identity
        }
    }

    fn test_variant_fixture() -> Fixture {
        Fixture::from_project(
            InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                .file("consumer/use.go", "package consumer\nvar Value int\n")
                .file(
                    "consumer/use_test.go",
                    "package consumer\nvar Internal int\n",
                )
                .file(
                    "consumer/external_test.go",
                    "package consumer_test\nvar External int\n",
                )
                .file("provider/item.go", "package provider\ntype Item struct{}\n")
                .build(),
        )
    }

    #[test]
    fn go_context_canonical_test_variants_use_compiled_files_and_exact_package_clauses() {
        let fixture = test_variant_fixture();
        let mut discovery = fixture.discovery();
        let base = &mut discovery.packages[0];
        base.test_go_files = vec!["use_test.go".into()];
        base.x_test_go_files = vec!["external_test.go".into()];
        base.test_imports = vec!["not-selected.test/description-only".into()];
        let mut internal = base.clone();
        internal.import_path =
            "example.test/root/consumer [example.test/root/consumer.test]".into();
        internal.for_test = "example.test/root/consumer".into();
        internal.go_files.push("use_test.go".into());
        let mut external = base.clone();
        external.import_path =
            "example.test/root/consumer_test [example.test/root/consumer.test]".into();
        external.name = "consumer_test".into();
        external.for_test = "example.test/root/consumer".into();
        external.go_files = vec!["external_test.go".into()];
        external.imports = vec![internal.import_path.clone()];
        external.import_map.insert(
            "example.test/root/consumer".into(),
            internal.import_path.clone(),
        );
        discovery.packages.extend([internal, external]);
        let identity = fixture.publish(discovery, None);
        let conn = fixture.store().read_conn().unwrap();
        let mut query = conn.prepare("SELECT p.tool_import_path,f.rel_path,f.source_role,p.package_name,p.for_test FROM go_context_source_files f JOIN go_package_instances p USING(package_id) WHERE f.context_id=?1 ORDER BY p.tool_import_path,f.rel_path").unwrap();
        let rows = query
            .query_map([identity.context_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows.len(), 5, "{rows:?}");
        let base = rows
            .iter()
            .filter(|row| row.0 == "example.test/root/consumer")
            .collect::<Vec<_>>();
        assert_eq!(
            base.len(),
            1,
            "incidental test inventories are not package membership: {rows:?}"
        );
        assert_eq!(base[0].1, "consumer/use.go");
        assert_eq!(base[0].2, "go");
        let internal = rows
            .iter()
            .filter(|row| row.0 == "example.test/root/consumer [example.test/root/consumer.test]")
            .collect::<Vec<_>>();
        assert_eq!(
            internal
                .iter()
                .map(|row| row.2.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["go", "test"])
        );
        let external = rows.iter().find(|row| row.2 == "xtest").unwrap();
        assert_eq!(external.3, "consumer_test");
        assert_eq!(external.4, "example.test/root/consumer");
        assert!(external.0.starts_with("example.test/root/consumer_test ["));
        let mapped: (String,String) = conn.query_row("SELECT target.tool_import_path,imports.source_spelling FROM go_package_imports imports JOIN go_package_instances target ON target.package_id=imports.target_package_id WHERE imports.context_id=?1 AND imports.import_role='xtest'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(
            mapped.0,
            "example.test/root/consumer [example.test/root/consumer.test]"
        );
        assert_eq!(mapped.1, "example.test/root/consumer");
        let description_only: i64 = conn.query_row("SELECT count(*) FROM go_package_imports WHERE context_id=?1 AND source_spelling='not-selected.test/description-only'",[identity.context_id],|row|row.get(0)).unwrap();
        assert_eq!(description_only, 0);
    }

    #[test]
    fn go_context_rejects_unproven_test_variants_and_conflicting_package_clauses() {
        let fixture = test_variant_fixture();
        let mut discovery = fixture.discovery();
        discovery.packages[0]
            .go_files
            .extend(["use_test.go".into(), "external_test.go".into()]);
        let identity = fixture.publish(discovery, None);
        let conn = fixture.store().read_conn().unwrap();
        let gaps:String = conn.query_row("SELECT json(gaps) FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/consumer'",[identity.context_id],|row|row.get(0)).unwrap();
        assert!(gaps.contains("test_variant_unselected"), "{gaps}");
        assert!(gaps.contains("package_source_identity_mismatch"), "{gaps}");
        let count:i64 = conn.query_row("SELECT count(*) FROM go_context_source_files WHERE context_id=?1 AND source_role IN ('test','xtest')",[identity.context_id],|row|row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn go_context_publication_preserves_aba_retry_and_cancellation() {
        let fixture = Fixture::new();
        let first = fixture.publish(fixture.discovery(), None);
        let mut partial = fixture.discovery();
        partial.packages[1].incomplete = true;
        let second = fixture.publish(partial, Some(first.clone()));
        assert_ne!(first, second);
        assert_eq!(
            fixture
                .store()
                .go_context_head_status(&first, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Withdrawn
        );
        let before = fixture.observe();
        assert!(matches!(
            fixture
                .store()
                .publish_go_package_context(
                    fixture.snapshot.clone(),
                    fixture.project.root().to_path_buf(),
                    Some(first.clone()),
                    &before,
                    &before,
                    fixture.discovery(),
                    &CancellationToken::new()
                )
                .unwrap(),
            GoContextPublicationOutcome::InputsChanged
        ));
        let third = fixture.publish(fixture.discovery(), Some(second));
        assert_eq!(first, third, "A/B/A reuses immutable A publication");
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            fixture
                .store()
                .publish_go_package_context(
                    fixture.snapshot.clone(),
                    fixture.project.root().to_path_buf(),
                    Some(third.clone()),
                    &before,
                    &before,
                    fixture.discovery(),
                    &cancelled
                )
                .unwrap(),
            GoContextPublicationOutcome::Cancelled
        ));
        assert_eq!(
            fixture
                .store()
                .go_context_head_status(&third, &cancelled)
                .unwrap(),
            GoContextHeadStatus::Cancelled
        );
        assert_eq!(
            fixture
                .store()
                .go_context_head_status(&third, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Current
        );
        fixture
            .project
            .file("provider/item.go")
            .write("package provider\ntype Changed struct{}\n")
            .unwrap();
        assert!(matches!(
            fixture
                .store()
                .observe_go_context_inputs(
                    &fixture.snapshot,
                    fixture.workspace.analyzer().project(),
                    &CancellationToken::new()
                )
                .unwrap(),
            GoInputObservationOutcome::InputsChanged
        ));
    }

    #[test]
    fn go_context_source_inventory_is_partial_selected_and_incremental() {
        let fixture = Fixture::new();
        let profile = source_inventory_profile();
        let first = fixture
            .store()
            .selected_go_context(&fixture.snapshot, &profile)
            .unwrap()
            .unwrap();
        {
            let conn = fixture.store().read_conn().unwrap();
            let (complete, gaps): (bool, String) = conn
                .query_row(
                    "SELECT complete,json(gaps) FROM go_context_publications WHERE context_id=?1",
                    [first.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(!complete);
            assert!(gaps.contains("build_selection_unavailable"));
            let (package_complete, provenance): (bool, String) = conn
                .query_row(
                    "SELECT complete,provider_provenance FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider'",
                    [first.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(
                package_complete,
                "source-only package has exact local placement"
            );
            assert_eq!(provenance, "source_inventory");
            let import_complete: bool = conn
                .query_row(
                    "SELECT complete FROM go_package_imports WHERE context_id=?1 AND source_spelling='example.test/root/provider'",
                    [first.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                import_complete,
                "workspace source import has an exact provider"
            );
            let target:String=conn.query_row("SELECT target.tool_import_path FROM go_package_imports i JOIN go_package_instances target ON target.package_id=i.target_package_id WHERE i.context_id=?1 AND i.source_spelling='example.test/root/provider'",[first.context_id],|row|row.get(0)).unwrap();
            assert_eq!(target, "example.test/root/provider");
        }
        let changed = fixture.project.file("provider/item.go");
        changed
            .write("package provider\ntype Changed struct{}\n")
            .unwrap();
        let GoContextPublicationOutcome::Published(retained) = fixture
            .store()
            .publish_go_source_context(
                fixture.snapshot.clone(),
                fixture.project.root(),
                &CancellationToken::new(),
            )
            .unwrap()
        else {
            panic!("selected source inventory publishes");
        };
        assert_eq!(
            retained, first,
            "new disk text cannot contaminate the old selection"
        );
        let updated = fixture.workspace.update(&BTreeSet::from([changed]));
        let store = updated.store().unwrap();
        let mut next = fixture.snapshot.clone();
        next.revision = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                [next.workspace_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(next.revision > fixture.snapshot.revision);
        let second = store.selected_go_context(&next, &profile).unwrap().unwrap();
        assert_ne!(first.publication_digest, second.publication_digest);
        assert_eq!(
            store
                .go_context_head_status(&first, &CancellationToken::new())
                .unwrap(),
            GoContextHeadStatus::Current
        );
        let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
            fixture.project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let fresh_store = fresh.store().unwrap();
        let mut fresh_snapshot = fixture.snapshot.clone();
        fresh_snapshot.revision = fresh_store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                [fresh_snapshot.workspace_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            second.publication_digest,
            fresh_store
                .selected_go_context(&fresh_snapshot, &profile)
                .unwrap()
                .unwrap()
                .publication_digest
        );
    }

    #[test]
    fn go_source_inventory_separates_external_test_package_clause() {
        let fixture = test_variant_fixture();
        let context = fixture
            .store()
            .selected_go_context(&fixture.snapshot, &source_inventory_profile())
            .unwrap()
            .expect("source inventory is selected");
        let conn = fixture.store().read_conn().unwrap();
        let external: (String, String, String, bool) = conn
            .query_row(
                "SELECT package.tool_import_path,package.package_name,file.rel_path,package.complete FROM go_context_source_files source JOIN workspace_file_versions file USING(file_version_id) JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND source.source_role='xtest'",
                [context.context_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(external.0, "example.test/root/consumer_test");
        assert_eq!(external.1, "consumer_test");
        assert_eq!(external.2, "consumer/external_test.go");
        assert!(
            external.3,
            "the external package clause has source-only identity"
        );
        let base_external_files: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_context_source_files source JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND package.tool_import_path='example.test/root/consumer' AND source.rel_path='consumer/external_test.go'",
                [context.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(base_external_files, 0);
    }

    #[test]
    fn go_source_inventory_keeps_known_files_when_build_selection_is_constrained() {
        let fixture = Fixture::from_project(
            InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                .file("pkg/plain.go", "package pkg\nvar Plain = 1\n")
                .file(
                    "pkg/tagged.go",
                    "//go:build linux\n\npackage pkg\nvar Tagged = 2\n",
                )
                .file("pkg/platform_arm64.go", "package pkg\nvar Platform = 3\n")
                .file("other/plain.go", "package other\nvar Known = 4\n")
                .build(),
        );
        let context = fixture
            .store()
            .selected_go_context(&fixture.snapshot, &source_inventory_profile())
            .unwrap()
            .expect("source inventory is selected");
        let conn = fixture.store().read_conn().unwrap();
        let (constrained_complete, constrained_gaps): (bool, String) = conn
            .query_row(
                "SELECT package.complete,json(package.gaps) FROM go_package_instances package WHERE package.context_id=?1 AND package.tool_import_path='example.test/root/pkg'",
                [context.context_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            !constrained_complete,
            "one constrained file opens its package inventory"
        );
        assert!(constrained_gaps.contains("source_file_build_selection_unavailable"));
        let constrained_files: Vec<String> = conn
            .prepare(
                "SELECT file.rel_path FROM go_context_source_files source JOIN workspace_file_versions file USING(file_version_id) JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND package.tool_import_path='example.test/root/pkg' ORDER BY file.rel_path",
            )
            .unwrap()
            .query_map([context.context_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            constrained_files,
            vec![
                "pkg/plain.go".to_owned(),
                "pkg/platform_arm64.go".to_owned(),
                "pkg/tagged.go".to_owned(),
            ],
            "build constraints preserve every positively placed file"
        );
        let other_complete: bool = conn
            .query_row(
                "SELECT complete FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/other'",
                [context.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            other_complete,
            "constraints do not lower an unrelated package"
        );
    }

    #[test]
    fn go_context_source_inventory_preserves_roles_and_vendor_ambiguity() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/root\n")
            .file(
                "consumer/use.go",
                "package consumer\nimport . \"example.test/shared\"\nvar Value Item\n",
            )
            .file("consumer/use_test.go", "package consumer\n")
            .file("consumer/external_test.go", "package consumer_test\n")
            .file(
                "left/vendor/example.test/shared/empty.go",
                "package shared\n",
            )
            .file(
                "right/vendor/example.test/shared/empty.go",
                "package shared\n",
            )
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let context: i64 = conn
            .query_row("SELECT context_id FROM go_context_heads", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (complete, gaps): (bool, String) = conn
            .query_row(
                "SELECT complete,json(gaps) FROM go_context_publications WHERE context_id=?1",
                [context],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!complete);
        assert!(
            gaps.contains("source_import_provider_unavailable"),
            "{gaps}"
        );
        assert!(
            gaps.contains("left/vendor/example.test/shared")
                && gaps.contains("right/vendor/example.test/shared"),
            "{gaps}"
        );
        let target:Option<i64>=conn.query_row("SELECT target_package_id FROM go_package_imports WHERE context_id=?1 AND source_spelling='example.test/shared'",[context],|row|row.get(0)).unwrap();
        assert_eq!(target, None);
        for (path, role) in [
            ("consumer/use.go", "go"),
            ("consumer/use_test.go", "test"),
            ("consumer/external_test.go", "xtest"),
            ("left/vendor/example.test/shared/empty.go", "go"),
        ] {
            let actual:String=conn.query_row("SELECT source_role FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2",params![context,path],|row|row.get(0)).unwrap();
            assert_eq!(actual, role);
        }
    }

    #[test]
    fn go_context_active_tool_profile_never_falls_back_after_source_update() {
        let fixture = Fixture::new();
        let discovery = fixture.discovery();
        let profile = profile_digest(&discovery);
        let original = fixture.publish(discovery, None);
        let go = crate::analyzer::resolve_analyzer::<crate::analyzer::GoAnalyzer>(
            fixture.workspace.analyzer(),
        )
        .unwrap();
        assert!(go.activate_native_context_profile(&fixture.snapshot, profile));
        let changed = fixture.project.file("provider/item.go");
        changed
            .write("package provider\ntype Updated struct{}\n")
            .unwrap();
        let updated = fixture.workspace.update(&BTreeSet::from([changed]));
        let go =
            crate::analyzer::resolve_analyzer::<crate::analyzer::GoAnalyzer>(updated.analyzer())
                .unwrap();
        assert_eq!(go.native_context_profile(), Some(profile));
        let store = updated.store().unwrap();
        let mut next = fixture.snapshot.clone();
        next.revision = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                [next.workspace_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(next.revision > fixture.snapshot.revision);
        assert_eq!(store.selected_go_context(&next, &profile).unwrap(), None);
        assert_eq!(
            store
                .selected_go_context(&next, &source_inventory_profile())
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .selected_go_context(&fixture.snapshot, &profile)
                .unwrap(),
            Some(original)
        );
        assert!(!go.activate_native_context_profile(&fixture.snapshot, source_inventory_profile()));
        assert_eq!(go.native_context_profile(), Some(profile));
    }

    #[test]
    fn go_context_profile_is_explicit_and_clone_local() {
        let fixture = Fixture::new();
        let first_discovery = fixture.discovery();
        let first_profile = profile_digest(&first_discovery);
        let first = fixture.publish(first_discovery, None);
        let mut second_discovery = fixture.discovery();
        second_discovery.build_tags.push("another-profile".into());
        let second_profile = profile_digest(&second_discovery);
        fixture.publish(second_discovery, None);
        let go = crate::analyzer::resolve_analyzer::<crate::analyzer::GoAnalyzer>(
            fixture.workspace.analyzer(),
        )
        .unwrap();
        assert_eq!(
            go.native_context_profile(),
            Some(source_inventory_profile())
        );
        assert!(go.activate_native_context_profile(&fixture.snapshot, first_profile));
        let cloned = go.clone();
        assert!(cloned.activate_native_context_profile(&fixture.snapshot, second_profile));
        assert_eq!(go.native_context_profile(), Some(first_profile));
        assert_eq!(cloned.native_context_profile(), Some(second_profile));
        assert_eq!(
            fixture
                .store()
                .selected_go_context(&fixture.snapshot, &go.native_context_profile().unwrap())
                .unwrap(),
            Some(first)
        );
        let mut wrong = fixture.snapshot.clone();
        wrong.revision += 1;
        assert!(!go.activate_native_context_profile(&wrong, second_profile));
        assert_eq!(go.native_context_profile(), Some(first_profile));
    }

    #[test]
    fn go_context_maps_source_spelling_and_keeps_missing_provider_partial() {
        let fixture = Fixture::new();
        let mut discovery = fixture.discovery();
        discovery.packages[0].import_map.insert(
            "visible/provider".into(),
            "example.test/root/provider".into(),
        );
        discovery.packages[0]
            .imports
            .push("external/missing".into());
        let identity = fixture.publish(discovery, None);
        let conn = fixture.store().read_conn().unwrap();
        let target: (String,bool) = conn.query_row("SELECT target.package_name,i.complete FROM go_package_imports i JOIN go_package_instances target ON target.package_id=i.target_package_id WHERE i.context_id=?1 AND i.source_spelling='visible/provider'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(target, ("provider".into(), true));
        let missing: (Option<i64>,bool,String) = conn.query_row("SELECT target_package_id,complete,json(gaps) FROM go_package_imports WHERE context_id=?1 AND source_spelling='external/missing'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(missing.0, None);
        assert!(!missing.1);
        assert!(missing.2.contains("incomplete_import_provider"));
        let member_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_context_source_files WHERE context_id=?1",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(member_count, 2);
    }

    #[test]
    fn go_context_publishes_fileless_standard_and_module_import_targets() {
        let fixture = Fixture::new();
        let mut discovery = fixture.discovery();
        discovery.packages[0].imports = vec!["strings".into(), "example.com/dep/pkg".into()];
        let standard_dir = fixture.project.root().join("external/stdlib/strings");
        let module_dir = fixture.project.root().join("external/module-cache/dep/pkg");
        discovery.packages.push(
            serde_json::from_value(json!({
                "ImportPath": "strings",
                "Name": "strings",
                "Dir": standard_dir,
                "Standard": true,
                "GoFiles": ["strings.go"]
            }))
            .unwrap(),
        );
        discovery.packages.push(
            serde_json::from_value(json!({
                "ImportPath": "example.com/dep/pkg",
                "Name": "pkg",
                "Dir": module_dir,
                "Module": {
                    "Path": "example.com/dep",
                    "Version": "v1.2.3",
                    "Sum": "h1:dep",
                    "Dir": fixture.project.root().join("external/module-cache/dep"),
                    "GoMod": fixture.project.root().join("external/module-cache/dep/go.mod"),
                    "Main": false
                },
                "GoFiles": ["dep.go"]
            }))
            .unwrap(),
        );

        let identity = fixture.publish(discovery, None);
        let conn = fixture.store().read_conn().unwrap();
        let providers = conn
            .prepare("SELECT tool_import_path,package_name,provider_kind,provider_module_path,provider_module_version,complete,json(gaps) FROM go_package_instances WHERE context_id=?1 AND provider_kind<>'workspace' ORDER BY tool_import_path")
            .unwrap()
            .query_map([identity.context_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            providers,
            vec![
                (
                    "example.com/dep/pkg".into(),
                    "pkg".into(),
                    "module".into(),
                    Some("example.com/dep".into()),
                    Some("v1.2.3".into()),
                    true,
                    "[]".into(),
                ),
                (
                    "strings".into(),
                    "strings".into(),
                    "standard".into(),
                    None,
                    None,
                    true,
                    "[]".into(),
                ),
            ]
        );
        let external_file_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_package_files files JOIN go_package_instances packages USING(package_id) WHERE packages.context_id=?1 AND packages.provider_kind<>'workspace'",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(external_file_count, 0);
        let complete: bool = conn
            .query_row(
                "SELECT complete FROM go_context_publications WHERE context_id=?1",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(complete);
        for spelling in ["strings", "example.com/dep/pkg"] {
            let (name, import_path, complete): (String, String, bool) = conn
                .query_row(
                    "SELECT target.package_name,target.tool_import_path,imports.complete FROM go_package_imports imports JOIN go_package_instances target ON target.package_id=imports.target_package_id WHERE imports.context_id=?1 AND imports.source_spelling=?2",
                    rusqlite::params![identity.context_id, spelling],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert!(complete, "{spelling}");
            assert_eq!(
                name,
                if spelling == "strings" {
                    "strings"
                } else {
                    "pkg"
                }
            );
            assert_eq!(import_path, spelling);
        }
    }

    #[test]
    fn go_context_conflicting_tool_identities_are_withheld() {
        let fixture = Fixture::new();
        let mut discovery = fixture.discovery();
        discovery.packages.push(discovery.packages[1].clone());
        let identity = fixture.publish(discovery, None);
        let conn = fixture.store().read_conn().unwrap();
        let count: i64 = conn.query_row("SELECT count(*) FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider'",[identity.context_id],|row|row.get(0)).unwrap();
        assert_eq!(count, 0);
        let complete: bool = conn
            .query_row(
                "SELECT complete FROM go_context_publications WHERE context_id=?1",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!complete);
    }

    #[test]
    fn go_context_source_membership_view_excludes_wrong_selection_domains() {
        let fixture = Fixture::new();
        let identity = fixture.publish(fixture.discovery(), None);
        let conn = fixture.store().conn.lock().unwrap();
        let package: i64 = conn
            .query_row(
                "SELECT package_id FROM go_package_instances WHERE context_id=?1 LIMIT 1",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        let selected_workspace = fixture.snapshot.workspace_id.as_str();
        let selected_generation = fixture.snapshot.generation.get();
        let selected_revision = fixture.snapshot.revision;
        let oid = Oid::hash_object(ObjectType::Blob, b"package invalid")
            .unwrap()
            .to_string();
        let projection = "a".repeat(64);
        for (index, (workspace, lang, generation, from, until, kind)) in [
            (
                "b".repeat(64),
                "go",
                selected_generation,
                selected_revision,
                None::<i64>,
                "source",
            ),
            (
                selected_workspace.to_owned(),
                "java",
                selected_generation,
                selected_revision,
                None,
                "source",
            ),
            (
                selected_workspace.to_owned(),
                "go",
                selected_generation + 1,
                selected_revision,
                None,
                "source",
            ),
            (
                selected_workspace.to_owned(),
                "go",
                selected_generation,
                selected_revision + 1,
                None,
                "source",
            ),
            (
                selected_workspace.to_owned(),
                "go",
                selected_generation,
                selected_revision,
                None,
                "configuration",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            conn.execute("INSERT OR IGNORE INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",params![workspace,lang,generation,from]).unwrap();
            conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,input_kind,projection_digest,valid_from,valid_until) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![workspace,lang,generation,format!("invalid{index}.go"),oid,kind,(kind=="source").then_some(&projection),from,until]).unwrap();
            conn.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role) VALUES(?1,?2,'go')",params![package,conn.last_insert_rowid()]).unwrap();
        }
        let visible: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_context_source_files WHERE context_id=?1",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            visible, 2,
            "wrong workspace/language/generation/revision/kind must never join"
        );
        // A row whose interval ended at this revision is likewise excluded.
        conn.execute("UPDATE workspace_file_versions SET valid_until=?1 WHERE rel_path='provider/item.go' AND workspace_id=?2",params![selected_revision+1,selected_workspace]).unwrap();
        let shifted = selected_revision + 1;
        conn.execute("INSERT OR IGNORE INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,'go',?2,?3)",params![selected_workspace,selected_generation,shifted]).unwrap();
        conn.execute(
            "UPDATE go_context_selections SET revision=?1 WHERE selection_id=?2",
            params![shifted, identity.selection_id],
        )
        .unwrap();
        let ended: i64 = conn.query_row("SELECT count(*) FROM go_context_source_files WHERE context_id=?1 AND rel_path='provider/item.go'",[identity.context_id],|row|row.get(0)).unwrap();
        assert_eq!(ended, 0);
    }

    #[test]
    fn go_context_readers_use_indexed_selection_and_input_access() {
        use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
        use rusqlite::types::Value;
        let fixture = Fixture::new();
        let mut identities = Vec::new();
        for index in 0..48 {
            let mut discovery = fixture.discovery();
            discovery.build_tags.push(format!("profile{index}"));
            let profile = profile_digest(&discovery);
            identities.push((profile, fixture.publish(discovery, None)));
        }
        let (profile, identity) = &identities[24];
        let conn = fixture.store().conn.lock().unwrap();
        let mut selection = pinned("go_native_selected_context");
        selection.params = vec![
            Value::Text(fixture.snapshot.workspace_id.as_str().into()),
            Value::Integer(fixture.snapshot.generation.get()),
            Value::Integer(fixture.snapshot.revision),
            Value::Blob(profile.to_vec()),
            Value::Integer(DERIVATION_VERSION),
        ];
        let mut head = pinned("go_native_context_head");
        head.params = vec![
            Value::Integer(identity.selection_id),
            Value::Integer(identity.context_id),
            Value::Blob(identity.publication_digest.to_vec()),
        ];
        let mut inputs = pinned("go_native_observed_inputs");
        inputs.params = selection.params[..3].to_vec();
        let mut source_inventory = pinned("go_native_source_inventory");
        source_inventory.params = inputs.params.clone();
        let mut canonical_source = pinned("go_native_canonical_source");
        canonical_source.params = vec![
            inputs.params[0].clone(),
            inputs.params[1].clone(),
            Value::Text("consumer/use.go".into()),
            inputs.params[2].clone(),
        ];
        let mut prior = pinned("go_native_prior_heads");
        prior.params = inputs.params.clone();
        prior.params.push(Value::Integer(DERIVATION_VERSION));
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            state.install(&conn);
            for query in [
                &selection,
                &head,
                &inputs,
                &prior,
                &source_inventory,
                &canonical_source,
            ] {
                let plan = explain_pin(&conn, query);
                assert!(
                    !plan.iter().any(|line| line.contains("SCAN s")
                        || line.contains("SCAN h")
                        || line.contains("SCAN p")
                        || line.contains("SCAN workspace_file_versions")
                        || line.contains("AUTOMATIC")
                        || line.contains("TEMP B-TREE")),
                    "{} {state:?}: {plan:?}",
                    query.name
                );
                if query.name == "go_native_canonical_source" {
                    assert!(
                        !plan.iter().any(|line| line.contains("SCAN f")),
                        "{state:?}: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|line| line.contains("SEARCH f")),
                        "{state:?}: {plan:?}"
                    );
                }
                if query.name == "go_native_observed_inputs" {
                    assert!(
                        plan.iter().any(|line| line
                            .contains("idx_workspace_file_versions_snapshot_kind")
                            || line.contains("sqlite_autoindex_workspace_file_versions_1")),
                        "{state:?}: {plan:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn go_context_foreign_keys_reject_cross_context_imports() {
        let fixture = Fixture::new();
        let first = fixture.publish(fixture.discovery(), None);
        let mut partial = fixture.discovery();
        partial.packages[0].incomplete = true;
        let second = fixture.publish(partial, Some(first.clone()));
        let conn = fixture.store().conn.lock().unwrap();
        let package = |context| {
            conn.query_row(
                "SELECT package_id FROM go_package_instances WHERE context_id=?1 LIMIT 1",
                [context],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        let result = conn.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,'wrong','go',?3,0,jsonb('[]'))",params![first.context_id,package(first.context_id),package(second.context_id)]);
        assert!(
            matches!(result,Err(rusqlite::Error::SqliteFailure(error,_)) if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY)
        );
    }
}
