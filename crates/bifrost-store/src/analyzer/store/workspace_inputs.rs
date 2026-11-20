//! Revision publication shared by source projections and retained configuration.

pub(super) const OPEN_PARTITION_DECISIONS_SQL: &str = "SELECT files.file_version_id, files.rel_path, files.blob_oid, files.projection_digest, files.file_present,
                    decisions.decision_digest, decisions.assignment_digest
             FROM workspace_file_versions AS files
             LEFT JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id = files.file_version_id
             WHERE files.workspace_id = ?1 AND files.lang = ?2 AND files.generation = ?3
               AND files.input_kind = ?4 AND files.valid_until IS NULL";

use git2::Oid;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::analyzer::semantic::source_admission::SourceAdmissionRefusal;
use crate::hash::{HashMap, HashSet};

use super::{GenerationId, Result, StoreError, WorkspaceId, WorkspaceSnapshotId};

/// Exact input bytes retained independently of source extraction or Cargo parsing.
#[derive(Clone)]
#[doc(hidden)]
pub struct WorkspaceConfigurationInput {
    #[doc(hidden)]
    pub relative_path: String,
    content_oid: Oid,
    #[doc(hidden)]
    pub source_bytes: Box<[u8]>,
    #[doc(hidden)]
    pub file_present: bool,
    // Request-only capture metadata; retain() persists local bytes separately.
    // The acquired input set stores typed facts/hashes, never external TOML.
    rust_cargo_external_reads:
        std::sync::Arc<[crate::analyzer::semantic_model::ExternalDiscoveryRead]>,
    rust_cargo_acquisition: Option<
        std::sync::Arc<brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView>,
    >,
}

impl WorkspaceConfigurationInput {
    /// Whether a recorder may name this source or native metadata path in a
    /// File read for `language`. Metadata ownership does not make it source
    /// code, so source admission keeps its narrower language classification.
    #[doc(hidden)]
    pub fn may_record_file_read(
        language: crate::analyzer::Language,
        file: &crate::analyzer::ProjectFile,
    ) -> bool {
        brokk_bifrost_core::analyzer::common::workspace_language_for_file(file) == language
            || Self::is_native_input(language, file.rel_path())
    }

    /// Workspace-contained inputs shared by capture and selected-context guards.
    #[doc(hidden)]
    pub fn is_native_input(language: crate::analyzer::Language, path: &std::path::Path) -> bool {
        crate::analyzer::store::store_language_support_for_hook(
            language,
            "is_configuration_input_path",
        )
        .is_some_and(|support| support.is_configuration_input_path(path))
    }

    #[doc(hidden)]
    pub fn include_native_metadata_paths(
        project: &dyn crate::analyzer::Project,
        files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
        language: crate::analyzer::Language,
        inputs: &mut std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> std::io::Result<()> {
        use crate::analyzer::{Language, ProjectFile};
        use std::collections::BTreeSet;
        let root = project.root();
        // Metadata can be readable by path even when ignore rules omit it
        // from enumeration. Membership still belongs to the selected Project.
        if let Some(support) = crate::analyzer::store::store_language_support_for_hook(
            language,
            "include_native_metadata_paths",
        ) {
            support.include_native_metadata_paths(project, files, inputs)?;
        }
        if super::resolution_operation::nominal_rules::jvm_package_rules().admits(language) {
            // The toolchain selector is read explicitly even when .bifrost is
            // excluded from the project's ordinary source listing.
            let toolchains = ProjectFile::new(
                root,
                std::path::PathBuf::from(".bifrost/jvm-toolchains.json"),
            );
            if toolchains.abs_path().try_exists()? {
                inputs.insert(toolchains);
            }
        }
        if language == Language::Rust {
            let source_directories = metadata_ancestor_directories(files.iter().filter(|file| {
                file.rel_path()
                    .extension()
                    .is_some_and(|extension| extension == "rs")
            }));
            for directory in source_directories {
                let manifest = ProjectFile::new(root, directory.join("Cargo.toml"));
                if manifest.abs_path().try_exists()? {
                    inputs.insert(manifest);
                }
            }
            let crate_directories = inputs
                .iter()
                .filter(|file| {
                    file.rel_path()
                        .file_name()
                        .is_some_and(|name| name == "Cargo.toml")
                })
                .map(|file| {
                    file.rel_path()
                        .parent()
                        .expect("manifest parent")
                        .to_path_buf()
                })
                .collect::<Vec<_>>();
            for directory in crate_directories {
                for kind in brokk_bifrost_core::analyzer::project::RUST_TARGET_LAYOUT_DIRECTORIES {
                    let target_directory = root.join(&directory).join(kind);
                    let entries = match std::fs::read_dir(target_directory) {
                        Ok(entries) => entries,
                        // Cargo discovers no targets where the layout directory is
                        // absent or is an ordinary file.
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    for entry in entries {
                        let entry = entry?;
                        let main = ProjectFile::new(
                            root,
                            directory.join(kind).join(entry.file_name()).join("main.rs"),
                        );
                        if main.abs_path().is_file() {
                            inputs.insert(main);
                        }
                    }
                }
            }
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml")
            }));
            for directory in directories {
                for name in ["Cargo.lock", ".cargo/config.toml", ".cargo/config"] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if matches!(language, Language::JavaScript | Language::TypeScript) {
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .file_name()
                    .is_some_and(|name| name == "package.json")
            }));
            for directory in directories {
                for name in [
                    "package.json",
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                ] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if language == Language::CSharp {
            // MSBuild imports the nearest Directory.Build.props/.targets and
            // Directory.Packages.props above a project whether or not ignore
            // rules list them, and each can change the project's items. Probe
            // them by path so membership records their bytes, or absence.
            let directories = metadata_ancestor_directories(inputs.iter().filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("csproj"))
            }));
            for directory in directories {
                for name in [
                    "Directory.Build.props",
                    "Directory.Build.targets",
                    "Directory.Packages.props",
                ] {
                    let file = ProjectFile::new(root, directory.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        if language == Language::Go {
            // Go reads metadata beside its module/workspace manifests even
            // when ignore rules omit checksums or vendor metadata from listing.
            let mut roots = BTreeSet::from([std::path::PathBuf::new()]);
            for file in inputs.iter() {
                if matches!(
                    file.rel_path().file_name().and_then(|name| name.to_str()),
                    Some("go.mod" | "go.work")
                ) {
                    roots.insert(
                        file.rel_path()
                            .parent()
                            .expect("relative input parent")
                            .to_path_buf(),
                    );
                }
            }
            for relative_root in roots {
                for name in [
                    "go.mod",
                    "go.sum",
                    "go.work",
                    "go.work.sum",
                    "vendor/modules.txt",
                ] {
                    let file = ProjectFile::new(root, relative_root.join(name));
                    if file.abs_path().try_exists()? {
                        inputs.insert(file);
                    }
                }
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn new(relative_path: String, source_bytes: Box<[u8]>) -> Self {
        assert!(!relative_path.is_empty());
        assert!(
            std::path::Path::new(&relative_path)
                .components()
                .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
            "configuration path must be workspace relative"
        );
        Self {
            content_oid: Oid::hash_object(git2::ObjectType::Blob, &source_bytes)
                .expect("hashing configuration input"),
            relative_path,
            source_bytes,
            file_present: true,
            rust_cargo_acquisition: None,
            rust_cargo_external_reads: Default::default(),
        }
    }

    #[doc(hidden)]
    pub fn absent(relative_path: String) -> Self {
        let mut input = Self::new(relative_path, Box::new([]));
        input.file_present = false;
        input
    }

    /// Attach one explicitly acquired input view to this capture. The chosen
    /// anchor is an existing local configuration input, not a synthetic file.
    #[doc(hidden)]
    pub fn attach_rust_cargo_acquisition(
        inputs: &mut [Self],
        view: brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView,
    ) {
        for input in inputs.iter_mut() {
            input.rust_cargo_acquisition = None;
        }
        if let Some(input) = inputs.first_mut() {
            input.rust_cargo_acquisition = Some(std::sync::Arc::new(view));
        }
    }

    /// Existing read keys are ephemeral admission receipts. They are never
    /// written by retain() or included in the persisted acquired input record.
    #[doc(hidden)]
    pub fn attach_rust_cargo_external_reads(
        inputs: &mut [Self],
        reads: Vec<crate::analyzer::semantic_model::ExternalDiscoveryRead>,
    ) {
        for input in inputs.iter_mut() {
            input.rust_cargo_external_reads = Default::default();
        }
        if let Some(input) = inputs.first_mut() {
            input.rust_cargo_external_reads = reads.into();
        }
    }
    #[doc(hidden)]
    pub fn rust_cargo_external_reads(
        inputs: &[Self],
    ) -> std::sync::Arc<[crate::analyzer::semantic_model::ExternalDiscoveryRead]> {
        inputs
            .iter()
            .find(|input| !input.rust_cargo_external_reads.is_empty())
            .map_or_else(Default::default, |input| {
                std::sync::Arc::clone(&input.rust_cargo_external_reads)
            })
    }

    #[doc(hidden)]
    pub fn rust_cargo_acquisition(
        inputs: &[Self],
    ) -> Option<&brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView> {
        let mut views = inputs
            .iter()
            .filter_map(|input| input.rust_cargo_acquisition.as_deref());
        let view = views.next()?;
        views.next().is_none().then_some(view)
    }

    #[doc(hidden)]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    #[doc(hidden)]
    pub fn content_oid(&self) -> Oid {
        self.content_oid
    }
    #[doc(hidden)]
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    pub(super) fn row(&self) -> WorkspaceInputRow<'_> {
        WorkspaceInputRow {
            relative_path: &self.relative_path,
            content_oid: self.content_oid(),
            projection_digest: None,
            csharp_decision: None,
            file_present: Some(self.file_present),
        }
    }

    pub(super) fn retain(&self, tx: &Transaction<'_>) -> Result<()> {
        tx.execute(
            "INSERT OR IGNORE INTO workspace_input_sources(content_oid, source_bytes)
             VALUES(?1, ?2)",
            params![self.content_oid.to_string(), &self.source_bytes],
        )?;
        let equal: bool = tx.query_row(
            "SELECT source_bytes = ?2 FROM workspace_input_sources WHERE content_oid = ?1",
            params![self.content_oid.to_string(), &self.source_bytes],
            |row| row.get(0),
        )?;
        if !equal {
            return Err(StoreError::new(format!(
                "retained configuration bytes conflict for {} at {:?}",
                self.content_oid, self.relative_path,
            )));
        }
        Ok(())
    }
}

/// Ancestors of selected inputs, including the workspace root.
#[doc(hidden)]
pub fn metadata_ancestor_directories<'a>(
    files: impl Iterator<Item = &'a crate::analyzer::ProjectFile>,
) -> std::collections::BTreeSet<std::path::PathBuf> {
    std::iter::once(std::path::PathBuf::new())
        .chain(files.flat_map(|file| {
            file.rel_path()
                .parent()
                .into_iter()
                .flat_map(std::path::Path::ancestors)
                .map(std::path::Path::to_path_buf)
        }))
        .collect()
}

/// Digest of one revision's complete configuration partition. Inputs must be
/// ordered by relative path, the order SQL `ORDER BY rel_path` also yields.
#[doc(hidden)]
pub fn configuration_digest<'a>(
    inputs: impl IntoIterator<Item = (&'a str, Oid, Option<bool>)>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut digest = crate::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-workspace-configuration:v1",
    );
    let mut previous: Option<&str> = None;
    for (relative_path, content_oid, present) in inputs {
        debug_assert!(
            previous.is_none_or(|previous| previous < relative_path),
            "configuration inputs ordered by unique path: {previous:?} then {relative_path:?}"
        );
        previous = Some(relative_path);
        digest.field(
            relative_path,
            match present {
                Some(true) => content_oid.as_bytes(),
                Some(false) => b"absent",
                None => b"unvalidated",
            },
        );
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(digest.finish())
}

pub(super) const SELECTED_CONFIGURATION_BYTES_SQL: &str = "SELECT retained.source_bytes
     FROM workspace_file_versions AS versions
     JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2
       AND versions.generation = ?3 AND versions.rel_path = ?4
       AND versions.input_kind = 'configuration'
       AND versions.valid_from <= ?5
       AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)";

pub(super) const SELECTED_CARGO_MANIFESTS_SQL: &str =
    "SELECT versions.rel_path, retained.source_bytes
     FROM workspace_file_versions AS versions
     JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2
       AND versions.generation = ?3 AND versions.input_kind = 'configuration'
       AND versions.valid_from <= ?4
       AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
       AND (versions.rel_path = 'Cargo.toml' OR versions.rel_path GLOB '*/Cargo.toml')";

// Layout membership is shared with the classifier rather than duplicated in SQL.
pub(super) const SELECTED_RUST_TARGET_ROOTS_SQL: &str = "SELECT rel_path
       FROM workspace_file_versions
       WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
         AND input_kind IN ('source', 'configuration') AND file_present = 1 AND valid_from <= ?4
         AND (valid_until IS NULL OR ?4 < valid_until)
         AND rel_path GLOB '*/main.rs'";

#[derive(Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum NativeConfigurationOverlayAuthority {
    Current,
    Mismatch(String),
    Cancelled,
}

impl super::AnalyzerStore {
    /// The canonical OwnModule identity already published with this file version.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn selected_module_name(
        &self,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<String>> {
        let conn = self.read_conn()?;
        Self::selected_module_name_with_conn(&conn, snapshot, relative_path)
    }

    /// Read a selected module without checking out another store connection.
    pub fn selected_module_name_with_conn(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<String>> {
        conn.query_row(
            "SELECT anchors.package_name FROM workspace_file_versions versions
             JOIN workspace_file_anchor_rows anchors USING(file_version_id)
             WHERE versions.workspace_id=?1 AND versions.lang=?2
               AND versions.generation=?3 AND versions.rel_path=?4
               AND versions.input_kind='source'
               AND versions.valid_from<=?5
               AND (versions.valid_until IS NULL OR ?5<versions.valid_until)
               AND anchors.anchor_kind='own_module' AND anchors.anchor_pop=0",
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.get(),
                relative_path,
                snapshot.revision
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
    }

    /// Preload target layout before a query holds a store reader.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn selected_rust_target_roots(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<std::collections::HashSet<String>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(SELECTED_RUST_TARGET_ROOTS_SQL)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| row.get::<_, String>(0),
        )?;
        rows.filter(|row| {
            row.as_ref().map_or(true, |path| {
                brokk_bifrost_core::analyzer::project::is_rust_target_layout_main(
                    std::path::Path::new(path),
                )
            })
        })
        .collect::<rusqlite::Result<_>>()
        .map_err(StoreError::from)
    }

    /// Capture naming authority at publication, before any query holds a reader.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn selected_cargo_manifests(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<crate::hash::HashMap<String, Vec<u8>>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(SELECTED_CARGO_MANIFESTS_SQL)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        rows.collect::<rusqlite::Result<_>>()
            .map_err(StoreError::from)
    }

    /// Configuration-class inputs only; capture and overlay proofs use the same language hook.
    pub fn rust_configuration_inputs_on_connection(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Vec<(String, String, Vec<u8>)>> {
        let mut statement = conn.prepare_cached(
            "SELECT versions.rel_path, versions.blob_oid, retained.source_bytes
          FROM main.workspace_file_versions versions
          LEFT JOIN main.workspace_input_sources retained ON retained.content_oid=versions.blob_oid
          WHERE versions.workspace_id=?1 AND versions.lang='rust' AND versions.generation=?2
          AND versions.input_kind='configuration' AND versions.file_present=1
          AND versions.valid_from<=?3 AND (versions.valid_until IS NULL OR ?3<versions.valid_until)
          ORDER BY versions.rel_path",
        )?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )?;
        let mut inputs = Vec::new();
        for row in rows {
            let (path, oid, bytes) = row?;
            if !WorkspaceConfigurationInput::is_native_input(
                crate::analyzer::Language::Rust,
                std::path::Path::new(&path),
            ) {
                continue;
            }
            let bytes = bytes.ok_or_else(|| {
                StoreError::corrupt(format!("configuration bytes missing: {path}"))
            })?;
            inputs.push((path, oid, bytes));
        }
        Ok(inputs)
    }

    /// Exact configuration bytes, including absence, selected by this revision.
    #[doc(hidden)]
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn selected_configuration_source(
        &self,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.read_conn()?;
        Self::selected_configuration_source_with_conn(&conn, snapshot, relative_path)
    }

    /// Read retained configuration without checking out a second connection.
    pub fn selected_configuration_source_with_conn(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        relative_path: &str,
    ) -> Result<Option<Vec<u8>>> {
        conn.query_row(
            SELECTED_CONFIGURATION_BYTES_SQL,
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.get(),
                relative_path,
                snapshot.revision
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
    }

    /// Return the first native configuration overlay that cannot use the disk
    /// context selected by this exact workspace revision. Bytes live in SQL;
    /// this check retains only one input for the duration of the request.
    #[doc(hidden)]
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn native_configuration_overlay_mismatch(
        &self,
        project: &dyn crate::analyzer::Project,
        snapshots: &super::WorkspaceSnapshots,
        storage_language: &str,
        language: crate::analyzer::Language,
        cancellation: &crate::CancellationToken,
    ) -> Result<NativeConfigurationOverlayAuthority> {
        if cancellation.is_cancelled() {
            return Ok(NativeConfigurationOverlayAuthority::Cancelled);
        }
        let Some(overlays) = project.overlay_content() else {
            return Ok(NativeConfigurationOverlayAuthority::Current);
        };
        if !overlays.entries().iter().any(|(file, _)| {
            WorkspaceConfigurationInput::is_native_input(language, file.rel_path())
        }) {
            return Ok(if cancellation.is_cancelled() {
                NativeConfigurationOverlayAuthority::Cancelled
            } else {
                NativeConfigurationOverlayAuthority::Current
            });
        }
        let conn = self.read_conn()?;
        Self::native_configuration_overlay_mismatch_on_connection(
            &conn,
            project,
            snapshots,
            storage_language,
            language,
            cancellation,
        )
    }

    /// Check configuration bytes on the connection held by a selected operation.
    #[doc(hidden)]
    pub fn native_configuration_overlay_mismatch_on_connection(
        conn: &Connection,
        project: &dyn crate::analyzer::Project,
        snapshots: &super::WorkspaceSnapshots,
        storage_language: &str,
        language: crate::analyzer::Language,
        cancellation: &crate::CancellationToken,
    ) -> Result<NativeConfigurationOverlayAuthority> {
        if cancellation.is_cancelled() {
            return Ok(NativeConfigurationOverlayAuthority::Cancelled);
        }
        let Some(overlays) = project.overlay_content() else {
            return Ok(NativeConfigurationOverlayAuthority::Current);
        };
        for (file, digest) in overlays.entries() {
            if cancellation.is_cancelled() {
                return Ok(NativeConfigurationOverlayAuthority::Cancelled);
            }
            if !WorkspaceConfigurationInput::is_native_input(language, file.rel_path()) {
                continue;
            }
            let path = crate::path_utils::rel_path_string(file);
            let Some(snapshot) = snapshots.get(storage_language) else {
                return Ok(NativeConfigurationOverlayAuthority::Mismatch(path));
            };
            let bytes: Option<Vec<u8>> = conn
                .query_row(
                    SELECTED_CONFIGURATION_BYTES_SQL,
                    params![
                        snapshot.workspace_id.as_str(),
                        storage_language,
                        snapshot.generation.get(),
                        path,
                        snapshot.revision
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if cancellation.is_cancelled() {
                return Ok(NativeConfigurationOverlayAuthority::Cancelled);
            }
            if !bytes.is_some_and(|bytes| {
                crate::analyzer::canonical_hash::sha256_bytes(&bytes) == *digest
            }) {
                return Ok(NativeConfigurationOverlayAuthority::Mismatch(path));
            }
        }
        if cancellation.is_cancelled() {
            return Ok(NativeConfigurationOverlayAuthority::Cancelled);
        }
        Ok(NativeConfigurationOverlayAuthority::Current)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum WorkspaceInputKind {
    Source,
    Configuration,
}

impl WorkspaceInputKind {
    fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Configuration => "configuration",
        }
    }
}

pub(super) struct WorkspaceInputRow<'a> {
    pub relative_path: &'a str,
    pub content_oid: Oid,
    pub projection_digest: Option<&'a str>,
    pub csharp_decision: Option<super::csharp_compilation::FileVersionDecision>,
    pub file_present: Option<bool>,
}

/// A live source that source admission refused. It has no source row; this
/// row completes the revision's input domain with the refusal evidence, so a
/// reader can tell an explained exclusion from a missing or changed input.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct WorkspaceSourceRefusalRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub reason: SourceAdmissionRefusal,
}

impl WorkspaceSourceRefusalRow {
    /// The `workspace_source_refusals.reason` object.
    fn reason_json(&self) -> serde_json::Value {
        use crate::analyzer::semantic::source_admission::AdmissionDimension;
        use serde_json::json;
        match &self.reason {
            SourceAdmissionRefusal::Binary => json!({"code": "binary"}),
            SourceAdmissionRefusal::ProofRejected => json!({"code": "proof_rejected"}),
            SourceAdmissionRefusal::StructuralLine { limit, observed } => {
                json!({"code": "structural_line", "limit": limit, "observed": observed})
            }
            SourceAdmissionRefusal::Budget {
                dimension,
                limit,
                observed,
            } => {
                let dimension = match dimension {
                    AdmissionDimension::SourceBytes => "source_bytes",
                    AdmissionDimension::ExcludedNodes => "excluded_nodes",
                };
                json!({"code": "budget", "dimension": dimension, "limit": limit, "observed": observed})
            }
        }
    }
}

/// Refusal rows one publication closes and opens, applied at the revision
/// that also carries its file-version changes.
#[derive(Default)]
pub(super) struct WorkspaceRefusalChanges<'a> {
    closed_paths: Vec<String>,
    opened: Vec<&'a WorkspaceSourceRefusalRow>,
}

impl<'a> WorkspaceRefusalChanges<'a> {
    fn is_empty(&self) -> bool {
        self.closed_paths.is_empty() && self.opened.is_empty()
    }

    /// Replace every open refusal row of one storage language that the
    /// publisher owns; rows at `foreign_paths` belong to another publisher.
    pub(super) fn replacing(
        tx: &Transaction<'_>,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        rows: &'a [WorkspaceSourceRefusalRow],
        foreign_paths: &HashSet<String>,
    ) -> Result<Self> {
        let mut incoming = HashMap::default();
        for row in rows {
            assert!(
                incoming.insert(row.rel_path.as_str(), row).is_none(),
                "unique refused paths"
            );
            assert!(
                !foreign_paths.contains(&row.rel_path),
                "a publisher does not refuse a path it names as foreign: {}",
                row.rel_path
            );
        }
        let mut changes = Self::default();
        let mut statement = tx.prepare_cached(
            "SELECT rel_path, blob_oid, json(reason) FROM workspace_source_refusals
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND valid_until IS NULL",
        )?;
        let mut open = statement.query(params![workspace_id.as_str(), lang, generation.0])?;
        while let Some(row) = open.next()? {
            let path: String = row.get(0)?;
            if foreign_paths.contains(&path) {
                continue;
            }
            let (oid, reason): (String, String) = (row.get(1)?, row.get(2)?);
            let unchanged = incoming
                .get(path.as_str())
                .is_some_and(|new| refusal_matches(new, &oid, &reason));
            if unchanged {
                incoming.remove(path.as_str());
            } else {
                changes.closed_paths.push(path);
            }
        }
        changes.opened.extend(incoming.into_values());
        Ok(changes)
    }

    /// Replace the refusal row, if any, of one path in one storage language.
    pub(super) fn replacing_path(
        tx: &Transaction<'_>,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        rel_path: &str,
        refusal: Option<&'a WorkspaceSourceRefusalRow>,
    ) -> Result<Self> {
        if let Some(refusal) = refusal {
            assert_eq!(
                refusal.rel_path, rel_path,
                "a path replacement refuses that path"
            );
        }
        let open = tx
            .query_row(
                "SELECT blob_oid, json(reason) FROM workspace_source_refusals
                 WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                   AND rel_path = ?4 AND valid_until IS NULL",
                params![workspace_id.as_str(), lang, generation.0, rel_path],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let unchanged = match (&open, refusal) {
            (None, None) => true,
            (Some((oid, reason)), Some(new)) => refusal_matches(new, oid, reason),
            _ => false,
        };
        let mut changes = Self::default();
        if !unchanged {
            if open.is_some() {
                changes.closed_paths.push(rel_path.to_owned());
            }
            changes.opened.extend(refusal);
        }
        Ok(changes)
    }
}

/// Admission is a function of the bytes and the process's admission policy,
/// which not every language folds into its epoch, so the reason is compared
/// as well as the blob.
fn refusal_matches(new: &WorkspaceSourceRefusalRow, oid: &str, reason: &str) -> bool {
    oid == new.blob_oid.to_string()
        && serde_json::from_str::<serde_json::Value>(reason)
            .expect("the schema checks refusal reasons are JSON")
            == new.reason_json()
}

/// A complete replacement of the rows one publisher owns in one input family;
/// omitted families remain selected.
///
/// Two publishers can share one family of one storage language: the
/// analyzer's ordinary workspace sync owns the files whose own storage
/// language this is, and a content-reading publisher (C++ publishes the C
/// reading of headers under `cpp:c`) owns the other files it mounts there.
/// Each names the paths the other owns in `foreign_paths`, and their open
/// rows are left as they are. Without that, each publisher closed the
/// other's rows and every warm start advanced the revision twice (#3763).
pub(super) struct WorkspaceInputPartition<'a> {
    pub kind: WorkspaceInputKind,
    pub rows: &'a [WorkspaceInputRow<'a>],
    pub foreign_paths: &'a HashSet<String>,
}

pub(super) type PublishedWorkspaceInputChanges = (
    WorkspaceSnapshotId,
    HashMap<(WorkspaceInputKind, String), i64>,
);

/// An open input version as the partition replacement compares it.
pub(super) struct OpenInput {
    pub id: i64,
    pub path: String,
    oid: Oid,
    digest: Option<String>,
    present: Option<bool>,
    decision: Option<super::csharp_compilation::FileVersionDecision>,
}

impl OpenInput {
    /// Whether `incoming` replaces this version with an identical input, so the
    /// version stays open. The one predicate of both the replacement and the
    /// pre-publication question of which inputs it will change.
    pub(super) fn matches(&self, incoming: Option<&WorkspaceInputRow<'_>>) -> bool {
        incoming.is_some_and(|new| {
            new.content_oid == self.oid
                && new.projection_digest == self.digest.as_deref()
                && new.csharp_decision == self.decision
                && new.file_present == self.present
        })
    }
}

pub(super) fn open_inputs(
    conn: &Connection,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    kind: WorkspaceInputKind,
) -> Result<Vec<OpenInput>> {
    let mut statement = conn.prepare_cached(OPEN_PARTITION_DECISIONS_SQL)?;
    let rows = statement.query_map(
        params![workspace_id.as_str(), lang, generation.0, kind.label()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<bool>>(4)?,
                super::csharp_compilation::decode_file_decision(row, 5)?,
            ))
        },
    )?;
    rows.map(|row| {
        let (id, path, oid, digest, present, decision) = row?;
        Ok(OpenInput {
            id,
            path,
            oid: Oid::from_str(&oid)?,
            digest,
            present,
            decision,
        })
    })
    .collect()
}

/// Publish all supplied input families at one revision and return new row IDs.
/// The caller inserts source projection children before committing the same
/// transaction. Configuration-only changes never replace source rows.
#[allow(clippy::too_many_arguments)]
pub(super) fn replace_workspace_input_partitions(
    tx: &Transaction<'_>,
    budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    partitions: &[WorkspaceInputPartition<'_>],
    refusals: &WorkspaceRefusalChanges<'_>,
    acquired: Option<&brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView>,
) -> Result<PublishedWorkspaceInputChanges> {
    super::require_current_generation(tx, lang, generation)?;
    let head = tx
        .query_row(
            "SELECT revision FROM workspace_heads
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
            params![workspace_id.as_str(), lang, generation.0],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let mut closed_ids = Vec::new();
    let mut replacements = Vec::new();
    let mut kinds = crate::hash::HashSet::default();
    for partition in partitions {
        assert!(
            kinds.insert(partition.kind),
            "one replacement per input family"
        );
        let mut incoming = HashMap::default();
        for row in partition.rows {
            assert_eq!(
                row.projection_digest.is_some(),
                partition.kind == WorkspaceInputKind::Source,
                "only source inputs own projection digests"
            );
            assert!(
                incoming.insert(row.relative_path, row).is_none(),
                "unique input paths"
            );
            assert!(
                !partition.foreign_paths.contains(row.relative_path),
                "a publisher does not supply a row it names as foreign: {}",
                row.relative_path
            );
        }
        for open in open_inputs(tx, workspace_id, lang, generation, partition.kind)? {
            if partition.foreign_paths.contains(&open.path) {
                continue;
            }
            if open.matches(incoming.get(open.path.as_str()).copied()) {
                incoming.remove(open.path.as_str());
            } else {
                closed_ids.push(open.id);
            }
        }
        replacements.extend(incoming.into_values().map(|row| (partition.kind, row)));
    }
    publish_workspace_input_changes(
        tx,
        budget,
        workspace_id,
        lang,
        generation,
        head,
        &closed_ids,
        &replacements,
        refusals,
        acquired,
    )
}

/// Allocate the revision after `head` and make it the generation's head. This
/// is the one place a workspace revision is allocated. The caller closes and
/// opens the file versions that revision carries; a file version still open
/// stays valid across it.
pub(super) fn open_workspace_revision(
    tx: &Transaction<'_>,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    head: Option<i64>,
) -> Result<i64> {
    let revision = head
        .unwrap_or(0)
        .checked_add(1)
        .expect("workspace revision fits i64");
    tx.execute(
        "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
         VALUES(?1, ?2, ?3, ?4)",
        params![workspace_id.as_str(), lang, generation.0, revision],
    )?;
    tx.execute(
        "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(workspace_id, lang, generation)
         DO UPDATE SET revision = excluded.revision",
        params![workspace_id.as_str(), lang, generation.0, revision],
    )?;
    Ok(revision)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_workspace_input_changes(
    tx: &Transaction<'_>,
    budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    workspace_id: &WorkspaceId,
    lang: &str,
    generation: GenerationId,
    head: Option<i64>,
    closed_ids: &[i64],
    replacements: &[(WorkspaceInputKind, &WorkspaceInputRow<'_>)],
    refusals: &WorkspaceRefusalChanges<'_>,
    acquired: Option<&brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView>,
) -> Result<PublishedWorkspaceInputChanges> {
    // A complete predecessor plus the explicitly published replacement decisions
    // proves completeness inductively. Unknown predecessors require one census;
    // no application counter or per-edit walk of an unchanged selected set.
    let predecessor_complete = head
        .map(|revision| {
            selected_set_complete(
                tx,
                &WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: lang.to_owned(),
                    generation,
                    revision,
                },
            )
        })
        .transpose()?
        .unwrap_or(false);
    let replacements_complete = lang != "csharp"
        || replacements.iter().all(|(kind, row)| {
            *kind != WorkspaceInputKind::Source || row.csharp_decision.is_some()
        });
    // A source-only publication carries the prior snapshot's explicitly
    // recorded config input, validated again against the new local references.
    // This is an exact revision lookup inside admission, never a head guess.
    let carried = if acquired.is_none() && lang == "rust" {
        head.map(|revision| {
            super::rust_acquired_cargo_config::selected(
                tx,
                &WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: lang.to_owned(),
                    generation,
                    revision,
                },
                &super::dependency_file_evidence::NonQueryEvidenceReadRecorder,
            )
        })
        .transpose()?
        .flatten()
    } else {
        None
    };
    let acquired = acquired.or(carried.as_ref());
    // What the previous revision's acquisition meant. Local input OIDs are not
    // part of it, so republishing an edit that keeps the meaning (a comment)
    // withdraws nothing.
    let previous_acquired_effect = if lang == "rust" {
        head.map(|revision| {
            super::rust_acquired_cargo_config::selected(
                tx,
                &WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: lang.to_owned(),
                    generation,
                    revision,
                },
                &super::dependency_file_evidence::NonQueryEvidenceReadRecorder,
            )
        })
        .transpose()?
        .flatten()
        .map(|view| view.effective_digest())
    } else {
        None
    };
    // Non-Rust and test-only snapshots may have no Cargo acquisition. They
    // publish an explicit unknown view, never an evidence set without a view.
    let unknown =
        brokk_bifrost_rust::cargo_config::acquired::RustCargoAcquiredConfigView::default();
    let effective_acquired = acquired.unwrap_or(&unknown);
    let mut inserted = HashMap::default();
    let revision = match head {
        Some(revision)
            if closed_ids.is_empty()
                && replacements.is_empty()
                && refusals.is_empty()
                && super::dependency_file_evidence::disk_evidence_identity_matches(
                    tx,
                    &WorkspaceSnapshotId {
                        workspace_id: workspace_id.clone(),
                        lang: lang.to_owned(),
                        generation,
                        revision,
                    },
                    effective_acquired,
                )? =>
        {
            revision
        }
        _ => {
            let revision = open_workspace_revision(tx, workspace_id, lang, generation, head)?;
            {
                let mut close = tx.prepare_cached(
                    "UPDATE workspace_file_versions SET valid_until = ?2
                 WHERE file_version_id = ?1 AND valid_until IS NULL",
                )?;
                for id in closed_ids {
                    assert_eq!(
                        close.execute(params![id, revision])?,
                        1,
                        "one open input version"
                    );
                }
            }
            {
                let mut insert = tx.prepare_cached(
                    "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, input_kind, rel_path, blob_oid,
                   projection_digest, valid_from, file_present
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )?;
                for (kind, row) in replacements {
                    insert.execute(params![
                        workspace_id.as_str(),
                        lang,
                        generation.0,
                        kind.label(),
                        row.relative_path,
                        row.content_oid.to_string(),
                        row.projection_digest,
                        revision,
                        row.file_present,
                    ])?;
                    let file_version_id = tx.last_insert_rowid();
                    if let Some(decision) = row.csharp_decision {
                        assert!(
                            lang == "csharp" && *kind == WorkspaceInputKind::Source,
                            "only C# source file versions carry decisions"
                        );
                        tx.execute(
                            "INSERT INTO csharp_file_version_decisions(file_version_id, decision_digest, assignment_digest)
                             VALUES(?1, ?2, ?3)",
                            params![file_version_id, decision.decision_digest.as_slice(), decision.assignment_digest.as_slice()],
                        )?;
                    }
                    inserted.insert((*kind, row.relative_path.to_owned()), file_version_id);
                }
            }
            {
                let mut close = tx.prepare_cached(
                    "UPDATE workspace_source_refusals SET valid_until = ?5
                     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                       AND rel_path = ?4 AND valid_until IS NULL",
                )?;
                for path in &refusals.closed_paths {
                    assert_eq!(
                        close.execute(params![
                            workspace_id.as_str(),
                            lang,
                            generation.0,
                            path,
                            revision
                        ])?,
                        1,
                        "one open refusal for {path}"
                    );
                }
                let mut insert = tx.prepare_cached(
                    "INSERT INTO workspace_source_refusals(
                       workspace_id, lang, generation, rel_path, blob_oid, reason, valid_from
                     ) VALUES(?1, ?2, ?3, ?4, ?5, jsonb(?6), ?7)",
                )?;
                for row in &refusals.opened {
                    insert.execute(params![
                        workspace_id.as_str(),
                        lang,
                        generation.0,
                        row.rel_path,
                        row.blob_oid.to_string(),
                        row.reason_json().to_string(),
                        revision,
                    ])?;
                }
            }
            revision
        }
    };
    let snapshot = WorkspaceSnapshotId {
        workspace_id: workspace_id.clone(),
        lang: lang.to_owned(),
        generation,
        revision,
    };
    super::dependency_file_evidence::publish_with_acquired(tx, &snapshot, effective_acquired)?;
    if lang == "rust"
        && previous_acquired_effect
            != super::rust_acquired_cargo_config::selected(
                tx,
                &snapshot,
                &super::dependency_file_evidence::NonQueryEvidenceReadRecorder,
            )?
            .map(|view| view.effective_digest())
    {
        // An edit that changes what the acquisition means, external or local,
        // withdraws the certificate and all FK-cascaded feature projections
        // before rediscovery is admitted.
        let _cascade = super::sealed_families::CascadeDelete::new(tx);
        tx.execute(
            "DELETE FROM rust_crate_reconciliations WHERE workspace_id=?1 AND generation=?2",
            params![workspace_id.as_str(), generation.get()],
        )?;
    }
    super::csharp_compilation::publish(tx, &snapshot)?;
    if lang == super::csharp_compilation::STORAGE_LANGUAGE {
        let changed = closed_ids
            .iter()
            .copied()
            .chain(inserted.values().copied())
            .collect::<Vec<_>>();
        super::csharp_compilation::extent::publish(tx, &snapshot, head, &changed, budget)?;
    }
    if predecessor_complete && replacements_complete || selected_decisions_complete(tx, &snapshot)?
    {
        tx.execute("INSERT OR IGNORE INTO workspace_selected_set_completeness(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",
            params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision])?;
    }
    Ok((snapshot, inserted))
}

/// The owner-issued selected-set certificate. Absence is Unknown, never an
/// optimistic empty set. Caller holds the publication or verification transaction.
pub(crate) fn selected_set_complete(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM workspace_selected_set_completeness WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND revision=?4)",
        params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision], |row|row.get(0))?)
}

/// A metadata-only revision preserves the selected source set. This owner
/// checks/republishes the same completeness fact before committing that revision.
pub(super) fn certify_unchanged_selected_set(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    previous: &WorkspaceSnapshotId,
) -> Result<()> {
    if selected_set_complete(tx, previous)? || selected_decisions_complete(tx, snapshot)? {
        tx.execute("INSERT OR IGNORE INTO workspace_selected_set_completeness(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision])?;
    }
    Ok(())
}

fn selected_decisions_complete(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<bool> {
    if snapshot.lang != "csharp" {
        return Ok(true);
    }
    Ok(!conn.query_row("SELECT EXISTS(SELECT 1 FROM workspace_file_versions AS files LEFT JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id=files.file_version_id WHERE files.workspace_id=?1 AND files.lang=?2 AND files.generation=?3 AND files.input_kind='source' AND files.valid_from<=?4 AND (files.valid_until IS NULL OR ?4<files.valid_until) AND decisions.file_version_id IS NULL)",
        params![snapshot.workspace_id.as_str(), snapshot.lang, snapshot.generation.get(), snapshot.revision], |row|row.get::<_,bool>(0))?)
}

/// Acquisition is part of selection identity, including external-only edits.
#[doc(hidden)]
pub fn bind_acquired_configuration_digest(
    configuration: crate::analyzer::semantic::ids::StableDigest,
    acquired: Option<[u8; 32]>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let Some(acquired) = acquired else {
        return configuration;
    };
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost.captured-configuration-with-acquired-cargo.v1",
    );
    hash.field("configuration", configuration.as_bytes());
    hash.field("acquired-cargo-config", &acquired);
    crate::analyzer::semantic::ids::StableDigest::from_array(hash.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::csharp_compilation::FileVersionDecision;
    use crate::analyzer::store::{AnalyzerStore, WorkspaceFileRow};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#10774: the stored target-root filter omitted src/bin directory targets")]
    fn selected_target_roots_filter_the_listing() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE workspace_file_versions (
            workspace_id TEXT, lang TEXT, generation INTEGER, input_kind TEXT,
            valid_from INTEGER, valid_until INTEGER, rel_path TEXT, file_present INTEGER DEFAULT 1
        );",
        )
        .unwrap();
        for path in [
            "tests/check/main.rs",
            "nested/examples/demo/main.rs",
            "tests/nested/tests/check/main.rs",
            "benches/perf/main.rs",
            "src/bin/tool/main.rs",
            "nested/src/bin/tool/main.rs",
            "src/main.rs",
            "tests/check/helper.rs",
            "tests/check/nested/main.rs",
            "examples/main.rs",
        ] {
            conn.execute(
                "INSERT INTO workspace_file_versions (workspace_id,lang,generation,input_kind,valid_from,valid_until,rel_path) VALUES ('w','rust',1,'source',1,NULL,?1)",
                [path],
            )
            .unwrap();
        }
        conn.execute("INSERT INTO workspace_file_versions (workspace_id,lang,generation,input_kind,valid_from,valid_until,rel_path) VALUES ('w','rust',1,'source',1,2,'tests/deleted/main.rs')", []).unwrap();
        conn.execute("INSERT INTO workspace_file_versions (workspace_id,lang,generation,input_kind,valid_from,valid_until,rel_path) VALUES ('w','rust',2,'source',1,NULL,'tests/future/main.rs')", []).unwrap();
        let mut stmt = conn.prepare(SELECTED_RUST_TARGET_ROOTS_SQL).unwrap();
        let paths = stmt
            .query_map(params!["w", "rust", 1, 2], |row| row.get::<_, String>(0))
            .unwrap()
            .filter(|row| {
                row.as_ref().map_or(true, |path| {
                    brokk_bifrost_core::analyzer::project::is_rust_target_layout_main(
                        std::path::Path::new(path),
                    )
                })
            })
            .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
            .unwrap();
        assert_eq!(
            paths,
            std::collections::BTreeSet::from([
                "tests/check/main.rs".to_string(),
                "nested/examples/demo/main.rs".to_string(),
                "tests/nested/tests/check/main.rs".to_string(),
                "benches/perf/main.rs".to_string(),
                "src/bin/tool/main.rs".to_string(),
                "nested/src/bin/tool/main.rs".to_string()
            ])
        );
    }

    #[hardwon(
        "#10596: a Cargo.toml left out of the listing was not captured, so crate naming fell back to directory names"
    )]
    #[test]
    fn rust_metadata_captures_an_unlisted_ancestor_manifest() {
        use crate::analyzer::{Language, ProjectFile};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("crates/app/src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(
            root.join("crates/app/Cargo.toml"),
            "[package]\nname = \"app\"\n",
        )
        .unwrap();
        std::fs::write(root.join("crates/app/src/lib.rs"), "").unwrap();
        let project =
            brokk_bifrost_core::analyzer::project::TestProject::new(root.clone(), Language::Rust);
        // Ignore rules can drop manifests from the listing while their sources
        // stay listed; the listing here holds only the source.
        let files = std::collections::BTreeSet::from([ProjectFile::new(
            root.clone(),
            "crates/app/src/lib.rs",
        )]);
        let mut inputs = std::collections::BTreeSet::new();
        WorkspaceConfigurationInput::include_native_metadata_paths(
            &project,
            &files,
            Language::Rust,
            &mut inputs,
        )
        .unwrap();
        for manifest in ["Cargo.toml", "crates/app/Cargo.toml"] {
            assert!(
                inputs.contains(&ProjectFile::new(root.clone(), manifest)),
                "{manifest} missing from {inputs:?}"
            );
        }
    }

    #[test]
    fn rust_listing_certificate_is_bound_to_revision_and_derivation() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "listing-test")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let publish = |complete| {
            store
                .sync_workspace_inputs_with_rust_listing(
                    &workspace,
                    "rust",
                    generation,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    Some(super::super::RustListingInput::new(
                        super::super::rust_source_listing_derivation_identity(),
                        if complete {
                            vec![]
                        } else {
                            vec![("x.rs".to_string(), "test".to_string())]
                        },
                    )),
                )
                .unwrap()
        };
        let snapshot = publish(true);
        assert!(
            store
                .rust_source_listing_complete(
                    &snapshot,
                    super::super::rust_source_listing_derivation_identity()
                )
                .unwrap()
        );
        assert!(
            !store
                .rust_source_listing_complete(
                    &snapshot,
                    brokk_bifrost_rust::cargo_routes::rust_source_listing_derivation_identity_before_last_token()
                )
                .unwrap()
        );
        // A different listing opens a new revision; the first keeps its own.
        let failed = publish(false);
        assert_eq!(failed.revision, snapshot.revision + 1);
        assert!(
            store
                .rust_source_listing_complete(
                    &snapshot,
                    super::super::rust_source_listing_derivation_identity()
                )
                .unwrap()
        );
        assert!(
            !store
                .rust_source_listing_complete(
                    &failed,
                    super::super::rust_source_listing_derivation_identity()
                )
                .unwrap()
        );
    }

    #[hardwon("#10321: a listing-only change rewrote the certificate of an existing revision")]
    #[test]
    fn republishing_a_certificate_keeps_the_revision_only_when_identical() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "listing-test")
            .unwrap();
        let version = super::super::rust_source_listing_derivation_identity();
        let snapshot = store
            .sync_workspace_inputs_with_rust_listing(
                &WorkspaceId("a".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                Some(super::super::RustListingInput::new(
                    version,
                    vec![("x.rs".to_string(), "test".to_string())],
                )),
            )
            .unwrap();
        let failures = vec![("x.rs".to_string(), "test".to_string())];
        assert_eq!(
            store
                .publish_rust_source_listing(
                    &snapshot,
                    super::super::RustListingInput::new(version, failures.clone()),
                    Default::default()
                )
                .unwrap(),
            snapshot,
            "an identical certificate stays at its revision"
        );
        let moved = store
            .publish_rust_source_listing(
                &snapshot,
                super::super::RustListingInput::new(version, Vec::new()),
                Default::default(),
            )
            .unwrap();
        assert_eq!(moved.revision, snapshot.revision + 1);
        assert_eq!(
            store
                .rust_source_listing_failures(&snapshot, version)
                .unwrap(),
            Some(failures),
            "the earlier revision keeps its certificate"
        );
        assert_eq!(
            store.rust_source_listing_failures(&moved, version).unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn a_bounded_tree_record_round_trips_and_certifies_by_tree_and_digest() {
        use super::super::{BoundedTreeRecord, RustListingInput};
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "bounded-listing-test")
            .unwrap();
        let version = super::super::rust_source_listing_derivation_identity();
        let summary = vec![(String::new(), "omission: BoundedTree".to_string())];
        let overlaid = |tree: u8, paths: &[&str], present: &[&str], absent: &[&str]| {
            let own = |paths: &[&str]| {
                paths
                    .iter()
                    .map(|path| path.to_string())
                    .collect::<Vec<_>>()
            };
            let (materialized, present, absent) = (own(paths), own(present), own(absent));
            BoundedTreeRecord {
                tree: vec![tree; 20],
                digest: brokk_bifrost_core::analyzer::project::BoundedTreeOmission::digest_of(
                    &materialized,
                    &present,
                    &absent,
                ),
                materialized,
                overlay_present: present,
                overlay_absent: absent,
            }
        };
        let record = |tree: u8, paths: &[&str]| overlaid(tree, paths, &[], &[]);
        let input = |record: BoundedTreeRecord| RustListingInput {
            identity: version,
            failures: summary.clone(),
            bounded: Some(record),
        };
        let first = record(1, &["Cargo.toml", "src/lib.rs"]);
        let snapshot = store
            .sync_workspace_inputs_with_rust_listing(
                &WorkspaceId("b".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                Some(input(first.clone())),
            )
            .unwrap();
        // The certificate is not complete, keeps its summary row, and returns
        // the record, with the paths, as written.
        assert!(
            !store
                .rust_source_listing_complete(&snapshot, version)
                .unwrap()
        );
        assert_eq!(
            store
                .rust_source_listing_failures(&snapshot, version)
                .unwrap(),
            Some(summary.clone())
        );
        assert_eq!(
            store
                .rust_source_listing_bounded_record(&snapshot, version)
                .unwrap(),
            Some(first.clone())
        );
        // An exact-rows certificate has no record, and neither does a stale one.
        assert_eq!(
            store
                .rust_source_listing_bounded_record(
                    &snapshot,
                    brokk_bifrost_rust::cargo_routes::rust_source_listing_derivation_identity_before_last_token()
                )
                .unwrap(),
            None
        );
        // The same tree and digest stay at their revision; a different digest
        // or a different tree opens a new one and the old record stays readable.
        let same = store
            .publish_rust_source_listing(&snapshot, input(first.clone()), Default::default())
            .unwrap();
        assert_eq!(same, snapshot);
        let other_digest = record(1, &["Cargo.toml", "src/lib.rs", "src/ops.rs"]);
        let moved = store
            .publish_rust_source_listing(&snapshot, input(other_digest.clone()), Default::default())
            .unwrap();
        assert_eq!(moved.revision, snapshot.revision + 1);
        assert_eq!(
            store
                .rust_source_listing_bounded_record(&moved, version)
                .unwrap(),
            Some(other_digest)
        );
        assert_eq!(
            store
                .rust_source_listing_bounded_record(&snapshot, version)
                .unwrap(),
            Some(first.clone())
        );
        let other_tree = record(2, &["Cargo.toml", "src/lib.rs"]);
        let retreed = store
            .publish_rust_source_listing(&moved, input(other_tree), Default::default())
            .unwrap();
        assert_eq!(retreed.revision, moved.revision + 1);
        assert!(
            store
                .rust_listing_certificates_differ(&snapshot, &retreed)
                .unwrap()
        );
        // A working-tree record keeps its overlay roles apart from the
        // materialized paths.
        let worktree = overlaid(
            2,
            &["Cargo.toml", "src/new.rs"],
            &["src/new.rs"],
            &["src/old.rs"],
        );
        let with_overlay = store
            .publish_rust_source_listing(&retreed, input(worktree.clone()), Default::default())
            .unwrap();
        assert_eq!(
            store
                .rust_source_listing_bounded_record(&with_overlay, version)
                .unwrap(),
            Some(worktree)
        );
    }

    #[test]
    fn a_bounded_listing_registration_ends_with_its_guard() {
        use brokk_bifrost_core::analyzer::project::{BoundedListingResolver, ListingUnknown};
        struct Fixed;
        impl BoundedListingResolver for Fixed {
            fn omitted_files(
                &self,
                _: &[&str],
            ) -> std::result::Result<Vec<String>, ListingUnknown> {
                Ok(vec!["fixed".to_string()])
            }
            fn dirs_with_omissions(
                &self,
                _: &[&str],
            ) -> std::result::Result<Vec<String>, ListingUnknown> {
                Ok(Vec::new())
            }
            fn changed_paths(
                &self,
                _: &dyn BoundedListingResolver,
            ) -> std::result::Result<Vec<String>, ListingUnknown> {
                Ok(Vec::new())
            }
        }
        let snapshot = |revision| WorkspaceSnapshotId {
            workspace_id: WorkspaceId("c".repeat(64)),
            lang: "rust".to_string(),
            generation: GenerationId(1),
            revision,
        };
        assert!(super::super::bounded_listing_resolver(&snapshot(7)).is_none());
        let first = super::super::register_bounded_listing_resolver(
            snapshot(7),
            std::sync::Arc::new(Fixed),
        );
        let found = super::super::bounded_listing_resolver(&snapshot(7)).expect("registered");
        assert_eq!(found.omitted_files(&[]).unwrap(), ["fixed"]);
        assert!(super::super::bounded_listing_resolver(&snapshot(8)).is_none());
        // A later registration replaces the entry, and the replaced guard
        // dropping must not remove the newer one.
        let second = super::super::register_bounded_listing_resolver(
            snapshot(7),
            std::sync::Arc::new(Fixed),
        );
        drop(first);
        assert!(super::super::bounded_listing_resolver(&snapshot(7)).is_some());
        drop(second);
        assert!(super::super::bounded_listing_resolver(&snapshot(7)).is_none());
    }

    #[hardwon(
        "#10321: a revision committed without a certificate gained one later, under readers' bindings"
    )]
    #[test]
    fn certifying_an_observable_revision_opens_a_new_one() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "listing-test")
            .unwrap();
        let version = super::super::rust_source_listing_derivation_identity();
        let observable = store
            .sync_workspace_inputs_with_rust_listing(
                &WorkspaceId("a".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .rust_source_listing_failures(&observable, version)
                .unwrap(),
            None
        );
        let certified = store
            .publish_rust_source_listing(
                &observable,
                super::super::RustListingInput::new(version, Vec::new()),
                Default::default(),
            )
            .unwrap();
        assert_eq!(certified.revision, observable.revision + 1);
        assert_eq!(
            store
                .rust_source_listing_failures(&observable, version)
                .unwrap(),
            None,
            "the revision readers could select still reads no certificate"
        );
        assert_eq!(
            store
                .rust_source_listing_failures(&certified, version)
                .unwrap(),
            Some(Vec::new())
        );
        assert!(
            store
                .rust_listing_certificates_differ(&observable, &certified)
                .unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "is written once")]
    fn writing_a_different_certificate_at_one_revision_panics() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "listing-test")
            .unwrap();
        let version = super::super::rust_source_listing_derivation_identity();
        let snapshot = store
            .sync_workspace_inputs_with_rust_listing(
                &WorkspaceId("a".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                Some(super::super::RustListingInput::new(version, Vec::new())),
            )
            .unwrap();
        store
            .execute_selection_publication(move |conn| {
                let tx = conn.transaction()?;
                super::super::write_rust_listing_certificate(
                    &tx,
                    &snapshot,
                    &super::super::RustListingInput::new(
                        version,
                        vec![("x.rs".to_string(), "test".to_string())],
                    ),
                )
            })
            .unwrap();
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9755: selected_workspace_file_versions fills parse_variant from csharp_file_version_decisions, which classification treats as C#-only"
    )]
    fn only_csharp_source_file_versions_get_decision_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let oid = |text: &str| Oid::hash_object(git2::ObjectType::Blob, text.as_bytes()).unwrap();
        for lang in ["rust", "csharp"] {
            let generation = store
                .ensure_language_epoch_value(lang, "decision-rows")
                .unwrap();
            let files =
                [("a", "fn a() {}"), ("b", "fn b() {}")].map(|(name, text)| WorkspaceFileRow {
                    rel_path: format!("src/{name}.{}", if lang == "rust" { "rs" } else { "cs" }),
                    blob_oid: oid(text),
                    decision: (lang == "csharp").then_some(FileVersionDecision {
                        decision_digest: [1; 32],
                        assignment_digest: [2; 32],
                    }),
                });
            store
                .sync_workspace_inputs_for_workspace(
                    &workspace,
                    lang,
                    generation,
                    &files,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap();
        }
        let conn = store.conn.lock().unwrap();
        let count = |lang: &str| -> i64 {
            conn.query_row(
                "SELECT count(*) FROM workspace_file_versions WHERE lang = ?1",
                [lang],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(count("rust"), 2);
        assert_eq!(count("csharp"), 2);
        let decisions: Vec<(String, String)> = conn
            .prepare(
                "SELECT versions.lang, versions.input_kind
                 FROM csharp_file_version_decisions AS decisions
                 JOIN workspace_file_versions AS versions USING(file_version_id)
                 ORDER BY versions.file_version_id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        // The C# rows prove the writer ran; no Rust file version has a row.
        assert_eq!(
            decisions,
            vec![
                ("csharp".to_owned(), "source".to_owned()),
                ("csharp".to_owned(), "source".to_owned())
            ]
        );
    }

    #[test]
    fn selected_configuration_bytes_use_indexed_revision_path_lookup() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "configuration-pin")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let inputs = (0..96)
            .map(|index| {
                WorkspaceConfigurationInput::new(
                    if index == 0 {
                        "gradle.properties".into()
                    } else {
                        format!("module{index}/gradle.properties")
                    },
                    format!("value={index}\n").into_bytes().into_boxed_slice(),
                )
            })
            .collect::<Vec<_>>();
        store
            .sync_workspace_inputs_for_workspace(
                &workspace,
                "java",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &inputs,
                &[],
                &[],
            )
            .unwrap();
        let conn = store.conn.lock().unwrap();
        let mut query =
            super::super::planner_statistics::pinned_plans::pinned("selected_configuration_bytes");
        query.params[2] = rusqlite::types::Value::Integer(generation.get());
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = super::super::planner_statistics::pinned_plans::explain_pin(&conn, &query);
            assert!(
                plan.iter().any(
                    |line| line.contains("idx_workspace_file_versions_snapshot_kind")
                        || line.contains("idx_workspace_file_versions_snapshot_path")
                ),
                "{state:?}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("SCAN versions")
                    || line.contains("SCAN retained")
                    || line.contains("AUTOMATIC")
                    || line.contains("TEMP B-TREE")),
                "{state:?}: {plan:?}"
            );
        }
    }
}

#[cfg(test)]
mod selected_set_certificate_tests {
    use super::super::{AnalyzerStore, WorkspaceFileRow};
    use super::*;

    #[test]
    fn randomized_publication_retraction_and_selection_equal_fresh() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceId::for_root(temp.path());
        let mut authored = std::collections::BTreeMap::new();
        let mut random = 0x13066_u64;
        for step in 0..160 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let path = format!("Source{}.cs", (random >> 32) % 7);
            if random & 3 == 0 {
                authored.remove(&path);
            } else {
                authored.insert(path, ((random >> 8) % 251 + 1) as u8);
            }
            let files = authored
                .iter()
                .map(|(path, byte)| WorkspaceFileRow {
                    rel_path: path.clone(),
                    blob_oid: Oid::hash_object(git2::ObjectType::Blob, &[*byte]).unwrap(),
                    decision: Some(super::super::csharp_compilation::FileVersionDecision {
                        decision_digest: [*byte; 32],
                        assignment_digest: [byte.wrapping_add(1); 32],
                    }),
                })
                .collect::<Vec<_>>();
            let publish = |store: &AnalyzerStore| {
                store
                    .sync_workspace_inputs_for_workspace(
                        &workspace,
                        "csharp",
                        GenerationId::BOOTSTRAP,
                        &files,
                        &[],
                        &[],
                        &[],
                        &[],
                        &[],
                        &[],
                        &[],
                        &[],
                    )
                    .unwrap()
            };
            let snapshot = publish(&store);
            let fresh = AnalyzerStore::open_ephemeral().unwrap();
            let fresh_snapshot = publish(&fresh);
            let paths = authored.keys().cloned().collect::<Vec<_>>();
            let read = store.begin_update_projection_read().unwrap();
            assert!(
                read.selected_set_complete(&snapshot).unwrap(),
                "step {step}"
            );
            let projected = read.selected_variants(&snapshot, &paths).unwrap();
            assert_eq!(
                projected,
                store
                    .selected_parse_variants_for_paths(&snapshot, &paths)
                    .unwrap()
            );
            assert_eq!(
                projected,
                fresh
                    .selected_parse_variants_for_paths(&fresh_snapshot, &paths)
                    .unwrap(),
                "warm/fresh at step {step}"
            );
            drop(read);
            if step % 5 == 0 && !files.is_empty() {
                let selected = snapshot.clone();
                store.execute_selection_publication(move |conn| {
                    conn.execute("DELETE FROM csharp_file_version_decisions WHERE file_version_id=(SELECT file_version_id FROM workspace_file_versions WHERE workspace_id=?1 AND lang='csharp' AND generation=0 AND valid_until IS NULL LIMIT 1)",[selected.workspace_id.as_str()]).unwrap();
                });
                let read = store.begin_update_projection_read().unwrap();
                assert!(
                    !read.selected_set_complete(&snapshot).unwrap(),
                    "retraction is Unknown"
                );
                drop(read);
                let repaired = publish(&store);
                assert!(
                    store
                        .begin_update_projection_read()
                        .unwrap()
                        .selected_set_complete(&repaired)
                        .unwrap()
                );
            }
        }
    }
}
