//! The content-addressed (module, stage) artifact store.
//!
//! Every stage's output for a module is one file in the foundry work directory.
//! The file's identity is the hash of the stage's inputs: the module, the stage
//! id, the stage code version, the prompt version, the pinned source slice
//! digest, and the upstream artifact's key. A re-run recomputes that key; when
//! it matches the stored key the artifact is reused and the stage never runs.
//! That is the whole resumability and selective-invalidation substrate the
//! foundry driver rides on:
//!
//! * an interrupted run resumes at no cost, because every finished stage already
//!   has a matching artifact and only the unfinished tail re-runs;
//! * editing one stage (for example a prompt) changes exactly that stage's key
//!   and, through the upstream-key chain, every stage downstream of it, and
//!   nothing upstream.
//!
//! The file lives at a stable logical path (`<module>/<stage>.json`) and records
//! its own key inside, rather than being named by the key. That choice is
//! deliberate: it keeps the work directory git-committable so that reviewing an
//! artifact and diffing it edition-over-edition are the same `git diff`, which a
//! key-named file could not do because its name would churn on every input
//! change. The key still governs reuse; it is a field, not the file name.
//!
//! Writes are atomic (temp file plus rename), so a process killed mid-write
//! never leaves a half-written artifact that a later run could mistake for a
//! finished stage.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The report format tag. Bump it when a consumer must read the artifact file
/// differently, not when a payload field is added.
pub const FOUNDRY_ARTIFACT_FORMAT: &str = "bifrost_summary_foundry_artifact/v1";

/// One stdlib namespace, for example `java/lang` or `os`.
///
/// A module id is the class-file directory of the targets it groups, spelled
/// with forward slashes so it is stable across operating systems. Its path
/// components name a subdirectory of the store, so they are validated to hold no
/// traversal segment: a module id is derived from a trusted artifact path, and a
/// segment that could climb out of the store is a construction bug, not a state
/// to recover from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModuleId(String);

impl ModuleId {
    /// Build a module id from a forward-slash namespace path.
    ///
    /// Panics on a traversal or empty segment, per the house rule of failing at
    /// the construction point rather than passing corrupted state on.
    pub fn new(path: impl Into<String>) -> Self {
        let path = path.into();
        assert!(!path.is_empty(), "a module id must not be empty");
        for segment in path.split('/') {
            assert!(
                !segment.is_empty() && segment != "." && segment != ".." && !segment.contains('\\'),
                "module id `{path}` has an unsafe path segment `{segment}`"
            );
        }
        Self(path)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The store subdirectory for this module, joined component by component so
    /// the separator is the host's.
    fn relative_dir(&self) -> PathBuf {
        let mut dir = PathBuf::new();
        for segment in self.0.split('/') {
            dir.push(segment);
        }
        dir
    }
}

/// The inputs that fix one stage artifact's identity.
///
/// The key is a pure function of these fields, so two runs with the same inputs
/// compute the same key and the second reuses the first's artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StageKeyInputs<'a> {
    pub module: &'a ModuleId,
    pub stage: &'a str,
    pub stage_code_version: u32,
    /// Present only for a stage whose output depends on a prompt, which is
    /// adjudication today. A stage with no prompt records `None`, so a prompt
    /// bump cannot change its key.
    pub prompt_version: Option<u32>,
    pub source_slice_digest: &'a str,
    /// The key of the artifact this stage consumes, or `None` for the first
    /// stage. Chaining on the upstream key is what makes a change to one stage
    /// invalidate every stage downstream and nothing upstream.
    pub upstream_key: Option<&'a str>,
}

impl StageKeyInputs<'_> {
    /// The content-addressed key: the hex SHA-256 of the canonical JSON of these
    /// inputs. Canonical JSON sorts object keys, so the digest is stable.
    pub fn key(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("stage key inputs are serializable");
        let mut digest = Sha256::new();
        digest.update(&canonical);
        hex(&digest.finalize())
    }
}

/// One stored (module, stage) artifact, as human-readable JSON.
///
/// The envelope records the key material beside the key, so a reader sees why an
/// artifact has the identity it has, and the store can assert on load that the
/// recorded key still hashes from its recorded material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageArtifact {
    pub format: String,
    pub module: ModuleId,
    pub stage: String,
    pub key: String,
    pub stage_code_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_version: Option<u32>,
    pub source_slice_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_key: Option<String>,
    /// The stage's output. Any serializable stage payload fits, and it stays
    /// legible because the store never opaquely encodes it.
    pub payload: serde_json::Value,
}

impl StageArtifact {
    /// Assemble an artifact from its key inputs and a payload.
    pub fn new(inputs: &StageKeyInputs<'_>, payload: serde_json::Value) -> Self {
        Self {
            format: FOUNDRY_ARTIFACT_FORMAT.to_owned(),
            module: inputs.module.clone(),
            stage: inputs.stage.to_owned(),
            key: inputs.key(),
            stage_code_version: inputs.stage_code_version,
            prompt_version: inputs.prompt_version,
            source_slice_digest: inputs.source_slice_digest.to_owned(),
            upstream_key: inputs.upstream_key.map(ToOwned::to_owned),
            payload,
        }
    }
}

/// A failure of the store itself, never a verdict about a stage.
#[derive(Debug)]
pub enum StoreError {
    Io { path: PathBuf, error: io::Error },
    Corrupt { path: PathBuf, message: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, error } => {
                write!(formatter, "store io error at {}: {error}", path.display())
            }
            Self::Corrupt { path, message } => {
                write!(
                    formatter,
                    "corrupt artifact at {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// The content-addressed foundry work directory.
#[derive(Debug, Clone)]
pub struct FoundryStore {
    root: PathBuf,
}

impl FoundryStore {
    /// Open (or adopt) a work directory as the store root.
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn artifact_path(&self, module: &ModuleId, stage: &str) -> PathBuf {
        self.root
            .join(module.relative_dir())
            .join(format!("{stage}.json"))
    }

    /// Load the artifact stored for one (module, stage), if any.
    ///
    /// A file whose recorded key does not hash from its own recorded material is
    /// a corrupt artifact and is reported, not silently discarded: the store is
    /// git-committable, so a mismatch is a review signal.
    pub fn load(
        &self,
        module: &ModuleId,
        stage: &str,
    ) -> Result<Option<StageArtifact>, StoreError> {
        let path = self.artifact_path(module, stage);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::Io { path, error }),
        };
        let artifact: StageArtifact =
            serde_json::from_slice(&bytes).map_err(|error| StoreError::Corrupt {
                path: path.clone(),
                message: error.to_string(),
            })?;
        let recomputed = StageKeyInputs {
            module: &artifact.module,
            stage: &artifact.stage,
            stage_code_version: artifact.stage_code_version,
            prompt_version: artifact.prompt_version,
            source_slice_digest: &artifact.source_slice_digest,
            upstream_key: artifact.upstream_key.as_deref(),
        }
        .key();
        if recomputed != artifact.key {
            return Err(StoreError::Corrupt {
                path,
                message: format!(
                    "recorded key {} does not match its material (hashes to {recomputed})",
                    artifact.key
                ),
            });
        }
        Ok(Some(artifact))
    }

    /// Write an artifact atomically to its logical path.
    pub fn store(&self, artifact: &StageArtifact) -> Result<(), StoreError> {
        let path = self.artifact_path(&artifact.module, &artifact.stage);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| StoreError::Io {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        let mut rendered =
            serde_json::to_string_pretty(artifact).expect("a stage artifact is serializable");
        rendered.push('\n');
        write_atomic(&path, rendered.as_bytes())
    }
}

/// Write bytes to `path` through a sibling temp file and a rename, so a reader
/// never observes a partial write. The rename replaces on Unix; on Windows a
/// pre-existing destination is removed first, which is the documented way to get
/// a replacing rename there.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, bytes).map_err(|error| StoreError::Io {
        path: temp.clone(),
        error,
    })?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(_) if path.exists() => {
            fs::remove_file(path).map_err(|error| StoreError::Io {
                path: path.to_path_buf(),
                error,
            })?;
            fs::rename(&temp, path).map_err(|error| StoreError::Io {
                path: path.to_path_buf(),
                error,
            })
        }
        Err(error) => Err(StoreError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

/// The lowercase hex of a digest.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(rendered, "{byte:02x}").expect("writing to a String cannot fail");
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> (tempfile::TempDir, FoundryStore) {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        (directory, store)
    }

    fn inputs<'a>(
        module: &'a ModuleId,
        stage: &'a str,
        prompt: Option<u32>,
        upstream: Option<&'a str>,
    ) -> StageKeyInputs<'a> {
        StageKeyInputs {
            module,
            stage,
            stage_code_version: 1,
            prompt_version: prompt,
            source_slice_digest: "abc123",
            upstream_key: upstream,
        }
    }

    #[test]
    fn a_key_is_a_pure_function_of_its_inputs() {
        let module = ModuleId::new("java/util");
        let first = inputs(&module, "join", None, Some("up")).key();
        let second = inputs(&module, "join", None, Some("up")).key();
        assert_eq!(first, second);
    }

    #[test]
    fn changing_any_input_changes_the_key() {
        let module = ModuleId::new("java/util");
        let base = inputs(&module, "adjudicate", Some(1), Some("up")).key();

        let other_module = ModuleId::new("java/lang");
        assert_ne!(
            base,
            inputs(&other_module, "adjudicate", Some(1), Some("up")).key()
        );
        assert_ne!(base, inputs(&module, "fixture", Some(1), Some("up")).key());
        assert_ne!(
            base,
            inputs(&module, "adjudicate", Some(2), Some("up")).key()
        );
        assert_ne!(
            base,
            inputs(&module, "adjudicate", Some(1), Some("down")).key()
        );
        let mut bumped = inputs(&module, "adjudicate", Some(1), Some("up"));
        bumped.stage_code_version = 2;
        assert_ne!(base, bumped.key());
        let mut redigested = inputs(&module, "adjudicate", Some(1), Some("up"));
        redigested.source_slice_digest = "def456";
        assert_ne!(base, redigested.key());
    }

    #[test]
    fn a_stored_artifact_round_trips_and_reuses_on_a_matching_key() {
        let (_directory, store) = store();
        let module = ModuleId::new("java/util");
        let artifact = StageArtifact::new(&inputs(&module, "join", None, None), json!({"a": 1}));
        store.store(&artifact).expect("the artifact stores");

        let loaded = store
            .load(&module, "join")
            .expect("the artifact loads")
            .expect("the artifact is present");
        assert_eq!(loaded, artifact);
        assert_eq!(loaded.key, inputs(&module, "join", None, None).key());
    }

    #[test]
    fn an_absent_artifact_loads_as_none() {
        let (_directory, store) = store();
        let module = ModuleId::new("java/util");
        assert_eq!(store.load(&module, "join").expect("no io error"), None);
    }

    #[test]
    fn a_tampered_key_is_reported_as_corrupt() {
        let (_directory, store) = store();
        let module = ModuleId::new("java/util");
        let mut artifact =
            StageArtifact::new(&inputs(&module, "join", None, None), json!({"a": 1}));
        artifact.key = "deadbeef".to_owned();
        // Bypass `store()` so the on-disk key is inconsistent with its material.
        let path = store.artifact_path(&module, "join");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();

        let error = store
            .load(&module, "join")
            .expect_err("corruption is reported");
        assert!(matches!(error, StoreError::Corrupt { .. }), "{error}");
    }

    #[test]
    fn a_module_id_rejects_a_traversal_segment() {
        assert!(std::panic::catch_unwind(|| ModuleId::new("java/../etc")).is_err());
    }
}
