//! Explicit source-tree JDK selection shared by every workspace host.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::analyzer::JvmSourceToolchainBinding;
use crate::workspace_document::{
    WorkspaceDocumentError, WorkspaceRoot, read_workspace_document,
    validate_workspace_relative_path,
};

pub(crate) const DOCUMENT_PATH: &str = ".bifrost/jvm-toolchains.json";

const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolchainsDocument {
    schema_version: u32,
    source_toolchains: Vec<SourceToolchain>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceToolchain {
    source_root: String,
    jdk_home: PathBuf,
}

pub(crate) fn load_source_toolchains(
    workspace_root: &Path,
) -> Result<Vec<JvmSourceToolchainBinding>, String> {
    let root = WorkspaceRoot::open(workspace_root).map_err(|error| error.to_string())?;
    let document = match read_workspace_document(
        &root,
        Path::new(DOCUMENT_PATH),
        &["json"],
        MAX_DOCUMENT_BYTES as u64,
    ) {
        Ok(document) => document,
        Err(WorkspaceDocumentError::OpenFile { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error.to_string()),
    };
    parse_source_toolchains_bytes(document.source().as_bytes())
        .map_err(|error| format!("invalid {DOCUMENT_PATH}: {error}"))
}

/// Parse exact selected document bytes without consulting the workspace or JDK.
/// The returned paths are bindings, not evidence of the JDK artifact contents.
pub(crate) fn parse_source_toolchains_bytes(
    source: &[u8],
) -> Result<Vec<JvmSourceToolchainBinding>, String> {
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "toolchain document exceeds {MAX_DOCUMENT_BYTES} bytes"
        ));
    }
    let source = std::str::from_utf8(source).map_err(|error| error.to_string())?;
    parse_source_toolchains(source)
}

fn parse_source_toolchains(source: &str) -> Result<Vec<JvmSourceToolchainBinding>, String> {
    let document: ToolchainsDocument =
        serde_json::from_str(source).map_err(|error| error.to_string())?;
    if document.schema_version != 1 {
        return Err(format!(
            "unsupported schema_version {}",
            document.schema_version
        ));
    }
    if document.source_toolchains.len() > 128 {
        return Err("source_toolchains exceeds 128 bindings".to_owned());
    }
    document
        .source_toolchains
        .into_iter()
        .map(|binding| {
            // A dot explicitly binds the entire workspace. All other roots
            // use the same portable relative-path rules as workspace files.
            let source_root = if binding.source_root == "." {
                PathBuf::new()
            } else {
                validate_workspace_relative_path(Path::new(&binding.source_root))
                    .map_err(|error| error.to_string())?
            };
            if binding.jdk_home.as_os_str().is_empty() {
                return Err("jdk_home must name a JDK installation".to_owned());
            }
            Ok(JvmSourceToolchainBinding::new(
                source_root,
                binding.jdk_home,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        JvmSourceToolchainSelectionOpen, JvmStandardLibraryDiscoveryConfig, ProjectFile,
    };

    #[test]
    fn selected_toolchain_bytes_enforce_document_bounds_and_preserve_bindings() {
        let source = br#"{"schema_version":1,"source_toolchains":[{"source_root":"old","jdk_home":"jdks/21"}]}"#;
        let config = JvmStandardLibraryDiscoveryConfig {
            source_toolchains: parse_source_toolchains_bytes(source).unwrap(),
            ..Default::default()
        };
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            config.selected_jdk_home_for_file(&ProjectFile::new(root.path(), "old/App.java")),
            Ok(Path::new("jdks/21"))
        );
        assert!(parse_source_toolchains_bytes(b"\xff").is_err());
        let mut oversized = source.to_vec();
        oversized.resize(MAX_DOCUMENT_BYTES + 1, b' ');
        assert!(parse_source_toolchains_bytes(&oversized).is_err());
        oversized.truncate(MAX_DOCUMENT_BYTES);
        assert!(parse_source_toolchains_bytes(&oversized).is_ok());
    }

    #[test]
    fn document_preserves_specific_and_conflicting_source_bindings() {
        let bindings = parse_source_toolchains(
            r#"{
            "schema_version": 1,
            "source_toolchains": [
                {"source_root": ".", "jdk_home": "jdks/21"},
                {"source_root": "next", "jdk_home": "jdks/22"},
                {"source_root": "conflict", "jdk_home": "jdks/21"},
                {"source_root": "conflict", "jdk_home": "jdks/22"}
            ]
        }"#,
        )
        .expect("valid toolchain document");
        let config = JvmStandardLibraryDiscoveryConfig {
            source_toolchains: bindings,
            ..Default::default()
        };
        let root = tempfile::tempdir().expect("workspace");
        for (path, home) in [("App.java", "jdks/21"), ("next/App.java", "jdks/22")] {
            assert_eq!(
                config.selected_jdk_home_for_file(&ProjectFile::new(root.path(), path)),
                Ok(Path::new(home))
            );
        }
        assert_eq!(
            config.selected_jdk_home_for_file(&ProjectFile::new(root.path(), "conflict/App.java")),
            Err(JvmSourceToolchainSelectionOpen::ConflictingBindings)
        );
    }

    #[test]
    fn invalid_toolchain_document_is_an_error() {
        for source in [
            r#"{"schema_version":2,"source_toolchains":[]}"#,
            r#"{"schema_version":1,"source_toolchains":[{"source_root":"../outside","jdk_home":"jdk"}]}"#,
            r#"{"schema_version":1,"source_toolchains":[{"source_root":".","jdk_home":""}]}"#,
            r#"{"schema_version":1,"source_toolchains":[],"typo":true}"#,
        ] {
            assert!(parse_source_toolchains(source).is_err(), "{source}");
        }
    }
}
