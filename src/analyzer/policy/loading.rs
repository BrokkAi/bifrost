//! Workspace-safe source loading seams for policy registries.
//!
//! This module stops at parsed documents, resolved RQL selectors, and
//! transactional endpoint-directory inputs. Catalog composition and final
//! [`LoadedPolicy`](super::LoadedPolicy) construction remain separate.

mod directory;
mod selector;

use std::fmt;
use std::path::Path;

use crate::analyzer::semantic::{WorkspaceRelativePath, WorkspaceRelativePathError};
use crate::workspace_document::{
    WorkspaceDocument, WorkspaceDocumentError, WorkspaceRoot, read_workspace_document,
};

use super::source::{
    MAX_RQLP_SOURCE_BYTES, ParsedRqlpDocument, PolicySourceError, PolicySourceIdentity,
    parse_rqlp_source,
};
use super::{
    LoadedEndpoint, LoadedModelError, PolicySelectorPath, PolicySelectorPathError, RqlpDocument,
};

pub(crate) use directory::{
    EndpointDirectoryError, MatchDirectoryLimitError, MatchDirectoryLimits,
    enumerate_endpoint_directory,
};
pub(crate) use selector::{ResolvedReferencedRql, SelectorLoadError, resolve_parsed_selector};

pub(crate) const MAX_POLICY_DOCUMENT_BYTES: u64 = MAX_RQLP_SOURCE_BYTES as u64;

/// One capability-read RQLP source and its parser-validated authoring model.
#[derive(Debug)]
pub(crate) struct LoadedRqlpSource {
    workspace_path: WorkspaceRelativePath,
    document: WorkspaceDocument,
    parsed: ParsedRqlpDocument,
}

impl LoadedRqlpSource {
    pub(crate) fn workspace_path(&self) -> &WorkspaceRelativePath {
        &self.workspace_path
    }

    pub(crate) fn parsed(&self) -> &ParsedRqlpDocument {
        &self.parsed
    }

    pub(crate) fn into_parts(
        self,
    ) -> (WorkspaceRelativePath, WorkspaceDocument, ParsedRqlpDocument) {
        (self.workspace_path, self.document, self.parsed)
    }
}

/// Read and parse exactly one `.rqlp` file beneath `root`.
pub(crate) fn read_rqlp_document(
    root: &WorkspaceRoot,
    relative_path: &Path,
) -> Result<LoadedRqlpSource, PolicyDocumentLoadError> {
    let document =
        read_workspace_document(root, relative_path, &["rqlp"], MAX_POLICY_DOCUMENT_BYTES)?;
    parse_workspace_rqlp_document(document)
}

/// Loaded closure of one standalone endpoint source, before any aggregate
/// dependency composition.
#[derive(Debug)]
pub(crate) struct LoadedEndpointClosure {
    endpoint: LoadedEndpoint,
    referenced_selector: Option<ResolvedReferencedRql>,
    retained_source_and_selector_bytes: usize,
}

impl LoadedEndpointClosure {
    #[cfg(test)]
    pub(crate) fn endpoint(&self) -> &LoadedEndpoint {
        &self.endpoint
    }

    #[cfg(test)]
    pub(crate) fn referenced_selector(&self) -> Option<&ResolvedReferencedRql> {
        self.referenced_selector.as_ref()
    }

    #[cfg(test)]
    pub(crate) const fn retained_source_and_selector_bytes(&self) -> usize {
        self.retained_source_and_selector_bytes
    }

    pub(crate) fn into_parts(self) -> (LoadedEndpoint, Option<ResolvedReferencedRql>, usize) {
        (
            self.endpoint,
            self.referenced_selector,
            self.retained_source_and_selector_bytes,
        )
    }
}

/// Close the selector of one parser-validated endpoint document.
///
/// `root` may be absent for byte registration only when the endpoint selector
/// is inline. The returned byte charge includes the original endpoint bytes
/// plus referenced RQL bytes, if any.
pub(crate) fn load_endpoint_closure(
    root: Option<&WorkspaceRoot>,
    parsed: ParsedRqlpDocument,
    source_bytes: &[u8],
) -> Result<LoadedEndpointClosure, EndpointClosureError> {
    let source = parsed.identity().clone();
    let schema_resolution = parsed.schema_resolution();
    let definition = match parsed.document() {
        RqlpDocument::Endpoint { definition } => definition.as_ref().clone(),
        RqlpDocument::Policy { .. } => return Err(EndpointClosureError::WrongDocumentKind),
    };
    let selector_path = PolicySelectorPath::new("/endpoint/selector")?;
    let resolved = resolve_parsed_selector(root, &parsed, selector_path, &definition.selector)?;
    let referenced_bytes = resolved
        .referenced
        .as_ref()
        .map_or(0, |reference| reference.document().source().len());
    let retained_source_and_selector_bytes = source_bytes
        .len()
        .checked_add(referenced_bytes)
        .ok_or(EndpointClosureError::RetainedByteCountOverflow)?;
    let endpoint = LoadedEndpoint::try_new(
        definition,
        source,
        source_bytes,
        schema_resolution,
        resolved.selector,
    )?;
    Ok(LoadedEndpointClosure {
        endpoint,
        referenced_selector: resolved.referenced,
        retained_source_and_selector_bytes,
    })
}

fn parse_workspace_rqlp_document(
    document: WorkspaceDocument,
) -> Result<LoadedRqlpSource, PolicyDocumentLoadError> {
    let workspace_path =
        WorkspaceRelativePath::try_from_path(document.relative_path()).map_err(|source| {
            PolicyDocumentLoadError::InvalidWorkspacePath {
                path: document.relative_path().to_path_buf(),
                source,
            }
        })?;
    let identity = PolicySourceIdentity::new(workspace_path.as_str());
    let parsed = parse_rqlp_source(document.source(), identity.clone())
        .map_err(|source| PolicyDocumentLoadError::InvalidSource { identity, source })?;
    Ok(LoadedRqlpSource {
        workspace_path,
        document,
        parsed,
    })
}

#[derive(Debug)]
pub(crate) enum PolicyDocumentLoadError {
    Workspace(WorkspaceDocumentError),
    InvalidWorkspacePath {
        path: std::path::PathBuf,
        source: WorkspaceRelativePathError,
    },
    InvalidSource {
        identity: PolicySourceIdentity,
        source: PolicySourceError,
    },
}

impl fmt::Display for PolicyDocumentLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::InvalidWorkspacePath { path, source } => write!(
                formatter,
                "invalid portable workspace path `{}`: {source}",
                path.display()
            ),
            Self::InvalidSource { identity, source } => {
                write!(formatter, "invalid RQLP document `{identity}`: {source}")
            }
        }
    }
}

impl std::error::Error for PolicyDocumentLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::InvalidWorkspacePath { source, .. } => Some(source),
            Self::InvalidSource { source, .. } => Some(source),
        }
    }
}

impl From<WorkspaceDocumentError> for PolicyDocumentLoadError {
    fn from(error: WorkspaceDocumentError) -> Self {
        Self::Workspace(error)
    }
}

#[derive(Debug)]
pub(crate) enum EndpointClosureError {
    WrongDocumentKind,
    SelectorPath(PolicySelectorPathError),
    Selector(SelectorLoadError),
    Model(LoadedModelError),
    RetainedByteCountOverflow,
}

impl fmt::Display for EndpointClosureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongDocumentKind => {
                formatter.write_str("endpoint registration requires an endpoint document")
            }
            Self::SelectorPath(error) => error.fmt(formatter),
            Self::Selector(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
            Self::RetainedByteCountOverflow => {
                formatter.write_str("endpoint retained byte count overflowed")
            }
        }
    }
}

impl std::error::Error for EndpointClosureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SelectorPath(error) => Some(error),
            Self::Selector(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::WrongDocumentKind | Self::RetainedByteCountOverflow => None,
        }
    }
}

impl From<PolicySelectorPathError> for EndpointClosureError {
    fn from(error: PolicySelectorPathError) -> Self {
        Self::SelectorPath(error)
    }
}

impl From<SelectorLoadError> for EndpointClosureError {
    fn from(error: SelectorLoadError) -> Self {
        Self::Selector(error)
    }
}

impl From<LoadedModelError> for EndpointClosureError {
    fn from(error: LoadedModelError) -> Self {
        Self::Model(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn endpoint(selector: &str) -> String {
        format!(
            "(endpoint :id \"source-a\" :name \"Source A\" :display-name \"Source A\" :role source :categories [test] :selector {selector} :binding matched-value :supersedes [])"
        )
    }

    #[test]
    fn closes_inline_endpoint_without_workspace() {
        let source = endpoint("(rql (name \"A\"))");
        let parsed =
            parse_rqlp_source(&source, PolicySourceIdentity::new("embedded:endpoint-a")).unwrap();

        let loaded = load_endpoint_closure(None, parsed, source.as_bytes()).unwrap();

        assert_eq!(loaded.endpoint().definition().id.as_str(), "source-a");
        assert!(loaded.referenced_selector().is_none());
        assert_eq!(loaded.retained_source_and_selector_bytes(), source.len());
    }

    #[test]
    fn closes_file_endpoint_and_charges_referenced_bytes() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("queries")).unwrap();
        let query = "(rql :schema-version 2 (name \"A\"))";
        fs::write(temp.path().join("queries/a.rql"), query).unwrap();
        let source = endpoint("(rql-file :schema-version 2 :path \"queries/a.rql\")");
        let parsed = parse_rqlp_source(
            &source,
            PolicySourceIdentity::new("policies/endpoint-a.rqlp"),
        )
        .unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();

        let loaded = load_endpoint_closure(Some(&root), parsed, source.as_bytes()).unwrap();

        let reference = loaded.referenced_selector().unwrap();
        assert_eq!(reference.wrapper_authored_schema_version(), Some(2));
        assert_eq!(reference.document_authored_schema_version(), Some(2));
        assert_eq!(
            loaded.retained_source_and_selector_bytes(),
            source.len() + query.len()
        );
    }

    #[test]
    fn endpoint_closure_rejects_policy_document() {
        let source = r#"(policy
          :id "policy-a"
          :name "Policy A"
          :message "Message"
          :severity warning
          :analysis (analysis :type match :selector (rql (name "A"))))"#;
        let parsed =
            parse_rqlp_source(source, PolicySourceIdentity::new("embedded:policy-a")).unwrap();

        assert!(matches!(
            load_endpoint_closure(None, parsed, source.as_bytes()),
            Err(EndpointClosureError::WrongDocumentKind)
        ));
    }
}
