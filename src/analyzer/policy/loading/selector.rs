//! Resolution of policy `rql-file` selectors through a workspace capability.

use std::fmt;
use std::ops::Range;
use std::path::Path;

use crate::analyzer::policy::{
    LoadedModelError, PolicySelector, PolicySelectorPath, ResolvedPolicySelector, SelectorOrigin,
};
use crate::analyzer::structural::CodeQuery;
use crate::analyzer::structural::query::schema::resolve_rql_schema_version;
use crate::analyzer::structural::query::sexp::{
    code_query_from_expr, validate_policy_selector_expr,
};
use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
use crate::sexp::{Expr, parse_sexp};
use crate::workspace_document::{
    WorkspaceDocument, WorkspaceDocumentError, WorkspaceRoot, read_workspace_document,
};

use super::super::source::{
    ParsedRqlpDocument, PolicySourceDiagnostic, PolicySourceDiagnosticSeverity,
    PolicySourceIdentity, PolicySourceRelatedDiagnostic, UnresolvedPolicySelectorReference,
};

const MAX_REFERENCED_RQL_BYTES: u64 = 64 * 1024;

/// A referenced query together with both authored pins and its effective version.
#[derive(Debug)]
pub(crate) struct ResolvedReferencedRql {
    document: WorkspaceDocument,
    source_identity: PolicySourceIdentity,
    wrapper_authored_schema_version: Option<u32>,
    document_authored_schema_version: Option<u32>,
    schema_resolution: SchemaVersionResolution,
    query: CodeQuery,
}

impl ResolvedReferencedRql {
    pub(crate) fn document(&self) -> &WorkspaceDocument {
        &self.document
    }

    #[cfg(test)]
    pub(crate) const fn wrapper_authored_schema_version(&self) -> Option<u32> {
        self.wrapper_authored_schema_version
    }

    #[cfg(test)]
    pub(crate) const fn document_authored_schema_version(&self) -> Option<u32> {
        self.document_authored_schema_version
    }

    #[cfg(test)]
    pub(crate) const fn schema_resolution(&self) -> SchemaVersionResolution {
        self.schema_resolution
    }
}

/// One resolved selector plus optional file-source provenance retained for the
/// registry's accounting and resolution manifest.
#[derive(Debug)]
pub(crate) struct ResolvedSelectorLoad {
    pub(crate) selector: ResolvedPolicySelector,
    pub(crate) referenced: Option<ResolvedReferencedRql>,
}

/// Resolve a selector from one already parsed policy/endpoint document.
pub(crate) fn resolve_parsed_selector(
    root: Option<&WorkspaceRoot>,
    parsed: &ParsedRqlpDocument,
    selector_path: PolicySelectorPath,
    selector: &PolicySelector,
) -> Result<ResolvedSelectorLoad, SelectorLoadError> {
    match selector {
        PolicySelector::Inline { schema, query } => {
            let selector = ResolvedPolicySelector::try_new(
                selector_path,
                *schema,
                query.clone(),
                SelectorOrigin::Document {
                    source: parsed.identity().clone(),
                },
            )?;
            Ok(ResolvedSelectorLoad {
                selector,
                referenced: None,
            })
        }
        PolicySelector::File {
            authored_schema_version,
            path,
        } => {
            let reference = parsed
                .unresolved_file_selectors()
                .iter()
                .find(|reference| {
                    reference.path == selector_path.as_str()
                        && reference.authored_schema_version == *authored_schema_version
                        && reference.workspace_path == *path
                })
                .ok_or_else(|| SelectorLoadError::MissingReference {
                    path: selector_path.clone(),
                })?;
            let root = root.ok_or_else(|| SelectorLoadError::WorkspaceRequired {
                path: selector_path.clone(),
            })?;
            let referenced = resolve_referenced_rql(root, parsed.identity(), reference)?;
            let selector = ResolvedPolicySelector::try_new(
                selector_path,
                referenced.schema_resolution,
                referenced.query.clone(),
                SelectorOrigin::ReferencedFile {
                    reference: path.clone(),
                    source: referenced.source_identity.clone(),
                    wrapper_authored_schema_version: referenced.wrapper_authored_schema_version,
                    document_authored_schema_version: referenced.document_authored_schema_version,
                },
            )?;
            Ok(ResolvedSelectorLoad {
                selector,
                referenced: Some(referenced),
            })
        }
    }
}

/// Read and decode one referenced `.rql` document.
///
/// The source is either the existing raw query form or exactly the explicit
/// envelope `(rql :schema-version N QUERY)`. The document pin determines
/// provenance whenever present, including when an equal wrapper pin agrees.
pub(crate) fn resolve_referenced_rql(
    root: &WorkspaceRoot,
    referrer: &PolicySourceIdentity,
    reference: &UnresolvedPolicySelectorReference,
) -> Result<ResolvedReferencedRql, ReferencedRqlError> {
    let document = read_workspace_document(
        root,
        Path::new(reference.workspace_path.as_str()),
        &["rql"],
        MAX_REFERENCED_RQL_BYTES,
    )
    .map_err(|source| ReferencedRqlError::Workspace {
        referrer: referrer.clone(),
        reference_range: reference.range.clone(),
        source,
    })?;
    let source_identity = PolicySourceIdentity::new(reference.workspace_path.as_str());
    let parsed = parse_sexp(document.source()).map_err(|error| {
        source_error(
            "invalid-referenced-rql-s-expression",
            source_identity.clone(),
            error.range,
            error.message,
            referrer,
            &reference.range,
        )
    })?;
    if let Some(error) = parsed.incomplete {
        return Err(source_error(
            "incomplete-referenced-rql",
            source_identity,
            error.range,
            error.message,
            referrer,
            &reference.range,
        ));
    }
    let expr = parsed.expr.ok_or_else(|| {
        source_error(
            "missing-referenced-rql-query",
            source_identity.clone(),
            document.source().len()..document.source().len(),
            "expected one RQL query expression",
            referrer,
            &reference.range,
        )
    })?;
    let decoded = decode_referenced_rql_document(&expr).map_err(|error| {
        source_error(
            error.code,
            source_identity.clone(),
            error.range,
            error.message,
            referrer,
            &reference.range,
        )
    })?;

    if let (Some(wrapper), Some(document_version)) = (
        reference.authored_schema_version,
        decoded.authored_schema_version,
    ) && wrapper != document_version
    {
        return Err(source_error(
            "conflicting-rql-schema-version",
            source_identity,
            decoded
                .schema_version_range
                .unwrap_or_else(|| expr.range.clone()),
            format!(
                "rql-file wrapper pins schema version {wrapper}, but referenced document pins {document_version}"
            ),
            referrer,
            &reference.range,
        ));
    }

    let mut schema_resolution = match (
        reference.authored_schema_version,
        decoded.authored_schema_version,
    ) {
        (_, Some(version)) => resolve_rql_schema_version(Some(version)).map_err(|error| {
            source_error(
                "unsupported-rql-schema-version",
                source_identity.clone(),
                decoded
                    .schema_version_range
                    .clone()
                    .unwrap_or_else(|| expr.range.clone()),
                error.to_string(),
                referrer,
                &reference.range,
            )
        })?,
        (Some(version), None) => resolve_rql_schema_version(Some(version)).map_err(|error| {
            source_error(
                "unsupported-rql-schema-version",
                source_identity.clone(),
                expr.range.clone(),
                error.to_string(),
                referrer,
                &reference.range,
            )
        })?,
        (None, None) => resolve_rql_schema_version(None)
            .expect("the compiled-in RQL schema lineage has an implicit head"),
    };
    if decoded.authored_schema_version.is_some() {
        schema_resolution.origin = SchemaVersionOrigin::ReferencedDocumentExplicit;
    }

    validate_policy_selector_expr(decoded.query).map_err(|error| {
        source_error(
            "query-output-control-not-allowed",
            source_identity.clone(),
            error.range,
            error.message,
            referrer,
            &reference.range,
        )
    })?;
    let query = code_query_from_expr(decoded.query, schema_resolution).map_err(|error| {
        let message = error.to_string();
        source_error(
            "invalid-referenced-rql",
            source_identity.clone(),
            error.range,
            message,
            referrer,
            &reference.range,
        )
    })?;

    Ok(ResolvedReferencedRql {
        document,
        source_identity,
        wrapper_authored_schema_version: reference.authored_schema_version,
        document_authored_schema_version: decoded.authored_schema_version,
        schema_resolution,
        query,
    })
}

struct DecodedReferencedRql<'a> {
    authored_schema_version: Option<u32>,
    schema_version_range: Option<Range<usize>>,
    query: &'a Expr,
}

fn decode_referenced_rql_document(
    expr: &Expr,
) -> Result<DecodedReferencedRql<'_>, ReferencedDocumentShapeError> {
    let Some(items) = expr.as_list() else {
        return Ok(DecodedReferencedRql {
            authored_schema_version: None,
            schema_version_range: None,
            query: expr,
        });
    };
    if items.first().and_then(Expr::as_symbol) != Some("rql") {
        return Ok(DecodedReferencedRql {
            authored_schema_version: None,
            schema_version_range: None,
            query: expr,
        });
    }
    if items.len() != 4 || items.get(1).and_then(Expr::as_symbol) != Some(":schema-version") {
        return Err(ReferencedDocumentShapeError {
            code: "invalid-rql-document-envelope",
            range: expr.range.clone(),
            message: "RQL document envelope must be exactly `(rql :schema-version N QUERY)`"
                .to_string(),
        });
    }
    let version_expr = &items[2];
    let version = version_expr
        .as_number()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ReferencedDocumentShapeError {
            code: "invalid-rql-document-schema-version",
            range: version_expr.range.clone(),
            message: "RQL document schema version must be an unsigned 32-bit integer".to_string(),
        })?;
    Ok(DecodedReferencedRql {
        authored_schema_version: Some(version),
        schema_version_range: Some(version_expr.range.clone()),
        query: &items[3],
    })
}

struct ReferencedDocumentShapeError {
    code: &'static str,
    range: Range<usize>,
    message: String,
}

fn source_error(
    code: &'static str,
    source: PolicySourceIdentity,
    range: Range<usize>,
    message: impl Into<String>,
    referrer: &PolicySourceIdentity,
    reference_range: &Range<usize>,
) -> ReferencedRqlError {
    ReferencedRqlError::Source {
        source,
        diagnostic: PolicySourceDiagnostic {
            code,
            severity: PolicySourceDiagnosticSeverity::Error,
            message: message.into(),
            range,
            fix: None,
            related: vec![PolicySourceRelatedDiagnostic {
                source: referrer.clone(),
                range: reference_range.clone(),
                message: "referenced by this rql-file selector".to_string(),
            }],
        },
    }
}

#[derive(Debug)]
pub(crate) enum ReferencedRqlError {
    Workspace {
        referrer: PolicySourceIdentity,
        reference_range: Range<usize>,
        source: WorkspaceDocumentError,
    },
    Source {
        source: PolicySourceIdentity,
        diagnostic: PolicySourceDiagnostic,
    },
}

impl fmt::Display for ReferencedRqlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace {
                referrer,
                reference_range,
                source,
            } => write!(
                formatter,
                "failed to load RQL referenced by `{referrer}` at bytes {}..{}: {source}",
                reference_range.start, reference_range.end
            ),
            Self::Source { source, diagnostic } => {
                write!(
                    formatter,
                    "invalid referenced RQL `{source}`: {}",
                    diagnostic.message
                )
            }
        }
    }
}

impl std::error::Error for ReferencedRqlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace { source, .. } => Some(source),
            Self::Source { .. } => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum SelectorLoadError {
    MissingReference { path: PolicySelectorPath },
    WorkspaceRequired { path: PolicySelectorPath },
    Referenced(ReferencedRqlError),
    Model(LoadedModelError),
}

impl fmt::Display for SelectorLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingReference { path } => {
                write!(
                    formatter,
                    "parsed source is missing file-selector provenance for {path}"
                )
            }
            Self::WorkspaceRequired { path } => {
                write!(formatter, "selector {path} requires a workspace root")
            }
            Self::Referenced(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SelectorLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Referenced(error) => Some(error),
            Self::Model(error) => Some(error),
            Self::MissingReference { .. } | Self::WorkspaceRequired { .. } => None,
        }
    }
}

impl From<ReferencedRqlError> for SelectorLoadError {
    fn from(error: ReferencedRqlError) -> Self {
        Self::Referenced(error)
    }
}

impl From<LoadedModelError> for SelectorLoadError {
    fn from(error: LoadedModelError) -> Self {
        Self::Model(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use std::fs;
    use tempfile::TempDir;

    fn reference(wrapper: Option<u32>) -> UnresolvedPolicySelectorReference {
        UnresolvedPolicySelectorReference {
            path: "/analysis/selector".to_string(),
            authored_schema_version: wrapper,
            workspace_path: WorkspaceRelativePath::new("queries/query.rql").unwrap(),
            range: 12..42,
        }
    }

    fn resolve(
        source: &str,
        wrapper: Option<u32>,
    ) -> Result<ResolvedReferencedRql, ReferencedRqlError> {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("queries")).unwrap();
        fs::write(temp.path().join("queries/query.rql"), source).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        resolve_referenced_rql(
            &root,
            &PolicySourceIdentity::new("policies/root.rqlp"),
            &reference(wrapper),
        )
    }

    #[test]
    fn resolves_all_wrapper_document_version_precedence_cases() {
        let neither = resolve("(name \"A\")", None).unwrap();
        assert_eq!(neither.wrapper_authored_schema_version(), None);
        assert_eq!(neither.document_authored_schema_version(), None);
        assert_eq!(
            neither.schema_resolution(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::ImplicitCompatible,
            }
        );

        let wrapper = resolve("(name \"A\")", Some(2)).unwrap();
        assert_eq!(wrapper.wrapper_authored_schema_version(), Some(2));
        assert_eq!(wrapper.document_authored_schema_version(), None);
        assert_eq!(
            wrapper.schema_resolution().origin,
            SchemaVersionOrigin::Explicit
        );

        let document = resolve("(rql :schema-version 2 (name \"A\"))", None).unwrap();
        assert_eq!(document.wrapper_authored_schema_version(), None);
        assert_eq!(document.document_authored_schema_version(), Some(2));
        assert_eq!(
            document.schema_resolution().origin,
            SchemaVersionOrigin::ReferencedDocumentExplicit
        );

        let agreeing = resolve("(rql :schema-version 2 (name \"A\"))", Some(2)).unwrap();
        assert_eq!(agreeing.wrapper_authored_schema_version(), Some(2));
        assert_eq!(agreeing.document_authored_schema_version(), Some(2));
        assert_eq!(
            agreeing.schema_resolution().origin,
            SchemaVersionOrigin::ReferencedDocumentExplicit
        );
    }

    #[test]
    fn conflict_precedes_unsupported_document_version() {
        let error = resolve("(rql :schema-version 3 (name \"A\"))", Some(2)).unwrap_err();
        let ReferencedRqlError::Source { diagnostic, .. } = error else {
            panic!("expected source diagnostic");
        };
        assert_eq!(diagnostic.code, "conflicting-rql-schema-version");
        assert_eq!(diagnostic.range, 21..22);
        assert_eq!(diagnostic.related[0].source.as_str(), "policies/root.rqlp");
        assert_eq!(diagnostic.related[0].range, 12..42);
    }

    #[test]
    fn rejects_non_exact_envelope_and_policy_output_controls() {
        let envelope = resolve("(rql (name \"A\"))", None).unwrap_err();
        let ReferencedRqlError::Source { diagnostic, .. } = envelope else {
            panic!("expected source diagnostic");
        };
        assert_eq!(diagnostic.code, "invalid-rql-document-envelope");

        let output_control = resolve("(limit 1 (name \"A\"))", None).unwrap_err();
        let ReferencedRqlError::Source { diagnostic, .. } = output_control else {
            panic!("expected source diagnostic");
        };
        assert_eq!(diagnostic.code, "query-output-control-not-allowed");
        assert_eq!(diagnostic.range, 1..6);
    }
}
