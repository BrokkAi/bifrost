//! Activation of imported declaration-selection documents (#5931).
//!
//! A released policy names the declarations it protects through a reviewed
//! workspace document instead of an edited copy of its own source. The
//! document is read once per policy, so every binding over it sees the same
//! bytes, and a missing, empty, malformed, wrong-kind or wrong-language
//! document fails activation instead of leaving the policy vacuously clean.

use super::*;
use crate::source::{
    PolicySelectorContext, PolicySourceDiagnostic, PolicySourceDiagnosticSeverity,
    parse_rqlp_source_with_context,
};
use brokk_bifrost_analysis::schema_version::SchemaVersionResolution;
use brokk_bifrost_analysis::workspace_document::read_workspace_document;
use brokk_bifrost_rql::query::{CodeQueryPlan, CodeQueryPlanSource, QueryStep, SetOperator};
use brokk_bifrost_rql::structural::CodeQuery;

/// One document's declarations as a single query: the union of its exact
/// selectors.
pub(super) struct LoadedDeclarationSelection {
    source: PolicySourceIdentity,
    schema: SchemaVersionResolution,
    query: CodeQuery,
}

impl PolicyRegistry {
    /// Resolve one binding over an imported selection. `None` means the
    /// registry has no workspace and the caller deferred workspace
    /// configuration, exactly as endpoint-set imports defer at the built-in
    /// catalog boundary.
    pub(super) fn resolve_declaration_selection(
        &self,
        parsed: &ParsedRqlpDocument,
        path: PolicySelectorPath,
        reference: &DeclarationSelectionReference,
        loaded: &mut HashMap<WorkspaceRelativePath, LoadedDeclarationSelection>,
        retained_bytes: &mut usize,
        locators: LocatorResolution<'_>,
    ) -> Result<Option<ResolvedPolicySelector>, PolicyRegistryError> {
        let Some(root) = self.workspace_root.as_ref() else {
            if locators.is_deferred() {
                return Ok(None);
            }
            return Err(selection_error(
                parsed,
                reference,
                "declaration-selection-import-requires-workspace",
                format!(
                    "declaration selection `{}` is workspace configuration and cannot load before activation",
                    reference.path
                ),
            ));
        };
        if !loaded.contains_key(&reference.path) {
            let selection =
                self.load_declaration_selection(root, parsed, reference, retained_bytes)?;
            loaded.insert(reference.path.clone(), selection);
        }
        let selection = &loaded[&reference.path];
        let mut query = selection.query.clone();
        match reference.output {
            DeclarationSelectionOutput::Declarations => {}
            DeclarationSelectionOutput::ProcedureEffects => {
                query.plan.steps.push(QueryStep::ProcedureEffects);
            }
        }
        Ok(Some(ResolvedPolicySelector::try_new(
            path,
            selection.schema,
            query,
            SelectorOrigin::DeclarationSelection {
                reference: reference.path.clone(),
                source: selection.source.clone(),
            },
        )?))
    }

    fn load_declaration_selection(
        &self,
        root: &WorkspaceRoot,
        parsed: &ParsedRqlpDocument,
        reference: &DeclarationSelectionReference,
        retained_bytes: &mut usize,
    ) -> Result<LoadedDeclarationSelection, PolicyRegistryError> {
        self.check_cancellation()?;
        let available = self
            .available_local_bytes(*retained_bytes)?
            .min(MAX_RQLP_SOURCE_BYTES);
        let document = read_workspace_document(
            root,
            Path::new(reference.path.as_str()),
            &["rqlp"],
            available as u64,
        )
        .map_err(|error| {
            let code = if matches!(error, WorkspaceDocumentError::TooLarge { .. }) {
                "declaration-selection-byte-limit"
            } else {
                "declaration-selection-unavailable"
            };
            selection_error(
                parsed,
                reference,
                code,
                format!(
                    "no protected declarations configured: declaration selection `{}` is unavailable: {error}",
                    reference.path
                ),
            )
        })?;
        self.charge_local(retained_bytes, document.source().len())?;
        let source = PolicySourceIdentity::new(reference.path.as_str());
        // The document is decoded with no inherited scope: its own :language
        // is its scope, and nothing from the importing policy widens it.
        let imported = parse_rqlp_source_with_context(
            document.source(),
            source.clone(),
            PolicySelectorContext::default(),
        )
        .map_err(|error| PolicyRegistryError::DeclarationSelectionImport {
            source: source.clone(),
            error: Box::new(error),
        })?;
        let RqlpDocument::DeclarationSelection { definition } = imported.document() else {
            return Err(selection_error(
                parsed,
                reference,
                "declaration-selection-wrong-document",
                format!(
                    "`{}` is not a declaration-selection document",
                    reference.path
                ),
            ));
        };
        if definition.language != reference.language {
            return Err(selection_error(
                parsed,
                reference,
                "declaration-selection-wrong-language",
                format!(
                    "declaration selection `{}` selects {} declarations, but this policy protects {} declarations",
                    reference.path,
                    definition.language.config_label(),
                    reference.language.config_label()
                ),
            ));
        }
        let [(schema, first), rest @ ..] = definition.declarations.as_slice() else {
            unreachable!("a decoded declaration selection is non-empty");
        };
        if rest
            .iter()
            .any(|(other, _)| other.version != schema.version)
        {
            return Err(selection_error(
                parsed,
                reference,
                "declaration-selection-schema-conflict",
                format!(
                    "declaration selection `{}` mixes RQL schema versions",
                    reference.path
                ),
            ));
        }
        // RQL set operations take at least two branches, so a one-entry
        // selection is that entry's query.
        let query = if rest.is_empty() {
            first.clone()
        } else {
            CodeQuery {
                schema_version: first.schema_version,
                plan: CodeQueryPlan {
                    source: CodeQueryPlanSource::Set {
                        op: SetOperator::Union,
                        branches: definition
                            .declarations
                            .iter()
                            .map(|(_, query)| query.plan.clone())
                            .collect(),
                    },
                    steps: Vec::new(),
                },
                limit: first.limit,
                result_detail: first.result_detail,
                execution_mode: first.execution_mode,
            }
        };
        Ok(LoadedDeclarationSelection {
            source,
            schema: *schema,
            query,
        })
    }
}

/// An activation failure located at the importing reference.
fn selection_error(
    parsed: &ParsedRqlpDocument,
    reference: &DeclarationSelectionReference,
    code: &'static str,
    message: String,
) -> PolicyRegistryError {
    PolicyRegistryError::DeclarationSelectionImport {
        source: parsed.identity().clone(),
        error: Box::new(PolicySourceError {
            diagnostic: PolicySourceDiagnostic {
                code,
                severity: PolicySourceDiagnosticSeverity::Error,
                message,
                range: reference.range.clone(),
                fix: None,
                related: Vec::new(),
            },
        }),
    }
}
