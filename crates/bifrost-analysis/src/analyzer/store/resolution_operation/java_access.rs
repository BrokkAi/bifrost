//! Java access refines visibility only; source/classpath coverage stays on the
//! selected binding paths. This policy retains no source collections.

use super::*;
use crate::analyzer::resolution::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    SelectedDeclarationAccessSource, SelectedTypedFactSource, TypedFactReadOutcome,
    TypedFactRequest,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

#[derive(Debug)]
pub(super) struct JavaAccessPolicy {
    pub(super) identity: SemanticId,
}

impl SelectedDeclarationAccessSource for JavaAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn visit_access_pages(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<TypedFactReadOutcome> {
        let semantics = requests
            .as_slice()
            .iter()
            .flat_map(|request| [request.reference, request.definition])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(endpoints) = facts.java_access_endpoints(&semantics, cancellation)? else {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        };
        let endpoints = endpoints
            .into_iter()
            .map(|row| (row.semantic, row))
            .collect::<HashMap<_, _>>();
        let definitions = requests
            .as_slice()
            .iter()
            .map(|request| request.definition)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut visibilities = HashMap::default();
        for chunk in definitions.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let mut collect = |rows: &[crate::analyzer::resolution::SelectedTypedRow<
                crate::analyzer::resolution::LoweredDeclarationVisibilityProperty,
            >]| {
                for row in rows {
                    assert!(
                        visibilities
                            .insert(row.row().definition(), row.row().visibility())
                            .is_none()
                    );
                }
                Ok(!cancellation.is_cancelled())
            };
            let mut nested = match visitor.resolution_session() {
                Some(session) => FactPageVisitor::with_maximum_rows_in_session(
                    &mut collect,
                    MAX_SOURCE_ROWS_PER_BATCH,
                    session,
                ),
                None => FactPageVisitor::new(&mut collect),
            };
            let outcome = facts.visit_declaration_visibility_pages_for_definitions(
                TypedFactRequest::new(chunk),
                cancellation,
                &mut nested,
            )?;
            if outcome.is_cancelled() || cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            let (terminal, completion) = outcome.into_parts();
            if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted
                || completion != ResolutionCompletion::Complete
            {
                return Err(StoreError::new(
                    "Java access visibility read did not exhaust its exact request",
                ));
            }
        }
        let mut rows = Vec::with_capacity(requests.as_slice().len());
        for request in requests.as_slice() {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            let decision = match (
                endpoints.get(&request.reference),
                endpoints.get(&request.definition),
            ) {
                (Some(reference), Some(target)) => {
                    let same_package = reference
                        .package
                        .as_ref()
                        .zip(target.package.as_ref())
                        .map(|(a, b)| a == b);
                    let same_nest = reference
                        .outermost_type
                        .zip(target.outermost_type)
                        .map(|(a, b)| a == b);
                    // Qualifier lookup owns enclosing-type accessibility.
                    // An inherited public member may be named through an
                    // accessible subtype of an inaccessible declaring class.
                    match visibilities.get(&request.definition) {
                        Some(DeclaredVisibility::Public) => DeclarationAccessDecision::Allowed,
                        Some(DeclaredVisibility::Private) => match same_nest {
                            Some(true) => DeclarationAccessDecision::Allowed,
                            Some(false) => DeclarationAccessDecision::Denied,
                            None => DeclarationAccessDecision::Unknown,
                        },
                        Some(DeclaredVisibility::PackagePrivate) => match same_package {
                            Some(true) => DeclarationAccessDecision::Allowed,
                            Some(false) => DeclarationAccessDecision::Denied,
                            None => DeclarationAccessDecision::Unknown,
                        },
                        Some(DeclaredVisibility::Protected) if same_package == Some(true) => {
                            DeclarationAccessDecision::Allowed
                        }
                        // Cross-package protected access needs subclass and
                        // qualifying receiver evidence, not import rules.
                        _ => DeclarationAccessDecision::Unknown,
                    }
                }
                _ => DeclarationAccessDecision::Unknown,
            };
            rows.push(DeclarationAccessRow {
                request: *request,
                decision,
                activation_reason: None,
            });
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else if !rows.is_empty() && !visitor.visit_page(&rows)? {
            if cancellation.is_cancelled() {
                TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
            } else {
                TypedFactReadOutcome::stopped(ResolutionCompletion::Complete)
            }
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }
}
