//! JVM access refines visibility only; source/classpath coverage stays on the
//! selected binding paths. This policy retains no source collections.

use super::nominal_rules::nominal_language_rules;
use super::*;
use crate::analyzer::resolution::{
    CompanionTypeRelation, DeclarationAccessDecision, DeclarationAccessRequest,
    DeclarationAccessRow, FactPageVisitor, JvmAccessEndpoint, JvmDeclarationAccessRules,
    SelectedDeclarationAccessSource, SelectedTypedFactSource, SubclassAccessContext,
    TypedFactReadOutcome, TypedFactRequest, language_jvm_declaration_access_rules,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

/// One shared lexical-region membership check. Package strings are structured
/// package values, compared segment by segment rather than by a text prefix.
pub(super) fn boundary_access_decision(
    boundary: &brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary<SemanticId>,
    caller_package: Option<&str>,
    caller_templates: Option<&[SemanticId]>,
    companions: &HashSet<(SemanticId, SemanticId)>,
) -> DeclarationAccessDecision {
    use brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary;
    match boundary {
        DeclarationAccessBoundary::Package(region) => {
            let Some(package) = caller_package else {
                return DeclarationAccessDecision::Unknown;
            };
            if brokk_bifrost_core::analyzer::source_facts::PackageAccessRegion::enclosing_contains(
                region, package,
            ) {
                DeclarationAccessDecision::Allowed
            } else {
                DeclarationAccessDecision::Denied
            }
        }
        DeclarationAccessBoundary::Template(owner) => {
            let Some(templates) = caller_templates else {
                return DeclarationAccessDecision::Unknown;
            };
            if templates.iter().any(|caller| {
                caller == owner
                    || companions.contains(&(*owner, *caller))
                    || companions.contains(&(*caller, *owner))
            }) {
                DeclarationAccessDecision::Allowed
            } else {
                DeclarationAccessDecision::Denied
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct JvmAccessPolicy {
    pub(crate) identity: SemanticId,
}

// Both policy identities are stateless; canonicalize their Arc inside the
// selected operation so independently prepared file contexts can merge without
// relaxing the shared context's access-source correspondence requirement.
pub(super) type JvmAccessPolicyMemo = HashMap<SemanticId, Arc<JvmAccessPolicy>>;

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_declaration_access_source(
        &self,
        identity: SemanticId,
    ) -> Arc<dyn SelectedDeclarationAccessSource> {
        Arc::clone(
            self.jvm_access_policies
                .borrow_mut()
                .entry(identity)
                .or_insert_with(|| Arc::new(JvmAccessPolicy { identity })),
        ) as Arc<dyn SelectedDeclarationAccessSource>
    }
}

pub(super) struct JvmAccessFacts {
    visibilities:
        HashMap<SemanticId, crate::analyzer::resolution::LoweredDeclarationVisibilityProperty>,
    companions: HashSet<(SemanticId, SemanticId)>,
}

impl super::declaration_access::DeclarationAccessRules for JvmAccessPolicy {
    type Endpoint = JvmAccessEndpoint;
    type Facts = JvmAccessFacts;
    type TargetContext = ();

    fn prepare_target(&self, _target: &JvmAccessEndpoint) -> Result<()> {
        Ok(())
    }

    fn declaration_relation(
        &self,
        reference: &JvmAccessEndpoint,
        target: &JvmAccessEndpoint,
        data: &JvmAccessFacts,
        _context: &(),
    ) -> Result<Option<super::declaration_access::AccessEvidence>> {
        let reference = Some(reference);
        let property = data.visibilities.get(&target.semantic);
        let target = Some(target);
        let visibility = property.map(|property| property.visibility());
        let rules =
            target.and_then(|endpoint| language_jvm_declaration_access_rules(endpoint.language));
        let mut visibility_applies = false;
        let mut subclass_access = None;
        let decision = match (reference, target, visibility, rules) {
            (Some(_), Some(_), Some(DeclaredVisibility::Public), _) => {
                DeclarationAccessDecision::Allowed
            }
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::Private),
                Some(JvmDeclarationAccessRules::Java),
            ) => match reference.outermost_type.zip(target.outermost_type) {
                Some((caller, owner)) if caller == owner => DeclarationAccessDecision::Allowed,
                Some(_) => DeclarationAccessDecision::Denied,
                None => DeclarationAccessDecision::Unknown,
            },
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::PackagePrivate),
                Some(JvmDeclarationAccessRules::Java),
            ) => match reference.package.as_ref().zip(target.package.as_ref()) {
                Some((caller, owner)) if caller == owner => DeclarationAccessDecision::Allowed,
                Some(_) => DeclarationAccessDecision::Denied,
                None => DeclarationAccessDecision::Unknown,
            },
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::Protected),
                Some(JvmDeclarationAccessRules::Java),
            ) if reference.package == target.package => DeclarationAccessDecision::Allowed,
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::Private),
                Some(JvmDeclarationAccessRules::Scala),
            ) => {
                visibility_applies = true;
                if let Some(boundary) = property.and_then(|property| property.boundary()) {
                    boundary_access_decision(
                        boundary,
                        reference.package.as_deref(),
                        Some(&reference.enclosing_templates),
                        &data.companions,
                    )
                } else {
                    match target.enclosing_templates.first().copied() {
                        Some(owner)
                            if reference.enclosing_templates.iter().any(|caller| {
                                *caller == owner
                                    || data.companions.contains(&(owner, *caller))
                                    || data.companions.contains(&(*caller, owner))
                            }) =>
                        {
                            DeclarationAccessDecision::Allowed
                        }
                        Some(_) => DeclarationAccessDecision::Denied,
                        None => DeclarationAccessDecision::Unknown,
                    }
                }
            }
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::Protected),
                Some(JvmDeclarationAccessRules::Scala),
            ) => {
                visibility_applies = true;
                let boundary_allowed = property
                    .and_then(|property| property.boundary())
                    .is_some_and(|boundary| {
                        boundary_access_decision(
                            boundary,
                            reference.package.as_deref(),
                            Some(&reference.enclosing_templates),
                            &data.companions,
                        ) == DeclarationAccessDecision::Allowed
                    });
                if !boundary_allowed
                    && let Some(owner) = target.enclosing_templates.first().copied()
                {
                    subclass_access = Some(SubclassAccessContext {
                        enclosing_templates: reference.enclosing_templates.clone(),
                        declaration_template: owner,
                    });
                }
                if boundary_allowed {
                    DeclarationAccessDecision::Allowed
                } else {
                    DeclarationAccessDecision::Unknown
                }
            }
            (
                Some(reference),
                Some(target),
                Some(DeclaredVisibility::Protected),
                Some(JvmDeclarationAccessRules::Java),
            ) if nominal_language_rules(reference.language).is_some_and(|rules| {
                rules
                    .declaration_access_rules()
                    .protected_access_requires_qualifier_subtype()
            }) =>
            {
                visibility_applies = true;
                if let Some(owner) = target.enclosing_templates.first().copied() {
                    subclass_access = Some(SubclassAccessContext {
                        enclosing_templates: reference.enclosing_templates.clone(),
                        declaration_template: owner,
                    });
                }
                DeclarationAccessDecision::Unknown
            }
            (Some(_), Some(_), _, Some(JvmDeclarationAccessRules::Kotlin)) => {
                DeclarationAccessDecision::Unknown
            }
            _ => DeclarationAccessDecision::Unknown,
        };
        Ok(Some(super::declaration_access::AccessEvidence {
            decision,
            activation_reason: None,
            visibility_applies,
            subclass_access,
        }))
    }

    fn combine_placements(
        &self,
        answers: impl Iterator<Item = Result<super::declaration_access::AccessEvidence>>,
    ) -> Result<super::declaration_access::AccessEvidence> {
        // One selected JVM endpoint per semantic; absent endpoints stay unknown.
        let mut answers = answers.collect::<Result<Vec<_>>>()?;
        assert!(answers.len() <= 1);
        Ok(answers.pop().unwrap_or_else(|| self.unknown_reason()))
    }

    fn unknown_reason(&self) -> super::declaration_access::AccessEvidence {
        super::declaration_access::AccessEvidence {
            decision: DeclarationAccessDecision::Unknown,
            activation_reason: None,
            visibility_applies: false,
            subclass_access: None,
        }
    }
}

impl super::declaration_access::SelectedDeclarationAccessRules for JvmAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn read_endpoints(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: &[DeclarationAccessRequest],
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<super::declaration_access::AccessEndpointRead<Self::Endpoint, Self::Facts>> {
        let semantics = requests
            .iter()
            .flat_map(|request| [request.reference, request.definition])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(jvm_endpoints) = facts.jvm_access_endpoints(&semantics, cancellation)? else {
            return Ok(super::declaration_access::AccessEndpointRead::Terminal(
                TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete),
            ));
        };
        let mut endpoints = HashMap::<SemanticId, JvmAccessEndpoint>::default();
        for endpoint in jvm_endpoints {
            if nominal_language_rules(endpoint.language)
                .is_some_and(|rules| rules.has_declaration_access_endpoints())
            {
                assert!(endpoints.insert(endpoint.semantic, endpoint).is_none());
            }
        }
        let definitions = requests
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
                            .insert(row.row().definition(), row.row().clone())
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
                return Ok(super::declaration_access::AccessEndpointRead::Terminal(
                    TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete),
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
        let templates = endpoints
            .values()
            .filter(|endpoint| nominal_language_rules(endpoint.language)
                .is_some_and(|rules| rules.has_lexical_access_templates()))
            .flat_map(|endpoint| endpoint.enclosing_templates.iter().copied())
            .chain(visibilities.values().filter_map(|property| {
                match property.boundary() {
                    Some(brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary::Template(owner)) => Some(*owner),
                    _ => None,
                }
            }))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(companions) =
            self.companion_relations(facts, &templates, cancellation, visitor)?
        else {
            return Ok(super::declaration_access::AccessEndpointRead::Terminal(
                TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete),
            ));
        };
        Ok(super::declaration_access::AccessEndpointRead::Ready(
            super::declaration_access::AccessEndpoints {
                endpoints: endpoints
                    .into_iter()
                    .map(|(key, value)| (key, vec![value]))
                    .collect(),
                facts: JvmAccessFacts {
                    visibilities,
                    companions,
                },
            },
        ))
    }

    fn companion_relations(
        &self,
        facts: &dyn SelectedTypedFactSource,
        templates: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<Option<HashSet<(SemanticId, SemanticId)>>> {
        let mut companions = HashSet::default();
        for chunk in templates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let mut collect = |rows: &[crate::analyzer::resolution::SelectedTypedRow<
                CompanionTypeRelation,
            >]| {
                for row in rows {
                    companions.insert((row.row().enclosing_type(), row.row().companion_type()));
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
            let outcome = facts.visit_companion_relation_pages_for_enclosing_types(
                TypedFactRequest::new(chunk),
                cancellation,
                &mut nested,
            )?;
            if outcome.is_cancelled() || cancellation.is_cancelled() {
                return Ok(None);
            }
            let (terminal, completion) = outcome.into_parts();
            if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted
                || completion != ResolutionCompletion::Complete
            {
                return Err(StoreError::new(
                    "JVM access companion relation read did not exhaust its exact request",
                ));
            }
        }
        Ok(Some(companions))
    }

    fn declaration_activation(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _definition: SemanticId,
        cancellation: &CancellationToken,
        _session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
        Ok((!cancellation.is_cancelled()).then_some((DeclarationAccessDecision::Allowed, None)))
    }
}

impl SelectedDeclarationAccessSource for JvmAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn declaration_activation(
        &self,
        facts: &dyn SelectedTypedFactSource,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
        super::declaration_access::SelectedDeclarationAccessRules::declaration_activation(
            self,
            facts,
            definition,
            cancellation,
            session,
        )
    }

    fn qualify_selection_path(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: SemanticId,
        path: &mut crate::analyzer::resolution::PartialPath,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        super::declaration_access::SelectedDeclarationAccessRules::qualify_selection_path(
            self,
            facts,
            reference,
            path,
            cancellation,
        )
    }

    fn visit_reason_owners(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reasons: TypedFactRequest<SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, crate::analyzer::resolution::ReasonOwnerRow>,
    ) -> Result<TypedFactReadOutcome> {
        super::declaration_access::SelectedDeclarationAccessRules::visit_reason_owners(
            self,
            facts,
            reasons,
            cancellation,
            visitor,
        )
    }

    fn visit_access_pages(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<TypedFactReadOutcome> {
        super::declaration_access::visit_access_pages(self, facts, requests, cancellation, visitor)
    }
}
