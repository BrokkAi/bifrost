//! C# private access is a case of the shared declaration-access rules. Other
//! visibility forms retain their existing open evidence until general access.
use super::declaration_access::{
    AccessEndpointRead, AccessEndpoints, AccessEvidence, DeclarationAccessRules,
    SelectedDeclarationAccessRules,
};
use super::*;
use crate::analyzer::resolution::fact_source::{
    DeclarationAccessContext, PreparedDeclarationAccessContext, SelectedAccessDeclaration,
    SelectedAccessReference,
};
use crate::analyzer::resolution::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    SelectedDeclarationAccessSource, SelectedTypedFactSource, TypedFactReadOutcome,
    TypedFactRequest,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

pub(super) fn with_declaration_access(
    ready: &ReadySelectedResolution<'_, '_>,
    blueprint: crate::analyzer::resolution::SelectedFactOperationBlueprint,
) -> crate::analyzer::resolution::SelectedFactOperationBlueprint {
    blueprint.with_declaration_access_source(Arc::new(CSharpAccessPolicy {
        identity: ready.context_identities.named_semantic(
            CanonicalHasher::new(b"csharp-private-access-unknown:v1").finish(),
            "csharp_private_access_unknown",
            crate::analyzer::resolution::ReasonDeterminism::Unaudited,
            "private declaration access lacks complete ordinary nonpartial source authority",
        ),
    }))
}

pub(super) struct CSharpAccessPolicy {
    pub(super) identity: SemanticId,
}

pub(super) struct Caller {
    reference: SelectedAccessReference,
    context: DeclarationAccessContext,
    containing_types: Vec<SemanticId>,
}
pub(super) enum Endpoint {
    Caller(Option<Caller>),
    Target {
        declaration: SelectedAccessDeclaration,
        owner: Option<SelectedAccessDeclaration>,
    },
}

impl CSharpAccessPolicy {
    fn nonmember(declaration: &SelectedAccessDeclaration) -> bool {
        use crate::analyzer::DeclarationKind;
        declaration.source.language == Language::CSharp
            && matches!(
                declaration.lexical_kind,
                Some(
                    DeclarationKind::Parameter
                        | DeclarationKind::TypeParameter
                        | DeclarationKind::LocalVariable
                        | DeclarationKind::PatternVariable
                        | DeclarationKind::BlockLocalItem
                )
            )
    }

    fn known_nonprivate(declaration: &SelectedAccessDeclaration) -> bool {
        declaration.visibility.is_some_and(|visibility| {
            visibility != DeclaredVisibility::Private && visibility != DeclaredVisibility::Unknown
        })
    }

    fn refuse(&self, facts: &dyn SelectedTypedFactSource) {
        if let Some(services) = facts.receiver_proof_services() {
            services.refuse_read_reuse();
        }
    }
    fn caller(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Caller>> {
        let Some(reference) = facts.selected_access_reference(reference, cancellation)? else {
            self.refuse(facts);
            return Ok(None);
        };
        if reference.source.language != Language::CSharp {
            self.refuse(facts);
            return Ok(None);
        }
        let chain = super::declaration_access::complete_source_type_containment(
            facts,
            &reference,
            cancellation,
        )?;
        let (context, containing_types) = match chain {
            Some(chain) => (
                chain.first().copied().map_or(
                    DeclarationAccessContext::OutsideType,
                    DeclarationAccessContext::EnclosingType,
                ),
                chain,
            ),
            None => (DeclarationAccessContext::Unproven, Vec::new()),
        };
        if context == DeclarationAccessContext::Unproven {
            self.refuse(facts);
        }
        Ok(Some(Caller {
            reference,
            context,
            containing_types,
        }))
    }
}

impl DeclarationAccessRules for CSharpAccessPolicy {
    type Endpoint = Endpoint;
    type Facts = ();
    type TargetContext = ();
    fn prepare_target(&self, _target: &Endpoint) -> Result<()> {
        Ok(())
    }
    fn declaration_relation(
        &self,
        caller: &Endpoint,
        target: &Endpoint,
        _facts: &(),
        _context: &(),
    ) -> Result<Option<AccessEvidence>> {
        let Endpoint::Target { declaration, owner } = target else {
            return Ok(None);
        };
        if Self::nonmember(declaration) || Self::known_nonprivate(declaration) {
            // This private-only predicate does not apply. In particular,
            // synthetic public roots need no ordinary private caller context.
            // Unrelated language access/activation gaps remain open.
            return Ok(Some(AccessEvidence {
                decision: DeclarationAccessDecision::Unknown,
                activation_reason: None,
                visibility_applies: false,
                subclass_access: None,
            }));
        }
        let Endpoint::Caller(Some(caller)) = caller else {
            return Ok(Some(self.unknown_reason()));
        };
        if declaration.visibility != Some(DeclaredVisibility::Private) {
            return Ok(Some(self.unknown_reason()));
        }
        let Some(owner) = owner.as_ref().filter(|owner| {
            owner.is_type
                && owner.partial == Some(false)
                && owner.source.language == Language::CSharp
        }) else {
            return Ok(Some(self.unknown_reason()));
        };
        if caller.context == DeclarationAccessContext::Unproven {
            return Ok(Some(self.unknown_reason()));
        }
        let source = &caller.reference.source;
        let declaring_type = declaration
            .ordinary_owner
            .flatten()
            .expect("private ordinary target has an exact declaring type");
        let inside = caller.containing_types.contains(&declaring_type);
        if inside
            && (source.file != owner.source.file
                || owner.source.start_byte > source.start_byte
                || source.end_byte > owner.source.end_byte)
        {
            return Ok(Some(self.unknown_reason()));
        }
        Ok(Some(AccessEvidence {
            decision: if inside {
                DeclarationAccessDecision::Allowed
            } else {
                DeclarationAccessDecision::Denied
            },
            activation_reason: None,
            visibility_applies: true,
            subclass_access: None,
        }))
    }
    fn combine_placements(
        &self,
        answers: impl Iterator<Item = Result<AccessEvidence>>,
    ) -> Result<AccessEvidence> {
        let mut selected: Option<AccessEvidence> = None;
        for answer in answers {
            let answer = answer?;
            match &selected {
                Some(previous)
                    if previous.decision != answer.decision
                        || previous.visibility_applies != answer.visibility_applies =>
                {
                    return Ok(self.unknown_reason());
                }
                Some(_) => {}
                None => selected = Some(answer),
            }
        }
        Ok(selected.unwrap_or_else(|| self.unknown_reason()))
    }
    fn unknown_reason(&self) -> AccessEvidence {
        AccessEvidence {
            decision: DeclarationAccessDecision::Unknown,
            activation_reason: Some(self.identity),
            visibility_applies: true,
            subclass_access: None,
        }
    }
}

impl SelectedDeclarationAccessRules for CSharpAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }
    fn read_endpoints(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: &[DeclarationAccessRequest],
        cancellation: &CancellationToken,
        _visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<AccessEndpointRead<Endpoint, ()>> {
        let mut endpoints = HashMap::<SemanticId, Vec<Endpoint>>::default();
        for request in requests {
            if cancellation.is_cancelled() {
                return Ok(AccessEndpointRead::Terminal(
                    TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete),
                ));
            }
            if let std::collections::hash_map::Entry::Vacant(entry) =
                endpoints.entry(request.definition)
            {
                let targets =
                    match facts.selected_access_declaration(request.definition, cancellation)? {
                        Some(declaration) => {
                            if !Self::nonmember(&declaration)
                                && matches!(
                                    declaration.visibility,
                                    None | Some(DeclaredVisibility::Unknown)
                                )
                            {
                                self.refuse(facts);
                            }
                            let owner = match declaration.ordinary_owner {
                                Some(Some(owner)) => {
                                    facts.selected_access_declaration(owner, cancellation)?
                                }
                                _ => None,
                            };
                            if declaration.visibility == Some(DeclaredVisibility::Private)
                                && owner.as_ref().is_none_or(|owner| {
                                    !owner.is_type || owner.partial != Some(false)
                                })
                            {
                                self.refuse(facts);
                            }
                            vec![Endpoint::Target { declaration, owner }]
                        }
                        None => {
                            self.refuse(facts);
                            Vec::new()
                        }
                    };
                entry.insert(targets);
            }
        }
        let mut callers = HashSet::default();
        let mut required = HashSet::default();
        for request in requests {
            callers.insert(request.reference);
            if !matches!(endpoints.get(&request.definition).map(Vec::as_slice), Some([Endpoint::Target { declaration, .. }]) if Self::nonmember(declaration) || Self::known_nonprivate(declaration))
            {
                required.insert(request.reference);
            }
        }
        for reference in callers {
            let caller = if required.contains(&reference) {
                self.caller(facts, reference, cancellation)?
            } else {
                None
            };
            endpoints.insert(reference, vec![Endpoint::Caller(caller)]);
        }
        Ok(AccessEndpointRead::Ready(AccessEndpoints {
            endpoints,
            facts: (),
        }))
    }
    fn declaration_activation(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _definition: SemanticId,
        cancellation: &CancellationToken,
        _session: Option<&ResolutionSession>,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
        Ok((!cancellation.is_cancelled()).then_some((DeclarationAccessDecision::Allowed, None)))
    }
}

impl SelectedDeclarationAccessSource for CSharpAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }
    fn prepare_candidate_context(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<PreparedDeclarationAccessContext>> {
        let context = self
            .caller(facts, reference, cancellation)?
            .map_or(DeclarationAccessContext::Unproven, |caller| caller.context);
        Ok(Some(PreparedDeclarationAccessContext {
            context,
            reference,
        }))
    }
    fn prepare_candidate_access(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: SemanticId,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<DeclarationAccessRequest>> {
        let mut requests = Vec::new();
        for &definition in definitions {
            if cancellation.is_cancelled() {
                break;
            }
            let declaration = facts.selected_access_declaration(definition, cancellation)?;
            if declaration.as_ref().is_some_and(|declaration| {
                Self::nonmember(declaration) || Self::known_nonprivate(declaration)
            }) {
                continue;
            }
            // Missing visibility can still denote a private member. It must
            // retain uncertainty and cannot certify admission or retained reuse.
            if declaration.as_ref().is_none_or(|declaration| {
                matches!(
                    declaration.visibility,
                    None | Some(DeclaredVisibility::Unknown)
                )
            }) {
                self.refuse(facts);
            }
            requests.push(DeclarationAccessRequest {
                reference,
                definition,
            });
        }
        Ok(requests)
    }
    fn visit_access_pages(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<DeclarationAccessRow>,
    ) -> Result<TypedFactReadOutcome> {
        super::declaration_access::visit_access_pages(self, facts, requests, cancellation, visitor)
    }
}
