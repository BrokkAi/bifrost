//! Request-local declaration access orchestration. Language rules own selected
//! endpoint reads and reduction; no access completion is retained here.

use super::*;
use crate::analyzer::resolution::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    SelectedTypedFactSource, SubclassAccessContext, TypedFactReadOutcome, TypedFactRequest,
};
use crate::analyzer::resolution::{
    MAX_TYPED_FACT_REQUESTS_PER_BATCH, MAX_TYPED_FACT_ROWS_PER_PAGE,
    SelectedDeclarationAccessSource, TypedFactPageVisitor, TypedFactReadTerminal,
};

pub(super) struct AccessEvidence {
    pub(super) decision: DeclarationAccessDecision,
    pub(super) activation_reason: Option<SemanticId>,
    pub(super) visibility_applies: bool,
    pub(super) subclass_access: Option<SubclassAccessContext>,
}

pub(super) struct AccessEndpoints<E, F> {
    pub(super) endpoints: HashMap<SemanticId, Vec<E>>,
    pub(super) facts: F,
}

pub(super) enum AccessEndpointRead<E, F> {
    Ready(AccessEndpoints<E, F>),
    Terminal(TypedFactReadOutcome),
}

pub(super) trait DeclarationAccessRules {
    type Endpoint;
    type Facts;
    type TargetContext;

    /// Absence means this language has no per-target context.
    fn prepare_target(&self, target: &Self::Endpoint) -> Result<Self::TargetContext>;
    fn declaration_relation(
        &self,
        caller: &Self::Endpoint,
        target: &Self::Endpoint,
        facts: &Self::Facts,
        context: &Self::TargetContext,
    ) -> Result<Option<AccessEvidence>>;
    /// Each implementor defines its empty-input result explicitly.
    fn combine_placements(
        &self,
        answers: impl Iterator<Item = Result<AccessEvidence>>,
    ) -> Result<AccessEvidence>;
    fn unknown_reason(&self) -> AccessEvidence;
}

pub(super) type AccessEndpointPair<'a, E> = (&'a [E], &'a [E]);

pub(super) trait SelectedDeclarationAccessRules: DeclarationAccessRules {
    fn identity(&self) -> SemanticId;
    fn read_endpoints(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: &[DeclarationAccessRequest],
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<AccessEndpointRead<Self::Endpoint, Self::Facts>>;
    fn request_endpoints<'a>(
        &self,
        request: &DeclarationAccessRequest,
        selected: &'a AccessEndpoints<Self::Endpoint, Self::Facts>,
    ) -> Result<AccessEndpointPair<'a, Self::Endpoint>> {
        Ok((
            selected
                .endpoints
                .get(&request.reference)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            selected
                .endpoints
                .get(&request.definition)
                .map(Vec::as_slice)
                .unwrap_or_default(),
        ))
    }
    fn request_activation_reason(
        &self,
        _request: &DeclarationAccessRequest,
        _selected: &AccessEndpoints<Self::Endpoint, Self::Facts>,
    ) -> Option<SemanticId> {
        None
    }
    fn declaration_activation(
        &self,
        facts: &dyn SelectedTypedFactSource,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>>;
    /// Absence means this language has none of this selection-path qualification.
    fn qualify_selection_path(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _reference: SemanticId,
        _path: &mut crate::analyzer::resolution::PartialPath,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        Ok((!cancellation.is_cancelled()).then_some(true))
    }

    /// Absence means this language has none of this activation reason ownership.
    fn visit_reason_owners(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _reasons: TypedFactRequest<SemanticId>,
        cancellation: &CancellationToken,
        _visitor: &mut FactPageVisitor<'_, crate::analyzer::resolution::ReasonOwnerRow>,
    ) -> Result<TypedFactReadOutcome> {
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    /// Absence means this language has none of this companion relation evidence.
    fn companion_relations(
        &self,
        _facts: &dyn SelectedTypedFactSource,
        _templates: &[SemanticId],
        cancellation: &CancellationToken,
        _visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<Option<HashSet<(SemanticId, SemanticId)>>> {
        Ok((!cancellation.is_cancelled()).then(HashSet::default))
    }
}

pub(super) fn visit_access_pages<R: SelectedDeclarationAccessRules>(
    rules: &R,
    facts: &dyn SelectedTypedFactSource,
    requests: TypedFactRequest<DeclarationAccessRequest>,
    cancellation: &CancellationToken,
    visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
) -> Result<TypedFactReadOutcome> {
    let requests = requests
        .as_slice()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selected = match rules.read_endpoints(facts, &requests, cancellation, visitor)? {
        AccessEndpointRead::Ready(selected) => selected,
        AccessEndpointRead::Terminal(outcome) => return Ok(outcome),
    };
    let semantics = requests
        .iter()
        .flat_map(|r| [r.reference, r.definition])
        .collect::<HashSet<_>>();
    assert!(
        selected.endpoints.keys().all(|key| semantics.contains(key)),
        "access policy {} returned foreign endpoints",
        rules.identity()
    );
    let mut rows = Vec::with_capacity(requests.len());
    for request in requests {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        let (callers, targets) = rules.request_endpoints(&request, &selected)?;
        let evidence = evaluate_placements(rules, callers, targets, &selected.facts)?;
        rows.push(DeclarationAccessRow {
            request,
            decision: evidence.decision,
            activation_reason: evidence
                .activation_reason
                .or_else(|| rules.request_activation_reason(&request, &selected)),
            visibility_applies: evidence.visibility_applies,
            subclass_access: evidence.subclass_access,
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

/// Pull answers lazily so a language reduction can stop once it has positive
/// authority, without reading later crate contexts. Preparation streams in
/// target order and immediately precedes that target's caller relations.
pub(super) fn evaluate_placements<R: DeclarationAccessRules>(
    rules: &R,
    callers: &[R::Endpoint],
    targets: &[R::Endpoint],
    facts: &R::Facts,
) -> Result<AccessEvidence> {
    let mut target_index = 0;
    let mut caller_index = 0;
    let mut context = None;
    let answers = std::iter::from_fn(|| {
        while let Some(target) = targets.get(target_index) {
            if context.is_none() {
                match rules.prepare_target(target) {
                    Ok(prepared) => context = Some(prepared),
                    Err(error) => {
                        target_index = targets.len();
                        return Some(Err(error));
                    }
                }
            }
            if let Some(caller) = callers.get(caller_index) {
                caller_index += 1;
                match rules.declaration_relation(caller, target, facts, context.as_ref().unwrap()) {
                    Ok(Some(answer)) => return Some(Ok(answer)),
                    Ok(None) => continue,
                    Err(error) => {
                        target_index = targets.len();
                        return Some(Err(error));
                    }
                }
            }
            target_index += 1;
            caller_index = 0;
            context = None;
        }
        None
    });
    rules.combine_placements(answers)
}

pub(in crate::analyzer::store) fn owner_templates(
    semantic: SemanticId,
    seed_owner: Option<SemanticId>,
    definition: bool,
    parents: &HashMap<SemanticId, Option<SemanticId>>,
    templates: &HashSet<SemanticId>,
    lexical_templates: Vec<SemanticId>,
) -> Vec<SemanticId> {
    let mut enclosing_templates = Vec::new();
    let mut current = seed_owner;
    if definition && current == Some(semantic) && templates.contains(&semantic) {
        current = parents.get(&semantic).copied().flatten();
    }
    let mut visited = HashSet::default();
    while let Some(owner) = current {
        assert!(
            visited.insert(owner),
            "selected declaration owners are acyclic"
        );
        if templates.contains(&owner) {
            enclosing_templates.push(owner);
        }
        current = parents.get(&owner).copied().flatten();
    }
    for template in lexical_templates {
        if !enclosing_templates.contains(&template) {
            enclosing_templates.push(template);
        }
    }
    enclosing_templates
}

pub(crate) fn ensure_declaration_access_rows(
    source: &dyn SelectedDeclarationAccessSource,
    typed_source: &dyn SelectedTypedFactSource,
    resolution_session: Option<&ResolutionSession>,
    cancellation: &CancellationToken,
    cache: &mut HashMap<DeclarationAccessRequest, DeclarationAccessRow>,
    requests: &[DeclarationAccessRequest],
    mut observe_completion: impl FnMut(&ResolutionCompletion),
) -> Result<bool> {
    assert!(
        requests.windows(2).all(|pair| pair[0] < pair[1]),
        "selected declaration access requests must be sorted and unique"
    );
    let mut missing = Vec::new();
    for &request in requests {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        if !cache.contains_key(&request) {
            missing.push(request);
        }
    }
    for chunk in missing.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let mut staged = HashMap::default();
        let mut collect = |rows: &[DeclarationAccessRow]| {
            for row in rows {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                if chunk.binary_search(&row.request).is_err() {
                    return Err(StoreError::new(format!(
                        "selected access policy {} emitted unrequested endpoint pair {:?}",
                        source.identity(),
                        row.request
                    )));
                }
                if staged.insert(row.request, row.clone()).is_some() {
                    return Err(StoreError::new(format!(
                        "selected access policy {} emitted duplicate endpoint pair {:?}",
                        source.identity(),
                        row.request
                    )));
                }
            }
            Ok(true)
        };
        let mut visitor = match resolution_session {
            Some(session) => TypedFactPageVisitor::with_maximum_rows_in_session(
                &mut collect,
                MAX_TYPED_FACT_ROWS_PER_PAGE,
                session,
            ),
            None => TypedFactPageVisitor::new(&mut collect),
        };
        let (terminal, evidence) = source
            .visit_access_pages(
                typed_source,
                TypedFactRequest::new(chunk),
                cancellation,
                &mut visitor,
            )?
            .into_parts();
        observe_completion(&evidence);
        if terminal == TypedFactReadTerminal::Cancelled || cancellation.is_cancelled() {
            return Ok(false);
        }
        if terminal != TypedFactReadTerminal::Exhausted
            || evidence != ResolutionCompletion::Complete
            || staged.len() != chunk.len()
        {
            return Err(StoreError::new(format!(
                "selected access policy {} did not exhaust exact request {chunk:?}: terminal {terminal:?}, evidence {evidence:?}, rows {staged:?}",
                source.identity()
            )));
        }
        for (request, decision) in staged {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            cache.insert(request, decision);
        }
    }
    Ok(true)
}
