//! One source-observation algorithm shared by evaluator fill and head replay.
use super::super::TypedFactInventoryEvidence;
use super::super::fact_source::{
    ConditionalOwnerApplicationInputs, ReceiptUse, SelectedDeclarationClassLikeMetadata,
    SelectedDeclarationModifier, SelectedReceiverProofReceipt, UsableReceiverProofReceipt,
};
use super::*;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer;

#[derive(Clone, Debug)]
pub struct OwnerApplicationObservation {
    pub application_slot: SemanticId,
    pub canonical_inputs: ConditionalOwnerApplicationInputs,
    pub canonical_answer: Option<SelectedReceiverProofAnswer>,
    pub inputs: ConditionalOwnerApplicationInputs,
    pub answer: Option<SelectedReceiverProofAnswer>,
}

fn owner_seed_inputs_without_proof(
    application: SemanticId,
    mut inputs: ConditionalOwnerApplicationInputs,
) -> ConditionalOwnerApplicationInputs {
    use super::super::fact_source::{TypedFactReadOutcome, TypedFactReadTerminal};
    let (terminal, completion, _) = inputs.outcome.into_complete_parts();
    let completion = completion.combine(&ResolutionCompletion::incomplete([
        ResolutionIncompleteReason::UnsupportedSemantic(application),
    ]));
    inputs.outcome = match terminal {
        TypedFactReadTerminal::Exhausted => TypedFactReadOutcome::exhausted(completion),
        TypedFactReadTerminal::Stopped => TypedFactReadOutcome::stopped(completion),
        TypedFactReadTerminal::Cancelled => TypedFactReadOutcome::cancelled(completion),
    };
    inputs.application = None;
    inputs
}

struct ProofInventory {
    hash: CanonicalHasher,
    reasons: Vec<[u8; 32]>,
    reusable: bool,
    incomplete: bool,
}
impl ProofInventory {
    fn new(question: &str) -> Self {
        let mut hash = CanonicalHasher::new(b"bifrost-selected-receiver-proof:inventory:v1");
        hash.field("question", question.as_bytes());
        Self {
            hash,
            reasons: Vec::new(),
            reusable: true,
            incomplete: false,
        }
    }
    fn identity(
        &mut self,
        session: &FactReadSession<'_>,
        field: &str,
        value: SemanticId,
    ) -> StoreResult<()> {
        if let Some(digest) = session
            .lexical_source
            .proof_identity_content_digest(value.into(), session.cancellation)?
        {
            self.hash.field(field, &digest);
        } else {
            self.reusable = false;
        }
        Ok(())
    }
    fn node_identity(
        &mut self,
        session: &FactReadSession<'_>,
        field: &str,
        value: BindingNodeId,
    ) -> StoreResult<()> {
        if let Some(digest) = session
            .lexical_source
            .proof_identity_content_digest(value.into(), session.cancellation)?
        {
            self.hash.field(field, &digest);
        } else {
            self.reusable = false;
        }
        Ok(())
    }
    fn completion(
        &mut self,
        session: &FactReadSession<'_>,
        completion: &ResolutionCompletion,
    ) -> StoreResult<()> {
        self.incomplete |= completion != &ResolutionCompletion::Complete;
        let mut reasons = Vec::new();
        if let ResolutionCompletion::Incomplete(items) = completion {
            for reason in items.iter() {
                let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                    self.reusable = false;
                    continue;
                };
                if let Some(digest) = session
                    .lexical_source
                    .proof_identity_content_digest((*reason).into(), session.cancellation)?
                {
                    reasons.push(digest);
                } else {
                    self.reusable = false;
                }
            }
        }
        reasons.sort_unstable();
        reasons.dedup();
        self.hash.field(
            "complete",
            &[u8::from(completion == &ResolutionCompletion::Complete)],
        );
        self.hash
            .field("reason_count", &(reasons.len() as u64).to_le_bytes());
        for reason in &reasons {
            self.hash.field("reason", reason);
        }
        self.reasons.extend(reasons);
        Ok(())
    }
    fn observe<R: ProofRow>(
        &mut self,
        session: &FactReadSession<'_>,
        relation: &str,
        selectors: &[SemanticId],
        rows: &[R],
        inventory: &TypedFactInventoryEvidence,
    ) -> StoreResult<()> {
        self.hash.field("relation", relation.as_bytes());
        self.hash.field("exhausted", &[1]);
        self.hash
            .field("selector_count", &(selectors.len() as u64).to_le_bytes());
        for selector in selectors {
            self.identity(session, "selector", *selector)?;
        }
        self.hash
            .field("row_count", &(rows.len() as u64).to_le_bytes());
        // Keep the ordinary session relation natural-key order.
        let mut canonical = Vec::new();
        for row in rows {
            let mut row_trace = Self::new("row");
            row.hash(session, &mut row_trace)?;
            self.reusable &= row_trace.reusable;
            self.incomplete |= row_trace.incomplete;
            self.reasons.extend(row_trace.reasons);
            canonical.push(row_trace.hash.finish());
        }
        for row in canonical {
            self.hash.field("row", &row);
        }
        self.inventory(session, inventory)
    }
    fn inventory(
        &mut self,
        session: &FactReadSession<'_>,
        inventory: &TypedFactInventoryEvidence,
    ) -> StoreResult<()> {
        match inventory {
            TypedFactInventoryEvidence::Established(completion) => {
                self.hash.field("inventory", b"established");
                self.completion(session, completion)
            }
            TypedFactInventoryEvidence::Unestablished => {
                self.hash.field("inventory", b"unestablished");
                self.reusable = false;
                Ok(())
            }
        }
    }
    fn finish(mut self) -> Option<SelectedReceiverProofAnswer> {
        if !self.reusable {
            return None;
        }
        let consumed_inventory_digest = StableDigest::from_array(self.hash.finish());
        self.reasons.sort_unstable();
        self.reasons.dedup();
        if !self.incomplete {
            Some(SelectedReceiverProofAnswer::ExhaustedComplete {
                consumed_inventory_digest,
            })
        } else {
            let mut hash = CanonicalHasher::new(b"bifrost-selected-receiver-proof:reasons:v1");
            for reason in self.reasons {
                hash.field("reason", &reason);
            }
            Some(SelectedReceiverProofAnswer::ExhaustedIncomplete {
                consumed_inventory_digest,
                reasons_digest: StableDigest::from_array(hash.finish()),
            })
        }
    }
}
trait ProofRow {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        _question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        _relation: &str,
        _selectors: &[SemanticId],
        _rows: &mut Vec<Self>,
    ) where
        Self: Sized,
    {
    }
    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()>;
}
impl ProofRow for SelectedTypedRow<LoweredDeclarationTypeProperty> {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        relation: &str,
        selectors: &[SemanticId],
        rows: &mut Vec<Self>,
    ) {
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            if relation == "declaration_types_for_slots" {
                decorator.application_properties(question, rows);
            } else {
                decorator.formal_identities(question, rows);
            }
        });
        let _ = (relation, selectors);
    }

    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        let row = self.row();
        trace.identity(session, "definition", row.definition())?;
        trace.identity(session, "slot", row.slot())?;
        trace.hash.field("role", row.role().label().as_bytes());
        Ok(())
    }
}
impl ProofRow for SelectedTypedRow<LoweredGenericFormal> {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        relation: &str,
        selectors: &[SemanticId],
        rows: &mut Vec<Self>,
    ) {
        let owner = selectors[0];
        let fragment =
            BindingFragmentId::at_ordinal(owner.ordinal().expect("ordinary selected owner"));
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            decorator.generic_formals(question, owner, fragment, rows)
        });
        let _ = (relation, selectors);
    }

    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        let row = self.row();
        trace.identity(session, "owner", row.owner())?;
        trace.identity(session, "parameter", row.parameter())?;
        trace.hash.field("ordinal", &row.ordinal().to_le_bytes());
        Ok(())
    }
}
impl ProofRow for SelectedTypedRow<LoweredTypeArgument> {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        relation: &str,
        selectors: &[SemanticId],
        rows: &mut Vec<Self>,
    ) {
        let application = selectors[0];
        let fragment = BindingFragmentId::at_ordinal(
            application
                .ordinal()
                .expect("ordinary selected application"),
        );
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            decorator.type_arguments(question, application, fragment, rows)
        });
        let _ = (relation, selectors);
    }

    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        let row = self.row();
        trace.identity(session, "application", row.application())?;
        trace.identity(session, "argument", row.argument())?;
        trace.hash.field("ordinal", &row.ordinal().to_le_bytes());
        trace
            .hash
            .field("indirection_delta", &row.indirection_delta().to_le_bytes());
        trace.hash.field(
            "reference_indirection_delta",
            &row.reference_indirection_delta().to_le_bytes(),
        );
        Ok(())
    }
}
impl ProofRow for SelectedTypedRow<SelectedDeclarationModifier> {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        relation: &str,
        selectors: &[SemanticId],
        rows: &mut Vec<Self>,
    ) {
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            decorator.declaration_modifiers(question, rows)
        });
        let _ = (relation, selectors);
    }

    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        trace.identity(session, "definition", self.row().definition)?;
        trace.hash.field("partial", &[u8::from(self.row().partial)]);
        Ok(())
    }
}
impl ProofRow for SelectedTypeFrontierCompletion {
    #[cfg(any(test, feature = "test-support"))]
    fn decorate(
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        _relation: &str,
        _selectors: &[SemanticId],
        rows: &mut Vec<Self>,
    ) {
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            decorator.frontier_completions(question, rows)
        });
    }

    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        trace.identity(session, "frontier", self.frontier())?;
        trace.completion(session, self.completion())
    }
}
impl ProofRow for SelectedGapReasonProvenance {
    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        trace.identity(session, "reason", self.reason())?;
        trace.identity(
            session,
            "source_site",
            super::super::mounted_site_semantic(self.fragment(), self.source_site()),
        )?;
        trace
            .hash
            .field("origin", self.origin().kind().label().as_bytes());
        Ok(())
    }
}
impl ProofRow for super::super::ReferenceSeed {
    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        trace.identity(session, "reference", self.reference())?;
        trace.node_identity(session, "reference_head", self.node())?;
        trace
            .hash
            .field("language", format!("{:?}", self.language()).as_bytes());
        match self.site_metadata() {
            Some(metadata) => {
                trace.hash.field("site_metadata", b"present");
                trace.identity(
                    session,
                    "reference_site",
                    super::super::mounted_site_semantic(self.fragment(), metadata.site()),
                )?;
                trace
                    .hash
                    .field("namespace", metadata.namespace().label().as_bytes());
                trace
                    .hash
                    .field("site_kind", metadata.site_kind().label().as_bytes());
                trace
                    .hash
                    .field("unqualified", &[u8::from(metadata.unqualified())]);
                match metadata.reference_owner() {
                    None => trace.hash.field("owner_state", b"unrecorded"),
                    Some(None) => trace.hash.field("owner_state", b"no-owner"),
                    Some(Some(owner)) => {
                        trace.hash.field("owner_state", b"owner");
                        trace.identity(session, "reference_owner", owner)?;
                    }
                }
                trace.hash.field(
                    "receiver_origin",
                    metadata
                        .receiver_origin()
                        .map_or("absent", |origin| origin.label())
                        .as_bytes(),
                );
            }
            None => trace.hash.field("site_metadata", b"absent"),
        }
        trace.completion(session, self.completion())
    }
}
#[cfg(any(test, feature = "test-support"))]
fn decorate_proof_rows<R: ProofRow>(
    question: Option<&crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion>,
    relation: &str,
    selectors: &[SemanticId],
    rows: &mut Vec<R>,
) {
    if let Some(question) = question {
        R::decorate(question, relation, selectors, rows);
    }
}

impl FactReadSession<'_> {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn pending_receiver_proof_nodes_for_test(&self) -> Vec<[u8; 32]> {
        self.pending_receiver_proof_nodes.clone()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn drain_pending_receiver_proof_nodes_for_test(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.pending_receiver_proof_nodes)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn receiver_proof_memo_count_for_test(&self) -> usize {
        self.receiver_proof_memos.len()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn receiver_proof_memo_retained_for_test(
        &self,
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
    ) -> bool {
        self.receiver_proof_memos.contains_key(question)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn replay_base_after_question_change_for_test(
        &mut self,
        reference: SemanticId,
        replacement: crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
    ) -> StoreResult<(
        ReceiptUse<BaseReceiverContextObservation>,
        Vec<[u8; 32]>,
        bool,
    )> {
        let question = self
            .typed_source
            .selected_base_receiver_context_question(reference, self.cancellation)?
            .expect("test reference has a selected Base question");
        let _ = self.consume_base_receiver_context_proof_with_receipt(reference)?;
        let _ = self.drain_pending_receiver_proof_nodes_for_test();
        let replay = super::receiver_proof_tests::with_changed_base_question(replacement, || {
            self.consume_base_receiver_context_proof_with_receipt(reference)
        })?;
        Ok((
            replay,
            self.pending_receiver_proof_nodes_for_test(),
            self.receiver_proof_memo_retained_for_test(&question),
        ))
    }

    /// Resolve owner staticness only from complete modifier inventory plus
    /// every recorded class-like metadata entry for an ordinary C# owner.
    /// Other languages and incomplete/partial owners remain Unknown.
    pub fn read_owner_static_authority(
        &mut self,
        owner: SemanticId,
    ) -> StoreResult<super::super::fact_source::OwnerStaticAuthority> {
        use super::super::fact_source::{
            OwnerStaticAuthority as Authority, SelectedDeclarationClassLikeMetadata,
        };
        if self.cancellation.is_cancelled() {
            return Ok(Authority::Unknown);
        }
        let Some(language) = self.typed_source.admitted_owner_language(owner) else {
            return Ok(Authority::Unknown);
        };
        if !self.typed_source.records_class_like_staticness(language) {
            return Ok(Authority::Unknown);
        }
        let (modifiers, modifier_inventory_complete) =
            match self.exact_declaration_modifiers_for_definitions(&[owner])? {
                SessionFactRead::Exhausted {
                    rows,
                    inventory_evidence:
                        TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete),
                    ..
                } => (
                    rows.into_iter()
                        .map(|row| *row.get(self).row())
                        .collect::<Vec<_>>(),
                    true,
                ),
                SessionFactRead::Exhausted { .. } | SessionFactRead::Cancelled(_) => {
                    (Vec::new(), false)
                }
            };
        if !modifier_inventory_complete
            || !matches!(modifiers.as_slice(), [modifier]
                if modifier.definition == owner && !modifier.partial)
        {
            return Ok(Authority::Unknown);
        }
        let Some(metadata) = self
            .typed_source
            .declaration_class_like_metadata(&[owner], self.cancellation)?
        else {
            return Ok(Authority::Unknown);
        };
        Ok(classify_owner_static_authority(
            owner, &modifiers, true, &metadata,
        ))
    }

    pub fn read_owner_application_observation(
        &mut self,
        slot: SemanticId,
    ) -> StoreResult<OwnerApplicationObservation> {
        let mut trace = ProofInventory::new("owner_application");
        let inputs = self.read_owner_application_inputs(slot, &mut trace)?;
        let answer = trace.finish();
        Ok(OwnerApplicationObservation {
            application_slot: slot,
            canonical_inputs: inputs.clone(),
            canonical_answer: answer,
            inputs,
            answer,
        })
    }
    pub fn read_owner_application_proof(
        &mut self,
        slot: SemanticId,
    ) -> StoreResult<ConditionalOwnerApplicationInputs> {
        Ok(self.read_owner_application_observation(slot)?.inputs)
    }
    /// Shared source observation for fill and head replay; it never solves a slot.
    fn read_owner_application_inputs(
        &mut self,
        slot: SemanticId,
        trace: &mut ProofInventory,
    ) -> StoreResult<super::super::fact_source::ConditionalOwnerApplicationInputs> {
        use super::super::fact_source::{
            ConditionalOwnerApplication, ConditionalOwnerApplicationInputs,
        };
        #[cfg(any(test, feature = "test-support"))]
        let proof_question =
            self.typed_source
                .selected_receiver_proof_question(slot, None, self.cancellation)?;

        macro_rules! rows {
            ($method:ident, $keys:expr) => {{
                match self.$method($keys)? {
                    SessionFactRead::Exhausted {
                        rows,
                        inventory_evidence,
                        ..
                    } => {
                        #[allow(unused_mut)]
                        let mut rows = rows
                            .into_iter()
                            .map(|row| row.get(self).clone())
                            .collect::<Vec<_>>();
                        let relation = stringify!($method)
                            .strip_prefix("exact_")
                            .unwrap_or(stringify!($method));
                        #[cfg(any(test, feature = "test-support"))]
                        decorate_proof_rows(proof_question.as_ref(), relation, $keys, &mut rows);
                        trace.observe(self, relation, $keys, &rows, &inventory_evidence)?;
                        if inventory_evidence
                            != TypedFactInventoryEvidence::Established(
                                ResolutionCompletion::Complete,
                            )
                        {
                            let outcome = match &inventory_evidence {
                                TypedFactInventoryEvidence::Established(completion) => {
                                    TypedFactReadOutcome::exhausted(completion.clone())
                                }
                                TypedFactInventoryEvidence::Unestablished => {
                                    TypedFactReadOutcome::stopped(ResolutionCompletion::Complete)
                                }
                            }
                            .with_inventory_evidence(inventory_evidence);
                            return Ok(ConditionalOwnerApplicationInputs {
                                outcome,
                                application: None,
                                unsupported_implicit_receiver: false,
                                ambiguous_application: false,
                            });
                        }
                        rows
                    }
                    SessionFactRead::Cancelled(evidence) => {
                        trace.reusable = false;
                        return Ok(ConditionalOwnerApplicationInputs {
                            outcome: TypedFactReadOutcome::cancelled(evidence),
                            application: None,
                            unsupported_implicit_receiver: false,
                            ambiguous_application: false,
                        });
                    }
                }
            }};
        }
        let properties = rows!(exact_declaration_types_for_slots, &[slot]);
        let applications = properties
            .iter()
            .filter(|row| row.row().role() == DeclarationTypeRole::NominalIdentity)
            .collect::<Vec<_>>();
        let [application] = applications.as_slice() else {
            let frontiers = rows!(exact_frontier_completions, &[slot]);
            let reasons = frontiers
                .iter()
                .flat_map(|row| match row.completion() {
                    ResolutionCompletion::Complete => Vec::new(),
                    ResolutionCompletion::Incomplete(reasons) => reasons
                        .iter()
                        .filter_map(|reason| match reason {
                            ResolutionIncompleteReason::UnsupportedSemantic(reason) => {
                                Some(*reason)
                            }
                            _ => None,
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            let mut provenance = Vec::new();
            for chunk in reasons.chunks(super::super::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                provenance.extend(rows!(exact_gap_reason_provenance_for_reasons, chunk));
            }
            return Ok(ConditionalOwnerApplicationInputs {
                outcome: TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                    .with_inventory_evidence(TypedFactInventoryEvidence::Established(
                        ResolutionCompletion::Complete,
                    )),
                application: None,
                unsupported_implicit_receiver: provenance.iter().any(|row| {
                    row.origin()
                        == super::super::LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedImplicitReceiver,
                        )
                }),
                ambiguous_application: !applications.is_empty(),
            });
        };
        let owner = application.row().definition();
        let formals = rows!(exact_generic_formals_for_owners, &[owner]);
        let arguments = rows!(exact_type_arguments_for_applications, &[slot]);
        let parameters = formals
            .iter()
            .map(|row| row.row().parameter())
            .collect::<Vec<_>>();
        let mut identities = Vec::new();
        for chunk in parameters.chunks(super::super::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            identities.extend(rows!(exact_declaration_types_for_definitions, chunk));
        }
        let modifiers = rows!(exact_declaration_modifiers_for_definitions, &[owner]);
        let partial = match modifiers.as_slice() {
            [row] => Some(row.row().partial),
            _ => None,
        };
        let complete_positions =
            formals.len() == arguments.len()
                && formals.iter().enumerate().zip(&arguments).all(
                    |((position, formal), argument)| {
                        let formal = formal.row();
                        let argument = argument.row();
                        formal.ordinal() as usize == position
                            && argument.ordinal() as usize == position
                            && argument.indirection_delta() == 0
                            && argument.reference_indirection_delta() == 0
                            && identities
                                .iter()
                                .filter(|row| {
                                    row.row().definition() == formal.parameter()
                                        && row.row().role() == DeclarationTypeRole::Identity
                                })
                                .map(|row| row.row().slot())
                                .collect::<Vec<_>>()
                                == [argument.argument()]
                    },
                );
        Ok(ConditionalOwnerApplicationInputs {
            outcome: TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                .with_inventory_evidence(TypedFactInventoryEvidence::Established(
                    ResolutionCompletion::Complete,
                )),
            application: Some(ConditionalOwnerApplication {
                owner,
                partial,
                complete_positions,
            }),
            unsupported_implicit_receiver: false,
            ambiguous_application: false,
        })
    }
}

fn classify_owner_static_authority(
    owner: SemanticId,
    modifiers: &[SelectedDeclarationModifier],
    modifier_inventory_complete: bool,
    metadata: &[SelectedDeclarationClassLikeMetadata],
) -> super::super::fact_source::OwnerStaticAuthority {
    use super::super::fact_source::OwnerStaticAuthority as Authority;
    let [modifier] = modifiers else {
        return Authority::Unknown;
    };
    if !modifier_inventory_complete || modifier.definition != owner || modifier.partial {
        return Authority::Unknown;
    }
    let [
        SelectedDeclarationClassLikeMetadata {
            definition,
            metadata_complete,
            staticness_recorded,
            parts,
        },
    ] = metadata
    else {
        return Authority::Unknown;
    };
    if *definition != owner || !metadata_complete || !staticness_recorded || parts.is_empty() {
        return Authority::Unknown;
    }
    let mut staticness = None;
    for part in parts {
        let (Some(_kind), Some(is_static)) = (part.kind, part.is_static) else {
            return Authority::Unknown;
        };
        if staticness.is_some_and(|previous| previous != is_static) {
            return Authority::Unknown;
        }
        staticness = Some(is_static);
    }
    match staticness {
        Some(true) => Authority::KnownStatic,
        Some(false) => Authority::KnownNonStatic,
        None => Authority::Unknown,
    }
}

#[cfg(test)]
mod owner_static_authority_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::ClassLikeKind;

    fn selected_metadata(
        owner: SemanticId,
        parts: Vec<crate::analyzer::resolution::fact_source::SelectedClassLikeMetadataPart>,
    ) -> Vec<SelectedDeclarationClassLikeMetadata> {
        vec![SelectedDeclarationClassLikeMetadata {
            definition: owner,
            metadata_complete: true,
            staticness_recorded: true,
            parts,
        }]
    }

    #[test]
    fn owner_static_authority_requires_complete_nonpartial_selected_source() {
        use crate::analyzer::resolution::fact_source::{
            OwnerStaticAuthority as Authority, SelectedClassLikeMetadataPart as Part,
            SelectedDeclarationModifier as Modifier,
        };
        let owner = SemanticId::for_test("owner-static-authority");
        let nonpartial = [Modifier {
            definition: owner,
            partial: false,
        }];
        let partial = [Modifier {
            definition: owner,
            partial: true,
        }];

        assert_eq!(
            classify_owner_static_authority(
                owner,
                &nonpartial,
                true,
                &selected_metadata(
                    owner,
                    vec![Part {
                        kind: Some(ClassLikeKind::Class),
                        is_static: Some(true),
                    }],
                ),
            ),
            Authority::KnownStatic
        );
        assert_eq!(
            classify_owner_static_authority(
                owner,
                &nonpartial,
                true,
                &selected_metadata(
                    owner,
                    vec![Part {
                        kind: Some(ClassLikeKind::Class),
                        is_static: Some(false),
                    }],
                ),
            ),
            Authority::KnownNonStatic
        );
        let mut unrecorded_metadata = selected_metadata(
            owner,
            vec![Part {
                kind: Some(ClassLikeKind::Class),
                is_static: Some(false),
            }],
        );
        unrecorded_metadata[0].staticness_recorded = false;
        assert_eq!(
            classify_owner_static_authority(owner, &nonpartial, true, &unrecorded_metadata),
            Authority::Unknown
        );
        for (modifiers, inventory_complete, parts) in [
            (
                &partial[..],
                true,
                vec![Part {
                    kind: Some(ClassLikeKind::Class),
                    is_static: Some(false),
                }],
            ),
            (
                &nonpartial[..],
                false,
                vec![Part {
                    kind: Some(ClassLikeKind::Class),
                    is_static: Some(false),
                }],
            ),
            (
                &nonpartial[..],
                true,
                vec![Part {
                    kind: None,
                    is_static: None,
                }],
            ),
        ] {
            assert_eq!(
                classify_owner_static_authority(
                    owner,
                    modifiers,
                    inventory_complete,
                    &selected_metadata(owner, parts),
                ),
                Authority::Unknown
            );
        }
    }

    #[test]
    fn owner_static_authority_reaches_selected_facts_through_profiled_mount() {
        use super::super::PreloadedFactResolutionService;
        use crate::analyzer::resolution::fact_source::OwnerStaticAuthority as Authority;
        use crate::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;
        use crate::analyzer::resolution::mounted::Mounted;
        use crate::analyzer::resolution::seam_profile::SeamProfiled;

        let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let fragment = BindingFragmentId::unmounted();
        service.selected_fragments = vec![fragment].into_boxed_slice();
        service
            .fragment_languages
            .insert(fragment, crate::analyzer::Language::CSharp);
        let interior_owner =
            SemanticId::local(crate::analyzer::resolution::model::UNMOUNTED_ORDINAL, 7);
        service.owner_static_test_owner = Some(interior_owner);
        service.owner_static_test_language = crate::analyzer::Language::CSharp;
        let mounted = Mounted::at(&service, SelectedResolutionMountOrdinal::new(19));
        let profiled = SeamProfiled::observing(&mounted);
        let owner = SemanticId::local(19, 7);
        let cancellation = CancellationToken::new();
        let mut session = FactReadSession::from_split_sources(&service, &profiled, &cancellation);

        assert_eq!(
            session.read_owner_static_authority(owner).unwrap(),
            Authority::KnownNonStatic,
            "modifier_reads={} metadata_reads={}",
            service.owner_static_test_modifier_reads.get(),
            service.owner_static_test_metadata_reads.get()
        );
        assert_eq!(service.owner_static_test_modifier_reads.get(), 1);
        assert_eq!(service.owner_static_test_metadata_reads.get(), 1);

        session.conditional_type_seeds(&[owner]).unwrap();
        assert_eq!(
            service.owner_static_test_callback_authority.get(),
            Some(Authority::KnownNonStatic)
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let before = (
            service.owner_static_test_modifier_reads.get(),
            service.owner_static_test_metadata_reads.get(),
        );
        let mut cancelled_session =
            FactReadSession::from_split_sources(&service, &profiled, &cancelled);
        cancelled_session.conditional_type_seeds(&[owner]).unwrap();
        assert_eq!(
            service.owner_static_test_callback_authority.get(),
            Some(Authority::Unknown)
        );
        assert_eq!(
            (
                service.owner_static_test_modifier_reads.get(),
                service.owner_static_test_metadata_reads.get(),
            ),
            before
        );
    }
}

#[derive(Clone, Debug)]
pub struct CurrentInstanceTransferObservation {
    /// Canonical evidence produced by the selected source read, retained for
    /// diagnostics even when its read receipt is unusable.
    pub canonical_answer: Option<SelectedReceiverProofAnswer>,
    pub canonical_completion: ResolutionCompletion,
    pub canonical_discharged_gap_reasons: BTreeSet<SemanticId>,
    /// Semantic authority is present only when the selected read has a usable
    /// receipt. Unretained observations keep the canonical fields above.
    pub answer: Option<SelectedReceiverProofAnswer>,
    pub completion: Option<ResolutionCompletion>,
    pub discharged_gap_reasons: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug)]
pub struct BaseReceiverContextObservation {
    pub reference: SemanticId,
    /// Exact typed source/route authority, independent of reference semantics.
    pub source_inventory: TypedFactInventoryEvidence,
    /// The distinct owner-application receipt consumed by this proof.
    pub owner_application_receipt: SelectedReceiverProofReceipt,
    pub owner_application_answer: Option<SelectedReceiverProofAnswer>,
    pub receiver_slot: Option<SemanticId>,
    pub owner: Option<SemanticId>,
    pub owner_application: Option<SemanticId>,
    pub owner_kind: Option<brokk_bifrost_core::analyzer::model::ClassLikeKind>,
    pub owner_staticness: super::super::fact_source::OwnerStaticAuthority,
    pub owner_partial: Option<bool>,
    pub provisional_reasons: BTreeSet<SemanticId>,
    /// Unmodified completion of the selected reference seed/member answer.
    pub reference_completion: ResolutionCompletion,
    /// Effective receiver-source completion after exact gap provenance checks.
    /// None means the selected source completion could not be established.
    pub receiver_source_completion: Option<ResolutionCompletion>,
    /// Combined completion for callers that need the conservative union.
    pub completion: ResolutionCompletion,
    /// Canonical answer before read-receipt admission. `answer` is the
    /// positive authority projection and is cleared when the read is refused.
    pub canonical_answer: Option<SelectedReceiverProofAnswer>,
    pub answer: Option<SelectedReceiverProofAnswer>,
}

impl ReceiptUse<BaseReceiverContextObservation> {
    /// Own raw evidence does not grant the positive owner composite.
    pub(crate) fn positive_base_receipt(&self) -> Option<&UsableReceiverProofReceipt> {
        let base = &self.observation;
        if base.source_inventory
            != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
            || base.receiver_source_completion != Some(ResolutionCompletion::Complete)
            || base.owner.is_none()
            || base.owner_application.is_none()
            || base.owner_kind.is_none()
            || base.owner_partial != Some(false)
            || base.owner_staticness
                != super::super::fact_source::OwnerStaticAuthority::KnownNonStatic
        {
            return None;
        }
        self.usable_receipt.as_ref()
    }
}

pub(super) struct ReceiverProofNodeReplay {
    pub(super) receipt: SelectedReceiverProofReceipt,
    pub(super) owner_application_receipt: Option<SelectedReceiverProofReceipt>,
    pub(super) usable_receipt: Option<UsableReceiverProofReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReceiverProofQuery {
    OwnerApplication(SemanticId),
    CurrentInstanceTransfer {
        application: SemanticId,
        receiver: SemanticId,
        rule: SemanticId,
    },
    BaseReceiverContext {
        reference: SemanticId,
    },
}
impl ProofRow for SelectedTypedRow<LoweredTypeTransfer> {
    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        let row = self.row();
        let rule = row.rule();
        trace.identity(session, "source", row.source_slot())?;
        trace.identity(session, "target", rule.target_slot())?;
        trace.identity(session, "rule", rule.semantic())?;
        trace.hash.field("kind", row.kind().label().as_bytes());
        trace
            .hash
            .field("indirection_delta", &rule.indirection_delta().to_le_bytes());
        trace.hash.field(
            "reference_indirection_delta",
            &rule.reference_indirection_delta().to_le_bytes(),
        );
        // These are existing value-transform variants, not a proof mode.
        let (transform, addressable) = match rule.value_transform() {
            TypeTransferValueTransform::Preserve => ("preserve", false),
            TypeTransferValueTransform::ToRuntime { addressable } => ("to_runtime", addressable),
            TypeTransferValueTransform::ToNoValue => ("to_no_value", false),
            TypeTransferValueTransform::TypeObjectOnly => ("type_object_only", false),
            TypeTransferValueTransform::AddressableRuntimeOnly => {
                ("addressable_runtime_only", true)
            }
            TypeTransferValueTransform::AddressableOperandOnly => {
                ("addressable_operand_only", true)
            }
            TypeTransferValueTransform::RuntimeOnly => ("runtime_only", false),
            TypeTransferValueTransform::StaticTypeObject => ("static_type_object", false),
        };
        trace.hash.field("transform", transform.as_bytes());
        trace.hash.field("addressable", &[u8::from(addressable)]);
        trace.completion(session, rule.completion())
    }
}
impl ProofRow for SourceSelectedQualifiedRoute {
    fn hash(&self, session: &FactReadSession<'_>, trace: &mut ProofInventory) -> StoreResult<()> {
        let row = self.row();
        trace.identity(session, "reference", row.reference())?;
        trace.identity(session, "qualifier", row.qualifier_slot())?;
        trace.identity(session, "lookup", row.lookup())?;
        trace.identity(session, "source_lookup", row.source_lookup())?;
        trace.identity(session, "output", row.projection_output_slot())?;
        trace.identity(session, "coarse_gap", row.coarse_gap_reason())?;
        trace
            .hash
            .field("namespace", row.namespace().label().as_bytes());
        trace
            .hash
            .field("precedence", &row.precedence_ordinal().to_le_bytes());
        trace
            .hash
            .field("projection", row.projection_kind().label().as_bytes());
        trace.hash.field(
            "open_member_surface",
            &[u8::from(row.open_member_surface())],
        );
        Ok(())
    }
}
impl FactReadSession<'_> {
    pub fn read_base_receiver_context_observation(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<BaseReceiverContextObservation> {
        Ok(self.read_base_receiver_context_use(reference)?.0)
    }

    fn read_base_receiver_context_use(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<(
        BaseReceiverContextObservation,
        Option<UsableReceiverProofReceipt>,
    )> {
        use super::super::fact_source::OwnerStaticAuthority;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteKind,
        };
        #[cfg(any(test, feature = "test-support"))]
        let proof_question = self
            .typed_source
            .selected_base_receiver_context_question(reference, self.cancellation)?;

        let mut trace = ProofInventory::new("base_receiver_context");
        trace.identity(self, "requested_reference", reference)?;
        let mut receiver_slot = None;
        let mut source_inventory;
        let mut owner_application_receipt = SelectedReceiverProofReceipt::Unretained;
        let mut owner_application_answer = None;
        let mut owner_application_usable_receipt = None;
        let mut owner = None;
        let mut owner_application = None;
        let mut owner_kind = None;
        let mut owner_staticness = OwnerStaticAuthority::Unknown;
        let mut owner_partial = None;
        let mut provisional_reasons = BTreeSet::new();
        let mut reference_completion = ResolutionCompletion::Complete;
        let mut receiver_source_completion = None;
        let mut completion = ResolutionCompletion::Complete;

        macro_rules! finish {
            () => {
                let canonical_answer = trace.finish();
                return Ok((
                    BaseReceiverContextObservation {
                        reference,
                        source_inventory: source_inventory.clone(),
                        owner_application_receipt,
                        owner_application_answer,
                        receiver_slot,
                        owner,
                        owner_application,
                        owner_kind,
                        owner_staticness,
                        owner_partial,
                        provisional_reasons,
                        reference_completion,
                        receiver_source_completion,
                        completion,
                        canonical_answer,
                        answer: canonical_answer,
                    },
                    owner_application_usable_receipt,
                ));
            };
        }

        let routes = match self.routes_for_references(&[reference])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                let rows = rows.iter().map(|row| *row.get(self)).collect::<Vec<_>>();
                trace.observe(
                    self,
                    "routes_for_references",
                    &[reference],
                    &rows,
                    &inventory_evidence,
                )?;
                source_inventory = inventory_evidence.clone();
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    if let TypedFactInventoryEvidence::Established(evidence) = inventory_evidence {
                        completion = evidence;
                    }
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                let cancelled = evidence.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ]));
                completion = cancelled.clone();
                source_inventory = TypedFactInventoryEvidence::Established(cancelled);
                trace.reusable = false;
                finish!();
            }
        };
        let routes = routes
            .iter()
            .filter(|route| route.row().reference() == reference)
            .collect::<Vec<_>>();
        let Some(route) = routes.first() else {
            finish!();
        };
        let route = route.row();
        if routes.iter().any(|candidate| {
            let candidate = candidate.row();
            candidate.qualifier_slot() != route.qualifier_slot()
        }) {
            finish!();
        }
        receiver_slot = Some(route.qualifier_slot());
        // This is the QualifiedReference route gap, not the producer's
        // receiver-specific uncertainty. Keep the route in the canonical
        // observation above; exact provisional IDs are read below from the
        // receiver frontier and source-site provenance.
        trace.identity(self, "reference_route_gap", route.coarse_gap_reason())?;

        let observed = self
            .lexical_source
            .lookup_reference_seeds(&[ResolutionQuery::new(reference)], self.cancellation)?;
        if !observed.is_exhausted() {
            let cancelled = observed
                .evidence()
                .combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ]));
            completion = cancelled.clone();
            trace.reusable = false;
            finish!();
        }
        let [answer] = observed.rows() else {
            trace.reusable = false;
            finish!();
        };
        assert_eq!(answer.request_ordinal(), 0);
        assert_eq!(answer.query(), ResolutionQuery::new(reference));
        let seed = answer.seed().cloned();
        // This indexed singleton API has its own exact-query contract: an
        // exhausted result contains one answer (present or absent) for this
        // requested reference. Bind that terminal and only these rows; the
        // legacy completion is semantic evidence, not inventory authority.
        trace
            .hash
            .field("relation", b"indexed_reference_seed_exact_query");
        trace.hash.field("exhausted", &[1]);
        trace.hash.field("selector_count", &1_u64.to_le_bytes());
        trace.identity(self, "selector", reference)?;
        trace.hash.field("row_count", &1_u64.to_le_bytes());
        if let Some(seed) = &seed {
            let mut row_trace = ProofInventory::new("reference_seed_row");
            seed.hash(self, &mut row_trace)?;
            trace.reusable &= row_trace.reusable;
            trace.incomplete |= row_trace.incomplete;
            trace.reasons.extend(row_trace.reasons);
            trace.hash.field("row", &row_trace.hash.finish());
        } else {
            trace.hash.field("row", b"absent");
        }
        trace.completion(self, observed.evidence())?;
        reference_completion = observed.evidence().clone();
        completion = completion.combine(&reference_completion);
        let Some(seed) = seed else {
            finish!();
        };
        assert_eq!(
            seed.reference(),
            reference,
            "reference seed matches its key"
        );
        reference_completion = reference_completion.combine(seed.completion());
        completion = completion.combine(seed.completion());
        let Some(metadata) = seed.site_metadata() else {
            finish!();
        };
        let Some(Some(selected_owner)) = metadata.reference_owner() else {
            finish!();
        };
        owner = Some(selected_owner);
        if !matches!(
            metadata.namespace(),
            ResolutionNamespace::Callable
                | ResolutionNamespace::Value
                | ResolutionNamespace::TypeOrValue
        ) || metadata.site_kind() != ResolutionSiteKind::MemberReference
            || metadata.receiver_origin() != Some(ResolutionCallableReceiverOrigin::Super)
        {
            finish!();
        }
        source_inventory = TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete);

        let receiver_frontiers = match self.exact_frontier_completions(&[route.qualifier_slot()])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                // Only the test-support row decoration below mutates the rows.
                #[allow(unused_mut)]
                let mut rows = rows
                    .iter()
                    .map(|row| row.get(self).clone())
                    .collect::<Vec<_>>();
                #[cfg(any(test, feature = "test-support"))]
                decorate_proof_rows(
                    proof_question.as_ref(),
                    "frontier_completions",
                    &[route.qualifier_slot()],
                    &mut rows,
                );
                trace.observe(
                    self,
                    "base_receiver_frontier_completion",
                    &[route.qualifier_slot()],
                    &rows,
                    &inventory_evidence,
                )?;
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                let cancelled = evidence.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ]));
                source_inventory = TypedFactInventoryEvidence::Established(cancelled.clone());
                receiver_source_completion = Some(cancelled.clone());
                completion = completion.combine(&cancelled);
                trace.reusable = false;
                finish!();
            }
        };
        let receiver_frontiers = receiver_frontiers
            .iter()
            .filter(|frontier| {
                frontier.fragment() == seed.fragment()
                    && frontier.frontier() == route.qualifier_slot()
            })
            .collect::<Vec<_>>();
        if receiver_frontiers.is_empty() {
            trace.reusable = false;
            finish!();
        }
        let semantic_reasons = receiver_frontiers
            .iter()
            .flat_map(|frontier| match frontier.completion() {
                ResolutionCompletion::Complete => Vec::new(),
                ResolutionCompletion::Incomplete(reasons) => reasons
                    .iter()
                    .filter_map(|reason| match reason {
                        ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                        _ => None,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let raw_receiver_source_completion = receiver_frontiers
            .iter()
            .fold(ResolutionCompletion::Complete, |completion, frontier| {
                completion.combine(frontier.completion())
            });
        let mut gap_provenance = Vec::new();
        for chunk in semantic_reasons.chunks(super::super::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            match self.exact_gap_reason_provenance_for_reasons(chunk)? {
                SessionFactRead::Exhausted {
                    rows,
                    inventory_evidence,
                    ..
                } => {
                    let rows = rows.iter().map(|row| *row.get(self)).collect::<Vec<_>>();
                    trace.observe(
                        self,
                        "base_receiver_gap_provenance",
                        chunk,
                        &rows,
                        &inventory_evidence,
                    )?;
                    if inventory_evidence
                        != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                    {
                        finish!();
                    }
                    gap_provenance.extend(rows);
                }
                SessionFactRead::Cancelled(evidence) => {
                    let cancelled = evidence.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ]));
                    let source_completion = raw_receiver_source_completion.combine(&cancelled);
                    receiver_source_completion = Some(source_completion.clone());
                    completion = completion.combine(&source_completion);
                    trace.reusable = false;
                    finish!();
                }
            }
        }
        let exact_receiver_reasons = gap_provenance
            .iter()
            .filter(|row| {
                row.fragment() == seed.fragment()
                    && row.source_site() == metadata.site()
                    && row.origin()
                        == super::super::LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedTypeSyntax,
                        )
            })
            .map(|row| row.reason())
            .collect::<BTreeSet<_>>();
        let residual_reasons = receiver_frontiers
            .iter()
            .flat_map(|frontier| match frontier.completion() {
                ResolutionCompletion::Complete => Vec::new(),
                ResolutionCompletion::Incomplete(reasons) => reasons
                    .iter()
                    .filter(|reason| {
                        !matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(id)
                            if exact_receiver_reasons.contains(id))
                    })
                    .copied()
                    .collect(),
            })
            .collect::<Vec<_>>();
        let source_completion = if residual_reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(residual_reasons)
        };
        receiver_source_completion = Some(source_completion.clone());
        completion = completion.combine(&source_completion);
        provisional_reasons = exact_receiver_reasons;

        let owner_types = match self.exact_declaration_types_for_definitions(&[selected_owner])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                let rows = rows
                    .iter()
                    .map(|row| row.get(self).clone())
                    .collect::<Vec<_>>();
                trace.observe(
                    self,
                    "declaration_types_for_owner",
                    &[selected_owner],
                    &rows,
                    &inventory_evidence,
                )?;
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                completion = evidence.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ]));
                trace.reusable = false;
                finish!();
            }
        };
        let applications = owner_types
            .iter()
            .filter(|row| row.row().role() == DeclarationTypeRole::NominalIdentity)
            .collect::<Vec<_>>();
        let [application] = applications.as_slice() else {
            finish!();
        };
        let application = application.row().slot();
        owner_application = Some(application);
        let application_proof = self.consume_owner_application_proof_with_receipt(application)?;
        owner_application_receipt = application_proof.receipt;
        owner_application_usable_receipt = application_proof.usable_receipt;
        let application_observation = application_proof.observation;
        if let Some(answer) = &application_observation.answer {
            owner_application_answer = Some(*answer);
            trace.hash.field(
                "owner_application_receipt",
                answer.canonical_digest().as_bytes(),
            );
        } else {
            trace.reusable = false;
        }
        if owner_application_receipt == SelectedReceiverProofReceipt::Unretained {
            trace.reusable = false;
        }
        if !matches!(
            application_observation.inputs.application,
            Some(application) if application.owner == selected_owner
                && application.partial == Some(false)
                && application.complete_positions
        ) || !application_observation.inputs.outcome.is_exhausted()
            || application_observation.inputs.outcome.inventory_evidence()
                != &TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
        {
            owner_partial = application_observation
                .inputs
                .application
                .and_then(|application| application.partial);
            trace.reusable = false;
            finish!();
        }
        owner_partial = Some(false);

        let records_staticness = self
            .typed_source
            .records_class_like_staticness(seed.language());
        trace.hash.field(
            "owner_staticness_capability",
            &[u8::from(records_staticness)],
        );
        if !records_staticness {
            finish!();
        }

        let modifiers = match self.exact_declaration_modifiers_for_definitions(&[selected_owner])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                let rows = rows
                    .iter()
                    .map(|row| row.get(self).clone())
                    .collect::<Vec<_>>();
                trace.observe(
                    self,
                    "declaration_modifiers_for_owner",
                    &[selected_owner],
                    &rows,
                    &inventory_evidence,
                )?;
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                completion = evidence.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::Cancelled,
                ]));
                trace.reusable = false;
                finish!();
            }
        };
        let metadata = self
            .typed_source
            .declaration_class_like_metadata(&[selected_owner], self.cancellation)?;
        let Some(metadata) = metadata else {
            trace.reusable = false;
            finish!();
        };
        for selected in &metadata {
            trace.identity(self, "class_like_owner", selected.definition)?;
            trace.hash.field(
                "class_like_metadata_complete",
                &[u8::from(selected.metadata_complete)],
            );
            trace.hash.field(
                "class_like_staticness_recorded",
                &[u8::from(selected.staticness_recorded)],
            );
            trace.hash.field(
                "class_like_part_count",
                &(selected.parts.len() as u64).to_le_bytes(),
            );
            for part in &selected.parts {
                trace.hash.field(
                    "class_like_kind",
                    part.kind.map_or("unknown", |kind| kind.label()).as_bytes(),
                );
                trace.hash.field(
                    "class_like_is_static",
                    match part.is_static {
                        Some(true) => b"true".as_slice(),
                        Some(false) => b"false".as_slice(),
                        None => b"unknown".as_slice(),
                    },
                );
            }
        }
        if let [selected] = metadata.as_slice()
            && selected.metadata_complete
            && !selected.parts.is_empty()
        {
            let kind = selected.parts[0].kind;
            if kind.is_some() && selected.parts.iter().all(|part| part.kind == kind) {
                owner_kind = kind;
            }
        }
        owner_staticness = classify_owner_static_authority(
            selected_owner,
            &modifiers.iter().map(|row| *row.row()).collect::<Vec<_>>(),
            true,
            &metadata,
        );
        let canonical_answer = trace.finish();
        Ok((
            BaseReceiverContextObservation {
                reference,
                source_inventory,
                owner_application_receipt,
                owner_application_answer,
                receiver_slot,
                owner,
                owner_application,
                owner_kind,
                owner_staticness,
                owner_partial,
                provisional_reasons,
                reference_completion,
                receiver_source_completion,
                completion,
                canonical_answer,
                answer: canonical_answer,
            },
            owner_application_usable_receipt,
        ))
    }

    pub fn read_current_instance_transfer_proof(
        &mut self,
        application: SemanticId,
        receiver: SemanticId,
        rule: SemanticId,
    ) -> StoreResult<CurrentInstanceTransferObservation> {
        let owner = self.read_owner_application_observation(application)?;
        let mut trace = ProofInventory::new("current_instance_transfer");
        if let Some(answer) = &owner.answer {
            trace
                .hash
                .field("owner_application", answer.canonical_digest().as_bytes());
        } else {
            trace.reusable = false;
        }
        let mut discharged_gap_reasons = BTreeSet::new();
        let mut completion =
            match owner.inputs.outcome.inventory_evidence() {
                TypedFactInventoryEvidence::Established(
                    failure @ ResolutionCompletion::Incomplete(_),
                ) => failure.clone(),
                TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete) => {
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(rule),
                    ])
                }
                TypedFactInventoryEvidence::Unestablished => ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(rule),
                ]),
            };
        macro_rules! finish {
            () => {
                let canonical_answer = trace.finish();
                let canonical_completion = completion.clone();
                let canonical_discharged_gap_reasons = discharged_gap_reasons.clone();
                return Ok(CurrentInstanceTransferObservation {
                    canonical_answer,
                    canonical_completion: canonical_completion.clone(),
                    canonical_discharged_gap_reasons: canonical_discharged_gap_reasons.clone(),
                    answer: canonical_answer,
                    completion: Some(canonical_completion),
                    discharged_gap_reasons: canonical_discharged_gap_reasons,
                });
            };
        }
        let Some(owner) = owner
            .inputs
            .application
            .filter(|app| app.partial == Some(false) && app.complete_positions)
        else {
            finish!();
        };
        let transfers = match self.exact_transfers_to_targets(&[receiver])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                let rows = rows
                    .iter()
                    .map(|row| row.get(self).clone())
                    .collect::<Vec<_>>();
                trace.observe(
                    self,
                    "transfers_to_targets",
                    &[receiver],
                    &rows,
                    &inventory_evidence,
                )?;
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    completion = match inventory_evidence {
                        TypedFactInventoryEvidence::Established(failure) => {
                            completion.combine(&failure)
                        }
                        TypedFactInventoryEvidence::Unestablished => {
                            completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(rule),
                            ]))
                        }
                    };
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                completion =
                    completion
                        .combine(&evidence)
                        .combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::Cancelled,
                        ]));
                trace.reusable = false;
                finish!();
            }
        };
        let transfers = transfers
            .iter()
            .filter(|row| row.row().rule().semantic() == rule)
            .collect::<Vec<_>>();
        let [transfer] = transfers.as_slice() else {
            finish!();
        };
        let transfer = transfer.row();
        if transfer.source_slot() != application
            || transfer.rule().target_slot() != receiver
            || transfer.kind() != ResolutionTypeTransferKind::Receiver
            || transfer.rule().value_transform()
                != (TypeTransferValueTransform::ToRuntime { addressable: false })
            || transfer.rule().indirection_delta() != 0
            || transfer.rule().reference_indirection_delta() != 0
        {
            finish!();
        }
        let routes = match self.exact_routes_for_qualifier_slots(&[receiver])? {
            SessionFactRead::Exhausted {
                rows,
                inventory_evidence,
                ..
            } => {
                let rows = rows.iter().map(|row| *row.get(self)).collect::<Vec<_>>();
                trace.observe(
                    self,
                    "routes_for_qualifier_slots",
                    &[receiver],
                    &rows,
                    &inventory_evidence,
                )?;
                if inventory_evidence
                    != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                {
                    completion = match inventory_evidence {
                        TypedFactInventoryEvidence::Established(failure) => {
                            completion.combine(&failure)
                        }
                        TypedFactInventoryEvidence::Unestablished => {
                            completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(rule),
                            ]))
                        }
                    };
                    finish!();
                }
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                completion =
                    completion
                        .combine(&evidence)
                        .combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::Cancelled,
                        ]));
                trace.reusable = false;
                finish!();
            }
        };
        // Namespace alternatives may share one source reference (TypeOrValue).
        // The complete inventory above remains part of the recorded answer.
        let Some(route) = routes.first() else {
            finish!();
        };
        let reference = route.row().reference();
        if routes.iter().any(|route| {
            route.row().reference() != reference || route.row().qualifier_slot() != receiver
        }) {
            finish!();
        }
        let observed = self
            .lexical_source
            .lookup_reference_seeds(&[ResolutionQuery::new(reference)], self.cancellation)?;
        if !observed.is_exhausted() {
            completion =
                completion
                    .combine(observed.evidence())
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ]));
            trace.reusable = false;
            finish!();
        }
        trace.inventory(
            self,
            &TypedFactInventoryEvidence::Established(observed.evidence().clone()),
        )?;
        if observed.evidence() != &ResolutionCompletion::Complete {
            completion = completion.combine(observed.evidence());
            finish!();
        }
        trace.hash.field(
            "reference_seed_count",
            &(observed.rows().len() as u64).to_le_bytes(),
        );
        let [row] = observed.rows() else {
            finish!();
        };
        assert_eq!(
            row.query(),
            ResolutionQuery::new(reference),
            "reference proof answers its exact requested query"
        );
        let Some(seed) = row.seed() else {
            finish!();
        };
        trace.identity(self, "reference", seed.reference())?;
        trace.completion(self, seed.completion())?;
        if seed.completion() != &ResolutionCompletion::Complete {
            completion = completion.combine(seed.completion());
            finish!();
        }
        let Some(metadata) = seed.site_metadata() else {
            trace.hash.field("metadata", b"absent");
            finish!();
        };
        trace.hash.field("metadata", b"present");
        trace.identity(
            self,
            "reference_site",
            super::super::mounted_site_semantic(seed.fragment(), metadata.site()),
        )?;
        let selected_owner = metadata.reference_owner();
        trace
            .hash
            .field("owner_present", &[u8::from(selected_owner.is_some())]);
        trace.hash.field(
            "owner_is_declaration",
            &[u8::from(selected_owner.flatten().is_some())],
        );
        if let Some(selected_owner) = selected_owner.flatten() {
            trace.identity(self, "exact_owner", selected_owner)?;
        }
        trace.hash.field(
            "origin",
            metadata
                .receiver_origin()
                .map_or("absent", |origin| origin.label())
                .as_bytes(),
        );
        if metadata.receiver_origin() != Some(ResolutionCallableReceiverOrigin::CurrentInstance)
            || selected_owner != Some(Some(owner.owner))
        {
            finish!();
        }
        let reasons = match transfer.rule().completion() {
            ResolutionCompletion::Complete => Vec::new(),
            ResolutionCompletion::Incomplete(reasons) => reasons
                .iter()
                .filter_map(|reason| match reason {
                    ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        };
        for chunk in reasons.chunks(super::super::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            match self.exact_gap_reason_provenance_for_reasons(chunk)? {
                SessionFactRead::Exhausted {
                    rows,
                    inventory_evidence,
                    ..
                } => {
                    let rows = rows.iter().map(|row| *row.get(self)).collect::<Vec<_>>();
                    trace.observe(
                        self,
                        "transfer_gap_provenance",
                        chunk,
                        &rows,
                        &inventory_evidence,
                    )?;
                    if inventory_evidence
                        != TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                    {
                        completion = match inventory_evidence {
                            TypedFactInventoryEvidence::Established(failure) => {
                                completion.combine(&failure)
                            }
                            TypedFactInventoryEvidence::Unestablished => {
                                completion.combine(&ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(rule),
                                ]))
                            }
                        };
                        discharged_gap_reasons.clear();
                        finish!();
                    }
                    for row in rows {
                        if row.fragment() == seed.fragment()
                            && row.source_site() == metadata.site()
                            && row.origin()
                                == LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedTypeSyntax,
                                )
                        {
                            discharged_gap_reasons.insert(row.reason());
                        }
                    }
                }
                SessionFactRead::Cancelled(evidence) => {
                    completion =
                        completion
                            .combine(&evidence)
                            .combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::Cancelled,
                            ]));
                    trace.reusable = false;
                    discharged_gap_reasons.clear();
                    finish!();
                }
            }
        }
        completion = ResolutionCompletion::Complete;
        finish!();
    }
}

#[derive(Clone)]
pub(super) enum ReceiverProofObservation {
    Owner(OwnerApplicationObservation),
    Transfer(CurrentInstanceTransferObservation),
    Base(Box<BaseReceiverContextObservation>),
}
impl ReceiverProofObservation {
    fn answer(&self) -> Option<&SelectedReceiverProofAnswer> {
        match self {
            Self::Owner(row) => row.canonical_answer.as_ref(),
            Self::Transfer(row) => row.canonical_answer.as_ref(),
            Self::Base(row) => row.canonical_answer.as_ref(),
        }
    }

    fn revoke_positive_authority(&mut self) {
        match self {
            Self::Owner(owner) => {
                owner.answer = None;
                owner.inputs = owner_seed_inputs_without_proof(
                    owner.application_slot,
                    owner.canonical_inputs.clone(),
                );
            }
            Self::Transfer(transfer) => {
                transfer.answer = None;
                transfer.completion = None;
                transfer.discharged_gap_reasons.clear();
            }
            Self::Base(base) => {
                base.answer = None;
                base.owner_application_answer = None;
            }
        }
    }

    fn base_owner_application(&self) -> Option<SemanticId> {
        match self {
            Self::Base(base) => base.owner_application,
            Self::Owner(_) | Self::Transfer(_) => None,
        }
    }
}
#[derive(Clone)]
pub(super) struct ReceiverProofMemo {
    pub(super) query: ReceiverProofQuery,
    pub(super) observation: ReceiverProofObservation,
    pub(super) receipt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}
impl ReceiverProofMemo {
    // Diagnostic classification of a previously admitted producer, not proof
    // of current usability. Only replay can provide the token for a new use.
    pub(super) fn supplied_positive_authority(&self) -> bool {
        match &self.observation {
            ReceiverProofObservation::Owner(owner) => {
                owner.answer.is_some()
                    && owner.inputs.outcome.is_exhausted()
                    && owner.inputs.outcome.evidence() == &ResolutionCompletion::Complete
                    && owner
                        .inputs
                        .application
                        .as_ref()
                        .is_some_and(|application| {
                            application.partial == Some(false) && application.complete_positions
                        })
            }
            ReceiverProofObservation::Transfer(transfer) => {
                transfer.answer.is_some() && !transfer.discharged_gap_reasons.is_empty()
            }
            ReceiverProofObservation::Base(base) => {
                base.answer.is_some()
                    && base.owner_application.is_some()
                    && base.owner_application_answer.is_some()
                    && base.source_inventory
                        == TypedFactInventoryEvidence::Established(ResolutionCompletion::Complete)
                    && base.receiver_source_completion == Some(ResolutionCompletion::Complete)
                    && base.owner.is_some()
                    && base.owner_kind.is_some()
                    && base.owner_partial == Some(false)
                    && base.owner_staticness
                        == super::super::fact_source::OwnerStaticAuthority::KnownNonStatic
            }
        }
    }
}
impl FactReadSession<'_> {
    fn consume_receiver_proof(
        &mut self,
        query: ReceiverProofQuery,
    ) -> StoreResult<ReceiverProofObservation> {
        Ok(self.consume_receiver_proof_use(query)?.observation)
    }

    fn consume_receiver_proof_use(
        &mut self,
        query: ReceiverProofQuery,
    ) -> StoreResult<ReceiptUse<ReceiverProofObservation>> {
        let question_for = |source: &dyn super::super::fact_source::SelectedTypedFactSource,
                            cancellation: &CancellationToken| {
            match query {
                ReceiverProofQuery::OwnerApplication(application) => {
                    source.selected_receiver_proof_question(application, None, cancellation)
                }
                ReceiverProofQuery::CurrentInstanceTransfer {
                    application,
                    receiver,
                    rule,
                } => source.selected_receiver_proof_question(
                    application,
                    Some((receiver, rule)),
                    cancellation,
                ),
                ReceiverProofQuery::BaseReceiverContext { reference } => {
                    source.selected_base_receiver_context_question(reference, cancellation)
                }
            }
        };
        #[cfg(any(test, feature = "test-support"))]
        let application_transfer = match query {
            ReceiverProofQuery::OwnerApplication(application) => Some((application, None)),
            ReceiverProofQuery::CurrentInstanceTransfer {
                application,
                receiver,
                rule,
            } => Some((application, Some((receiver, rule)))),
            ReceiverProofQuery::BaseReceiverContext { .. } => None,
        };
        #[cfg(any(test, feature = "test-support"))]
        if let Some((application, transfer)) = application_transfer {
            super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
                decorator.proof_attempted(None, application, transfer);
            });
        }
        let source = self.typed_source;
        let services = source.receiver_proof_services();
        let question = question_for(source, self.cancellation)?;
        #[cfg(any(test, feature = "test-support"))]
        super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
            if let Some(question) = &question {
                decorator.proof_recordable(question);
            } else if let Some((application, transfer)) = application_transfer {
                decorator.proof_refused(
                    None,
                    application,
                    transfer,
                    "selected_question_unavailable",
                );
            }
        });
        if let Some(question) = &question
            && let Some(memo) = self.receiver_proof_memos.get(question).cloned()
            && let Some(services) = services
        {
            let mut observation = memo.observation.clone();
            #[cfg(any(test, feature = "test-support"))]
            let replay_question = super::receiver_proof_tests::replay_question_for_test(question)
                .unwrap_or_else(|| question.clone());
            #[cfg(not(any(test, feature = "test-support")))]
            let replay_question = question.clone();
            let usable_receipt = match &mut observation {
                ReceiverProofObservation::Base(base) => {
                    let application_proof = if let Some(application) = base.owner_application {
                        Some(self.consume_owner_application_proof_with_receipt(application)?)
                    } else {
                        None
                    };
                    let same_answer = match &application_proof {
                        Some(proof) => proof.observation.answer == base.owner_application_answer,
                        None => base.owner_application.is_none(),
                    };
                    if let Some(proof) = &application_proof {
                        base.owner_application_receipt = proof.receipt;
                    }
                    let owner_receipt = application_proof.and_then(|proof| proof.usable_receipt);
                    // Replay both captured channels even when owner validation
                    // fails, so every dependency is forwarded to the caller.
                    let base_receipt =
                        services.replay_selected_receiver_proof(memo.receipt.as_ref());
                    if replay_question == *question
                        && same_answer
                        && (base.owner_application.is_none() || owner_receipt.is_some())
                        && let Some(base_receipt) = base_receipt
                    {
                        if base.owner_application.is_none() {
                            base.answer = None;
                        }
                        self.pending_receiver_proof_nodes
                            .push(*question.canonical_digest().as_bytes());
                        #[cfg(any(test, feature = "test-support"))]
                        super::receiver_proof_tests::with_receiver_proof_test_decorator(
                            |decorator| decorator.receipt_replayed(question),
                        );
                        let own = UsableReceiverProofReceipt::from_service_receipt(base_receipt);
                        Some(match owner_receipt {
                            Some(owner) => own.combine(owner),
                            None => own,
                        })
                    } else {
                        services.refuse_read_reuse();
                        self.receiver_proof_memos.remove(question);
                        observation.revoke_positive_authority();
                        None
                    }
                }
                _ => {
                    if let Some(receipt) =
                        services.replay_selected_receiver_proof(memo.receipt.as_ref())
                    {
                        self.pending_receiver_proof_nodes
                            .push(*question.canonical_digest().as_bytes());
                        #[cfg(any(test, feature = "test-support"))]
                        super::receiver_proof_tests::with_receiver_proof_test_decorator(
                            |decorator| decorator.receipt_replayed(question),
                        );
                        Some(super::super::fact_source::UsableReceiverProofReceipt::from_service_receipt(receipt))
                    } else {
                        services.refuse_read_reuse();
                        self.receiver_proof_memos.remove(question);
                        observation.revoke_positive_authority();
                        None
                    }
                }
            };
            let receipt = if usable_receipt.is_some() {
                SelectedReceiverProofReceipt::Replayed
            } else {
                SelectedReceiverProofReceipt::Unretained
            };
            if usable_receipt.is_none()
                && let Some(application) = observation.base_owner_application()
            {
                self.remove_pending_owner_application_node(application)?;
            }
            return Ok(ReceiptUse {
                observation,
                receipt,
                usable_receipt,
            });
        }
        #[cfg(any(test, feature = "test-support"))]
        let prior_question =
            std::mem::replace(&mut self.receiver_inventory_test_question, question.clone());
        let mut observation = None;
        let mut established = false;
        let mut nested_usable = None;
        let mut acquire = || {
            let observed = match query {
                ReceiverProofQuery::OwnerApplication(application) => {
                    ReceiverProofObservation::Owner(
                        self.read_owner_application_observation(application)?,
                    )
                }
                ReceiverProofQuery::CurrentInstanceTransfer {
                    application,
                    receiver,
                    rule,
                } => ReceiverProofObservation::Transfer(
                    self.read_current_instance_transfer_proof(application, receiver, rule)?,
                ),
                ReceiverProofQuery::BaseReceiverContext { reference } => {
                    let (observation, receipt) = self.read_base_receiver_context_use(reference)?;
                    nested_usable = receipt;
                    ReceiverProofObservation::Base(Box::new(observation))
                }
            };
            let selected = question_for(source, self.cancellation)?;
            if let (Some(services), Some(question), Some(answer)) =
                (services, question.as_ref(), observed.answer())
            {
                if selected.as_ref() == Some(question) {
                    services.record_selected_receiver_proof(question, answer);
                    established = true;
                } else {
                    #[cfg(any(test, feature = "test-support"))]
                    super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
                        if let Some((application, transfer)) = application_transfer {
                            decorator.proof_refused(
                                Some(question.source().rel_path.as_ref()),
                                application,
                                transfer,
                                "selected_question_changed",
                            );
                        }
                    });
                    services.refuse_read_reuse();
                }
            } else {
                #[cfg(any(test, feature = "test-support"))]
                super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
                    let reason = if services.is_none() {
                        "services_unavailable"
                    } else if question.is_none() {
                        "selected_question_unavailable"
                    } else {
                        "canonical_answer_unavailable"
                    };
                    if let Some((application, transfer)) = application_transfer {
                        decorator.proof_refused(
                            question.as_ref().map(|q| q.source().rel_path.as_ref()),
                            application,
                            transfer,
                            reason,
                        );
                    }
                });
                if let Some(services) = services {
                    services.refuse_read_reuse();
                }
            }
            observation = Some(observed);
            Ok(())
        };
        let (outcome, receipt) = if let Some(services) = services {
            services.capture_selected_receiver_proof(&mut acquire)
        } else {
            (acquire(), None)
        };
        #[cfg(any(test, feature = "test-support"))]
        {
            self.receiver_inventory_test_question = prior_question;
        }
        outcome?;
        let mut observation =
            observation.expect("successful proof acquisition produces an observation");
        let requires_nested = matches!(&observation, ReceiverProofObservation::Base(base) if base.owner_application.is_some());
        let retained = established
            && question.is_some()
            && receipt.is_some()
            && observation.answer().is_some()
            && (!requires_nested || nested_usable.is_some());
        let usable_receipt = if retained {
            let service_receipt = receipt
                .as_ref()
                .expect("retained proof has a service receipt");
            let usable =
                super::super::fact_source::UsableReceiverProofReceipt::from_service_receipt(
                    std::sync::Arc::clone(service_receipt),
                );
            Some(match nested_usable {
                Some(nested) => usable.combine(nested),
                None => usable,
            })
        } else {
            None
        };
        if retained {
            let question = question.expect("retained proof has a selected question");
            let receipt = receipt.expect("retained proof has a concrete receipt");
            self.pending_receiver_proof_nodes
                .push(*question.canonical_digest().as_bytes());
            self.receiver_proof_memos.insert(
                question,
                ReceiverProofMemo {
                    query,
                    observation: observation.clone(),
                    receipt,
                },
            );
        }
        if let ReceiverProofObservation::Base(base) = &mut observation
            && base.owner_application.is_none()
        {
            base.answer = None;
        }
        let receipt = if retained {
            SelectedReceiverProofReceipt::Captured
        } else {
            let base_application = observation.base_owner_application();
            observation.revoke_positive_authority();
            if let Some(application) = base_application {
                self.remove_pending_owner_application_node(application)?;
            }
            SelectedReceiverProofReceipt::Unretained
        };
        Ok(ReceiptUse {
            observation,
            receipt,
            usable_receipt,
        })
    }

    fn remove_pending_owner_application_node(
        &mut self,
        application: SemanticId,
    ) -> StoreResult<()> {
        if let Some(question) = self.typed_source.selected_receiver_proof_question(
            application,
            None,
            self.cancellation,
        )? {
            let digest = *question.canonical_digest().as_bytes();
            self.pending_receiver_proof_nodes
                .retain(|pending| pending != &digest);
        }
        Ok(())
    }

    pub(super) fn consume_owner_application_proof(
        &mut self,
        application: SemanticId,
    ) -> StoreResult<ReceiptUse<ConditionalOwnerApplicationInputs>> {
        let proof = self.consume_owner_application_proof_with_receipt(application)?;
        // Raw classification is not permission to construct a positive seed.
        Ok(ReceiptUse {
            observation: proof.observation.canonical_inputs,
            receipt: proof.receipt,
            usable_receipt: proof.usable_receipt,
        })
    }

    pub(crate) fn consume_owner_application_proof_with_receipt(
        &mut self,
        application: SemanticId,
    ) -> StoreResult<ReceiptUse<OwnerApplicationObservation>> {
        let proof =
            self.consume_receiver_proof_use(ReceiverProofQuery::OwnerApplication(application))?;
        let receipt = proof.receipt;
        let usable_receipt = proof.usable_receipt;
        let ReceiverProofObservation::Owner(observation) = proof.observation else {
            unreachable!()
        };
        Ok(ReceiptUse {
            observation,
            receipt,
            usable_receipt,
        })
    }

    pub(super) fn consume_current_instance_transfer_proof(
        &mut self,
        application: SemanticId,
        receiver: SemanticId,
        rule: SemanticId,
    ) -> StoreResult<ReceiptUse<CurrentInstanceTransferObservation>> {
        let proof =
            self.consume_receiver_proof_use(ReceiverProofQuery::CurrentInstanceTransfer {
                application,
                receiver,
                rule,
            })?;
        let receipt = proof.receipt;
        let usable_receipt = proof.usable_receipt;
        let ReceiverProofObservation::Transfer(observation) = proof.observation else {
            unreachable!()
        };
        #[cfg(any(test, feature = "test-support"))]
        if let Some(question) = self.typed_source.selected_receiver_proof_question(
            application,
            Some((receiver, rule)),
            self.cancellation,
        )? {
            super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
                decorator.transfer_proof_read(&question, &observation)
            });
        }
        Ok(ReceiptUse {
            observation,
            receipt,
            usable_receipt,
        })
    }

    pub(crate) fn consume_base_receiver_context_proof(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<BaseReceiverContextObservation> {
        Ok(self
            .consume_base_receiver_context_proof_with_receipt(reference)?
            .observation)
    }

    pub(crate) fn consume_base_receiver_context_proof_with_receipt(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<ReceiptUse<BaseReceiverContextObservation>> {
        let proof =
            self.consume_receiver_proof_use(ReceiverProofQuery::BaseReceiverContext { reference })?;
        let receipt = proof.receipt;
        let usable_receipt = proof.usable_receipt;
        let ReceiverProofObservation::Base(observation) = proof.observation else {
            unreachable!()
        };
        let mut proof = ReceiptUse {
            observation: *observation,
            receipt,
            usable_receipt,
        };
        if proof.positive_base_receipt().is_none() {
            proof.observation.answer = None;
        }
        Ok(proof)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn replay_receiver_proof_node_with_usability_for_test(
        &mut self,
        digest: &[u8; 32],
    ) -> StoreResult<(
        SelectedReceiverProofReceipt,
        Option<SelectedReceiverProofReceipt>,
        bool,
    )> {
        self.replay_receiver_proof_node_use(digest).map(|proof| {
            (
                proof.receipt,
                proof.owner_application_receipt,
                proof.usable_receipt.is_some(),
            )
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn replay_receiver_proof_node_for_test(
        &mut self,
        digest: &[u8; 32],
    ) -> StoreResult<(
        SelectedReceiverProofReceipt,
        Option<SelectedReceiverProofReceipt>,
    )> {
        self.replay_receiver_proof_node_use(digest)
            .map(|proof| (proof.receipt, proof.owner_application_receipt))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn replay_receiver_proof_node_after_owner_change_for_test(
        &mut self,
        digest: &[u8; 32],
    ) -> StoreResult<(
        SelectedReceiverProofReceipt,
        Option<SelectedReceiverProofReceipt>,
    )> {
        let Some((_, memo)) = self
            .receiver_proof_memos
            .iter()
            .find(|(question, _)| question.canonical_digest().as_bytes() == digest)
        else {
            return self.replay_receiver_proof_node_for_test(digest);
        };
        let ReceiverProofObservation::Base(base) = &memo.observation else {
            return self.replay_receiver_proof_node_for_test(digest);
        };
        if let Some(application) = base.owner_application {
            self.receiver_proof_memos
                .retain(|_, memo| memo.query != ReceiverProofQuery::OwnerApplication(application));
        }
        super::receiver_proof_tests::with_empty_application_properties(|| {
            self.replay_receiver_proof_node_for_test(digest)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn consume_base_receiver_context_with_unestablished_routes_for_test(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<ReceiptUse<BaseReceiverContextObservation>> {
        super::receiver_proof_tests::with_unestablished_base_routes(|| {
            self.consume_base_receiver_context_proof_with_receipt(reference)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn consume_base_receiver_context_without_owner_application_for_test(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<ReceiptUse<BaseReceiverContextObservation>> {
        super::receiver_proof_tests::with_empty_application_properties(|| {
            self.consume_base_receiver_context_proof_with_receipt(reference)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn consume_base_receiver_context_without_frontier_for_test(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<ReceiptUse<BaseReceiverContextObservation>> {
        super::receiver_proof_tests::with_missing_base_frontier(|| {
            self.consume_base_receiver_context_proof_with_receipt(reference)
        })
    }

    pub(super) fn replay_receiver_proof_node_use(
        &mut self,
        digest: &[u8; 32],
    ) -> StoreResult<ReceiverProofNodeReplay> {
        let Some(services) = self.typed_source.receiver_proof_services() else {
            return Ok(ReceiverProofNodeReplay {
                receipt: SelectedReceiverProofReceipt::Unretained,
                owner_application_receipt: None,
                usable_receipt: None,
            });
        };
        let Some((question, memo)) = self
            .receiver_proof_memos
            .iter()
            .find(|(question, _)| question.canonical_digest().as_bytes() == digest)
            .map(|(question, memo)| (question.clone(), memo.clone()))
        else {
            services.refuse_read_reuse();
            return Ok(ReceiverProofNodeReplay {
                receipt: SelectedReceiverProofReceipt::Unretained,
                owner_application_receipt: None,
                usable_receipt: None,
            });
        };
        let mut owner_application_receipt = None;
        let mut owner_application_replayed = true;
        let mut owner_usable_receipt = None;
        if let ReceiverProofQuery::BaseReceiverContext { .. } = memo.query {
            let ReceiverProofObservation::Base(base) = &memo.observation else {
                unreachable!("base receiver question retains its observation kind")
            };
            owner_application_replayed = if let (Some(application), Some(expected_answer)) =
                (base.owner_application, base.owner_application_answer)
            {
                let proof = self.consume_owner_application_proof_with_receipt(application)?;
                owner_application_receipt = Some(proof.receipt);
                owner_usable_receipt = proof.usable_receipt;
                owner_usable_receipt.is_some() && proof.observation.answer == Some(expected_answer)
            } else {
                base.owner_application.is_none()
            };
        }
        let current = match memo.query {
            ReceiverProofQuery::OwnerApplication(application) => self
                .typed_source
                .selected_receiver_proof_question(application, None, self.cancellation)?,
            ReceiverProofQuery::CurrentInstanceTransfer {
                application,
                receiver,
                rule,
            } => self.typed_source.selected_receiver_proof_question(
                application,
                Some((receiver, rule)),
                self.cancellation,
            )?,
            ReceiverProofQuery::BaseReceiverContext { reference } => self
                .typed_source
                .selected_base_receiver_context_question(reference, self.cancellation)?,
        };
        // Always replay the memo's channel, even if the selected question or
        // the separate owner proof has already changed. The enclosing ledger
        // must observe every original dependency on every attempted replay.
        let replayed_receipt = services.replay_selected_receiver_proof(memo.receipt.as_ref());
        if current.as_ref() == Some(&question)
            && owner_application_replayed
            && let Some(receipt) = replayed_receipt
        {
            #[cfg(any(test, feature = "test-support"))]
            super::receiver_proof_tests::with_receiver_proof_test_decorator(|decorator| {
                decorator.receipt_replayed(&question)
            });
            let own = UsableReceiverProofReceipt::from_service_receipt(receipt);
            Ok(ReceiverProofNodeReplay {
                receipt: SelectedReceiverProofReceipt::Replayed,
                owner_application_receipt,
                usable_receipt: Some(match owner_usable_receipt {
                    Some(owner) => own.combine(owner),
                    None => own,
                }),
            })
        } else {
            services.refuse_read_reuse();
            self.receiver_proof_memos.remove(&question);
            Ok(ReceiverProofNodeReplay {
                receipt: SelectedReceiverProofReceipt::Unretained,
                owner_application_receipt,
                usable_receipt: None,
            })
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FactReadSession<'_> {
    pub(crate) fn owner_seed_cycle_for_test(
        &mut self,
        application: SemanticId,
    ) -> StoreResult<[Vec<super::super::ConditionalTypeSeedRead>; 2]> {
        let fill = self.conditional_type_seeds(&[application])?;
        let hit = self.conditional_type_seeds(&[application])?;
        Ok([fill, hit])
    }

    pub(crate) fn receiver_inventory_question_for_test(
        &mut self,
        question: crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
    ) {
        self.receiver_inventory_test_question = Some(question);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FactReadSession<'_> {
    pub(crate) fn warm_receiver_transfer_batch_for_test(
        &mut self,
        receivers: &[SemanticId],
    ) -> StoreResult<bool> {
        Ok(matches!(
            self.transfers_to_targets(receivers)?,
            SessionFactRead::Exhausted { .. }
        ))
    }
    pub(crate) fn read_receiver_proof_memo_for_test(
        &mut self,
        application: SemanticId,
        transfer: Option<(SemanticId, SemanticId)>,
    ) -> StoreResult<Option<SelectedReceiverProofAnswer>> {
        let query = match transfer {
            Some((receiver, rule)) => ReceiverProofQuery::CurrentInstanceTransfer {
                application,
                receiver,
                rule,
            },
            None => ReceiverProofQuery::OwnerApplication(application),
        };
        let observed = self.consume_receiver_proof(query)?;
        let repeated = self.consume_receiver_proof(query)?;
        assert_eq!(
            observed.answer(),
            repeated.answer(),
            "one exact proof question has identical fill and memo-hit answers"
        );
        Ok(observed.answer().cloned())
    }
}
