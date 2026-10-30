//! Shared request-scoped demand execution and closed-overlay reads.
//!
//! A closed endpoint relation is immutable: it is published once, it may add
//! candidate cells, and it may never rewrite a cell another relation already
//! published. `ClosedForwardSource` layers the published relations over the
//! operation's ordinary base source, so every answer is still composed from
//! persisted candidates and the base's own coverage.

use super::*;
use crate::analyzer::resolution::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification,
    DemandClosureDischarges, DemandMemberSelection, DemandMemberSelectionOutcome,
    DemandRootDiscovery as RootDiscovery, DemandRootPlan as RootPlan,
    DemandRootProvider as RootProvider, DemandRootUnavailableReason as RootUnavailableReason,
    DemandSelectedOverlayBlueprint, EndpointSignature, FactResolutionAnswer, PartialPath,
    ReferenceSeed, ReferenceSeedBatch, ReferenceSeedReadOutcome, ResolutionCompletionAccumulator,
    ResolutionQuery, ReverseReferenceSeedRequest, SelectedContextPathSource, SemanticId,
    TypeTransferRule,
};
use crate::analyzer::resolution::{CALLER_ENVIRONMENT, DemandReferenceKey, DemandRelationKey};
use crate::analyzer::resolution::{
    CloseProgress, CloseResume, HierarchyProvenanceView, RootClosure,
};
use std::hash::Hash;

/// A root question selected by one language adapter. The generic provider
/// keeps it only for the lifetime of this one demand operation.
pub(crate) enum LanguageRootDiscovery<Q> {
    AlreadyReady {
        completion: ResolutionCompletion,
    },
    Ready {
        question: Q,
        completion: ResolutionCompletion,
    },
    Unavailable {
        reason: RootUnavailableReason,
        completion: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}

/// The language-local result of admitting a root's file or mount context.
pub(crate) enum LanguageContextPreparation<D> {
    Ready {
        data: D,
        completion: ResolutionCompletion,
    },
    Unavailable(ResolutionCompletion),
    Cancelled(ResolutionCompletion),
}

/// Prefixes the scheduler must answer after the language has prepared its
/// root question. A language may answer a prefix inside its context and return
/// no scheduler inputs, retaining that answer on `RootQuestion` instead.
pub(crate) struct LanguagePrefixInputs {
    pub(crate) references: Vec<DemandReferenceKey>,
    pub(crate) completion: ResolutionCompletion,
}

/// Completion and any placeholder reasons discharged by one closed root.
#[doc(hidden)]
pub struct LanguageClosure {
    pub(crate) outcome: RootClosure,
    pub(crate) discharges: Option<DemandClosureDischarges>,
}
impl LanguageClosure {
    #[doc(hidden)]
    pub fn completion(&self) -> &ResolutionCompletion {
        self.outcome.completion()
    }

    pub(crate) fn cancelled(completion: ResolutionCompletion) -> Self {
        Self {
            outcome: RootClosure::Cancelled(completion),
            discharges: None,
        }
    }
    pub(crate) fn settled(completion: ResolutionCompletion) -> Self {
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return Self::cancelled(completion);
        }
        Self {
            outcome: RootClosure::settled(completion),
            discharges: None,
        }
    }
}

/// Language-specific root selection and context preparation used by the
/// shared request-scoped demand provider.
pub(crate) trait DemandLanguage {
    fn root_has_receipt(&self, endpoint: &EndpointSignature) -> bool;
    fn finalize_closure(
        &mut self,
        _endpoint: &EndpointSignature,
        closure: LanguageClosure,
    ) -> Result<LanguageClosure> {
        Ok(closure)
    }

    fn qualified_members(
        &mut self,
    ) -> Option<&mut dyn crate::analyzer::resolution::QualifiedMemberProvider> {
        None
    }

    fn cancel_close_root(&mut self, _endpoint: &EndpointSignature) {}

    // This mirrors the approved scheduler handoff without hiding its evidence inputs.
    #[allow(clippy::too_many_arguments)]
    fn poll_close_root(
        &mut self,
        endpoint: &EndpointSignature,
        question: &Self::RootQuestion,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        initial_members: Option<&DemandMemberSelection>,
        member_completion: &ResolutionCompletion,
        _provenance: HierarchyProvenanceView<'_>,
        resume: CloseResume<'_>,
    ) -> Result<CloseProgress<LanguageClosure>> {
        assert!(
            matches!(resume, CloseResume::Start),
            "only a suspended language resumes"
        );
        let closure = if let Some(selection) = initial_members {
            self.close_selected_members(endpoint, question, context, inputs, selection)?
        } else {
            self.close_root_with_member_completion(
                endpoint,
                question,
                context,
                inputs,
                member_completion,
            )?
        };
        Ok(CloseProgress::Ready(closure))
    }

    type RootQuestion;
    type ContextKey: Clone + Eq + Hash;
    type ContextData;

    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<Self::RootQuestion>>;

    /// Prepare independent root reads as one batch before the provider
    /// materializes their language questions. The default retains the scalar
    /// behavior for languages without a keyed batch reader.
    fn prepare_root_discoveries(&mut self, _endpoints: &[EndpointSignature]) -> Result<()> {
        Ok(())
    }

    /// Whether this language can batch its independent root source reads.
    fn supports_batched_root_discoveries(&self) -> bool {
        false
    }

    /// The key includes every dimension that changes a source context, such
    /// as Go's source role. Returning `None` means the language's root is
    /// already represented by its own query plan and needs no file context.
    fn context_key(&self, question: &Self::RootQuestion) -> Option<Self::ContextKey>;

    fn prepare_context(
        &mut self,
        key: &Self::ContextKey,
        question: &Self::RootQuestion,
    ) -> Result<LanguageContextPreparation<Self::ContextData>>;

    fn prefix_inputs(
        &mut self,
        question: &mut Self::RootQuestion,
        context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs>;

    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        question: &Self::RootQuestion,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure>;

    /// Include a ready member reader's evidence before publication and memoization.
    fn close_root_with_member_completion(
        &mut self,
        endpoint: &EndpointSignature,
        question: &Self::RootQuestion,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        member_completion: &ResolutionCompletion,
    ) -> Result<LanguageClosure> {
        let mut closure = self.close_root(endpoint, question, context, inputs)?;
        closure.outcome = closure.outcome.combine(member_completion);
        Ok(closure)
    }

    /// Select the declaring owners of a requested member after the receiver
    /// references resolve. The scheduler owns all hierarchy dependencies.
    fn member_selection(
        &mut self,
        _question: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<DemandMemberSelectionOutcome> {
        Ok(DemandMemberSelectionOutcome::Ready {
            request: None,
            completion: ResolutionCompletion::Complete,
        })
    }

    fn close_selected_members(
        &mut self,
        _endpoint: &EndpointSignature,
        _question: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        _selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        unreachable!("a language requesting member selection installs its result")
    }

    fn reverse_dependencies(
        &mut self,
        _endpoint: &EndpointSignature,
    ) -> Result<Vec<EndpointSignature>> {
        Ok(Vec::new())
    }

    fn close_reverse(&mut self, _endpoint: &EndpointSignature) {}
}

struct PreparedContext<D> {
    data: D,
    completion: ResolutionCompletion,
}

struct PendingRoot<Q, K> {
    question: Q,
    context_key: Option<K>,
    prefixes: Vec<DemandReferenceKey>,
    completion: ResolutionCompletion,
    closed: bool,
    closed_completion: Option<ResolutionCompletion>,
}

/// The common demand lifecycle. Its maps are owned by the selected operation
/// and are dropped with it; they never become workspace or selection caches.
pub(crate) struct DemandProvider<L: DemandLanguage> {
    language: L,
    contexts: HashMap<L::ContextKey, PreparedContext<L::ContextData>>,
    pending: HashMap<DemandRelationKey, PendingRoot<L::RootQuestion, L::ContextKey>>,
    discharges: HashMap<DemandRelationKey, DemandClosureDischarges>,
}

impl<L: DemandLanguage> DemandProvider<L> {
    pub(crate) fn new(language: L) -> Self {
        Self {
            language,
            contexts: HashMap::default(),
            pending: HashMap::default(),
            discharges: HashMap::default(),
        }
    }

    fn finish_closure(
        &mut self,
        endpoint: &DemandRelationKey,
        closure: LanguageClosure,
    ) -> Result<RootClosure> {
        let closure = self.language.finalize_closure(endpoint, closure)?;
        let root = self
            .pending
            .get_mut(endpoint)
            .expect("only discovered roots may close");
        root.closed = !matches!(closure.outcome, RootClosure::Cancelled(_));
        if root.closed {
            debug_assert!(self.language.root_has_receipt(endpoint));
            root.closed_completion = Some(closure.outcome.completion().clone());
            if let Some(discharges) = closure.discharges {
                self.discharges.insert(endpoint.clone(), discharges);
            }
        }
        Ok(closure.outcome)
    }

    fn plan(root: &PendingRoot<L::RootQuestion, L::ContextKey>) -> RootPlan {
        RootPlan {
            prefixes: root.prefixes.clone(),
            completion: root.completion.clone(),
        }
    }
}

impl<L: DemandLanguage> RootProvider for DemandProvider<L> {
    fn qualified_members(
        &mut self,
    ) -> Option<&mut dyn crate::analyzer::resolution::QualifiedMemberProvider> {
        self.language.qualified_members()
    }

    fn cancel_close(&mut self, endpoint: &DemandRelationKey) {
        self.language.cancel_close_root(endpoint);
    }

    fn poll_close(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        initial_members: Option<&DemandMemberSelection>,
        member_completion: &ResolutionCompletion,
        provenance: HierarchyProvenanceView<'_>,
        resume: CloseResume<'_>,
    ) -> Result<CloseProgress<RootClosure>> {
        let root = self
            .pending
            .get(endpoint)
            .expect("only discovered roots close");
        let context = root
            .context_key
            .as_ref()
            .and_then(|key| self.contexts.get(key))
            .map(|context| &context.data);
        Ok(
            match self.language.poll_close_root(
                endpoint,
                &root.question,
                context,
                inputs,
                initial_members,
                member_completion,
                provenance,
                resume,
            )? {
                CloseProgress::Ready(closure) => {
                    CloseProgress::Ready(self.finish_closure(endpoint, closure)?)
                }
                CloseProgress::Reference {
                    continuation,
                    key,
                    completion,
                } => CloseProgress::Reference {
                    continuation,
                    key,
                    completion,
                },
                CloseProgress::Members {
                    continuation,
                    request,
                    completion,
                } => CloseProgress::Members {
                    continuation,
                    request,
                    completion,
                },
                CloseProgress::Cancelled(completion) => CloseProgress::Cancelled(completion),
            },
        )
    }

    fn supports_batched_discoveries(&self) -> bool {
        self.language.supports_batched_root_discoveries()
    }

    fn discover_many(&mut self, endpoints: &[DemandRelationKey]) -> Result<Vec<RootDiscovery>> {
        let mut missing = Vec::new();
        let mut seen = HashSet::default();
        for endpoint in endpoints {
            assert_eq!(
                endpoint.environment, CALLER_ENVIRONMENT,
                "language providers still execute in the caller environment"
            );
            if !self.pending.contains_key(endpoint) && seen.insert(endpoint.clone()) {
                missing.push(endpoint.clone());
            }
        }
        let missing = missing
            .iter()
            .map(|key| key.endpoint.clone())
            .collect::<Vec<_>>();
        self.language.prepare_root_discoveries(&missing)?;
        endpoints
            .iter()
            .map(|endpoint| self.discover(endpoint))
            .collect()
    }

    fn reverse_dependencies(
        &mut self,
        endpoint: &DemandRelationKey,
    ) -> Result<Vec<DemandRelationKey>> {
        assert_eq!(
            endpoint.environment, CALLER_ENVIRONMENT,
            "language providers still execute in the caller environment"
        );
        let endpoint_environment = endpoint.environment;
        self.language
            .reverse_dependencies(endpoint)
            .map(|endpoints| {
                endpoints
                    .into_iter()
                    .map(|endpoint| DemandRelationKey {
                        endpoint,
                        environment: endpoint_environment,
                    })
                    .collect()
            })
    }

    fn close_reverse(&mut self, endpoint: &DemandRelationKey) {
        assert_eq!(
            endpoint.environment, CALLER_ENVIRONMENT,
            "language providers still execute in the caller environment"
        );
        self.language.close_reverse(endpoint);
    }

    fn discover(&mut self, endpoint: &DemandRelationKey) -> Result<RootDiscovery> {
        assert_eq!(
            endpoint.environment, CALLER_ENVIRONMENT,
            "language providers still execute in the caller environment"
        );
        if let Some(root) = self.pending.get(endpoint) {
            return Ok(if root.closed {
                RootDiscovery::AlreadyReady {
                    completion: root.completion.combine(
                        root.closed_completion
                            .as_ref()
                            .expect("a closed demand root retains its closure completion"),
                    ),
                }
            } else {
                RootDiscovery::Ready(Self::plan(root))
            });
        }
        let (mut question, mut evidence) = match self.language.discover_root(endpoint)? {
            LanguageRootDiscovery::AlreadyReady { completion } => {
                return Ok(RootDiscovery::AlreadyReady { completion });
            }
            LanguageRootDiscovery::Ready {
                question,
                completion,
            } => (question, completion),
            LanguageRootDiscovery::Unavailable { reason, completion } => {
                return Ok(RootDiscovery::Unavailable { reason, completion });
            }
            LanguageRootDiscovery::Cancelled(completion) => {
                return Ok(RootDiscovery::Cancelled(completion));
            }
        };
        let context_key = self.language.context_key(&question);
        if let Some(key) = context_key.as_ref() {
            if !self.contexts.contains_key(key) {
                match self.language.prepare_context(key, &question)? {
                    LanguageContextPreparation::Ready { data, completion } => {
                        assert!(
                            self.contexts
                                .insert(key.clone(), PreparedContext { data, completion })
                                .is_none()
                        );
                    }
                    LanguageContextPreparation::Unavailable(completion) => {
                        return Ok(RootDiscovery::Unavailable {
                            reason: RootUnavailableReason::IncompletePreparation,
                            completion: evidence.combine(&completion),
                        });
                    }
                    LanguageContextPreparation::Cancelled(completion) => {
                        return Ok(RootDiscovery::Cancelled(evidence.combine(&completion)));
                    }
                }
            }
            evidence = evidence.combine(&self.contexts[key].completion);
        }
        let context = context_key
            .as_ref()
            .and_then(|key| self.contexts.get(key))
            .map(|context| &context.data);
        let prefixes = self.language.prefix_inputs(&mut question, context)?;
        evidence = evidence.combine(&prefixes.completion);
        if evidence.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return Ok(RootDiscovery::Cancelled(evidence));
        }
        let root = PendingRoot {
            question,
            context_key,
            prefixes: prefixes.references,
            completion: evidence,
            closed: false,
            closed_completion: None,
        };
        let plan = Self::plan(&root);
        assert!(self.pending.insert(endpoint.clone(), root).is_none());
        Ok(RootDiscovery::Ready(plan))
    }

    fn close(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<RootClosure> {
        self.close_with_member_completion(endpoint, inputs, &ResolutionCompletion::Complete)
    }

    fn close_with_member_completion(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        member_completion: &ResolutionCompletion,
    ) -> Result<RootClosure> {
        let root = self
            .pending
            .get_mut(endpoint)
            .expect("only discovered roots may close");
        let context = root
            .context_key
            .as_ref()
            .and_then(|key| self.contexts.get(key))
            .map(|context| &context.data);
        let closure = self.language.close_root_with_member_completion(
            endpoint,
            &root.question,
            context,
            inputs,
            member_completion,
        )?;
        self.finish_closure(endpoint, closure)
    }

    fn member_selection(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<DemandMemberSelectionOutcome> {
        let root = self
            .pending
            .get(endpoint)
            .expect("member selection follows discovery");
        let context = root
            .context_key
            .as_ref()
            .and_then(|key| self.contexts.get(key))
            .map(|context| &context.data);
        self.language
            .member_selection(&root.question, context, inputs)
    }

    fn close_selected_members(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        selection: &DemandMemberSelection,
    ) -> Result<RootClosure> {
        let root = self
            .pending
            .get(endpoint)
            .expect("selected member closure follows discovery");
        let context = root
            .context_key
            .as_ref()
            .and_then(|key| self.contexts.get(key))
            .map(|context| &context.data);
        let closure = self.language.close_selected_members(
            endpoint,
            &root.question,
            context,
            inputs,
            selection,
        )?;
        self.finish_closure(endpoint, closure)
    }

    fn retain_member_provider_reasons(
        &mut self,
        endpoint: &DemandRelationKey,
        reasons: &BTreeSet<SemanticId>,
    ) {
        self.discharges
            .entry(endpoint.clone())
            .or_default()
            .discharged_provider_reasons
            .extend(reasons.iter().copied());
    }

    fn discharged_provider_reasons(
        &self,
        endpoint: &DemandRelationKey,
    ) -> Option<&BTreeSet<SemanticId>> {
        self.discharges
            .get(endpoint)
            .map(|discharges| &discharges.discharged_provider_reasons)
            .filter(|reasons| !reasons.is_empty())
    }

    fn resolved_closure_discharges(
        &self,
        endpoint: &DemandRelationKey,
    ) -> Option<DemandClosureDischarges> {
        self.discharges.get(endpoint).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::{BindingNodeId, ResolutionIncompleteReason, StackPattern};
    use std::cell::Cell;
    use std::rc::Rc;

    struct RepeatedRootLanguage {
        discoveries: Rc<Cell<usize>>,
        discovery_completion: ResolutionCompletion,
        closure_completion: ResolutionCompletion,
        discharged: SemanticId,
    }

    impl DemandLanguage for RepeatedRootLanguage {
        fn root_has_receipt(&self, _: &EndpointSignature) -> bool {
            true
        }
        type RootQuestion = ();
        type ContextKey = ();
        type ContextData = ();

        fn discover_root(
            &mut self,
            _endpoint: &EndpointSignature,
        ) -> Result<LanguageRootDiscovery<Self::RootQuestion>> {
            self.discoveries.set(self.discoveries.get() + 1);
            Ok(LanguageRootDiscovery::Ready {
                question: (),
                completion: self.discovery_completion.clone(),
            })
        }

        fn context_key(&self, _question: &Self::RootQuestion) -> Option<Self::ContextKey> {
            None
        }

        fn prepare_context(
            &mut self,
            _key: &Self::ContextKey,
            _question: &Self::RootQuestion,
        ) -> Result<LanguageContextPreparation<Self::ContextData>> {
            unreachable!("the fixture root needs no context")
        }

        fn prefix_inputs(
            &mut self,
            _question: &mut Self::RootQuestion,
            _context: Option<&Self::ContextData>,
        ) -> Result<LanguagePrefixInputs> {
            Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: ResolutionCompletion::Complete,
            })
        }

        fn close_root(
            &mut self,
            _endpoint: &EndpointSignature,
            _question: &Self::RootQuestion,
            _context: Option<&Self::ContextData>,
            _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<LanguageClosure> {
            Ok(LanguageClosure {
                outcome: RootClosure::Published(self.closure_completion.clone()),
                discharges: Some(DemandClosureDischarges::exact([self.discharged])),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: owner review found Ready(None,incomplete) lost its reason on positive memo reuse"
    )]
    fn member_reader_completion_is_memoized_before_rediscovery() {
        let gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::for_test("member-none-gap"),
            )]);
        let endpoint = DemandRelationKey::caller(EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::closed([SemanticId::for_test("member-none-root")]),
            StackPattern::closed(Vec::<BindingNodeId>::new()),
        ));
        let discoveries = Rc::new(Cell::new(0));
        let mut provider = DemandProvider::new(RepeatedRootLanguage {
            discoveries: Rc::clone(&discoveries),
            discovery_completion: ResolutionCompletion::Complete,
            closure_completion: ResolutionCompletion::Complete,
            discharged: SemanticId::for_test("memo-discharged"),
        });
        assert!(matches!(
            provider.discover(&endpoint).unwrap(),
            RootDiscovery::Ready(_)
        ));
        assert_eq!(
            provider
                .close_with_member_completion(&endpoint, &[], &gap)
                .unwrap()
                .completion(),
            &gap
        );
        let RootDiscovery::AlreadyReady { completion } = provider.discover(&endpoint).unwrap()
        else {
            panic!("positive memo")
        };
        assert_eq!(completion, gap);
        assert_eq!(discoveries.get(), 1);
    }

    #[test]
    fn rediscovered_closed_root_reuses_its_completion_and_discharges() {
        let discoveries = Rc::new(Cell::new(0));
        let discovery_gap = SemanticId::for_test("demand-discovery-gap");
        let closure_gap = SemanticId::for_test("demand-closure-gap");
        let discharged = SemanticId::for_test("demand-discharged-gap");
        let endpoint = EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::closed([SemanticId::for_test("demand-root")]),
            StackPattern::closed(Vec::<BindingNodeId>::new()),
        );
        let endpoint = DemandRelationKey::caller(endpoint);
        let mut provider = DemandProvider::new(RepeatedRootLanguage {
            discoveries: Rc::clone(&discoveries),
            discovery_completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(discovery_gap),
            ]),
            closure_completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(closure_gap),
            ]),
            discharged,
        });

        assert!(matches!(
            RootProvider::discover(&mut provider, &endpoint).unwrap(),
            RootDiscovery::Ready(_)
        ));
        RootProvider::close(&mut provider, &endpoint, &[]).unwrap();

        let RootDiscovery::AlreadyReady { completion } =
            RootProvider::discover(&mut provider, &endpoint).unwrap()
        else {
            panic!("a closed endpoint is reused instead of being planned again");
        };
        assert!(
            completion.contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                discovery_gap
            ))
        );
        assert!(
            completion
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(closure_gap))
        );
        assert_eq!(discoveries.get(), 1, "the same endpoint has one root plan");
        assert_eq!(
            RootProvider::resolved_closure_discharges(&provider, &endpoint),
            Some(DemandClosureDischarges::exact([discharged]))
        );
    }
}

#[derive(Default)]
#[doc(hidden)]
pub struct ClosedRelations {
    /// Language-certified universe fallbacks, owned by this query only.
    pub(crate) selected_universe: HashMap<
        SemanticId,
        (
            DemandRelationKey,
            super::source_demand::SourceDemandKey,
            Option<crate::analyzer::resolution::UniverseEntry>,
        ),
    >,
    #[doc(hidden)]
    pub registrations:
        HashMap<DemandRelationKey, super::demand_closure::ClosedEndpointRegistration>,
    #[doc(hidden)]
    pub continuations: super::demand_closure::ContinuationRelations,
    #[doc(hidden)]
    pub endpoints: HashMap<DemandRelationKey, DemandSelectedOverlayBlueprint>,
    /// Endpoint-local obligations returned by a demanded root closure. These
    /// must remain branch completion when the selected fact source reads the
    /// caller's already-published paths for that exact root.
    pub(crate) endpoint_completions: HashMap<DemandRelationKey, ResolutionCompletion>,
    #[doc(hidden)]
    pub paths: HashMap<CandidatePathIdentity, PartialPath>,
    /// Equal cells can belong to several endpoint relations. Reverse reads
    /// emit the cell only through the first relation that published it.
    path_owners: HashMap<
        (
            CandidatePathIdentity,
            crate::analyzer::resolution::EnvironmentId,
        ),
        DemandRelationKey,
    >,
    pub(crate) base_ready: HashSet<DemandRelationKey>,
    /// Closed roots whose selected relation excludes provisional base routes.
    /// With no additions this is an empty domain, as used by Rust's negative
    /// closures. Scala uses it after proving a lexical import qualifier.
    pub(crate) excluded_base: HashSet<DemandRelationKey>,
    pub(crate) unconditional: Option<ResolutionCompletion>,
    /// Reverse candidate coverage is a different relation from forward
    /// candidate coverage: it carries the reverse inventory's own gaps, which
    /// a forward read never sees. The two therefore share the arena but not
    /// one unconditional cell.
    pub(crate) unconditional_reverse: Option<ResolutionCompletion>,
    /// Reverse targets whose candidate domain was discovered and completely
    /// forward-validated. A reverse candidate read before any of them is a
    /// read the demand relations do not justify.
    pub(crate) reverse_targets: HashSet<SemanticId>,
    pub(crate) reverse_endpoints: HashSet<DemandRelationKey>,
    #[cfg(test)]
    pub(crate) reads: Vec<EndpointSignature>,
}

impl ClosedRelations {
    pub(super) fn registered_endpoint(
        &self,
        endpoint: &EndpointSignature,
    ) -> Option<&super::demand_closure::ClosedEndpointRegistration> {
        self.registrations
            .get(&DemandRelationKey::caller(endpoint.clone()))
    }

    pub(crate) fn publish(
        &mut self,
        endpoint: DemandRelationKey,
        relation: DemandSelectedOverlayBlueprint,
        paths: Vec<(CandidatePathIdentity, PartialPath)>,
    ) {
        assert!(
            !self.endpoints.contains_key(&endpoint),
            "a closed relation is immutable"
        );
        // Validate every cell before publishing any part of this relation.
        for (id, path) in &paths {
            if let Some(previous) = self.paths.get(id) {
                assert_eq!(
                    previous, path,
                    "one candidate identity must have one immutable cell"
                );
            }
        }
        for (id, path) in &paths {
            self.paths.entry(*id).or_insert_with(|| path.clone());
            self.path_owners
                .entry((*id, endpoint.environment))
                .or_insert_with(|| endpoint.clone());
        }
        self.endpoints.insert(endpoint, relation);
    }

    pub(crate) fn publish_without_base(
        &mut self,
        endpoint: DemandRelationKey,
        relation: DemandSelectedOverlayBlueprint,
        paths: Vec<(CandidatePathIdentity, PartialPath)>,
        completion: ResolutionCompletion,
    ) {
        self.publish(endpoint.clone(), relation, paths);
        self.reverse_endpoints.insert(endpoint.clone());
        assert!(self.excluded_base.insert(endpoint.clone()));
        assert!(
            self.endpoint_completions
                .insert(endpoint, completion)
                .is_none()
        );
    }

    /// Keyed evidence is scoped to the requested relation in either direction.
    fn branch_completion(
        &self,
        key: &DemandRelationKey,
        base: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        self.endpoint_completions.get(key).map_or_else(
            || base.clone(),
            |completion| {
                if self.excluded_base.contains(key) && self.endpoints.contains_key(key) {
                    completion.clone()
                } else {
                    base.combine(completion)
                }
            },
        )
    }

    pub(crate) fn observe_coverage(&mut self, completion: &ResolutionCompletion) {
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return;
        }
        match &self.unconditional {
            Some(previous) => assert_eq!(
                previous, completion,
                "all endpoint and local reads share operation-wide unconditional coverage"
            ),
            None => self.unconditional = Some(completion.clone()),
        }
    }

    pub(crate) fn observe_reverse_coverage(&mut self, completion: &ResolutionCompletion) {
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
            return;
        }
        match &self.unconditional_reverse {
            Some(previous) => assert_eq!(
                previous, completion,
                "all reverse candidate reads share operation-wide unconditional coverage"
            ),
            None => self.unconditional_reverse = Some(completion.clone()),
        }
    }
}

struct PackageInventoryRows<'a> {
    complete: &'a RefCell<Option<bool>>,
    fragments: &'a RefCell<HashMap<BindingFragmentId, bool>>,
}

pub(crate) struct ClosedForwardSource<'a> {
    environment: crate::analyzer::resolution::EnvironmentId,
    pub(crate) base: &'a dyn BatchResolutionFragmentSource,
    pub(crate) paths: &'a dyn SelectedContextPathSource,
    pub(crate) arena: &'a RefCell<ClosedRelations>,
    /// Rows supplied by the language hook for this request. Local bindings
    /// inside a reached file can finish without asking the root provider for
    /// another context, so proof reads must also see those hook publications.
    package_inventory: Option<PackageInventoryRows<'a>>,
    pub(crate) session: &'a ResolutionSession,
}

impl<'a> ClosedForwardSource<'a> {
    pub(crate) fn new(
        base: &'a dyn BatchResolutionFragmentSource,
        paths: &'a dyn SelectedContextPathSource,
        arena: &'a RefCell<ClosedRelations>,
        session: &'a ResolutionSession,
        environment: crate::analyzer::resolution::EnvironmentId,
    ) -> Self {
        Self {
            environment,
            base,
            paths,
            arena,
            session,
            package_inventory: None,
        }
    }

    pub(crate) fn with_package_inventory_rows(
        mut self,
        complete: &'a RefCell<Option<bool>>,
        fragments: &'a RefCell<HashMap<BindingFragmentId, bool>>,
    ) -> Self {
        self.package_inventory = Some(PackageInventoryRows {
            complete,
            fragments,
        });
        self
    }
}

impl ClosedForwardSource<'_> {
    fn relation_key(&self, endpoint: &EndpointSignature) -> DemandRelationKey {
        DemandRelationKey {
            endpoint: endpoint.clone(),
            environment: self.environment,
        }
    }

    /// Reverse mirror of `visit_forward_candidate_match_pages_limited`.
    ///
    /// The reverse readiness law is not the forward one. A forward read names
    /// the endpoint its own relation was closed under, so a missing key is a
    /// read before closure. A reverse read walks the other way: it names the
    /// *end* of a bridge, whose forward closure is keyed by its start.
    /// Production readiness exhausts the exact reverse endpoint's dependencies
    /// before this read. The test oracle also supports whole-target closure.
    /// Every published relation then filters the base rows and contributes its
    /// own reverse additions, without reopening the base; each retained base
    /// row is charged one session step exactly as the forward page visitor
    /// charges it.
    fn visit_reverse_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        limit: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        assert!(requests.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&limit));
        for (ordinal, request) in requests.iter().enumerate() {
            assert_eq!(request.request_ordinal(), ordinal);
        }
        if self.arena.borrow().reverse_targets.is_empty()
            && requests.iter().any(|request| {
                !self
                    .arena
                    .borrow()
                    .reverse_endpoints
                    .contains(&self.relation_key(request.endpoint()))
            })
        {
            return Err(StoreError::new(
                "selected reverse candidate read before its target was materialized".to_owned(),
            ));
        }
        let mut suppressed = vec![ResolutionCompletion::Complete; requests.len()];
        let mut stopped = false;
        let mut cancellation_observed = false;
        let mut coverage =
            self.base
                .visit_reverse_candidate_match_pages(requests, cancellation, &mut |page| {
                    assert!(!stopped, "base emitted after its visitor stopped");
                    let mut retained = Vec::with_capacity(page.len());
                    {
                        let arena = self.arena.borrow();
                        let candidates = page
                            .iter()
                            .map(|row| row.candidate())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();
                        let mut excluded = BTreeSet::new();
                        let mut excluded_evidence = HashMap::default();
                        if arena.endpoints.keys().any(|endpoint| endpoint.environment == self.environment && arena.excluded_base.contains(endpoint)) {
                            let hydrated = self.base.hydrate_candidate_paths(&candidates, cancellation)?;
                            if cancellation.is_cancelled() {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                            let returned = hydrated.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
                            let requested = candidates.iter().copied().collect::<BTreeSet<_>>();
                            if returned != requested {
                                return Err(StoreError::new(format!("closed reverse base candidates lack cells: requested={requested:?}, returned={returned:?}")));
                            }
                            for (id, path) in hydrated {
                                let key = self.relation_key(path.start());
                                if arena.excluded_base.contains(&key) {
                                    excluded.insert(id);
                                    if let Some(completion) = arena.endpoint_completions.get(&key) {
                                        excluded_evidence.insert(id, completion);
                                    }
                                }
                            }
                        }
                        for (endpoint, relation) in &arena.endpoints {
                            if endpoint.environment != self.environment { continue; }
                            if arena.excluded_base.contains(endpoint) { continue; }
                            if !relation.check_base_candidates(
                                self.paths,
                                self.base,
                                &candidates,
                                cancellation,
                            )? {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                        }
                        for row in page {
                            if cancellation.is_cancelled() || !self.session.scope_step() {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                            if !excluded.contains(&row.candidate()) {
                                retained.push(*row);
                            } else if let Some(completion) = excluded_evidence.get(&row.candidate()) {
                                let branch = &mut suppressed[row.request_ordinal()];
                                *branch = branch.combine(completion);
                            }
                        }
                    }
                    if !retained.is_empty() {
                        stopped = !visitor(&retained)?;
                    }
                    Ok(!stopped)
                })?;
        if cancellation_observed {
            coverage = BatchCandidateCompletionOutcome::new(
                requests.len(),
                coverage
                    .unconditional_completion()
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ])),
                coverage.branch_completions().iter().cloned(),
            );
        }
        {
            let mut arena = self.arena.borrow_mut();
            arena.observe_reverse_coverage(coverage.unconditional_completion());
            #[cfg(test)]
            arena
                .reads
                .extend(requests.iter().map(|request| request.endpoint().clone()));
        }
        assert_eq!(coverage.branch_completions().len(), requests.len());
        if stopped
            || coverage
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(coverage);
        }
        let mut unconditional = ResolutionCompletionAccumulator::default();
        unconditional.include(coverage.unconditional_completion());
        let branches = {
            let arena = self.arena.borrow();
            requests
                .iter()
                .enumerate()
                .map(|(ordinal, request)| {
                    arena
                        .branch_completion(
                            &self.relation_key(request.endpoint()),
                            &coverage.branch_completions()[ordinal],
                        )
                        .combine(&suppressed[ordinal])
                })
                .collect::<Vec<_>>()
        };
        'requests: for (ordinal, request) in requests.iter().enumerate() {
            let arena = self.arena.borrow();
            for (endpoint, relation) in &arena.endpoints {
                if endpoint.environment != self.environment {
                    continue;
                }
                let local = [BatchCandidateRequest::new(0, request.endpoint().clone())];
                let local_coverage = BatchCandidateCompletionOutcome::new(
                    1,
                    ResolutionCompletion::Complete,
                    [branches[ordinal].clone()],
                );
                let added = relation.visit_reverse_additions(
                    self.paths,
                    &local,
                    local_coverage,
                    limit,
                    cancellation,
                    self.session,
                    &mut |page| {
                        assert!(!stopped, "overlay emitted after its visitor stopped");
                        let remapped = page
                            .iter()
                            .filter(|row| {
                                &arena.path_owners[&(row.candidate(), self.environment)] == endpoint
                            })
                            .map(|row| BatchCandidateMatch::new(row.candidate(), ordinal))
                            .collect::<Vec<_>>();
                        if !remapped.is_empty() {
                            stopped = !visitor(&remapped)?;
                        }
                        Ok(!stopped)
                    },
                )?;
                unconditional.include(added.unconditional_completion());
                assert_eq!(added.branch_completions(), &branches[ordinal..=ordinal]);
                if stopped
                    || added
                        .unconditional_completion()
                        .contains_reason(ResolutionIncompleteReason::Cancelled)
                {
                    break 'requests;
                }
            }
        }
        Ok(BatchCandidateCompletionOutcome::new(
            requests.len(),
            unconditional.finish(),
            branches,
        ))
    }
}

impl BatchResolutionFragmentSource for ClosedForwardSource<'_> {
    fn candidate_admission_session(&self) -> Option<&ResolutionSession> {
        Some(self.session)
    }

    fn identity_content_digest(
        &self,
        key: crate::analyzer::resolution::ResolutionIdentityDigestKey,
        cancellation: &CancellationToken,
    ) -> Result<Option<[u8; 32]>> {
        self.base.identity_content_digest(key, cancellation)
    }

    /// The persisted selection behind this source names the authority.
    ///
    /// This source also serves the relations the provider has closed, and that
    /// arena grows while the operation runs, so the authority alone does not
    /// say what this source will answer at an arbitrary moment. It does say it
    /// for the answers a caller may memoize: a closed relation is immutable,
    /// and the readiness gate holds every frame until each endpoint it
    /// requested has a closed relation, so a reference's answer is the same
    /// whenever inside one operation it is computed.
    fn selection_authority(&self) -> Option<crate::analyzer::resolution::SeedReadAuthority> {
        self.base.selection_authority()
    }

    fn admits_reverse_reference(&self, reference: SemanticId) -> bool {
        self.base.admits_reverse_reference(reference)
    }

    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        self.base.scope_reverse_inventory_completion(completion)
    }

    fn namespace_definition_languages(&self) -> Vec<crate::analyzer::Language> {
        self.base.namespace_definition_languages()
    }

    fn semantic_language_of(
        &self,
        identity: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::Language>> {
        self.base.semantic_language_of(identity, cancellation)
    }

    fn universe_entry(
        &self,
        reference: SemanticId,
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::resolution::UniverseEntry>> {
        self.base.universe_entry(reference, namespace, cancellation)
    }

    fn selected_universe_entry(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::resolution::UniverseEntry>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let arena = self.arena.borrow();
        Ok(arena
            .selected_universe
            .get(&reference)
            .and_then(|(owner, _, entry)| {
                arena
                    .endpoints
                    .contains_key(owner)
                    .then_some(*entry)
                    .flatten()
            }))
    }

    fn intern_shared_name_digest(
        &self,
        digest: [u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        self.base.intern_shared_name_digest(digest, cancellation)
    }

    fn shared_name_digest_for_identity(
        &self,
        identity: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<[u8; 32]>> {
        self.base
            .shared_name_digest_for_identity(identity, cancellation)
    }

    fn supports_direct_type_shapes(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.base
            .supports_direct_type_shapes(reference, cancellation)
    }

    fn supports_go_universe(&self) -> bool {
        self.base.supports_go_universe()
    }

    fn go_package_inventory_complete(&self) -> Option<bool> {
        self.package_inventory
            .as_ref()
            .and_then(|rows| *rows.complete.borrow())
            .map(|complete| complete || self.base.go_package_inventory_complete() == Some(true))
            .or_else(|| self.base.go_package_inventory_complete())
    }

    fn go_package_inventory_complete_for_fragment(&self, fragment: BindingFragmentId) -> bool {
        self.package_inventory
            .as_ref()
            .and_then(|rows| rows.fragments.borrow().get(&fragment).copied())
            .unwrap_or_else(|| {
                self.base
                    .go_package_inventory_complete_for_fragment(fragment)
            })
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> Result<Option<ReferenceSeed>> {
        self.base.reference_seed(query, cancellation)
    }
    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> Result<ReferenceSeedReadOutcome> {
        self.base.lookup_reference_seeds(queries, cancellation)
    }
    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<BindingNodeId>> {
        self.base.lookup_definition_node(definition, cancellation)
    }
    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<BatchDefinitionNode>> {
        self.base.lookup_definition_nodes(definitions, cancellation)
    }
    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> Result<Vec<ReferenceSeed>> {
        // A reverse seed is read from the persisted and transient lexical
        // stores by reference semantic. No closed relation participates, so
        // this delegates exactly like `lookup_definition_nodes`.
        self.base
            .issue_reverse_reference_seeds(requests, cancellation)
    }
    fn visit_reference_seed_batches(
        &self,
        size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> Result<bool>,
    ) -> Result<ResolutionCompletion> {
        self.base
            .visit_reference_seed_batches(size, cancellation, visitor)
    }
    fn scope_owners_for_heads(
        &self,
        heads: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<crate::analyzer::resolution::LoweredMemberScopeProperty>> {
        self.base.scope_owners_for_heads(heads, cancellation)
    }

    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> Result<Vec<BatchEndpointClassification>> {
        self.base.classify_endpoint_nodes(nodes, cancellation)
    }
    fn classify_endpoint_nodes_with_member_owners(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
        member_owners: &mut crate::analyzer::resolution::ClassificationMemberOwnerReader<'_>,
    ) -> Result<Option<Vec<BatchEndpointClassification>>> {
        self.base
            .classify_endpoint_nodes_with_member_owners(nodes, cancellation, member_owners)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> Result<BatchCandidateOutcome> {
        let mut matches = Vec::new();
        let coverage =
            self.visit_forward_candidate_match_pages(requests, cancellation, &mut |page| {
                matches.extend_from_slice(page);
                Ok(true)
            })?;
        Ok(BatchCandidateOutcome::new(
            requests.len(),
            matches,
            coverage.unconditional_completion().clone(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        self.visit_forward_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            Some(self.session),
            cancellation,
            visitor,
        )
    }
    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        limit: usize,
        session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        assert!(requests.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&limit));
        // Validate the whole readiness domain before any candidate read. A
        // later missing key must not become an empty branch after a stop.
        for (ordinal, request) in requests.iter().enumerate() {
            assert_eq!(request.request_ordinal(), ordinal);
            if request.endpoint().node() == BindingNodeId::universal_root() && {
                let arena = self.arena.borrow();
                !arena
                    .endpoints
                    .contains_key(&self.relation_key(request.endpoint()))
                    && !arena
                        .base_ready
                        .contains(&self.relation_key(request.endpoint()))
                    && !arena
                        .excluded_base
                        .contains(&self.relation_key(request.endpoint()))
            } {
                return Err(StoreError::new(format!(
                    "selected root relation read before closure: {:?}",
                    request.endpoint()
                )));
            }
        }
        let mut stopped = false;
        let mut cancellation_observed = false;
        // One canonical base visit returns coverage for *all* requests even
        // when the visitor stops. Only a bounded output page is retained.
        let mut coverage = self.base.visit_forward_candidate_match_pages_limited(
            requests,
            limit,
            session,
            cancellation,
            &mut |page| {
                assert!(!stopped, "base emitted after its visitor stopped");
                let mut retained = Vec::with_capacity(page.len());
                {
                    let arena = self.arena.borrow();
                    for (ordinal, request) in requests.iter().enumerate() {
                        if arena
                            .excluded_base
                            .contains(&self.relation_key(request.endpoint()))
                        {
                            continue;
                        }
                        let Some(relation) =
                            arena.endpoints.get(&self.relation_key(request.endpoint()))
                        else {
                            continue;
                        };
                        let candidates = page
                            .iter()
                            .filter(|row| row.request_ordinal() == ordinal)
                            .map(|row| row.candidate())
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>();
                        if !candidates.is_empty()
                            && !relation.check_base_candidates(
                                self.paths,
                                self.base,
                                &candidates,
                                cancellation,
                            )?
                        {
                            cancellation_observed = true;
                            stopped = true;
                            return Ok(false);
                        }
                    }
                    for row in page {
                        let request = &requests[row.request_ordinal()];
                        let keep = if arena
                            .excluded_base
                            .contains(&self.relation_key(request.endpoint()))
                        {
                            if cancellation.is_cancelled()
                                || !session.unwrap_or(self.session).scope_step()
                            {
                                cancellation_observed = true;
                                stopped = true;
                                return Ok(false);
                            }
                            false
                        } else {
                            match arena.endpoints.get(&self.relation_key(request.endpoint())) {
                                Some(_) => {
                                    // Match the canonical overlay's pre-filter
                                    // row charge, without mutating the caller token.
                                    if cancellation.is_cancelled()
                                        || !session.unwrap_or(self.session).scope_step()
                                    {
                                        cancellation_observed = true;
                                        stopped = true;
                                        return Ok(false);
                                    }
                                    true
                                }
                                None => true,
                            }
                        };
                        if keep {
                            retained.push(*row);
                        }
                    }
                }
                if !retained.is_empty() {
                    stopped = !visitor(&retained)?;
                }
                Ok(!stopped)
            },
        )?;
        if cancellation_observed {
            coverage = BatchCandidateCompletionOutcome::new(
                requests.len(),
                coverage
                    .unconditional_completion()
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::Cancelled,
                    ])),
                coverage.branch_completions().iter().cloned(),
            );
        }
        {
            let mut arena = self.arena.borrow_mut();
            arena.observe_coverage(coverage.unconditional_completion());
            #[cfg(test)]
            arena
                .reads
                .extend(requests.iter().map(|request| request.endpoint().clone()));
        }
        assert_eq!(coverage.branch_completions().len(), requests.len());
        if stopped
            || coverage
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(coverage);
        }
        let mut unconditional = ResolutionCompletionAccumulator::default();
        unconditional.include(coverage.unconditional_completion());
        let branch_completions = {
            let arena = self.arena.borrow();
            requests
                .iter()
                .enumerate()
                .map(|(ordinal, request)| {
                    arena.branch_completion(
                        &self.relation_key(request.endpoint()),
                        &coverage.branch_completions()[ordinal],
                    )
                })
                .collect::<Vec<_>>()
        };
        for (ordinal, request) in requests.iter().enumerate() {
            // The callback below never visits the base source. It reuses the
            // canonical overlay cursor against exactly this immutable key.
            let arena = self.arena.borrow();
            let Some(relation) = arena.endpoints.get(&self.relation_key(request.endpoint())) else {
                continue;
            };
            let local = [BatchCandidateRequest::new(0, request.endpoint().clone())];
            let local_coverage = BatchCandidateCompletionOutcome::new(
                1,
                ResolutionCompletion::Complete,
                [branch_completions[ordinal].clone()],
            );
            let added = relation.visit_forward_additions(
                self.paths,
                &local,
                local_coverage,
                limit,
                cancellation,
                self.session,
                &mut |page| {
                    assert!(!stopped, "overlay emitted after its visitor stopped");
                    let remapped = page
                        .iter()
                        .map(|row| BatchCandidateMatch::new(row.candidate(), ordinal))
                        .collect::<Vec<_>>();
                    stopped = !visitor(&remapped)?;
                    Ok(!stopped)
                },
            )?;
            unconditional.include(added.unconditional_completion());
            assert_eq!(
                added.branch_completions(),
                &branch_completions[ordinal..=ordinal]
            );
            if stopped
                || added
                    .unconditional_completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                break;
            }
        }
        Ok(BatchCandidateCompletionOutcome::new(
            requests.len(),
            unconditional.finish(),
            branch_completions,
        ))
    }
    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> Result<bool>,
    ) -> Result<BatchCandidateCompletionOutcome> {
        self.visit_reverse_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            cancellation,
            visitor,
        )
    }
    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> Result<BatchCandidateOutcome> {
        let mut matches = Vec::new();
        let coverage = self.visit_reverse_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            cancellation,
            &mut |page| {
                matches.extend_from_slice(page);
                Ok(true)
            },
        )?;
        Ok(BatchCandidateOutcome::new(
            requests.len(),
            matches,
            coverage.unconditional_completion().clone(),
            coverage.branch_completions().iter().cloned(),
        ))
    }
    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> Result<Vec<(CandidatePathIdentity, PartialPath)>> {
        assert!(candidates.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        let arena = self.arena.borrow();
        let mut persisted = Vec::new();
        let mut rows = Vec::new();
        for id in candidates {
            if cancellation.is_cancelled() {
                return Ok(rows);
            }
            match arena.paths.get(id) {
                Some(path) => rows.push((*id, path.clone())),
                None => persisted.push(*id),
            }
        }
        rows.extend(
            self.base
                .hydrate_candidate_paths(&persisted, cancellation)?,
        );
        Ok(rows)
    }
    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> Result<bool>,
    ) -> Result<ResolutionCompletion> {
        self.base
            .visit_type_transfer_rules(source_slot, cancellation, visitor)
    }
}
