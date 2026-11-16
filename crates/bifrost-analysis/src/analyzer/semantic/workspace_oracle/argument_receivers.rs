//! The two oracle questions that discharge a parametric procedure-effect
//! summary at a call edge (#12968).
//!
//! A callee whose call has the unchanged value of a formal parameter as its
//! receiver cannot be resolved alone: what runs depends on what the caller
//! passed. The effect derivation therefore asks, per entering call, which
//! classes the call proves for the callee's parameters
//! ([`WorkspaceSemanticOracle::argument_classes`]), and then resolves the
//! callee's call again under the hypothesis that its receiver holds such an
//! instance ([`WorkspaceSemanticOracle::resolve_call_with_receiver_class`]).
//! Both answers are a function of the call and the hypothesis alone, never of
//! a caller inventory, so a procedure reached any other way (as a query root,
//! through `send`, a method object or a framework callback) keeps its
//! context-free, open answer.
//!
//! The hypothesis runs through the ordinary dispatch entry, so every guard the
//! language applies to a written receiver (workspace shadowing of the class,
//! method-table rewrites, refinements, workspace overrides) applies to the
//! hypothetical one too. It crosses the oracle, the call-relation session and
//! the definition batch to the language receiver typer as ambient state for
//! the duration of one fresh, unmemoized dispatch session; a language that
//! does not consult it answers the call context-free, which is sound.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::carried_context;
use brokk_bifrost_core::path_utils::rel_path_string;

use crate::analyzer::ProjectFile;
use crate::analyzer::languages::language_support_for_hook;
use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
use crate::analyzer::semantic::workspace_oracle::dispatch::{
    exact_call_range, exact_source_for_procedure, parameter_origin, unique_argument_for_parameter,
};
use crate::analyzer::semantic::workspace_oracle::source::{
    one_call_dispatch_answer_digest, procedure_dispatch_question,
};
use crate::analyzer::semantic::{
    ArgumentClass, ArgumentClasses, CallBinding, CallSiteHandle, CandidateCoverage, DispatchOracle,
    DispatchResult, EvidenceCompleteness, LengthDelimitedDigest, OracleCallContext,
    ProcedurePortKind, ProofStatus, SemanticLanguage, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, ValueFlowOracle,
};
use crate::analyzer::usages::get_definition::parse_tree_for_language;

struct ReceiverHypothesis {
    rel_path: Box<str>,
    call: (usize, usize),
    class: Box<str>,
}

/// The class a receiver hypothesis assigns to the receiver of the call that
/// spans exactly `call_start..call_end` in `file`, while the oracle answers
/// that call under it. Language receiver typers consult this before typing a
/// call's receiver expression.
pub fn receiver_hypothesis(
    file: &ProjectFile,
    call_start: usize,
    call_end: usize,
) -> Option<Box<str>> {
    let hypothesis = carried_context::hypothesis::<ReceiverHypothesis>()?;
    (hypothesis.call == (call_start, call_end) && *hypothesis.rel_path == *rel_path_string(file))
        .then(|| hypothesis.class.clone())
}

/// Run `run` under `hypothesis`. The hypothesis rides the carried context, so
/// it follows work this request hands to helper threads, and a job carrying
/// another context, even one stolen onto this thread while `run` waits, never
/// observes it.
fn with_receiver_hypothesis<R>(hypothesis: ReceiverHypothesis, run: impl FnOnce() -> R) -> R {
    assert!(
        carried_context::hypothesis::<ReceiverHypothesis>().is_none(),
        "receiver hypotheses do not nest"
    );
    let _scope = carried_context::push_hypothesis(Arc::new(hypothesis));
    run()
}

impl WorkspaceSemanticOracle<'_> {
    /// The classes `entering` proves for the formal parameters of its unique
    /// callee. `None` when the call has no unique, proven, complete callee or
    /// no exhaustive binding to it; a parameter whose actual is not bound
    /// exactly, or has no proven class, is absent from the answer.
    ///
    /// An actual that is the unchanged value of one of the caller's own
    /// parameters is reported as that parameter, since only the caller's
    /// context can say more. Anything else is typed by the caller's language.
    pub fn argument_classes(
        &self,
        entering: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<ArgumentClasses>>, SemanticProviderError> {
        let dispatch = self.resolve_call(entering, request)?;
        let mut work = dispatch.work();
        let dispatch = match dispatch {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            _ => return Ok(SemanticOutcome::Complete { value: None, work }),
        };
        let none = |work| Ok(SemanticOutcome::Complete { value: None, work });
        if dispatch.coverage() != CandidateCoverage::Exhaustive {
            return none(work);
        }
        let [candidate] = dispatch.candidates() else {
            return none(work);
        };
        if candidate.proof() != &ProofStatus::Proven
            || candidate.completeness() != &EvidenceCompleteness::Complete
        {
            return none(work);
        }
        let bindings =
            self.call_bindings(entering, candidate, &OracleCallContext::empty(), request)?;
        work = work.conservative_add(bindings.work());
        let bindings = match bindings {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            _ => return none(work),
        };
        let target = candidate.target();
        let mut ordinals = bindings
            .bindings()
            .iter()
            .filter_map(|binding| match binding {
                CallBinding::ArgumentGroup(group) => Some(group.mappings()),
                _ => None,
            })
            .flatten()
            .filter_map(|mapping| match mapping.value().formal().kind() {
                ProcedurePortKind::Parameter { ordinal }
                    if mapping.value().formal().procedure() == target =>
                {
                    Some(ordinal)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        ordinals.dedup();
        let scan = SemanticWork {
            nested_entries: ordinals.len(),
            ..SemanticWork::default()
        };
        work = work.conservative_add(scan);
        request.budget.charge_work(scan);

        let mut caller_syntax = None;
        let mut classes = Vec::new();
        for ordinal in ordinals {
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            let Some(mapping) = unique_argument_for_parameter(&bindings, target, ordinal) else {
                continue;
            };
            let actual = mapping.value().actual().value();
            let origin = parameter_origin(actual.procedure(), actual.id(), request)?;
            work = work.conservative_add(origin.work());
            let caller_parameter = match origin {
                SemanticOutcome::Complete { value, .. } => value,
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                SemanticOutcome::Cancelled { .. } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
                _ => None,
            };
            let semantics = actual.procedure().semantics();
            let Some(span) = semantics
                .value(actual.id())
                .and_then(|value| semantics.source_mapping(value.source))
                .map(|mapping| mapping.locator.anchor().span())
            else {
                continue;
            };
            let span = span.start_byte() as usize..span.end_byte() as usize;
            if caller_syntax.is_none() {
                caller_syntax = Some(self.caller_syntax(actual.procedure(), request)?);
            }
            let Some(Some((file, source, tree))) = caller_syntax.as_ref() else {
                continue;
            };
            let SemanticLanguage::Standard(language) =
                actual.procedure().artifact().key().language()
            else {
                continue;
            };
            let Some(support) = language_support_for_hook(language, "receiver_class_of_expression")
            else {
                continue;
            };
            // A forwarded parameter has no class of its own; it carries the
            // caller's context only while the language proves nothing in
            // between changed what that class claims.
            if let Some(caller_ordinal) = caller_parameter {
                if support.argument_forwards_receiver_class(source, tree, span) {
                    classes.push((ordinal, ArgumentClass::CallerParameter(caller_ordinal)));
                }
                continue;
            }
            let class = support.receiver_class_of_expression(
                self.workspace.analyzer(),
                file,
                source,
                tree,
                span,
                Some(request.cancellation),
            );
            if let Some(class) = class {
                classes.push((ordinal, ArgumentClass::Class(class)));
            }
        }
        Ok(SemanticOutcome::Complete {
            value: Some(ArgumentClasses {
                callee: target.clone(),
                classes,
            }),
            work,
        })
    }

    /// The caller's exact source and its syntax tree, charged once per
    /// [`Self::argument_classes`] question; `None` when the source exceeds the
    /// request's source budget or does not parse.
    #[allow(clippy::type_complexity)]
    fn caller_syntax(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<(ProjectFile, std::sync::Arc<str>, tree_sitter::Tree)>, SemanticProviderError>
    {
        let Some((file, source)) = exact_source_for_procedure(
            self.workspace,
            procedure,
            request.budget.limits().source_bytes,
        )?
        else {
            return Ok(None);
        };
        request.budget.charge_work(SemanticWork {
            source_bytes: source.len(),
            ..SemanticWork::default()
        });
        let language = crate::analyzer::common::language_for_file(&file);
        Ok(parse_tree_for_language(&file, language, &source).map(|tree| (file, source, tree)))
    }

    /// Resolve `call` as ordinary dispatch would if its receiver expression
    /// were proven to hold an instance of `class`, a class name in the call's
    /// own language as [`Self::argument_classes`] reports it.
    ///
    /// The answer is computed in a fresh dispatch session and never memoized
    /// where a context-free question could read it.
    pub fn resolve_call_with_receiver_class(
        &self,
        call: &CallSiteHandle,
        class: &str,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let span = exact_call_range(call)?;
        let hypothesis = ReceiverHypothesis {
            rel_path: call.procedure().artifact().key().path().as_str().into(),
            call: (span.start_byte, span.end_byte),
            class: class.into(),
        };
        with_receiver_hypothesis(hypothesis, || self.resolve_call(call, request))
    }

    /// [`Self::argument_classes`], recording its answer in the read ledger
    /// when one is attached.
    pub fn argument_classes_recorded(
        &self,
        entering: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<ArgumentClasses>>, SemanticProviderError> {
        self.recorded_call_answer(
            entering,
            request,
            |oracle, request| oracle.argument_classes(entering, request),
            |question, outcome| {
                (
                    LookupKind::ArgumentClasses,
                    question,
                    argument_classes_answer_digest(outcome),
                )
            },
        )
    }

    /// [`Self::resolve_call_with_receiver_class`], recording its answer in
    /// the read ledger when one is attached.
    pub fn resolve_call_with_receiver_class_recorded(
        &self,
        call: &CallSiteHandle,
        class: &str,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.recorded_call_answer(
            call,
            request,
            |oracle, request| oracle.resolve_call_with_receiver_class(call, class, request),
            |question, outcome| {
                let LookupQuestion::CallSite {
                    rel_path,
                    procedure,
                    site,
                } = question
                else {
                    unreachable!("a procedure dispatch question is a call-site question")
                };
                (
                    LookupKind::ConditionalDispatch,
                    LookupQuestion::ReceiverCallSite {
                        rel_path,
                        procedure,
                        site,
                        receiver_class: class.into(),
                    },
                    one_call_dispatch_answer_digest(call, outcome),
                )
            },
        )
    }

    /// Answer one question about `call` and record the answer under the
    /// call's stable procedure/rank address, the way source dispatch records
    /// its answers: interrupted work, a budget refusal or an unaddressable
    /// call records an unattributed read instead, so no unit reuses it.
    fn recorded_call_answer<T>(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
        answer: impl FnOnce(
            &Self,
            &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<T>, SemanticProviderError>,
        key: impl FnOnce(
            LookupQuestion,
            &SemanticOutcome<T>,
        ) -> (LookupKind, LookupQuestion, StableDigest),
    ) -> Result<SemanticOutcome<T>, SemanticProviderError> {
        let analyzer = self.workspace.analyzer();
        let recording =
            crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached());
        let refusals_before = request.budget.refusal_count();
        let (resolved, operationally_incomplete) = if recording {
            match crate::analyzer::common::replayable_query_cache_fill(analyzer, || {
                answer(self, request)
            }) {
                Ok(outcome) => (outcome, false),
                Err(outcome) => (outcome, true),
            }
        } else {
            (answer(self, request), false)
        };
        let outcome = match resolved {
            Ok(outcome) => outcome,
            Err(error) => {
                analyzer.record_unattributed_read();
                return Err(error);
            }
        };
        if !recording {
            return Ok(outcome);
        }
        if operationally_incomplete
            || matches!(
                &outcome,
                SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
            )
            || request.cancellation.is_cancelled()
            || request.budget.refusal_count() > refusals_before
        {
            analyzer.record_unattributed_read();
            return Ok(outcome);
        }
        match procedure_dispatch_question(call) {
            Some(question) => {
                let (kind, question, digest) = key(question, &outcome);
                analyzer.record_read(ReadKey::lookup(kind, question, digest));
            }
            None => analyzer.record_unattributed_read(),
        }
        Ok(outcome)
    }
}

/// Canonical answer of one [`WorkspaceSemanticOracle::argument_classes`]
/// question: its quality, the callee by stable lineage, and every proven
/// parameter class.
#[doc(hidden)]
pub fn argument_classes_answer_digest(
    outcome: &SemanticOutcome<Option<ArgumentClasses>>,
) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-read-ledger:argument-classes-answer:v1");
    crate::analyzer::semantic::workspace_oracle::source::push_source_outcome_quality(
        &mut digest,
        crate::analyzer::semantic::workspace_oracle::source::SourceOutcomeQuality::from_outcome(
            outcome,
        ),
    );
    let Some(Some(answer)) = outcome.available_value() else {
        digest.push(b"unavailable");
        return digest.finish();
    };
    digest.push(b"available");
    let key = answer.callee.artifact().key();
    digest.push(key.path().as_str().as_bytes());
    digest.push(
        key.procedure_lineage_fingerprint(answer.callee.semantics().locator().declaration())
            .as_bytes(),
    );
    for (ordinal, class) in &answer.classes {
        digest.push(&ordinal.to_le_bytes());
        match class {
            ArgumentClass::Class(name) => {
                digest.push(b"class");
                digest.push(name.as_bytes());
            }
            ArgumentClass::CallerParameter(caller) => {
                digest.push(b"caller-parameter");
                digest.push(&caller.to_le_bytes());
            }
        }
    }
    digest.finish()
}
