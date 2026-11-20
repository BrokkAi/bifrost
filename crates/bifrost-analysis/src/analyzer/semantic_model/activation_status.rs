//! The status of one semantic-model activation, and the one reducer that
//! derives it (#13182).
//!
//! Hosts that answer questions over a workspace (the policy explanation tools,
//! the MCP session, `get_active_workspace`) must say whether the semantic models
//! the workspace selected were active when the answer was computed. A missing
//! snapshot alone proves nothing: it is legitimate only when activation ran and
//! selected nothing. [`SemanticModelActivationRead::reduce`] is the only place
//! that decides which inputs mean "no models" and which mean "models are not
//! usable", so an unusable activation can never be presented as an absent one.

use std::sync::Arc;

use serde::Serialize;

use crate::analyzer::IAnalyzer;
use crate::analyzer::packs_document::{WorkspaceActivationError, WorkspacePacksLoadError};
use crate::analyzer::semantic_model::SemanticModelActivationStatus;
use crate::analyzer::semantic_model::SemanticModelOverlayBudgetExceeded;
use crate::analyzer::semantic_model::dependency::PendingDependencyPackAcquisition;
use crate::analyzer::semantic_model::runtime::{
    ActiveSemanticModelSnapshot, SemanticModelOverlayRead, SemanticModelRuntimeOutcome,
};
use crate::analyzer::workspace::DependencyPackEcosystemOutcome;

/// Runtime state of the semantic-model declaration overlay, separate from warm-up completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SemanticModelOverlayStatus {
    Ready,
    NoModels,
    Pending {
        stage: SemanticModelWarmStage,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pending_acquisitions: Vec<PendingSemanticPackAcquisition>,
        /// The host's shipped-pack acquisition the warm still waits for.
        #[serde(skip_serializing_if = "Option::is_none")]
        shipped_pack_acquisition: Option<String>,
    },
    Partial {
        reasons: Vec<String>,
    },
    Unavailable {
        reason: String,
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        budget: Option<SemanticModelOverlayBudgetExceeded>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelWarmStage {
    ActivatingInstalledPacks,
    ActivatingConfiguredPacks,
    AcquisitionPending,
    /// The analyzer selected semantic models and has not published them. A
    /// reader that only sees the analyzer cannot tell which warm stage is
    /// running.
    SelectedNotPublished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PendingSemanticPackAcquisition {
    pub ecosystem: String,
    pub dependency_id: String,
}

impl SemanticModelOverlayStatus {
    /// Whether the answer computed under this status used every model the
    /// workspace selected. Only `Ready` and `NoModels` are complete.
    pub const fn is_model_complete(&self) -> bool {
        matches!(self, Self::Ready | Self::NoModels)
    }

    /// An actionable sentence for a status that is not model-complete, naming
    /// every pending acquisition and every reported reason. `None` when the
    /// status is complete.
    pub fn cause(&self) -> Option<String> {
        match self {
            Self::Ready | Self::NoModels => None,
            Self::Pending {
                stage,
                pending_acquisitions,
                shipped_pack_acquisition,
            } => {
                let mut text = match stage {
                    SemanticModelWarmStage::AcquisitionPending => {
                        let waiting = pending_acquisitions
                            .iter()
                            .map(|pending| {
                                format!("{}:{}", pending.ecosystem, pending.dependency_id)
                            })
                            .collect::<Vec<_>>();
                        format!(
                            "Waiting to acquire {}; wait for acquisition to finish and retry.",
                            if waiting.is_empty() {
                                "semantic packs".to_owned()
                            } else {
                                waiting.join(", ")
                            }
                        )
                    }
                    SemanticModelWarmStage::ActivatingInstalledPacks
                    | SemanticModelWarmStage::ActivatingConfiguredPacks => format!(
                        "Semantic-model activation is still running ({}); wait for activation \
                         to finish and retry. MCP clients can check \
                         get_active_workspace.semantic_packs_ready.",
                        match stage {
                            SemanticModelWarmStage::ActivatingInstalledPacks => {
                                "activating_installed_packs"
                            }
                            _ => "activating_configured_packs",
                        }
                    ),
                    SemanticModelWarmStage::SelectedNotPublished => {
                        "Semantic models are selected for this workspace but not published; wait \
                         for activation to finish and retry."
                            .to_owned()
                    }
                };
                if let Some(shipped) = shipped_pack_acquisition {
                    text.push_str(&format!(" Shipped pack acquisition pending: {shipped}."));
                }
                Some(text)
            }
            Self::Partial { reasons } => Some(format!(
                "Activation is incomplete; resolve the listed activation errors and retry: {}.",
                reasons.join("; ")
            )),
            Self::Unavailable { reason, budget } => Some(match budget {
                Some(budget) => format!(
                    "Activation exceeded the semantic-model budget ({budget:?}); reduce the \
                     selected models or increase that configured budget, then retry. {reason}"
                ),
                None => reason.clone(),
            }),
        }
    }
}

/// Why activation failed before any runtime outcome existed.
#[derive(Debug, Clone, Copy)]
pub enum SemanticModelSetupFailure<'a> {
    /// `.bifrost/packs.json` could not be read or validated.
    PacksDocument(&'a WorkspacePacksLoadError),
    /// The catalog, a shipped bundle or a reviewed workspace model refused to
    /// contribute.
    Activation(&'a WorkspaceActivationError),
}

/// Everything [`SemanticModelActivationRead::reduce`] accepts. Hosts adapt
/// their private session types into these neutral inputs.
pub enum SemanticModelActivationInput<'a> {
    /// An activation transaction finished. `ecosystems` is its per-ecosystem
    /// discovery record and `runtime` its published runtime outcome. A `None`
    /// runtime means "nothing to publish" only when discovery and preparation
    /// finished without cancellation.
    Runtime {
        ecosystems: &'a [DependencyPackEcosystemOutcome],
        runtime: Option<&'a SemanticModelRuntimeOutcome>,
    },
    /// Activation failed before a runtime outcome existed.
    SetupFailed(SemanticModelSetupFailure<'a>),
    /// A warm that has not settled. Never NoModels.
    Pending {
        analyzer: &'a dyn IAnalyzer,
        stage: SemanticModelWarmStage,
        pending_acquisitions: &'a [PendingDependencyPackAcquisition],
        shipped_pack_acquisition: Option<&'a str>,
    },
    /// A settled warm that published no activation outcome.
    NoPublishedOutcome(&'a dyn IAnalyzer),
    /// A warm that stopped with a failure, for example a panic in its
    /// worker. `cause` is the host's description of that failure.
    WarmFailed {
        analyzer: &'a dyn IAnalyzer,
        cause: &'a str,
    },
    /// A status this reducer produced earlier and a host stored, validated
    /// against the publication `analyzer` serves now.
    Stored {
        status: &'a SemanticModelOverlayStatus,
        analyzer: &'a dyn IAnalyzer,
    },
    /// An analyzer read directly: its publication first, then its overlay read.
    Detached(&'a dyn IAnalyzer),
}

/// One captured snapshot paired with the status that describes it. Fields are
/// private and [`Self::reduce`] is the only constructor, so a snapshot never
/// travels without its status and a bare absent snapshot never becomes
/// `NoModels`.
#[derive(Debug, Clone)]
pub struct SemanticModelActivationRead {
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    status: SemanticModelOverlayStatus,
}

impl SemanticModelActivationRead {
    fn new(
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        status: SemanticModelOverlayStatus,
    ) -> Self {
        assert!(
            !matches!(status, SemanticModelOverlayStatus::Ready) || snapshot.is_some(),
            "a ready semantic-model status owns its publication"
        );
        Self { snapshot, status }
    }

    fn status_only(status: SemanticModelOverlayStatus) -> Self {
        Self::new(None, status)
    }

    fn unavailable(reason: String) -> Self {
        Self::status_only(SemanticModelOverlayStatus::Unavailable {
            reason,
            budget: None,
        })
    }

    pub fn snapshot(&self) -> Option<&Arc<ActiveSemanticModelSnapshot>> {
        self.snapshot.as_ref()
    }

    pub fn status(&self) -> &SemanticModelOverlayStatus {
        &self.status
    }

    pub fn is_model_complete(&self) -> bool {
        self.status.is_model_complete()
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<Arc<ActiveSemanticModelSnapshot>>,
        SemanticModelOverlayStatus,
    ) {
        (self.snapshot, self.status)
    }

    /// Read an analyzer's publication. A single call to [`Self::reduce`].
    pub fn capture(analyzer: &dyn IAnalyzer) -> Self {
        Self::reduce(SemanticModelActivationInput::Detached(analyzer))
    }

    /// The one mapping from activation evidence to status.
    pub fn reduce(input: SemanticModelActivationInput<'_>) -> Self {
        match input {
            SemanticModelActivationInput::Runtime {
                ecosystems,
                runtime,
            } => reduce_runtime(ecosystems, runtime),
            SemanticModelActivationInput::SetupFailed(failure) => {
                Self::unavailable(setup_failure_reason(failure))
            }
            SemanticModelActivationInput::Pending {
                analyzer,
                stage,
                pending_acquisitions,
                shipped_pack_acquisition,
            } => {
                // An earlier stage may already have published usable models;
                // the answer uses them, and the status still states the wait.
                let status = SemanticModelOverlayStatus::Pending {
                    stage,
                    pending_acquisitions: pending_acquisitions
                        .iter()
                        .map(|pending| PendingSemanticPackAcquisition {
                            ecosystem: pending.ecosystem.label().to_owned(),
                            dependency_id: pending.dependency_id.clone(),
                        })
                        .collect(),
                    shipped_pack_acquisition: shipped_pack_acquisition.map(str::to_owned),
                };
                Self::new(analyzer.active_semantic_model_snapshot(), status)
            }
            SemanticModelActivationInput::NoPublishedOutcome(analyzer) => {
                let status = SemanticModelOverlayStatus::Unavailable {
                    reason: "No semantic-model activation result was published for this \
                             workspace; refresh or restart activation and retry."
                        .to_owned(),
                    budget: None,
                };
                Self::new(analyzer.active_semantic_model_snapshot(), status)
            }
            SemanticModelActivationInput::WarmFailed { analyzer, cause } => {
                // Earlier stages may have published models; the answer uses
                // them, and the status states the failure.
                let status = SemanticModelOverlayStatus::Unavailable {
                    reason: cause.to_owned(),
                    budget: None,
                };
                Self::new(analyzer.active_semantic_model_snapshot(), status)
            }
            SemanticModelActivationInput::Stored { status, analyzer } => {
                let snapshot = analyzer.active_semantic_model_snapshot();
                // A complete status must describe the publication the answer
                // uses. An activation that publishes nothing leaves an
                // earlier publication in place, so a stored `no_models` can
                // sit beside active models, and a stored `ready` beside none.
                // The answer still uses what the analyzer serves, as the
                // session's other queries do; the status names the mismatch.
                if status.is_model_complete() {
                    let serves_models = snapshot
                        .as_ref()
                        .is_some_and(|snapshot| !snapshot.active_models().shards().is_empty());
                    let stored_ready = matches!(status, SemanticModelOverlayStatus::Ready);
                    if serves_models != stored_ready {
                        let reason = if stored_ready {
                            "The latest semantic-model activation is ready, but this analyzer \
                             serves no active models; refresh activation and retry."
                        } else {
                            "The latest semantic-model activation selected no models, but this \
                             analyzer still serves active models from an earlier publication; \
                             refresh activation and retry."
                        };
                        return Self::new(
                            snapshot,
                            SemanticModelOverlayStatus::Unavailable {
                                reason: reason.to_owned(),
                                budget: None,
                            },
                        );
                    }
                }
                Self::new(snapshot, status.clone())
            }
            SemanticModelActivationInput::Detached(analyzer) => reduce_detached(analyzer),
        }
    }
}

fn reduce_detached(analyzer: &dyn IAnalyzer) -> SemanticModelActivationRead {
    // The snapshot is read first and decides Ready/NoModels from its own
    // shards. Only an absent snapshot consults the overlay read, whose
    // `NotSelected` is the single authoritative proof of legitimate absence.
    for _ in 0..2 {
        if let Some(snapshot) = analyzer.active_semantic_model_snapshot() {
            let status = if snapshot.active_models().shards().is_empty() {
                SemanticModelOverlayStatus::NoModels
            } else {
                SemanticModelOverlayStatus::Ready
            };
            return SemanticModelActivationRead::new(Some(snapshot), status);
        }
        match analyzer.semantic_model_overlay_read() {
            SemanticModelOverlayRead::NotSelected => {
                return SemanticModelActivationRead::status_only(
                    SemanticModelOverlayStatus::NoModels,
                );
            }
            SemanticModelOverlayRead::Pending(_) => {
                return SemanticModelActivationRead::status_only(
                    SemanticModelOverlayStatus::Pending {
                        stage: SemanticModelWarmStage::SelectedNotPublished,
                        pending_acquisitions: Vec::new(),
                        shipped_pack_acquisition: None,
                    },
                );
            }
            // A publication appeared between the two reads: capture again.
            SemanticModelOverlayRead::Published(_) => {}
        }
    }
    SemanticModelActivationRead::unavailable(
        "The semantic-model publication changed while it was being captured; retry.".to_owned(),
    )
}

/// Every explanation whose status makes the runtime incomplete: a pack the
/// catalog could not supply (`Unavailable`), a conflicting activation control
/// (`Conflict`), and a held approximate distributed shard
/// (`ApproximateDistributedBlocked`). These are the statuses the runtime
/// records when it sets its incomplete flag. Disabled, shadowed, incompatible
/// and review-gated packs are ordinary outcomes, not gaps.
fn failed_reasons(
    report: &crate::analyzer::semantic_model::SemanticModelActivationReport,
) -> Vec<&str> {
    report
        .explanations
        .iter()
        .filter(|explanation| {
            matches!(
                explanation.status,
                SemanticModelActivationStatus::Unavailable
                    | SemanticModelActivationStatus::Conflict
                    | SemanticModelActivationStatus::ApproximateDistributedBlocked
            )
        })
        .map(|explanation| explanation.reason.as_str())
        .collect()
}

fn reduce_runtime(
    ecosystems: &[DependencyPackEcosystemOutcome],
    runtime: Option<&SemanticModelRuntimeOutcome>,
) -> SemanticModelActivationRead {
    use SemanticModelOverlayStatus as Status;
    match runtime {
        Some(SemanticModelRuntimeOutcome::Ready {
            active, snapshot, ..
        }) => SemanticModelActivationRead::new(
            Some(Arc::clone(snapshot)),
            if active.shards().is_empty() {
                Status::NoModels
            } else {
                Status::Ready
            },
        ),
        Some(SemanticModelRuntimeOutcome::Incomplete {
            usable: Some(_),
            report,
        }) => {
            let mut reasons = failed_reasons(report)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if reasons.is_empty() {
                // The report's explanation list is bounded and may have
                // dropped the entry; the status must still name a cause.
                reasons.push(
                    "semantic-model activation did not activate every selected pack".to_owned(),
                );
            }
            SemanticModelActivationRead::status_only(Status::Partial { reasons })
        }
        Some(SemanticModelRuntimeOutcome::Unavailable(report))
        | Some(SemanticModelRuntimeOutcome::Cancelled(report))
        | Some(SemanticModelRuntimeOutcome::Incomplete {
            usable: None,
            report,
        }) => {
            let reasons = failed_reasons(report);
            let reason = if reasons.is_empty() {
                if matches!(runtime, Some(SemanticModelRuntimeOutcome::Cancelled(_))) {
                    "Semantic-model activation was cancelled; retry activation before relying on \
                     model-dependent answers."
                        .to_owned()
                } else {
                    "semantic-model activation did not publish a complete overlay".to_owned()
                }
            } else {
                reasons.join("; ")
            };
            SemanticModelActivationRead::new(
                None,
                Status::Unavailable {
                    reason,
                    budget: report.overlay_budget_exceeded,
                },
            )
        }
        None => {
            // No runtime outcome means nothing was published. That is "no
            // models" only when discovery finished: an incomplete or cancelled
            // discovery also yields an empty dependency set.
            let gaps = ecosystem_gaps(ecosystems);
            if gaps.is_empty() {
                SemanticModelActivationRead::status_only(Status::NoModels)
            } else {
                SemanticModelActivationRead::unavailable(format!(
                    "Dependency discovery or preparation did not finish, so this activation \
                     published nothing and any earlier publication was kept ({}); fix the \
                     reported activation problem, refresh activation and retry.",
                    gaps.join("; ")
                ))
            }
        }
    }
}

fn ecosystem_gaps(ecosystems: &[DependencyPackEcosystemOutcome]) -> Vec<String> {
    let mut gaps = ecosystems
        .iter()
        .filter(|outcome| {
            let discovery = &outcome.discovery;
            !discovery.complete || discovery.cancelled || discovery.incomplete_reason.is_some()
        })
        .map(|outcome| {
            let discovery = &outcome.discovery;
            let mut detail = match discovery.incomplete_reason {
                Some(reason) => format!("incomplete: {reason:?}"),
                None => "incomplete".to_owned(),
            };
            if discovery.cancelled {
                detail.push_str(", cancelled");
            }
            // The discovery diagnostics carry the actionable part, for
            // example the missing JDK home and how to set it.
            for diagnostic in &discovery.diagnostics {
                detail.push_str(&format!("; {}: {}", diagnostic.code, diagnostic.message));
            }
            format!("{} discovery {detail}", outcome.ecosystem.label())
        })
        .collect::<Vec<_>>();
    for outcome in ecosystems {
        if let Some(preparation) = &outcome.preparation
            && (!preparation.complete || preparation.cancelled)
        {
            let mut detail = format!(
                "{} preparation incomplete; cancelled: {}; failures: {:?}",
                outcome.ecosystem.label(),
                preparation.cancelled,
                preparation.failures
            );
            for diagnostic in &preparation.diagnostics {
                detail.push_str(&format!("; {}: {}", diagnostic.code, diagnostic.message));
            }
            gaps.push(detail);
        }
    }
    gaps
}

fn setup_failure_reason(failure: SemanticModelSetupFailure<'_>) -> String {
    match failure {
        SemanticModelSetupFailure::PacksDocument(error) => format!(
            "Cannot read .bifrost/packs.json: {error}. Fix or remove the failing packs \
             configuration, then refresh or restart and retry."
        ),
        SemanticModelSetupFailure::Activation(WorkspaceActivationError::Catalog(error)) => format!(
            "Cannot open the semantic-pack catalog: {error}. Fix the catalog path or its \
             permissions (.bifrost/packs.json can select one), then refresh and retry."
        ),
        SemanticModelSetupFailure::Activation(WorkspaceActivationError::ShippedModels(error)) => {
            format!(
                "Cannot load the configured semantic bundle: {error}. Repair or install the \
                 bundle, or remove the bundle configuration, then refresh and retry."
            )
        }
        SemanticModelSetupFailure::Activation(WorkspaceActivationError::WorkspaceModels(error)) => {
            format!(
                "Cannot activate the reviewed workspace semantic models: {error}. Fix or remove \
                 the failing model under .bifrost/semantic-models/, then refresh and retry."
            )
        }
    }
}
