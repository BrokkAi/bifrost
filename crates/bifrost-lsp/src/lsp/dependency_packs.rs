//! Host-owned dependency-pack activation for one LSP session (#1628).
//!
//! Unrecognized-symbol diagnostics can only prove a name absent when the
//! session has published exact dependency-pack evidence. Publishing that
//! evidence is `WorkspaceAnalyzer::activate_dependency_packs`, which is
//! host-owned by contract: a diagnostic request reads the published result and
//! never discovers or prepares anything itself. Before this module the LSP had
//! no caller, so every positive unrecognized-symbol result stayed suppressed
//! with a typed `MissingDependencyDiscovery` reason even after the client
//! opted in.
//!
//! This activator supplies the missing host. It runs activation on one
//! background worker thread, never on the request path. A diagnostic served
//! before activation completes reports the collectors' typed suppressions,
//! which is the correct fail-closed answer rather than a stall. When a job
//! completes, the worker posts [`DependencyPackActivation`] to the server's
//! main loop, which owns every state mutation and every publication.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender, unbounded};
use semver::Version;

use crate::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticPackCatalog,
};
use crate::analyzer::{
    AnalyzerConfig, DependencyPackEcosystem, DependencyPackWorkspaceContext, Language,
    WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;

/// Prefix of the one-line-per-activation session log. Stable so a rollout
/// campaign and the host tests can both select these lines.
pub(crate) const ACTIVATION_LOG_PREFIX: &str = "[bifrost-lsp] dependency-pack activation";

/// The ecosystems whose languages the workspace actually analyzes. Activating
/// an ecosystem with no source in the workspace would scan for manifests that
/// cannot inform any diagnostic.
pub(crate) fn ecosystems_for_languages(
    languages: &BTreeSet<Language>,
) -> Vec<DependencyPackEcosystem> {
    DependencyPackEcosystem::ALL
        .into_iter()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .collect()
}

/// The ecosystems whose declared dependency inputs include `file_name`. The
/// names come from `DependencyPackEcosystem::dependency_inputs`, the single
/// declared table.
pub(crate) fn ecosystems_for_dependency_input(file_name: &str) -> Vec<DependencyPackEcosystem> {
    DependencyPackEcosystem::ALL
        .into_iter()
        .filter(|ecosystem| ecosystem.dependency_inputs().contains(&file_name))
        .collect()
}

/// One completed activation, delivered to the server's main loop.
#[derive(Debug)]
pub(crate) struct DependencyPackActivation {
    /// The scheduling generation this job answers. The main loop drops an
    /// answer that a newer schedule already superseded.
    pub(crate) generation: u64,
    pub(crate) ecosystems: Vec<DependencyPackEcosystem>,
    /// `true` when the analyzer published new proof, which obliges the host to
    /// refresh every document it has published diagnostics for.
    pub(crate) refresh_required: bool,
    /// The full outcome dump, present only when the activation did not
    /// complete. An incomplete activation is not an error: the collectors keep
    /// reporting typed suppressions, so the session stays correct and quiet.
    pub(crate) incomplete_detail: Option<String>,
}

struct ActivationJob {
    generation: u64,
    snapshot: Arc<WorkspaceAnalyzer>,
    config: AnalyzerConfig,
    ecosystems: Vec<DependencyPackEcosystem>,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct ActivatorState {
    /// The latest job waiting to run. A newer schedule replaces an older one:
    /// a burst of watched-file changes must cost one activation, not one per
    /// change.
    pending: Option<ActivationJob>,
    running: Option<CancellationToken>,
    stopped: bool,
    worker: Option<JoinHandle<()>>,
    next_generation: u64,
}

/// One background dependency-pack activation worker per LSP session.
pub(crate) struct DependencyPackActivator {
    state: Mutex<ActivatorState>,
    wake: Condvar,
    idle: Condvar,
    events: Sender<DependencyPackActivation>,
    completions: Receiver<DependencyPackActivation>,
}

impl DependencyPackActivator {
    pub(crate) fn new() -> Arc<Self> {
        let (events, completions) = unbounded();
        Arc::new(Self {
            state: Mutex::new(ActivatorState::default()),
            wake: Condvar::new(),
            idle: Condvar::new(),
            events,
            completions,
        })
    }

    /// The channel the server's main loop selects on. Cloning it lets the loop
    /// wait for client traffic and activation completions at the same time
    /// without borrowing server state.
    pub(crate) fn completions(&self) -> Receiver<DependencyPackActivation> {
        self.completions.clone()
    }

    /// Queue an activation of `snapshot` over `ecosystems`, superseding any
    /// queued or running job. Returns the scheduling generation. Starts the
    /// worker thread on first use, so a session that never opts in never
    /// spawns one.
    pub(crate) fn schedule(
        self: &Arc<Self>,
        snapshot: Arc<WorkspaceAnalyzer>,
        config: AnalyzerConfig,
        ecosystems: Vec<DependencyPackEcosystem>,
    ) -> u64 {
        assert!(
            !ecosystems.is_empty(),
            "scheduling an activation over no ecosystem cannot publish proof"
        );
        let mut state = self.lock();
        if state.stopped {
            return state.next_generation;
        }
        state.next_generation = state.next_generation.saturating_add(1);
        let generation = state.next_generation;
        // The superseded job's snapshot is older than this one, so finishing it
        // would publish proof the next job immediately replaces.
        if let Some(running) = state.running.as_ref() {
            running.cancel();
        }
        state.pending = Some(ActivationJob {
            generation,
            snapshot,
            config,
            ecosystems,
            cancellation: CancellationToken::new(),
        });
        if state.worker.is_none() {
            let activator = Arc::clone(self);
            match std::thread::Builder::new()
                .name("bifrost-lsp-dependency-packs".to_string())
                .spawn(move || run_worker(&activator))
            {
                Ok(handle) => state.worker = Some(handle),
                Err(error) => {
                    // Without a worker there is no activation and therefore no
                    // proof; the collectors keep their typed suppressions and
                    // the session publishes nothing it cannot prove.
                    eprintln!("[bifrost-lsp] dependency-pack activation is unavailable: {error}");
                    state.stopped = true;
                    state.pending = None;
                }
            }
        }
        drop(state);
        self.wake.notify_all();
        generation
    }

    /// Cancel the queued and running jobs without stopping the worker. Used
    /// when the client turns the diagnostic opt-in off.
    pub(crate) fn cancel(&self) {
        let mut state = self.lock();
        state.pending = None;
        if let Some(running) = state.running.as_ref() {
            running.cancel();
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Cancel everything and join the worker. Called once on session teardown.
    pub(crate) fn shutdown(&self) {
        let handle = {
            let mut state = self.lock();
            state.stopped = true;
            state.pending = None;
            if let Some(running) = state.running.as_ref() {
                running.cancel();
            }
            state.worker.take()
        };
        self.wake.notify_all();
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            eprintln!("[bifrost-lsp] dependency-pack activation worker panicked during shutdown");
        }
    }

    /// Test support: block until no activation is queued or running.
    #[cfg(test)]
    pub(crate) fn wait_until_idle(&self) {
        let state = self.lock();
        let (state, timeout) = self
            .idle
            .wait_timeout_while(state, std::time::Duration::from_secs(60), |state| {
                state.running.is_some() || state.pending.is_some()
            })
            .expect("dependency-pack activator lock poisoned while waiting for idle");
        assert!(!timeout.timed_out(), "dependency-pack activation stalled");
        assert!(state.running.is_none() && state.pending.is_none());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ActivatorState> {
        self.state
            .lock()
            .expect("dependency-pack activator lock poisoned")
    }
}

fn run_worker(activator: &Arc<DependencyPackActivator>) {
    // The catalog holds SQLite state, so it stays on this thread for the
    // session's lifetime and is opened only once a job actually needs it.
    let mut catalog: Option<SemanticPackCatalog> = None;
    loop {
        let job = {
            let mut state = activator.lock();
            loop {
                if state.stopped {
                    return;
                }
                if let Some(job) = state.pending.take() {
                    state.running = Some(job.cancellation.clone());
                    break job;
                }
                activator.idle.notify_all();
                state = activator
                    .wake
                    .wait(state)
                    .expect("dependency-pack activator lock poisoned");
            }
        };

        let completion = run_job(&mut catalog, &job);
        {
            let mut state = activator.lock();
            state.running = None;
            if catalog.is_none() {
                // The catalog could not be opened, so no later job can publish
                // proof either. Stop rather than retry the same failure per
                // keystroke.
                state.stopped = true;
                state.pending = None;
            }
        }
        activator.idle.notify_all();
        if let Some(completion) = completion
            && activator.events.send(completion).is_err()
        {
            // The main loop has gone; nothing can consume further completions.
            return;
        }
    }
}

/// Run one activation. Returns `None` when the job was cancelled before it
/// could publish, so the main loop is not asked to refresh for a job that
/// deliberately changed nothing.
fn run_job(
    catalog: &mut Option<SemanticPackCatalog>,
    job: &ActivationJob,
) -> Option<DependencyPackActivation> {
    if job.cancellation.is_cancelled() {
        return None;
    }
    if catalog.is_none() {
        match SemanticPackCatalog::open_ephemeral(CatalogOptions::default()) {
            Ok(opened) => *catalog = Some(opened),
            Err(error) => {
                eprintln!(
                    "[bifrost-lsp] dependency-pack catalog is unavailable, unrecognized-symbol \
                     diagnostics stay suppressed: {error}"
                );
                return None;
            }
        }
    }
    let catalog = catalog.as_ref().expect("catalog opened above");
    let activation = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("package version must be semver"),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let started = Instant::now();
    let outcome = job.snapshot.activate_dependency_packs(
        &job.config,
        &job.ecosystems,
        DependencyPackWorkspaceContext {
            catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &job.cancellation,
        },
    );
    // One line per activation, so a rollout campaign can read activation
    // latency and completeness out of an ordinary session log (#1628).
    eprintln!(
        "{ACTIVATION_LOG_PREFIX} ecosystems={:?} elapsed_ms={:.3} complete={} refresh={} cancelled={}",
        job.ecosystems,
        started.elapsed().as_secs_f64() * 1000.0,
        outcome.complete(),
        outcome.diagnostic_refresh_required,
        job.cancellation.is_cancelled(),
    );
    if job.cancellation.is_cancelled() && !outcome.diagnostic_refresh_required {
        return None;
    }
    let incomplete_detail = (!outcome.complete()).then(|| format!("{outcome:#?}"));
    Some(DependencyPackActivation {
        generation: job.generation,
        ecosystems: job.ecosystems.clone(),
        refresh_required: outcome.diagnostic_refresh_required,
        incomplete_detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn languages(languages: &[Language]) -> BTreeSet<Language> {
        languages.iter().copied().collect()
    }

    #[test]
    fn every_ecosystem_declares_a_dependency_input_that_maps_back_to_it() {
        for ecosystem in DependencyPackEcosystem::ALL {
            let inputs = ecosystem.dependency_inputs();
            assert!(
                !inputs.is_empty(),
                "{ecosystem:?} must declare the files whose change invalidates its packs"
            );
            for input in inputs {
                assert!(
                    ecosystems_for_dependency_input(input).contains(&ecosystem),
                    "{input} must map back to {ecosystem:?}"
                );
            }
        }
    }

    #[test]
    fn ecosystem_selection_follows_the_languages_present() {
        assert_eq!(
            ecosystems_for_languages(&languages(&[Language::Python])),
            vec![DependencyPackEcosystem::Python]
        );
        assert_eq!(
            ecosystems_for_languages(&languages(&[Language::Kotlin, Language::Go])),
            vec![DependencyPackEcosystem::Jvm, DependencyPackEcosystem::Go]
        );
        assert!(ecosystems_for_languages(&languages(&[Language::Cpp])).is_empty());
    }

    #[test]
    fn shutdown_without_a_scheduled_activation_starts_no_worker() {
        let activator = DependencyPackActivator::new();
        activator.shutdown();
        assert!(activator.lock().worker.is_none());
    }
}
