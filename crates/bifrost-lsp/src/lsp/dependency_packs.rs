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

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use crossbeam_channel::{Receiver, Sender, unbounded};

use crate::analyzer::packs_document::{
    WorkspaceActivationSources, WorkspacePacksActivation, WorkspacePacksConfig,
    activate_workspace_semantic_sources,
};
use crate::analyzer::semantic_model::DependencyPackDiagnostic;
use crate::analyzer::{AnalyzerConfig, DependencyPackEcosystem, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;

/// Prefix of the one-line-per-activation session log. Stable so a rollout
/// campaign and the host tests can both select these lines.
pub(crate) const ACTIVATION_LOG_PREFIX: &str = "[bifrost-lsp] dependency-pack activation";

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
#[derive(Debug, Clone)]
pub(crate) struct DependencyPackActivation {
    /// The scheduling generation this job answers. The main loop drops an
    /// answer that a newer schedule already superseded.
    pub(crate) generation: u64,
    /// The exact workspace configuration used by this activation. None
    /// denotes compatible discovered-pack defaults.
    pub(crate) config: Option<WorkspacePacksConfig>,
    /// A malformed configuration is retained so callers do not mistake it
    /// for absent configuration and enable defaults.
    pub(crate) config_error: Option<String>,
    /// The shared activation transaction, when one completed or produced a
    /// typed incomplete outcome.
    pub(crate) activation: Option<Arc<WorkspacePacksActivation>>,
    pub(crate) ecosystems: Vec<DependencyPackEcosystem>,
    /// `true` when the analyzer published new proof, which obliges the host to
    /// refresh every document it has published diagnostics for.
    pub(crate) refresh_required: bool,
    /// The full outcome dump, present only when the activation did not
    /// complete. An incomplete activation is not an error: the collectors keep
    /// reporting typed suppressions, so the session stays correct and quiet.
    pub(crate) incomplete_detail: Option<String>,
    /// Actionable host-facing messages derived from structured activation
    /// diagnostics. These are separate from source diagnostics because a
    /// missing toolchain has no honest source range to attach to.
    pub(crate) user_messages: Vec<String>,
}

struct ActivationJob {
    generation: u64,
    snapshot: Arc<WorkspaceAnalyzer>,
    config: AnalyzerConfig,
    ecosystems: Vec<DependencyPackEcosystem>,
    /// Root beneath which the shared activation transaction resolves the
    /// configured catalog path.
    workspace_root: PathBuf,
    packs_config: Option<WorkspacePacksConfig>,
    config_error: Option<String>,
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
    events: Sender<DependencyPackActivation>,
    completions: Receiver<DependencyPackActivation>,
    completed: Arc<(Mutex<Option<DependencyPackActivation>>, Condvar)>,
}

impl DependencyPackActivator {
    pub(crate) fn new() -> Arc<Self> {
        let (events, completions) = unbounded();
        Arc::new(Self {
            state: Mutex::new(ActivatorState::default()),
            wake: Condvar::new(),
            events,
            completions,
            completed: Arc::new((Mutex::new(None), Condvar::new())),
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
        workspace_root: PathBuf,
        packs_config: Option<WorkspacePacksConfig>,
        config_error: Option<String>,
    ) -> u64 {
        let mut state = self.lock();
        if state.stopped {
            return state.next_generation;
        }
        state.next_generation = state.next_generation.saturating_add(1);
        let generation = state.next_generation;
        *self
            .completed
            .0
            .lock()
            .expect("dependency-pack completion lock poisoned") = None;
        // A disabled or malformed replacement must also supersede an older
        // running activation; otherwise that job could publish stale proof
        // after the new generation has already become current.
        if let Some(running) = state.running.as_ref() {
            running.cancel();
        }
        let workspace_models_present = std::fs::symlink_metadata(
            workspace_root
                .join(crate::analyzer::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY),
        )
        .is_ok();
        if (ecosystems.is_empty() && !workspace_models_present) || config_error.is_some() {
            let completion = DependencyPackActivation {
                generation,
                config: packs_config,
                config_error: config_error.clone(),
                activation: None,
                ecosystems,
                refresh_required: false,
                incomplete_detail: config_error,
                user_messages: Vec::new(),
            };
            drop(state);
            self.set_completion(completion);
            return generation;
        }
        state.pending = Some(ActivationJob {
            generation,
            snapshot,
            config,
            ecosystems,
            workspace_root,
            packs_config,
            config_error,
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

    pub(crate) fn current_completion(&self) -> Option<DependencyPackActivation> {
        self.completed
            .0
            .lock()
            .expect("dependency-pack completion lock poisoned")
            .clone()
    }

    pub(crate) fn wait_for_generation(&self, generation: u64) -> Option<DependencyPackActivation> {
        let mut completed = self
            .completed
            .0
            .lock()
            .expect("dependency-pack completion lock poisoned");
        loop {
            if completed
                .as_ref()
                .is_some_and(|completion| completion.generation == generation)
            {
                return completed.clone();
            }
            drop(completed);
            if self.lock().stopped {
                return None;
            }
            completed = self
                .completed
                .0
                .lock()
                .expect("dependency-pack completion lock poisoned");
            if completed
                .as_ref()
                .is_some_and(|completion| completion.generation == generation)
            {
                return completed.clone();
            }
            completed = self
                .completed
                .1
                .wait(completed)
                .expect("dependency-pack completion lock poisoned");
        }
    }

    fn set_completion(&self, completion: DependencyPackActivation) {
        *self
            .completed
            .0
            .lock()
            .expect("dependency-pack completion lock poisoned") = Some(completion);
        self.completed.1.notify_all();
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
        self.completed.1.notify_all();
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            eprintln!("[bifrost-lsp] dependency-pack activation worker panicked during shutdown");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ActivatorState> {
        self.state
            .lock()
            .expect("dependency-pack activator lock poisoned")
    }
}

fn run_worker(activator: &Arc<DependencyPackActivator>) {
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
                state = activator
                    .wake
                    .wait(state)
                    .expect("dependency-pack activator lock poisoned");
            }
        };

        let completion = run_job(&job);
        {
            let mut state = activator.lock();
            state.running = None;
        }
        if let Some(completion) = completion {
            let current_generation = activator.lock().next_generation;
            if current_generation != completion.generation {
                continue;
            }
            activator.set_completion(completion.clone());
            if activator.events.send(completion).is_err() {
                // The main loop has gone; nothing can consume further completions.
                return;
            }
        }
    }
}

/// Run one activation. Returns `None` when the job was cancelled before it
/// could publish, so the main loop is not asked to refresh for a job that
/// deliberately changed nothing.
fn run_job(job: &ActivationJob) -> Option<DependencyPackActivation> {
    if job.cancellation.is_cancelled() {
        return None;
    }
    let started = Instant::now();
    let outcome = activate_workspace_semantic_sources(
        job.snapshot.as_ref(),
        &job.config,
        WorkspaceActivationSources {
            catalog_root: &job.workspace_root,
            workspace_model_root: Some(&job.workspace_root),
            config: job.packs_config.as_ref(),
            intrinsic_shipped_models: true,
        },
        &job.cancellation,
    );
    let (activation, incomplete_detail, refresh_required, complete, user_messages) = match outcome {
        Ok(Some(activation)) => {
            let complete = activation.outcome.complete();
            let incomplete_detail = (!complete).then(|| format!("{activation:#?}"));
            let refresh_required = activation.outcome.diagnostic_refresh_required;
            let user_messages = activation
                .outcome
                .ecosystems
                .iter()
                .flat_map(|outcome| {
                    outcome
                        .discovery
                        .diagnostics
                        .iter()
                        .chain(
                            outcome
                                .preparation
                                .iter()
                                .flat_map(|preparation| preparation.diagnostics.iter()),
                        )
                        .filter_map(move |diagnostic| {
                            dependency_pack_guidance(outcome.ecosystem, diagnostic)
                        })
                })
                .collect();
            (
                Some(Arc::new(activation)),
                incomplete_detail,
                refresh_required,
                complete,
                user_messages,
            )
        }
        Ok(None) => (None, None, false, true, Vec::new()),
        Err(error) => {
            eprintln!(
                "[bifrost-lsp] dependency-pack activation is unavailable, \
                 unrecognized-symbol diagnostics stay suppressed: {error}"
            );
            (None, Some(error.to_string()), false, false, Vec::new())
        }
    };
    // One line per activation, so a rollout campaign can read activation
    // latency and completeness out of an ordinary session log (#1628).
    eprintln!(
        "{ACTIVATION_LOG_PREFIX} ecosystems={:?} elapsed_ms={:.3} complete={} refresh={} cancelled={}",
        job.ecosystems,
        started.elapsed().as_secs_f64() * 1000.0,
        complete,
        refresh_required,
        job.cancellation.is_cancelled(),
    );
    if job.cancellation.is_cancelled() && !refresh_required {
        return None;
    }
    Some(DependencyPackActivation {
        generation: job.generation,
        config: job.packs_config.clone(),
        config_error: job.config_error.clone(),
        activation,
        ecosystems: job.ecosystems.clone(),
        refresh_required,
        incomplete_detail,
        user_messages,
    })
}

fn dependency_pack_guidance(
    ecosystem: DependencyPackEcosystem,
    diagnostic: &DependencyPackDiagnostic,
) -> Option<String> {
    let remediation = match (ecosystem, diagnostic.code.as_str()) {
        (
            DependencyPackEcosystem::Jvm,
            "jdk.home.unavailable" | "jdk.home.invalid" | "jdk.jmods.invalid",
        ) => {
            "Configure JAVA_HOME to a JDK with lib/src.zip, or install a compatible JDK, then restart Bifrost."
        }
        (
            DependencyPackEcosystem::Go,
            "go.config_invalid"
            | "go.env_failed"
            | "go.env_invalid_json"
            | "go.module_missing"
            | "go.module_root_missing"
            | "go.target_missing"
            | "go.list_failed"
            | "go.list_invalid_json"
            | "go.workspace_metadata_invalid"
            | "go.vendor_metadata_invalid"
            | "go.package_incomplete",
        ) => "Install Go or configure bifrost's Go executable and GOROOT, then restart Bifrost.",
        (
            DependencyPackEcosystem::Cargo,
            "rust.toolchain.missing"
            | "rust.toolchain.not_file"
            | "rust.toolchain.invalid_utf8"
            | "rust.toolchain.invalid_toml"
            | "rust.toolchain.stdlib_channel_mismatch"
            | "rust.toolchain.metadata",
        ) => "Add or fix rust-toolchain.toml so it pins nightly-2026-08-24, then restart Bifrost.",
        (DependencyPackEcosystem::DotNet, "csharp.dependency_unresolved") => {
            "Restore the project with a compatible .NET SDK so project.assets.json is available, then restart Bifrost."
        }
        (
            DependencyPackEcosystem::Npm,
            "npm.lockfile.missing"
            | "npm.lockfile.invalid"
            | "npm.lockfile.unsupported"
            | "npm.package.manifest_missing"
            | "npm.declarations.missing",
        ) => {
            "Install the locked npm dependencies and ensure package metadata is readable, then restart Bifrost."
        }
        (DependencyPackEcosystem::Python, code) if code.starts_with("python.toolchain.") => {
            "Configure the intended Python environment and exact version metadata, then restart Bifrost."
        }
        (DependencyPackEcosystem::Ruby, code) if code.starts_with("ruby.evidence.") => {
            "Install the locked Ruby gems or configure their archive evidence, then restart Bifrost."
        }
        (DependencyPackEcosystem::Composer, code)
            if code.starts_with("php.toolchain.") || code.starts_with("composer.evidence.") =>
        {
            "Install the locked Composer dependencies and configure the intended PHP version, then restart Bifrost."
        }
        (DependencyPackEcosystem::Cpp, "cpp.header_discovery_failed") => {
            "Generate a current compile_commands.json with the intended compiler/toolchain, then restart Bifrost."
        }
        _ => return None,
    };
    let subject = match ecosystem {
        DependencyPackEcosystem::Jvm => "JVM standard-library semantic packs are inactive",
        DependencyPackEcosystem::Cargo => "Rust standard-library semantic packs are inactive",
        DependencyPackEcosystem::Go => "Go semantic packs are incomplete",
        DependencyPackEcosystem::DotNet => ".NET semantic packs are incomplete",
        DependencyPackEcosystem::Npm => "npm semantic packs are incomplete",
        DependencyPackEcosystem::Python => "Python semantic packs are incomplete",
        DependencyPackEcosystem::Ruby => "Ruby semantic packs are incomplete",
        DependencyPackEcosystem::Composer => "Composer semantic packs are incomplete",
        DependencyPackEcosystem::Cpp => "C/C++ semantic packs are incomplete",
    };
    Some(format!(
        "{subject} ({}): {} {remediation}",
        diagnostic.code, diagnostic.message
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic(code: &str) -> DependencyPackDiagnostic {
        DependencyPackDiagnostic {
            severity: crate::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Error,
            code: code.to_string(),
            dependency_id: None,
            location: None,
            message: "discovery failed".to_string(),
        }
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
    fn rust_toolchain_changes_invalidate_cargo_activation() {
        assert!(
            ecosystems_for_dependency_input("rust-toolchain.toml")
                .contains(&DependencyPackEcosystem::Cargo)
        );
    }

    #[test]
    fn readiness_guidance_is_limited_to_missing_prerequisites() {
        let missing = dependency_pack_guidance(
            DependencyPackEcosystem::Cargo,
            &diagnostic("rust.toolchain.missing"),
        )
        .expect("missing Rust toolchain should be actionable");
        assert!(missing.contains("rust-toolchain.toml"));
        assert!(missing.contains("nightly-2026-08-24"));

        for (ecosystem, code, expected) in [
            (
                DependencyPackEcosystem::Jvm,
                "jdk.jmods.invalid",
                "JAVA_HOME",
            ),
            (DependencyPackEcosystem::Go, "go.target_missing", "GOROOT"),
            (
                DependencyPackEcosystem::Npm,
                "npm.declarations.missing",
                "npm dependencies",
            ),
            (
                DependencyPackEcosystem::Ruby,
                "ruby.evidence.missing_archive_roots",
                "Ruby gems",
            ),
            (
                DependencyPackEcosystem::Composer,
                "composer.evidence.archive_root",
                "Composer dependencies",
            ),
        ] {
            let guidance = dependency_pack_guidance(ecosystem, &diagnostic(code))
                .unwrap_or_else(|| panic!("{code} should have remediation guidance"));
            assert!(guidance.contains(expected), "{guidance}");
        }

        assert!(
            dependency_pack_guidance(
                DependencyPackEcosystem::Cargo,
                &diagnostic("rust.rustdoc.no_external_declarations"),
            )
            .is_none()
        );
        assert!(
            dependency_pack_guidance(
                DependencyPackEcosystem::Jvm,
                &diagnostic("limit.dependencies"),
            )
            .is_none()
        );
    }

    #[test]
    fn shutdown_without_a_scheduled_activation_starts_no_worker() {
        let activator = DependencyPackActivator::new();
        activator.shutdown();
        assert!(activator.lock().worker.is_none());
    }
}
