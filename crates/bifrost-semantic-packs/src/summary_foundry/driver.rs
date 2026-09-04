//! The foundry driver: depth-first module scheduling over the content-addressed
//! store.
//!
//! A module runs through every stage of the pipeline, in order, to a finished
//! module report before the next module begins. Modules are given in demand
//! order, so the pilot module a human sanity-checks is also the highest-value
//! content, exactly as the plan specifies.
//!
//! Each stage is a [`StageExecutor`], a seam the caller fills. The pipeline the
//! milestone wires is translate -> derive -> join -> adjudicate -> fixture: the
//! first four live in this crate (translation, derivation, the join, and the
//! blind-then-graded adjudication of [`super::adjudicate`]), and the fixture
//! stage's executable proof runs through the policy evaluator in the facade, so
//! a facade driver supplies that stage. The driver itself knows only the seam,
//! which is what lets the store, the scheduling, and the invalidation be tested
//! with cheap deterministic executors while the production stages plug into the
//! same interface.
//!
//! The invalidation contract is the store's: a stage reuses its artifact when
//! its key is unchanged and re-runs otherwise, and because every stage's key
//! chains on the upstream stage's key, editing one stage re-runs it and every
//! stage after it and nothing before it. A stage that fails propagates its
//! failure and stores nothing, so a re-run resumes exactly at the failed stage.

use serde::Serialize;

use super::store::{FoundryStore, ModuleId, StageArtifact, StageKeyInputs, StoreError};

/// One stage's static shape in a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageDefinition {
    /// The stage id, which is also its artifact file name.
    pub id: &'static str,
    /// The stage's code version. Bump it when the stage's logic changes so its
    /// cached artifacts invalidate.
    pub stage_code_version: u32,
    /// Whether the stage's output depends on a prompt version. Only adjudication
    /// does today; a stage that sets this false cannot be invalidated by a
    /// prompt edit.
    pub uses_prompt_version: bool,
}

/// A failure inside one stage executor. It is the stage's failure, not the
/// driver's: the driver reports it and stores nothing for that stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageExecutionError {
    pub detail: String,
}

impl StageExecutionError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// The seam the driver runs each stage through.
///
/// A stage reads the module and its upstream stage's payload and returns its own
/// payload. It is implemented for any matching closure, so a production stage is
/// a closure that captures the pinned corpora and the analyzer, and a test stage
/// is a closure that captures a counter.
pub trait StageExecutor {
    fn execute(
        &self,
        module: &ModuleId,
        upstream: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, StageExecutionError>;
}

impl<F> StageExecutor for F
where
    F: Fn(&ModuleId, Option<&serde_json::Value>) -> Result<serde_json::Value, StageExecutionError>,
{
    fn execute(
        &self,
        module: &ModuleId,
        upstream: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, StageExecutionError> {
        self(module, upstream)
    }
}

/// One stage bound to its executor.
pub struct PipelineStage<'a> {
    pub definition: StageDefinition,
    pub executor: &'a dyn StageExecutor,
}

/// An ordered pipeline plus the prompt version this run uses.
pub struct Pipeline<'a> {
    stages: Vec<PipelineStage<'a>>,
    prompt_version: u32,
}

impl<'a> Pipeline<'a> {
    pub fn new(prompt_version: u32) -> Self {
        Self {
            stages: Vec::new(),
            prompt_version,
        }
    }

    /// Append a stage. The order stages are appended is the order they run.
    pub fn stage(
        mut self,
        id: &'static str,
        stage_code_version: u32,
        uses_prompt_version: bool,
        executor: &'a dyn StageExecutor,
    ) -> Self {
        self.stages.push(PipelineStage {
            definition: StageDefinition {
                id,
                stage_code_version,
                uses_prompt_version,
            },
            executor,
        });
        self
    }
}

/// One module and the digest of its pinned source slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSource {
    pub module: ModuleId,
    /// The digest of the module's pinned source slice. When the pinned edition
    /// changes, this digest changes, and every stage that reads the slice
    /// invalidates.
    pub source_slice_digest: String,
}

/// Whether one stage ran or reused its cached artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageDisposition {
    Ran,
    Reused,
}

/// One stage's outcome in a module report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StageOutcome {
    pub stage: String,
    pub key: String,
    pub disposition: StageDisposition,
}

/// One module's finished report: every stage, its key, and whether it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleReport {
    pub module: String,
    pub stages: Vec<StageOutcome>,
}

/// One driver run over every module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DriverReport {
    pub modules: Vec<ModuleReport>,
}

/// A driver failure.
#[derive(Debug)]
pub enum DriverError {
    Store(StoreError),
    Stage {
        module: String,
        stage: String,
        detail: String,
    },
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Stage {
                module,
                stage,
                detail,
            } => write!(
                formatter,
                "stage {stage} on module {module} failed: {detail}"
            ),
        }
    }
}

impl std::error::Error for DriverError {}

/// Run the pipeline over the modules, depth-first, resuming from the store.
pub fn run_pipeline(
    store: &FoundryStore,
    pipeline: &Pipeline<'_>,
    modules: &[ModuleSource],
) -> Result<DriverReport, DriverError> {
    let mut module_reports = Vec::with_capacity(modules.len());
    for source in modules {
        let mut upstream_key: Option<String> = None;
        let mut upstream_payload: Option<serde_json::Value> = None;
        let mut stages = Vec::with_capacity(pipeline.stages.len());
        for stage in &pipeline.stages {
            let prompt_version = stage
                .definition
                .uses_prompt_version
                .then_some(pipeline.prompt_version);
            let inputs = StageKeyInputs {
                module: &source.module,
                stage: stage.definition.id,
                stage_code_version: stage.definition.stage_code_version,
                prompt_version,
                source_slice_digest: &source.source_slice_digest,
                upstream_key: upstream_key.as_deref(),
            };
            let key = inputs.key();
            let stored = store
                .load(&source.module, stage.definition.id)
                .map_err(DriverError::Store)?;
            let (payload, disposition) = match stored {
                Some(artifact) if artifact.key == key => {
                    (artifact.payload, StageDisposition::Reused)
                }
                _ => {
                    let payload = stage
                        .executor
                        .execute(&source.module, upstream_payload.as_ref())
                        .map_err(|error| DriverError::Stage {
                            module: source.module.as_str().to_owned(),
                            stage: stage.definition.id.to_owned(),
                            detail: error.detail,
                        })?;
                    let artifact = StageArtifact::new(&inputs, payload.clone());
                    store.store(&artifact).map_err(DriverError::Store)?;
                    (payload, StageDisposition::Ran)
                }
            };
            stages.push(StageOutcome {
                stage: stage.definition.id.to_owned(),
                key: key.clone(),
                disposition,
            });
            upstream_key = Some(key);
            upstream_payload = Some(payload);
        }
        module_reports.push(ModuleReport {
            module: source.module.as_str().to_owned(),
            stages,
        });
    }
    Ok(DriverReport {
        modules: module_reports,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde_json::{Value, json};

    use super::*;
    use crate::summary_foundry::adjudicate::{
        AdjudicationCandidate, CorpusFacts, DerivedFacts, FakeAdjudicator, run_adjudication,
    };
    use crate::summary_foundry::ir::{
        FoundryArtifactBinding, FoundryBoundary, FoundryClaim, FoundryCompleteness, FoundryCorpus,
        FoundryEntry, FoundrySignature, FoundryTarget, summary_id,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput,
        AuthoredSummaryTransfer,
    };

    /// One counter per stage of the five-stage pipeline.
    #[derive(Default)]
    struct Counters {
        translate: Cell<u32>,
        derive: Cell<u32>,
        join: Cell<u32>,
        adjudicate: Cell<u32>,
        fixture: Cell<u32>,
    }

    fn bump(counter: &Cell<u32>) {
        counter.set(counter.get() + 1);
    }

    fn module() -> Vec<ModuleSource> {
        vec![ModuleSource {
            module: ModuleId::new("java/util"),
            source_slice_digest: "slice-digest".to_owned(),
        }]
    }

    fn dispositions(report: &DriverReport) -> Vec<(String, StageDisposition)> {
        report.modules[0]
            .stages
            .iter()
            .map(|stage| (stage.stage.clone(), stage.disposition))
            .collect()
    }

    #[test]
    fn a_re_run_reuses_every_finished_stage() {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        let counters = Counters::default();

        let translate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.translate);
            Ok(json!({"stage": "translate"}))
        };
        let derive = |_: &ModuleId, up: Option<&Value>| {
            bump(&counters.derive);
            Ok(json!({"stage": "derive", "upstream": up}))
        };
        let join = |_: &ModuleId, up: Option<&Value>| {
            bump(&counters.join);
            Ok(json!({"stage": "join", "upstream": up}))
        };
        let adjudicate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.adjudicate);
            Ok(json!({"stage": "adjudicate"}))
        };
        let fixture = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.fixture);
            Ok(json!({"stage": "fixture"}))
        };
        let pipeline = Pipeline::new(1)
            .stage("translate", 1, false, &translate)
            .stage("derive", 1, false, &derive)
            .stage("join", 1, false, &join)
            .stage("adjudicate", 1, true, &adjudicate)
            .stage("fixture", 1, false, &fixture);

        let first = run_pipeline(&store, &pipeline, &module()).expect("the first run succeeds");
        assert!(
            dispositions(&first)
                .iter()
                .all(|(_, disposition)| *disposition == StageDisposition::Ran)
        );
        assert_eq!(counters.translate.get(), 1);
        assert_eq!(counters.fixture.get(), 1);

        let second = run_pipeline(&store, &pipeline, &module()).expect("the second run succeeds");
        assert!(
            dispositions(&second)
                .iter()
                .all(|(_, disposition)| *disposition == StageDisposition::Reused),
            "{:?}",
            dispositions(&second)
        );
        // Nothing ran again.
        assert_eq!(counters.translate.get(), 1);
        assert_eq!(counters.derive.get(), 1);
        assert_eq!(counters.join.get(), 1);
        assert_eq!(counters.adjudicate.get(), 1);
        assert_eq!(counters.fixture.get(), 1);
    }

    #[test]
    fn an_interrupted_run_resumes_without_repeating_finished_stages() {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        let counters = Counters::default();
        let adjudicate_fails_first = Cell::new(true);

        let translate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.translate);
            Ok(json!({"stage": "translate"}))
        };
        let derive = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.derive);
            Ok(json!({"stage": "derive"}))
        };
        let join = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.join);
            Ok(json!({"stage": "join"}))
        };
        // Stage three fails on the first invocation, which is the interruption.
        let adjudicate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.adjudicate);
            if adjudicate_fails_first.replace(false) {
                Err(StageExecutionError::new("interrupted mid-stage"))
            } else {
                Ok(json!({"stage": "adjudicate"}))
            }
        };
        let fixture = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.fixture);
            Ok(json!({"stage": "fixture"}))
        };
        let pipeline = Pipeline::new(1)
            .stage("translate", 1, false, &translate)
            .stage("derive", 1, false, &derive)
            .stage("join", 1, false, &join)
            .stage("adjudicate", 1, true, &adjudicate)
            .stage("fixture", 1, false, &fixture);

        let interrupted = run_pipeline(&store, &pipeline, &module());
        assert!(
            matches!(interrupted, Err(DriverError::Stage { ref stage, .. }) if stage == "adjudicate"),
            "{interrupted:?}"
        );
        // translate, derive, join finished and stored; adjudicate ran and failed;
        // fixture was never reached.
        assert_eq!(counters.translate.get(), 1);
        assert_eq!(counters.derive.get(), 1);
        assert_eq!(counters.join.get(), 1);
        assert_eq!(counters.adjudicate.get(), 1);
        assert_eq!(counters.fixture.get(), 0);

        let resumed = run_pipeline(&store, &pipeline, &module()).expect("the resumed run succeeds");
        assert_eq!(
            dispositions(&resumed),
            vec![
                ("translate".to_owned(), StageDisposition::Reused),
                ("derive".to_owned(), StageDisposition::Reused),
                ("join".to_owned(), StageDisposition::Reused),
                ("adjudicate".to_owned(), StageDisposition::Ran),
                ("fixture".to_owned(), StageDisposition::Ran),
            ]
        );
        // The three finished stages did not run again; only the interrupted tail
        // did.
        assert_eq!(counters.translate.get(), 1);
        assert_eq!(counters.derive.get(), 1);
        assert_eq!(counters.join.get(), 1);
        assert_eq!(counters.adjudicate.get(), 2);
        assert_eq!(counters.fixture.get(), 1);
    }

    #[test]
    fn bumping_the_prompt_version_re_runs_only_stage_three_and_later() {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        let counters = Counters::default();

        let translate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.translate);
            Ok(json!({"stage": "translate"}))
        };
        let derive = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.derive);
            Ok(json!({"stage": "derive"}))
        };
        let join = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.join);
            Ok(json!({"stage": "join"}))
        };
        let adjudicate = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.adjudicate);
            Ok(json!({"stage": "adjudicate"}))
        };
        let fixture = |_: &ModuleId, _: Option<&Value>| {
            bump(&counters.fixture);
            Ok(json!({"stage": "fixture"}))
        };
        let build = |prompt: u32| {
            Pipeline::new(prompt)
                .stage("translate", 1, false, &translate)
                .stage("derive", 1, false, &derive)
                .stage("join", 1, false, &join)
                .stage("adjudicate", 1, true, &adjudicate)
                .stage("fixture", 1, false, &fixture)
        };

        run_pipeline(&store, &build(1), &module()).expect("prompt v1 run");
        assert_eq!(counters.adjudicate.get(), 1);
        assert_eq!(counters.fixture.get(), 1);

        let bumped = run_pipeline(&store, &build(2), &module()).expect("prompt v2 run");
        assert_eq!(
            dispositions(&bumped),
            vec![
                ("translate".to_owned(), StageDisposition::Reused),
                ("derive".to_owned(), StageDisposition::Reused),
                ("join".to_owned(), StageDisposition::Reused),
                ("adjudicate".to_owned(), StageDisposition::Ran),
                ("fixture".to_owned(), StageDisposition::Ran),
            ]
        );
        // Only stage three and its downstream re-ran.
        assert_eq!(counters.translate.get(), 1);
        assert_eq!(counters.derive.get(), 1);
        assert_eq!(counters.join.get(), 1);
        assert_eq!(counters.adjudicate.get(), 2);
        assert_eq!(counters.fixture.get(), 2);
    }

    #[test]
    fn two_modules_run_depth_first() {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        let order = Cell::new(String::new());

        let record = |module: &ModuleId, _: Option<&Value>| {
            let mut seen = order.take();
            seen.push_str(module.as_str());
            seen.push(';');
            order.set(seen);
            Ok(json!({"module": module.as_str()}))
        };
        let record_two = |module: &ModuleId, _: Option<&Value>| {
            let mut seen = order.take();
            seen.push_str(module.as_str());
            seen.push('>');
            order.set(seen);
            Ok(json!({"module": module.as_str()}))
        };
        let pipeline = Pipeline::new(1).stage("first", 1, false, &record).stage(
            "second",
            1,
            false,
            &record_two,
        );
        let modules = vec![
            ModuleSource {
                module: ModuleId::new("java/util"),
                source_slice_digest: "a".to_owned(),
            },
            ModuleSource {
                module: ModuleId::new("java/lang"),
                source_slice_digest: "b".to_owned(),
            },
        ];

        run_pipeline(&store, &pipeline, &modules).expect("both modules run");

        // Depth-first: java/util finishes both stages before java/lang starts.
        assert_eq!(order.take(), "java/util;java/util>java/lang;java/lang>");
    }

    /// The real adjudication stage plugs into the driver seam: its executor runs
    /// the blind-then-graded harness and its calibration lands in the store as a
    /// human-readable artifact.
    #[test]
    fn the_adjudication_stage_composes_into_the_driver() {
        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());

        let target = FoundryTarget {
            artifact_path: "java/util/Fixture.class".to_owned(),
            member: "wrap".to_owned(),
            signature: FoundrySignature::Overload {
                types: vec!["String".to_owned()],
            },
        };
        let transfer = AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::NormalReturn {},
            value_transfer: None,
        };
        let entry = FoundryEntry {
            id: summary_id(FoundryCorpus::Codeql, &target),
            corpus: FoundryCorpus::Codeql,
            target: target.clone(),
            boundary: FoundryBoundary {
                has_receiver: false,
                parameter_count: 1,
            },
            claim: FoundryClaim::Flows,
            completeness: FoundryCompleteness::Partial,
            transfers: vec![transfer],
            artifact: FoundryArtifactBinding::Unresolved,
            evidence: Vec::new(),
            notes: Vec::new(),
            derivation: None,
        };
        // One underivable, CodeQL-covered candidate: it ships the translation and
        // produces a calibration datum.
        let candidate = AdjudicationCandidate {
            target,
            boundary: FoundryBoundary {
                has_receiver: false,
                parameter_count: 1,
            },
            derived: Some(DerivedFacts {
                entry: entry.clone(),
                boundaries: vec![
                    crate::summary_foundry::ir::FoundryDerivationBoundary::UnresolvedCall,
                ],
            }),
            codeql: Some(CorpusFacts { entry }),
        };

        let adjudicate = |_: &ModuleId, _: Option<&Value>| {
            let outcome = run_adjudication(
                std::slice::from_ref(&candidate),
                &FakeAdjudicator::conceding(),
                1,
            );
            Ok(serde_json::to_value(&outcome).expect("the outcome serializes"))
        };
        let pipeline = Pipeline::new(1).stage("adjudicate", 1, true, &adjudicate);

        run_pipeline(&store, &pipeline, &module()).expect("the run succeeds");

        let stored = store
            .load(&ModuleId::new("java/util"), "adjudicate")
            .expect("the artifact loads")
            .expect("adjudicate stored an artifact");
        assert_eq!(stored.payload["shipping"].as_array().unwrap().len(), 1);
        assert_eq!(stored.payload["calibration"]["totals"]["graded"], 1);
        assert_eq!(
            stored.payload["calibration"]["totals"]["first_pass_agree"],
            1
        );
    }

    /// The real milestone-2 derivation composes into the driver as a stage, and
    /// the store saves its cost on re-run. This is the plan's "31 minutes, paid
    /// twice" turning into "paid once": the expensive derivation runs on the
    /// first pass and its artifact is reused on the second without re-deriving.
    #[test]
    fn the_real_derivation_stage_composes_and_is_cached_across_runs() {
        use crate::summary_foundry::derive::{DerivationLimits, derive_jvm_summaries};

        let directory = tempfile::tempdir().expect("a work directory");
        let store = FoundryStore::open(directory.path());
        let sources = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/summary-sources/temurin-jdk-21.0.8+9");
        let derive_calls = Cell::new(0u32);

        let derive = |_: &ModuleId, _: Option<&Value>| {
            derive_calls.set(derive_calls.get() + 1);
            let run = derive_jvm_summaries(&sources, DerivationLimits::default())
                .map_err(|error| StageExecutionError::new(error.to_string()))?;
            Ok(json!({
                "files_read": run.files_read,
                "entries": run.entries,
            }))
        };
        let modules = vec![ModuleSource {
            module: ModuleId::new("java/util"),
            source_slice_digest: "objects-slice-v1".to_owned(),
        }];
        let pipeline = Pipeline::new(1).stage("derive", 1, false, &derive);

        let first = run_pipeline(&store, &pipeline, &modules).expect("the first derive run");
        assert_eq!(
            first.modules[0].stages[0].disposition,
            StageDisposition::Ran
        );
        assert_eq!(derive_calls.get(), 1);

        let second = run_pipeline(&store, &pipeline, &modules).expect("the second derive run");
        assert_eq!(
            second.modules[0].stages[0].disposition,
            StageDisposition::Reused
        );
        // The expensive derivation did not run again.
        assert_eq!(derive_calls.get(), 1);

        let stored = store
            .load(&ModuleId::new("java/util"), "derive")
            .expect("the artifact loads")
            .expect("derive stored an artifact");
        assert_eq!(stored.payload["files_read"], 2);
        assert!(!stored.payload["entries"].as_array().unwrap().is_empty());
    }
}
