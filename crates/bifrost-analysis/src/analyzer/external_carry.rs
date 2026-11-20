//! Carrying a lazily built external index into the next analyzer generation.
//!
//! An external index (JVM declarations, .NET assemblies) is expensive to build
//! and depends on files that an ordinary edit leaves alone. A generation does
//! not share its predecessor's cell. It receives the predecessor's filled index
//! as a candidate, and the first read of the new generation decides, inside the
//! cell's single fill, whether the candidate still holds: the reader samples
//! the inputs of the index at the new generation and compares the sample with
//! the one the candidate was built from. Equal samples keep the index; any
//! difference rebuilds it. No changed-path list decides, so an input that moved
//! without being reported still rebuilds the index.

use std::sync::{Arc, Mutex};

/// One filled index together with the sample of inputs it was built from.
#[derive(Debug)]
pub struct ExternalFill<V, S> {
    value: V,
    inputs: S,
}

impl<V, S> ExternalFill<V, S> {
    pub fn new(value: V, inputs: S) -> Self {
        Self { value, inputs }
    }

    /// The built index.
    pub fn value(&self) -> &V {
        &self.value
    }

    /// The sample that the index was built from.
    pub fn inputs(&self) -> &S {
        &self.inputs
    }
}

/// Whether an index was decoded from inputs that stayed stable during its build.
pub enum ExternalBuildOutcome<V> {
    Verified(V),
    InputsChanged(V),
}

impl<V> ExternalBuildOutcome<V> {
    /// A raced result can answer this read, but cannot be retained or carried.
    pub fn into_value(self, analyzer: &dyn super::IAnalyzer) -> V {
        match self {
            Self::Verified(value) => value,
            Self::InputsChanged(value) => {
                analyzer.record_unattributed_read();
                analyzer.refuse_read_reuse();
                value
            }
        }
    }
}

/// Decode once, then verify the input sample without adding duplicate project
/// reads to the receipt. An unavailable post-build sample also refuses reuse.
pub fn build_with_verified_inputs<V, S: PartialEq>(
    before: &S,
    build: impl FnOnce() -> V,
    verify: impl FnOnce() -> Option<S>,
) -> ExternalBuildOutcome<V> {
    use brokk_bifrost_core::analyzer::project_reads::without_project_reads;
    let value = without_project_reads(build);
    match without_project_reads(verify) {
        Some(after) if &after == before => ExternalBuildOutcome::Verified(value),
        _ => ExternalBuildOutcome::InputsChanged(value),
    }
}

/// The predecessor generation's fill, held until a fill of this generation is
/// retained. The candidate is the fill that recorded the inputs, so two
/// successive updates compare against that generation and never against each
/// other.
type Candidate<V, S> = Arc<Mutex<Option<Arc<ExternalFill<V, S>>>>>;

#[derive(Debug)]
pub struct ExternalCarry<V, S> {
    candidate: Candidate<V, S>,
}

impl<V, S> Clone for ExternalCarry<V, S> {
    fn clone(&self) -> Self {
        Self {
            candidate: Arc::clone(&self.candidate),
        }
    }
}

impl<V, S> Default for ExternalCarry<V, S> {
    fn default() -> Self {
        Self {
            candidate: Arc::new(Mutex::new(None)),
        }
    }
}

impl<V, S: PartialEq> ExternalCarry<V, S> {
    /// The carry of the next generation: `filled`, this generation's retained
    /// fill, or else the candidate this generation never settled.
    pub fn successor(&self, filled: Option<&Arc<ExternalFill<V, S>>>) -> Self {
        Self {
            candidate: Arc::new(Mutex::new(filled.cloned().or_else(|| self.pending()))),
        }
    }

    /// The fill that awaits this generation's decision, if any.
    pub fn pending(&self) -> Option<Arc<ExternalFill<V, S>>> {
        self.candidate
            .lock()
            .expect("external index candidate poisoned")
            .clone()
    }

    /// Decide the fill of this generation. The candidate is reused when this
    /// generation's `inputs` sample is `reusable` and equals the candidate's;
    /// otherwise `build` runs. Call this inside the cell's single fill so that
    /// concurrent first readers wait for one decision.
    pub fn resolve(
        &self,
        inputs: S,
        reusable: bool,
        build: impl FnOnce() -> V,
    ) -> Arc<ExternalFill<V, S>> {
        match self
            .pending()
            .filter(|candidate| reusable && candidate.inputs == inputs)
        {
            Some(candidate) => candidate,
            None => Arc::new(ExternalFill::new(build(), inputs)),
        }
    }

    /// Drop the candidate once a fill of this generation is retained, so the
    /// predecessor's index can be freed. A cancelled or refused fill never
    /// calls this and leaves the decision to the next reader.
    pub fn settle(&self) {
        self.candidate
            .lock()
            .expect("external index candidate poisoned")
            .take();
    }
}
