//! Bounded, source-free observations of one workspace build. No subscriber lists
//! or per-file data are retained, and producers never perform transport IO.
use crate::analyzer::{BuildProgressEvent, BuildProgressPhase};
use serde::Serialize;
use std::sync::{Arc, Mutex};

// There are twelve languages and five phases. Leave room for additions while
// keeping a hard cap independent of workspace size and subscriber count.
const MAX_COUNTERS: usize = 128;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BuildCounter {
    language: crate::analyzer::Language,
    phase: &'static str,
    unit: &'static str,
    completed: usize,
    total: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BuildSnapshot {
    pub generation: u64,
    pub workspace_generation: u64,
    pub revision: u64,
    pub status: &'static str,
    pub counters: Vec<BuildCounter>,
    // One real intermediate observation per language/phase survives a build
    // faster than the polling interval. This is bounded, not an event history.
    pub intermediate: Vec<BuildCounter>,
}

#[derive(Default)]
pub(crate) struct WorkspaceBuildProgress(Mutex<Option<BuildSnapshot>>);

impl WorkspaceBuildProgress {
    pub fn begin(self: &Arc<Self>, workspace_generation: u64) -> BuildObservation {
        let mut state = self.0.lock().expect("workspace progress lock poisoned");
        let generation = state.as_ref().map_or(1, |state| state.generation + 1);
        *state = Some(BuildSnapshot {
            generation,
            workspace_generation,
            revision: 1,
            status: "running",
            counters: Vec::new(),
            intermediate: Vec::new(),
        });
        BuildObservation {
            progress: Arc::clone(self),
            generation,
            finished: false,
        }
    }

    pub fn snapshot(&self, workspace_generation: u64) -> Option<BuildSnapshot> {
        self.0
            .lock()
            .expect("workspace progress lock poisoned")
            .as_ref()
            .filter(|state| state.workspace_generation == workspace_generation)
            .cloned()
    }
}

pub(crate) struct BuildObservation {
    progress: Arc<WorkspaceBuildProgress>,
    generation: u64,
    finished: bool,
}

impl BuildObservation {
    pub fn sink(&self) -> impl Fn(BuildProgressEvent) + Send + Sync + 'static {
        let progress = Arc::clone(&self.progress);
        let generation = self.generation;
        move |event| {
            let (phase, unit) = match event.phase {
                BuildProgressPhase::Enumerate => ("enumerate", "files"),
                BuildProgressPhase::Reconcile => ("reconcile", "files"),
                BuildProgressPhase::Parse => ("parse", "blobs"),
                BuildProgressPhase::Persist => ("persist", "blobs"),
                BuildProgressPhase::Index => ("index", "files"),
            };
            // Discard the path before taking the lock; neither the snapshot nor
            // the wire type can represent a file label or source text.
            let counter = BuildCounter {
                language: event.language,
                phase,
                unit,
                completed: event.completed,
                total: (event.total != 0).then_some(event.total),
            };
            let mut state = progress.0.lock().expect("workspace progress lock poisoned");
            let Some(state) = state
                .as_mut()
                .filter(|state| state.generation == generation && state.status == "running")
            else {
                return;
            };
            if counter.completed > 0
                && counter.total.is_some_and(|total| counter.completed < total)
                && !state
                    .intermediate
                    .iter()
                    .any(|old| old.language == counter.language && old.phase == counter.phase)
                && state.intermediate.len() < MAX_COUNTERS
            {
                state.intermediate.push(counter.clone());
            }
            let has_room = state.counters.len() < MAX_COUNTERS;
            match state
                .counters
                .iter_mut()
                .find(|old| old.language == counter.language && old.phase == counter.phase)
            {
                // Parallel producers may acquire the lock out of count order.
                Some(old) if old.total == counter.total && old.completed > counter.completed => {
                    return;
                }
                Some(old) => *old = counter,
                None if has_room => state.counters.push(counter),
                None => return,
            }
            state.revision += 1;
        }
    }

    pub fn complete(mut self) {
        self.finish("completed");
    }

    fn finish(&mut self, status: &'static str) {
        if let Some(state) = self
            .progress
            .0
            .lock()
            .expect("workspace progress lock poisoned")
            .as_mut()
            .filter(|state| state.generation == self.generation)
        {
            state.status = status;
            state.revision += 1;
        }
        self.finished = true;
    }
}

impl Drop for BuildObservation {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, ProjectFile};

    fn event(completed: usize, total: usize) -> BuildProgressEvent {
        BuildProgressEvent {
            language: Language::Python,
            phase: BuildProgressPhase::Parse,
            completed,
            total,
            file: Some(ProjectFile::new(
                std::env::temp_dir(),
                "credential_secret.py",
            )),
        }
    }

    #[test]
    fn flood_is_bounded_and_old_builds_cannot_publish_into_new_scope() {
        let progress = Arc::new(WorkspaceBuildProgress::default());
        let old = progress.begin(1);
        let sink = old.sink();
        for count in 1..100_000 {
            sink(event(count, 100_000));
        }
        let state = progress.snapshot(1).unwrap();
        assert_eq!(state.counters.len(), 1);
        assert_eq!(state.intermediate.len(), 1);
        assert_eq!(state.counters[0].completed, 99_999);
        assert!(
            !serde_json::to_string(&state)
                .unwrap()
                .contains("credential")
        );
        let new = progress.begin(2);
        sink(event(100_000, 100_000));
        old.complete();
        assert!(progress.snapshot(1).is_none());
        assert!(progress.snapshot(2).unwrap().counters.is_empty());
        drop(new);
        assert_eq!(progress.snapshot(2).unwrap().status, "failed");
    }

    #[test]
    fn unknown_and_changed_totals_are_not_percentages_and_retries_get_new_generations() {
        let progress = Arc::new(WorkspaceBuildProgress::default());
        let build = progress.begin(1);
        let sink = build.sink();
        sink(event(5, 10));
        sink(event(3, 10)); // Out-of-order producer delivery, not a retry.
        assert_eq!(progress.snapshot(1).unwrap().counters[0].completed, 5);
        sink(event(2, 20));
        assert_eq!(progress.snapshot(1).unwrap().counters[0].completed, 2);
        sink(event(4, 0));
        assert_eq!(progress.snapshot(1).unwrap().counters[0].total, None);
        build.complete();
        let retry = progress.begin(1);
        assert_eq!(progress.snapshot(1).unwrap().generation, 2);
        assert!(progress.snapshot(1).unwrap().intermediate.is_empty());
        retry.complete();
    }
}
