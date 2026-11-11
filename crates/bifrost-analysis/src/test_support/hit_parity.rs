//! The engine of the hit-path read parity test (#7262).
//!
//! A cache or memo hit that records fewer read keys than its fill leaves a
//! policy unit with an incomplete read set: a change that only the fill
//! depended on would not invalidate the unit. A row of the test is one hit
//! path. [`Rows::row`] runs one operation twice on one warm cache, each time
//! under its own read ledger: the first run fills and the second hits. It
//! asserts that the path's own hit counter moved, so a hit really happened,
//! and then compares the two ledgers by the class of the path.
//!
//! Class R ([`Class::Replay`]): the hit replays the fill's receipt, so the
//! two key sets are equal.
//!
//! Class C ([`Class::ConsumerKeys`]): the hit records consumer-side keys that
//! read verification recomputes from the head. For each key the fill
//! recorded, the key's observed value is changed, as if the head disagreed
//! with it, and the real verifier must reject the hit's read set whenever it
//! rejects the fill's. Soundness needs one direction only: a hit that fails
//! more often than its fill costs only reuse. The mutations come from the
//! fill's recorded key set, not from a hand-picked list. A key that names a
//! question and no observed value (an index probe, an absent path) cannot be
//! changed by value; the hit must still hold a key that asks the same
//! question.
//!
//! The rows live where the paths they exercise are reachable:
//! `tests/suite_bench_policy/hit_path_read_parity.rs` (value-flow caches and
//! the field-slot memory hit), `crates/bifrost-tools/src/engine_tests/
//! hit_path_read_parity.rs` (the tree-sitter analyzer's request caches),
//! the Rust analysis crate's `hit_path_read_parity_tests.rs` (the Rust walk
//! caches, the route and package request memo, the naming caches) and the
//! policy crate's `taint_policy/tests/compose_memo_parity.rs` (the
//! composition memo). Each file carries its own row table.

use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{DerivedArtifactId, DerivedArtifactKind};
use crate::analyzer::read_ledger::{ReadLedger, read_set_digest};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{
    AnalyzerConfig, ChangedFacts, HeadInputs, IAnalyzer, LookupMemo, LookupReplayLimits,
    NoSummaryAnswers, Project, ReadKey, ReadVerdict, SummaryAnswers, WorkspaceAnalyzer,
    capture_query_reads, verify_read_set_for_artifact,
};
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The hit replays the fill's receipt: equal key sets.
    Replay,
    /// The hit records consumer-side keys: every fill key's change fails the
    /// hit too.
    ConsumerKeys,
}

/// How a row knows that its second run hit the path's cache.
pub enum Evidence<'a> {
    /// The path's own hit counter rises across the second run.
    Hits(&'a dyn Fn() -> u64),
    /// The path counts only its fills: the first run raises the count and the
    /// second leaves it where it was.
    Fills(&'a dyn Fn() -> u64),
    /// Each named hit counter rises across the second run: one fixture
    /// exercises a family of caches that each count their own hits.
    EachHits(&'a [(&'a str, &'a dyn Fn() -> u64)]),
}

/// A declared coverage: a fill key that the hit does not hold in a form that
/// fails when the key's value changes is still accounted for when the hit
/// holds a coarser key that does. Each declaration is one reviewable claim
/// about a path ("the fill's per-file probes are covered by the whole-answer
/// key the hit records instead"); the engine checks that the covering key is
/// present in the hit and that changing its value fails the hit.
pub struct Coverage<'a> {
    pub claim: &'a str,
    /// The fill keys the claim accounts for.
    pub covered: &'a dyn Fn(&ReadKey) -> bool,
    /// The hit key that accounts for them.
    pub by: &'a dyn Fn(&ReadKey) -> bool,
}

/// The head the recorded keys are verified against: the same workspace
/// again, so every key that is not changed holds.
pub struct Head {
    workspace: WorkspaceAnalyzer,
    changed: ChangedFacts,
    answers: Box<dyn SummaryAnswers>,
}

impl Head {
    pub fn of(project: Arc<dyn Project>, base: &WorkspaceAnalyzer) -> Self {
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("the head workspace builds");
        let changed = ChangedFacts::between(base, &workspace);
        Self {
            workspace,
            changed,
            answers: Box::new(NoSummaryAnswers),
        }
    }

    /// The verifier's answers for summary and workspace-fact lookups that the
    /// workspace cannot recompute alone, computed from the head workspace.
    pub fn with_answers<A: SummaryAnswers + 'static>(
        mut self,
        answers: impl FnOnce(&WorkspaceAnalyzer) -> A,
    ) -> Self {
        self.answers = Box::new(answers(&self.workspace));
        self
    }

    pub fn verdict(&self, keys: &[ReadKey]) -> ReadVerdict {
        let digest = StableDigest::from_array([0; 32]);
        let inputs = HeadInputs {
            // #9755 records the active (or absent) model set as a Models read.
            // These fixtures activate no models, so the head's model read
            // digest is the absence digest, not the zero placeholder.
            models: crate::analyzer::i_analyzer::current_model_set_digest(None),
            policy_semantic_hash: digest,
            policy_source: digest,
            configuration: digest,
            epoch: digest,
        };
        let artifact = DerivedArtifactId::new(
            DerivedArtifactKind::PolicyEvaluationUnit,
            read_set_digest(keys).digest(),
        );
        verify_read_set_for_artifact(
            artifact,
            &self.workspace,
            &self.changed,
            &inputs,
            keys,
            LookupReplayLimits::default(),
            self.answers.as_ref(),
            &mut LookupMemo::default(),
        )
    }
}

/// `key` with its observed value replaced by the value `tag` names, or `None`
/// when the key has no observed value (it is its question and nothing else).
fn with_observed(key: &ReadKey, tag: u8) -> Option<ReadKey> {
    let digest = StableDigest::from_array([tag; 32]);
    Some(match key {
        ReadKey::File {
            language,
            rel_path,
            parse_variant,
            ..
        } => ReadKey::File {
            language: *language,
            rel_path: rel_path.clone(),
            blob: git2::Oid::from_bytes(&[tag; 20]).expect("twenty bytes make an object id"),
            parse_variant: *parse_variant,
        },
        ReadKey::Lookup { kind, question, .. } => ReadKey::Lookup {
            kind: *kind,
            question: question.clone(),
            digest,
        },
        ReadKey::Artifact { id, rel_path } => ReadKey::Artifact {
            id: DerivedArtifactId::new(id.kind(), digest),
            rel_path: rel_path.clone(),
        },
        ReadKey::Scope { languages, .. } => ReadKey::Scope {
            languages: languages.clone(),
            identity: WorkspaceContentIdentity::from_digest(digest),
        },
        ReadKey::Models(_) => ReadKey::Models(digest),
        ReadKey::Policy { .. } => ReadKey::Policy {
            semantic_hash: digest,
            source: digest,
        },
        ReadKey::Configuration(_) => ReadKey::Configuration(digest),
        ReadKey::Epoch(_) => ReadKey::Epoch(digest),
        ReadKey::Index { .. } | ReadKey::PathAbsent { .. } => return None,
    })
}

/// A workspace-fact lookup of overlay membership: of one file, or (`whole`) of
/// the whole workspace. Any change to one file's membership changes the whole,
/// so the whole covers the file.
fn overlay_membership(key: &ReadKey, whole: bool) -> bool {
    matches!(key, ReadKey::Lookup {
        question: crate::analyzer::LookupQuestion::WorkspaceFact {
            family: crate::analyzer::WorkspaceFactFamily::WorkspaceOverlayMembership,
            subject,
            ..
        },
        ..
    } if matches!(subject, crate::analyzer::FactSubject::Whole) == whole)
}

/// The question a key asks, with whatever value it observed taken out.
fn question(key: &ReadKey) -> ReadKey {
    with_observed(key, 0).unwrap_or_else(|| key.clone())
}

/// `keys` as the head would see them if the answer to `changed`'s question
/// differed from the recorded one.
fn perturbed(keys: &[ReadKey], changed: &ReadKey) -> Vec<ReadKey> {
    let asked = question(changed);
    keys.iter()
        .map(|key| {
            if question(key) == asked {
                with_observed(key, 0xA5).unwrap_or_else(|| key.clone())
            } else {
                key.clone()
            }
        })
        .collect()
}

/// The current value of each counter a row's evidence names.
fn evidence_counts(evidence: &Evidence<'_>) -> Vec<u64> {
    match evidence {
        Evidence::Hits(counter) | Evidence::Fills(counter) => vec![counter()],
        Evidence::EachHits(counters) => counters.iter().map(|(_, counter)| counter()).collect(),
    }
}

/// The rows of one fixture, and what its hits lost.
pub struct Rows<'a> {
    analyzer: &'a dyn IAnalyzer,
    head: &'a Head,
    failures: Vec<String>,
    /// Rows whose fill recorded no key, so that their hit had nothing to lose.
    pub vacuous: Vec<String>,
}

impl<'a> Rows<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, head: &'a Head) -> Self {
        Self {
            analyzer,
            head,
            failures: Vec::new(),
            vacuous: Vec::new(),
        }
    }

    /// One row: `operation` fills under one ledger and hits under another.
    pub fn row<T>(
        &mut self,
        name: &str,
        class: Class,
        evidence: Evidence<'_>,
        operation: impl Fn() -> T,
    ) {
        self.row_covering(name, class, evidence, &[], operation);
    }

    /// [`Self::row`] for a class C path whose hit holds coarser keys than its
    /// fill, with the declared coverage that accounts for the difference.
    pub fn row_covering<T>(
        &mut self,
        name: &str,
        class: Class,
        evidence: Evidence<'_>,
        coverage: &[Coverage<'_>],
        operation: impl Fn() -> T,
    ) {
        let counts = || evidence_counts(&evidence);
        let start = counts();
        let (_, fill) = capture_query_reads(self.analyzer, &operation);
        let after_fill = counts();
        let (_, hit) = capture_query_reads(self.analyzer, &operation);
        let after_hit = counts();
        let stalled: Vec<usize> = (0..start.len())
            .filter(|index| match evidence {
                Evidence::Hits(_) | Evidence::EachHits(_) => {
                    after_hit[*index] <= after_fill[*index]
                }
                Evidence::Fills(_) => {
                    !(after_fill[*index] > start[*index] && after_hit[*index] == after_fill[*index])
                }
            })
            .collect();
        if !stalled.is_empty() || start.is_empty() {
            let names: Vec<&str> = match &evidence {
                Evidence::EachHits(counters) => {
                    stalled.iter().map(|index| counters[*index].0).collect()
                }
                _ => vec!["the counter"],
            };
            self.failures.push(format!(
                "{name}: the second run did not hit the path's cache: {names:?} (counters {start:?} -> {after_fill:?} -> {after_hit:?})"
            ));
            return;
        }
        self.compare(name, class, &fill, &hit, coverage);
    }

    /// A [`Class::Replay`] row whose fill runs with no outer capture, as the
    /// policy cold fallback's fills do (#10647). `reference` fills a fresh
    /// cache inside a capture. `operation` fills the row's own cache with no
    /// capture and then hits it inside one. The hit must record the reference
    /// fill's keys: what an entry replays cannot depend on whether a capture
    /// was active when it was built.
    pub fn row_after_uncaptured_fill<T>(
        &mut self,
        name: &str,
        evidence: Evidence<'_>,
        reference: impl Fn() -> T,
        operation: impl Fn() -> T,
    ) {
        let counts = || evidence_counts(&evidence);
        let (_, fill) = capture_query_reads(self.analyzer, &reference);
        assert!(
            self.analyzer.current_thread_read_ledger().is_none(),
            "{name}: the uncaptured fill must run with no capture on this thread"
        );
        operation();
        let after_fill = counts();
        let (_, hit) = capture_query_reads(self.analyzer, &operation);
        let after_hit = counts();
        if after_fill.is_empty()
            || after_fill
                .iter()
                .zip(&after_hit)
                .any(|(fill, hit)| hit <= fill)
        {
            self.failures.push(format!(
                "{name}: the captured run did not hit the cache the uncaptured run filled (counters {after_fill:?} -> {after_hit:?})"
            ));
            return;
        }
        self.compare(name, Class::Replay, &fill, &hit, &[]);
    }

    fn compare(
        &mut self,
        name: &str,
        class: Class,
        fill: &ReadLedger,
        hit: &ReadLedger,
        coverage: &[Coverage<'_>],
    ) {
        for (side, ledger) in [("fill", fill), ("hit", hit)] {
            if ledger.unattributed_reads() > 0 {
                self.failures.push(format!(
                    "{name}: the {side} ledger holds {} unattributed reads",
                    ledger.unattributed_reads()
                ));
            }
        }
        let (fill, hit) = (fill.keys(), hit.keys());
        eprintln!(
            "hit_parity {name}: {} keys in the fill, {} in the hit",
            fill.len(),
            hit.len()
        );
        if fill.is_empty() {
            // Nothing to compare: both runs record nothing, as for a path
            // whose input is an already-materialized artifact.
            self.vacuous.push(name.to_owned());
            return;
        }
        match class {
            Class::Replay => {
                let (fill, hit): (BTreeSet<_>, BTreeSet<_>) =
                    (fill.iter().collect(), hit.iter().collect());
                if fill != hit {
                    self.failures.push(format!(
                        "{name}: fill and hit key sets differ\nonly in the fill: {:#?}\nonly in the hit: {:#?}",
                        fill.difference(&hit).collect::<Vec<_>>(),
                        hit.difference(&fill).collect::<Vec<_>>()
                    ));
                }
            }
            Class::ConsumerKeys => self.consumer_keys(name, &fill, &hit, coverage),
        }
    }

    fn consumer_keys(
        &mut self,
        name: &str,
        fill: &[ReadKey],
        hit: &[ReadKey],
        coverage: &[Coverage<'_>],
    ) {
        for (side, keys) in [("fill", fill), ("hit", hit)] {
            let verdict = self.head.verdict(keys);
            if !verdict.is_unchanged() {
                self.failures.push(format!(
                    "{name}: the unchanged head rejects the {side} read set: {verdict:?}"
                ));
            }
        }
        let mut covered_by_claim = std::collections::BTreeMap::<&str, usize>::new();
        for key in fill {
            let lost = if with_observed(key, 0).is_none() {
                let asked = question(key);
                hit.iter().all(|other| question(other) != asked)
            } else {
                // A key whose change the verifier cannot see does not fail
                // the fill, so the hit owes nothing for it.
                !self.head.verdict(&perturbed(fill, key)).is_unchanged()
                    && self.head.verdict(&perturbed(hit, key)).is_unchanged()
            };
            if !lost {
                continue;
            }
            let overlay = Coverage {
                claim: "a file's overlay membership is covered by the whole overlay membership",
                covered: &|key| overlay_membership(key, false),
                by: &|key| overlay_membership(key, true),
            };
            let covering = coverage
                .iter()
                .chain(std::iter::once(&overlay))
                .filter(|claim| (claim.covered)(key))
                .find_map(|claim| {
                    hit.iter()
                        .find(|other| (claim.by)(other))
                        .map(|other| (claim, other))
                });
            match covering {
                Some((claim, by))
                    if with_observed(by, 0).is_some()
                        && !self.head.verdict(&perturbed(hit, by)).is_unchanged() =>
                {
                    *covered_by_claim.entry(claim.claim).or_default() += 1;
                }
                _ => self.failures.push(format!(
                    "{name}: changing {key:?} fails the fill but not the hit\nhit keys: {hit:#?}"
                )),
            }
        }
        for (claim, keys) in covered_by_claim {
            eprintln!("hit_parity {name}: {keys} fill keys covered by the declared claim: {claim}");
        }
    }

    /// Fails with every row that lost a read.
    pub fn finish(self) {
        for name in &self.vacuous {
            eprintln!("hit_parity {name}: vacuous, the fill recorded no key");
        }
        assert!(
            self.failures.is_empty(),
            "hit paths that lost reads:\n{}",
            self.failures.join("\n")
        );
    }
}
