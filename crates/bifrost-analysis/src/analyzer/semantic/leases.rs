//! Bounded strong leases for complete semantic artifact allocations.
//!
//! A lease is deliberately not an artifact cache. It preserves the exact
//! allocation that produced pointer-scoped semantic handles while ordinary
//! provider lookup continues to derive and validate the current artifact key.

pub use brokk_bifrost_semantic::analyzer::semantic::leases::*;

#[cfg(test)]
pub(crate) mod tests {

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::leases::LEASE_STORAGE_BASE_BYTES;

    use brokk_bifrost_analysis::analyzer::semantic::leases::LeaseStorage;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactCollector;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLease;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLeaseCapacityExceeded;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLeaseCharge;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLeaseError;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLeaseScope;

    use brokk_bifrost_analysis::analyzer::semantic::leases::SemanticArtifactLeaseSet;

    use brokk_bifrost_analysis::analyzer::semantic::leases::retained_artifact_bytes;

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::analyzer::semantic::ContentIdentity;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapabilities;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceRevision;

    fn file(path: &str) -> ProjectFile {
        brokk_bifrost_analysis::analyzer::common::project_file_for_test(&std::env::temp_dir(), path)
    }

    fn artifact(path: &str, source: &str) -> Arc<SemanticArtifact> {
        let key = crate::test_support::semantic_artifact_key_fixture(
            "semantic lease test mount",
            path,
            SemanticLanguage::Standard(Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(source.as_bytes()),
            },
            "lease-test-typescript",
            "adapter",
            "lease test IR",
            "lease test configuration",
            "lease test dependencies",
        );
        Arc::new(
            SemanticArtifact::try_new(key, SemanticCapabilities::default(), Vec::new())
                .expect("empty complete fixture artifact"),
        )
    }

    fn observe(
        collector: &SemanticArtifactCollector,
        file: &ProjectFile,
        artifact: &Arc<SemanticArtifact>,
    ) {
        collector.observe_complete(file, artifact);
    }

    fn one_lease_retained_bytes(file: &ProjectFile, artifact: &Arc<SemanticArtifact>) -> usize {
        LEASE_STORAGE_BASE_BYTES
            .checked_add(
                retained_artifact_bytes(file, artifact).expect("fixture lease weight fits usize"),
            )
            .expect("fixture storage weight fits usize")
    }

    #[test]
    fn distinct_allocations_with_the_same_key_are_retained_separately() {
        let file = file("src/twins.ts");
        let first = artifact("src/twins.ts", "export const twins = 1;\n");
        let second = artifact("src/twins.ts", "export const twins = 1;\n");
        let third = artifact("src/twins.ts", "export const twins = 1;\n");
        assert_eq!(first.key(), second.key());
        assert!(!Arc::ptr_eq(&first, &second));

        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &first);
        observe(&collector, &file, &second);
        drop(collector);
        window
            .commit(&mut child)
            .expect("both exact allocations fit");
        assert!(child.contains_exact(&first));
        assert!(child.contains_exact(&second));
        assert!(!child.contains_exact(&third));
        let charge = child.into_charge();
        assert_eq!(charge.len(), 2);
        leases
            .try_apply_charge(charge, 0)
            .expect("both exact allocations apply");
        assert_eq!(leases.len(), 2);
        let snapshot = leases.snapshot();
        assert!(snapshot.contains_exact(&first));
        assert!(snapshot.contains_exact(&second));
        assert!(!snapshot.contains_exact(&third));
    }

    #[test]
    fn apply_preflights_the_whole_batch_and_source_headroom_atomically() {
        let first_file = file("src/first.ts");
        let first = artifact("src/first.ts", "export const first = 1;\n");
        let second_file = file("src/second.ts");
        let second = artifact("src/second.ts", "export const second = 2;\n");
        let first_bytes = one_lease_retained_bytes(&first_file, &first);
        let second_bytes = retained_artifact_bytes(&second_file, &second)
            .expect("second fixture lease weight fits usize");
        let cap = first_bytes
            .checked_add(LEASE_STORAGE_BASE_BYTES)
            .and_then(|bytes| bytes.checked_add(second_bytes))
            .expect("two live lease storages fit usize");
        let mut leases = SemanticArtifactLeaseSet::new(cap);

        let mut first_child = leases.snapshot().into_child();
        let first_window = first_child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        first_window
            .commit(&mut first_child)
            .expect("first artifact fits");
        leases
            .try_apply_charge(first_child.into_charge(), 0)
            .expect("first artifact applies");
        let before_len = leases.len();
        let before_bytes = leases.retained_bytes();

        let mut second_child = leases.snapshot().into_child();
        assert_eq!(second_child.len(), 1);
        assert_eq!(second_child.additions_len(), 0);
        let second_window = second_child.begin_window(0);
        assert!(second_window.contains_exact(&first));
        assert!(!second_window.contains_exact(&second));
        let collector = second_window.collector();
        observe(&collector, &second_file, &second);
        assert!(second_window.contains_exact(&second));
        drop(collector);
        second_window
            .commit(&mut second_child)
            .expect("second artifact fits without a live source");
        assert_eq!(second_child.len(), 2);
        assert_eq!(second_child.additions_len(), 1);
        let error = leases
            .try_apply_charge(second_child.into_charge(), 1)
            .expect_err("one live source byte exceeds the shared physical cap");
        assert!(matches!(
            error,
            SemanticArtifactLeaseError::Capacity(
                SemanticArtifactLeaseCapacityExceeded { limit, attempted }
            ) if limit == cap && attempted == cap + 1
        ));
        assert_eq!(leases.len(), before_len);
        assert_eq!(leases.retained_bytes(), before_bytes);
    }

    #[test]
    fn windows_discard_or_promote_into_one_cumulative_child() {
        let first_file = file("src/first.ts");
        let first = artifact("src/first.ts", "export const first = 1;\n");
        let second_file = file("src/second.ts");
        let second = artifact("src/second.ts", "export const second = 2;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();

        let discarded = child.begin_window(0);
        let collector = discarded.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        discarded.discard();

        let first_window = child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &first_file, &first);
        drop(collector);
        first_window
            .commit(&mut child)
            .expect("first positive window fits");

        let second_window = child.begin_window(0);
        let collector = second_window.collector();
        observe(&collector, &first_file, &first);
        observe(&collector, &second_file, &second);
        assert_eq!(collector.len(), 1, "the promoted first Arc is deduplicated");
        drop(collector);
        second_window
            .commit(&mut child)
            .expect("second positive window fits");

        let charge = child.into_charge();
        assert_eq!(charge.len(), 2);
        leases
            .try_apply_charge(charge, 0)
            .expect("cumulative positive windows apply");
        assert_eq!(leases.len(), 2);
    }

    #[test]
    fn charges_reject_wrong_scope_stale_replay_and_overlap() {
        let file = file("src/scope.ts");
        let artifact = artifact("src/scope.ts", "export const scope = 1;\n");
        let mut first_set = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut unrelated = SemanticArtifactLeaseSet::new(usize::MAX);

        let wrong_scope = first_set.snapshot().into_child().into_charge();
        assert_eq!(
            unrelated.try_apply_charge(wrong_scope, 0),
            Err(SemanticArtifactLeaseError::WrongScope)
        );

        let shared_snapshot = first_set.snapshot();
        let first_charge = shared_snapshot.clone().into_child().into_charge();
        let replay = shared_snapshot.into_child().into_charge();
        first_set
            .try_apply_charge(first_charge, 0)
            .expect("first one-shot generation applies");
        assert_eq!(
            first_set.try_apply_charge(replay, 0),
            Err(SemanticArtifactLeaseError::StaleGeneration {
                expected: 0,
                actual: 1,
            })
        );

        let mut overlap = LeaseStorage::default();
        assert_eq!(
            overlap.try_insert(SemanticArtifactLease::new(
                file.clone(),
                Arc::clone(&artifact),
            )),
            Ok(true)
        );
        let current = SemanticArtifactLeaseCharge {
            scope: Arc::clone(&first_set.scope),
            expected_generation: first_set.state.generation,
            additions: overlap,
        };
        first_set
            .try_apply_charge(current, 0)
            .expect("first artifact is not yet in the committed set");

        let mut duplicate = LeaseStorage::default();
        assert_eq!(
            duplicate.try_insert(SemanticArtifactLease::new(file, artifact)),
            Ok(true)
        );
        let overlapping = SemanticArtifactLeaseCharge {
            scope: Arc::clone(&first_set.scope),
            expected_generation: first_set.state.generation,
            additions: duplicate,
        };
        assert_eq!(
            first_set.try_apply_charge(overlapping, 0),
            Err(SemanticArtifactLeaseError::Overlap)
        );
    }

    #[test]
    fn apply_rejects_an_outstanding_snapshot_without_cloning_state() {
        let file = file("src/outstanding.ts");
        let artifact = artifact("src/outstanding.ts", "export const outstanding = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut initial_child = leases.snapshot().into_child();
        let window = initial_child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        window
            .commit(&mut initial_child)
            .expect("initial lease fits");
        leases
            .try_apply_charge(initial_child.into_charge(), 0)
            .expect("initial lease applies");

        let outstanding = leases.snapshot();
        let charge = outstanding.clone().into_child().into_charge();
        let before_generation = leases.state.generation;
        let before_len = leases.len();
        let before_bytes = leases.retained_bytes();
        let before_state = leases.state_identity();
        assert_eq!(
            leases.try_apply_charge(charge, 0),
            Err(SemanticArtifactLeaseError::OutstandingGeneration)
        );
        assert_eq!(leases.state.generation, before_generation);
        assert_eq!(leases.len(), before_len);
        assert_eq!(leases.retained_bytes(), before_bytes);
        assert_eq!(leases.state_identity(), before_state);

        drop(outstanding);
        let fresh_charge = leases.snapshot().into_child().into_charge();
        leases
            .try_apply_charge(fresh_charge, 0)
            .expect("a consumed fresh snapshot applies in place");
        assert_eq!(leases.state.generation, before_generation + 1);
        assert_eq!(leases.state_identity(), before_state);
    }

    #[test]
    fn charge_weight_accounts_for_long_project_file_storage() {
        let artifact = artifact("src/weight.ts", "export const weight = 1;\n");
        let short_file = file("src/weight.ts");
        let long_path = format!("src/{}/weight.ts", "nested/".repeat(128));
        let long_file = file(&long_path);
        let charge_for = |file: ProjectFile| {
            let mut additions = LeaseStorage::default();
            assert_eq!(
                additions.try_insert(SemanticArtifactLease::new(file, Arc::clone(&artifact),)),
                Ok(true)
            );
            SemanticArtifactLeaseCharge {
                scope: Arc::new(SemanticArtifactLeaseScope),
                expected_generation: 0,
                additions,
            }
        };

        let short = charge_for(short_file).retained_bytes();
        let long = charge_for(long_file).retained_bytes();
        assert!(
            long >= short.saturating_add(long_path.len() / 2),
            "lease charge weights must include owned ProjectFile paths"
        );
    }
    #[test]
    fn child_allows_only_one_live_window_and_seals_late_collectors() {
        let file = file("src/window.ts");
        let artifact = artifact("src/window.ts", "export const window = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let first = child.begin_window(0);
        let late_collector = first.collector();

        let second =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.begin_window(0)));
        assert!(second.is_err(), "one child cannot own concurrent windows");

        first.discard();
        assert_eq!(
            Arc::strong_count(&child.additions),
            1,
            "closing a window releases its promoted snapshot before publishing the child reusable"
        );
        observe(&late_collector, &file, &artifact);
        assert_eq!(late_collector.len(), 0, "sealed collectors retain nothing");
        drop(late_collector);

        let replacement = child.begin_window(0);
        replacement.discard();
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn window_rejects_a_different_child_from_the_same_snapshot() {
        let file = file("src/wrong_child.ts");
        let artifact = artifact("src/wrong_child.ts", "export const wrongChild = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let snapshot = leases.snapshot();
        let mut first_child = snapshot.clone().into_child();
        let mut second_child = snapshot.into_child();
        let first_window = first_child.begin_window(0);
        let collector = first_window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        let second_window = second_child.begin_window(0);

        assert_eq!(
            first_window.commit(&mut second_child),
            Err(SemanticArtifactLeaseError::WrongScope)
        );
        second_window.discard();
        assert_eq!(first_child.into_charge().len(), 0);
        assert_eq!(second_child.into_charge().len(), 0);
    }
    #[test]
    fn bounded_collector_latches_retained_byte_arithmetic_overflow() {
        let file = file("src/arithmetic.ts");
        let artifact = artifact("src/arithmetic.ts", "export const arithmetic = 1;\n");
        let leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(usize::MAX);
        assert_eq!(window.overflow(), None, "source alone exactly fits usize");
        let collector = window.collector();

        observe(&collector, &file, &artifact);
        assert_eq!(
            collector.overflow(),
            Some(SemanticArtifactLeaseError::RetainedBytesOverflow)
        );
        assert_eq!(collector.len(), 0);
        drop(collector);
        assert_eq!(
            window.commit(&mut child),
            Err(SemanticArtifactLeaseError::RetainedBytesOverflow)
        );
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn bounded_collector_cannot_drain_cap_accounted_leases() {
        let file = file("src/no_drain.ts");
        let artifact = artifact("src/no_drain.ts", "export const noDrain = 1;\n");
        let mut leases = SemanticArtifactLeaseSet::new(usize::MAX);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        observe(&collector, &file, &artifact);

        let one_file = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.take_complete(&file)
        }));
        assert!(
            one_file.is_err(),
            "bounded collectors cannot drain one file"
        );
        let all = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.take_all_complete()
        }));
        assert!(all.is_err(), "bounded collectors cannot drain a window");
        assert_eq!(collector.len(), 1, "failed drains retain the staged lease");

        drop(collector);
        window
            .commit(&mut child)
            .expect("the still-accounted lease commits");
        leases
            .try_apply_charge(child.into_charge(), 0)
            .expect("the still-accounted lease applies");
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn caller_owned_window_reservations_shrink_or_rollback_atomically() {
        let file = file("src/reservation.ts");
        let artifact = artifact("src/reservation.ts", "export const reservation = 1;\n");
        let artifact_bytes = one_lease_retained_bytes(&file, &artifact);
        let cap = artifact_bytes + 8;

        let leases = SemanticArtifactLeaseSet::new(cap);
        let mut child = leases.snapshot().into_child();
        let rollback_window = child.begin_window(0);
        let collector = rollback_window.collector();
        observe(&collector, &file, &artifact);
        drop(collector);
        let rollback = rollback_window
            .reserve_other_live_bytes(8)
            .expect("the full caller-owned reservation fits");
        drop(rollback);
        rollback_window
            .commit(&mut child)
            .expect("dropping a reservation restores all headroom");

        let exact_window = child.begin_window(0);
        let exact = exact_window
            .reserve_other_live_bytes(8)
            .expect("the conservative caller-owned reservation fits");
        let retained = vec![0_u8; 3].into_boxed_slice();
        exact.retain_exact(retained.len());
        exact_window
            .commit(&mut child)
            .expect("shrinking retains only the exact caller-owned bytes");
        drop(retained);

        let overflow_window = child.begin_window(0);
        let error = overflow_window
            .reserve_other_live_bytes(9)
            .expect_err("one byte beyond the physical authority is refused");
        assert_eq!(
            error,
            SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                limit: cap,
                attempted: cap + 1,
            })
        );
        assert_eq!(
            overflow_window.retained_bytes(),
            artifact_bytes,
            "a refused caller-owned reservation mutates no retained lease storage"
        );
        assert_eq!(overflow_window.commit(&mut child), Err(error));
        assert_eq!(child.len(), 1);

        let delayed_window = child.begin_window(0);
        let delayed = delayed_window
            .reserve_other_live_bytes(8)
            .expect("a final reservation fits");
        drop(delayed_window);
        let premature_reuse =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.begin_window(0)));
        assert!(
            premature_reuse.is_err(),
            "dropping a window cannot publish its child while a reservation remains live"
        );
        drop(delayed);
        child.begin_window(0).discard();
        assert_eq!(child.len(), 1);
    }

    #[test]
    fn caller_owned_window_reservations_participate_in_artifact_admission() {
        let file = file("src/reserved-admission.ts");
        let artifact = artifact(
            "src/reserved-admission.ts",
            "export const reservedAdmission = 1;\n",
        );
        let artifact_bytes = one_lease_retained_bytes(&file, &artifact);
        let caller_bytes = 8;
        let cap = artifact_bytes + caller_bytes - 1;

        let leases = SemanticArtifactLeaseSet::new(cap);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let reservation = window
            .reserve_other_live_bytes(caller_bytes)
            .expect("caller-owned bytes fit before artifact observation");
        let retained = vec![0_u8; caller_bytes].into_boxed_slice();
        reservation.retain_exact(retained.len());
        let collector = window.collector();
        let original_strong_count = Arc::strong_count(&artifact);

        observe(&collector, &file, &artifact);

        let error = collector
            .overflow()
            .expect("caller-owned bytes leave one byte too little for the artifact");
        assert_eq!(
            error,
            SemanticArtifactLeaseError::Capacity(SemanticArtifactLeaseCapacityExceeded {
                limit: cap,
                attempted: artifact_bytes + caller_bytes,
            })
        );
        assert_eq!(collector.len(), 0);
        assert_eq!(Arc::strong_count(&artifact), original_strong_count);
        drop(collector);
        assert_eq!(window.commit(&mut child), Err(error));
        drop(retained);
        assert_eq!(child.into_charge().len(), 0);
    }

    #[test]
    fn bounded_collector_latches_overflow_without_retaining_candidates() {
        let first_file = file("src/overflow.ts");
        let first = artifact("src/overflow.ts", "export const overflow = 1;\n");
        let second_file = file("src/later.ts");
        let second = artifact("src/later.ts", "export const later = 2;\n");
        let required = one_lease_retained_bytes(&first_file, &first);
        let leases = SemanticArtifactLeaseSet::new(required.saturating_sub(1));
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        let collector = window.collector();
        let first_count = Arc::strong_count(&first);
        let second_count = Arc::strong_count(&second);

        observe(&collector, &first_file, &first);
        let overflow = collector.overflow().expect("first candidate exceeds cap");
        let SemanticArtifactLeaseError::Capacity(exceeded) = overflow else {
            panic!("first candidate must report typed capacity exhaustion")
        };
        assert_eq!(exceeded.limit(), required - 1);
        assert_eq!(exceeded.attempted(), required);
        assert!(
            window.retained_bytes() < exceeded.attempted(),
            "the refused candidate's attempted charge is not a live retained peak"
        );
        assert_eq!(collector.len(), 0);
        assert_eq!(Arc::strong_count(&first), first_count);

        observe(&collector, &second_file, &second);
        assert_eq!(collector.len(), 0, "overflow refuses every later new Arc");
        assert_eq!(Arc::strong_count(&second), second_count);
        drop(collector);
        assert_eq!(window.commit(&mut child), Err(overflow));
        assert_eq!(child.into_charge().len(), 0);
    }
}
