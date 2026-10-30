use crate::dataflow::{MAX_WITNESS_ALTERNATIVES_PER_QUALITY, WitnessRetentionLimits};

#[test]
fn retention_limits_admit_inclusive_public_ceilings() {
    for alternatives in [1, MAX_WITNESS_ALTERNATIVES_PER_QUALITY] {
        let limit = WitnessRetentionLimits::new(alternatives).unwrap();
        assert_eq!(limit.max_alternatives_per_quality(), alternatives);
        assert!(limit.is_enabled());
        assert!(!limit.is_best_effort());
    }
    for alternatives in [0, MAX_WITNESS_ALTERNATIVES_PER_QUALITY + 1] {
        assert_eq!(
            WitnessRetentionLimits::new(alternatives)
                .unwrap_err()
                .field(),
            "max_alternatives_per_quality"
        );
    }
    let limit = WitnessRetentionLimits::best_effort(1, u32::MAX as usize, 1).unwrap();
    assert!(limit.is_best_effort());
    assert_eq!(limit.max_alternatives_per_quality(), 1);
    assert_eq!(
        WitnessRetentionLimits::best_effort(1, 0, 1)
            .unwrap_err()
            .field(),
        "max_retained_relations"
    );
    assert_eq!(
        WitnessRetentionLimits::best_effort(1, 1, 0)
            .unwrap_err()
            .field(),
        "max_retained_bytes"
    );
    assert_eq!(
        WitnessRetentionLimits::best_effort(2, 1, 1)
            .unwrap_err()
            .field(),
        "max_alternatives_per_quality"
    );
    if let Some(overflow) = (u32::MAX as usize).checked_add(1) {
        assert_eq!(
            WitnessRetentionLimits::best_effort(1, overflow, 1)
                .unwrap_err()
                .field(),
            "max_retained_relations"
        );
    }
}
