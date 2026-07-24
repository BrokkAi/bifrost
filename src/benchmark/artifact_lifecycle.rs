//! Shared evidence gates for promoting equivalent analysis artifacts.
//!
//! These types evaluate benchmark measurements only. They deliberately do not
//! infer runtime cache identity, completeness, or storage ownership: each
//! artifact domain must define those semantics before it becomes eligible for
//! a persistence experiment.

use std::{error::Error, fmt};

/// Predeclared thresholds for one equivalent-artifact persistence experiment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArtifactPromotionThresholds {
    pub minimum_hydration_speedup_percent: f64,
    pub minimum_hydration_saved_ms: f64,
    pub maximum_hydration_rss_ratio: f64,
    pub maximum_serialized_to_hydrated_bytes_ratio: f64,
    pub maximum_build_write_time_ratio: f64,
    pub maximum_build_write_overhead_ms: f64,
}

impl Default for ArtifactPromotionThresholds {
    fn default() -> Self {
        Self {
            minimum_hydration_speedup_percent: 30.0,
            minimum_hydration_saved_ms: 50.0,
            maximum_hydration_rss_ratio: 1.10,
            maximum_serialized_to_hydrated_bytes_ratio: 2.0,
            maximum_build_write_time_ratio: 1.25,
            maximum_build_write_overhead_ms: 250.0,
        }
    }
}

/// Median measurements for one dataset and one equivalent persisted artifact.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArtifactPromotionMeasurement {
    pub rebuild_ms: f64,
    pub build_write_ms: f64,
    pub hydrate_ms: f64,
    pub rebuild_peak_rss_bytes: Option<u64>,
    pub hydrate_peak_rss_bytes: Option<u64>,
    pub serialized_bytes: u64,
    pub estimated_hydrated_bytes: u64,
}

/// Result of one independently required promotion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPromotionGateStatus {
    Passed,
    Failed,
    Unavailable,
}

impl ArtifactPromotionGateStatus {
    pub const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Calculated evidence and per-gate outcomes for one dataset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArtifactPromotionEvaluation {
    pub hydration_speedup_percent: f64,
    pub hydration_saved_ms: f64,
    pub hydration_speedup: ArtifactPromotionGateStatus,
    pub hydration_absolute_saving: ArtifactPromotionGateStatus,
    pub hydration_rss: ArtifactPromotionGateStatus,
    pub serialized_size: ArtifactPromotionGateStatus,
    pub build_write_time: ArtifactPromotionGateStatus,
    pub build_write_absolute_overhead: ArtifactPromotionGateStatus,
    pub passed: bool,
}

/// Invalid benchmark input that cannot support a promotion decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPromotionInputKind {
    Threshold,
    Measurement,
}

/// A named invalid threshold or measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPromotionInputError {
    kind: ArtifactPromotionInputKind,
    field: &'static str,
    requirement: &'static str,
}

impl ArtifactPromotionInputError {
    fn threshold(field: &'static str, requirement: &'static str) -> Self {
        Self {
            kind: ArtifactPromotionInputKind::Threshold,
            field,
            requirement,
        }
    }

    fn measurement(field: &'static str, requirement: &'static str) -> Self {
        Self {
            kind: ArtifactPromotionInputKind::Measurement,
            field,
            requirement,
        }
    }

    pub const fn kind(&self) -> ArtifactPromotionInputKind {
        self.kind
    }

    pub const fn field(&self) -> &'static str {
        self.field
    }

    pub const fn requirement(&self) -> &'static str {
        self.requirement
    }
}

impl fmt::Display for ArtifactPromotionInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid artifact promotion {} `{}`: {}",
            match self.kind {
                ArtifactPromotionInputKind::Threshold => "threshold",
                ArtifactPromotionInputKind::Measurement => "measurement",
            },
            self.field,
            self.requirement
        )
    }
}

impl Error for ArtifactPromotionInputError {}

/// Evaluate all required gates for one equivalent-artifact dataset.
pub fn evaluate_artifact_promotion(
    thresholds: ArtifactPromotionThresholds,
    measurement: ArtifactPromotionMeasurement,
) -> Result<ArtifactPromotionEvaluation, ArtifactPromotionInputError> {
    validate_threshold_nonnegative(
        "minimum_hydration_speedup_percent",
        thresholds.minimum_hydration_speedup_percent,
    )?;
    validate_threshold_nonnegative(
        "minimum_hydration_saved_ms",
        thresholds.minimum_hydration_saved_ms,
    )?;
    validate_threshold_positive(
        "maximum_hydration_rss_ratio",
        thresholds.maximum_hydration_rss_ratio,
    )?;
    validate_threshold_positive(
        "maximum_serialized_to_hydrated_bytes_ratio",
        thresholds.maximum_serialized_to_hydrated_bytes_ratio,
    )?;
    validate_threshold_positive(
        "maximum_build_write_time_ratio",
        thresholds.maximum_build_write_time_ratio,
    )?;
    validate_threshold_nonnegative(
        "maximum_build_write_overhead_ms",
        thresholds.maximum_build_write_overhead_ms,
    )?;

    validate_measurement_positive("rebuild_ms", measurement.rebuild_ms)?;
    validate_measurement_nonnegative("build_write_ms", measurement.build_write_ms)?;
    validate_measurement_nonnegative("hydrate_ms", measurement.hydrate_ms)?;
    if measurement.estimated_hydrated_bytes == 0 {
        return Err(ArtifactPromotionInputError::measurement(
            "estimated_hydrated_bytes",
            "must be greater than zero",
        ));
    }
    validate_optional_rss("rebuild_peak_rss_bytes", measurement.rebuild_peak_rss_bytes)?;
    validate_optional_rss("hydrate_peak_rss_bytes", measurement.hydrate_peak_rss_bytes)?;

    let hydration_saved_ms = measurement.rebuild_ms - measurement.hydrate_ms;
    let hydration_speedup_percent = hydration_saved_ms / measurement.rebuild_ms * 100.0;
    let hydration_speedup =
        gate(hydration_speedup_percent >= thresholds.minimum_hydration_speedup_percent);
    let hydration_absolute_saving =
        gate(hydration_saved_ms >= thresholds.minimum_hydration_saved_ms);
    let hydration_rss = match (
        measurement.rebuild_peak_rss_bytes,
        measurement.hydrate_peak_rss_bytes,
    ) {
        (Some(rebuild), Some(hydrate)) => {
            gate(hydrate as f64 / rebuild as f64 <= thresholds.maximum_hydration_rss_ratio)
        }
        _ => ArtifactPromotionGateStatus::Unavailable,
    };
    let serialized_size = gate(
        measurement.serialized_bytes as f64 / measurement.estimated_hydrated_bytes as f64
            <= thresholds.maximum_serialized_to_hydrated_bytes_ratio,
    );
    let build_write_time = gate(
        measurement.build_write_ms / measurement.rebuild_ms
            <= thresholds.maximum_build_write_time_ratio,
    );
    let build_write_absolute_overhead = gate(
        measurement.build_write_ms - measurement.rebuild_ms
            <= thresholds.maximum_build_write_overhead_ms,
    );
    let statuses = [
        hydration_speedup,
        hydration_absolute_saving,
        hydration_rss,
        serialized_size,
        build_write_time,
        build_write_absolute_overhead,
    ];

    Ok(ArtifactPromotionEvaluation {
        hydration_speedup_percent,
        hydration_saved_ms,
        hydration_speedup,
        hydration_absolute_saving,
        hydration_rss,
        serialized_size,
        build_write_time,
        build_write_absolute_overhead,
        passed: statuses
            .into_iter()
            .all(ArtifactPromotionGateStatus::passed),
    })
}

const fn gate(passed: bool) -> ArtifactPromotionGateStatus {
    if passed {
        ArtifactPromotionGateStatus::Passed
    } else {
        ArtifactPromotionGateStatus::Failed
    }
}

fn validate_threshold_nonnegative(
    field: &'static str,
    value: f64,
) -> Result<(), ArtifactPromotionInputError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(ArtifactPromotionInputError::threshold(
            field,
            "must be finite and nonnegative",
        ))
    }
}

fn validate_threshold_positive(
    field: &'static str,
    value: f64,
) -> Result<(), ArtifactPromotionInputError> {
    if value.is_finite() && value > 0.0 {
        Ok(())
    } else {
        Err(ArtifactPromotionInputError::threshold(
            field,
            "must be finite and greater than zero",
        ))
    }
}

fn validate_measurement_nonnegative(
    field: &'static str,
    value: f64,
) -> Result<(), ArtifactPromotionInputError> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(ArtifactPromotionInputError::measurement(
            field,
            "must be finite and nonnegative",
        ))
    }
}

fn validate_measurement_positive(
    field: &'static str,
    value: f64,
) -> Result<(), ArtifactPromotionInputError> {
    if value.is_finite() && value > 0.0 {
        Ok(())
    } else {
        Err(ArtifactPromotionInputError::measurement(
            field,
            "must be finite and greater than zero",
        ))
    }
}

fn validate_optional_rss(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ArtifactPromotionInputError> {
    if value == Some(0) {
        Err(ArtifactPromotionInputError::measurement(
            field,
            "must be greater than zero when present",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary_measurement() -> ArtifactPromotionMeasurement {
        ArtifactPromotionMeasurement {
            rebuild_ms: 1_000.0,
            build_write_ms: 1_250.0,
            hydrate_ms: 700.0,
            rebuild_peak_rss_bytes: Some(1_000),
            hydrate_peak_rss_bytes: Some(1_100),
            serialized_bytes: 2_000,
            estimated_hydrated_bytes: 1_000,
        }
    }

    #[test]
    fn exact_default_boundaries_pass() {
        let evaluation = evaluate_artifact_promotion(
            ArtifactPromotionThresholds::default(),
            boundary_measurement(),
        )
        .unwrap();

        assert_eq!(evaluation.hydration_speedup_percent, 30.0);
        assert_eq!(evaluation.hydration_saved_ms, 300.0);
        assert!(evaluation.passed);
    }

    #[test]
    fn every_gate_is_required() {
        let defaults = ArtifactPromotionThresholds::default();
        let cases = [
            ArtifactPromotionMeasurement {
                hydrate_ms: 700.1,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                rebuild_ms: 100.0,
                build_write_ms: 100.0,
                hydrate_ms: 60.0,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                hydrate_peak_rss_bytes: Some(1_101),
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                serialized_bytes: 2_001,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                build_write_ms: 1_250.1,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                rebuild_ms: 2_000.0,
                build_write_ms: 2_250.1,
                hydrate_ms: 1_000.0,
                ..boundary_measurement()
            },
        ];

        for measurement in cases {
            assert!(
                !evaluate_artifact_promotion(defaults, measurement)
                    .unwrap()
                    .passed
            );
        }
    }

    #[test]
    fn missing_rss_is_unavailable_and_cannot_pass() {
        let evaluation = evaluate_artifact_promotion(
            ArtifactPromotionThresholds::default(),
            ArtifactPromotionMeasurement {
                rebuild_peak_rss_bytes: None,
                hydrate_peak_rss_bytes: None,
                ..boundary_measurement()
            },
        )
        .unwrap();

        assert_eq!(
            evaluation.hydration_rss,
            ArtifactPromotionGateStatus::Unavailable
        );
        assert!(!evaluation.passed);
    }

    #[test]
    fn invalid_thresholds_and_measurements_are_rejected() {
        let invalid_threshold = evaluate_artifact_promotion(
            ArtifactPromotionThresholds {
                maximum_hydration_rss_ratio: f64::NAN,
                ..ArtifactPromotionThresholds::default()
            },
            boundary_measurement(),
        )
        .unwrap_err();
        assert_eq!(
            invalid_threshold.kind(),
            ArtifactPromotionInputKind::Threshold
        );
        assert_eq!(invalid_threshold.field(), "maximum_hydration_rss_ratio");

        for measurement in [
            ArtifactPromotionMeasurement {
                rebuild_ms: 0.0,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                hydrate_ms: f64::INFINITY,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                estimated_hydrated_bytes: 0,
                ..boundary_measurement()
            },
            ArtifactPromotionMeasurement {
                rebuild_peak_rss_bytes: Some(0),
                ..boundary_measurement()
            },
        ] {
            assert_eq!(
                evaluate_artifact_promotion(ArtifactPromotionThresholds::default(), measurement)
                    .unwrap_err()
                    .kind(),
                ArtifactPromotionInputKind::Measurement
            );
        }
    }

    #[test]
    fn large_byte_values_do_not_overflow() {
        let evaluation = evaluate_artifact_promotion(
            ArtifactPromotionThresholds::default(),
            ArtifactPromotionMeasurement {
                serialized_bytes: u64::MAX,
                estimated_hydrated_bytes: u64::MAX / 2,
                ..boundary_measurement()
            },
        )
        .unwrap();

        assert_eq!(
            evaluation.serialized_size,
            ArtifactPromotionGateStatus::Failed
        );
    }
}
