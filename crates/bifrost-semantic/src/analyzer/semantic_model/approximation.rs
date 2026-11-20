//! Typed reasons a model shard was selected without exact activation evidence.
//!
//! Discovery is the only producer of a reason. A shard carries a non-empty set,
//! so "approximate" and "why" cannot disagree: the activation bit everyone reads
//! is `Option<ApproximationReasons>::is_some()`.

use std::num::NonZeroU8;

/// One way an activation fell short of exact toolchain evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApproximationReason {
    /// The target the standard library was built for is unknown.
    TargetUnknown,
    /// The toolchain version was not observed: unpinned, a declared floor, or an
    /// assumed toolchain.
    ToolchainVersionUnknown,
    /// The standard library may be rebuilt (`-Zbuild-std`) or its build mode is
    /// unknown, so its declarations may differ from the prebuilt one.
    StdlibBuildUnverified,
    /// A dependency artifact was matched to a close package version.
    DependencyVersionApproximate,
}

impl ApproximationReason {
    const fn bit(self) -> u8 {
        match self {
            Self::TargetUnknown => 1,
            Self::ToolchainVersionUnknown => 2,
            Self::StdlibBuildUnverified => 4,
            Self::DependencyVersionApproximate => 8,
        }
    }

    const ALL: [Self; 4] = [
        Self::TargetUnknown,
        Self::ToolchainVersionUnknown,
        Self::StdlibBuildUnverified,
        Self::DependencyVersionApproximate,
    ];
}

/// A non-empty set of [`ApproximationReason`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApproximationReasons(NonZeroU8);

impl ApproximationReasons {
    pub const fn only(reason: ApproximationReason) -> Self {
        match NonZeroU8::new(reason.bit()) {
            Some(bits) => Self(bits),
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn with(self, reason: ApproximationReason) -> Self {
        match NonZeroU8::new(self.0.get() | reason.bit()) {
            Some(bits) => Self(bits),
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        match NonZeroU8::new(self.0.get() | other.0.get()) {
            Some(bits) => Self(bits),
            None => unreachable!(),
        }
    }

    pub const fn contains(self, reason: ApproximationReason) -> bool {
        self.0.get() & reason.bit() != 0
    }

    /// Every reason is [`ApproximationReason::TargetUnknown`]. The only
    /// predicate under which an authored target-independent family claim
    /// survives an approximate activation.
    pub const fn target_unknown_only(self) -> bool {
        self.0.get() == ApproximationReason::TargetUnknown.bit()
    }

    pub fn iter(self) -> impl Iterator<Item = ApproximationReason> {
        ApproximationReason::ALL
            .into_iter()
            .filter(move |reason| self.contains(*reason))
    }

    /// Stable bytes for identity hashes.
    pub const fn bits(self) -> u8 {
        self.0.get()
    }
}

impl From<ApproximationReason> for ApproximationReasons {
    fn from(reason: ApproximationReason) -> Self {
        Self::only(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_target_unknown_is_target_unknown_only() {
        use ApproximationReason::*;
        assert!(ApproximationReasons::only(TargetUnknown).target_unknown_only());
        for other in [
            ToolchainVersionUnknown,
            StdlibBuildUnverified,
            DependencyVersionApproximate,
        ] {
            assert!(!ApproximationReasons::only(other).target_unknown_only());
            assert!(
                !ApproximationReasons::only(TargetUnknown)
                    .with(other)
                    .target_unknown_only()
            );
        }
        assert_eq!(
            ApproximationReasons::only(TargetUnknown)
                .with(ToolchainVersionUnknown)
                .iter()
                .collect::<Vec<_>>(),
            vec![TargetUnknown, ToolchainVersionUnknown]
        );
    }
}
