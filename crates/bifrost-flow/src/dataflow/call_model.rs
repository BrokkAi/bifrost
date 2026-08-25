use std::fmt;

/// Fallback transfer semantics for a call arm without an executable body or
/// applicable semantic model.
///
/// This choice does not control whether the ICFG reaches the call's normal or
/// exceptional continuation. It only controls which analysis facts cross the
/// resulting boundary edge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnmodeledCallBehavior {
    /// Conservatively add every transfer supported by the currently available
    /// structured call-site metadata.
    #[default]
    Paranoid,
    /// Preserve existing facts without introducing flows through the unseen
    /// body. The retained boundary still makes the result incomplete.
    Optimistic,
    /// Mark the unmodeled transfer as an abstention. Clients must not turn the
    /// missing model into a complete negative result.
    RequireModel,
}

impl UnmodeledCallBehavior {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Paranoid => "paranoid",
            Self::Optimistic => "optimistic",
            Self::RequireModel => "require-model",
        }
    }
}

impl fmt::Display for UnmodeledCallBehavior {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paranoid_is_the_stable_default() {
        assert_eq!(
            UnmodeledCallBehavior::default(),
            UnmodeledCallBehavior::Paranoid
        );
        assert_eq!(UnmodeledCallBehavior::Paranoid.label(), "paranoid");
        assert_eq!(UnmodeledCallBehavior::Optimistic.label(), "optimistic");
        assert_eq!(UnmodeledCallBehavior::RequireModel.label(), "require-model");
    }
}
