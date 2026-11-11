use brokk_bifrost_core::retention_budget::RetainedBytes;
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    DerivationAuthority, NotReusableCause,
};
use brokk_bifrost_store::analyzer::store::reader_binding::ReaderBinding;

/// A proved main selection retains. Unsaved buffers and stages are request-owned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AnalyzerAuthority {
    Main,
    Overlay,
    UnprovedStage,
}

impl AnalyzerAuthority {
    pub fn for_binding(binding: &ReaderBinding) -> Self {
        if binding.proves_main_selection() {
            Self::Main
        } else {
            Self::UnprovedStage
        }
    }
}

impl DerivationAuthority for AnalyzerAuthority {
    fn retention_refusal(&self) -> Option<NotReusableCause> {
        match self {
            Self::Main => None,
            Self::Overlay => Some(NotReusableCause::OverlayAuthority),
            Self::UnprovedStage => Some(NotReusableCause::UnprovedStage),
        }
    }
}

impl RetainedBytes for AnalyzerAuthority {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsaved_overlay_and_unproved_stage_refuse_retention() {
        assert_eq!(
            AnalyzerAuthority::Overlay.retention_refusal(),
            Some(NotReusableCause::OverlayAuthority)
        );
        assert_eq!(
            AnalyzerAuthority::UnprovedStage.retention_refusal(),
            Some(NotReusableCause::UnprovedStage)
        );
    }
}
