#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;

    use brokk_bifrost_analysis::analyzer::read_verification::analysis_epoch_digest;

    use brokk_bifrost_analysis::analyzer::read_verification::analysis_epoch_digest_with_authority;

    use brokk_bifrost_test_macros::hardwon;
    /// The engine epoch a recorded read set carries must move when a language's
    /// graph authority flips.
    ///
    /// `LookupKind::Usages`, `Callers` and `Callees` replay through whichever
    /// implementation the registry routes the language to, so a unit recorded
    /// against the legacy Rust resolver carries answer digests this engine no
    /// longer derives. Nothing detects that on its own: the recorded digests
    /// simply disagree one lookup at a time, at replay cost, and a unit whose
    /// Rust reads happened to agree is reused across two different engines.
    /// Folding the authority into the epoch is what retires the whole
    /// generation up front instead.
    #[test]
    #[hardwon(
        "9acc891b89ad: native routing authority changes left the analysis epoch and cached answers stale"
    )]
    fn the_analysis_epoch_moves_when_a_language_changes_graph_authority() {
        let production = brokk_bifrost_analysis::analyzer::languages::graph_authority_digest();
        assert_eq!(
            analysis_epoch_digest(),
            analysis_epoch_digest_with_authority(production),
            "the production epoch is the epoch of the production authority"
        );
        assert_ne!(
            analysis_epoch_digest(),
            analysis_epoch_digest_with_authority(StableDigest::sha256(b"another-authority")),
            "two routings of the same grammars are two engines"
        );
    }
}
