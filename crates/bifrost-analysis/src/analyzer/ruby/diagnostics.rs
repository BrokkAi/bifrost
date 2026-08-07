//! Ruby's semantic diagnostics: the downcast that produces the arguments, and
//! the retained gem surface behind [`RubyGemSurface`].
//!
//! The pass itself is [`brokk_bifrost_ruby::diagnostics`]. Unlike Go's,
//! Python's and PHP's it routes through the *graph* semantic index rather than a
//! `BoundedDefinitionLookup`, so it moved with `graph::resolver` and takes the
//! same `RubyGraphSource` the scans do. What stays here is what that crate
//! cannot name: the activated semantic-model overlay and the retained
//! gem-discovery evidence.
//!
//! Both are read from the *dispatching* analyzer, because a host activates packs
//! against the composite analyzer in a workspace, not against the Ruby delegate.

use std::sync::Arc;

use crate::analyzer::ruby::constant_identity::RubyOverlayConstants;
use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, RetainedDiscoveryVerdict, SemanticModelOverlay,
    retained_discovery_verdict,
};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::usages::ruby_graph::with_ruby_graph_source;
use crate::analyzer::{
    IAnalyzer, Language, ProjectFile, RubyAnalyzer, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_ruby::diagnostics::{RubyGemBoundary, RubyGemSurface};

pub(crate) fn collect_ruby_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "no Ruby analyzer serves this file".to_string(),
            }],
        );
        return report;
    };
    // Both reads are of state a host already published. Neither starts
    // dependency discovery nor touches a gem archive.
    let gems = RetainedRubyGems {
        overlay: analyzer.semantic_model_overlay(),
        evidence: analyzer.dependency_discovery_evidence(Language::Ruby),
    };
    with_ruby_graph_source(analyzer, |graph| {
        brokk_bifrost_ruby::diagnostics::collect_ruby_semantic_diagnostics(
            graph, ruby, &gems, file, source,
        )
    })
}

/// The gem facts a diagnostic request is allowed to read: what an activation
/// published, and what a discovery run retained. Both are analyzer state a host
/// produced earlier. Nothing here runs Bundler, reads a `.gem`, or walks a gem
/// directory.
struct RetainedRubyGems {
    overlay: Option<Arc<SemanticModelOverlay>>,
    evidence: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl RetainedRubyGems {
    fn constants(&self) -> RubyOverlayConstants<'_> {
        RubyOverlayConstants::new(self.overlay.as_deref())
    }

    /// How far retained discovery could see for a name no activated pack
    /// publishes.
    fn missing_evidence(&self, name: &str) -> SemanticDiagnosticIncompleteReason {
        match retained_discovery_verdict(self.evidence.as_deref(), name) {
            RetainedDiscoveryVerdict::NoDiscovery | RetainedDiscoveryVerdict::Undeclared => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                }
            }
            RetainedDiscoveryVerdict::Truncated => SemanticDiagnosticIncompleteReason::Truncated,
            RetainedDiscoveryVerdict::Declared => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                }
            }
        }
    }
}

impl RubyGemSurface for RetainedRubyGems {
    fn constant_boundary(&self, owner_path: &[String], terminal: &str) -> RubyGemBoundary {
        debug_assert!(
            !owner_path.is_empty(),
            "a constant path's owner always has at least one segment"
        );
        let constants = self.constants();
        let owner_name = owner_path.join("::");
        // The whole path first: a nested type an activated pack publishes
        // settles the question without any completeness argument.
        if constants.publishes_type(&format!("{owner_name}::{terminal}")) {
            return RubyGemBoundary::Indexed;
        }
        if constants.conflicts(&owner_name) {
            return RubyGemBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: format!("more than one activated gem pack declares `{owner_name}`"),
                },
            );
        }
        let Some(owner) = constants.unique_type(&owner_name) else {
            return RubyGemBoundary::Unpublished(self.missing_evidence(&owner_name));
        };
        let surface = constants.constant_surface(owner);
        if surface
            .searched
            .iter()
            .any(|symbol| constants.publishes_under(symbol, terminal))
        {
            return RubyGemBoundary::Indexed;
        }
        // The owner is published, so the packs do own this namespace. Whether
        // they can prove a name missing from it is what the walk decided.
        match surface.open {
            Some(detail) => RubyGemBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail },
            ),
            None => RubyGemBoundary::Absent(RubyOverlayConstants::absence_domain(owner)),
        }
    }

    fn require_boundary(&self, require_path: &str) -> RubyGemBoundary {
        let Some(evidence) = self.evidence.as_deref() else {
            return RubyGemBoundary::Unpublished(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
            );
        };
        if evidence.truncated() {
            return RubyGemBoundary::Incomplete(SemanticDiagnosticIncompleteReason::Truncated);
        }
        if !evidence.declares_ruby_require_path(require_path) {
            return RubyGemBoundary::Unpublished(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
            );
        }
        // Discovery evidence is retained only after every gem it resolved was
        // prepared and activated (see `WorkspaceAnalyzer::activate_dependency_packs`),
        // so a declared gem with a published overlay is an indexed gem. A
        // declared gem with no overlay is the one that discovery reached and
        // activation did not.
        if self.overlay.is_none() {
            return RubyGemBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                },
            );
        }
        RubyGemBoundary::Indexed
    }
}

#[cfg(test)]
mod tests {
    use super::RetainedRubyGems;
    use crate::analyzer::SemanticDiagnosticIncompleteReason;
    use crate::analyzer::semantic_model::{
        CatalogCoordinate, DependencyDiscoveryEvidence, DependencyDiscoveryOutcome,
        ResolvedDependency, SemanticModelActivationEvidence,
    };
    use crate::analyzer::structural::BoundaryStatus;
    use brokk_bifrost_ruby::diagnostics::{RubyGemBoundary, RubyGemSurface};
    use std::sync::Arc;

    fn evidence(gems: &[&str], complete: bool) -> DependencyDiscoveryEvidence {
        let dependencies = gems
            .iter()
            .map(|gem| ResolvedDependency {
                id: format!("rubygems:{gem}"),
                evidence: SemanticModelActivationEvidence {
                    language: "ruby".to_owned(),
                    ecosystem: "rubygems".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: (*gem).to_owned(),
                        version: None,
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                provenance: Vec::new(),
                artifacts: Vec::new(),
            })
            .collect();
        let mut outcome = DependencyDiscoveryOutcome::complete(dependencies);
        outcome.complete = complete;
        DependencyDiscoveryEvidence::from_outcome(&outcome)
    }

    fn gems(evidence: Option<DependencyDiscoveryEvidence>) -> RetainedRubyGems {
        RetainedRubyGems {
            overlay: None,
            evidence: evidence.map(Arc::new),
        }
    }

    #[test]
    fn ruby_require_boundary_reports_a_declared_gem_nothing_indexed() {
        // Discovery reached the lockfile and named the gem; no activation
        // published an overlay. That is exactly `ExternalDeclaredUnindexed`,
        // and it is the one state the workspace activation path can leave
        // behind, because evidence is retained only after preparation succeeds.
        assert_eq!(
            RubyGemBoundary::Incomplete(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed
                }
            ),
            gems(Some(evidence(&["widget"], true))).require_boundary("widget")
        );
    }

    #[test]
    fn ruby_require_boundary_walks_a_gem_load_path_by_segment() {
        let surface = gems(Some(evidence(&["widget"], true)));
        // `widget/core` is published by the `widget` gem.
        assert!(matches!(
            surface.require_boundary("widget/core"),
            RubyGemBoundary::Incomplete(_)
        ));
        // Segment removal, not string prefixing: `widgetfork` is not `widget`.
        assert!(matches!(
            surface.require_boundary("widgetfork"),
            RubyGemBoundary::Unpublished(_)
        ));
    }

    #[test]
    fn ruby_require_boundary_separates_no_discovery_from_truncated() {
        assert_eq!(
            RubyGemBoundary::Unpublished(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown
                }
            ),
            gems(None).require_boundary("widget")
        );
        assert_eq!(
            RubyGemBoundary::Incomplete(SemanticDiagnosticIncompleteReason::Truncated),
            gems(Some(evidence(&["widget"], false))).require_boundary("widget")
        );
    }

    #[test]
    fn ruby_constant_boundary_without_an_overlay_publishes_nothing() {
        // No pack owns the namespace, so the packs say nothing either way and
        // the caller's own workspace surface stays free to prove absence.
        assert_eq!(
            RubyGemBoundary::Unpublished(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown
                }
            ),
            gems(Some(evidence(&["widget"], true)))
                .constant_boundary(&["Widget".to_owned()], "Config")
        );
    }
}
