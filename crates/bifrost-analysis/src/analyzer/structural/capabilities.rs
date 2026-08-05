//! Query feature requirements and capability diagnostics.
//!
//! `CodeQuery` remains the semantic matcher input. This module is the narrower
//! planning surface for asking whether a language adapter can evaluate the
//! kinds and roles a query references, and for turning unsupported features
//! into stable diagnostics.

use super::edges::EdgeAxis;
use super::kinds::{NormalizedKind, Role};
use super::occurrences::OccurrenceRole;
use super::query::{CodeQuerySeed, OccurrenceFilter};
use super::resolution::EnvironmentAxis;
use crate::analyzer::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum QueryFeature {
    Kind(NormalizedKind),
    Role(Role),
    /// Produced by [`QueryFeatures::for_occurrence_filter`]: the occurrence
    /// roles a query's `:class`/`:role` filter depends on being classified.
    OccurrenceRole(OccurrenceRole),
    /// The lexical-environment axes an environment or candidate query depends
    /// on an adapter answering (issue #1474).
    ///
    /// The query surface that produces these arrives with the `scopes`,
    /// `bindings`, `reaching-binding` and `candidates-of` steps; the variant
    /// exists now so the environment support tables the adapters already
    /// declare have exactly one route to a diagnostic, and so the derivation
    /// layer built next has the message to report against. This mirrors how
    /// `OccurrenceRole` was parked between its registry and its query surface.
    #[allow(dead_code)]
    EnvironmentAxis(EnvironmentAxis),
    /// The reference-edge axes an edge query or parity assertion depends on an
    /// adapter answering (issue #1479).
    ///
    /// The query surface that produces these arrives with the edge seeds and
    /// steps; the variant exists now so the edge support tables the adapters
    /// already declare have exactly one route to a diagnostic, and so the
    /// derivation layer built next has the message to report against. This is
    /// the same parking `EnvironmentAxis` had between its registry and its
    /// query surface.
    #[allow(dead_code)]
    EdgeAxis(EdgeAxis),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QueryFeatures {
    features: Vec<QueryFeature>,
}

impl QueryFeatures {
    pub(crate) fn for_query(query: &CodeQuerySeed) -> Self {
        let features = query
            .referenced_kinds()
            .into_iter()
            .map(QueryFeature::Kind)
            .chain(query.used_roles().into_iter().map(QueryFeature::Role));
        Self::new(features)
    }

    /// The occurrence roles an occurrence query depends on.
    ///
    /// An unconstrained filter depends on every role, so an adapter that
    /// classifies none of them makes the whole answer untrustworthy rather
    /// than merely incomplete for one role.
    pub(crate) fn for_occurrence_filter(filter: &OccurrenceFilter) -> Self {
        Self::new(
            filter
                .required_roles()
                .into_iter()
                .map(QueryFeature::OccurrenceRole),
        )
    }

    fn new(features: impl IntoIterator<Item = QueryFeature>) -> Self {
        let mut features = features.into_iter().collect::<Vec<_>>();
        features.sort_unstable();
        features.dedup();
        Self { features }
    }

    pub(crate) fn unsupported_by(
        &self,
        mut supports: impl FnMut(QueryFeature) -> bool,
    ) -> UnsupportedQueryFeatures {
        let mut unsupported = UnsupportedQueryFeatures::default();
        for &feature in &self.features {
            if supports(feature) {
                continue;
            }
            match feature {
                QueryFeature::Kind(kind) => unsupported.kinds.push(kind),
                QueryFeature::Role(role) => unsupported.roles.push(role),
                QueryFeature::OccurrenceRole(role) => unsupported.occurrence_roles.push(role),
                QueryFeature::EnvironmentAxis(axis) => unsupported.environment_axes.push(axis),
                QueryFeature::EdgeAxis(axis) => unsupported.edge_axes.push(axis),
            }
        }
        unsupported
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnsupportedQueryFeatures {
    kinds: Vec<NormalizedKind>,
    roles: Vec<Role>,
    occurrence_roles: Vec<OccurrenceRole>,
    environment_axes: Vec<EnvironmentAxis>,
    edge_axes: Vec<EdgeAxis>,
}

impl UnsupportedQueryFeatures {
    pub(crate) fn into_diagnostics(self, language: Language) -> Vec<QueryCapabilityDiagnostic> {
        let mut diagnostics = Vec::new();
        if !self.kinds.is_empty() {
            diagnostics.push(QueryCapabilityDiagnostic {
                language,
                unsupported: UnsupportedFeatureGroup::Kinds(self.kinds),
            });
        }
        if !self.roles.is_empty() {
            diagnostics.push(QueryCapabilityDiagnostic {
                language,
                unsupported: UnsupportedFeatureGroup::Roles(self.roles),
            });
        }
        if !self.occurrence_roles.is_empty() {
            diagnostics.push(QueryCapabilityDiagnostic {
                language,
                unsupported: UnsupportedFeatureGroup::OccurrenceRoles(self.occurrence_roles),
            });
        }
        if !self.environment_axes.is_empty() {
            diagnostics.push(QueryCapabilityDiagnostic {
                language,
                unsupported: UnsupportedFeatureGroup::EnvironmentAxes(self.environment_axes),
            });
        }
        if !self.edge_axes.is_empty() {
            diagnostics.push(QueryCapabilityDiagnostic {
                language,
                unsupported: UnsupportedFeatureGroup::EdgeAxes(self.edge_axes),
            });
        }
        diagnostics
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueryCapabilityDiagnostic {
    language: Language,
    unsupported: UnsupportedFeatureGroup,
}

impl QueryCapabilityDiagnostic {
    pub(crate) fn language(&self) -> Language {
        self.language
    }

    pub(crate) fn message(&self) -> String {
        match &self.unsupported {
            UnsupportedFeatureGroup::Kinds(kinds) => format!(
                "structural adapter for {} does not support kind(s): {}",
                self.language.config_label(),
                labels(kinds.iter().copied().map(NormalizedKind::label))
            ),
            UnsupportedFeatureGroup::Roles(roles) => format!(
                "structural adapter for {} does not support role(s): {}",
                self.language.config_label(),
                labels(roles.iter().copied().map(Role::label))
            ),
            UnsupportedFeatureGroup::OccurrenceRoles(roles) => format!(
                "structural adapter for {} does not support occurrence role(s): {}",
                self.language.config_label(),
                labels(roles.iter().copied().map(OccurrenceRole::label))
            ),
            UnsupportedFeatureGroup::EnvironmentAxes(axes) => format!(
                "structural adapter for {} does not support lexical environment axis(es): {}",
                self.language.config_label(),
                labels(axes.iter().copied().map(EnvironmentAxis::label))
            ),
            UnsupportedFeatureGroup::EdgeAxes(axes) => format!(
                "structural adapter for {} does not support reference-edge axis(es): {}",
                self.language.config_label(),
                labels(axes.iter().copied().map(EdgeAxis::label))
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnsupportedFeatureGroup {
    Kinds(Vec<NormalizedKind>),
    Roles(Vec<Role>),
    OccurrenceRoles(Vec<OccurrenceRole>),
    EnvironmentAxes(Vec<EnvironmentAxis>),
    EdgeAxes(Vec<EdgeAxis>),
}

fn labels(labels: impl Iterator<Item = &'static str>) -> String {
    labels.collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use serde_json::json;

    #[test]
    fn query_features_are_grouped_and_sorted() {
        let query = CodeQuery::from_json(&json!({
            "match": {
                "kind": "call",
                "callee": { "name": "eval" },
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            },
            "not_inside": { "kind": "class" }
        }))
        .expect("query should parse");

        let unsupported =
            QueryFeatures::for_query(query.seed().unwrap()).unsupported_by(|feature| {
                !matches!(
                    feature,
                    QueryFeature::Kind(NormalizedKind::BooleanLiteral)
                        | QueryFeature::Role(Role::Kwarg)
                )
            });
        let diagnostics = unsupported.into_diagnostics(Language::Python);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].message(),
            "structural adapter for python does not support kind(s): boolean_literal"
        );
        assert_eq!(
            diagnostics[1].message(),
            "structural adapter for python does not support role(s): kwargs"
        );
    }

    /// An occurrence role an adapter has not declared must reach the same
    /// `Incomplete` diagnostic spine kinds and roles already use (#1473), so a
    /// query depending on it is never silently answered from zero rows.
    #[test]
    fn unsupported_occurrence_roles_become_their_own_diagnostic_group() {
        let features = QueryFeatures::new([
            QueryFeature::OccurrenceRole(OccurrenceRole::Binder),
            QueryFeature::OccurrenceRole(OccurrenceRole::DeclarationName),
            QueryFeature::Kind(NormalizedKind::Class),
        ]);
        let diagnostics = features
            .unsupported_by(|feature| matches!(feature, QueryFeature::Kind(_)))
            .into_diagnostics(Language::Scala);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message(),
            "structural adapter for scala does not support occurrence role(s): declaration_name, binder"
        );
    }

    /// An adapter that declares no lexical environment must reach the same
    /// `Incomplete` diagnostic spine (#1474), and each unsupported family stays
    /// its own group so a caller can tell "cannot classify this token" from
    /// "cannot state this file's scopes".
    #[test]
    fn unsupported_environment_axes_become_their_own_diagnostic_group() {
        let features = QueryFeatures::new([
            QueryFeature::EnvironmentAxis(EnvironmentAxis::Scopes),
            QueryFeature::EnvironmentAxis(EnvironmentAxis::CandidateRejection),
            QueryFeature::OccurrenceRole(OccurrenceRole::Binder),
        ]);
        let diagnostics = features
            .unsupported_by(|_| false)
            .into_diagnostics(Language::Scala);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].message(),
            "structural adapter for scala does not support occurrence role(s): binder"
        );
        assert_eq!(
            diagnostics[1].message(),
            "structural adapter for scala does not support lexical environment axis(es): scopes, candidate_rejection"
        );
    }

    /// An adapter that declares no edge axes must reach the same `Incomplete`
    /// diagnostic spine (#1479), and the family stays its own group so a
    /// caller can tell "cannot state this file's environment" from "cannot
    /// project reference edges".
    #[test]
    fn unsupported_edge_axes_become_their_own_diagnostic_group() {
        let features = QueryFeatures::new([
            QueryFeature::EdgeAxis(EdgeAxis::ForwardProjection),
            QueryFeature::EdgeAxis(EdgeAxis::OwnerClassification),
            QueryFeature::EnvironmentAxis(EnvironmentAxis::Scopes),
        ]);
        let diagnostics = features
            .unsupported_by(|_| false)
            .into_diagnostics(Language::Kotlin);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].message(),
            "structural adapter for kotlin does not support lexical environment axis(es): scopes"
        );
        assert_eq!(
            diagnostics[1].message(),
            "structural adapter for kotlin does not support reference-edge axis(es): forward_projection, owner_classification"
        );
    }
}
