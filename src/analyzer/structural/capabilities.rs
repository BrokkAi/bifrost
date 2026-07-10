//! Query feature requirements and capability diagnostics.
//!
//! `CodeQuery` remains the semantic matcher input. This module is the narrower
//! planning surface for asking whether a language adapter can evaluate the
//! kinds and roles a query references, and for turning unsupported features
//! into stable diagnostics.

use super::kinds::{NormalizedKind, Role};
use super::query::CodeQuery;
use crate::analyzer::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum QueryFeature {
    Kind(NormalizedKind),
    Role(Role),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QueryFeatures {
    features: Vec<QueryFeature>,
}

impl QueryFeatures {
    pub(crate) fn for_query(query: &CodeQuery) -> Self {
        let features = query
            .referenced_kinds()
            .into_iter()
            .map(QueryFeature::Kind)
            .chain(query.used_roles().into_iter().map(QueryFeature::Role));
        Self::new(features)
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
            }
        }
        unsupported
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnsupportedQueryFeatures {
    kinds: Vec<NormalizedKind>,
    roles: Vec<Role>,
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnsupportedFeatureGroup {
    Kinds(Vec<NormalizedKind>),
    Roles(Vec<Role>),
}

fn labels(labels: impl Iterator<Item = &'static str>) -> String {
    labels.collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let unsupported = QueryFeatures::for_query(&query).unsupported_by(|feature| {
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
}
