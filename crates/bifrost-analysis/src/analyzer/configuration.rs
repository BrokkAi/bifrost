//! Maintained-parser ingestion for authored configuration documents.

use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationCompleteness, ConfigurationDocumentFacts, ConfigurationFact, ConfigurationFactId,
    ConfigurationFeatureSemantics, ConfigurationFormat, ConfigurationKey, ConfigurationMemberRole,
    ConfigurationModelError, ConfigurationNodeKind, ConfigurationPathClassification,
    ConfigurationRecovery, ConfigurationRecoveryReason, ConfigurationRoute,
    ConfigurationRouteSegment, ConfigurationScalarKind, ConfigurationSourceRange,
    classify_configuration_path,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use tree_sitter::{Language, Node, Parser};

const JSON_ADAPTER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationIngestionOutcome {
    Facts(ConfigurationDocumentFacts),
    Unsupported { format: Option<ConfigurationFormat> },
    Incomplete { reason: ConfigurationIngestionError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationIngestionError {
    InvalidUtf8,
    ParserUnavailable(String),
    InvalidFactModel(String),
}

impl fmt::Display for ConfigurationIngestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("configuration document is not valid UTF-8"),
            Self::ParserUnavailable(message) | Self::InvalidFactModel(message) => {
                formatter.write_str(message)
            }
        }
    }
}

pub fn ingest_configuration_document(path: &Path, bytes: &[u8]) -> ConfigurationIngestionOutcome {
    let format = match classify_configuration_path(path) {
        ConfigurationPathClassification::Supported(format) => format,
        ConfigurationPathClassification::Unsupported => {
            return ConfigurationIngestionOutcome::Unsupported { format: None };
        }
    };
    if format != ConfigurationFormat::Json {
        return ConfigurationIngestionOutcome::Unsupported {
            format: Some(format),
        };
    }
    let Ok(source) = std::str::from_utf8(bytes) else {
        return ConfigurationIngestionOutcome::Incomplete {
            reason: ConfigurationIngestionError::InvalidUtf8,
        };
    };
    match ingest_json(source) {
        Ok(facts) => ConfigurationIngestionOutcome::Facts(facts),
        Err(error) => ConfigurationIngestionOutcome::Incomplete { reason: error },
    }
}

/// Cache compatibility identity for the JSON adapter and its live grammar.
pub fn json_configuration_adapter_epoch() -> String {
    let language: Language = tree_sitter_json::LANGUAGE.into();
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost-configuration-json-adapter\n");
    hasher.update(JSON_ADAPTER_SCHEMA_VERSION.to_le_bytes());
    hasher.update(language.abi_version().to_le_bytes());
    for id in 0..language.node_kind_count() {
        if let Some(name) = language.node_kind_for_id(id as u16) {
            hasher.update(name.as_bytes());
        }
        hasher.update([language.node_kind_is_named(id as u16) as u8, 0]);
    }
    for id in 1..=language.field_count() {
        if let Some(name) = language.field_name_for_id(id as u16) {
            hasher.update(name.as_bytes());
        }
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Debug)]
struct PendingFact {
    parent: Option<usize>,
    route: ConfigurationRoute,
    range: ConfigurationSourceRange,
    kind: PendingKind,
}

#[derive(Debug)]
enum PendingKind {
    Document(Option<usize>),
    Object(Vec<usize>),
    Sequence(Vec<usize>),
    Member {
        key: ConfigurationKey,
        value: Option<usize>,
    },
    Scalar(ConfigurationScalarKind),
}

#[derive(Clone, Copy)]
enum Link {
    DocumentRoot,
    ObjectMember,
    SequenceItem,
    MemberValue,
}

struct Work<'tree> {
    node: Node<'tree>,
    parent: usize,
    link: Link,
    route: ConfigurationRoute,
}

fn ingest_json(source: &str) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let language: Language = tree_sitter_json::LANGUAGE.into();
    let mut parser = Parser::new();
    parser.set_language(&language).map_err(|error| {
        ConfigurationIngestionError::ParserUnavailable(format!(
            "failed to load JSON grammar: {error}"
        ))
    })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        ConfigurationIngestionError::ParserUnavailable("JSON parser did not return a tree".into())
    })?;
    let root = tree.root_node();
    let document_range = source_range(root)?;
    let mut pending = vec![PendingFact {
        parent: None,
        route: ConfigurationRoute::root(),
        range: document_range,
        kind: PendingKind::Document(None),
    }];
    let mut recoveries = collect_recoveries(root)?;
    if let Some(value) = first_named_child(root) {
        let mut stack = vec![Work {
            node: value,
            parent: 0,
            link: Link::DocumentRoot,
            route: ConfigurationRoute::root(),
        }];
        while let Some(work) = stack.pop() {
            add_node(source, work, &mut pending, &mut stack, &mut recoveries)?;
        }
    }
    let facts = finalize(pending)?;
    let completeness = if recoveries.is_empty() {
        ConfigurationCompleteness::Complete
    } else {
        ConfigurationCompleteness::Incomplete { recoveries }
    };
    ConfigurationDocumentFacts::new(
        ConfigurationFormat::Json,
        facts,
        completeness,
        ConfigurationFeatureSemantics::not_applicable(),
    )
    .map_err(model_error)
}

fn add_node<'tree>(
    source: &str,
    work: Work<'tree>,
    pending: &mut Vec<PendingFact>,
    stack: &mut Vec<Work<'tree>>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<(), ConfigurationIngestionError> {
    let id = pending.len();
    attach(&mut pending[work.parent].kind, work.link, id)?;
    let range = source_range(work.node)?;
    match work.node.kind() {
        "object" => {
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range,
                kind: PendingKind::Object(Vec::new()),
            });
            let mut occurrences = HashMap::<String, usize>::new();
            let mut children = Vec::new();
            let mut cursor = work.node.walk();
            for pair in work.node.named_children(&mut cursor) {
                if pair.kind() != "pair" {
                    continue;
                }
                let Some(key_node) = pair.child_by_field_name("key") else {
                    continue;
                };
                let key = decode_json_string(source, key_node)?;
                let occurrence = occurrences.entry(key.clone()).or_default();
                *occurrence += 1;
                let key_range = source_range(key_node)?;
                let route = work.route.clone().child(
                    ConfigurationRouteSegment::key(key.clone(), *occurrence, key_range)
                        .map_err(model_error)?,
                );
                children.push((pair, route, key, key_range));
            }
            for (pair, route, key, key_range) in children.into_iter().rev() {
                stack.push(Work {
                    node: pair,
                    parent: id,
                    link: Link::ObjectMember,
                    route,
                });
                let _ = (key, key_range);
            }
        }
        "array" => {
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range,
                kind: PendingKind::Sequence(Vec::new()),
            });
            let mut cursor = work.node.walk();
            let children: Vec<_> = work.node.named_children(&mut cursor).enumerate().collect();
            for (index, child) in children.into_iter().rev() {
                let route = work.route.clone().child(
                    ConfigurationRouteSegment::index(index, source_range(child)?)
                        .map_err(model_error)?,
                );
                stack.push(Work {
                    node: child,
                    parent: id,
                    link: Link::SequenceItem,
                    route,
                });
            }
        }
        "pair" => {
            let key_node = work.node.child_by_field_name("key").ok_or_else(|| {
                ConfigurationIngestionError::InvalidFactModel(
                    "JSON pair has no structured key field".into(),
                )
            })?;
            let key = ConfigurationKey::new(
                decode_json_string(source, key_node)?,
                source_range(key_node)?,
            )
            .map_err(model_error)?;
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range,
                kind: PendingKind::Member { key, value: None },
            });
            if let Some(value) = work.node.child_by_field_name("value") {
                stack.push(Work {
                    node: value,
                    parent: id,
                    link: Link::MemberValue,
                    route: work.route,
                });
            }
        }
        "string" => pending.push(PendingFact {
            parent: Some(work.parent),
            route: work.route,
            range,
            kind: PendingKind::Scalar(ConfigurationScalarKind::String),
        }),
        "number" => {
            let text = work.node.utf8_text(source.as_bytes()).map_err(|_| {
                ConfigurationIngestionError::InvalidFactModel(
                    "JSON number range is not UTF-8".into(),
                )
            })?;
            let kind = if text.contains(['.', 'e', 'E']) {
                ConfigurationScalarKind::Decimal
            } else {
                ConfigurationScalarKind::Integer
            };
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route,
                range,
                kind: PendingKind::Scalar(kind),
            });
        }
        "true" | "false" => pending.push(PendingFact {
            parent: Some(work.parent),
            route: work.route,
            range,
            kind: PendingKind::Scalar(ConfigurationScalarKind::Boolean),
        }),
        "null" => pending.push(PendingFact {
            parent: Some(work.parent),
            route: work.route,
            range,
            kind: PendingKind::Scalar(ConfigurationScalarKind::Null),
        }),
        "ERROR" => recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            range,
        )),
        _ => recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::UnsupportedScalar,
            range,
        )),
    }
    Ok(())
}

fn attach(
    parent: &mut PendingKind,
    link: Link,
    child: usize,
) -> Result<(), ConfigurationIngestionError> {
    match (parent, link) {
        (PendingKind::Document(root), Link::DocumentRoot) => *root = Some(child),
        (PendingKind::Object(members), Link::ObjectMember) => members.push(child),
        (PendingKind::Sequence(items), Link::SequenceItem) => items.push(child),
        (PendingKind::Member { value, .. }, Link::MemberValue) => *value = Some(child),
        _ => {
            return Err(ConfigurationIngestionError::InvalidFactModel(
                "configuration fact parent/child relation is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn finalize(
    pending: Vec<PendingFact>,
) -> Result<Vec<ConfigurationFact>, ConfigurationIngestionError> {
    pending
        .into_iter()
        .map(|fact| {
            let parent = fact.parent.map(fact_id).transpose()?;
            let kind = match fact.kind {
                PendingKind::Document(root) => ConfigurationNodeKind::Document {
                    root: root.map(fact_id).transpose()?,
                },
                PendingKind::Object(members) => ConfigurationNodeKind::Object {
                    members: members.into_iter().map(fact_id).collect::<Result<_, _>>()?,
                },
                PendingKind::Sequence(items) => ConfigurationNodeKind::Sequence {
                    items: items.into_iter().map(fact_id).collect::<Result<_, _>>()?,
                },
                PendingKind::Member { key, value } => ConfigurationNodeKind::Member {
                    role: ConfigurationMemberRole::ObjectMember,
                    key,
                    value: value.map(fact_id).transpose()?,
                },
                PendingKind::Scalar(scalar_kind) => ConfigurationNodeKind::Scalar { scalar_kind },
            };
            Ok(ConfigurationFact::new(parent, fact.route, fact.range, kind))
        })
        .collect()
}

fn fact_id(index: usize) -> Result<ConfigurationFactId, ConfigurationIngestionError> {
    ConfigurationFactId::new(index).ok_or_else(|| {
        ConfigurationIngestionError::InvalidFactModel("configuration fact arena overflow".into())
    })
}

fn source_range(node: Node<'_>) -> Result<ConfigurationSourceRange, ConfigurationIngestionError> {
    ConfigurationSourceRange::new(node.start_byte(), node.end_byte()).map_err(model_error)
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn decode_json_string(source: &str, node: Node<'_>) -> Result<String, ConfigurationIngestionError> {
    let token = node.utf8_text(source.as_bytes()).map_err(|_| {
        ConfigurationIngestionError::InvalidFactModel("JSON key range is not UTF-8".into())
    })?;
    serde_json::from_str::<String>(token).map_err(|error| {
        ConfigurationIngestionError::InvalidFactModel(format!(
            "JSON grammar produced an invalid string token: {error}"
        ))
    })
}

fn collect_recoveries(
    root: Node<'_>,
) -> Result<Vec<ConfigurationRecovery>, ConfigurationIngestionError> {
    let mut recoveries = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::MalformedSyntax,
                source_range(node)?,
            ));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    recoveries.sort_by_key(|recovery| {
        (
            recovery.evidence().start_byte(),
            recovery.evidence().end_byte(),
        )
    });
    recoveries.dedup();
    Ok(recoveries)
}

fn model_error(error: ConfigurationModelError) -> ConfigurationIngestionError {
    ConfigurationIngestionError::InvalidFactModel(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(source: &str) -> ConfigurationDocumentFacts {
        match ingest_configuration_document(Path::new("config.JSON"), source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => facts,
            other => panic!("expected facts, got {other:?}"),
        }
    }

    #[test]
    fn json_ingestion_preserves_structure_duplicates_scalars_and_ranges() {
        let source = r#"{"a":1,"a":2.5,"nested":[true,null,"x"]}"#;
        let document = facts(source);
        assert!(document.completeness().is_complete());
        assert_eq!(document.format(), ConfigurationFormat::Json);
        assert_eq!(document.facts().len(), 11);
        let members: Vec<_> = document
            .facts()
            .iter()
            .filter(|fact| matches!(fact.kind(), ConfigurationNodeKind::Member { .. }))
            .collect();
        assert_eq!(members.len(), 3);
        assert_ne!(
            members[0].stable_id(ConfigurationFormat::Json),
            members[1].stable_id(ConfigurationFormat::Json)
        );
        for fact in document.facts() {
            assert!(fact.evidence().end_byte() <= source.len());
            assert_eq!(
                fact.provenance(),
                brokk_bifrost_core::analyzer::configuration::ConfigurationValueProvenance::Authored
            );
        }
        assert!(matches!(
            document.features().aliases(),
            brokk_bifrost_core::analyzer::configuration::ConfigurationFeatureState::NotApplicable
        ));
    }

    #[test]
    fn stable_identity_ignores_unrelated_sibling_edits() {
        let before = facts(r#"{"target":{"enabled":true},"other":1}"#);
        let after = facts(r#"{"target":{"enabled":true},"unrelated":[1,2,3],"other":1}"#);
        let enabled = |facts: &ConfigurationDocumentFacts| {
            facts.facts().iter().find(|fact| fact.route().segments().iter().any(|segment| matches!(segment.selector(), brokk_bifrost_core::analyzer::configuration::ConfigurationRouteSelector::Key { name, .. } if name == "enabled"))).unwrap().stable_id(ConfigurationFormat::Json)
        };
        assert_eq!(enabled(&before), enabled(&after));
    }

    #[test]
    fn malformed_and_unsupported_are_typed() {
        assert!(
            !facts(r#"{"ok":true,"broken":}"#)
                .completeness()
                .is_complete()
        );
        assert!(matches!(
            ingest_configuration_document(Path::new("config.yaml"), b"a: 1"),
            ConfigurationIngestionOutcome::Unsupported {
                format: Some(ConfigurationFormat::Yaml)
            }
        ));
        assert!(matches!(
            ingest_configuration_document(Path::new("config.json"), b"{\xff}"),
            ConfigurationIngestionOutcome::Incomplete {
                reason: ConfigurationIngestionError::InvalidUtf8
            }
        ));
    }

    #[test]
    fn adapter_epoch_is_stable_and_nonempty() {
        assert_eq!(
            json_configuration_adapter_epoch(),
            json_configuration_adapter_epoch()
        );
        assert_eq!(json_configuration_adapter_epoch().len(), 64);
    }
}
