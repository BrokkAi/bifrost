//! Maintained-parser ingestion for authored configuration documents.

use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationCompleteness, ConfigurationDocumentFacts, ConfigurationFact, ConfigurationFactId,
    ConfigurationFeatureSemantics, ConfigurationFeatureState, ConfigurationFormat,
    ConfigurationKey, ConfigurationMemberRole, ConfigurationModelError, ConfigurationNodeKind,
    ConfigurationPathClassification, ConfigurationRecovery, ConfigurationRecoveryReason,
    ConfigurationRoute, ConfigurationRouteSegment, ConfigurationScalarKind,
    ConfigurationSourceRange, classify_configuration_path,
};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use tree_sitter::{Language, Node, Parser};

const JSON_ADAPTER_SCHEMA_VERSION: u32 = 1;
const XML_ADAPTER_SCHEMA_VERSION: u32 = 1;

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
    let Ok(source) = std::str::from_utf8(bytes) else {
        return ConfigurationIngestionOutcome::Incomplete {
            reason: ConfigurationIngestionError::InvalidUtf8,
        };
    };
    let result = match format {
        ConfigurationFormat::Json => ingest_json(source),
        ConfigurationFormat::Xml => ingest_xml(source),
        _ => {
            return ConfigurationIngestionOutcome::Unsupported {
                format: Some(format),
            };
        }
    };
    match result {
        Ok(facts) => ConfigurationIngestionOutcome::Facts(facts),
        Err(error) => ConfigurationIngestionOutcome::Incomplete { reason: error },
    }
}

pub fn xml_configuration_adapter_epoch() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost-configuration-xml-adapter\n");
    hasher.update(XML_ADAPTER_SCHEMA_VERSION.to_le_bytes());
    hasher.update(b"quick-xml-0.40.1");
    format!("{:x}", hasher.finalize())
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
    Section {
        header: Option<usize>,
        members: Vec<usize>,
    },
    Sequence(Vec<usize>),
    Member {
        role: ConfigurationMemberRole,
        key: ConfigurationKey,
        value: Option<usize>,
    },
    Scalar(ConfigurationScalarKind),
}

#[derive(Clone, Copy)]
enum Link {
    DocumentRoot,
    ObjectMember,
    SectionMember,
    SectionHeader,
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
                kind: PendingKind::Member {
                    role: ConfigurationMemberRole::ObjectMember,
                    key,
                    value: None,
                },
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
        (PendingKind::Section { members, .. }, Link::SectionMember) => members.push(child),
        (PendingKind::Section { header, .. }, Link::SectionHeader) => *header = Some(child),
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
                PendingKind::Section { header, members } => ConfigurationNodeKind::Section {
                    header: header.map(fact_id).transpose()?,
                    members: members.into_iter().map(fact_id).collect::<Result<_, _>>()?,
                },
                PendingKind::Sequence(items) => ConfigurationNodeKind::Sequence {
                    items: items.into_iter().map(fact_id).collect::<Result<_, _>>()?,
                },
                PendingKind::Member { role, key, value } => ConfigurationNodeKind::Member {
                    role,
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

struct XmlFrame {
    section: usize,
    route: ConfigurationRoute,
    occurrences: HashMap<String, usize>,
}

fn ingest_xml(source: &str) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let document_range = ConfigurationSourceRange::new(0, source.len()).map_err(model_error)?;
    let mut pending = vec![PendingFact {
        parent: None,
        route: ConfigurationRoute::root(),
        range: document_range,
        kind: PendingKind::Document(None),
    }];
    let mut reader = Reader::from_str(source);
    reader.config_mut().check_end_names = true;
    let mut stack = Vec::<XmlFrame>::new();
    let mut root_occurrences = HashMap::<String, usize>::new();
    let mut recoveries = Vec::new();
    let mut entity_evidence = Vec::new();

    loop {
        let start = reader.buffer_position() as usize;
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(_) => {
                let start = (reader.error_position() as usize).min(source.len());
                recoveries.push(ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::MalformedSyntax,
                    ConfigurationSourceRange::new(start, source.len()).map_err(model_error)?,
                ));
                break;
            }
        };
        let end = (reader.buffer_position() as usize).min(source.len());
        let range = ConfigurationSourceRange::new(start.min(end), end).map_err(model_error)?;
        match event {
            Event::Start(element) => add_xml_element(
                source,
                &element,
                range,
                &mut pending,
                &mut stack,
                &mut root_occurrences,
                &mut recoveries,
            )?,
            Event::Empty(element) => {
                add_xml_element(
                    source,
                    &element,
                    range,
                    &mut pending,
                    &mut stack,
                    &mut root_occurrences,
                    &mut recoveries,
                )?;
                stack.pop();
            }
            Event::End(_) => {
                if stack.pop().is_none() {
                    recoveries.push(ConfigurationRecovery::new(
                        ConfigurationRecoveryReason::MalformedSyntax,
                        range,
                    ));
                }
            }
            Event::Text(text) => {
                let content = text.xml10_content().map_err(|_| {
                    ConfigurationIngestionError::InvalidFactModel(
                        "XML text could not be decoded without expansion".into(),
                    )
                })?;
                let content_range = borrowed_xml_range(source, &text)?;
                add_xml_text(
                    content.trim().is_empty(),
                    content_range,
                    &stack,
                    &mut pending,
                    &mut recoveries,
                )?;
            }
            Event::CData(cdata) => {
                let content = cdata.decode().map_err(|_| {
                    ConfigurationIngestionError::InvalidFactModel(
                        "XML CDATA could not be decoded".into(),
                    )
                })?;
                let content_range = borrowed_xml_range(source, &cdata)?;
                add_xml_text(
                    content.trim().is_empty(),
                    content_range,
                    &stack,
                    &mut pending,
                    &mut recoveries,
                )?;
            }
            Event::DocType(_) | Event::GeneralRef(_) => {
                entity_evidence.push(range);
                recoveries.push(ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::UnsupportedScalar,
                    range,
                ));
            }
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
    if !stack.is_empty() {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            document_range,
        ));
    }
    if matches!(pending[0].kind, PendingKind::Document(None)) {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            document_range,
        ));
    }
    recoveries.sort_by_key(|item| (item.evidence().start_byte(), item.evidence().end_byte()));
    recoveries.dedup();
    let completeness = if recoveries.is_empty() {
        ConfigurationCompleteness::Complete
    } else {
        ConfigurationCompleteness::Incomplete { recoveries }
    };
    let entity_state = if entity_evidence.is_empty() {
        ConfigurationFeatureState::NotApplicable
    } else {
        ConfigurationFeatureState::Unresolved {
            evidence: entity_evidence,
        }
    };
    ConfigurationDocumentFacts::new(
        ConfigurationFormat::Xml,
        finalize(pending)?,
        completeness,
        ConfigurationFeatureSemantics::new(
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            entity_state,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
        ),
    )
    .map_err(model_error)
}

fn add_xml_element(
    source: &str,
    element: &BytesStart<'_>,
    range: ConfigurationSourceRange,
    pending: &mut Vec<PendingFact>,
    stack: &mut Vec<XmlFrame>,
    root_occurrences: &mut HashMap<String, usize>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<(), ConfigurationIngestionError> {
    let name_bytes = element.name();
    let name_range = borrowed_xml_range(source, name_bytes.as_ref())?;
    let name = std::str::from_utf8(name_bytes.as_ref())
        .map_err(|_| ConfigurationIngestionError::InvalidUtf8)?
        .to_owned();
    let (parent, route, occurrence, link) = if let Some(frame) = stack.last_mut() {
        let occurrence = frame.occurrences.entry(name.clone()).or_default();
        *occurrence += 1;
        (
            frame.section,
            frame.route.clone(),
            *occurrence,
            Link::SectionMember,
        )
    } else {
        if !matches!(pending[0].kind, PendingKind::Document(None)) {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::MalformedSyntax,
                range,
            ));
            return Ok(());
        }
        let occurrence = root_occurrences.entry(name.clone()).or_default();
        *occurrence += 1;
        (
            0,
            ConfigurationRoute::root(),
            *occurrence,
            Link::DocumentRoot,
        )
    };
    let route = route.child(
        ConfigurationRouteSegment::key(name.clone(), occurrence, name_range)
            .map_err(model_error)?,
    );
    let member = pending.len();
    attach(&mut pending[parent].kind, link, member)?;
    pending.push(PendingFact {
        parent: Some(parent),
        route: route.clone(),
        range: name_range,
        kind: PendingKind::Member {
            role: ConfigurationMemberRole::XmlElement,
            key: ConfigurationKey::new(name, name_range).map_err(model_error)?,
            value: None,
        },
    });
    let section = pending.len();
    pending.push(PendingFact {
        parent: Some(member),
        route: route.clone(),
        range,
        kind: PendingKind::Section {
            header: None,
            members: Vec::new(),
        },
    });
    if let PendingKind::Member { value, .. } = &mut pending[member].kind {
        *value = Some(section);
    }

    let mut occurrences = HashMap::<String, usize>::new();
    for attribute in element.attributes().with_checks(true) {
        let attribute = match attribute {
            Ok(attribute) => attribute,
            Err(_) => {
                recoveries.push(ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::MalformedSyntax,
                    range,
                ));
                continue;
            }
        };
        let key_range = borrowed_xml_range(source, attribute.key.as_ref())?;
        let value_range = borrowed_xml_range(source, attribute.value.as_ref())?;
        if attribute
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, element.decoder())
            .is_err()
        {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::UnsupportedScalar,
                value_range,
            ));
        }
        let key = std::str::from_utf8(attribute.key.as_ref())
            .map_err(|_| ConfigurationIngestionError::InvalidUtf8)?
            .to_owned();
        let occurrence = occurrences.entry(key.clone()).or_default();
        *occurrence += 1;
        let attribute_route = route.clone().child(
            ConfigurationRouteSegment::key(key.clone(), *occurrence, key_range)
                .map_err(model_error)?,
        );
        let attribute_member = pending.len();
        if let PendingKind::Section { members, .. } = &mut pending[section].kind {
            members.push(attribute_member);
        }
        pending.push(PendingFact {
            parent: Some(section),
            route: attribute_route.clone(),
            range: key_range,
            kind: PendingKind::Member {
                role: ConfigurationMemberRole::XmlAttribute,
                key: ConfigurationKey::new(key, key_range).map_err(model_error)?,
                value: None,
            },
        });
        let scalar = pending.len();
        pending.push(PendingFact {
            parent: Some(attribute_member),
            route: attribute_route,
            range: value_range,
            kind: PendingKind::Scalar(ConfigurationScalarKind::String),
        });
        if let PendingKind::Member { value, .. } = &mut pending[attribute_member].kind {
            *value = Some(scalar);
        }
    }
    stack.push(XmlFrame {
        section,
        route,
        occurrences: HashMap::new(),
    });
    Ok(())
}

fn borrowed_xml_range(
    source: &str,
    bytes: &[u8],
) -> Result<ConfigurationSourceRange, ConfigurationIngestionError> {
    let source_start = source.as_ptr() as usize;
    let source_end = source_start + source.len();
    let bytes_start = bytes.as_ptr() as usize;
    let bytes_end = bytes_start + bytes.len();
    if bytes_start < source_start || bytes_end > source_end {
        return Err(ConfigurationIngestionError::InvalidFactModel(
            "quick-xml returned source evidence outside the input buffer".into(),
        ));
    }
    ConfigurationSourceRange::new(bytes_start - source_start, bytes_end - source_start)
        .map_err(model_error)
}

fn add_xml_text(
    is_whitespace: bool,
    range: ConfigurationSourceRange,
    stack: &[XmlFrame],
    pending: &mut Vec<PendingFact>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<(), ConfigurationIngestionError> {
    if is_whitespace {
        return Ok(());
    }
    let Some(frame) = stack.last() else {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            range,
        ));
        return Ok(());
    };
    let has_header = matches!(
        pending[frame.section].kind,
        PendingKind::Section {
            header: Some(_),
            ..
        }
    );
    if has_header {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::UnsupportedScalar,
            range,
        ));
        return Ok(());
    }
    let scalar = pending.len();
    attach(
        &mut pending[frame.section].kind,
        Link::SectionHeader,
        scalar,
    )?;
    pending.push(PendingFact {
        parent: Some(frame.section),
        route: frame.route.clone(),
        range,
        kind: PendingKind::Scalar(ConfigurationScalarKind::String),
    });
    Ok(())
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

    fn xml_facts(source: &str) -> ConfigurationDocumentFacts {
        match ingest_configuration_document(Path::new("config.XML"), source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => facts,
            other => panic!("expected XML facts, got {other:?}"),
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
        assert_eq!(
            xml_configuration_adapter_epoch(),
            xml_configuration_adapter_epoch()
        );
        assert_eq!(xml_configuration_adapter_epoch().len(), 64);
    }

    #[test]
    fn xml_ingestion_preserves_roles_scalars_occurrences_and_ranges() {
        let source = r#"<server mode="prod"><host>one</host><host>two</host></server>"#;
        let document = xml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(document.format(), ConfigurationFormat::Xml);
        let members: Vec<_> = document
            .facts()
            .iter()
            .filter(|fact| matches!(fact.kind(), ConfigurationNodeKind::Member { .. }))
            .collect();
        assert_eq!(members.len(), 4, "{:#?}", document.facts());
        for member in &members {
            let ConfigurationNodeKind::Member { key, .. } = member.kind() else {
                unreachable!();
            };
            assert_eq!(
                &source[key.evidence().start_byte()..key.evidence().end_byte()],
                key.text()
            );
            assert_eq!(member.evidence(), key.evidence());
        }
        assert!(members.iter().any(|fact| matches!(
            fact.kind(),
            ConfigurationNodeKind::Member {
                role: ConfigurationMemberRole::XmlAttribute,
                key,
                ..
            } if key.text() == "mode"
        )));
        let hosts: Vec<_> = members
            .iter()
            .filter(|fact| {
                matches!(
                    fact.kind(),
                    ConfigurationNodeKind::Member {
                        role: ConfigurationMemberRole::XmlElement,
                        key,
                        ..
                    } if key.text() == "host"
                )
            })
            .collect();
        assert_eq!(hosts.len(), 2);
        assert_ne!(
            hosts[0].stable_id(ConfigurationFormat::Xml),
            hosts[1].stable_id(ConfigurationFormat::Xml)
        );
        let mode = members
            .iter()
            .find(|fact| {
                matches!(
                    fact.kind(),
                    ConfigurationNodeKind::Member { key, .. } if key.text() == "mode"
                )
            })
            .unwrap();
        let ConfigurationNodeKind::Member {
            value: Some(value), ..
        } = mode.kind()
        else {
            panic!("XML attribute must have a scalar value");
        };
        let scalar = document.fact(*value).unwrap();
        assert_eq!(
            &source[scalar.evidence().start_byte()..scalar.evidence().end_byte()],
            "prod"
        );
        assert!(
            document
                .facts()
                .iter()
                .all(|fact| fact.evidence().end_byte() <= source.len())
        );
    }

    #[test]
    fn xml_malformed_and_entity_documents_are_typed_incomplete() {
        assert!(
            !xml_facts("<server><host>x</server>")
                .completeness()
                .is_complete()
        );
        let entity =
            xml_facts("<!DOCTYPE server [<!ENTITY x SYSTEM 'file:///tmp/x'>]><server>&x;</server>");
        assert!(!entity.completeness().is_complete());
        assert!(matches!(
            entity.features().aliases(),
            ConfigurationFeatureState::NotApplicable
        ));
        assert!(matches!(
            entity.features().includes(),
            ConfigurationFeatureState::Unresolved { .. }
        ));
        for source in ["", "<one/><two/>", "outside<server/>", "<server/>outside"] {
            assert!(!xml_facts(source).completeness().is_complete(), "{source}");
        }
        assert!(
            !xml_facts("<server key=\"one\" key=\"two\"/>")
                .completeness()
                .is_complete()
        );
    }

    #[test]
    fn xml_cdata_is_preserved_as_structured_text() {
        let source = "<server><![CDATA[<literal>]]></server>";
        let document = xml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        let scalar = document
            .facts()
            .iter()
            .find(|fact| {
                matches!(
                    fact.kind(),
                    ConfigurationNodeKind::Scalar {
                        scalar_kind: ConfigurationScalarKind::String
                    }
                )
            })
            .unwrap();
        assert_eq!(
            &source[scalar.evidence().start_byte()..scalar.evidence().end_byte()],
            "<literal>"
        );
    }

    #[test]
    fn xml_stable_identity_ignores_unrelated_sibling_edits() {
        let before = xml_facts("<server><target enabled=\"true\"/><other/></server>");
        let after = xml_facts(
            "<server><target enabled=\"true\"/><unrelated><child/></unrelated><other/></server>",
        );
        let enabled = |facts: &ConfigurationDocumentFacts| {
            facts
                .facts()
                .iter()
                .find(|fact| {
                    matches!(
                        fact.kind(),
                        ConfigurationNodeKind::Member {
                            role: ConfigurationMemberRole::XmlAttribute,
                            key,
                            ..
                        } if key.text() == "enabled"
                    )
                })
                .unwrap()
                .stable_id(ConfigurationFormat::Xml)
        };
        assert_eq!(enabled(&before), enabled(&after));
    }
}
