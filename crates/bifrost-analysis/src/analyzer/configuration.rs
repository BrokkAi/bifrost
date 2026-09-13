//! Maintained-parser ingestion for authored configuration documents.

use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationCompleteness, ConfigurationDocumentFacts, ConfigurationFact, ConfigurationFactId,
    ConfigurationFeatureSemantics, ConfigurationFeatureState, ConfigurationFormat,
    ConfigurationKey, ConfigurationMemberRole, ConfigurationModelError, ConfigurationNodeKind,
    ConfigurationPathClassification, ConfigurationRecovery, ConfigurationRecoveryReason,
    ConfigurationRoute, ConfigurationRouteSegment, ConfigurationRouteSelector,
    ConfigurationScalarKind, ConfigurationSourceRange, classify_configuration_path,
};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use toml_edit::{Array, ArrayOfTables, ImDocument, Item, Key, TableLike, Value};
use tree_sitter::{Language, Node, Parser};

const JSON_ADAPTER_SCHEMA_VERSION: u32 = 2;
const TOML_ADAPTER_SCHEMA_VERSION: u32 = 1;
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
        ConfigurationFormat::Toml => ingest_toml(source),
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

/// Cache compatibility identity for the TOML adapter and its pinned parser.
pub fn toml_configuration_adapter_epoch() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost-configuration-toml-adapter\n");
    hasher.update(TOML_ADAPTER_SCHEMA_VERSION.to_le_bytes());
    hasher.update(b"toml_edit-0.22.27");
    format!("{:x}", hasher.finalize())
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
    // RFC 8259 admits exactly one top-level value, but the grammar's document
    // rule repeats values, so a document with none or with more than one is
    // authored evidence this model cannot represent as a single root.
    let mut cursor = root.walk();
    let mut values = root
        .named_children(&mut cursor)
        .filter(|node| !node.is_error() && !node.is_missing() && node.kind() != "comment");
    match values.next() {
        Some(value) => {
            let mut stack = vec![Work {
                node: value,
                parent: 0,
                link: Link::DocumentRoot,
                route: ConfigurationRoute::root(),
            }];
            while let Some(work) = stack.pop() {
                add_node(source, work, &mut pending, &mut stack, &mut recoveries)?;
            }
            for extra in values {
                recoveries.push(ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::MalformedSyntax,
                    source_range(extra)?,
                ));
            }
        }
        None => recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            document_range,
        )),
    }
    let facts = finalize(pending)?;
    recoveries.sort_by_key(|recovery| {
        (
            recovery.evidence().start_byte(),
            recovery.evidence().end_byte(),
        )
    });
    recoveries.dedup();
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

/// Map one tree-sitter node onto the shared fact model.
///
/// The parent link is recorded only after the node maps to a fact. A node the
/// adapter does not represent (recovered syntax, or a grammar extra such as a
/// comment reached through a value position) contributes typed recovery
/// evidence and no arena entry, so the parent can never reference a fact that
/// was never pushed.
fn add_node<'tree>(
    source: &str,
    work: Work<'tree>,
    pending: &mut Vec<PendingFact>,
    stack: &mut Vec<Work<'tree>>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<(), ConfigurationIngestionError> {
    let range = source_range(work.node)?;
    let id = pending.len();
    let mut children = Vec::new();
    let kind = match work.node.kind() {
        "object" => {
            let mut occurrences = HashMap::<String, usize>::new();
            let mut cursor = work.node.walk();
            for pair in work.node.named_children(&mut cursor) {
                if pair.kind() == "comment" {
                    continue;
                }
                let Some(key_node) = pair.child_by_field_name("key") else {
                    recoveries.push(ConfigurationRecovery::new(
                        ConfigurationRecoveryReason::MalformedSyntax,
                        source_range(pair)?,
                    ));
                    continue;
                };
                let key_range = source_range(key_node)?;
                let key = decode_json_key(source, key_node, key_range, recoveries)?;
                let occurrence = occurrences.entry(key.clone()).or_default();
                *occurrence += 1;
                children.push(Work {
                    node: pair,
                    parent: id,
                    link: Link::ObjectMember,
                    route: work.route.clone().child(ConfigurationRouteSegment::key(
                        key,
                        *occurrence,
                        key_range,
                    )),
                });
            }
            PendingKind::Object(Vec::new())
        }
        "array" => {
            let mut cursor = work.node.walk();
            // Comments are grammar extras and hold no element position; every
            // other child occupies one, so a recovered element keeps the
            // authored indexes of the elements after it.
            for (index, child) in work
                .node
                .named_children(&mut cursor)
                .filter(|node| node.kind() != "comment")
                .enumerate()
            {
                children.push(Work {
                    node: child,
                    parent: id,
                    link: Link::SequenceItem,
                    route: work.route.clone().child(ConfigurationRouteSegment::index(
                        index,
                        source_range(child)?,
                    )),
                });
            }
            PendingKind::Sequence(Vec::new())
        }
        "pair" => {
            // The object arm queues every pair with its own decoded key
            // segment, so the authored key never needs a second decode.
            let Some(segment) = work.route.segments().last() else {
                unreachable!("a JSON pair is only queued with its own key route segment");
            };
            let ConfigurationRouteSelector::Key { name, .. } = segment.selector() else {
                unreachable!("a JSON pair route segment is always an authored key");
            };
            let key = ConfigurationKey::new(name.clone(), segment.evidence());
            if let Some(value) = work.node.child_by_field_name("value") {
                children.push(Work {
                    node: value,
                    parent: id,
                    link: Link::MemberValue,
                    route: work.route.clone(),
                });
            }
            PendingKind::Member {
                role: ConfigurationMemberRole::ObjectMember,
                key,
                value: None,
            }
        }
        "string" => PendingKind::Scalar(json_string_scalar_kind(source, work.node, recoveries)?),
        "number" => PendingKind::Scalar(json_number_scalar_kind(source, work.node, recoveries)?),
        "true" | "false" => PendingKind::Scalar(ConfigurationScalarKind::Boolean),
        "null" => PendingKind::Scalar(ConfigurationScalarKind::Null),
        "ERROR" => {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::MalformedSyntax,
                range,
            ));
            return Ok(());
        }
        _ => {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::UnsupportedScalar,
                range,
            ));
            return Ok(());
        }
    };
    attach(&mut pending[work.parent].kind, work.link, id)?;
    pending.push(PendingFact {
        parent: Some(work.parent),
        route: work.route,
        range,
        kind,
    });
    // The stack is LIFO, so queueing in reverse keeps authored order.
    stack.extend(children.into_iter().rev());
    Ok(())
}

/// Whether one authored token is a valid JSON token.
///
/// `serde::de::IgnoredAny` is the maintained parser's syntax verdict without
/// its representation limits: it rejects the constructs tree-sitter-json's
/// tolerant grammar accepts (`1.`, `01`, `"\u"`, an unescaped control
/// character) while accepting a number outside `f64` range and an unpaired
/// surrogate escape, which are authored JSON that Rust's own `f64` and
/// `String` cannot hold.
fn json_token_is_valid(token: &str) -> bool {
    serde_json::from_str::<serde::de::IgnoredAny>(token).is_ok()
}

fn json_token_text<'source>(
    source: &'source str,
    node: Node<'_>,
) -> Result<&'source str, ConfigurationIngestionError> {
    node.utf8_text(source.as_bytes()).map_err(|_| {
        ConfigurationIngestionError::InvalidFactModel("JSON token range is not UTF-8".into())
    })
}

/// tree-sitter-json emits `number` as one opaque token, so the authored form
/// is the only structure available for the integer/decimal distinction. The
/// maintained parser still supplies the validity verdict, because the grammar
/// also accepts numbers JSON does not.
fn json_number_scalar_kind(
    source: &str,
    node: Node<'_>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<ConfigurationScalarKind, ConfigurationIngestionError> {
    let text = json_token_text(source, node)?;
    if !json_token_is_valid(text) {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::UnsupportedScalar,
            source_range(node)?,
        ));
        return Ok(ConfigurationScalarKind::Opaque);
    }
    Ok(if text.contains(['.', 'e', 'E']) {
        ConfigurationScalarKind::Decimal
    } else {
        ConfigurationScalarKind::Integer
    })
}

fn json_string_scalar_kind(
    source: &str,
    node: Node<'_>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<ConfigurationScalarKind, ConfigurationIngestionError> {
    if json_token_is_valid(json_token_text(source, node)?) {
        return Ok(ConfigurationScalarKind::String);
    }
    recoveries.push(ConfigurationRecovery::new(
        ConfigurationRecoveryReason::UnsupportedScalar,
        source_range(node)?,
    ));
    Ok(ConfigurationScalarKind::Opaque)
}

/// The authored text of one object key.
///
/// A key that the maintained parser cannot decode into a Rust `String` is
/// typed recovery evidence, never a whole-document failure: the member keeps
/// the authored content the grammar recorded in the token's `string_content`
/// and `escape_sequence` children.
fn decode_json_key(
    source: &str,
    node: Node<'_>,
    range: ConfigurationSourceRange,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<String, ConfigurationIngestionError> {
    let token = json_token_text(source, node)?;
    if let Ok(text) = serde_json::from_str::<String>(token) {
        return Ok(text);
    }
    recoveries.push(ConfigurationRecovery::new(
        ConfigurationRecoveryReason::UnsupportedScalar,
        range,
    ));
    let mut cursor = node.walk();
    let mut authored = String::new();
    for child in node.named_children(&mut cursor) {
        authored.push_str(json_token_text(source, child)?);
    }
    Ok(authored)
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

fn collect_recoveries(
    root: Node<'_>,
) -> Result<Vec<ConfigurationRecovery>, ConfigurationIngestionError> {
    let mut recoveries = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() || node.kind() == "comment" {
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

/// One TOML subtree waiting to become a fact.
///
/// The adapter walks the parsed document with this explicit stack rather than
/// with Rust recursion, so a deeply nested authored document cannot exhaust
/// the thread stack.
struct TomlWork<'doc> {
    node: TomlNode<'doc>,
    parent: usize,
    link: Link,
    route: ConfigurationRoute,
    /// Exact evidence for the fact this work item creates.
    range: ConfigurationSourceRange,
}

enum TomlNode<'doc> {
    /// One authored key and the item it names.
    Entry {
        key: &'doc Key,
        item: &'doc Item,
    },
    /// A standard table, a `[parent.child]` header table, a dotted-key proxy,
    /// or an inline table: every one of them is an ordered key/value
    /// container, so they share this arm.
    Table(&'doc dyn TableLike),
    /// An inline array such as `ciphers = ["a", "b"]`.
    Array(&'doc Array),
    /// An array of tables declared with repeated `[[header]]` blocks.
    ArrayOfTables(&'doc ArrayOfTables),
    Scalar(ConfigurationScalarKind),
}

fn ingest_toml(source: &str) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let document_range = ConfigurationSourceRange::new(0, source.len()).map_err(model_error)?;
    let mut pending = vec![PendingFact {
        parent: None,
        route: ConfigurationRoute::root(),
        range: document_range,
        kind: PendingKind::Document(None),
    }];
    // TOML has no partial document: the format rejects a duplicate key, a
    // redefined table, a dotted key that reopens a header table, and malformed
    // syntax outright. A rejected document therefore recovers no root and
    // reports the parser's own byte range as its recovery evidence, so its
    // absent rows can never read as a clean empty answer.
    let document = match ImDocument::parse(source) {
        Ok(document) => document,
        Err(error) => {
            let evidence = match error.span() {
                Some(span) => {
                    ConfigurationSourceRange::new(span.start, span.end).map_err(model_error)?
                }
                None => document_range,
            };
            return ConfigurationDocumentFacts::new(
                ConfigurationFormat::Toml,
                finalize(pending)?,
                ConfigurationCompleteness::Incomplete {
                    recoveries: vec![ConfigurationRecovery::new(
                        ConfigurationRecoveryReason::MalformedSyntax,
                        evidence,
                    )],
                },
                ConfigurationFeatureSemantics::not_applicable(),
            )
            .map_err(model_error);
        }
    };
    // A TOML document is its root table. The parser's own root span covers
    // only the bare top-level keys, so the whole buffer is the exact evidence.
    let mut stack = vec![TomlWork {
        node: TomlNode::Table(document.as_table()),
        parent: 0,
        link: Link::DocumentRoot,
        route: ConfigurationRoute::root(),
        range: document_range,
    }];
    while let Some(work) = stack.pop() {
        add_toml_node(work, &mut pending, &mut stack)?;
    }
    ConfigurationDocumentFacts::new(
        ConfigurationFormat::Toml,
        finalize(pending)?,
        ConfigurationCompleteness::Complete,
        // TOML has no anchors, aliases, includes, interpolation, or document
        // merge: none of them can be structurally authored in the format, so
        // every axis is not applicable rather than unresolved.
        ConfigurationFeatureSemantics::not_applicable(),
    )
    .map_err(model_error)
}

fn add_toml_node<'doc>(
    work: TomlWork<'doc>,
    pending: &mut Vec<PendingFact>,
    stack: &mut Vec<TomlWork<'doc>>,
) -> Result<(), ConfigurationIngestionError> {
    let id = pending.len();
    attach(&mut pending[work.parent].kind, work.link, id)?;
    match work.node {
        TomlNode::Entry { key, item } => {
            let key_range = toml_span(key.span(), "key")?;
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range: work.range,
                kind: PendingKind::Member {
                    // Every TOML key/value pair is an entry of some table: a
                    // header table, a dotted-key proxy, or an inline table.
                    role: ConfigurationMemberRole::TableEntry,
                    key: ConfigurationKey::new(key.get().to_owned(), key_range),
                    value: None,
                },
            });
            let (node, range) = match item {
                Item::Table(table) => (TomlNode::Table(table), table.span()),
                Item::ArrayOfTables(tables) => (TomlNode::ArrayOfTables(tables), tables.span()),
                Item::Value(value) => (toml_value_node(value), value.span()),
                Item::None => return Ok(()),
            };
            // A table the parser synthesised was never authored as a header or
            // a brace of its own, so the key that named it is its exact
            // evidence. That covers an implicit `[parent.child]` parent, a
            // dotted-key proxy under a header, and a dotted-key proxy inside
            // an inline table, which is an unspanned value rather than a
            // table item.
            let range = toml_span_or(range, key_range)?;
            stack.push(TomlWork {
                node,
                parent: id,
                link: Link::MemberValue,
                route: work.route,
                range,
            });
        }
        TomlNode::Table(table) => {
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range: work.range,
                kind: PendingKind::Object(Vec::new()),
            });
            let mut entries = Vec::new();
            for (name, _) in table.iter() {
                let (key, item) = table.get_key_value(name).ok_or_else(|| {
                    ConfigurationIngestionError::InvalidFactModel(format!(
                        "toml_edit listed key {name:?} that its own table does not hold"
                    ))
                })?;
                let key_range = toml_span(key.span(), "key")?;
                // A member spans from its key to the end of the value it
                // names, the same extent a JSON pair covers.
                let member_end = item.span().map_or(key_range.end_byte(), |span| span.end);
                let member_range =
                    ConfigurationSourceRange::new(key_range.start_byte(), member_end)
                        .map_err(model_error)?;
                entries.push(TomlWork {
                    node: TomlNode::Entry { key, item },
                    parent: id,
                    link: Link::ObjectMember,
                    // TOML rejects a duplicate key, so a name occurs at most
                    // once per table and every occurrence is the first.
                    route: work.route.clone().child(ConfigurationRouteSegment::key(
                        key.get(),
                        1,
                        key_range,
                    )),
                    range: member_range,
                });
            }
            stack.extend(entries.into_iter().rev());
        }
        TomlNode::Array(array) => {
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range: work.range,
                kind: PendingKind::Sequence(Vec::new()),
            });
            let mut items = Vec::new();
            for (index, value) in array.iter().enumerate() {
                let range = toml_span(value.span(), "array item")?;
                items.push(TomlWork {
                    node: toml_value_node(value),
                    parent: id,
                    link: Link::SequenceItem,
                    route: work
                        .route
                        .clone()
                        .child(ConfigurationRouteSegment::index(index, range)),
                    range,
                });
            }
            stack.extend(items.into_iter().rev());
        }
        TomlNode::ArrayOfTables(tables) => {
            pending.push(PendingFact {
                parent: Some(work.parent),
                route: work.route.clone(),
                range: work.range,
                kind: PendingKind::Sequence(Vec::new()),
            });
            let mut items = Vec::new();
            for (index, table) in tables.iter().enumerate() {
                let range = toml_span(table.span(), "array-of-tables element")?;
                items.push(TomlWork {
                    node: TomlNode::Table(table),
                    parent: id,
                    link: Link::SequenceItem,
                    route: work
                        .route
                        .clone()
                        .child(ConfigurationRouteSegment::index(index, range)),
                    range,
                });
            }
            stack.extend(items.into_iter().rev());
        }
        TomlNode::Scalar(scalar_kind) => pending.push(PendingFact {
            parent: Some(work.parent),
            route: work.route,
            range: work.range,
            kind: PendingKind::Scalar(scalar_kind),
        }),
    }
    Ok(())
}

fn toml_value_node(value: &Value) -> TomlNode<'_> {
    match value {
        Value::String(_) => TomlNode::Scalar(ConfigurationScalarKind::String),
        Value::Integer(_) => TomlNode::Scalar(ConfigurationScalarKind::Integer),
        Value::Float(_) => TomlNode::Scalar(ConfigurationScalarKind::Decimal),
        Value::Boolean(_) => TomlNode::Scalar(ConfigurationScalarKind::Boolean),
        // A TOML date-time is a first-class scalar that the format-neutral
        // kind registry does not name. Opaque keeps its route, its kind, and
        // its exact bytes queryable; it is not a gap the parser left behind.
        Value::Datetime(_) => TomlNode::Scalar(ConfigurationScalarKind::Opaque),
        Value::Array(array) => TomlNode::Array(array),
        Value::InlineTable(table) => TomlNode::Table(table),
    }
}

fn toml_span(
    span: Option<std::ops::Range<usize>>,
    node: &'static str,
) -> Result<ConfigurationSourceRange, ConfigurationIngestionError> {
    let span = span.ok_or_else(|| {
        ConfigurationIngestionError::InvalidFactModel(format!(
            "toml_edit recorded no source span for a parsed {node}"
        ))
    })?;
    ConfigurationSourceRange::new(span.start, span.end).map_err(model_error)
}

fn toml_span_or(
    span: Option<std::ops::Range<usize>>,
    authored_by: ConfigurationSourceRange,
) -> Result<ConfigurationSourceRange, ConfigurationIngestionError> {
    match span {
        Some(span) => ConfigurationSourceRange::new(span.start, span.end).map_err(model_error),
        None => Ok(authored_by),
    }
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
    let route = route.child(ConfigurationRouteSegment::key(
        name.clone(),
        occurrence,
        name_range,
    ));
    let member = pending.len();
    attach(&mut pending[parent].kind, link, member)?;
    pending.push(PendingFact {
        parent: Some(parent),
        route: route.clone(),
        range: name_range,
        kind: PendingKind::Member {
            role: ConfigurationMemberRole::XmlElement,
            key: ConfigurationKey::new(name, name_range),
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
        let attribute_route = route.clone().child(ConfigurationRouteSegment::key(
            key.clone(),
            *occurrence,
            key_range,
        ));
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
                key: ConfigurationKey::new(key, key_range),
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
    fn malformed_json_prefix_keeps_the_following_root() {
        let document = facts(r#"@ {"kept":true}"#);
        assert!(!document.completeness().is_complete());
        assert_eq!(member_keys(&document), vec!["kept"]);
    }

    #[test]
    fn json_comments_keep_facts_with_exact_malformed_evidence() {
        let source = "// header\n{\"kept\":true}";
        let document = facts(source);
        assert_eq!(member_keys(&document), vec!["kept"]);
        let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness() else {
            panic!("a JSON comment is malformed syntax: {document:#?}");
        };
        assert!(
            recoveries.iter().any(|recovery| {
                recovery.reason() == ConfigurationRecoveryReason::MalformedSyntax
                    && &source[recovery.evidence().start_byte()..recovery.evidence().end_byte()]
                        == "// header"
            }),
            "{recoveries:#?}"
        );
    }

    #[test]
    fn adapter_epochs_are_stable_and_distinct_per_adapter() {
        for epoch in [
            json_configuration_adapter_epoch(),
            xml_configuration_adapter_epoch(),
        ] {
            assert_eq!(epoch.len(), 64, "{epoch}");
            assert!(
                epoch
                    .chars()
                    .all(|digit| digit.is_ascii_hexdigit() && !digit.is_ascii_uppercase()),
                "{epoch}"
            );
        }
        assert_eq!(
            json_configuration_adapter_epoch(),
            json_configuration_adapter_epoch()
        );
        assert_eq!(
            xml_configuration_adapter_epoch(),
            xml_configuration_adapter_epoch()
        );
        // Two adapters over the same document model must never share a cache
        // compatibility identity.
        assert_ne!(
            json_configuration_adapter_epoch(),
            xml_configuration_adapter_epoch()
        );
    }

    /// Every referenced child exists exactly once and agrees with its parent.
    fn arena_children_are_exclusive(document: &ConfigurationDocumentFacts) {
        let mut referenced = vec![0usize; document.facts().len()];
        for (index, fact) in document.facts().iter().enumerate() {
            let children: Vec<_> = match fact.kind() {
                ConfigurationNodeKind::Document { root } => root.iter().copied().collect(),
                ConfigurationNodeKind::Object { members } => members.clone(),
                ConfigurationNodeKind::Section { header, members } => header
                    .iter()
                    .copied()
                    .chain(members.iter().copied())
                    .collect(),
                ConfigurationNodeKind::Sequence { items } => items.clone(),
                ConfigurationNodeKind::Member { value, .. } => value.iter().copied().collect(),
                ConfigurationNodeKind::Scalar { .. } => Vec::new(),
            };
            for child in children {
                referenced[child.index()] += 1;
                assert_eq!(
                    document.fact(child).and_then(ConfigurationFact::parent),
                    ConfigurationFactId::new(index),
                    "{document:#?}"
                );
            }
        }
        for (index, count) in referenced.iter().enumerate().skip(1) {
            assert_eq!(*count, 1, "fact {index} in {document:#?}");
        }
    }

    fn recovery_reasons(document: &ConfigurationDocumentFacts) -> Vec<ConfigurationRecoveryReason> {
        match document.completeness() {
            ConfigurationCompleteness::Complete => Vec::new(),
            ConfigurationCompleteness::Incomplete { recoveries } => recoveries
                .iter()
                .map(ConfigurationRecovery::reason)
                .collect(),
        }
    }

    fn member_keys(document: &ConfigurationDocumentFacts) -> Vec<&str> {
        document
            .facts()
            .iter()
            .filter_map(|fact| match fact.kind() {
                ConfigurationNodeKind::Member { key, .. } => Some(key.text()),
                _ => None,
            })
            .collect()
    }

    fn scalar_kinds(document: &ConfigurationDocumentFacts) -> Vec<ConfigurationScalarKind> {
        document
            .facts()
            .iter()
            .filter_map(|fact| match fact.kind() {
                ConfigurationNodeKind::Scalar { scalar_kind } => Some(*scalar_kind),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn recovered_json_keeps_its_surviving_facts_and_an_exclusive_arena() {
        // tree-sitter-json 0.24.8 does not accept a `+` exponent, so this
        // authored member is valid JSON that the grammar recovers from. Before
        // the parent link moved behind fact creation, the recovered value left
        // a dangling child id and the whole document returned no facts at all.
        let document = facts(r#"{"kept": "value", "budget": 1e+9}"#);
        arena_children_are_exclusive(&document);
        assert!(member_keys(&document).contains(&"kept"), "{document:#?}");
        assert!(
            recovery_reasons(&document)
                .iter()
                .all(|reason| *reason == ConfigurationRecoveryReason::MalformedSyntax),
            "{document:#?}"
        );

        // A grammar extra in an element position must not alias the next real
        // element's arena entry.
        let commented = facts("[1, /* note */ 2]");
        arena_children_are_exclusive(&commented);
        assert_eq!(
            scalar_kinds(&commented),
            vec![
                ConfigurationScalarKind::Integer,
                ConfigurationScalarKind::Integer
            ],
            "{commented:#?}"
        );
        let indexes: Vec<_> = commented
            .facts()
            .iter()
            .filter_map(
                |fact| match fact.route().segments().last().map(|s| s.selector()) {
                    Some(ConfigurationRouteSelector::Index(index)) => Some(*index),
                    _ => None,
                },
            )
            .collect();
        assert_eq!(indexes, vec![0, 1], "{commented:#?}");
    }

    #[test]
    fn an_empty_authored_key_is_a_member_rather_than_a_lost_document() {
        // `{"": ...}` occurs in released JSON configuration (for example
        // SchemaStore's cloudify.json and bun.lock.json); the model must hold
        // it instead of discarding every fact in the file.
        let document = facts(r#"{"": 0, "a": 1}"#);
        assert!(document.completeness().is_complete(), "{document:#?}");
        arena_children_are_exclusive(&document);
        assert_eq!(member_keys(&document), vec!["", "a"], "{document:#?}");
        let ids: Vec<_> = document
            .facts()
            .iter()
            .filter(|fact| matches!(fact.kind(), ConfigurationNodeKind::Member { .. }))
            .map(|fact| fact.stable_id(ConfigurationFormat::Json))
            .collect();
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn json_scalar_kinds_and_exact_ranges_follow_the_authored_document() {
        let source = r#"{"s":"t","b":true,"i":-7,"d":1.5e2,"n":null,"nested":{"list":[0,"x"]}}"#;
        let document = facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(
            scalar_kinds(&document),
            vec![
                ConfigurationScalarKind::String,
                ConfigurationScalarKind::Boolean,
                ConfigurationScalarKind::Integer,
                ConfigurationScalarKind::Decimal,
                ConfigurationScalarKind::Null,
                ConfigurationScalarKind::Integer,
                ConfigurationScalarKind::String,
            ],
            "{document:#?}"
        );
        for fact in document.facts() {
            assert!(source.is_char_boundary(fact.evidence().start_byte()));
            assert!(source.is_char_boundary(fact.evidence().end_byte()));
            if let ConfigurationNodeKind::Member { key, .. } = fact.kind() {
                // The authored key evidence is the quoted token, and decoding
                // it reproduces the member's key text exactly.
                let token = &source[key.evidence().start_byte()..key.evidence().end_byte()];
                assert_eq!(
                    serde_json::from_str::<String>(token).expect("authored key token"),
                    key.text()
                );
            }
        }
    }

    #[test]
    fn grammar_tolerated_scalars_are_typed_rather_than_clean() {
        // The grammar accepts a missing fraction, a truncated escape, and a
        // raw control character; JSON does not. Each keeps its authored fact
        // and adds exact recovery evidence.
        for source in [r#"{"a":1.}"#, r#"{"a":"\u"}"#, "{\"a\":\"x\ty\"}"] {
            let document = facts(source);
            assert_eq!(
                recovery_reasons(&document),
                vec![ConfigurationRecoveryReason::UnsupportedScalar],
                "{source}: {document:#?}"
            );
            assert_eq!(
                scalar_kinds(&document),
                vec![ConfigurationScalarKind::Opaque],
                "{source}: {document:#?}"
            );
            arena_children_are_exclusive(&document);
        }
        // A number outside f64 range is still authored JSON syntax.
        assert!(facts(r#"{"a":1e400}"#).completeness().is_complete());
    }

    #[test]
    fn json_document_root_cardinality_is_typed() {
        for source in ["", "   \n", "{}{}", "[] []"] {
            let document = facts(source);
            assert_eq!(
                recovery_reasons(&document),
                vec![ConfigurationRecoveryReason::MalformedSyntax],
                "{source:?}: {document:#?}"
            );
        }
        // A comment is malformed JSON, but never a second top-level value.
        let document = facts("{\"a\":1} // trailing");
        assert!(!document.completeness().is_complete());
        assert_eq!(member_keys(&document), vec!["a"]);
    }

    #[test]
    fn json_feature_semantics_are_all_not_applicable() {
        let document = facts(r#"{"a":{"b":[1]}}"#);
        let features = document.features();
        for state in [
            features.anchors(),
            features.aliases(),
            features.includes(),
            features.interpolation(),
            features.format_merge(),
        ] {
            assert!(
                matches!(state, ConfigurationFeatureState::NotApplicable),
                "{features:#?}"
            );
        }
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

    #[test]
    fn toml_table_member_has_authored_key_and_scalar_evidence() {
        let source = "[server]\nhost = \"example\"\n";
        let ConfigurationIngestionOutcome::Facts(document) =
            ingest_configuration_document(Path::new("config.toml"), source.as_bytes())
        else {
            panic!("TOML adapter must return facts")
        };
        assert!(document.completeness().is_complete());
        let member = document
            .facts()
            .iter()
            .find(|fact| {
                matches!(
                    fact.kind(), ConfigurationNodeKind::Member { key, .. } if key.text() == "host"
                )
            })
            .expect("host member");
        let ConfigurationNodeKind::Member {
            key,
            value: Some(value),
            ..
        } = member.kind()
        else {
            unreachable!()
        };
        assert_eq!(
            &source[key.evidence().start_byte()..key.evidence().end_byte()],
            "host"
        );
        let value = document.fact(*value).unwrap();
        assert!(matches!(
            value.kind(),
            ConfigurationNodeKind::Scalar {
                scalar_kind: ConfigurationScalarKind::String
            }
        ));
        assert_eq!(
            &source[value.evidence().start_byte()..value.evidence().end_byte()],
            "\"example\""
        );
    }
}
