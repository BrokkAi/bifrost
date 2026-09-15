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
use std::sync::{Mutex, PoisonError};
use toml_edit::{Array, ArrayOfTables, ImDocument, Item, Key, TableLike, Value};
use tree_sitter::{Language, Node, Parser, Tree};

// Version 3: brokk-tree-sitter-json accepts positive exponent signs and emits
// recoverable syntax for whitespace outside RFC 8259's four-character set.
const JSON_ADAPTER_SCHEMA_VERSION: u32 = 3;
const PROPERTIES_ADAPTER_SCHEMA_VERSION: u32 = 1;
const TOML_ADAPTER_SCHEMA_VERSION: u32 = 1;
const XML_ADAPTER_SCHEMA_VERSION: u32 = 1;
const YAML_ADAPTER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationIngestionOutcome {
    /// Boxed because a fact arena with six capability axes is several times
    /// the size of the other outcomes; the query layer moves it into an `Arc`
    /// once per document.
    Facts(Box<ConfigurationDocumentFacts>),
    Unsupported {
        format: Option<ConfigurationFormat>,
    },
    Incomplete {
        reason: ConfigurationIngestionError,
    },
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
        ConfigurationFormat::Properties => ingest_properties(source),
        ConfigurationFormat::Toml => ingest_toml(source),
        ConfigurationFormat::Xml => ingest_xml(source),
        ConfigurationFormat::Yaml => ingest_yaml(source),
    };
    match result {
        Ok(facts) => ConfigurationIngestionOutcome::Facts(Box::new(facts)),
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
    grammar_adapter_epoch(
        b"bifrost-configuration-json-adapter\n",
        JSON_ADAPTER_SCHEMA_VERSION,
        tree_sitter_json::GRAMMAR_VERSION.as_bytes(),
        &tree_sitter_json::LANGUAGE.into(),
    )
}

/// Cache compatibility identity for the Java `.properties` adapter and its
/// live grammar.
pub fn properties_configuration_adapter_epoch() -> String {
    grammar_adapter_epoch(
        b"bifrost-configuration-properties-adapter\n",
        PROPERTIES_ADAPTER_SCHEMA_VERSION,
        b"tree-sitter-properties-0.3.0",
        &tree_sitter_properties::LANGUAGE.into(),
    )
}

/// Cache compatibility identity for the YAML adapter and its live grammar.
pub fn yaml_configuration_adapter_epoch() -> String {
    grammar_adapter_epoch(
        b"bifrost-configuration-yaml-adapter\n",
        YAML_ADAPTER_SCHEMA_VERSION,
        b"tree-sitter-yaml-0.7.2",
        &tree_sitter_yaml::LANGUAGE.into(),
    )
}

/// The digest of an adapter's schema revision plus the fingerprint of the
/// tree-sitter grammar it walks: every node kind and field name the grammar
/// can produce, so a grammar upgrade rotates the epoch even when the adapter
/// source is unchanged.
fn grammar_adapter_epoch(
    domain: &[u8],
    schema_version: u32,
    grammar_identity: &[u8],
    language: &Language,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(schema_version.to_le_bytes());
    // Lexer-only grammar changes do not necessarily move node kinds, fields,
    // or ABI. Include the published grammar identity explicitly so a crate
    // update cannot reuse facts produced by different parser tables.
    hasher.update(grammar_identity);
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

/// Parse one document with a tree-sitter grammar.
fn parse_tree(
    language: &Language,
    grammar: &str,
    source: &str,
) -> Result<Tree, ConfigurationIngestionError> {
    let mut parser = Parser::new();
    parser.set_language(language).map_err(|error| {
        ConfigurationIngestionError::ParserUnavailable(format!(
            "failed to load {grammar} grammar: {error}"
        ))
    })?;
    parser.parse(source, None).ok_or_else(|| {
        ConfigurationIngestionError::ParserUnavailable(format!(
            "{grammar} parser did not return a tree"
        ))
    })
}

fn ingest_json(source: &str) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let tree = parse_tree(&tree_sitter_json::LANGUAGE.into(), "JSON", source)?;
    let root = tree.root_node();
    let document_range = source_range(root)?;
    let mut pending = vec![PendingFact {
        parent: None,
        route: ConfigurationRoute::root(),
        range: document_range,
        kind: PendingKind::Document(None),
    }];
    // JSON has no comments, so a grammar `comment` extra is malformed syntax
    // alongside the parser's own error and missing nodes.
    let mut recoveries = collect_recoveries(root, |node| {
        node.is_error() || node.is_missing() || node.kind() == "comment"
    })?;
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

fn token_text<'source>(
    source: &'source str,
    node: Node<'_>,
) -> Result<&'source str, ConfigurationIngestionError> {
    node.utf8_text(source.as_bytes()).map_err(|_| {
        ConfigurationIngestionError::InvalidFactModel("tree-sitter token range is not UTF-8".into())
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
    let text = token_text(source, node)?;
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
    if json_token_is_valid(token_text(source, node)?) {
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
    let token = token_text(source, node)?;
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
        authored.push_str(token_text(source, child)?);
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

/// Malformed-syntax recovery evidence for every node of the tree that the
/// grammar-specific predicate names, walked with an explicit stack.
fn collect_recoveries(
    root: Node<'_>,
    is_malformed: impl Fn(Node<'_>) -> bool,
) -> Result<Vec<ConfigurationRecovery>, ConfigurationIngestionError> {
    let mut recoveries = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_malformed(node) {
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

/// `tree-sitter-properties` 0.3.0 keeps its external scanner's one-bit
/// end-of-input state in a C static (`static bool reached_eof` in the crate's
/// `src/scanner.c`) rather than in the scanner payload. tree-sitter rewrites
/// that state from the parse's own serialised buffer before every external
/// scan, so one parse at a time is correct, but parses on different threads
/// interleave between the rewrite and the read: at eight concurrent parsers
/// the lexer stops terminating. Every parse holds this lock until the grammar
/// moves the flag into its payload.
static PROPERTIES_PARSE_LOCK: Mutex<()> = Mutex::new(());

/// Ingest a Java `.properties` document through the tree-sitter-properties
/// grammar.
///
/// The grammar's `file` is a sequence of `property` and `comment` lines. A
/// `property` is a `key`, an optional `=` or `:` separator, and an optional
/// `value`; a key stops at the first unescaped separator or whitespace, and a
/// value runs to the end of its logical line, across `\`-continued physical
/// lines. Every backslash sequence the format defines (`\uXXXX`, `\t`, `\n`,
/// `\r`, `\f`, and `\` before any other character) is an `escape` token, and
/// a `${...}` placeholder inside a value is a `substitution` node, so no byte
/// of a key or value is interpreted outside the grammar's own tokens.
///
/// The format is flat: every logical line is one member of the root object
/// with role `Property`, its route is the one authored key with a same-key
/// occurrence ordinal, and a dotted key stays one authored name because the
/// shared contract defines no structural dotted expansion. Every value is a
/// string; the format has no other scalar kind. The format itself neither
/// includes other files nor interpolates, so a placeholder is recorded as
/// unresolved interpolation evidence and never expanded.
fn ingest_properties(
    source: &str,
) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let tree = {
        let _parse = PROPERTIES_PARSE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        parse_tree(
            &tree_sitter_properties::LANGUAGE.into(),
            "Java properties",
            source,
        )?
    };
    let root = tree.root_node();
    // The grammar skips a byte-order mark, so the parse tree can start after
    // byte zero; the document and its root object are still the whole buffer.
    let document_range = ConfigurationSourceRange::new(0, source.len()).map_err(model_error)?;
    let mut pending = vec![
        PendingFact {
            parent: None,
            route: ConfigurationRoute::root(),
            range: document_range,
            kind: PendingKind::Document(Some(1)),
        },
        PendingFact {
            parent: Some(0),
            route: ConfigurationRoute::root(),
            range: document_range,
            kind: PendingKind::Object(Vec::new()),
        },
    ];
    let mut recoveries = collect_recoveries(root, |node| node.is_error() || node.is_missing())?;
    let mut occurrences = HashMap::<String, usize>::new();
    let mut interpolation = Vec::new();
    let mut cursor = root.walk();
    for line in root.named_children(&mut cursor) {
        match line.kind() {
            "property" => add_property(
                source,
                line,
                &mut pending,
                &mut occurrences,
                &mut recoveries,
                &mut interpolation,
            )?,
            "comment" => {
                if let Some(range) = bare_carriage_return(source, line, &[])? {
                    recoveries.push(ConfigurationRecovery::new(
                        ConfigurationRecoveryReason::ParserLimit,
                        range,
                    ));
                }
            }
            // Error nodes are already recovery evidence.
            _ => {}
        }
    }
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
    let interpolation = if interpolation.is_empty() {
        ConfigurationFeatureState::NotApplicable
    } else {
        ConfigurationFeatureState::Unresolved {
            evidence: interpolation,
        }
    };
    ConfigurationDocumentFacts::new(
        ConfigurationFormat::Properties,
        finalize(pending)?,
        completeness,
        ConfigurationFeatureSemantics::new(
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
            interpolation,
            ConfigurationFeatureState::NotApplicable,
            ConfigurationFeatureState::NotApplicable,
        ),
    )
    .map_err(model_error)
}

/// Map one grammar `property` line onto a `Property` member of the root
/// object and its string value.
///
/// The grammar is a superset of the format in four places where its tokens
/// do not follow `java.util.Properties`, and a line the grammar tokenized
/// differently from the format is typed `ParserLimit` recovery evidence with
/// no fact, because the key the grammar produced would be a false fact: an
/// unescaped separator as the first key byte (the format reads an empty key,
/// the grammar cannot produce one); a value that starts at the key's own end
/// (the key continued across a line break, which the grammar only joins
/// inside a value); a `[...]` index that swallowed a separator, whitespace,
/// or backslash the format would have honoured; and a bare carriage return
/// inside a token (the format ends a line there, the grammar does not).
fn add_property(
    source: &str,
    property: Node<'_>,
    pending: &mut Vec<PendingFact>,
    occurrences: &mut HashMap<String, usize>,
    recoveries: &mut Vec<ConfigurationRecovery>,
    interpolation: &mut Vec<ConfigurationSourceRange>,
) -> Result<(), ConfigurationIngestionError> {
    let property_range = source_range(property)?;
    let mut key = None;
    let mut value = None;
    let mut cursor = property.walk();
    for child in property.named_children(&mut cursor) {
        match child.kind() {
            "key" => key = Some(child),
            "value" => value = Some(child),
            _ => {}
        }
    }
    let Some(key) = key.filter(|key| key.end_byte() > key.start_byte()) else {
        // The grammar's `property` rule begins with a mandatory, non-empty
        // key, so only error recovery reaches here, and that error is
        // already recorded.
        assert!(
            property.has_error(),
            "a properties line without a key must carry the parser's own error: {property:?}"
        );
        return Ok(());
    };
    let key_range = source_range(key)?;
    let first_key_byte = source.as_bytes()[key_range.start_byte()];
    let mut key_cursor = key.walk();
    let first_escape_starts_key = key
        .named_children(&mut key_cursor)
        .next()
        .is_some_and(|child| child.kind() == "escape" && child.start_byte() == key.start_byte());
    let empty_key = matches!(first_key_byte, b'=' | b':') && !first_escape_starts_key;
    let continued_key = value.is_some_and(|value| value.start_byte() == key.end_byte());
    let index_swallowed_terminator = key.named_children(&mut key_cursor).any(|child| {
        child.kind() == "index"
            && child.byte_range().any(|offset| {
                matches!(
                    source.as_bytes()[offset],
                    b'\\' | b'=' | b':' | b' ' | b'\t' | b'\x0c'
                )
            })
    });
    let mut bare_cr = bare_carriage_return(source, key, &[])?;
    if let (None, Some(value)) = (bare_cr, value) {
        bare_cr = bare_carriage_return(source, value, &value_continuations(value))?;
    }
    if empty_key || continued_key || index_swallowed_terminator || bare_cr.is_some() {
        recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::ParserLimit,
            bare_cr.unwrap_or(property_range),
        ));
        return Ok(());
    }

    let key_text = decode_properties_key(source, key, recoveries)?;
    let occurrence = occurrences.entry(key_text.clone()).or_default();
    *occurrence += 1;
    let route = ConfigurationRoute::root().child(ConfigurationRouteSegment::key(
        key_text.clone(),
        *occurrence,
        key_range,
    ));
    let member = pending.len();
    attach(&mut pending[1].kind, Link::ObjectMember, member)?;
    pending.push(PendingFact {
        parent: Some(1),
        route: route.clone(),
        range: property_range,
        kind: PendingKind::Member {
            role: ConfigurationMemberRole::Property,
            key: ConfigurationKey::new(key_text, key_range),
            value: None,
        },
    });
    // A line with no value token still authors the empty string as its
    // value, at the point where the value would have started.
    let value_range = match value {
        Some(value) => {
            inspect_properties_value(source, value, recoveries, interpolation)?;
            source_range(value)?
        }
        None => ConfigurationSourceRange::new(property_range.end_byte(), property_range.end_byte())
            .map_err(model_error)?,
    };
    let scalar = pending.len();
    attach(&mut pending[member].kind, Link::MemberValue, scalar)?;
    pending.push(PendingFact {
        parent: Some(member),
        route,
        range: value_range,
        kind: PendingKind::Scalar(ConfigurationScalarKind::String),
    });
    Ok(())
}

/// The end offsets of the `\` continuation tokens of a value: the grammar
/// honours a carriage return as a line terminator there and nowhere else.
fn value_continuations(value: Node<'_>) -> Vec<usize> {
    let mut cursor = value.walk();
    value
        .children(&mut cursor)
        .filter(|child| !child.is_named() && child.kind() == "\\")
        .map(|child| child.end_byte())
        .collect()
}

/// The first carriage return inside a token that the format reads as a line
/// terminator but the grammar read as token content: one not followed by a
/// line feed and not the terminator of a `\` continuation.
fn bare_carriage_return(
    source: &str,
    token: Node<'_>,
    continuation_ends: &[usize],
) -> Result<Option<ConfigurationSourceRange>, ConfigurationIngestionError> {
    let bytes = source.as_bytes();
    for offset in token.byte_range() {
        if bytes[offset] == b'\r'
            && bytes.get(offset + 1) != Some(&b'\n')
            && !continuation_ends.contains(&offset)
        {
            return ConfigurationSourceRange::new(offset, offset + 1)
                .map(Some)
                .map_err(model_error);
        }
    }
    Ok(None)
}

/// The authored key text, decoded the way `java.util.Properties` decodes it:
/// the bytes between the grammar's `escape` tokens are literal, and each
/// escape token yields the UTF-16 code unit or character it names. The units
/// are assembled as UTF-16 because a `\uXXXX` pair spells one supplementary
/// character across two tokens.
///
/// A `\u` escape that the grammar could not complete with four hex digits is
/// the format's "Malformed \uxxxx encoding" error: typed malformed evidence
/// at the token, with the authored bytes kept as the key text. A decoded
/// unpaired surrogate is a key Rust cannot hold exactly, so it is typed
/// unsupported evidence with the lossy text.
fn decode_properties_key(
    source: &str,
    key: Node<'_>,
    recoveries: &mut Vec<ConfigurationRecovery>,
) -> Result<String, ConfigurationIngestionError> {
    let mut units = Vec::<u16>::new();
    let mut literal_start = key.start_byte();
    let mut cursor = key.walk();
    for child in key.named_children(&mut cursor) {
        if child.kind() != "escape" {
            // An `index` token is literal key text; an error node's bytes are
            // authored text whose recovery is already recorded.
            continue;
        }
        units.extend(source[literal_start..child.start_byte()].encode_utf16());
        let token = token_text(source, child)?;
        if properties_escape_is_malformed(token) {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::MalformedSyntax,
                source_range(child)?,
            ));
            units.extend(token.encode_utf16());
        } else {
            push_properties_escape(token, &mut units);
        }
        literal_start = child.end_byte();
    }
    units.extend(source[literal_start..key.end_byte()].encode_utf16());
    match String::from_utf16(&units) {
        Ok(text) => Ok(text),
        Err(_) => {
            recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::UnsupportedScalar,
                source_range(key)?,
            ));
            Ok(String::from_utf16_lossy(&units))
        }
    }
}

/// The two-byte `\u` token the grammar emits when fewer than four hex digits
/// follow: the format's "Malformed \uxxxx encoding" error, and the only
/// escape it rejects.
fn properties_escape_is_malformed(token: &str) -> bool {
    token == "\\u"
}

/// Decode one well-formed grammar `escape` token into UTF-16 code units, the
/// way `java.util.Properties.loadConvert` does.
fn push_properties_escape(token: &str, units: &mut Vec<u16>) {
    debug_assert!(!properties_escape_is_malformed(token));
    let mut characters = token.chars();
    assert_eq!(
        characters.next(),
        Some('\\'),
        "a properties escape token begins with a backslash: {token:?}"
    );
    let Some(escaped) = characters.next() else {
        unreachable!("a properties escape token names the character it escapes: {token:?}");
    };
    if escaped == 'u' {
        let Ok(unit) = u16::from_str_radix(characters.as_str(), 16) else {
            unreachable!("the grammar only completes a \\u escape with four hex digits: {token:?}");
        };
        units.push(unit);
        return;
    }
    let decoded = match escaped {
        't' => '\t',
        'n' => '\n',
        'r' => '\r',
        'f' => '\x0c',
        other => other,
    };
    units.extend(decoded.encode_utf16(&mut [0; 2]).iter());
}

/// Walk a value subtree for the evidence it carries: a `\u` escape the
/// grammar could not complete is typed malformed, and each outermost
/// `${...}` placeholder is unresolved interpolation evidence. The walk uses
/// an explicit stack that carries whether a node is inside a placeholder,
/// because placeholders nest without bound and asking tree-sitter for a
/// node's parent costs the node's depth.
fn inspect_properties_value(
    source: &str,
    value: Node<'_>,
    recoveries: &mut Vec<ConfigurationRecovery>,
    interpolation: &mut Vec<ConfigurationSourceRange>,
) -> Result<(), ConfigurationIngestionError> {
    let mut stack = vec![(value, false)];
    while let Some((node, inside_placeholder)) = stack.pop() {
        let mut inside_placeholder = inside_placeholder;
        match node.kind() {
            "escape" => {
                if properties_escape_is_malformed(token_text(source, node)?) {
                    recoveries.push(ConfigurationRecovery::new(
                        ConfigurationRecoveryReason::MalformedSyntax,
                        source_range(node)?,
                    ));
                }
            }
            "substitution" => {
                if !inside_placeholder {
                    interpolation.push(source_range(node)?);
                }
                inside_placeholder = true;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node
            .named_children(&mut cursor)
            .map(|child| (child, inside_placeholder))
            .collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(())
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

/// One YAML subtree waiting to become a fact.
///
/// The adapter walks the tree-sitter tree with this explicit stack rather
/// than with Rust recursion, so a deeply nested authored document cannot
/// exhaust the thread stack.
struct YamlWork<'tree> {
    node: YamlNode<'tree>,
    parent: usize,
    link: Link,
    route: ConfigurationRoute,
}

enum YamlNode<'tree> {
    /// A `block_node` or `flow_node`: optional anchor and tag properties
    /// around one content node, or around nothing at all when only the
    /// properties were authored (`key: !!str`).
    Node(Node<'tree>),
    /// A node the author left implicit and the grammar therefore never
    /// produced: `key:` with nothing after the colon, `-` with nothing after
    /// the dash, or `---` opening an otherwise empty document. YAML resolves
    /// an empty node to null; the evidence is the empty range at the position
    /// the value would have occupied.
    Empty(ConfigurationSourceRange),
    /// One mapping entry: a `block_mapping_pair`, a `flow_pair`, or a bare
    /// `flow_node` inside a flow mapping, which is a key with an empty value
    /// (`{c, d: 1}`). `entry` is the node whose range the member covers.
    Entry {
        entry: Node<'tree>,
        value: Option<Node<'tree>>,
    },
    /// A `flow_pair` used directly as a sequence item: `[k: v]` is a sequence
    /// whose element is a one-entry mapping.
    SinglePairMapping(Node<'tree>),
}

/// The three parts the grammar wraps around every authored YAML node.
struct YamlNodeParts<'tree> {
    anchor: Option<Node<'tree>>,
    tag: Option<Node<'tree>>,
    content: Option<Node<'tree>>,
}

fn yaml_node_parts(node: Node<'_>) -> YamlNodeParts<'_> {
    let mut parts = YamlNodeParts {
        anchor: None,
        tag: None,
        content: None,
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "anchor" => parts.anchor = Some(child),
            "tag" => parts.tag = Some(child),
            "comment" => {}
            _ if child.is_error() || child.is_missing() => {}
            _ => parts.content = Some(child),
        }
    }
    parts
}

/// What the grammar found inside a node, as the shape a tag must agree with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum YamlShape {
    Scalar,
    Sequence,
    Mapping,
    Alias,
}

enum YamlTagResolution {
    /// A core-schema scalar tag on a scalar: the kind it names wins over the
    /// grammar's plain-scalar resolution (`!!str 123` is a string).
    Scalar(ConfigurationScalarKind),
    /// `!!seq` on a sequence or `!!map` on a mapping: the shape was already
    /// what the tag names.
    Collection,
    /// A local tag (`!Ref`), a named-handle tag (`!e!foo`), a non-core
    /// `tag:yaml.org` type (`!!binary`, `!!timestamp`), or a core tag on a
    /// shape it cannot type. The application that consumes the document
    /// defines what the value means, so the fact layer leaves it unresolved.
    Unresolved,
}

/// YAML 1.2 core-schema tags, in their shorthand and verbatim spellings.
/// The grammar emits a tag as one opaque token, so the whole token is the
/// structure available; each entry is compared as a complete token.
const YAML_CORE_SCALAR_TAGS: [(&str, &str, ConfigurationScalarKind); 5] = [
    (
        "!!str",
        "!<tag:yaml.org,2002:str>",
        ConfigurationScalarKind::String,
    ),
    (
        "!!int",
        "!<tag:yaml.org,2002:int>",
        ConfigurationScalarKind::Integer,
    ),
    (
        "!!float",
        "!<tag:yaml.org,2002:float>",
        ConfigurationScalarKind::Decimal,
    ),
    (
        "!!bool",
        "!<tag:yaml.org,2002:bool>",
        ConfigurationScalarKind::Boolean,
    ),
    (
        "!!null",
        "!<tag:yaml.org,2002:null>",
        ConfigurationScalarKind::Null,
    ),
];

/// The prefix YAML binds to the `!!` handle unless a `%TAG` directive rebinds it.
const YAML_NAMESPACE_PREFIX: &str = "tag:yaml.org,2002:";

/// `secondary_handle_is_yaml` is false when the document's `%TAG !! prefix`
/// directive rebinds the `!!` handle away from the YAML namespace, in which
/// case `!!int` is an application tag and only the verbatim spelling names
/// the core type.
fn yaml_tag_resolution(
    tag: &str,
    shape: YamlShape,
    secondary_handle_is_yaml: bool,
) -> YamlTagResolution {
    let names = |shorthand: &str, verbatim: &str| {
        (secondary_handle_is_yaml && tag == shorthand) || tag == verbatim
    };
    match shape {
        YamlShape::Scalar => YAML_CORE_SCALAR_TAGS
            .iter()
            .find(|(shorthand, verbatim, _)| names(shorthand, verbatim))
            .map_or(YamlTagResolution::Unresolved, |(_, _, kind)| {
                YamlTagResolution::Scalar(*kind)
            }),
        YamlShape::Sequence if names("!!seq", "!<tag:yaml.org,2002:seq>") => {
            YamlTagResolution::Collection
        }
        YamlShape::Mapping if names("!!map", "!<tag:yaml.org,2002:map>") => {
            YamlTagResolution::Collection
        }
        YamlShape::Sequence | YamlShape::Mapping | YamlShape::Alias => {
            YamlTagResolution::Unresolved
        }
    }
}

/// Exact ranges of every capability construct the document authors, gathered
/// during the walk and folded into [`ConfigurationFeatureSemantics`] once the
/// arena is complete.
#[derive(Default)]
struct YamlFeatureEvidence {
    anchors: Vec<ConfigurationSourceRange>,
    aliases: Vec<ConfigurationSourceRange>,
    merge_keys: Vec<ConfigurationSourceRange>,
    resolved_tags: Vec<ConfigurationSourceRange>,
    unresolved_tags: Vec<ConfigurationSourceRange>,
}

impl YamlFeatureEvidence {
    fn into_semantics(self) -> ConfigurationFeatureSemantics {
        fn authored(evidence: Vec<ConfigurationSourceRange>) -> ConfigurationFeatureState {
            if evidence.is_empty() {
                ConfigurationFeatureState::NotApplicable
            } else {
                ConfigurationFeatureState::Authored { evidence }
            }
        }
        fn unresolved(evidence: Vec<ConfigurationSourceRange>) -> ConfigurationFeatureState {
            if evidence.is_empty() {
                ConfigurationFeatureState::NotApplicable
            } else {
                ConfigurationFeatureState::Unresolved { evidence }
            }
        }
        let tags = if self.unresolved_tags.is_empty() {
            authored(self.resolved_tags)
        } else {
            ConfigurationFeatureState::Unresolved {
                evidence: self.unresolved_tags,
            }
        };
        ConfigurationFeatureSemantics::new(
            // An anchor labels a node the arena represents in full.
            authored(self.anchors),
            // An alias is authored as a reference and never expanded here.
            unresolved(self.aliases),
            // YAML defines no include construct; an `!include`-style local tag
            // is an unresolved tag, because its meaning is the consuming
            // application's, not the format's.
            ConfigurationFeatureState::NotApplicable,
            // YAML defines no interpolation; `${VAR}` inside a scalar is an
            // application convention that the effective-configuration layer
            // interprets with knowledge of the consuming framework.
            ConfigurationFeatureState::NotApplicable,
            // A `<<` merge key is authored, and the merge is not applied here.
            unresolved(self.merge_keys),
            tags,
        )
    }
}

struct YamlIngestion<'source> {
    source: &'source str,
    pending: Vec<PendingFact>,
    recoveries: Vec<ConfigurationRecovery>,
    features: YamlFeatureEvidence,
    /// Whether `!!` still means the YAML namespace in the ingested document.
    secondary_handle_is_yaml: bool,
}

fn ingest_yaml(source: &str) -> Result<ConfigurationDocumentFacts, ConfigurationIngestionError> {
    let tree = parse_tree(&tree_sitter_yaml::LANGUAGE.into(), "YAML", source)?;
    let root = tree.root_node();
    // A YAML stream is its whole buffer; the grammar's stream node shrinks to
    // the authored tokens and is empty for a blank file.
    let document_range = ConfigurationSourceRange::new(0, source.len()).map_err(model_error)?;
    let mut ingestion = YamlIngestion {
        source,
        pending: vec![PendingFact {
            parent: None,
            route: ConfigurationRoute::root(),
            range: document_range,
            kind: PendingKind::Document(None),
        }],
        // Comments are authored YAML, so only recovered and missing nodes are
        // malformed syntax.
        recoveries: collect_recoveries(root, |node| node.is_error() || node.is_missing())?,
        features: YamlFeatureEvidence::default(),
        secondary_handle_is_yaml: true,
    };
    // On a fatal error the grammar stops consuming input; whatever follows the
    // recovered root was never parsed and must not read as a clean absence.
    if root.end_byte() < source.len() && !source[root.end_byte()..].trim().is_empty() {
        ingestion.recoveries.push(ConfigurationRecovery::new(
            ConfigurationRecoveryReason::MalformedSyntax,
            ConfigurationSourceRange::new(root.end_byte(), source.len()).map_err(model_error)?,
        ));
    }
    if root.kind() == "stream" {
        let mut cursor = root.walk();
        let mut documents = root
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "document");
        match documents.next() {
            Some(first) => {
                ingestion.secondary_handle_is_yaml = yaml_secondary_handle_is_yaml(source, first)?;
                let mut stack = vec![YamlWork {
                    node: yaml_document_node(first),
                    parent: 0,
                    link: Link::DocumentRoot,
                    route: ConfigurationRoute::root(),
                }];
                while let Some(work) = stack.pop() {
                    ingestion.add(work, &mut stack)?;
                }
            }
            // An empty stream is well-formed YAML with no document at all, so
            // there is nothing the single-root model can present as its root.
            None => ingestion.recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::UnsupportedConstruct,
                document_range,
            )),
        }
        // The fact model roots one document. Every later document in the
        // stream is well-formed authored evidence it cannot represent, so the
        // first document's facts are retained and the rest are a typed gap.
        for extra in documents {
            ingestion.recoveries.push(ConfigurationRecovery::new(
                ConfigurationRecoveryReason::UnsupportedConstruct,
                source_range(extra)?,
            ));
        }
    } else {
        assert!(
            root.is_error(),
            "tree-sitter-yaml roots are streams or recovered errors, not {}",
            root.kind()
        );
    }
    let YamlIngestion {
        pending,
        mut recoveries,
        features,
        ..
    } = ingestion;
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
        ConfigurationFormat::Yaml,
        finalize(pending)?,
        completeness,
        features.into_semantics(),
    )
    .map_err(model_error)
}

/// Whether the document's `%TAG` directives leave `!!` bound to the YAML
/// namespace. The grammar exposes each directive's handle and prefix as their
/// own nodes, so the check compares whole tokens.
fn yaml_secondary_handle_is_yaml(
    source: &str,
    document: Node<'_>,
) -> Result<bool, ConfigurationIngestionError> {
    let mut cursor = document.walk();
    for directive in document
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "tag_directive")
    {
        let mut parts = directive.walk();
        let mut handle = None;
        let mut prefix = None;
        for part in directive.named_children(&mut parts) {
            match part.kind() {
                "tag_handle" => handle = Some(token_text(source, part)?),
                "tag_prefix" => prefix = Some(token_text(source, part)?),
                _ => {}
            }
        }
        if handle == Some("!!") && prefix != Some(YAML_NAMESPACE_PREFIX) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The node a `document` holds, or the empty node an explicit `---` opens.
fn yaml_document_node(document: Node<'_>) -> YamlNode<'_> {
    let mut cursor = document.walk();
    document
        .named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "block_node" | "flow_node"))
        .map_or_else(
            || YamlNode::Empty(empty_range_at(document.end_byte())),
            YamlNode::Node,
        )
}

fn empty_range_at(position: usize) -> ConfigurationSourceRange {
    ConfigurationSourceRange::new(position, position)
        .expect("an empty range at one position is always ordered")
}

impl YamlIngestion<'_> {
    /// Map one work item onto the shared fact model.
    ///
    /// As in the JSON adapter, the parent link is recorded only once the item
    /// maps to a fact, so a recovered subtree contributes typed evidence and
    /// no dangling child id.
    fn add<'tree>(
        &mut self,
        work: YamlWork<'tree>,
        stack: &mut Vec<YamlWork<'tree>>,
    ) -> Result<(), ConfigurationIngestionError> {
        let id = self.pending.len();
        let mut children = Vec::new();
        let (range, kind) = match work.node {
            YamlNode::Empty(range) => (range, PendingKind::Scalar(ConfigurationScalarKind::Null)),
            YamlNode::Node(node) => {
                let range = source_range(node)?;
                let parts = yaml_node_parts(node);
                if let Some(anchor) = parts.anchor {
                    self.features.anchors.push(source_range(anchor)?);
                }
                let shape = match parts.content.map(|content| content.kind()) {
                    Some("block_mapping" | "flow_mapping") => YamlShape::Mapping,
                    Some("block_sequence" | "flow_sequence") => YamlShape::Sequence,
                    Some("alias") => YamlShape::Alias,
                    // A node with only properties (`key: !!str`) is an empty
                    // scalar the tag types.
                    Some(_) | None => YamlShape::Scalar,
                };
                let tagged_kind = match parts.tag {
                    Some(tag) => {
                        let tag_range = source_range(tag)?;
                        match yaml_tag_resolution(
                            token_text(self.source, tag)?,
                            shape,
                            self.secondary_handle_is_yaml,
                        ) {
                            YamlTagResolution::Scalar(kind) => {
                                self.features.resolved_tags.push(tag_range);
                                Some(kind)
                            }
                            YamlTagResolution::Collection => {
                                self.features.resolved_tags.push(tag_range);
                                None
                            }
                            YamlTagResolution::Unresolved => {
                                self.features.unresolved_tags.push(tag_range);
                                Some(ConfigurationScalarKind::Opaque)
                            }
                        }
                    }
                    None => None,
                };
                let kind = match parts.content {
                    Some(content) if shape == YamlShape::Mapping => {
                        self.queue_mapping_entries(content, id, &work.route, &mut children)?;
                        PendingKind::Object(Vec::new())
                    }
                    Some(content) if shape == YamlShape::Sequence => {
                        self.queue_sequence_items(content, id, &work.route, &mut children)?;
                        PendingKind::Sequence(Vec::new())
                    }
                    Some(content) if shape == YamlShape::Alias => {
                        // The alias token is authored; the node it names is
                        // not expanded into this arena.
                        self.features.aliases.push(source_range(content)?);
                        PendingKind::Scalar(tagged_kind.unwrap_or(ConfigurationScalarKind::Opaque))
                    }
                    Some(content) => {
                        PendingKind::Scalar(tagged_kind.unwrap_or(yaml_scalar_kind(content)))
                    }
                    None => {
                        PendingKind::Scalar(tagged_kind.unwrap_or(ConfigurationScalarKind::Null))
                    }
                };
                (range, kind)
            }
            YamlNode::Entry { entry, value } => {
                // The mapping arm queues every entry with its own decoded key
                // segment, so the authored key never needs a second decode.
                let Some(segment) = work.route.segments().last() else {
                    unreachable!(
                        "a YAML mapping entry is only queued with its own key route segment"
                    );
                };
                let ConfigurationRouteSelector::Key { name, .. } = segment.selector() else {
                    unreachable!("a YAML mapping entry route segment is always an authored key");
                };
                let key = ConfigurationKey::new(name.clone(), segment.evidence());
                let entry_range = source_range(entry)?;
                children.push(YamlWork {
                    node: value.map_or_else(
                        || YamlNode::Empty(empty_range_at(entry_range.end_byte())),
                        YamlNode::Node,
                    ),
                    parent: id,
                    link: Link::MemberValue,
                    route: work.route.clone(),
                });
                (
                    entry_range,
                    PendingKind::Member {
                        // A YAML mapping is the same ordered key/value
                        // container a JSON object is; YAML is a superset of
                        // JSON and `{"a": 1}` is authored identically in both.
                        role: ConfigurationMemberRole::ObjectMember,
                        key,
                        value: None,
                    },
                )
            }
            YamlNode::SinglePairMapping(pair) => {
                let range = source_range(pair)?;
                let (key_text, key_range) =
                    self.yaml_key(pair.child_by_field_name("key"), range)?;
                children.push(YamlWork {
                    node: YamlNode::Entry {
                        entry: pair,
                        value: pair.child_by_field_name("value"),
                    },
                    parent: id,
                    link: Link::ObjectMember,
                    route: work
                        .route
                        .clone()
                        .child(ConfigurationRouteSegment::key(key_text, 1, key_range)),
                });
                (range, PendingKind::Object(Vec::new()))
            }
        };
        attach(&mut self.pending[work.parent].kind, work.link, id)?;
        self.pending.push(PendingFact {
            parent: Some(work.parent),
            route: work.route,
            range,
            kind,
        });
        // The stack is LIFO, so queueing in reverse keeps authored order.
        stack.extend(children.into_iter().rev());
        Ok(())
    }

    fn queue_mapping_entries<'tree>(
        &mut self,
        mapping: Node<'tree>,
        parent: usize,
        route: &ConfigurationRoute,
        children: &mut Vec<YamlWork<'tree>>,
    ) -> Result<(), ConfigurationIngestionError> {
        let mut occurrences = HashMap::<String, usize>::new();
        let mut cursor = mapping.walk();
        for child in mapping.named_children(&mut cursor) {
            let (entry, key, value) = match child.kind() {
                "block_mapping_pair" | "flow_pair" => (
                    child,
                    child.child_by_field_name("key"),
                    child.child_by_field_name("value"),
                ),
                // A bare node inside a flow mapping is a key whose value the
                // author left empty: `{c, d: 1}`.
                "flow_node" => (child, Some(child), None),
                // Comments are authored extras; recovered nodes were already
                // collected as malformed syntax.
                _ => continue,
            };
            let (key_text, key_range) = self.yaml_key(key, source_range(entry)?)?;
            let occurrence = occurrences.entry(key_text.clone()).or_default();
            *occurrence += 1;
            children.push(YamlWork {
                node: YamlNode::Entry { entry, value },
                parent,
                link: Link::ObjectMember,
                route: route.clone().child(ConfigurationRouteSegment::key(
                    key_text,
                    *occurrence,
                    key_range,
                )),
            });
        }
        Ok(())
    }

    fn queue_sequence_items<'tree>(
        &mut self,
        sequence: Node<'tree>,
        parent: usize,
        route: &ConfigurationRoute,
        children: &mut Vec<YamlWork<'tree>>,
    ) -> Result<(), ConfigurationIngestionError> {
        let mut cursor = sequence.walk();
        // Comments are grammar extras and hold no element position; every
        // other child occupies one, so a recovered element keeps the authored
        // indexes of the elements after it.
        for (index, child) in sequence
            .named_children(&mut cursor)
            .filter(|node| node.kind() != "comment")
            .enumerate()
        {
            let node = match child.kind() {
                // `- value`: the item is its node, or empty after the dash.
                "block_sequence_item" => {
                    let mut item_cursor = child.walk();
                    child
                        .named_children(&mut item_cursor)
                        .find(|node| matches!(node.kind(), "block_node" | "flow_node"))
                        .map_or_else(
                            || YamlNode::Empty(empty_range_at(child.end_byte())),
                            YamlNode::Node,
                        )
                }
                "flow_node" => YamlNode::Node(child),
                "flow_pair" => YamlNode::SinglePairMapping(child),
                _ => continue,
            };
            let range = match &node {
                YamlNode::Empty(range) => *range,
                YamlNode::Node(node) | YamlNode::SinglePairMapping(node) => source_range(*node)?,
                YamlNode::Entry { .. } => {
                    unreachable!("a sequence item is never queued as a mapping entry")
                }
            };
            children.push(YamlWork {
                node,
                parent,
                link: Link::SequenceItem,
                route: route
                    .clone()
                    .child(ConfigurationRouteSegment::index(index, range)),
            });
        }
        Ok(())
    }

    /// The authored text and exact range of one mapping key.
    ///
    /// A single-line plain scalar is its own text: it has no escapes, and the
    /// grammar's token already excludes the surrounding indicators. A quoted
    /// scalar, a block scalar, and the multi-line plain scalar only an
    /// explicit `? ` key can author are decoded by the maintained YAML parser,
    /// so escapes, doubled quotes, and line folding follow the specification
    /// rather than a local decoder; a token it rejects keeps its authored
    /// bytes as text and is typed recovery evidence. A plain null spelling
    /// (`~`, `null`) has no string value, so its spelling is its textual
    /// identity. An alias key keeps its authored `*name` and is unresolved
    /// alias state. A collection key keeps its authored bytes as text, and the
    /// structure inside it is an unsupported construct because the model's
    /// keys are text. A missing key (a pair the grammar recovered around) is
    /// the empty key at the entry's start.
    fn yaml_key(
        &mut self,
        key: Option<Node<'_>>,
        entry_range: ConfigurationSourceRange,
    ) -> Result<(String, ConfigurationSourceRange), ConfigurationIngestionError> {
        let Some(key) = key else {
            return Ok((String::new(), empty_range_at(entry_range.start_byte())));
        };
        let key_range = source_range(key)?;
        let parts = yaml_node_parts(key);
        if let Some(anchor) = parts.anchor {
            self.features.anchors.push(source_range(anchor)?);
        }
        let Some(content) = parts.content else {
            if let Some(tag) = parts.tag {
                self.record_tag(tag, YamlShape::Scalar)?;
            }
            return Ok((String::new(), key_range));
        };
        let text = match content.kind() {
            "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" | "block_scalar" => {
                let token = token_text(self.source, content)?;
                // The YAML 1.1 merge key is the plain scalar `<<`; the fact
                // layer records the entry and leaves the merge unapplied.
                if content.kind() == "plain_scalar" && token == "<<" {
                    self.features.merge_keys.push(key_range);
                }
                if let Some(tag) = parts.tag {
                    self.record_tag(tag, YamlShape::Scalar)?;
                }
                // A plain token is re-read only when it spans lines: out of
                // its context a single-line plain scalar ending in `:` would
                // read as a mapping, while its text is simply the token.
                let single_line_plain = content.kind() == "plain_scalar"
                    && content.start_position().row == content.end_position().row;
                let decoded = if single_line_plain {
                    Ok(token.to_owned())
                } else {
                    serde_saphyr::from_str::<String>(token)
                };
                match decoded {
                    Ok(text) => text,
                    Err(_) => {
                        self.recoveries.push(ConfigurationRecovery::new(
                            ConfigurationRecoveryReason::UnsupportedScalar,
                            key_range,
                        ));
                        token.to_owned()
                    }
                }
            }
            "alias" => {
                self.features.aliases.push(source_range(content)?);
                if let Some(tag) = parts.tag {
                    self.record_tag(tag, YamlShape::Alias)?;
                }
                token_text(self.source, content)?.to_owned()
            }
            "block_mapping" | "flow_mapping" | "block_sequence" | "flow_sequence" => {
                let shape = if content.kind().ends_with("mapping") {
                    YamlShape::Mapping
                } else {
                    YamlShape::Sequence
                };
                if let Some(tag) = parts.tag {
                    self.record_tag(tag, shape)?;
                }
                self.recoveries.push(ConfigurationRecovery::new(
                    ConfigurationRecoveryReason::UnsupportedConstruct,
                    key_range,
                ));
                token_text(self.source, content)?.to_owned()
            }
            other => {
                return Err(ConfigurationIngestionError::InvalidFactModel(format!(
                    "tree-sitter-yaml produced an unexpected key node {other:?}"
                )));
            }
        };
        Ok((text, key_range))
    }

    fn record_tag(
        &mut self,
        tag: Node<'_>,
        shape: YamlShape,
    ) -> Result<(), ConfigurationIngestionError> {
        let tag_range = source_range(tag)?;
        match yaml_tag_resolution(
            token_text(self.source, tag)?,
            shape,
            self.secondary_handle_is_yaml,
        ) {
            YamlTagResolution::Scalar(_) | YamlTagResolution::Collection => {
                self.features.resolved_tags.push(tag_range);
            }
            YamlTagResolution::Unresolved => self.features.unresolved_tags.push(tag_range),
        }
        Ok(())
    }
}

/// The scalar kind the grammar resolved for one content node.
///
/// A plain scalar carries its YAML 1.2 core-schema resolution as a typed
/// child, so `true` is a boolean, `~` is null, `0x1F` is an integer, and `yes`
/// is a string. Quoted and block scalars are always strings.
fn yaml_scalar_kind(content: Node<'_>) -> ConfigurationScalarKind {
    match content.kind() {
        "plain_scalar" => {
            let mut cursor = content.walk();
            let resolved = content
                .named_children(&mut cursor)
                .find(|child| child.kind().ends_with("_scalar"))
                .map(|child| child.kind());
            match resolved {
                Some("integer_scalar") => ConfigurationScalarKind::Integer,
                Some("float_scalar") => ConfigurationScalarKind::Decimal,
                Some("boolean_scalar") => ConfigurationScalarKind::Boolean,
                Some("null_scalar") => ConfigurationScalarKind::Null,
                Some("string_scalar") => ConfigurationScalarKind::String,
                // The grammar's optional legacy schema names timestamps; the
                // format-neutral registry does not, as with TOML date-times.
                Some("timestamp_scalar") => ConfigurationScalarKind::Opaque,
                Some(_) | None => ConfigurationScalarKind::Opaque,
            }
        }
        "single_quote_scalar" | "double_quote_scalar" | "block_scalar" => {
            ConfigurationScalarKind::String
        }
        _ => ConfigurationScalarKind::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn facts(source: &str) -> ConfigurationDocumentFacts {
        match ingest_configuration_document(Path::new("config.JSON"), source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => *facts,
            other => panic!("expected facts, got {other:?}"),
        }
    }

    fn xml_facts(source: &str) -> ConfigurationDocumentFacts {
        match ingest_configuration_document(Path::new("config.XML"), source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => *facts,
            other => panic!("expected XML facts, got {other:?}"),
        }
    }

    fn properties_facts(source: &str) -> ConfigurationDocumentFacts {
        let path = PathBuf::from("src")
            .join("main")
            .join("application.Properties");
        match ingest_configuration_document(&path, source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => *facts,
            other => panic!("expected properties facts, got {other:?}"),
        }
    }

    fn slice(source: &str, range: ConfigurationSourceRange) -> &str {
        &source[range.start_byte()..range.end_byte()]
    }

    /// Each member's key text, occurrence, key token, and value token, in
    /// authored order.
    fn properties_members(
        source: &str,
        document: &ConfigurationDocumentFacts,
    ) -> Vec<(String, usize, String, String)> {
        document
            .facts()
            .iter()
            .filter_map(|fact| {
                let ConfigurationNodeKind::Member { role, key, value } = fact.kind() else {
                    return None;
                };
                assert_eq!(*role, ConfigurationMemberRole::Property, "{fact:#?}");
                let [segment] = fact.route().segments() else {
                    panic!("a property route is exactly one authored key: {fact:#?}");
                };
                let ConfigurationRouteSelector::Key { name, occurrence } = segment.selector()
                else {
                    panic!("{fact:#?}");
                };
                assert_eq!(name, key.text());
                assert_eq!(segment.evidence(), key.evidence());
                let value = document
                    .fact(value.expect("every property has a value"))
                    .unwrap();
                assert!(matches!(
                    value.kind(),
                    ConfigurationNodeKind::Scalar {
                        scalar_kind: ConfigurationScalarKind::String
                    }
                ));
                assert_eq!(value.route(), fact.route());
                Some((
                    key.text().to_owned(),
                    *occurrence,
                    slice(source, key.evidence()).to_owned(),
                    slice(source, value.evidence()).to_owned(),
                ))
            })
            .collect()
    }

    const PROPERTIES_WITNESS: &str = "# Service settings\n\
! legacy comment marker\n\
server.host = primary.example\n\
server.host: backup.example\n\
server.port=8080\n\
key\\ with\\ spaces\\=and\\:colons = escaped\n\
ttl-ms 250\n\
message.greeting = Hello, \\\n    world\\u0021\n\
empty.value =\n\
bare.key\n\
datasource.url=jdbc:postgresql://${db.host}:${db.port:5432}/app\n\
caf\\u00e9.mode=on\n";

    #[test]
    fn properties_ingestion_preserves_escaped_keys_continuations_duplicates_and_ranges() {
        let source = PROPERTIES_WITNESS;
        let document = properties_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(document.format(), ConfigurationFormat::Properties);
        arena_children_are_exclusive(&document);
        let members = properties_members(source, &document);
        let expected: Vec<(&str, usize, &str, &str)> = vec![
            ("server.host", 1, "server.host", "primary.example"),
            ("server.host", 2, "server.host", "backup.example"),
            ("server.port", 1, "server.port", "8080"),
            (
                "key with spaces=and:colons",
                1,
                "key\\ with\\ spaces\\=and\\:colons",
                "escaped",
            ),
            ("ttl-ms", 1, "ttl-ms", "250"),
            (
                "message.greeting",
                1,
                "message.greeting",
                "Hello, \\\n    world\\u0021",
            ),
            ("empty.value", 1, "empty.value", ""),
            ("bare.key", 1, "bare.key", ""),
            (
                "datasource.url",
                1,
                "datasource.url",
                "jdbc:postgresql://${db.host}:${db.port:5432}/app",
            ),
            ("caf\u{e9}.mode", 1, "caf\\u00e9.mode", "on"),
        ];
        assert_eq!(
            members
                .iter()
                .map(|(key, occurrence, token, value)| (
                    key.as_str(),
                    *occurrence,
                    token.as_str(),
                    value.as_str()
                ))
                .collect::<Vec<_>>(),
            expected,
            "{document:#?}"
        );

        // A member spans its whole logical line, and duplicate occurrences
        // keep distinct identities under one parent.
        let hosts: Vec<_> = document
            .facts()
            .iter()
            .filter(|fact| {
                matches!(fact.kind(), ConfigurationNodeKind::Member { key, .. } if key.text() == "server.host")
            })
            .collect();
        assert_eq!(
            slice(source, hosts[0].evidence()),
            "server.host = primary.example"
        );
        assert_eq!(
            slice(source, hosts[1].evidence()),
            "server.host: backup.example"
        );
        assert_eq!(hosts[0].parent(), hosts[1].parent());
        assert_ne!(
            hosts[0].stable_id(ConfigurationFormat::Properties),
            hosts[1].stable_id(ConfigurationFormat::Properties)
        );

        // A placeholder is unresolved interpolation evidence, never expanded;
        // the format itself has no includes, anchors, aliases, or merges.
        let features = document.features();
        let ConfigurationFeatureState::Unresolved { evidence } = features.interpolation() else {
            panic!("{features:#?}");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|range| slice(source, *range))
                .collect::<Vec<_>>(),
            vec!["${db.host}", "${db.port:5432}"]
        );
        for state in [
            features.anchors(),
            features.aliases(),
            features.includes(),
            features.format_merge(),
        ] {
            assert!(
                matches!(state, ConfigurationFeatureState::NotApplicable),
                "{features:#?}"
            );
        }
    }

    #[test]
    fn properties_malformed_escapes_and_grammar_limits_are_typed_incomplete() {
        // A `\u` escape without four hex digits is the format's own load
        // error; the authored member survives with typed malformed evidence.
        let source = "kept=1\nbad.value=\\u00zz\nbad\\uXYZkey=2\n";
        let document = properties_facts(source);
        assert_eq!(
            recovery_reasons(&document),
            vec![
                ConfigurationRecoveryReason::MalformedSyntax,
                ConfigurationRecoveryReason::MalformedSyntax
            ],
            "{document:#?}"
        );
        assert_eq!(
            member_keys(&document),
            vec!["kept", "bad.value", "bad\\uXYZkey"]
        );

        // Input the format accepts but the grammar tokenizes differently is
        // a typed parser limit with no false fact: an empty key, a key that
        // continues across a line break, an index that swallowed a separator,
        // and a bare carriage return.
        for (source, lost) in [
            ("kept=1\n=empty-key\n", "=empty-key"),
            ("kept=1\nke\\\ny=split\n", "ke\\\ny=split"),
            ("kept=1\nmap[a=b]=c\n", "map[a=b]=c"),
            ("kept=1\ra=b\r", "\r"),
        ] {
            let document = properties_facts(source);
            let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness()
            else {
                panic!("{source:?} must be incomplete: {document:#?}");
            };
            assert_eq!(recoveries.len(), 1, "{source:?}: {document:#?}");
            assert_eq!(
                recoveries[0].reason(),
                ConfigurationRecoveryReason::ParserLimit,
                "{source:?}"
            );
            assert_eq!(slice(source, recoveries[0].evidence()), lost, "{source:?}");
            assert!(
                !member_keys(&document)
                    .iter()
                    .any(|key| key.starts_with('=') || *key == "ke" || key.contains('[')),
                "{source:?}: {document:#?}"
            );
        }

        // An unterminated placeholder and a trailing backslash at end of
        // input are the grammar's own error nodes.
        for source in ["kept=1\na=${b\n", "kept=1\na=b\\"] {
            let document = properties_facts(source);
            assert!(
                recovery_reasons(&document).contains(&ConfigurationRecoveryReason::MalformedSyntax),
                "{source:?}: {document:#?}"
            );
            assert!(member_keys(&document).contains(&"kept"), "{source:?}");
        }

        // A comment-only document is a complete, empty root object.
        let document = properties_facts("# nothing authored\n\n");
        assert!(document.completeness().is_complete());
        assert!(matches!(
            document.facts()[1].kind(),
            ConfigurationNodeKind::Object { members } if members.is_empty()
        ));
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
        // Every ConfigurationFormat variant now has an adapter, so an
        // unclassified path is the only remaining source of an Unsupported
        // outcome.
        assert!(matches!(
            ingest_configuration_document(Path::new("config.txt"), b"a=1"),
            ConfigurationIngestionOutcome::Unsupported { format: None }
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
        let epochs = [
            json_configuration_adapter_epoch(),
            properties_configuration_adapter_epoch(),
            toml_configuration_adapter_epoch(),
            xml_configuration_adapter_epoch(),
            yaml_configuration_adapter_epoch(),
        ];
        for epoch in &epochs {
            assert_eq!(epoch.len(), 64, "{epoch}");
            assert!(
                epoch
                    .chars()
                    .all(|digit| digit.is_ascii_hexdigit() && !digit.is_ascii_uppercase()),
                "{epoch}"
            );
        }
        assert_eq!(
            epochs,
            [
                json_configuration_adapter_epoch(),
                properties_configuration_adapter_epoch(),
                toml_configuration_adapter_epoch(),
                xml_configuration_adapter_epoch(),
                yaml_configuration_adapter_epoch(),
            ]
        );
        // Adapters over the same document model must never share a cache
        // compatibility identity, including the two that hash a live
        // tree-sitter grammar the same way.
        for (left, first) in epochs.iter().enumerate() {
            for second in &epochs[left + 1..] {
                assert_ne!(first, second, "{epochs:#?}");
            }
        }
    }

    #[test]
    fn every_discovery_extension_reaches_its_format_adapter() {
        // The canonical registry's discovery extensions and the ingestion
        // dispatch are one contract: a path the registry discovers must reach
        // the adapter of the same format, never an unclassified rejection.
        for format in ConfigurationFormat::ALL {
            for extension in format.discovery_extensions() {
                let path = PathBuf::from("conf").join(format!("candidate.{extension}"));
                match ingest_configuration_document(&path, b"") {
                    ConfigurationIngestionOutcome::Facts(facts) => {
                        assert_eq!(facts.format(), format, "{path:?}");
                    }
                    other => panic!("{path:?} did not reach its adapter: {other:?}"),
                }
            }
        }
        // `.props` is an MSBuild XML project extension, not a Java properties
        // spelling, and no registry discovers it.
        assert_eq!(
            ingest_configuration_document(Path::new("Directory.Build.props"), b"k=v\n"),
            ConfigurationIngestionOutcome::Unsupported { format: None }
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
        // A leading `+` is invalid JSON that the grammar recovers from inside
        // the member. Before the parent link moved behind fact creation, the
        // recovered value left a dangling child id and the whole document
        // returned no facts at all.
        let document = facts(r#"{"kept": "value", "budget": +1}"#);
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

    fn yaml_facts(source: &str) -> ConfigurationDocumentFacts {
        match ingest_configuration_document(Path::new("config.YAML"), source.as_bytes()) {
            ConfigurationIngestionOutcome::Facts(facts) => *facts,
            other => panic!("expected YAML facts, got {other:?}"),
        }
    }

    /// The route as key texts and indexes, for readable assertions.
    fn route_labels(fact: &ConfigurationFact) -> Vec<String> {
        fact.route()
            .segments()
            .iter()
            .map(|segment| match segment.selector() {
                ConfigurationRouteSelector::Key { name, occurrence } if *occurrence > 1 => {
                    format!("{name}#{occurrence}")
                }
                ConfigurationRouteSelector::Key { name, .. } => name.clone(),
                ConfigurationRouteSelector::Index(index) => index.to_string(),
            })
            .collect()
    }

    fn fact_at<'doc>(
        document: &'doc ConfigurationDocumentFacts,
        route: &[&str],
    ) -> &'doc ConfigurationFact {
        document
            .facts()
            .iter()
            .find(|fact| {
                route_labels(fact) == route
                    && !matches!(
                        fact.kind(),
                        ConfigurationNodeKind::Member { .. }
                            | ConfigurationNodeKind::Document { .. }
                    )
            })
            .unwrap_or_else(|| panic!("no value fact at {route:?} in {document:#?}"))
    }

    fn member_at<'doc>(
        document: &'doc ConfigurationDocumentFacts,
        route: &[&str],
    ) -> &'doc ConfigurationFact {
        document
            .facts()
            .iter()
            .find(|fact| {
                route_labels(fact) == route
                    && matches!(fact.kind(), ConfigurationNodeKind::Member { .. })
            })
            .unwrap_or_else(|| panic!("no member fact at {route:?} in {document:#?}"))
    }

    fn scalar_kind_of(fact: &ConfigurationFact) -> ConfigurationScalarKind {
        match fact.kind() {
            ConfigurationNodeKind::Scalar { scalar_kind } => *scalar_kind,
            other => panic!("expected a scalar, got {other:?}"),
        }
    }

    /// A production-shaped service manifest: nested block mappings, a block
    /// sequence of mappings, flow collections, block scalars, comments, an
    /// empty value, and every core-schema scalar kind.
    const YAML_WITNESS: &str = r#"# Deployment settings for the example service.
version: "3.9"
services:
  web:
    image: example/web:1.4.2
    host: primary.example
    hostname: near-miss.example
    replicas: 3
    weight: 0.75
    healthy: true
    deprecated: ~
    fallback: null
    limits:
    ports:
      - "8080:80"
      - 8443:443   # a sexagesimal-looking plain scalar is a string in YAML 1.2
    env: {DEBUG: false, LEVEL: 0x1F}
    command: |
      run --serve
      --verbose
    motd: >-
      folded
      text
  db:
    image: example/db
    host: replica.example
tags: [primary, 2, 3.5, yes]
"#;

    #[test]
    fn yaml_ingestion_preserves_nested_keys_sequences_scalar_kinds_and_ranges() {
        let source = YAML_WITNESS;
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(document.format(), ConfigurationFormat::Yaml);
        arena_children_are_exclusive(&document);

        // Every scalar kind the core schema resolves, plus the tag override
        // free document's quoted and block strings.
        let kinds = |route: &[&str]| scalar_kind_of(fact_at(&document, route));
        assert_eq!(kinds(&["version"]), ConfigurationScalarKind::String);
        assert_eq!(
            kinds(&["services", "web", "image"]),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            kinds(&["services", "web", "replicas"]),
            ConfigurationScalarKind::Integer
        );
        assert_eq!(
            kinds(&["services", "web", "weight"]),
            ConfigurationScalarKind::Decimal
        );
        assert_eq!(
            kinds(&["services", "web", "healthy"]),
            ConfigurationScalarKind::Boolean
        );
        assert_eq!(
            kinds(&["services", "web", "deprecated"]),
            ConfigurationScalarKind::Null
        );
        assert_eq!(
            kinds(&["services", "web", "fallback"]),
            ConfigurationScalarKind::Null
        );
        assert_eq!(
            kinds(&["services", "web", "ports", "0"]),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            kinds(&["services", "web", "ports", "1"]),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            kinds(&["services", "web", "env", "DEBUG"]),
            ConfigurationScalarKind::Boolean
        );
        assert_eq!(
            kinds(&["services", "web", "env", "LEVEL"]),
            ConfigurationScalarKind::Integer
        );
        assert_eq!(
            kinds(&["services", "web", "command"]),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            kinds(&["services", "web", "motd"]),
            ConfigurationScalarKind::String
        );
        assert_eq!(kinds(&["tags", "1"]), ConfigurationScalarKind::Integer);
        assert_eq!(kinds(&["tags", "2"]), ConfigurationScalarKind::Decimal);
        // YAML 1.2 dropped the 1.1 `yes`/`no` booleans.
        assert_eq!(kinds(&["tags", "3"]), ConfigurationScalarKind::String);

        // Containers keep their shape.
        assert!(matches!(
            fact_at(&document, &["services"]).kind(),
            ConfigurationNodeKind::Object { members } if members.len() == 2
        ));
        assert!(matches!(
            fact_at(&document, &["services", "web", "ports"]).kind(),
            ConfigurationNodeKind::Sequence { items } if items.len() == 2
        ));
        assert!(matches!(
            fact_at(&document, &["services", "web", "env"]).kind(),
            ConfigurationNodeKind::Object { members } if members.len() == 2
        ));

        // An empty value is YAML's null, anchored where the value would be.
        let limits = fact_at(&document, &["services", "web", "limits"]);
        assert_eq!(scalar_kind_of(limits), ConfigurationScalarKind::Null);
        assert_eq!(limits.evidence().start_byte(), limits.evidence().end_byte());
        assert_eq!(
            slice(
                source,
                member_at(&document, &["services", "web", "limits"]).evidence()
            ),
            "limits:"
        );
        assert_eq!(
            limits.evidence().start_byte(),
            member_at(&document, &["services", "web", "limits"])
                .evidence()
                .end_byte()
        );

        // Exact provenance: members span key through value, keys slice to
        // their own text, scalars slice to their authored token.
        assert_eq!(
            slice(
                source,
                member_at(&document, &["services", "web", "host"]).evidence()
            ),
            "host: primary.example"
        );
        assert_eq!(
            slice(
                source,
                fact_at(&document, &["services", "web", "ports", "0"]).evidence()
            ),
            "\"8080:80\""
        );
        assert_eq!(
            slice(
                source,
                fact_at(&document, &["services", "web", "ports", "1"]).evidence()
            ),
            "8443:443"
        );
        assert_eq!(
            slice(
                source,
                fact_at(&document, &["services", "web", "command"]).evidence()
            ),
            "|\n      run --serve\n      --verbose"
        );
        for fact in document.facts() {
            assert!(source.is_char_boundary(fact.evidence().start_byte()));
            assert!(source.is_char_boundary(fact.evidence().end_byte()));
            assert_eq!(
                fact.provenance(),
                brokk_bifrost_core::analyzer::configuration::ConfigurationValueProvenance::Authored
            );
            if let ConfigurationNodeKind::Member { role, key, .. } = fact.kind() {
                assert_eq!(*role, ConfigurationMemberRole::ObjectMember);
                assert_eq!(slice(source, key.evidence()), key.text());
            }
        }

        // The two `host` entries live under different parents and keep
        // distinct identities; `hostname` is never one of them.
        let hosts: Vec<_> = document
            .facts()
            .iter()
            .filter(|fact| {
                matches!(fact.kind(), ConfigurationNodeKind::Member { key, .. } if key.text() == "host")
            })
            .collect();
        assert_eq!(hosts.len(), 2);
        assert_ne!(hosts[0].parent(), hosts[1].parent());
        assert_ne!(
            hosts[0].stable_id(ConfigurationFormat::Yaml),
            hosts[1].stable_id(ConfigurationFormat::Yaml)
        );
        let mut ids: Vec<_> = document
            .facts()
            .iter()
            .map(|fact| fact.stable_id(ConfigurationFormat::Yaml))
            .collect();
        let distinct = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), distinct, "{document:#?}");
    }

    #[test]
    fn yaml_duplicate_keys_have_distinct_occurrences_and_identities() {
        let source = "host: one\nhost: two\nother: 3\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        let first = member_at(&document, &["host"]);
        let second = member_at(&document, &["host#2"]);
        assert_eq!(first.parent(), second.parent());
        assert_ne!(
            first.stable_id(ConfigurationFormat::Yaml),
            second.stable_id(ConfigurationFormat::Yaml)
        );
        assert_eq!(slice(source, second.evidence()), "host: two");
        assert_eq!(member_keys(&document), vec!["host", "host", "other"]);
    }

    #[test]
    fn yaml_anchors_aliases_merge_keys_and_tags_are_explicit_capability_state() {
        let source = r#"defaults: &defaults
  retries: 3
  port: !!str 8080
  bucket: !Ref MyBucket
  digits: !!int "42"
prod:
  <<: *defaults
  db: *defaults
  hosts: !!seq [a, b]
  extra: !custom {x: 1}
"#;
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        arena_children_are_exclusive(&document);
        let features = document.features();

        let ConfigurationFeatureState::Authored { evidence } = features.anchors() else {
            panic!("anchors are authored: {features:#?}");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|range| slice(source, *range))
                .collect::<Vec<_>>(),
            vec!["&defaults"]
        );

        let ConfigurationFeatureState::Unresolved { evidence } = features.aliases() else {
            panic!("aliases are unresolved: {features:#?}");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|range| slice(source, *range))
                .collect::<Vec<_>>(),
            vec!["*defaults", "*defaults"]
        );
        // The alias occupies its node position as an authored, unexpanded
        // reference rather than the anchored mapping's facts.
        let db = fact_at(&document, &["prod", "db"]);
        assert_eq!(scalar_kind_of(db), ConfigurationScalarKind::Opaque);
        assert_eq!(slice(source, db.evidence()), "*defaults");

        let ConfigurationFeatureState::Unresolved { evidence } = features.format_merge() else {
            panic!("merge keys are unresolved: {features:#?}");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|range| slice(source, *range))
                .collect::<Vec<_>>(),
            vec!["<<"]
        );
        // The merge entry itself is an authored member with its authored key.
        assert_eq!(
            slice(source, member_at(&document, &["prod", "<<"]).evidence()),
            "<<: *defaults"
        );

        // A core-schema tag wins over the grammar's plain-scalar resolution;
        // a collection tag that agrees with the shape is resolved; a local
        // tag is the application's to interpret.
        assert_eq!(
            scalar_kind_of(fact_at(&document, &["defaults", "port"])),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            slice(source, fact_at(&document, &["defaults", "port"]).evidence()),
            "!!str 8080"
        );
        assert_eq!(
            scalar_kind_of(fact_at(&document, &["defaults", "digits"])),
            ConfigurationScalarKind::Integer
        );
        assert_eq!(
            scalar_kind_of(fact_at(&document, &["defaults", "bucket"])),
            ConfigurationScalarKind::Opaque
        );
        assert!(matches!(
            fact_at(&document, &["prod", "hosts"]).kind(),
            ConfigurationNodeKind::Sequence { items } if items.len() == 2
        ));
        assert!(matches!(
            fact_at(&document, &["prod", "extra"]).kind(),
            ConfigurationNodeKind::Object { members } if members.len() == 1
        ));
        let ConfigurationFeatureState::Unresolved { evidence } = features.tags() else {
            panic!("a local tag leaves tags unresolved: {features:#?}");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|range| slice(source, *range))
                .collect::<Vec<_>>(),
            vec!["!Ref", "!custom"]
        );

        // YAML defines neither includes nor interpolation.
        assert!(matches!(
            features.includes(),
            ConfigurationFeatureState::NotApplicable
        ));
        assert!(matches!(
            features.interpolation(),
            ConfigurationFeatureState::NotApplicable
        ));

        // With only core-schema tags, the axis is authored and resolved.
        let resolved = yaml_facts("a: !!str 1\nb: !!map {x: 1}\nc: !!null\n");
        assert!(resolved.completeness().is_complete(), "{resolved:#?}");
        assert!(
            matches!(
                resolved.features().tags(),
                ConfigurationFeatureState::Authored { evidence } if evidence.len() == 3
            ),
            "{resolved:#?}"
        );
        assert_eq!(
            scalar_kind_of(fact_at(&resolved, &["c"])),
            ConfigurationScalarKind::Null
        );
        assert!(resolved.features().anchors().is_resolved());
        assert!(resolved.features().aliases().is_resolved());
        assert!(resolved.features().format_merge().is_resolved());

        // A plain document authors none of it.
        let plain = yaml_facts("a: 1\n");
        for state in [
            plain.features().anchors(),
            plain.features().aliases(),
            plain.features().format_merge(),
            plain.features().tags(),
        ] {
            assert!(
                matches!(state, ConfigurationFeatureState::NotApplicable),
                "{plain:#?}"
            );
        }
    }

    #[test]
    fn yaml_quoted_keys_decode_through_the_maintained_parser() {
        let source = "\"h\\u00f6st\": one\n'it''s': two\nkey\u{e9}: caf\u{e9}\n\"\": empty\n? |\n  block key\n: three\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(
            member_keys(&document),
            vec!["h\u{f6}st", "it's", "key\u{e9}", "", "block key\n"]
        );
        // The key's evidence stays the authored token even when its decoded
        // text differs from it.
        let host = member_at(&document, &["h\u{f6}st"]);
        let ConfigurationNodeKind::Member { key, .. } = host.kind() else {
            unreachable!()
        };
        assert_eq!(slice(source, key.evidence()), "\"h\\u00f6st\"");
        assert_eq!(slice(source, host.evidence()), "\"h\\u00f6st\": one");
        assert_eq!(
            slice(source, fact_at(&document, &["key\u{e9}"]).evidence()),
            "caf\u{e9}"
        );
        let empty = member_at(&document, &[""]);
        assert_ne!(
            empty.stable_id(ConfigurationFormat::Yaml),
            host.stable_id(ConfigurationFormat::Yaml)
        );
    }

    #[test]
    fn yaml_flow_collections_bare_keys_and_single_pair_items_nest_by_position() {
        let source = "flow: {a: 1, b: [x, y], c, d: }\nmulti: [k: v, plain]\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        arena_children_are_exclusive(&document);
        // `c` and `d:` are keys whose values the author left empty.
        for key in ["c", "d"] {
            let value = fact_at(&document, &["flow", key]);
            assert_eq!(
                scalar_kind_of(value),
                ConfigurationScalarKind::Null,
                "{key}"
            );
            assert_eq!(
                value.evidence().start_byte(),
                value.evidence().end_byte(),
                "{key}"
            );
        }
        assert_eq!(
            slice(source, fact_at(&document, &["flow", "b", "1"]).evidence()),
            "y"
        );
        // `[k: v, plain]` is a sequence whose first element is a one-entry
        // mapping, so the entry is reachable only through the index.
        let pair_mapping = fact_at(&document, &["multi", "0"]);
        assert!(matches!(
            pair_mapping.kind(),
            ConfigurationNodeKind::Object { members } if members.len() == 1
        ));
        assert_eq!(slice(source, pair_mapping.evidence()), "k: v");
        assert_eq!(
            scalar_kind_of(fact_at(&document, &["multi", "0", "k"])),
            ConfigurationScalarKind::String
        );
        assert_eq!(
            slice(source, fact_at(&document, &["multi", "1"]).evidence()),
            "plain"
        );
    }

    #[test]
    fn yaml_empty_streams_documents_and_items_are_typed_where_the_model_allows() {
        // A stream with no document at all has nothing to root: typed, not a
        // clean empty answer.
        for source in ["", "   \n", "# only a comment\n"] {
            let document = yaml_facts(source);
            assert_eq!(
                recovery_reasons(&document),
                vec![ConfigurationRecoveryReason::UnsupportedConstruct],
                "{source:?}: {document:#?}"
            );
            assert!(matches!(
                document.fact(document.document()).unwrap().kind(),
                ConfigurationNodeKind::Document { root: None }
            ));
        }
        // An explicit document marker opens an authored empty document,
        // which YAML resolves to null.
        let explicit = yaml_facts("---\n");
        assert!(explicit.completeness().is_complete(), "{explicit:#?}");
        let root = fact_at(&explicit, &[]);
        assert_eq!(scalar_kind_of(root), ConfigurationScalarKind::Null);
        assert_eq!(root.evidence().start_byte(), root.evidence().end_byte());

        // A top-level scalar and a top-level sequence are documents too.
        let scalar = yaml_facts("just text\n");
        assert_eq!(
            scalar_kind_of(fact_at(&scalar, &[])),
            ConfigurationScalarKind::String
        );
        let source = "-\n- second\n";
        let sequence = yaml_facts(source);
        assert!(sequence.completeness().is_complete(), "{sequence:#?}");
        let first = fact_at(&sequence, &["0"]);
        assert_eq!(scalar_kind_of(first), ConfigurationScalarKind::Null);
        assert_eq!(first.evidence(), empty_range_at(1));
        assert_eq!(
            slice(source, fact_at(&sequence, &["1"]).evidence()),
            "second"
        );
    }

    #[test]
    fn yaml_multi_document_streams_keep_the_first_document_and_type_the_rest() {
        let source =
            "apiVersion: v1\nkind: Service\n---\napiVersion: apps/v1\nkind: Deployment\n...\n";
        let document = yaml_facts(source);
        assert_eq!(member_keys(&document), vec!["apiVersion", "kind"]);
        assert_eq!(
            slice(source, fact_at(&document, &["kind"]).evidence()),
            "Service"
        );
        let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness() else {
            panic!("a second document is a typed gap: {document:#?}");
        };
        assert_eq!(recoveries.len(), 1, "{recoveries:#?}");
        assert_eq!(
            recoveries[0].reason(),
            ConfigurationRecoveryReason::UnsupportedConstruct
        );
        assert_eq!(
            slice(source, recoveries[0].evidence()),
            "---\napiVersion: apps/v1\nkind: Deployment\n..."
        );
    }

    #[test]
    fn yaml_collection_keys_keep_their_authored_text_as_an_unsupported_construct() {
        let source = "? [a, b]\n: seqkey\nplain: 1\n";
        let document = yaml_facts(source);
        assert_eq!(member_keys(&document), vec!["[a, b]", "plain"]);
        assert_eq!(
            recovery_reasons(&document),
            vec![ConfigurationRecoveryReason::UnsupportedConstruct]
        );
        let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness() else {
            unreachable!()
        };
        assert_eq!(slice(source, recoveries[0].evidence()), "[a, b]");
        assert_eq!(
            slice(source, fact_at(&document, &["[a, b]"]).evidence()),
            "seqkey"
        );
    }

    #[test]
    fn yaml_malformed_documents_are_typed_incomplete() {
        // A tab indent, a mixed mapping/sequence, and an unclosed quote each
        // make the grammar give up on the whole document: no root survives,
        // and the evidence is inside the file.
        for source in [
            "a: 1\n\tb: 2\nc: 3\n",
            "a: 1\n- item\nc: 3\n",
            "a: \"bad \\q escape\"\n",
            "e: \"unclosed\n",
        ] {
            let document = yaml_facts(source);
            let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness()
            else {
                panic!("{source:?} must be incomplete: {document:#?}");
            };
            assert!(
                recoveries.iter().all(|recovery| recovery.reason()
                    == ConfigurationRecoveryReason::MalformedSyntax
                    && recovery.evidence().end_byte() <= source.len()),
                "{source:?}: {recoveries:#?}"
            );
            assert!(
                matches!(
                    document.fact(document.document()).unwrap().kind(),
                    ConfigurationNodeKind::Document { root: None }
                ),
                "{source:?}: {document:#?}"
            );
            // Input the grammar never consumed is malformed evidence too.
            let last = recoveries.last().unwrap();
            assert!(
                source[last.evidence().end_byte()..].trim().is_empty(),
                "{source:?}: {recoveries:#?}"
            );
        }

        // An unclosed flow collection or an unclosed quote followed by more
        // entries recovers around the broken value and keeps the entries
        // before and after it, typed incomplete with the broken token's
        // exact range.
        for (source, broken) in [
            ("a: 1\nb: {x: 1\nc: 3\n", "{x: 1"),
            ("a: 1\nb: \"unclosed\nc: 3\n", "\"unclosed"),
        ] {
            let document = yaml_facts(source);
            arena_children_are_exclusive(&document);
            assert_eq!(member_keys(&document), vec!["a", "b", "c"], "{document:#?}");
            let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness()
            else {
                panic!("{source:?} must be incomplete: {document:#?}");
            };
            assert_eq!(
                recoveries
                    .iter()
                    .map(|recovery| (recovery.reason(), slice(source, recovery.evidence())))
                    .collect::<Vec<_>>(),
                vec![(ConfigurationRecoveryReason::MalformedSyntax, broken)],
                "{document:#?}"
            );
            assert_eq!(
                scalar_kind_of(fact_at(&document, &["c"])),
                ConfigurationScalarKind::Integer
            );
        }
    }

    #[test]
    fn yaml_stable_identity_ignores_unrelated_sibling_edits() {
        let before = yaml_facts("target:\n  enabled: true\nother: 1\n");
        let after = yaml_facts(
            "target:\n  enabled: true\nunrelated:\n  - 1\n  - 2\n  - {deep: [x]}\nother: 1\n",
        );
        let enabled = |document: &ConfigurationDocumentFacts| {
            member_at(document, &["target", "enabled"]).stable_id(ConfigurationFormat::Yaml)
        };
        assert_eq!(enabled(&before), enabled(&after));
        // An edit that changes the value's kind changes the value's identity
        // without moving the member's.
        let retyped = yaml_facts("target:\n  enabled: \"true\"\nother: 1\n");
        assert_eq!(enabled(&before), enabled(&retyped));
        assert_ne!(
            fact_at(&before, &["target", "enabled"]).stable_id(ConfigurationFormat::Yaml),
            fact_at(&retyped, &["target", "enabled"]).stable_id(ConfigurationFormat::Yaml)
        );
    }

    #[test]
    fn yaml_deep_nesting_and_crlf_do_not_crash_or_recurse() {
        let depth = 4_000;
        let mut source = String::new();
        for _ in 0..depth {
            source.push('[');
        }
        source.push('1');
        for _ in 0..depth {
            source.push(']');
        }
        let document = yaml_facts(&source);
        // Whether the grammar admits the depth or recovers, the answer is a
        // valid arena rather than a stack overflow.
        arena_children_are_exclusive(&document);
        if document.completeness().is_complete() {
            assert_eq!(
                document.facts().len(),
                depth + 2,
                "{}",
                document.facts().len()
            );
        }

        let source = "a: 1\r\nb:\r\n  - x\r\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(
            slice(source, member_at(&document, &["a"]).evidence()),
            "a: 1"
        );
        assert_eq!(
            slice(source, fact_at(&document, &["b", "0"]).evidence()),
            "x"
        );
    }

    #[test]
    fn yaml_multi_line_explicit_keys_and_null_spellings_take_their_specified_text() {
        // Found by the yaml-test-suite `in.json` oracle (cases 8KB6, CT4Q,
        // JTV5, NJ66): an explicit key may span lines, and YAML folds the
        // break into one space, so the key is `multi line`, not the authored
        // line structure. A null spelling has no string value and keeps its
        // spelling as its textual identity.
        // Cases 8CWC and UKK6/01 add plain keys that end in a colon, which
        // would read as a mapping if re-parsed outside their context.
        let source =
            "? multi\n  line\n: v\n~: tilde\nnull: word\n\"null\": quoted\ntwo colons::: v\n::\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(
            member_keys(&document),
            vec!["multi line", "~", "null", "null", "two colons::", ":"]
        );
        let ConfigurationNodeKind::Member { key, .. } =
            member_at(&document, &["multi line"]).kind()
        else {
            unreachable!()
        };
        assert_eq!(slice(source, key.evidence()), "multi\n  line");
        // The quoted `"null"` and the plain `null` are the same textual key,
        // so they are distinct occurrences rather than distinct names.
        assert_eq!(
            slice(source, member_at(&document, &["null#2"]).evidence()),
            "\"null\": quoted"
        );
    }

    #[test]
    fn yaml_tag_directive_rebinding_the_secondary_handle_unresolves_shorthand_tags() {
        // Found by the yaml-test-suite `in.json` oracle (case P76L, spec
        // example 6.19): after `%TAG !! tag:example.com,2000:app/`, `!!int`
        // names an application type, not the core integer.
        let source = "%TAG !! tag:example.com,2000:app/\n---\n!!int 1 - 3\n";
        let document = yaml_facts(source);
        assert!(document.completeness().is_complete(), "{document:#?}");
        assert_eq!(
            scalar_kind_of(fact_at(&document, &[])),
            ConfigurationScalarKind::Opaque
        );
        assert!(
            matches!(
                document.features().tags(),
                ConfigurationFeatureState::Unresolved { evidence } if evidence.len() == 1
            ),
            "{document:#?}"
        );

        // Rebinding `!!` to the YAML namespace itself, or binding some other
        // handle, leaves the core shorthand intact; the verbatim spelling is
        // always the core type.
        for source in [
            "%TAG !! tag:yaml.org,2002:\n---\n!!int 3\n",
            "%TAG !e! tag:example.com,2000:app/\n---\n!!int 3\n",
            "%TAG !! tag:example.com,2000:app/\n---\n!<tag:yaml.org,2002:int> 3\n",
        ] {
            let document = yaml_facts(source);
            assert_eq!(
                scalar_kind_of(fact_at(&document, &[])),
                ConfigurationScalarKind::Integer,
                "{source:?}: {document:#?}"
            );
            assert!(document.features().tags().is_resolved(), "{source:?}");
        }
    }

    /// The route selectors, node kind, and scalar kind of every value fact,
    /// sorted so two adapters over equivalent documents can be compared.
    fn value_shape(document: &ConfigurationDocumentFacts) -> Vec<String> {
        let mut shape: Vec<String> = document
            .facts()
            .iter()
            .filter_map(|fact| {
                match fact.kind() {
                    ConfigurationNodeKind::Object { .. } => Some(("object", None)),
                    ConfigurationNodeKind::Sequence { .. } => Some(("sequence", None)),
                    ConfigurationNodeKind::Scalar { scalar_kind } => {
                        Some(("scalar", Some(*scalar_kind)))
                    }
                    _ => None,
                }
                .map(|(kind, scalar_kind)| {
                    format!("{:?} {kind} {scalar_kind:?}", route_labels(fact))
                })
            })
            .collect();
        shape.sort();
        shape
    }

    /// Operator census over an external corpus.
    ///
    /// `BIFROST_YAML_CENSUS_FILES` names a file listing one YAML path per
    /// line; every file is ingested and tallied by completeness and recovery
    /// reason. `BIFROST_YAML_TEST_SUITE` names a checkout of the `data`
    /// branch of `yaml/yaml-test-suite`; every `in.yaml` beside an `error`
    /// marker must be typed incomplete, every other `in.yaml` must be
    /// complete, and where the suite supplies an `in.json` twin for a
    /// single-document, alias-free, resolved-tag document, the YAML and JSON
    /// adapters must produce the same value shape.
    #[test]
    #[ignore = "operator census over external corpora named by environment variables"]
    fn yaml_census_over_external_corpora() {
        if let Ok(list) = std::env::var("BIFROST_YAML_CENSUS_FILES") {
            let list = std::fs::read_to_string(&list).expect("census file list");
            let mut complete = 0usize;
            let mut incomplete = Vec::new();
            let mut failed = Vec::new();
            let mut facts = 0usize;
            for path in list.lines().filter(|line| !line.is_empty()) {
                let bytes = std::fs::read(path).expect(path);
                match ingest_configuration_document(Path::new(path), &bytes) {
                    ConfigurationIngestionOutcome::Facts(document) => {
                        arena_children_are_exclusive(&document);
                        facts += document.facts().len();
                        if document.completeness().is_complete() {
                            complete += 1;
                        } else {
                            incomplete.push(format!("{path}: {:?}", recovery_reasons(&document)));
                        }
                    }
                    other => failed.push(format!("{path}: {other:?}")),
                }
            }
            println!(
                "census: complete={complete} incomplete={} failed={} facts={facts}",
                incomplete.len(),
                failed.len()
            );
            for line in incomplete.iter().chain(failed.iter()) {
                println!("  {line}");
            }
        }
        if let Ok(suite) = std::env::var("BIFROST_YAML_TEST_SUITE") {
            let mut inputs = Vec::new();
            let mut stack = vec![std::path::PathBuf::from(&suite)];
            while let Some(directory) = stack.pop() {
                for entry in std::fs::read_dir(&directory).expect("suite directory") {
                    let entry = entry.expect("suite entry");
                    // `name/` and `tags/` hold symlinks back into the cases.
                    if entry.file_type().expect("suite entry type").is_symlink() {
                        continue;
                    }
                    let entry = entry.path();
                    if entry.is_dir() {
                        stack.push(entry);
                    } else if entry.file_name().is_some_and(|name| name == "in.yaml") {
                        inputs.push(entry);
                    }
                }
            }
            inputs.sort();
            let mut valid_complete = 0usize;
            let mut valid_incomplete = Vec::new();
            let mut invalid_rejected = 0usize;
            let mut invalid_accepted = Vec::new();
            let mut compared = 0usize;
            let mut skipped = 0usize;
            let mut mismatched = Vec::new();
            for input in inputs {
                let case = input.parent().unwrap();
                let bytes = std::fs::read(&input).expect("in.yaml");
                let document = match ingest_configuration_document(&input, &bytes) {
                    ConfigurationIngestionOutcome::Facts(document) => *document,
                    other => panic!("{}: {other:?}", input.display()),
                };
                arena_children_are_exclusive(&document);
                let label = case.strip_prefix(&suite).unwrap().display().to_string();
                if case.join("error").exists() {
                    if document.completeness().is_complete() {
                        invalid_accepted.push(label);
                    } else {
                        invalid_rejected += 1;
                    }
                    continue;
                }
                if !document.completeness().is_complete() {
                    valid_incomplete.push(format!("{label}: {:?}", recovery_reasons(&document)));
                    continue;
                }
                valid_complete += 1;
                let twin = case.join("in.json");
                let features = document.features();
                let comparable = twin.exists()
                    && matches!(features.aliases(), ConfigurationFeatureState::NotApplicable)
                    && features.tags().is_resolved();
                if !comparable {
                    skipped += 1;
                    continue;
                }
                let json = std::fs::read(&twin).expect("in.json");
                let ConfigurationIngestionOutcome::Facts(json) =
                    ingest_configuration_document(&twin, &json)
                else {
                    skipped += 1;
                    continue;
                };
                if !json.completeness().is_complete() {
                    skipped += 1;
                    continue;
                }
                compared += 1;
                let (yaml_shape, json_shape) = (value_shape(&document), value_shape(&json));
                if yaml_shape != json_shape {
                    mismatched.push(format!(
                        "{label}:\n    yaml {yaml_shape:?}\n    json {json_shape:?}"
                    ));
                }
            }
            println!(
                "suite: valid_complete={valid_complete} valid_incomplete={} invalid_rejected={invalid_rejected} invalid_accepted={} compared={compared} skipped={skipped} mismatched={}",
                valid_incomplete.len(),
                invalid_accepted.len(),
                mismatched.len()
            );
            for line in valid_incomplete
                .iter()
                .chain(invalid_accepted.iter())
                .chain(mismatched.iter())
            {
                println!("  {line}");
            }
        }
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
