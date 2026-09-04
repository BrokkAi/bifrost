//! Translation of CodeQL Models-as-Data rows into the foundry IR.
//!
//! A Models-as-Data file is a YAML document of extension blocks. Each block
//! names an extensible predicate and carries rows of fixed width. Milestone 1
//! reads two of them:
//!
//! * `summaryModel` rows, `[package, type, subtypes, name, signature, ext,
//!   input, output, kind, provenance]`, one value flow each.
//! * `neutralModel` rows, `[package, type, name, signature, kind, provenance]`,
//!   which state for `kind: summary` that the member carries no flow.
//!
//! `sourceModel` and `sinkModel` rows are out of scope for this milestone and
//! are counted as skipped rows, never dropped in silence.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer,
};
use serde::Deserialize;

use super::ir::{
    FoundryCorpus, FoundryEndpointPort, FoundryEndpointRole, FoundryEntry, FoundryEntryBuilder,
    FoundryEvidence, FoundryNote, FoundrySignature, FoundrySkip, FoundrySkipReason,
    FoundryTaintEndpoint, FoundryTarget, class_file_path, nested_type_simple_name,
    split_parameter_types,
};

const SUMMARY_MODEL: &str = "summaryModel";
const NEUTRAL_MODEL: &str = "neutralModel";
const SOURCE_MODEL: &str = "sourceModel";
const SINK_MODEL: &str = "sinkModel";
const SUMMARY_ROW_COLUMNS: usize = 10;
const NEUTRAL_ROW_COLUMNS: usize = 6;
/// A `sourceModel`/`sinkModel` row: `[package, type, subtypes, name, signature,
/// ext, port, kind, provenance]`. The port column is the tainted `output` for a
/// source and the sensitive `input` for a sink; the two extensibles share the
/// column layout and differ only in how the port is read.
const ENDPOINT_ROW_COLUMNS: usize = 9;

/// Everything one Models-as-Data corpus translation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeqlTranslation {
    pub entries: Vec<FoundryEntry>,
    pub files_read: u32,
    pub rows_by_kind: BTreeMap<String, u32>,
    pub skips: Vec<FoundrySkip>,
}

/// A Models-as-Data file the translator could not read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeqlParseError {
    pub file: String,
    pub message: String,
}

impl std::fmt::Display for CodeqlParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.file, self.message)
    }
}

impl std::error::Error for CodeqlParseError {}

#[derive(Debug, Deserialize)]
struct MadDocument {
    #[serde(default)]
    extensions: Vec<MadExtension>,
}

#[derive(Debug, Deserialize)]
struct MadExtension {
    #[serde(rename = "addsTo")]
    adds_to: MadAddsTo,
    #[serde(default)]
    data: Vec<Vec<MadCell>>,
}

#[derive(Debug, Deserialize)]
struct MadAddsTo {
    extensible: String,
}

/// One row cell. Models-as-Data spells the `subtypes` column as a YAML boolean
/// and every other column as a string.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum MadCell {
    Bool(bool),
    Text(String),
}

impl MadCell {
    fn text(&self) -> &str {
        match self {
            Self::Bool(true) => "true",
            Self::Bool(false) => "false",
            Self::Text(value) => value,
        }
    }

    /// The cell read as the `subtypes` flag.
    ///
    /// The corpus writes `True`/`False`; a reader that resolves YAML 1.1
    /// booleans returns [`Self::Bool`] and one that does not returns the
    /// spelling, so both are accepted here and nothing else is.
    fn boolean(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            Self::Text(value) => match value.as_str() {
                "true" | "True" | "TRUE" => Some(true),
                "false" | "False" | "FALSE" => Some(false),
                _ => None,
            },
        }
    }
}

fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        strict_booleans: false,
    }
}

/// Translate a set of Models-as-Data files, read in the given order.
///
/// The caller supplies file name and bytes so the report never carries a host
/// path and two runs over the same pin produce the same bytes.
pub fn translate_codeql_models(
    files: &[(String, Vec<u8>)],
) -> Result<CodeqlTranslation, CodeqlParseError> {
    let mut builders: BTreeMap<FoundryTarget, FoundryEntryBuilder> = BTreeMap::new();
    let mut rows_by_kind: BTreeMap<String, u32> = BTreeMap::new();
    let mut skips = Vec::new();

    for (file, bytes) in files {
        let document: MadDocument = serde_saphyr::from_slice_with_options(bytes, yaml_options())
            .map_err(|error| CodeqlParseError {
                file: file.clone(),
                message: error.to_string(),
            })?;
        for extension in &document.extensions {
            let kind = extension.adds_to.extensible.as_str();
            let mut ordinal = 0u32;
            for row in &extension.data {
                ordinal += 1;
                *rows_by_kind.entry(kind.to_owned()).or_default() += 1;
                match kind {
                    SUMMARY_MODEL => {
                        translate_summary_row(file, ordinal, row, &mut builders, &mut skips)
                    }
                    NEUTRAL_MODEL => {
                        translate_neutral_row(file, ordinal, row, &mut builders, &mut skips)
                    }
                    _ => skips.push(FoundrySkip {
                        file: file.clone(),
                        row: ordinal,
                        reason: FoundrySkipReason::RowKindOutOfScope,
                        detail: format!("{kind} rows are out of scope for summary translation"),
                    }),
                }
            }
        }
    }

    let entries = builders
        .into_iter()
        .map(|(target, builder)| {
            let arity = target.signature.arity();
            builder.finish(FoundryCorpus::Codeql, target, arity)
        })
        .collect::<Vec<_>>();
    skips.sort();
    Ok(CodeqlTranslation {
        entries,
        files_read: files.len() as u32,
        rows_by_kind,
        skips,
    })
}

/// Everything one Models-as-Data corpus translation produced for the taint
/// endpoint half: the `sourceModel` and `sinkModel` rows that summary
/// translation skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeqlEndpointTranslation {
    pub endpoints: Vec<FoundryTaintEndpoint>,
    pub files_read: u32,
    pub rows_by_kind: BTreeMap<String, u32>,
    pub skips: Vec<FoundrySkip>,
}

/// Translate the taint-endpoint half of a set of Models-as-Data files.
///
/// This is the counterpart of [`translate_codeql_models`]: that function reads
/// `summaryModel` and `neutralModel` rows and skips sources and sinks; this one
/// reads `sourceModel` and `sinkModel` rows and skips everything else. Each half
/// counts the other half's rows as out of scope rather than dropping them in
/// silence, so a run over the same files sees every row accounted for under
/// exactly one of the two translators.
///
/// The caller supplies file name and bytes so the report never carries a host
/// path and two runs over the same pin produce the same bytes.
pub fn translate_codeql_taint_endpoints(
    files: &[(String, Vec<u8>)],
) -> Result<CodeqlEndpointTranslation, CodeqlParseError> {
    let mut endpoints: Vec<FoundryTaintEndpoint> = Vec::new();
    let mut rows_by_kind: BTreeMap<String, u32> = BTreeMap::new();
    let mut skips = Vec::new();

    for (file, bytes) in files {
        let document: MadDocument = serde_saphyr::from_slice_with_options(bytes, yaml_options())
            .map_err(|error| CodeqlParseError {
                file: file.clone(),
                message: error.to_string(),
            })?;
        for extension in &document.extensions {
            let kind = extension.adds_to.extensible.as_str();
            let role = match kind {
                SOURCE_MODEL => Some(FoundryEndpointRole::Source),
                SINK_MODEL => Some(FoundryEndpointRole::Sink),
                _ => None,
            };
            let mut ordinal = 0u32;
            for row in &extension.data {
                ordinal += 1;
                *rows_by_kind.entry(kind.to_owned()).or_default() += 1;
                match role {
                    Some(role) => {
                        translate_endpoint_row(role, file, ordinal, row, &mut endpoints, &mut skips)
                    }
                    None => skips.push(FoundrySkip {
                        file: file.clone(),
                        row: ordinal,
                        reason: FoundrySkipReason::RowKindOutOfScope,
                        detail: format!("{kind} rows are out of scope for endpoint translation"),
                    }),
                }
            }
        }
    }

    endpoints.sort();
    skips.sort();
    Ok(CodeqlEndpointTranslation {
        endpoints,
        files_read: files.len() as u32,
        rows_by_kind,
        skips,
    })
}

fn translate_endpoint_row(
    role: FoundryEndpointRole,
    file: &str,
    ordinal: u32,
    row: &[MadCell],
    endpoints: &mut Vec<FoundryTaintEndpoint>,
    skips: &mut Vec<FoundrySkip>,
) {
    let mut skip = |reason: FoundrySkipReason, detail: String| {
        skips.push(FoundrySkip {
            file: file.to_owned(),
            row: ordinal,
            reason,
            detail,
        });
    };
    if row.len() != ENDPOINT_ROW_COLUMNS {
        skip(
            FoundrySkipReason::MalformedRow,
            format!(
                "{} row has {} columns, expected {ENDPOINT_ROW_COLUMNS}",
                role.as_str(),
                row.len()
            ),
        );
        return;
    }
    let package = row[0].text();
    let type_name = row[1].text();
    let Some(subtypes) = row[2].boolean() else {
        skip(
            FoundrySkipReason::MalformedRow,
            format!("subtypes column is not a boolean: {}", row[2].text()),
        );
        return;
    };
    let name = row[3].text();
    let signature_text = row[4].text();
    let extension_qualifier = row[5].text();
    let port_text = row[6].text();
    let kind = row[7].text();
    let provenance = row[8].text();

    if !extension_qualifier.is_empty() {
        skip(
            FoundrySkipReason::RowQualifierUnsupported,
            format!("row selects a declaration through ext `{extension_qualifier}`"),
        );
        return;
    }
    let signature = match parse_signature(signature_text) {
        Ok(signature) => signature,
        Err(message) => {
            skip(FoundrySkipReason::MalformedRow, message);
            return;
        }
    };
    let access_path = match parse_access_path(port_text) {
        Ok(path) => path,
        Err(message) => {
            skip(FoundrySkipReason::MalformedRow, message);
            return;
        }
    };
    let ports = match &access_path.root {
        MadRoot::ReturnValue => match role {
            FoundryEndpointRole::Source => vec![FoundryEndpointPort::ReturnValue],
            // A sink consumes an argument or the receiver; a return value is not
            // an input a call site can carry taint into.
            FoundryEndpointRole::Sink => {
                skip(
                    FoundrySkipReason::InputPortUnsupported,
                    format!("a sink cannot read `{port_text}`; a return is not an input"),
                );
                return;
            }
        },
        MadRoot::Argument(items) => items
            .iter()
            .flat_map(|item| match item {
                MadArgumentItem::This => vec![FoundryEndpointPort::Receiver],
                MadArgumentItem::Index(index) => {
                    vec![FoundryEndpointPort::Parameter { ordinal: *index }]
                }
                MadArgumentItem::Range(low, high) => (*low..=*high)
                    .map(|index| FoundryEndpointPort::Parameter { ordinal: index })
                    .collect(),
            })
            .collect::<Vec<_>>(),
    };
    assert!(
        !ports.is_empty(),
        "an access-path root always yields at least one port"
    );
    let qualifier = render_qualifier(&access_path.components);

    let target = FoundryTarget {
        artifact_path: class_file_path(package, type_name),
        member: member_name(type_name, name),
        signature,
    };
    endpoints.push(FoundryTaintEndpoint {
        role,
        target,
        package: package.to_owned(),
        type_name: type_name.to_owned(),
        subtypes,
        ports,
        qualifier,
        kind: kind.to_owned(),
        provenance: provenance.to_owned(),
        evidence: FoundryEvidence {
            file: file.to_owned(),
            row: ordinal,
            text: format!(
                "{package}.{type_name}#{name}{signature_text} {port_text} {kind} {provenance}"
            ),
        },
    });
}

/// Render the trailing access-path components (`.Element`,
/// `.SyntheticField[..]`) as a stable string, or `None` when the row named a
/// bare root port. The port set is the root; this records what the root drops.
fn render_qualifier(components: &[MadComponent]) -> Option<String> {
    if components.is_empty() {
        return None;
    }
    let mut rendered = String::new();
    for component in components {
        rendered.push('.');
        rendered.push_str(&component.name);
        if let Some(argument) = &component.argument {
            rendered.push('[');
            rendered.push_str(argument);
            rendered.push(']');
        }
    }
    Some(rendered)
}

fn translate_summary_row(
    file: &str,
    ordinal: u32,
    row: &[MadCell],
    builders: &mut BTreeMap<FoundryTarget, FoundryEntryBuilder>,
    skips: &mut Vec<FoundrySkip>,
) {
    let mut skip = |reason: FoundrySkipReason, detail: String| {
        skips.push(FoundrySkip {
            file: file.to_owned(),
            row: ordinal,
            reason,
            detail,
        });
    };
    if row.len() != SUMMARY_ROW_COLUMNS {
        skip(
            FoundrySkipReason::MalformedRow,
            format!(
                "summaryModel row has {} columns, expected {SUMMARY_ROW_COLUMNS}",
                row.len()
            ),
        );
        return;
    }
    let package = row[0].text();
    let type_name = row[1].text();
    let Some(subtypes) = row[2].boolean() else {
        skip(
            FoundrySkipReason::MalformedRow,
            format!("subtypes column is not a boolean: {}", row[2].text()),
        );
        return;
    };
    let name = row[3].text();
    let signature_text = row[4].text();
    let extension_qualifier = row[5].text();
    let input_text = row[6].text();
    let output_text = row[7].text();
    let flow_kind = row[8].text();
    let provenance = row[9].text();

    if !extension_qualifier.is_empty() {
        skip(
            FoundrySkipReason::RowQualifierUnsupported,
            format!("row selects a declaration through ext `{extension_qualifier}`"),
        );
        return;
    }
    let signature = match parse_signature(signature_text) {
        Ok(signature) => signature,
        Err(message) => {
            skip(FoundrySkipReason::MalformedRow, message);
            return;
        }
    };
    let input = match parse_access_path(input_text) {
        Ok(path) => path,
        Err(message) => {
            skip(FoundrySkipReason::MalformedRow, message);
            return;
        }
    };
    let output = match parse_access_path(output_text) {
        Ok(path) => path,
        Err(message) => {
            skip(FoundrySkipReason::MalformedRow, message);
            return;
        }
    };
    if !input.components.is_empty() || !output.components.is_empty() {
        skip(
            FoundrySkipReason::AccessPathUnsupported,
            format!("access path `{input_text}` -> `{output_text}` has no authored spelling"),
        );
        return;
    }
    let inputs = match &input.root {
        MadRoot::ReturnValue => {
            skip(
                FoundrySkipReason::InputPortUnsupported,
                "the authored IR has no return-value input".to_owned(),
            );
            return;
        }
        MadRoot::Argument(items) => items
            .iter()
            .flat_map(|item| match item {
                MadArgumentItem::This => vec![AuthoredSummaryInput::Receiver {}],
                MadArgumentItem::Index(index) => {
                    vec![AuthoredSummaryInput::Parameter { ordinal: *index }]
                }
                MadArgumentItem::Range(low, high) => (*low..=*high)
                    .map(|index| AuthoredSummaryInput::Parameter { ordinal: index })
                    .collect(),
            })
            .collect::<Vec<_>>(),
    };
    let authored_output = match &output.root {
        MadRoot::ReturnValue => AuthoredSummaryOutput::NormalReturn {},
        MadRoot::Argument(items) if items.as_slice() == [MadArgumentItem::This] => {
            AuthoredSummaryOutput::Receiver {}
        }
        MadRoot::Argument(_) => {
            skip(
                FoundrySkipReason::OutputPortUnsupported,
                format!("the authored IR has no parameter output for `{output_text}`"),
            );
            return;
        }
    };

    let member = member_name(type_name, name);
    let target = FoundryTarget {
        artifact_path: class_file_path(package, type_name),
        member,
        signature,
    };
    if let Some(arity) = target.signature.arity() {
        for input in &inputs {
            if let AuthoredSummaryInput::Parameter { ordinal: index } = input
                && *index >= arity
            {
                skip(
                    FoundrySkipReason::OrdinalOutOfRange,
                    format!("`{input_text}` exceeds the arity of `{signature_text}`"),
                );
                return;
            }
        }
    }
    let builder = builders.entry(target).or_default();
    for input in inputs {
        builder.add_transfer(AuthoredSummaryTransfer {
            input,
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: authored_output.clone(),
            value_transfer: None,
        });
    }
    builder.add_evidence(FoundryEvidence {
        file: file.to_owned(),
        row: ordinal,
        text: format!(
            "{package}.{type_name}#{name}{signature_text} {input_text} -> {output_text} {flow_kind} {provenance}"
        ),
    });
    if subtypes {
        builder.add_note(FoundryNote::SubtypeClaimNotCarried);
    }
    if !signature_text.is_empty() {
        builder.add_note(FoundryNote::SignatureTypesUnqualified);
    }
}

fn translate_neutral_row(
    file: &str,
    ordinal: u32,
    row: &[MadCell],
    builders: &mut BTreeMap<FoundryTarget, FoundryEntryBuilder>,
    skips: &mut Vec<FoundrySkip>,
) {
    if row.len() != NEUTRAL_ROW_COLUMNS {
        skips.push(FoundrySkip {
            file: file.to_owned(),
            row: ordinal,
            reason: FoundrySkipReason::MalformedRow,
            detail: format!(
                "neutralModel row has {} columns, expected {NEUTRAL_ROW_COLUMNS}",
                row.len()
            ),
        });
        return;
    }
    let package = row[0].text();
    let type_name = row[1].text();
    let name = row[2].text();
    let signature_text = row[3].text();
    let neutral_kind = row[4].text();
    let provenance = row[5].text();
    if neutral_kind != "summary" {
        skips.push(FoundrySkip {
            file: file.to_owned(),
            row: ordinal,
            reason: FoundrySkipReason::RowKindOutOfScope,
            detail: format!("neutral `{neutral_kind}` rows are out of scope"),
        });
        return;
    }
    let signature = match parse_signature(signature_text) {
        Ok(signature) => signature,
        Err(message) => {
            skips.push(FoundrySkip {
                file: file.to_owned(),
                row: ordinal,
                reason: FoundrySkipReason::MalformedRow,
                detail: message,
            });
            return;
        }
    };
    let target = FoundryTarget {
        artifact_path: class_file_path(package, type_name),
        member: member_name(type_name, name),
        signature,
    };
    let builder = builders.entry(target).or_default();
    builder.declare_no_flow();
    builder.add_evidence(FoundryEvidence {
        file: file.to_owned(),
        row: ordinal,
        text: format!("neutral {package}.{type_name}#{name}{signature_text} summary {provenance}"),
    });
}

/// The member name a JVM class file carries.
///
/// Models-as-Data names a constructor after its type, including the innermost
/// segment of a nested type. A class file names every constructor `<init>`,
/// which is also how Joern spells it, so both corpora reduce to one key.
fn member_name(type_name: &str, name: &str) -> String {
    if name == type_name || name == nested_type_simple_name(type_name) {
        "<init>".to_owned()
    } else {
        name.to_owned()
    }
}

/// The root port of a Models-as-Data access path.
///
/// `Argument[..]` selects a set: `Argument[this,0]` and `Argument[0..1]` both
/// name more than one port in one row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MadRoot {
    Argument(Vec<MadArgumentItem>),
    ReturnValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MadArgumentItem {
    This,
    Index(u32),
    Range(u32, u32),
}

/// A parsed Models-as-Data access path: one root port and its qualifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MadAccessPath {
    root: MadRoot,
    components: Vec<MadComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MadComponent {
    name: String,
    argument: Option<String>,
}

/// Parse `Argument[0].SyntheticField[java.lang.Throwable.message]` and friends.
fn parse_access_path(text: &str) -> Result<MadAccessPath, String> {
    let mut components = Vec::new();
    let mut rest = text;
    loop {
        let (component, remainder) = parse_component(rest)?;
        components.push(component);
        match remainder.strip_prefix('.') {
            Some(next) => rest = next,
            None => {
                if remainder.is_empty() {
                    break;
                }
                return Err(format!("unexpected `{remainder}` in access path `{text}`"));
            }
        }
    }
    let mut components = components.into_iter();
    let head = components
        .next()
        .expect("parse_component produces at least one component");
    let root = match head.name.as_str() {
        "Argument" => {
            let argument = head
                .argument
                .ok_or_else(|| format!("`Argument` has no index in `{text}`"))?;
            MadRoot::Argument(parse_argument_set(&argument, text)?)
        }
        "ReturnValue" if head.argument.is_none() => MadRoot::ReturnValue,
        other => return Err(format!("unknown access-path root `{other}` in `{text}`")),
    };
    Ok(MadAccessPath {
        root,
        components: components.collect(),
    })
}

fn parse_component(text: &str) -> Result<(MadComponent, &str), String> {
    let name_end = text
        .find(['.', '['])
        .filter(|index| *index > 0)
        .unwrap_or(text.len());
    if name_end == 0 {
        return Err(format!("empty access-path component in `{text}`"));
    }
    let name = text[..name_end].to_owned();
    let rest = &text[name_end..];
    let Some(inner_start) = rest.strip_prefix('[') else {
        return Ok((
            MadComponent {
                name,
                argument: None,
            },
            rest,
        ));
    };
    let mut depth = 1usize;
    for (index, character) in inner_start.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((
                        MadComponent {
                            name,
                            argument: Some(inner_start[..index].to_owned()),
                        },
                        &inner_start[index + 1..],
                    ));
                }
            }
            _ => {}
        }
    }
    Err(format!("unterminated `[` in access path `{text}`"))
}

fn parse_argument_set(argument: &str, text: &str) -> Result<Vec<MadArgumentItem>, String> {
    split_parameter_types(argument)
        .iter()
        .map(|item| parse_argument_item(item, text))
        .collect()
}

fn parse_argument_item(argument: &str, text: &str) -> Result<MadArgumentItem, String> {
    if argument == "this" {
        return Ok(MadArgumentItem::This);
    }
    if let Some((low, high)) = argument.split_once("..") {
        let low = parse_ordinal(low, text)?;
        let high = parse_ordinal(high, text)?;
        if high < low {
            return Err(format!("argument range `{argument}` is empty in `{text}`"));
        }
        return Ok(MadArgumentItem::Range(low, high));
    }
    Ok(MadArgumentItem::Index(parse_ordinal(argument, text)?))
}

fn parse_ordinal(value: &str, text: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|error| format!("argument ordinal `{value}` in `{text}` is not a count: {error}"))
}

/// Parse a Models-as-Data signature column.
///
/// An empty column states the claim for every overload of the member. A
/// present column is a parenthesised list of erased parameter types.
fn parse_signature(text: &str) -> Result<FoundrySignature, String> {
    if text.is_empty() {
        return Ok(FoundrySignature::AnyOverload);
    }
    let inner = text
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| format!("signature `{text}` is not parenthesised"))?;
    Ok(FoundrySignature::Overload {
        types: split_parameter_types(inner),
    })
}

/// Render a translation's skip counts, for the report and for logging.
pub fn skip_counts(skips: &[FoundrySkip]) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for skip in skips {
        *counts.entry(skip.reason.as_str().to_owned()).or_default() += 1;
    }
    counts
}

/// A stable digest over the exact corpus bytes a translation read.
pub fn corpus_digest(files: &[(String, Vec<u8>)]) -> String {
    use sha2::{Digest, Sha256};

    let mut lines = files
        .iter()
        .map(|(name, bytes)| {
            let mut file_digest = Sha256::new();
            file_digest.update(bytes);
            let mut hex = String::with_capacity(64);
            for byte in file_digest.finalize() {
                write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            }
            format!("{name} {hex}")
        })
        .collect::<Vec<_>>();
    lines.sort();
    let mut digest = Sha256::new();
    for line in &lines {
        digest.update(line.as_bytes());
        digest.update(b"\n");
    }
    let mut hex = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary_foundry::ir::FoundryClaim;

    const SLICE: &str = include_str!("../../testdata/summary-corpora/codeql/java.lang.model.yml");

    fn slice_files() -> Vec<(String, Vec<u8>)> {
        vec![("java.lang.model.yml".to_owned(), SLICE.as_bytes().to_vec())]
    }

    fn entry<'a>(translation: &'a CodeqlTranslation, symbol: &str) -> &'a FoundryEntry {
        translation
            .entries
            .iter()
            .find(|entry| entry.target.signature.symbol(&entry.target.member) == symbol)
            .unwrap_or_else(|| {
                panic!(
                    "no entry for {symbol}; have {:#?}",
                    translation
                        .entries
                        .iter()
                        .map(|entry| entry.target.signature.symbol(&entry.target.member))
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn access_paths_parse_into_root_and_qualifiers() {
        assert_eq!(
            parse_access_path("Argument[this]").unwrap(),
            MadAccessPath {
                root: MadRoot::Argument(vec![MadArgumentItem::This]),
                components: Vec::new(),
            }
        );
        assert_eq!(
            parse_access_path("Argument[0..1]").unwrap().root,
            MadRoot::Argument(vec![MadArgumentItem::Range(0, 1)])
        );
        assert_eq!(
            parse_access_path("Argument[this,0]").unwrap().root,
            MadRoot::Argument(vec![MadArgumentItem::This, MadArgumentItem::Index(0)])
        );
        let qualified = parse_access_path("Argument[this].SyntheticField[java.lang.T.message]")
            .expect("qualified path parses");
        assert_eq!(
            qualified.root,
            MadRoot::Argument(vec![MadArgumentItem::This])
        );
        assert_eq!(
            qualified.components,
            vec![MadComponent {
                name: "SyntheticField".to_owned(),
                argument: Some("java.lang.T.message".to_owned()),
            }]
        );
        assert!(parse_access_path("Receiver[0]").is_err());
    }

    #[test]
    fn signatures_split_on_top_level_commas_only() {
        assert_eq!(parse_signature("").unwrap(), FoundrySignature::AnyOverload);
        assert_eq!(
            parse_signature("()").unwrap(),
            FoundrySignature::Overload { types: Vec::new() }
        );
        assert_eq!(
            parse_signature("(Locale,String,Object[])").unwrap(),
            FoundrySignature::Overload {
                types: vec![
                    "Locale".to_owned(),
                    "String".to_owned(),
                    "Object[]".to_owned()
                ],
            }
        );
        assert_eq!(
            split_parameter_types("Map<String,Object>,int"),
            vec!["Map<String,Object>".to_owned(), "int".to_owned()]
        );
    }

    #[test]
    fn summary_rows_become_transfers_on_the_named_target() {
        let translation = translate_codeql_models(&slice_files()).expect("slice parses");

        let concat = entry(&translation, "concat(String)");
        assert_eq!(concat.claim, FoundryClaim::Flows);
        assert_eq!(
            concat.rendered_transfers(),
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "receiver->normal_return@normal".to_owned(),
            ]
        );
        assert!(concat.boundary.has_receiver);
        assert_eq!(concat.boundary.parameter_count, 1);
        assert_eq!(concat.target.artifact_path, "java/lang/String.class");
        assert_eq!(concat.evidence.len(), 2);
    }

    #[test]
    fn an_argument_range_expands_to_one_transfer_per_ordinal() {
        let translation = translate_codeql_models(&slice_files()).expect("slice parses");

        let join = entry(&translation, "join");
        assert_eq!(
            join.rendered_transfers(),
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "parameter[1]->normal_return@normal".to_owned(),
            ]
        );
        assert!(
            join.notes
                .contains(&FoundryNote::ParameterCountIsLowerBound { observed: 2 })
        );
    }

    #[test]
    fn a_constructor_row_lands_on_the_class_file_member_name() {
        let translation = translate_codeql_models(&slice_files()).expect("slice parses");

        let constructor = entry(&translation, "<init>(String)");
        assert_eq!(
            constructor.rendered_transfers(),
            vec!["parameter[0]->receiver@normal".to_owned()]
        );
        assert!(
            constructor
                .notes
                .contains(&FoundryNote::SubtypeClaimNotCarried)
        );
    }

    #[test]
    fn a_neutral_summary_row_is_a_no_flow_claim_without_an_authored_spelling() {
        let translation = translate_codeql_models(&slice_files()).expect("slice parses");

        let neutral = entry(&translation, "length()");
        assert_eq!(neutral.claim, FoundryClaim::NoFlow);
        assert!(neutral.transfers.is_empty());
        assert!(neutral.authored_summary().is_none());
        assert!(neutral.notes.contains(&FoundryNote::NoFlowClaimNotCarried));
    }

    #[test]
    fn unrepresentable_rows_are_counted_by_typed_reason() {
        let translation = translate_codeql_models(&slice_files()).expect("slice parses");
        let counts = skip_counts(&translation.skips);

        assert_eq!(counts.get("access_path_unsupported"), Some(&2));
        assert_eq!(counts.get("output_port_unsupported"), Some(&1));
        assert_eq!(counts.get("row_kind_out_of_scope"), Some(&3));
        assert_eq!(translation.rows_by_kind.get("sinkModel"), Some(&1));
        assert_eq!(translation.rows_by_kind.get("sourceModel"), Some(&1));
    }

    #[test]
    fn translation_is_deterministic() {
        let first = translate_codeql_models(&slice_files()).expect("slice parses");
        let second = translate_codeql_models(&slice_files()).expect("slice parses");

        assert_eq!(first, second);
    }

    // --- taint endpoint translation (sourceModel / sinkModel) ---

    fn endpoint<'a>(
        translation: &'a CodeqlEndpointTranslation,
        role: FoundryEndpointRole,
        member: &str,
    ) -> &'a FoundryTaintEndpoint {
        translation
            .endpoints
            .iter()
            .find(|endpoint| endpoint.role == role && endpoint.target.member == member)
            .unwrap_or_else(|| {
                panic!(
                    "no {} endpoint for {member}; have {:#?}",
                    role.as_str(),
                    translation
                        .endpoints
                        .iter()
                        .map(|endpoint| (endpoint.role, endpoint.target.member.clone()))
                        .collect::<Vec<_>>()
                )
            })
    }

    /// An inline Models-as-Data document exercising every endpoint shape the
    /// translator must handle. Every row is the real CodeQL column layout.
    const ENDPOINT_SLICE: &str = r#"
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - ["javax.servlet.http", "HttpServletRequest", False, "getParameter", "(String)", "", "ReturnValue", "remote", "manual"]
      - ["java.lang", "System", False, "getenv", "", "", "ReturnValue", "environment", "manual"]
      - ["java.util.function", "Consumer", True, "accept", "(Object)", "", "Argument[0]", "callback", "manual"]
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["java.sql", "Statement", True, "executeQuery", "", "", "Argument[0]", "sql-injection", "manual"]
      - ["javax.servlet.http", "HttpServletResponse", False, "addHeader", "", "", "Argument[0..1]", "response-splitting", "manual"]
      - ["java.lang", "ProcessBuilder", False, "environment", "()", "", "Argument[this]", "command-injection", "manual"]
      - ["java.util", "Collection", True, "addAll", "(Collection)", "", "Argument[0].Element", "unsafe-deserialization", "manual"]
      - ["java.lang", "System", False, "exit", "(int)", "", "ReturnValue", "code-injection", "manual"]
      - ["java.lang", "Runtime", True, "exec", "(String)", "", "", "", "manual", "extra"]
  - addsTo:
      pack: codeql/java-all
      extensible: summaryModel
    data:
      - ["java.lang", "String", False, "concat", "(String)", "", "Argument[this]", "ReturnValue", "taint", "manual"]
"#;

    fn endpoint_slice_files() -> Vec<(String, Vec<u8>)> {
        vec![(
            "endpoints.model.yml".to_owned(),
            ENDPOINT_SLICE.as_bytes().to_vec(),
        )]
    }

    #[test]
    fn a_source_row_names_the_method_and_the_tainted_output_port() {
        let translation =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");

        let get_parameter = endpoint(&translation, FoundryEndpointRole::Source, "getParameter");
        assert_eq!(get_parameter.ports, vec![FoundryEndpointPort::ReturnValue]);
        assert_eq!(get_parameter.kind, "remote");
        assert_eq!(
            get_parameter.declaring_type_fqn(),
            "javax.servlet.http.HttpServletRequest"
        );
        assert_eq!(
            get_parameter.target.artifact_path,
            "javax/servlet/http/HttpServletRequest.class"
        );
        assert!(get_parameter.qualifier.is_none());

        // A source whose tainted output is a parameter (a callback) keeps the
        // parameter port rather than a return.
        let accept = endpoint(&translation, FoundryEndpointRole::Source, "accept");
        assert_eq!(
            accept.ports,
            vec![FoundryEndpointPort::Parameter { ordinal: 0 }]
        );
    }

    #[test]
    fn a_sink_row_names_the_method_and_the_sensitive_input_ports() {
        let translation =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");

        let execute_query = endpoint(&translation, FoundryEndpointRole::Sink, "executeQuery");
        assert_eq!(
            execute_query.ports,
            vec![FoundryEndpointPort::Parameter { ordinal: 0 }]
        );
        assert_eq!(execute_query.kind, "sql-injection");
        assert!(execute_query.subtypes);

        // A range input expands to one sensitive port per ordinal.
        let add_header = endpoint(&translation, FoundryEndpointRole::Sink, "addHeader");
        assert_eq!(
            add_header.ports,
            vec![
                FoundryEndpointPort::Parameter { ordinal: 0 },
                FoundryEndpointPort::Parameter { ordinal: 1 },
            ]
        );

        // A receiver input becomes the receiver port.
        let environment = endpoint(&translation, FoundryEndpointRole::Sink, "environment");
        assert_eq!(environment.ports, vec![FoundryEndpointPort::Receiver]);
    }

    #[test]
    fn a_qualified_endpoint_keeps_the_root_port_and_records_the_qualifier() {
        let translation =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");

        let add_all = endpoint(&translation, FoundryEndpointRole::Sink, "addAll");
        assert_eq!(
            add_all.ports,
            vec![FoundryEndpointPort::Parameter { ordinal: 0 }]
        );
        assert_eq!(add_all.qualifier.as_deref(), Some(".Element"));
    }

    #[test]
    fn unrepresentable_endpoint_rows_are_counted_by_typed_reason() {
        let translation =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");
        let counts = skip_counts(&translation.skips);

        // A sink cannot read a return value.
        assert_eq!(counts.get("input_port_unsupported"), Some(&1));
        // The Runtime.exec row has ten columns, not nine.
        assert_eq!(counts.get("malformed_row"), Some(&1));
        // The summaryModel row is out of scope for endpoint translation.
        assert_eq!(counts.get("row_kind_out_of_scope"), Some(&1));
        assert_eq!(translation.rows_by_kind.get("summaryModel"), Some(&1));
        assert_eq!(translation.rows_by_kind.get("sourceModel"), Some(&3));
        assert_eq!(translation.rows_by_kind.get("sinkModel"), Some(&6));

        // The malformed and unsupported rows never produce an endpoint. The
        // slice defines three sources and four well-formed sinks (executeQuery,
        // addHeader, environment, and the qualified addAll); the ReturnValue
        // sink and the ten-column row are skipped.
        let sources = translation
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == FoundryEndpointRole::Source)
            .count();
        let sinks = translation
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.role == FoundryEndpointRole::Sink)
            .count();
        assert_eq!((sources, sinks), (3, 4));
    }

    #[test]
    fn the_two_translators_partition_the_corpus_rows() {
        // The checked-in slice carries both halves. The summary translator sees
        // the source/sink rows as out of scope; the endpoint translator sees the
        // summary/neutral rows as out of scope. Neither drops a row in silence.
        let summary = translate_codeql_models(&slice_files()).expect("slice parses");
        let endpoints = translate_codeql_taint_endpoints(&slice_files()).expect("slice parses");

        assert_eq!(endpoints.endpoints.len(), 2);
        let get_env = endpoint(&endpoints, FoundryEndpointRole::Source, "getenv");
        assert_eq!(get_env.ports, vec![FoundryEndpointPort::ReturnValue]);
        let exec = endpoint(&endpoints, FoundryEndpointRole::Sink, "exec");
        assert_eq!(
            exec.ports,
            vec![FoundryEndpointPort::Parameter { ordinal: 0 }]
        );
        assert!(exec.subtypes);

        // Every row the summary translator counted appears under its kind, and
        // the endpoint translator counts the same kinds from the other side.
        assert_eq!(summary.rows_by_kind.get("sourceModel"), Some(&1));
        assert_eq!(summary.rows_by_kind.get("sinkModel"), Some(&1));
        assert_eq!(endpoints.rows_by_kind.get("summaryModel"), Some(&7));
        assert_eq!(endpoints.rows_by_kind.get("neutralModel"), Some(&2));
    }

    #[test]
    fn endpoint_translation_is_deterministic() {
        let first =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");
        let second =
            translate_codeql_taint_endpoints(&endpoint_slice_files()).expect("slice parses");

        assert_eq!(first, second);
    }
}
