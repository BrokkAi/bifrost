//! The procedure-summary model foundry (#1871).
//!
//! This module owns the foundry's interchange form, the corpus translators that
//! feed it, and the derivation that produces Bifrost's own answers. It is
//! generation-time tooling: it lives behind the `release-tooling` feature, next
//! to the pinned-pack release bundle, and no analyzer or runtime path depends
//! on it.
//!
//! One run reads the pinned external corpora, translates each into the
//! authored procedure-summary IR, derives summaries from the pinned standard
//! library sources with the analyzer's own value-flow machinery, compiles the
//! translated and derived entries back through the production pack compiler,
//! and joins the three slots into one deterministic report. Two runs over the
//! same pins produce byte-identical output.

pub mod adjudicate;
pub mod codeql;
pub mod demand;
pub mod derive;
pub mod driver;
pub mod fixture;
pub mod framework_pack;
pub mod golden_pack;
pub mod ir;
pub mod joern;
pub mod join;
pub mod sanitizer;
pub mod sanitizer_pack;
pub mod store;
pub mod taint_policy;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, Compatibility,
    CompilerOptions, Completeness, Diagnostic, Producer, Provenance, Safety, SourceFormat,
    compile_source,
};
use serde::{Deserialize, Serialize};

use codeql::{CodeqlParseError, corpus_digest, skip_counts, translate_codeql_models};
use derive::{DERIVED_OUTPUT_PORTS, DerivationLimits, derive_jvm_summaries};
use ir::{FoundryClaim, FoundryCorpus, FoundryEntry, FoundrySkip};
use joern::{
    JoernParseError, parse_default_semantics_scala, parse_semantics_dsl, translate_joern_semantics,
};
use join::{FoundryJoin, join_corpora};

/// Shared foundry producer version. Advance it when a converter changes the
/// shape of its output. It is not the crate version: checked-in packs are
/// gated on byte equality with the generator, and reading the crate version
/// would break that gate at every release bump without any content change.
pub const FOUNDRY_PRODUCER_VERSION: &str = "0.9.0";

/// Bifrost compatibility window every foundry-generated pack declares. It is
/// a pack contract, not the crate version. `release-version.mjs` used to
/// rewrite the exclusive upper bound from the crate minor, which would
/// deactivate already-shipped packs at 0.11 without any content change.
/// Advance this only when a generated pack actually requires a newer Bifrost.
pub const FOUNDRY_BIFROST_REQUIREMENT: &str = ">=0.8.0, <1.0.0";

/// The report format tag. Bump it when a consumer must read the file
/// differently, not when a field is added.
pub const FOUNDRY_JOIN_REPORT_FORMAT: &str = "bifrost_summary_foundry_join/v1";

/// The `DefaultSemantics.scala` definition that holds the JVM corpus.
const JOERN_JAVA_DEFINITION: &str = "javaFlows";

/// The suffix every Models-as-Data file carries.
const MODEL_FILE_SUFFIX: &str = ".model.yml";

/// The provenance of the derived slot. Its content comes from this tool over
/// the pinned sources, not from an upstream corpus, so it names itself.
fn derived_pin() -> FoundryPin {
    FoundryPin {
        upstream: "https://github.com/BrokkAi/bifrost".to_owned(),
        revision: env!("CARGO_PKG_VERSION").to_owned(),
        license: "Apache-2.0".to_owned(),
    }
}

/// Where one corpus came from, recorded in every report it produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundryPin {
    pub upstream: String,
    pub revision: String,
    pub license: String,
}

/// The checked-in pin record for one corpus.
///
/// The pins file is the single source of truth for both the acquisition script
/// and this tool, so a revision bump is one edit and a report can never claim a
/// revision the download did not use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundryPinRecord {
    pub corpus: FoundryCorpus,
    #[serde(flatten)]
    pub pin: FoundryPin,
    pub archive: FoundryArchivePin,
}

/// The pinned archive that carries one corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundryArchivePin {
    pub url: String,
    pub sha256: String,
    /// The path inside the archive that the foundry reads.
    pub member: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoundryPins {
    pub schema_version: u32,
    pub corpora: Vec<FoundryPinRecord>,
}

impl FoundryPins {
    pub fn read(path: &Path) -> Result<Self, FoundryError> {
        let bytes = fs::read(path).map_err(|error| FoundryError::Io {
            path: path.to_path_buf(),
            error,
        })?;
        let pins: Self = serde_json::from_slice(&bytes).map_err(|error| FoundryError::Pins {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        if pins.schema_version != 1 {
            return Err(FoundryError::Pins {
                path: path.to_path_buf(),
                message: format!("unsupported pins schema_version {}", pins.schema_version),
            });
        }
        Ok(pins)
    }

    pub fn pin(&self, corpus: FoundryCorpus) -> Option<&FoundryPin> {
        self.corpora
            .iter()
            .find(|record| record.corpus == corpus)
            .map(|record| &record.pin)
    }
}

/// One foundry run's inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundryRunInputs {
    /// The directory of `*.model.yml` files, for example `java/ql/lib/ext`.
    pub codeql_models: PathBuf,
    pub codeql_pin: FoundryPin,
    /// `DefaultSemantics.scala`, or a `.semantics` file in Joern's DSL.
    pub joern_source: PathBuf,
    pub joern_pin: FoundryPin,
    /// The package root of the extracted pinned standard-library sources. A run
    /// without it leaves the derived slot empty and says so in the report.
    pub jvm_sources: Option<PathBuf>,
    pub derivation_limits: DerivationLimits,
}

impl FoundryRunInputs {
    /// Build a run from the checked-in pins and the extracted corpus paths.
    pub fn from_pins(
        pins: &FoundryPins,
        codeql_models: PathBuf,
        joern_source: PathBuf,
    ) -> Result<Self, FoundryError> {
        let codeql_pin = pins
            .pin(FoundryCorpus::Codeql)
            .ok_or(FoundryError::MissingPin {
                corpus: FoundryCorpus::Codeql,
            })?
            .clone();
        let joern_pin = pins
            .pin(FoundryCorpus::Joern)
            .ok_or(FoundryError::MissingPin {
                corpus: FoundryCorpus::Joern,
            })?
            .clone();
        Ok(Self {
            codeql_models,
            codeql_pin,
            joern_source,
            joern_pin,
            jvm_sources: None,
            derivation_limits: DerivationLimits::default(),
        })
    }
}

#[derive(Debug)]
pub enum FoundryError {
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    NotUtf8 {
        path: PathBuf,
    },
    UnknownJoernFormat {
        path: PathBuf,
    },
    Pins {
        path: PathBuf,
        message: String,
    },
    MissingPin {
        corpus: FoundryCorpus,
    },
    Codeql(CodeqlParseError),
    Joern {
        path: PathBuf,
        error: JoernParseError,
    },
    Derivation {
        detail: String,
    },
}

impl fmt::Display for FoundryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => {
                write!(formatter, "cannot read {}: {error}", path.display())
            }
            Self::NotUtf8 { path } => write!(formatter, "{} is not UTF-8", path.display()),
            Self::UnknownJoernFormat { path } => write!(
                formatter,
                "{} is neither a .scala default-semantics file nor a .semantics file",
                path.display()
            ),
            Self::Pins { path, message } => {
                write!(formatter, "cannot read pins {}: {message}", path.display())
            }
            Self::MissingPin { corpus } => write!(
                formatter,
                "the pins file declares no `{}` corpus",
                corpus.as_str()
            ),
            Self::Codeql(error) => write!(formatter, "cannot read Models-as-Data: {error}"),
            Self::Joern { path, error } => {
                write!(formatter, "cannot read {}: {error}", path.display())
            }
            Self::Derivation { detail } => write!(formatter, "cannot derive summaries: {detail}"),
        }
    }
}

impl std::error::Error for FoundryError {}

/// One corpus and the exact bytes this run translated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryCorpusRecord {
    pub corpus: FoundryCorpus,
    pub upstream: String,
    pub revision: String,
    pub license: String,
    /// A digest over the corpus bytes, so a report states which content it
    /// read and not only which revision was asked for.
    pub source_sha256: String,
}

/// What one corpus translation produced and what it could not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryTranslationReport {
    pub corpus: FoundryCorpus,
    pub files_read: u32,
    pub rows_read: u32,
    pub rows_by_kind: BTreeMap<String, u32>,
    pub entries: u32,
    pub flow_entries: u32,
    pub no_flow_entries: u32,
    pub transfers: u32,
    pub skipped_rows: u32,
    pub skips_by_reason: BTreeMap<String, u32>,
    pub notes_by_kind: BTreeMap<String, u32>,
    pub skips: Vec<FoundrySkip>,
}

/// The result of compiling one corpus's translated entries with the production
/// pack compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryRoundTripReport {
    pub corpus: FoundryCorpus,
    /// Entries with an authored spelling. A no-flow claim has none.
    pub entries: u32,
    pub shards: u32,
    pub manifest_content_sha256: Option<String>,
    pub diagnostics: Vec<String>,
}

/// What the derivation over the pinned sources produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryDerivationReport {
    pub files_read: u32,
    pub procedures_read: u32,
    pub entries: u32,
    pub flow_entries: u32,
    pub no_flow_entries: u32,
    pub complete_entries: u32,
    pub transfers: u32,
    /// Derived flows whose granularity the authored IR cannot carry. The
    /// entries ship the argument-level projection; this counts what the
    /// projection dropped.
    pub qualified_flows: u32,
    pub boundaries_by_kind: BTreeMap<String, u32>,
    /// Output ports this stage observes. Any other output is silent, not
    /// denied.
    pub observed_output_ports: Vec<String>,
    /// Files the semantic provider could not materialize, with its reason.
    pub unavailable_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryReport {
    pub format: String,
    pub corpora: Vec<FoundryCorpusRecord>,
    pub translation: Vec<FoundryTranslationReport>,
    /// Absent when the run had no pinned sources to derive from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation: Option<FoundryDerivationReport>,
    pub round_trip: Vec<FoundryRoundTripReport>,
    pub join: FoundryJoin,
}

impl FoundryReport {
    /// Whether every translated entry compiled without a diagnostic.
    pub fn round_trip_is_clean(&self) -> bool {
        self.round_trip
            .iter()
            .all(|report| report.diagnostics.is_empty())
    }

    /// The report as deterministic JSON, newline terminated.
    pub fn to_json(&self) -> String {
        let mut rendered =
            serde_json::to_string_pretty(self).expect("the foundry report is serializable");
        rendered.push('\n');
        rendered
    }
}

/// Translate both pinned corpora, derive from the pinned sources, round-trip
/// every entry, and join the three slots.
pub fn run_foundry_join(inputs: &FoundryRunInputs) -> Result<FoundryReport, FoundryError> {
    let codeql_files = read_codeql_models(&inputs.codeql_models)?;
    let codeql = translate_codeql_models(&codeql_files).map_err(FoundryError::Codeql)?;

    let joern_name = file_name(&inputs.joern_source);
    let joern_text = read_utf8(&inputs.joern_source)?;
    let joern_semantics = match Path::new(&joern_name)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("scala") => parse_default_semantics_scala(&joern_text, JOERN_JAVA_DEFINITION),
        Some("semantics") => parse_semantics_dsl(&joern_text),
        _ => {
            return Err(FoundryError::UnknownJoernFormat {
                path: inputs.joern_source.clone(),
            });
        }
    }
    .map_err(|error| FoundryError::Joern {
        path: inputs.joern_source.clone(),
        error,
    })?;
    let joern = translate_joern_semantics(&joern_name, &joern_semantics);

    let derived = match &inputs.jvm_sources {
        Some(sources) => Some(derive_jvm_summaries(sources, inputs.derivation_limits)?),
        None => None,
    };
    let derived_entries = derived
        .as_ref()
        .map_or(&[][..], |run| run.entries.as_slice());

    let join = join_corpora(&[
        (FoundryCorpus::Codeql, &codeql.entries),
        (FoundryCorpus::Joern, &joern.entries),
        (FoundryCorpus::Derived, derived_entries),
    ]);

    Ok(FoundryReport {
        format: FOUNDRY_JOIN_REPORT_FORMAT.to_owned(),
        corpora: vec![
            FoundryCorpusRecord {
                corpus: FoundryCorpus::Codeql,
                upstream: inputs.codeql_pin.upstream.clone(),
                revision: inputs.codeql_pin.revision.clone(),
                license: inputs.codeql_pin.license.clone(),
                source_sha256: corpus_digest(&codeql_files),
            },
            FoundryCorpusRecord {
                corpus: FoundryCorpus::Joern,
                upstream: inputs.joern_pin.upstream.clone(),
                revision: inputs.joern_pin.revision.clone(),
                license: inputs.joern_pin.license.clone(),
                source_sha256: corpus_digest(&[(
                    joern_name.clone(),
                    joern_text.as_bytes().to_vec(),
                )]),
            },
        ],
        translation: vec![
            translation_report(
                FoundryCorpus::Codeql,
                codeql.files_read,
                codeql.rows_by_kind,
                &codeql.entries,
                codeql.skips,
            ),
            translation_report(
                FoundryCorpus::Joern,
                1,
                BTreeMap::from([("flowSemantic".to_owned(), joern.semantics_read)]),
                &joern.entries,
                joern.skips,
            ),
        ],
        derivation: derived.as_ref().map(derivation_report),
        round_trip: vec![
            round_trip(FoundryCorpus::Codeql, &codeql.entries, &inputs.codeql_pin),
            round_trip(FoundryCorpus::Joern, &joern.entries, &inputs.joern_pin),
            round_trip(FoundryCorpus::Derived, derived_entries, &derived_pin()),
        ],
        join,
    })
}

fn derivation_report(run: &derive::DerivationRun) -> FoundryDerivationReport {
    let mut boundaries_by_kind: BTreeMap<String, u32> = BTreeMap::new();
    let mut complete_entries = 0u32;
    let mut qualified_flows = 0u32;
    for entry in &run.entries {
        let Some(derivation) = &entry.derivation else {
            continue;
        };
        if entry.completeness == ir::FoundryCompleteness::Complete {
            complete_entries += 1;
        }
        qualified_flows += derivation.qualified_flows().len() as u32;
        for boundary in &derivation.boundaries {
            *boundaries_by_kind
                .entry(boundary.kind().to_owned())
                .or_default() += 1;
        }
    }
    FoundryDerivationReport {
        files_read: run.files_read,
        procedures_read: run.procedures_read,
        entries: run.entries.len() as u32,
        flow_entries: run
            .entries
            .iter()
            .filter(|entry| entry.claim == FoundryClaim::Flows)
            .count() as u32,
        no_flow_entries: run
            .entries
            .iter()
            .filter(|entry| entry.claim == FoundryClaim::NoFlow)
            .count() as u32,
        complete_entries,
        transfers: run
            .entries
            .iter()
            .map(|entry| entry.transfers.len() as u32)
            .sum(),
        qualified_flows,
        boundaries_by_kind,
        observed_output_ports: DERIVED_OUTPUT_PORTS
            .iter()
            .map(|port| (*port).to_owned())
            .collect(),
        unavailable_files: run.unavailable_files.clone(),
    }
}

fn translation_report(
    corpus: FoundryCorpus,
    files_read: u32,
    rows_by_kind: BTreeMap<String, u32>,
    entries: &[FoundryEntry],
    skips: Vec<FoundrySkip>,
) -> FoundryTranslationReport {
    let mut notes_by_kind: BTreeMap<String, u32> = BTreeMap::new();
    for entry in entries {
        for note in &entry.notes {
            *notes_by_kind.entry(note.kind().to_owned()).or_default() += 1;
        }
    }
    FoundryTranslationReport {
        corpus,
        files_read,
        rows_read: rows_by_kind.values().sum(),
        rows_by_kind,
        entries: entries.len() as u32,
        flow_entries: entries
            .iter()
            .filter(|entry| entry.claim == FoundryClaim::Flows)
            .count() as u32,
        no_flow_entries: entries
            .iter()
            .filter(|entry| entry.claim == FoundryClaim::NoFlow)
            .count() as u32,
        transfers: entries
            .iter()
            .map(|entry| entry.transfers.len() as u32)
            .sum(),
        skipped_rows: skips.len() as u32,
        skips_by_reason: skip_counts(&skips),
        notes_by_kind,
        skips,
    }
}

/// Compile one corpus's translated entries with the production pack compiler.
///
/// The entries are serialized as an authored pack and read back through
/// [`compile_source`], so the check covers the authored serde contract, the
/// validator, and canonical compilation, exactly as an authored pack would.
fn round_trip(
    corpus: FoundryCorpus,
    entries: &[FoundryEntry],
    pin: &FoundryPin,
) -> FoundryRoundTripReport {
    let summaries = entries
        .iter()
        .filter_map(FoundryEntry::authored_summary)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return FoundryRoundTripReport {
            corpus,
            entries: 0,
            shards: 0,
            manifest_content_sha256: None,
            diagnostics: Vec::new(),
        };
    }
    let entry_count = summaries.len() as u32;
    // A pack's claim has to dominate its members': the validator rejects a
    // `complete` summary inside a `partial` pack (`summary.completeness_exceeds_pack`).
    let completeness = if summaries
        .iter()
        .any(|summary| summary.completeness == Completeness::Complete)
    {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    let pack = AuthoredSemanticModelPack {
        schema_version: 2,
        pack_id: format!("bifrost.summary-foundry.{}", corpus.as_str()),
        version: "0.0.0".to_owned(),
        producer: Producer {
            name: "bifrost-summary-foundry".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        language: "java".to_owned(),
        ecosystem: "maven".to_owned(),
        compatibility: Compatibility {
            bifrost: ">=0.8.0, <1.0.0".to_owned(),
            toolchains: Vec::new(),
        },
        provenance: Provenance {
            source: pin.upstream.clone(),
            revision: Some(pin.revision.clone()),
        },
        license: pin.license.clone(),
        completeness,
        safety: Safety {
            generated_code_only: false,
            review_required: true,
        },
        carried_sources: Vec::new(),
        cpp_portability: None,
        shards: vec![AuthoredShard {
            id: format!("summaries.{}", corpus.as_str()),
            // The language-intrinsic activation form: the corpus names classes
            // and members, never a package coordinate.
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            payload: AuthoredPayload::ProcedureSummaries { summaries },
        }],
    };
    let source = serde_json::to_vec(&pack).expect("the authored pack is serializable");
    match compile_source(SourceFormat::Json, &source, &CompilerOptions::default()) {
        Ok(compiled) => FoundryRoundTripReport {
            corpus,
            entries: entry_count,
            shards: compiled.shards.len() as u32,
            manifest_content_sha256: Some(compiled.manifest.content_sha256),
            diagnostics: Vec::new(),
        },
        Err(diagnostics) => FoundryRoundTripReport {
            corpus,
            entries: entry_count,
            shards: 0,
            manifest_content_sha256: None,
            diagnostics: diagnostics.iter().map(render_diagnostic).collect(),
        },
    }
}

fn render_diagnostic(diagnostic: &Diagnostic) -> String {
    format!(
        "{:?} {} {}: {}",
        diagnostic.severity, diagnostic.code, diagnostic.path, diagnostic.message
    )
}

/// Read every Models-as-Data file in a directory, in file-name order.
pub fn read_codeql_models(directory: &Path) -> Result<Vec<(String, Vec<u8>)>, FoundryError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| FoundryError::Io {
        path: directory.to_path_buf(),
        error,
    })? {
        let entry = entry.map_err(|error| FoundryError::Io {
            path: directory.to_path_buf(),
            error,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(MODEL_FILE_SUFFIX) {
            names.push(name);
        }
    }
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let path = directory.join(&name);
            let bytes = fs::read(&path).map_err(|error| FoundryError::Io {
                path: path.clone(),
                error,
            })?;
            Ok((name, bytes))
        })
        .collect()
}

fn read_utf8(path: &Path) -> Result<String, FoundryError> {
    let bytes = fs::read(path).map_err(|error| FoundryError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    String::from_utf8(bytes).map_err(|_| FoundryError::NotUtf8 {
        path: path.to_path_buf(),
    })
}

/// The file name a report records, never a host path.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_inputs() -> FoundryRunInputs {
        let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/summary-corpora");
        FoundryRunInputs {
            codeql_models: testdata.join("codeql"),
            codeql_pin: FoundryPin {
                upstream: "https://github.com/github/codeql".to_owned(),
                revision: "c9142680f5b6409dbe0944350321c54e8c801e61".to_owned(),
                license: "MIT".to_owned(),
            },
            joern_source: testdata.join("joern/DefaultSemantics.scala"),
            joern_pin: FoundryPin {
                upstream: "https://github.com/joernio/joern".to_owned(),
                revision: "8a73ec09be8fa59dba3cfed5959690c003d7ca52".to_owned(),
                license: "Apache-2.0".to_owned(),
            },
            jvm_sources: None,
            derivation_limits: DerivationLimits::default(),
        }
    }

    /// The same run with the pinned JDK slices, so the derived slot is live.
    fn fixture_inputs_with_derivation() -> FoundryRunInputs {
        FoundryRunInputs {
            jvm_sources: Some(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("testdata/summary-sources/temurin-jdk-21.0.8+9"),
            ),
            ..fixture_inputs()
        }
    }

    #[test]
    fn every_translated_entry_round_trips_through_the_pack_compiler() {
        let report = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");

        assert!(
            report.round_trip_is_clean(),
            "round trip diagnostics: {:#?}",
            report.round_trip
        );
        for round_trip in &report.round_trip {
            if round_trip.corpus == FoundryCorpus::Derived {
                // The derived slot is empty in this run.
                assert_eq!(round_trip.entries, 0, "{round_trip:?}");
                continue;
            }
            assert!(round_trip.entries > 0, "{round_trip:?}");
            assert_eq!(round_trip.shards, 1, "{round_trip:?}");
            assert!(round_trip.manifest_content_sha256.is_some());
        }
    }

    #[test]
    fn every_derived_entry_round_trips_through_the_pack_compiler() {
        let report = run_foundry_join(&fixture_inputs_with_derivation())
            .expect("the fixture corpora and pinned slices run");

        assert!(
            report.round_trip_is_clean(),
            "round trip diagnostics: {:#?}",
            report.round_trip
        );
        let derived = report
            .round_trip
            .iter()
            .find(|round_trip| round_trip.corpus == FoundryCorpus::Derived)
            .expect("the derived slot is reported");
        assert!(derived.entries > 0, "{derived:?}");
        assert_eq!(derived.shards, 1, "{derived:?}");
    }

    #[test]
    fn the_derived_slot_classifies_against_codeql_at_the_argument_level_projection() {
        let report = run_foundry_join(&fixture_inputs_with_derivation())
            .expect("the fixture corpora and pinned slices run");

        let derivation = report.derivation.expect("the run derived");
        assert_eq!(derivation.files_read, 2);
        assert!(derivation.entries > 0);
        assert_eq!(
            derivation.observed_output_ports,
            vec!["normal_return".to_owned(), "exceptional_return".to_owned()]
        );
        assert_eq!(
            derivation.boundaries_by_kind.get("native_callee"),
            Some(&1),
            "boundaries: {:?}",
            derivation.boundaries_by_kind
        );

        assert!(
            report
                .join
                .slots
                .iter()
                .any(|slot| slot.corpus == FoundryCorpus::Derived && slot.populated)
        );
        // CodeQL states `Objects.requireNonNullElse` without a signature, so its
        // key pins no overload. The derived entry pins arity 2. Both keys are
        // gaps against each other, and the gap names the sibling so a reviewer
        // sees the neighbourhood.
        let derived_gap = report
            .join
            .gaps
            .iter()
            .find(|gap| {
                gap.key.artifact_path == "java/util/Objects.class"
                    && gap.key.member == "requireNonNullElse"
                    && gap.key.arity == Some(2)
            })
            .expect("the derived entry is a gap against the unsigned CodeQL row");
        assert_eq!(
            derived_gap.views["derived"].transfers,
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "parameter[1]->normal_return@normal".to_owned(),
            ]
        );
        let codeql_row = report
            .join
            .gaps
            .iter()
            .find(|gap| {
                gap.key.artifact_path == "java/util/Objects.class"
                    && gap.key.member == "requireNonNullElse"
                    && gap.key.arity.is_none()
            })
            .expect("the unsigned CodeQL row keeps its own key");
        assert_eq!(
            codeql_row.views["codeql"].transfers, derived_gap.views["derived"].transfers,
            "the derived transfers match the CodeQL translation exactly"
        );
    }

    #[test]
    fn the_report_states_counts_for_both_corpora_and_the_empty_derived_slot() {
        let report = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");

        let codeql = &report.translation[0];
        assert_eq!(codeql.corpus, FoundryCorpus::Codeql);
        assert_eq!(codeql.files_read, 3);
        assert_eq!(codeql.rows_by_kind.get("summaryModel"), Some(&14));
        assert!(codeql.entries > 0);
        assert_eq!(codeql.no_flow_entries, 1);
        assert!(codeql.skipped_rows > 0);

        let joern = &report.translation[1];
        assert_eq!(joern.corpus, FoundryCorpus::Joern);
        assert_eq!(joern.no_flow_entries, 1);

        assert_eq!(
            report
                .join
                .slots
                .iter()
                .find(|slot| slot.corpus == FoundryCorpus::Derived)
                .map(|slot| slot.populated),
            Some(false)
        );
    }

    #[test]
    fn the_two_corpora_agree_on_the_no_flow_claim_they_share() {
        let report = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");

        let agreement = report
            .join
            .agreements
            .iter()
            .find(|agreement| agreement.key.member == "length")
            .expect("both corpora state String.length carries no flow");

        assert_eq!(agreement.claim, FoundryClaim::NoFlow);
        assert_eq!(agreement.key.artifact_path, "java/lang/String.class");
        assert!(agreement.transfers.is_empty());
        assert!(report.join.gap_count > 0);
    }

    #[test]
    fn one_row_that_names_an_argument_set_produces_one_transfer_per_port() {
        let report = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");

        let gap = report
            .join
            .gaps
            .iter()
            .find(|gap| {
                gap.key.artifact_path
                    == "org/springframework/web/util/DefaultUriBuilderFactory.class"
            })
            .expect("the Argument[this,0] row produced an entry");

        assert_eq!(
            gap.views["codeql"].transfers,
            vec![
                "parameter[0]->normal_return@normal".to_owned(),
                "receiver->normal_return@normal".to_owned(),
            ]
        );
    }

    #[test]
    fn two_runs_over_the_same_pins_are_byte_identical() {
        let first = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");
        let second = run_foundry_join(&fixture_inputs()).expect("the fixture corpora translate");

        assert_eq!(first.to_json(), second.to_json());
    }
}
