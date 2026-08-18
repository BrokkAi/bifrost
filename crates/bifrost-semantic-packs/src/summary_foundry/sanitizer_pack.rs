//! Convert the audited k3 sanitizer candidates into shippable
//! `procedure_summaries` packs, gated through the M4 adversarial mechanism gate
//! (#1871, #1923).
//!
//! Each candidate carries an audited claim: a method neutralizes taint for a set
//! of injection contexts (`neutralizes`) and explicitly does not for another set
//! (`does_not_neutralize`). This converter maps that claim onto the shipped
//! pack IR #1923 added:
//!
//! * `neutralizes` -> a `Sanitize` effect's `removes` labels (each context token
//!   is the taint label a policy sources and accepts);
//! * `sanitized_input` -> the effect's `input` port;
//! * `output` -> the effect's `output` port;
//! * the target is carried from the candidate.
//!
//! A `Sanitize` effect must ride a declared transfer with the same ports (the
//! validator enforces `summary.sanitize_without_transfer`), so every summary
//! also carries the matching `input -> output` transfer. The labels the entry
//! lists under `does_not_neutralize` are exactly the labels the transfer leaves
//! flowing, because they are absent from `removes`.
//!
//! Every candidate runs through [`gate_sanitizer`], the adversarial mechanism
//! gate: it expresses each `neutralizes` context as a probe over that context's
//! real breakout metacharacter and each `does_not_neutralize` context as a
//! survival probe. A candidate the gate rejects is never shipped on its
//! assertion; it is recorded in the audit report. Real-body verification (that a
//! real escaper's body actually encodes the metacharacter) is the separate M4
//! seam, a tracked follow-up, not this converter.
//!
//! Packs are organized one per artifact, mirroring the checked-in declaration
//! packs (`bifrost.jdk`, `kotlin-stdlib`, ...), because a pack pins one
//! artifact. The JDK-artifact entries ship as `bifrost.java-sanitizers`, pinned
//! by the `jdk` toolchain. The external-library entries target Maven
//! coordinates whose byte-level artifact digest cannot be produced here without
//! the jar, so they are generated but staged unpinned (a package coordinate,
//! no `artifact_sha256`), with the reason recorded, rather than shipped on a
//! faked pin.
//!
//! The whole conversion is a deterministic function of the candidate content:
//! two runs produce byte-identical pack sources and audit report, with no clock.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryEffect, AuthoredSummaryExitKind,
    AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer, Compatibility,
    CompilerOptions, Completeness, NameSelector, Producer, Provenance, Safety, SourceFormat,
    VersionConstraint, compile_source,
};
use serde::{Deserialize, Serialize};

use super::sanitizer::{
    InjectionContext, SanitizerCompleteness, SanitizerEntry, SanitizerPort, SanitizerRejection,
    gate_sanitizer,
};

/// The audit-report format tag. Bump it when a consumer must read the file
/// differently, not when a field is added.
pub const SANITIZER_PACK_AUDIT_FORMAT: &str = "bifrost_sanitizer_pack_audit/v1";

/// The producer name recorded in every generated pack.
const PRODUCER_NAME: &str = "bifrost-sanitizer-foundry";

/// The sanitizer foundry's own version, advanced when the converter changes the
/// shape of its output. It is deliberately not the crate version: the checked-in
/// packs are gated on byte equality with this generator, and reading the crate
/// version would break that gate at every release bump without any content
/// change. `golden_pack.rs` states the same rule; #1871 applied it there and
/// left this converter behind, which is what made
/// `the_checked_in_packs_match_the_generator` fail at v0.10.3.
const PRODUCER_VERSION: &str = "0.9.0";

/// The pack content version. It is the sanitizer content's own version, not the
/// Bifrost version, and advances when the shipped claims change.
const PACK_CONTENT_VERSION: &str = "0.1.0";

/// The Bifrost compatibility requirement every generated pack declares.
const BIFROST_REQUIREMENT: &str = ">=0.8.0, <0.11.0";

/// The authored sanitizer content is Bifrost's own claim, not a slice of the
/// described library. New Bifrost-owned public packs use the public project
/// license; retained packs may declare their own provenance and license in
/// their checked-in metadata.
const PACK_LICENSE: &str = "Apache-2.0";

/// The JDK toolchain requirement. Every claimed API (`Integer.parseInt`,
/// `Base64`, `URLEncoder(String, Charset)`, `UUID`) exists in Java 17 and later.
const JDK_TOOLCHAIN_REQUIREMENT: &str = ">=17.0.0";

/// The one artifact string that names the JDK rather than a Maven coordinate.
const JDK_ARTIFACT: &str = "jdk";

/// One generated pack: its identity, whether it is byte-pinned, and its source
/// text ready to write and to compile through the production compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSanitizerPack {
    pub pack_id: String,
    /// The artifact the pack pins: `"jdk"` or a Maven coordinate.
    pub artifact: String,
    /// The path under the output root, so the writer keeps staged packs apart
    /// from the pinned one without a second decision.
    pub relative_path: PathBuf,
    /// A pinned pack activates on a concrete artifact identity (the JDK
    /// toolchain). A staged pack carries the coordinate but no byte-level
    /// `artifact_sha256`, because the jar is not available here to digest.
    pub pinned: bool,
    /// The pack source JSON, pretty-printed with a trailing newline. This is the
    /// exact checked-in bytes and the exact input to `compile_source`.
    pub source_json: String,
}

/// The structured audit report written beside the packs as `rejects.json`. It is
/// the real audit outcome: every candidate's disposition, deterministic and
/// clock-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerAuditReport {
    pub format: String,
    pub candidates_total: usize,
    pub gate_rejected: usize,
    pub shipped_summaries: usize,
    pub folded_overloads: usize,
    /// The total adversarial probes the gate generated over every shipped
    /// candidate. This is the mechanism-proof volume: one probe per claimed or
    /// disclaimed injection context, each injecting a real breakout
    /// metacharacter.
    pub adversarial_probes: usize,
    pub gate_rejects: Vec<SanitizerGateReject>,
    pub folded: Vec<FoldedOverload>,
    pub packs: Vec<SanitizerPackAudit>,
}

/// One candidate the adversarial gate rejected, never shipped on its assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerGateReject {
    pub artifact: String,
    pub target_path: String,
    pub target_symbol: String,
    /// The rejection reason code, stable across runs.
    pub reason: String,
    pub message: String,
}

/// One overload folded into an identical-claim twin because the audited symbol
/// carries no signature and the pack forbids two summaries on one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoldedOverload {
    pub artifact: String,
    pub target_path: String,
    pub target_symbol: String,
    pub kept_parameter_count: u32,
    pub folded_parameter_count: u32,
}

/// One generated pack's audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerPackAudit {
    pub pack_id: String,
    pub artifact: String,
    pub pinned: bool,
    pub ecosystem: String,
    pub completeness: Completeness,
    pub shipped_summaries: usize,
    pub adversarial_probes: usize,
}

/// The full conversion outcome: the generated packs and the audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizerConversion {
    pub packs: Vec<GeneratedSanitizerPack>,
    pub audit: SanitizerAuditReport,
}

/// Why a conversion could not complete. These are converter or candidate-shape
/// failures, distinct from an adversarial-gate rejection, which is recorded in
/// the report rather than raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizerPackError {
    ReadDir {
        path: PathBuf,
        message: String,
    },
    ReadFile {
        path: PathBuf,
        message: String,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    MalformedArtifact {
        artifact: String,
    },
    UnsupportedOutput {
        symbol: String,
        message: String,
    },
    /// Two overloads share a signature-less symbol but make different claims, so
    /// neither can ship without contradicting the other on one name.
    ConflictingOverload {
        artifact: String,
        symbol: String,
    },
    /// Two distinct symbols produced the same summary id in one pack. The fix is
    /// a more qualified slug, not a silent rename.
    DuplicateSummaryId {
        pack_id: String,
        id: String,
    },
    /// A generated pack did not survive the production compiler. That is a
    /// converter bug: the report lists the diagnostics.
    CompileFailed {
        pack_id: String,
        diagnostics: Vec<String>,
    },
}

impl fmt::Display for SanitizerPackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadDir { path, message } => {
                write!(
                    formatter,
                    "cannot read directory {}: {message}",
                    path.display()
                )
            }
            Self::ReadFile { path, message } => {
                write!(formatter, "cannot read {}: {message}", path.display())
            }
            Self::Parse { path, message } => {
                write!(formatter, "cannot parse {}: {message}", path.display())
            }
            Self::MalformedArtifact { artifact } => write!(
                formatter,
                "artifact `{artifact}` is neither `jdk` nor a `group:artifact:version` coordinate"
            ),
            Self::UnsupportedOutput { symbol, message } => {
                write!(
                    formatter,
                    "output port of `{symbol}` is unsupported: {message}"
                )
            }
            Self::ConflictingOverload { artifact, symbol } => write!(
                formatter,
                "overloads of `{symbol}` in `{artifact}` make conflicting sanitizer claims under one signature-less symbol"
            ),
            Self::DuplicateSummaryId { pack_id, id } => write!(
                formatter,
                "pack `{pack_id}` derived the summary id `{id}` twice"
            ),
            Self::CompileFailed {
                pack_id,
                diagnostics,
            } => write!(
                formatter,
                "generated pack `{pack_id}` failed the production compiler: {diagnostics:?}"
            ),
        }
    }
}

impl std::error::Error for SanitizerPackError {}

/// The audit report's file name, written beside the packs.
pub const SANITIZER_AUDIT_FILE_NAME: &str = "rejects.json";

/// Read every `*.json` candidate file under `candidates_dir`, gate each entry,
/// and produce the pack sources plus the audit report.
pub fn convert_sanitizer_candidates(
    candidates_dir: &Path,
) -> Result<SanitizerConversion, SanitizerPackError> {
    let entries = read_candidates(candidates_dir)?;
    build_conversion(entries)
}

/// Write the generated pack sources and the audit report under `output_root`,
/// pinned packs at the root and staged packs under `staged/`. Returns the
/// written paths in sorted order. The bytes are the deterministic conversion
/// output, so re-running the writer over unchanged candidates rewrites identical
/// files.
pub fn write_sanitizer_packs(
    conversion: &SanitizerConversion,
    output_root: &Path,
) -> Result<Vec<PathBuf>, SanitizerPackError> {
    let mut written = Vec::new();
    for pack in &conversion.packs {
        let path = output_root.join(&pack.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| SanitizerPackError::ReadDir {
                path: parent.to_owned(),
                message: error.to_string(),
            })?;
        }
        fs::write(&path, pack.source_json.as_bytes()).map_err(|error| {
            SanitizerPackError::ReadFile {
                path: path.clone(),
                message: error.to_string(),
            }
        })?;
        written.push(path);
    }
    let audit_path = output_root.join(SANITIZER_AUDIT_FILE_NAME);
    fs::write(&audit_path, serialize_audit(&conversion.audit).as_bytes()).map_err(|error| {
        SanitizerPackError::ReadFile {
            path: audit_path.clone(),
            message: error.to_string(),
        }
    })?;
    written.push(audit_path);
    written.sort();
    Ok(written)
}

/// One accepted candidate paired with the artifact whose file carried it.
struct AcceptedCandidate {
    entry: SanitizerEntry,
    probes: usize,
}

/// Read the candidate files in a stable order and pair every entry with its
/// artifact. Entry order within a file is preserved; files are read in sorted
/// name order.
fn read_candidates(candidates_dir: &Path) -> Result<Vec<SanitizerEntry>, SanitizerPackError> {
    let mut files = Vec::new();
    let read_dir = fs::read_dir(candidates_dir).map_err(|error| SanitizerPackError::ReadDir {
        path: candidates_dir.to_owned(),
        message: error.to_string(),
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|error| SanitizerPackError::ReadDir {
            path: candidates_dir.to_owned(),
            message: error.to_string(),
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    let mut all = Vec::new();
    for path in files {
        let bytes = fs::read(&path).map_err(|error| SanitizerPackError::ReadFile {
            path: path.clone(),
            message: error.to_string(),
        })?;
        let parsed: Vec<SanitizerEntry> =
            serde_json::from_slice(&bytes).map_err(|error| SanitizerPackError::Parse {
                path: path.clone(),
                message: error.to_string(),
            })?;
        all.extend(parsed);
    }
    Ok(all)
}

fn build_conversion(
    entries: Vec<SanitizerEntry>,
) -> Result<SanitizerConversion, SanitizerPackError> {
    let candidates_total = entries.len();

    // Group by artifact in sorted order so pack assembly is deterministic.
    let mut by_artifact: BTreeMap<String, Vec<SanitizerEntry>> = BTreeMap::new();
    for entry in entries {
        let artifact = entry
            .artifact
            .clone()
            .unwrap_or_else(|| JDK_ARTIFACT.to_owned());
        by_artifact.entry(artifact).or_default().push(entry);
    }

    let mut packs = Vec::new();
    let mut pack_audits = Vec::new();
    let mut gate_rejects = Vec::new();
    let mut folded = Vec::new();
    let mut shipped_summaries = 0usize;
    let mut total_probes = 0usize;

    for (artifact, entries) in by_artifact {
        let identity = PackIdentity::for_artifact(&artifact)?;

        // Gate every candidate. An accepted candidate keeps its probe count as
        // the recorded mechanism proof; a rejected one is reported, never
        // shipped.
        let mut accepted: Vec<AcceptedCandidate> = Vec::new();
        for entry in entries {
            match gate_sanitizer(&entry) {
                Ok(suite) => accepted.push(AcceptedCandidate {
                    probes: suite.probes.len(),
                    entry,
                }),
                Err(rejection) => gate_rejects.push(SanitizerGateReject {
                    artifact: artifact.clone(),
                    target_path: entry.target.path.clone(),
                    target_symbol: entry.target.symbol.clone(),
                    reason: rejection_reason(&rejection),
                    message: rejection.to_string(),
                }),
            }
        }

        let pack_probes: usize = accepted.iter().map(|candidate| candidate.probes).sum();
        total_probes = total_probes.saturating_add(pack_probes);

        let summaries = fold_and_build(&artifact, accepted, &mut folded)?;
        if summaries.is_empty() {
            continue;
        }
        shipped_summaries = shipped_summaries.saturating_add(summaries.len());

        let completeness = if summaries
            .iter()
            .any(|summary| matches!(summary.completeness, Completeness::Complete))
        {
            Completeness::Complete
        } else {
            Completeness::Partial
        };

        let pack = identity.build_pack(summaries, completeness);
        assert_ids_unique(&identity.pack_id, &pack)?;
        let source_json = serialize_pack(&pack);
        compile_check(&identity.pack_id, &source_json)?;

        pack_audits.push(SanitizerPackAudit {
            pack_id: identity.pack_id.clone(),
            artifact: artifact.clone(),
            pinned: identity.pinned,
            ecosystem: identity.ecosystem.clone(),
            completeness,
            shipped_summaries: pack_records(&pack),
            adversarial_probes: pack_probes,
        });
        packs.push(GeneratedSanitizerPack {
            pack_id: identity.pack_id.clone(),
            artifact,
            relative_path: identity.relative_path(),
            pinned: identity.pinned,
            source_json,
        });
    }

    gate_rejects.sort_by(|left, right| {
        (&left.artifact, &left.target_symbol, &left.reason).cmp(&(
            &right.artifact,
            &right.target_symbol,
            &right.reason,
        ))
    });
    folded.sort_by(|left, right| {
        (
            &left.artifact,
            &left.target_symbol,
            left.folded_parameter_count,
        )
            .cmp(&(
                &right.artifact,
                &right.target_symbol,
                right.folded_parameter_count,
            ))
    });
    packs.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
    pack_audits.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));

    let audit = SanitizerAuditReport {
        format: SANITIZER_PACK_AUDIT_FORMAT.to_owned(),
        candidates_total,
        gate_rejected: gate_rejects.len(),
        shipped_summaries,
        folded_overloads: folded.len(),
        adversarial_probes: total_probes,
        gate_rejects,
        folded,
        packs: pack_audits,
    };
    Ok(SanitizerConversion { packs, audit })
}

/// Fold overloads that share a signature-less `(path, symbol)` target and carry
/// an identical claim into one summary, and build the summaries for one pack.
fn fold_and_build(
    artifact: &str,
    accepted: Vec<AcceptedCandidate>,
    folded: &mut Vec<FoldedOverload>,
) -> Result<Vec<AuthoredProcedureSummary>, SanitizerPackError> {
    // Preserve first-seen order per target so the fold is deterministic.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut groups: BTreeMap<(String, String), Vec<SanitizerEntry>> = BTreeMap::new();
    for candidate in accepted {
        let key = (
            candidate.entry.target.path.clone(),
            candidate.entry.target.symbol.clone(),
        );
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(candidate.entry);
    }

    let mut summaries = Vec::new();
    for key in order {
        let group = groups.remove(&key).expect("group present for ordered key");
        let first = &group[0];
        // A safe fold requires identical claims across the overloads; a
        // difference under one signature-less symbol is a conflict we refuse to
        // ship rather than silently pick one.
        for other in &group[1..] {
            if claim_of(other) != claim_of(first) {
                return Err(SanitizerPackError::ConflictingOverload {
                    artifact: artifact.to_owned(),
                    symbol: first.target.symbol.clone(),
                });
            }
        }
        let kept_parameter_count = group
            .iter()
            .map(|entry| entry.target.parameter_count)
            .max()
            .expect("non-empty group");
        for other in &group[1..] {
            folded.push(FoldedOverload {
                artifact: artifact.to_owned(),
                target_path: first.target.path.clone(),
                target_symbol: first.target.symbol.clone(),
                kept_parameter_count,
                folded_parameter_count: other.target.parameter_count,
            });
        }
        summaries.push(build_summary(first, kept_parameter_count)?);
    }
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(summaries)
}

/// The claim fields that must match for two overloads to fold safely.
fn claim_of(
    entry: &SanitizerEntry,
) -> (
    Vec<InjectionContext>,
    Vec<InjectionContext>,
    SanitizerPort,
    serde_json::Value,
    SanitizerCompleteness,
) {
    let mut neutralizes = entry.neutralizes.clone();
    neutralizes.sort();
    let mut does_not = entry.does_not_neutralize.clone();
    does_not.sort();
    (
        neutralizes,
        does_not,
        entry.sanitized_input.clone(),
        entry.output.clone(),
        entry.completeness,
    )
}

/// Build one shipped summary from one accepted candidate.
fn build_summary(
    entry: &SanitizerEntry,
    parameter_count: u32,
) -> Result<AuthoredProcedureSummary, SanitizerPackError> {
    let input = summary_input(&entry.sanitized_input);
    let output: AuthoredSummaryOutput =
        serde_json::from_value(entry.output.clone()).map_err(|error| {
            SanitizerPackError::UnsupportedOutput {
                symbol: entry.target.symbol.clone(),
                message: error.to_string(),
            }
        })?;

    // The context tokens are the taint labels. Sort them for a canonical,
    // diff-stable `removes` list.
    let mut removes: Vec<String> = entry
        .neutralizes
        .iter()
        .map(|context| context.as_str().to_owned())
        .collect();
    removes.sort();

    let transfer = AuthoredSummaryTransfer {
        input: input.clone(),
        exit_kind: AuthoredSummaryExitKind::Normal,
        output: output.clone(),
    };
    let effect = AuthoredSummaryEffect::Sanitize {
        input,
        output,
        removes,
    };
    Ok(AuthoredProcedureSummary {
        id: summary_id(&entry.target.symbol),
        target: AuthoredProcedureTarget {
            path: entry.target.path.clone(),
            symbol: entry.target.symbol.clone(),
            has_receiver: entry.target.has_receiver,
            parameter_count,
        },
        completeness: match entry.completeness {
            SanitizerCompleteness::Partial => Completeness::Partial,
            SanitizerCompleteness::Complete => Completeness::Complete,
        },
        locations: Vec::new(),
        transfers: vec![transfer],
        effects: vec![effect],
    })
}

fn summary_input(port: &SanitizerPort) -> AuthoredSummaryInput {
    match port {
        SanitizerPort::Receiver => AuthoredSummaryInput::Receiver {},
        SanitizerPort::Parameter { ordinal } => {
            AuthoredSummaryInput::Parameter { ordinal: *ordinal }
        }
    }
}

/// Derive a stable, valid summary id from the target symbol. The id charset is
/// lowercase ASCII alphanumerics plus `.`, `-`, and `_`; every other character
/// collapses to a single `-`, and leading or trailing separators are trimmed.
///
/// An array suffix is spelled out first. Collapsing `[]` to a separator would
/// make `append(char[])` and `append(char)` slug identically, and two shipped
/// overloads must not share an id.
///
/// Shared with the golden-core and framework-declaration converters, which slug
/// a summary id or a pack coordinate the same way.
pub(crate) fn summary_id(symbol: &str) -> String {
    let symbol = symbol.replace("[]", "_array");
    let mut id = String::with_capacity(symbol.len());
    let mut last_dash = false;
    for character in symbol.chars() {
        let lowered = character.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() || matches!(lowered, '.' | '_') {
            id.push(lowered);
            last_dash = false;
        } else if !last_dash {
            id.push('-');
            last_dash = true;
        }
    }
    let trimmed = id.trim_matches(|character| matches!(character, '-' | '.'));
    trimmed.to_owned()
}

/// The identity of one pack: its id, ecosystem, activation, and whether it is
/// byte-pinned.
struct PackIdentity {
    pack_id: String,
    ecosystem: String,
    pinned: bool,
    activation: ActivationSelector,
    toolchains: Vec<VersionConstraint>,
    provenance_source: String,
}

impl PackIdentity {
    fn for_artifact(artifact: &str) -> Result<Self, SanitizerPackError> {
        if artifact == JDK_ARTIFACT {
            return Ok(Self {
                pack_id: "bifrost.java-sanitizers".to_owned(),
                ecosystem: "jdk".to_owned(),
                pinned: true,
                activation: ActivationSelector {
                    package: None,
                    module: None,
                    toolchain: Some(NameSelector {
                        name: "jdk".to_owned(),
                        version: Some(JDK_TOOLCHAIN_REQUIREMENT.to_owned()),
                    }),
                    targets: vec!["jvm".to_owned()],
                    configurations: Vec::new(),
                    artifact_sha256: None,
                },
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: JDK_TOOLCHAIN_REQUIREMENT.to_owned(),
                }],
                provenance_source: "audited k3 sanitizer content over the JDK standard library"
                    .to_owned(),
            });
        }

        // A Maven coordinate `group:artifact:version`. The package name is
        // `group:artifact`; the artifact id becomes the pack slug.
        let parts: Vec<&str> = artifact.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(SanitizerPackError::MalformedArtifact {
                artifact: artifact.to_owned(),
            });
        }
        let package_name = format!("{}:{}", parts[0], parts[1]);
        let slug = summary_id(parts[1]);
        Ok(Self {
            pack_id: format!("bifrost.{slug}-sanitizers"),
            ecosystem: "maven".to_owned(),
            // Staged: the coordinate is named but the byte-level artifact digest
            // is not produced here, so the pack is not shipped on a faked pin.
            pinned: false,
            activation: ActivationSelector {
                package: Some(NameSelector {
                    name: package_name,
                    version: None,
                }),
                module: None,
                toolchain: None,
                targets: vec!["jvm".to_owned()],
                configurations: Vec::new(),
                artifact_sha256: None,
            },
            toolchains: Vec::new(),
            provenance_source: format!(
                "audited k3 sanitizer content over {artifact} (staged: artifact digest not pinned)"
            ),
        })
    }

    fn relative_path(&self) -> PathBuf {
        let file_name = format!("{}.json", self.pack_id);
        if self.pinned {
            PathBuf::from(file_name)
        } else {
            Path::new("staged").join(file_name)
        }
    }

    fn build_pack(
        &self,
        summaries: Vec<AuthoredProcedureSummary>,
        completeness: Completeness,
    ) -> AuthoredSemanticModelPack {
        AuthoredSemanticModelPack {
            schema_version: 1,
            pack_id: self.pack_id.clone(),
            version: PACK_CONTENT_VERSION.to_owned(),
            producer: Producer {
                name: PRODUCER_NAME.to_owned(),
                version: PRODUCER_VERSION.to_owned(),
            },
            language: "java".to_owned(),
            ecosystem: self.ecosystem.clone(),
            compatibility: Compatibility {
                bifrost: BIFROST_REQUIREMENT.to_owned(),
                toolchains: self.toolchains.clone(),
            },
            provenance: Provenance {
                source: self.provenance_source.clone(),
                revision: Some("k3-sanitizers".to_owned()),
            },
            license: PACK_LICENSE.to_owned(),
            completeness,
            safety: Safety {
                generated_code_only: false,
                review_required: true,
            },
            shards: vec![AuthoredShard {
                id: format!("sanitizers.{}", self.ecosystem),
                activation: vec![self.activation.clone()],
                payload: AuthoredPayload::ProcedureSummaries { summaries },
            }],
        }
    }
}

fn pack_records(pack: &AuthoredSemanticModelPack) -> usize {
    pack.shards
        .iter()
        .map(|shard| match &shard.payload {
            AuthoredPayload::ProcedureSummaries { summaries } => summaries.len(),
            AuthoredPayload::DeclarationFacts { .. } | AuthoredPayload::GeneratorRules { .. } => 0,
        })
        .sum()
}

fn assert_ids_unique(
    pack_id: &str,
    pack: &AuthoredSemanticModelPack,
) -> Result<(), SanitizerPackError> {
    let mut seen = std::collections::HashSet::new();
    for shard in &pack.shards {
        if let AuthoredPayload::ProcedureSummaries { summaries } = &shard.payload {
            for summary in summaries {
                if !seen.insert(summary.id.as_str()) {
                    return Err(SanitizerPackError::DuplicateSummaryId {
                        pack_id: pack_id.to_owned(),
                        id: summary.id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Serialize a pack to canonical pretty JSON with a trailing newline. serde
/// serializes struct fields in declaration order and vectors in order, so the
/// bytes are deterministic for the same input.
fn serialize_pack(pack: &AuthoredSemanticModelPack) -> String {
    let mut json = serde_json::to_string_pretty(pack).expect("a pack is serializable");
    json.push('\n');
    json
}

/// Compile a generated pack through the production compiler. A failure is a
/// converter bug, not a candidate reject, so it is raised rather than recorded.
fn compile_check(pack_id: &str, source_json: &str) -> Result<(), SanitizerPackError> {
    compile_source(
        SourceFormat::Json,
        source_json.as_bytes(),
        &CompilerOptions::default(),
    )
    .map(|_| ())
    .map_err(|diagnostics| SanitizerPackError::CompileFailed {
        pack_id: pack_id.to_owned(),
        diagnostics: diagnostics
            .iter()
            .map(|diagnostic| format!("{diagnostic:?}"))
            .collect(),
    })
}

/// Serialize the audit report to canonical pretty JSON with a trailing newline.
pub fn serialize_audit(audit: &SanitizerAuditReport) -> String {
    let mut json = serde_json::to_string_pretty(audit).expect("the audit report is serializable");
    json.push('\n');
    json
}

fn rejection_reason(rejection: &SanitizerRejection) -> String {
    match rejection {
        SanitizerRejection::NoNeutralizedContext => "no_neutralized_context".to_owned(),
        SanitizerRejection::ContradictoryContext { .. } => "contradictory_context".to_owned(),
        SanitizerRejection::UnprovableContext { .. } => "unprovable_context".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write one candidate file into a fresh directory and convert it.
    fn convert(files: &[(&str, &str)]) -> SanitizerConversion {
        let dir = tempfile::tempdir().expect("temp candidates dir");
        for (name, body) in files {
            fs::write(dir.path().join(name), body).expect("write candidate file");
        }
        convert_sanitizer_candidates(dir.path()).expect("conversion")
    }

    #[test]
    fn a_gate_rejected_candidate_is_reported_and_not_shipped() {
        // An entry that neutralizes nothing is not a sanitizer: the gate rejects
        // it, so it is recorded and no summary ships for it.
        let candidate = r#"[{
          "target": {"path": "p/Q.java", "symbol": "p.Q.m", "parameter_count": 1},
          "artifact": "com.example:lib:1.0.0",
          "sanitized_input": {"kind": "parameter", "ordinal": 0},
          "output": {"kind": "normal_return"},
          "neutralizes": [],
          "does_not_neutralize": ["sql"],
          "completeness": "partial"
        }]"#;
        let conversion = convert(&[("lib.json", candidate)]);
        assert_eq!(conversion.audit.candidates_total, 1);
        assert_eq!(conversion.audit.gate_rejected, 1);
        assert_eq!(conversion.audit.shipped_summaries, 0);
        assert!(conversion.packs.is_empty());
        assert_eq!(
            conversion.audit.gate_rejects[0].reason,
            "no_neutralized_context"
        );
        assert_eq!(conversion.audit.gate_rejects[0].target_symbol, "p.Q.m");
    }

    #[test]
    fn identical_overloads_fold_into_one_summary() {
        // Two overloads under one signature-less symbol carry an identical claim,
        // so they fold into one summary and the fold is recorded.
        let candidate = r#"[
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.escape", "parameter_count": 1},
            "artifact": "com.example:lib:1.0.0",
            "sanitized_input": {"kind": "parameter", "ordinal": 0},
            "output": {"kind": "normal_return"},
            "neutralizes": ["sql"],
            "does_not_neutralize": ["html"],
            "completeness": "partial"
          },
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.escape", "parameter_count": 2},
            "artifact": "com.example:lib:1.0.0",
            "sanitized_input": {"kind": "parameter", "ordinal": 0},
            "output": {"kind": "normal_return"},
            "neutralizes": ["sql"],
            "does_not_neutralize": ["html"],
            "completeness": "partial"
          }
        ]"#;
        let conversion = convert(&[("lib.json", candidate)]);
        assert_eq!(conversion.audit.candidates_total, 2);
        assert_eq!(conversion.audit.gate_rejected, 0);
        assert_eq!(conversion.audit.shipped_summaries, 1);
        assert_eq!(conversion.audit.folded_overloads, 1);
        assert_eq!(conversion.audit.folded[0].kept_parameter_count, 2);
        let pack = &conversion.packs[0];
        assert_eq!(pack.pack_id, "bifrost.lib-sanitizers");
        assert!(!pack.pinned, "a library pack is staged unpinned");
        // The generated pack compiles through the production compiler.
        compile_source(
            SourceFormat::Json,
            pack.source_json.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("the folded pack compiles");
    }

    #[test]
    fn conflicting_overloads_are_refused() {
        // Two overloads under one symbol disagree, so neither can ship without
        // contradicting the other: the converter refuses rather than pick one.
        let candidate = r#"[
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.escape", "parameter_count": 1},
            "artifact": "com.example:lib:1.0.0",
            "sanitized_input": {"kind": "parameter", "ordinal": 0},
            "output": {"kind": "normal_return"},
            "neutralizes": ["sql"],
            "does_not_neutralize": [],
            "completeness": "partial"
          },
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.escape", "parameter_count": 2},
            "artifact": "com.example:lib:1.0.0",
            "sanitized_input": {"kind": "parameter", "ordinal": 0},
            "output": {"kind": "normal_return"},
            "neutralizes": ["html"],
            "does_not_neutralize": [],
            "completeness": "partial"
          }
        ]"#;
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("lib.json"), candidate).expect("write");
        let error = convert_sanitizer_candidates(dir.path()).expect_err("conflict refused");
        assert!(matches!(
            error,
            SanitizerPackError::ConflictingOverload { .. }
        ));
    }

    #[test]
    fn the_jdk_artifact_produces_a_pinned_toolchain_pack() {
        let candidate = r#"[{
          "target": {"path": "java.base/java/lang/Boolean.java", "symbol": "java.lang.Boolean.parseBoolean", "parameter_count": 1},
          "artifact": "jdk",
          "sanitized_input": {"kind": "parameter", "ordinal": 0},
          "output": {"kind": "normal_return"},
          "neutralizes": ["sql", "html"],
          "does_not_neutralize": [],
          "completeness": "complete"
        }]"#;
        let conversion = convert(&[("jdk.json", candidate)]);
        let pack = &conversion.packs[0];
        assert_eq!(pack.pack_id, "bifrost.java-sanitizers");
        assert!(pack.pinned, "the JDK pack is pinned by its toolchain");
        assert_eq!(
            pack.relative_path,
            PathBuf::from("bifrost.java-sanitizers.json")
        );
    }

    #[test]
    fn conversion_is_deterministic() {
        let candidate = r#"[{
          "target": {"path": "p/Q.java", "symbol": "p.Q.escape", "parameter_count": 1},
          "artifact": "com.example:lib:1.0.0",
          "sanitized_input": {"kind": "parameter", "ordinal": 0},
          "output": {"kind": "normal_return"},
          "neutralizes": ["sql", "html"],
          "does_not_neutralize": ["shell"],
          "completeness": "partial"
        }]"#;
        let first = convert(&[("lib.json", candidate)]);
        let second = convert(&[("lib.json", candidate)]);
        assert_eq!(first, second);
        // removes is sorted for a canonical, diff-stable list.
        let value: serde_json::Value = serde_json::from_str(&first.packs[0].source_json).unwrap();
        let removes = &value["shards"][0]["payload"]["summaries"][0]["effects"][0]["removes"];
        assert_eq!(removes, &serde_json::json!(["html", "sql"]));
    }
}
