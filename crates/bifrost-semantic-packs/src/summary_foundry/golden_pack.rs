//! Convert the hand-authored golden-core JDK flow-through summaries into a
//! shippable `procedure_summaries` pack (#1935 blocker 4).
//!
//! Each candidate is a straight flow-through claim: a JDK transform carries a
//! tainted value from one input port to one output port, spelled as a set of
//! `transfers` (input -> output). Unlike the sanitizer content, a golden entry
//! records NO sanitize effect; it only propagates. The OWASP Benchmark bakeoff
//! (#1935) abstains under `require-model` on nearly every bindable case because
//! the flow crosses an unmodeled JDK transform (`String`/`StringBuilder`,
//! collections, boxing/`Optional`, IO wrappers, `Base64`), so shipping and
//! activating these summaries is what lets a modeled flow conclude instead of
//! failing closed.
//!
//! The candidate shape maps directly onto the shipped IR: `target` is an
//! [`AuthoredProcedureTarget`], `transfers` is a `Vec<AuthoredSummaryTransfer>`,
//! and `completeness` is a [`Completeness`]. The converter carries them verbatim
//! onto an [`AuthoredProcedureSummary`] with an empty `effects` list (a pure
//! propagation), derives a stable summary id from the target symbol, and
//! assembles one pack.
//!
//! Every candidate target carries a signed symbol (for example
//! `java.lang.String.valueOf(int)`), so overloads do not collide the way the
//! signature-less sanitizer symbols did. The pack validator still forbids two
//! summaries on one `(path, symbol)` target (`summary.duplicate_target`), so the
//! converter detects a duplicate target itself, drops the later candidate, and
//! records it in the audit report rather than force-shipping a pack the compiler
//! would reject. The assembled pack is then run through the production compiler;
//! a residual failure is a converter bug, raised rather than shipped.
//!
//! All golden targets name JDK standard-library paths (`java.base/...`), so the
//! whole set ships as one `jdk`-toolchain-pinned pack, the same real pin the JDK
//! declaration and sanitizer packs use.
//!
//! The conversion is a deterministic function of the candidate content: two runs
//! produce byte-identical pack source and audit report, with no clock.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryTransfer, Compatibility,
    CompilerOptions, Completeness, NameSelector, Producer, Provenance, Safety, SourceFormat,
    VersionConstraint, compile_source,
};
use serde::{Deserialize, Serialize};

use super::sanitizer_pack::summary_id;

/// The audit-report format tag. Bump it when a consumer must read the file
/// differently, not when a field is added.
pub const GOLDEN_PACK_AUDIT_FORMAT: &str = "bifrost_golden_pack_audit/v1";

/// The audit report's file name, written beside the pack.
pub const GOLDEN_AUDIT_FILE_NAME: &str = "rejects.json";

/// The producer name recorded in the generated pack.
const PRODUCER_NAME: &str = "bifrost-golden-foundry";

/// The pack content version. It is the golden content's own version, not the
/// Bifrost version, and advances when the shipped claims change.
const PACK_CONTENT_VERSION: &str = "0.1.0";

/// The Bifrost compatibility requirement the generated pack declares.
const BIFROST_REQUIREMENT: &str = ">=0.8.0, <0.11.0";

/// The authored golden content is Bifrost's own claim, licensed like the
/// workspace. It is not a slice of the JDK.
const PACK_LICENSE: &str = "Apache-2.0";

/// The JDK toolchain requirement. Every claimed API (`String`, `StringBuilder`,
/// `Optional`, `Base64`, the `java.util` collections, the `java.io` wrappers)
/// exists in Java 17 and later.
const JDK_TOOLCHAIN_REQUIREMENT: &str = ">=17.0.0";

/// The pack id: one JDK-pinned golden-core summary pack.
const GOLDEN_PACK_ID: &str = "bifrost.jdk-golden-summaries";

/// The one JDK completeness value one candidate carries. It deserializes as
/// [`Completeness`] directly (serde `snake_case`).
type GoldenCompleteness = Completeness;

/// One golden candidate, as the checked-in `*.json` files spell it. The
/// `rationale`, `provenance`, `confidence`, and `citations` fields are the
/// author's audit trail; the converter reads the flow claim and records the
/// citation-bearing fields only through the file, not the pack.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenCandidate {
    target: AuthoredProcedureTarget,
    completeness: GoldenCompleteness,
    transfers: Vec<AuthoredSummaryTransfer>,
    #[allow(dead_code)]
    rationale: String,
    #[allow(dead_code)]
    provenance: String,
    #[allow(dead_code)]
    confidence: String,
    #[allow(dead_code)]
    citations: String,
}

/// The generated golden pack: its identity, that it is byte-pinned by the JDK
/// toolchain, and its source text ready to write and to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedGoldenPack {
    pub pack_id: String,
    /// The artifact the pack pins: `"jdk"`.
    pub artifact: String,
    /// The path under the output root.
    pub relative_path: PathBuf,
    /// A golden pack is pinned by the JDK toolchain selector, the same real pin
    /// the JDK declaration and sanitizer packs use.
    pub pinned: bool,
    /// The pack source JSON, pretty-printed with a trailing newline. This is the
    /// exact checked-in bytes and the exact input to `compile_source`.
    pub source_json: String,
}

/// One candidate the converter dropped because it would make the pack fail the
/// production compiler, recorded rather than force-shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenReject {
    pub target_path: String,
    pub target_symbol: String,
    /// The rejection reason code, stable across runs.
    pub reason: String,
    pub message: String,
}

/// The generated pack's audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenPackAudit {
    pub pack_id: String,
    pub artifact: String,
    pub pinned: bool,
    pub ecosystem: String,
    pub completeness: Completeness,
    pub shipped_summaries: usize,
}

/// The structured audit report written beside the pack as `rejects.json`. It is
/// the real conversion outcome: the candidate totals, every dropped candidate,
/// and the shipped pack, deterministic and clock-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenAuditReport {
    pub format: String,
    pub candidates_total: usize,
    pub shipped_summaries: usize,
    pub rejected: usize,
    pub rejects: Vec<GoldenReject>,
    pub packs: Vec<GoldenPackAudit>,
}

/// The full conversion outcome: the generated pack(s) and the audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenConversion {
    pub packs: Vec<GeneratedGoldenPack>,
    pub audit: GoldenAuditReport,
}

/// Why a conversion could not complete. These are converter or candidate-shape
/// failures, distinct from a per-candidate reject, which is recorded in the
/// report rather than raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoldenPackError {
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
    /// Two distinct symbols produced the same summary id in the pack. The fix is
    /// a more qualified slug, not a silent rename.
    DuplicateSummaryId {
        id: String,
    },
    /// The generated pack did not survive the production compiler after the
    /// per-candidate rejects were removed. That is a converter bug: the report
    /// lists the diagnostics.
    CompileFailed {
        diagnostics: Vec<String>,
    },
}

impl fmt::Display for GoldenPackError {
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
            Self::DuplicateSummaryId { id } => write!(
                formatter,
                "pack `{GOLDEN_PACK_ID}` derived the summary id `{id}` twice"
            ),
            Self::CompileFailed { diagnostics } => write!(
                formatter,
                "generated pack `{GOLDEN_PACK_ID}` failed the production compiler: {diagnostics:?}"
            ),
        }
    }
}

impl std::error::Error for GoldenPackError {}

/// Read every `*.json` candidate file under `candidates_dir`, drop the
/// duplicate-target candidates, and produce the pack source plus the audit
/// report.
pub fn convert_golden_candidates(
    candidates_dir: &Path,
) -> Result<GoldenConversion, GoldenPackError> {
    let candidates = read_candidates(candidates_dir)?;
    build_conversion(candidates)
}

/// Write the generated pack source and the audit report under `output_root`.
/// Returns the written paths in sorted order. The bytes are the deterministic
/// conversion output, so re-running the writer over unchanged candidates
/// rewrites identical files.
pub fn write_golden_packs(
    conversion: &GoldenConversion,
    output_root: &Path,
) -> Result<Vec<PathBuf>, GoldenPackError> {
    let mut written = Vec::new();
    for pack in &conversion.packs {
        let path = output_root.join(&pack.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| GoldenPackError::ReadDir {
                path: parent.to_owned(),
                message: error.to_string(),
            })?;
        }
        fs::write(&path, pack.source_json.as_bytes()).map_err(|error| {
            GoldenPackError::ReadFile {
                path: path.clone(),
                message: error.to_string(),
            }
        })?;
        written.push(path);
    }
    let audit_path = output_root.join(GOLDEN_AUDIT_FILE_NAME);
    fs::write(&audit_path, serialize_audit(&conversion.audit).as_bytes()).map_err(|error| {
        GoldenPackError::ReadFile {
            path: audit_path.clone(),
            message: error.to_string(),
        }
    })?;
    written.push(audit_path);
    written.sort();
    Ok(written)
}

/// Read the candidate files in a stable order. Files are read in sorted name
/// order; entry order within a file is preserved.
fn read_candidates(candidates_dir: &Path) -> Result<Vec<GoldenCandidate>, GoldenPackError> {
    let mut files = Vec::new();
    let read_dir = fs::read_dir(candidates_dir).map_err(|error| GoldenPackError::ReadDir {
        path: candidates_dir.to_owned(),
        message: error.to_string(),
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|error| GoldenPackError::ReadDir {
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
        let bytes = fs::read(&path).map_err(|error| GoldenPackError::ReadFile {
            path: path.clone(),
            message: error.to_string(),
        })?;
        let parsed: Vec<GoldenCandidate> =
            serde_json::from_slice(&bytes).map_err(|error| GoldenPackError::Parse {
                path: path.clone(),
                message: error.to_string(),
            })?;
        all.extend(parsed);
    }
    Ok(all)
}

fn build_conversion(candidates: Vec<GoldenCandidate>) -> Result<GoldenConversion, GoldenPackError> {
    let candidates_total = candidates.len();

    // Drop a candidate whose (path, symbol) target already appeared: the pack
    // validator forbids two summaries on one target, so a second one is reported
    // rather than force-shipped. First-seen order is preserved.
    let mut seen_targets: BTreeSet<(String, String)> = BTreeSet::new();
    let mut rejects: Vec<GoldenReject> = Vec::new();
    let mut kept: Vec<GoldenCandidate> = Vec::new();
    for candidate in candidates {
        let key = (
            candidate.target.path.clone(),
            candidate.target.symbol.clone(),
        );
        if seen_targets.contains(&key) {
            rejects.push(GoldenReject {
                target_path: candidate.target.path.clone(),
                target_symbol: candidate.target.symbol.clone(),
                reason: "duplicate_target".to_owned(),
                message: format!(
                    "a summary for target `{}` in `{}` was already shipped; the pack validator \
                     forbids two summaries on one target",
                    candidate.target.symbol, candidate.target.path
                ),
            });
            continue;
        }
        seen_targets.insert(key);
        kept.push(candidate);
    }

    let mut summaries = kept
        .into_iter()
        .map(build_summary)
        .collect::<Result<Vec<_>, _>>()?;
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    assert_ids_unique(&summaries)?;

    let shipped_summaries = summaries.len();
    // A pack's claim must dominate its members': the validator rejects a
    // `complete` summary inside a `partial` pack. Ship the pack `complete` when
    // any summary is complete, so a partial summary stays legal beside it.
    let completeness = if summaries
        .iter()
        .any(|summary| matches!(summary.completeness, Completeness::Complete))
    {
        Completeness::Complete
    } else {
        Completeness::Partial
    };

    let pack = build_pack(summaries, completeness);
    let source_json = serialize_pack(&pack);
    compile_check(&source_json)?;

    rejects.sort_by(|left, right| {
        (&left.target_path, &left.target_symbol, &left.reason).cmp(&(
            &right.target_path,
            &right.target_symbol,
            &right.reason,
        ))
    });

    let audit = GoldenAuditReport {
        format: GOLDEN_PACK_AUDIT_FORMAT.to_owned(),
        candidates_total,
        shipped_summaries,
        rejected: rejects.len(),
        rejects,
        packs: vec![GoldenPackAudit {
            pack_id: GOLDEN_PACK_ID.to_owned(),
            artifact: "jdk".to_owned(),
            pinned: true,
            ecosystem: "jdk".to_owned(),
            completeness,
            shipped_summaries,
        }],
    };

    Ok(GoldenConversion {
        packs: vec![GeneratedGoldenPack {
            pack_id: GOLDEN_PACK_ID.to_owned(),
            artifact: "jdk".to_owned(),
            relative_path: PathBuf::from(format!("{GOLDEN_PACK_ID}.json")),
            pinned: true,
            source_json,
        }],
        audit,
    })
}

/// Build one shipped summary from one candidate. A golden entry carries only
/// flow-through transfers, so the effects list stays empty.
fn build_summary(candidate: GoldenCandidate) -> Result<AuthoredProcedureSummary, GoldenPackError> {
    Ok(AuthoredProcedureSummary {
        id: summary_id(&candidate.target.symbol),
        target: candidate.target,
        completeness: candidate.completeness,
        locations: Vec::new(),
        transfers: candidate.transfers,
        effects: Vec::new(),
    })
}

fn build_pack(
    summaries: Vec<AuthoredProcedureSummary>,
    completeness: Completeness,
) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: 1,
        pack_id: GOLDEN_PACK_ID.to_owned(),
        version: PACK_CONTENT_VERSION.to_owned(),
        producer: Producer {
            name: PRODUCER_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        language: "java".to_owned(),
        ecosystem: "jdk".to_owned(),
        compatibility: Compatibility {
            bifrost: BIFROST_REQUIREMENT.to_owned(),
            toolchains: vec![VersionConstraint {
                name: "jdk".to_owned(),
                requirement: JDK_TOOLCHAIN_REQUIREMENT.to_owned(),
            }],
        },
        provenance: Provenance {
            source: "hand-authored golden-core JDK flow-through summaries".to_owned(),
            revision: Some("golden-core".to_owned()),
        },
        license: PACK_LICENSE.to_owned(),
        completeness,
        safety: Safety {
            generated_code_only: false,
            review_required: true,
        },
        shards: vec![AuthoredShard {
            id: "summaries.jdk".to_owned(),
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: Some(NameSelector {
                    name: "jdk".to_owned(),
                    version: Some(JDK_TOOLCHAIN_REQUIREMENT.to_owned()),
                }),
                targets: vec!["jvm".to_owned()],
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            payload: AuthoredPayload::ProcedureSummaries { summaries },
        }],
    }
}

fn assert_ids_unique(summaries: &[AuthoredProcedureSummary]) -> Result<(), GoldenPackError> {
    let mut seen = std::collections::HashSet::new();
    for summary in summaries {
        if !seen.insert(summary.id.as_str()) {
            return Err(GoldenPackError::DuplicateSummaryId {
                id: summary.id.clone(),
            });
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

/// Compile the generated pack through the production compiler. A failure after
/// the per-candidate rejects were removed is a converter bug, not a candidate
/// reject, so it is raised rather than recorded.
fn compile_check(source_json: &str) -> Result<(), GoldenPackError> {
    compile_source(
        SourceFormat::Json,
        source_json.as_bytes(),
        &CompilerOptions::default(),
    )
    .map(|_| ())
    .map_err(|diagnostics| GoldenPackError::CompileFailed {
        diagnostics: diagnostics
            .iter()
            .map(|diagnostic| format!("{diagnostic:?}"))
            .collect(),
    })
}

/// Serialize the audit report to canonical pretty JSON with a trailing newline.
pub fn serialize_audit(audit: &GoldenAuditReport) -> String {
    let mut json = serde_json::to_string_pretty(audit).expect("the audit report is serializable");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write one candidate file into a fresh directory and convert it.
    fn convert(files: &[(&str, &str)]) -> GoldenConversion {
        let dir = tempfile::tempdir().expect("temp candidates dir");
        for (name, body) in files {
            fs::write(dir.path().join(name), body).expect("write candidate file");
        }
        convert_golden_candidates(dir.path()).expect("conversion")
    }

    const STRING_CONCAT: &str = r#"[{
      "target": {
        "path": "java.base/java/lang/String.java",
        "symbol": "java.lang.String.concat(java.lang.String)",
        "has_receiver": true,
        "parameter_count": 1
      },
      "completeness": "complete",
      "transfers": [
        {"input": {"kind": "receiver"}, "exit_kind": "normal", "output": {"kind": "normal_return"}},
        {"input": {"kind": "parameter", "ordinal": 0}, "exit_kind": "normal", "output": {"kind": "normal_return"}}
      ],
      "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "javadoc"
    }]"#;

    #[test]
    fn a_flow_through_candidate_ships_as_a_pinned_jdk_summary() {
        let conversion = convert(&[("string.json", STRING_CONCAT)]);
        assert_eq!(conversion.audit.candidates_total, 1);
        assert_eq!(conversion.audit.shipped_summaries, 1);
        assert_eq!(conversion.audit.rejected, 0);
        let pack = &conversion.packs[0];
        assert_eq!(pack.pack_id, "bifrost.jdk-golden-summaries");
        assert!(
            pack.pinned,
            "the golden pack is pinned by the jdk toolchain"
        );
        assert_eq!(
            pack.relative_path,
            PathBuf::from("bifrost.jdk-golden-summaries.json")
        );
        // A golden summary carries transfers and no effects.
        let value: serde_json::Value = serde_json::from_str(&pack.source_json).unwrap();
        let summary = &value["shards"][0]["payload"]["summaries"][0];
        assert_eq!(summary["effects"], serde_json::json!([]));
        assert_eq!(summary["transfers"].as_array().unwrap().len(), 2);
        // The generated pack compiles through the production compiler.
        compile_source(
            SourceFormat::Json,
            pack.source_json.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("the golden pack compiles");
    }

    #[test]
    fn a_duplicate_target_is_reported_and_dropped_not_force_shipped() {
        // Two candidates on one (path, symbol) target: the second is dropped and
        // recorded, so the pack the validator would reject is never shipped.
        let duplicate = r#"[
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.m(java.lang.String)", "has_receiver": true, "parameter_count": 1},
            "completeness": "partial",
            "transfers": [{"input": {"kind": "parameter", "ordinal": 0}, "exit_kind": "normal", "output": {"kind": "normal_return"}}],
            "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "javadoc"
          },
          {
            "target": {"path": "p/Q.java", "symbol": "p.Q.m(java.lang.String)", "has_receiver": true, "parameter_count": 1},
            "completeness": "partial",
            "transfers": [{"input": {"kind": "receiver"}, "exit_kind": "normal", "output": {"kind": "normal_return"}}],
            "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "javadoc"
          }
        ]"#;
        let conversion = convert(&[("dup.json", duplicate)]);
        assert_eq!(conversion.audit.candidates_total, 2);
        assert_eq!(conversion.audit.shipped_summaries, 1);
        assert_eq!(conversion.audit.rejected, 1);
        assert_eq!(conversion.audit.rejects[0].reason, "duplicate_target");
        assert_eq!(
            conversion.audit.rejects[0].target_symbol,
            "p.Q.m(java.lang.String)"
        );
    }

    #[test]
    fn conversion_is_deterministic() {
        let first = convert(&[("string.json", STRING_CONCAT)]);
        let second = convert(&[("string.json", STRING_CONCAT)]);
        assert_eq!(first, second);
    }
}
