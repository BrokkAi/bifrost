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
//! A realm ([`GoldenRealm`]) names the standard library one candidate directory
//! describes: the JDK realm ships every `java.base/...` target as one
//! `jdk`-toolchain-pinned pack, the same real pin the JDK declaration and
//! sanitizer packs use, and the CPython realm ships the Python standard-library
//! targets as one `python`-toolchain-pinned pack. The realm is the only
//! language-shaped input; everything else in the converter is shared, so the
//! non-JVM pack passes exactly the gates the JDK pack does.
//!
//! The conversion is a deterministic function of the candidate content and the
//! realm: two runs produce byte-identical pack source and audit report, with no
//! clock.

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
use super::{FOUNDRY_BIFROST_REQUIREMENT, FOUNDRY_PRODUCER_VERSION};

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

/// The authored golden content is Bifrost's own claim, not a slice of the JDK
/// or of CPython. New Bifrost-owned public packs use the public project
/// license; retained packs may declare their own provenance and license in
/// their checked-in metadata.
const PACK_LICENSE: &str = "Apache-2.0";

/// One standard library the golden core models. It is the converter's only
/// language-shaped input: the pack identity, the toolchain pin, and the
/// call-shape rule below. Everything else is shared, so a non-JVM realm passes
/// the same gates the JDK realm does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoldenRealm {
    /// The shipped pack id, which is also the id a workspace names in the
    /// `enable` list of `.bifrost/packs.json`.
    pub pack_id: &'static str,
    /// The pack language, matched against the analyzer's language name.
    pub language: &'static str,
    /// The pack ecosystem and the artifact the audit report names.
    pub ecosystem: &'static str,
    /// The toolchain the single shard's activation selector pins.
    pub toolchain: &'static str,
    /// The toolchain version requirement, low enough that every claimed API
    /// exists.
    pub toolchain_requirement: &'static str,
    /// The activation target names. Empty when the realm has no target axis, as
    /// the pinned CPython declaration pack already spells it.
    pub targets: &'static [&'static str],
    /// The `provenance.source` recorded in the pack.
    pub provenance_source: &'static str,
    /// The `provenance.revision` recorded in the pack.
    pub provenance_revision: &'static str,
    /// Whether a call to an external static (module-level) procedure presents a
    /// receiver at the boundary. See [`shipped_has_receiver`].
    pub qualified_static_call_has_receiver: bool,
}

/// The JDK realm. Every claimed API (`String`, `StringBuilder`, `Optional`,
/// `Base64`, the `java.util` collections, the `java.io` wrappers) exists in
/// Java 17 and later.
pub const JDK_REALM: GoldenRealm = GoldenRealm {
    pack_id: "bifrost.jdk-golden-summaries",
    language: "java",
    ecosystem: "jdk",
    toolchain: "jdk",
    toolchain_requirement: ">=17.0.0",
    targets: &["jvm"],
    provenance_source: "hand-authored golden-core JDK flow-through summaries",
    provenance_revision: "golden-core",
    // A Java call to an external static method always spells its owner --
    // `java.net.URLDecoder.decode(x, enc)` -- and the Java IR models that owner
    // qualifier as the call receiver (#1978).
    qualified_static_call_has_receiver: true,
};

/// The CPython realm. Its ecosystem and toolchain names match the pinned
/// CPython declaration pack (`bifrost.python-stdlib`), so one workspace's
/// activation evidence serves both. Every claimed API (`urllib.parse`, `base64`,
/// `os.path`, `html`) exists in CPython 3.8 and later.
pub const PYTHON_REALM: GoldenRealm = GoldenRealm {
    pack_id: "bifrost.cpython-golden-summaries",
    language: "python",
    ecosystem: "python",
    toolchain: "cpython",
    toolchain_requirement: ">=3.8.0",
    targets: &[],
    provenance_source: "hand-authored golden-core CPython flow-through summaries",
    provenance_revision: "golden-core",
    // A Python call to a module-level function spells the module --
    // `urllib.parse.unquote(x)` -- and the Python IR models that module
    // qualifier as the call receiver, exactly as Java models the type
    // qualifier.
    qualified_static_call_has_receiver: true,
};

/// Resolve a realm from its short name, as the CLI spells it.
pub fn realm_by_name(name: &str) -> Option<GoldenRealm> {
    match name {
        "jdk" => Some(JDK_REALM),
        "python" => Some(PYTHON_REALM),
        _ => None,
    }
}

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
        pack_id: String,
        id: String,
    },
    /// The generated pack did not survive the production compiler after the
    /// per-candidate rejects were removed. That is a converter bug: the report
    /// lists the diagnostics.
    CompileFailed {
        pack_id: String,
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

impl std::error::Error for GoldenPackError {}

/// Read every `*.json` candidate file under `candidates_dir`, drop the
/// duplicate-target candidates, and produce the pack source plus the audit
/// report for one realm.
pub fn convert_golden_candidates(
    candidates_dir: &Path,
    realm: GoldenRealm,
) -> Result<GoldenConversion, GoldenPackError> {
    let candidates = read_candidates(candidates_dir)?;
    build_conversion(candidates, realm)
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

fn build_conversion(
    candidates: Vec<GoldenCandidate>,
    realm: GoldenRealm,
) -> Result<GoldenConversion, GoldenPackError> {
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
        .map(|candidate| build_summary(candidate, realm))
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    reconcile_overload_groups(&mut summaries, &mut rejects);
    assert_ids_unique(&summaries, realm)?;

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

    let pack = build_pack(summaries, completeness, realm);
    let source_json = serialize_pack(&pack);
    compile_check(&source_json, realm)?;

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
            pack_id: realm.pack_id.to_owned(),
            artifact: realm.ecosystem.to_owned(),
            pinned: true,
            ecosystem: realm.ecosystem.to_owned(),
            completeness,
            shipped_summaries,
        }],
    };

    Ok(GoldenConversion {
        packs: vec![GeneratedGoldenPack {
            pack_id: realm.pack_id.to_owned(),
            artifact: realm.ecosystem.to_owned(),
            relative_path: PathBuf::from(format!("{}.json", realm.pack_id)),
            pinned: true,
            source_json,
        }],
        audit,
    })
}

/// Java owners declared `final` in every supported toolchain version, so an
/// instance method on them has no overrides to cover. Reviewed list; a class
/// that is merely effectively-final does not belong here.
const JAVA_FINAL_OWNERS: &[&str] = &[
    "java.lang.String",
    "java.lang.StringBuilder",
    "java.lang.StringBuffer",
    "java.util.StringJoiner",
];

/// Whether the shipped summary may claim `covers_overrides` (#2371) from
/// language semantics alone: a static method has exactly one target, and an
/// instance method on a `final` class has no overrides. A constructor's target
/// is also exact, but it stays receiverless after conversion and a receiverless
/// claim is rejected at validation, so it keeps `false`. Everything else --
/// interface and overridable-class members -- stays `false` honestly.
///
/// Reads the authored `has_receiver`, which marks staticness, so it must run
/// before [`shipped_has_receiver`] rewrites the field for binding.
fn shipped_covers_overrides(target: &AuthoredProcedureTarget, realm: GoldenRealm) -> bool {
    if realm.language != "java" || target.symbol.contains("<init>") {
        return false;
    }
    if !target.has_receiver {
        return true;
    }
    let name = target.symbol.split('(').next().unwrap_or(&target.symbol);
    name.rsplit_once('.')
        .is_some_and(|(owner, _)| JAVA_FINAL_OWNERS.contains(&owner))
}

/// Build one shipped summary from one candidate. A golden entry carries only
/// flow-through transfers, so the effects list stays empty.
fn build_summary(candidate: GoldenCandidate, realm: GoldenRealm) -> AuthoredProcedureSummary {
    let mut target = candidate.target;
    // The production compiler rejects the claim on a partial summary, so the
    // language-semantics derivation only applies to complete entries.
    let covers_overrides = candidate.completeness == Completeness::Complete
        && shipped_covers_overrides(&target, realm);
    target.has_receiver = shipped_has_receiver(&target, realm);
    AuthoredProcedureSummary {
        id: summary_id(&target.symbol),
        target,
        completeness: candidate.completeness,
        covers_overrides,
        locations: Vec::new(),
        transfers: candidate.transfers,
        effects: Vec::new(),
        declared_effects: Vec::new(),
    }
}

/// Make every same-arity overload group internally consistent, because the
/// binding key for an unmaterialized external callee cannot tell the overloads
/// apart.
///
/// That key is (language, owner FQN, member, receiver, arity) (#1978), so
/// `String.valueOf(int)`, `String.valueOf(char[])`, and
/// `String.valueOf(Object)` are one key with three records. The runtime treats
/// several records that make the SAME claim as one answer and refuses a real
/// disagreement, so a pack that ships a disagreeing group fails a policy closed
/// at the call. This function removes that possibility at authoring time:
///
///   * A group whose transfers and effects agree ships at the group's weakest
///     completeness. The transfers are unchanged, so propagation is unchanged;
///     only the exhaustiveness claim weakens, which is the honest reading when a
///     call could be any member of the group.
///   * A group whose transfers or effects disagree cannot be reconciled without
///     inventing a claim, so every member is dropped and recorded in the audit
///     report. Losing the model abstains honestly; shipping it would fail the
///     run.
fn reconcile_overload_groups(
    summaries: &mut Vec<AuthoredProcedureSummary>,
    rejects: &mut Vec<GoldenReject>,
) {
    // (owner, member, has_receiver, parameter_count) -> indexes into summaries.
    let mut groups: std::collections::BTreeMap<(String, String, bool, u32), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (index, summary) in summaries.iter().enumerate() {
        let Some((owner, member)) = canonical_owner_and_member(&summary.target.symbol) else {
            continue;
        };
        groups
            .entry((
                owner.to_owned(),
                member.to_owned(),
                summary.target.has_receiver,
                summary.target.parameter_count,
            ))
            .or_default()
            .push(index);
    }

    let mut dropped: BTreeSet<usize> = BTreeSet::new();
    let mut weakened: Vec<usize> = Vec::new();
    for ((owner, member, _, arity), indexes) in groups {
        if indexes.len() < 2 {
            continue;
        }
        let first = &summaries[indexes[0]];
        let agrees = indexes.iter().all(|index| {
            let summary = &summaries[*index];
            summary.transfers == first.transfers && summary.effects == first.effects
        });
        if agrees {
            if indexes
                .iter()
                .any(|index| matches!(summaries[*index].completeness, Completeness::Partial))
            {
                weakened.extend(indexes.iter().copied());
            }
            continue;
        }
        for index in &indexes {
            let summary = &summaries[*index];
            rejects.push(GoldenReject {
                target_path: summary.target.path.clone(),
                target_symbol: summary.target.symbol.clone(),
                reason: "ambiguous_overload_group".to_owned(),
                message: format!(
                    "`{owner}.{member}` has {} shipped overloads of arity {arity} whose transfers \
                     disagree; the canonical binding key cannot tell them apart, so none is \
                     shipped",
                    indexes.len()
                ),
            });
            dropped.insert(*index);
        }
    }

    for index in weakened {
        summaries[index].completeness = Completeness::Partial;
        // A partial summary cannot carry the covers_overrides claim (#2371),
        // and the production compiler rejects the combination.
        summaries[index].covers_overrides = false;
    }
    if !dropped.is_empty() {
        let mut index = 0usize;
        summaries.retain(|_| {
            let keep = !dropped.contains(&index);
            index += 1;
            keep
        });
    }
}

/// Split a signed symbol (`java.lang.String.valueOf(int)`) into its owner FQN
/// and member name, the two halves of the canonical binding key. Returns `None`
/// for a symbol that carries no signature or no owner.
fn canonical_owner_and_member(symbol: &str) -> Option<(&str, &str)> {
    let unsigned = symbol.split_once('(').map(|(head, _)| head)?;
    unsigned.rsplit_once('.')
}

/// The receiver shape the shipped target must declare.
///
/// A candidate records the language-level truth: a static or module-level
/// procedure has no receiver. The shipped target must instead match the shape
/// the analyzer reports at the CALL, because that shape is part of the lookup
/// key on both binding routes -- `ProcedureSummaryTargetKey` for a materialized
/// declaration and `ProcedureSummaryMemberKey` for an unmaterialized
/// fully-qualified callee (#1978) -- and a mismatched key simply never binds.
///
/// A call to an external static procedure always spells its owner
/// (`java.net.URLDecoder.decode(x, enc)`, `urllib.parse.unquote(x)`), and the
/// IR models that qualifier as the call receiver. So such a target ships with a
/// receiver even though the language calls the method static. This is the
/// authoring rule #1978's fix left as a follow-up: it was applied by hand to
/// `URLDecoder.decode`, which drifted the checked-in pack from its generator,
/// and now applies uniformly here.
///
/// A constructor is different. `new StringBuilder(s)` has no qualifier before
/// the member, so an `<init>` target keeps the candidate's `false`.
fn shipped_has_receiver(target: &AuthoredProcedureTarget, realm: GoldenRealm) -> bool {
    if target.has_receiver {
        return true;
    }
    let is_constructor = target.symbol.contains("<init>");
    realm.qualified_static_call_has_receiver && !is_constructor
}

fn build_pack(
    summaries: Vec<AuthoredProcedureSummary>,
    completeness: Completeness,
    realm: GoldenRealm,
) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: 1,
        pack_id: realm.pack_id.to_owned(),
        version: PACK_CONTENT_VERSION.to_owned(),
        producer: Producer {
            name: PRODUCER_NAME.to_owned(),
            version: FOUNDRY_PRODUCER_VERSION.to_owned(),
        },
        language: realm.language.to_owned(),
        ecosystem: realm.ecosystem.to_owned(),
        compatibility: Compatibility {
            bifrost: FOUNDRY_BIFROST_REQUIREMENT.to_owned(),
            toolchains: vec![VersionConstraint {
                name: realm.toolchain.to_owned(),
                requirement: realm.toolchain_requirement.to_owned(),
            }],
        },
        provenance: Provenance {
            source: realm.provenance_source.to_owned(),
            revision: Some(realm.provenance_revision.to_owned()),
        },
        license: PACK_LICENSE.to_owned(),
        completeness,
        safety: Safety {
            generated_code_only: false,
            review_required: true,
        },
        shards: vec![AuthoredShard {
            id: format!("summaries.{}", realm.ecosystem),
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: Some(NameSelector {
                    name: realm.toolchain.to_owned(),
                    version: Some(realm.toolchain_requirement.to_owned()),
                }),
                targets: realm
                    .targets
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            payload: AuthoredPayload::ProcedureSummaries { summaries },
        }],
    }
}

fn assert_ids_unique(
    summaries: &[AuthoredProcedureSummary],
    realm: GoldenRealm,
) -> Result<(), GoldenPackError> {
    let mut seen = std::collections::HashSet::new();
    for summary in summaries {
        if !seen.insert(summary.id.as_str()) {
            return Err(GoldenPackError::DuplicateSummaryId {
                pack_id: realm.pack_id.to_owned(),
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
fn compile_check(source_json: &str, realm: GoldenRealm) -> Result<(), GoldenPackError> {
    compile_source(
        SourceFormat::Json,
        source_json.as_bytes(),
        &CompilerOptions::default(),
    )
    .map(|_| ())
    .map_err(|diagnostics| GoldenPackError::CompileFailed {
        pack_id: realm.pack_id.to_owned(),
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
        convert_in(files, JDK_REALM)
    }

    fn convert_in(files: &[(&str, &str)], realm: GoldenRealm) -> GoldenConversion {
        let dir = tempfile::tempdir().expect("temp candidates dir");
        for (name, body) in files {
            fs::write(dir.path().join(name), body).expect("write candidate file");
        }
        convert_golden_candidates(dir.path(), realm).expect("conversion")
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

    /// A static candidate is authored with no receiver -- that is the language
    /// truth -- but ships with one, because the call spells its owner and the IR
    /// models that qualifier as the receiver. A constructor keeps `false`.
    #[test]
    fn a_static_target_ships_with_the_receiver_the_call_presents() {
        let statics = r#"[
          {
            "target": {"path": "java.base/java/lang/String.java", "symbol": "java.lang.String.valueOf(int)", "has_receiver": false, "parameter_count": 1},
            "completeness": "complete",
            "transfers": [{"input": {"kind": "parameter", "ordinal": 0}, "exit_kind": "normal", "output": {"kind": "normal_return"}}],
            "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "javadoc"
          },
          {
            "target": {"path": "java.base/java/lang/StringBuilder.java", "symbol": "java.lang.StringBuilder.<init>(java.lang.String)", "has_receiver": false, "parameter_count": 1},
            "completeness": "complete",
            "transfers": [{"input": {"kind": "parameter", "ordinal": 0}, "exit_kind": "normal", "output": {"kind": "normal_return"}}],
            "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "javadoc"
          }
        ]"#;
        let conversion = convert(&[("statics.json", statics)]);
        let value: serde_json::Value =
            serde_json::from_str(&conversion.packs[0].source_json).unwrap();
        let summaries = value["shards"][0]["payload"]["summaries"]
            .as_array()
            .expect("summaries");
        let shape = |symbol: &str| {
            summaries
                .iter()
                .find(|summary| summary["target"]["symbol"] == symbol)
                .unwrap_or_else(|| panic!("{symbol} is shipped"))["target"]["has_receiver"]
                .as_bool()
                .expect("has_receiver is a bool")
        };
        assert!(
            shape("java.lang.String.valueOf(int)"),
            "a static target ships with the qualifier receiver the call presents"
        );
        assert!(
            !shape("java.lang.StringBuilder.<init>(java.lang.String)"),
            "a constructor call has no qualifier before the member, so it keeps no receiver"
        );
    }

    /// The realm is the only language-shaped input: the same candidate shape
    /// ships as a Python-toolchain-pinned pack under the CPython realm.
    #[test]
    fn the_python_realm_ships_a_python_pinned_pack_from_the_same_converter() {
        let unquote = r#"[{
          "target": {"path": "urllib/parse.py", "symbol": "urllib.parse.unquote(string)", "has_receiver": false, "parameter_count": 1},
          "completeness": "complete",
          "transfers": [{"input": {"kind": "parameter", "ordinal": 0}, "exit_kind": "normal", "output": {"kind": "normal_return"}}],
          "rationale": "flow", "provenance": "hand", "confidence": "high", "citations": "cpython docs"
        }]"#;
        let conversion = convert_in(&[("codec.json", unquote)], PYTHON_REALM);
        let pack = &conversion.packs[0];
        assert_eq!(pack.pack_id, "bifrost.cpython-golden-summaries");
        assert_eq!(conversion.audit.packs[0].ecosystem, "python");
        let value: serde_json::Value = serde_json::from_str(&pack.source_json).unwrap();
        assert_eq!(value["language"], "python");
        assert_eq!(value["compatibility"]["toolchains"][0]["name"], "cpython");
        assert_eq!(
            value["shards"][0]["activation"][0]["targets"],
            serde_json::json!([])
        );
        // The static-call receiver rule is the realm's, not Java's.
        assert_eq!(
            value["shards"][0]["payload"]["summaries"][0]["target"]["has_receiver"],
            serde_json::Value::Bool(true)
        );
    }
}
