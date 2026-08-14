//! Stage 4: the fixture engine.
//!
//! Every entry the foundry would ship must carry machine-run executable
//! evidence, and that evidence is generated mechanically from the entry, never
//! by the model that proposed it. This module is that generator. It turns one
//! [`FoundryEntry`] into a fixture suite: a minimal workspace that flows
//! attacker-controlled data through the entry's target into a sink, a
//! `require-model` taint policy over that workspace, and the entry compiled
//! into a semantic pack. The suite carries three polarities:
//!
//! - the positive case, which must yield one finding per claimed transfer;
//! - the fail-before control, the same workspace with the entry absent, which
//!   must yield none and report honest incompleteness instead;
//! - the negative case, generated only for an entry that claims `complete`,
//!   which routes taint through an input port the entry does *not* claim and
//!   must yield none. Only a `complete` claim can deny a flow, so only a
//!   `complete` entry gets one.
//!
//! What the fixture proves is executability, not truth. The target is always a
//! synthetic declaration the generator writes into the fixture's own workspace,
//! for two reasons that both hold today: every entry carries
//! [`FoundryArtifactBinding::Unresolved`](super::ir::FoundryArtifactBinding), so
//! there is no artifact to point at; and a procedure summary binds only where
//! the workspace has a *declaration without a body*, so the target's real body
//! could not be in the fixture even if the artifact were known. The fixture
//! therefore states: this entry's transfer set, applied to a target of the shape
//! the entry itself declares, survives the production pack compiler, binds
//! through the production binder, and carries taint exactly where it claims and
//! nowhere else. Whether the claim matches the real standard-library body is
//! stage 1's and stage 2's question, not this stage's.
//!
//! The language seam is [`FixtureLanguage`]. Everything above it -- port
//! routing, probe layout, pack assembly, the three polarities, the expected
//! finding counts -- is language independent, so a second language is one
//! implementation of that trait plus one entry in the caller's language table.

use std::fmt;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryExitKind, AuthoredSummaryInput,
    AuthoredSummaryOutput, Compatibility, Completeness, NameSelector, Producer, Provenance, Safety,
};
use serde::Serialize;

use super::ir::{FoundryCompleteness, FoundryEntry, FoundrySignature, render_transfer};

/// The pack id every generated fixture pack carries.
pub const FIXTURE_PACK_ID: &str = "bifrost.summary-foundry.fixture";

/// The activation coordinate a fixture pack declares and a fixture run claims.
/// The generator and the runner read the same constants, so the two cannot
/// drift into a silent non-activation.
pub const FIXTURE_PACKAGE_NAME: &str = "bifrost.summary-foundry:fixture";
pub const FIXTURE_PACKAGE_VERSION: &str = "1.0.0";
pub const FIXTURE_PACKAGE_REQUIREMENT: &str = ">=1.0.0, <2.0.0";
pub const FIXTURE_TARGET: &str = "jvm";
pub const FIXTURE_CONFIGURATION: &str = "release";

/// The stable summary id a fixture pack gives the entry under test. The pack
/// holds exactly one summary, so the id names the role rather than the target.
pub const FIXTURE_SUMMARY_ID: &str = "foundry.fixture.target";

/// Which polarity one generated case carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixturePolarity {
    /// The entry is active and taint enters a claimed input port.
    Positive,
    /// The same workspace with the entry absent. The claimed flow must not
    /// appear, and the run must report incompleteness rather than a clean
    /// negative.
    FailBefore,
    /// The entry is active and taint enters an input port it does not claim.
    /// Generated only for an entry claiming `complete`.
    Negative,
}

impl FixturePolarity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::FailBefore => "fail_before",
            Self::Negative => "negative",
        }
    }
}

/// One input port a fixture can route attacker-controlled data into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "port", rename_all = "snake_case")]
pub enum FixtureInputPort {
    Receiver,
    Parameter { ordinal: u32 },
}

impl FixtureInputPort {
    fn from_authored(input: &AuthoredSummaryInput) -> Self {
        match input {
            AuthoredSummaryInput::Receiver {} => Self::Receiver,
            AuthoredSummaryInput::Parameter { ordinal } => Self::Parameter { ordinal: *ordinal },
        }
    }
}

/// One attacker-to-sink route the fixture drives through the target.
///
/// One probe per claimed transfer keeps every finding attributable: probe `n`
/// proves transfer `n` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureProbe {
    /// The probe's index, which also names its source and sink helpers.
    pub index: usize,
    pub input: FixtureInputPort,
    /// The transfer this probe proves, rendered the way the join renders it.
    /// Absent on a negative probe, which proves the *absence* of a transfer.
    pub transfer: Option<String>,
}

/// The declaration shape a fixture renders for the target under test.
///
/// The parameter list is wide enough to give every input port the entry
/// mentions a call-site slot, so a claim is carried into the production
/// compiler rather than filtered out here. A claim that exceeds the entry's own
/// declared parameter count is exactly what the pack compiler rejects, and that
/// rejection is the proof gate working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureTargetShape {
    pub member: String,
    /// The declared parameter type spellings, as the entry pins them, padded
    /// with the language's filler type when a claimed ordinal runs past them.
    pub parameter_types: Vec<String>,
    pub has_receiver: bool,
}

/// One file a fixture writes into its workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureFile {
    /// Workspace-relative, always spelled with forward slashes.
    pub path: String,
    pub contents: String,
}

/// One runnable case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureCase {
    /// Unique within its suite, and usable as a directory name.
    pub id: String,
    pub polarity: FixturePolarity,
    /// Sorted by path, so two generations produce byte-identical output.
    pub files: Vec<FixtureFile>,
    /// The workspace-relative policy path inside `files`.
    pub policy_path: String,
    /// The authored pack, as canonical JSON. Absent for the fail-before
    /// control: its whole point is that no pack is present.
    pub pack_source: Option<String>,
    pub probes: Vec<FixtureProbe>,
    /// How many findings the production run must report. The runner treats any
    /// other count as a failed case.
    pub expected_findings: usize,
}

/// Every case generated for one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureSuite {
    pub entry_id: String,
    /// The target as the entry spells it, for the report.
    pub target: String,
    pub shape: FixtureTargetShape,
    pub completeness: Completeness,
    pub cases: Vec<FixtureCase>,
}

/// Why one entry has no fixture.
///
/// Each variant is a fact about the entry or about this stage's reach, never a
/// judgement about the claim. A refused entry is an entry stage 4 cannot
/// discharge, which is a failure for the entry, not a silent pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum FixtureUnsupported {
    /// The entry claims no flow at all, so it has no authored spelling and
    /// nothing to execute. Milestone 1 recorded the same gap as
    /// `FoundryNote::NoFlowClaimNotCarried`.
    NoAuthoredSummary,
    /// The entry pins no overload, so its symbol names no exact procedure and
    /// the production binder has nothing to bind it to.
    NoPinnedOverload,
    /// The transfer writes into an output port this stage cannot observe. Only
    /// the normal return is routable today: a receiver, heap, or capture output
    /// needs a fixture that reads the mutated cell back, and an exceptional
    /// output needs a throwing fixture.
    OutputPortUnsupported { output: String },
    /// The transfer leaves through the exceptional exit.
    ExitKindUnsupported { exit_kind: String },
}

impl fmt::Display for FixtureUnsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuthoredSummary => formatter.write_str(
                "the entry states no transfer, so it has no authored spelling to execute",
            ),
            Self::NoPinnedOverload => formatter
                .write_str("the entry pins no overload, so its symbol names no exact procedure"),
            Self::OutputPortUnsupported { output } => write!(
                formatter,
                "the fixture engine cannot observe the `{output}` output port"
            ),
            Self::ExitKindUnsupported { exit_kind } => write!(
                formatter,
                "the fixture engine cannot drive the `{exit_kind}` exit"
            ),
        }
    }
}

impl std::error::Error for FixtureUnsupported {}

/// The per-language seam.
///
/// One implementation owns everything about how a language spells a bodyless
/// declaration, how the analyzer will spell that declaration's symbol back, and
/// how a call site routes a value into one input port. Nothing else in this
/// module is language specific.
pub trait FixtureLanguage {
    /// The pack manifest's `language`, which is also the RQL `language` token.
    fn language(&self) -> &'static str;

    /// The pack manifest's `ecosystem`.
    fn ecosystem(&self) -> &'static str;

    /// The workspace-relative source path, which is also the `path` every
    /// generated summary target carries: a summary binds against the artifact
    /// that holds the declaration, and the fixture's declaration is in this
    /// file.
    fn source_path(&self) -> &'static str;

    /// The parameter type this language writes when a claimed ordinal runs past
    /// the types the entry pins.
    fn filler_parameter_type(&self) -> &'static str;

    /// The symbol the analyzer will spell for the declaration
    /// [`FixtureLanguage::render_source`] renders.
    ///
    /// This is the one place the pack's `symbol` is decided. It cannot be the
    /// entry's own spelling: the corpora join parameter types without a
    /// separator space and the analyzer joins them with one, so a symbol copied
    /// from the entry would silently fail to bind for every target of arity two
    /// or more.
    fn symbol(&self, shape: &FixtureTargetShape) -> String;

    /// The workspace source that declares the target, declares one source and
    /// one sink helper per probe, and drives each probe's call.
    fn render_source(&self, shape: &FixtureTargetShape, probes: &[FixtureProbe]) -> String;
}

/// Generate every case for one entry.
pub fn generate_fixture_suite(
    entry: &FoundryEntry,
    language: &dyn FixtureLanguage,
) -> Result<FixtureSuite, FixtureUnsupported> {
    let FoundrySignature::Overload { types } = &entry.target.signature else {
        return Err(FixtureUnsupported::NoPinnedOverload);
    };
    if entry.transfers.is_empty() {
        return Err(FixtureUnsupported::NoAuthoredSummary);
    }
    for transfer in &entry.transfers {
        match transfer.exit_kind {
            AuthoredSummaryExitKind::Normal => {}
            AuthoredSummaryExitKind::Exceptional => {
                return Err(FixtureUnsupported::ExitKindUnsupported {
                    exit_kind: "exceptional".to_owned(),
                });
            }
        }
        if !matches!(transfer.output, AuthoredSummaryOutput::NormalReturn {}) {
            return Err(FixtureUnsupported::OutputPortUnsupported {
                output: rendered_output(&transfer.output),
            });
        }
    }

    let shape = target_shape(entry, types, language);
    let completeness = completeness_of(entry);
    let positive_probes = entry
        .transfers
        .iter()
        .enumerate()
        .map(|(index, transfer)| FixtureProbe {
            index,
            input: FixtureInputPort::from_authored(&transfer.input),
            transfer: Some(render_transfer(transfer)),
        })
        .collect::<Vec<_>>();
    let pack_source = pack_source(entry, &shape, completeness, language);

    let mut cases = vec![
        case(
            "positive",
            FixturePolarity::Positive,
            &shape,
            &positive_probes,
            Some(pack_source.clone()),
            positive_probes.len(),
            language,
        ),
        case(
            "fail-before",
            FixturePolarity::FailBefore,
            &shape,
            &positive_probes,
            None,
            0,
            language,
        ),
    ];
    if completeness == Completeness::Complete
        && let Some(unclaimed) = unclaimed_input_port(entry, &shape)
    {
        let probes = vec![FixtureProbe {
            index: 0,
            input: unclaimed,
            transfer: None,
        }];
        cases.push(case(
            "negative",
            FixturePolarity::Negative,
            &shape,
            &probes,
            Some(pack_source),
            0,
            language,
        ));
    }

    Ok(FixtureSuite {
        entry_id: entry.id.clone(),
        target: format!(
            "{}#{}",
            entry.target.artifact_path,
            entry.target.signature.symbol(&entry.target.member)
        ),
        shape,
        completeness,
        cases,
    })
}

/// The shape the fixture declares.
///
/// The parameter list starts from the types the entry pins and grows to cover
/// every ordinal its transfers mention, so no claim is dropped before the
/// production compiler sees it.
fn target_shape(
    entry: &FoundryEntry,
    types: &[String],
    language: &dyn FixtureLanguage,
) -> FixtureTargetShape {
    let mut parameter_types = types.to_vec();
    let required = entry
        .transfers
        .iter()
        .filter_map(|transfer| match transfer.input {
            AuthoredSummaryInput::Parameter { ordinal } => Some(ordinal as usize + 1),
            AuthoredSummaryInput::Receiver {} => None,
        })
        .max()
        .unwrap_or(0)
        .max(entry.boundary.parameter_count as usize);
    while parameter_types.len() < required {
        parameter_types.push(language.filler_parameter_type().to_owned());
    }
    FixtureTargetShape {
        member: entry.target.member.clone(),
        parameter_types,
        has_receiver: entry.boundary.has_receiver,
    }
}

/// The completeness the fixture ships for this entry.
///
/// The fixture never softens or strengthens a claim: it ships exactly what the
/// entry states, because the whole point of the gate is to execute the claim
/// the foundry would ship.
fn completeness_of(entry: &FoundryEntry) -> Completeness {
    match entry.completeness {
        FoundryCompleteness::Partial => Completeness::Partial,
        FoundryCompleteness::Complete => Completeness::Complete,
    }
}

/// One input port the entry declares and claims no transfer from.
///
/// The negative case routes taint here: a `complete` entry states this port
/// reaches nothing, so a finding would refute the entry.
fn unclaimed_input_port(
    entry: &FoundryEntry,
    shape: &FixtureTargetShape,
) -> Option<FixtureInputPort> {
    let claimed = entry
        .transfers
        .iter()
        .map(|transfer| FixtureInputPort::from_authored(&transfer.input))
        .collect::<Vec<_>>();
    if shape.has_receiver && !claimed.contains(&FixtureInputPort::Receiver) {
        return Some(FixtureInputPort::Receiver);
    }
    (0..shape.parameter_types.len() as u32)
        .map(|ordinal| FixtureInputPort::Parameter { ordinal })
        .find(|port| !claimed.contains(port))
}

fn case(
    id: &str,
    polarity: FixturePolarity,
    shape: &FixtureTargetShape,
    probes: &[FixtureProbe],
    pack_source: Option<String>,
    expected_findings: usize,
    language: &dyn FixtureLanguage,
) -> FixtureCase {
    let policy_path = "policies/fixture.rqlp".to_owned();
    let mut files = vec![
        FixtureFile {
            path: language.source_path().to_owned(),
            contents: language.render_source(shape, probes),
        },
        FixtureFile {
            path: policy_path.clone(),
            contents: render_policy(language.language(), probes),
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    FixtureCase {
        id: id.to_owned(),
        polarity,
        files,
        policy_path,
        pack_source,
        probes: probes.to_vec(),
        expected_findings,
    }
}

/// The `require-model` taint policy over one fixture workspace.
///
/// `require-model` is the mode the whole stage rests on: without a model an
/// unmodeled call abstains instead of guessing, so a finding can only come from
/// the entry under test and its absence is not an accident of a permissive
/// fallback.
fn render_policy(language: &str, probes: &[FixtureProbe]) -> String {
    let sources = probes
        .iter()
        .map(|probe| {
            let index = probe.index;
            format!(
                "      (source :id attacker-{index} :display-name \"attacker {index}\" \
                 :categories [input.user]\n        \
                 :selector (rql :schema-version 1\n          \
                 (language {language} (call :callee (name \"attacker{index}\"))))\n        \
                 :bind return-value :labels [untrusted])"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let sinks = probes
        .iter()
        .map(|probe| {
            let index = probe.index;
            format!(
                "      (sink :id sensitive-{index} :display-name \"sensitive {index}\" \
                 :categories [data.sensitive]\n        \
                 :selector (rql :schema-version 1\n          \
                 (language {language} (call :callee (name \"sensitive{index}\"))))\n        \
                 :dangerous-operand (argument :index 0) :accepts [untrusted])"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"(policy
  :schema-version 1
  :id "bifrost.summary-foundry.fixture"
  :name "Summary foundry fixture"
  :message "attacker-controlled data reached a sink through the modelled procedure"
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :call-modeling (call-modeling :unmodeled require-model)
    :sources (endpoint-set :entries [
{sources}])
    :sinks (endpoint-set :entries [
{sinks}]))
  :classification (classification
    :fallback (classification-id :taxonomy "Foundry" :id "SUMMARY-FIXTURE")))
"#
    )
}

/// The entry compiled into an authored pack, as canonical JSON.
fn pack_source(
    entry: &FoundryEntry,
    shape: &FixtureTargetShape,
    completeness: Completeness,
    language: &dyn FixtureLanguage,
) -> String {
    let pack = AuthoredSemanticModelPack {
        schema_version: 1,
        pack_id: FIXTURE_PACK_ID.to_owned(),
        version: FIXTURE_PACKAGE_VERSION.to_owned(),
        producer: Producer {
            name: "bifrost-summary-foundry".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        language: language.language().to_owned(),
        ecosystem: language.ecosystem().to_owned(),
        compatibility: Compatibility {
            bifrost: ">=0.8.0, <1.0.0".to_owned(),
            toolchains: Vec::new(),
        },
        provenance: Provenance {
            source: "bifrost:summary-foundry/fixture".to_owned(),
            revision: Some(entry.id.clone()),
        },
        license: "Apache-2.0".to_owned(),
        completeness,
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
        shards: vec![AuthoredShard {
            id: "summaries.fixture".to_owned(),
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: FIXTURE_PACKAGE_NAME.to_owned(),
                    version: Some(FIXTURE_PACKAGE_REQUIREMENT.to_owned()),
                }),
                module: None,
                toolchain: None,
                targets: vec![FIXTURE_TARGET.to_owned()],
                configurations: vec![FIXTURE_CONFIGURATION.to_owned()],
                artifact_sha256: None,
            }],
            payload: AuthoredPayload::ProcedureSummaries {
                summaries: vec![AuthoredProcedureSummary {
                    id: FIXTURE_SUMMARY_ID.to_owned(),
                    target: AuthoredProcedureTarget {
                        path: language.source_path().to_owned(),
                        symbol: language.symbol(shape),
                        has_receiver: entry.boundary.has_receiver,
                        // The entry's own declared count, not the rendered one:
                        // a disagreement between the two is the entry's claim
                        // to answer for, and the production compiler is what
                        // answers it.
                        parameter_count: entry.boundary.parameter_count,
                    },
                    completeness,
                    locations: Vec::new(),
                    transfers: entry.transfers.clone(),
                    effects: Vec::new(),
                }],
            },
        }],
    };
    let mut rendered =
        serde_json::to_string_pretty(&pack).expect("the authored pack is serializable");
    rendered.push('\n');
    rendered
}

/// The output port an entry names, spelled the way the join spells it.
fn rendered_output(output: &AuthoredSummaryOutput) -> String {
    match output {
        AuthoredSummaryOutput::NormalReturn {} => "normal_return".to_owned(),
        AuthoredSummaryOutput::ExceptionalReturn {} => "exceptional_return".to_owned(),
        AuthoredSummaryOutput::Receiver {} => "receiver".to_owned(),
        AuthoredSummaryOutput::Capture { location } => format!("capture[{location}]"),
        AuthoredSummaryOutput::Heap { location } => format!("heap[{location}]"),
    }
}

/// Java's fixture template.
#[derive(Debug, Clone, Copy, Default)]
pub struct JavaFixtureLanguage;

impl JavaFixtureLanguage {
    /// The class that holds the target declaration and every probe. One class
    /// keeps a receiver-input probe's attacker able to return the receiver's
    /// own type without a second declaration.
    const CLASS: &'static str = "FoundryFixture";
}

impl FixtureLanguage for JavaFixtureLanguage {
    fn language(&self) -> &'static str {
        "java"
    }

    fn ecosystem(&self) -> &'static str {
        "maven"
    }

    fn source_path(&self) -> &'static str {
        "FoundryFixture.java"
    }

    fn filler_parameter_type(&self) -> &'static str {
        "Object"
    }

    fn symbol(&self, shape: &FixtureTargetShape) -> String {
        // The Java declaration walk renders a canonical parameter signature by
        // joining the declared type texts with ", ". The exact external target
        // a call site publishes is the identifier followed by that signature,
        // so this is the spelling the summary target has to carry.
        format!("{}({})", shape.member, shape.parameter_types.join(", "))
    }

    fn render_source(&self, shape: &FixtureTargetShape, probes: &[FixtureProbe]) -> String {
        let class = Self::CLASS;
        let mut source = format!("class {class} {{\n");
        for probe in probes {
            let index = probe.index;
            let attacker_type = match probe.input {
                FixtureInputPort::Receiver => class,
                FixtureInputPort::Parameter { .. } => "String",
            };
            source.push_str(&format!(
                "    static native {attacker_type} attacker{index}();\n"
            ));
            source.push_str(&format!(
                "    static native void sensitive{index}(String value);\n"
            ));
        }
        let modifiers = if shape.has_receiver {
            "native"
        } else {
            "static native"
        };
        let parameters = shape
            .parameter_types
            .iter()
            .enumerate()
            .map(|(ordinal, spelling)| format!("{spelling} p{ordinal}"))
            .collect::<Vec<_>>()
            .join(", ");
        source.push_str(&format!(
            "    {modifiers} String {}({parameters});\n",
            shape.member
        ));
        for probe in probes {
            let index = probe.index;
            let arguments = (0..shape.parameter_types.len())
                .map(|ordinal| match probe.input {
                    FixtureInputPort::Parameter { ordinal: tainted }
                        if tainted as usize == ordinal =>
                    {
                        format!("attacker{index}()")
                    }
                    _ => format!("\"clean{ordinal}\""),
                })
                .collect::<Vec<_>>()
                .join(", ");
            // A static target is called unqualified: a qualified call carries a
            // receiver expression, and the dispatch oracle then publishes an
            // exact external target with a receiver, which no static summary
            // can bind.
            let call = match (shape.has_receiver, probe.input) {
                (false, _) => format!("{}({arguments})", shape.member),
                (true, FixtureInputPort::Receiver) => {
                    format!("attacker{index}().{}({arguments})", shape.member)
                }
                (true, FixtureInputPort::Parameter { .. }) => {
                    format!("this.{}({arguments})", shape.member)
                }
            };
            source.push_str(&format!("\n    void probe{index}() {{\n"));
            source.push_str(&format!("        sensitive{index}({call});\n"));
            source.push_str("    }\n");
        }
        source.push_str("}\n");
        source
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::semantic_model::AuthoredSummaryTransfer;

    use super::*;
    use crate::summary_foundry::ir::{
        FoundryArtifactBinding, FoundryBoundary, FoundryClaim, FoundryCorpus, FoundryTarget,
    };

    fn transfer(input: AuthoredSummaryInput) -> AuthoredSummaryTransfer {
        AuthoredSummaryTransfer {
            input,
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::NormalReturn {},
        }
    }

    fn entry(
        member: &str,
        types: &[&str],
        has_receiver: bool,
        transfers: Vec<AuthoredSummaryTransfer>,
    ) -> FoundryEntry {
        FoundryEntry {
            id: format!("test.{member}"),
            corpus: FoundryCorpus::Derived,
            target: FoundryTarget {
                artifact_path: "java/lang/String.class".to_owned(),
                member: member.to_owned(),
                signature: FoundrySignature::Overload {
                    types: types.iter().map(|value| (*value).to_owned()).collect(),
                },
            },
            boundary: FoundryBoundary {
                has_receiver,
                parameter_count: types.len() as u32,
            },
            claim: FoundryClaim::Flows,
            completeness: FoundryCompleteness::Partial,
            transfers,
            artifact: FoundryArtifactBinding::Unresolved,
            evidence: Vec::new(),
            notes: Vec::new(),
            derivation: None,
        }
    }

    #[test]
    fn a_static_two_parameter_entry_routes_one_probe_per_claimed_transfer() {
        let entry = entry(
            "format",
            &["String", "Object"],
            false,
            vec![
                transfer(AuthoredSummaryInput::Parameter { ordinal: 0 }),
                transfer(AuthoredSummaryInput::Parameter { ordinal: 1 }),
            ],
        );

        let suite = generate_fixture_suite(&entry, &JavaFixtureLanguage).expect("a routable entry");

        assert_eq!(
            suite.cases.len(),
            2,
            "a partial entry gets no negative case"
        );
        let positive = &suite.cases[0];
        assert_eq!(positive.polarity, FixturePolarity::Positive);
        assert_eq!(positive.expected_findings, 2);
        let source = &positive.files[0].contents;
        assert!(
            source.contains("static native String format(String p0, Object p1);"),
            "{source}"
        );
        assert!(
            source.contains("sensitive0(format(attacker0(), \"clean1\"));"),
            "{source}"
        );
        assert!(
            source.contains("sensitive1(format(\"clean0\", attacker1()));"),
            "{source}"
        );
        // The pack symbol has to be the analyzer's spelling, not the corpus's.
        assert!(
            positive
                .pack_source
                .as_ref()
                .unwrap()
                .contains("format(String, Object)"),
            "{:?}",
            positive.pack_source
        );
        assert_eq!(suite.cases[1].polarity, FixturePolarity::FailBefore);
        assert!(suite.cases[1].pack_source.is_none());
        assert_eq!(suite.cases[1].expected_findings, 0);
        assert_eq!(suite.cases[1].files, positive.files);
    }

    #[test]
    fn a_receiver_input_probe_taints_the_receiver_and_a_parameter_probe_uses_this() {
        let entry = entry(
            "replace",
            &["CharSequence", "CharSequence"],
            true,
            vec![
                transfer(AuthoredSummaryInput::Receiver {}),
                transfer(AuthoredSummaryInput::Parameter { ordinal: 1 }),
            ],
        );

        let suite = generate_fixture_suite(&entry, &JavaFixtureLanguage).expect("a routable entry");

        let source = &suite.cases[0].files[0].contents;
        assert!(
            source.contains("static native FoundryFixture attacker0();"),
            "{source}"
        );
        assert!(
            source.contains("sensitive0(attacker0().replace(\"clean0\", \"clean1\"));"),
            "{source}"
        );
        assert!(
            source.contains("static native String attacker1();"),
            "{source}"
        );
        assert!(
            source.contains("sensitive1(this.replace(\"clean0\", attacker1()));"),
            "{source}"
        );
        assert!(
            source.contains("    native String replace(CharSequence p0, CharSequence p1);"),
            "{source}"
        );
    }

    #[test]
    fn a_complete_entry_gains_a_negative_case_over_an_unclaimed_port() {
        let mut entry = entry(
            "substring",
            &["int", "int"],
            true,
            vec![transfer(AuthoredSummaryInput::Receiver {})],
        );
        entry.completeness = FoundryCompleteness::Complete;

        let suite = generate_fixture_suite(&entry, &JavaFixtureLanguage).expect("a routable entry");

        assert_eq!(suite.completeness, Completeness::Complete);
        let negative = suite
            .cases
            .iter()
            .find(|case| case.polarity == FixturePolarity::Negative)
            .expect("a complete entry with an unclaimed port gets a negative case");
        assert_eq!(negative.expected_findings, 0);
        assert_eq!(
            negative.probes[0].input,
            FixtureInputPort::Parameter { ordinal: 0 }
        );
        assert!(negative.pack_source.is_some());
    }

    #[test]
    fn an_unsigned_or_output_bound_entry_is_refused_with_its_reason() {
        let mut unsigned = entry(
            "join",
            &[],
            false,
            vec![transfer(AuthoredSummaryInput::Parameter { ordinal: 0 })],
        );
        unsigned.target.signature = FoundrySignature::AnyOverload;
        assert_eq!(
            generate_fixture_suite(&unsigned, &JavaFixtureLanguage),
            Err(FixtureUnsupported::NoPinnedOverload)
        );

        let receiver_output = entry(
            "getChars",
            &["char[]"],
            true,
            vec![AuthoredSummaryTransfer {
                input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                exit_kind: AuthoredSummaryExitKind::Normal,
                output: AuthoredSummaryOutput::Receiver {},
            }],
        );
        assert_eq!(
            generate_fixture_suite(&receiver_output, &JavaFixtureLanguage),
            Err(FixtureUnsupported::OutputPortUnsupported {
                output: "receiver".to_owned()
            })
        );

        let no_flow = entry("length", &[], true, Vec::new());
        assert_eq!(
            generate_fixture_suite(&no_flow, &JavaFixtureLanguage),
            Err(FixtureUnsupported::NoAuthoredSummary)
        );
    }

    #[test]
    fn a_transfer_past_the_declared_arity_still_reaches_the_production_compiler() {
        // The entry declares one parameter and claims a transfer from a second.
        // The fixture widens its own declaration so the claim is carried, and
        // the pack keeps the entry's declared count, which is what the pack
        // compiler rejects.
        let mut corrupted = entry(
            "valueOf",
            &["Object"],
            false,
            vec![transfer(AuthoredSummaryInput::Parameter { ordinal: 1 })],
        );
        corrupted.boundary.parameter_count = 1;

        let suite =
            generate_fixture_suite(&corrupted, &JavaFixtureLanguage).expect("still renders");

        let positive = &suite.cases[0];
        assert!(
            positive.files[0]
                .contents
                .contains("static native String valueOf(Object p0, Object p1);"),
            "{}",
            positive.files[0].contents
        );
        assert!(
            positive
                .pack_source
                .as_ref()
                .unwrap()
                .contains("\"parameter_count\": 1"),
            "{:?}",
            positive.pack_source
        );
    }

    #[test]
    fn two_generations_of_one_entry_are_identical() {
        let entry = entry(
            "concat",
            &["String"],
            true,
            vec![
                transfer(AuthoredSummaryInput::Receiver {}),
                transfer(AuthoredSummaryInput::Parameter { ordinal: 0 }),
            ],
        );

        assert_eq!(
            generate_fixture_suite(&entry, &JavaFixtureLanguage),
            generate_fixture_suite(&entry, &JavaFixtureLanguage)
        );
    }
}
