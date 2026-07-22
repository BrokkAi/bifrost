//! Engine tests for the MCP property fuzzer (`src/mcp_property_fuzzer/mod.rs`).
//!
//! The pure-checker tests fabricate `I1Input` directly so firing behavior is
//! deterministic and independent of whatever the analyzer happens to do at
//! HEAD; the integration tests run the engine over real analyzer output from
//! `InlineTestProject` fixtures.

mod common;

use brokk_bifrost::mcp_property_fuzzer::{
    FuzzerConfig, I1File, I1Input, InvariantKind, SymbolFacts, check_i1, rerun::rerun_configs,
    run_invariants,
};
use brokk_bifrost::{AnalyzerConfig, CodeUnitType, ParseError, ParseErrorKind, Range};
use common::InlineTestProject;

/// Verbatim `cortex/connector/.../controllers/v0/JobCtrl.scala` from
/// TheHive-Project/TheHive @ d390a031 (AGPL-3.0), as reported in issue #1016.
const ISSUE_1016_JOBCTRL: &str = include_str!("fixtures/scala-issue-1016/JobCtrl.scala");

fn range(text: &str, needle: &str, end: Option<&str>) -> Range {
    let start_byte = text.find(needle).expect("needle present");
    let end_byte = match end {
        Some(end) => start_byte + text[start_byte..].find(end).expect("end present") + end.len(),
        None => text.len(),
    };
    let start_line = text[..start_byte].matches('\n').count() + 1;
    let end_line = text[..end_byte].matches('\n').count() + 1;
    Range {
        start_byte,
        end_byte,
        start_line,
        end_line,
    }
}

fn facts(
    fq_name: &str,
    identifier: &str,
    kind: CodeUnitType,
    ranges: Vec<Range>,
    child_indexes: Vec<usize>,
) -> SymbolFacts {
    SymbolFacts {
        fq_name: fq_name.to_string(),
        identifier: identifier.to_string(),
        display_fq: fq_name.to_string(),
        kind,
        file_index: 0,
        ranges,
        child_indexes,
        parent_index: None,
        aux_constructor: false,
    }
}

fn check(input: &I1Input) -> Vec<brokk_bifrost::mcp_property_fuzzer::Violation> {
    let mut summary = Default::default();
    check_i1(input, "scala", &mut summary)
}

#[test]
fn i1_fires_when_container_range_excludes_member() {
    let text =
        "package x\n\n@Singleton\nclass JobCtrl @Inject()\n\n  def create: Int = 1\n".to_string();
    // The #1016 shape: the class range stops at the annotated constructor,
    // while its method is indexed further down the file.
    let class_range = range(&text, "@Singleton", Some("@Inject()"));
    let method_range = range(&text, "def create", Some("1"));
    let input = I1Input {
        files: vec![I1File {
            path: "src/JobCtrl.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![
            facts(
                "x.JobCtrl",
                "JobCtrl",
                CodeUnitType::Class,
                vec![class_range],
                vec![1],
            ),
            facts(
                "x.JobCtrl.create",
                "create",
                CodeUnitType::Function,
                vec![method_range],
                vec![],
            ),
        ],
    };
    let violations = check(&input);
    assert_eq!(violations.len(), 1, "{violations:?}");
    let violation = &violations[0];
    assert_eq!(
        violation.signature,
        "(I1, scala, index, container-range-misses-member)"
    );
    assert_eq!(violation.symbol, "x.JobCtrl.create");
    assert_eq!(violation.occurrences, 1);
    assert_eq!(violation.evidence["parent"]["fq_name"], "x.JobCtrl");
    assert_eq!(violation.evidence["child"]["fq_name"], "x.JobCtrl.create");
}

#[test]
fn i1_silent_when_container_range_covers_member() {
    let text = "package x\n\nclass JobCtrl {\n  def create: Int = 1\n}\n".to_string();
    let class_range = range(&text, "class JobCtrl", None);
    let method_range = range(&text, "def create", Some("1"));
    let input = I1Input {
        files: vec![I1File {
            path: "src/JobCtrl.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![
            facts(
                "x.JobCtrl",
                "JobCtrl",
                CodeUnitType::Class,
                vec![class_range],
                vec![1],
            ),
            facts(
                "x.JobCtrl.create",
                "create",
                CodeUnitType::Function,
                vec![method_range],
                vec![],
            ),
        ],
    };
    assert!(check(&input).is_empty());
}

#[test]
fn i1_silent_when_any_parent_range_covers_member() {
    // Re-opened constructs legitimately carry several ranges; containment only
    // requires that some parent range covers the member.
    let text = "class A {\n  def m: Int = 1\n}\nclass A {\n  def n: Int = 2\n}\n".to_string();
    let first_range = range(&text, "class A {\n  def m", Some("}\n"));
    let second_range = range(&text, "class A {\n  def n", None);
    let method_range = range(&text, "def n", Some("2"));
    let input = I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![
            facts(
                "A",
                "A",
                CodeUnitType::Class,
                vec![first_range, second_range],
                vec![1],
            ),
            facts(
                "A.n",
                "n",
                CodeUnitType::Function,
                vec![method_range],
                vec![],
            ),
        ],
    };
    assert!(check(&input).is_empty());
}

#[test]
fn i1_fires_when_range_text_lacks_name_token() {
    let text = "package x\n\nclass JobCtrl {\n}\n".to_string();
    // Range covers text that does not contain the terminal name.
    let wrong_range = range(&text, "package x", Some("package"));
    let input = I1Input {
        files: vec![I1File {
            path: "src/JobCtrl.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![facts(
            "x.JobCtrl",
            "JobCtrl",
            CodeUnitType::Class,
            vec![wrong_range],
            vec![],
        )],
    };
    let violations = check(&input);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I1, scala, index, range-name-token-absent)"
    );
    assert_eq!(violations[0].symbol, "x.JobCtrl");
}

#[test]
fn i1_fires_when_range_extends_past_source() {
    let text = "class A {}\n".to_string();
    let mut bad = range(&text, "class A", None);
    bad.end_byte = text.len() + 50;
    let input = I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![facts("A", "A", CodeUnitType::Class, vec![bad], vec![])],
    };
    let violations = check(&input);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I1, scala, index, range-outside-source)"
    );
}

#[test]
fn i1_skips_non_identifier_names() {
    let text = "class A {\n  def this()\n}\n".to_string();
    let ctor_range = range(&text, "def this", None);
    let input = I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![facts(
            "A.<init>",
            "<init>",
            CodeUnitType::Function,
            vec![ctor_range],
            vec![],
        )],
    };
    assert!(check(&input).is_empty());
}

#[test]
fn i1_skips_module_name_token_check() {
    // A module unit's name comes from its file (`index.mjs` → terminal `mjs`),
    // not from a token in the source, so the name-token expectation never
    // applies (observed on vuejs/core: 102 false occurrences, one signature).
    let text = "export * from '@vue/compiler-sfc'\n\nimport './register-ts.js'\n".to_string();
    let module_range = range(&text, "export", None);
    let input = I1Input {
        files: vec![I1File {
            path: "packages/vue/compiler-sfc/index.mjs".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![facts(
            "index.mjs",
            "mjs",
            CodeUnitType::Module,
            vec![module_range],
            vec![],
        )],
    };
    let mut summary = Default::default();
    let violations = check_i1(&input, "ts", &mut summary);
    assert!(violations.is_empty(), "{violations:?}");
    assert_eq!(summary.skipped_module_name, 1);
    assert_eq!(summary.name_token_checks, 0);
}

#[test]
fn i1_deduplicates_by_signature_with_occurrence_count() {
    let text = "class A @Inject()\n\n  def m: Int = 1\n\n  def n: Int = 2\n".to_string();
    let class_range = range(&text, "class A", Some("@Inject()"));
    let m_range = range(&text, "def m", Some("1"));
    let n_range = range(&text, "def n", Some("2"));
    let input = I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![
            facts("A", "A", CodeUnitType::Class, vec![class_range], vec![1, 2]),
            facts("A.m", "m", CodeUnitType::Function, vec![m_range], vec![]),
            facts("A.n", "n", CodeUnitType::Function, vec![n_range], vec![]),
        ],
    };
    let violations = check(&input);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].occurrences, 2);
    assert_eq!(violations[0].exemplars, vec!["A.m", "A.n"]);
}

fn fuzzer_config(language: &str) -> FuzzerConfig {
    FuzzerConfig {
        corpus_language: language.to_string(),
        invariants: vec![InvariantKind::I1],
        max_symbols: 5_000,
        max_service_symbols: 1_000,
        max_scan_probes: 100,
        symbol_filter: None,
        path_filter: None,
        seed: 0,
    }
}

#[test]
fn i1_silent_on_healthy_scala_fixture() {
    let project = InlineTestProject::new()
        .file(
            "src/Greeter.scala",
            "package com.example\n\nclass Greeter {\n  def greet(name: String): String = \"hello \" + name\n  def twice(name: String): String = greet(name) + greet(name)\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report =
        run_invariants(workspace.analyzer(), &fuzzer_config("scala")).expect("run invariants");
    assert!(report.i1_summary.symbols_selected > 0);
    assert!(report.i1_summary.containment_checks > 0);
    assert!(
        report.violations.is_empty(),
        "{}",
        serde_json::to_string_pretty(&report.violations).expect("violations json")
    );
}

/// A second issue #1016 shape: an annotated, multi-line constructor with an
/// annotated parameter after the original TheHive imports. The excerpt is the
/// first 60 lines (plus closing brace) of
/// `cortex/connector/.../services/JobSrv.scala` from TheHive-Project/TheHive
/// (AGPL-3.0), the corpus repository #1016 was filed against. The fixed parser
/// must keep the body members inside `JobSrv` and leave I1 silent.
#[test]
fn issue_1016_i1_accepts_annotated_constructor_parameter_scala_fixture() {
    let project = InlineTestProject::new()
        .file("src/JobSrv.scala", ISSUE_1016_JOBSRV_EXCERPT)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report =
        run_invariants(workspace.analyzer(), &fuzzer_config("scala")).expect("run invariants");
    assert!(
        report.violations.is_empty(),
        "{}",
        serde_json::to_string_pretty(&report.violations).expect("violations json")
    );

    let analyzer = workspace.analyzer();
    let job_srv = analyzer
        .get_definitions("org.thp.thehive.connector.cortex.services.JobSrv")
        .into_iter()
        .find(|unit| unit.is_class())
        .expect("JobSrv class");
    let source = analyzer.get_source(&job_srv, false).expect("JobSrv source");
    assert!(
        source.contains("@Named(\"cortex-actor\") cortexActor: ActorRef"),
        "{source}"
    );
    assert!(source.contains("val observableJobSrv"), "{source}");
    assert!(source.contains("val reportObservableSrv"), "{source}");
}

/// First 60 lines of `JobSrv.scala` (TheHive-Project/TheHive @ d390a031,
/// AGPL-3.0) plus the closing brace; see the test above for why paraphrases
/// do not reproduce the truncated range.
const ISSUE_1016_JOBSRV_EXCERPT: &str = r#"package org.thp.thehive.connector.cortex.services

import akka.Done
import akka.actor._
import akka.stream.Materializer
import akka.stream.scaladsl.FileIO
import com.google.inject.name.Named
import io.scalaland.chimney.dsl._
import org.apache.tinkerpop.gremlin.process.traversal.P
import org.thp.cortex.client.CortexClient
import org.thp.cortex.dto.v0.{InputArtifact, OutputArtifact, Attachment => CortexAttachment, JobStatus => CortexJobStatus, OutputJob => CortexJob}
import org.thp.scalligraph.auth.{AuthContext, Permission}
import org.thp.scalligraph.controllers.FFile
import org.thp.scalligraph.models.{Database, Entity}
import org.thp.scalligraph.services._
import org.thp.scalligraph.traversal.TraversalOps._
import org.thp.scalligraph.traversal.{Converter, Graph, StepLabel, Traversal}
import org.thp.scalligraph.{CreateError, EntityId, EntityIdOrName, NotFoundError}
import org.thp.thehive.connector.cortex.controllers.v0.Conversion._
import org.thp.thehive.connector.cortex.models._
import org.thp.thehive.connector.cortex.services.Conversion._
import org.thp.thehive.connector.cortex.services.JobOps._
import org.thp.thehive.controllers.v0.Conversion._
import org.thp.thehive.models._
import org.thp.thehive.services.CaseOps._
import org.thp.thehive.services.ObservableOps._
import org.thp.thehive.services.OrganisationOps._
import org.thp.thehive.services.{AttachmentSrv, ObservableSrv, ObservableTypeSrv, OrganisationSrv, ReportTagSrv}
import play.api.libs.json.{JsObject, JsString, Json}

import java.nio.file.Files
import java.util.{Date, Map => JMap}
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Success, Try}

@Singleton
class JobSrv @Inject() (
    connector: Connector,
    @Named("cortex-actor") cortexActor: ActorRef,
    observableSrv: ObservableSrv,
    observableTypeSrv: ObservableTypeSrv,
    attachmentSrv: AttachmentSrv,
    reportTagSrv: ReportTagSrv,
    actionOperationSrv: ActionOperationSrv,
    serviceHelper: ServiceHelper,
    auditSrv: CortexAuditSrv,
    organisationSrv: OrganisationSrv,
    implicit val db: Database,
    implicit val ec: ExecutionContext,
    implicit val mat: Materializer
) extends VertexSrv[Job] {

  val observableJobSrv    = new EdgeSrv[ObservableJob, Observable, Job]
  val reportObservableSrv = new EdgeSrv[ReportObservable, Job, Observable]

  /**
    * Submits an observable for analysis to cortex client and stores
    * resulting job and send the cortex reference id to the polling job status actor
    *
}
"#;

#[test]
fn service_invariants_are_rejected_by_engine_only_entry() {
    let project = InlineTestProject::new()
        .file("src/A.scala", "class A {\n  def m: Int = 1\n}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let mut config = fuzzer_config("scala");
    config.invariants = vec![InvariantKind::I2];
    let error = run_invariants(workspace.analyzer(), &config)
        .expect_err("I2 needs the service-phase entry point");
    assert!(error.contains("I2"), "{error}");
}

#[test]
fn i1_fires_when_class_declaration_is_truncated_at_parse_error() {
    // The other half of #1016: the parser truncates the class at its
    // annotated constructor and error recovery swallows the body, so no
    // members are indexed at all and containment has nothing to check.
    let text = "package x\n\n@Singleton\nclass JobCtrl @Inject()\n  def get: Int = 1\n".to_string();
    let class_range = range(&text, "@Singleton", Some("@Inject()"));
    let error_range = Range {
        start_byte: class_range.end_byte + 1,
        end_byte: text.len(),
        start_line: 5,
        end_line: 5,
    };
    let input = I1Input {
        files: vec![I1File {
            path: "src/JobCtrl.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![ParseError {
                range: error_range,
                kind: ParseErrorKind::Error,
            }]),
        }],
        symbols: vec![facts(
            "x.JobCtrl",
            "JobCtrl",
            CodeUnitType::Class,
            vec![class_range],
            vec![],
        )],
    };
    let violations = check(&input);
    assert_eq!(violations.len(), 1, "{violations:?}");
    let violation = &violations[0];
    assert_eq!(
        violation.signature,
        "(I1, scala, index, declaration-truncated-at-parse-error)"
    );
    assert_eq!(violation.symbol, "x.JobCtrl");
    assert_eq!(violation.evidence["gap_bytes"], 1);
}

#[test]
fn i1_silent_when_parse_error_is_unrelated_to_class() {
    let text = "package x\n\nclass A {\n  def m: Int = 1\n}\n".to_string();
    let class_range = range(&text, "class A", Some("}"));
    let error_at = |gap: usize, span: usize, kind: ParseErrorKind| ParseError {
        range: Range {
            start_byte: class_range.end_byte + gap,
            end_byte: class_range.end_byte + gap + span,
            start_line: 6,
            end_line: 6,
        },
        kind,
    };
    let mk_input = |error: ParseError, kind: CodeUnitType| I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text.clone()),
            parse_errors: Some(vec![error]),
        }],
        symbols: vec![facts("x.A", "A", kind, vec![class_range], vec![])],
    };
    // Too far from the declaration end to be its truncation point.
    assert!(
        check(&mk_input(
            error_at(10, 20, ParseErrorKind::Error),
            CodeUnitType::Class
        ))
        .is_empty()
    );
    // Too small to be a swallowed body.
    assert!(
        check(&mk_input(
            error_at(1, 4, ParseErrorKind::Error),
            CodeUnitType::Class
        ))
        .is_empty()
    );
    // MISSING-node placeholders are single-token insertions, not truncation.
    assert!(
        check(&mk_input(
            error_at(1, 30, ParseErrorKind::Missing("}".to_string())),
            CodeUnitType::Class
        ))
        .is_empty()
    );
    // Only classes make the swallowed-members claim; a function adjacent to
    // an error is out of scope for I1(d).
    assert!(
        check(&mk_input(
            error_at(1, 30, ParseErrorKind::Error),
            CodeUnitType::Function
        ))
        .is_empty()
    );
}

#[test]
fn i1_skips_auxiliary_constructor_name_token() {
    // Scala's `def this` indexes under the class name by convention; the
    // class identifier never appears in the constructor text. Collection
    // flags the convention from a pre-sampling class census (so the flag
    // never depends on the parent surviving sampling); the pure checker
    // simply honors the flag.
    let text = "class A {\n  def this() = this(1)\n}\n".to_string();
    let ctor_range = range(&text, "def this", Some("this(1)"));
    let mut ctor = facts("A.A", "A", CodeUnitType::Function, vec![ctor_range], vec![]);
    ctor.aux_constructor = true;
    let input = I1Input {
        files: vec![I1File {
            path: "A.scala".to_string(),
            text: Some(text),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![ctor],
    };
    assert!(check(&input).is_empty());
}

#[test]
fn i1_silent_on_scala_auxiliary_constructor_fixture() {
    let project = InlineTestProject::new()
        .file(
            "src/Greeter.scala",
            "package com.example\n\nclass Greeter(val name: String) {\n  def this() = this(\"anon\")\n\n  def greet(): String = \"hello \" + name\n}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report =
        run_invariants(workspace.analyzer(), &fuzzer_config("scala")).expect("run invariants");
    assert!(
        report.violations.is_empty(),
        "{}",
        serde_json::to_string_pretty(&report.violations).expect("violations json")
    );
}

/// Issue #1016's exact severe-grade fixture must parse as two complete classes.
#[test]
fn issue_1016_i1_accepts_annotated_constructor_jobctrl_scala_fixture() {
    let project = InlineTestProject::new()
        .file("src/JobCtrl.scala", ISSUE_1016_JOBCTRL)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report =
        run_invariants(workspace.analyzer(), &fuzzer_config("scala")).expect("run invariants");
    assert!(
        report.violations.is_empty(),
        "{}",
        serde_json::to_string_pretty(&report.violations).expect("violations json")
    );

    let analyzer = workspace.analyzer();
    let job_ctrl = analyzer
        .get_definitions("org.thp.thehive.connector.cortex.controllers.v0.JobCtrl")
        .into_iter()
        .find(|unit| unit.is_class())
        .expect("JobCtrl class");
    let create = analyzer
        .get_definitions("org.thp.thehive.connector.cortex.controllers.v0.JobCtrl.create")
        .into_iter()
        .next()
        .expect("JobCtrl.create");
    let public_job = analyzer
        .get_definitions("org.thp.thehive.connector.cortex.controllers.v0.PublicJob")
        .into_iter()
        .find(|unit| unit.is_class())
        .expect("PublicJob class");

    let source = analyzer
        .get_source(&job_ctrl, false)
        .expect("JobCtrl source");
    assert!(
        source.contains("override val entrypoint: Entrypoint"),
        "{source}"
    );
    assert!(
        source.contains("def create: Action[AnyContent]"),
        "{source}"
    );
    assert!(
        source.contains("jobSrv\n                  .submit"),
        "{source}"
    );
    assert!(!source.contains("class PublicJob"), "{source}");

    let class_range = analyzer.ranges(&job_ctrl)[0];
    let create_range = analyzer.ranges(&create)[0];
    let public_job_range = analyzer.ranges(&public_job)[0];
    assert!(
        class_range.start_byte <= create_range.start_byte
            && class_range.end_byte >= create_range.end_byte,
        "JobCtrl range {class_range:?} must contain create {create_range:?}"
    );
    assert!(
        class_range.end_byte <= public_job_range.start_byte,
        "JobCtrl range {class_range:?} must not consume PublicJob {public_job_range:?}"
    );
    assert_eq!(
        analyzer
            .parent_of(&create)
            .as_ref()
            .map(|unit| unit.fq_name()),
        Some("org.thp.thehive.connector.cortex.controllers.v0.JobCtrl".to_string())
    );
}

// ---------------------------------------------------------------------------
// `--rerun` config reconstruction (`src/mcp_property_fuzzer/rerun.rs`)
// ---------------------------------------------------------------------------

fn rerun_record(violations: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "record_type": "repository",
        "status": "completed",
        "report": {
            "config": {
                "corpus_language": "scala",
                "invariants": ["I1", "I2", "I3", "I4", "I5"],
                "max_symbols": 5000,
                "max_service_symbols": 200,
                "max_scan_probes": 40,
                "seed": 7
            },
            "violations": violations
        }
    })
}

fn rerun_violation(signature: &str, invariant: &str, symbol: &str) -> serde_json::Value {
    serde_json::json!({
        "signature": signature,
        "invariant": invariant,
        "tool": "get_symbol_sources",
        "shape": "test",
        "language": "scala",
        "symbol": symbol,
        "path": "src/Foo.scala",
        "evidence": {},
        "exemplars": [symbol],
        "occurrences": 1
    })
}

#[test]
fn rerun_configs_narrow_each_violation_to_its_exemplar_symbol() {
    let record = rerun_record(serde_json::json!([
        rerun_violation("(I2, scala, get_symbol_sources, sig-a)", "I2", "a.b.Foo"),
        rerun_violation("(I1, scala, index, sig-b)", "I1", "a.b.Bar")
    ]));
    let configs = rerun_configs(&record, None).expect("rerun configs");
    assert_eq!(configs.len(), 2, "{configs:?}");
    assert_eq!(configs[0].0, "(I2, scala, get_symbol_sources, sig-a)");
    assert_eq!(configs[0].1.symbol_filter.as_deref(), Some("a.b.Foo"));
    assert_eq!(configs[1].0, "(I1, scala, index, sig-b)");
    assert_eq!(configs[1].1.symbol_filter.as_deref(), Some("a.b.Bar"));
    // The recorded base config carries through unchanged apart from the filter.
    assert_eq!(configs[0].1.corpus_language, "scala");
    assert_eq!(configs[0].1.seed, 7);
    assert_eq!(configs[0].1.max_symbols, 5000);
}

#[test]
fn rerun_configs_keep_the_base_config_for_i5_and_symbol_less_violations() {
    let record = rerun_record(serde_json::json!([
        rerun_violation("(I5, scala, search_symbols, sig-c)", "I5", "a.b.Baz"),
        rerun_violation("(I1, scala, index, sig-d)", "I1", "")
    ]));
    let configs = rerun_configs(&record, None).expect("rerun configs");
    assert_eq!(configs.len(), 2, "{configs:?}");
    assert_eq!(
        configs[0].1.symbol_filter, None,
        "I5 derives from the sample"
    );
    assert_eq!(configs[1].1.symbol_filter, None, "no symbol to filter by");
}

#[test]
fn rerun_configs_filter_signatures_by_substring() {
    let record = rerun_record(serde_json::json!([
        rerun_violation(
            "(I2, scala, get_definitions_by_reference, batch-outcome-differs)",
            "I2",
            "a.b.Foo"
        ),
        rerun_violation("(I3, scala, get_symbol_sources, sig-b)", "I3", "a.b.Bar")
    ]));
    let configs = rerun_configs(&record, Some("batch-outcome")).expect("rerun configs");
    assert_eq!(configs.len(), 1, "{configs:?}");
    assert_eq!(configs[0].1.symbol_filter.as_deref(), Some("a.b.Foo"));

    let err = rerun_configs(&record, Some("no-such-signature")).expect_err("no match");
    assert!(err.contains("--signature"), "{err}");
}

#[test]
fn rerun_configs_reject_a_record_without_violations() {
    let record = rerun_record(serde_json::json!([]));
    let err = rerun_configs(&record, None).expect_err("empty violations");
    assert!(err.contains("no violations"), "{err}");
}

#[test]
fn rerun_configs_target_summaries_listed_signatures_by_file_not_symbol() {
    // The exemplar "symbol" of a summaries-listed violation is an element
    // name from the summaries response, which usually is not a sampled
    // workspace symbol; filtering by it empties the probe set. The file is
    // the reproduction scope.
    let record = rerun_record(serde_json::json!([
        rerun_violation(
            "(I3, scala, get_symbol_sources, summaries-listed-symbol-path-mismatch)",
            "I3",
            "org.apache.spark.util.Utils"
        ),
        rerun_violation(
            "(I3, scala, get_symbol_sources, summaries-listed-symbol-unresolvable)",
            "I3",
            "com.example.Phantom"
        )
    ]));
    let configs = rerun_configs(&record, None).expect("rerun configs");
    assert_eq!(configs.len(), 2, "{configs:?}");
    for (_, config) in &configs {
        assert_eq!(config.symbol_filter, None, "no symbol filter");
        assert_eq!(
            config.path_filter.as_deref(),
            Some("src/Foo.scala"),
            "file-scoped rerun"
        );
    }
}

// Python function-local classes carry the enclosing path in their display
// identifier (`test_deprecated_class$BadlyDeprecatedClass`); the name-token
// check must look for the terminal segment, which is what the declaration's
// own text carries (the Cirq ×130 shape).
#[test]
fn i1_silent_on_python_nested_class_fixture() {
    let project = InlineTestProject::new()
        .file(
            "src/test_compat.py",
            "class NewClass:\n    pass\n\n\ndef deprecated_class(*args, **kwargs):\n    def wrap(cls):\n        return cls\n    return wrap\n\n\ndef test_deprecated_class():\n    @deprecated_class(deadline='invalid')\n    class BadlyDeprecatedClass(NewClass):\n        pass\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report =
        run_invariants(workspace.analyzer(), &fuzzer_config("py")).expect("run invariants");
    assert!(
        report
            .violations
            .iter()
            .all(|violation| violation.shape != "range-name-token-absent"),
        "{:?}",
        report.violations
    );
}
