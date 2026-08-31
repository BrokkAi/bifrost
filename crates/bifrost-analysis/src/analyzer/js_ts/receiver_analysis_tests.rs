//! JS/TS receiver-facts coverage, kept beside the analyzers it exercises.
//!
//! The provider itself is [`brokk_bifrost_js_ts::graph::receiver_analysis`].
//! These tests build a concrete `TypescriptAnalyzer` and a request-local
//! definition lookup, so they stay on this side of the crate line.

#[cfg(test)]
mod tests {
    use crate::analyzer::{
        AnalyzerDefinitionLookup, Language, ProjectFile, TestProject, TypescriptAnalyzer,
    };
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::DEFAULT_RECEIVER_MAX_TARGETS;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
        ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverValue,
    };
    use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
    use brokk_bifrost_js_ts::graph::receiver_analysis::*;
    use brokk_bifrost_js_ts::syntax::{JsTsImportBinder, compute_import_binder};
    use std::path::PathBuf;
    use tree_sitter::Node;
    use tree_sitter::Parser;

    fn test_project(source: &str) -> (tempfile::TempDir, ProjectFile, TypescriptAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("src/app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        (temp, file, analyzer)
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("typescript parser");
        parser.parse(source, None).expect("parse source")
    }

    fn receiver_node<'tree>(
        root: Node<'tree>,
        source: &str,
        marker: &str,
        receiver: &str,
    ) -> Node<'tree> {
        let marker_start = source.find(marker).expect("marker");
        let receiver_start = source[marker_start..]
            .find(receiver)
            .map(|offset| marker_start + offset)
            .expect("receiver");
        smallest_named_node_covering(root, receiver_start, receiver_start + receiver.len())
            .expect("receiver node")
    }

    #[test]
    fn tiny_scope_budget_exits_without_precise_targets() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            JsTsImportBinder::empty(),
        );
        let receiver = receiver_node(tree.root_node(), source, "service.run", "service");

        let report = provider.resolve_member_targets_report(
            receiver,
            "run",
            receiver.start_byte(),
            ReceiverAnalysisBudget::tiny(),
        );

        assert_eq!(
            report.outcome,
            ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            }
        );
        assert!(report.outcome.is_terminal_for_graph());
        assert_eq!(report.work.scope_nodes, 2);
        assert!(!report.candidates_truncated);
    }

    #[test]
    fn scope_node_budget_is_per_receiver_query() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function first() {
  const a0 = 0; const a1 = 1; const a2 = 2; const a3 = 3; const a4 = 4;
  const a5 = 5; const a6 = 6; const a7 = 7; const a8 = 8; const a9 = 9;
  const service = makeService();
  // first call
  service.run();
}
export function second() {
  const b0 = 0; const b1 = 1; const b2 = 2; const b3 = 3; const b4 = 4;
  const b5 = 5; const b6 = 6; const b7 = 7; const b8 = 8; const b9 = 9;
  const service = makeService();
  // second call
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            JsTsImportBinder::empty(),
        );
        let first = receiver_node(tree.root_node(), source, "first call", "service");
        let second = receiver_node(tree.root_node(), source, "second call", "service");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 80,
            ..ReceiverAnalysisBudget::default()
        };

        for receiver in [first, second] {
            let outcome =
                provider.resolve_member_targets(receiver, "run", receiver.start_byte(), budget);
            assert!(
                matches!(outcome, ReceiverAnalysisOutcome::Precise(ref targets) if targets.len() == 1),
                "expected each lookup to stay within its own budget, got {outcome:?}"
            );
        }
    }

    #[test]
    fn fanout_over_default_target_cap_is_ambiguous() {
        let source = r#"
class A { run() {} }
class B { run() {} }
class C { run() {} }
class D { run() {} }
class E { run() {} }
function make(which: number) {
  if (which === 0) return new A();
  if (which === 1) return new B();
  if (which === 2) return new C();
  if (which === 3) return new D();
  return new E();
}
export function caller(which: number) {
  const service = make(which);
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            JsTsImportBinder::empty(),
        );
        let receiver = receiver_node(tree.root_node(), source, "service.run", "service");

        let report = provider.resolve_member_targets_report(
            receiver,
            "run",
            receiver.start_byte(),
            ReceiverAnalysisBudget::default(),
        );

        assert!(
            matches!(report.outcome, ReceiverAnalysisOutcome::Ambiguous(ref targets) if targets.len() == DEFAULT_RECEIVER_MAX_TARGETS),
            "expected fanout to become ambiguous, got {:?}",
            report.outcome
        );
        assert!(report.outcome.is_terminal_for_graph());
        assert!(report.candidates_truncated);
        assert!(report.work.summary_expansions > 0);
    }

    #[test]
    fn receiver_history_does_not_false_prove_after_an_unknown_write() {
        let cases = [
            (
                "annotated",
                r#"
class Store { put() {} }
class Cache { put() {} static make() { return new Cache(); } }
function run(store: Store) {
  store = Cache.make();
  store.put();
}
"#,
                Some("Cache.put"),
            ),
            (
                "dynamic-first",
                r#"
class Store { put() {} static make() { return new Store(); } }
declare function dynamicValue(): unknown;
function run() {
  let store = dynamicValue();
  store = Store.make();
  store.put();
}
"#,
                None,
            ),
        ];

        for (label, source, exact_target) in cases {
            let (_temp, file, analyzer) = test_project(source);
            let tree = parse(source);
            let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
            let provider = JsTsReceiverFactProvider::new(
                &analyzer,
                &definitions,
                Language::TypeScript,
                &file,
                source,
                tree.root_node(),
                JsTsImportBinder::empty(),
            );
            let receiver = receiver_node(tree.root_node(), source, "store.put", "store");
            let report = provider.resolve_member_targets_report(
                receiver,
                "put",
                receiver.start_byte(),
                ReceiverAnalysisBudget::default(),
            );

            match exact_target {
                Some(expected) => assert!(
                    matches!(&report.outcome, ReceiverAnalysisOutcome::Precise(targets)
                        if matches!(targets.as_slice(), [target] if target.fq_name() == expected)),
                    "{label}: the straight-line assignment proves Cache, never annotated Store: {report:#?}"
                ),
                None => assert!(
                    !matches!(report.outcome, ReceiverAnalysisOutcome::Precise(_)),
                    "{label}: an unknown earlier write remains explicit: {report:#?}"
                ),
            }
        }
    }

    #[test]
    fn nested_same_name_factory_does_not_reuse_the_enclosing_declaration() {
        let source = r#"
class Outer {}
class Inner {}
function make() {
  function make() { return new Inner(); }
  return make();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            JsTsImportBinder::empty(),
        );
        let inner_start = source.rfind("function make").expect("inner factory");
        let inner = smallest_named_node_covering(
            tree.root_node(),
            inner_start,
            inner_start + "function make".len(),
        )
        .expect("inner function node");
        assert_eq!(provider.function_unit_for_node("make", inner), None);
    }

    #[test]
    fn unique_package_imports_are_complete_module_receiver_identities() {
        let source = r#"
import path from "node:path";
import * as os from "node:os";
import { Buffer } from "node:buffer";
const crypto = require("node:crypto");

path.basename("a");
os.platform();
Buffer.from("a");
crypto.randomUUID();
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            compute_import_binder(source, &tree),
        );

        for (marker, receiver, expected) in [
            ("path.basename", "path", "node:path"),
            ("os.platform", "os", "node:os"),
            ("Buffer.from", "Buffer", "Buffer"),
            ("crypto.randomUUID", "crypto", "node:crypto"),
        ] {
            let receiver = receiver_node(tree.root_node(), source, marker, receiver);
            let report =
                provider.resolve_receiver_node_report(receiver, ReceiverAnalysisBudget::default());
            assert!(
                matches!(
                    report.outcome,
                    ReceiverAnalysisOutcome::Precise(ref values)
                        if matches!(
                            values.as_slice(),
                            [ReceiverValue::ModuleOrExportObject(unit)]
                                if unit.fq_name() == expected
                        )
                ),
                "{marker} must resolve to exact imported module identity {expected}: {:?}",
                report.outcome
            );
            assert_eq!(report.work.summary_expansions, 0, "{marker}");
        }
    }

    #[test]
    fn competing_and_reassigned_import_receivers_stay_incomplete() {
        let source = r#"
import api from "pkg-a";
import api from "pkg-b";
import path from "node:path";

api.exec("a");
path = makePath();
path.basename("a");
"#;
        let (_temp, file, analyzer) = test_project(source);
        let tree = parse(source);
        let definitions = AnalyzerDefinitionLookup::new(&analyzer, Language::TypeScript);
        let provider = JsTsReceiverFactProvider::new(
            &analyzer,
            &definitions,
            Language::TypeScript,
            &file,
            source,
            tree.root_node(),
            compute_import_binder(source, &tree),
        );

        let api = receiver_node(tree.root_node(), source, "api.exec", "api");
        assert!(matches!(
            provider
                .resolve_receiver_node_report(api, ReceiverAnalysisBudget::default())
                .outcome,
            ReceiverAnalysisOutcome::Ambiguous(ref values) if values.is_empty()
        ));

        let path = receiver_node(tree.root_node(), source, "path.basename", "path");
        assert!(matches!(
            provider
                .resolve_receiver_node_report(path, ReceiverAnalysisBudget::default())
                .outcome,
            ReceiverAnalysisOutcome::Unknown
        ));
    }
}
