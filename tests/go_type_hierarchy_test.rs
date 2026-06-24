mod common;

use brokk_bifrost::{CodeUnit, GoAnalyzer, IAnalyzer, TypeHierarchyProvider};
use common::go_analyzer_with_files;
use std::collections::BTreeSet;

fn definition(analyzer: &GoAnalyzer, fqn: &str) -> CodeUnit {
    analyzer
        .definitions(fqn)
        .next()
        .unwrap_or_else(|| panic!("missing definition {fqn}"))
        .clone()
}

fn identifiers(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units
        .into_iter()
        .map(|unit| unit.identifier().to_string())
        .collect()
}

#[test]
fn concrete_type_satisfies_simple_interface() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run() error }
type Worker struct{}

func (Worker) Run() error { return nil }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert!(analyzer.type_hierarchy_provider().is_some());
    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&runner))
    );
}

#[test]
fn pointer_receiver_does_not_satisfy_value_type_hierarchy() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run() error }
type Worker struct{}

func (*Worker) Run() error { return nil }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(
        !identifiers(analyzer.get_direct_descendants(&runner)).contains("Worker"),
        "Worker must not satisfy Runner through ambiguous promoted methods"
    );
}

#[test]
fn embedded_interfaces_and_structs_contribute_methods() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Reader interface { Read() string }
type Runner interface {
    Reader
    Run() error
}

type Base struct{}
func (Base) Read() string { return "" }

type Worker struct { Base }
func (Worker) Run() error { return nil }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&runner))
    );
}

#[test]
fn direct_projection_omits_transitive_interface_ancestors() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Reader interface { Read() string }
type Runner interface {
    Reader
    Run() error
}

type Worker struct{}
func (Worker) Read() string { return "" }
func (Worker) Run() error { return nil }
"#,
    )]);

    let reader = definition(&analyzer, "example.com/app.Reader");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert!(
        !identifiers(analyzer.get_direct_descendants(&reader)).contains("Worker"),
        "Worker should be reached through Runner, not directly under Reader"
    );
}

#[test]
fn interface_to_interface_satisfaction_is_projected() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Reader interface { Read() string }
type ReadWriter interface {
    Reader
    Write(string) error
}
"#,
    )]);

    let reader = definition(&analyzer, "example.com/app.Reader");
    let read_writer = definition(&analyzer, "example.com/app.ReadWriter");

    assert_eq!(
        BTreeSet::from(["Reader".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&read_writer))
    );
    assert_eq!(
        BTreeSet::from(["ReadWriter".to_string()]),
        identifiers(analyzer.get_direct_descendants(&reader))
    );
}

#[test]
fn interface_alias_embedding_is_projected() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Reader interface { Read() string }
type R = Reader
type Runner interface {
    R
    Run() error
}
"#,
    )]);

    let reader = definition(&analyzer, "example.com/app.Reader");
    let runner = definition(&analyzer, "example.com/app.Runner");

    assert_eq!(
        BTreeSet::from(["Reader".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&runner))
    );
    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_descendants(&reader))
    );
}

#[test]
fn embedded_pointer_struct_promotes_pointer_receiver_methods() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Reader interface { Read() string }
type Base struct{}
func (*Base) Read() string { return "" }

type Worker struct { *Base }
"#,
    )]);

    let reader = definition(&analyzer, "example.com/app.Reader");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Reader".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&reader))
    );
}

#[test]
fn transitive_pointer_embedding_promotes_pointer_receiver_methods() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run() error }

type Leaf struct{}
func (*Leaf) Run() error { return nil }

type Mid struct { Leaf }
type Worker struct { *Mid }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&runner))
    );
}

#[test]
fn pointer_embedding_cycles_do_not_loop_during_promotion() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run() error }

type A struct { *B }
func (A) Run() error { return nil }

type B struct { *A }
type Worker struct { *B }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert!(
        identifiers(analyzer.get_direct_descendants(&runner)).contains("Worker"),
        "cyclic embedding should terminate and still expose reachable promoted methods"
    );
}

#[test]
fn conflicting_promoted_methods_do_not_satisfy_by_union() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run(int) error }

type A struct{}
func (A) Run(int) error { return nil }

type B struct{}
func (B) Run(string) error { return nil }

type Worker struct { A; B }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(
        !identifiers(analyzer.get_direct_descendants(&runner)).contains("Worker"),
        "Worker must not satisfy Runner through ambiguous promoted methods"
    );
}

#[test]
fn identical_same_depth_promoted_methods_are_ambiguous() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run() error }

type A struct{}
func (A) Run() error { return nil }

type B struct{}
func (B) Run() error { return nil }

type Worker struct { A; B }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(
        !identifiers(analyzer.get_direct_descendants(&runner)).contains("Worker"),
        "Worker must not satisfy Runner through ambiguous same-depth promoted methods"
    );
}

#[test]
fn shallower_promoted_methods_hide_deeper_conflicts() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run(int) error }

type A struct{}
func (A) Run(int) error { return nil }

type C struct{}
func (C) Run(string) error { return nil }

type B struct { C }
type Worker struct { A; B }
"#,
    )]);

    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
}

#[test]
fn alias_types_normalize_inside_method_signatures() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Payload struct{}
type Alias = Payload

type Handler interface { Handle(Alias) Payload }
type Worker struct{}

func (Worker) Handle(Payload) Alias { return Payload{} }
"#,
    )]);

    let handler = definition(&analyzer, "example.com/app.Handler");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Handler".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&handler))
    );
}

#[test]
fn imported_types_are_resolved_inside_method_signatures() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "pkg/payload.go",
            r#"
package pkg

type Payload struct{}
"#,
        ),
        (
            "service.go",
            r#"
package app

import aliased "example.com/app/pkg"

type Handler interface { Handle(aliased.Payload) aliased.Payload }
type Worker struct{}

func (Worker) Handle(aliased.Payload) aliased.Payload { return aliased.Payload{} }
"#,
        ),
    ]);

    let handler = definition(&analyzer, "example.com/app.Handler");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Handler".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&handler))
    );
}

#[test]
fn unaliased_import_uses_declared_package_name_for_method_signatures() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "internal/model/payload.go",
            r#"
package domain

type Payload struct{}
"#,
        ),
        (
            "service.go",
            r#"
package app

import "example.com/app/internal/model"

type Handler interface { Handle(domain.Payload) domain.Payload }
type Worker struct{}

func (Worker) Handle(domain.Payload) domain.Payload { return domain.Payload{} }
"#,
        ),
    ]);

    let handler = definition(&analyzer, "example.com/app.Handler");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Handler".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&handler))
    );
}

#[test]
fn external_import_aliases_canonicalize_by_import_path() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

import iface "external.example/lib"
import impl "external.example/lib"

type Handler interface { Handle(iface.Payload) error }
type Worker struct{}

func (Worker) Handle(impl.Payload) error { return nil }
"#,
    )]);

    let handler = definition(&analyzer, "example.com/app.Handler");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Handler".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&handler))
    );
}

#[test]
fn external_import_paths_are_not_collapsed_by_local_alias() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "api/runner.go",
            r#"
package api

import dep "external.example/one"

type Handler interface { Handle(dep.Payload) error }
"#,
        ),
        (
            "worker/worker.go",
            r#"
package worker

import dep "external.example/two"

type Worker struct{}
func (Worker) Handle(dep.Payload) error { return nil }
"#,
        ),
    ]);

    let handler = definition(&analyzer, "example.com/app/api.Handler");
    let worker = definition(&analyzer, "example.com/app/worker.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&handler).is_empty());
}

#[test]
fn unresolved_local_type_tokens_are_package_scoped() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "api/runner.go",
            r#"
package api

type Handler interface { Handle(Payload) error }
"#,
        ),
        (
            "worker/worker.go",
            r#"
package worker

type Worker struct{}
func (Worker) Handle(Payload) error { return nil }
"#,
        ),
    ]);

    let handler = definition(&analyzer, "example.com/app/api.Handler");
    let worker = definition(&analyzer, "example.com/app/worker.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&handler).is_empty());
}

#[test]
fn grouped_parameters_and_results_preserve_arity() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Pair interface {
    Convert(a, b int) (left, right string)
}

type Worker struct{}
func (Worker) Convert(a int, b int) (string, string) { return "", "" }

type Short struct{}
func (Short) Convert(a int) (string, string) { return "", "" }
"#,
    )]);

    let pair = definition(&analyzer, "example.com/app.Pair");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let short = definition(&analyzer, "example.com/app.Short");

    assert_eq!(
        BTreeSet::from(["Pair".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert!(analyzer.get_direct_ancestors(&short).is_empty());
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&pair))
    );
}

#[test]
fn variadic_parameters_are_part_of_method_signatures() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Variadic interface { Run(values ...int) error }

type Worker struct{}
func (Worker) Run(values ...int) error { return nil }

type SliceWorker struct{}
func (SliceWorker) Run(values []int) error { return nil }
"#,
    )]);

    let variadic = definition(&analyzer, "example.com/app.Variadic");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let slice_worker = definition(&analyzer, "example.com/app.SliceWorker");

    assert_eq!(
        BTreeSet::from(["Variadic".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert!(analyzer.get_direct_ancestors(&slice_worker).is_empty());
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&variadic))
    );
}

#[test]
fn channel_direction_is_part_of_method_signatures() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Receiver interface { Stream(<-chan int) error }
type Sender interface { Stream(chan<- int) error }
type Bidirectional interface { Stream(chan int) error }

type ReceiveWorker struct{}
func (ReceiveWorker) Stream(values <-chan int) error { return nil }

type SendWorker struct{}
func (SendWorker) Stream(values chan<- int) error { return nil }

type BiWorker struct{}
func (BiWorker) Stream(values chan int) error { return nil }
"#,
    )]);

    let receiver = definition(&analyzer, "example.com/app.Receiver");
    let sender = definition(&analyzer, "example.com/app.Sender");
    let bidirectional = definition(&analyzer, "example.com/app.Bidirectional");
    let receive_worker = definition(&analyzer, "example.com/app.ReceiveWorker");
    let send_worker = definition(&analyzer, "example.com/app.SendWorker");
    let bi_worker = definition(&analyzer, "example.com/app.BiWorker");

    assert_eq!(
        BTreeSet::from(["Receiver".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&receive_worker))
    );
    assert_eq!(
        BTreeSet::from(["Sender".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&send_worker))
    );
    assert_eq!(
        BTreeSet::from(["Bidirectional".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&bi_worker))
    );
    assert_eq!(
        BTreeSet::from(["ReceiveWorker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&receiver))
    );
    assert_eq!(
        BTreeSet::from(["SendWorker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&sender))
    );
    assert_eq!(
        BTreeSet::from(["BiWorker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&bidirectional))
    );
}

#[test]
fn array_parameters_preserve_length_and_element_type() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Handler interface { Handle([2]int) error }

type Worker struct{}
func (Worker) Handle([2]int) error { return nil }

type WrongElement struct{}
func (WrongElement) Handle([2]string) error { return nil }
"#,
    )]);

    let handler = definition(&analyzer, "example.com/app.Handler");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let wrong_element = definition(&analyzer, "example.com/app.WrongElement");

    assert_eq!(
        BTreeSet::from(["Handler".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert!(analyzer.get_direct_ancestors(&wrong_element).is_empty());
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&handler))
    );
}

#[test]
fn same_method_name_with_incompatible_signature_does_not_satisfy() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface { Run(int) error }
type Worker struct{}

func (Worker) Run(string) error { return nil }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&runner).is_empty());
}

#[test]
fn constraint_interfaces_are_supported_but_not_projected_as_method_only_hierarchy() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Stringish interface {
    ~string
    String() string
}

type Worker struct{}
func (Worker) String() string { return "" }
"#,
    )]);

    let stringish = definition(&analyzer, "example.com/app.Stringish");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let provider = analyzer.type_hierarchy_provider().unwrap();

    assert!(provider.supports_type_hierarchy(&stringish));
    assert!(provider.supports_type_hierarchy(&worker));
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&stringish).is_empty());
}

#[test]
fn embedded_any_is_neutral_for_non_empty_interfaces() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Runner interface {
    any
    Run() error
}

type Worker struct{}
func (Worker) Run() error { return nil }
"#,
    )]);

    let runner = definition(&analyzer, "example.com/app.Runner");
    let worker = definition(&analyzer, "example.com/app.Worker");

    assert_eq!(
        BTreeSet::from(["Runner".to_string()]),
        identifiers(analyzer.get_direct_ancestors(&worker))
    );
    assert_eq!(
        BTreeSet::from(["Worker".to_string()]),
        identifiers(analyzer.get_direct_descendants(&runner))
    );
}

#[test]
fn embedded_constraint_interfaces_are_not_projected_as_method_only_hierarchy() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Stringish interface {
    ~string
    String() string
}

type NamedStringish interface {
    Stringish
}

type Worker struct{}
func (Worker) String() string { return "" }
"#,
    )]);

    let named_stringish = definition(&analyzer, "example.com/app.NamedStringish");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let provider = analyzer.type_hierarchy_provider().unwrap();

    assert!(provider.supports_type_hierarchy(&named_stringish));
    assert!(provider.supports_type_hierarchy(&worker));
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&named_stringish).is_empty());
}

#[test]
fn unexported_methods_from_different_packages_do_not_satisfy() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "api/runner.go",
            r#"
package api

type Runner interface { run() error }
"#,
        ),
        (
            "worker/worker.go",
            r#"
package worker

type Worker struct{}
func (Worker) run() error { return nil }
"#,
        ),
    ]);

    let runner = definition(&analyzer, "example.com/app/api.Runner");
    let worker = definition(&analyzer, "example.com/app/worker.Worker");

    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&runner).is_empty());
}

#[test]
fn empty_interface_is_supported_but_not_expanded_to_every_type() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "service.go",
        r#"
package app

type Anything interface{}
type Worker struct{}
"#,
    )]);

    let anything = definition(&analyzer, "example.com/app.Anything");
    let worker = definition(&analyzer, "example.com/app.Worker");
    let provider = analyzer.type_hierarchy_provider().unwrap();

    assert!(provider.supports_type_hierarchy(&anything));
    assert!(provider.supports_type_hierarchy(&worker));
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
    assert!(analyzer.get_direct_descendants(&anything).is_empty());
}
