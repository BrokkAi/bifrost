#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::CodeUnitIndex;
    use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;
    use std::collections::BTreeSet;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_go_analysis::analyzer::go::GoAnalyzer;

    use brokk_bifrost_go_analysis::analyzer::go::native_graph::GoNativeWorkspaceGraphProvider;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_go_analysis::analyzer::go::native_graph::build_go_native_workspace_graph_for_files;

    use crate::inline_project::InlineTestProject;
    use crate::searchtools::{UsageGraphParams, UsageGraphResult, usage_graph};

    fn native_edge_names(
        graph: &brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjection,
    ) -> BTreeSet<(String, String)> {
        graph
            .edges
            .iter()
            .map(|edge| {
                (
                    graph.nodes[edge.from].primary.fq_name().to_string(),
                    graph.nodes[edge.to].primary.fq_name().to_string(),
                )
            })
            .collect()
    }

    fn incumbent_edge_names(graph: &UsageGraphResult) -> BTreeSet<(String, String)> {
        graph
            .edges
            .iter()
            .map(|edge| (edge.from.clone(), edge.to.clone()))
            .collect()
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6524: argument typing cycle blocked an argument-independent interface method binding"
    )]
    fn native_go_graph_keeps_interface_method_edge_with_cyclic_argument_types() {
        let source = r#"package diag
import "net/http"
import "context"
type J interface { Do(req *http.Request) (*http.Response, error) }
func newRequest(ctx context.Context) (*http.Request, error) { return nil, nil }
func caller(client J, ctx context.Context) {
    req, err := newRequest(ctx)
    req = req.WithContext(ctx)
    resp, err := client.Do(req)
    _, _ = resp, err
}
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/diag\n\ngo 1.22\n")
            .file("main.go", source)
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &[fixture.file("main.go")], &CancellationToken::new())
            .unwrap();
        let graph = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let edges = native_edge_names(&graph);
        assert!(
            edges
                .iter()
                .any(|(from, to)| from.ends_with("caller") && to.ends_with("J.Do")),
            "argument cycle must not discard the interface method edge: {edges:?}"
        );
    }

    #[test]
    fn native_go_graph_projects_whole_and_rooted_references() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/graph\n\ngo 1.22\n")
            .file(
                "pkg/model.go",
                "package pkg\ntype Item struct{}\nfunc Target() {}\n",
            )
            .file(
                "pkg/caller.go",
                "package pkg\nfunc Caller() { Target(); _ = Item{}; _ = len([]int{}) }\n",
            )
            .file("other/other.go", "package other\nfunc Other() {}\n")
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let files = [
            fixture.file("pkg/model.go"),
            fixture.file("pkg/caller.go"),
            fixture.file("other/other.go"),
        ];
        let whole = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let (graph, incomplete) = match whole {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => (graph, false),
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => (graph, true),
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let incumbent_whole = usage_graph(
            &go,
            UsageGraphParams {
                include_same_owner: false,
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        assert_eq!(
            native_edge_names(&graph),
            incumbent_edge_names(&incumbent_whole),
            "whole-workspace native Go edges must match the incumbent",
        );
        assert!(
            !incomplete || graph.build_selection_unavailable.is_some(),
            "only an unavailable Go build selection may make this graph incomplete; the builtin contributes no unresolved TypeOrCallable edge: forward {:?}, unresolved {:?}, kind projection {}, references {}, build selection {:?}",
            graph.forward_completeness,
            graph.unresolved_names,
            graph.kind_projection_complete,
            graph.reference_count,
            graph.build_selection_unavailable,
        );
        assert!(graph.resolved_ecosystems.contains(&UsageEcosystem::Go));
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes[edge.from].primary.fq_name().ends_with("Caller")
                && graph.nodes[edge.to].primary.fq_name().ends_with("Target")
        }));
        assert!(graph.edges.iter().any(|edge| {
            graph.nodes[edge.from].primary.fq_name().ends_with("Caller")
                && graph.nodes[edge.to].primary.fq_name().ends_with("Item")
        }));
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.primary.fq_name().ends_with("Other"))
        );

        let rooted = build_go_native_workspace_graph_for_files(
            &go,
            &[fixture.file("pkg/caller.go")],
            &CancellationToken::new(),
        )
        .unwrap();
        let rooted = match rooted {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("rooted Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("rooted Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("rooted Go graph projection unavailable: {reason}")
            }
        };
        let incumbent_rooted = usage_graph(
            &go,
            UsageGraphParams {
                include_same_owner: false,
                include_tests: true,
                paths: Some(vec!["pkg/caller.go".to_owned()]),
                depth: 1,
            },
        );
        assert_eq!(
            native_edge_names(&rooted),
            incumbent_edge_names(&incumbent_rooted),
            "rooted native Go edges must match the incumbent",
        );
        assert!(
            rooted
                .nodes
                .iter()
                .all(|node| !node.primary.fq_name().ends_with("Other"))
        );
    }

    #[test]
    fn native_go_graph_keeps_import_binders_with_their_source_file() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/graph\n\ngo 1.22\n")
            .file(
                "dep/dep.go",
                r#"package foreign
func Explicit() {}
func Aliased() {}
func DotImported() {}
"#,
            )
            .file(
                "pkg/default_import.go",
                r#"package pkg
import "example.test/graph/dep"
func DefaultImportCaller() { foreign.Explicit() }
"#,
            )
            .file(
                "pkg/alias_import.go",
                r#"package pkg
import chosen "example.test/graph/dep"
func AliasImportCaller() { chosen.Aliased() }
"#,
            )
            .file(
                "pkg/dot_import.go",
                r#"package pkg
import . "example.test/graph/dep"
func DotImportCaller() { DotImported() }
"#,
            )
            .file(
                "pkg/no_import.go",
                r#"package pkg
func NoImportCaller() { foreign.Explicit(); chosen.Aliased(); DotImported() }
"#,
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let files = [
            fixture.file("dep/dep.go"),
            fixture.file("pkg/default_import.go"),
            fixture.file("pkg/alias_import.go"),
            fixture.file("pkg/dot_import.go"),
            fixture.file("pkg/no_import.go"),
        ];
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let graph = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let edges = native_edge_names(&graph);
        for (caller, target) in [
            ("DefaultImportCaller", "Explicit"),
            ("AliasImportCaller", "Aliased"),
            ("DotImportCaller", "DotImported"),
        ] {
            assert!(
                edges
                    .iter()
                    .any(|(from, to)| from.ends_with(caller) && to.ends_with(target)),
                "the file-local {caller} import must resolve to {target}; edges were {edges:?}"
            );
        }
        assert!(
            edges.iter().all(|(from, to)| {
                !from.ends_with("NoImportCaller")
                    || !["Explicit", "Aliased", "DotImported"]
                        .iter()
                        .any(|target| to.ends_with(target))
            }),
            "another same-package file's import binder must not resolve from NoImportCaller: {edges:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "ee74b4a4c9d6: qualified Go callees were emitted only in the callable namespace, so pkg.T(x) conversions never bound"
    )]
    fn native_go_graph_resolves_qualified_type_conversions_and_function_calls() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/graph\n\ngo 1.22\n")
            .file(
                "dep/dep.go",
                "package dep\ntype T int\nfunc F(int) {}\ntype Receiver struct{}\nfunc (Receiver) M() {}\n",
            )
            .file(
                "caller/caller.go",
                "package caller\nimport \"example.test/graph/dep\"\ntype Widget struct{}\nfunc (Widget) Method() {}\nfunc Caller(x int, w Widget) { _ = dep.T(x); dep.F(x); var receiver dep.Receiver; receiver.M(); Widget.Method(w); _ = Widget{}; _ = Widget(w) }\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        super::super::persist_live_go_sources_for_test(&go);
        let files = [fixture.file("dep/dep.go"), fixture.file("caller/caller.go")];
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let graph = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("Go graph projection unavailable: {reason}")
            }
        };
        let edges = native_edge_names(&graph);
        for target in ["T", "F", "Receiver.M", "Widget", "Widget.Method"] {
            assert!(
                edges
                    .iter()
                    .any(|(from, to)| from.ends_with("Caller") && to.ends_with(target)),
                "qualified call or conversion to {target} must resolve; edges were {edges:?}"
            );
        }
    }

    #[test]
    #[ignore = "manual whole-corpus graph-stage profile"]
    fn native_go_graph_ttlcache_profile() {
        use std::path::PathBuf;
        use std::time::Instant;

        let root = PathBuf::from(
            std::env::var_os("BIFROST_GO_GRAPH_CORPUS")
                .expect("set BIFROST_GO_GRAPH_CORPUS to the ttlcache repository root"),
        );
        let project = brokk_bifrost_core::analyzer::project::FilesystemProject::new(root)
            .expect("open ttlcache as a persistent filesystem project");
        let go = GoAnalyzer::new(std::sync::Arc::new(project));
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        if std::env::var_os("BIFROST_GO_GRAPH_SETUP_ONLY").is_some() {
            return;
        }
        let output_path = PathBuf::from(
            std::env::var_os("BIFROST_GO_GRAPH_OUTPUT")
                .expect("set BIFROST_GO_GRAPH_OUTPUT to a temporary JSONL output path"),
        );
        let files = go.get_analyzed_files().into_iter().collect::<Vec<_>>();
        let started = Instant::now();
        let projected = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
        let (graph, complete) = match projected {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph) => (graph, true),
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => (graph, false),
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("ttlcache Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("ttlcache Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("ttlcache Go graph projection unavailable: {reason}")
            }
        };
        let mut edge_rows = graph
            .edges
            .iter()
            .map(|edge| {
                let from = &graph.nodes[edge.from];
                let to = &graph.nodes[edge.to];
                let mut sites = edge
                    .sites
                    .iter()
                    .map(|(file, line)| {
                        let path = file.rel_path().to_string_lossy().replace('\\', "/");
                        (path, *line)
                    })
                    .collect::<Vec<_>>();
                sites.sort();
                let row = serde_json::json!({
                    "from": from.key.fqn,
                    "from_id": from.key.id.to_string(),
                    "language": "go",
                    "sites": sites.iter().map(|(path, line)| serde_json::json!({
                        "line": line,
                        "path": path,
                    })).collect::<Vec<_>>(),
                    "to": to.key.fqn,
                    "to_id": to.key.id.to_string(),
                    "weight": sites.len(),
                });
                (
                    from.key.fqn.clone(),
                    to.key.fqn.clone(),
                    from.key.id.to_string(),
                    to.key.id.to_string(),
                    row,
                )
            })
            .collect::<Vec<_>>();
        edge_rows.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
        });
        let rows = edge_rows
            .into_iter()
            .map(|(_, _, _, _, row)| row)
            .collect::<Vec<_>>();
        let encoded = rows
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&output_path, format!("{encoded}\n"))
            .expect("write ttlcache Go graph edge set");
        if let Some(expected_path) = std::env::var_os("BIFROST_GO_GRAPH_EXPECTED_EDGE_SET") {
            let expected = std::fs::read_to_string(expected_path)
                .expect("read accepted ttlcache Go graph edge set")
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(rows, expected, "ttlcache graph edges match accepted set");
        }
        println!(
            "ttlcache native graph files={} nodes={} edges={} sites={} complete={} references={} batches={} wall_ms={wall_ms:.3}",
            files.len(),
            graph.nodes.len(),
            graph.edges.len(),
            graph
                .edges
                .iter()
                .map(|edge| edge.sites.len())
                .sum::<usize>(),
            complete,
            graph.reference_count,
            graph.batch_count,
        );
    }

    #[test]
    fn native_go_graph_keeps_nested_field_type_uses_and_excludes_receiver_types() {
        let source = r#"package cache

type Item[K comparable, V any] struct{}
type EvictionReason int

type Cache[K comparable, V any] struct {
    events struct {
        insertion struct {
            fns map[uint64]func(*Item[K, V])
        }
        eviction struct {
            fns map[uint64]func(EvictionReason, *Item[K, V])
        }
    }
}

func (item *Item[K, V]) Touch() {}

func Make() Cache[int, string] { return Cache[int, string]{} }
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/cache\n\ngo 1.22\n")
            .file("cache.go", source)
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let graph = GoNativeWorkspaceGraphProvider
            .project(&go, &[fixture.file("cache.go")], &CancellationToken::new())
            .unwrap();
        let graph = match graph {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("nested-field Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("nested-field Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("nested-field Go graph projection unavailable: {reason}")
            }
        };
        let names = native_edge_names(&graph);
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("Cache") && to.ends_with("Item") }),
            "generic type uses inside nested anonymous fields belong to Cache: {names:#?}"
        );
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("Cache") && to.ends_with("EvictionReason") }),
            "callback parameter type uses inside nested anonymous fields belong to Cache: {names:#?}"
        );
        assert!(
            !names
                .iter()
                .any(|(from, to)| { from.ends_with("Item.Touch") && to.ends_with("Item") }),
            "a method receiver type is a self-receiver hit, not an external graph edge: {names:#?}"
        );
    }

    #[test]
    fn native_go_graph_keeps_generic_callable_result_type_use() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/cache\n\ngo 1.22\n")
            .file(
                "item.go",
                "package cache\ntype Item[K comparable, V any] struct{}\n",
            )
            .file(
                "queue.go",
                "package cache\ntype Queue[K comparable, V any] []*Item[K, V]\n\
                 func newQueue[K comparable, V any]() Queue[K, V] {\n\
                 \t_ = make(Queue[K, V], 0)\n\
                 \tfor {}\n}\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let graph = GoNativeWorkspaceGraphProvider
            .project(
                &go,
                &[fixture.file("item.go"), fixture.file("queue.go")],
                &CancellationToken::new(),
            )
            .unwrap();
        let graph = match graph {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("generic result Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("generic result Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("generic result Go graph projection unavailable: {reason}")
            }
        };
        let names = native_edge_names(&graph);
        assert!(
            names
                .iter()
                .any(|(from, to)| { from.ends_with("newQueue") && to.ends_with("Queue") }),
            "the generic result type remains a reference of its callable: {names:#?}"
        );
        let queue_edge = graph
            .edges
            .iter()
            .find(|edge| {
                graph.nodes[edge.from]
                    .primary
                    .fq_name()
                    .ends_with("newQueue")
                    && graph.nodes[edge.to].primary.fq_name().ends_with("Queue")
            })
            .expect("generic result and make type use share their owner edge");
        assert_eq!(
            queue_edge.counts.types, 2,
            "the signature result and make type operand are both type-use sites"
        );
    }

    #[test]
    fn native_generic_receiver_and_promoted_method_edges_match_the_incumbent() {
        let source = r#"package auth

type Authenticator[T any] interface {
    Authenticate(value *T) error
}

type Handler[T any] struct {
    Authenticator[T]
}

func Use[T any](handler *Handler[T], value *T) error {
    return handler.Authenticate(value)
}

type Override[T any] struct {
    Authenticator[T]
}

func (*Override[T]) Authenticate(value *T) error { return nil }

func UseOverride[T any](handler *Override[T], value *T) error {
    return handler.Authenticate(value)
}

type Stack[T any] struct{}
func (stack Stack[T]) Push(value T) {}
func (stack *Stack[T]) Pop() {}
func Build() Stack[int] { return Stack[int]{} }
"#;
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/generic\n\ngo 1.22\n")
            .file("auth/auth.go", source)
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);
        let files = [fixture.file("auth/auth.go")];
        let native = GoNativeWorkspaceGraphProvider
            .project(&go, &files, &CancellationToken::new())
            .unwrap();
        let native = match native {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(graph)
            | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(graph) => graph,
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("generic Go graph projection was cancelled")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                panic!("generic Go graph projection became stale")
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                panic!("generic Go graph projection unavailable: {reason}")
            }
        };
        let incumbent = usage_graph(
            &go,
            UsageGraphParams {
                include_same_owner: false,
                include_tests: true,
                paths: None,
                depth: 1,
            },
        );
        let is_external_source = |(from, _): &(String, String)| {
            matches!(
                from.rsplit('.').next(),
                Some("Use" | "UseOverride" | "Build")
            )
        };
        let native_edges = native_edge_names(&native);
        let native_external_edges = native_edges
            .iter()
            .filter(|edge| is_external_source(edge))
            .cloned()
            .collect::<BTreeSet<_>>();
        let incumbent_external_edges = incumbent_edge_names(&incumbent)
            .into_iter()
            .filter(|(from, _)| {
                matches!(
                    from.rsplit('.').next(),
                    Some("Use" | "UseOverride" | "Build")
                )
            })
            .collect::<BTreeSet<_>>();
        eprintln!(
            "native generic graph completeness={:?} unresolved={:?} references={} edges={:?}",
            native.forward_completeness,
            native.unresolved_names,
            native.reference_count,
            native_edge_names(&native)
        );
        assert_eq!(
            native_external_edges, incumbent_external_edges,
            "native generic calls and type mentions match the incumbent; declaration and self-receiver edges remain available in the native projection"
        );
        for source in ["Handler", "Override"] {
            assert!(
                native_edges.contains(&(
                    format!("example.test/generic/auth.{source}"),
                    "example.test/generic/auth.Authenticator".into()
                )),
                "the native package context retains {source}'s promoted embedded interface edge"
            );
        }
        assert!(
            native.edges.iter().any(|edge| {
                native.nodes[edge.from].primary.fq_name().ends_with("Use")
                    && native.nodes[edge.to]
                        .primary
                        .fq_name()
                        .ends_with("Authenticator.Authenticate")
            }),
            "the generic embedded interface call retains its exact target"
        );
        assert!(
            native.edges.iter().any(|edge| {
                native.nodes[edge.from].primary.fq_name().ends_with("Build")
                    && native.nodes[edge.to].primary.fq_name().ends_with("Stack")
            }),
            "generic receiver and composite type references resolve to Stack"
        );
        for method in ["Push", "Pop"] {
            assert!(
                !native.edges.iter().any(|edge| {
                    native.nodes[edge.from]
                        .primary
                        .fq_name()
                        .ends_with(&format!("Stack.{method}"))
                        && native.nodes[edge.to].primary.fq_name().ends_with("Stack")
                }),
                "generic {method} receiver reference stays off the external usage graph"
            );
        }
    }

    #[test]
    fn go_native_graph_does_not_change_rust_answers_in_a_mixed_workspace() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_rust_analysis::analyzer::rust::native_graph::RustNativeWorkspaceGraphOutcome;

        use brokk_bifrost_rust_analysis::analyzer::rust::native_graph::build_rust_native_workspace_graph_for_files;

        let fixture = InlineTestProject::new()
            .file("go.mod", "module example.test/mixed\n\ngo 1.22\n")
            .file(
                "go/calls.go",
                "package calls\nfunc GoTarget() {}\nfunc GoCaller() { GoTarget() }\n",
            )
            .file(
                "Cargo.toml",
                "[package]\nname = \"mixed_graph\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn rust_target() {}\npub fn rust_caller() { rust_target() }\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        let rust = RustAnalyzer::new(fixture.project_dyn());
        brokk_bifrost_go_analysis::analyzer::go::persist_live_go_sources_for_test(&go);

        let rust_file = fixture.file("src/lib.rs");
        let cancellation = CancellationToken::new();
        let before = build_rust_native_workspace_graph_for_files(
            &rust,
            std::slice::from_ref(&rust_file),
            brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
        )
        .unwrap();
        let before = match before {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph) => graph,
            RustNativeWorkspaceGraphOutcome::Cancelled => {
                panic!("Rust baseline graph was cancelled")
            }
            RustNativeWorkspaceGraphOutcome::Stale(reason)
            | RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                panic!("Rust baseline graph unavailable: {reason}")
            }
        };
        let baseline_edges = native_edge_names(&before);
        let go_outcome = build_go_native_workspace_graph_for_files(
            &go,
            &[fixture.file("go/calls.go")],
            &cancellation,
        )
        .unwrap();
        assert!(matches!(
            go_outcome,
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(_)
                | SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(_)
        ));
        let after = build_rust_native_workspace_graph_for_files(
            &rust,
            std::slice::from_ref(&rust_file),
            brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
        )
        .unwrap();
        let after = match after {
            RustNativeWorkspaceGraphOutcome::Complete(graph)
            | RustNativeWorkspaceGraphOutcome::Incomplete(graph) => graph,
            RustNativeWorkspaceGraphOutcome::Cancelled => {
                panic!("Rust comparison graph was cancelled")
            }
            RustNativeWorkspaceGraphOutcome::Stale(reason)
            | RustNativeWorkspaceGraphOutcome::Unavailable(reason) => {
                panic!("Rust comparison graph unavailable: {reason}")
            }
        };
        assert_eq!(native_edge_names(&after), baseline_edges);
    }
}
