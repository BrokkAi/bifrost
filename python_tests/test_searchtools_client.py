from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import get_args
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import (
    CodeQueryCacheLayerKind,
    CodeQueryCacheMetricsKind,
    CodeQueryCallSite,
    CodeQueryCompletionKind,
    CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact,
    CodeQueryDerivedLayerCacheCounters,
    CodeQueryExecutionMode,
    CodeQueryExpressionSite,
    CodeQueryExplain,
    CodeQueryFile,
    CodeQueryMatch,
    CodeQueryOperatorDisposition,
    CodeQueryPhysicalOperator,
    CodeQueryProfile,
    CodeQueryProfileCacheCounters,
    CodeQueryReferenceSite,
    CodeQueryResult,
    CodeQueryStructuralFactsCacheCounters,
    ContainerKind,
    DeclarationLookupResult,
    DefinitionLookupResult,
    DirectoryListingEntry,
    FileSummariesResult,
    MostRelevantFilesRankingMode,
    NavigationOperation,
    SearchToolsClient,
    SearchToolsError,
    SymbolKindFilter,
    XmlSelectOutput,
    parse_code_query_response,
    tool_descriptors,
)
from bifrost_searchtools.client import (
    CodeQueryExecutionMode as ClientCodeQueryExecutionMode,
)
from bifrost_searchtools.models import (
    CodeQueryExecutionMode as ModelCodeQueryExecutionMode,
    SemanticSearchResult,
    SemanticSearchStatus,
)


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True)


def _git_commit(root: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            message,
        ],
        cwd=root,
        check=True,
    )


def _code_query_explain_payload(
    execution_mode: CodeQueryExecutionMode = "explain",
) -> dict:
    return {
        "format": "bifrost_code_query_explain/v1",
        "query_schema_version": 2,
        "parsed_query": {
            "schema_version": 2,
            "match": {"kind": "class", "name": "A"},
            "where": ["src/**"],
            "limit": 20,
            "result_detail": "compact",
            "execution_mode": execution_mode,
            "future_parse_fact": "retained",
        },
        "logical_plan": {
            "root": 1,
            "nodes": [
                {
                    "id": 0,
                    "operation": {
                        "kind": "seed",
                        "seed": {"match": {"kind": "class", "name": "A"}},
                    },
                    "output_kind": "structural_match",
                    "dependencies": [],
                },
                {
                    "id": 1,
                    "operation": {"kind": "limit", "count": 20},
                    "output_kind": "structural_match",
                    "dependencies": [0],
                },
            ],
        },
        "physical_plan": {
            "root": 1,
            "nodes": [
                {
                    "id": 0,
                    "logical_node": 0,
                    "operator": "seed_scan",
                    "output_kind": "structural_match",
                    "dependencies": [],
                },
                {
                    "id": 1,
                    "logical_node": 1,
                    "operator": "limit",
                    "output_kind": "structural_match",
                    "dependencies": [0],
                    "future_physical_fact": True,
                },
            ],
        },
        "scheduling": {
            "policy": "auto",
            "selected": "sequential",
            "max_concurrency": 1,
            "selection_reason": "production policy",
        },
    }


def _code_query_profile_payload() -> dict:
    return {
        "format": "bifrost_code_query_profile/v2",
        "result": {"results": [], "truncated": False, "diagnostics": []},
        "explain": _code_query_explain_payload(execution_mode="profile"),
        "timings_ns": {
            "planning": 11,
            "execution": 22,
            "rendering": 33,
            "total": 66,
        },
        "work": {
            "scanned_files": 1,
            "scanned_source_bytes": 120,
            "fact_nodes": 4,
            "pipeline_rows": 3,
            "examined_references": 2,
            "provenance_steps": 1,
            "import_files_resolved": 0,
            "import_edges_resolved": 0,
        },
        "cache_layers": [
            {
                "layer": "seed_result",
                "metrics": {
                    "kind": "complete_value",
                    "lookups": 1,
                    "hits": 1,
                    "future_counter": 7,
                },
            },
            {
                "layer": "seed_structural_facts",
                "metrics": {
                    "kind": "structural_facts",
                    "lookups": 1,
                    "memory_hits": 1,
                    "replayed_files": 1,
                },
            },
            {
                "layer": "direct_import_topology",
                "metrics": {
                    "kind": "complete_value",
                    "lookups": 1,
                    "hits": 1,
                    "build_files": 3,
                    "build_edges": 2,
                    "retained_bytes": 256,
                },
            },
        ],
        "access_path": {
            "selected": "posting:kind+name",
            "representation_version": 1,
            "estimated_provider_files": 1,
            "scoped_files": 1,
            "scoped_fact_nodes": 4,
            "admitted_fact_nodes": 4,
            "candidate_files": 1,
            "candidate_facts": 1,
            "selected_terms": [
                {"label": "name", "candidate_facts": 1},
                {"label": "kind", "candidate_facts": 4},
            ],
            "source_verification_required": True,
            "cache_ready_lookups": 1,
            "materialized_files": 1,
            "materialized_fact_nodes": 4,
            "inspected_source_bytes": 120,
            "examined_fact_nodes": 1,
            "index_lookups": 1,
            "index_hits": 1,
            "index_misses": 0,
            "index_builds": 0,
            "index_waits": 0,
            "index_wait_ns": 0,
            "index_cancelled": 0,
            "index_unavailable": 0,
            "index_over_budget": 0,
            "scan_fallbacks": 0,
            "index_build_files": 0,
            "index_build_source_bytes": 0,
            "index_build_fact_nodes": 0,
            "index_build_facts_bytes": 0,
            "index_build_ns": 0,
            "retained_bytes": 512,
            "future_access_fact": True,
        },
        "scheduling": {
            "peak_concurrency": 1,
            "bounded_dispatch": {
                "worker_limit": 4,
                "workers_spawned": 1,
                "tasks_enqueued": 1,
                "tasks_started": 1,
                "tasks_completed": 1,
                "peak_concurrency": 1,
                "future_scheduler_fact": 9,
            },
        },
        "operators": [
            {
                "node": 0,
                "branch": [0],
                "operator": "seed_scan",
                "disposition": "completed",
                "timings_ns": {
                    "elapsed": 20,
                    "total": 22,
                    "dependency_execution": 0,
                    "dependency_wait": 0,
                    "merge": 1,
                    "scheduling_overhead": 1,
                },
                "input_rows": 0,
                "rows_visited": 1,
                "relation_expansions": 0,
                "rows_discarded": None,
                "output_rows": 1,
                "temporary_capacity_bytes_lower_bound": 128,
                "work": {"scanned_files": 1},
                "cache_layers": [
                    {
                        "layer": "seed_result",
                        "metrics": {
                            "kind": "complete_value",
                            "lookups": 1,
                            "misses": 1,
                        },
                    }
                ],
                "terminations": ["result_limit"],
                "operator_truncated": False,
                "result_truncated": False,
                "result_cancelled": False,
            }
        ],
        "future_profile_fact": "retained",
    }


class CodeQueryModelTest(unittest.TestCase):
    def test_execution_mode_alias_is_reexported_from_public_import_paths(self) -> None:
        self.assertIs(CodeQueryExecutionMode, ModelCodeQueryExecutionMode)
        self.assertIs(ClientCodeQueryExecutionMode, ModelCodeQueryExecutionMode)
        self.assertEqual(
            get_args(ModelCodeQueryExecutionMode),
            ("results", "explain", "profile"),
        )

    def test_explain_response_parses_typed_plan_layers(self) -> None:
        response = parse_code_query_response(
            _code_query_explain_payload(), rendered_text="server explain"
        )

        self.assertIsInstance(response, CodeQueryExplain)
        self.assertEqual(response.parsed_query.source_kind, "match")
        self.assertEqual(response.parsed_query.where, ["src/**"])
        self.assertEqual(response.parsed_query.execution_mode, "explain")
        self.assertEqual(
            response.parsed_query.extra["future_parse_fact"], "retained"
        )
        self.assertEqual(response.logical_plan.nodes[1].operation.kind, "limit")
        self.assertEqual(response.logical_plan.nodes[1].operation.count, 20)
        self.assertEqual(response.physical_plan.nodes[1].dependencies, [0])
        self.assertIs(
            response.physical_plan.nodes[1].operator,
            CodeQueryPhysicalOperator.LIMIT,
        )
        self.assertTrue(
            response.physical_plan.nodes[1].extra["future_physical_fact"]
        )
        self.assertEqual(response.scheduling.selected, "sequential")
        self.assertEqual(
            response.scheduling.extra["selection_reason"], "production policy"
        )
        self.assertEqual(response.render_text(), "server explain")

    def test_explain_rejects_unknown_execution_mode(self) -> None:
        payload = _code_query_explain_payload()
        payload["parsed_query"]["execution_mode"] = "speculate"
        with self.assertRaisesRegex(
            ValueError,
            "execution_mode must be one of 'results', 'explain', 'profile'",
        ):
            parse_code_query_response(payload)

    def test_profile_response_parses_results_observations_and_future_metrics(self) -> None:
        response = parse_code_query_response(
            _code_query_profile_payload(), rendered_text="server profile"
        )

        self.assertIsInstance(response, CodeQueryProfile)
        self.assertIsInstance(response.result, CodeQueryResult)
        self.assertIsInstance(response.explain, CodeQueryExplain)
        self.assertEqual(response.explain.parsed_query.execution_mode, "profile")
        self.assertEqual(response.timings_ns.total, 66)
        self.assertEqual(response.work.scanned_source_bytes, 120)
        self.assertEqual(response.access_path.selected, "posting:kind+name")
        self.assertEqual(response.access_path.candidate_facts, 1)
        self.assertEqual(response.access_path.selected_terms[0].label, "name")
        self.assertTrue(response.access_path.source_verification_required)
        self.assertEqual(response.access_path.cache_ready_lookups, 1)
        self.assertTrue(response.access_path.extra["future_access_fact"])
        self.assertIs(
            response.cache_layers[0].layer, CodeQueryCacheLayerKind.SEED_RESULT
        )
        self.assertIsInstance(
            response.cache_layers[0].metrics, CodeQueryProfileCacheCounters
        )
        self.assertIs(
            response.cache_layers[0].metrics.kind,
            CodeQueryCacheMetricsKind.COMPLETE_VALUE,
        )
        self.assertEqual(response.cache_layers[0].metrics.hits, 1)
        self.assertEqual(response.cache_layers[0].metrics.extra["future_counter"], 7)
        self.assertIsInstance(
            response.cache_layers[1].metrics,
            CodeQueryStructuralFactsCacheCounters,
        )
        self.assertEqual(
            response.cache_layers[2].layer,
            CodeQueryCacheLayerKind.DIRECT_IMPORT_TOPOLOGY,
        )
        self.assertIsInstance(
            response.cache_layers[2].metrics,
            CodeQueryDerivedLayerCacheCounters,
        )
        self.assertEqual(response.cache_layers[2].metrics.build_files, 3)
        self.assertEqual(response.cache_layers[2].metrics.build_edges, 2)
        self.assertEqual(response.cache_layers[2].metrics.retained_bytes, 256)
        self.assertEqual(response.scheduling.bounded_dispatch.worker_limit, 4)
        self.assertEqual(
            response.scheduling.bounded_dispatch.extra["future_scheduler_fact"], 9
        )
        self.assertEqual(response.operators[0].timings_ns.elapsed, 20)
        self.assertEqual(response.operators[0].node, 0)
        self.assertIs(
            response.operators[0].disposition,
            CodeQueryOperatorDisposition.COMPLETED,
        )
        self.assertIsNone(response.operators[0].rows_discarded)
        self.assertIs(
            response.operators[0].cache_layers[0].layer,
            CodeQueryCacheLayerKind.SEED_RESULT,
        )
        self.assertEqual(response.extra["future_profile_fact"], "retained")
        self.assertEqual(response.render_text(), "server profile")

    def test_profile_rejects_noncanonical_cache_layer_shapes(self) -> None:
        payload = _code_query_profile_payload()
        payload["cache_layers"] = {
            "seed_result": {"kind": "complete_value", "lookups": 1}
        }
        with self.assertRaisesRegex(ValueError, "cache_layers must be a list"):
            parse_code_query_response(payload)

        payload = _code_query_profile_payload()
        payload["cache"] = payload.pop("cache_layers")
        with self.assertRaisesRegex(ValueError, "cache_layers is required"):
            parse_code_query_response(payload)

        payload = _code_query_profile_payload()
        payload["cache_layers"][0] = {
            "layer": "seed_result",
            "kind": "complete_value",
            "lookups": 1,
        }
        with self.assertRaisesRegex(ValueError, "metrics must be a nested object"):
            parse_code_query_response(payload)

    def test_profile_rejects_missing_aliased_or_mismatched_cache_metric_kinds(
        self,
    ) -> None:
        cases = (
            (None, "None is not a valid CodeQueryCacheMetricsKind"),
            (
                "seed_structural_facts",
                "seed_structural_facts.*is not a valid CodeQueryCacheMetricsKind",
            ),
            (
                "structural_facts",
                "seed_result.*requires metrics kind 'complete_value'",
            ),
        )
        for kind, error_pattern in cases:
            with self.subTest(kind=kind):
                payload = _code_query_profile_payload()
                metrics = payload["cache_layers"][0]["metrics"]
                if kind is None:
                    metrics.pop("kind")
                else:
                    metrics["kind"] = kind
                with self.assertRaisesRegex(ValueError, error_pattern):
                    parse_code_query_response(payload)

        payload = _code_query_profile_payload()
        payload["cache_layers"][1]["metrics"]["kind"] = "complete_value"
        with self.assertRaisesRegex(
            ValueError,
            "seed_structural_facts.*requires metrics kind 'structural_facts'",
        ):
            parse_code_query_response(payload)

    def test_operator_cache_layers_use_the_same_canonical_decoder(self) -> None:
        payload = _code_query_profile_payload()
        operator = payload["operators"][0]
        operator["cache"] = operator.pop("cache_layers")
        with self.assertRaisesRegex(ValueError, "cache_layers is required"):
            parse_code_query_response(payload)

        payload = deepcopy(_code_query_profile_payload())
        payload["operators"][0]["cache_layers"] = {
            "seed_result": {"kind": "complete_value", "lookups": 1}
        }
        with self.assertRaisesRegex(ValueError, "cache_layers must be a list"):
            parse_code_query_response(payload)

    def test_query_code_forwards_execution_mode_and_dispatches_by_format(self) -> None:
        calls: list[tuple[str, dict]] = []
        client = object.__new__(SearchToolsClient)
        payloads = {
            "results": {"results": [], "truncated": False},
            "explain": _code_query_explain_payload(),
            "profile": _code_query_profile_payload(),
        }

        def call_tool_payload(tool: str, arguments: dict) -> SimpleNamespace:
            calls.append((tool, arguments))
            return SimpleNamespace(
                structured=payloads[arguments["execution_mode"]],
                rendered_text=f"server {arguments['execution_mode']}",
            )

        client._call_tool_payload = call_tool_payload
        results = client.query_code({"kind": "class"}, execution_mode="results")
        explain = client.query_code({"kind": "class"}, execution_mode="explain")
        profile = client.query_code({"kind": "class"}, execution_mode="profile")

        self.assertIsInstance(results, CodeQueryResult)
        self.assertIsInstance(explain, CodeQueryExplain)
        self.assertIsInstance(profile, CodeQueryProfile)
        self.assertEqual(
            [arguments["execution_mode"] for _, arguments in calls],
            ["results", "explain", "profile"],
        )
        self.assertTrue(
            all(arguments["match"] == {"kind": "class"} for _, arguments in calls)
        )
        with self.assertRaisesRegex(ValueError, "execution_mode must be one of"):
            client.query_code({"kind": "class"}, execution_mode="trace")
        self.assertEqual(len(calls), 3)

    def test_unknown_formatted_query_response_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported code-query response"):
            parse_code_query_response({"format": "future/v1"})

    def test_navigation_models_deserialize_distinct_fields_and_render_operation(self) -> None:
        candidate = {
            "name": "run",
            "fqn": "Runner.run",
            "path": "Runner.java",
            "start_line": 2,
            "end_line": 2,
            "kind": "function",
            "signature": "()",
            "language": "java",
        }
        declaration = DeclarationLookupResult.from_dict(
            {
                "query": {"path": "App.java", "line": 1},
                "operation": "declaration",
                "status": "resolved",
                "declarations": [candidate],
                "diagnostics": [],
            }
        )
        definition = DefinitionLookupResult.from_dict(
            {
                "query": {"path": "App.java", "line": 1},
                "operation": "definition",
                "status": "resolved",
                "definitions": [candidate],
                "diagnostics": [],
            }
        )

        self.assertIs(declaration.operation, NavigationOperation.DECLARATION)
        self.assertEqual(["Runner.run"], [item.fqn for item in declaration.declarations])
        self.assertIsNone(declaration.declarations[0].start_column)
        self.assertIsNone(declaration.declarations[0].end_column)
        self.assertIn("Runner.java:2..2", declaration.declarations[0].render_text())
        self.assertIn("operation: declaration", declaration.render_text())
        self.assertIs(definition.operation, NavigationOperation.DEFINITION)
        self.assertEqual(["Runner.run"], [item.fqn for item in definition.definitions])
        self.assertIn("operation: definition", definition.render_text())

    def test_typed_diagnostics_drive_completion_without_message_parsing(self) -> None:
        advisory = CodeQueryResult.from_dict(
            {
                "results": [],
                "truncated": False,
                "diagnostics": [
                    {
                        "code": "broad_query",
                        "impact": "advisory",
                        "language": "workspace",
                        "message": "wording is not part of completion",
                    }
                ],
            }
        )
        self.assertIs(
            advisory.diagnostics[0].code, CodeQueryDiagnosticCode.BROAD_QUERY
        )
        self.assertIs(
            advisory.diagnostics[0].impact, CodeQueryDiagnosticImpact.ADVISORY
        )
        self.assertIs(advisory.completion.kind, CodeQueryCompletionKind.COMPLETE)
        self.assertIn("advisory [broad_query]", advisory.render_text())

    def test_summary_model_parses_typed_container_listings(self) -> None:
        result = FileSummariesResult.from_dict(
            {
                "summaries": [],
                "listings": [
                    {
                        "target": "src",
                        "kind": "directory",
                        "entries": [
                            {
                                "kind": "directory",
                                "name": "internal",
                                "path": "src/internal",
                            }
                        ],
                        "total_entries": 1,
                        "truncated": False,
                    }
                ],
                "not_found": [],
                "ambiguous": [],
            }
        )

        self.assertEqual(ContainerKind.DIRECTORY, result.listings[0].kind)
        self.assertIsInstance(result.listings[0].entries[0], DirectoryListingEntry)
        self.assertEqual(1, result.count)
        self.assertIn("[directory] src/internal", result.render_text())

        incomplete = CodeQueryResult.from_dict(
            {
                "results": [],
                "truncated": False,
                "diagnostics": [
                    {
                        "code": "missing_structural_adapter",
                        "impact": "incomplete",
                        "language": "rust",
                        "message": "arbitrary localized wording",
                    }
                ],
            }
        )
        self.assertIs(incomplete.completion.kind, CodeQueryCompletionKind.INCOMPLETE)
        self.assertEqual(
            incomplete.completion.codes,
            (CodeQueryDiagnosticCode.MISSING_STRUCTURAL_ADAPTER,),
        )

        invalid = CodeQueryResult.from_dict(
            {
                "results": [],
                "truncated": False,
                "diagnostics": [
                    {
                        "code": "invalid_plan",
                        "impact": "invalid",
                        "language": "workspace",
                        "message": "not inspected",
                    }
                ],
            }
        )
        self.assertIs(invalid.completion.kind, CodeQueryCompletionKind.INVALID)

        cancelled = CodeQueryResult.from_dict(
            {
                "results": [],
                "truncated": True,
                "diagnostics": [
                    {
                        "code": "cancelled",
                        "impact": "incomplete",
                        "language": "workspace",
                        "message": "not inspected",
                    }
                ],
            }
        )
        self.assertIs(cancelled.completion.kind, CodeQueryCompletionKind.CANCELLED)


class SearchToolsClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Keep the test suite from starting the background semantic indexer or downloading models.
        os.environ.setdefault("BIFROST_SEMANTIC_INDEX", "off")
        maturin = shutil.which("maturin")
        if maturin is None:
            raise RuntimeError(
                "maturin is required for python_tests. Run scripts/test_python.sh "
                "or `uv run --python 3.12 --with maturin python -m unittest ...`."
            )
        subprocess.run(
            [maturin, "develop"], cwd=ROOT, check=True
        )
        cls.fixture_root = ROOT / "tests" / "fixtures" / "testcode-java"

    def test_file_summary_uses_fixture_line_ranges(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            summaries = client.get_summaries(["A.java"])
            text = summaries.render_text()

        with SearchToolsClient(
            root=self.fixture_root,
            render_line_numbers=False,
        ) as client:
            summaries_without_lines = client.get_summaries(["A.java"])
            text_without_lines = summaries_without_lines.render_text()

        self.assertIn("A.java", text)
        self.assertEqual("import java.util.function.Function;", summaries.summaries[0].preamble)
        self.assertEqual("A", summaries.summaries[0].elements[0].symbol)
        self.assertEqual("class", summaries.summaries[0].elements[0].kind)
        self.assertNotIn("import java.util.function.Function;", text)
        self.assertIn("3..52: public class A", text)
        self.assertIn("8..10: public String method2(String input)", text)
        self.assertIn("41..43: public void method7()", text)
        self.assertNotIn("[...]", text)
        self.assertNotIn("{", text)
        self.assertNotIn("import java.util.function.Function;", text_without_lines)
        self.assertIn("public class A", text_without_lines)
        self.assertNotIn("3..52:", text_without_lines)
        self.assertNotIn("8..10:", text_without_lines)
        self.assertNotIn("41..43:", text_without_lines)

    def test_manual_client_does_not_create_analyzer_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.java").write_text(
                "class A {\n    void method() {}\n}\n",
                encoding="utf-8",
            )

            with SearchToolsClient(root=root, manual=True) as client:
                summaries = client.get_summaries(["A.java"])

            self.assertEqual("A.java", summaries.summaries[0].path)
            self.assertFalse((root / ".bifrost" / "analyzer.db").exists())

    def test_usage_graph_builds_resolved_reference_graph(self) -> None:
        python_fixture = ROOT / "tests" / "fixtures" / "usage-graph-python"
        with SearchToolsClient(root=python_fixture) as client:
            graph = client.usage_graph()

        node_fqns = {node.fqn for node in graph.nodes}
        self.assertTrue(any(fqn.endswith("helper") for fqn in node_fqns), node_fqns)
        self.assertTrue(any(fqn.endswith("run") for fqn in node_fqns), node_fqns)
        self.assertTrue(any(fqn.endswith("unused") for fqn in node_fqns), node_fqns)
        for node in graph.nodes:
            self.assertIn(node.kind, {"function", "class"})

        def edge(from_suffix: str, to_suffix: str):
            return next(
                (
                    candidate
                    for candidate in graph.edges
                    if candidate.from_fqn.endswith(from_suffix)
                    and candidate.to_fqn.endswith(to_suffix)
                ),
                None,
            )

        # Edges are resolved caller -> callee references, weighted by call site.
        run_edge = edge("run", "helper")
        self.assertIsNotNone(run_edge, graph.edges)
        self.assertEqual(run_edge.weight, 1)

        # Two calls on separate lines aggregate into one weight-2 edge.
        twice_edge = edge("run_twice", "helper")
        self.assertIsNotNone(twice_edge, graph.edges)
        self.assertEqual(twice_edge.weight, 2)

        # `a.unused` is never called, so nothing points to it.
        self.assertFalse(any(e.to_fqn.endswith("unused") for e in graph.edges))

        # Every edge lists its reference locations, and the site count matches the
        # weight. `run_twice` calls `helper` on b.py:14 and b.py:15.
        for candidate in graph.edges:
            self.assertEqual(len(candidate.sites), candidate.weight, candidate)
        self.assertEqual(
            [(site.path, site.line) for site in twice_edge.sites],
            [("b.py", 14), ("b.py", 15)],
        )

    def test_query_code_returns_typed_matches(self) -> None:
        absolute_where = str(self.fixture_root / "*.java")
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.query_code(
                {"kind": "class", "name": "A"},
                where=[absolute_where],
                languages=["java"],
                schema_version=2,
            )

        self.assertIsInstance(result, CodeQueryResult)
        self.assertEqual(result.count, 1)
        self.assertIsInstance(result.results[0], CodeQueryMatch)
        self.assertEqual(result.results[0].path, "A.java")
        self.assertEqual(result.results[0].kind, "class")
        self.assertEqual(result.results[0].language, "java")
        self.assertEqual(result.results[0].text, "public class A {…")
        self.assertIsNone(result.results[0].id)
        self.assertIsNone(result.results[0].node_range)
        self.assertEqual(result.diagnostics, [])

        with SearchToolsClient(root=self.fixture_root) as client:
            detailed = client.query_code(
                {"kind": "class", "name": "A", "capture": "klass"},
                where=[absolute_where],
                languages=["java"],
                result_detail="full",
            )

        self.assertIsNotNone(detailed.results[0].id)
        self.assertIsNotNone(detailed.results[0].node_range)
        self.assertGreater(
            (
                detailed.results[0].node_range.end_line,
                detailed.results[0].node_range.end_column,
            ),
            (
                detailed.results[0].node_range.start_line,
                detailed.results[0].node_range.start_column,
            ),
        )
        self.assertEqual(detailed.results[0].captures[0].kind, "class")
        self.assertIsNotNone(detailed.results[0].captures[0].range)
        self.assertGreaterEqual(detailed.results[0].captures[0].range.end_line, detailed.results[0].captures[0].start_line)

        with SearchToolsClient(root=self.fixture_root) as client:
            files = client.query_code(
                {"kind": "class", "name": "A"},
                where=[absolute_where],
                languages=["java"],
                steps=[{"op": "file_of"}],
            )

        self.assertIsInstance(files.results[0], CodeQueryFile)
        self.assertEqual(files.results[0].path, "A.java")
        self.assertEqual(len(files.results[0].provenance), 1)

    def test_query_code_returns_typed_explain_and_profile_reports(self) -> None:
        absolute_where = str(self.fixture_root / "*.java")
        with SearchToolsClient(root=self.fixture_root) as client:
            explain = client.query_code(
                {"kind": "class", "name": "A"},
                where=[absolute_where],
                languages=["java"],
                execution_mode="explain",
            )
            profile = client.query_code(
                {"kind": "class", "name": "A"},
                where=[absolute_where],
                languages=["java"],
                execution_mode="profile",
            )

        self.assertIsInstance(explain, CodeQueryExplain)
        self.assertEqual(explain.parsed_query.execution_mode, "explain")
        self.assertGreaterEqual(len(explain.logical_plan.nodes), 2)
        self.assertEqual(
            explain.logical_plan.root,
            explain.physical_plan.nodes[explain.physical_plan.root].logical_node,
        )
        self.assertIsInstance(profile, CodeQueryProfile)
        self.assertEqual(profile.result.count, 1)
        self.assertIsInstance(profile.result.results[0], CodeQueryMatch)
        self.assertEqual(profile.explain.parsed_query.execution_mode, "profile")
        self.assertGreaterEqual(len(profile.operators), 2)
        self.assertEqual(len(profile.cache_layers), 9)
        self.assertEqual(
            profile.cache_layers[-1].layer,
            CodeQueryCacheLayerKind.DIRECT_IMPORT_TOPOLOGY,
        )
        self.assertGreaterEqual(profile.scheduling.peak_concurrency, 1)

    def test_query_code_builds_typed_set_plans_and_parses_branch_paths(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.query_code(
                union=[
                    {"match": {"kind": "class", "name": "A"}},
                    {"match": {"kind": "class", "name": "A"}},
                ],
                result_detail="full",
            )

        self.assertEqual(result.count, 1)
        self.assertEqual(
            [trace.branch for trace in result.results[0].provenance],
            [[0], [1]],
        )

        with SearchToolsClient(root=self.fixture_root) as client:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                client.query_code(
                    {"kind": "class"},
                    union=[{"match": {"kind": "class"}}] * 2,
                )
            with self.assertRaisesRegex(ValueError, "scope fields"):
                client.query_code(
                    intersect=[{"match": {"kind": "class"}}] * 2,
                    languages=["java"],
                )

    def test_query_code_parses_reference_sites_and_via_provenance(self) -> None:
        result = CodeQueryResult.from_dict(
            {
                "results": [
                    {
                        "result_type": "reference_site",
                        "path": "User.java",
                        "language": "java",
                        "range": {
                            "start_line": 3,
                            "start_column": 12,
                            "end_line": 3,
                            "end_column": 18,
                        },
                        "target": {
                            "path": "Target.java",
                            "language": "java",
                            "kind": "field",
                            "fq_name": "Target.status",
                            "start_line": 1,
                            "end_line": 1,
                        },
                        "enclosing_declaration": {
                            "path": "User.java",
                            "language": "java",
                            "kind": "function",
                            "fq_name": "User.read",
                            "start_line": 2,
                            "end_line": 4,
                        },
                        "usage_kind": "reference",
                        "proof": "proven",
                        "reference_kind": "field_read",
                        "provenance": [
                            {
                                "seed": {
                                    "result_type": "structural_match",
                                    "path": "Target.java",
                                    "kind": "class",
                                    "start_line": 1,
                                    "end_line": 1,
                                },
                                "steps": [
                                    {
                                        "op": "used_by",
                                        "result": {
                                            "result_type": "declaration",
                                            "path": "User.java",
                                            "kind": "function",
                                            "fq_name": "User.read",
                                            "start_line": 2,
                                            "end_line": 4,
                                        },
                                        "via": {
                                            "result_type": "reference_site",
                                            "path": "User.java",
                                            "range": {
                                                "start_line": 3,
                                                "start_column": 12,
                                                "end_line": 3,
                                                "end_column": 18,
                                            },
                                            "target_fq_name": "Target.status",
                                            "target_id": "Target.java:field:Target.status:0-11",
                                            "proof": "proven",
                                            "reference_kind": "field_read",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
                "truncated": False,
            }
        )
        site = result.results[0]
        self.assertIsInstance(site, CodeQueryReferenceSite)
        self.assertEqual(site.target.fq_name, "Target.status")
        self.assertEqual(site.enclosing_declaration.fq_name, "User.read")
        self.assertEqual(
            site.provenance[0].steps[0].via.target_fq_name,
            "Target.status",
        )
        self.assertEqual(
            site.provenance[0].steps[0].via.target_id,
            "Target.java:field:Target.status:0-11",
        )

    def test_query_code_parses_call_and_expression_sites(self) -> None:
        declaration = lambda fq_name: {
            "path": "sample.py",
            "language": "python",
            "kind": "function",
            "fq_name": fq_name,
            "start_line": 1,
            "end_line": 2,
        }
        source_range = {
            "start_line": 4,
            "start_column": 4,
            "end_line": 4,
            "end_column": 19,
        }
        result = CodeQueryResult.from_dict(
            {
                "results": [
                    {
                        "result_type": "call_site",
                        "path": "sample.py",
                        "language": "python",
                        "range": source_range,
                        "callee_range": source_range,
                        "caller": declaration("sample.caller"),
                        "callee": declaration("sample.target"),
                        "call_kind": "function_call",
                        "proof": "proven",
                        "arguments": [
                            {
                                "range": source_range,
                                "position": 0,
                                "formal_index": 0,
                                "formal_name": "payload",
                            }
                        ],
                    },
                    {
                        "result_type": "expression_site",
                        "path": "sample.py",
                        "language": "python",
                        "range": source_range,
                        "text": '"value"',
                        "input_kind": "parameter",
                        "caller_fq_name": "sample.caller",
                        "callee_fq_name": "sample.target",
                        "call_range": source_range,
                        "parameter_index": 0,
                        "parameter_name": "payload",
                    },
                ],
                "truncated": False,
            }
        )
        self.assertIsInstance(result.results[0], CodeQueryCallSite)
        self.assertEqual(result.results[0].arguments[0].formal_name, "payload")
        self.assertIsInstance(result.results[1], CodeQueryExpressionSite)
        self.assertEqual(result.results[1].text, '"value"')

    def test_symbol_sources_use_original_file_line_numbers(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            sources = client.get_symbol_sources(
                ["A.method2"], kind_filter=SymbolKindFilter.FUNCTION
            )
            text = sources.render_text()

        with SearchToolsClient(
            root=self.fixture_root,
            render_line_numbers=False,
        ) as client:
            sources_without_lines = client.get_symbol_sources(
                ["A.method2"], kind_filter=SymbolKindFilter.FUNCTION
            )
            text_without_lines = sources_without_lines.render_text()

        self.assertEqual(2, sources.count)
        self.assertIn("## A.method2", text)
        self.assertIn("- Location: A.java:8..10", text)
        self.assertIn("- Location: A.java:12..15", text)
        self.assertEqual(1, text.count("- Location: A.java:8..10"))
        self.assertEqual(1, text.count("- Location: A.java:12..15"))
        self.assertIn("```text", text)
        self.assertIn("## A.method2", text_without_lines)
        self.assertIn("- Path: A.java", text_without_lines)
        self.assertNotIn(":8..10", text_without_lines)
        self.assertNotIn(":12..15", text_without_lines)
        self.assertNotIn("8: ", text_without_lines)
        self.assertNotIn("12: ", text_without_lines)

    def test_list_symbols_matches_recursive_brokk_style_output(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            summaries = client.list_symbols(["A.java"])
            text = summaries.render_text()

        self.assertEqual(1, summaries.count)
        self.assertIn("  - AInner", text)
        self.assertIn("    - AInnerInner", text)
        self.assertIn("      - method7", text)

    def test_classify_test_files_classifies_files(self) -> None:
        py_root = ROOT / "tests" / "fixtures" / "testcode-py"
        with SearchToolsClient(root=py_root) as client:
            result = client.classify_test_files(
                [
                    "tests/units/utils/test_utils.py",
                    "documented.py",
                    "does_not_exist.py",
                ]
            )
        self.assertEqual("test", result["tests/units/utils/test_utils.py"]["kind"])
        self.assertEqual("ambiguous", result["documented.py"]["kind"])
        self.assertNotIn("does_not_exist.py", result)

    def test_scoped_revision_client_reads_selected_old_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "Demo.java").write_text(
                "class OldDemo {\n  int value() { return 1; }\n}\n"
            )
            (root / "Other.java").write_text("class Other {}\n")
            _init_git_repo(root)
            _git_commit(root, "v1")
            (root / "Demo.java").write_text(
                "class NewDemo {\n  int value() { return 2; }\n}\n"
            )
            (root / "Other.java").write_text("class ChangedOther {}\n")
            _git_commit(root, "v2")

            with SearchToolsClient(
                root=root,
                sources=["Demo.java"],
                revision="HEAD~1",
            ) as client:
                summaries = client.get_summaries(["Demo.java", "Other.java"])

        self.assertEqual("Demo.java", summaries.summaries[0].path)
        text = summaries.summaries[0].elements[0].text
        self.assertIn("OldDemo", text)
        self.assertNotIn("NewDemo", text)
        self.assertTrue(
            any(item["input"] == "Other.java" for item in summaries.not_found),
            summaries.not_found,
        )

    def test_scan_usages_returns_rendered_native_payload(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            usages = client.scan_usages_by_reference(["A.method2"])
            text = usages.render_text()

        self.assertIn("A.method2", text)
        self.assertIsInstance(usages.structured, dict)
        hits = usages.structured["results"][0]["files"][0]["hits"]
        self.assertTrue(hits)
        for hit in hits:
            self.assertTrue(
                all(
                    coordinate in hit
                    for coordinate in ("column", "end_line", "end_column")
                ),
                hit,
            )
            exact_range = (
                f"line {hit['line']}:{hit['column']}-"
                f"{hit['end_line']}:{hit['end_column']}"
            )
            self.assertIn(exact_range, text)

    def test_scan_usages_by_location_returns_rendered_native_payload(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            usages = client.scan_usages_by_location(
                [{"path": "A.java", "line": 8, "column": 19}]
            )
            text = usages.render_text()

        self.assertIn("A.method2", text)
        self.assertIsInstance(usages.structured, dict)

    def test_rename_symbol_returns_typed_non_mutating_edit_set(self) -> None:
        before_a = (self.fixture_root / "A.java").read_text()
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.rename_symbol(
                "A.java", line=8, column=19, new_name="renamedMethod2"
            )

        self.assertEqual("ok", result.status)
        self.assertIsNotNone(result.target)
        assert result.target is not None
        self.assertEqual("A.method2", result.target.symbol)
        self.assertEqual("method2", result.old_name)
        self.assertTrue(
            any(
                file_edits.path == "B.java"
                and any(
                    edit.old_text == "method2" and edit.new_text == "renamedMethod2"
                    for edit in file_edits.edits
                )
                for file_edits in result.edits
            )
        )
        self.assertEqual(before_a, (self.fixture_root / "A.java").read_text())

    def test_get_summaries_returns_typed_root_listing(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            summaries = client.get_summaries(["."])
            text = summaries.render_text()

        self.assertEqual(0, len(summaries.summaries))
        self.assertIsNone(summaries.compact_symbols)
        self.assertEqual(1, len(summaries.listings))
        self.assertEqual(ContainerKind.DIRECTORY, summaries.listings[0].kind)
        self.assertGreaterEqual(summaries.listings[0].total_entries, 1)
        self.assertIn("A.java", text)

    def test_native_errors_are_raised_as_searchtools_error(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            with self.assertRaisesRegex(SearchToolsError, "Unknown tool: nope"):
                client._call_tool("nope", {})

    def test_semantic_search_disabled_raises(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            with self.assertRaisesRegex(SearchToolsError, "disabled"):
                client.semantic_search("anything", k=1)

    def test_client_supports_concurrent_requests_from_threads(self) -> None:
        def call_tool(index: int) -> str:
            if index % 4 == 0:
                return client.search_symbols(["A"], include_tests=True, limit=5).render_text()
            if index % 4 == 1:
                return client.get_symbol_sources(
                    ["A.method2"], kind_filter=SymbolKindFilter.FUNCTION
                ).render_text()
            if index % 4 == 2:
                return client.get_summaries(["A.java"]).render_text()
            return client.most_relevant_files(["A.java"], limit=5).render_text()

        with SearchToolsClient(root=self.fixture_root) as client:
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(call_tool, range(16)))

        self.assertEqual(16, len(results))
        self.assertTrue(all(result for result in results))
        self.assertTrue(any("A.method2" in result for result in results))

    def test_client_rejects_calls_after_close(self) -> None:
        client = SearchToolsClient(root=self.fixture_root)
        client.close()

        with self.assertRaisesRegex(SearchToolsError, "SearchToolsClient is closed"):
            client.search_symbols(["A"])

    def test_most_relevant_files_returns_ranked_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.java").write_text("public class A { }\n")
            (root / "B.java").write_text("public class B { }\n")
            subprocess.run(["git", "init"], cwd=root, check=True)
            subprocess.run(["git", "add", "A.java", "B.java"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "initial",
                ],
                cwd=root,
                check=True,
            )

            with SearchToolsClient(root=root) as client:
                result = client.most_relevant_files(
                    ["A.java"],
                    limit=5,
                    seed_weights=[2.0],
                    recency_half_life=250.0,
                    ranking_mode=MostRelevantFilesRankingMode.USAGE_GRAPH,
                )
                text = result.render_text()

        self.assertIn("B.java", result.files)
        self.assertEqual([], result.not_found)
        self.assertEqual([], result.duplicates)
        self.assertIn("B.java", text)

    def test_most_relevant_files_reports_duplicate_resolved_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.java").write_text("public class A { }\n")

            with SearchToolsClient(root=root) as client:
                result = client.most_relevant_files(
                    ["A.java", "./A.java"], limit=5, seed_weights=[1.0, 2.0]
                )
                text = result.render_text()

        self.assertEqual([], result.files)
        self.assertEqual(["A.java"], result.duplicates)
        self.assertIn("Duplicate seeds: A.java", text)

    def test_most_relevant_files_explicit_none_pins_uniform_git_weighting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Seed.java").write_text("public class Seed { }\n")
            (root / "OldTarget.java").write_text("public class OldTarget { }\n")
            (root / "RecentTarget.java").write_text("public class RecentTarget { }\n")
            subprocess.run(["git", "init"], cwd=root, check=True)
            subprocess.run(["git", "add", "Seed.java"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "initial seed",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "add", "OldTarget.java"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "add old target",
                ],
                cwd=root,
                check=True,
            )
            (root / "Seed.java").write_text(
                "public class Seed { int oldUse() { return 1; } }\n"
            )
            (root / "OldTarget.java").write_text(
                "public class OldTarget { int value() { return 1; } }\n"
            )
            subprocess.run(["git", "add", "Seed.java", "OldTarget.java"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "old cochange",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "add", "RecentTarget.java"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "add recent target",
                ],
                cwd=root,
                check=True,
            )
            (root / "Seed.java").write_text(
                "public class Seed { int recentUse() { return 2; } }\n"
            )
            (root / "RecentTarget.java").write_text(
                "public class RecentTarget { int value() { return 2; } }\n"
            )
            subprocess.run(
                ["git", "add", "Seed.java", "RecentTarget.java"], cwd=root, check=True
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-m",
                    "recent cochange",
                ],
                cwd=root,
                check=True,
            )

            with SearchToolsClient(root=root) as client:
                result = client.most_relevant_files(
                    ["Seed.java"], limit=2, recency_half_life=None
                )

        self.assertEqual("OldTarget.java", result.files[0])

    def test_get_symbol_ancestors_returns_csharp_hierarchy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Types.cs").write_text(
                """
namespace Demo
{
    public class BaseType {}
    public interface IService {}
    public class ChildType : BaseType, IService {}
}
""".strip()
                + "\n"
            )

            with SearchToolsClient(root=root) as client:
                result = client.get_symbol_ancestors(["Demo.ChildType"])
                text = result.render_text()

        self.assertEqual(1, result.count)
        self.assertEqual("Demo.ChildType", result.ancestors[0].symbol)
        self.assertEqual(
            ["Demo.BaseType", "Demo.IService"],
            result.ancestors[0].ancestors,
        )
        self.assertIn("Demo.BaseType", text)
        self.assertIn("Demo.IService", text)

    def test_semantic_search_result_from_dict_renders_hits_and_notes(self) -> None:
        result = SemanticSearchResult.from_dict(
            {
                "vector_ranked": [
                    {
                        "fqfn": "Foo.primary",
                        "score": 0.87,
                    },
                ],
                "bm25_ranked": [
                    {
                        "fqfn": "Bar.secondary",
                        "score": 0.1254,
                    },
                ],
                "coedit_ranked": [{"path": "src/Baz.java", "score": 0.42}],
                "notes": ["index warmed from cache"],
            }
        )

        self.assertEqual(1, result.count)
        self.assertEqual("Foo.primary", result.vector_ranked[0].fqfn)
        self.assertEqual(0.87, result.vector_ranked[0].score)
        self.assertEqual("Bar.secondary", result.bm25_ranked[0].fqfn)
        self.assertEqual("src/Baz.java", result.coedit_ranked[0].path)
        self.assertEqual(["index warmed from cache"], result.notes)

        text = result.render_text()
        self.assertIn("note: index warmed from cache", text)
        self.assertIn("=== vector ===", text)
        self.assertIn("Foo.primary (score 0.870)", text)
        self.assertIn("=== bm25 ===", text)
        self.assertIn("Bar.secondary (score 0.125)", text)
        self.assertIn("=== co-edit ===", text)
        self.assertIn("src/Baz.java (score 0.420)", text)

    def test_semantic_search_status_from_dict(self) -> None:
        status = SemanticSearchStatus.from_dict(
            {
                "indexed_chunks": 12,
                "pending_batches": 1,
                "phase": "ready",
                "materialized_files": 4,
                "materialize_total_files": 5,
            }
        )

        self.assertEqual(12, status.indexed_chunks)
        self.assertEqual(1, status.pending_batches)
        self.assertEqual("ready", status.phase)
        self.assertEqual(4, status.materialized_files)
        self.assertEqual(5, status.materialize_total_files)

    def test_refresh_returns_typed_metrics(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.refresh()

        self.assertGreater(result.analyzed_files, 0)
        self.assertGreater(result.declarations, 0)
        self.assertIn("java", result.languages)

    def test_get_active_workspace_reports_root(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.get_active_workspace()

        self.assertEqual("testcode-java", Path(result.workspace_path).name)

    def test_tool_descriptors_reflect_hidden_line_number_surface(self) -> None:
        visible_names = {
            descriptor["name"]
            for descriptor in tool_descriptors("symbol", render_line_numbers=True)
        }
        names = {
            descriptor["name"]
            for descriptor in tool_descriptors("symbol", render_line_numbers=False)
        }

        self.assertIn("get_definitions_by_location", visible_names)
        self.assertIn("get_declarations_by_location", visible_names)
        self.assertNotIn("get_definitions_by_reference", visible_names)
        self.assertIn("get_definitions_by_reference", names)
        self.assertNotIn("get_definitions_by_location", names)
        self.assertNotIn("get_declarations_by_location", names)

    def test_location_navigation_dispatches_typed_declaration_and_definition_results(self) -> None:
        references = [{"path": "B.java", "line": 8, "column": 11}]
        with SearchToolsClient(root=self.fixture_root) as client:
            declarations = client.get_declarations_by_location(references)
            definitions = client.get_definitions_by_location(references)

        self.assertEqual(1, len(declarations))
        self.assertIs(declarations[0].operation, NavigationOperation.DECLARATION)
        self.assertEqual("A.method1", declarations[0].declarations[0].fqn)
        self.assertIsNotNone(declarations[0].declarations[0].start_column)
        self.assertIsNotNone(declarations[0].declarations[0].end_column)
        self.assertEqual(1, len(definitions))
        self.assertIs(definitions[0].operation, NavigationOperation.DEFINITION)
        self.assertEqual("A.method1", definitions[0].definitions[0].fqn)
        self.assertIsNotNone(definitions[0].definitions[0].start_column)
        self.assertIsNotNone(definitions[0].definitions[0].end_column)
        rendered = definitions[0].definitions[0].render_text()
        self.assertIn(
            f":{definitions[0].definitions[0].start_column}-",
            rendered,
        )

    def test_location_navigation_deserializes_exact_lexical_candidate(self) -> None:
        source = (
            "class Demo { void Run(string arg) { "
            "System.Console.WriteLine(arg); } }\n"
        )
        column = source.rindex("arg") + 1
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Demo.cs").write_text(source)
            with SearchToolsClient(root=root) as client:
                results = client.get_definitions_by_location(
                    [{"path": "Demo.cs", "line": 1, "column": column}]
                )

        self.assertEqual(1, len(results))
        self.assertEqual("resolved", results[0].status)
        self.assertEqual(1, len(results[0].definitions))
        candidate = results[0].definitions[0]
        self.assertEqual("arg", candidate.name)
        self.assertIsNone(candidate.fqn)
        self.assertEqual(1, candidate.start_line)
        self.assertEqual(30, candidate.start_column)
        self.assertEqual(1, candidate.end_line)
        self.assertEqual(33, candidate.end_column)
        self.assertIn("arg (parameter, csharp)", candidate.render_text())

    def test_activate_workspace_switches_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp)
            (other / "A.java").write_text("public class A { }\n")

            with SearchToolsClient(root=self.fixture_root) as client:
                activated = client.activate_workspace(other)
                active = client.get_active_workspace()

            # Rust canonicalizes the root (on Windows that adds a \\?\ prefix),
            # so compare by filesystem identity rather than string equality.
            self.assertTrue(os.path.samefile(activated.workspace_path, other))
            self.assertTrue(
                os.path.samefile(active.workspace_path, activated.workspace_path)
            )

    def test_get_file_contents_reads_fixture_file(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.get_file_contents(["A.java"])

        self.assertEqual(1, result.count)
        self.assertEqual("A.java", result.files[0].path)
        self.assertIn("public class A", result.files[0].content)
        self.assertEqual([], result.not_found)

    def test_find_filenames_matches_glob(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.find_filenames(["*.java"], limit=5)

        self.assertTrue(any(name.endswith("A.java") for name in result.files))
        self.assertLessEqual(result.count, 5)

    def test_search_file_contents_returns_matches_with_context(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.search_file_contents(["public class A"], file_path="A.java")

        self.assertTrue(result.matches)
        group = result.matches[0]
        self.assertEqual("A.java", group.path)
        self.assertTrue(any("public class A" in m.text for m in group.matches))

    def test_find_files_containing_matches_contents(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.find_files_containing(["public class A\\b"])

        self.assertTrue(any(name.endswith("A.java") for name in result.files))
        self.assertEqual([], result.invalid_patterns)

    def test_list_files_lists_workspace_root(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.list_files("")

        self.assertTrue(any(name.endswith("A.java") for name in result.files))

    def test_compute_cyclomatic_complexity_reports(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.compute_cyclomatic_complexity(["A.java"], threshold=1)

        self.assertIsInstance(result.report, str)
        self.assertTrue(result.report.strip())
        self.assertEqual(result.report, result.render_text())

    def test_structured_data_tools_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.json").write_text('{"name": "bifrost", "version": "0.2.0"}\n')
            (root / "doc.xml").write_text(
                "<root><item>alpha</item><item>beta</item></root>\n"
            )
            (root / "attrs.xml").write_text(
                '<root><item id="1"/><item id="2"/></root>\n'
            )

            with SearchToolsClient(root=root) as client:
                jq_result = client.jq("data.json", ".name")
                skim = client.xml_skim("doc.xml")
                selected = client.xml_select("doc.xml", "//item")
                attrs = client.xml_select(
                    "attrs.xml",
                    "//item",
                    output=XmlSelectOutput.ATTRIBUTE,
                    attr_name="id",
                )

        self.assertEqual(['"bifrost"'], jq_result.files[0].matches)
        self.assertTrue(any(el.tag == "item" for el in skim.files[0].elements))
        self.assertEqual(["alpha", "beta"], selected.files[0].matches)
        self.assertEqual(["1", "2"], attrs.files[0].matches)

    def test_git_tools_return_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_git_repo(root)
            (root / "a.txt").write_text("alpha\n")
            _git_commit(root, "Add alpha file")

            with SearchToolsClient(root=root) as client:
                log = client.get_git_log()
                diff = client.get_commit_diff("HEAD")
                search = client.search_git_commit_messages("alpha")

        self.assertIn("Add alpha file", log.text)
        self.assertIn("a.txt", diff.text)
        self.assertIn("alpha", search.text)
        self.assertEqual(log.text, log.render_text())

    def test_update_paths_returns_typed_metrics(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            result = client.update_paths(["A.java"])

        self.assertGreaterEqual(result.analyzed_files, 1)
        self.assertIn("java", result.languages)

    def test_code_quality_reports_on_java_fixture(self) -> None:
        # One analyzer build, every Java-backed slopcop tool exercised so an
        # argument-name typo in any single wrapper surfaces here.
        with SearchToolsClient(root=self.fixture_root) as client:
            reports = {
                "cognitive": client.compute_cognitive_complexity(
                    ["A.java"], threshold=1
                ),
                "density_unit": client.report_comment_density_for_code_unit("A"),
                "density_files": client.report_comment_density_for_files(["A.java"]),
                "exception": client.report_exception_handling_smells(["A.java"]),
                "assertion": client.report_test_assertion_smells(["A.java"]),
                "clone": client.report_structural_clone_smells(["A.java", "B.java"]),
                "size": client.report_long_method_and_god_object_smells(["A.java"]),
            }

        for name, report in reports.items():
            self.assertIsInstance(report.report, str, name)
            self.assertEqual(report.report, report.render_text(), name)

    def test_report_dead_code_on_rust_fixture(self) -> None:
        rust_fixture = ROOT / "tests" / "fixtures" / "testcode-rs"
        with SearchToolsClient(root=rust_fixture) as client:
            report = client.report_dead_code_and_unused_abstraction_smells()

        self.assertIsInstance(report.report, str)
        self.assertEqual(report.report, report.render_text())

    def test_secret_like_code_and_git_hotspots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _init_git_repo(root)
            (root / "config.py").write_text('API_KEY = "AKIA1234567890ABCDEF"\n')
            _git_commit(root, "Add config")

            with SearchToolsClient(root=root) as client:
                secrets = client.report_secret_like_code()
                hotspots = client.analyze_git_hotspots()

        self.assertIsInstance(secrets.report, str)
        self.assertIsInstance(hotspots.report, str)


if __name__ == "__main__":
    unittest.main()
