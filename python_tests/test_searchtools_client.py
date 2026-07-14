from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import (
    CodeQueryFile,
    CodeQueryMatch,
    CodeQueryReferenceSite,
    CodeQueryResult,
    SearchToolsClient,
    SearchToolsError,
    SymbolKindFilter,
    XmlSelectOutput,
    tool_descriptors,
)
from bifrost_searchtools.models import SemanticSearchResult, SemanticSearchStatus


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

    def test_get_summaries_keeps_compact_symbols_for_wrapper_callers(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            summaries = client.get_summaries(["."])
            text = summaries.render_text()

        self.assertEqual(0, len(summaries.summaries))
        self.assertIsNotNone(summaries.compact_symbols)
        assert summaries.compact_symbols is not None
        self.assertGreaterEqual(summaries.compact_symbols.count, 1)
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
                    ["A.java"], limit=5, seed_weights=[2.0], recency_half_life=250.0
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
        self.assertNotIn("get_definitions_by_reference", visible_names)
        self.assertIn("get_definitions_by_reference", names)
        self.assertNotIn("get_definitions_by_location", names)

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
