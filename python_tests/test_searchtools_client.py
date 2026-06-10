from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import SearchToolsClient, SearchToolsError, SymbolKindFilter

class SearchToolsClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
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
        self.assertIn("3..52: public class A", text)
        self.assertIn("8..10: public String method2(String input)", text)
        self.assertIn("41..43: public void method7()", text)
        self.assertNotIn("[...]", text)
        self.assertNotIn("{", text)
        self.assertIn("public class A", text_without_lines)
        self.assertNotIn("3..52:", text_without_lines)
        self.assertNotIn("8..10:", text_without_lines)
        self.assertNotIn("41..43:", text_without_lines)

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

    def test_get_summaries_keeps_directory_inventory_for_wrapper_callers(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            summaries = client.get_summaries(["."])
            text = summaries.render_text()

        self.assertEqual(0, len(summaries.summaries))
        self.assertIsNotNone(summaries.directory_symbols)
        assert summaries.directory_symbols is not None
        self.assertGreaterEqual(summaries.directory_symbols.count, 1)
        self.assertIn("A.java", text)

    def test_native_errors_are_raised_as_searchtools_error(self) -> None:
        with SearchToolsClient(root=self.fixture_root) as client:
            with self.assertRaisesRegex(SearchToolsError, "Unknown tool: nope"):
                client._call_tool("nope", {})

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
                    ["A.java"], limit=5, seed_weights=[2.0]
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


if __name__ == "__main__":
    unittest.main()
