from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import SearchToolsClient, SearchToolsError, SymbolKindFilter


def native_library_path() -> Path:
    if sys.platform == "darwin":
        name = "libbrokk_analyzer.dylib"
    elif sys.platform == "win32":
        name = "brokk_analyzer.dll"
    else:
        name = "libbrokk_analyzer.so"
    return ROOT / "target" / "debug" / name


class SearchToolsClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(["cargo", "build", "--lib"], cwd=ROOT, check=True)
        cls.library_path = native_library_path()
        cls.fixture_root = ROOT / "tests" / "fixtures" / "testcode-java"

    def test_file_summary_uses_fixture_line_ranges(self) -> None:
        with SearchToolsClient(
            root=self.fixture_root, library_path=self.library_path
        ) as client:
            summaries = client.get_file_summaries(["A.java"])
            text = summaries.render_text()

        self.assertIn("A.java", text)
        self.assertIn("3..3: public class A", text)
        self.assertIn("8..8: public String method2(String input)", text)
        self.assertIn("41..41: public void method7()", text)
        self.assertNotIn("[...]", text)
        self.assertNotIn("{", text)

    def test_symbol_sources_use_original_file_line_numbers(self) -> None:
        with SearchToolsClient(
            root=self.fixture_root, library_path=self.library_path
        ) as client:
            sources = client.get_symbol_sources(
                ["A.method2"], kind_filter=SymbolKindFilter.FUNCTION
            )
            text = sources.render_text()

        self.assertEqual(2, sources.count)
        self.assertIn("A.method2 (A.java:8..10)", text)
        self.assertIn("A.method2 (A.java:12..15)", text)
        self.assertEqual(1, text.count("A.method2 (A.java:8..10)"))
        self.assertEqual(1, text.count("A.method2 (A.java:12..15)"))

    def test_summarize_symbols_matches_recursive_brokk_style_output(self) -> None:
        with SearchToolsClient(
            root=self.fixture_root, library_path=self.library_path
        ) as client:
            summaries = client.summarize_symbols(["A.java"])
            text = summaries.render_text()

        self.assertEqual(1, summaries.count)
        self.assertIn("  - AInner", text)
        self.assertIn("    - AInnerInner", text)
        self.assertIn("      - method7", text)

    def test_native_errors_are_raised_as_searchtools_error(self) -> None:
        with SearchToolsClient(
            root=self.fixture_root, library_path=self.library_path
        ) as client:
            with self.assertRaisesRegex(SearchToolsError, "Unknown tool: nope"):
                client._call_tool("nope", {})

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

            with SearchToolsClient(
                root=root, library_path=self.library_path
            ) as client:
                result = client.most_relevant_files(["A.java"], limit=5)
                text = result.render_text()

        self.assertIn("B.java", result.files)
        self.assertEqual([], result.not_found)
        self.assertIn("B.java", text)


if __name__ == "__main__":
    unittest.main()
