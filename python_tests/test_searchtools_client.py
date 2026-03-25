from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bifrost_searchtools import SearchToolsClient, SymbolKindFilter


class SearchToolsClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(["cargo", "build", "--bin", "bifrost"], cwd=ROOT, check=True)
        cls.server_path = ROOT / "target" / "debug" / "bifrost"
        cls.fixture_root = ROOT / "tests" / "fixtures" / "testcode-java"

    def test_file_summary_uses_fixture_line_ranges(self) -> None:
        with SearchToolsClient(
            root=self.fixture_root, server_path=self.server_path
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
            root=self.fixture_root, server_path=self.server_path
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


if __name__ == "__main__":
    unittest.main()
