"""Compile every shipped Python entry point, not only imported test helpers."""
import ast
from pathlib import Path
import unittest


class ScriptSyntaxTests(unittest.TestCase):
    def test_all_entry_points_parse(self):
        for path in Path(__file__).parent.glob("*.py"):
            with self.subTest(script=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


if __name__ == "__main__":
    unittest.main()
