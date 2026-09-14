from pathlib import Path
import tempfile
import unittest

from backend.scanner.models import RepositoryValidationError
from backend.scanner.parser import RepositoryParser
from backend.scanner.repo_validator import RepositoryValidator


class RepositoryParserTests(unittest.TestCase):
    def test_parser_returns_normalized_eligible_text_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_bytes("caf\u00e9\r\nprint('ok')\r".encode("utf-8"))
            (root / "image.png").write_bytes(b"\x89PNG\x00binary")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "dependency.js").write_text("ignored")

            result = RepositoryParser().parse(root)

            self.assertEqual(result.file_count, 1)
            self.assertEqual(result.files[0].metadata.relative_path, "src/app.py")
            self.assertEqual(result.files[0].text, "caf\u00e9\nprint('ok')\n")
            self.assertEqual(result.metadata.total_files_seen, 2)
            self.assertEqual(result.metadata.skipped_files, {"binary_extension": 1})

    def test_parser_handles_utf16_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "readme.txt").write_text("hello", encoding="utf-16")
            result = RepositoryParser().parse(root)
            self.assertEqual(result.files[0].text, "hello")
            self.assertEqual(result.files[0].metadata.encoding, "utf-16")

    def test_validator_rejects_missing_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(RepositoryValidationError):
                RepositoryValidator().validate_local_path(Path(temporary_directory) / "missing")
