"""Matching must not turn ambiguous or unlabeled alerts into false positives."""
import unittest
from benchmarks.creddata import classify_alert


def row(label, start, end):
    return {'GroundTruth': label, 'LineStart': str(start), 'LineEnd': str(end)}


class CredDataMatchingTests(unittest.TestCase):
    def test_multiline_overlap_and_boundaries(self):
        rows = [row('T', 3, 8)]
        self.assertEqual(classify_alert(1, 3, rows), 'true_positive')
        self.assertEqual(classify_alert(8, 8, rows), 'true_positive')
        self.assertEqual(classify_alert(9, 9, rows), 'unlabeled')

    def test_conflicting_labels_are_ambiguous(self):
        self.assertEqual(classify_alert(4, 4, [row('T', 3, 5), row('F', 4, 4)]), 'ambiguous')

    def test_unknown_and_unlabeled_are_separate_from_negative(self):
        rows = [row('X', 1, 1), row('F', 2, 2)]
        self.assertEqual(classify_alert(1, 1, rows), 'unknown')
        self.assertEqual(classify_alert(2, 2, rows), 'false_positive')
        self.assertEqual(classify_alert(3, 3, rows), 'unlabeled')


class ArchiveDownloadTests(unittest.TestCase):
    def test_truncated_download_retries_without_reusing_partial_bytes(self):
        import http.client
        import io
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from benchmarks.creddata import download_archive
        class Broken(io.BytesIO):
            def read(self, size=-1):
                raise http.client.IncompleteRead(b'partial')
        with tempfile.TemporaryDirectory() as root:
            target=Path(root)/'source.tar.gz'
            with patch('benchmarks.creddata.urllib.request.urlopen', side_effect=[Broken(), io.BytesIO(b'complete')]) as fetch:
                download_archive('https://github.com/example/repo', 'a'*40, target)
            self.assertEqual(fetch.call_count,2)
            self.assertEqual(target.read_bytes(),b'complete')
            self.assertFalse(target.with_suffix('.partial').exists())

    def test_repeated_truncation_is_bounded_and_leaves_no_cache(self):
        import http.client
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from benchmarks.creddata import download_archive
        with tempfile.TemporaryDirectory() as root:
            target=Path(root)/'source.tar.gz'
            with patch('benchmarks.creddata.urllib.request.urlopen', side_effect=http.client.IncompleteRead(b'')) as fetch:
                with self.assertRaises(http.client.IncompleteRead):
                    download_archive('https://github.com/example/repo', 'a'*40, target)
            self.assertEqual(fetch.call_count,3)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix('.partial').exists())
