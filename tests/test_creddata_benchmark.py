"""Matching must not turn ambiguous or unlabeled alerts into false positives."""
import unittest
import gzip
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
            with patch('benchmarks.creddata.urllib.request.urlopen', side_effect=[Broken(), io.BytesIO(gzip.compress(b'complete'))]) as fetch:
                download_archive('https://github.com/example/repo', 'a'*40, target)
            self.assertEqual(fetch.call_count,2)
            self.assertEqual(gzip.decompress(target.read_bytes()),b'complete')
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


class TriageBenchmarkTests(unittest.TestCase):
    def test_low_priority_alerts_remain_in_raw_detection_counts(self):
        import csv,tempfile
        from pathlib import Path
        from unittest.mock import patch
        from benchmarks.creddata import evaluate
        source='token="ghp_'+'aB3dE6gH'*4+'aB3d'+'"\nexpected_password="hunter2"\n'
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);meta=root/'labels.csv'
            fields=['FileID','FilePath','LineStart','LineEnd','GroundTruth','Category']
            with meta.open('w',newline='') as output:
                writer=csv.DictWriter(output,fieldnames=fields);writer.writeheader()
                for line,label in ((1,'T'),(2,'F')):
                    writer.writerow(dict(FileID='file',FilePath='app.py',LineStart=line,LineEnd=line,GroundTruth=label,Category='credential'))
            with patch('benchmarks.creddata.selected_repositories',return_value=([('repo','a'*40,'https://github.com/example/repo',meta)],1)), patch('benchmarks.creddata.subprocess.check_output',return_value='revision'), patch('benchmarks.creddata.source_members',return_value=[('file',len(source),source.encode())]):
                result=evaluate(root,root/'cache',1,triage=True)
            self.assertEqual(result['counts']['alerts'],2)
            self.assertEqual(result['counts']['positive_annotations_detected'],1)
            self.assertEqual(result['triage']['counts']['low_false_positive'],1)
            self.assertEqual(result['triage']['counts']['medium_or_higher_true_positive'],1)


class OriginalPathTests(unittest.TestCase):
    def test_archive_paths_stay_in_memory_for_filename_features(self):
        import hashlib,io,tarfile,tempfile
        from collections import Counter
        from pathlib import Path
        from benchmarks.creddata import source_members
        path='src/login.test.ts'
        file_id=hashlib.sha256(path.encode()).hexdigest()[:8]
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);archive=root/'source.tar.gz'
            with tarfile.open(archive,'w:gz') as out:
                member=tarfile.TarInfo('prefix/'+path);member.size=3
                out.addfile(member,io.BytesIO(b'abc'))
            names={}
            items=list(source_members(archive,{file_id},root,'a'*40,'https://github.com/example/repo',False,Counter(),original_paths=names))
            self.assertEqual(items,[(file_id,3,b'abc')])
            self.assertEqual(names,{file_id:path})


class SilentArchiveTruncationTests(unittest.TestCase):
    def test_silent_eof_retries_and_repairs_corrupt_cache(self):
        import io, tempfile
        from pathlib import Path
        from unittest.mock import patch
        from benchmarks.creddata import download_archive
        complete=gzip.compress(b'archive content')
        with tempfile.TemporaryDirectory() as root:
            target=Path(root)/'source.tar.gz'
            target.write_bytes(complete[:-5])
            with patch('benchmarks.creddata.urllib.request.urlopen',side_effect=[io.BytesIO(complete[:-5]),io.BytesIO(complete)]) as fetch:
                download_archive('https://github.com/example/repo','a'*40,target)
            self.assertEqual(fetch.call_count,2)
            self.assertEqual(target.read_bytes(),complete)
            self.assertFalse(target.with_suffix('.partial').exists())

    def test_silent_eof_never_publishes_partial_cache(self):
        import io, tempfile
        from pathlib import Path
        from unittest.mock import patch
        from benchmarks.creddata import download_archive
        with tempfile.TemporaryDirectory() as root:
            target=Path(root)/'source.tar.gz'
            with patch('benchmarks.creddata.urllib.request.urlopen',side_effect=lambda *a,**kw:io.BytesIO(gzip.compress(b'data')[:-5])) as fetch:
                with self.assertRaises(EOFError):
                    download_archive('https://github.com/example/repo','a'*40,target)
            self.assertEqual(fetch.call_count,3)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix('.partial').exists())
