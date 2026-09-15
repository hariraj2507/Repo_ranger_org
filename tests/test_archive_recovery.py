import io,tarfile,tempfile,subprocess,hashlib,shutil
from collections import Counter
from pathlib import Path
import unittest
from benchmarks.creddata import source_members

@unittest.skipUnless(shutil.which('git'),'Git is required')
class ArchiveRecoveryTests(unittest.TestCase):
    def test_missing_archive_file_is_recovered_from_pinned_git_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            repository=root/'source';repository.mkdir()
            def git(*args):
                return subprocess.check_output(['git','-C',str(repository),*args],stderr=subprocess.PIPE)
            git('init')
            content=b'password=h7Rk92za\n'
            (repository/'settings.env').write_bytes(content)
            git('add','settings.env')
            git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture')
            commit=git('rev-parse','HEAD').decode().strip()
            archive=root/'fixture.tar.gz'
            with tarfile.open(archive,'w:gz') as tar:
                info=tarfile.TarInfo('root/README');info.size=4
                tar.addfile(info,io.BytesIO(b'test'))
            cache=root/'cache';cache.mkdir()
            file_id=hashlib.sha256(b'settings.env').hexdigest()[:8]
            counts=Counter()
            files=list(source_members(archive,{file_id},cache,commit+'0'*20,str(repository),True,counts))
            self.assertEqual(files,[(file_id,len(content),content)])
            self.assertEqual(counts['git_recovered_files'],1)
            self.assertFalse((cache/'settings.env').exists())
