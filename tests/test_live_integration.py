import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from backend.analysis_pipeline import FindingAnalyzer
from backend.application.cli import main
from backend.application.scan_orchestrator import ScanOrchestrator
from backend.engine.report_generator import ReportGenerator
from backend.validators.live_github import LiveCheck
from backend.validators.router import ValidatorRouter
from tests.test_improvements import repo


TOKEN = 'ghp_' + 'aB3dE7fG9hJ2kL4mN6pQ8rS1tU5vW0xY3zA9'


class LiveVerificationIntegrationTests(unittest.TestCase):
    def test_live_outcomes_do_not_rewrite_format_validity_or_remove_findings(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            (path/'settings.py').write_text('token="' + TOKEN + '"', encoding='utf8')
            for status in ('active', 'inactive', 'inconclusive', 'skipped'):
                verifier = Mock()
                verifier.verify.return_value = LiveCheck(status, 'fixed_reason')
                result = ScanOrchestrator(validator_router=ValidatorRouter(live_github=verifier)).scan(path)
                data = ReportGenerator().as_dict(result.source, result.score, result.assessments)
                finding = next(f for f in data['findings'] if f['rule_id']=='github_token')
                self.assertTrue(finding['validation']['format_valid'])
                self.assertEqual(finding['validation']['live_verified'], status=='active')
                self.assertEqual(finding['validation']['live_check']['status'], status)
                self.assertNotIn(TOKEN, json.dumps(data))

    def test_cli_is_offline_unless_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as td, patch('backend.application.cli.GitHubLiveVerifier') as factory:
            (Path(td)/'config.py').write_text('token="' + TOKEN + '"', encoding='utf8')
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                self.assertEqual(main([td,'--format','json']),0)
            factory.assert_not_called()
            data=json.loads(stream.getvalue())
            self.assertFalse(data['scan_profile']['live_verification']['github'])
            factory.return_value.verify.return_value=LiveCheck('active','github_authenticated')
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):
                self.assertEqual(main([td,'--format','json','--verify-github']),0)
            factory.assert_called_once_with()
            data=json.loads(stream.getvalue())
            self.assertTrue(data['scan_profile']['live_verification']['github'])
            self.assertTrue(data['findings'][0]['validation']['live_verified'])

    def test_unsupported_findings_never_reach_live_verifier(self):
        verifier=Mock()
        FindingAnalyzer(router=ValidatorRouter(live_github=verifier)).analyze(repo('password="hunter2"'))
        verifier.verify.assert_not_called()
