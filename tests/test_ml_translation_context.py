"""Translation evidence is structural and never suppresses credentials."""
import unittest
from backend.analysis_pipeline import FindingAnalyzer
from backend.ml.feature_extractor import FeatureExtractor
from tests.test_improvements import repo


class TranslationContextTests(unittest.TestCase):
    def features(self, source, path):
        return [(item, FeatureExtractor().extract(item.finding, item.validation, item.context))
                for item in FindingAnalyzer().analyze(repo(source, path))]

    def test_json_and_php_dictionary_evidence_does_not_require_locale_path(self):
        for source, path in (
            ('{"password":"Password required", "save":"Save changes", "cancel":"Cancel"}', 'ui.json'),
            ("<?php return ['password' => 'Password required', 'save' => 'Save changes', 'cancel' => 'Cancel'];", 'ui.php'),
            ('{"password":"Passwort", "save":"Änderungen speichern", "cancel":"Abbrechen"}', 'ui.json'),
        ):
            with self.subTest(path=path, source=source):
                items = self.features(source, path)
                self.assertTrue(items)
                _, vector = items[0]
                self.assertEqual(vector.value('mapping_literal_context'), 1)
                self.assertEqual(vector.value('translation_map_context'), 1)
                self.assertEqual(vector.value('localization_resource_context'), 0)

    def test_locale_path_does_not_make_real_credentials_translation_text(self):
        for source, path in (
            ('{"password":"hunter2", "host":"localhost", "port":5432}', 'locales/config.json'),
            ('password=hunter2\nhost=localhost\nport=5432', 'locales/config.properties'),
            ('{"password":"correct horse battery staple", "host":"localhost", "port":5432}', 'locales/config.json'),
            ('{"password":"qLxAaVmKpNrTsWdYcHeZuB", "save":"Save changes", "cancel":"Cancel"}', 'locales/en.json'),
        ):
            with self.subTest(path=path, source=source):
                items = self.features(source, path)
                self.assertTrue(items)
                self.assertTrue(all(vector.value('translation_map_context') == 0 for _, vector in items))

    def test_evidence_belongs_to_the_candidate_even_on_same_line(self):
        source = '{"password":"Password required", "db_password":"hunter2", "save":"Save changes", "cancel":"Cancel"}'
        items = self.features(source, 'locales/en.json')
        self.assertEqual(len(items), 2)
        self.assertEqual(sorted(vector.value('translation_map_context') for _, vector in items), [0, 1])
        self.assertTrue(all('hunter2' not in str(item.context) for item, _ in items))

    def test_single_mapping_and_assignment_are_not_translation_dictionary(self):
        for source in ('{"password":"Password required"}', 'password="Password required"'):
            items = self.features(source, 'locales/config.json')
            self.assertTrue(items)
            self.assertEqual(items[0][1].value('translation_map_context'), 0)
