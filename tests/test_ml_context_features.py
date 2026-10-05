import unittest
from tests.test_improvements import repo
from backend.analysis_pipeline import FindingAnalyzer
from backend.ml.feature_extractor import FeatureExtractor

class MlContextFeatureTests(unittest.TestCase):
    def features(self,source,path='config.py'):
        items=FindingAnalyzer().analyze(repo(source,path))
        return [(item,FeatureExtractor().extract(item.finding,item.validation,item.context)) for item in items]

    def test_semantic_names_belong_to_the_matched_value(self):
        items=self.features('public_key="q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"; password="hunter2"')
        self.assertEqual(len(items),2)
        password=next(v for i,v in items if i.finding.rule_id=='hardcoded_password')
        public=next(v for i,v in items if i.finding.rule_id=='high_entropy_token')
        self.assertEqual(password.value('credential_name_context'),1)
        self.assertEqual(password.value('password_name_context'),1)
        self.assertEqual(public.value('credential_name_context'),0)
        self.assertEqual(public.value('password_name_context'),0)

    def test_weak_xml_and_setter_passwords_have_usage_features(self):
        for source,path in [('<password>hunter2</password>','config.xml'),('setPassword("hunter2")','app.java')]:
            with self.subTest(path=path):
                items=self.features(source,path);self.assertEqual(len(items),1)
                self.assertEqual(items[0][1].value('credential_usage_context'),1)
                self.assertEqual(items[0][1].value('password_literal_signal'),1)
        self.assertEqual(self.features('<password>hunter2</password>','config.xml')[0][1].value('xml_value_context'),1)

    def test_public_metadata_and_configuration_features(self):
        items=self.features('token_checksum="q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"','settings.json')
        self.assertEqual(len(items),1)
        vector=items[0][1]
        self.assertEqual(vector.value('public_metadata_context'),1)
        self.assertEqual(vector.value('token_name_context'),1)
        self.assertEqual(vector.value('configuration_file'),1)
        self.assertEqual(vector.value('quoted_literal_context'),1)
        self.assertTrue(all(type(v) in (int,float) and 0<=v<=1 for v in vector.values.values()))

    def test_php_localized_label_is_distinguished_from_application_password(self):
        translated=self.features("<?php return ['password' => 'Password required'];",'languages/en/messages.php')
        credential=self.features("<?php $password = 'hunter2';",'config.php')
        self.assertEqual(len(translated),1);self.assertEqual(len(credential),1)
        vector=translated[0][1]
        self.assertEqual(vector.value('mapping_literal_context'),1)
        self.assertEqual(vector.value('localization_resource_context'),1)
        self.assertEqual(vector.value('php_source_file'),1)
        self.assertEqual(translated[0][0].context.language,'php')
        self.assertEqual(credential[0][1].value('mapping_literal_context'),0)
        self.assertEqual(credential[0][1].value('localization_resource_context'),0)
        # Both remain visible; ML receives evidence rather than a hard exclusion.
        self.assertEqual(vector.value('password_name_context'),1)

    def test_environment_basenames_are_configuration(self):
        for path in ('.env','.env.production','.env.local'):
            with self.subTest(path=path):
                items=self.features('password="hunter2"',path)
                self.assertEqual(len(items),1)
                self.assertEqual(items[0][1].value('configuration_file'),1)
