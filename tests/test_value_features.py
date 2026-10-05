"""Privacy, quantization, and backwards compatibility of safe value features."""
from dataclasses import FrozenInstanceError, asdict, replace
import json
import math
import unittest

from backend.detectors.finding import Finding, Severity, VALUE_SHAPE_FEATURES
from backend.ml import CandidateClassifier, FeatureExtractor


def finding(value: str) -> Finding:
    return Finding.from_match(
        detector="entropy", rule_id="high_entropy_token", category="credential",
        severity=Severity.MEDIUM, file_path="src/config.py", line_start=1,
        line_end=1, matched_value=value,
    )


class ValueFeatureTests(unittest.TestCase):
    def test_shapes_are_fixed_bounded_numeric_and_deterministic(self) -> None:
        for value in ("", "x", "A" * 100_000, "1234567890", "!@#$%^&*()", "字🙂é" * 100,
                      "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"):
            with self.subTest(length=len(value)):
                first = finding(value)
                self.assertIsInstance(first.value_shape, tuple)
                self.assertEqual(len(first.value_shape), len(VALUE_SHAPE_FEATURES))
                self.assertEqual(first.value_shape, finding(value).value_shape)
                vector = FeatureExtractor().extract(first)
                self.assertEqual(tuple(vector.value(name) for name in VALUE_SHAPE_FEATURES), first.value_shape)
                for feature in first.value_shape:
                    self.assertIs(type(feature), float)
                    self.assertTrue(math.isfinite(feature))
                    self.assertTrue(0.0 <= feature <= 1.0)

    def test_shape_metadata_contains_no_credential_material(self) -> None:
        value = "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB"
        result = finding(value)
        serialized = json.dumps(asdict(result))
        self.assertNotIn(value, serialized)
        self.assertNotIn(value[4:-4], serialized)
        self.assertNotIn(value, repr(FeatureExtractor().extract(result)))
        self.assertNotIn("matched_value", asdict(result))
        with self.assertRaises(FrozenInstanceError):
            result.value_shape = ()
        # Permuting characters within a syntax class retains no ordering data.
        self.assertEqual(result.value_shape, finding(value[::-1]).value_shape)

    def test_new_format_flags_do_not_retain_url_path_or_pattern_fragments(self) -> None:
        for value in ("https://private.example/path/sensitive-query?key=Ab12Cd34",
                      r"C:\private-directory\sensitive-config.json", "Ab1!" * 6):
            with self.subTest(value=value):
                result = finding(value)
                serialized = json.dumps(asdict(result))
                self.assertNotIn(value, serialized)
                self.assertNotIn(value[4:-4], serialized)
                self.assertNotIn(value, repr(FeatureExtractor().extract(result)))
                self.assertTrue(all(type(feature) is float for feature in result.value_shape))
        # A repetition flag reveals neither the characters nor the period itself.
        self.assertEqual(finding("Ab1!" * 4).value_shape, finding("Cd2@" * 4).value_shape)

    def test_direct_constructor_without_shape_remains_supported(self) -> None:
        result = Finding("entropy", "high_entropy_token", "credential", Severity.MEDIUM,
                         "src/config.py", 1, 1, "****", "fingerprint")
        self.assertEqual(result.value_shape, ())
        vector = FeatureExtractor().extract(result)
        self.assertTrue(all(vector.value(name) == 0.0 for name in VALUE_SHAPE_FEATURES))

    def test_legacy_eight_value_shapes_remain_supported(self) -> None:
        legacy = (0, 0.125, 0.25, 0.5, 0.75, 1, 0, 1)
        result = replace(finding("x"), value_shape=legacy)
        self.assertEqual(result.value_shape, legacy)
        vector = FeatureExtractor().extract(result)
        self.assertEqual(tuple(vector.value(name) for name in VALUE_SHAPE_FEATURES[:8]), legacy)
        self.assertTrue(all(vector.value(name) == 0.0 for name in VALUE_SHAPE_FEATURES[8:]))
        full = replace(result, value_shape=legacy + (0,) * (len(VALUE_SHAPE_FEATURES) - 8))
        full_vector = FeatureExtractor().extract(full)
        self.assertEqual(tuple(full_vector.value(name) for name in VALUE_SHAPE_FEATURES),
                         tuple(vector.value(name) for name in VALUE_SHAPE_FEATURES))

    def test_default_classifier_is_unchanged_by_shape(self) -> None:
        classifier = CandidateClassifier()
        extractor = FeatureExtractor()
        for value in ("", "1234567890abcdef", "b258fd87-5319-4156-8f40-9929bba27fe3",
                      "q7Lx9Aa2Vm3Kp8Nr5Ts1Wd6Yc4He0ZuB", "!" * 80):
            with self.subTest(value=value):
                shaped = finding(value)
                self.assertEqual(classifier.classify(extractor.extract(shaped)),
                                 classifier.classify(extractor.extract(replace(shaped, value_shape=()))))
        self.assertTrue(set(VALUE_SHAPE_FEATURES).isdisjoint(classifier._DEFAULT_WEIGHTS))

    def test_bins_and_format_flags(self) -> None:
        extractor = FeatureExtractor()
        zeros = extractor.extract(finding(""))
        self.assertTrue(all(zeros.value(name) == 0 for name in VALUE_SHAPE_FEATURES))
        same = extractor.extract(finding("A" * 16))
        self.assertEqual(same.value("value_entropy_bin"), 0.0)
        self.assertEqual(same.value("value_uppercase_ratio_bin"), 1.0)
        self.assertEqual(same.value("value_length_bin"), 5 / 12)
        self.assertEqual(extractor.extract(finding("1" * 15 + "a")).value("value_digit_ratio_bin"), 0.75)
        for value, flag in (("b258fd87-5319-4156-8f40-9929bba27fe3", "value_uuid_like"),
                            ("0123456789abcdef", "value_hex_like"),
                            ("c29tZS10ZXN0LXZhbHVl", "value_base64_like")):
            self.assertEqual(extractor.extract(finding(value)).value(flag), 1.0)
        malformed = extractor.extract(finding("b258fd87-5319-4156-8f40-9929bba27fg3"))
        self.assertEqual(malformed.value("value_uuid_like"), 0.0)

    def test_original_feature_order_and_values_are_preserved(self) -> None:
        self.assertEqual(VALUE_SHAPE_FEATURES[:8], (
            "value_length_bin", "value_entropy_bin", "value_digit_ratio_bin",
            "value_uppercase_ratio_bin", "value_symbol_ratio_bin", "value_uuid_like",
            "value_hex_like", "value_base64_like",
        ))
        self.assertEqual(finding("A" * 16).value_shape[:8], (5 / 12, 0, 0, 1, 0, 0, 1, 1))
        self.assertEqual(finding("ABab12!?" * 2).value_shape[:8],
                         (5 / 12, 3 / 8, 0.25, 0.25, 0.25, 0, 0, 0))

    def test_detail_length_and_entropy_quantization(self) -> None:
        extractor = FeatureExtractor()
        for length, expected in ((1, 0), (3, 0), (4, 1 / 64), (7, 1 / 64),
                                 (8, 2 / 64), (255, 63 / 64), (256, 1), (4096, 1)):
            with self.subTest(length=length):
                self.assertEqual(extractor.extract(finding("x" * length)).value("value_length_detail_bin"), expected)
        two_chars = extractor.extract(finding("AB" * 6))
        three_chars = extractor.extract(finding("ABC" * 4))
        self.assertEqual(two_chars.value("value_entropy_bin"), three_chars.value("value_entropy_bin"))
        self.assertEqual(two_chars.value("value_entropy_detail_bin"), 2 / 16)
        self.assertEqual(three_chars.value("value_entropy_detail_bin"), 3 / 16)
        unique_chars = "".join(chr(0x1000 + index) for index in range(512))
        self.assertEqual(extractor.extract(finding(unique_chars)).value("value_entropy_detail_bin"), 1)

    def test_detail_character_ratios_use_sixteenth_bins(self) -> None:
        extractor = FeatureExtractor()
        for char, coarse, detail in (("1", "value_digit_ratio_bin", "value_digit_ratio_detail_bin"),
                                     ("A", "value_uppercase_ratio_bin", "value_uppercase_ratio_detail_bin"),
                                     ("!", "value_symbol_ratio_bin", "value_symbol_ratio_detail_bin")):
            with self.subTest(feature=detail):
                one = extractor.extract(finding(char + "a" * 15))
                three = extractor.extract(finding(char * 3 + "a" * 13))
                self.assertEqual(one.value(coarse), three.value(coarse))
                self.assertEqual(one.value(detail), 1 / 16)
                self.assertEqual(three.value(detail), 3 / 16)
                self.assertEqual(extractor.extract(finding(char + "a" * 16)).value(detail), 0)
                self.assertEqual(extractor.extract(finding(char * 16)).value(detail), 1)
        unicode_value = extractor.extract(finding("字🙂É١" * 4))
        self.assertEqual(unicode_value.value("value_digit_ratio_detail_bin"), 0.25)
        self.assertEqual(unicode_value.value("value_uppercase_ratio_detail_bin"), 0.25)
        self.assertEqual(unicode_value.value("value_symbol_ratio_detail_bin"), 0.25)

    def test_url_and_path_syntax_flags(self) -> None:
        extractor = FeatureExtractor()
        for value in ("https://example.com", "http://localhost:8080/path", "HTTPS://example.com/a?b=c#d"):
            with self.subTest(url=value):
                vector = extractor.extract(finding(value))
                self.assertEqual(vector.value("value_url_like"), 1)
                self.assertEqual(vector.value("value_path_like"), 0)
        for value in ("/etc/service/config", "./config.json", "../secrets/key", "src/config.py",
                      r"C:\Users\example\config.json", r"src\config.py"):
            with self.subTest(path=value):
                vector = extractor.extract(finding(value))
                self.assertEqual(vector.value("value_path_like"), 1)
                self.assertEqual(vector.value("value_url_like"), 0)
        for value in ("plain-value", "config.json", "https://", "http:///missing-host", "http://bad host/path"):
            with self.subTest(value=value):
                self.assertEqual(extractor.extract(finding(value)).value("value_url_like"), 0)
        self.assertEqual(extractor.extract(finding("config.json")).value("value_path_like"), 0)

    def test_repetition_requires_full_short_pattern_and_minimum_length(self) -> None:
        extractor = FeatureExtractor()
        for value in ("x" * 12, "ab" * 6, "abc" * 4, "abcd" * 3, "abcdefgh" * 3):
            with self.subTest(repeated=value):
                self.assertEqual(extractor.extract(finding(value)).value("value_repeated_pattern"), 1)
        for value in ("x" * 11, "abcdef" * 2, "abcdefgh" * 2, "abcdefghi" * 3,
                      "abc" * 4 + "x", "abcdefghijkl"):
            with self.subTest(non_repeated=value):
                self.assertEqual(extractor.extract(finding(value)).value("value_repeated_pattern"), 0)

    def test_direct_shape_rejects_mutable_or_unsafe_values(self) -> None:
        result = finding("x")
        for invalid in ([0.0] * 8, ("raw-value",) * 8, (0.0,), (float("nan"),) * 8,
                        (float("inf"),) * 8, (-0.1,) * 8, (1.1,) * 8,
                        [0.0] * len(VALUE_SHAPE_FEATURES), (0.0,) * 9, (0.0,) * 15,
                        (0.0,) * 17, (True,) * len(VALUE_SHAPE_FEATURES),
                        ("raw-value",) * len(VALUE_SHAPE_FEATURES),
                        (float("nan"),) * len(VALUE_SHAPE_FEATURES),
                        (float("inf"),) * len(VALUE_SHAPE_FEATURES),
                        (-0.1,) * len(VALUE_SHAPE_FEATURES), (1.1,) * len(VALUE_SHAPE_FEATURES)):
            with self.subTest(shape=invalid), self.assertRaises(ValueError):
                replace(result, value_shape=invalid)
