"""Privacy, normalization, and backwards compatibility of coarse value features."""
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
                self.assertEqual(len(first.value_shape), 8)
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

    def test_direct_constructor_without_shape_remains_supported(self) -> None:
        result = Finding("entropy", "high_entropy_token", "credential", Severity.MEDIUM,
                         "src/config.py", 1, 1, "****", "fingerprint")
        self.assertEqual(result.value_shape, ())
        vector = FeatureExtractor().extract(result)
        self.assertTrue(all(vector.value(name) == 0.0 for name in VALUE_SHAPE_FEATURES))

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

    def test_direct_shape_rejects_mutable_or_unsafe_values(self) -> None:
        result = finding("x")
        for invalid in ([0.0] * 8, ("raw-value",) * 8, (0.0,), (float("nan"),) * 8,
                        (float("inf"),) * 8, (-0.1,) * 8, (1.1,) * 8):
            with self.subTest(shape=invalid), self.assertRaises(ValueError):
                replace(result, value_shape=invalid)
