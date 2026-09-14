# External detection pilot, 2026-09-14

The frozen revision-3 detector has a substantial recall gap on this independent sample from [Samsung CredData](https://github.com/Samsung/CredData). No detector rules, thresholds, or model weights were tuned using these results.

Five repositories were selected deterministically from 337 repositories with metadata at commit `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. All 144 labeled files were scanned, with no acquisition, decoding, size or missing-file exclusions. The source files came from original pinned archives, without upstream obfuscation. This is a small repository sample, not a full-corpus result or production accuracy estimate.

| Measure | Result |
| --- | ---: |
| Annotations | 660 |
| Positive / negative / unknown annotations | 191 / 396 / 73 |
| Positive annotations detected / missed | 35 / 156 |
| Positive annotation recall | 18.3% |
| Alerts matching positive / negative labels | 34 / 10 |
| Precision among alerts with definite labels | 77.3% |
| Unlabeled alerts, excluded from precision | 28 |

Matching uses inclusive line overlap because the detector does not expose character spans. Recall counts annotations; precision counts alerts. One alert can overlap multiple annotations, so these are different units and should not be combined into an F1 score. Mixed-label overlaps are classified as ambiguous; X labels and unlabeled alerts are excluded from precision. A match on the same line can be a different value, so these are approximate location-based results. No true-negative count or overall accuracy is claimed.

CredData labels include credential-like examples and test credentials; a positive label does not establish an active credential or exploitable exposure. Only labeled files were sampled, not every file in each repository. The pilot exercises the raw default detector, not repository filtering, historical scanning, custom rules, offline validation, ML ranking or score calibration. These results therefore do not calibrate risk scores as probabilities.

Category-level counts suggest where to investigate next: 53 of 57 annotations labeled exactly `Password` were missed; all 36 labeled `Auth` were missed; 28 of 29 labeled `PEM Private Key` were detected. Full category combinations are preserved in the JSON. Label categories alone do not establish the implementation cause of a miss. UUID and other benchmark categories also need a documented product-scope decision before broadening detection.

The next accuracy work should create separate development examples for password/authentication syntax and additional token families, then evaluate on another untouched repository sample. This pilot is now diagnostic data and must not be reused as a claimed held-out evaluation after tuning. The experimental ML model remains opt-in: training on artificial metadata does not resolve detector misses.
