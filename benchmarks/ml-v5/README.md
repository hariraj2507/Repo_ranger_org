# ML-v5 evaluation: 2026-10-05

V5 adds finer quantized value statistics, candidate-matched field names and usage context, PHP/mapping/localization evidence, configuration paths and private-key structure. All findings remain visible. Legacy eight-value metadata are supported. Derived numeric statistics are not anonymization; datasets contain no raw credentials, source snippets or original paths.

## Frozen protocol

CredData pin: `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Previously inspected ranks 100–219 supply development: 120 selected repositories, 4,431/4,431 labeled files, 4,928 candidates (2,908 positive / 2,020 negative) in 102 candidate repositories. V4 training settings are retained: 100 trees, learning rate 0.1, regularization 1, inverse repository-size then equal-class-mass weighting. Validation loss alone selects depth 2/3/4; depth four wins. Internal comparisons are development evidence.

Model and feature semantics were frozen before untouched ranks 220–239 were evaluated. All 557 expected labeled files from 20 repositories were recovered, yielding 154 definite candidates (130 positive / 24 negative) in 14 repositories. Source was not executed; credentials were not verified online. Inclusive line-overlap matching excludes unknown, unlabeled and conflicting alerts from definite-label precision. Evaluation rejects development repository overlap.

## Candidate results at threshold 0.5

| Independent classifier | TP | FP | FN | TN | Precision | Recall | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|
| Heuristic | 32 | 0 | 98 | 24 | 100% | 24.62% | 0.381049 |
| Unrestricted v4 | 117 | 5 | 13 | 19 | 95.90% | 90.00% | 0.102980 |
| Unrestricted v5 | 123 | 7 | 7 | 17 | 94.62% | 94.62% | 0.069265 |

The v4 reference uses the new feature extraction, including changed PHP semantics; it does not reproduce the published a7 pipeline. V5 internal precision/recall are 88.36%/89.33%. The relative candidate gate fails precision regression against the conservative heuristic internally and independently. The fresh sample is positive-heavy, with only 24 negative candidates. Pooled specificity is 70.83%, while equal-repository specificity averages 26.19% across six negative-bearing repositories. Equal-repository precision/recall are 92.89%/96.62%. The model remains an experimental override; the bundled guarded v4 default is unchanged. No exposure-probability calibration is claimed.

## Overall scanner readiness

Raw scanning detects 139/489 positive annotations: **28.43% recall**. Definite alerts contain 130 true and 24 false positives: **84.42% labeled-alert precision**. Another 8 ambiguous, 72 unknown and 57 unlabeled alerts are separate. The scanner misses 350 positive annotations, including 122 NTLM-related and 57 UUID annotations. Generic annotated values require scope review before being treated as credential categories. ML evaluates only supplied candidates; its candidate recall cannot replace scanner recall.

`final/readiness.json` fails the existing 90% labeled-alert precision / 80% annotation-recall targets. Coverage is complete, with 489 positive and 1,802 negative annotations. Local regression checks passed 165 tests and all 52 detector fixtures. Detector revision remains 8; scoring revision 7 requires new saved-report baselines. These changes are not released; the latest published version remains `v0.2.0a7`.

The current wheel was built and installed in an isolated local target. A synthetic scan outside the checkout verified automatic loading of all 100 bundled trees, explicit v5 override loading, report redaction and scoring revision 7. Cross-platform CI for these changes remains pending.

## Reproduce

```sh
python -m backend.ml.tree_training benchmarks/ml-v5/development.jsonl models/creddata-v5-trees.json output/v5-training.json
python -m benchmarks.evaluate_model benchmarks/ml-v5/final/holdout.jsonl models/creddata-v5-trees.json output/v5-audit.json
python -m benchmarks.readiness benchmarks/ml-v5/final/holdout-detection.json --require-ready
reporanger /path/to/repository --model models/creddata-v5-trees.json --format json
```

The readiness command intentionally fails. Source acquisition uses `python -m benchmarks.creddata` with `--repositories 20 --offset 220 --git-fallback --original-paths --max-file-mib 16` and optional `--download`. Original source stays in ignored caches. Hashes and per-repository metrics are recorded in the audit. `pre-localization.jsonl` and `pre-localization-training.json` preserve the earlier finer-shape/field-context pilot before localization/PHP evidence; it was not independently evaluated.
