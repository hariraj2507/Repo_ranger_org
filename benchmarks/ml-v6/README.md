# ML-v6 evaluation: 2026-10-06

V6 is an experimental candidate-triage model. Its validation policies and fresh audit fail; it must not replace the bundled guarded v4 default. Scores are threshold-shifted triage estimates, not probabilities that a credential is active. The frozen v6 artifacts are retained even though its fresh sample has since been inspected for follow-up development.

## Data and frozen protocol

CredData is pinned to `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`, with deterministic seed `reporanger-external-pilot-v1`. Previously inspected ranks 100–239 supply 140 selected development repositories. All 4,988 expected labeled files were recovered. The numeric development dataset contains 5,144 definite candidate labels (3,100 positive / 2,044 negative) in 117 candidate-bearing repositories. It exports features, labels and repository groups without credential values, snippets or original paths; quantized value statistics remain secret-derived metadata, rather than anonymization.

Whole-repository partitions contain 3,086 training, 1,029 validation and 1,029 internal test rows across 69, 22 and 26 repositories respectively. Class counts are 1,481/1,605, 845/184 and 774/255 positive/negative. These partitions are development evidence. Fitting uses inverse repository-size then equal-global-class-mass weighting. Repeated feature vectors retain weighted mass, but do not count as separate vectors for leaf support.

Before the fresh audit, the trainer declared six configurations: depths 2/3/4, each with regularization 5 and at least 8 distinct leaf vectors from 2 sources, or regularization 15 and at least 20 vectors from 3 sources. All use 100 trees, learning rate 0.08, minimum leaf weight 8 and minimum split gain 0.1. Thirteen fixed thresholds from 0.35 through 0.95 are checked only on validation data.

The validation policy requires pooled and repository/class-weighted precision at least 90%, recall at least 80% and specificity at least 50%, plus equal-repository specificity at least 50% across at least five negative-bearing repositories. **None of the six configurations passed at any declared threshold.** The explicitly failed fallback selects minimum balanced validation log loss, then a threshold that retains both recall floors where possible. This is a fallback experiment, not policy acceptance.

`tree-training.json` records the actual selected configuration: depth 3, regularization 15, at least 20 vectors / 3 sources, and decision threshold 0.35. A logit offset of `0.6190392084062235` maps that raw cutoff to runtime score 0.5; it is not probability calibration. Selected validation metrics are pooled precision 89.49%, recall 97.75%, specificity 47.28%; weighted precision 72.83%, recall 89.59%, specificity 66.58%; macro specificity 57.09% across 12 negative-bearing repositories. The policy remains failed.

The shifted internal test reports 88.32% precision, 89.92% recall, 63.92% specificity and Brier error 0.130046, versus heuristic 97.85% precision / 23.51% recall. The relative candidate gate fails precision regression. Internal scores cannot establish independent generalization.

## Initially independent audit: ranks 240–259

The model and settings were frozen before evaluating 20 new repositories. All 662 expected files were recovered. The resulting dataset has 469 definite candidates (124 positive / 345 negative) in 18 candidate-bearing repositories; development group overlap is rejected. Inclusive line-overlap labels describe annotated candidates, not authenticated credentials. Source code was never executed and corpus credentials were never checked online.

| Candidate classifier at runtime score 0.5 | TP | FP | FN | TN | Precision | Recall | Specificity | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Heuristic | 14 | 22 | 110 | 323 | 38.89% | 11.29% | 93.62% | 0.280848 |
| V6 | 116 | 285 | 8 | 60 | 28.93% | 93.55% | 17.39% | 0.453557 |

V6 equal-repository precision/recall are 81.57%/94.32%. Macro specificity is 44.61% across 12 negative-bearing repositories. The gap between pooled and macro precision exposes strong repository-size effects; neither metric substitutes for the other. `final/model-audit.json` also reports AUROC, average precision, reliability bins and per-repository results.

`final/readiness.json` requires at least 20 selected repositories, complete file coverage, at least 100 candidates of each class, pooled precision/recall of 90%/80%, and pooled/macro specificity of at least 50% with at least five negative-bearing repositories. It fails pooled precision, pooled specificity and macro specificity. The older relative gate also fails specificity, precision regression and Brier improvement. Default deployment is not authorized by candidate acceptance alone, even if a future sample passes.

Diagnostics after this audit found that 263 of the 285 ML false positives were JSON localization labels. That diagnosis makes ranks 240–259 inspected development evidence for any subsequent context changes or model tuning. The saved v6 audit remains an evaluation of its originally frozen model; it cannot supply untouched evidence for a later model.

## Raw detector units and scanner readiness

Raw detection produced 124 true-positive and 345 false-positive definite alerts: **26.44% labeled-alert precision**. It detected 125 of 237 positive source annotations: **52.74% annotation recall**. Another 6 ambiguous, 108 unknown and 42 unlabeled alerts are excluded from definite precision. There are 3,697 negative and 155 unknown source annotations. Alert counts and annotation counts are different units: one alert can overlap multiple annotations.

The candidate dataset includes emitted definite alerts only. V6's 93.55% candidate recall cannot recover the 112 missed source annotations or replace the scanner's 52.74% recall. Both full-scanner thresholds fail. The corresponding historical raw report is `../revision9/independent.json`; `final/holdout-detection.json` also preserves coverage. Neither this sample nor its scores establish production readiness, natural-prevalence calibration or active exposure.

## Reproduce the frozen artifacts

```sh
python -m backend.ml.tree_training benchmarks/ml-v6/development.jsonl models/creddata-v6-trees.json output/v6-training.json
python -m benchmarks.evaluate_model benchmarks/ml-v6/final/holdout.jsonl models/creddata-v6-trees.json output/v6-audit.json
python -m benchmarks.model_readiness benchmarks/ml-v6/final/model-audit.json benchmarks/ml-v6/final/holdout-detection.json output/v6-readiness.json --model models/creddata-v6-trees.json --dataset benchmarks/ml-v6/final/holdout.jsonl --independence independent --require-ready
reporanger /path/to/repository --model models/creddata-v6-trees.json --format json
```

Use the v6 trainer and feature semantics associated with `tree-training.json` to reproduce that model; later feature changes can produce a different model even when the grid is unchanged. The readiness command intentionally fails. Acquisition uses `python -m benchmarks.creddata` with `--repositories 20 --offset 240 --git-fallback --original-paths --max-file-mib 16`, adding `--download` when needed. Original source stays in ignored caches. Dataset/model hashes and repository partitions are recorded in the reports.
