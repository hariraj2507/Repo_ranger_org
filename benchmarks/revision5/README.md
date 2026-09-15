# Revision 5 improvement evaluation

The evaluation used Samsung CredData metadata pinned at `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Source archives and filtered Git objects were read without checkout, execution or online credential validation. No corpus source or raw credentials are committed. Numeric candidate features and aggregate results are included.

All 2,273 labeled files across 80 repositories were processed, covering 10,996 annotations. Seventy repositories formed the development pool; ten others were reserved for the final comparison. These are sampled labeled files, not all files in each repository or the full CredData corpus. CredData positive labels include test credentials and do not establish active exposure.

## Independent detector comparison

Both detectors used the same 282 files, 1,086 annotations and line-overlap matcher. Revision 4 used the entropy detector from commit `c4fa9dc12a1c5622e74791b12520e76fcca27037`. Revision 5 added the contextual syntax and shorter-password rules before evaluating these repositories.

| Measure | Revision 4 | Revision 5 |
| --- | ---: | ---: |
| Positive annotations detected / total | 30 / 234 | 46 / 234 |
| Positive annotation recall | 12.8% | 19.7% |
| Alerts matching positive labels | 27 | 43 |
| Alerts matching negative labels | 2 | 5 |
| Precision among definitely labeled alerts | 93.1% | 89.6% |
| Unknown-label / unlabeled alerts excluded | 3 / 1 | 4 / 2 |

The detector found 16 additional positive annotations, with three additional false-positive alerts. This is a recall/precision tradeoff, not improvement in every metric. It still missed 188 positive annotations. Recall counts annotations while precision counts alerts; do not combine them into F1. Inclusive line matching can associate different values on the same line, and unreviewed alerts are not assumed false. Category counts and per-repository results are in the JSON files.

The earlier 20 missing Composer files were recovered from Git, along with seven other archive omissions in the development pool. GitHub rejected the WebKit archive with HTTP 422; a filtered Git fetch recovered all 76 labeled files. Four were 6.4-9.3 MB, so this benchmark explicitly used a 16 MiB cap. This does not change the application's smaller file limits. No missing, oversized or undecodable files remain in this final comparison. Aggregate coverage across development and evaluation includes 103 Git-recovered files.

## ML and calibration

The 70-repository development pool produced 391 candidates with definite T/F labels. Whole-repository train/validation/test partitions contain 232/78/81 candidate rows. Training and Platt calibration give equal total weight to each repository. L2 strength is selected on validation loss, and calibration uses validation only. The test partition is not used by the training algorithm; it was inspected during development, so the separate ten-repository result is the final external evaluation.

The independent repositories produced 48 definite candidate labels (43 positive and 5 negative). At classifier threshold 0.5, the default scored 5 true positives and 1 false positive; the trained model scored all 48 as positive. Brier error improved from 0.3914 to 0.0935, but this positive-heavy sample and the all-positive predictions do not demonstrate strong discrimination. On the internal 81-row test, Brier worsened from 0.2625 to 0.3705 and precision fell from 0.8333 to 0.5679. The quality gate failed, and the trained model remains opt-in.

`external-training.json` and `independent-model.json` include reliability bins, expected calibration error and observed label counts in each risk band. Those audits expose score behavior; they do not calibrate risk scores into exposure probabilities. The underlying features cannot always distinguish synthetic, public and secret values, and contextual labels are approximate.

## Reproduction

Use the pinned CredData checkout from the parent benchmark README. Repository ranking is SHA-256 of `reporanger-external-pilot-v1` plus metadata repository ID. Development comprises ranks 0-29 and 40-79. Independent evaluation comprises ranks 30-39. The snapshot has no duplicate repository URLs.

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 30 --download --git-fallback --features output/primary.jsonl --output output/primary.json
python -m benchmarks.creddata --metadata tmp/creddata --repositories 40 --offset 40 --download --git-fallback --features output/extension.jsonl --output output/extension.json
python -m benchmarks.creddata --metadata tmp/creddata --repositories 10 --offset 30 --max-file-mib 16 --download --git-fallback --features output/independent.jsonl --output output/independent.json
python -m backend.ml.training benchmarks/external-triage.jsonl models/creddata-experimental.json output/training.json --external
python -m benchmarks.evaluate_model benchmarks/external-holdout.jsonl models/creddata-experimental.json output/model-evaluation.json
```

The checked-in development rows concatenate primary then extension exports. The model evaluator rejects repository overlap with any model-development partition. The archived baseline detector comparison can be reproduced in an isolated copy of the current harness with `backend/detectors/entropy_detector.py` restored from the revision-4 commit and report revision marked 4. Corpus downloads remain in ignored `tmp/`; no original source is redistributed. Original source licenses apply, and upstream metadata is Apache-2.0. This inspected sample must be treated as diagnostic data in future tuning.
