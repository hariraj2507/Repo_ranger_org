# Frozen v7 experiment

V7 adds source-derived translation-map context to the candidate scorer. It was trained on the previously inspected ranks 100–239 and frozen before the untouched ranks 260–279 evaluation. It is an experimental `--model models/creddata-v7-trees.json` override. The bundled guarded v4 model was not changed.

The development set contains 5,144 labeled candidates from 140 selected repositories. Whole-repository partitions contain 3,086 training, 1,029 validation and 1,029 internal-test rows. Six predeclared tree configurations were evaluated using validation-only threshold selection. Every configuration failed the precision, recall and specificity policy; the selected fallback is not considered ready for default use. The exact settings and partitions are recorded in [`tree-training.json`](tree-training.json), and [`freeze.json`](freeze.json) binds the model and source hashes before the fresh audit.

## Fresh ranks 260–279

The pinned CredData sample contains 20 selected repositories and 416/416 recovered labeled files. Original paths were used in memory for feature extraction and are not exported. No repository code was executed and corpus credentials were not checked online.

| Candidate classifier at score 0.5 | TP | FP | FN | TN | Precision | Recall | Specificity | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Heuristic | 9 | 0 | 128 | 51 | 100.00% | 6.57% | 100.00% | 0.422022 |
| V7 | 111 | 13 | 26 | 38 | 89.52% | 81.02% | 74.51% | 0.142297 |

The candidate readiness gate fails: precision is below 90%, and only 51 negative labels are available against the minimum of 100. The relative gate also fails because v7 reduces precision from the heuristic's 100%. Repository-macro precision/recall are 89.08%/86.96%; macro specificity is 75.13% across nine negative-bearing repositories.

The full scanner has separate units. It emitted 137 true-positive and 51 false-positive definite alerts (72.87% labeled-alert precision), detected 141 of 449 positive annotations (31.40% annotation recall), and missed 308 positive annotations. Candidate recall only measures emitted candidates and cannot replace raw scanner recall. Both full-scanner release thresholds fail.

Ranks 240–259 were reused as a diagnostic after their v6 localization errors informed the translation-map feature. On that sample v7 produced 26.34% candidate precision and 79.03% recall. Those results are not independent and show no broad improvement over v6. See [`diagnostic-v6/readiness.json`](diagnostic-v6/readiness.json) and the originally frozen [v6 audit](../ml-v6/README.md).

## Reproduction

The checked-in development rows are numeric features and labels; they contain no source snippets, credential values or original paths. They were normalized from CRLF to canonical UTF-8/LF before freezing, with parsed rows unchanged. `freeze.json` records canonical source hashes, model hash and development-data hash. The fresh sample, audit and readiness files record their own identities.

```sh
python -m backend.ml.tree_training benchmarks/ml-v7/development.jsonl output/creddata-v7-trees.json output/v7-training.json
python -m benchmarks.evaluate_model benchmarks/ml-v7/final/holdout.jsonl models/creddata-v7-trees.json output/v7-audit.json
python -m benchmarks.model_readiness benchmarks/ml-v7/final/model-audit.json benchmarks/ml-v7/final/holdout-detection.json output/v7-readiness.json --model models/creddata-v7-trees.json --dataset benchmarks/ml-v7/final/holdout.jsonl --independence independent --require-ready
```

The readiness command is expected to exit unsuccessfully because the measured evidence fails policy. `evaluate_model` reproduces the candidate metrics; `holdout-detection.json` is the separate raw scanner evaluation used by the current release-evidence manifest. Repository identifiers in these aggregate reports are stable pseudonyms. Scores are triage estimates, not probabilities of active exposure, and this sample does not establish production performance.
