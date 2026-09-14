# Experimental triage model

## Intended use

Optional candidate ranking in RepoRanger, loaded with `--model models/experimental.json`. The default remains the transparent hand-weighted baseline. Model output does not verify whether a credential is active.

## Training data and limits

`benchmarks/triage.jsonl` contains 200 synthetic labeled metadata rows in 20 scenario groups. Rows contain numeric features only, not source code or credential values. These scenarios deliberately repeat some feature combinations; group separation prevents identical scenario IDs crossing partitions, but does not establish independence of feature distributions. Public tokens and secrets can have identical observable metadata.

The split is 120 training / 40 validation / 40 test rows. Whole groups remain in one partition. Validation log loss selects one of three L2 regularization strengths; the test set is not used for training or parameter selection. The deterministic pure-Python trainer writes a dataset hash and group membership alongside the weights.

## Results and deployment decision

At classifier threshold 0.5 on the 40-row synthetic test partition:

| Classifier | Precision | Recall | Brier score |
|---|---:|---:|---:|
| Baseline | 0.429 | 0.750 | 0.314 |
| Experimental trained | 1.000 | 0.500 | 0.090 |

Although the experimental model has lower Brier error, it misses more positive examples at this threshold. It is **not promoted to the default**. The evaluation concerns the classifier output, before confidence adjustments and risk policy; it does not establish calibration of final risk scores. Independent labeled real-repository data is needed before production promotion.

## Reproduce

```sh
python -m backend.ml.training benchmarks/triage.jsonl models/experimental.json benchmarks/model_metrics.json
python -m benchmarks.evaluate
```

The detection benchmark is separate: 52 synthetic source examples (28 positive, 24 negative). All currently pass. This is development regression coverage, not an independent production benchmark.
