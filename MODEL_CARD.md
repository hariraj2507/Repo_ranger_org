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

## External candidate model: 0.2.0a2

`models/creddata-experimental.json` is a separate opt-in model trained on 391 numeric candidates from a 70-repository CredData development pool. `benchmarks/external-triage.jsonl` contains features, binary labels and repository groups only. It contains no source snippets, tokens, fingerprints, URLs or original paths. The labels are external human-reviewed annotations matched approximately by line overlap, not verified active credentials.

Repository-separated partitions contain 232 training, 78 validation and 81 test candidates. Fit and calibration use equal repository weighting. Validation loss selects L2 regularization; positive Platt scaling is fit on validation only. Model JSON records data hash, partitions, calibration parameters, weighting, test metrics and a failed quality gate. We inspected internal tests during development; the final evaluation used ten additional repositories excluded from all model-development partitions.

On 48 independently acquired candidate labels, default vs trained Brier error was 0.3914 vs 0.0935; precision was 0.8333 vs 0.8958 and recall 0.1163 vs 1.0 at threshold 0.5. However, the trained model classified every candidate as positive, and 43 of 48 labels were positive. On the internal 81-row test, its Brier error and precision were worse than the default. **It is not promoted.** These small, mixed results do not demonstrate production discrimination or calibrated active-exposure probabilities.

See [the complete revision-5 report](benchmarks/revision5/README.md) for provenance, sample selection, detection tradeoffs, reliability bins and risk-band label counts. Classification metrics precede confidence adjustments and policy risk scoring. Existing synthetic-model results above describe the original experiment; the external model does not replace it or the transparent default.
