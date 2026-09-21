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

## Revision-6 promotion safeguard

The newer evaluation gate additionally requires both predicted classes, at least ten examples of each ground-truth class, and at least 50% specificity. Single-class predictions cannot pass merely because a positive-heavy sample produces good Brier error. The existing external model also fails this gate on the fresh ranks 90-99 sample; see `benchmarks/revision6/final/model-audit.json`. Its weights were not retrained using that sample. JWT structure now has a separate safe metadata feature and does not receive known-credential or valid-credential boosts. Neither model is promoted to default.


## Revision-7 candidate coverage

The detector now includes weak literal password candidates without an entropy threshold. Existing model weights were not retrained or recalibrated for this broader population, and remain experimental and opt-in. Detection results in `benchmarks/revision7/` measure raw candidate detection, not model discrimination or exposure probabilities.


## Revision-8 context evidence

New numeric features describe test scopes, expected/mock fields and likely source references. The default heuristic uses them to lower review priority; candidate detections remain visible. Existing opt-in model weights are unchanged, contain no learned weights for these new features, and do not establish calibration for this population. The separate review-queue benchmark is a policy measurement, not model validation or a probability of active exposure.


## External model v2: 0.2.0a6

`models/creddata-v2-experimental.json` is a new optional classifier trained on 1,656 current candidate labels from 60 previously inspected repositories (51 with definite candidates). It adds eight coarse token-shape features, restores original-path context in memory, balances whole-repository partition sizes and applies inverse repository-size then equal-class-mass weighting consistently in fitting, selection and validation-only calibration. Scores target balanced candidate triage, not natural-prevalence or active-exposure probabilities.

On 217 candidates from 20 untouched repositories, v2 precision/recall were 92.78%/51.14%, versus 79.31%/13.07% for the default heuristic. Specificity was 82.93%; it predicts both classes. The old external model predicted everything positive. V2 improves discrimination but misses 86 positive candidate labels at threshold 0.5, and internal development comparisons still regress. It **remains opt-in**, despite passing the independent candidate gate. Raw detection and default scoring are unchanged.

See [ML-v2 evaluation](benchmarks/ml-v2/README.md) for the pilot, exact splits, dataset hashes, repository-macro results, ambiguity diagnostic, weighting and limitations. Older model artifacts remain available unchanged.
