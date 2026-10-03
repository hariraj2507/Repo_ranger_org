# Experimental triage model

## Intended use

As of 0.2.0a7, normal scans use bundled trained trees to refine ranking inside baseline classifier/risk bands. Older unrestricted classifiers remain experimental overrides. Earlier results below are historical. Model output does not verify active credentials.

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


## Follow-up generalization audit

A later 2,756-candidate sample (CredData repository ranks 180-199) exposes a substantial v2 regression: precision 43.19%, recall 89.75%, and 1,451 false positives, versus the default's 74.07% precision and seven false positives. Brier error worsens from 0.2002 to 0.3807. The earlier 217-candidate result does not generalize. V2 remains experimental and must not become the default. See `benchmarks/ml-v3/v2-fresh-audit.json`.

## Guarded ML-v3

`models/creddata-v3-guarded.json` uses the v2 training procedure with a conservative runtime policy. It never lowers a baseline score. It promotes only above a validation-selected cutoff (0.8), and only without test, test-value, placeholder, public-identifier, reference or non-production-path signals. Existing detections remain visible. Schema 2 explicitly records the policy; unknown policies are rejected. A cutoff of 1 disables promotion.

An initial floor-only experiment failed badly on ranks 180-199 (5.03% precision, 963 false positives); its model and results are preserved under `benchmarks/ml-v3/rejected-*`. That sample became diagnostic when used to identify the context problem. The context-veto policy adds two true positives without adding false positives there, but makes no change on the internal 331-row test and fails the required Brier-improvement gate. These are limited safeguards, not proof that ML is production-ready. Scores remain triage estimates.

Fresh guarded-model verification on ranks 200-202 recovered all 46 files but produced only 11 definite candidate labels. Guarded and default scores were identical, with zero positive predictions at threshold 0.5. This supplies no independent accuracy gain. The planned 20-repository evaluation remains incomplete after slow/truncated downloads; see [ML-v3 evidence](benchmarks/ml-v3/README.md). No promotion is approved.


## Bundled guarded tree ranking: 0.2.0a7

Normal CLI and API scans load `backend/ml/data/default.json`: 100 gradient-boosted trees over safe numeric metadata. The development pool contains 4,640 previously inspected labels; fitting uses 2,784 rows, repository-separated validation (928 rows) selects depth four from 2/3/4, and 928 internal test rows supply development evidence. No probability calibration or active-exposure claim is made.

Unrestricted trees raise internal recall from 22.33% to 72.40%, but precision falls from 95.27% to 79.09%. On fresh ranks 203-219 (17 repositories, 639/639 files, 288 labels: 119 positive / 169 negative), unrestricted precision/recall are 63.64%/70.59% (84 TP, 48 FP). Expanded ML alert decisions fail the precision gate.

The bundled policy uses a configured cutoff of 0.8, a baseline floor, negative-context vetoes, baseline-positive-only refinement and explicit caps preserving classifier labels and current/historical risk levels. This cutoff is a fixed conservative policy, not a newly validated optimum. Across development data, 157 classifier scores and 148 confidence scores change. Three independent scores change while TP11/FP0 and 9.24% recall remain identical; Brier improves slightly from 0.326217 to 0.325432. Validation Brier regresses from 0.532082 to 0.532402; internal Brier improves from 0.436167 to 0.431394. The guard constrains decisions; it does not demonstrate learned accuracy gains.

This limited integration makes trained ML part of normal scanning, with mixed ranking evidence. It does not solve the scanner's 90%/80% goal or establish production readiness. Both wheel and source distributions include the model. See [complete ML-v4 evidence](benchmarks/ml-v4/README.md).

Independent review reproduced the audit. AUROC and average precision are unchanged for the guarded default, so a ranking-order improvement has not been demonstrated; the observed change is limited numerical score refinement.
