# RepoRanger model card

## Intended use

Normal scans in the `0.2.0a8` candidate awaiting release CI retain the bundled guarded v4 trees introduced in a7, refining scores inside baseline classifier/risk bands. Unrestricted v5/v6/v7 models remain experimental overrides. The fresh v7 audit is complete and fails candidate readiness; earlier results below are historical. Model output does not verify active credentials; the separate CLI-only `--verify-github` option performs bounded opt-in authentication checks and is not used in model evaluation.

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

In 0.2.0a7, normal CLI scans and the Python library API load `backend/ml/data/default.json`: 100 gradient-boosted trees over numeric metadata. The a8 local dashboard uses the same guarded model. The development pool contains 4,640 previously inspected labels; fitting uses 2,784 rows, repository-separated validation (928 rows) selects depth four from 2/3/4, and 928 internal test rows supply development evidence. No probability calibration or active-exposure claim is made.

Unrestricted trees raise internal recall from 22.33% to 72.40%, but precision falls from 95.27% to 79.09%. On fresh ranks 203-219 (17 repositories, 639/639 files, 288 labels: 119 positive / 169 negative), unrestricted precision/recall are 63.64%/70.59% (84 TP, 48 FP). Expanded ML alert decisions fail the precision gate.

The bundled policy uses a configured cutoff of 0.8, a baseline floor, negative-context vetoes, baseline-positive-only refinement and explicit caps preserving classifier labels and current/historical risk levels. This cutoff is a fixed conservative policy, not a newly validated optimum. Across development data, 157 classifier scores and 148 confidence scores change. Three independent scores change while TP11/FP0 and 9.24% recall remain identical; Brier improves slightly from 0.326217 to 0.325432. Validation Brier regresses from 0.532082 to 0.532402; internal Brier improves from 0.436167 to 0.431394. The guard constrains decisions; it does not demonstrate learned accuracy gains.

This limited integration makes trained ML part of normal scanning, with mixed ranking evidence. It does not solve the scanner's 90%/80% goal or establish production readiness. Both wheel and source distributions include the model. See [complete ML-v4 evidence](benchmarks/ml-v4/README.md).

Independent review reproduced the audit. AUROC and average precision are unchanged for the guarded default, so a ranking-order improvement has not been demonstrated; the observed change is limited numerical score refinement.

## Historical v5 experiment (2026-10-05)

V5 adds eight detail/format features alongside the original eight shape features, plus semantic name, usage, mapping, file-type and localization context. Legacy eight-value metadata remains supported. Features contain no raw credential values or source snippets, but finer quantized statistics remain secret-derived metadata and are not anonymization. Mapping syntax, paths and localization flags do not prove that a candidate is harmless.

The development pool has 4,928 labels (2,908 positive / 2,020 negative) from 102 candidate-bearing repositories among 120 selected repositories; 4,431 of 4,431 expected files were recovered. The fixed training run reports internal candidate precision of 88.36% and recall of 89.33%. These development results do not establish independent performance, raw detection recall or readiness to replace the bundled default.

The frozen v5 model was evaluated on 20 fresh repositories at ranks 220–239, recovering all 557 expected files. The candidate dataset contains 154 definite labels from 14 candidate-bearing repositories: 130 positive and 24 negative. V5 produces TP123/FP7/FN7/TN17, giving 94.62% pooled precision and recall, 70.83% specificity and Brier error 0.069265 (heuristic: 0.381049). Repository-macro precision/recall are 92.89%/96.62%; macro specificity is only 26.19% across the six negative-bearing repositories. The small, positive-heavy sample limits generalization.

The relative candidate gate fails: heuristic precision is 100% with 24.62% recall, so v5's added false positives are a precision regression. For comparison, unrestricted v4 evaluated on the same new feature metadata has 95.90% precision, 90.00% recall and Brier error 0.10298. These are candidate-level comparisons, not evidence that v5 improves every metric or detects additional source credentials.

The raw scanner produces 130 true-positive and 24 false-positive labeled alerts (84.42% precision), and detects 139 of 489 positive annotations (28.43% recall). Alerts and annotations use different counting units. Both stable-release accuracy thresholds fail. V5 remains an experimental override; the bundled guarded v4 model is unchanged and no new release is published. See [the complete v5 audit](benchmarks/ml-v5/README.md).

Local feature changes use scoring revision 7, so comparisons require fresh report baselines; this is separate from the published a7 model's scoring revision 6. The feature changes can affect heuristic scores even though the bundled model artifact is unchanged.

## Frozen v6 experiment: a8 development (2026-10-06)

`models/creddata-v6-trees.json` remains an opt-in experiment. Development expands to previously inspected ranks 100–239: 140 selected repositories, complete 4,988-file recovery and 5,144 definite candidate labels (3,100 positive / 2,044 negative) in 117 candidate-bearing repositories. Whole-repository partitions contain 3,086/1,029/1,029 training/validation/internal-test rows across 69/22/26 repositories. Numeric data exclude credential values, snippets and original paths; derived value statistics are not anonymization.

The six predeclared configurations combine depths 2/3/4 with regularization 5 or 15 and stronger leaf-vector/source requirements. All use 100 rounds, learning rate 0.08, minimum leaf weight 8 and split gain 0.1. Thirteen fixed thresholds are checked on validation only. The policy requires 90% precision, 80% recall and 50% specificity in both pooled and balanced-weighted metrics, plus at least 50% equal-repository specificity across five negative-bearing repositories. **Every configuration fails that policy.** The selected fallback has depth 3, regularization 15, at least 20 vectors from 3 sources and raw cutoff 0.35. The runtime logit offset maps that cutoff to score 0.5 without calibrating probabilities. See `benchmarks/ml-v6/tree-training.json` for the complete settings, partitions and failures.

The frozen v6 audit used 20 initially untouched ranks 240–259 and recovered 662/662 labeled files. Among 469 definite candidates (124 positive / 345 negative) in 18 repositories, v6 has TP116/FP285/FN8/TN60: 28.93% precision, 93.55% recall, 17.39% specificity and Brier error 0.453557. The heuristic has TP14/FP22, 38.89% precision, 11.29% recall and Brier 0.280848. V6 equal-repository precision/recall are 81.57%/94.32%; macro specificity is 44.61% across 12 negative-bearing repositories. Both the relative comparison gate and strict candidate-readiness gate fail. Strong repository-size effects prevent interpreting the macro precision as pooled accuracy.

Raw scanning separately detects 125/237 positive annotations (52.74% recall), with 124 true and 345 false definite alerts (26.44% precision), plus separate ambiguous/unknown/unlabeled alerts. Candidate recall excludes missed source annotations; its units cannot be substituted for raw detector recall. The 90%/80% full-scanner gate also fails. The bundled guarded v4 model is unchanged, and these results do not authorize unrestricted default promotion or establish active-exposure accuracy.

Subsequent diagnostics identified 263 v6 ML false positives as JSON localization labels. Once that audit informed further context or model changes, ranks 240–259 became development evidence for those changes. The saved results remain the evaluation of the originally frozen v6 model; a future model requires fresh independent evidence. See [the complete v6 audit](benchmarks/ml-v6/README.md) and [revision-9 evidence](benchmarks/revision9/README.md).

## Frozen v7 experiment and completed fresh audit

V7 adds source-derived translation-map context and retrains on the same inspected ranks 100–239, with 5,144 definite candidate labels and whole-repository partitions of 3,086/1,029/1,029 rows. The six fixed configurations and thirteen validation thresholds retain the v6 policy. Every configuration fails that policy. The selected failed fallback has depth 3, regularization 15, 100 trees, at least 20 leaf vectors from three sources and runtime threshold 0.5. Its pooled validation precision/recall are 90.71%/93.61%, but repository/class-weighted precision is 73.10%; favorable pooled values do not override the failed policy.

The model and source were frozen before the fresh ranks 260–279 audit; [freeze.json](benchmarks/ml-v7/freeze.json) records their identities. The completed audit selected 20 repositories and recovered all 416 expected labeled files. It contains 188 definite emitted candidates from 16 repositories: 137 positive and 51 negative labels.

| Candidate classifier at runtime score 0.5 | TP | FP | FN | TN | Precision | Recall | Specificity | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Heuristic | 9 | 0 | 128 | 51 | 100.00% | 6.57% | 100.00% | 0.422022 |
| V7 | 111 | 13 | 26 | 38 | 89.52% | 81.02% | 74.51% | 0.142297 |

V7 repository-macro precision/recall are 89.08%/86.96%; macro specificity is 75.13% across nine negative-bearing repositories. The strict candidate gate fails because precision is below 90% and only 51 negative labels are available against the unchanged minimum of 100. The relative gate also fails precision regression against the heuristic. These results do not authorize default promotion.

The reused ranks 240–259 diagnostic has TP98/FP274/FN26/TN71: 26.34% precision, 79.03% recall and 20.58% specificity. V6's originally frozen results on that sample were 28.93% precision and 93.55% recall. V7 therefore does not establish a broad improvement; inspected diagnostic data and the differently composed fresh sample must remain separate.

Raw scanning on the fresh sample yields 137 true-positive and 51 false-positive definite alerts, or 72.87% labeled-alert precision. It detects 141/449 positive annotations, or 31.40% annotation recall, and misses 308. Another 7 ambiguous, 88 unknown and 21 unlabeled alerts are excluded from definite precision. Candidate recall counts only emitted candidates and cannot substitute for annotation recall. Both full-scanner targets fail. The current release manifest validates this fresh evidence but does not pass stable readiness.

V7 JSON/JSONL artifacts use canonical UTF-8/LF. The training report records CRLF-to-LF normalization of development data before model freeze, with unchanged parsed rows and the original hash. Source hashes use `utf8-lf-v1`; frozen v6 artifacts retain their original bytes through targeted Git attributes. Reproduction details, dataset/model hashes and limits are in [ML-v7 evidence](benchmarks/ml-v7/README.md). The bundled guarded v4 model remains unchanged, scores are not active-exposure probabilities, and corpus credentials were never checked online.
