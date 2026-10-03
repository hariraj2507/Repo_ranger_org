# Trained ML-v4 and conservative default integration

Normal scans load trained trees automatically from `backend/ml/data/default.json`. The model can refine ranking scores inside existing classifier/risk bands, with a baseline floor and negative-context veto. It cannot widen positive decisions at threshold 0.5. Caps preserve the classifier label and risk level, including historical exposure's 0.08 increment. This does not solve recall gaps.

## Data and training

CredData pin: `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Development combines previously inspected ranks 100-202: 4,640 rows (2,789 positive / 1,851 negative), 90 candidate repositories. Whole-repository partitions are 2,784 training / 928 validation / 928 internal test. All internal comparisons are development evidence. Only numeric features, labels and repository groups are committed; original source stays in ignored cache, is never executed, and credentials are never validated online.

The stdlib trainer fits 100 Newton gradient-boosted trees, learning rate 0.1, leaf regularization 1.0, update clipping +/-2 before shrinkage, at least three distinct vectors and weighted mass two per split branch. Repeated vectors compress into exact weighted label means. Fit weights use inverse repository size then equal class mass. Validation log loss selects depth 2/3/4; depth four wins. The configured guard cutoff 0.8 is a conservative fixed policy, not a validation-selected optimum. No probability calibration is claimed.

Linear and pairwise-interaction experiments still failed precision. `training.json` records the interaction fit; `tree-training.json` records the unrestricted tree fit. Internal unrestricted precision/recall are 79.09%/72.40%, versus heuristic 95.27%/22.33%, failing expanded alert promotion.

## Independent results

Weights and conservative policy were frozen before evaluating ranks 203-219. All 639 expected files from 17 repositories were recovered. There are 288 definite candidates (119 positive / 169 negative), in 12 candidate repositories. Ranks 200-202 were already inspected and excluded. The prior planned 20-repository acquisition is now covered by three inspected development repositories plus 17 fresh evaluation repositories.

| Candidate policy | TP | FP | Precision | Recall | Brier |
|---|---:|---:|---:|---:|---:|
| Heuristic | 11 | 0 | 100% | 9.24% | 0.326217 |
| Unrestricted trees | 84 | 48 | 63.64% | 70.59% | 0.220840 |
| Bundled guarded ranking | 11 | 0 | 100% | 9.24% | 0.325432 |

Raw trees fail precision. The guarded policy passes the candidate comparison gate on internal and fresh evaluations, but validation Brier regresses (0.532082 to 0.532402). This mixed, modest ranking evidence does not certify production accuracy. Three independent confidence scores and 148 development confidence scores are refined while labels/risk bands stay identical. Explicit band constraints explain preserved decisions and must not be described as learned precision/recall improvement.

Raw scanner recall is separate: 139/290 positive annotations detected (47.93%), with 151 missed. Definite raw alerts contain 119 true positives and 169 false positives, plus separate unknown/unlabeled/ambiguous alerts. The scanner's 90% precision / 80% annotation recall target is still unmet.

## Reproduce

```sh
python -m backend.ml.tree_training benchmarks/ml-v4/development.jsonl models/creddata-v4-trees.json output/tree-training.json
python -m benchmarks.evaluate_model benchmarks/ml-v4/final/holdout.jsonl models/creddata-v4-trees.json output/raw-tree-audit.json
python -m benchmarks.evaluate_model benchmarks/ml-v4/final/holdout.jsonl backend/ml/data/default.json output/default-policy-audit.json
reporanger /path/to/repository --format json
```

Acquire with `--repositories 17 --offset 203 --git-fallback --original-paths --max-file-mib 16`; add `--download` when needed. JSON model loading bounds size to 1 MB, depth to six and count to 200 trees, rejects malformed models/policies, and uses no executable serialization.

153 tests pass, including deterministic learning, automatic loading, full development class/current+historical-risk preservation, invalid model rejection, and complete model/policy report identity. All 52 scanner fixtures pass. Scoring revision 6 requires new saved-report baselines. Unrestricted decision expansion remains experimental.

Independent review reproduced the audit. AUROC and average precision are unchanged for the guarded default, so a ranking-order improvement has not been demonstrated; the observed change is limited numerical score refinement.
