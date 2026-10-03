# ML v2: broader labeled data and balanced training

The previous external model predicted every independent candidate as positive. This iteration adds eight coarse numeric token-shape features, current context signals, actual repository filenames in memory, balanced repository partitions, and a class-balanced fit/selection/calibration objective. Raw tokens, paths, fingerprints and code are not exported to training rows. Numeric shape statistics describe syntax, not credential validity.

## Data and procedure

Metadata is pinned to `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Development uses previously inspected CredData ranks 100-159: 2415 files, 60 repositories, 1,656 definite candidate labels (1,376 positive, 280 negative), with candidates in 51 repositories. Ambiguous, unlabeled and X-labeled candidates are excluded. Original relative paths are used in memory so test/spec/fixture names are meaningful; they are not exported.

The initial old hash split produced 658/39/959 rows. Its report is preserved as `pilot-training.json`; it failed specificity. After inspecting this development result, we used deterministic size-balanced whole-repository partitions. All internal partitions are treated as development evidence, not independent validation of the new procedure. Final sizes: 993/332/331. Group assignment uses repository sizes and stable hashes, not labels. Repositories never cross partitions.

Fit, validation regularization selection and validation-only positive Platt scaling use inverse repository-size weights, then equal total class mass. Class balancing changes repository totals and targets a balanced reference population. Scores are candidate triage signals, not natural-prevalence probabilities or probabilities of active exposure. Identical feature/label rows are combined by summed weights during fitting, preserving the gradient objective while reducing computation. The three regularization values remain 0.001, 0.01 and 0.1; validation chose 0.01. Training code, weights and selection were frozen before the independent audit.

## Independent results

Ranks 160-179 contain 20 previously untouched repositories and 478 labeled files, with full source coverage including 13 archive-omitted files recovered from pinned Git blobs. There are 217 definite candidates (176 positive, 41 negative) from 18 repositories. Metrics below classify already-detected candidates at score 0.5; they do not measure scanner annotation recall or recover missed detections.

| Candidate metric | Default heuristic | Previous ML | New ML v2 |
| --- | ---: | ---: | ---: |
| Precision | 79.31% | 81.11% | 92.78% |
| Recall | 13.07% | 100.00% | 51.14% |
| Specificity | 85.37% | 0.00% | 82.93% |
| True positives / false positives | 23 / 6 | 176 / 41 | 90 / 7 |
| False negatives / true negatives | 153 / 35 | 0 / 0 | 86 / 34 |
| Brier error | 0.4330 | 0.1693 | 0.2225 |

The old model's lower Brier error does not establish discrimination: it classifies everything positive. Its AUROC is 0.2945 versus 0.7041 for v2; average precision is 0.7402 versus 0.9255. Equal-repository macro metrics and counts of defined denominators are in `independent-model.json`. V2 macro precision is 80.89%, recall 57.91%, and specificity 66.87%; pooled metrics alone overstate consistency across repositories.

Identical available feature vectors carry conflicting labels in five groups of vectors (22 rows, seven minority-label rows). This indicates ambiguity in available metadata, not proof of leakage. Labels are approximate inclusive line matches and do not establish active exposure. Whole-source repositories, natural prevalence and live credentials were not validated.

## Promotion decision

The independent candidate gate passes: both classes are predicted, specificity exceeds 50%, precision and recall beat the default, and Brier error improves over the default. The internal 331-row development evaluation still fails precision and recall comparisons. **V2 remains opt-in.** Neither the existing default nor the old model files are replaced. This does not meet the separate scanner target of 90% labeled precision and 80% annotation recall.

## Reproduce

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 60 --offset 100 --max-file-mib 16 --git-fallback --original-paths --features benchmarks/ml-v2/development.jsonl --output benchmarks/ml-v2/development-detection.json
python -m backend.ml.training benchmarks/ml-v2/development.jsonl models/creddata-v2-experimental.json benchmarks/ml-v2/training.json --external
python -m benchmarks.evaluate_model benchmarks/ml-v2/holdout.jsonl models/creddata-v2-experimental.json output/ml-v2-audit.json
reporanger /path/to/repository --model models/creddata-v2-experimental.json
```

For holdout acquisition use the same source command with `--repositories 20 --offset 160` and separate outputs; use `--download` when archives are absent. Never tune weights on the independent audit and continue describing it as untouched. See `manifest.json` for hashes, feature names and promotion gates.

Validation: 138 unit/integration tests pass, including weighting, split isolation, ranking ties, privacy and backwards compatibility.

Later evidence: the larger ranks 180-199 audit substantially regresses precision and calibration. See [the updated model card](../../MODEL_CARD.md#follow-up-generalization-audit); the earlier passing independent gate is not evidence of broad generalization.
