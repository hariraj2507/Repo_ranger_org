# Guarded ML-v3 evaluation

The default heuristic is unchanged. This experiment adds a baseline score floor, a validation-selected promotion cutoff, and a veto on ML promotions when negative context is present. It never removes a detection. Load the optional artifact with `--model models/creddata-v3-guarded.json`.

## Provenance and sample use

CredData metadata pin: `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Sampling order is the existing fixed RepoRanger benchmark order. Training uses previously inspected ranks 100-159, the same 1,656 safe feature rows and repository-separated 993/332/331 partitions as v2. Weights, calibration, and cutoff selection use training/validation only. Validation selects cutoff 0.8. The internal test matches the baseline exactly and fails the required Brier-improvement gate.

Ranks 180-199 were initially independent for a baseline-floor-only model. It produced 51 true positives and 963 false positives (5.03% precision), versus 20 and seven for the default. Its model, training and audit are preserved as `rejected-*`. The original `independent-model.json` and `previous-sample-audit.json` also describe that rejected model; their model hashes identify it. The rejected model has an obsolete research schema and is intentionally not loadable by the finalized policy loader.

After inspecting this failure, these ranks became diagnostic. Many false promotions overrode non-production/public-value context. The final veto preserves baseline scores for test, test-value, non-production-path, public-identifier, placeholder, and reference signals. This conservative policy improves the diagnostic result to 22 true positives and seven false positives; it is not an independent validation result. See `context-veto-diagnostic.json`.

The same 2,756-candidate sample exposes v2 generalization failure: 1,103 true positives and 1,451 false positives (43.19% precision). See `v2-fresh-audit.json`. Earlier favorable v2 results should not be generalized.

## Interpretation

Metrics classify detected candidates at score 0.5, before confidence adjustments and risk policy. They do not measure raw detector annotation recall, active credentials, or exposure probabilities. Whole-repository separation does not remove feature ambiguity or cross-repository duplication. Negative-context vetoes deliberately preserve low priority even when a benchmark labels a test fixture as a secret. ML remains experimental and optional.

## Reproduce

```sh
python -m backend.ml.training benchmarks/ml-v2/development.jsonl models/creddata-v3-guarded.json benchmarks/ml-v3/training.json --external --guarded
python -m benchmarks.evaluate_model benchmarks/ml-v3/holdout.jsonl models/creddata-v3-guarded.json output/guarded-diagnostic.json
```

Regression verification: all 148 full-suite tests passed, including all eight guarded-model tests and archive-integrity regressions. All 52 synthetic detector fixtures pass. An end-to-end CLI scan with the guarded model produced valid JSON with the test credential redacted.


## Fresh verification and acquisition limitation

After the policy and weights were frozen, the planned ranks 200-219 archive acquisition encountered slow and silently truncated downloads. Acquisition was stopped; this is not a completed 20-repository evaluation. A smaller fixed prefix, ranks 200-202, was chosen for a quick check before examining its labels. All 46 expected files were recovered, including pinned Git-object recovery for the damaged archive. These ranks did not inform tuning.

`quick-independent/model-audit.json` covers 11 definite candidate labels (eight positive, three negative; two repositories with labeled candidates). Both default and guarded models return identical scores and no positive predictions at the evaluation threshold: recall 0%, precision undefined (the pooled metric serializes zero), Brier 0.5103. This small result supplies no evidence of an accuracy gain and fails the quality gate. It does not mean raw detection found no credentials: these are classifier metrics for already detected candidates.

No further tuning followed this check. Ranks 200-202 are now used; ranks 203-219 were not evaluated. The broader independent evaluation remains incomplete. Neither this guarded candidate nor v2 is promoted or released as a new default.

The benchmark downloader now checks the entire gzip stream, including the footer, before accepting a cache entry. It retries silent truncation up to three times, repairs invalid cached gzip streams, limits expanded size, and records EOF failures as repository errors. Partial acquisition must not be used to claim complete benchmark coverage.
