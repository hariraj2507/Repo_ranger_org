# RepoRanger v0.2.0a6

- Add an optional ML-v2 classifier trained on 1,656 current, externally labeled candidates with whole-repository partitions.
- Add eight coarse numeric token-shape features without retaining raw credential material; default heuristic scores remain unchanged.
- Balance partition sizes and apply inverse repository-size then equal-class-mass weighting across fit, validation selection and calibration.
- Speed up fitting by combining identical feature/label contributions without changing the objective.
- Add tie-aware AUROC, average precision, balanced accuracy, per-repository evaluation and feature-label ambiguity diagnostics.

Independent evaluation: 217 candidates from 20 untouched repositories. ML-v2 precision/recall: 92.78%/51.14%; default heuristic: 79.31%/13.07%. Specificity: 82.93%. The independent candidate gate passes, but internal development precision/recall regress, so ML-v2 remains optional. These are candidate-classification metrics, not raw detection accuracy or exposure probabilities. See `benchmarks/ml-v2/README.md` and `MODEL_CARD.md`.

Try: `reporanger /path/to/repository --model models/creddata-v2-experimental.json`. Existing model artifacts and default behavior remain available.

Validation: 138 unit/integration tests pass, including weighting, split isolation, ranking ties, privacy and backwards compatibility.
