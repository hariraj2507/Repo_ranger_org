# Benchmark provenance

All examples are author-created synthetic development fixtures. No leaked production credential corpus was downloaded or used. `additional_cases.json` extends the original 32 source examples with token-family boundary cases, Unicode, CRLF, key headers, and benign references. `triage.jsonl` is a separate artificial candidate-ranking dataset described in MODEL_CARD.md.

Run `python -m benchmarks.evaluate` for detector precision/recall counts and `python -m backend.ml.training` for model training/evaluation. The latter requires paths to the dataset, output model, and output metrics.
