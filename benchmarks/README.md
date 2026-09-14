# Benchmark provenance

The checked-in source examples are author-created synthetic development fixtures. `additional_cases.json` extends the original 32 source examples with token-family boundary cases, Unicode, CRLF, key headers, and benign references. `triage.jsonl` is a separate artificial candidate-ranking dataset described in MODEL_CARD.md.

Run `python -m benchmarks.evaluate` for detector precision/recall counts and `python -m backend.ml.training` for model training/evaluation. The latter requires paths to the dataset, output model, and output metrics.

## Independent CredData pilot

`creddata.py` evaluates a deterministic repository sample from Samsung's externally labeled CredData metadata. See [the pilot report](creddata-pilot.md) and aggregate [results](creddata-pilot.json). Downloaded original source archives stay under ignored `tmp/`; no source credentials or corpus files are committed. This differs from the upstream obfuscated benchmark, so results are not directly comparable to its leaderboard.

Reproduce from the project root (network required for clone and first download):

```sh
git clone https://github.com/Samsung/CredData.git tmp/creddata
git -C tmp/creddata checkout c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d
python -m benchmarks.creddata --metadata tmp/creddata --repositories 5 --download --output output/accuracy/creddata-pilot.json
```

Omit `--download` for an offline rerun with cached archives. A nonzero exit signals incomplete evaluation, not low detector accuracy. Sampling ranks all repositories with metadata by SHA-256 of the fixed seed plus repository ID, before reading outcomes. Archives are pinned to upstream source commits and their hashes recorded. Files are read from archives without extraction or execution. Corpus contents may contain credentials; never validate them online or redistribute the archives. Original project licenses apply to source material; upstream metadata is Apache-2.0.
