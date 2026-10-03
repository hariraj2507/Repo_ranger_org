# RepoRanger v0.2.0a7

Normal scans now load a bundled trained ML model automatically. The 100-tree ensemble refines ranking inside existing classifier/risk bands, with baseline floors and negative-context safeguards for current and historical findings. No manual flag or external training dependency is needed.

- Expand development coverage to 4,640 labels from 90 repositories.
- Add deterministic tree training, bounded JSON inference and model package data.
- Include full model/policy identity in reports; scoring revision 6.
- Complete fresh evaluation: 17 repositories, 639 files, 288 labels.
- Reject and retry silently truncated benchmark archives.

Unrestricted ML still fails precision (63.64% precision / 70.59% recall on the independent candidate sample). The guarded default preserves TP11/FP0 and risk levels, refining three scores with a small Brier improvement. Validation ranking error slightly worsens. ML integration is complete for conservative ranking; overall detection accuracy and production readiness remain unfinished. The 90%/80% scanner goal is unmet.

Validation: 153 tests and 52 synthetic scanner fixtures pass. See `benchmarks/ml-v4/README.md` and `MODEL_CARD.md` for complete evidence. This is an alpha prerelease.
