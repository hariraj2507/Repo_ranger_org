# Implementation progress

Status as of 2026-10-05: the CLI core is implemented and 0.2.0a7 is published. Richer v5 features have been evaluated locally; v5 remains experimental and no new release is published. The sections below retain the earlier milestones as historical evidence.

## Completed: CLI release foundation

- Reachable Git history and local reflog flags, historical scoring and report provenance.
- Full temporary clones for remote history; remote reflog requests are rejected.
- Commit/blob limits, coverage counters, and visible truncation warnings.
- CI thresholds and exit codes, including errors for incomplete historical coverage.
- GitHub Actions annotations with historical locations kept distinct from current-file annotations.
- Installable Python package and portable entry points.
- Setup documentation and Windows/Linux test workflow.
- Real temporary Git repository integration tests; remote orchestration uses mocks.

## Completed: detection and policy configuration

- Shared deterministic duplicate selection in both detection pipelines.
- Explicit JSON configuration and repeatable CLI path exclusions.
- Rule and fingerprint suppression with report counters.
- Policy applies to current files, history, and reflog scans.
- Regression coverage for detector ordering, excluded-file reads, and policy-driven CI outcomes.

## Completed: history coverage and saved scans

- Shallow repositories are explicitly marked incomplete, with CI errors and fetch guidance.
- Cached historical detection retains each distinct path for identical blobs.
- Redacted report snapshots can be saved to new files.
- Compatible scans can be compared for new, unchanged, and no-longer-detected findings.
- Invalid baselines, mismatched settings, and incomplete histories are rejected for comparison.

## Completed: contextual entropy accuracy

- Entropy requires credential-related assignments and retains complete values.
- Known signatures remain active across all scanned files.
- Added 32 labeled precision/recall regression fixtures.
- Re-scanned the same Cherry Blossom checkout: 3,063 candidates reduced to two without exclusions.
- Detector revisions prevent misleading baseline comparisons after algorithm changes.

## Completed: v0.2.0a1 local release candidate

- Historical validation and code context come from the original blob, with safe metadata in reports.
- Historical UTF-16 text is supported.
- Bounded custom signature rules run in current and historical scans.
- Fine-grained GitHub detection is aligned with its validator.
- Repository risk no longer increases solely from repeated weak findings.
- The detection benchmark covers 52 synthetic cases.
- A reproducible experimental logistic model is trained on 200 synthetic metadata rows with group-separated partitions. It remains opt-in because recall worsened on the synthetic test set.
- Release workflow requires all Windows/Linux test jobs to pass before a version-tag prerelease is published.

## Historical milestone: first GitHub prerelease (0.2.0a1)

- Source pushed to `hariraj2507/Repo_ranger_org`, a verified private repository.
- All 64 tests and the 52-case detection benchmark passed on Windows/Linux with Python 3.10/3.12.
- Tag `v0.2.0a1` passed the complete matrix and release job.
- Published wheel, source archive, experimental model JSON, and model card.

[Prerelease](https://github.com/hariraj2507/Repo_ranger_org/releases/tag/v0.2.0a1)

[Successful release workflow](https://github.com/hariraj2507/Repo_ranger_org/actions/runs/34799858828)

## Completed: published 0.2.0a7

- Added literal-password and JWT/private-JWK detection, richer custom rules, offline validation and contextual review priority.
- Bundled 100 trained trees for conservative numerical score refinement inside existing classifier and risk bands; unrestricted ML remains experimental.
- Included model and runtime-policy identity in saved reports (scoring revision 6).
- Passed 153 tests and 52 synthetic detector fixtures across Windows/Linux with Python 3.10/3.12 before publishing the alpha artifacts.

[Published a7](https://github.com/hariraj2507/Repo_ranger_org/releases/tag/v0.2.0a7) · [Successful release CI](https://github.com/hariraj2507/Repo_ranger_org/actions/runs/37121064050)

## Current local work: v5 features and evaluation

- Added finer quantized value shapes and semantic context, retaining legacy eight-value metadata support. Derived statistics are not anonymized credentials.
- Corrected `.env` configuration recognition and named mapping evidence independently of translation semantics.
- Bumped scoring revision to 7 because PHP/context changes can alter heuristic scores; saved-report comparisons require a fresh baseline.
- Passed 165 local tests and 52 synthetic detector fixtures. These changes are not yet released or verified by a new release CI run.
- Built and installed the current wheel locally; a scan outside the checkout verified bundled model loading, the explicit v5 override, redaction and scoring revision 7.
- Prepared 4,928 labeled candidates (2,908 positive / 2,020 negative), spanning 102 candidate-bearing repositories among 120 selected repositories and all 4,431 expected files.
- Completed the frozen-model audit on 20 fresh repositories at ranks 220–239, recovering 557/557 files. V5 candidate precision/recall are both 94.62%, but seven false positives versus the heuristic's zero fail the relative promotion gate. The bundled guarded v4 model remains unchanged.
- Raw scanner labeled-alert precision is 84.42% and positive-annotation recall is 28.43%, failing both stable-release targets. Candidate results do not solve missed detections. See [the v5 evaluation](benchmarks/ml-v5/README.md) for counts, repository-macro metrics and sample limitations.

## Remaining

- Improve model precision/generalization before reconsidering unrestricted default deployment; v5 stays an experimental override.
- Update release evidence and complete Windows/Linux release CI before publishing the next package; local installed-wheel verification has passed.
- Improve independently measured detection toward the 90% precision / 80% recall goal. CI still checks the stored revision-8 report (93.69% labeled-alert precision / 43.16% annotation recall); the fresh v5 audit also fails. These measurements use different units and are not production guarantees.
- Build the web API service and frontend dashboard; neither is implemented. The existing API is a Python library interface.
- Establish broader production evidence. Validation remains offline; active credential verification and PyPI publishing are not configured.
