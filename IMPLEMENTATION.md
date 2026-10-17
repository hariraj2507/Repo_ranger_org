# Implementation progress

Status as of 2026-10-11: `0.2.0a8` is a release candidate awaiting release CI; the latest published prerelease is `0.2.0a7`. The local web API/dashboard and optional GitHub authentication checks are implemented. All 245 local tests, 52 synthetic detector fixtures and the installed-wheel smoke check pass. The fresh v7 audit is complete: current release evidence is valid, but both candidate readiness and full-scanner readiness fail. Distribution will remain on the private GitHub repository; PyPI setup and publication are outside this release scope. Earlier milestones below are historical evidence.

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

## Historical milestone: v5 features and evaluation

- Added finer quantized value shapes and semantic context, retaining legacy eight-value metadata support. Derived statistics are not anonymized credentials.
- Corrected `.env` configuration recognition and named mapping evidence independently of translation semantics.
- Bumped scoring revision to 7 because PHP/context changes can alter heuristic scores; saved-report comparisons require a fresh baseline.
- At this stage, passed 165 local tests and 52 synthetic detector fixtures.
- Built and installed the current wheel locally; a scan outside the checkout verified bundled model loading, the explicit v5 override, redaction and scoring revision 7.
- Prepared 4,928 labeled candidates (2,908 positive / 2,020 negative), spanning 102 candidate-bearing repositories among 120 selected repositories and all 4,431 expected files.
- Completed the frozen-model audit on 20 fresh repositories at ranks 220–239, recovering 557/557 files. V5 candidate precision/recall are both 94.62%, but seven false positives versus the heuristic's zero fail the relative promotion gate. The bundled guarded v4 model remains unchanged.
- Raw scanner labeled-alert precision is 84.42% and positive-annotation recall is 28.43%, failing both stable-release targets. Candidate results do not solve missed detections. See [the v5 evaluation](benchmarks/ml-v5/README.md) for counts, repository-macro metrics and sample limitations.

## Completed locally: a8 service and validation

- Added `reporanger-web` and a packaged dashboard backed by the standard-library HTTP API. It scans allowed local folders or exact public GitHub HTTPS repository URLs, with optional history, progress, redacted findings and JSON downloads.
- Confined the service to loopback and a configured filesystem root; checked hosts, origins and session tokens. The bounded worker has a five-minute deadline, input/report limits, hardened Git cloning and at most 20 session-only scan records.
- Added CLI-only `--verify-github`: explicit opt-in, at most 20 distinct structurally valid supported GitHub user tokens, a fixed HTTPS authenticated-user endpoint, blocked redirects, fixed safe outcomes and no response-body reading. All provider tests use mocks; corpus credentials were never checked online.
- Added bounded NTLM type-three authenticate-response and authorization-literal detection, including supported Basic/Bearer headers and curl/wget credential arguments. Structural matching does not establish active credentials.
- Added source-derived JSON translation-map evidence alongside filename/path context. Findings remain visible; this context does not prove that a value is safe.
- Centralized detector/scoring revisions at 9/9. Saved comparisons require matching engine, model, policy and verification settings; create new baselines after upgrading.
- Passed 245 local tests and the 52-case regression benchmark (28 TP, 24 TN, no FP/FN). These are development checks, not independent production accuracy.
- Built and installed the wheel in an isolated environment. Checks outside the checkout passed for the bundled model, ten authorization formats, CLI/report redaction, packaged dashboard, protected API session, actual scan worker and JSON download.
- Inspected the desktop and mobile dashboard views with a history scan showing two findings. Browser automation did not complete the file-save download check; the installed-wheel smoke check verified the HTTP attachment, report equality and redaction.
- Updated the four Windows/Linux Python 3.10/3.12 CI jobs to check the installed distribution, full suite, detector fixtures and current evidence. A tag release depends on all four jobs; release CI has not yet run for a8.

## Frozen v6 and follow-up v7 evaluation

V6 uses 5,144 labels from 140 selected development repositories, with complete 4,988-file coverage and repository-separated partitions. All six declared validation policies failed. Its initially fresh ranks 240–259 sample recovered 662/662 files and produced TP116/FP285/FN8/TN60 at the candidate threshold: 28.93% precision, 93.55% recall and 17.39% specificity. Macro specificity is 44.61%. Strict candidate readiness fails, and v6 remains experimental.

The same sample's raw scanner results are 26.44% labeled-alert precision and 52.74% positive-annotation recall. Those units differ from candidate classification; neither scanner target passes. After the JSON-localization diagnosis informed follow-up development, ranks 240–259 became inspected data for v7. The frozen v6 artifacts remain unchanged; see [v6 evidence](benchmarks/ml-v6/README.md).

V7 adds the source-derived translation feature and retains the declared validation policy; all six configurations fail that validation policy. The model was frozen before the completed fresh ranks 260–279 audit, which recovered 416/416 files across 20 repositories. Its 188 definite candidates (137 positive / 51 negative) give TP111/FP13/FN26/TN38: 89.52% precision, 81.02% recall, 74.51% specificity and 75.13% repository-macro specificity. Strict readiness fails precision below 90% and insufficient negative candidates; the relative gate also fails precision regression. V7 remains experimental.

The reused ranks 240–259 diagnostic gives v7 only 26.34% precision and 79.03% candidate recall, so no broad improvement over v6 is established. Development and diagnostic results remain separate from fresh evidence. The bundled guarded v4 model remains unchanged.

Fresh raw scanning separately yields 137 true-positive / 51 false-positive definite alerts (72.87% precision), with 141/449 positive annotations detected (31.40% recall) and 308 missed. The manifest at `benchmarks/revision9/release-evidence.json` binds this report directly to detector/scoring revisions 9/9 and frozen source hashes. Local verification reports valid evidence and failed readiness. See [v7 evidence](benchmarks/ml-v7/README.md) for the frozen protocol, normalization and complete gate results.

## Remaining before the private a8 release

- Complete all four Windows/Linux release CI jobs and the version-tag build before publishing the private GitHub prerelease.

Further accuracy work remains after the alpha release: improve independent scanner precision/recall and model generalization. The 90% precision / 80% source-annotation recall goal remains unmet; no production accuracy or calibrated exposure-probability claim is made. Valid alpha evidence and stable accuracy readiness are separate checks.

The optional PyPI workflow remains disabled. There is no pending PyPI account, publisher setup or publication task for the chosen private distribution.
