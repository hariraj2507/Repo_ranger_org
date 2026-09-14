# Implementation progress

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

## Pending external release steps

- Connect this checkout to the user's private RepoRanger GitHub repository.
- Run GitHub Actions and verify every matrix job.
- Publish the v0.2.0a1 prerelease after CI passes.

The GitHub account was verified as hariraj2507. The user is creating a private repository and will provide its URL. No GitHub release has been published.

## Beyond this release

- Web API and frontend dashboard.
- Independently labeled real-world accuracy evaluation before promoting the trained model.
