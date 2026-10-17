# RepoRanger v0.2.0a8

This alpha adds a local dashboard and optional GitHub authentication checks. Distribution remains through the private GitHub repository; PyPI publication is outside scope and its manual workflow remains disabled.

- Start `reporanger-web --root /path/to/projects` to scan local folders or public GitHub repositories, include history, filter redacted findings and download JSON reports. The loopback-only service uses a protected session, confined local paths, bounded workers and temporary in-memory scan records.
- Use the CLI's explicit `--verify-github` option for at most 20 supported GitHub user-token authentication checks. The fixed HTTPS endpoint receives read-only GET requests; reports expose safe outcomes without reading account identities or response bodies. Offline scanning remains the default, and the dashboard does not enable online verification.
- Recognize bounded NTLM authenticate responses and additional authorization literals. Add source-derived JSON translation-map context for candidate triage; findings remain visible.
- Record detector/scoring revisions 9/9 and verification settings in report identity. Create fresh saved-report baselines after upgrading.
- Verify the installed package outside the checkout in each Windows/Linux Python 3.10/3.12 CI job. Version-tag releases require all four jobs and current code-bound independent detector evidence.

The bundled guarded v4 model is unchanged. V5, v6 and v7 remain experimental overrides. The frozen v7 audit covers 20 fresh repositories (ranks 260–279), recovering all 416 labeled files. Among 188 definite candidates, v7 produces TP111/FP13/FN26/TN38: 89.52% precision, 81.02% candidate recall, 74.51% specificity and 75.13% repository-macro specificity. The strict gate fails precision below 90% and only 51 negative candidates against the required 100. The relative gate also fails precision regression.

The reused ranks 240–259 diagnostic gives v7 26.34% precision and 79.03% candidate recall. It informed development, and no broad improvement over v6 is established. On the fresh sample, raw scanning separately yields 137 true-positive / 51 false-positive definite alerts (72.87% precision) and detects 141/449 positive annotations (31.40% recall). The current release manifest validates this fresh evidence while reporting failed scanner readiness.

Local validation passed 245 tests, all 52 synthetic detector fixtures (28 TP / 24 TN) and an isolated installed-wheel smoke check covering the bundled model, authorization formats, redaction, dashboard assets, protected API session, actual scan worker and HTTP JSON download. Desktop and mobile dashboard views were inspected. Browser automation did not complete a file-save download check; HTTP attachment, report equality and redaction were verified.

This is an alpha, with false positives and missed credentials. Candidate recall does not measure full-scanner recall; scores are triage estimates, not probabilities of active exposure. The scanner's 90% precision / 80% annotation-recall goal remains unmet. Corpus credentials were never checked online. See [MODEL_CARD.md](MODEL_CARD.md), [ML-v7 evidence](benchmarks/ml-v7/README.md) and [revision-9 evidence](benchmarks/revision9/README.md).
