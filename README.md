# RepoRanger

[Releases](https://github.com/hariraj2507/Repo_ranger_org/releases) | [CI](https://github.com/hariraj2507/Repo_ranger_org/actions)

RepoRanger scans repository files and Git history for potential credentials. It combines signature and entropy detection, offline structural validation, syntax context, and explainable risk scoring. JSON, Markdown, and GitHub Actions output contain redacted findings.

The current checkout is `0.2.0a8`, an alpha candidate awaiting release CI. The latest published GitHub prerelease is `0.2.0a7`. The local dashboard and optional GitHub authentication checks described below are new a8 work. The completed fresh audit covers 20 repositories and all 416 labeled files; raw scanner precision is 72.87% and positive-annotation recall is 31.40%, below the 90% / 80% targets. Distribution remains through the private GitHub repository.

## Install and run

Requires Python 3.10+ and Git on PATH for remote, history, and reflog scans.

```sh
python -m pip install .
reporanger /path/to/repository
```

You can also run from this checkout without installing dependencies:

```sh
python -m backend . --format json
python run.py . --format markdown
```

On Windows, use `py` or the full path to your Python executable if `python` is not on PATH. Quote paths containing spaces.

## Features

```sh
# Include reachable commits from every local ref
reporanger . --history --format json

# Also inspect commit targets retained by local reflogs
reporanger . --history --reflog

# Scan remote history using a temporary full clone
reporanger https://github.com/OWNER/REPOSITORY.git --history

# Fail CI when high or critical risk findings are found
reporanger . --history --format github --fail-on high

# Set history scan limits
reporanger . --history --max-commits 500 --max-blobs 10000
```

Current-file scans are the default. Remote scans use shallow clones unless `--history` is requested. Reflogs cannot be fetched from a remote server: `--reflog` requires a local working tree. History scanning does not check out or modify old revisions.

Exit codes:

- `0`: scan completed and no configured policy threshold was met; without `--fail-on`, findings do not change the exit code.
- `1`: a finding meets or exceeds `--fail-on` (`low`, `medium`, `high`, or `critical`).
- `2`: invalid arguments or scan failure; with `--fail-on`, also returned when history limits are reached or historical blobs cannot be scanned (unreadable, oversized, or undecodable). Empty and binary blobs are expected skips.

JSON includes scan counters, skipped file reasons, and history truncation flags. Markdown includes history counters and commit locations. GitHub output places historical locations in annotation messages because old line numbers may no longer match the current file.

History and reflog scans each have their own limits. Repeated historical blob findings are deduplicated across both scans; the first encountered commit provides provenance. Current and historical occurrences are reported separately. Identical blobs reuse analysis for the same file extension, while every distinct included path is retained (with the first encountered commit at that path). This is not a complete inventory of every commit containing a credential. Shallow local checkouts are marked incomplete; fetch full history with `git fetch --unshallow` before scanning. With `--fail-on`, shallow history returns exit code 2.

## Local dashboard

```sh
reporanger-web --root /path/to/allowed/projects --port 8765
# From the checkout:
python -m backend.web --root /path/to/allowed/projects --port 8765
```

Open `http://127.0.0.1:8765` in a browser. The dashboard starts scans, shows progress and recent results, filters redacted findings, displays coverage warnings, and downloads redacted JSON reports. Choose a local folder within `--root` or an exact public `https://github.com/OWNER/REPOSITORY` URL; optional Git history uses the same scanner and bundled guarded model as the CLI. Git must be installed for remote and history scans. The default allowed root is the current folder.

The standard-library service binds only to loopback. It checks request hosts, origins and a session token; local scans reject paths outside the allowed root and skip symbolic links and junctions. Public GitHub clones disable credential helpers, prompts, hooks and redirects. Repository code is not executed. One worker processes a bounded queue, with a five-minute total scan deadline, at most 500 commits / 10,000 historical blobs, and explicit input/report limits. Coverage warnings must be reviewed before interpreting a clean report.

Up to 20 recent scan records are kept in memory for the server session. Stopping the service discards them; download reports you need to retain. The dashboard does not expose custom policies, model overrides, reflogs, comparison baselines, or online credential checks. It is a local tool, without hosted accounts or durable server storage.

## Optional GitHub authentication checks

```sh
reporanger /path/to/repository --verify-github --format json
```

Scans remain offline unless `--verify-github` is explicitly supplied. This option sends at most 20 distinct structurally valid detected GitHub user tokens to `https://api.github.com/user` using a read-only `GET`. Supported families include classic and fine-grained personal access tokens, OAuth access tokens and GitHub App user access tokens. Installation and refresh tokens are skipped because that endpoint cannot establish their validity.

Reports contain only fixed statuses (`active`, `inactive`, `inconclusive`, `skipped`) and safe reasons. HTTP 200 means authentication succeeded at that moment; 401 means it was rejected. Rate limits, redirects, unsupported families and network failures do not establish inactivity. Response bodies and account identities are not read, and credential values are not retained by the verifier or written to its logs. Repeated values are cached by fingerprint in memory. The report profile records the opt-in setting; comparison baselines must use matching verification settings. All verification tests use mocked responses, and no CredData credentials were checked online.

## GitHub Actions usage

Install RepoRanger from your checked-out source, then run:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
- run: python -m pip install .
- run: reporanger . --history --format github --fail-on high
```

The included CI workflow runs all tests and the 52-case detector benchmark on Windows and Linux with Python 3.10 and 3.12. It checks the installed CLI, bundled model and dashboard outside the checkout, then validates the current release evidence. Its tests use synthetic credentials, so it does not enforce a secret-scanning policy against those fixtures.

## Development

```sh
python -m unittest discover -s tests -v
```

Integration tests create isolated temporary Git repositories to verify deleted-secret recovery, reflog recovery, reporting, and exit codes. Remote clone orchestration is mocked; live network cloning is not covered by this suite.

## Current limitations

- Default validation is offline and structural; a positive result does not prove a credential is live. Optional GitHub user-token authentication requires `--verify-github`.
- Normal scans load a bundled trained tree model for conservative ranking refinement. The transparent baseline protects alert decisions and risk levels; unrestricted ML classifiers remain experimental overrides.
- Historical and current findings receive offline validation and syntax enrichment. Other providers have no online verification integration.
- Non-Python syntax context requires an optional compatible Tree-sitter provider; otherwise scans fall back to line context.
- The dashboard/API is confined to the local computer and has bounded, temporary storage.
- Detection can produce false positives and false negatives; a clean report is not proof that a repository contains no secrets.

## Scan policy

Pass a policy explicitly; RepoRanger does not automatically load configuration from a scanned repository.

```sh
reporanger . --config reporanger.json --exclude 'generated/' --history
```

Example `reporanger.json`:

```json
{
  "exclude": ["fixtures/", "**/*.lock"],
  "disabled_rules": ["high_entropy_token"],
  "suppress_fingerprints": []
}
```

- Exclusions match case-sensitive, repository-relative paths with `/` separators. `*` may span directories; a trailing `/` excludes everything under that root-relative folder. `**/*.lock` also matches root-level lock files. Repeat `--exclude` to add patterns to the policy.
- Excluded current files are skipped before extraction; matching historical paths are skipped before blob reads. Existing built-in directory exclusions remain active.
- Built-in rule IDs accepted by `disabled_rules`: `aws_access_key_id`, `github_token`, `gitlab_token`, `private_key_block`, `high_entropy_token`, `jwt`, `private_jwk`, `hardcoded_password`, `authorization_literal`, `ntlm_authenticate`. Custom rule IDs are also accepted.
- Fingerprint suppression accepts SHA-256 hashes copied from JSON reports; it suppresses that fingerprint across paths and revisions. Do not put raw credentials in configuration.
- Suppression applies after duplicate selection to both current and historical findings, before risk aggregation and CI policy evaluation. JSON records `suppressed_findings`; the CLI also prints a suppression count to stderr.
- Unknown keys, unknown rule IDs, malformed hashes, and invalid configuration fail with exit code 2. Custom bounded signatures are supported below; arbitrary regular expressions are not accepted.

Duplicate selection consistently prefers signature matches over entropy matches for the same fingerprint and line range. Occurrences on different lines remain separate findings.

## Save and compare scans

Save reports **outside the repository being scanned**, so report content does not become scan input. The destination directory must exist; existing files are never overwritten.

```sh
reporanger /path/to/repository --history --save-report /path/to/reports/before.json
# After making repository changes:
reporanger /path/to/repository --history --compare /path/to/reports/before.json --save-report /path/to/reports/after.json
```

`--save-report` always saves redacted JSON regardless of the selected console format. `--compare` adds counts for new, unchanged, and no-longer-detected findings. JSON also lists new and no-longer-detected locations. Comparisons require the same source string, history/reflog options, scan limits, and exclusion/suppression policy. Incomplete history scans cannot be compared.

Comparison groups findings by path, rule, fingerprint, and historical blob/source kind. Moving a token to another line in the same file does not make it new; moving it to another file does. Repeated occurrences of the same token within one file count as one comparison item. CI thresholds continue to evaluate all findings, rather than only new findings.

“No longer detected” is a comparison result, not proof of remediation. Findings deleted from current files can remain in Git history. Changing the scan engine can also change detection results. Reports generated before snapshot schema version 1 cannot be used as baselines; create a new baseline with the current CLI.

## Detection accuracy and scope

Entropy screening now requires a credential-related assignment (for example `token`, `password`, `apiKey`, or `clientSecret`). It inspects the assigned value as a whole, rather than arbitrary fragments of identifiers, URLs, or dependency hashes. Environment references and URL values are not entropy candidates. Known credential signatures remain active regardless of assignment context, including in lockfiles and generated files.

This improves precision at a recall cost: an unrecognized credential without a recognizable field assignment can be missed. Entropy also retains minimum length and diversity requirements and supports common single-line literal formats; it is not a complete parser for every language or credential syntax. Public or publishable keys may still require manual review. Default scans perform no live validity checks.

The expanded 52-case detection benchmark covers 28 positive and 24 negative examples. They are regression tests, not an independent production benchmark. On the Cherry Blossom test repository, an unchanged 101-file/40-commit scan dropped from 3,063 potential findings to two low-confidence findings for one `.env` value (current and historical), with no exclusions. This reduction is not a claim that every removed finding was manually verified or that every secret can be found.

Saved reports now record a detector revision in the scan profile. Comparisons across detector/scoring revisions or model weights are rejected; create a fresh baseline after upgrading from the earlier detector.

## Custom signatures

Add rules to your explicit JSON policy:

```json
{
  "custom_rules": [
    {"rule_id": "company_key", "prefix": "acme_", "alphabet": "base64url",
     "min_length": 24, "max_length": 64, "severity": "high"}
  ]
}
```

Lengths describe the variable token portion after the prefix and before an optional literal suffix. Available alphabets: `alnum`, `hex`, `base64url`, `base64`. Rules must use unique IDs and cannot replace built-ins. Up to 100 rules are accepted. Prefixes are escaped, and lengths are bounded; arbitrary regular expressions are deliberately unsupported. Custom rules are unverified signatures, not provider-validated credentials. They apply to history as well as current files and can be disabled by ID.

## Validation and scoring

JSON findings include offline validation results when a validator supports the rule, plus safe code-context metadata. Historical context is derived from that revision's text, not today's file. Python uses its AST; other supported languages fall back to line context if no compatible Tree-sitter provider is installed. Identical blobs under different file extensions are analyzed separately to avoid reusing the wrong language context.

The repository risk level and score reflect the strongest finding. Repeating medium findings cannot promote the repository to high risk. Scores are triage indicators, not calibrated probabilities of exposure.

## Experimental trained classifier

```sh
python -m backend.ml.training benchmarks/triage.jsonl models/experimental.json benchmarks/model_metrics.json
reporanger /path/to/repository --model models/experimental.json
python -m benchmarks.evaluate
```

This older synthetic model remains opt-in. Its lower synthetic recall prevented unrestricted promotion; normal scans now use the newer guarded tree model described below. See [MODEL_CARD.md](MODEL_CARD.md) for data provenance, metrics and limitations. Download the model JSON asset with a wheel installation, or use the `models/` directory from the source distribution. Model loading accepts bounded validated JSON weights or trees; it never loads executable serialization.

An [independent CredData pilot](benchmarks/creddata-pilot.md) scanned 144 labeled files from five deterministically selected repositories. Raw detection reached 18.3% positive-annotation recall and 77.3% precision among alerts with definite labels; 28 unlabeled alerts were excluded from precision. Matching is approximate by line overlap. These results expose substantial detection gaps and do not establish production readiness or risk-score calibration. See the report for reproduction, scope and category counts.

Detector revision 5 recognizes mixed-character password literals of at least 8 characters, XML password/token elements, literal setter calls, credential-bearing connection URLs, and Basic/Bearer headers. Shorter password candidates require contextual literals, entropy of at least 2.5 bits/character and two character classes; obvious placeholders are filtered by that rule. These remain medium-severity candidates. In a complete independent sample, positive-annotation recall increased from 12.8% to 19.7%, with labeled-alert precision changing from 93.1% to 89.6%. See the [revision-5 evaluation](benchmarks/revision5/README.md) for the full tradeoff, broader coverage and model limitations. That release used detector revision 5 and scoring revision 3.

## Release process

The package version is `0.2.0a8`; release CI and publication remain pending. Distribution is through the private GitHub repository and its releases. Pushing a matching version tag runs the Windows/Linux Python 3.10/3.12 matrix, then builds and publishes a GitHub prerelease with the wheel, source archive, model JSON and model card. CI binds the current independent detector report to its report hash, detector/scoring revisions and detector/feature code hashes. The [current evidence manifest](benchmarks/revision9/release-evidence.json) points directly to the fresh ranks 260–279 audit and passes evidence validation while failing scanner readiness. Alpha tags require valid evidence from at least 20 selected repositories with complete file coverage. Stable `X.Y.Z` tags additionally require the unchanged 90% labeled-alert precision / 80% positive-annotation recall thresholds. Evidence validity and accuracy readiness are separate results; neither certifies production readiness.

`.github/workflows/pypi.yml` is an unused manual publishing scaffold, disabled unless the repository variable `PYPI_ENABLED` equals `true`. Keep it disabled for the chosen private GitHub distribution. PyPI/TestPyPI setup and publication are outside the current release scope.

## Context, richer custom rules, and external ML

Configuration assignments now receive structural context. JSON findings include safe `context.evidence`, numeric `confidence_score`, and `confidence_rationale`. Public-identifier and placeholder evidence can reduce heuristic scores but does not remove findings; those two reductions are not applied to built-in signatures. Comment context is also reported. Values of 16 characters or fewer are fully masked.

Custom rules additionally accept `suffix`, `paths`, `exclude_paths`, `keywords` and `minimum_entropy`. Path globs use the same repository-relative matcher as exclusions; keywords are case-insensitive literal substrings on the matching line. Entropy applies to the complete matched token, including prefix and suffix. For example:

```json
{
  "custom_rules": [{
    "rule_id": "company_key", "prefix": "acme_", "suffix": "!",
    "alphabet": "base64url", "min_length": 24, "max_length": 64,
    "paths": ["config/*"], "exclude_paths": ["config/examples/*"],
    "keywords": ["token", "secret"], "minimum_entropy": 3.5, "severity": "high"
  }]
}
```

The external-data model is opt-in:

```sh
reporanger /path/to/repository --model models/creddata-experimental.json
python -m backend.ml.training benchmarks/external-triage.jsonl models/creddata-experimental.json output/external-training.json --external
python -m benchmarks.evaluate_model benchmarks/external-holdout.jsonl models/creddata-experimental.json output/independent-model.json
```

Its repository-separated training, validation-only calibration and independent evaluation are documented in [MODEL_CARD.md](MODEL_CARD.md). Mixed results prevent default promotion. Risk remains a prioritization policy, not a calibrated probability of active exposure.

## Structural detection and release gates (revision 6)

Signed compact JWTs and private JWK material are detected by bounded offline parsing. Public-only JWKs, duplicate members and dynamic expressions are excluded. Supported JWK forms include flat JSON and JavaScript/Python literal objects. JWT signatures are not verified, so syntax alone no longer adds credential-validity confidence. Literal command-line credentials and PowerShell plaintext conversion arguments are also covered. Built-in IDs `jwt` and `private_jwk` are available in `disabled_rules`.

The [revision-6 evaluation](benchmarks/revision6/README.md) records both the initial no-gain sample and the final modest gain: 104 to 107 detected positive annotations, with nine false-positive alerts in both versions. That revision added rejection of all-positive/all-negative predictions and low specificity to the model promotion gate. Its experimental model remained opt-in. That release used detector/scoring revisions 6/4.

Stable `X.Y.Z` release tags must pass the explicit minimum-evidence gate; the current evidence fails because detection recall remains below the project threshold. This does not prevent alpha builds, and passing it in future will not alone certify production readiness.


## Literal password coverage (revision 7)

Explicit password fields now detect short and low-entropy literal values, including weak defaults such as `password123`. Supported forms include quoted assignments, config-file bare values, indexed assignments, Ruby/PHP hash arrows, XML, setter calls, SQL password clauses, connection URLs, Basic authorization headers and command arguments. Variable references, obvious templates and masked values are excluded. These findings use the medium-severity `hardcoded_password` rule; disable it through `disabled_rules` when needed. Existing stronger detections are deduplicated. DSA and encrypted PEM private-key headers are also recognized.

This trades broader credential coverage against alerts on examples and weak test defaults. A literal is not proof of an active credential. See [the revision-7 comparison](benchmarks/revision7/README.md) for independent measurements and exclusions. That release used detector revision 7 and scoring revision 4; its experimental models remained opt-in and had not been retrained for the wider candidate population.


## Context-based review priority (revision 8)

Findings inside Python test functions/classes, test/spec filenames, README/Markdown/reStructuredText files and example configuration files receive lower-priority evidence. Expected/mock/fixture field names and unquoted source references are also explained. These findings remain in the report. Public-identifier and placeholder evidence is matched to the actual candidate, preventing one field from lowering an unrelated finding on the same line. These heuristics do not establish that a credential is safe, and scores remain triage estimates.

Short passwords in explicit PowerShell `ConvertTo-SecureString ... -AsPlainText` calls are detected. That release used detector revision 8 and scoring revision 5. The [revision-8 evaluation](benchmarks/revision8/README.md) separates raw detection from the medium-or-higher risk review queue, including any recall cost from prioritization. Neither experimental model had been retrained or promoted at that stage.


## Updated optional ML classifier

The older v2 classifier remains an experimental override (`--model models/creddata-v2-experimental.json`). Its first independent audit passed, but a later 2,756-candidate sample produced 1,451 false positives and only 43.19% precision; the earlier result did not generalize. See [the original ML-v2 evaluation](benchmarks/ml-v2/README.md) and [the follow-up audit](benchmarks/ml-v3/v2-fresh-audit.json). Omitting `--model` uses the bundled guarded tree model. Candidate scoring does not increase raw scanning recall or verify live credentials.


## Trained ML in normal scans

Version 0.2.0a7 automatically loads 100 learned decision trees from the installed package. No model download, training service or manual flag is needed. ML refines scores inside existing classifier and risk bands, preserving current and historical alert decisions and respecting negative context. Scoring revision 6 includes tree and runtime policy identity; create new saved-report comparison baselines after upgrading.

The development pool has 4,640 numeric candidate labels from 90 repositories. Fitting uses 2,784 rows, depth selection uses 928 validation rows, and 928 internal test rows supply development evidence. Unrestricted ML still introduces too many false positives and cannot widen default alert decisions. See [ML-v4 results](benchmarks/ml-v4/README.md) for the fresh 17-repository evaluation and limitations. The 90% precision / 80% recall scanner target remains unmet.

```sh
reporanger /path/to/repository --format json
# Historical v4 training requires the trainer at commit 9ca9bcbc2f33dcfb29c138c0dac92ec2fbaa222d:
python -m backend.ml.tree_training benchmarks/ml-v4/development.jsonl models/creddata-v4-trees.json output/tree-training.json
```

Inference and training use the Python standard library. Model data contain no raw credentials or source snippets. Numeric shape features are derived from credential candidates; quantization is not anonymization. `--model` is an explicit experimental override; scores do not validate active credentials.

The current tree trainer uses the later six-configuration v6 grid, so running the historical v4 command in this checkout trains a new experiment rather than reproducing the saved v4 model. See the [v4 reproduction notes](benchmarks/ml-v4/README.md).

## Historical v5 experiment (2026-10-05)

The v5 stage added finer numeric shape features and semantic context, with scoring revision 7. At that stage, local regression checks passed 165 tests and 52 synthetic detector fixtures. These results are preserved as historical evidence.

The v5 development pool contains 4,928 candidate labels from 102 candidate-bearing repositories, with all 4,431 expected files recovered. Independent evaluation on 20 fresh repositories (ranks 220–239) recovered all 557 files. V5 candidate precision and recall are both 94.62%, but this positive-heavy sample has only 24 negative candidates and the model adds seven false positives versus the heuristic's zero, failing the relative promotion gate.

Raw scanner precision was 84.42% among definitively labeled alerts and positive-annotation recall was 28.43%; both missed the 90%/80% release targets. V5 remains an experimental override. See [the complete v5 evaluation](benchmarks/ml-v5/README.md).

## V6 experiment and a8 evaluation (2026-10-06)

V6 uses 140 previously inspected development repositories (ranks 100–239), complete coverage of 4,988 expected labeled files, six predeclared tree configurations and validation-only threshold selection. All six validation policies failed. The selected model is an experimental override; the bundled guarded v4 artifact remains unchanged.

The frozen v6 audit recovered 662/662 files from 20 new repositories (ranks 240–259). Its 469 definite candidate labels give v6 28.93% precision, 93.55% recall, 17.39% specificity and 44.61% repository-macro specificity. The strict candidate-readiness gate fails. Raw detection on that sample separately gives 26.44% labeled-alert precision and 52.74% positive-annotation recall. Candidate recall excludes missed source annotations and cannot stand in for scanner recall. These results provide no production accuracy claim.

The initial v6 model and results are retained in [ML-v6 evidence](benchmarks/ml-v6/README.md). Once the ranks 240–259 audit was used to diagnose localization false positives, that sample became development evidence for any subsequent tuning. See [revision-9 detector evidence](benchmarks/revision9/README.md), [implementation status](IMPLEMENTATION.md) and [model evidence](MODEL_CARD.md) for the current release candidate's evidence.

## V7 fresh audit and a8 status

V7 adds source-derived JSON translation-map context and uses a model frozen before evaluating fresh ranks 260–279. All 416 expected labeled files across 20 repositories were recovered. The 188 definite emitted candidates contain 137 positive and 51 negative labels. V7 produces TP111/FP13/FN26/TN38: 89.52% precision, 81.02% candidate recall, 74.51% specificity and 75.13% repository-macro specificity. The strict gate fails because precision is below 90% and there are fewer than 100 negative candidates; the relative gate also fails precision regression against the heuristic. V7 remains an experimental `--model models/creddata-v7-trees.json` override. The bundled guarded v4 model is unchanged.

On the reused ranks 240–259 diagnostic sample, v7 has only 26.34% precision and 79.03% candidate recall. This is inspected evidence, and the fresh sample has a different composition; the two results do not establish a broad improvement over v6. Raw scanning on fresh ranks 260–279 separately produces 137 true-positive and 51 false-positive definite alerts (72.87% precision), detecting 141 of 449 positive source annotations (31.40% recall). Candidate scoring excludes detector misses and cannot replace annotation recall. See [the complete v7 audit](benchmarks/ml-v7/README.md).

Local validation passed 245 regression tests, all 52 synthetic detector fixtures and an installed-wheel smoke check outside the checkout, including the CLI, bundled model, authorization formats, redaction, protected API, dashboard assets, scan worker and HTTP report download. Desktop and mobile dashboard views were inspected. Browser automation did not complete a file-save download check; the HTTP attachment, report equality and redaction checks passed. The candidate awaits release CI and private GitHub publication; PyPI remains outside scope.
