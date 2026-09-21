# Revision 8: context and precision investigation

## Development diagnosis

The already-used revision-7 final sample (CredData ranks 120-139) contained 195 negative-labeled alerts: 153 generic entropy findings, 38 literal-password findings and four private-key headers. The leading missed categories were UUID (116), Password (77), Key (25), Token (23), Auth (18), Dropbox App secret (14), Secret (10) and Nonce (9). These categories are not proof of active exposure; indiscriminately flagging UUIDs, nonces or public identifiers would be misleading.

A development experiment excluding unquoted code assignments removed four false-positive alerts but also lost four positive annotations, so it was rejected. Source references remain visible with explicit uncertainty evidence. No corpus snippets or credential values are included here.

## Changes

- Recognize Python test scopes, test/spec filenames, README/Markdown/reStructuredText and example-config paths for lower review priority.
- Explain expected/mock/fixture fields and unquoted source references. Keep findings visible.
- Attach public-identifier and placeholder evidence only when the candidate fingerprint matches the assignment, avoiding unrelated-field penalties on a shared line.
- Detect short literal passwords in explicit PowerShell plaintext conversions.
- Measure raw detection separately from the medium-or-higher risk review queue; do not count demoted positives as detection improvements.

## Untouched repository comparison

Metadata: CredData `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Sample: deterministic ranks 140-159, not used for tuning. Baseline: `d951e7a9a2add9fa7b9fbb10e20b37226d6345ee`, detector/scoring revisions 7/4; current revisions 8/5. All 573 labeled files, 2,549 annotations and 20 repositories were processed, including one archive-omitted file recovered from pinned Git objects. Both versions used identical source bytes and matching.

| Measure | Baseline | Current |
| --- | ---: | ---: |
| Raw positive annotations detected | 322 / 746 | 322 / 746 |
| Raw annotation recall | 43.16% | 43.16% |
| Raw positive / negative-labeled alerts | 297 / 20 | 297 / 20 |
| Raw definite-label precision | 93.69% | 93.69% |
| Medium-or-higher positive / negative-labeled alerts | 212 / 16 | 195 / 14 |
| Medium-or-higher definite-label precision | 92.98% | 93.30% |
| Medium-or-higher positive annotations detected | 237 / 746 | 220 / 746 |
| Medium-or-higher annotation recall | 31.77% | 29.49% |

All 386 raw findings remain in each report, including low-priority findings. The new policy demotes 17 positive annotations along with two false-positive alerts from the main review queue. This is a small precision improvement with a review-queue recall cost, not an overall accuracy breakthrough. The PowerShell fix has regression coverage but no measured gain on this sample. The 80% raw-recall milestone remains unmet; 424 positive annotations were missed.

Raw precision excludes 37 unlabeled and 32 X-labeled alerts in each version. Review-queue precision excludes 14/12 unlabeled alerts and three X-labeled alerts for baseline/current. Excluded alerts have not been judged correct. Metadata uses obfuscated paths, so filename-specific behavior has unit coverage but this sample does not fully measure its effect in original repository layouts.

Matching is approximate inclusive line overlap and may match the wrong value on a shared line. Recall counts annotations while precision counts alerts. Only labeled files are scanned, with original pinned sources and no upstream obfuscation. Results are not the official dataset leaderboard, calibrated exposure probabilities or a production-readiness certificate. Scores from different repository samples must not be treated as before/after results.

## Validation and reproduction

119 unit/integration tests and all 52 synthetic regression fixtures pass. No ML weights were retrained or promoted. Existing opt-in models do not have learned weights for the new context features.

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 20 --offset 140 --max-file-mib 16 --download --git-fallback --triage --output output/revision8.json
python -m benchmarks.readiness benchmarks/revision8/current.json --require-ready
```

For baseline scoring, load the literal-password detector, context engine, feature extractor, classifier and confidence engine from `d951e7a` in an isolated copy, with the same evaluation harness and source cache. Stable-release readiness fails on recall. This remains an alpha; callers using medium-or-higher failure policies should be aware of the measured demotions.
