# Revision 6 verification

This update adds bounded structural JWT/private-JWK parsing and command-line credential detection. JWT structure alone no longer receives known-credential or valid-credential confidence boosts. A new promotion gate rejects single-class models, low specificity, insufficient labels, precision/recall regressions and unimproved Brier error.

Structural parsing follows [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) and the private-key members in [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html). JWT header and payload must be JSON objects, with a nonempty algorithm other than `none` and a decodable signature segment. This does not verify the signature or secrecy. Private JWK detection requires `d` for RSA/EC or `k` for symmetric `oct` keys; public-only JWKs are excluded. Flat JSON, JavaScript and Python literal objects are supported without executing code; duplicate keys and dynamic expressions are rejected.

## Measurements

CredData metadata remains pinned to `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Rankings and original-source acquisition are unchanged. The revision-5 baseline uses the entropy detector from `b0fa9b9ed43f4c2aab10bd962999f3de072c4b57` with the new structural detector disabled. Both versions share the evaluation harness.

- First fresh sample, ranks 80-89: all 313 files and 1,571 annotations processed. Both versions detected 35/283 positive annotations, with 29 positive-labeled and 11 negative-labeled alerts. No gain was measured. These initial results are preserved in this directory.
- Previously inspected diagnostic sample, ranks 30-39: positive annotations detected increased from 46 to 78 out of 234 after the format fixes, with false-positive alerts unchanged at five. This is diagnostic progress, not held-out evidence.
- Final fresh sample, ranks 90-99: all 305 files and 1,148 annotations processed, with no coverage exclusions. Results are under `final/`.

| Final sample measure | Revision 5 | Revision 6 |
| --- | ---: | ---: |
| Positive annotations detected / total | 104 / 279 | 107 / 279 |
| Positive annotation recall | 37.28% | 38.35% |
| Positive-labeled alerts | 89 | 92 |
| False-positive alerts | 9 | 9 |
| Precision among definite labels | 90.82% | 91.09% |

There were 17 unlabeled alerts, one X-labeled alert and 11 mixed-label alerts excluded from precision in each final run. Matching remains approximate inclusive line overlap: annotation recall and alert precision use different units. The sample still has 172 missed positive annotations. Scores across different samples must not be treated as a before/after comparison. All inspected repositories are diagnostic data for future tuning.

## ML and readiness

The existing experimental model was audited on the final sample without retraining on it. It failed the stronger gate because it predicted only one class, had inadequate specificity and fewer than ten negative examples, and regressed precision against the default. The default remains unchanged except for the JWT confidence correction. Risk scores remain prioritization estimates, not calibrated active-exposure probabilities.

`python -m benchmarks.readiness benchmarks/revision6/final/current.json --require-ready` exits nonzero: final independent recall is below 80%, and there are fewer than 20 repositories in that evaluation. These are explicit minimum project acceptance criteria, not an industry certification or sufficient proof of production readiness. The GitHub workflow enforces this check for stable `X.Y.Z` package versions; alpha releases remain available for testing. Operational readiness and representative full-repository testing are still required.

Reproduce current detection with the pinned metadata checkout:

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 10 --offset 90 --max-file-mib 16 --download --git-fallback --output output/revision6.json
```

Reproduce the old detector comparison in an isolated copy using the entropy module from the baseline commit and omitting `StructuredDetector` from `DetectionEngine`. Do not mutate the release checkout to compare versions. No original corpus source or credentials are included in the committed results.
