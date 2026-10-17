# Detector revision 9 evidence: 2026-10-06

The initial v6 raw-detector audit is preserved in `independent.json`. The current release manifest binds the fresh v7 raw-detector report in `../ml-v7/final/holdout-detection.json` to pinned CredData evidence and the current detector/feature code. Both reports use line-labeled files without history, ML scoring, risk thresholds or online credential verification. They do not estimate production accuracy.

## Initial frozen sample: ranks 240–259

CredData pin: `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Deterministic seed: `reporanger-external-pilot-v1`. Twenty selected repositories at ranks 240–259 were initially untouched by v6 development, which used ranks 100–239. Original paths were used in memory for context and were not exported. Archive recovery with Git fallback recovered all 662 expected labeled files, with a 16 MiB per-file acquisition limit and no missing-file errors. Source was not executed and corpus credentials were not checked online.

| Raw detector measurement | Count / result |
|---|---:|
| True-positive definite alerts | 124 |
| False-positive definite alerts | 345 |
| Labeled-alert precision | 26.44% |
| Positive annotations detected / total | 125 / 237 |
| Positive-annotation recall | 52.74% |
| Positive annotations missed | 112 |
| Negative annotations | 3,697 |
| Unknown annotations | 155 |
| Ambiguous / unknown / unlabeled alerts | 6 / 108 / 42 |

Matching uses inclusive line overlap. Conflicting, unknown and unlabeled alerts are excluded from definite-label precision and reported separately. Annotation recall and alert precision have different denominators; a true-positive alert may overlap more than one positive annotation. Complete file recovery describes acquisition coverage, not comprehensive credential detection.

Both project scanner targets fail: 90% labeled-alert precision and 80% positive-annotation recall. The corresponding [v6 classifier evaluation](../ml-v6/README.md) evaluates 469 emitted definite candidates; its candidate recall cannot replace raw annotation recall. After these results informed localization/context diagnostics, ranks 240–259 became inspected evidence for future development. Preserve this report as the frozen v6 audit, and obtain a fresh sample for subsequent tuning.

## Release evidence requirements

`benchmarks.release_gate` checks report identity, detector/scoring revisions, normalized UTF-8/LF code hashes, selected repository IDs, aggregate counts and complete per-repository file coverage. The code manifest covers detector, AST, validator, analysis and feature-extraction modules. Independence is an explicit evaluator declaration backed by a frozen protocol; favorable scores or a manifest alone cannot establish it.

An alpha requires valid current evidence from at least 20 independently selected repositories with complete file coverage. Stable tags additionally require the unchanged scanner readiness thresholds, including at least 100 positive and 100 negative annotations and the 90%/80% precision/recall floors. Raw reports explicitly omit scoring (`scoring_revision: null`) because the scorer is not run; the manifest still binds the current scoring revision and code. Evidence validity and readiness are distinct, and neither is an operational certification.

```sh
python -m benchmarks.release_gate verify benchmarks/revision9/release-evidence.json
python -m benchmarks.release_gate verify benchmarks/revision9/release-evidence.json --require-ready
```

The first command validates the current bound evidence; the second additionally enforces stable readiness. Create a new manifest only after freezing the detector and declaring provenance. Regenerating a hash manifest does not make an inspected sample independent for subsequent tuning.

## Current fresh audit for a8

The release manifest selects 20 fresh repositories at ranks 260–279 and verifies complete recovery of all 416 labeled files. Raw detection produces 137 true-positive and 51 false-positive definite alerts, or **72.87% labeled-alert precision**. It detects 141 of 449 positive annotations, or **31.40% positive-annotation recall**, and misses 308. Ambiguous, unknown and unlabeled alerts are reported separately in the JSON evidence. Both the 90% precision and 80% recall targets fail. The manifest is valid for an alpha release, but readiness is false. The matching [v7 candidate audit](../ml-v7/README.md) reports separate candidate-level measurements and also fails its promotion gate.
