# Revision 7: literal password detection

Passwords need not be long or random. This revision adds bounded literal detection for explicit password assignments, indexed fields, hash arrows, XML, setters, SQL, connection URLs, Basic headers and command arguments. Templates, references, masked values and configuration syntax are excluded. Existing stronger findings are deduplicated; the new rule is medium severity and can be disabled with `hardcoded_password`. DSA and encrypted private-key headers are covered as well.

## Independent comparison

CredData metadata is pinned to `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Baseline detector revision 6 comes from `c06e8179557da536898d92c22a925a446ca29bae`. Both versions use identical source bytes, file bounds and matching. The final sample is ranks 120-139 using the existing deterministic seed; it was not used for tuning.

All 831 labeled files and 4362 annotations from 20 repositories were processed. Source downloads interrupted the first attempt; the complete retry is the recorded result.

| Measure | Revision 6 | Revision 7 |
| --- | ---: | ---: |
| Positive annotations detected | 684 / 1170 | 790 / 1170 |
| Annotation recall | 58.46% | 67.52% |
| Positive-labeled alerts | 678 | 783 |
| Negative-labeled alerts | 156 | 195 |
| Definite-label alert precision | 81.29% | 80.06% |

Excluded from precision: baseline/current unlabeled alerts 63/89, X labels 89/146, and conflicting-label alerts 2/11. These excluded alerts have not been judged correct. There are still 380 missed positive annotations.

The initial fresh sample (ranks 100-119, reports in this directory) improved recall from 42.50% to 59.97%, while labeled precision fell from 87.98% to 81.72%. We then used that sample diagnostically to exclude format placeholders and nonliteral configuration syntax. It is now development data. The final sample above measures the frozen changes on separate repositories; sample percentages must not be compared across different samples.

## Scope and release decision

Matching uses inclusive line overlap and can match the wrong value on a shared line. Annotation recall and alert precision use different units. Only labeled files are scanned, using original pinned source, without upstream obfuscation; this is not the official CredData leaderboard. Test/example literals may be detected, and labels do not establish active credential exposure. No source code was executed, credentials tested online, or original corpus material committed.

This remains an alpha. Run the readiness check below for unmet project thresholds. ML weights and scoring revision 4 are unchanged; neither model is promoted or recalibrated for the expanded candidate population. Regression verification: 111 unit/integration tests and all 52 synthetic detector fixtures pass.

## Reproduce

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 20 --offset 120 --max-file-mib 16 --download --git-fallback --output output/revision7.json
python -m benchmarks.readiness benchmarks/revision7/final/current.json --require-ready
```

For the baseline use an isolated copy at commit `c06e817`, with the same evaluation command and source cache. The benchmark retry fix handles interrupted HTTP bodies without promoting partial files into the archive cache; regression tests cover recovery and bounded failure.
