# Authentication detection follow-up, 2026-09-15

Detector revision 4 adds complex quoted password literals of at least 12 characters and Basic/Bearer authorization headers. Password literals require at least three character classes and entropy of at least 3 bits per character. Basic headers must decode as UTF-8 username:password with a nonempty username and a password satisfying the same heuristic. Bearer values retain the existing 20-character/4-bit thresholds. Environment references are excluded. The existing generic assignment screen and signature rules remain active. These are medium-severity candidate findings, not validated active credentials.

New synthetic tests cover those syntaxes, weak/invalid Basic values, environment references, redaction, line numbers and duplicate alerts. They establish implementation behavior, not real-world recall improvement.

## Second external repository sample

The same fixed ranking from the [first pilot](creddata-pilot.md) was used with offset 5 and count 5, so no repository overlapped the first sample. Metadata remains pinned to `c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d`. Revision 3 used the entropy detector from project commit `e57b8171aa64faf5bbb6780cda1be7f95759913b`; both versions used the current identical archive and matching harness. No source examples or credentials are included in the aggregate results.

| Measure | Revision 3 | Revision 4 |
| --- | ---: | ---: |
| Files scanned / expected | 80 / 100 | 80 / 100 |
| Positive annotations detected / available | 3 / 24 | 3 / 24 |
| Positive annotation recall | 12.5% | 12.5% |
| Alerts matching positive / negative labels | 3 / 5 | 3 / 5 |
| Precision among definitely labeled alerts | 37.5% | 37.5% |
| Unlabeled alerts excluded from precision | 3 | 3 |

**The external comparison shows no measured improvement and is incomplete.** Twenty labeled files were absent from the selected source archive for repository `1d8ec728`. Of 361 expected annotations, 294 were available (24 T, 260 F, 10 X); 67 were excluded with the missing files. No replacement repository was selected. Scores apply only to available files, and missing coverage may bias them. The matching and scope caveats in the first pilot also apply here. The sample's composition differs from the first pilot, so percentages across the two samples do not show a regression.

The added syntaxes should not be marketed as a demonstrated general accuracy improvement. Broader password/authentication formats and missing-file acquisition remain follow-up work. Both inspected samples are now diagnostic data; a further independent evaluation needs new repositories.

Run the current detector with:

```sh
python -m benchmarks.creddata --metadata tmp/creddata --repositories 5 --offset 5 --download --output output/accuracy/creddata-followup.json
```

The command exits nonzero for the known missing files while still writing the report. Baseline comparison requires an isolated copy of the project using this same harness with `backend/detectors/entropy_detector.py` restored from commit `e57b8171aa64faf5bbb6780cda1be7f95759913b`; mark that report's detector revision as 3. Archive hashes and per-repository counts are preserved in the checked-in `creddata-holdout-revision3.json` and `creddata-holdout-revision4.json` files.
