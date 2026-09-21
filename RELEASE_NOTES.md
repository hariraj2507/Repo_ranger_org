# RepoRanger v0.2.0a5

- Add explicit context evidence and lower review priority for test scopes, test/spec/documentation filenames, expected/mock fields and likely source references. Findings remain visible.
- Fix evidence attribution so a public identifier on a line does not penalize a different credential on that line.
- Detect short passwords in explicit PowerShell plaintext conversions.
- Add separate raw-detection and medium-or-higher review-queue benchmark counts.
- Detector/scoring revisions: 8/5. ML weights remain experimental and unchanged.

On 20 untouched repositories (573 files), raw detection was unchanged: 93.69% labeled precision and 43.16% annotation recall. Main review-queue precision increased from 92.98% to 93.30%, but 17 positive annotations moved to low priority along with two false-positive alerts. All findings remain available. The 80% recall milestone is not met. See `benchmarks/revision8/README.md` for limitations and full counts.

Validation: 119 tests and 52 synthetic regression cases pass. Alpha release; not production-certified.
