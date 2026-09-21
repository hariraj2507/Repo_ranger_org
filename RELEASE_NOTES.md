# RepoRanger v0.2.0a4

- Detect weak and short literal passwords across configuration, code, SQL, URLs and Basic authentication, without an entropy requirement.
- Exclude dynamic references, templates, masked values and configuration markers. New medium-severity rule: `hardcoded_password`.
- Recognize DSA and encrypted PEM private-key headers.
- Recover interrupted benchmark downloads with bounded retries and no partial cache entries.
- Reports use detector revision 7 and scoring revision 4; experimental ML remains opt-in.

On 20 independent repositories, positive-annotation recall changed from 58.46% to 67.52%; definite-label alert precision changed from 81.29% to 80.06%. See `benchmarks/revision7/README.md` for full counts, excluded labels, the earlier precision regression and limitations. This is an alpha, not a claim that accuracy is solved or production readiness established.
