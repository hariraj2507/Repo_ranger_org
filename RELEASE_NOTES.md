# RepoRanger v0.2.0a3

- Add bounded JWT and private-JWK structural detectors. Flat JSON, JavaScript and Python JWK literals are supported; public-only keys and duplicate fields are excluded.
- Add literal curl/wget/database command credentials and PowerShell `ConvertTo-SecureString` arguments used with `-AsPlainText`. Variable references and username-only options are excluded.
- Correct JWT scoring: decoded structure is not evidence of a verified credential or signature.
- Strengthen model promotion checks to reject single-class predictions and poor specificity even when class imbalance makes Brier error look favorable.
- Add explicit stable-release acceptance checks. The current evidence fails these checks, so this remains an alpha.
- Saved reports use detector revision 6 and scoring revision 4. New built-in IDs `jwt` and `private_jwk` can be disabled but cannot be overwritten by custom rules.

In the final fresh sample, positive annotations detected increased from 104 to 107 out of 279, with false-positive alerts unchanged at nine. This is a modest improvement; substantial misses remain. The earlier fresh sample showed no gain. The experimental ML model remains opt-in and is not production-promoted. See `benchmarks/revision6/README.md` for complete results and limits.
