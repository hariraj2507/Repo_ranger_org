# RepoRanger v0.2.0a2

This alpha improves contextual detection, evaluation coverage and configurable rules, while documenting remaining accuracy limits.

- Detect mixed-character password literals of at least eight characters in quoted assignments and configuration files, XML elements, setter calls, connection URLs, and Basic/Bearer headers. Short passwords are fully masked.
- Add configuration assignment context and safe comment/public-identifier/placeholder evidence, with explicit confidence explanations. Known built-in signatures are retained.
- Extend bounded custom rules with literal suffixes, include/exclude paths, same-line keywords and entropy limits for current and historical scans.
- Recover benchmark archive omissions with filtered Git-object reads. Evaluate 2,273 labeled files across 80 repositories with complete selected-file coverage.
- On ten independent repositories, positive-annotation recall increased from 12.8% to 19.7%; labeled-alert precision changed from 93.1% to 89.6%. This is a tradeoff and broad recall remains low.
- Add external numeric training data, repository-separated training, validation-only calibration, reliability tables and risk-band audits. The external model stays opt-in after mixed evaluation results and a failed quality gate.
- Saved reports use detector revision 5 and scoring revision 3 and reject comparisons against older behavior.

The release includes a wheel, source archive, both experimental model JSON files and model card. GitHub release publication requires all Windows/Linux Python 3.10/3.12 CI jobs to pass. There is no live credential validation, PyPI publication or claim of production readiness.
