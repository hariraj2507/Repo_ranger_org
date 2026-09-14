# RepoRanger v0.2.0a1

This prerelease completes the local CLI release foundation.

- Historical candidates receive offline structural validation and syntax context from their own Git blob. Reports include safe validation and context metadata.
- UTF-16 historical text is decoded instead of being treated as binary.
- Custom credential signatures support literal prefixes, bounded alphabets and lengths, and severity. They apply to current files and history; built-in rules cannot be overwritten.
- Repository score follows the strongest finding. Repeated weak candidates cannot inflate severity.
- Fine-grained GitHub token detection now matches the already-supported offline validator.
- Added a 52-case synthetic detection benchmark and an experimental trained logistic classifier with group-separated train/validation/test partitions.
- The trained model stays opt-in because its held-out synthetic recall is lower than the baseline. These results do not establish real-world accuracy.
- CI tests Windows/Linux on Python 3.10/3.12. Version-tag releases publish only after all test jobs pass.

No live credential verification is performed. Non-Python syntax context requires an optional compatible Tree-sitter provider. This is an early alpha, not a guarantee that a repository is secret-free.
