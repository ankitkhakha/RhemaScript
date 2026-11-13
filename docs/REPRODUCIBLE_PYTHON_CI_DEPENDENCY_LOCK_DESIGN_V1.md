# Reproducible Python CI dependency lock design

Status: generated hash-lock candidate verified in GitHub Actions; repository commitment and final governance acceptance remain pending.

## Supported target and generated candidate

- CI target: Ubuntu 24.04, CPython 3.12, Linux x86_64.
- Lock inputs: `requirements-ci.in`.
- Lock generator: pip-tools 7.4.1 with pip 24.3.1.
- Generator Python: 3.12.16.
- Generated candidate: `requirements-ci.lock`, `requirements-ci.lock.sha256`, and `lock-generation-record.txt` in GitHub Actions artifact `rhemascript-ci-lock-candidate`.
- Candidate lock SHA-256: `a8210130b58d3fe86c8805b97a5cf98229e13d270e04a21ace171f717d62582c`.
- Candidate ZIP SHA-256 for CI run 1657: `c471caf3dd369ee38511ada103d45db4206ae592bd7e36f91d41fe91c209bdba`.
- Lock contains four exact pinned distributions and 153 SHA-256 artifact hashes. All four distributions have hash entries.
- The downloaded archive was independently checked against its ZIP digest; the embedded lock checksum was then verified with `sha256sum -c`.

The candidate is an actual generated artifact, not a hand-authored lock. It has not yet been committed as repository files; do not describe the repository itself as containing the committed lock until those files are present on the branch.

## Clean-install CI sequence

CI downloads the generated candidate produced by the same workflow run, verifies the embedded lock digest, creates a fresh virtual environment, installs the complete hash-pinned dependency closure with `--require-hashes`, installs the project editable with `--no-deps --no-build-isolation`, runs `pip check`, and executes the full contract and synthetic integration suite.

The lock includes the project runtime dependency closure and the setuptools build backend. The generator validates exact versions and SHA-256 hashes, and downloads supported wheels for the declared runner target before uploading the candidate.

## Verified CI result

For commit `0d876faf8c4a9581557ceb56fdd1e38e67f73e42`, GitHub Actions run 1657 completed successfully:
- lock candidate generation and validation: PASS;
- artifact download and embedded lock digest verification: PASS;
- fresh virtual-environment locked installation: PASS;
- editable install and `pip check`: PASS (workflow step completed);
- `ci/run_ci.py` complete contract and synthetic test suite: PASS, exit code 0;
- IF-18 read-only allowlist: PASS, with only `CHANNEL_READ` and `OAUTH_TOKEN`.

The redacted validation report states that this was synthetic-only validation. It does not prove live Google OAuth consent, account access, or channel identity. No live Google connection was attempted and publishing remained disabled.

## Completion gate

The reproducible CI execution path has passed on the exact commit above. Remaining repository-governance work:
1. Commit the inspected `requirements-ci.lock`, `requirements-ci.lock.sha256`, and `lock-generation-record.txt` into the feature branch.
2. Re-run CI after those files are committed and verify the new commit's result.
3. Review lock changes whenever `requirements-ci.in`, `pyproject.toml`, Python minor version, runner platform, or build backend changes.

Do not hand-write hashes, copy hashes from an unrelated platform, or treat an observed package version as a lock. Other platforms need separately generated and reviewed locks rather than reusing Linux wheel hashes.
