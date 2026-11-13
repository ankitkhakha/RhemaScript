# Reproducible Python CI dependency lock design

Status: generated lock reviewed and committed; primary CI now installs from the committed lock in a clean environment. Exact-head CI validation passed.

## Supported target and committed lock

- CI target: Ubuntu 24.04, CPython 3.12, Linux x86_64.
- Lock inputs: `requirements-ci.in`.
- Lock generator: pip-tools 7.4.1 with pip 24.3.1.
- Generator Python: 3.12.16.
- Committed files: `requirements-ci.lock`, `requirements-ci.lock.sha256`, and `lock-generation-record.txt`.
- Lock SHA-256: `a8210130b58d3fe86c8805b97a5cf98229e13d270e04a21ace171f717d62582c`.
- Verified candidate ZIP SHA-256 from CI run 1659: `10f0430fbadb37ec0a1523e69d85685fc4c4f1d6149b893f876fb3f6b73c1cc6`.
- Lock contains four exact pinned distributions and 153 SHA-256 artifact hashes. All four distributions have hash entries: cffi (100), cryptography (49), pycparser (2), and setuptools (2).
- The downloaded archive was independently checked against its GitHub artifact digest; the embedded lock checksum was verified with `sha256sum -c`.
- The committed lock blob SHA is `c1b90013dd52c3340302c08778f8ddc5e95c5bc9`, matching the generated artifact file's Git blob hash. The checksum manifest blob is `8586bb8081ba2eab522a363bb4a75a066271b374`; the generation record blob is `0dd9bdc524ec061e27491a759dcac7349e204ca4`.

The candidate is an actual generated artifact, not a hand-authored lock. Do not hand-write hashes, copy hashes from an unrelated platform, or treat an observed package version as a lock.

## Clean-install CI sequence

The primary `.github/workflows/ci.yml` checks out the committed lock directly, verifies `requirements-ci.lock.sha256`, creates a fresh virtual environment, installs the complete hash-pinned dependency closure with `--require-hashes`, installs the project editable with `--no-deps --no-build-isolation`, runs `pip check`, and executes the full contract and synthetic integration suite. The primary CI no longer generates or consumes an ephemeral lock artifact.

The separate `.github/workflows/generate-ci-lock.yml` remains a candidate-regeneration workflow. It generates and validates a new lock artifact when lock inputs or the generator workflow change; that artifact must be reviewed and committed deliberately. It does not silently replace the committed lock.

## Exact-head CI validation

- CI run 1659 completed successfully on commit `a029e9c8b4e1352146eace96234833ac3075a539` using the generated candidate artifact. This validated the earlier generated-candidate path, not the committed-lock path.
- After committing the files and changing primary CI to use them, runs 1665-1670 exposed two separate issues: an initial single-character lock-hash transcription error, then stale workflow-contract tests that still expected the old artifact-download design. These runs failed and are retained as audit history.
- The lock transcription was corrected against the generated artifact; the committed lock's SHA-256 and Git blob SHA now match the artifact exactly.
- Updated `tests/test_remote_ci_workflow.py` to assert the committed-lock design and verify that the workflow no longer downloads an ephemeral lock artifact.
- GitHub Actions run 1671 completed SUCCESS on exact head `fa87123b5c83298752f78df7e151a946b9e29297`: https://github.com/ankitkhakha/RhemaScript/actions/runs/43416638581.
- On that exact head, the checksum verification and clean locked dependency installation passed, the full local CI suite passed, and the redacted IF-18 report uploaded successfully.

## Security and platform boundaries

The lock's hashes constrain the allowed distribution bytes for the supported runner target. The workflow installs only hash-verified dependencies and disables persistence of checkout credentials. The editable project install intentionally uses `--no-deps --no-build-isolation` because its complete declared build/runtime closure is already installed from the lock.

This lock is specific to the declared Ubuntu 24.04 / CPython 3.12 target. Other Python/platform combinations need separately generated and reviewed locks rather than reusing Linux wheel hashes. Regenerate and review whenever `requirements-ci.in`, `pyproject.toml`, Python minor version, runner platform, or build backend changes.

The generator itself currently bootstraps pip and pip-tools with exact direct versions, but pip-tools' own transitive bootstrap environment is not itself represented as a separate hash-locked toolchain. That is a remaining reproducibility-hardening opportunity; it does not alter the hash-pinned application/test dependency install performed by primary CI.

## Remaining integration gate

1. Perform the final dependency-provenance and lock-regeneration review.
2. Revalidate the combined candidate against current `main`.
3. Keep PR #62 draft until the independent security and integration review is complete.

Passing synthetic CI is not production certification or live Google authorization.
