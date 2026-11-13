# Reproducible Python CI dependency lock design

Status: generated lock reviewed and committed; CI has been changed to install from the committed lock in a clean environment. Exact-commit validation is pending.

## Supported target and committed lock

- CI target: Ubuntu 24.04, CPython 3.12, Linux x86_64.
- Lock inputs: `requirements-ci.in`.
- Lock generator: pip-tools 7.4.1 with pip 24.3.1.
- Generator Python: 3.12.16.
- Committed files: `requirements-ci.lock`, `requirements-ci.lock.sha256`, and `lock-generation-record.txt`.
- Lock SHA-256: `a8210130b58d3fe86c8805b97a5cf98229e13d270e04a21ace171f717d62582c`.
- Verified candidate ZIP SHA-256 from CI run 1659: `10f0430fbadb37ec0a1523e69d85685fc4c4f1d6149b893f876fb3f6b73c1cc6`.
- Lock contains four exact pinned distributions and 153 SHA-256 artifact hashes. All four distributions have hash entries.
- The downloaded archive was independently checked against its GitHub artifact digest; the embedded lock checksum was verified with `sha256sum -c`.
- The three committed file blob SHAs were independently fetched from GitHub after the writes: lock `90dfefc42e88e9e072699ffedba03c80ead08aa8`; checksum manifest `8586bb8081ba2eab522a363bb4a75a066271b374`; generation record `0dd9bdc524ec061e27491a759dcac7349e204ca4`.

The candidate is an actual generated artifact, not a hand-authored lock. Do not hand-write hashes, copy hashes from an unrelated platform, or treat an observed package version as a lock.

## Clean-install CI sequence

The primary `.github/workflows/ci.yml` now checks out the committed lock directly, verifies `requirements-ci.lock.sha256`, creates a fresh virtual environment, installs the complete hash-pinned dependency closure with `--require-hashes`, installs the project editable with `--no-deps --no-build-isolation`, runs `pip check`, and executes the full contract and synthetic integration suite. The primary CI no longer generates or consumes an ephemeral lock artifact.

The separate `.github/workflows/generate-ci-lock.yml` remains a candidate-regeneration workflow. It generates and validates a new lock artifact when lock inputs or the generator workflow change; that artifact must be reviewed and committed deliberately. It does not silently replace the committed lock.

## Verified generator and prior CI results

- CI run 1659 completed successfully on commit `a029e9c8b4e1352146eace96234833ac3075a539`: generated lock candidate, hash verification, fresh environment installation, editable install, `pip check`, and full contract/synthetic suite all passed. This run validated the generated candidate workflow, not the new committed-lock CI path.
- The archive from run 1659 was independently downloaded and its SHA-256 matched the GitHub artifact digest. The lock's embedded checksum matched.
- The lock and checksum manifest were committed on feature branch `feat/ieif-raei-integration`; the primary CI workflow was then changed to install from those committed files.
- Exact new CI run 1665 is queued/running for commit `0d0794dcb8e5557cf013cd8bc369602092981204`. No pass is claimed until its jobs complete successfully.

## Security and platform boundaries

The lock's hashes constrain the allowed distribution bytes for the supported runner target. The workflow installs only hash-verified dependencies and disables persistence of checkout credentials. The editable project install intentionally uses `--no-deps --no-build-isolation` because its complete declared build/runtime closure is already installed from the lock.

This lock is specific to the declared Ubuntu 24.04 / CPython 3.12 target. Other Python/platform combinations need separately generated and reviewed locks rather than reusing Linux wheel hashes. Regenerate and review whenever `requirements-ci.in`, `pyproject.toml`, Python minor version, runner platform, or build backend changes.

The generator itself currently bootstraps pip and pip-tools with exact direct versions, but pip-tools' own transitive bootstrap environment is not itself represented as a separate hash-locked toolchain. That is a remaining reproducibility-hardening opportunity; it does not alter the hash-pinned application/test dependency install performed by primary CI.

## Remaining completion gate

1. Confirm CI run 1665 passes on the exact committed-lock workflow head.
2. If it fails, correct the workflow or lock based on the observed failure, then rerun on the resulting exact head.
3. Independently review dependency provenance, lock regeneration controls, and the final combined candidate against current `main`.

The PR remains draft pending integration and independent security review. Passing synthetic CI is not production certification or live Google authorization.
